package browser

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"image/jpeg"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

const (
	maxLiveBrowserFrames     = 4
	liveBrowserCapturePeriod = 500 * time.Millisecond
	liveInteractionHold      = 4 * time.Second
	liveInteractionMaxAge    = 30 * time.Second

	// Keep accepted synchronous work bounded during shutdown. Producers wait
	// before admission when the queue is full, so cancellation can reject them
	// without weakening the guarantee for observations already accepted.
	maxPendingLiveBrowserObservations = maxLiveBrowserFrames * 2

	// Blankness inspection is deliberately much cheaper than capture: decode
	// the JPEG once, then inspect at most roughly this many regularly spaced
	// pixels. The threshold is conservative so a mostly-white page with even a
	// small amount of visible UI remains a valid frame.
	maxLiveBrowserBlanknessSamples = 50_000
	liveBrowserNearSolidDelta      = 10
)

type liveBrowserFrame struct {
	ID             string                  `json:"id"`
	URL            string                  `json:"url"`
	LastAction     string                  `json:"last_action,omitempty"`
	UpdatedAt      time.Time               `json:"updated_at"`
	Active         bool                    `json:"active"`
	Status         string                  `json:"status"`
	HasImage       bool                    `json:"has_image"`
	ImageVersion   string                  `json:"image_version,omitempty"`
	ImageUpdatedAt *time.Time              `json:"image_updated_at,omitempty"`
	Interaction    *liveBrowserInteraction `json:"interaction,omitempty"`
}

// liveBrowserInteraction is a short-lived, truthful description of the
// browser gesture currently being performed (or just completed) on a page.
// Coordinates are percentages of the captured viewport, so the UI can draw
// a focus box and cursor over a resized frame without storing page content.
// Input values are deliberately never included.
type liveBrowserInteraction struct {
	Agent       string     `json:"agent,omitempty"`
	Action      string     `json:"action"`
	Selector    string     `json:"selector,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	URL         string     `json:"url,omitempty"`
	State       string     `json:"state"`
	X           float64    `json:"x,omitempty"`
	Y           float64    `json:"y,omitempty"`
	Width       float64    `json:"width,omitempty"`
	Height      float64    `json:"height,omitempty"`
	HasBounds   bool       `json:"has_bounds,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type liveBrowserFrameManifest struct {
	Frames           []liveBrowserFrame `json:"frames"`
	CapturedAt       time.Time          `json:"captured_at"`
	Status           string             `json:"status"`
	SessionActive    bool               `json:"session_active"`
	BrowserConnected bool               `json:"browser_connected"`
	HasTabs          bool               `json:"has_tabs"`
	HasImages        bool               `json:"has_images"`
}

type capturedBrowserFrame struct {
	metadata     liveBrowserFrame
	image        []byte
	imageVersion string
}

type liveBrowserFrameObservation struct {
	allowImage bool
	capture    func(bool) *capturedBrowserFrame
	done       chan struct{}
}

// FrameCaptureSession owns one scan's manifest writer. Stop cancels and joins
// the writer, guaranteeing the terminal manifest is durable before the scan
// process can close Chromium or exit.
type FrameCaptureSession struct {
	controller *Controller
	cancel     context.CancelFunc
	done       chan struct{}
	stopOnce   sync.Once

	observationMu    sync.Mutex
	observationCond  *sync.Cond
	observations     []liveBrowserFrameObservation
	observationReady chan struct{}
	accepting        bool
}

// requestStop closes observation admission before cancelling the writer.
// Consequently, once captureCtx is done, the writer has a finite, immutable
// set of accepted observations to drain before it can close session.done.
func (s *FrameCaptureSession) requestStop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		s.observationMu.Lock()
		s.accepting = false
		if s.observationCond != nil {
			s.observationCond.Broadcast()
		}
		s.observationMu.Unlock()
		if s.cancel != nil {
			s.cancel()
		}
	})
}

// Stop finalizes replay metadata and waits for the writer goroutine. It is
// safe to call more than once and after the parent context has already ended.
func (s *FrameCaptureSession) Stop() {
	if s == nil {
		return
	}
	s.requestStop()
	if s.done != nil {
		<-s.done
	}
	if s.controller != nil {
		s.controller.frameCaptureMu.Lock()
		if s.controller.frameCapture == s {
			s.controller.frameCapture = nil
		}
		s.controller.frameCaptureMu.Unlock()
	}
}

func (s *FrameCaptureSession) observe(observation liveBrowserFrameObservation) {
	if s == nil || observation.capture == nil {
		return
	}
	if observation.done == nil {
		observation.done = make(chan struct{})
	}
	if !s.enqueueObservation(observation) {
		return
	}
	// Once enqueueObservation accepts an item, only its durability
	// acknowledgement may release this synchronous caller. session.done is not
	// an acknowledgement: shutdown closes it only after this queue is drained.
	<-observation.done
}

func (s *FrameCaptureSession) enqueueObservation(observation liveBrowserFrameObservation) bool {
	if s == nil || observation.capture == nil {
		return false
	}
	if observation.done == nil {
		observation.done = make(chan struct{})
	}
	s.observationMu.Lock()
	for s.accepting && len(s.observations) >= maxPendingLiveBrowserObservations {
		s.observationCond.Wait()
	}
	if !s.accepting {
		s.observationMu.Unlock()
		return false
	}
	s.observations = append(s.observations, observation)
	if s.observationCond != nil {
		s.observationCond.Broadcast()
	}
	s.observationMu.Unlock()
	select {
	case s.observationReady <- struct{}{}:
	default:
	}
	return true
}

func (s *FrameCaptureSession) dequeueObservation() (liveBrowserFrameObservation, bool) {
	if s == nil {
		return liveBrowserFrameObservation{}, false
	}
	s.observationMu.Lock()
	if len(s.observations) == 0 {
		s.observationMu.Unlock()
		return liveBrowserFrameObservation{}, false
	}
	observation := s.observations[0]
	s.observations[0] = liveBrowserFrameObservation{}
	s.observations = s.observations[1:]
	if s.observationCond != nil {
		s.observationCond.Signal()
	}
	s.observationMu.Unlock()
	// A proactive dequeue can run before the writer selects on the coalesced
	// wake token. Consume that stale token so it cannot trigger an immediate,
	// unnecessary periodic browser sample after the queue is already empty.
	select {
	case <-s.observationReady:
	default:
	}
	return observation, true
}

// StopFrameCapture finalizes the controller's active capture session, if any.
func (c *Controller) StopFrameCapture() {
	if c == nil {
		return
	}
	c.frameCaptureMu.RLock()
	session := c.frameCapture
	c.frameCaptureMu.RUnlock()
	if session != nil {
		session.Stop()
	}
}

func (c *Controller) currentFrameCapture() *FrameCaptureSession {
	if c == nil {
		return nil
	}
	c.frameCaptureMu.RLock()
	session := c.frameCapture
	c.frameCaptureMu.RUnlock()
	return session
}

// AnnounceLiveBrowserPage persists truthful tab metadata immediately after a
// target is created. It performs no screenshot and therefore does not delay
// navigation, but it prevents a short-lived tab from being invisible merely
// because it opened and closed between periodic samples.
func (c *Controller) AnnounceLiveBrowserPage(page *rod.Page, fallbackURL, action string) {
	session := c.currentFrameCapture()
	if session == nil || page == nil {
		return
	}
	metadata := c.liveBrowserPageMetadata(page, fallbackURL, action, false)
	if metadata == nil {
		return
	}
	session.observe(liveBrowserFrameObservation{
		capture: func(bool) *capturedBrowserFrame {
			copy := *metadata
			copy.UpdatedAt = time.Now().UTC()
			return &capturedBrowserFrame{metadata: copy}
		},
	})
}

// ObserveLiveBrowserPage captures one bounded, event-driven frame while the
// caller still owns a live page. The session rate-limits successful image
// captures, but always persists fresh URL/action metadata before returning.
func (c *Controller) ObserveLiveBrowserPage(page *rod.Page, fallbackURL, action string) {
	session := c.currentFrameCapture()
	if session == nil || page == nil {
		return
	}
	session.observe(liveBrowserFrameObservation{
		allowImage: true,
		capture: func(captureImage bool) *capturedBrowserFrame {
			return c.captureLiveBrowserPage(page, fallbackURL, action, captureImage)
		},
	})
}

// StartFrameCapture launches a background goroutine that periodically
// screenshots every active page (up to maxLiveBrowserFrames). A small JSON
// manifest lets the UI render the pages as a live browser fleet. The newest
// page is also written to the legacy scan-<scanID>.jpg path so older UIs keep
// working with newer scanners.
//
// Runs until ctx is cancelled. Errors are silently ignored (frame capture
// is best-effort; we never want it to crash a scan).
func (c *Controller) StartFrameCapture(ctx context.Context, scanID int64, outputDir string) *FrameCaptureSession {
	framesDir := filepath.Join(outputDir, "frames")
	if err := os.MkdirAll(framesDir, 0o755); err != nil {
		c.logger.Warn("frame capture: failed to create frames dir", "error", err)
		return nil
	}
	c.StopFrameCapture()
	if ctx == nil {
		ctx = context.Background()
	}
	// Parent cancellation is routed through requestStop rather than inherited
	// directly. That closes admission before captureCtx becomes done, removing
	// the enqueue-vs-exit race and giving the writer a stable queue to drain.
	captureCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	session := &FrameCaptureSession{
		controller: c, cancel: cancel, done: make(chan struct{}),
		observationReady: make(chan struct{}, 1), accepting: true,
	}
	session.observationCond = sync.NewCond(&session.observationMu)
	c.frameCaptureMu.Lock()
	c.frameCapture = session
	c.frameCaptureMu.Unlock()
	legacyPath := filepath.Join(framesDir, fmt.Sprintf("scan-%d.jpg", scanID))
	manifestPath := filepath.Join(framesDir, fmt.Sprintf("scan-%d.json", scanID))
	now := time.Now().UTC()
	// Publish the capture session before the goroutine gets scheduled. This is a
	// heartbeat, not a claim that a tab or bitmap already exists.
	_ = writeLiveBrowserManifest(manifestPath, liveBrowserFrameManifest{
		Frames: []liveBrowserFrame{}, CapturedAt: now, Status: "starting", SessionActive: true,
	})
	go func() {
		select {
		case <-ctx.Done():
			session.requestStop()
		case <-session.done:
		}
	}()

	go func() {
		defer close(session.done)
		// Short discovery crawls can open, inspect, and close a page in about a
		// second. Sampling every 1.5s routinely missed the entire browser phase,
		// leaving the Live view empty even though the scan was healthy.
		ticker := time.NewTicker(liveBrowserCapturePeriod)
		defer ticker.Stop()
		lastGood := make(map[string]capturedBrowserFrame)
		writtenVersions := make(map[string]string)
		legacyVersion := ""
		lastManifest := liveBrowserFrameManifest{
			Frames: []liveBrowserFrame{}, CapturedAt: now, Status: "starting", SessionActive: true,
		}

		c.logger.Info("frame capture started", "output", framesDir, "max_frames", maxLiveBrowserFrames)

		var pendingObservation *liveBrowserFrameObservation
		stopping := false
		lastSynchronousImage := time.Time{}
		synchronousImageCaptured := false
		for {
			// requestStop closes admission before cancellation, so an empty queue
			// here is a stable terminal condition. Every accepted observation is
			// processed and acknowledged before session.done can close.
			if stopping && pendingObservation == nil {
				if observation, ok := session.dequeueObservation(); ok {
					pendingObservation = &observation
				} else {
					lastManifest = stoppedLiveBrowserManifest(lastManifest, time.Now().UTC())
					_ = writeLiveBrowserManifest(manifestPath, lastManifest)
					c.logger.Info("frame capture stopped")
					return
				}
			}
			// Refresh the session heartbeat before attempting screenshots. A slow
			// or temporarily unpaintable tab must not make the capture session look
			// as though it never started.
			heartbeat := lastManifest
			heartbeat.CapturedAt = time.Now().UTC()
			heartbeat.Status = "capturing"
			heartbeat.SessionActive = true
			_ = writeLiveBrowserManifest(manifestPath, heartbeat)

			var active []capturedBrowserFrame
			var browserConnected bool
			var tabCount int
			if pendingObservation != nil {
				captureImage := pendingObservation.allowImage &&
					(!synchronousImageCaptured || time.Since(lastSynchronousImage) >= liveBrowserCapturePeriod)
				if frame := pendingObservation.capture(captureImage); frame != nil {
					active = append(active, *frame)
					browserConnected = true
					tabCount = 1
					if captureImage && len(frame.image) > 0 {
						synchronousImageCaptured = true
						lastSynchronousImage = time.Now()
					}
				}
			} else {
				active, browserConnected, tabCount = c.captureActivePages(captureCtx)
			}
			captured := make([]capturedBrowserFrame, 0, len(active))
			activeIDs := make(map[string]bool, len(active))
			for _, frame := range active {
				frameID := frame.metadata.ID
				activeIDs[frameID] = true
				frame.metadata.Active = true
				if previous, ok := lastGood[frameID]; ok && previous.metadata.URL == frame.metadata.URL {
					if frame.metadata.LastAction == "" {
						frame.metadata.LastAction = previous.metadata.LastAction
					}
				}
				if len(frame.image) > 0 {
					frame.imageVersion = liveBrowserImageVersion(frame.image)
					frame.metadata.HasImage = true
					frame.metadata.ImageVersion = frame.imageVersion
					imageUpdatedAt := frame.metadata.UpdatedAt
					frame.metadata.ImageUpdatedAt = &imageUpdatedAt
					frame.metadata.Status = "image_updated"
					if previous, ok := lastGood[frameID]; ok &&
						previous.metadata.URL == frame.metadata.URL &&
						previous.imageVersion == frame.imageVersion {
						frame.metadata.Status = "image_unchanged"
						frame.metadata.ImageUpdatedAt = previous.metadata.ImageUpdatedAt
					}
					lastGood[frameID] = frame
					captured = append(captured, frame)
					continue
				}
				// A page can briefly stop painting while Chromium swaps its
				// renderer. Keep its last real image only while the URL still
				// matches; never label an old page as a new navigation. Retain
				// the current metadata so an in-flight click/fill marker is not
				// lost merely because that exact screenshot tick missed a paint.
				if previous, ok := lastGood[frameID]; ok && previous.metadata.URL == frame.metadata.URL &&
					previous.metadata.HasImage && len(previous.image) > 0 {
					frame.image = previous.image
					frame.imageVersion = previous.imageVersion
					frame.metadata.HasImage = true
					frame.metadata.ImageVersion = previous.metadata.ImageVersion
					frame.metadata.ImageUpdatedAt = previous.metadata.ImageUpdatedAt
					frame.metadata.Status = "last_image"
					lastGood[frameID] = frame
					captured = append(captured, frame)
					continue
				}
				frame.metadata.Status = "waiting_for_image"
				lastGood[frameID] = frame
				captured = append(captured, frame)
			}
			captured = appendRetainedClosedBrowserFrames(captured, activeIDs, lastGood, maxLiveBrowserFrames)
			frames := make([]liveBrowserFrame, 0, len(captured))
			currentFiles := make(map[string]bool, len(captured))
			hasImages := false
			hasActiveImages := false
			for _, frame := range captured {
				framePath := liveBrowserVersionedFramePath(framesDir, scanID, frame.metadata.ID, frame.imageVersion)
				if frame.metadata.HasImage {
					if err := writeLiveBrowserImageIfChanged(framePath, frame.image, frame.imageVersion, writtenVersions); err != nil {
						frame.metadata.HasImage = false
						frame.metadata.Status = "image_write_failed"
						frame.metadata.ImageVersion = ""
						frame.metadata.ImageUpdatedAt = nil
					} else {
						hasImages = true
						hasActiveImages = hasActiveImages || frame.metadata.Active
						currentFiles[framePath] = true
					}
				}
				frames = append(frames, frame.metadata)
			}

			status := "ready"
			if !browserConnected {
				status = "browser_unavailable"
			} else if len(active) == 0 && len(frames) > 0 {
				status = "saved_frames"
			} else if tabCount == 0 {
				status = "no_tabs"
			} else if len(frames) == 0 {
				status = "no_web_tabs"
			} else if !hasActiveImages {
				status = "tabs_waiting_for_image"
			}
			lastManifest = liveBrowserFrameManifest{
				Frames: frames, CapturedAt: time.Now().UTC(), Status: status,
				SessionActive: true, BrowserConnected: browserConnected,
				HasTabs: len(active) > 0, HasImages: hasImages,
			}
			_ = writeLiveBrowserManifest(manifestPath, lastManifest)
			if pendingObservation != nil {
				close(pendingObservation.done)
				pendingObservation = nil
			}

			// Preserve the original single-frame contract. Prefer an active frame;
			// only fall back to replay evidence when no live tab has a usable image.
			// Otherwise an active+saved fleet could make the legacy endpoint look as
			// though the closed tab were the browser's current page.
			legacyWritten := false
			for _, activeOnly := range []bool{true, false} {
				for i := len(captured) - 1; i >= 0; i-- {
					if !captured[i].metadata.HasImage || captured[i].metadata.Active != activeOnly {
						continue
					}
					if legacyVersion != captured[i].imageVersion {
						if writeFileAtomically(legacyPath, captured[i].image, 0o644) == nil {
							legacyVersion = captured[i].imageVersion
						}
					}
					legacyWritten = true
					break
				}
				if legacyWritten {
					break
				}
			}
			if !legacyWritten {
				_ = os.Remove(legacyPath)
				legacyVersion = ""
			}
			removeStaleLiveBrowserFrames(framesDir, scanID, currentFiles)

			if stopping {
				continue
			}
			if observation, ok := session.dequeueObservation(); ok {
				pendingObservation = &observation
				continue
			}
			select {
			case <-captureCtx.Done():
				stopping = true
			case <-session.observationReady:
				if observation, ok := session.dequeueObservation(); ok {
					pendingObservation = &observation
				}
			case <-ticker.C:
			}
		}
	}()
	return session
}

// appendRetainedClosedBrowserFrames keeps a bounded replay of recently seen
// targets after their tabs close. Active frames always win the budget; the
// remaining slots hold the newest distinct target IDs. Closed frames retain
// their last metadata and, when available, real pixels; they never retain a
// live interaction marker.
func appendRetainedClosedBrowserFrames(captured []capturedBrowserFrame, activeIDs map[string]bool, lastGood map[string]capturedBrowserFrame, limit int) []capturedBrowserFrame {
	if limit <= 0 {
		clear(lastGood)
		return nil
	}
	closed := make([]capturedBrowserFrame, 0, len(lastGood))
	for frameID, previous := range lastGood {
		if activeIDs[frameID] {
			continue
		}
		previous.metadata.Active = false
		previous.metadata.Status = "tab_closed"
		if !previous.metadata.HasImage {
			previous.metadata.Status = "closed_without_image"
		}
		previous.metadata.Interaction = nil
		closed = append(closed, previous)
	}
	sort.Slice(closed, func(i, j int) bool {
		if closed[i].metadata.UpdatedAt.Equal(closed[j].metadata.UpdatedAt) {
			return closed[i].metadata.ID < closed[j].metadata.ID
		}
		return closed[i].metadata.UpdatedAt.After(closed[j].metadata.UpdatedAt)
	})
	for _, frame := range closed {
		if len(captured) >= limit {
			break
		}
		captured = append(captured, frame)
	}

	retained := make(map[string]bool, len(captured))
	for _, frame := range captured {
		retained[frame.metadata.ID] = true
	}
	for frameID := range lastGood {
		if !retained[frameID] {
			delete(lastGood, frameID)
		}
	}
	return captured
}

func stoppedLiveBrowserManifest(manifest liveBrowserFrameManifest, stoppedAt time.Time) liveBrowserFrameManifest {
	manifest.CapturedAt = stoppedAt
	manifest.Status = "stopped"
	manifest.SessionActive = false
	manifest.HasTabs = false
	for i := range manifest.Frames {
		manifest.Frames[i].Active = false
		manifest.Frames[i].Interaction = nil
		if manifest.Frames[i].HasImage {
			manifest.Frames[i].Status = "tab_closed"
		} else {
			manifest.Frames[i].Status = "closed_without_image"
		}
	}
	return manifest
}

func (c *Controller) captureActivePages(ctx context.Context) ([]capturedBrowserFrame, bool, int) {
	if c == nil {
		return nil, false, 0
	}
	browser := c.browserSnapshot()
	if browser == nil {
		return nil, false, 0
	}
	if ctx == nil {
		ctx = context.Background()
	}
	enumerationCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	pages, err := browser.Context(enumerationCtx).Pages()
	if err != nil {
		return nil, false, 0
	}
	tabCount := len(pages)
	if tabCount == 0 {
		return nil, true, 0
	}
	if len(pages) > maxLiveBrowserFrames {
		pages = pages[len(pages)-maxLiveBrowserFrames:]
	}
	c.pruneLiveBrowserInteractions(time.Now().UTC())

	results := make([]*capturedBrowserFrame, len(pages))
	var wg sync.WaitGroup
	for i, page := range pages {
		wg.Add(1)
		go func(index int, page *rod.Page) {
			defer wg.Done()
			results[index] = c.captureLiveBrowserPage(page, "", "", true)
		}(i, page)
	}
	wg.Wait()

	captured := make([]capturedBrowserFrame, 0, len(results))
	for _, result := range results {
		if result != nil {
			captured = append(captured, *result)
		}
	}
	return captured, true, tabCount
}

func (c *Controller) liveBrowserPageMetadata(page *rod.Page, fallbackURL, action string, inspectPageURL bool) *liveBrowserFrame {
	if page == nil {
		return nil
	}
	now := time.Now().UTC()
	targetID := string(page.TargetID)
	pageURL := strings.TrimSpace(fallbackURL)
	if inspectPageURL {
		if info, err := page.Timeout(250 * time.Millisecond).Info(); err == nil && info != nil && isLiveBrowserURL(info.URL) {
			pageURL = info.URL
		}
	}
	if !isLiveBrowserURL(pageURL) {
		return nil
	}
	if targetID == "" {
		targetID = "url:" + pageURL
	}
	return &liveBrowserFrame{
		ID:          liveBrowserFrameID(targetID),
		URL:         pageURL,
		LastAction:  strings.TrimSpace(action),
		UpdatedAt:   now,
		Active:      true,
		Interaction: c.liveBrowserInteractionForTarget(string(page.TargetID), now),
	}
}

func (c *Controller) captureLiveBrowserPage(page *rod.Page, fallbackURL, action string, captureImage bool) *capturedBrowserFrame {
	metadata := c.liveBrowserPageMetadata(page, fallbackURL, action, true)
	if metadata == nil {
		return nil
	}
	frame := &capturedBrowserFrame{metadata: *metadata}
	if !captureImage {
		return frame
	}
	quality := 60
	format := proto.PageCaptureScreenshotFormatJpeg
	shot, err := page.Timeout(750*time.Millisecond).Screenshot(false, &proto.PageCaptureScreenshot{
		Format:  format,
		Quality: &quality,
	})
	if err == nil && len(shot) > 0 && !liveBrowserFrameLooksBlank(shot) {
		frame.image = shot
	}
	return frame
}

// liveBrowserFrameLooksBlank prevents a renderer's white/gray/solid interim
// paint from being advertised as successful target pixels. It intentionally
// does not attempt to judge page usefulness: any modest amount of visible
// contrast is enough to keep a light, sparse, or minimalist page.
//
// Decode failures are unusable captures and therefore follow the same path as
// a blank frame. StartFrameCapture will retain a same-URL last-good image when
// one exists, but it will never carry those pixels across a navigation.
func liveBrowserFrameLooksBlank(data []byte) bool {
	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		return true
	}
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width <= 0 || height <= 0 {
		return true
	}

	step := 1
	for sampledWidth := (width + step - 1) / step; sampledWidth*((height+step-1)/step) > maxLiveBrowserBlanknessSamples; {
		step++
		sampledWidth = (width + step - 1) / step
	}
	offset := step / 2

	var sumR, sumG, sumB uint64
	count := 0
	for y := bounds.Min.Y + offset; y < bounds.Max.Y; y += step {
		for x := bounds.Min.X + offset; x < bounds.Max.X; x += step {
			r, g, b, _ := img.At(x, y).RGBA()
			sumR += uint64(r >> 8)
			sumG += uint64(g >> 8)
			sumB += uint64(b >> 8)
			count++
		}
	}
	if count == 0 {
		return true
	}
	meanR := int(sumR / uint64(count))
	meanG := int(sumG / uint64(count))
	meanB := int(sumB / uint64(count))

	// Requiring only 0.1% of sampled pixels (with a tiny absolute floor) to
	// differ from the dominant field preserves sparse text and controls while
	// filtering isolated JPEG ringing or a one-pixel renderer artifact.
	minimumDistinct := count / 1000
	if minimumDistinct < 12 {
		minimumDistinct = 12
	}
	distinct := 0
	for y := bounds.Min.Y + offset; y < bounds.Max.Y; y += step {
		for x := bounds.Min.X + offset; x < bounds.Max.X; x += step {
			r, g, b, _ := img.At(x, y).RGBA()
			if absInt(int(r>>8)-meanR) > liveBrowserNearSolidDelta ||
				absInt(int(g>>8)-meanG) > liveBrowserNearSolidDelta ||
				absInt(int(b>>8)-meanB) > liveBrowserNearSolidDelta {
				distinct++
				if distinct >= minimumDistinct {
					return false
				}
			}
		}
	}
	return true
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

type liveInteractionBounds struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

func (c *Controller) beginLiveBrowserInteraction(page *rod.Page, action *NavigatorAction) func(error) {
	if c == nil || page == nil || action == nil {
		return func(error) {}
	}
	targetID := string(page.TargetID)
	if targetID == "" {
		return func(error) {}
	}

	now := time.Now().UTC()
	interaction := liveBrowserInteraction{
		Agent:     strings.TrimSpace(c.TrafficProvenance().SourceAgent),
		Action:    strings.ToLower(strings.TrimSpace(action.Action)),
		Selector:  strings.TrimSpace(action.Selector),
		Reason:    truncateLiveInteractionText(action.Reason, 280),
		URL:       strings.TrimSpace(action.URL),
		State:     "running",
		StartedAt: now,
	}
	if interaction.URL == "" {
		if info, err := page.Info(); err == nil && info != nil {
			interaction.URL = info.URL
		}
	}
	if interaction.Selector != "" &&
		(interaction.Action == "click" || interaction.Action == "fill" || interaction.Action == "submit") {
		if bounds, ok := captureLiveInteractionBounds(page, interaction.Selector); ok {
			interaction.X = bounds.X
			interaction.Y = bounds.Y
			interaction.Width = bounds.Width
			interaction.Height = bounds.Height
			interaction.HasBounds = true
		}
	}

	c.liveInteractionMu.Lock()
	if c.liveInteractions == nil {
		c.liveInteractions = make(map[string]liveBrowserInteraction)
	}
	c.liveInteractions[targetID] = interaction
	c.liveInteractionMu.Unlock()

	var once sync.Once
	return func(actionErr error) {
		once.Do(func() {
			completed := time.Now().UTC()
			c.liveInteractionMu.Lock()
			current, ok := c.liveInteractions[targetID]
			if ok && current.StartedAt.Equal(interaction.StartedAt) {
				current.State = "succeeded"
				if actionErr != nil {
					current.State = "failed"
				}
				current.CompletedAt = &completed
				c.liveInteractions[targetID] = current
			}
			c.liveInteractionMu.Unlock()
		})
	}
}

func captureLiveInteractionBounds(page *rod.Page, selector string) (liveInteractionBounds, bool) {
	encoded, err := json.Marshal(selector)
	if err != nil {
		return liveInteractionBounds{}, false
	}
	script := fmt.Sprintf(`() => {
		let el;
		try { el = document.querySelector(%s); } catch (_) { return null; }
		if (!el) return null;
		const r = el.getBoundingClientRect();
		const vw = Math.max(window.innerWidth || 0, 1);
		const vh = Math.max(window.innerHeight || 0, 1);
		if (r.width <= 0 || r.height <= 0) return null;
		return {
			x: Math.max(0, Math.min(100, ((r.left + r.width / 2) / vw) * 100)),
			y: Math.max(0, Math.min(100, ((r.top + r.height / 2) / vh) * 100)),
			width: Math.max(1, Math.min(100, (r.width / vw) * 100)),
			height: Math.max(1, Math.min(100, (r.height / vh) * 100))
		};
	}`, string(encoded))
	result, err := page.Timeout(750 * time.Millisecond).Eval(script)
	if err != nil || result == nil {
		return liveInteractionBounds{}, false
	}
	var bounds *liveInteractionBounds
	if err := json.Unmarshal([]byte(result.Value.JSON("", "")), &bounds); err != nil || bounds == nil {
		return liveInteractionBounds{}, false
	}
	return *bounds, true
}

func (c *Controller) liveBrowserInteractionForTarget(targetID string, now time.Time) *liveBrowserInteraction {
	if c == nil || targetID == "" {
		return nil
	}
	c.liveInteractionMu.RLock()
	interaction, ok := c.liveInteractions[targetID]
	c.liveInteractionMu.RUnlock()
	if !ok || !liveBrowserInteractionFresh(interaction, now) {
		return nil
	}
	copy := interaction
	return &copy
}

func (c *Controller) pruneLiveBrowserInteractions(now time.Time) {
	if c == nil {
		return
	}
	c.liveInteractionMu.Lock()
	for targetID, interaction := range c.liveInteractions {
		if !liveBrowserInteractionFresh(interaction, now) {
			delete(c.liveInteractions, targetID)
		}
	}
	c.liveInteractionMu.Unlock()
}

func liveBrowserInteractionFresh(interaction liveBrowserInteraction, now time.Time) bool {
	if interaction.StartedAt.IsZero() {
		return false
	}
	if interaction.CompletedAt != nil {
		return now.Sub(*interaction.CompletedAt) <= liveInteractionHold
	}
	return now.Sub(interaction.StartedAt) <= liveInteractionMaxAge
}

func truncateLiveInteractionText(value string, limit int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if limit <= 0 || len(runes) <= limit {
		return value
	}
	return strings.TrimSpace(string(runes[:limit-1])) + "…"
}

func liveBrowserFrameID(targetID string) string {
	sum := sha256.Sum256([]byte(targetID))
	return fmt.Sprintf("%x", sum[:6])
}

func liveBrowserImageVersion(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:8])
}

func writeLiveBrowserImageIfChanged(path string, data []byte, version string, written map[string]string) error {
	if written[path] == version {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
	}
	if err := writeFileAtomically(path, data, 0o644); err != nil {
		return err
	}
	written[path] = version
	return nil
}

func writeLiveBrowserManifest(path string, manifest liveBrowserFrameManifest) error {
	if manifest.Frames == nil {
		manifest.Frames = []liveBrowserFrame{}
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return writeFileAtomically(path, data, 0o644)
}

func liveBrowserFramePath(framesDir string, scanID int64, frameID string) string {
	return filepath.Join(framesDir, fmt.Sprintf("scan-%d-frame-%s.jpg", scanID, frameID))
}

func liveBrowserVersionedFramePath(framesDir string, scanID int64, frameID, version string) string {
	if strings.TrimSpace(version) == "" {
		return liveBrowserFramePath(framesDir, scanID, frameID)
	}
	return filepath.Join(framesDir, fmt.Sprintf("scan-%d-frame-%s-%s.jpg", scanID, frameID, version))
}

func isLiveBrowserURL(rawURL string) bool {
	return strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://")
}

func writeFileAtomically(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err == nil {
		return nil
	}
	// On Windows, Rename won't overwrite an existing file. Fall back to a
	// remove + rename there; Unix already returned through the atomic path.
	_ = os.Remove(path)
	return os.Rename(tmpPath, path)
}

func removeStaleLiveBrowserFrames(framesDir string, scanID int64, current map[string]bool) {
	pattern := filepath.Join(framesDir, fmt.Sprintf("scan-%d-frame-*.jpg", scanID))
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	for _, path := range paths {
		if !current[path] {
			_ = os.Remove(path)
		}
	}
}

// activePage returns the most recently created page, which in practice is
// the one the crawler/navigator is working on. Returns nil if no pages.
func (c *Controller) activePage() *rod.Page {
	browser := c.browserSnapshot()
	if browser == nil {
		return nil
	}
	pages, err := browser.Pages()
	if err != nil || len(pages) == 0 {
		return nil
	}
	// Pages() returns in creation order; the last one is usually the most recent.
	return pages[len(pages)-1]
}
