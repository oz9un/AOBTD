package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/go-rod/rod/lib/proto"
)

type fixedErrorCDPClient struct {
	events chan *cdp.Event
	err    error
}

func (c *fixedErrorCDPClient) Event() <-chan *cdp.Event { return c.events }

func (c *fixedErrorCDPClient) Call(context.Context, string, string, interface{}) ([]byte, error) {
	return nil, c.err
}

func encodeLiveBrowserTestJPEG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, img, &jpeg.Options{Quality: 60}); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func TestLiveBrowserFrameLooksBlankRejectsSolidAndNearBlankJPEGs(t *testing.T) {
	tests := []struct {
		name  string
		color color.RGBA
	}{
		{name: "white", color: color.RGBA{R: 255, G: 255, B: 255, A: 255}},
		{name: "gray", color: color.RGBA{R: 132, G: 132, B: 132, A: 255}},
		{name: "brand-color", color: color.RGBA{R: 24, G: 87, B: 149, A: 255}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			img := image.NewRGBA(image.Rect(0, 0, 640, 360))
			for y := 0; y < 360; y++ {
				for x := 0; x < 640; x++ {
					img.SetRGBA(x, y, test.color)
				}
			}
			if !liveBrowserFrameLooksBlank(encodeLiveBrowserTestJPEG(t, img)) {
				t.Fatal("solid renderer paint was accepted as target content")
			}
		})
	}

	nearBlank := image.NewRGBA(image.Rect(0, 0, 640, 360))
	for y := 0; y < 360; y++ {
		for x := 0; x < 640; x++ {
			nearBlank.SetRGBA(x, y, color.RGBA{R: 250, G: 250, B: 250, A: 255})
		}
	}
	// A tiny transient renderer artifact must not turn the frame into a
	// successful-looking browser capture.
	nearBlank.SetRGBA(320, 180, color.RGBA{R: 110, G: 110, B: 110, A: 255})
	if !liveBrowserFrameLooksBlank(encodeLiveBrowserTestJPEG(t, nearBlank)) {
		t.Fatal("near-blank renderer paint was accepted as target content")
	}
	if !liveBrowserFrameLooksBlank([]byte("not a jpeg")) {
		t.Fatal("an undecodable capture was accepted as target content")
	}
}

func TestLiveBrowserFrameLooksBlankKeepsSparseVisiblePage(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 640, 360))
	for y := 0; y < 360; y++ {
		for x := 0; x < 640; x++ {
			img.SetRGBA(x, y, color.RGBA{R: 253, G: 253, B: 253, A: 255})
		}
	}
	// A deliberately sparse login-card outline and two controls occupy only a
	// small fraction of this mostly-white page, but are plainly visible.
	ink := color.RGBA{R: 68, G: 76, B: 89, A: 255}
	for x := 245; x < 395; x++ {
		for _, y := range []int{125, 126, 234, 235, 160, 161, 198, 199} {
			img.SetRGBA(x, y, ink)
		}
	}
	for y := 125; y < 236; y++ {
		for _, x := range []int{245, 246, 393, 394} {
			img.SetRGBA(x, y, ink)
		}
	}

	if liveBrowserFrameLooksBlank(encodeLiveBrowserTestJPEG(t, img)) {
		t.Fatal("a mostly-white page with sparse visible controls was rejected")
	}
}

func TestStartFrameCaptureWritesImmediateHeartbeatAndStoppedState(t *testing.T) {
	outputDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	controller := NewController("127.0.0.1:0", true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	session := controller.StartFrameCapture(ctx, 71, outputDir)
	if session == nil {
		t.Fatal("frame capture session was not created")
	}

	manifestPath := filepath.Join(outputDir, "frames", "scan-71.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("heartbeat was not written synchronously: %v", err)
	}
	var heartbeat liveBrowserFrameManifest
	if err := json.Unmarshal(data, &heartbeat); err != nil {
		t.Fatal(err)
	}
	if !heartbeat.SessionActive || heartbeat.CapturedAt.IsZero() {
		t.Fatalf("initial heartbeat did not describe an active session: %#v", heartbeat)
	}

	cancel()
	session.Stop()
	data, err = os.ReadFile(manifestPath)
	if err != nil || json.Unmarshal(data, &heartbeat) != nil {
		t.Fatalf("read stopped manifest: %v", err)
	}
	if heartbeat.Status != "stopped" || heartbeat.SessionActive {
		t.Fatalf("stopped manifest retained active session: %#v", heartbeat)
	}
}

func TestSynchronousObservationPersistsPixelsBeforeAcknowledgingAndRetainsReplay(t *testing.T) {
	outputDir := t.TempDir()
	controller := NewController("127.0.0.1:0", true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	session := controller.StartFrameCapture(context.Background(), 72, outputDir)
	if session == nil {
		t.Fatal("frame capture session was not created")
	}

	img := image.NewRGBA(image.Rect(0, 0, 640, 360))
	for y := 0; y < 360; y++ {
		for x := 0; x < 640; x++ {
			img.SetRGBA(x, y, color.RGBA{R: 250, G: 250, B: 250, A: 255})
		}
	}
	for y := 90; y < 270; y++ {
		for x := 120; x < 520; x++ {
			if x%17 == 0 || y%23 == 0 {
				img.SetRGBA(x, y, color.RGBA{R: 31, G: 91, B: 140, A: 255})
			}
		}
	}
	pixels := encodeLiveBrowserTestJPEG(t, img)
	imageRequested := false
	now := time.Now().UTC()
	session.observe(liveBrowserFrameObservation{
		allowImage: true,
		capture: func(captureImage bool) *capturedBrowserFrame {
			imageRequested = captureImage
			frame := &capturedBrowserFrame{metadata: liveBrowserFrame{
				ID: "short-page", URL: "https://example.test/checkout", LastAction: "crawl_complete",
				UpdatedAt: now, Active: true,
			}}
			if captureImage {
				frame.image = pixels
			}
			return frame
		},
	})
	if !imageRequested {
		t.Fatal("the first synchronous page observation did not request pixels")
	}

	framePath := liveBrowserVersionedFramePath(
		filepath.Join(outputDir, "frames"), 72, "short-page", liveBrowserImageVersion(pixels),
	)
	gotPixels, err := os.ReadFile(framePath)
	if err != nil {
		t.Fatalf("frame was not durable when observation returned: %v", err)
	}
	if !bytes.Equal(gotPixels, pixels) {
		t.Fatal("durable frame bytes differ from the synchronous capture")
	}

	session.Stop()
	manifestPath := filepath.Join(outputDir, "frames", "scan-72.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest liveBrowserFrameManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SessionActive || manifest.Status != "stopped" || len(manifest.Frames) != 1 {
		t.Fatalf("terminal replay manifest = %#v", manifest)
	}
	frame := manifest.Frames[0]
	if frame.Active || !frame.HasImage || frame.URL != "https://example.test/checkout" ||
		frame.LastAction != "crawl_complete" || frame.Status != "tab_closed" {
		t.Fatalf("synchronous frame was not retained as truthful replay: %#v", frame)
	}
	assertNoLiveBrowserTempArtifacts(t, filepath.Join(outputDir, "frames"))
}

func TestFrameCaptureCancellationDrainsAcceptedObservationBeforeAcknowledging(t *testing.T) {
	outputDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	controller := NewController("127.0.0.1:0", true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	session := controller.StartFrameCapture(ctx, 77, outputDir)
	if session == nil {
		t.Fatal("frame capture session was not created")
	}

	firstCaptureStarted := make(chan struct{})
	releaseFirstCapture := make(chan struct{})
	firstReturned := make(chan struct{})
	go func() {
		session.observe(liveBrowserFrameObservation{capture: func(bool) *capturedBrowserFrame {
			close(firstCaptureStarted)
			<-releaseFirstCapture
			return &capturedBrowserFrame{metadata: liveBrowserFrame{
				ID: "first", URL: "https://example.test/first",
				LastAction: "first", UpdatedAt: time.Now().UTC(), Active: true,
			}}
		}})
		close(firstReturned)
	}()
	select {
	case <-firstCaptureStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not begin the first controlled observation")
	}

	secondReturned := make(chan struct{})
	go func() {
		session.observe(liveBrowserFrameObservation{capture: func(bool) *capturedBrowserFrame {
			return &capturedBrowserFrame{metadata: liveBrowserFrame{
				ID: "accepted-during-stop", URL: "https://example.test/accepted-during-stop",
				LastAction: "cancel_race", UpdatedAt: time.Now().UTC(), Active: true,
			}}
		}})
		close(secondReturned)
	}()

	// The first callback keeps the writer occupied, so observing a queued item
	// here proves that the second synchronous call crossed the admission point
	// before cancellation. The condition removes scheduler sleeps from the race
	// regression.
	session.observationMu.Lock()
	for len(session.observations) == 0 {
		session.observationCond.Wait()
	}
	session.observationMu.Unlock()

	cancel()
	// Parent cancellation must first close admission, making the accepted queue
	// immutable, before the writer is allowed to take its terminal path.
	session.observationMu.Lock()
	for session.accepting {
		session.observationCond.Wait()
	}
	session.observationMu.Unlock()

	select {
	case <-secondReturned:
		t.Fatal("accepted observation was acknowledged while its predecessor was still blocked")
	default:
	}
	close(releaseFirstCapture)

	for name, returned := range map[string]<-chan struct{}{
		"first observation":    firstReturned,
		"accepted observation": secondReturned,
	} {
		select {
		case <-returned:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s was not durably drained during bounded shutdown", name)
		}
	}

	// The synchronous acknowledgement must describe actual durability, not the
	// unrelated session.done signal. Read immediately after observe returned.
	data, err := os.ReadFile(filepath.Join(outputDir, "frames", "scan-77.json"))
	if err != nil {
		t.Fatal(err)
	}
	var acknowledged liveBrowserFrameManifest
	if err := json.Unmarshal(data, &acknowledged); err != nil {
		t.Fatal(err)
	}
	foundAccepted := false
	for _, frame := range acknowledged.Frames {
		if frame.URL == "https://example.test/accepted-during-stop" && frame.LastAction == "cancel_race" {
			foundAccepted = true
		}
	}
	if !foundAccepted {
		t.Fatalf("accepted observation was acknowledged before persistence: %#v", acknowledged)
	}

	session.Stop()
	data, err = os.ReadFile(filepath.Join(outputDir, "frames", "scan-77.json"))
	if err != nil || json.Unmarshal(data, &acknowledged) != nil {
		t.Fatalf("read terminal manifest: %v", err)
	}
	if acknowledged.Status != "stopped" || acknowledged.SessionActive || !foundLiveBrowserFrameURL(acknowledged.Frames, "https://example.test/accepted-during-stop") {
		t.Fatalf("terminal manifest lost the accepted observation: %#v", acknowledged)
	}
}

func foundLiveBrowserFrameURL(frames []liveBrowserFrame, targetURL string) bool {
	for _, frame := range frames {
		if frame.URL == targetURL {
			return true
		}
	}
	return false
}

func TestMetadataOnlyObservationSurvivesShortTabAndCleanShutdown(t *testing.T) {
	outputDir := t.TempDir()
	controller := NewController("127.0.0.1:0", true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	session := controller.StartFrameCapture(context.Background(), 73, outputDir)
	if session == nil {
		t.Fatal("frame capture session was not created")
	}
	now := time.Now().UTC()
	session.observe(liveBrowserFrameObservation{
		capture: func(captureImage bool) *capturedBrowserFrame {
			if captureImage {
				t.Fatal("metadata announcement unexpectedly requested pixels")
			}
			return &capturedBrowserFrame{metadata: liveBrowserFrame{
				ID: "blink", URL: "https://example.test/fast", LastAction: "crawl_navigate",
				UpdatedAt: now, Active: true,
			}}
		},
	})
	session.Stop()

	data, err := os.ReadFile(filepath.Join(outputDir, "frames", "scan-73.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest liveBrowserFrameManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SessionActive || manifest.HasTabs || manifest.Status != "stopped" || len(manifest.Frames) != 1 {
		t.Fatalf("terminal metadata replay = %#v", manifest)
	}
	frame := manifest.Frames[0]
	if frame.URL != "https://example.test/fast" || frame.LastAction != "crawl_navigate" ||
		frame.HasImage || frame.Active || frame.Status != "closed_without_image" {
		t.Fatalf("short-lived metadata frame was lost or overstated: %#v", frame)
	}
	assertNoLiveBrowserTempArtifacts(t, filepath.Join(outputDir, "frames"))
}

func TestControllerCloseJoinsActiveFrameCapture(t *testing.T) {
	outputDir := t.TempDir()
	controller := NewController("127.0.0.1:0", true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if session := controller.StartFrameCapture(context.Background(), 74, outputDir); session == nil {
		t.Fatal("frame capture session was not created")
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(outputDir, "frames", "scan-74.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest liveBrowserFrameManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "stopped" || manifest.SessionActive {
		t.Fatalf("controller returned before capture session finalized: %#v", manifest)
	}
	assertNoLiveBrowserTempArtifacts(t, filepath.Join(outputDir, "frames"))
}

func TestNewPageReconnectPreservesCaptureSessionAndReplay(t *testing.T) {
	outputDir := t.TempDir()
	controller := NewController("127.0.0.1:0", true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	session := controller.StartFrameCapture(context.Background(), 75, outputDir)
	if session == nil {
		t.Fatal("frame capture session was not created")
	}

	// Establish replay evidence from the first Chrome runtime.
	session.observe(liveBrowserFrameObservation{capture: func(bool) *capturedBrowserFrame {
		return &capturedBrowserFrame{metadata: liveBrowserFrame{
			ID: "before-reconnect", URL: "https://example.test/before",
			LastAction: "crawl_last_seen", UpdatedAt: time.Now().UTC(), Active: true,
		}}
	}})

	oldBrowser := rod.New()
	newBrowser := rod.New()
	controller.publishBrowserRuntime(browserRuntime{browser: oldBrowser})
	openAttempts := 0
	page, err := controller.newPageWithReconnect(
		context.Background(),
		"https://example.test/after",
		func(_ context.Context, browser *rod.Browser, _ string) (*rod.Page, error) {
			openAttempts++
			switch browser {
			case oldBrowser:
				return nil, errors.New("websocket: close 1006 unexpected EOF")
			case newBrowser:
				return &rod.Page{TargetID: proto.TargetTargetID("after-reconnect")}, nil
			default:
				t.Fatalf("page opener received unknown browser runtime %p", browser)
				return nil, nil
			}
		},
		func(_ context.Context, failed *rod.Browser) error {
			if failed != oldBrowser {
				t.Fatalf("reconnect received browser %p, want stale runtime %p", failed, oldBrowser)
			}
			if controller.currentFrameCapture() != session {
				t.Fatal("capture session was detached before browser runtime replacement")
			}
			select {
			case <-session.done:
				t.Fatal("capture writer stopped during browser runtime replacement")
			default:
			}
			detached, ok := controller.detachBrowserRuntime(oldBrowser)
			if !ok || detached.browser != oldBrowser {
				t.Fatalf("stale runtime was not detached: %#v, %v", detached, ok)
			}
			controller.publishBrowserRuntime(browserRuntime{browser: newBrowser})
			if controller.currentFrameCapture() != session {
				t.Fatal("capture session did not remain bound to the controller")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("NewPage reconnect: %v", err)
	}
	if page == nil || page.TargetID != proto.TargetTargetID("after-reconnect") || openAttempts != 2 {
		t.Fatalf("retry result page=%#v attempts=%d", page, openAttempts)
	}

	// Keep the test's inert Rod pointer away from the periodic sampler, then
	// join normally. NewPage's successful retry announced the replacement tab
	// synchronously, so both sides of the reconnect must survive as replay.
	if _, ok := controller.detachBrowserRuntime(newBrowser); !ok {
		t.Fatal("replacement runtime was not installed")
	}
	session.Stop()

	data, err := os.ReadFile(filepath.Join(outputDir, "frames", "scan-75.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest liveBrowserFrameManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "stopped" || manifest.SessionActive || len(manifest.Frames) != 2 {
		t.Fatalf("terminal reconnect replay = %#v", manifest)
	}
	wantURLs := map[string]bool{
		"https://example.test/before": false,
		"https://example.test/after":  false,
	}
	for _, frame := range manifest.Frames {
		if _, ok := wantURLs[frame.URL]; ok {
			wantURLs[frame.URL] = true
		}
		if frame.Active {
			t.Fatalf("terminal reconnect frame remained active: %#v", frame)
		}
	}
	for targetURL, found := range wantURLs {
		if !found {
			t.Fatalf("reconnect replay lost %s: %#v", targetURL, manifest.Frames)
		}
	}
	assertNoLiveBrowserTempArtifacts(t, filepath.Join(outputDir, "frames"))
}

func TestRelaunchBrowserCancellationDoesNotStopCaptureSession(t *testing.T) {
	outputDir := t.TempDir()
	controller := NewController("127.0.0.1:0", true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	session := controller.StartFrameCapture(context.Background(), 76, outputDir)
	if session == nil {
		t.Fatal("frame capture session was not created")
	}

	transportErr := errors.New("websocket: close 1006 unexpected EOF")
	stale := rod.New().Client(&fixedErrorCDPClient{events: make(chan *cdp.Event), err: transportErr})
	controller.publishBrowserRuntime(browserRuntime{browser: stale})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := controller.relaunchBrowser(ctx, stale); !errors.Is(err, context.Canceled) {
		t.Fatalf("relaunch error = %v, want context canceled", err)
	}
	if controller.browserSnapshot() != nil {
		t.Fatal("stale runtime remained published after failed relaunch")
	}
	if controller.currentFrameCapture() != session {
		t.Fatal("failed relaunch stopped or detached the scan capture session")
	}
	select {
	case <-session.done:
		t.Fatal("failed relaunch terminated the capture writer")
	default:
	}

	// The writer must still accept and durably finalize observations while no
	// browser is connected; a later successful launch will simply become the
	// controller's next sampled runtime.
	session.observe(liveBrowserFrameObservation{capture: func(bool) *capturedBrowserFrame {
		return &capturedBrowserFrame{metadata: liveBrowserFrame{
			ID: "during-reconnect", URL: "https://example.test/reconnecting",
			LastAction: "navigate", UpdatedAt: time.Now().UTC(), Active: true,
		}}
	}})
	session.Stop()

	data, err := os.ReadFile(filepath.Join(outputDir, "frames", "scan-76.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest liveBrowserFrameManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SessionActive || manifest.Status != "stopped" || len(manifest.Frames) != 1 ||
		manifest.Frames[0].URL != "https://example.test/reconnecting" {
		t.Fatalf("capture did not survive relaunch failure: %#v", manifest)
	}
}

func assertNoLiveBrowserTempArtifacts(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("atomic writer left temporary artifact %q", entry.Name())
		}
	}
}

func TestWriteLiveBrowserImageOnlyRewritesChangedPixels(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "frame.jpg")
	written := map[string]string{}
	first := []byte("mostly-white-real-jpeg")
	firstVersion := liveBrowserImageVersion(first)
	if err := writeLiveBrowserImageIfChanged(path, first, firstVersion, written); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := writeLiveBrowserImageIfChanged(path, first, firstVersion, written); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.ModTime().After(old.Add(time.Second)) {
		t.Fatalf("unchanged image was rewritten: modtime %s", info.ModTime())
	}

	second := []byte("changed-real-jpeg")
	if err := writeLiveBrowserImageIfChanged(path, second, liveBrowserImageVersion(second), written); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(second) {
		t.Fatalf("changed image bytes = %q, want %q", got, second)
	}
}

func TestWriteLiveBrowserManifestPreservesEmptyHeartbeatState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan-12.json")
	manifest := liveBrowserFrameManifest{
		Frames: []liveBrowserFrame{}, CapturedAt: time.Now().UTC(), Status: "tabs_waiting_for_image",
		SessionActive: true, BrowserConnected: true, HasTabs: true, HasImages: false,
	}
	if err := writeLiveBrowserManifest(path, manifest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got liveBrowserFrameManifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !got.SessionActive || !got.BrowserConnected || !got.HasTabs || got.HasImages || got.Status != "tabs_waiting_for_image" {
		t.Fatalf("heartbeat state changed: %#v", got)
	}
	if got.Frames == nil {
		t.Fatal("empty heartbeat encoded frames as null")
	}
}

func TestAppendRetainedClosedBrowserFramesKeepsNewestBoundedReplay(t *testing.T) {
	now := time.Now().UTC()
	interaction := &liveBrowserInteraction{Action: "click", State: "succeeded", StartedAt: now}
	makeFrame := func(id string, age int) capturedBrowserFrame {
		updatedAt := now.Add(time.Duration(age) * time.Second)
		return capturedBrowserFrame{
			metadata: liveBrowserFrame{
				ID: id, URL: "https://example.test/" + id, UpdatedAt: updatedAt,
				Active: true, Status: "image_updated", HasImage: true,
				ImageVersion: id + "-version", ImageUpdatedAt: &updatedAt, Interaction: interaction,
			},
			image: []byte("image-" + id), imageVersion: id + "-version",
		}
	}

	active := makeFrame("active", 10)
	lastGood := map[string]capturedBrowserFrame{"active": active}
	for i, id := range []string{"closed-1", "closed-2", "closed-3", "closed-4", "closed-5"} {
		lastGood[id] = makeFrame(id, i+1)
	}

	got := appendRetainedClosedBrowserFrames(
		[]capturedBrowserFrame{active}, map[string]bool{"active": true}, lastGood, 4,
	)
	wantIDs := []string{"active", "closed-5", "closed-4", "closed-3"}
	if len(got) != len(wantIDs) {
		t.Fatalf("retained frame count = %d, want %d: %#v", len(got), len(wantIDs), got)
	}
	for i, wantID := range wantIDs {
		if got[i].metadata.ID != wantID {
			t.Fatalf("frame %d ID = %q, want %q", i, got[i].metadata.ID, wantID)
		}
		if i == 0 {
			if !got[i].metadata.Active {
				t.Fatal("active frame lost its activity marker")
			}
			continue
		}
		if got[i].metadata.Active || got[i].metadata.Status != "tab_closed" || got[i].metadata.Interaction != nil {
			t.Fatalf("closed frame was presented as live: %#v", got[i].metadata)
		}
		if !got[i].metadata.HasImage || len(got[i].image) == 0 {
			t.Fatalf("closed frame lost its replay image: %#v", got[i])
		}
	}
	if len(lastGood) != len(wantIDs) {
		t.Fatalf("last-good cache was not bounded: got %d entries", len(lastGood))
	}
	for _, id := range wantIDs {
		if _, ok := lastGood[id]; !ok {
			t.Fatalf("retained frame %q was pruned from last-good cache", id)
		}
	}
}

func TestStoppedLiveBrowserManifestConvertsFramesToReplay(t *testing.T) {
	now := time.Now().UTC()
	interaction := &liveBrowserInteraction{Action: "click", State: "running", StartedAt: now}
	manifest := liveBrowserFrameManifest{
		Frames: []liveBrowserFrame{
			{ID: "painted", Active: true, Status: "image_updated", HasImage: true, Interaction: interaction},
			{ID: "waiting", Active: true, Status: "waiting_for_image", Interaction: interaction},
		},
		CapturedAt: now.Add(-time.Second), Status: "ready", SessionActive: true,
		BrowserConnected: true, HasTabs: true, HasImages: true,
	}

	got := stoppedLiveBrowserManifest(manifest, now)
	if got.Status != "stopped" || got.SessionActive || got.HasTabs || !got.HasImages || !got.CapturedAt.Equal(now) {
		t.Fatalf("stopped manifest has incorrect top-level state: %#v", got)
	}
	if got.Frames[0].Active || got.Frames[0].Interaction != nil || got.Frames[0].Status != "tab_closed" {
		t.Fatalf("painted frame was not converted to replay: %#v", got.Frames[0])
	}
	if got.Frames[1].Active || got.Frames[1].Interaction != nil || got.Frames[1].Status != "closed_without_image" {
		t.Fatalf("unpainted frame was not closed truthfully: %#v", got.Frames[1])
	}
}

func TestLiveBrowserInteractionFreshness(t *testing.T) {
	now := time.Now().UTC()
	running := liveBrowserInteraction{StartedAt: now.Add(-liveInteractionMaxAge + time.Second)}
	if !liveBrowserInteractionFresh(running, now) {
		t.Fatal("recent running interaction was treated as stale")
	}
	running.StartedAt = now.Add(-liveInteractionMaxAge - time.Second)
	if liveBrowserInteractionFresh(running, now) {
		t.Fatal("expired running interaction was retained")
	}

	completedAt := now.Add(-liveInteractionHold + time.Second)
	completed := liveBrowserInteraction{StartedAt: now.Add(-time.Minute), CompletedAt: &completedAt}
	if !liveBrowserInteractionFresh(completed, now) {
		t.Fatal("recent completed interaction was not held for the UI")
	}
	oldCompletedAt := now.Add(-liveInteractionHold - time.Second)
	completed.CompletedAt = &oldCompletedAt
	if liveBrowserInteractionFresh(completed, now) {
		t.Fatal("expired completed interaction was retained")
	}
}

func TestPruneLiveBrowserInteractionsKeepsOnlyFreshEntries(t *testing.T) {
	now := time.Now().UTC()
	controller := NewController("127.0.0.1:0", true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	controller.liveInteractions = make(map[string]liveBrowserInteraction)
	controller.liveInteractions["fresh"] = liveBrowserInteraction{StartedAt: now.Add(-time.Second)}
	controller.liveInteractions["stale"] = liveBrowserInteraction{StartedAt: now.Add(-liveInteractionMaxAge - time.Second)}

	// This path runs on every capture tick once a browser tab exists. Keep a
	// direct regression around its lock lifecycle as well as its pruning rule.
	controller.pruneLiveBrowserInteractions(now)

	if _, ok := controller.liveInteractions["fresh"]; !ok {
		t.Fatal("fresh browser interaction was pruned")
	}
	if _, ok := controller.liveInteractions["stale"]; ok {
		t.Fatal("stale browser interaction was retained")
	}
}

func TestLiveBrowserFrameIDIsStableAndFilenameSafe(t *testing.T) {
	first := liveBrowserFrameID("target-123")
	second := liveBrowserFrameID("target-123")
	other := liveBrowserFrameID("target-456")
	if first != second {
		t.Fatalf("frame ID changed for the same target: %q != %q", first, second)
	}
	if first == other {
		t.Fatalf("different targets received the same test frame ID %q", first)
	}
	if len(first) != 12 {
		t.Fatalf("frame ID length = %d, want 12", len(first))
	}
	for _, r := range first {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("frame ID contains filename-unsafe character %q", r)
		}
	}
}

func TestRemoveStaleLiveBrowserFramesOnlyTouchesSelectedScan(t *testing.T) {
	dir := t.TempDir()
	keep := liveBrowserFramePath(dir, 9, "aaaaaaaaaaaa")
	stale := liveBrowserFramePath(dir, 9, "bbbbbbbbbbbb")
	otherScan := liveBrowserFramePath(dir, 10, "cccccccccccc")
	for _, path := range []string{keep, stale, otherScan} {
		if err := os.WriteFile(path, []byte("frame"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	removeStaleLiveBrowserFrames(dir, 9, map[string]bool{keep: true})
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("current frame was removed: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale frame still exists: %v", err)
	}
	if _, err := os.Stat(otherScan); err != nil {
		t.Fatalf("another scan's frame was removed: %v", err)
	}
	if filepath.Dir(keep) != dir {
		t.Fatalf("frame path escaped capture directory: %s", keep)
	}
}
