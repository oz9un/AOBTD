package ui

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiveBrowserFleetReportsActiveAndIdleStates(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	for _, want := range []string{
		"setInterval(updateBrowserFrame, 500)",
		"Last browser frame · reasoning continues",
		"Browser replay · ${savedFrameCount} saved",
		"Replay only — no tab is active.",
		"Browser replay from this run — not a live tab.",
		"liveState.hasBrowserTabs = data?.has_tabs === true && activeFrameCount > 0",
		"const frameIsActive = frame => data?.active === true && frame?.active === true",
		"updateBrowserInteractionOverlay(screen, frame.interaction, frameActive)",
		"liveState.frameLastAction = String(frames.find(frame => frame?.last_action)?.last_action || '')",
		"Capture page state",
		"hasActiveBrowserImages",
		"browser-screen-history",
		"renderBrowserFleetIdle(el, data)",
		"Visual capture unavailable · action trail preserved",
		"Page open · waiting for paint",
		"frame.image_version || frame.image_updated_at",
		"resetBrowserScreenImage(screen)",
		"screen.dataset.frameUrl !== frameURL",
		"img.dataset.requestedFrameKey !== requestKey",
		"isBlankBrowserImage(probe)",
		"Blank render withheld · action trail preserved",
		"heldSamePage ? 'last good' : 'page open'",
		"availableFrames.filter(frame => frameIsActive(frame) || frameHasImage(frame))",
		"visibleFrames.length ? visibleFrames : availableFrames.slice(0, 1)",
		"Browser idle — scan still running",
		"The crawler is between browser tasks",
		"else void updateBrowserFrame()",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("Live browser fleet is missing %q", want)
		}
	}
}

func TestLiveBrowserFleetHasNoDecorativeScanline(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	for _, unwanted := range []string{
		"browser-scanline",
		".browser-screen-viewport::after",
	} {
		if strings.Contains(page, unwanted) {
			t.Fatalf("Live browser fleet still contains decorative scanline %q", unwanted)
		}
	}
}

func TestLiveBrowserTheatreShowsTruthfulDecisionLoop(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	for _, want := range []string{
		"AI Browser",
		"Live decision loop",
		"Observe",
		"Decide",
		"Act",
		"Browser trail",
		"browser-interaction-layer",
		"updateBrowserInteractionOverlay",
		"renderBrowserIntelligence",
		"interaction?.has_bounds === true",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("AI browser theatre is missing %q", want)
		}
	}
}

func TestLiveFramesManifestAndSelectedFrame(t *testing.T) {
	outputDir := t.TempDir()
	framesDir := filepath.Join(outputDir, "frames")
	if err := os.MkdirAll(framesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := liveFrameManifest{
		Frames: []liveFrameMetadata{
			{ID: "aaaaaaaaaaaa", URL: "https://example.test/one", UpdatedAt: time.Now().UTC()},
			{
				ID: "bbbbbbbbbbbb", URL: "https://example.test/two", LastAction: "crawl_last_seen", UpdatedAt: time.Now().UTC(),
				Interaction: &liveFrameInteractionMetadata{
					Agent: "navigator", Action: "click", Selector: "#checkout", Reason: "Inspect checkout controls",
					State: "running", X: 62.5, Y: 44, Width: 12, Height: 6, HasBounds: true, StartedAt: time.Now().UTC(),
				},
			},
		},
		CapturedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(framesDir, "scan-42.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	frameBytes := []byte("jpeg-frame-two")
	if err := os.WriteFile(filepath.Join(framesDir, "scan-42-frame-bbbbbbbbbbbb.jpg"), frameBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	server := &Server{outputDir: outputDir}
	listReq := httptest.NewRequest(http.MethodGet, "/api/live/frames?scan_id=42", nil)
	listRec := httptest.NewRecorder()
	server.handleLiveFrames(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("manifest status = %d, want 200", listRec.Code)
	}
	var got liveFrameManifest
	if err := json.Unmarshal(listRec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Active || len(got.Frames) != 2 || got.Frames[1].URL != "https://example.test/two" || got.Frames[1].LastAction != "crawl_last_seen" {
		t.Fatalf("unexpected manifest: %#v", got)
	}
	interaction := got.Frames[1].Interaction
	if interaction == nil || interaction.Agent != "navigator" || interaction.Action != "click" ||
		interaction.Selector != "#checkout" || !interaction.HasBounds || interaction.X != 62.5 {
		t.Fatalf("live interaction metadata was not preserved: %#v", interaction)
	}

	frameReq := httptest.NewRequest(http.MethodGet,
		"/api/live/frame?scan_id=42&frame_id=bbbbbbbbbbbb", nil)
	frameRec := httptest.NewRecorder()
	server.handleLiveFrame(frameRec, frameReq)
	if frameRec.Code != http.StatusOK {
		t.Fatalf("frame status = %d, want 200", frameRec.Code)
	}
	if frameRec.Body.String() != string(frameBytes) {
		t.Fatalf("frame body = %q, want %q", frameRec.Body.String(), frameBytes)
	}
	if gotType := frameRec.Header().Get("Content-Type"); gotType != "image/jpeg" {
		t.Fatalf("content type = %q, want image/jpeg", gotType)
	}
}

func TestLiveFrameRequiresManifestImageGeneration(t *testing.T) {
	outputDir := t.TempDir()
	framesDir := filepath.Join(outputDir, "frames")
	if err := os.MkdirAll(framesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const version = "0123456789abcdef"
	manifest := liveFrameManifest{
		Frames: []liveFrameMetadata{{
			ID: "aaaaaaaaaaaa", URL: "https://example.test/new", UpdatedAt: time.Now().UTC(),
			Active: true, Status: "image_updated", HasImage: true, ImageVersion: version,
		}},
		CapturedAt: time.Now().UTC(), Status: "ready", SessionActive: true,
		BrowserConnected: true, HasTabs: true, HasImages: true,
	}
	data, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(framesDir, "scan-47.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	frameBytes := []byte("generation-consistent-frame")
	if err := os.WriteFile(filepath.Join(framesDir, "scan-47-frame-aaaaaaaaaaaa-"+version+".jpg"), frameBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	// A stale UI request must never receive the new generation's pixels under
	// old metadata.
	server := &Server{outputDir: outputDir}
	stale := httptest.NewRecorder()
	server.handleLiveFrame(stale, httptest.NewRequest(http.MethodGet,
		"/api/live/frame?scan_id=47&frame_id=aaaaaaaaaaaa&v=ffffffffffffffff", nil))
	if stale.Code != http.StatusNoContent {
		t.Fatalf("stale generation status = %d, want 204", stale.Code)
	}

	current := httptest.NewRecorder()
	server.handleLiveFrame(current, httptest.NewRequest(http.MethodGet,
		"/api/live/frame?scan_id=47&frame_id=aaaaaaaaaaaa&v="+version, nil))
	if current.Code != http.StatusOK || current.Body.String() != string(frameBytes) {
		t.Fatalf("current generation response = %d %q", current.Code, current.Body.String())
	}

	// A UI loaded before generation-aware URLs were introduced can still ask
	// for the current frame by ID. The server resolves the immutable generation
	// from the manifest; only an explicitly stale generation is rejected.
	compatible := httptest.NewRecorder()
	server.handleLiveFrame(compatible, httptest.NewRequest(http.MethodGet,
		"/api/live/frame?scan_id=47&frame_id=aaaaaaaaaaaa", nil))
	if compatible.Code != http.StatusOK || compatible.Body.String() != string(frameBytes) {
		t.Fatalf("generation-less compatibility response = %d %q", compatible.Code, compatible.Body.String())
	}
}

func TestLiveFrameServesOnlyHashMatchedHistoricalStableGeneration(t *testing.T) {
	outputDir := t.TempDir()
	framesDir := filepath.Join(outputDir, "frames")
	if err := os.MkdirAll(framesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const frameID = "fc8f0f62f07b"
	frameBytes := []byte("mixed-era-scan-66-frame")
	digest := sha256.Sum256(frameBytes)
	version := fmt.Sprintf("%x", digest[:8])
	stablePath := filepath.Join(framesDir, "scan-66-frame-"+frameID+".jpg")
	if err := os.WriteFile(stablePath, frameBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	writeManifest := func(status string, sessionActive, frameActive bool, imageVersion string) {
		t.Helper()
		manifest := liveFrameManifest{
			Frames: []liveFrameMetadata{{
				ID: frameID, URL: "https://partner.example.com/", UpdatedAt: time.Now().UTC(),
				Active: frameActive, Status: "tab_closed", HasImage: true, ImageVersion: imageVersion,
			}},
			CapturedAt: time.Now().UTC(), Status: status, SessionActive: sessionActive, HasImages: true,
		}
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(framesDir, "scan-66.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	server := &Server{outputDir: outputDir}
	requestFrame := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleLiveFrame(rec, httptest.NewRequest(http.MethodGet,
			"/api/live/frame?scan_id=66&frame_id="+frameID+"&v="+version, nil))
		return rec
	}

	writeManifest("stopped", false, false, version)
	replay := requestFrame()
	if replay.Code != http.StatusOK || replay.Body.String() != string(frameBytes) {
		t.Fatalf("historical replay response = %d %q", replay.Code, replay.Body.String())
	}

	// A mutable stable path is never a current-generation source for an active
	// frame, even when its bytes happen to match the manifest version.
	writeManifest("ready", true, true, version)
	if active := requestFrame(); active.Code != http.StatusNoContent {
		t.Fatalf("active stable fallback status = %d, want 204", active.Code)
	}

	// A stopped replay also fails closed when stable pixels do not prove the
	// generation named by the manifest.
	writeManifest("stopped", false, false, "0000000000000000")
	if mismatched := requestFrame(); mismatched.Code != http.StatusNoContent {
		t.Fatalf("mismatched replay status = %d, want 204", mismatched.Code)
	}
}

func TestLiveFramesTreatsStaleManifestAsIdle(t *testing.T) {
	outputDir := t.TempDir()
	framesDir := filepath.Join(outputDir, "frames")
	if err := os.MkdirAll(framesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := liveFrameManifest{
		Frames: []liveFrameMetadata{{
			ID: "aaaaaaaaaaaa", URL: "https://example.test/closed",
			UpdatedAt: time.Now().Add(-time.Minute).UTC(),
		}},
		CapturedAt: time.Now().Add(-time.Minute).UTC(),
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(framesDir, "scan-43.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	server := &Server{outputDir: outputDir}
	req := httptest.NewRequest(http.MethodGet, "/api/live/frames?scan_id=43", nil)
	rec := httptest.NewRecorder()
	server.handleLiveFrames(rec, req)

	var got liveFrameManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Active || got.SessionActive || got.BrowserConnected || got.HasTabs ||
		len(got.Frames) != 1 || got.Frames[0].URL != "https://example.test/closed" {
		t.Fatalf("stale manifest did not preserve one idle frame: %#v", got)
	}
}

func TestLiveFramesTreatsStaleExplicitHeartbeatAsIdle(t *testing.T) {
	outputDir := t.TempDir()
	framesDir := filepath.Join(outputDir, "frames")
	if err := os.MkdirAll(framesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute).UTC()
	manifest := liveFrameManifest{
		Frames: []liveFrameMetadata{{
			ID: "aaaaaaaaaaaa", URL: "https://example.test/stale", UpdatedAt: old,
			Active: true, Status: "image_updated", HasImage: true,
		}},
		CapturedAt: old, Status: "ready", SessionActive: true,
		BrowserConnected: true, HasTabs: true, HasImages: true, Active: true,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(framesDir, "scan-48.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	server := &Server{outputDir: outputDir}
	rec := httptest.NewRecorder()
	server.handleLiveFrames(rec, httptest.NewRequest(http.MethodGet, "/api/live/frames?scan_id=48", nil))
	var got liveFrameManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Active || got.SessionActive || got.BrowserConnected || got.HasTabs ||
		len(got.Frames) != 1 || got.Frames[0].Active {
		t.Fatalf("stale explicit heartbeat remained live: %#v", got)
	}
}

func TestLiveFramesPreservesFreshHeartbeatWithoutClaimingAnImage(t *testing.T) {
	outputDir := t.TempDir()
	framesDir := filepath.Join(outputDir, "frames")
	if err := os.MkdirAll(framesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := liveFrameManifest{
		Frames: []liveFrameMetadata{{
			ID: "aaaaaaaaaaaa", URL: "https://example.test/white",
			UpdatedAt: time.Now().UTC(), Active: true, Status: "waiting_for_image", HasImage: false,
		}},
		CapturedAt: time.Now().UTC(), Status: "tabs_waiting_for_image",
		SessionActive: true, BrowserConnected: true, HasTabs: true, HasImages: false,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(framesDir, "scan-44.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	// Simulate the narrow cleanup race where the previous URL's file still
	// exists even though the manifest says the current tab has no image.
	if err := os.WriteFile(filepath.Join(framesDir, "scan-44-frame-aaaaaaaaaaaa.jpg"), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	server := &Server{outputDir: outputDir}
	req := httptest.NewRequest(http.MethodGet, "/api/live/frames?scan_id=44", nil)
	rec := httptest.NewRecorder()
	server.handleLiveFrames(rec, req)
	var got liveFrameManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Active || !got.SessionActive || !got.BrowserConnected || !got.HasTabs || got.HasImages {
		t.Fatalf("heartbeat state was not preserved: %#v", got)
	}
	if len(got.Frames) != 1 || got.Frames[0].HasImage || got.Frames[0].Status != "waiting_for_image" {
		t.Fatalf("no-image tab was presented as a frame: %#v", got.Frames)
	}

	frameReq := httptest.NewRequest(http.MethodGet,
		"/api/live/frame?scan_id=44&frame_id=aaaaaaaaaaaa", nil)
	frameRec := httptest.NewRecorder()
	server.handleLiveFrame(frameRec, frameReq)
	if frameRec.Code != http.StatusNoContent {
		t.Fatalf("missing bitmap status = %d, want 204", frameRec.Code)
	}
}

func TestLiveFramesKeepsFreshSavedFrameWithoutClaimingActiveTab(t *testing.T) {
	outputDir := t.TempDir()
	framesDir := filepath.Join(outputDir, "frames")
	if err := os.MkdirAll(framesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	manifest := liveFrameManifest{
		Frames: []liveFrameMetadata{{
			ID: "replay000001", URL: "https://example.test/closed", UpdatedAt: now,
			Active: false, Status: "tab_closed", HasImage: true, ImageVersion: "saved-v1",
			Interaction: &liveFrameInteractionMetadata{Action: "click", State: "succeeded", StartedAt: now},
		}},
		CapturedAt: now, Status: "saved_frames", SessionActive: true,
		BrowserConnected: true, HasTabs: false, HasImages: true, Active: true,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(framesDir, "scan-46.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(framesDir, "scan-46-frame-replay000001.jpg"), []byte("saved-frame"), 0o644); err != nil {
		t.Fatal(err)
	}

	server := &Server{outputDir: outputDir}
	req := httptest.NewRequest(http.MethodGet, "/api/live/frames?scan_id=46", nil)
	rec := httptest.NewRecorder()
	server.handleLiveFrames(rec, req)
	var got liveFrameManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Active || !got.SessionActive || !got.BrowserConnected || got.HasTabs || !got.HasImages || got.Status != "saved_frames" {
		t.Fatalf("fresh saved frame claimed a live browser: %#v", got)
	}
	if len(got.Frames) != 1 || got.Frames[0].Active || got.Frames[0].Status != "tab_closed" {
		t.Fatalf("saved frame metadata was not preserved as replay: %#v", got.Frames)
	}
	if got.Frames[0].Interaction != nil {
		t.Fatalf("saved frame retained a live interaction marker: %#v", got.Frames[0].Interaction)
	}
}

func TestLiveFramesRecentStoppedManifestIsInactive(t *testing.T) {
	outputDir := t.TempDir()
	framesDir := filepath.Join(outputDir, "frames")
	if err := os.MkdirAll(framesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := liveFrameManifest{
		Frames: []liveFrameMetadata{}, CapturedAt: time.Now().UTC(),
		Status: "stopped", SessionActive: false, BrowserConnected: true, HasTabs: true,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(framesDir, "scan-45.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	server := &Server{outputDir: outputDir}
	req := httptest.NewRequest(http.MethodGet, "/api/live/frames?scan_id=45", nil)
	rec := httptest.NewRecorder()
	server.handleLiveFrames(rec, req)
	var got liveFrameManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Active || got.SessionActive || got.BrowserConnected || got.HasTabs || got.Status != "stopped" {
		t.Fatalf("stopped heartbeat was shown as active: %#v", got)
	}
}

func TestLiveFrameRejectsUnsafeID(t *testing.T) {
	server := &Server{outputDir: t.TempDir()}
	req := httptest.NewRequest(http.MethodGet,
		"/api/live/frame?scan_id=42&frame_id=../../secrets", nil)
	rec := httptest.NewRecorder()
	server.handleLiveFrame(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestLiveFramesFallsBackToLegacyCapture(t *testing.T) {
	outputDir := t.TempDir()
	framesDir := filepath.Join(outputDir, "frames")
	if err := os.MkdirAll(framesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(framesDir, "scan-7.jpg"), []byte("legacy"), 0o644); err != nil {
		t.Fatal(err)
	}

	server := &Server{outputDir: outputDir}
	req := httptest.NewRequest(http.MethodGet, "/api/live/frames?scan_id=7", nil)
	rec := httptest.NewRecorder()
	server.handleLiveFrames(rec, req)
	var got liveFrameManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Active || len(got.Frames) != 1 || got.Frames[0].ID != "legacy" || !got.Frames[0].Active {
		t.Fatalf("legacy manifest = %#v", got)
	}
}

func TestLiveFramesPreservesStaleLegacyCaptureAsIdle(t *testing.T) {
	outputDir := t.TempDir()
	framesDir := filepath.Join(outputDir, "frames")
	if err := os.MkdirAll(framesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(framesDir, "scan-8.jpg")
	if err := os.WriteFile(legacyPath, []byte("legacy"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(legacyPath, old, old); err != nil {
		t.Fatal(err)
	}

	server := &Server{outputDir: outputDir}
	req := httptest.NewRequest(http.MethodGet, "/api/live/frames?scan_id=8", nil)
	rec := httptest.NewRecorder()
	server.handleLiveFrames(rec, req)

	var got liveFrameManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Active || len(got.Frames) != 1 || got.Frames[0].ID != "legacy" {
		t.Fatalf("stale legacy capture did not remain as idle context: %#v", got)
	}
}
