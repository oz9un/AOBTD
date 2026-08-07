package ui

import (
	"strings"
	"testing"
)

func TestRefreshLifecyclePreservesEveryViewAndRejectsStaleWork(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)

	for _, contract := range []string{
		`.view-container.refresh-preserve-scroll::after`,
		`vc.classList.add('refresh-preserve-scroll')`,
		`vc.style.setProperty('--refresh-scroll-spacer'`,
		`renderEpoch === _renderViewEpoch && currentView === renderedView`,
		`await new Promise(resolve => requestAnimationFrame(resolve))`,
		`vc.classList.remove('refresh-preserve-scroll')`,
		`const requestedScanID = scanID`,
		`const requestedView = opts.freshView || currentView`,
		`if (scanID !== requestedScanID) return`,
		`currentView === requestedView`,
		`await renderView()`,
		`datasetValues[index] !== null && datasetValues[index] !== undefined`,
		`if (document.hidden) return`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("shared refresh lifecycle contract missing %q", contract)
		}
	}
}

func TestOverviewRefreshWaitsForItsHeightChangingProjection(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	start := strings.Index(html, "async function renderOverview(el)")
	end := strings.Index(html[start:], "async function loadPageOverview()")
	if start < 0 || end < 0 {
		t.Fatal("could not isolate Overview render lifecycle")
	}
	renderer := html[start : start+end]
	for _, contract := range []string{
		`pageOverviewCacheScanID === overviewScanKey`,
		`${preservedPageOverview || 'Loading…'}`,
		`await loadPageOverview()`,
	} {
		if !strings.Contains(renderer, contract) {
			t.Fatalf("Overview refresh lifecycle contract missing %q", contract)
		}
	}
	for _, contract := range []string{
		`if (scanID !== requestScanID || !root.isConnected) return`,
		`if (!data)`,
		`Keep the last good projection`,
		`pageOverviewCacheScanID = requestScanID`,
		`pageOverviewHTMLCache = html`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Overview deferred projection contract missing %q", contract)
		}
	}
}

func TestProgrammaticHashChangeCannotTriggerSecondRefresh(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		`let _selfWrittenHash = ''`,
		`_selfWrittenHash = target`,
		`location.hash === _selfWrittenHash`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("hash refresh de-duplication contract missing %q", contract)
		}
	}
	if strings.Contains(html, "setTimeout(() => { _suppressHashChange") {
		t.Fatal("programmatic hash suppression is still cleared by a timing race")
	}
}

func TestCopilotRefreshKeepsReadersInPlace(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		`function captureConversationScroll(thread)`,
		`followLatest:remaining < 48`,
		`function restoreConversationScroll(thread, state)`,
		`else thread.scrollTop = state.top`,
		`captureConversationScroll(el.querySelector('#askThread'))`,
		`restoreConversationScroll(thread, threadScroll)`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Copilot refresh scroll contract missing %q", contract)
		}
	}
}
