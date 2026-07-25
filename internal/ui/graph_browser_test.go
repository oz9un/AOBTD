package ui

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// TestGraphBrowserBehavior exercises the real embedded UI when a local
// Chromium-family browser is available. It intentionally skips (rather than
// downloading a browser) on minimal CI workers; the API and projection tests
// remain unconditional.
func TestGraphBrowserBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("headless browser coverage is disabled in short mode")
	}
	bin, ok := launcher.LookPath()
	if !ok {
		t.Skip("no local Chromium-family browser available")
	}

	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test/", `{"Scan":{"Scope":["https://example.test/"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, discovery := range []store.Discovery{
		{TargetURL: "https://example.test/", Kind: store.DiscoverySeed},
		{SourceURL: "https://example.test/", TargetURL: "https://example.test/login", Kind: store.DiscoveryFormAction},
		{SourceURL: "https://example.test/", TargetURL: "https://example.test/search?q=alpha", Kind: store.DiscoveryHTMLLink},
		{SourceURL: "https://example.test/", TargetURL: "https://example.test/search?q=beta", Kind: store.DiscoveryHTMLLink},
	} {
		if err := db.InsertDiscovery(scanID, discovery); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []*types.TrafficEntry{
		{
			EndpointHash: "login-post",
			Request:      types.CapturedRequest{Method: "POST", URL: "https://example.test/login", Headers: map[string]string{"Referer": "https://example.test/"}},
			Response:     types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html", Body: []byte(`<main>signed in</main>`)},
			Timestamp:    time.Now(),
		},
		{
			EndpointHash: "api-me-get",
			Request:      types.CapturedRequest{Method: "GET", URL: "https://example.test/api/me", Headers: map[string]string{"Referer": "https://example.test/login", "Authorization": "Bearer test"}},
			Response:     types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "application/json", Body: []byte(`{"id":1}`)},
			Timestamp:    time.Now(),
		},
	} {
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.InsertFinding(scanID, types.Finding{
		Title: "Login boundary", Severity: types.SeverityHigh, Confidence: types.ConfidenceConfirmed, EndpointID: "POST /login",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.FinishScan(scanID, "completed"); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	s := NewServer(db, t.TempDir(), addr, slog.New(slog.NewTextHandler(io.Discard, nil)))
	go func() { serverDone <- s.Start(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Errorf("UI server shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("UI server did not stop")
		}
	}()
	baseURL := "http://" + addr
	client := &http.Client{Timeout: 250 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, requestErr := client.Get(baseURL + "/api/scans")
		if requestErr == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("UI server did not become ready: %v", requestErr)
		}
		time.Sleep(25 * time.Millisecond)
	}

	l := launcher.New().Bin(bin).Headless(true).Leakless(false)
	controlURL, err := l.Launch()
	if err != nil {
		t.Fatalf("launch headless browser: %v", err)
	}
	defer l.Cleanup()
	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		t.Fatalf("connect headless browser: %v", err)
	}
	defer browser.Close()
	page := browser.MustPage("about:blank").Timeout(20 * time.Second)
	defer page.Close()
	page.MustEvalOnNewDocument(`
		window.__graphTestErrors=[];
		window.addEventListener('error',event=>window.__graphTestErrors.push(String(event.message||event.error||'error')));
		window.addEventListener('unhandledrejection',event=>window.__graphTestErrors.push(String(event.reason||'unhandled rejection')));
	`)
	page.MustNavigate(fmt.Sprintf("%s/#/scan/%d/graph", baseURL, scanID)).MustWaitLoad()

	treeOverview := page.MustElement("#targetTreeOverview").MustWaitVisible().MustText()
	if !strings.Contains(treeOverview, "4") || !strings.Contains(strings.ToUpper(treeOverview), "LOGICAL ROUTES") {
		t.Fatalf("Target Tree overview does not show the four logical-route surface: %q", treeOverview)
	}
	page.MustElementR(".tt-action", `^Show routes$`).MustClick()
	treeText := strings.ToUpper(page.MustElement("#targetTree").MustText())
	if !strings.Contains(treeText, "/SEARCH?Q={…}") || !strings.Contains(treeText, "2 QUERY VARIANTS") {
		t.Fatalf("Target Tree does not expose the collapsed query facet: %q", treeText)
	}

	page.MustElementR(".recon-graph-tabs button", `^URL Paths$`).MustClick()
	countText := page.MustElement("#gtEndpointCount").MustWaitVisible().MustText()
	if countText != "4" {
		t.Fatalf("URL Paths count=%q, want 4 logical routes", countText)
	}
	page.MustElementR(".sm-actions button", `^Expand all$`).MustClick()
	leaves := page.MustElements(".sm-row.is-leaf")
	if len(leaves) != 4 {
		t.Fatalf("URL Paths leaves=%d, want 4 logical routes", len(leaves))
	}
	pathsText := strings.ToUpper(page.MustElement("#gtBody").MustText())
	if !strings.Contains(pathsText, "/SEARCH?Q={…}") || !strings.Contains(pathsText, "2 QUERY VARIANTS") {
		t.Fatalf("URL Paths does not expose the collapsed query facet: %q", pathsText)
	}
	methodCounts := make(map[string]int)
	for _, chip := range page.MustElements(".sm-method") {
		methodCounts[strings.TrimSpace(chip.MustText())]++
	}
	if methodCounts["POST"] != 1 || methodCounts["GET"] != 1 || methodCounts["ROUTE"] != 2 {
		t.Fatalf("truthful method chips=%#v, want POST=1 GET=1 ROUTE=2", methodCounts)
	}

	page.MustElementR(".sm-row.is-leaf", `/login`).MustClick()
	detailPanel := page.MustElement("#detailPanel.open").MustWaitVisible()
	detailDeadline := time.Now().Add(5 * time.Second)
	detail := detailPanel.MustText()
	for (!strings.Contains(detail, "POST") || !strings.Contains(detail, "/login")) && time.Now().Before(detailDeadline) {
		time.Sleep(25 * time.Millisecond)
		detail = detailPanel.MustText()
	}
	if !strings.Contains(detail, "POST") || !strings.Contains(detail, "/login") {
		t.Fatalf("endpoint evidence did not open the captured POST /login: %q", detail)
	}
	page.MustElement("#detailPanel.open .detail-close").MustClick()

	page.MustElementR(".recon-graph-tabs button", `^Visual Map$`).MustClick()
	page.MustElement("#atlasCanvas").MustWaitVisible()
	hud := page.MustElement("#atlasHud").MustText()
	hudUpper := strings.ToUpper(hud)
	if !strings.Contains(hud, "4") || !strings.Contains(hudUpper, "LOGICAL ROUTES") || !strings.Contains(hud, "1") || !strings.Contains(hudUpper, "RISK") {
		t.Fatalf("Visual Map HUD does not agree with graph evidence: %q", hud)
	}

	page.MustElementR(".atlas-toolbar button", `^Causal flows$`).MustClick()
	flowDetail := page.MustElement("#causalFlowDetail").MustWaitVisible().MustText()
	flowUpper := strings.ToUpper(flowDetail)
	if !strings.Contains(flowDetail, "/login") || !strings.Contains(flowDetail, "/api/me") ||
		!strings.Contains(flowUpper, "REFERER NAVIGATION") || !strings.Contains(flowUpper, "OBSERVED") ||
		!strings.Contains(flowUpper, "CONFIRMED FINDING") || !strings.Contains(flowUpper, "LOGIN BOUNDARY") ||
		!strings.Contains(flowUpper, "SAME ENDPOINT ASSOCIATION") {
		t.Fatalf("Causal Flows did not preserve the observed Referer transition: %q", flowDetail)
	}
	if browserErrors := page.MustEval(`() => JSON.stringify(window.__graphTestErrors || [])`).Str(); browserErrors != "[]" {
		t.Fatalf("browser errors during graph flow: %s", browserErrors)
	}
}
