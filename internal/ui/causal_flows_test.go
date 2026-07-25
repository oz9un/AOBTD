package ui

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestCausalFlowsGradesObservedAttributedAndCorrelatedEvidence(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test/", `{"Scan":{"Scope":["https://example.test/"]}}`)
	if err != nil {
		t.Fatal(err)
	}

	entries := []*types.TrafficEntry{
		{
			EndpointHash: "login-get",
			Request:      types.CapturedRequest{Method: "GET", URL: "https://example.test/login", Headers: map[string]string{}},
			Response:     types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html"},
		},
		{
			EndpointHash: "session-post",
			Request: types.CapturedRequest{Method: "POST", URL: "https://example.test/session", Headers: map[string]string{
				"Referer": "https://example.test/login",
			}},
			Response: types.CapturedResponse{StatusCode: 302, Headers: map[string]string{
				"Location": "/account", "Set-Cookie": "sid=abc; HttpOnly",
			}, ContentType: "text/html"},
		},
		{
			EndpointHash: "account-get",
			Request: types.CapturedRequest{Method: "GET", URL: "https://example.test/account", Headers: map[string]string{
				"Referer": "https://example.test/session", "Cookie": "sid=abc",
			}},
			Response: types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html"},
		},
		{
			EndpointHash: "orders-get",
			Request: types.CapturedRequest{Method: "GET", URL: "https://example.test/api/orders", Headers: map[string]string{
				"Referer": "https://example.test/account", "Cookie": "sid=abc",
			}},
			Response: types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "application/json"},
		},
		{
			EndpointHash: "external-get",
			Request:      types.CapturedRequest{Method: "GET", URL: "https://outside.test/pixel", Headers: map[string]string{}},
			Response:     types.CapturedResponse{StatusCode: 204, Headers: map[string]string{}, ContentType: "image/gif"},
		},
	}
	ids := make([]int64, 0, len(entries))
	for _, entry := range entries {
		id, insertErr := db.InsertTraffic(scanID, entry)
		if insertErr != nil {
			t.Fatal(insertErr)
		}
		ids = append(ids, id)
	}
	for index, id := range ids {
		captured := time.Date(2026, 7, 17, 12, 0, index, 0, time.UTC)
		if _, err := db.Conn().Exec(`UPDATE traffic SET captured_at = ? WHERE id = ?`, captured, id); err != nil {
			t.Fatal(err)
		}
	}
	// These provenance columns are optional in older databases. Adding them in
	// the fixture verifies that the API enriches flows when they are present,
	// while its dynamic query remains compatible with the baseline schema.
	_, _ = db.Conn().Exec(`ALTER TABLE traffic ADD COLUMN source_agent TEXT DEFAULT ''`)
	_, _ = db.Conn().Exec(`ALTER TABLE traffic ADD COLUMN source_action_id INTEGER DEFAULT 0`)
	_, _ = db.Conn().Exec(`ALTER TABLE traffic ADD COLUMN hypothesis_id TEXT DEFAULT ''`)
	if _, err := db.Conn().Exec(`
		UPDATE traffic
		   SET source_agent = 'navigator', source_action_id = 42, hypothesis_id = 'auth-orders'
		 WHERE id IN (?, ?)`, ids[2], ids[3]); err != nil {
		t.Fatal(err)
	}
	linkedFindingID, err := db.InsertFinding(scanID, types.Finding{
		Title: "Account authorization bypass", Severity: types.SeverityHigh, Confidence: types.ConfidenceConfirmed,
		EndpointID: "GET /account", TrafficIDs: []int64{ids[2]}, HypothesisID: "auth-orders",
	})
	if err != nil {
		t.Fatal(err)
	}
	unlinkedFindingID, err := db.InsertFinding(scanID, types.Finding{
		Title: "Missing endpoint issue", Severity: types.SeverityCritical, Confidence: types.ConfidenceConfirmed,
		EndpointID: "POST /missing",
	})
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	response := requestCausalFlows(t, s, "/api/causal-flows?scan_id="+strconv.FormatInt(scanID, 10))
	if response.SchemaVersion != causalFlowSchemaVersion || response.Scope != "in" {
		t.Fatalf("schema/scope=%d/%q", response.SchemaVersion, response.Scope)
	}
	if response.Stats["events_considered"] != 4 {
		t.Fatalf("in-scope events=%d, want 4", response.Stats["events_considered"])
	}
	if len(response.Flows) != 1 || len(response.Flows[0].Events) != 4 {
		t.Fatalf("flows=%#v", response.Flows)
	}
	flow := response.Flows[0]
	if flow.StrongestEvidence != "observed" || flow.Confidence <= 0 || flow.Confidence > 1 {
		t.Fatalf("flow evidence=%q confidence=%v", flow.StrongestEvidence, flow.Confidence)
	}
	linkTypes := make(map[string]bool)
	for _, link := range flow.Links {
		linkTypes[link.Type] = true
	}
	for _, wanted := range []string{"referer-submission", "redirect", "auth-transition", "agent-action", "hypothesis-sequence"} {
		if !linkTypes[wanted] {
			t.Fatalf("missing %q link in %#v", wanted, flow.Links)
		}
	}
	if response.Stats["observed_links"] < 2 || response.Stats["attributed_links"] < 2 || response.Stats["correlated_links"] < 1 {
		t.Fatalf("evidence stats=%#v", response.Stats)
	}
	if response.Stats["confirmed_findings"] != 2 || response.Stats["linked_findings"] != 1 || response.Stats["unlinked_findings"] != 1 {
		t.Fatalf("finding stats=%#v", response.Stats)
	}
	if flow.WorstSeverity != "high" || len(flow.Findings) != 1 || flow.Findings[0].ID != linkedFindingID ||
		flow.Findings[0].MatchBasis != "explicit-traffic" || len(flow.Findings[0].EventIDs) != 1 || flow.Findings[0].EventIDs[0] != ids[2] {
		t.Fatalf("flow findings=%#v severity=%q", flow.Findings, flow.WorstSeverity)
	}
	if len(response.UnlinkedFindings) != 1 || response.UnlinkedFindings[0].ID != unlinkedFindingID ||
		response.UnlinkedFindings[0].MatchBasis != "unmatched" || response.UnlinkedFindings[0].EventIDs == nil {
		t.Fatalf("unlinked findings=%#v", response.UnlinkedFindings)
	}

	allScope := requestCausalFlows(t, s, "/api/causal-flows?scope=all&scan_id="+strconv.FormatInt(scanID, 10))
	if allScope.Stats["events_considered"] != 5 || allScope.Scope != "all" {
		t.Fatalf("all-scope stats=%#v scope=%q", allScope.Stats, allScope.Scope)
	}
}

func TestCausalFlowsReturnsStableEmptyCollections(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test/", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	response := requestCausalFlows(t, s, "/api/causal-flows?scan_id="+strconv.FormatInt(scanID, 10))
	if response.Flows == nil || len(response.Flows) != 0 || response.UnlinkedFindings == nil ||
		response.Legend == nil || len(response.Legend) != 4 {
		t.Fatalf("empty response=%#v", response)
	}
}

func TestCausalFlowsResolvesPersistedBrowserActionsAndCoverage(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test/", `{"Scan":{"Scope":["https://example.test/"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	actionID, err := db.BeginTrafficAction(
		scanID, "navigator", "click", "open account settings",
		"https://example.test/account", "https://example.test/account/settings", "h-settings",
	)
	if err != nil {
		t.Fatal(err)
	}

	entries := []*types.TrafficEntry{
		{
			EndpointHash: "settings-page",
			Request:      types.CapturedRequest{Method: "GET", URL: "https://example.test/account/settings", Headers: map[string]string{}},
			Response:     types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html"},
			SourceAgent:  "navigator", SourceActionID: actionID, HypothesisID: "h-settings",
		},
		{
			EndpointHash: "settings-api",
			Request:      types.CapturedRequest{Method: "GET", URL: "https://example.test/api/settings", Headers: map[string]string{}},
			Response:     types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "application/json"},
			SourceAgent:  "navigator", SourceActionID: actionID, HypothesisID: "h-settings",
		},
	}
	for index, entry := range entries {
		trafficID, insertErr := db.InsertTraffic(scanID, entry)
		if insertErr != nil {
			t.Fatal(insertErr)
		}
		captured := time.Date(2026, 7, 17, 13, 0, index, 0, time.UTC)
		if _, err := db.Conn().Exec(`UPDATE traffic SET captured_at = ? WHERE id = ?`, captured, trafficID); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.CompleteTrafficAction(scanID, actionID, store.TrafficActionSucceeded, "settings loaded", "https://example.test/account/settings"); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	response := requestCausalFlows(t, s, "/api/causal-flows?scan_id="+strconv.FormatInt(scanID, 10))
	if len(response.Flows) != 1 || len(response.Flows[0].Events) != 2 {
		t.Fatalf("flows=%#v", response.Flows)
	}
	for _, event := range response.Flows[0].Events {
		if event.Action == nil || event.Action.ID != actionID || event.Action.Namespace != "browser" ||
			event.Action.Action != "click" || event.Action.Reason != "open account settings" ||
			event.Action.Status != store.TrafficActionSucceeded {
			t.Fatalf("event action=%#v", event.Action)
		}
	}
	if response.Stats["agent_attributed_events"] != 2 || response.Stats["action_attributed_events"] != 2 ||
		response.Stats["attribution_coverage_pct"] != 100 || response.Stats["action_coverage_pct"] != 100 ||
		response.Stats["unresolved_action_refs"] != 0 {
		t.Fatalf("attribution stats=%#v", response.Stats)
	}
}

func TestCausalFlowActionIDsAreScopedByAgent(t *testing.T) {
	start := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	events := []causalFlowEvent{
		{ID: 1, Method: "GET", URL: "https://example.test/a", Host: "example.test", Path: "/a", IsAPI: true, SourceAgent: "navigator", SourceActionID: 7, capturedTime: start},
		{ID: 2, Method: "GET", URL: "https://example.test/b", Host: "example.test", Path: "/b", IsAPI: true, SourceAgent: "auth", SourceActionID: 7, capturedTime: start.Add(5 * time.Second)},
	}
	if links := buildCausalFlowLinks(events); len(links) != 0 {
		t.Fatalf("cross-agent action IDs linked: %#v", links)
	}
	events[1].SourceAgent = "navigator"
	links := buildCausalFlowLinks(events)
	if len(links) != 1 || links[0].Type != "agent-action" {
		t.Fatalf("same-agent action IDs did not link: %#v", links)
	}
}

func TestCausalFlowInferenceDoesNotChainRoutineAPIReadsOrCookieRefreshes(t *testing.T) {
	start := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	events := make([]causalFlowEvent, 5)
	for index := range events {
		events[index] = causalFlowEvent{
			ID: int64(index + 1), Method: "GET", URL: "https://example.test/api/read", Host: "example.test",
			Path: "/api/read", HasAuth: true, IsAPI: true, capturedTime: start.Add(time.Duration(index) * 50 * time.Millisecond),
			responseHeader: `{"Set-Cookie":"tracking=refreshed"}`,
		}
	}
	if links := buildCausalFlowLinks(events); len(links) != 0 {
		t.Fatalf("routine API reads formed causal links: %#v", links)
	}

	events[1].Method = "POST"
	links := buildCausalFlowLinks(events)
	if len(links) != 2 || links[0].Type != "temporal-sequence" || links[1].Type != "temporal-sequence" {
		t.Fatalf("state-changing transition links=%#v", links)
	}
}

func requestCausalFlows(t *testing.T, s *Server, target string) causalFlowResponse {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	s.handleCausalFlows(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response causalFlowResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}
