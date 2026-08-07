package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestAppendStrategistArgsPreservesOmittedAndExplicitDisable(t *testing.T) {
	zero := 0
	negative := -1
	period := 90
	tests := []struct {
		name   string
		model  string
		period *int
		want   []string
	}{
		{name: "omitted uses CLI default", want: []string{"scan"}},
		{name: "explicit zero disables", period: &zero, want: []string{"scan", "--strategist-period=0"}},
		{name: "negative uses CLI default", period: &negative, want: []string{"scan"}},
		{name: "override model and cadence", model: "qwen2.5:14b", period: &period, want: []string{"scan", "--strategist-model=qwen2.5:14b", "--strategist-period=90"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendStrategistArgs([]string{"scan"}, tt.model, tt.period)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("appendStrategistArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNarrationsLatestReturnsNewestBoundedTail(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "narrations-latest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 7; i++ {
		if _, err := db.InsertNarration(scanID, "navigator", "plan", fmt.Sprintf("event-%d", i), "", nil); err != nil {
			t.Fatal(err)
		}
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/narrations?scan_id=%d&latest=1&limit=2", scanID), nil)
	s.handleNarrations(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got []store.Narration
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Message != "event-6" || got[1].Message != "event-7" {
		t.Fatalf("latest narrations = %+v", got)
	}
}

func TestSafeReconRouteLabelKeepsPageIdentityWithoutQueryData(t *testing.T) {
	for raw, want := range map[string]string{
		"inside_jobs.htm":       "jobs",
		"pages/privacy.html":    "privacy",
		"account-settings.aspx": "account settings",
	} {
		got, ok := safeReconRouteLabel(raw)
		if !ok || got != want {
			t.Fatalf("safeReconRouteLabel(%q)=(%q,%v), want (%q,true)", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"", "user@example.test", "token=secret", "callback?code=secret"} {
		if got, ok := safeReconRouteLabel(raw); ok {
			t.Fatalf("sensitive/non-route value %q exposed as %q", raw, got)
		}
	}
}

func TestReconQueryRoutesRequireDistinctResponseBackedViews(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "query-routes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://demo.example.test/", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	jobs := `<html><head><title>Jobs</title></head><body><main><h1>Jobs</h1><table><tr><td>Engineer</td></tr></table></main></body></html>`
	privacy := `<html><head><title>Privacy</title></head><body><main><h1>Privacy</h1><article>Customer information handling policy.</article></main></body></html>`
	for _, fixture := range []struct{ query, body string }{
		{"content=inside_jobs.htm", jobs},
		{"content=careers.htm", jobs}, // response-equivalent alias
		{"content=privacy.htm", privacy},
	} {
		if _, err := db.Conn().Exec(`INSERT INTO traffic(scan_id,method,url,host,path,query,status_code,content_type,response_body) VALUES (?,'GET',?,'demo.example.test','/index.jsp',?,200,'text/html',?)`,
			scanID, "https://demo.example.test/index.jsp?"+fixture.query, fixture.query, []byte(fixture.body)); err != nil {
			t.Fatal(err)
		}
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	got := s.reconQueryRoutes(scanID)
	if len(got) != 2 || got[0].Label != "jobs" || got[0].Aliases != 1 || got[1].Label != "privacy" {
		t.Fatalf("query routes = %+v", got)
	}
	if got[0].EvidenceID <= 0 || got[1].EvidenceID <= 0 {
		t.Fatalf("query routes omitted representative traffic evidence: %+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), ".htm") || strings.Contains(string(encoded), "inside_") {
		t.Fatalf("raw query route leaked to UI: %s", encoded)
	}
}

func TestReconClientRoutesExposeDirectNavigatorEvidence(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "client-routes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://spa.example.test/", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InsertDiscovery(scanID, store.Discovery{
		TargetURL: "https://spa.example.test/#/login", SourceURL: "https://spa.example.test/",
		Kind: store.DiscoveryNavigator, Detail: "browser visit",
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	got := s.reconClientRoutes(scanID)
	if len(got) != 1 || got[0].Label != "login" || got[0].URL != "https://spa.example.test/#/login" || got[0].EvidenceID <= 0 {
		t.Fatalf("client routes = %+v", got)
	}

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/discovery/%d?scan_id=%d", got[0].EvidenceID, scanID), nil)
	w := httptest.NewRecorder()
	s.handleDiscoveryDetail(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("discovery detail status=%d body=%s", w.Code, w.Body.String())
	}
	var detail store.Discovery
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.ID != got[0].EvidenceID || detail.Kind != store.DiscoveryNavigator || detail.TargetURL != got[0].URL {
		t.Fatalf("discovery detail = %+v", detail)
	}

	otherScanID, err := db.CreateScan("https://other.example.test/", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/discovery/%d?scan_id=%d", got[0].EvidenceID, otherScanID), nil)
	w = httptest.NewRecorder()
	s.handleDiscoveryDetail(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-scan discovery detail status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestTrafficDetailRequiresMatchingScan(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "traffic-detail-scope.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanA, err := db.CreateScan("https://a.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	scanB, err := db.CreateScan("https://b.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	trafficID, err := db.InsertTraffic(scanA, &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  http.MethodGet,
			URL:     "https://a.example.test/private",
			Headers: map[string]string{"Authorization": "Bearer scan-a-secret"},
		},
		Response: types.CapturedResponse{
			StatusCode:  http.StatusOK,
			Headers:     map[string]string{"Content-Type": "application/json"},
			ContentType: "application/json",
			Body:        []byte(`{"scan":"a","secret":"only-a"}`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	path := fmt.Sprintf("/api/traffic/%d?scan_id=%d", trafficID, scanA)
	w := httptest.NewRecorder()
	s.handleTrafficDetail(w, httptest.NewRequest(http.MethodGet, path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("same-scan traffic detail status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "only-a") {
		t.Fatalf("same-scan traffic detail omitted captured body: %s", w.Body.String())
	}

	path = fmt.Sprintf("/api/traffic/%d?scan_id=%d", trafficID, scanB)
	w = httptest.NewRecorder()
	s.handleTrafficDetail(w, httptest.NewRequest(http.MethodGet, path, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-scan traffic detail status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "only-a") || strings.Contains(w.Body.String(), "scan-a-secret") {
		t.Fatalf("cross-scan traffic detail leaked scan A data: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	s.handleTrafficDetail(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/traffic/%d", trafficID), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("traffic detail without scan_id status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestReconGraphProjectsRolesWorkflowsPagesAndObjects(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "recon-graph.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	u := extract.NewAppUnderstanding()
	u.Recon.Pages = []extract.PagePurposeCard{{ID: "POST /orders", Method: "POST", URL: "https://app.example.test/orders", Purpose: "Place order", ObjectIDs: []string{"order"}, Confidence: .8}}
	u.Recon.Roles = []extract.ReconRole{{ID: "customer", Name: "Customer", Confidence: .8}}
	u.Recon.Objects = []extract.BusinessObject{{ID: "order", Name: "Order", Confidence: .8, Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "POST /orders"}}}}
	u.Recon.Workflows = []extract.BusinessWorkflow{{ID: "checkout", Name: "Checkout", Confidence: .8, Steps: []extract.WorkflowStep{{ID: "place", Label: "Place order", PageIDs: []string{"POST /orders"}, RoleIDs: []string{"customer"}, ObjectIDs: []string{"order"}, StateChange: true}}}}
	u.NormalizeReconModel()
	if err := db.UpsertReconModel(scanID, u.ReconJSON()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodPost, URL: "https://app.example.test/orders"},
		Response: types.CapturedResponse{
			StatusCode: http.StatusOK, Headers: map[string]string{}, ContentType: "text/html",
			Body: []byte("<main>Order created</main>"),
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://app.example.test/"},
		Response: types.CapturedResponse{
			StatusCode: http.StatusOK, Headers: map[string]string{}, ContentType: "text/html",
			Body: []byte("<main>Store home</main>"),
		},
	}); err != nil {
		t.Fatal(err)
	}
	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/recon-graph?scan_id=%d", scanID), nil)
	s.handleReconGraph(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Nodes []struct {
			Kind string `json:"kind"`
		} `json:"nodes"`
		Edges []struct {
			Kind string `json:"kind"`
		} `json:"edges"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Nodes) != 4 {
		t.Fatalf("nodes=%d body=%s", len(got.Nodes), w.Body.String())
	}
	kinds := map[string]bool{}
	for _, e := range got.Edges {
		kinds[e.Kind] = true
	}
	for _, want := range []string{"performs", "step", "changes", "operates_on"} {
		if !kinds[want] {
			t.Fatalf("missing %s edge: %s", want, w.Body.String())
		}
	}
}

func TestReconGraphRemovesSemanticsSupportedOnlyByUnverifiedRoute(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "recon-graph-unverified.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	const pageID = "GET /admin"
	u := extract.NewAppUnderstanding()
	u.Recon.Pages = []extract.PagePurposeCard{{
		ID: pageID, Method: http.MethodGet, URL: "https://app.example.test/admin",
		Purpose: "Administrative dashboard", ObjectIDs: []string{"tenant"}, Confidence: .95,
	}}
	u.Recon.Roles = []extract.ReconRole{{
		ID: "admin", Name: "Administrator", Confidence: .9,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: pageID}},
	}}
	u.Recon.Objects = []extract.BusinessObject{{
		ID: "tenant", Name: "Tenant", Confidence: .9,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: pageID}},
	}}
	u.Recon.Workflows = []extract.BusinessWorkflow{{
		ID: "administration", Name: "Administration", Confidence: .9,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: pageID}},
		Steps:    []extract.WorkflowStep{{ID: "open", Label: "Open admin", PageIDs: []string{pageID}, RoleIDs: []string{"admin"}, ObjectIDs: []string{"tenant"}}},
	}}
	u.NormalizeReconModel()
	if err := db.UpsertReconModel(scanID, u.ReconJSON()); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: pageID, URL: "https://app.example.test/admin", Method: http.MethodGet,
		Purpose: "Administrative dashboard", Confidence: .95,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://app.example.test/admin"},
		Response: types.CapturedResponse{StatusCode: http.StatusFound, Headers: map[string]string{
			"Location": "/auth/login?redirect=%2Fadmin",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleReconGraph(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/recon-graph?scan_id=%d", scanID), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Nodes []struct {
			Kind  string `json:"kind"`
			Label string `json:"label"`
		} `json:"nodes"`
		Edges []any `json:"edges"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, node := range got.Nodes {
		if node.Kind == "role" || node.Kind == "object" || node.Kind == "workflow" || strings.Contains(strings.ToLower(node.Label), "administrative dashboard") {
			t.Fatalf("unverified route leaked semantic graph node %+v: %s", node, w.Body.String())
		}
	}
	if len(got.Edges) != 0 {
		t.Fatalf("unverified-only graph retained semantic edges: %s", w.Body.String())
	}
}

func TestOrphanProfileEvidenceCeilingReachesUnderstandingBrainAndSemanticGraph(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "orphan-semantic-surfaces.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	const pageID = "GET /admin"
	const adminURL = "https://app.example.test/admin"
	u := extract.NewAppUnderstanding()
	u.AppType = "partner_portal"
	u.Summary = "Administrators use the administrative console to approve tenant records."
	u.Recon.Identity.Summary = u.Summary
	u.Recon.Pages = []extract.PagePurposeCard{{
		ID: pageID, Method: http.MethodGet, URL: adminURL,
		Purpose: "Administrative console", Area: "admin", AuthRequired: "required",
		ObjectIDs: []string{"tenant"}, SecurityInterest: []string{"privileged approvals"}, Confidence: .95,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: pageID}},
	}}
	u.Recon.Roles = []extract.ReconRole{{
		ID: "administrator", Name: "Administrator", Confidence: .9,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: pageID}},
	}}
	u.Recon.Objects = []extract.BusinessObject{{
		ID: "tenant", Name: "Tenant record", Confidence: .9,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: pageID}},
	}}
	u.Recon.Workflows = []extract.BusinessWorkflow{{
		ID: "tenant_approval", Name: "Tenant approval", Confidence: .9,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: pageID}},
		Steps:    []extract.WorkflowStep{{ID: "approve", Label: "Approve tenant", PageIDs: []string{pageID}, RoleIDs: []string{"administrator"}, ObjectIDs: []string{"tenant"}, StateChange: true}},
	}}
	u.NormalizeReconModel()
	if err := db.UpsertAppUnderstanding(scanID, u.AppType, "[]", "[]", "{}", u.Summary); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertReconModel(scanID, u.ReconJSON()); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: pageID, URL: adminURL, Method: http.MethodGet,
		Purpose: "Administrative console", AuthRequired: "required", Confidence: .95,
		DataExposed: []string{"tenant records"}, Behaviors: []string{"approves tenants"},
	}); err != nil {
		t.Fatal(err)
	}
	// Keep the target globally available while leaving /admin itself without a
	// matching direct response. This proves the route-level ceiling, rather than
	// accidentally passing because the whole scan was access-capped.
	for _, path := range []string{"/", "/about"} {
		if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
			Request:  types.CapturedRequest{Method: http.MethodGet, URL: "https://app.example.test" + path},
			Response: types.CapturedResponse{StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte("<main>Public page</main>")},
		}); err != nil {
			t.Fatal(err)
		}
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	checks := []struct {
		name string
		path string
		call func(http.ResponseWriter, *http.Request)
	}{
		{name: "Understanding", path: "/api/understanding", call: s.handleUnderstanding},
		{name: "Target Brain", path: "/api/target-brain", call: s.handleTargetBrain},
		{name: "semantic Graph", path: "/api/recon-graph", call: s.handleReconGraph},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			check.call(w, httptest.NewRequest(http.MethodGet,
				fmt.Sprintf("%s?scan_id=%d", check.path, scanID), nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			body := w.Body.String()
			for _, stale := range []string{"Administrative console", "Tenant approval", `"label":"Administrator"`, `"label":"Tenant record"`} {
				if strings.Contains(body, stale) {
					t.Fatalf("%s retained orphan-backed semantic %q: %s", check.name, stale, body)
				}
			}
			if !strings.Contains(body, "No matching direct HTTP response") {
				t.Fatalf("%s omitted orphan evidence verdict: %s", check.name, body)
			}
		})
	}
}

func TestValidateRequestedScope(t *testing.T) {
	if err := validateRequestedScope("https://www.example.com", true, []string{
		"https://api.example.net",
		"*.staging.example.com",
	}); err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}
	if err := validateRequestedScope("https://www.example.com", false, []string{
		"https://*.localhost",
	}); err == nil {
		t.Fatal("malformed wildcard scope unexpectedly accepted")
	}
	if err := validateRequestedScope("https://*.example.com", true, nil); err == nil || !strings.Contains(err.Error(), "start URL") {
		t.Fatalf("wildcard target error = %v", err)
	}
	if err := validateRequestedScope("http://127.0.0.1:4280", true, nil); err != nil {
		t.Fatalf("IP literal should stay exact when Smart discovery is requested: %v", err)
	}
}

func TestNormalizeScanStartTargetDisablesSmartDiscoveryForIPLiteral(t *testing.T) {
	req := scanStartRequest{Target: "127.0.0.1:4280", IncludeSubdomains: true}
	if err := normalizeScanStartTarget(&req); err != nil {
		t.Fatal(err)
	}
	if req.Target != "https://127.0.0.1:4280" {
		t.Fatalf("target = %q", req.Target)
	}
	if req.IncludeSubdomains {
		t.Fatal("IP literal retained Smart discovery")
	}
}

func TestNormalizeScanStartTargetConvertsWildcardToSeedAndScope(t *testing.T) {
	req := scanStartRequest{Target: "*.example.com"}
	if err := normalizeScanStartTarget(&req); err != nil {
		t.Fatal(err)
	}
	if req.Target != "https://example.com" {
		t.Fatalf("target = %q", req.Target)
	}
	want := []string{"https://*.example.com"}
	if !reflect.DeepEqual(req.Scope, want) {
		t.Fatalf("scope = %#v, want %#v", req.Scope, want)
	}
	if err := validateRequestedScope(req.Target, false, req.Scope); err != nil {
		t.Fatalf("normalized wildcard request rejected: %v", err)
	}
}

func TestNormalizeScanStartTargetDoesNotDuplicateWildcardScope(t *testing.T) {
	req := scanStartRequest{
		Target: "https://*.example.com",
		Scope:  []string{"HTTPS://*.EXAMPLE.COM"},
	}
	if err := normalizeScanStartTarget(&req); err != nil {
		t.Fatal(err)
	}
	if len(req.Scope) != 1 {
		t.Fatalf("scope = %#v", req.Scope)
	}
}

func TestRepeaterUsesPersistedTestingAuthority(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewServer(db, t.TempDir(), "127.0.0.1:0", logger)

	for _, tt := range []struct {
		name      string
		authority policy.TestingAuthority
		method    string
		wantCode  int
		wantHit   bool
	}{
		{"recon blocks POST", policy.AuthorityRecon, http.MethodPost, http.StatusForbidden, false},
		{"active permits POST", policy.AuthorityActive, http.MethodPost, http.StatusOK, true},
		{"active blocks DELETE", policy.AuthorityActive, http.MethodDelete, http.StatusForbidden, false},
		{"full control permits DELETE", policy.AuthorityFullControl, http.MethodDelete, http.StatusOK, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := `{"Scan":{"testing_authority":"` + string(tt.authority) + `"}}`
			scanID, err := db.CreateScan(target.URL, config)
			if err != nil {
				t.Fatal(err)
			}
			before := hits.Load()
			body, _ := json.Marshal(map[string]string{
				"target_url":  target.URL + "/resource",
				"raw_request": tt.method + " /resource HTTP/1.1\r\n\r\n",
			})
			req := httptest.NewRequest(http.MethodPost,
				fmt.Sprintf("/api/repeater?scan_id=%d", scanID), strings.NewReader(string(body)))
			w := httptest.NewRecorder()
			s.handleRepeater(w, req)
			if w.Code != tt.wantCode {
				t.Fatalf("status = %d body=%s, want %d", w.Code, w.Body.String(), tt.wantCode)
			}
			wantHits := before
			if tt.wantHit {
				wantHits++
			}
			if hits.Load() != wantHits {
				t.Fatalf("server hits = %d, want %d", hits.Load(), wantHits)
			}
			if !tt.wantHit {
				narrations, err := db.GetNarrations(scanID, 0, 10)
				if err != nil || len(narrations) != 1 || narrations[0].Agent != "policy" {
					t.Fatalf("policy narrations = (%+v, %v)", narrations, err)
				}
			}
		})
	}
}

func TestScreenshotCaptureRejectsOffScopeBeforeBrowserLaunch(t *testing.T) {
	var hits atomic.Int32
	offScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer offScope.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://owned.example.test",
		`{"Scan":{"testing_authority":"full_control"}}`)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/screenshot?scan_id=%d&url=%s", scanID, url.QueryEscape(offScope.URL)), nil)
	s.handleScreenshotCapture(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), string(policy.CodeOutOfScope)) {
		t.Fatalf("response = %d %s", w.Code, w.Body.String())
	}
	if hits.Load() != 0 {
		t.Fatalf("off-scope screenshot target received %d request(s)", hits.Load())
	}
	narrations, err := db.GetNarrations(scanID, 0, 10)
	if err != nil || len(narrations) != 1 || narrations[0].Agent != "policy" {
		t.Fatalf("policy narrations = (%+v, %v)", narrations, err)
	}
}

func TestScreenshotCaptureReturnsRedirectEvidenceInsteadOfMisleadingPage(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const targetURL = "https://partner.example.test/admin"
	scanID, err := db.CreateScan("https://partner.example.test", `{"Scan":{"testing_authority":"full_control"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: targetURL},
		Response: types.CapturedResponse{StatusCode: http.StatusFound, Headers: map[string]string{
			"Location": "/account/logout?redirect=%2Fadmin",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	outputDir := t.TempDir()
	screenshotDir := filepath.Join(outputDir, "screenshots")
	if err := os.MkdirAll(screenshotDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A stale cached image must not bypass the evidence guard.
	filename := screenshotCacheFilename(scanID, targetURL)
	if err := os.WriteFile(filepath.Join(screenshotDir, filename), []byte("misleading cached page"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, outputDir, "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/screenshot?scan_id=%d&url=%s", scanID, url.QueryEscape(targetURL)), nil)
	s.handleScreenshotCapture(w, req)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "auth_gate_unverified") {
		t.Fatalf("response = %d %s", w.Code, w.Body.String())
	}
}

func TestScreenshotCaptureWithholdsEveryKnownNonContentResponseClass(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		wantField   string
	}{
		{name: "negative status", status: http.StatusNotFound, contentType: "text/html", body: `<h1>Page not found</h1>`},
		{name: "server error", status: http.StatusInternalServerError, contentType: "text/html", body: `<h1>Internal server error</h1>`},
		{name: "empty success", status: http.StatusOK, contentType: "text/html", body: " \n\t ", wantField: "empty_success"},
		{name: "authentication shell", status: http.StatusOK, contentType: "text/html", body: `<html><head><title>Login</title></head><body><form><input type="password"></form></body></html>`, wantField: "authentication_shell"},
		{name: "error shell", status: http.StatusOK, contentType: "text/html", body: `<html><head><title>404 Page not found</title></head><body><h1>Page not found</h1></body></html>`, wantField: "error_shell"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			const targetURL = "https://partner.example.test/admin"
			scanID, err := db.CreateScan("https://partner.example.test", `{"Scan":{"testing_authority":"full_control"}}`)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
				Request: types.CapturedRequest{Method: http.MethodGet, URL: targetURL},
				Response: types.CapturedResponse{
					StatusCode: tt.status, Headers: map[string]string{},
					ContentType: tt.contentType, Body: []byte(tt.body),
				},
			}); err != nil {
				t.Fatal(err)
			}

			s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet,
				fmt.Sprintf("/api/screenshot?scan_id=%d&url=%s", scanID, url.QueryEscape(targetURL)), nil)
			s.handleScreenshotCapture(w, req)
			if w.Code != http.StatusConflict {
				t.Fatalf("response = %d %s", w.Code, w.Body.String())
			}
			var payload map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload["evidence_state"] != "response_unverified" || payload["requested_url"] != targetURL {
				t.Fatalf("unexpected evidence payload: %#v", payload)
			}
			if tt.wantField != "" && payload[tt.wantField] != true {
				t.Fatalf("%s marker missing from payload: %#v", tt.wantField, payload)
			}
		})
	}
}

func TestScreenshotCaptureWithholdsKnownProfileWithoutDirectResponse(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const targetURL = "https://partner.example.test/admin"
	scanID, err := db.CreateScan("https://partner.example.test", `{"Scan":{"testing_authority":"full_control"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: "GET /admin", URL: targetURL, Method: http.MethodGet,
		Purpose: "Administrative console", AuthRequired: "required", Confidence: .95,
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleScreenshotCapture(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/screenshot?scan_id=%d&url=%s", scanID, url.QueryEscape(targetURL)), nil))
	if w.Code != http.StatusConflict {
		t.Fatalf("response = %d %s", w.Code, w.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["evidence_state"] != "response_unverified" || payload["requested_url"] != targetURL ||
		!strings.Contains(fmt.Sprint(payload["evidence_note"]), "No matching direct HTTP response") {
		t.Fatalf("unexpected orphan-profile screenshot verdict: %#v", payload)
	}
}

func TestScreenshotEvidenceDoesNotLiftSiblingQuerySpecimen(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request:  types.CapturedRequest{Method: http.MethodGet, URL: "https://app.example.test/view?id=1"},
			Response: types.CapturedResponse{StatusCode: http.StatusOK, Body: []byte("record one")},
		},
		{
			Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://app.example.test/view?id=2"},
			Response: types.CapturedResponse{
				StatusCode: http.StatusFound, Headers: map[string]string{"Location": "/login"},
			},
		},
	}
	if observation.EndpointHash(http.MethodGet, entries[0].Request.URL) != observation.EndpointHash(http.MethodGet, entries[1].Request.URL) {
		t.Fatal("test setup requires endpoint identity to collapse query values")
	}
	got := exactGETEvidenceForURL(entries, "https://APP.example.test:443/view?id=2")
	if len(got) != 1 || got[0].Request.URL != entries[1].Request.URL {
		t.Fatalf("exact screenshot evidence = %+v", got)
	}
	if state := directResponseEvidenceState(observation.SummarizeRedirectEvidence(got)); state != "redirect_only_unverified" {
		t.Fatalf("sibling content lifted redirect specimen: %s", state)
	}
}

func TestHistoricalPathOnlyProfileFailsClosedAcrossOrigins(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "legacy-profile-origins.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://partner.example.test/", `{}`)
	for _, rawURL := range []string{"https://partner.example.test/", "https://academy.example.test/"} {
		entry := &types.TrafficEntry{
			Request: types.CapturedRequest{Method: http.MethodGet, URL: rawURL},
			Response: types.CapturedResponse{
				StatusCode: http.StatusOK, ContentType: "text/html",
				Body: []byte(`<html><title>Portal</title><body>Substantive landing content</body></html>`),
			},
		}
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}
	profile := &types.PageProfile{
		ID: "GET /", URL: "https://partner.example.test/", Method: http.MethodGet,
		Purpose: "Academy landing page", Confidence: .92,
	}
	if err := db.UpsertProfile(scanID, profile); err != nil {
		t.Fatal(err)
	}
	profiles, err := db.GetAllProfiles(scanID)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.annotateProfilesWithEvidence(scanID, profiles)
	if len(profiles) != 1 || profiles[0].EvidenceState != "response_unverified" ||
		!strings.Contains(profiles[0].EvidenceNote, "collides across origins") ||
		strings.Contains(profiles[0].Purpose, "Academy") {
		t.Fatalf("legacy cross-origin profile retained borrowed semantics: %+v", profiles)
	}
}

func TestProfileMatchingObservedNegativeControlShellFailsClosed(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "catch-all-shell.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://app.example.test/", `{}`)
	const shell = `<html><title>Partner portal</title><body><div id="app"></div><script src="/app.js"></script></body></html>`
	for _, path := range []string{"/admin", "/adminasdasd"} {
		entry := &types.TrafficEntry{
			Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://app.example.test" + path},
			Response: types.CapturedResponse{
				StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte(shell), Size: int64(len(shell)),
			},
		}
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: "GET /admin", URL: "https://app.example.test/admin", Method: http.MethodGet,
		Purpose: "Administrative console", Confidence: .94,
	}); err != nil {
		t.Fatal(err)
	}
	profiles, err := db.GetAllProfiles(scanID)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.annotateProfilesWithEvidence(scanID, profiles)
	if len(profiles) != 1 || profiles[0].EvidenceState != "response_unverified" ||
		!strings.Contains(profiles[0].EvidenceNote, "negative-control route /adminasdasd") ||
		strings.Contains(profiles[0].Purpose, "Administrative") {
		t.Fatalf("shared catch-all shell verified route semantics: %+v", profiles)
	}

	// Knowledge detail used to re-run only the single-route redirect classifier
	// and thereby re-promote the same profile that the card list had rejected.
	detailW := httptest.NewRecorder()
	s.handleEndpointDetail(detailW, httptest.NewRequest(http.MethodGet, fmt.Sprintf(
		"/api/endpoint/detail?scan_id=%d&hash=%s&profile_id=%s",
		scanID, url.QueryEscape(observation.EndpointHash(http.MethodGet, "https://app.example.test/admin")), url.QueryEscape("GET /admin"),
	), nil))
	if detailW.Code != http.StatusOK {
		t.Fatalf("Knowledge detail status=%d body=%s", detailW.Code, detailW.Body.String())
	}
	var detail struct {
		EvidenceState string `json:"evidence_state"`
		EvidenceNote  string `json:"evidence_note"`
		Profile       struct {
			EvidenceState string `json:"evidence_state"`
			Purpose       string `json:"purpose"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(detailW.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.EvidenceState != "response_unverified" || detail.Profile.EvidenceState != "response_unverified" ||
		!strings.Contains(detail.EvidenceNote, "/adminasdasd") || strings.Contains(detail.Profile.Purpose, "Administrative") {
		t.Fatalf("Knowledge detail re-promoted shared shell: %+v", detail)
	}

	// The action endpoint must reject from persisted evidence before launching
	// Chromium, even though the direct response by itself is a non-empty 200.
	screenshotW := httptest.NewRecorder()
	s.handleScreenshotCapture(screenshotW, httptest.NewRequest(http.MethodGet, fmt.Sprintf(
		"/api/screenshot?scan_id=%d&url=%s", scanID, url.QueryEscape("https://app.example.test/admin"),
	), nil))
	if screenshotW.Code != http.StatusConflict || !strings.Contains(screenshotW.Body.String(), "catch-all shell") {
		t.Fatalf("catch-all screenshot action = %d %s", screenshotW.Code, screenshotW.Body.String())
	}

	// Graph traffic-only/method projection shares the same verdict instead of
	// treating the path name as an interesting administrative route.
	graphW := httptest.NewRecorder()
	s.handleDiscoveryGraph(graphW, httptest.NewRequest(http.MethodGet, fmt.Sprintf(
		"/api/discovery-graph?scan_id=%d&max_nodes=0&scope=in", scanID,
	), nil))
	if graphW.Code != http.StatusOK {
		t.Fatalf("Graph status=%d body=%s", graphW.Code, graphW.Body.String())
	}
	var graph struct {
		Nodes []discoveryGraphNodeMeta `json:"nodes"`
	}
	if err := json.Unmarshal(graphW.Body.Bytes(), &graph); err != nil {
		t.Fatal(err)
	}
	foundAdmin := false
	for _, node := range graph.Nodes {
		if node.Path != "/admin" {
			continue
		}
		foundAdmin = true
		if node.EvidenceState != "response_unverified" || node.FunctionalArea != "unverified" ||
			node.Interesting || node.HasIssues || len(node.MethodEvidence) != 1 ||
			node.MethodEvidence[0].State != "response_unverified" {
			t.Fatalf("Graph re-promoted shared shell: %+v", node)
		}
	}
	if !foundAdmin {
		t.Fatalf("Graph omitted /admin: %+v", graph.Nodes)
	}
}

func TestScreenshotEvidenceCacheIsScanScopedAndRejectsEmptyRender(t *testing.T) {
	const targetURL = "https://example.test/page"
	if screenshotCacheFilename(1, targetURL) == screenshotCacheFilename(2, targetURL) {
		t.Fatal("screenshot cache key was shared across scans")
	}
	encode := func(img image.Image) []byte {
		t.Helper()
		var out bytes.Buffer
		if err := png.Encode(&out, img); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	white := image.NewRGBA(image.Rect(0, 0, 100, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 100; x++ {
			white.Set(x, y, color.White)
		}
	}
	if !browserScreenshotLooksEmpty(encode(white)) {
		t.Fatal("all-white render was accepted as page evidence")
	}
	for y := 20; y < 40; y++ {
		for x := 20; x < 80; x++ {
			white.Set(x, y, color.Black)
		}
	}
	if browserScreenshotLooksEmpty(encode(white)) {
		t.Fatal("visible sparse content was rejected as an empty render")
	}
}

func TestExecutionPolicyForScanUsesPersistedWildcardScope(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const target = "https://www.example.com/"
	scanID, err := db.CreateScan(target, `{
		"Scan": {
			"Scope": ["https://www.example.com/", "https://*.example.com"],
			"testing_authority": "full_control"
		}
	}`)
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	engine, credentialOrigin, err := s.executionPolicyForScan(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if credentialOrigin != target {
		t.Fatalf("credential origin = %q, want %q", credentialOrigin, target)
	}

	for _, targetURL := range []string{
		"https://www.example.com/account",
		"https://api-service.example.com:443/v1/features/saml-status",
	} {
		decision := engine.Authorize(policy.Action{TargetURL: targetURL, Method: http.MethodGet})
		if !decision.Allowed {
			t.Errorf("%s denied: code=%s reason=%s", targetURL, decision.Code, decision.Reason)
		}
	}

	decision := engine.Authorize(policy.Action{
		TargetURL: "https://api-service.example.com.evil.test/",
		Method:    http.MethodGet,
	})
	if decision.Allowed || decision.Code != policy.CodeOutOfScope {
		t.Fatalf("lookalike origin decision = %+v, want out_of_scope", decision)
	}
}

func TestScreenshotCaptureAllowsPersistedWildcardScopeWithExplicitHTTPSPort(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const targetURL = "https://api-service.example.com:443/v1/features/saml-status"
	scanID, err := db.CreateScan("https://www.example.com/", `{
		"Scan": {
			"Scope": ["https://www.example.com/", "https://*.example.com"],
			"testing_authority": "full_control"
		}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: targetURL},
		Response: types.CapturedResponse{
			StatusCode: http.StatusOK, ContentType: "text/html",
			Body: []byte(`<html><title>SAML status</title><body>Feature status page</body></html>`),
		},
	}); err != nil {
		t.Fatal(err)
	}

	outputDir := t.TempDir()
	screenshotDir := filepath.Join(outputDir, "screenshots")
	if err := os.MkdirAll(screenshotDir, 0o755); err != nil {
		t.Fatal(err)
	}
	filename := screenshotCacheFilename(scanID, targetURL)
	if err := os.WriteFile(filepath.Join(screenshotDir, filename), []byte("cached screenshot"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, outputDir, "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/screenshot?scan_id=%d&url=%s", scanID, url.QueryEscape(targetURL)), nil)
	s.handleScreenshotCapture(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("response = %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"cached":true`) {
		t.Fatalf("response did not use cached screenshot: %s", w.Body.String())
	}
}

func TestResolveAndAppendTestingAuthority(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    policy.TestingAuthority
		wantErr bool
	}{
		{name: "omitted", want: policy.AuthorityActive},
		{name: "recon", raw: "recon", want: policy.AuthorityRecon},
		{name: "active", raw: "active", want: policy.AuthorityActive},
		{name: "full control", raw: "full_control", want: policy.AuthorityFullControl},
		{name: "invalid", raw: "full", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authority, err := resolveTestingAuthority(tt.raw)
			if (err != nil) != tt.wantErr || authority != tt.want {
				t.Fatalf("resolveTestingAuthority(%q) = (%q, %v), want (%q, err=%v)",
					tt.raw, authority, err, tt.want, tt.wantErr)
			}
			if err == nil {
				got := appendTestingAuthorityArg([]string{"scan"}, authority)
				want := []string{"scan", "--testing-authority=" + string(tt.want)}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("appendTestingAuthorityArg() = %v, want %v", got, want)
				}
			}
		})
	}
}

func TestUIScanAnalysisLimitIsAdaptiveAndKeepsActiveVerificationReachable(t *testing.T) {
	for _, tt := range []struct {
		authority policy.TestingAuthority
		pages     int
		want      string
	}{
		{authority: policy.AuthorityActive, pages: 3, want: "--analysis-endpoint-limit=8"},
		{authority: policy.AuthorityActive, pages: 20, want: "--analysis-endpoint-limit=8"},
		{authority: policy.AuthorityFullControl, pages: 100, want: "--analysis-endpoint-limit=8"},
		{authority: policy.AuthorityActive, pages: 0, want: "--analysis-endpoint-limit=8"},
	} {
		got := appendUIScanAnalysisLimit([]string{"scan"}, tt.authority, tt.pages)
		if len(got) != 2 || got[1] != tt.want {
			t.Fatalf("authority=%s pages=%d args=%v, want %s", tt.authority, tt.pages, got, tt.want)
		}
	}
	for _, tt := range []struct {
		pages int
		want  string
	}{
		{pages: 1, want: "--analysis-endpoint-limit=8"},
		{pages: 3, want: "--analysis-endpoint-limit=8"},
		{pages: 100, want: "--analysis-endpoint-limit=32"},
		{pages: 0, want: "--analysis-endpoint-limit=24"},
	} {
		got := appendUIScanAnalysisLimit([]string{"scan"}, policy.AuthorityRecon, tt.pages)
		if len(got) != 2 || got[1] != tt.want {
			t.Fatalf("pages=%d args=%v, want %s", tt.pages, got, tt.want)
		}
	}
}

func TestUIAdaptiveBreadthAddsConvergenceWithoutChangingBoundedScans(t *testing.T) {
	bounded := appendUIAdaptiveCrawlArgs([]string{"scan"}, 20)
	if !reflect.DeepEqual(bounded, []string{"scan"}) {
		t.Fatalf("bounded args = %v", bounded)
	}
	adaptive := appendUIAdaptiveCrawlArgs([]string{"scan"}, 0)
	want := []string{"scan", "--adaptive-crawl", "--crawl-timeout=8m"}
	if !reflect.DeepEqual(adaptive, want) {
		t.Fatalf("adaptive args = %v, want %v", adaptive, want)
	}
}

func TestAppendBOLAEnvPassesPersonaContextViaEnvironment(t *testing.T) {
	env := appendBOLAEnv([]string{"PATH=/bin"}, scanStartRequest{
		BOLAPrimaryOwner:       "1",
		BOLAPrimaryLoginURL:    "https://example.test/rest/user/login",
		BOLAPrimaryObjectURL:   "/api/orders/1",
		BOLASecondaryLoginURL:  "https://example.test/login",
		BOLASecondaryUser:      "bob@example.test",
		BOLASecondaryPass:      "bob-secret",
		BOLASecondaryOwner:     "2",
		BOLASecondaryObjectURL: "/api/orders/2",
	})
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"AOBTD_BOLA_PRIMARY_OWNER=1",
		"AOBTD_BOLA_PRIMARY_LOGIN_URL=https://example.test/rest/user/login",
		"AOBTD_BOLA_PRIMARY_OBJECT_URL=/api/orders/1",
		"AOBTD_BOLA_SECONDARY_LOGIN_URL=https://example.test/login",
		"AOBTD_BOLA_SECONDARY_USER=bob@example.test",
		"AOBTD_BOLA_SECONDARY_PASS=bob-secret",
		"AOBTD_BOLA_SECONDARY_OWNER=2",
		"AOBTD_BOLA_SECONDARY_OBJECT_URL=/api/orders/2",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("appendBOLAEnv missing %q in %v", want, env)
		}
	}
}

func TestResolveScanStartAPIKeyFallsBackToProviderEnvironment(t *testing.T) {
	t.Setenv("AOBTD_LLM_KEY", "")
	t.Setenv("OPENAI_API_KEY", "openai-secret")
	t.Setenv("ANTHROPIC_API_KEY", "anthropic-secret")
	t.Setenv("ZAI_API_KEY", "zai-secret")
	t.Setenv("MINIMAX_API_KEY", "minimax-secret")

	tests := []struct {
		provider string
		explicit string
		baseURL  string
		model    string
		want     string
	}{
		{provider: "openai", want: "openai-secret"},
		{provider: "anthropic", want: "anthropic-secret"},
		{provider: "openai-compatible", want: "zai-secret"},
		{provider: "openai-compatible", baseURL: "https://api.minimax.io/v1", model: "MiniMax-M2.7-highspeed", want: "minimax-secret"},
		{provider: "openai-compatible", baseURL: "https://api.z.ai/api/coding/paas/v4", model: "glm-4.6", want: "zai-secret"},
		{provider: "openai-compatible", explicit: "manual-secret", want: "manual-secret"},
	}
	for _, tt := range tests {
		if got := resolveScanStartAPIKey(tt.provider, tt.explicit, tt.baseURL, tt.model); got != tt.want {
			t.Fatalf("resolveScanStartAPIKey(%q, explicit=%v) = %q, want %q", tt.provider, tt.explicit != "", got, tt.want)
		}
	}
}

func TestLoadUIDotEnvLocalDoesNotOverrideExistingEnv(t *testing.T) {
	t.Setenv("ZAI_API_KEY", "already-set")
	t.Setenv("GLM_API_KEY", "")
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.local")
	if err := os.WriteFile(path, []byte("ZAI_API_KEY=from-file\nexport GLM_API_KEY='glm-from-file'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	loadUIDotEnvLocal(path)

	if got := os.Getenv("ZAI_API_KEY"); got != "already-set" {
		t.Fatalf("ZAI_API_KEY = %q, want existing env preserved", got)
	}
	if got := os.Getenv("GLM_API_KEY"); got != "glm-from-file" {
		t.Fatalf("GLM_API_KEY = %q, want value loaded from .env.local", got)
	}
}

func TestDefaultOpenAICompatibleBaseURLRoutesGLMToZAI(t *testing.T) {
	if got := defaultOpenAICompatibleBaseURL("glm-5.2"); got != "https://api.z.ai/api/coding/paas/v4" {
		t.Fatalf("GLM base URL = %q", got)
	}
	if got := defaultOpenAICompatibleBaseURL("MiniMax-M2.7-highspeed"); got != "https://api.minimax.io/v1" {
		t.Fatalf("MiniMax base URL = %q", got)
	}
}

func TestScanAPIExposesActualIncompleteReason(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan-terminal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	const reason = `final convergence stopped: empty response content from model MiniMax-M3 (finish_reason="length")`
	if _, err := db.Conn().Exec(`UPDATE scans SET status='incomplete' WHERE id=?`, scanID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertNarration(scanID, "orchestrator", "incomplete", reason, "", nil); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", nil)
	w := httptest.NewRecorder()
	s.handleScan(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/scan?scan_id=%d", scanID), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		TerminalDetail string `json:"terminal_detail"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.TerminalDetail != reason {
		t.Fatalf("terminal detail = %q, want %q", body.TerminalDetail, reason)
	}
}

func TestScanAPIExposesStreamingPipelineAndConfiguredModel(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan-pipeline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{"LLM":{"Provider":"openai-compatible","Model":"MiniMax-M3"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertNarration(scanID, "orchestrator", "phase", "Phase 1: Discovery — crawling the target.", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertNarration(scanID, "orchestrator", "streaming_analysis_start", "warm-up complete", "", nil); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", nil)
	w := httptest.NewRecorder()
	s.handleScan(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/scan?scan_id=%d", scanID), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		LLMConfigured bool `json:"llm_configured"`
		Pipeline      struct {
			Phase         string `json:"phase"`
			PhaseKey      string `json:"phase_key"`
			AnalysisState string `json:"analysis_state"`
		} `json:"pipeline"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.LLMConfigured || body.Pipeline.Phase != "Discovery + prioritized endpoint analysis" ||
		body.Pipeline.PhaseKey != "discovery_analysis" || body.Pipeline.AnalysisState != "active" {
		t.Fatalf("pipeline response = %+v", body)
	}
}

func TestHandleScanStartRejectsInvalidTestingAuthority(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/scan/start",
		strings.NewReader(`{"target":"https://example.test","testing_authority":"model_full"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	(&Server{}).handleScanStart(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid testing_authority") {
		t.Fatalf("response = %d %s, want invalid testing_authority", w.Code, w.Body.String())
	}
}

func TestScanMetadataAPIsExposePersistedTestingAuthority(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	legacyID, err := db.CreateScan("https://legacy.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	fullID, err := db.CreateScan("https://owned.example.test",
		`{"Scan":{"testing_authority":"full_control"}}`)
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", nil)
	for _, tt := range []struct {
		id   int64
		want policy.TestingAuthority
	}{
		{id: legacyID, want: policy.AuthorityActive},
		{id: fullID, want: policy.AuthorityFullControl},
	} {
		t.Run(fmt.Sprintf("scan-%d", tt.id), func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet,
				fmt.Sprintf("/api/scan?scan_id=%d", tt.id), nil)
			s.handleScan(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("handleScan status = %d body=%s", w.Code, w.Body.String())
			}
			var body struct {
				TestingAuthority policy.TestingAuthority `json:"testing_authority"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.TestingAuthority != tt.want {
				t.Fatalf("API authority = %q, want %q", body.TestingAuthority, tt.want)
			}
		})
	}

	w := httptest.NewRecorder()
	s.handleScans(w, httptest.NewRequest(http.MethodGet, "/api/scans", nil))
	var scans []struct {
		ID               int64                   `json:"id"`
		TestingAuthority policy.TestingAuthority `json:"testing_authority"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &scans); err != nil {
		t.Fatal(err)
	}
	got := map[int64]policy.TestingAuthority{}
	for _, scan := range scans {
		got[scan.ID] = scan.TestingAuthority
	}
	if got[legacyID] != policy.AuthorityActive || got[fullID] != policy.AuthorityFullControl {
		t.Fatalf("/api/scans authority metadata = %v", got)
	}
}

func TestActiveScanAPIExposesTestingAuthority(t *testing.T) {
	s := &Server{activeInfo: &activeScanInfo{
		Target:           "https://owned.example.test",
		TestingAuthority: policy.AuthorityFullControl,
		StartedAt:        time.Now(),
		PID:              42,
	}}
	w := httptest.NewRecorder()
	s.handleScanActive(w, httptest.NewRequest(http.MethodGet, "/api/scan/active", nil))
	var body struct {
		TestingAuthority policy.TestingAuthority `json:"testing_authority"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.TestingAuthority != policy.AuthorityFullControl {
		t.Fatalf("active API authority = %q", body.TestingAuthority)
	}
}

func TestMarkSpawnedScanInterruptedSurvivesCanonicalTargetChange(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldID, err := db.CreateScan("https://old.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	newID, err := db.CreateScan("https://www.example.test/canonical/path", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := markSpawnedScanInterrupted(db, oldID); err != nil {
		t.Fatal(err)
	}
	var oldStatus, newStatus string
	if err := db.Conn().QueryRow(`SELECT status FROM scans WHERE id=?`, oldID).Scan(&oldStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.Conn().QueryRow(`SELECT status FROM scans WHERE id=?`, newID).Scan(&newStatus); err != nil {
		t.Fatal(err)
	}
	if oldStatus != "running" || newStatus != "interrupted" {
		t.Fatalf("statuses old=%q new=%q", oldStatus, newStatus)
	}
}

func TestNewScanUIWiresTestingAuthoritySelector(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, want := range []string{
		`id="scanTestingAuthority"`,
		`<option value="recon">Recon Only</option>`,
		`<option value="active" selected>Active Pentest — Recommended</option>`,
		`<option value="full_control">Full Control / Owned Target</option>`,
		`testing_authority: testingAuthority`,
		`id="topAuthorityBadge"`,
		`scan.testing_authority`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("New Scan UI missing %q", want)
		}
	}
}

func TestLiveEndedStateUsesDesignedCTAButtons(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, want := range []string{
		`.live-empty-state`,
		`.live-terminal-banner`,
		`class="live-empty-status ${statusClass}"`,
		`Live browser stream is archived.`,
		`cache.scan?.terminal_detail`,
		`Why this run is incomplete`,
		`class="live-empty-action primary"`,
		`type="button" class="live-empty-action"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("Live ended UI missing %q", want)
		}
	}
	if strings.Contains(html, "Scan incomplete — convergence limit reached") {
		t.Fatal("Live ended UI still hardcodes an inaccurate convergence-limit explanation")
	}
}

func TestAILogUISurfacesFailedModelCalls(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, want := range []string{
		`function aiLogIsModelCall(e)`,
		`<div class="label">Failed Calls</div>`,
		`provider/model failures`,
		`hasMetrics ? 'unknown' : '-'`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("AI Log UI missing %q", want)
		}
	}
}

func TestStatsCarriesLightweightNavigationCounts(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "stats.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertNarration(scanID, "navigator", "visit", "Observed page", "https://app.example.test", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request:  types.CapturedRequest{Method: http.MethodGet, URL: "https://app.example.test", Headers: map[string]string{}},
		Response: types.CapturedResponse{StatusCode: http.StatusOK, Headers: map[string]string{}, ContentType: "text/html", Body: []byte("<main>app</main>")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertReconModel(scanID, `{"metrics":{"understanding_score":0.73,"targets_total":8}}`); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleStats(w, httptest.NewRequest(http.MethodGet, "/api/stats?scan_id="+stringID(scanID), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("stats status=%d body=%s", w.Code, w.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["narration_count"] != float64(1) || response["strategy_count"] != float64(0) ||
		response["changes_count"] != float64(0) || response["ai_log_count"] != float64(0) {
		t.Fatalf("navigation counts=%v", response)
	}
	if response["graph_route_count"] != float64(1) {
		t.Fatalf("canonical Graph route count=%v, want 1", response["graph_route_count"])
	}
	if response["recon_understanding_score"] != 0.73 || response["recon_targets_total"] != float64(8) {
		t.Fatalf("live Recon stats=%v targets=%v, want 0.73/8",
			response["recon_understanding_score"], response["recon_targets_total"])
	}

	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, want := range []string{"stats?.narration_count", "stats?.strategy_count", "stats?.changes_count", "stats?.ai_log_count", "stats?.recon_understanding_score"} {
		if !strings.Contains(html, want) {
			t.Fatalf("navigation badge does not use %q", want)
		}
	}
	for _, want := range []string{
		"refreshAll({runningView: true})",
		"live: ['scan','stats','endpoints','findings','aiStats']",
		"recon: ['scan','stats','endpoints','profiles','surface','understanding','aiStats']",
		"findings: ['scan','stats','endpoints','findings','surface']",
		"Number.isFinite(stats?.graph_route_count)",
		"freshView: nextView, repaint: true",
		"byView[opts.freshView || currentView]",
		"typeof stats?.recon_understanding_score === 'number'",
		"let refreshAllInFlight = null",
		"if (refreshAllInFlight && !opts.force && !opts.freshView) return refreshAllInFlight",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("view-specific refresh contract missing %q", want)
		}
	}
	if strings.Contains(html, "api('/api/discovery-graph?scope=in&stats_only=1')") {
		t.Fatal("auto-refresh still rebuilds the semantic Graph only to render its badge")
	}
	for _, heavy := range []string{"/api/narrations?scan_id=${scanID}&limit=2000", "api('/api/ailog').then"} {
		if strings.Contains(html, heavy) {
			t.Fatalf("auto-refresh still downloads heavy badge payload %q", heavy)
		}
	}
}

func TestProfileEvidenceCacheCoalescesReadsAndInvalidatesOnNewTraffic(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "evidence-cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(rawURL string, status int, body string) {
		t.Helper()
		if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
			Request: types.CapturedRequest{Method: http.MethodGet, URL: rawURL},
			Response: types.CapturedResponse{
				StatusCode: status, Headers: map[string]string{},
				ContentType: "text/html", Body: []byte(body), Size: int64(len(body)),
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, rawURL := range []string{"https://app.example.test/missing", "https://app.example.test/real"} {
		if err := db.UpsertProfile(scanID, &types.PageProfile{
			ID: "GET " + rawURL, URL: rawURL, Method: http.MethodGet,
		}); err != nil {
			t.Fatal(err)
		}
	}
	insert("https://app.example.test/missing", http.StatusNotFound, "not found")

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	first, err := s.profileEvidenceTraffic(scanID)
	if err != nil || len(first) != 1 {
		t.Fatalf("first evidence read len=%d err=%v", len(first), err)
	}
	firstRevision := s.profileEvidenceCache[scanID].revision
	second, err := s.profileEvidenceTraffic(scanID)
	if err != nil || len(second) != 1 || s.profileEvidenceCache[scanID].revision != firstRevision {
		t.Fatalf("stable evidence cache changed: len=%d err=%v cache=%+v", len(second), err, s.profileEvidenceCache[scanID])
	}

	insert("https://app.example.test/real", http.StatusOK, "<main>real page</main>")
	third, err := s.profileEvidenceTraffic(scanID)
	if err != nil || len(third) != 2 {
		t.Fatalf("new traffic did not invalidate evidence cache: len=%d err=%v", len(third), err)
	}
	if s.profileEvidenceCache[scanID].revision == firstRevision {
		t.Fatal("traffic revision did not advance after a new capture")
	}
	thirdRevision := s.profileEvidenceCache[scanID].revision
	if _, err := db.Conn().Exec(`UPDATE traffic SET is_duplicate = TRUE WHERE scan_id = ? AND url = ?`,
		scanID, "https://app.example.test/real"); err != nil {
		t.Fatal(err)
	}
	fourth, err := s.profileEvidenceTraffic(scanID)
	if err != nil || len(fourth) != 1 {
		t.Fatalf("deduplication did not invalidate evidence cache: len=%d err=%v", len(fourth), err)
	}
	if s.profileEvidenceCache[scanID].revision == thirdRevision {
		t.Fatal("traffic revision omitted mutable is_duplicate state")
	}
}

func TestNewScanUIWiresBOLAContextFields(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, want := range []string{
		`id="scanBOLAPrimaryOwner"`,
		`id="scanBOLAPrimaryLoginURL"`,
		`id="scanBOLAPrimaryObjectURL"`,
		`id="scanBOLASecondaryLoginURL"`,
		`id="scanBOLASecondaryUser"`,
		`id="scanBOLASecondaryPass"`,
		`id="scanBOLASecondaryOwner"`,
		`id="scanBOLASecondaryObjectURL"`,
		`bola_primary_login_url: bolaPrimaryLoginURL`,
		`bola_primary_owner: bolaPrimaryOwner`,
		`bola_secondary_pass: bolaSecondaryPass`,
		`Passwords are passed to the scan subprocess via environment variables`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("New Scan UI missing BOLA marker %q", want)
		}
	}
}
