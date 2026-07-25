package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestDiscoveryGraphProjectsOnlyOperatorAuthorizedScope(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("https://www.example.com/", `{
		"Scan":{"Scope":["https://www.example.com/","https://*.example.com"]}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	discoveries := []store.Discovery{
		{TargetURL: "https://www.example.com/", Kind: store.DiscoverySeed},
		{SourceURL: "https://www.example.com/", TargetURL: "https://careers.example.com/jobs", Kind: store.DiscoveryHTMLLink},
		{SourceURL: "https://careers.example.com/jobs", TargetURL: "https://www.linkedin.com/company/examplegroup", Kind: store.DiscoveryHTMLLink},
		{SourceURL: "https://careers.example.com/jobs", TargetURL: "https://open.spotify.com/show/example", Kind: store.DiscoveryHTMLLink},
	}
	for _, discovery := range discoveries {
		if err := db.InsertDiscovery(scanID, discovery); err != nil {
			t.Fatal(err)
		}
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	readGraph := func(path string) struct {
		Nodes []struct {
			URL     string `json:"url"`
			InScope bool   `json:"in_scope"`
		} `json:"nodes"`
		Edges []struct {
			Source string `json:"source"`
			Target string `json:"target"`
		} `json:"edges"`
		Stats map[string]int `json:"stats"`
	} {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		s.handleDiscoveryGraph(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var response struct {
			Nodes []struct {
				URL     string `json:"url"`
				InScope bool   `json:"in_scope"`
			} `json:"nodes"`
			Edges []struct {
				Source string `json:"source"`
				Target string `json:"target"`
			} `json:"edges"`
			Stats map[string]int `json:"stats"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}

	scanIDText := strconv.FormatInt(scanID, 10)
	all := readGraph("/api/discovery-graph?scan_id=" + scanIDText + "&max_nodes=0")
	if len(all.Nodes) != 4 {
		t.Fatalf("complete provenance nodes=%d, want 4", len(all.Nodes))
	}
	allScope := make(map[string]bool, len(all.Nodes))
	for _, node := range all.Nodes {
		allScope[node.URL] = node.InScope
	}
	if !allScope["https://www.example.com/"] || !allScope["https://careers.example.com/jobs"] {
		t.Fatalf("authorized Example nodes were not marked in-scope: %#v", allScope)
	}
	if allScope["https://www.linkedin.com/company/examplegroup"] || allScope["https://open.spotify.com/show/example"] {
		t.Fatalf("external links were marked in-scope: %#v", allScope)
	}

	scoped := readGraph("/api/discovery-graph?scan_id=" + scanIDText + "&max_nodes=0&scope=in")
	if len(scoped.Nodes) != 2 || len(scoped.Edges) != 2 {
		t.Fatalf("scoped graph nodes=%d edges=%d, want 2/2", len(scoped.Nodes), len(scoped.Edges))
	}
	for _, node := range scoped.Nodes {
		if !node.InScope || node.URL == "https://www.linkedin.com/company/examplegroup" || node.URL == "https://open.spotify.com/show/example" {
			t.Fatalf("scoped graph leaked external node: %#v", node)
		}
	}
	if scoped.Stats["total_nodes"] != 2 || scoped.Stats["all_nodes"] != 4 ||
		scoped.Stats["external_nodes"] != 2 || scoped.Stats["external_hosts"] != 2 {
		t.Fatalf("scoped graph stats=%#v", scoped.Stats)
	}

	statsOnly := readGraph("/api/discovery-graph?scan_id=" + scanIDText + "&scope=in&stats_only=1")
	if len(statsOnly.Nodes) != 0 || len(statsOnly.Edges) != 0 {
		t.Fatalf("stats-only graph returned payload nodes=%d edges=%d", len(statsOnly.Nodes), len(statsOnly.Edges))
	}
	if statsOnly.Stats["total_nodes"] != 2 || statsOnly.Stats["total_edges"] != 2 ||
		statsOnly.Stats["all_nodes"] != 4 || statsOnly.Stats["external_hosts"] != 2 {
		t.Fatalf("stats-only graph stats=%#v", statsOnly.Stats)
	}

	w := httptest.NewRecorder()
	s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet,
		"/api/discovery-graph?scan_id="+scanIDText+"&origins_only=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("origins status=%d body=%s", w.Code, w.Body.String())
	}
	var originResponse struct {
		Origins []discoveryGraphOriginOut `json:"origins"`
		Stats   map[string]int            `json:"stats"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &originResponse); err != nil {
		t.Fatal(err)
	}
	if len(originResponse.Origins) != 4 || originResponse.Stats["origin_count"] != 4 ||
		originResponse.Stats["in_scope_origins"] != 2 || originResponse.Stats["first_party_origins"] != 2 ||
		originResponse.Stats["external_origins"] != 2 || originResponse.Stats["first_party_subdomains"] != 1 {
		t.Fatalf("origin projection=%+v stats=%#v", originResponse.Origins, originResponse.Stats)
	}
	byOrigin := make(map[string]discoveryGraphOriginOut, len(originResponse.Origins))
	for _, origin := range originResponse.Origins {
		byOrigin[origin.Origin] = origin
	}
	if target := byOrigin["https://www.example.com"]; !target.Target || !target.InScope || !target.FirstParty {
		t.Fatalf("target origin=%+v", target)
	}
	if careers := byOrigin["https://careers.example.com"]; !careers.Subdomain || !careers.InScope || !careers.FirstParty {
		t.Fatalf("careers origin=%+v", careers)
	}
	if linkedin := byOrigin["https://www.linkedin.com"]; linkedin.InScope || linkedin.FirstParty {
		t.Fatalf("external origin=%+v", linkedin)
	}
}

func TestGraphScopeFromConfigFailsClosedToTarget(t *testing.T) {
	scope := graphProjectionScopeFromConfig("https://partner.example.com/auth/login", `{}`)
	_, exact, err := scope.MatchURL("https://partner.example.com/account")
	if err != nil || !exact {
		t.Fatalf("target origin did not match: in_scope=%v err=%v", exact, err)
	}
	_, sibling, err := scope.MatchURL("https://careers.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if sibling {
		t.Fatal("legacy exact-origin scan unexpectedly authorized a sibling host")
	}
}

func TestDiscoveryGraphOriginProjectionMarksLinkedFirstPartyOutsideExactScope(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://www.rolex.com/en-us", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, discovery := range []store.Discovery{
		{TargetURL: "https://www.rolex.com/en-us", Kind: store.DiscoverySeed},
		{SourceURL: "https://www.rolex.com/en-us", TargetURL: "https://newsroom.rolex.com/", Kind: store.DiscoveryHTMLLink},
	} {
		if err := db.InsertDiscovery(scanID, discovery); err != nil {
			t.Fatal(err)
		}
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet,
		"/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&origins_only=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Origins []discoveryGraphOriginOut `json:"origins"`
		Stats   map[string]int            `json:"stats"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Stats["first_party_origins"] != 2 || response.Stats["in_scope_origins"] != 1 ||
		response.Stats["linked_only_first_party"] != 1 || response.Stats["first_party_subdomains"] != 1 {
		t.Fatalf("stats=%#v origins=%+v", response.Stats, response.Origins)
	}
	for _, origin := range response.Origins {
		if origin.Hostname == "newsroom.rolex.com" && (!origin.FirstParty || origin.InScope || !origin.Subdomain) {
			t.Fatalf("linked sibling was promoted into scope: %+v", origin)
		}
	}
}

func TestDiscoveryGraphOriginProjectionIncludesPolicyBoundaryDependencies(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://www.khanacademy.org/", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InsertDiscovery(scanID, store.Discovery{TargetURL: "https://www.khanacademy.org/", Kind: store.DiscoverySeed}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertDiscovery(scanID, store.Discovery{
		SourceURL: "https://www.khanacademy.org/", TargetURL: "https://cdn.kastatic.org/app.js", Kind: store.DiscoveryHTMLLink,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertNarration(scanID, "policy", "denied", "dependency is outside scope", "", map[string]any{
		"canonical_origin": "https://cdn.kastatic.org:443", "code": "out_of_scope",
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet,
		"/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&origins_only=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Origins []discoveryGraphOriginOut `json:"origins"`
		Stats   map[string]int            `json:"stats"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Stats["origin_count"] != 2 || response.Stats["external_origins"] != 1 {
		t.Fatalf("stats=%#v origins=%+v", response.Stats, response.Origins)
	}
	for _, origin := range response.Origins {
		if origin.Hostname != "cdn.kastatic.org" {
			continue
		}
		if origin.InScope || origin.FirstParty || !slices.Contains(origin.KindTags, "policy-boundary") {
			t.Fatalf("policy boundary was promoted or mislabeled: %+v", origin)
		}
		return
	}
	t.Fatal("policy-boundary dependency origin was omitted")
}

func TestDiscoveryGraphOriginProjectionOmitsBrowserBackgroundBoundaries(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test/", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InsertDiscovery(scanID, store.Discovery{TargetURL: "https://example.test/", Kind: store.DiscoverySeed}); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{
		"https://accounts.google.com:443",
		"https://content-autofill.googleapis.com:443",
		"https://api.real-dependency.test:443",
	} {
		if _, err := db.InsertNarration(scanID, "policy", "denied", "outside scope", "", map[string]any{
			"canonical_origin": origin, "code": "out_of_scope",
		}); err != nil {
			t.Fatal(err)
		}
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet,
		"/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&origins_only=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Origins []discoveryGraphOriginOut `json:"origins"`
		Stats   map[string]int            `json:"stats"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Stats["origin_count"] != 2 || response.Stats["external_origins"] != 1 {
		t.Fatalf("stats=%#v origins=%+v", response.Stats, response.Origins)
	}
	for _, origin := range response.Origins {
		if origin.Hostname == "accounts.google.com" || origin.Hostname == "content-autofill.googleapis.com" {
			t.Fatalf("browser background origin leaked into target projection: %+v", origin)
		}
	}
}

func TestDiscoveryGraphCanonicalizesAndUnionsObservedEvidence(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("https://example.test/", `{
		"Scan":{"Scope":["https://example.test/","https://*.example.test"]}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, discovery := range []store.Discovery{
		{TargetURL: "https://example.test/", Kind: store.DiscoverySeed},
		{SourceURL: "https://example.test/", TargetURL: "https://example.test/login", Kind: store.DiscoveryHTMLLink},
		{SourceURL: "https://example.test/", TargetURL: "https://linked.example.test/docs", Kind: store.DiscoveryHTMLLink},
	} {
		if err := db.InsertDiscovery(scanID, discovery); err != nil {
			t.Fatal(err)
		}
	}

	trafficID, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		EndpointHash: "login-post",
		Request: types.CapturedRequest{
			Method: "POST", URL: "https://example.test:443/login", Headers: map[string]string{},
		},
		Response: types.CapturedResponse{
			StatusCode: 201, Headers: map[string]string{}, ContentType: "application/json", Body: []byte(`{"ok":true}`),
		},
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		EndpointHash: "private-data-get",
		Request: types.CapturedRequest{
			Method: "GET", URL: "https://api.example.test:443/private/data", Headers: map[string]string{},
		},
		Response: types.CapturedResponse{
			StatusCode: 200, Headers: map[string]string{}, ContentType: "application/json", Body: []byte(`{"data":1}`),
		},
		Timestamp: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkTrafficAnalyzed([]int64{trafficID}, 1); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: "POST /login", URL: "https://example.test:443/login", Method: "POST",
		Purpose: "Authenticate a user", Issues: []string{"credential boundary"}, Confidence: 0.9,
	}); err != nil {
		t.Fatal(err)
	}
	for _, finding := range []types.Finding{
		{Title: "Login flaw", Severity: types.SeverityCritical, Confidence: types.ConfidenceConfirmed, EndpointID: "POST /login"},
		{Title: "Orphan admin flaw", Severity: types.SeverityHigh, Confidence: types.ConfidenceConfirmed, EndpointID: "DELETE /admin/orphan"},
	} {
		if _, err := db.InsertFinding(scanID, finding); err != nil {
			t.Fatal(err)
		}
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&max_nodes=0&scope=in", nil)
	s.handleDiscoveryGraph(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Nodes []struct {
			URL          string                      `json:"url"`
			Methods      []string                    `json:"methods"`
			EndpointRefs []discoveryGraphEndpointRef `json:"endpoint_refs"`
			ProfileIDs   []string                    `json:"profile_ids"`
			Observed     bool                        `json:"observed"`
			IsAnalyzed   bool                        `json:"is_analyzed"`
			HasIssues    bool                        `json:"has_issues"`
			Severity     string                      `json:"worst_severity"`
			FindingCount int                         `json:"finding_count"`
		} `json:"nodes"`
		Stats map[string]int `json:"stats"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	byURL := make(map[string]struct {
		Methods      []string
		EndpointRefs []discoveryGraphEndpointRef
		ProfileIDs   []string
		Observed     bool
		IsAnalyzed   bool
		HasIssues    bool
		Severity     string
		FindingCount int
	}, len(response.Nodes))
	for _, node := range response.Nodes {
		byURL[node.URL] = struct {
			Methods      []string
			EndpointRefs []discoveryGraphEndpointRef
			ProfileIDs   []string
			Observed     bool
			IsAnalyzed   bool
			HasIssues    bool
			Severity     string
			FindingCount int
		}{node.Methods, node.EndpointRefs, node.ProfileIDs, node.Observed, node.IsAnalyzed, node.HasIssues, node.Severity, node.FindingCount}
	}
	login, ok := byURL["https://example.test/login"]
	if !ok {
		t.Fatalf("canonical login node missing: %#v", byURL)
	}
	if len(login.Methods) != 1 || login.Methods[0] != "POST" || len(login.EndpointRefs) != 1 ||
		!login.Observed || !login.IsAnalyzed || !login.HasIssues || login.Severity != "critical" || login.FindingCount != 1 {
		t.Fatalf("canonical login metadata=%#v", login)
	}
	if len(login.ProfileIDs) != 1 || login.ProfileIDs[0] != "POST /login" {
		t.Fatalf("canonical login profiles=%v", login.ProfileIDs)
	}
	apiNode, ok := byURL["https://api.example.test/private/data"]
	if !ok || !apiNode.Observed || len(apiNode.Methods) != 1 || apiNode.Methods[0] != "GET" {
		t.Fatalf("traffic-only API node=%#v present=%v", apiNode, ok)
	}
	orphan, ok := byURL["https://example.test/admin/orphan"]
	if !ok || orphan.Severity != "high" || orphan.FindingCount != 1 || len(orphan.Methods) != 1 || orphan.Methods[0] != "DELETE" {
		t.Fatalf("finding-only node=%#v present=%v", orphan, ok)
	}
	linked, ok := byURL["https://linked.example.test/docs"]
	if !ok || linked.Observed || linked.Methods == nil || linked.EndpointRefs == nil || linked.ProfileIDs == nil {
		t.Fatalf("linked-only node=%#v present=%v", linked, ok)
	}
}

func TestDiscoveryGraphCollapsesQueryValuesIntoRouteFacets(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://partner.example.test/", `{"Scan":{"Scope":["https://partner.example.test/"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InsertDiscovery(scanID, store.Discovery{TargetURL: "https://partner.example.test/", Kind: store.DiscoverySeed}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/admin", "/dashboard", "/api", "/auth/register", "/robots.txt"} {
		rawURL := "https://partner.example.test/auth/logout?redirect=" + url.QueryEscape(path)
		if err := db.InsertDiscovery(scanID, store.Discovery{
			SourceURL: "https://partner.example.test/", TargetURL: rawURL, Kind: store.DiscoveryNavigator,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
			Request:  types.CapturedRequest{Method: http.MethodGet, URL: rawURL},
			Response: types.CapturedResponse{StatusCode: http.StatusOK, Headers: map[string]string{}, Body: []byte("shell")},
		}); err != nil {
			t.Fatal(err)
		}
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet,
		"/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&max_nodes=0&scope=in", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Nodes []discoveryGraphNodeMeta `json:"nodes"`
		Edges []discoveryGraphEdgeOut  `json:"edges"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	var logoutNodes []discoveryGraphNodeMeta
	for _, node := range response.Nodes {
		if node.Path == "/auth/logout" {
			logoutNodes = append(logoutNodes, node)
		}
	}
	if len(logoutNodes) != 1 {
		t.Fatalf("logout nodes=%d, want one logical route: %+v", len(logoutNodes), logoutNodes)
	}
	node := logoutNodes[0]
	if node.URL != "https://partner.example.test/auth/logout" {
		t.Fatalf("node URL=%q, want query-free logical route identity", node.URL)
	}
	if node.QueryVariants != 5 || len(node.QueryKeys) != 1 || node.QueryKeys[0] != "redirect" {
		t.Fatalf("query facets = variants %d keys %v", node.QueryVariants, node.QueryKeys)
	}
	if node.HitCount != 5 || len(node.EndpointRefs) != 1 || !strings.Contains(node.Label, "redirect={…}") {
		t.Fatalf("logical node lost evidence: %+v", node)
	}
	redirectEdges := 0
	for _, edge := range response.Edges {
		if edge.Target == node.URL && edge.Kind == store.DiscoveryNavigator {
			redirectEdges++
			if edge.Count != 5 {
				t.Fatalf("collapsed edge count=%d, want 5", edge.Count)
			}
		}
	}
	if redirectEdges != 1 {
		t.Fatalf("navigator edges to logical route=%d, want 1", redirectEdges)
	}
	statsRecorder := httptest.NewRecorder()
	s.handleStats(statsRecorder, httptest.NewRequest(http.MethodGet,
		"/api/stats?scan_id="+strconv.FormatInt(scanID, 10), nil))
	if statsRecorder.Code != http.StatusOK {
		t.Fatalf("stats status=%d body=%s", statsRecorder.Code, statsRecorder.Body.String())
	}
	var statsResponse struct {
		GraphRouteCount int `json:"graph_route_count"`
	}
	if err := json.Unmarshal(statsRecorder.Body.Bytes(), &statsResponse); err != nil {
		t.Fatal(err)
	}
	if statsResponse.GraphRouteCount != len(response.Nodes) {
		t.Fatalf("badge logical routes=%d, Graph nodes=%d", statsResponse.GraphRouteCount, len(response.Nodes))
	}
}

func TestDiscoveryGraphExposesMixedExactQueryEvidenceWithoutBorrowingContent(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "query-mixed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://partner.example.test/", `{"Scan":{"Scope":["https://partner.example.test/"]}}`)
	entries := []*types.TrafficEntry{
		{
			Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://partner.example.test/auth/logout?redirect=%2Fpublic"},
			Response: types.CapturedResponse{
				StatusCode: http.StatusOK, ContentType: "text/html",
				Body: []byte(`<html><body><h1>Signed out</h1></body></html>`),
			},
		},
		{
			Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://partner.example.test/auth/logout?redirect=%2Fadmin"},
			Response: types.CapturedResponse{
				StatusCode: http.StatusFound, Headers: map[string]string{"Location": "/auth/login?redirect=%2Fadmin"},
			},
		},
	}
	for _, entry := range entries {
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}
	if entries[0].EndpointHash != entries[1].EndpointHash {
		t.Fatal("test setup requires query-value siblings to share endpoint identity")
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet,
		"/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&max_nodes=0&scope=in", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Nodes []discoveryGraphNodeMeta `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	for _, node := range response.Nodes {
		if node.Path != "/auth/logout" {
			continue
		}
		if node.EvidenceState != "query_mixed_unverified" || node.FunctionalArea != "mixed_evidence" ||
			node.Interesting || node.HasIssues || len(node.MethodEvidence) != 1 {
			t.Fatalf("mixed query family was promoted: %+v", node)
		}
		method := node.MethodEvidence[0]
		if method.State != "query_mixed_unverified" || method.QueryVariants != 2 ||
			method.ContentVariants != 1 || method.UnverifiedVariants != 1 || len(method.VariantStates) != 2 ||
			!strings.Contains(method.Note, "does not verify its siblings") {
			t.Fatalf("query variant evidence not exposed: %+v", method)
		}
		return
	}
	t.Fatalf("mixed /auth/logout node missing: %+v", response.Nodes)
}

func TestDiscoveryGraphOriginsOnlyBypassesSemanticGraphAndBodyEvidence(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test/", `{"Scan":{"Scope":["https://app.example.test/"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InsertDiscovery(scanID, store.Discovery{
		TargetURL: "https://app.example.test/", Kind: store.DiscoverySeed,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://app.example.test/admin"},
		Response: types.CapturedResponse{
			StatusCode: http.StatusFound, Headers: map[string]string{"Location": "/login"},
			Body: []byte(strings.Repeat("large-body-must-not-be-read", 4096)),
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: "GET /admin", URL: "https://app.example.test/admin", Method: http.MethodGet,
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet,
		"/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&origins_only=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("origins status=%d body=%s", w.Code, w.Body.String())
	}
	if len(s.profileEvidenceCache) != 0 {
		t.Fatalf("origins-only path populated semantic body-evidence cache: %+v", s.profileEvidenceCache)
	}
	var response struct {
		Origins []discoveryGraphOriginOut `json:"origins"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Origins) != 1 || response.Origins[0].URLs != 2 || response.Origins[0].Profiles != 1 {
		t.Fatalf("fast origin projection lost metadata: %+v", response.Origins)
	}
}

func TestDiscoveryGraphCountsTrafficOnlyQueryVariantsAndBoundsSpecimens(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test/", `{"Scan":{"Scope":["https://example.test/"]}}`)
	if err != nil {
		t.Fatal(err)
	}

	values := []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "alpha"}
	for _, value := range values {
		rawURL := "https://example.test/search?q=" + url.QueryEscape(value)
		if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
			Request: types.CapturedRequest{
				Method: http.MethodGet, URL: rawURL,
				Headers: map[string]string{"Referer": "https://example.test/"},
			},
			Response: types.CapturedResponse{
				StatusCode: http.StatusOK, Headers: map[string]string{},
				ContentType: "application/json", Body: []byte(`{"ok":true}`),
			},
		}); err != nil {
			t.Fatal(err)
		}
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet,
		"/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&max_nodes=0&scope=in", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Nodes []discoveryGraphNodeMeta `json:"nodes"`
		Edges []discoveryGraphEdgeOut  `json:"edges"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	var search discoveryGraphNodeMeta
	for _, node := range response.Nodes {
		if node.Path == "/search" {
			search = node
			break
		}
	}
	if search.URL != "https://example.test/search" {
		t.Fatalf("search URL=%q, want logical route identity", search.URL)
	}
	if search.QueryVariants != 7 || search.HitCount != len(values) {
		t.Fatalf("traffic facets variants=%d hits=%d, want 7 variants and %d hits", search.QueryVariants, search.HitCount, len(values))
	}
	if len(search.URLSamples) != 1 || !strings.Contains(search.URLSamples[0], "q={redacted}") {
		t.Fatalf("redacted URL specimens=%v, want one query-shape specimen", search.URLSamples)
	}
	for _, value := range values {
		if strings.Contains(strings.Join(search.URLSamples, "\n"), value) {
			t.Fatalf("query value %q leaked through Graph specimens: %v", value, search.URLSamples)
		}
	}
	if search.QueryVariantsCapped {
		t.Fatalf("small query facet set was unexpectedly capped: %+v", search)
	}
	if len(search.QueryKeys) != 1 || search.QueryKeys[0] != "q" || !strings.Contains(search.Label, "q={…}") {
		t.Fatalf("query facet label lost: %+v", search)
	}
	var apiEdges []discoveryGraphEdgeOut
	for _, edge := range response.Edges {
		if edge.Kind == "api-call" && edge.Target == search.URL {
			apiEdges = append(apiEdges, edge)
		}
	}
	if len(apiEdges) != 1 || apiEdges[0].Count != len(values) {
		t.Fatalf("logical-route API edge aggregation=%+v, want one edge with count %d", apiEdges, len(values))
	}
}

func TestDiscoveryGraphQueryFacetCardinalityIsBoundedAndValuesAreRedacted(t *testing.T) {
	var facet discoveryGraphQueryFacet
	count := 0
	for i := 0; i < discoveryGraphMaxQueryVariantFingerprints+73; i++ {
		canonical := fmt.Sprintf("https://example.test/reset?token=secret-%d", i)
		count = facet.observe(canonical)
	}
	if !facet.saturated || len(facet.fingerprints) != discoveryGraphMaxQueryVariantFingerprints {
		t.Fatalf("facet bound=%d saturated=%v, want %d/true",
			len(facet.fingerprints), facet.saturated, discoveryGraphMaxQueryVariantFingerprints)
	}
	if count != discoveryGraphMaxQueryVariantFingerprints+1 {
		t.Fatalf("capped lower-bound count=%d, want %d", count, discoveryGraphMaxQueryVariantFingerprints+1)
	}
	specimen := discoveryGraphQuerySpecimen("https://example.test/reset?token=super-secret&next=%2Fadmin")
	if strings.Contains(specimen, "super-secret") || strings.Contains(specimen, "%2Fadmin") ||
		!strings.Contains(specimen, "next={redacted}") || !strings.Contains(specimen, "token={redacted}") {
		t.Fatalf("query specimen is not safely redacted: %q", specimen)
	}
}

func TestProfileEvidenceTrafficDoesNotDropProfilesAfterEightHundred(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test/", `{"Scan":{"Scope":["https://example.test/"]}}`)
	if err != nil {
		t.Fatal(err)
	}

	const profileCount = 805
	traffic := make([]*types.TrafficEntry, 0, profileCount)
	profiles := make([]types.PageProfile, 0, profileCount)
	for i := 0; i < profileCount; i++ {
		rawURL := fmt.Sprintf("https://example.test/routes/profile-%04d", i)
		traffic = append(traffic, &types.TrafficEntry{
			Request: types.CapturedRequest{Method: http.MethodGet, URL: rawURL},
			Response: types.CapturedResponse{
				StatusCode: http.StatusOK, Headers: map[string]string{}, ContentType: "application/json",
				Body: []byte(fmt.Sprintf(`{"profile":%d}`, i)),
			},
		})
		profiles = append(profiles, types.PageProfile{
			ID: fmt.Sprintf("GET /routes/profile-%04d", i), URL: rawURL, Method: http.MethodGet,
		})
	}
	if inserted, err := db.InsertTrafficBatch(scanID, traffic); err != nil || inserted != profileCount {
		t.Fatalf("InsertTrafficBatch=(%d,%v), want (%d,nil)", inserted, err, profileCount)
	}
	for i := range profiles {
		if err := db.UpsertProfile(scanID, &profiles[i]); err != nil {
			t.Fatalf("profile %d: %v", i, err)
		}
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	entries, err := s.profileEvidenceTraffic(scanID)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		seen[entry.EndpointHash] = true
	}
	if len(seen) != profileCount {
		t.Fatalf("profile evidence identities=%d, want %d; a profile ceiling dropped routes", len(seen), profileCount)
	}
	for _, index := range []int{0, profileCount - 1} {
		if !seen[traffic[index].EndpointHash] {
			t.Fatalf("profile %d evidence was dropped", index)
		}
	}
}

func TestDiscoveryGraphProjectsAuthGateRedirectAsUnverifiedRoute(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://partner.example.test/", `{"Scan":{"Scope":["https://partner.example.test/"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	adminURL := "https://partner.example.test/admin"
	if err := db.InsertDiscovery(scanID, store.Discovery{TargetURL: adminURL, Kind: store.DiscoveryNavigator}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: adminURL},
		Response: types.CapturedResponse{
			StatusCode: http.StatusFound,
			Headers:    map[string]string{"Location": "/auth/login?redirect=%2Fadmin"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: "GET /admin", URL: adminURL, Method: http.MethodGet,
		Purpose: "Administrative dashboard", Issues: []string{"privileged area"}, Confidence: .95,
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet,
		"/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&max_nodes=0&scope=in", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Nodes []discoveryGraphNodeMeta `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	var admin *discoveryGraphNodeMeta
	for i := range response.Nodes {
		if response.Nodes[i].Path == "/admin" {
			admin = &response.Nodes[i]
			break
		}
	}
	if admin == nil {
		t.Fatalf("admin logical route missing: %+v", response.Nodes)
	}
	if admin.EvidenceState != "auth_gate_unverified" || !strings.Contains(admin.EvidenceNote, "Backing route existence and purpose are unverified") {
		t.Fatalf("redirect evidence projection=%+v", admin)
	}
	if admin.FunctionalArea != "redirect_unverified" || admin.AreaPriority != 0 {
		t.Fatalf("redirect route area=%q priority=%d, want low-priority redirect_unverified", admin.FunctionalArea, admin.AreaPriority)
	}
	if admin.Interesting || admin.HasIssues {
		t.Fatalf("stale path/profile semantics leaked into redirect-only node: %+v", admin)
	}
	if !slices.Equal(admin.ObservedStatuses, []int{http.StatusFound}) || !slices.Equal(admin.RedirectLocations, []string{"/auth/login?redirect=%2Fadmin"}) {
		t.Fatalf("redirect evidence details=%+v", admin)
	}
}

func TestDiscoveryGraphProjectsTrafficOnlyAuthGateBeforeProfileExists(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://partner.example.test/", `{"Scan":{"Scope":["https://partner.example.test/"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	adminURL := "https://partner.example.test/admin"
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: adminURL},
		Response: types.CapturedResponse{
			StatusCode: http.StatusFound,
			Headers:    map[string]string{"Location": "/auth/login?redirect=%2Fadmin"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet,
		"/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&max_nodes=0&scope=in", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Nodes []discoveryGraphNodeMeta `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	for i := range response.Nodes {
		admin := &response.Nodes[i]
		if admin.Path != "/admin" {
			continue
		}
		if admin.EvidenceState != "auth_gate_unverified" || admin.FunctionalArea != "redirect_unverified" ||
			admin.Interesting || admin.HasIssues || len(admin.ProfileIDs) != 0 {
			t.Fatalf("traffic-only redirect acquired route-name semantics: %+v", admin)
		}
		if len(admin.MethodEvidence) != 1 || admin.MethodEvidence[0].Method != http.MethodGet ||
			admin.MethodEvidence[0].State != "auth_gate_unverified" {
			t.Fatalf("traffic-only method verdict=%+v", admin.MethodEvidence)
		}
		return
	}
	t.Fatalf("traffic-only /admin node missing: %+v", response.Nodes)
}

func TestDiscoveryGraphKeepsResponseEvidenceSeparateByMethod(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("https://partner.example.test/", `{"Scan":{"Scope":["https://partner.example.test/"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	adminURL := "https://partner.example.test/admin"
	if err := db.InsertDiscovery(scanID, store.Discovery{TargetURL: adminURL, Kind: store.DiscoveryNavigator}); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []*types.TrafficEntry{
		{
			Request: types.CapturedRequest{Method: http.MethodGet, URL: adminURL},
			Response: types.CapturedResponse{
				StatusCode: http.StatusFound,
				Headers:    map[string]string{"Location": "/auth/login?redirect=%2Fadmin"},
			},
		},
		{
			Request: types.CapturedRequest{Method: http.MethodPost, URL: adminURL},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				Headers:     map[string]string{},
				ContentType: "application/json",
				Body:        []byte(`{"partner":{"id":17},"orders":[8172]}`),
			},
		},
	} {
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: "GET /admin", URL: adminURL, Method: http.MethodGet,
		Purpose: "Administrative dashboard", Issues: []string{"privileged area"}, Confidence: .95,
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet,
		"/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&max_nodes=0&scope=in", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Nodes []discoveryGraphNodeMeta `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}

	var admin *discoveryGraphNodeMeta
	for i := range response.Nodes {
		if response.Nodes[i].Path == "/admin" {
			admin = &response.Nodes[i]
			break
		}
	}
	if admin == nil {
		t.Fatalf("admin logical route missing: %+v", response.Nodes)
	}
	if admin.EvidenceState != "method_mixed" || admin.FunctionalArea != "mixed_evidence" {
		t.Fatalf("logical route evidence=%q area=%q, want method_mixed/mixed_evidence: %+v",
			admin.EvidenceState, admin.FunctionalArea, admin)
	}
	if !strings.Contains(admin.EvidenceNote, "Content observed for one method does not verify") {
		t.Fatalf("method-isolation explanation missing: %q", admin.EvidenceNote)
	}
	if admin.HasIssues {
		t.Fatalf("stale GET profile issue leaked through unverified method evidence: %+v", admin)
	}
	if !slices.Equal(admin.Methods, []string{http.MethodGet, http.MethodPost}) {
		t.Fatalf("methods=%v, want GET and POST", admin.Methods)
	}
	if !slices.Equal(admin.ObservedStatuses, []int{http.StatusOK, http.StatusFound}) ||
		!slices.Equal(admin.RedirectLocations, []string{"/auth/login?redirect=%2Fadmin"}) {
		t.Fatalf("combined factual evidence lost: statuses=%v locations=%v", admin.ObservedStatuses, admin.RedirectLocations)
	}
	if len(admin.MethodEvidence) != 2 {
		t.Fatalf("method evidence=%+v, want one verdict per method", admin.MethodEvidence)
	}
	byMethod := make(map[string]discoveryGraphMethodEvidence, len(admin.MethodEvidence))
	for _, evidence := range admin.MethodEvidence {
		byMethod[evidence.Method] = evidence
	}
	get, getOK := byMethod[http.MethodGet]
	post, postOK := byMethod[http.MethodPost]
	if !getOK || get.State != "auth_gate_unverified" ||
		!slices.Equal(get.ObservedStatuses, []int{http.StatusFound}) ||
		!slices.Equal(get.RedirectLocations, []string{"/auth/login?redirect=%2Fadmin"}) {
		t.Fatalf("GET evidence=%+v present=%v", get, getOK)
	}
	if !postOK || post.State != "content_observed" ||
		!slices.Equal(post.ObservedStatuses, []int{http.StatusOK}) || len(post.RedirectLocations) != 0 {
		t.Fatalf("POST evidence=%+v present=%v", post, postOK)
	}
}

func TestDiscoveryGraphFailsClosedForProfileMethodWithoutDirectEvidence(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://partner.example.test/", `{"Scan":{"Scope":["https://partner.example.test/"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	adminURL := "https://partner.example.test/admin"
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodPost, URL: adminURL},
		Response: types.CapturedResponse{
			StatusCode: http.StatusOK, Headers: map[string]string{}, ContentType: "application/json",
			Body: []byte(`{"updated":true,"partner_id":17}`),
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: "GET /admin", URL: adminURL, Method: http.MethodGet,
		Purpose: "Administrative dashboard", Issues: []string{"privileged area"}, Confidence: .95,
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet,
		"/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&max_nodes=0&scope=in", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Nodes []discoveryGraphNodeMeta `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	for i := range response.Nodes {
		admin := &response.Nodes[i]
		if admin.Path != "/admin" {
			continue
		}
		if admin.EvidenceState != "method_mixed" || admin.FunctionalArea != "mixed_evidence" ||
			!slices.Equal(admin.Methods, []string{http.MethodGet, http.MethodPost}) {
			t.Fatalf("missing GET evidence was hidden by POST content: %+v", admin)
		}
		byMethod := make(map[string]discoveryGraphMethodEvidence, len(admin.MethodEvidence))
		for _, evidence := range admin.MethodEvidence {
			byMethod[evidence.Method] = evidence
		}
		if byMethod[http.MethodGet].State != "response_unverified" ||
			byMethod[http.MethodPost].State != "content_observed" {
			t.Fatalf("method verdicts=%+v", byMethod)
		}
		return
	}
	t.Fatalf("/admin node missing: %+v", response.Nodes)
}

func TestDiscoveryGraphEmitsTypedEvidenceEdges(t *testing.T) {
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
		{SourceURL: "https://example.test/", TargetURL: "https://example.test/login", Kind: store.DiscoveryFormAction, Detail: "login form"},
		{SourceURL: "https://example.test/login", TargetURL: "https://example.test/account", Kind: store.DiscoveryRedirect, Detail: "302 Location"},
	} {
		if err := db.InsertDiscovery(scanID, discovery); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []*types.TrafficEntry{
		{
			Request:   types.CapturedRequest{Method: "POST", URL: "https://example.test/login", Headers: map[string]string{"Referer": "https://example.test/"}},
			Response:  types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "application/json", Body: []byte(`{"token":"ok"}`)},
			Timestamp: time.Now(),
		},
		{
			Request:   types.CapturedRequest{Method: "GET", URL: "https://example.test/api/me", Headers: map[string]string{"Referer": "https://example.test/account", "Authorization": "Bearer test"}},
			Response:  types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "application/json", Body: []byte(`{"id":1}`)},
			Timestamp: time.Now(),
		},
	} {
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/discovery-graph?scan_id="+strconv.FormatInt(scanID, 10)+"&max_nodes=0&scope=in", nil)
	s.handleDiscoveryGraph(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		SchemaVersion int                     `json:"schema_version"`
		Edges         []discoveryGraphEdgeOut `json:"edges"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != discoveryGraphSchemaVersion {
		t.Fatalf("schema_version=%d, want %d", response.SchemaVersion, discoveryGraphSchemaVersion)
	}
	byKind := make(map[string][]discoveryGraphEdgeOut)
	for _, edge := range response.Edges {
		byKind[edge.Kind] = append(byKind[edge.Kind], edge)
	}
	assertTyped := func(kind, edgeType, evidence string) discoveryGraphEdgeOut {
		t.Helper()
		edges := byKind[kind]
		if len(edges) == 0 {
			t.Fatalf("missing %s edge in %#v", kind, byKind)
		}
		for _, edge := range edges {
			if edge.Type == edgeType && edge.Evidence == evidence {
				return edge
			}
		}
		t.Fatalf("%s edges=%#v, want type=%q evidence=%q", kind, edges, edgeType, evidence)
		return discoveryGraphEdgeOut{}
	}
	assertTyped(store.DiscoveryFormAction, "form", "discovery")
	assertTyped(store.DiscoveryRedirect, "redirect", "discovery")
	apiEdge := assertTyped("api-call", "api", "traffic")
	if apiEdge.Method == "" || apiEdge.Count != 1 || apiEdge.Source == "" {
		t.Fatalf("API edge lacks grounded request evidence: %#v", apiEdge)
	}
	authEdge := assertTyped("auth-call", "authentication", "traffic")
	if authEdge.Method == "" || authEdge.Count != 1 {
		t.Fatalf("auth edge lacks grounded request evidence: %#v", authEdge)
	}
}

func TestDiscoveryGraphPagesLargeSurfacesWithoutLosingNodes(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("https://large.example.test/", `{"Scan":{"Scope":["https://large.example.test/"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InsertDiscovery(scanID, store.Discovery{TargetURL: "https://large.example.test/", Kind: store.DiscoverySeed}); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Conn().Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5505; i++ {
		if _, err := tx.Exec(`
			INSERT INTO url_discoveries (scan_id, target_url, source_url, kind, detail)
			VALUES (?, ?, ?, ?, ?)`, scanID, fmt.Sprintf("https://large.example.test/items/%04d", i), "https://large.example.test/", store.DiscoveryHTMLLink, "catalog"); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	type graphPageResponse struct {
		SchemaVersion int                      `json:"schema_version"`
		Nodes         []discoveryGraphNodeMeta `json:"nodes"`
		Edges         []discoveryGraphEdgeOut  `json:"edges"`
		Stats         map[string]int           `json:"stats"`
		Page          discoveryGraphPage       `json:"page"`
	}
	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	readPage := func(offset, pageSize int) (graphPageResponse, int) {
		t.Helper()
		w := httptest.NewRecorder()
		path := fmt.Sprintf("/api/discovery-graph?scan_id=%d&max_nodes=0&scope=in&page_size=%d&offset=%d", scanID, pageSize, offset)
		s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var response graphPageResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response, w.Body.Len()
	}

	seenNodes := make(map[string]bool)
	seenEdges := make(map[string]bool)
	offset, pages := 0, 0
	for {
		started := time.Now()
		response, payloadBytes := readPage(offset, 1000)
		t.Logf("page %d returned %d nodes / %d edges in %s (%d bytes)", pages+1, len(response.Nodes), len(response.Edges), time.Since(started), payloadBytes)
		if response.SchemaVersion != discoveryGraphSchemaVersion || response.Page.Limit != 1000 || len(response.Nodes) > 1000 {
			t.Fatalf("invalid page contract: %#v", response.Page)
		}
		if response.Stats["total_nodes"] != 5506 || response.Stats["paged"] != 1 {
			t.Fatalf("page stats=%#v", response.Stats)
		}
		if payloadBytes > 2<<20 {
			t.Fatalf("paged graph payload=%d bytes, want <= 2 MiB", payloadBytes)
		}
		for _, node := range response.Nodes {
			if seenNodes[node.URL] {
				t.Fatalf("node repeated across pages: %s", node.URL)
			}
			seenNodes[node.URL] = true
		}
		for _, edge := range response.Edges {
			key := edge.Source + "\x00" + edge.Target + "\x00" + edge.Kind + "\x00" + edge.Method
			if seenEdges[key] {
				t.Fatalf("edge repeated across pages: %q", key)
			}
			seenEdges[key] = true
		}
		pages++
		if !response.Page.HasMore {
			break
		}
		if response.Page.NextOffset <= offset {
			t.Fatalf("pagination did not advance: %#v", response.Page)
		}
		offset = response.Page.NextOffset
	}
	if pages != 6 || len(seenNodes) != 5506 || len(seenEdges) != 5506 {
		t.Fatalf("pages=%d nodes=%d edges=%d, want 6/5506/5506", pages, len(seenNodes), len(seenEdges))
	}

	capped, _ := readPage(0, 999999)
	if capped.Page.Limit != discoveryGraphMaxPageSize || len(capped.Nodes) != discoveryGraphMaxPageSize {
		t.Fatalf("oversized page was not capped: %#v nodes=%d", capped.Page, len(capped.Nodes))
	}
}

func BenchmarkDiscoveryGraphLargeScan(b *testing.B) {
	db, err := store.Open(filepath.Join(b.TempDir(), "scan.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://bench.example.test/", `{"Scan":{"Scope":["https://bench.example.test/"]}}`)
	if err != nil {
		b.Fatal(err)
	}
	tx, err := db.Conn().Begin()
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		if _, err := tx.Exec(`INSERT INTO url_discoveries (scan_id, target_url, source_url, kind) VALUES (?, ?, ?, ?)`, scanID, fmt.Sprintf("https://bench.example.test/items/%05d", i), "https://bench.example.test/", store.DiscoveryHTMLLink); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	s := NewServer(db, b.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	path := fmt.Sprintf("/api/discovery-graph?scan_id=%d&max_nodes=0&scope=in&page_size=1000", scanID)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		s.handleDiscoveryGraph(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			b.Fatalf("status=%d", w.Code)
		}
	}
}
