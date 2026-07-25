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
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestKnowledgeProfileDetailUsesExactEndpointIdentity(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, want := range []string{
		"function profileMatchesEndpoint",
		"function meaningfulProfileIssues",
		"function renderKnowledgeProfileOnly",
		"profileURL.pathname !== endpoint.path",
		"showEndpointDetail(match.hash, p.id)",
		"detailParams.set('profile_id', profileID)",
		"if (d.profile_only)",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("Knowledge detail identity contract missing %q", want)
		}
	}
	if strings.Contains(html, "p.url.includes(e.path)") {
		t.Fatal("Knowledge detail still uses the root-matching URL substring lookup")
	}
}

func TestUnverifiedKnowledgeDetailWithholdsNavigationAndScreenshotActions(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, want := range []string{
		`const routeUnverified = evidenceState.endsWith('_unverified')`,
		`const cantScreenshot = routeUnverified ||`,
		`if (routeUnverified) {`,
		`${fullURL && !routeUnverified ?`,
		`View captured response`,
		`Open URL and Screenshot stay withheld because model inventory is not page evidence.`,
		`Unverified route — not a confirmed page`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("unverified Knowledge action guard missing %q", want)
		}
	}
}

func TestTargetControlledKnowledgeActionsUseDataAttributesNotInlineJSStrings(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, want := range []string{
		`data-profile-id="${idAttr}" onclick="showProfileDetailFromCard(this)"`,
		`const idAttr  = escAttr(p.id || p.endpoint_hash || '')`,
		`data-screenshot-url="${escAttr(fullURL)}" onclick="captureScreenshotFromButton(this)"`,
		`data-open-url="${escAttr(fullURL)}" onclick="openCapturedURL(this)"`,
		`data-target-url="${escAttr(r.url)}" data-response-id="${escAttr(repeaterRespId)}" onclick="sendRepeaterFromButton(this)"`,
		`function capturedHTTPURL`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("safe target-controlled action contract missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`onclick="showProfileDetail('${idAttr}')"`,
		`onclick="captureScreenshot('${esc(fullURL)}', this)"`,
		`onclick="window.open('${esc(d.url)}'`,
		`onclick="screenshotURL('${esc(d.url)}', this)"`,
		`onclick="sendRepeater('${reqId}', '${esc(r.url)}'`,
	} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("target-controlled value remains embedded in inline JavaScript: %q", forbidden)
		}
	}
}

func TestTargetAndModelControlledHTMLUsesQuoteSafeAttributeEscaping(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, want := range []string{
		`String(s).replace(/[&<>"']/g`,
		`'"': '&quot;'`,
		`"'": '&#39;'`,
		`function escAttr(s)`,
		`data-open-url="${escAttr(d.url)}"`,
		`data-screenshot-url="${escAttr(d.url)}"`,
		`data-target-url="${escAttr(d.url)}"`,
		`<option value="${escAttr(m.id)}">`,
		`${esc(shortContentType(e.content_type))}`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("quote-safe render contract missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`function esc(s) { if (!s) return ''`,
		`${shortContentType(e.content_type)}</td>`,
		`data-open-url="${esc(d.url)}"`,
		`data-screenshot-url="${esc(d.url)}"`,
		`data-target-url="${esc(d.url)}"`,
		`<option value="${m.id}">`,
	} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("target/model-controlled attribute remains unsafe: %q", forbidden)
		}
	}
}

func TestKnowledgeProfileWithoutMatchingTrafficIsNotPresentedAsOpen(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "orphan-profile-detail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	const profileID = "GET /admin"
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: profileID, URL: "https://app.example.test/admin", Method: http.MethodGet,
		Purpose: "Administrative console", AuthRequired: "required", Confidence: .92,
		Inputs: []types.Input{{Name: "tenant_id"}}, DataExposed: []string{"tenant records"},
		Issues: []string{"possible privileged surface"},
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	listW := httptest.NewRecorder()
	s.handleProfiles(listW, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/profiles?scan_id=%d", scanID), nil))
	if listW.Code != http.StatusOK {
		t.Fatalf("profile list status=%d body=%s", listW.Code, listW.Body.String())
	}
	var listed []types.PageProfile
	if err := json.Unmarshal(listW.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].EvidenceState != "response_unverified" ||
		listed[0].AuthRequired != "unknown" || listed[0].Confidence != .35 ||
		strings.Contains(listed[0].Purpose, "Administrative console") {
		t.Fatalf("Knowledge card retained OPEN/model semantics: %+v", listed)
	}

	w := httptest.NewRecorder()
	s.handleEndpointDetail(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf(
		"/api/endpoint/detail?scan_id=%d&hash=%s&profile_id=%s",
		scanID, url.QueryEscape(profileID), url.QueryEscape(profileID),
	), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		ProfileOnly   bool   `json:"profile_only"`
		EvidenceState string `json:"evidence_state"`
		Profile       struct {
			EvidenceState string        `json:"evidence_state"`
			EvidenceNote  string        `json:"evidence_note"`
			Purpose       string        `json:"purpose"`
			AuthRequired  string        `json:"auth_required"`
			Confidence    float64       `json:"confidence"`
			Inputs        []types.Input `json:"inputs"`
			DataExposed   []string      `json:"data_exposed"`
			Issues        []string      `json:"issues"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.ProfileOnly || got.EvidenceState != "response_unverified" || got.Profile.EvidenceState != "response_unverified" {
		t.Fatalf("orphan detail verdict = %+v", got)
	}
	if got.Profile.AuthRequired != "unknown" || got.Profile.Confidence != .35 ||
		!strings.Contains(got.Profile.EvidenceNote, "No matching direct HTTP response") ||
		strings.Contains(got.Profile.Purpose, "Administrative console") || len(got.Profile.Inputs) != 0 ||
		len(got.Profile.DataExposed) != 0 || len(got.Profile.Issues) != 0 {
		t.Fatalf("orphan detail retained model semantics: %+v", got.Profile)
	}
}

func TestKnowledgeProfileCannotBorrowUnrelatedEndpointHash(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "profile-evidence-identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	orders := &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://app.example.test/orders"},
		Response: types.CapturedResponse{
			StatusCode: http.StatusOK, ContentType: "text/html",
			Body: []byte(`<html><title>Orders</title><body>Substantive order history</body></html>`),
		},
	}
	if _, err := db.InsertTraffic(scanID, orders); err != nil {
		t.Fatal(err)
	}
	const profileID = "GET /admin"
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: profileID, URL: "https://app.example.test/admin", Method: http.MethodGet,
		Purpose: "Administrative console", Confidence: .95,
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleEndpointDetail(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf(
		"/api/endpoint/detail?scan_id=%d&hash=%s&profile_id=%s",
		scanID, url.QueryEscape(orders.EndpointHash), url.QueryEscape(profileID),
	), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		ProfileOnly   bool   `json:"profile_only"`
		EvidenceState string `json:"evidence_state"`
		Profile       struct {
			EvidenceState string `json:"evidence_state"`
			Purpose       string `json:"purpose"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.ProfileOnly || got.EvidenceState != "response_unverified" || got.Profile.EvidenceState != "response_unverified" {
		t.Fatalf("unrelated /orders response verified /admin: %+v", got)
	}
	if strings.Contains(strings.ToLower(got.Profile.Purpose), "administrative") {
		t.Fatalf("unrelated evidence preserved stale semantics: %+v", got.Profile)
	}
}

func TestKnowledgeActionsRemainBoundToExactQuerySpecimen(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "knowledge-query-specimen.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://app.example.test/", `{}`)
	content := &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://app.example.test/view?id=1"},
		Response: types.CapturedResponse{
			StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte(`<html><body>Record one</body></html>`),
		},
	}
	redirect := &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://app.example.test/view?id=2"},
		Response: types.CapturedResponse{
			StatusCode: http.StatusFound, Headers: map[string]string{"Location": "/login?redirect=%2Fview%3Fid%3D2"},
		},
	}
	for _, entry := range []*types.TrafficEntry{content, redirect} {
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}
	if content.EndpointHash != redirect.EndpointHash {
		t.Fatal("test setup requires query-value siblings to share endpoint identity")
	}
	const profileID = "GET /view"
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: profileID, Method: http.MethodGet, URL: redirect.Request.URL,
		Purpose: "Sensitive record viewer", AuthRequired: "required", Confidence: .95,
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	listW := httptest.NewRecorder()
	s.handleProfiles(listW, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/profiles?scan_id=%d", scanID), nil))
	var profiles []types.PageProfile
	if listW.Code != http.StatusOK || json.Unmarshal(listW.Body.Bytes(), &profiles) != nil || len(profiles) != 1 {
		t.Fatalf("profile list = %d %s", listW.Code, listW.Body.String())
	}
	if profiles[0].EvidenceState != "query_mixed_unverified" ||
		!strings.Contains(profiles[0].EvidenceNote, "does not verify its siblings") ||
		strings.Contains(profiles[0].Purpose, "Sensitive") {
		t.Fatalf("logical Knowledge card borrowed sibling content: %+v", profiles[0])
	}

	detailW := httptest.NewRecorder()
	s.handleEndpointDetail(detailW, httptest.NewRequest(http.MethodGet, fmt.Sprintf(
		"/api/endpoint/detail?scan_id=%d&hash=%s&profile_id=%s",
		scanID, url.QueryEscape(content.EndpointHash), url.QueryEscape(profileID),
	), nil))
	if detailW.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", detailW.Code, detailW.Body.String())
	}
	var detail struct {
		SampleURL     string `json:"sample_url"`
		EvidenceState string `json:"evidence_state"`
		Profile       struct {
			EvidenceState string `json:"evidence_state"`
			Purpose       string `json:"purpose"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(detailW.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.SampleURL != redirect.Request.URL || detail.EvidenceState != "auth_gate_unverified" ||
		detail.Profile.EvidenceState != "query_mixed_unverified" || strings.Contains(detail.Profile.Purpose, "Sensitive") {
		t.Fatalf("Knowledge detail/action borrowed content query sibling: %+v", detail)
	}

	// Graph/endpoint-only entry points share this handler. Their endpoint hash
	// represents the logical family, but the returned action must still bind to
	// one exact specimen and must not attach the id=2 profile to id=1 content.
	endpointW := httptest.NewRecorder()
	s.handleEndpointDetail(endpointW, httptest.NewRequest(http.MethodGet, fmt.Sprintf(
		"/api/endpoint/detail?scan_id=%d&hash=%s",
		scanID, url.QueryEscape(content.EndpointHash),
	), nil))
	if endpointW.Code != http.StatusOK {
		t.Fatalf("endpoint-only detail status=%d body=%s", endpointW.Code, endpointW.Body.String())
	}
	var endpointDetail struct {
		SampleURL     string          `json:"sample_url"`
		EvidenceState string          `json:"evidence_state"`
		StatusCodes   []int           `json:"status_codes"`
		Profile       json.RawMessage `json:"profile"`
	}
	if err := json.Unmarshal(endpointW.Body.Bytes(), &endpointDetail); err != nil {
		t.Fatal(err)
	}
	if endpointDetail.SampleURL != content.Request.URL || endpointDetail.EvidenceState != "content_observed" ||
		len(endpointDetail.StatusCodes) != 1 || endpointDetail.StatusCodes[0] != http.StatusOK || len(endpointDetail.Profile) != 0 {
		t.Fatalf("endpoint-only detail mixed exact query specimens: %+v", endpointDetail)
	}
}

func TestRedirectOnlyProfileIsProjectedAsUnverifiedTransport(t *testing.T) {
	profile := &types.PageProfile{
		URL:          "https://partner.example.test/admin",
		Purpose:      "Administrative dashboard for partners",
		AuthRequired: "session_cookie",
		Confidence:   0.8,
		DataExposed:  []string{"partner records"},
	}
	entries := []types.TrafficEntry{{
		Request: types.CapturedRequest{Method: "GET", URL: profile.URL, Path: "/admin"},
		Response: types.CapturedResponse{StatusCode: 302, Headers: map[string]string{
			"Location": "/account/logout?redirect=%2Fadmin",
		}},
	}}

	annotateProfileRedirectEvidence(profile, entries)
	if profile.EvidenceState != "auth_gate_unverified" {
		t.Fatalf("evidence state = %q", profile.EvidenceState)
	}
	if !strings.Contains(strings.ToLower(profile.Purpose), "unverified") ||
		strings.Contains(strings.ToLower(profile.Purpose), "administrative dashboard") {
		t.Fatalf("purpose = %q", profile.Purpose)
	}
	if profile.AuthRequired != "unknown" || profile.Confidence != 0.35 || len(profile.DataExposed) != 0 {
		t.Fatalf("projected profile = %+v", profile)
	}
}

func TestEndpointDetailKeepsKnownNonContentResponseUnverified(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "endpoint-detail-unverified.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const targetURL = "https://partner.example.test/admin"
	scanID, err := db.CreateScan("https://partner.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	entry := &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: targetURL},
		Response: types.CapturedResponse{
			StatusCode:  http.StatusNotFound,
			Headers:     map[string]string{},
			ContentType: "text/html",
			Body:        []byte(`<html><body><h1>Page not found</h1></body></html>`),
		},
	}
	if _, err := db.InsertTraffic(scanID, entry); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: "GET /admin", URL: targetURL, Method: http.MethodGet,
		Purpose: "Administrative dashboard", Confidence: .95,
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf(
		"/api/endpoint/detail?scan_id=%d&hash=%s&profile_id=%s",
		scanID, url.QueryEscape(entry.EndpointHash), url.QueryEscape("GET /admin"),
	), nil)
	w := httptest.NewRecorder()
	s.handleEndpointDetail(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		EvidenceState string `json:"evidence_state"`
		RedirectOnly  bool   `json:"redirect_only"`
		Profile       struct {
			EvidenceState string  `json:"evidence_state"`
			Confidence    float64 `json:"confidence"`
			Purpose       string  `json:"purpose"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.EvidenceState != "response_unverified" || payload.RedirectOnly {
		t.Fatalf("top-level evidence verdict = %+v", payload)
	}
	if payload.Profile.EvidenceState != "response_unverified" || payload.Profile.Confidence != .35 ||
		!strings.Contains(strings.ToLower(payload.Profile.Purpose), "unverified") ||
		strings.Contains(strings.ToLower(payload.Profile.Purpose), "administrative dashboard") {
		t.Fatalf("profile evidence verdict = %+v", payload.Profile)
	}
}

func TestKnowledgeDetailUsesProgressiveDisclosure(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, want := range []string{
		"function knowledgeDetailDisclosure",
		"const compactKnowledge = Boolean(profileID)",
		"addSupportingDetail('Discovery & agent activity'",
		"addSupportingDetail('Behavior & technical notes'",
		"addSupportingDetail('Inputs & forms'",
		"addSupportingDetail('Response structure'",
		"addSupportingDetail('HTTP request / response'",
		"<details class=\"detail-disclosure\">",
		"<div class=\"detail-disclosures-label\">Supporting details</div>",
		"else html += bodyHTML",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("Knowledge progressive-disclosure contract missing %q", want)
		}
	}
}

func TestSyntheticKnowledgeProfileReturnsStoredRoutesWithoutTraffic(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "synthetic-knowledge-detail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	const routesJSON = `[
		{"method":"GET","path":"/api/catalog","source":"https://app.example.test/app.js","context":"fetch catalog","auth_type":"none","kind":"api"},
		{"method":"POST","path":"/api/orders","params":["itemId"],"source":"https://app.example.test/app.js","context":"create order","auth_type":"bearer","kind":"api"}
	]`
	if _, err := db.Conn().Exec(`
		INSERT INTO page_profiles (id, scan_id, url, method, purpose, issues, confidence)
		VALUES ('js_discovered_routes', ?, 'JavaScript source analysis', '',
		        'Discovered 2 routes from JavaScript analysis', ?, 0.7)`, scanID, routesJSON); err != nil {
		t.Fatal(err)
	}

	profile, err := db.GetProfile(scanID, "js_discovered_routes")
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.Issues) != 0 {
		t.Fatalf("structured routes leaked into security issues: %#v", profile.Issues)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf(
		"/api/endpoint/detail?scan_id=%d&hash=js_discovered_routes&profile_id=js_discovered_routes", scanID,
	), nil)
	w := httptest.NewRecorder()
	s.handleEndpointDetail(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		ProfileOnly bool `json:"profile_only"`
		Profile     struct {
			Purpose string   `json:"purpose"`
			Issues  []string `json:"issues"`
		} `json:"profile"`
		Artifact struct {
			Kind   string `json:"kind"`
			Routes []struct {
				Method string `json:"method"`
				Path   string `json:"path"`
			} `json:"routes"`
		} `json:"artifact"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.ProfileOnly || got.Artifact.Kind != "javascript_routes" || len(got.Artifact.Routes) != 2 {
		t.Fatalf("unexpected synthetic detail: %+v", got)
	}
	if got.Artifact.Routes[1].Method != "POST" || got.Artifact.Routes[1].Path != "/api/orders" {
		t.Fatalf("route detail lost: %+v", got.Artifact.Routes)
	}
	if got.Profile.Purpose != "Discovered 2 routes from JavaScript analysis" || len(got.Profile.Issues) != 0 {
		t.Fatalf("profile detail=%+v", got.Profile)
	}
}

func TestEndpointDetailKeepsRequestedKnowledgeProfile(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "knowledge-detail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	root := &types.TrafficEntry{
		EndpointHash: "root-hash",
		Request:      types.CapturedRequest{Method: "GET", URL: "https://app.example.test/"},
		Response:     types.CapturedResponse{StatusCode: 556, ContentType: "application/json", Body: []byte(`{"message":"root"}`)},
	}
	search := &types.TrafficEntry{
		EndpointHash: "search-hash",
		Request:      types.CapturedRequest{Method: "GET", URL: "https://api.example.test/mp/search/most-popular-trainings/guest"},
		Response:     types.CapturedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"courses":[]}`)},
	}
	for _, entry := range []*types.TrafficEntry{root, search} {
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}
	const profileID = "GET /mp/search/most-popular-trainings/guest"
	const purpose = "Public LMS backend API returning popular training courses."
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: profileID, URL: search.Request.URL, Method: "GET", Purpose: purpose, IsAPI: true,
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf(
		"/api/endpoint/detail?scan_id=%d&hash=%s&profile_id=%s",
		scanID, url.QueryEscape(search.EndpointHash), url.QueryEscape(profileID),
	), nil)
	w := httptest.NewRecorder()
	s.handleEndpointDetail(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Method      string `json:"method"`
		URLPattern  string `json:"url_pattern"`
		SampleURL   string `json:"sample_url"`
		StatusCodes []int  `json:"status_codes"`
		Profile     struct {
			ID      string `json:"id"`
			Purpose string `json:"purpose"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Method != "GET" || got.SampleURL != search.Request.URL || strings.Contains(got.URLPattern, "app.example.test") {
		t.Fatalf("detail resolved wrong endpoint: %+v", got)
	}
	if len(got.StatusCodes) != 1 || got.StatusCodes[0] != 200 {
		t.Fatalf("status codes=%v, want [200]", got.StatusCodes)
	}
	if got.Profile.ID != profileID || got.Profile.Purpose != purpose {
		t.Fatalf("profile=%+v, want id=%q purpose=%q", got.Profile, profileID, purpose)
	}
}

func TestEndpointDetailResolvesProfileIDWithoutCachedEndpointHash(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "knowledge-profile-ref.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://api.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	entry := &types.TrafficEntry{
		Request:  types.CapturedRequest{Method: "GET", URL: "https://api.example.test/catalog/featured"},
		Response: types.CapturedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"items":[]}`)},
	}
	if _, err := db.InsertTraffic(scanID, entry); err != nil {
		t.Fatal(err)
	}
	const profileID = "GET /catalog/featured"
	if err := db.UpsertProfile(scanID, &types.PageProfile{ID: profileID, URL: entry.Request.URL, Method: "GET", Purpose: "Featured catalog"}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf(
		"/api/endpoint/detail?scan_id=%d&hash=%s&profile_id=%s",
		scanID, url.QueryEscape(profileID), url.QueryEscape(profileID),
	), nil)
	w := httptest.NewRecorder()
	s.handleEndpointDetail(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
