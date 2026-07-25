package extract

import (
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

// mkEntry is a small factory so individual tests stay readable. All fields
// default to sensible empty values; tests override just what they need.
func mkEntry(id int64, method, url, path, query string, reqHeaders map[string]string, reqBody []byte,
	status int, respHeaders map[string]string, respCT string, respBody []byte, hash string) types.TrafficEntry {
	return types.TrafficEntry{
		ID: id,
		Request: types.CapturedRequest{
			Method:  method,
			URL:     url,
			Path:    path,
			Query:   query,
			Headers: reqHeaders,
			Body:    reqBody,
		},
		Response: types.CapturedResponse{
			StatusCode:  status,
			Headers:     respHeaders,
			ContentType: respCT,
			Body:        respBody,
			Size:        int64(len(respBody)),
		},
		EndpointHash: hash,
	}
}

// TestBuildEndpointBundle_Empty — nil/empty input must not panic, returns nil.
func TestBuildEndpointBundle_Empty(t *testing.T) {
	if BuildEndpointBundle(nil, 20) != nil {
		t.Error("nil entries should give nil bundle")
	}
	if BuildEndpointBundle([]types.TrafficEntry{}, 20) != nil {
		t.Error("empty entries should give nil bundle")
	}
}

// TestBuildEndpointBundle_BasicMerging — param collection across entries
// detects required vs optional params.
func TestBuildEndpointBundle_BasicMerging(t *testing.T) {
	// Two requests to same endpoint, different query strings
	e1 := mkEntry(1, "GET", "https://ex.com/search?q=foo&page=1",
		"/search", "q=foo&page=1",
		nil, nil,
		200, map[string]string{"content-type": "text/html"}, "text/html", []byte(`<html></html>`),
		"hash1")
	e2 := mkEntry(2, "GET", "https://ex.com/search?q=bar",
		"/search", "q=bar",
		nil, nil,
		200, map[string]string{"content-type": "text/html"}, "text/html", []byte(`<html></html>`),
		"hash1")

	b := BuildEndpointBundle([]types.TrafficEntry{e1, e2}, 20)
	if b == nil {
		t.Fatal("nil bundle")
	}
	if b.EntryCount != 2 {
		t.Errorf("EntryCount: got %d, want 2", b.EntryCount)
	}
	if b.Method != "GET" {
		t.Errorf("Method: got %q, want GET", b.Method)
	}

	byName := map[string]ParamVariant{}
	for _, p := range b.QueryParams {
		byName[p.Name] = p
	}

	// q appears in both → required
	q, ok := byName["q"]
	if !ok {
		t.Fatal("param q missing")
	}
	if !q.Required {
		t.Error("q should be Required (present in all)")
	}

	// page only in one → not required
	page, ok := byName["page"]
	if !ok {
		t.Fatal("param page missing")
	}
	if page.Required {
		t.Error("page should NOT be Required (missing from e2)")
	}
}

func TestBuildEndpointBundle_IgnoresStaticAssetCacheBusters(t *testing.T) {
	e := mkEntry(1, "GET", "https://ex.com/app.js?abc123",
		"/app.js", "abc123",
		nil, nil,
		200, nil, "application/javascript", []byte(`console.log("ok")`),
		"hash-js")

	b := BuildEndpointBundle([]types.TrafficEntry{e}, 20)
	if b == nil {
		t.Fatal("nil bundle")
	}
	if b.HasInput {
		t.Fatalf("cache-busted static asset should not be marked HasInput: %#v", b.QueryParams)
	}
	if len(b.QueryParams) != 0 {
		t.Fatalf("cache-buster query should not be collected as params: %#v", b.QueryParams)
	}
}

func TestBuildEndpointBundleIgnoresWordPressStaticMCacheBuster(t *testing.T) {
	e := mkEntry(1, "GET", "https://ex.com/plugin/app.js?m=1784576895g",
		"/plugin/app.js", "m=1784576895g",
		nil, nil,
		200, nil, "application/javascript", []byte(`console.log("ok")`),
		"hash-js-m")
	b := BuildEndpointBundle([]types.TrafficEntry{e}, 20)
	if b == nil || b.HasInput || len(b.QueryParams) != 0 {
		t.Fatalf("WordPress m cache-buster became application input: %+v", b)
	}
}

func TestBuildEndpointBundle_KeepsRealQueryInputOnHTMLRoute(t *testing.T) {
	e := mkEntry(1, "GET", "https://ex.com/search?q=milk",
		"/search", "q=milk",
		nil, nil,
		200, nil, "text/html", []byte(`<html></html>`),
		"hash-search")

	b := BuildEndpointBundle([]types.TrafficEntry{e}, 20)
	if b == nil {
		t.Fatal("nil bundle")
	}
	if !b.HasInput {
		t.Fatal("HTML route query should remain input")
	}
	if len(b.QueryParams) != 1 || b.QueryParams[0].Name != "q" {
		t.Fatalf("query input not preserved: %#v", b.QueryParams)
	}
}

// TestBuildEndpointBundle_HTMLExtraction — largest HTML response used for
// extraction; HasInput flipped when a form is present.
func TestBuildEndpointBundle_HTMLExtraction(t *testing.T) {
	// First: tiny HTML, no form. Second: full login form (larger).
	small := []byte(`<html><body><p>tiny</p></body></html>`)
	big := []byte(`<html><body><form action="/login" method="POST">
<input type="email" name="email"><input type="password" name="password">
</form></body></html>`)

	e1 := mkEntry(1, "GET", "https://ex.com/login", "/login", "", nil, nil,
		200, nil, "text/html", small, "hash1")
	e2 := mkEntry(2, "GET", "https://ex.com/login", "/login", "", nil, nil,
		200, nil, "text/html", big, "hash1")

	b := BuildEndpointBundle([]types.TrafficEntry{e1, e2}, 20)
	if b == nil || b.HTMLExtraction == nil {
		t.Fatal("expected HTML extraction")
	}
	if len(b.HTMLExtraction.Forms) != 1 {
		t.Errorf("Forms: got %d, want 1", len(b.HTMLExtraction.Forms))
	}
	if !b.HasInput {
		t.Error("HasInput should be true (form has inputs)")
	}
	if b.IsAPI {
		t.Error("IsAPI should be false for HTML response")
	}
}

// TestBuildEndpointBundle_JSONAPI — JSON response triggers IsAPI + schema
// extraction; Auth header flips HasAuth.
func TestBuildEndpointBundle_JSONAPI(t *testing.T) {
	reqHeaders := map[string]string{
		"Authorization": "Bearer abc.def.ghi",
		"Content-Type":  "application/json",
	}
	jsonBody := []byte(`[{"id":1,"email":"a@b.com"},{"id":2,"email":"c@d.com"}]`)

	e := mkEntry(1, "GET", "https://ex.com/api/users", "/api/users", "",
		reqHeaders, nil,
		200, map[string]string{"content-type": "application/json"}, "application/json", jsonBody,
		"hash1")

	b := BuildEndpointBundle([]types.TrafficEntry{e}, 20)
	if b == nil {
		t.Fatal("nil bundle")
	}
	if !b.IsAPI {
		t.Error("IsAPI should be true")
	}
	if !b.HasAuth {
		t.Error("HasAuth should be true (Authorization header)")
	}
	if b.JSONSchema == nil {
		t.Fatal("JSONSchema should be populated")
	}
	if b.JSONSchema.ArrayCounts["$root"] != 2 {
		t.Errorf("root array count: got %d, want 2", b.JSONSchema.ArrayCounts["$root"])
	}

	// Authorization should be in the security-relevant headers
	if _, ok := b.RequestHeaders["authorization"]; !ok {
		t.Errorf("Authorization header missing from RequestHeaders: %v", b.RequestHeaders)
	}
}

// TestBuildEndpointBundle_JSONBodyParams — POST with JSON body parses into
// BodyParams collection.
func TestBuildEndpointBundle_JSONBodyParams(t *testing.T) {
	reqHeaders := map[string]string{"content-type": "application/json"}
	body := []byte(`{"email":"a@b.com","password":"hunter2","remember":true}`)

	e := mkEntry(1, "POST", "https://ex.com/auth/login", "/auth/login", "",
		reqHeaders, body,
		200, nil, "application/json", []byte(`{"token":"xyz"}`),
		"hash1")

	b := BuildEndpointBundle([]types.TrafficEntry{e}, 20)
	if b == nil {
		t.Fatal("nil bundle")
	}
	if !b.HasInput {
		t.Error("HasInput should be true (body params present)")
	}

	byName := map[string]ParamVariant{}
	for _, p := range b.BodyParams {
		byName[p.Name] = p
	}

	if p, ok := byName["email"]; !ok {
		t.Error("body param email missing")
	} else if p.Type != "email" {
		t.Errorf("email param type: got %q, want email", p.Type)
	}

	if p, ok := byName["password"]; !ok {
		t.Error("body param password missing")
	} else if p.Type != "password" {
		t.Errorf("password param type: got %q, want password", p.Type)
	}
}

// TestBuildEndpointBundle_FormURLEncoded — x-www-form-urlencoded body.
func TestBuildEndpointBundle_FormURLEncoded(t *testing.T) {
	reqHeaders := map[string]string{"content-type": "application/x-www-form-urlencoded"}
	body := []byte(`username=alice&password=secret&csrf_token=abc`)

	e := mkEntry(1, "POST", "https://ex.com/login", "/login", "",
		reqHeaders, body,
		302, nil, "text/html", nil,
		"hash1")

	b := BuildEndpointBundle([]types.TrafficEntry{e}, 20)
	if b == nil {
		t.Fatal("nil bundle")
	}

	names := map[string]bool{}
	for _, p := range b.BodyParams {
		names[p.Name] = true
	}
	for _, want := range []string{"username", "password", "csrf_token"} {
		if !names[want] {
			t.Errorf("body param %q missing; got %v", want, names)
		}
	}
}

// TestBuildEndpointBundle_StatusCodesUnion — distinct status codes across
// entries preserved.
func TestBuildEndpointBundle_StatusCodesUnion(t *testing.T) {
	e1 := mkEntry(1, "POST", "https://ex.com/login", "/login", "", nil, nil,
		200, nil, "application/json", []byte(`{}`), "hash1")
	e2 := mkEntry(2, "POST", "https://ex.com/login", "/login", "", nil, nil,
		422, nil, "application/json", []byte(`{"error":"bad"}`), "hash1")
	e3 := mkEntry(3, "POST", "https://ex.com/login", "/login", "", nil, nil,
		200, nil, "application/json", []byte(`{}`), "hash1")

	b := BuildEndpointBundle([]types.TrafficEntry{e1, e2, e3}, 20)
	if b == nil {
		t.Fatal("nil bundle")
	}

	codes := map[int]bool{}
	for _, c := range b.StatusCodes {
		codes[c] = true
	}
	if !codes[200] || !codes[422] {
		t.Errorf("expected {200, 422} status codes, got %v", b.StatusCodes)
	}
	if !b.HasErrors {
		t.Error("HasErrors should be true for 422 response")
	}
}

// TestBuildEndpointBundle_MaxEntriesCap — respects maxEntries limit.
func TestBuildEndpointBundle_MaxEntriesCap(t *testing.T) {
	entries := make([]types.TrafficEntry, 50)
	for i := range entries {
		entries[i] = mkEntry(int64(i), "GET", "https://ex.com/x", "/x", "",
			nil, nil, 200, nil, "text/html", []byte(`<html></html>`), "hash1")
	}
	b := BuildEndpointBundle(entries, 10)
	if b == nil {
		t.Fatal("nil bundle")
	}
	if b.EntryCount != 10 {
		t.Errorf("EntryCount capped: got %d, want 10", b.EntryCount)
	}
	if len(b.TrafficIDs) != 10 {
		t.Errorf("TrafficIDs: got %d, want 10", len(b.TrafficIDs))
	}
}

// TestBuildEndpointBundle_InputSignature — bundles from same template
// (same form structure) produce identical input signatures even when the
// URLs and body values differ.
func TestBuildEndpointBundle_InputSignature(t *testing.T) {
	htmlTpl := func(id string) []byte {
		return []byte(`<html><body><form action="/cart/add" method="POST">
<input type="hidden" name="product_id" value="` + id + `">
<input type="number" name="qty" value="1">
</form></body></html>`)
	}

	eA := mkEntry(1, "GET", "https://ex.com/p/a", "/p/a", "", nil, nil,
		200, nil, "text/html", htmlTpl("42"), "hashA")
	eB := mkEntry(2, "GET", "https://ex.com/p/b", "/p/b", "", nil, nil,
		200, nil, "text/html", htmlTpl("99"), "hashB")

	bA := BuildEndpointBundle([]types.TrafficEntry{eA}, 20)
	bB := BuildEndpointBundle([]types.TrafficEntry{eB}, 20)

	sigA := bA.InputSignature()
	sigB := bB.InputSignature()
	if sigA == "" {
		t.Fatal("empty signature A")
	}
	if sigA != sigB {
		t.Errorf("product template pages should share signature:\n  A=%s\n  B=%s", sigA, sigB)
	}
}

// TestBuildEndpointBundle_QueryParamsFlipHasInput — regression: query
// params are input too. GET /search?q=foo MUST flip HasInput so downstream
// prioritization and reasoners see the attack surface.
func TestBuildEndpointBundle_QueryParamsFlipHasInput(t *testing.T) {
	e := mkEntry(1, "GET", "https://ex.com/search?q=foo",
		"/search", "q=foo",
		nil, nil,
		200, nil, "application/json", []byte(`{"results":[]}`),
		"hash1")

	b := BuildEndpointBundle([]types.TrafficEntry{e}, 20)
	if b == nil {
		t.Fatal("nil bundle")
	}
	if len(b.QueryParams) == 0 {
		t.Fatal("expected query params to be collected")
	}
	if !b.HasInput {
		t.Error("HasInput should be true when query params exist")
	}
}

// TestBuildCorpusTemplate_ExampleBFFSurvives — when multiple requests
// share long-but-stable BFF service names in a path, those segments must
// remain literal. The previous per-URL regex turned anything ≥20 chars
// into `{token}`, which collapsed Example's
// `/discovery-storefrontmarketing-marketinggw-service/internal-linking-seo/butik/liste/1/kadin`
// into `/{token}/{token}/butik/liste/{id}/kadin`. With corpus alignment
// the service-name segments stay literal because they don't vary across
// observations.
func TestBuildCorpusTemplate_ExampleBFFSurvives(t *testing.T) {
	const svc = "/discovery-storefrontmarketing-marketinggw-service/internal-linking-seo"
	mk := func(id int64, idSeg string) types.TrafficEntry {
		path := svc + "/butik/liste/" + idSeg + "/kadin"
		return mkEntry(id, "GET", "https://www.example.com"+path, path, "", nil, nil, 200, nil, "application/json", []byte(`{}`), "hash1")
	}
	entries := []types.TrafficEntry{mk(1, "1"), mk(2, "2"), mk(3, "47")}

	b := BuildEndpointBundle(entries, 20)
	if b == nil {
		t.Fatal("nil bundle")
	}
	want := svc + "/butik/liste/{id}/kadin"
	if b.URLPattern != want {
		t.Errorf("URLPattern:\n  got:  %q\n  want: %q", b.URLPattern, want)
	}
}

// TestBuildCorpusTemplate_AmbiguousSegmentMarked — when a varying segment
// can't be regex-classified (slug-style values), it gets `{seg}` and the
// distinct examples are exposed for the analyzer's LLM-refinement pass.
func TestBuildCorpusTemplate_AmbiguousSegmentMarked(t *testing.T) {
	mk := func(id int64, lang string) types.TrafficEntry {
		path := "/api/" + lang + "/products"
		return mkEntry(id, "GET", "https://ex.com"+path, path, "", nil, nil, 200, nil, "application/json", nil, "hash2")
	}
	entries := []types.TrafficEntry{mk(1, "en"), mk(2, "tr"), mk(3, "de")}
	b := BuildEndpointBundle(entries, 20)
	if b == nil {
		t.Fatal("nil bundle")
	}
	if b.URLPattern != "/api/{seg}/products" {
		t.Errorf("URLPattern: got %q, want %q", b.URLPattern, "/api/{seg}/products")
	}
	if len(b.SegmentSamples) != 1 || len(b.SegmentSamples[0]) != 3 {
		t.Errorf("expected one ambiguous position with 3 samples, got %v", b.SegmentSamples)
	}
}

// TestBuildCorpusTemplate_SingleEntryFallsBackToPerURL — single-entry
// bundles can't be aligned, so the legacy normalizer applies.
func TestBuildCorpusTemplate_SingleEntryFallsBackToPerURL(t *testing.T) {
	e := mkEntry(1, "GET", "https://ex.com/users/42", "/users/42", "", nil, nil, 200, nil, "application/json", nil, "hash3")
	b := BuildEndpointBundle([]types.TrafficEntry{e}, 20)
	if b == nil {
		t.Fatal("nil bundle")
	}
	if b.URLPattern != "/users/{id}" {
		t.Errorf("URLPattern: got %q, want %q", b.URLPattern, "/users/{id}")
	}
}

// TestNormalizePathForDisplay — numeric IDs and tokens swapped out.
func TestNormalizePathForDisplay(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/users/42", "/users/{id}"},
		{"/api/v1/orders/12345", "/api/v1/orders/{id}"},
		{"/products/550e8400-e29b-41d4-a716-446655440000", "/products/{id}"},
		{"/session/abcdefghijklmnopqrstuvwxyz123", "/session/{token}"},
		{"/rest/admin/application-configuration", "/rest/admin/application-configuration"},
		{"/session/dGhpcy1pc19hX2xvbmdfdG9rZW4", "/session/{token}"},
		{"/", "/"},
		{"/no/ids/here", "/no/ids/here"},
	}
	for _, c := range cases {
		got := normalizePathForDisplay(c.in)
		if got != c.want {
			t.Errorf("normalizePathForDisplay(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
