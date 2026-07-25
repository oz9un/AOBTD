package extract

import (
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

// TestNewAppUnderstanding — starts empty with a usable map.
func TestNewAppUnderstanding(t *testing.T) {
	u := NewAppUnderstanding()
	if u == nil {
		t.Fatal("nil understanding")
	}
	if u.AnalyzedHashes == nil {
		t.Error("AnalyzedHashes should be initialized")
	}
	if len(u.PageTemplates) != 0 {
		t.Errorf("PageTemplates should start empty, got %d", len(u.PageTemplates))
	}
	if u.IsAnalyzed("any") {
		t.Error("empty understanding should not report any hash as analyzed")
	}
}

// TestMarkAnalyzedAndLookup — MarkAnalyzed records hash; IsAnalyzed confirms.
func TestMarkAnalyzedAndLookup(t *testing.T) {
	u := NewAppUnderstanding()
	u.MarkAnalyzed("hash-abc", "tpl-login")
	u.MarkAnalyzed("hash-xyz", "")

	if !u.IsAnalyzed("hash-abc") {
		t.Error("hash-abc should be analyzed")
	}
	if !u.IsAnalyzed("hash-xyz") {
		t.Error("hash-xyz should be analyzed (even with empty template)")
	}
	if u.AnalyzedHashes["hash-xyz"] != "unique" {
		t.Errorf("empty templateID should map to 'unique', got %q", u.AnalyzedHashes["hash-xyz"])
	}
	if u.IsAnalyzed("hash-none") {
		t.Error("hash-none should NOT be analyzed")
	}
}

// TestRegisterAndMatchTemplate — after registering a template, bundles with
// the same input signature should match; different signature should not.
func TestRegisterAndMatchTemplate(t *testing.T) {
	u := NewAppUnderstanding()

	// Two bundles sharing an input signature (same form structure)
	htmlA := []byte(`<html><body><form action="/login" method="POST">
<input type="email" name="email"><input type="password" name="password">
</form></body></html>`)
	htmlB := []byte(`<html><body><form action="/login" method="POST">
<input type="email" name="email"><input type="password" name="password">
</form></body></html>`)

	entryA := mkEntry(1, "GET", "https://ex.com/login", "/login", "",
		nil, nil, 200, nil, "text/html", htmlA, "hashA")
	entryB := mkEntry(2, "GET", "https://ex.com/login", "/login", "",
		nil, nil, 200, nil, "text/html", htmlB, "hashB")

	bundleA := BuildEndpointBundle([]types.TrafficEntry{entryA}, 20)
	bundleB := BuildEndpointBundle([]types.TrafficEntry{entryB}, 20)

	// Before registration — no match
	if id, ok := u.MatchTemplate(bundleA); ok {
		t.Errorf("unexpected match before registration: id=%s", id)
	}

	// Register template from bundleA
	u.RegisterTemplate("login_form", "Standard login form", bundleA)

	// bundleB should match the same template
	id, ok := u.MatchTemplate(bundleB)
	if !ok {
		t.Fatal("bundleB should match registered template")
	}
	if id != "login_form" {
		t.Errorf("matched template ID: got %q, want login_form", id)
	}
}

func TestMatchTemplateLessonFamiliesMustStayInSameModule(t *testing.T) {
	u := NewAppUnderstanding()
	body := []byte(`{"content":"same shape","isValid":true}`)

	idorEntry := mkEntry(1, "GET",
		"https://ex.com/VulnerableApp/IDORVulnerability/LEVEL_5",
		"/VulnerableApp/IDORVulnerability/LEVEL_5", "",
		nil, nil, 200, nil, "application/json", body, "idor")
	idorBundle := BuildEndpointBundle([]types.TrafficEntry{idorEntry}, 20)
	u.RegisterTemplate("get_VulnerableApp_IDORVulnerability_LEVEL_5", "IDOR lesson", idorBundle)

	authEntry := mkEntry(2, "GET",
		"https://ex.com/VulnerableApp/AuthenticationVulnerability/LEVEL_3",
		"/VulnerableApp/AuthenticationVulnerability/LEVEL_3", "",
		nil, nil, 200, nil, "application/json", body, "auth")
	authBundle := BuildEndpointBundle([]types.TrafficEntry{authEntry}, 20)
	if id, ok := u.MatchTemplate(authBundle); ok {
		t.Fatalf("different lesson module matched template %q", id)
	}
}

func TestMatchTemplateLessonFamiliesIgnoreLevelNumberWithinSameModule(t *testing.T) {
	u := NewAppUnderstanding()
	body := []byte(`{"content":"same shape","isValid":true}`)

	level4Entry := mkEntry(1, "GET",
		"https://ex.com/VulnerableApp/PathTraversal/LEVEL_4",
		"/VulnerableApp/PathTraversal/LEVEL_4", "",
		nil, nil, 200, nil, "application/json", body, "pt4")
	level4Bundle := BuildEndpointBundle([]types.TrafficEntry{level4Entry}, 20)
	u.RegisterTemplate("get_VulnerableApp_PathTraversal_LEVEL_4", "Path traversal lesson", level4Bundle)

	level7Entry := mkEntry(2, "GET",
		"https://ex.com/VulnerableApp/PathTraversal/LEVEL_7",
		"/VulnerableApp/PathTraversal/LEVEL_7", "",
		nil, nil, 200, nil, "application/json", body, "pt7")
	level7Bundle := BuildEndpointBundle([]types.TrafficEntry{level7Entry}, 20)
	id, ok := u.MatchTemplate(level7Bundle)
	if !ok || id != "get_VulnerableApp_PathTraversal_LEVEL_4" {
		t.Fatalf("same lesson module should match ignoring level number; id=%q ok=%v", id, ok)
	}
}

func TestMatchTemplateSkipsDifferentObservedSemanticFamilies(t *testing.T) {
	u := NewAppUnderstanding()
	sharedChrome := []byte(`<html><body><form><input name="q"></form><main>content</main></body></html>`)

	communityEntry := mkEntry(1, "GET", "https://ex.com/community/", "/community/", "",
		nil, nil, 200, nil, "text/html", sharedChrome, "community")
	communityBundle := BuildEndpointBundle([]types.TrafficEntry{communityEntry}, 20)
	u.RegisterTemplate("get_community", "PostgreSQL community hub", communityBundle)

	downloadEntry := mkEntry(2, "GET", "https://ex.com/download/product-categories/", "/download/product-categories/", "",
		nil, nil, 200, nil, "text/html", sharedChrome, "download")
	downloadBundle := BuildEndpointBundle([]types.TrafficEntry{downloadEntry}, 20)
	if id, ok := u.MatchTemplate(downloadBundle); ok {
		t.Fatalf("catalog route should bypass unrelated community template, matched %q", id)
	}
}

func TestMatchTemplateAllowsExplicitSharedShellAcrossFamilies(t *testing.T) {
	u := NewAppUnderstanding()
	sharedChrome := []byte(`<html><body><form><input name="q"></form><main>content</main></body></html>`)

	communityEntry := mkEntry(1, "GET", "https://ex.com/community/", "/community/", "",
		nil, nil, 200, nil, "text/html", sharedChrome, "community")
	communityBundle := BuildEndpointBundle([]types.TrafficEntry{communityEntry}, 20)
	u.RegisterTemplate("site_shell", "Shared site shell and base layout", communityBundle)

	downloadEntry := mkEntry(2, "GET", "https://ex.com/download/products/", "/download/products/", "",
		nil, nil, 200, nil, "text/html", sharedChrome, "download")
	downloadBundle := BuildEndpointBundle([]types.TrafficEntry{downloadEntry}, 20)
	if id, ok := u.MatchTemplate(downloadBundle); !ok || id != "site_shell" {
		t.Fatalf("explicit shared shell should remain reusable, id=%q ok=%v", id, ok)
	}
}

func TestMatchTemplateUsesResponseSketchForOpaqueDocumentationRoute(t *testing.T) {
	u := NewAppUnderstanding()
	page := func(path, title string) *EndpointBundle {
		html := []byte(`<html><head><title>` + title + `</title></head><body><form action="/search"><input name="q"></form><h1>` + title + `</h1><pre>example</pre></body></html>`)
		entry := mkEntry(1, "GET", "https://ex.com"+path, path, "", nil, nil, 200, nil, "text/html", html, path)
		return BuildEndpointBundle([]types.TrafficEntry{entry}, 20)
	}

	// Register the tempting wrong family first to prove selection does not
	// depend on template insertion order or the shared search form.
	news := page("/news.html", "Recent SQLite News")
	u.RegisterTemplate("get_news", "Release announcements and changelog entries", news)
	docs := page("/docs.html", "SQLite Documentation and API Reference")
	u.RegisterTemplate("get_docs", "Technical documentation index", docs)

	opaque := page("/fts3.html", "SQLite FTS3 and FTS4 Extensions")
	id, ok := u.MatchTemplate(opaque)
	if !ok || id != "get_docs" {
		t.Fatalf("opaque documentation route matched id=%q ok=%v, templates=%+v sketch=%+v", id, ok, u.PageTemplates, opaque.SemanticSketch())
	}
	if u.PageTemplates[0].SemanticFamily != "content" || u.PageTemplates[1].SemanticFamily != "developer" {
		t.Fatalf("registered semantic sketches were not persisted: %+v", u.PageTemplates)
	}
}

func TestMatchTemplateKeepsFAQAndProfessionalSupportFacetsSeparate(t *testing.T) {
	page := func(path, title string) *EndpointBundle {
		html := []byte(`<html><head><title>` + title + `</title></head><body><form action="/search"><input name="q"></form><h1>` + title + `</h1></body></html>`)
		entry := mkEntry(1, "GET", "https://ex.com"+path, path, "", nil, nil, 200, nil, "text/html", html, path)
		return BuildEndpointBundle([]types.TrafficEntry{entry}, 20)
	}
	u := NewAppUnderstanding()
	u.RegisterTemplate("get_faq", "Frequently asked questions", page("/faq.html", "Frequently Asked Questions"))
	if id, ok := u.MatchTemplate(page("/prosupport.html", "Professional Support Services")); ok {
		t.Fatalf("professional support matched FAQ template %q", id)
	}
}

func TestMatchTemplatePrefersExactLearnedRouteOverConflictingSemanticLabel(t *testing.T) {
	html := []byte(`<html><head><title>Release Notes</title></head><body><form action="/search"><input name="q"></form><h1>Release Notes</h1></body></html>`)
	entry := mkEntry(1, "GET", "https://ex.com/about", "/about", "", nil, nil, 200, nil, "text/html", html, "about")
	bundle := BuildEndpointBundle([]types.TrafficEntry{entry}, 20)

	u := NewAppUnderstanding()
	u.RegisterTemplate("get_about", "About the community", bundle)
	// Simulate an older model-authored label that disagrees with the current
	// deterministic sketch. Exact learned-route evidence must remain usable.
	u.PageTemplates[0].SemanticFamily = "community"

	if id, ok := u.MatchTemplate(bundle); !ok || id != "get_about" {
		t.Fatalf("exact learned route should win over semantic label conflict, id=%q ok=%v sketch=%+v", id, ok, bundle.SemanticSketch())
	}
}

// TestIncrementTemplate — subsequent matches bump the count and collect
// example URLs (capped at 3).
func TestIncrementTemplate(t *testing.T) {
	u := NewAppUnderstanding()

	htmlSrc := []byte(`<html><body><form action="/p/add" method="POST">
<input type="hidden" name="id"><input name="qty" type="number">
</form></body></html>`)

	mkBundle := func(sampleURL string) *EndpointBundle {
		e := mkEntry(1, "GET", sampleURL, "/x", "", nil, nil,
			200, nil, "text/html", htmlSrc, "h")
		return BuildEndpointBundle([]types.TrafficEntry{e}, 20)
	}

	first := mkBundle("https://ex.com/p/1")
	u.RegisterTemplate("product", "product detail", first)

	// Bump several times with distinct URLs
	for i, url := range []string{
		"https://ex.com/p/2",
		"https://ex.com/p/3",
		"https://ex.com/p/4",
		"https://ex.com/p/5",
	} {
		u.IncrementTemplate("product", url)
		_ = i
	}

	if len(u.PageTemplates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(u.PageTemplates))
	}
	tmpl := u.PageTemplates[0]
	// Initial registration = 1, then 4 increments = 5
	if tmpl.EndpointCount != 5 {
		t.Errorf("EndpointCount: got %d, want 5", tmpl.EndpointCount)
	}
	// ExampleURLs cap: 1 initial + up to 2 more (cap = 3 total)
	if len(tmpl.ExampleURLs) > 3 {
		t.Errorf("ExampleURLs not capped at 3: got %d (%v)",
			len(tmpl.ExampleURLs), tmpl.ExampleURLs)
	}
	if len(tmpl.ExampleURLs) < 1 {
		t.Errorf("ExampleURLs should include at least the initial URL")
	}
}

// TestClassifyFunctionalArea — URL patterns map to known areas with
// appropriate priority.
func TestClassifyFunctionalArea(t *testing.T) {
	cases := []struct {
		url      string
		wantName string
	}{
		{"/login", "authentication"},
		{"/signin", "authentication"},
		{"/auth/oauth/callback", "authentication"},
		{"/admin/users", "admin"},
		{"/dashboard", "admin"},
		{"/checkout/step/1", "transaction"},
		{"/cart", "transaction"},
		{"/upload/avatar", "file_handling"},
		{"/api/v1/users", "api"},
		{"/profile/edit", "account"},
		{"/search", "search"},
		{"/products/{id}", "catalog"},
		{"/static/css/main.css", "static"},
		{"/random/page", "general"},
	}
	for _, c := range cases {
		name, prio := ClassifyFunctionalArea(c.url)
		if name != c.wantName {
			t.Errorf("ClassifyFunctionalArea(%q): name=%q, want %q", c.url, name, c.wantName)
		}
		if prio <= 0 {
			t.Errorf("ClassifyFunctionalArea(%q): priority %d should be > 0", c.url, prio)
		}
	}

	// Authentication should outrank catalog and static
	_, authPrio := ClassifyFunctionalArea("/login")
	_, catalogPrio := ClassifyFunctionalArea("/products/1")
	_, staticPrio := ClassifyFunctionalArea("/static/main.css")

	if authPrio <= catalogPrio {
		t.Errorf("auth priority %d should outrank catalog %d", authPrio, catalogPrio)
	}
	if catalogPrio <= staticPrio {
		t.Errorf("catalog priority %d should outrank static %d", catalogPrio, staticPrio)
	}
}

// TestAddToFunctionalArea — endpoints grouped into areas; duplicates skipped.
func TestAddToFunctionalArea(t *testing.T) {
	u := NewAppUnderstanding()

	u.AddToFunctionalArea("hash1", "/login")
	u.AddToFunctionalArea("hash2", "/signup")  // same area: authentication
	u.AddToFunctionalArea("hash1", "/login")   // dup — should not double-count
	u.AddToFunctionalArea("hash3", "/api/foo") // different area

	authArea := findArea(u, "authentication")
	if authArea == nil {
		t.Fatal("authentication area missing")
	}
	if len(authArea.Endpoints) != 2 {
		t.Errorf("authentication endpoints: got %d, want 2 (no dup)", len(authArea.Endpoints))
	}

	apiArea := findArea(u, "api")
	if apiArea == nil {
		t.Fatal("api area missing")
	}
	if len(apiArea.Endpoints) != 1 {
		t.Errorf("api endpoints: got %d, want 1", len(apiArea.Endpoints))
	}
}

func findArea(u *AppUnderstanding, name string) *FunctionalArea {
	for i := range u.FunctionalAreas {
		if u.FunctionalAreas[i].Name == name {
			return &u.FunctionalAreas[i]
		}
	}
	return nil
}

// TestSerializeLoadRoundtrip — serialize then reload produces the same
// templates, areas, analyzed hashes.
func TestSerializeLoadRoundtrip(t *testing.T) {
	orig := NewAppUnderstanding()
	orig.AppType = "e-commerce"
	orig.Summary = "A web shop with a standard cart."

	// Build a bundle so we have a real template
	htmlSrc := []byte(`<html><body><form><input name="a"><input name="b"></form></body></html>`)
	e := mkEntry(1, "GET", "https://ex.com/", "/", "", nil, nil,
		200, nil, "text/html", htmlSrc, "h1")
	bundle := BuildEndpointBundle([]types.TrafficEntry{e}, 20)
	orig.RegisterTemplate("home_form", "Homepage with a form", bundle)

	orig.MarkAnalyzed("hash-1", "home_form")
	orig.MarkAnalyzed("hash-2", "")
	orig.AddToFunctionalArea("hash-1", "/")
	orig.AddToFunctionalArea("hash-2", "/login")

	// Serialize
	tmpl, areas, hashes := orig.Serialize()
	if tmpl == "" || areas == "" || hashes == "" {
		t.Errorf("empty serialization: tmpl=%q areas=%q hashes=%q", tmpl, areas, hashes)
	}

	// Reload
	reloaded := LoadAppUnderstanding(orig.AppType, tmpl, areas, hashes, orig.Summary)

	if reloaded.AppType != orig.AppType {
		t.Errorf("AppType: got %q, want %q", reloaded.AppType, orig.AppType)
	}
	if reloaded.Summary != orig.Summary {
		t.Errorf("Summary: got %q, want %q", reloaded.Summary, orig.Summary)
	}
	if len(reloaded.PageTemplates) != len(orig.PageTemplates) {
		t.Errorf("PageTemplates len: got %d, want %d",
			len(reloaded.PageTemplates), len(orig.PageTemplates))
	}
	if reloaded.PageTemplates[0].ID != "home_form" {
		t.Errorf("reloaded template ID: got %q, want home_form",
			reloaded.PageTemplates[0].ID)
	}
	if !reloaded.IsAnalyzed("hash-1") || !reloaded.IsAnalyzed("hash-2") {
		t.Error("reloaded hashes lost")
	}
	if len(reloaded.FunctionalAreas) != len(orig.FunctionalAreas) {
		t.Errorf("FunctionalAreas: got %d, want %d",
			len(reloaded.FunctionalAreas), len(orig.FunctionalAreas))
	}
}

// TestRenderForLLM — output includes app type, summary, templates, areas.
func TestRenderForLLM(t *testing.T) {
	u := NewAppUnderstanding()
	u.AppType = "SaaS"
	u.Summary = "Multi-tenant dashboard app."

	htmlSrc := []byte(`<html><body><form><input name="q"></form></body></html>`)
	e := mkEntry(1, "GET", "https://ex.com/", "/", "", nil, nil,
		200, nil, "text/html", htmlSrc, "h")
	bundle := BuildEndpointBundle([]types.TrafficEntry{e}, 20)
	u.RegisterTemplate("search_form", "Search form", bundle)
	u.AddToFunctionalArea("h", "/api/foo")
	u.MarkAnalyzed("h", "search_form")

	out := u.RenderForLLM()
	if out == "" {
		t.Fatal("empty render")
	}
	for _, want := range []string{"SaaS", "Multi-tenant", "search_form", "api", "analyzed"} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("render missing %q; got:\n%s", want, out)
		}
	}
}

// TestRenderForLLM_Empty — nil and empty render to "".
func TestRenderForLLM_Empty(t *testing.T) {
	if s := (*AppUnderstanding)(nil).RenderForLLM(); s != "" {
		t.Errorf("nil render should be empty, got %q", s)
	}
	u := NewAppUnderstanding()
	if s := u.RenderForLLM(); s != "" {
		t.Errorf("empty render should be empty, got %q", s)
	}
}

func TestRenderForLLM_FunctionalAreasWithoutTemplates(t *testing.T) {
	u := NewAppUnderstanding()
	u.AddToFunctionalArea("hash-login", "/login")
	u.AddToFunctionalArea("hash-search", "/search")

	out := u.RenderForLLM()
	if out == "" {
		t.Fatal("functional areas should render even when no input templates exist")
	}
	for _, want := range []string{"Functional areas", "authentication", "search"} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q:\n%s", want, out)
		}
	}
}

// TestMatchTemplate_EmptySignature — a bundle with no form/body structure
// should NOT match anything (prevents false-positive template match on
// signature-less endpoints like static asset fetches).
func TestMatchTemplate_EmptySignature(t *testing.T) {
	u := NewAppUnderstanding()

	// First bundle: real form
	htmlWithForm := []byte(`<html><body><form><input name="q"></form></body></html>`)
	e1 := mkEntry(1, "GET", "https://ex.com/s", "/s", "",
		nil, nil, 200, nil, "text/html", htmlWithForm, "h1")
	b1 := BuildEndpointBundle([]types.TrafficEntry{e1}, 20)
	u.RegisterTemplate("search", "search page", b1)

	// Second bundle: no forms, no body params
	htmlNoForm := []byte(`<html><body><h1>hello</h1></body></html>`)
	e2 := mkEntry(2, "GET", "https://ex.com/empty", "/empty", "",
		nil, nil, 200, nil, "text/html", htmlNoForm, "h2")
	b2 := BuildEndpointBundle([]types.TrafficEntry{e2}, 20)

	if _, ok := u.MatchTemplate(b2); ok {
		t.Error("empty-signature bundle should NOT match any template")
	}
}

func TestMatchTemplateUsesHTMLResponseShapeAsVerificationCandidate(t *testing.T) {
	u := NewAppUnderstanding()
	firstHTML := []byte(`<html><head><meta name="viewport" content="width=device-width"></head><body><nav><a href="/one">One</a><a href="/two">Two</a></nav><main><h1>News</h1></main></body></html>`)
	secondHTML := []byte(`<html><head><meta name="viewport" content="width=device-width"></head><body><nav><a href="/jobs">Jobs</a><a href="/about">About</a></nav><main><h1>Careers</h1></main></body></html>`)
	first := BuildEndpointBundle([]types.TrafficEntry{mkEntry(1, "GET", "https://ex.com/news", "/news", "", nil, nil, 200, nil, "text/html", firstHTML, "news")}, 20)
	second := BuildEndpointBundle([]types.TrafficEntry{mkEntry(2, "GET", "https://ex.com/jobs", "/jobs", "", nil, nil, 200, nil, "text/html", secondHTML, "jobs")}, 20)
	if first.InputSignature() != "" || second.InputSignature() != "" {
		t.Fatal("fixture unexpectedly has an input signature")
	}
	if first.ResponseShapeSignature() == "" || first.ResponseShapeSignature() != second.ResponseShapeSignature() {
		t.Fatalf("equivalent shells have response shapes %q and %q", first.ResponseShapeSignature(), second.ResponseShapeSignature())
	}
	u.RegisterTemplate("site_shell", "shared public site shell", first)
	if id, ok := u.MatchTemplate(second); !ok || id != "site_shell" {
		t.Fatalf("same response shape did not become a template-verification candidate: id=%q ok=%v", id, ok)
	}

	differentHTML := []byte(`<html><body><form action="/search"><input name="q"></form><a href="/help">Help</a></body></html>`)
	different := BuildEndpointBundle([]types.TrafficEntry{mkEntry(3, "GET", "https://ex.com/search", "/search", "", nil, nil, 200, nil, "text/html", differentHTML, "search")}, 20)
	if id, ok := u.MatchTemplate(different); ok {
		t.Fatalf("materially different response shape matched %q", id)
	}
}

func TestResponseShapeIgnoresCatalogVolumeButPreservesNewBoundary(t *testing.T) {
	compactHTML := []byte(`<html><body><a href="/login">Login</a><a href="/tag/one/">One</a><a href="/author/a/">A</a></body></html>`)
	denseHTML := []byte(`<html><body><a href="/login">Login</a><a href="/tag/one/">One</a><a href="/tag/two/">Two</a><a href="/tag/three/">Three</a><a href="/author/a/">A</a><a href="/author/b/">B</a></body></html>`)
	withAPIHTML := []byte(`<html><body><a href="/login">Login</a><a href="/tag/one/">One</a><a href="/author/a/">A</a><a href="/api/v1/export">Export</a></body></html>`)
	bundle := func(id int64, body []byte) *EndpointBundle {
		return BuildEndpointBundle([]types.TrafficEntry{mkEntry(id, "GET", "https://ex.com/tag/example/", "/tag/example/", "", nil, nil, 200, nil, "text/html", body, "shape")}, 20)
	}
	compact := bundle(1, compactHTML).ResponseShapeSignature()
	if dense := bundle(2, denseHTML).ResponseShapeSignature(); compact != dense {
		t.Fatalf("catalog item volume changed response shape\ncompact: %s\ndense:   %s", compact, dense)
	}
	if withAPI := bundle(3, withAPIHTML).ResponseShapeSignature(); compact == withAPI {
		t.Fatalf("new API boundary was hidden by response-shape compaction: %s", withAPI)
	}
}

func TestEndpointBundleDoesNotTreatAmbientCookieAsAuthenticatedIdentity(t *testing.T) {
	ambient := mkEntry(1, "GET", "https://ex.com/catalog", "/catalog", "", map[string]string{"Cookie": "session=anonymous"}, nil, 200, nil, "text/html", []byte(`<html><body>Catalog</body></html>`), "ambient")
	if bundle := BuildEndpointBundle([]types.TrafficEntry{ambient}, 20); bundle.HasAuth {
		t.Fatal("anonymous session cookie became authenticated bundle evidence")
	}
	direct := ambient
	direct.Request.Headers = map[string]string{"Authorization": "Bearer observed"}
	if bundle := BuildEndpointBundle([]types.TrafficEntry{direct}, 20); !bundle.HasAuth {
		t.Fatal("explicit authorization header was not preserved as auth evidence")
	}
}

func TestMatchTemplateDoesNotVerifySameShellAgainstUnrelatedRouteTemplate(t *testing.T) {
	u := NewAppUnderstanding()
	bodyA := []byte(`<html><body><nav><a href="/one">One</a></nav><main><h1>Administration</h1></main></body></html>`)
	bodyB := []byte(`<html><body><nav><a href="/two">Two</a></nav><main><h1>Executive orders</h1></main></body></html>`)
	first := BuildEndpointBundle([]types.TrafficEntry{mkEntry(1, "GET", "https://ex.com/administration/", "/administration/", "", nil, nil, 200, nil, "text/html", bodyA, "administration")}, 20)
	second := BuildEndpointBundle([]types.TrafficEntry{mkEntry(2, "GET", "https://ex.com/presidential-actions/", "/presidential-actions/", "", nil, nil, 200, nil, "text/html", bodyB, "actions")}, 20)
	if first.ResponseShapeSignature() != second.ResponseShapeSignature() {
		t.Fatalf("fixture response shapes differ: %q vs %q", first.ResponseShapeSignature(), second.ResponseShapeSignature())
	}
	u.RegisterTemplate("get_administration", "Administration landing page", first)
	if id, ok := u.MatchTemplate(second); ok {
		t.Fatalf("unrelated route template became a verification candidate: %q", id)
	}
}
