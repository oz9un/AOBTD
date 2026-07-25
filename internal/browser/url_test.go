package browser

import (
	"net/url"
	"testing"
)

// Hash routes (#/login, #/score-board) drive client-side navigation in
// HashLocationStrategy SPAs. If they get stripped during normalize/resolve,
// every router link on a juice-shop-style target collapses to the bare
// host and BFS visits exactly one page. These tests pin the contract.

func TestNormalizeURL_PreservesHashRoutes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Plain anchor — strip.
		{"http://x/page#section1", "http://x/page"},
		{"http://x/page#top", "http://x/page"},
		// Hash route — keep.
		{"http://x/#/login", "http://x/#/login"},
		{"http://x/#/score-board", "http://x/#/score-board"},
		{"http://x/#/products/3", "http://x/#/products/3"},
		// Trailing slash on the path side still trimmed (sanity).
		{"http://x/foo/", "http://x/foo"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizeURL(tc.in); got != tc.want {
				t.Errorf("normalizeURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestResolveURL_PreservesHashRoutes(t *testing.T) {
	base, _ := url.Parse("http://x/")
	cases := []struct {
		href string
		want string
	}{
		{"#/login", "http://x/#/login"},
		{"#/score-board", "http://x/#/score-board"},
		// Plain in-page anchor on relative path — strip.
		{"about#contact-form", "http://x/about"},
		// Absolute hash route survives.
		{"http://x/#/products/42", "http://x/#/products/42"},
	}
	for _, tc := range cases {
		t.Run(tc.href, func(t *testing.T) {
			if got := resolveURL(base, tc.href); got != tc.want {
				t.Errorf("resolveURL(%q) = %q, want %q", tc.href, got, tc.want)
			}
		})
	}
}

func TestURLShape_HashRoutesGetTheirOwnBucket(t *testing.T) {
	// Each hash route should produce a distinct shape so saturation doesn't
	// kick in after the first hash-route visit collapses everything.
	shapes := map[string]string{}
	for _, raw := range []string{
		"http://x/#/login",
		"http://x/#/score-board",
		"http://x/#/products/3",
		"http://x/#/about",
	} {
		s := urlShape(raw)
		if prev, ok := shapes[s]; ok {
			t.Fatalf("expected distinct shapes, but %q and %q both shape to %q", raw, prev, s)
		}
		shapes[s] = raw
	}

	// And: a real path /admin must not collide with a hash route /#/admin —
	// totally different code paths server-side, so they need separate buckets.
	pathShape := urlShape("http://x/admin")
	hashShape := urlShape("http://x/#/admin")
	if pathShape == hashShape {
		t.Errorf("path /admin and hash /#/admin collided to same shape %q", pathShape)
	}
}

func TestLongPathSegmentClassificationIsConservative(t *testing.T) {
	if got := classifySegment("application-configuration"); got != "WORD" {
		t.Fatalf("readable route classified as %q, want WORD", got)
	}
	if got := classifySegment("dGhpcy1pc19hX2xvbmdfdG9rZW4"); got != "TOKEN" {
		t.Fatalf("opaque token classified as %q, want TOKEN", got)
	}

	if got := normalizeURLPattern("https://example.test/rest/admin/application-configuration"); got != "/rest/admin/application-configuration" {
		t.Fatalf("readable route normalized to %q", got)
	}
	if got := normalizeURLPattern("https://example.test/session/dGhpcy1pc19hX2xvbmdfdG9rZW4"); got != "/session/{id}" {
		t.Fatalf("opaque token normalized to %q, want /session/{id}", got)
	}
}

func TestShouldCrawlURLFiltersBrowserTransportNoise(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"https://shop.example/#/search", true},
		{"https://shop.example/rest/products/search?q=apple", true},
		{"https://dynamicmedia.audemarspiguet.com/is/image/audemarspiguet/lb_craftime_b2_v2?size=1920,0&wid=1920&fmt=avif-alpha&dpr=off", false},
		{"https://cdn.shop.example/assets/app.js?v=123", false},
		{"https://shop.example/api/users?size=50", true},
		{"https://shop.example/socket.io/?EIO=4&transport=polling&t=abc", false},
		{"https://shop.example/search/socket.io/?EIO=4&transport=polling&t=abc", false},
		{"https://shop.example/socket.io/?EIO=4&transport=websocket&sid=abc", false},
		{"https://shop.example/search?q=%3Ciframe%20src%3D%22javascript%3Aalert(%60xss%60)%22%3E", false},
		{"https://shop.example/orders*", false},
		{"https://shop.example/account/logout?redirect=%2Forders", false},
		{"https://shop.example/logout.php", false},
		{"https://shop.example/auth/signout.aspx?next=/", false},
		{"https://docs.example.test/contract.pdf", false},
		{"mailto:security@example.test", false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			if got := shouldCrawlURL(tc.raw); got != tc.want {
				t.Fatalf("shouldCrawlURL(%q)=%v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestExtractScriptDiscoveredLinksFindsAPISeeds(t *testing.T) {
	script := `
		window.accountBffUrl = "https://gateway.example.com/partner/account-bff-service/";
		window.noisyDoc = "https://tymp.mncdn.com/prod/documents/contract.pdf";
		window.asset = "https://cdn.example.test/app/main.js";
		const login = '/auth/login?lang=tr-TR';
		const gated = '/orders';
		const boring = '/static/logo.png';
	`
	got := extractScriptDiscoveredLinks("https://partner.example.com/auth/login", script, nil, 10)
	want := map[string]bool{
		"https://gateway.example.com/partner/account-bff-service/": true,
		"https://partner.example.com/auth/login?lang=tr-TR":                                      true,
	}
	if len(got) != len(want) {
		t.Fatalf("extractScriptDiscoveredLinks() = %v, want %d high-signal links", got, len(want))
	}
	for _, link := range got {
		if !want[link] {
			t.Fatalf("unexpected script-discovered link %q in %v", link, got)
		}
	}
}

func TestExtractSitemapDiscoveredLinksFindsLocEntries(t *testing.T) {
	sitemap := `<?xml version="1.0" encoding="UTF-8"?>
		<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
			<url><loc>https://shop.example/account/login</loc></url>
			<url><loc>https://shop.example/docs/contract.pdf</loc></url>
			<url><loc>/admin/users</loc></url>
		</urlset>`
	got := extractSitemapDiscoveredLinks("https://shop.example/sitemap.xml", sitemap, nil, 10)
	want := []string{
		"https://shop.example/account/login",
		"https://shop.example/admin/users",
	}
	if len(got) != len(want) {
		t.Fatalf("extractSitemapDiscoveredLinks() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("extractSitemapDiscoveredLinks()[%d] = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}

func TestExtractSitemapDiscoveredLinksHandlesEscapedBrowserXML(t *testing.T) {
	doc := `&lt;urlset&gt;&lt;url&gt;&lt;loc&gt;https://shop.example/path-one&lt;/loc&gt;&lt;/url&gt;&lt;/urlset&gt;`
	got := extractSitemapDiscoveredLinks("https://shop.example/sitemap.xml", doc, nil, 10)
	if len(got) != 1 || got[0] != "https://shop.example/path-one" {
		t.Fatalf("escaped sitemap links = %v, want one path-one URL", got)
	}
}

func TestExtractJSONDiscoveredLinksFindsSameOriginRouteKeys(t *testing.T) {
	doc := `[
		{"path":"/WebGoat/SqlInjection/attack9"},
		{"links":["/WebGoat/PathTraversal/random","https://webgoat.test/WebGoat/xxe/simple"]},
		{"action":"WebGoat/SqlInjection/attack2"},
		{"path":"https://evil.test/nope"},
		{"label":"/should/not/be/mined"},
		{"url":"/assets/app.js"},
		{"path":"/logout"}
	]`
	got := extractJSONDiscoveredLinks("https://webgoat.test/WebGoat/service/lessonoverview.mvc/SqlInjection.lesson", doc, nil, 10)
	want := []string{
		"https://webgoat.test/WebGoat/SqlInjection/attack9",
		"https://webgoat.test/WebGoat/PathTraversal/random",
		"https://webgoat.test/WebGoat/xxe/simple",
		"https://webgoat.test/WebGoat/SqlInjection/attack2",
	}
	if len(got) != len(want) {
		t.Fatalf("extractJSONDiscoveredLinks() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("extractJSONDiscoveredLinks()[%d] = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}

func TestExtractJSONDiscoveredLinksDedupesAndCaps(t *testing.T) {
	seen := map[string]bool{"https://api.example.test/already": true}
	doc := `[
		{"path":"/already"},
		{"endpoint":"/first"},
		{"route":"/second"}
	]`
	got := extractJSONDiscoveredLinks("https://api.example.test/meta", doc, seen, 1)
	if len(got) != 1 || got[0] != "https://api.example.test/first" {
		t.Fatalf("extractJSONDiscoveredLinks cap/dedupe = %v, want only /first", got)
	}
	if !seen["https://api.example.test/first"] || !seen["https://api.example.test/already"] {
		t.Fatalf("seen map not updated as expected: %#v", seen)
	}
}

func TestExtractDocumentDiscoveredLinksUsesBodyTextJSON(t *testing.T) {
	html := `<html><body><pre>[{"url":"https://target.test/VulnerableApp/PathTraversal/LEVEL_1"}]</pre></body></html>`
	body := `[{"url":"https://target.test/VulnerableApp/PathTraversal/LEVEL_1"}]`
	got := ExtractDocumentDiscoveredLinks("https://target.test/VulnerableApp/scanner", html, body, 10)
	want := "https://target.test/VulnerableApp/PathTraversal/LEVEL_1"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("ExtractDocumentDiscoveredLinks() = %v, want [%q]", got, want)
	}
}

func TestNormalizeURLStripsTrackingParamsButKeepsBusinessQuery(t *testing.T) {
	got := normalizeURL("https://shop.example/search?q=shoes&utm_source=newsletter&fbclid=abc&page=2")
	want := "https://shop.example/search?page=2&q=shoes"
	if got != want {
		t.Fatalf("normalizeURL tracking strip = %q, want %q", got, want)
	}
}
