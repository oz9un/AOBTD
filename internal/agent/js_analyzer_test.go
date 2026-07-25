package agent

import "testing"

func TestExtractRoutesRegexFindsSPAUIRoutes(t *testing.T) {
	js := `
		fetch("/api/Products")
		["mat-list-item","","routerLink","/score-board"]
		["mat-menu-item","","routerLink","/wallet"]
		["mat-cell"],N("routerLink",Dt("/address/edit/",e.id))
		const goPrivacy=()=>["privacy-security/privacy-policy"]
		this.router.navigate(["account/security"])
		["a","","href","/#/wallet-web3"]
		const routes=[{path:"login"},{path:"forgot-password"},{path:"**"}]
	`
	routes := (&JSAnalyzer{}).extractRoutesRegex(js, "https://shop.example.test/main.js")

	assertRouteKind(t, routes, "/api/Products", "api")
	assertRouteKind(t, routes, "/score-board", "ui")
	assertRouteKind(t, routes, "/wallet", "ui")
	assertRouteKind(t, routes, "/address/edit/", "ui")
	assertRouteKind(t, routes, "privacy-security/privacy-policy", "ui")
	assertRouteKind(t, routes, "account/security", "ui")
	assertRouteKind(t, routes, "wallet-web3", "ui")
	assertRouteKind(t, routes, "login", "ui")
	assertRouteKind(t, routes, "forgot-password", "ui")
	assertRouteAbsent(t, routes, "**")
}

func TestExtractRoutesRegexFindsRelativeNetworkCalls(t *testing.T) {
	js := `
		webgoat.customjs.jquery.ajax({
			method: "GET",
			url: "IDOR/profile",
			contentType: 'application/json; charset=UTF-8'
		});
		$.ajax({
			type: 'POST',
			url: 'JWT/refresh/login',
			contentType: "application/json",
			data: JSON.stringify({user: user, password: "demo"})
		});
		$.get("PathTraversal/profile-picture", function(){});
		$("#secrettoken").load('JWT/secret/gettoken');
	`
	routes := (&JSAnalyzer{}).extractRoutesRegex(js, "http://127.0.0.1:8085/WebGoat/lesson_js/jwt-refresh.js")

	assertRoute(t, routes, "GET", "IDOR/profile", "api")
	assertRoute(t, routes, "POST", "JWT/refresh/login", "api")
	assertRoute(t, routes, "GET", "PathTraversal/profile-picture", "api")
	assertRoute(t, routes, "GET", "JWT/secret/gettoken", "api")
	if got := resolvedRouteURL(DiscoveredRoute{
		Method:  "POST",
		Path:    "JWT/refresh/login",
		Source:  "http://127.0.0.1:8085/WebGoat/lesson_js/jwt-refresh.js",
		Context: "ajax object",
		Kind:    "api",
	}); got != "http://127.0.0.1:8085/WebGoat/JWT/refresh/login" {
		t.Fatalf("resolved relative WebGoat route = %q", got)
	}
}

func TestRelativeJSRouteResolutionUsesAppMountFromStaticAssetDirs(t *testing.T) {
	cases := []struct {
		source string
		path   string
		want   string
	}{
		{
			source: "https://example.test/app/assets/main.js",
			path:   "api/orders",
			want:   "https://example.test/app/api/orders",
		},
		{
			source: "https://example.test/static/main.js",
			path:   "api/orders",
			want:   "https://example.test/api/orders",
		},
		{
			source: "https://example.test/unknown/main.js",
			path:   "api/orders",
			want:   "https://example.test/api/orders",
		},
	}
	for _, tc := range cases {
		got := resolvedRouteURL(DiscoveredRoute{Method: "GET", Path: tc.path, Source: tc.source, Context: "fetch call"})
		if got != tc.want {
			t.Fatalf("resolvedRouteURL(%q, %q) = %q, want %q", tc.source, tc.path, got, tc.want)
		}
	}
}

func TestDedupeJSRoutesPrefersMountedEquivalentAndDropsDynamicExpressions(t *testing.T) {
	source := "http://127.0.0.1:8085/WebGoat/lesson_js/jwt-voting.js"
	routes := []DiscoveredRoute{
		{Method: "GET", Path: "/JWT/votings/login?user=", Source: source, Context: "LLM analysis", Kind: "api"},
		{Method: "GET", Path: "JWT/votings/login?user=", Source: source, Context: "ajax object", Kind: "api"},
		{Method: "UNKNOWN", Path: `$(context).attr("action")`, Source: source, Context: "LLM analysis", Kind: "dynamic"},
		{Method: "GET", Path: "this.collection.url", Source: source, Context: "LLM analysis", Kind: "api"},
	}

	got := dedupeJSRoutes(routes)
	if len(got) != 1 {
		t.Fatalf("dedupeJSRoutes() = %#v, want only mounted relative route", got)
	}
	if got[0].Path != "JWT/votings/login?user=" {
		t.Fatalf("kept path = %q, want relative mounted route", got[0].Path)
	}
	if resolved := resolvedRouteURL(got[0]); resolved != "http://127.0.0.1:8085/WebGoat/JWT/votings/login?user=" {
		t.Fatalf("resolved kept route = %q", resolved)
	}
}

func TestClassifyDiscoveredRoute(t *testing.T) {
	tests := []struct {
		path    string
		context string
		want    string
	}{
		{path: "/api/Users", want: "api"},
		{path: "/rest/user/login", want: "api"},
		{path: "/graphql", want: "api"},
		{path: "wss://example.test/socket", want: "ws"},
		{path: "/score-board", want: "ui"},
		{path: "login", context: "router path", want: "ui"},
		{path: "JWT/refresh/login?user=", context: "ajax object", want: "api"},
		{path: "/assets/app.js", want: "static"},
		{path: "//ipinfo.io/json", want: ""},
		{path: "**", context: "router path", want: ""},
	}

	for _, tt := range tests {
		if got := classifyDiscoveredRoute(tt.path, tt.context); got != tt.want {
			t.Errorf("classifyDiscoveredRoute(%q, %q) = %q, want %q", tt.path, tt.context, got, tt.want)
		}
	}
}

func assertRoute(t *testing.T, routes []DiscoveredRoute, method, path, kind string) {
	t.Helper()
	for _, route := range routes {
		if route.Path == path && route.Method == method {
			if got := routeKind(route); got != kind {
				t.Fatalf("route %s %q kind = %q, want %q", method, path, got, kind)
			}
			return
		}
	}
	t.Fatalf("route %s %q not found in %#v", method, path, routes)
}

func assertRouteKind(t *testing.T, routes []DiscoveredRoute, path, kind string) {
	t.Helper()
	for _, route := range routes {
		if route.Path == path {
			if got := routeKind(route); got != kind {
				t.Fatalf("route %q kind = %q, want %q", path, got, kind)
			}
			return
		}
	}
	t.Fatalf("route %q not found in %#v", path, routes)
}

func assertRouteAbsent(t *testing.T, routes []DiscoveredRoute, path string) {
	t.Helper()
	for _, route := range routes {
		if route.Path == path {
			t.Fatalf("route %q should not have been extracted: %#v", path, routes)
		}
	}
}
