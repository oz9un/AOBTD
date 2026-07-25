package agent

import (
	"path/filepath"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
)

func TestNormalizeJSUIRouteForBrowser(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		target   string
		hashMode bool
		want     string
	}{
		{
			name:     "hash routing rewrites absolute same-origin path into fragment route",
			raw:      "https://shop.example.test/score-board",
			target:   "https://shop.example.test/",
			hashMode: true,
			want:     "https://shop.example.test/#/score-board",
		},
		{
			name:     "history routing keeps absolute same-origin path",
			raw:      "https://shop.example.test/score-board",
			target:   "https://shop.example.test/",
			hashMode: false,
			want:     "https://shop.example.test/score-board",
		},
		{
			name:     "relative route becomes hash route",
			raw:      "login",
			target:   "https://shop.example.test/app",
			hashMode: true,
			want:     "https://shop.example.test/#/login",
		},
		{
			name:     "existing hash route is preserved on target origin",
			raw:      "https://shop.example.test/#/wallet",
			target:   "https://shop.example.test/",
			hashMode: true,
			want:     "https://shop.example.test/#/wallet",
		},
		{
			name:     "unbound params are skipped",
			raw:      "/address/edit/:id",
			target:   "https://shop.example.test/",
			hashMode: true,
			want:     "",
		},
		{
			name:     "cross origin routes are skipped",
			raw:      "https://evil.example.test/score-board",
			target:   "https://shop.example.test/",
			hashMode: true,
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeJSUIRouteForBrowser(tt.raw, tt.target, tt.hashMode); got != tt.want {
				t.Fatalf("normalizeJSUIRouteForBrowser(%q, %q, %v) = %q, want %q",
					tt.raw, tt.target, tt.hashMode, got, tt.want)
			}
		})
	}
}

func TestUnsafeSPAUIRoute(t *testing.T) {
	tests := []struct {
		route string
		want  bool
	}{
		{route: "https://shop.example.test/#/logout", want: true},
		{route: "https://shop.example.test/#/checkout", want: true},
		{route: "https://shop.example.test/#/score-board", want: false},
		{route: "https://shop.example.test/#/saved-payment-methods", want: false},
	}

	for _, tt := range tests {
		if got := unsafeSPAUIRoute(tt.route); got != tt.want {
			t.Errorf("unsafeSPAUIRoute(%q) = %v, want %v", tt.route, got, tt.want)
		}
	}
}

func TestPrivilegedSPAUIRoute(t *testing.T) {
	tests := []struct {
		route string
		want  bool
	}{
		{route: "https://shop.example.test/#/administration", want: true},
		{route: "https://shop.example.test/#/admin/users", want: true},
		{route: "https://shop.example.test/#/accounting", want: true},
		{route: "https://shop.example.test/#/search", want: false},
		{route: "https://shop.example.test/#/privacy-policy", want: false},
	}
	for _, tt := range tests {
		if got := privilegedSPAUIRoute(tt.route); got != tt.want {
			t.Errorf("privilegedSPAUIRoute(%q) = %v, want %v", tt.route, got, tt.want)
		}
	}
}

func TestJSUIRoutePrimerCandidatesFromDiscoveredRoutes(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("http://127.0.0.1:3000", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, discovery := range []store.Discovery{
		{
			TargetURL: "http://127.0.0.1:3000/administration",
			SourceURL: "http://127.0.0.1:3000/main.js",
			Kind:      store.DiscoveryJSRoute,
			Detail:    "GET kind=ui (params: )",
		},
		{
			TargetURL: "http://127.0.0.1:3000/address/edit/:addressId",
			SourceURL: "http://127.0.0.1:3000/main.js",
			Kind:      store.DiscoveryJSRoute,
			Detail:    "GET kind=ui (params: addressId)",
		},
		{
			TargetURL: "http://127.0.0.1:3000/api/Products",
			SourceURL: "http://127.0.0.1:3000/main.js",
			Kind:      store.DiscoveryJSRoute,
			Detail:    "GET kind=api (params: )",
		},
		{
			TargetURL: "http://127.0.0.1:3000/#/about",
			SourceURL: "http://127.0.0.1:3000/",
			Kind:      store.DiscoveryHTMLLink,
			Detail:    "observed hash route",
		},
	} {
		if err := db.InsertDiscovery(scanID, discovery); err != nil {
			t.Fatal(err)
		}
	}

	orch := &Orchestrator{
		db:     db,
		scanID: scanID,
		target: "http://127.0.0.1:3000",
	}
	candidates, err := orch.jsUIRoutePrimerCandidates(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v, want one safe static UI route", candidates)
	}
	if candidates[0] != "http://127.0.0.1:3000/#/administration" {
		t.Fatalf("candidate = %q", candidates[0])
	}
}

func TestVerifierPrivilegedUIRouteCandidates(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("http://127.0.0.1:3000", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, discovery := range []store.Discovery{
		{
			TargetURL: "http://127.0.0.1:3000/administration",
			SourceURL: "http://127.0.0.1:3000/main.js",
			Kind:      store.DiscoveryJSRoute,
			Detail:    "GET kind=ui (params: )",
		},
		{
			TargetURL: "http://127.0.0.1:3000/search",
			SourceURL: "http://127.0.0.1:3000/main.js",
			Kind:      store.DiscoveryJSRoute,
			Detail:    "GET kind=ui (params: )",
		},
		{
			TargetURL: "http://127.0.0.1:3000/#/about",
			SourceURL: "http://127.0.0.1:3000/",
			Kind:      store.DiscoveryHTMLLink,
			Detail:    "observed hash route",
		},
	} {
		if err := db.InsertDiscovery(scanID, discovery); err != nil {
			t.Fatal(err)
		}
	}

	v := &VerifierAgent{
		db:     db,
		scanID: scanID,
		target: "http://127.0.0.1:3000",
	}
	got := v.privilegedUIRouteCandidates(5)
	if len(got) != 5 {
		t.Fatalf("privileged candidates = %#v, want discovered route plus bounded fallbacks", got)
	}
	if got[0] != "http://127.0.0.1:3000/#/administration" {
		t.Fatalf("candidate = %q", got[0])
	}
	if got[1] != "http://127.0.0.1:3000/#/admin" {
		t.Fatalf("fallback candidate = %q, want hash admin fallback", got[1])
	}
}

func TestJSUIRoutePrimerCandidatesPrioritizeControlPlaneAndHiddenRoutes(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("http://127.0.0.1:3000", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/about", "/address/select", "/delivery-method", "/photo-wall", "/bee-haven",
		"/recycle", "/hacking-instructor", "/wallet-web3", "/web3-sandbox", "/score-board",
		"/privacy-policy", "/administration",
	} {
		if err := db.InsertDiscovery(scanID, store.Discovery{
			TargetURL: "http://127.0.0.1:3000" + path,
			SourceURL: "http://127.0.0.1:3000/main.js",
			Kind:      store.DiscoveryJSRoute,
			Detail:    "GET kind=ui (params: )",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.InsertDiscovery(scanID, store.Discovery{
		TargetURL: "http://127.0.0.1:3000/#/about",
		SourceURL: "http://127.0.0.1:3000/",
		Kind:      store.DiscoveryHTMLLink,
		Detail:    "observed hash route",
	}); err != nil {
		t.Fatal(err)
	}

	orch := &Orchestrator{
		db:     db,
		scanID: scanID,
		target: "http://127.0.0.1:3000",
	}
	candidates, err := orch.jsUIRoutePrimerCandidates(3)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"http://127.0.0.1:3000/#/score-board",
		"http://127.0.0.1:3000/#/administration",
		"http://127.0.0.1:3000/#/privacy-policy",
	}
	if len(candidates) != len(want) {
		t.Fatalf("candidates = %#v, want %#v", candidates, want)
	}
	for i := range want {
		if candidates[i] != want[i] {
			t.Fatalf("candidate[%d] = %q, want %q (all=%#v)", i, candidates[i], want[i], candidates)
		}
	}
}
