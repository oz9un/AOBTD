package reasoner

import (
	"testing"

	"github.com/ozzyw/aobtd/internal/discovery"
	"github.com/ozzyw/aobtd/pkg/types"
)

// TestAugmentLoginEndpointsFromFindings locks in the review-driven fix:
// the helper must ONLY inject URLs into LoginEndpoints when the finding
// is auth-related AND the path looks login-shaped. Earlier revision
// matched bare "sqli" which was a URL-injection vector.
func TestAugmentLoginEndpointsFromFindings(t *testing.T) {
	target := "http://target.test"
	ev := &Evidence{
		Target: target,
		Findings: []types.Finding{
			// weak_credentials on a login-shaped path: SHOULD be added.
			{
				Title:      "Weak credentials demo:demo",
				Severity:   types.SeverityCritical,
				Confidence: types.ConfidenceConfirmed,
				VulnType:   "weak_credentials",
				EndpointID: "POST /rest/user/login",
			},
			// sqli_login_bypass on a login-shaped path: SHOULD be added.
			{
				Title:      "SQLi login bypass",
				Severity:   types.SeverityCritical,
				Confidence: types.ConfidenceConfirmed,
				VulnType:   "sqli_login_bypass",
				EndpointID: "POST /api/auth/login",
			},
			// Generic SQLi on a product search: MUST NOT be added —
			// that was the pre-fix bug (bare "sqli" matched).
			{
				Title:      "SQL Injection in q param",
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceConfirmed,
				VulnType:   "sqli",
				EndpointID: "GET /rest/products/search",
			},
			// weak_credentials BUT on a non-login-shaped path:
			// MUST NOT be added — the second gate (LooksLikeLoginPath)
			// exists to catch mis-classified findings.
			{
				Title:      "Miscategorized weak-creds",
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceConfirmed,
				VulnType:   "weak_credentials",
				EndpointID: "GET /api/products",
			},
			// Different HTTP verbs are supported (review flagged GET-only).
			{
				Title:      "Weak creds on PUT endpoint",
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceConfirmed,
				VulnType:   "weak_credentials",
				EndpointID: "PUT /signin",
			},
		},
	}

	augmentLoginEndpointsFromFindings(ev)

	expected := map[string]string{
		"http://target.test/rest/user/login": "POST",
		"http://target.test/api/auth/login":  "POST",
		"http://target.test/signin":          "PUT",
	}
	if len(ev.LoginEndpoints) != len(expected) {
		t.Fatalf("want %d login endpoints, got %d: %+v",
			len(expected), len(ev.LoginEndpoints), ev.LoginEndpoints)
	}
	for _, e := range ev.LoginEndpoints {
		wantMethod, ok := expected[e.URL]
		if !ok {
			t.Errorf("unexpected URL in LoginEndpoints: %q", e.URL)
			continue
		}
		if e.Method != wantMethod {
			t.Errorf("URL %q has method %q, want %q", e.URL, e.Method, wantMethod)
		}
	}

	// Confirm the two should-NOT-be-added cases really aren't there.
	for _, e := range ev.LoginEndpoints {
		if e.URL == "http://target.test/rest/products/search" {
			t.Error("generic SQLi finding leaked into LoginEndpoints (pre-fix bug)")
		}
		if e.URL == "http://target.test/api/products" {
			t.Error("non-login-shaped weak-creds leaked into LoginEndpoints")
		}
	}
}

func TestConvertEndpointsDropsInvalidSentinelIdentifiers(t *testing.T) {
	got := convertEndpoints([]discovery.DiscoveredEndpoint{
		{URL: "https://example.test/rest/basket/NaN", Method: "GET", Path: "/rest/basket/NaN", Params: []string{"id"}},
		{URL: "https://example.test/rest/basket/7?id=NaN", Method: "GET", Path: "/rest/basket/7", Params: []string{"id"}},
		{URL: "https://example.test/rest/basket/7", Method: "GET", Path: "/rest/basket/7"},
	})
	if len(got) != 1 {
		t.Fatalf("converted endpoints = %+v, want only one clean endpoint", got)
	}
	if got[0].URL != "https://example.test/rest/basket/7" {
		t.Fatalf("kept endpoint = %q", got[0].URL)
	}
}

// TestAugmentLoginDedup ensures existing LoginEndpoints entries aren't
// duplicated when a finding refers to the same URL.
func TestAugmentLoginDedup(t *testing.T) {
	target := "http://target.test"
	ev := &Evidence{
		Target: target,
		LoginEndpoints: []DiscoveredEndpoint{
			{URL: "http://target.test/rest/user/login", Method: "POST"},
		},
		Findings: []types.Finding{
			{
				Title:      "Weak creds",
				Severity:   types.SeverityCritical,
				Confidence: types.ConfidenceConfirmed,
				VulnType:   "weak_credentials",
				EndpointID: "POST /rest/user/login",
			},
		},
	}
	augmentLoginEndpointsFromFindings(ev)
	if len(ev.LoginEndpoints) != 1 {
		t.Errorf("expected no duplicate, got %d entries", len(ev.LoginEndpoints))
	}
}
