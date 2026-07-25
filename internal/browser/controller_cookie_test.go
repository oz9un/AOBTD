package browser

import "testing"

func TestCookieDomainForTargetKeepsLocalhostAndIPsExact(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1": "127.0.0.1",
		"::1":       "::1",
		"localhost": "localhost",
	}
	for input, want := range tests {
		if got := cookieDomainForTarget(input); got != want {
			t.Fatalf("cookieDomainForTarget(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCookieDomainForTargetUsesApexForSubdomains(t *testing.T) {
	if got := cookieDomainForTarget("app.example.com"); got != "example.com" {
		t.Fatalf("cookieDomainForTarget(app.example.com) = %q, want example.com", got)
	}
}
