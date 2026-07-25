package policy

import (
	"fmt"
	"strings"
	"testing"
)

func TestCanonicalOrigin(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"https://EXAMPLE.com./path?q=1", "https://example.com:443"},
		{"https://example.com:443/other", "https://example.com:443"},
		{"https://example.com:8443/", "https://example.com:8443"},
		{"http://localhost/", "http://localhost:80"},
		{"http://127.0.0.1:8080/", "http://127.0.0.1:8080"},
		{"https://[2001:0db8:0:0::1]/", "https://[2001:db8::1]:443"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			origin, err := CanonicalOrigin(tt.raw)
			if err != nil {
				t.Fatalf("CanonicalOrigin: %v", err)
			}
			if origin.String() != tt.want {
				t.Fatalf("CanonicalOrigin(%q) = %q, want %q", tt.raw, origin, tt.want)
			}
		})
	}
}

func TestCanonicalOriginRejectsAmbiguousAndCredentialURLs(t *testing.T) {
	invalid := []string{
		"",
		"example.com/path",
		"//example.com/path",
		"ftp://example.com/file",
		"javascript:alert(1)",
		"https://user:pass@example.com/path",
		"https://example.com@evil.test/path",
		"https://evil.test@example.com/path",
		"https://example.com%2eevil.test/path",
		"https://example.com%2f@evil.test/path",
		`https://example.com\@evil.test/path`,
		"https://example.com:/path",
		"https://example.com:0/path",
		"https://example.com:65536/path",
		"https://example..com/path",
		"https://-example.com/path",
		"https://example-.com/path",
		"https://éxample.com/path",
		"https://[fe80::1%25en0]/path",
		"http://2130706433/path",
		"http://127.1/path",
		"http://127.000.000.001/path",
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			if got, err := CanonicalOrigin(raw); err == nil {
				t.Fatalf("CanonicalOrigin(%q) = %s, want error", raw, got)
			}
		})
	}
}

func TestScopeMatchesExactCanonicalOrigins(t *testing.T) {
	scope, err := NewScope([]string{
		"https://example.com/application/path",
		"https://api.example.com/",
		"http://127.0.0.1:8080/",
		"https://[2001:db8::1]/",
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"same origin", "https://example.com/anything", true},
		{"case and default port", "HTTPS://EXAMPLE.COM:443/path", true},
		{"trailing DNS dot", "https://example.com./path", true},
		{"explicit subdomain", "https://api.example.com/v1", true},
		{"IPv4 exact port", "http://127.0.0.1:8080/x", true},
		{"IPv6 equivalent spelling", "https://[2001:0db8::1]/x", true},
		{"encoded path stays same origin", "https://example.com/%2f%2fevil.test", true},
		{"lookalike suffix", "https://example.com.evil.test/path", false},
		{"lookalike prefix", "https://evil-example.com/path", false},
		{"unlisted subdomain", "https://admin.example.com/path", false},
		{"wrong scheme", "http://example.com/path", false},
		{"non-default port", "https://example.com:444/path", false},
		{"default port on wrong scoped port", "http://127.0.0.1/path", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got, err := scope.MatchURL(tt.raw)
			if err != nil {
				t.Fatalf("MatchURL(%q): %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("MatchURL(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}

	wantOrigins := "[http://127.0.0.1:8080 https://[2001:db8::1]:443 https://api.example.com:443 https://example.com:443]"
	if got := fmt.Sprint(scope.Origins()); got != wantOrigins {
		t.Fatalf("Origins() = %s, want %s", got, wantOrigins)
	}
}

func TestNewScopeFailsClosed(t *testing.T) {
	if _, err := NewScope(nil); err == nil {
		t.Fatal("empty scope unexpectedly succeeded")
	}
	if _, err := NewScope([]string{"https://example.com", "example.net"}); err == nil {
		t.Fatal("scope with relative entry unexpectedly succeeded")
	}
}

func TestScopeExplicitWildcardOrigin(t *testing.T) {
	scope, err := NewScope([]string{
		"https://example.com",
		"https://*.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		url  string
		want bool
	}{
		{"https://example.com", true},
		{"https://www.example.com", true},
		{"https://api.dev.example.com/path", true},
		{"http://api.example.com", false},
		{"https://example.net", false},
		{"https://notexample.com", false},
	}
	for _, tt := range tests {
		_, got, err := scope.MatchURL(tt.url)
		if err != nil {
			t.Fatalf("MatchURL(%q): %v", tt.url, err)
		}
		if got != tt.want {
			t.Errorf("MatchURL(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestScopeRejectsMalformedWildcardOrigin(t *testing.T) {
	for _, raw := range []string{
		"https://*.*.example.com",
		"https://*.localhost",
	} {
		if _, err := NewScope([]string{raw}); err == nil {
			t.Errorf("NewScope(%q) unexpectedly succeeded", raw)
		} else if !strings.Contains(err.Error(), "scope entry") {
			t.Errorf("NewScope(%q) error = %v", raw, err)
		}
	}
}
