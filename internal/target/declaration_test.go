package target

import "testing"

func TestNormalizeStartDeclaration(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		wantTarget   string
		wantScope    string
		wantWildcard bool
		wantError    bool
	}{
		{name: "bare host", raw: "example.com", wantTarget: "https://example.com"},
		{name: "concrete URL", raw: "https://www.example.com/app", wantTarget: "https://www.example.com/app"},
		{name: "bare wildcard", raw: "*.example.com", wantTarget: "https://example.com", wantScope: "https://*.example.com", wantWildcard: true},
		{name: "wildcard URL with path", raw: "https://*.example.com/app", wantTarget: "https://example.com/app", wantScope: "https://*.example.com", wantWildcard: true},
		{name: "wildcard port", raw: "http://*.staging.example.com:8080/", wantTarget: "http://staging.example.com:8080/", wantScope: "http://*.staging.example.com:8080", wantWildcard: true},
		{name: "nested wildcard rejected", raw: "https://*.*.example.com", wantError: true},
		{name: "partial wildcard rejected", raw: "https://api*.example.com", wantError: true},
		{name: "unsupported scheme", raw: "ftp://*.example.com", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeStartDeclaration(tt.raw)
			if (err != nil) != tt.wantError {
				t.Fatalf("error = %v, wantError=%v", err, tt.wantError)
			}
			if err != nil {
				return
			}
			if got.Target != tt.wantTarget || got.ScopeRule != tt.wantScope || got.WasWildcard != tt.wantWildcard {
				t.Fatalf("NormalizeStartDeclaration(%q) = %+v", tt.raw, got)
			}
		})
	}
}
