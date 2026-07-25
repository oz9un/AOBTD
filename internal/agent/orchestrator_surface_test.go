package agent

import (
	"strings"
	"testing"
)

func TestNoSurfaceErrorExplainsSkippedScan(t *testing.T) {
	err := (&NoSurfaceError{
		Target:       "https://example.test",
		TrafficTotal: 4,
		Filtered:     4,
	}).Error()
	for _, expected := range []string{"no in-scope endpoints", "https://example.test", "traffic=4", "filtered=4"} {
		if !strings.Contains(err, expected) {
			t.Fatalf("error %q missing %q", err, expected)
		}
	}
}

func TestResolveSeedURL(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "/openapi.json", want: "https://app.example.test/openapi.json"},
		{raw: "docs/swagger.json", want: "https://app.example.test/base/docs/swagger.json"},
		{raw: "https://app.example.test/absolute.json", want: "https://app.example.test/absolute.json"},
		{raw: "://bad", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got := resolveSeedURL("https://app.example.test/base/", tt.raw)
			if got != tt.want {
				t.Fatalf("resolveSeedURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
