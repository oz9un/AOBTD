package redact

import (
	"regexp"
	"strings"
	"testing"
)

func TestTextRedactsHTTPHeadersAndTokens(t *testing.T) {
	in := "Authorization: Bearer abcdefghijklmnop\nCookie: sid=s3cr3t; theme=dark\nGET /api/me?token=querysecret HTTP/1.1"
	got := Text(in)
	for _, secret := range []string{"abcdefghijklmnop", "s3cr3t", "querysecret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted text still contains %q:\n%s", secret, got)
		}
	}
	for _, marker := range []string{"[REDACTED:authorization:", "[REDACTED:cookie:", "[REDACTED:token:"} {
		if !strings.Contains(got, marker) {
			t.Fatalf("redacted text missing marker %q:\n%s", marker, got)
		}
	}
}

func TestTextRedactsJSONFields(t *testing.T) {
	in := `{"username":"alice","password":"p@ssw0rd","access_token":"tok_123456789","note":"safe"}`
	got := Text(in)
	for _, secret := range []string{"p@ssw0rd", "tok_123456789"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted JSON still contains %q:\n%s", secret, got)
		}
	}
	if !strings.Contains(got, `"username":"alice"`) || !strings.Contains(got, `"note":"safe"`) {
		t.Fatalf("non-sensitive fields changed unexpectedly:\n%s", got)
	}
}

func TestTextStableCorrelation(t *testing.T) {
	in := "Cookie: sid=same-secret\nCookie: sid=same-secret\nCookie: sid=other-secret"
	got := Text(in)
	re := regexp.MustCompile(`\[REDACTED:cookie:[^\]]+\]`)
	matches := re.FindAllString(got, -1)
	if len(matches) != 3 {
		t.Fatalf("expected 3 cookie placeholders, got %d in:\n%s", len(matches), got)
	}
	if matches[0] != matches[1] {
		t.Fatalf("same secret should produce same placeholder: %q vs %q", matches[0], matches[1])
	}
	if matches[0] == matches[2] {
		t.Fatalf("different secrets should produce different placeholders: %q", matches[0])
	}
}

func TestTextIsMostlyTransparentForOrdinaryText(t *testing.T) {
	in := "Public product catalog page with search, sorting, and cart actions."
	if got := Text(in); got != in {
		t.Fatalf("ordinary text changed:\nwant %q\ngot  %q", in, got)
	}
}
