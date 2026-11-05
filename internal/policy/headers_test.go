package policy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseHeaders(t *testing.T) {
	h, err := ParseHeaders([]string{"authorization: Bearer abc", "", "X-Api-Key:k1"})
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("Authorization") != "Bearer abc" || h.Get("X-Api-Key") != "k1" {
		t.Fatalf("got %v", h)
	}
	for _, bad := range []string{"no-colon", ": empty-name", "Host: evil", "Bad Name: x", "X: a\r\nInjected: y"} {
		if _, err := ParseHeaders([]string{bad}); err == nil {
			t.Errorf("ParseHeaders(%q) should fail", bad)
		}
	}
}

func TestInjectHeadersBoundToTargetOrigin(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
	}))
	defer srv.Close()

	e, err := New(AuthorityActive, []string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetInjectedHeaders(srv.URL, http.Header{"Authorization": {"Bearer tok"}}); err != nil {
		t.Fatal(err)
	}

	// Other origin: untouched.
	other, _ := http.NewRequest(http.MethodGet, "https://cdn.example.net/x.js", nil)
	if e.WithInjectedHeaders(other).Header.Get("Authorization") != "" {
		t.Fatal("header leaked to a different origin")
	}

	// Existing header wins (e.g. secondary BOLA persona).
	own, _ := http.NewRequest(http.MethodGet, srv.URL+"/a", nil)
	own.Header.Set("Authorization", "Bearer other-user")
	if e.WithInjectedHeaders(own).Header.Get("Authorization") != "Bearer other-user" {
		t.Fatal("existing header was overwritten")
	}

	// Through the protected client: injected on the wire, caller's request unmodified.
	client := ProtectHTTPClient(srv.Client(), e, HTTPOptions{CredentialOrigin: srv.URL})
	req, _ := http.NewRequestWithContext(WithActionClass(t.Context(), ActionPassive), http.MethodGet, srv.URL+"/b", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(got) != 1 || got[0] != "Bearer tok" {
		t.Fatalf("server saw %v", got)
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("RoundTrip mutated the caller's request")
	}
}
