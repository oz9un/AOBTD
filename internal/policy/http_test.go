package policy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestProtectedHTTPClientEnforcesAuthorityBeforeNetwork(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	tests := []struct {
		name      string
		authority TestingAuthority
		method    string
		allowed   bool
		code      DecisionCode
	}{
		{"recon GET", AuthorityRecon, http.MethodGet, true, CodeAllowed},
		{"recon POST", AuthorityRecon, http.MethodPost, false, CodeAuthorityDenied},
		{"active POST", AuthorityActive, http.MethodPost, true, CodeAllowed},
		{"active DELETE", AuthorityActive, http.MethodDelete, false, CodeAuthorityDenied},
		{"full DELETE", AuthorityFullControl, http.MethodDelete, true, CodeAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := hits.Load()
			engine := mustEngine(t, tt.authority, server.URL)
			var audited []Decision
			client := ProtectHTTPClient(nil, engine, HTTPOptions{
				Audit: func(d Decision) { audited = append(audited, d) },
			})
			req, err := http.NewRequest(tt.method, server.URL+"/resource", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if tt.allowed {
				if err != nil {
					t.Fatalf("Do() error = %v", err)
				}
				resp.Body.Close()
				if len(audited) != 0 {
					t.Fatalf("allowed request unexpectedly audited as denial: %+v", audited)
				}
				if hits.Load() != before+1 {
					t.Fatalf("server hits = %d, want %d", hits.Load(), before+1)
				}
				return
			}
			if err == nil {
				resp.Body.Close()
				t.Fatal("denied request reached the network")
			}
			decision, ok := DecisionFromError(err)
			if !ok || decision.Code != tt.code {
				t.Fatalf("denial = (%+v, %v), want %s", decision, ok, tt.code)
			}
			if hits.Load() != before {
				t.Fatalf("denied request changed server hits from %d to %d", before, hits.Load())
			}
			if len(audited) != 1 || audited[0].Code != tt.code {
				t.Fatalf("audit = %+v, want one %s decision", audited, tt.code)
			}
		})
	}
}

func TestProtectedHTTPClientBlocksCredentialMutationGETBeforeNetwork(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	engine := mustEngine(t, AuthorityActive, server.URL)
	client := ProtectHTTPClient(nil, engine, HTTPOptions{})
	req, err := http.NewRequest(
		http.MethodGet,
		server.URL+"/rest/user/change-password?current=admin123&new=admin1234&repeat=admin1234",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("credential mutation unexpectedly succeeded under active authority")
	}
	decision, ok := DecisionFromError(err)
	if !ok || decision.Code != CodeAuthorityDenied ||
		len(decision.Classes) != 1 || decision.Classes[0] != ActionDestructive {
		t.Fatalf("credential-mutation denial = (%+v, %v), want destructive authority denial", decision, ok)
	}
	if hits.Load() != 0 {
		t.Fatalf("credential mutation reached the network (%d hits)", hits.Load())
	}
}

func TestProtectedHTTPClientRevalidatesRedirectHops(t *testing.T) {
	var escaped atomic.Int32
	offScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer offScope.Close()

	inScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/escape":
			http.Redirect(w, r, offScope.URL+"/stolen", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer inScope.Close()

	engine := mustEngine(t, AuthorityActive, inScope.URL)
	client := ProtectHTTPClient(nil, engine, HTTPOptions{})
	resp, err := client.Get(inScope.URL + "/same")
	if err != nil {
		t.Fatalf("same-origin redirect error = %v", err)
	}
	resp.Body.Close()

	resp, err = client.Get(inScope.URL + "/escape")
	if err == nil {
		resp.Body.Close()
		t.Fatal("off-scope redirect unexpectedly succeeded")
	}
	decision, ok := DecisionFromError(err)
	if !ok || decision.Code != CodeOutOfScope {
		t.Fatalf("redirect denial = (%+v, %v), want out_of_scope", decision, ok)
	}
	if escaped.Load() != 0 {
		t.Fatalf("off-scope redirect target received %d request(s)", escaped.Load())
	}
}

func TestProtectedHTTPClientBindsCredentialOrigin(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer first.Close()
	var secondHits atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer second.Close()

	engine := mustEngine(t, AuthorityFullControl, first.URL, second.URL)
	client := ProtectHTTPClient(nil, engine, HTTPOptions{CredentialOrigin: first.URL})

	same, _ := http.NewRequest(http.MethodGet, first.URL+"/account", nil)
	same.Header.Set("Authorization", "Bearer secret")
	resp, err := client.Do(same)
	if err != nil {
		t.Fatalf("same-origin credential request error = %v", err)
	}
	resp.Body.Close()

	cross, _ := http.NewRequest(http.MethodGet, second.URL+"/account", nil)
	cross.Header.Set("Cookie", "sid=secret")
	resp, err = client.Do(cross)
	if err == nil {
		resp.Body.Close()
		t.Fatal("cross-origin credential request unexpectedly succeeded")
	}
	decision, ok := DecisionFromError(err)
	if !ok || decision.Code != CodeCredentialOriginMismatch {
		t.Fatalf("credential denial = (%+v, %v)", decision, ok)
	}
	if secondHits.Load() != 0 {
		t.Fatalf("credential escaped to second origin (%d hits)", secondHits.Load())
	}

	missingEngine := mustEngine(t, AuthorityFullControl, first.URL)
	missingClient := ProtectHTTPClient(nil, missingEngine, HTTPOptions{})
	missing, _ := http.NewRequest(http.MethodGet, first.URL, nil)
	missing.Header.Set("X-API-Key", "secret")
	if _, err := missingClient.Do(missing); err == nil {
		t.Fatal("sensitive header without bound origin unexpectedly succeeded")
	} else if d, ok := DecisionFromError(err); !ok || d.Code != CodeCredentialOriginRequired {
		t.Fatalf("missing binding denial = (%+v, %v)", d, ok)
	}
}

func TestProtectedHTTPClientHonorsRaisedContextClass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	engine := mustEngine(t, AuthorityActive, server.URL)
	client := ProtectHTTPClient(nil, engine, HTTPOptions{})
	req, _ := http.NewRequestWithContext(
		WithActionClass(context.Background(), ActionDestructive),
		http.MethodGet, server.URL+"/reset", nil,
	)
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("destructive GET unexpectedly allowed under active authority")
	}
	decision, ok := DecisionFromError(err)
	if !ok || decision.Code != CodeAuthorityDenied || len(decision.Classes) != 1 || decision.Classes[0] != ActionDestructive {
		t.Fatalf("raised-class denial = (%+v, %v)", decision, ok)
	}

	var denied *DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("errors.As could not unwrap DeniedError from %T", err)
	}
}

func TestProtectedHTTPClientRejectsVirtualHostOverride(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	engine := mustEngine(t, AuthorityFullControl, server.URL)
	client := ProtectHTTPClient(nil, engine, HTTPOptions{})
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/admin", nil)
	req.Host = "evil.test"
	_, err := client.Do(req)
	decision, ok := DecisionFromError(err)
	if !ok || decision.Code != CodeHostOverrideMismatch {
		t.Fatalf("Host override decision = (%+v, %v), err=%v", decision, ok, err)
	}
	if hits.Load() != 0 {
		t.Fatalf("Host override reached server (%d hits)", hits.Load())
	}

	matching, _ := http.NewRequest(http.MethodGet, server.URL+"/ok", nil)
	matching.Host = matching.URL.Host
	resp, err := client.Do(matching)
	if err != nil {
		t.Fatalf("matching Host override denied: %v", err)
	}
	resp.Body.Close()
}
