package proxy

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestProxyEnforcesPolicyForBrowserTrafficAndRedirects(t *testing.T) {
	var targetHits atomic.Int32
	var escapedHits atomic.Int32
	offScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escapedHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer offScope.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, offScope.URL+"/stolen", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	engine, err := policy.New(policy.AuthorityRecon, []string{target.URL})
	if err != nil {
		t.Fatal(err)
	}
	var auditMu sync.Mutex
	var audits []policy.Decision
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := New("127.0.0.1", 0, filepath.Join(t.TempDir(), "certs"), func(_ *types.TrafficEntry) {},
		engine, target.URL, func(d policy.Decision) {
			auditMu.Lock()
			audits = append(audits, d)
			auditMu.Unlock()
		}, logger)
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httptest.NewServer(p.gp)
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(target.URL + "/read")
	if err != nil {
		t.Fatalf("in-scope GET error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || targetHits.Load() != 1 {
		t.Fatalf("GET status/hits = %d/%d", resp.StatusCode, targetHits.Load())
	}

	req, _ := http.NewRequest(http.MethodPost, target.URL+"/write", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("denied POST transport error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || targetHits.Load() != 1 {
		t.Fatalf("POST status/hits = %d/%d, want 403/1", resp.StatusCode, targetHits.Load())
	}

	resp, err = client.Get(target.URL + "/redirect")
	if err != nil {
		t.Fatalf("redirect request error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("redirect final status = %d, want 403", resp.StatusCode)
	}
	if escapedHits.Load() != 0 {
		t.Fatalf("off-scope redirect escaped proxy (%d hits)", escapedHits.Load())
	}

	auditMu.Lock()
	defer auditMu.Unlock()
	if len(audits) != 2 || audits[0].Code != policy.CodeAuthorityDenied || audits[1].Code != policy.CodeOutOfScope {
		t.Fatalf("audits = %+v", audits)
	}
}

func TestProxyPolicyAllowsInScopeHTTPSMITM(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	engine, err := policy.New(policy.AuthorityRecon, []string{target.URL})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := New("127.0.0.1", 0, filepath.Join(t.TempDir(), "certs"),
		func(_ *types.TrafficEntry) {}, engine, target.URL, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httptest.NewServer(p.gp)
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get(target.URL + "/secure")
	if err != nil {
		t.Fatalf("HTTPS through policy proxy error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || hits.Load() != 1 {
		t.Fatalf("HTTPS status/hits = %d/%d", resp.StatusCode, hits.Load())
	}
}

func TestBrowserCredentialOriginUsesCookieJarForScopedSibling(t *testing.T) {
	engine, err := policy.New(policy.AuthorityRecon, []string{
		"https://www.example.com",
		"https://*.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://media.example.com/image.avif", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", "consent=yes")
	bound := browserCredentialOrigin(req, "https://www.example.com")
	decision := engine.AuthorizeHTTPRequest(req, bound)
	if !decision.Allowed {
		t.Fatalf("cookie-jar scoped sibling denied: %+v", decision)
	}

	req.Header.Set("Authorization", "Bearer secret")
	bound = browserCredentialOrigin(req, "https://www.example.com")
	decision = engine.AuthorizeHTTPRequest(req, bound)
	if decision.Allowed || decision.Code != policy.CodeCredentialOriginMismatch {
		t.Fatalf("bearer credential crossed sibling origin: %+v", decision)
	}
}
