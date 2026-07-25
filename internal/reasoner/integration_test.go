// Integration tests for the reasoner pipeline. Each test wires together:
//
//  1. A real store.DB (temp sqlite file)
//  2. A mock llm.Provider returning canned plan JSON
//  3. A tiny httptest.Server mimicking common vulnerable endpoints
//  4. A real reasoner.Executor executing the plans against that target
//
// The goal is to verify the end-to-end flow — Evidence → Reasoner →
// ProbePlan → Executor → HTTP → Finding — without hitting MiniMax or
// Juice Shop. These are the tests that lock the architecture against
// regression.
package reasoner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// mockProvider is a minimal llm.Provider that returns a pre-configured
// response. Used in tests so reasoners don't need a real MiniMax/Anthropic
// endpoint.
type mockProvider struct {
	name       string
	content    string
	inTokens   int
	outTokens  int
	err        error
	callCount  int
	lastSystem string
	lastUser   string
}

func (m *mockProvider) Complete(_ context.Context, req *llm.Request) (*llm.Response, error) {
	m.callCount++
	m.lastSystem = req.SystemPrompt
	if len(req.Messages) > 0 {
		m.lastUser = req.Messages[len(req.Messages)-1].Content
	}
	if m.err != nil {
		return nil, m.err
	}
	return &llm.Response{
		Content: m.content,
		Usage: llm.Usage{
			InputTokens:  m.inTokens,
			OutputTokens: m.outTokens,
		},
		StopReason: "stop",
	}, nil
}
func (m *mockProvider) CountTokens(text string) int { return len(text) / 4 }
func (m *mockProvider) ModelInfo() llm.ModelInfo {
	return llm.ModelInfo{Name: "mock", MaxContextTokens: 100000, MaxOutputTokens: 4000, SupportsJSON: true}
}
func (m *mockProvider) Name() string {
	if m.name == "" {
		return "mock"
	}
	return m.name
}

// vulnerableTestTarget returns an httptest.Server that mimics the classes
// of vulnerabilities the reasoner ensemble is designed to find.
func vulnerableTestTarget(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	// Weak-credentials login. Accepts demo:demo (+ a few other defaults)
	// and returns a JSON body with a token field. Rejects anything else
	// with 401.
	mux.HandleFunc("/rest/user/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var body struct{ Email, Password string }
		json.NewDecoder(r.Body).Decode(&body)
		if body.Email == "demo" && body.Password == "demo" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"authentication":{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vIn0.demo"}}`))
			return
		}
		// SQLi login-bypass variant: `admin' --` in email bypasses the password check.
		if strings.Contains(body.Email, "' --") || strings.Contains(body.Email, "' or ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"authentication":{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.x"}}`))
			return
		}
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"invalid_credentials"}`))
	})

	// Baseline-diff SQLi on q. Normal queries return a small JSON,
	// tautology-style payload returns a MUCH larger JSON (the "whole table").
	mux.HandleFunc("/rest/products/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		lower := strings.ToLower(q)
		if strings.Contains(lower, "' or 1=1") || strings.Contains(lower, "union select") {
			// Return a ~3× larger response.
			w.Write([]byte(`{"status":"success","data":[` +
				strings.Repeat(`{"id":1,"name":"p","price":1.0},`, 50) +
				`{"id":99,"name":"end","price":9.99}]}`))
			return
		}
		w.Write([]byte(`{"status":"success","data":[{"id":1,"name":"p","price":1.0}]}`))
	})

	// Generic 404 for anything else — realistic default behaviour.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})

	return httptest.NewServer(mux)
}

// testDB opens a clean DB in a t.TempDir + creates a scan row, returning
// both (cleanup is automatic via t.Cleanup).
func testDB(t *testing.T, target string) (*store.DB, int64) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	scanID, err := db.CreateScan(target, "{}")
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	return db, scanID
}

// ---------- Auth pipeline ----------

// TestAuthReasonerEndToEnd drives the full pipeline:
//
//	mock LLM → AuthReasoner.Apply() → validated plan →
//	Executor.ExecutePlan() → real HTTP → Finding in DB.
func TestAuthReasonerEndToEnd(t *testing.T) {
	srv := vulnerableTestTarget(t)
	defer srv.Close()
	target := srv.URL
	db, scanID := testDB(t, target)

	loginURL := target + "/rest/user/login"

	// Mock LLM returns a plan that the Executor can actually run against
	// the test server. URL must be in evidence (we'll add it as a
	// LoginEndpoint below) and technique must be in the allowlist.
	planJSON := fmt.Sprintf(`[
		{
			"technique":"weak_credentials",
			"target":{"url":%q,"method":"POST","body_type":"json"},
			"payloads":["demo:demo","wrong:wrong"],
			"confirmation":{"status_codes":[200],"body_contains":["\"token\""]},
			"rationale":"test: demo account + JSON body observed",
			"confidence":0.9
		}
	]`, loginURL)
	mock := &mockProvider{content: planJSON, inTokens: 500, outTokens: 120}

	r := NewAuthReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		ScanID: scanID, Target: target,
		LoginEndpoints: []DiscoveredEndpoint{
			{URL: loginURL, Method: "POST", Path: "/rest/user/login"},
		},
		ObservedEmails: []string{"demo"},
	}
	plans, usage, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected 1 validated plan, got %d", len(plans))
	}
	if plans[0].SourceReasoner != "AuthReasoner" {
		t.Errorf("SourceReasoner = %q, want AuthReasoner", plans[0].SourceReasoner)
	}
	if usage.InputTokens != 500 || usage.OutputTokens != 120 {
		t.Errorf("usage = %+v, want 500/120", usage)
	}

	// Executor runs the plan against the live test server.
	exec := NewExecutor(&http.Client{}, db, scanID, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	hit, err := exec.ExecutePlan(context.Background(), plans[0])
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if !hit {
		t.Fatal("Executor should have confirmed demo:demo login")
	}

	// Verify the finding landed in the DB.
	var count int
	var title string
	var sev string
	if err := db.Conn().QueryRow(
		`SELECT COUNT(*), COALESCE(MAX(title),''), COALESCE(MAX(severity),'') FROM findings WHERE scan_id = ? AND vuln_type = 'weak_credentials'`,
		scanID).Scan(&count, &title, &sev); err != nil {
		t.Fatalf("query finding: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 weak_credentials finding in DB, got %d", count)
	}
	if sev != string(types.SeverityCritical) {
		t.Errorf("severity = %q, want critical", sev)
	}
	if !strings.Contains(strings.ToLower(title), "demo:demo") &&
		!strings.Contains(strings.ToLower(title), "weak") {
		t.Errorf("title doesn't mention weak/demo: %q", title)
	}
}

// ---------- Injection pipeline ----------

// TestInjectionReasonerEndToEnd drives the SQLi pipeline against the
// baseline-diff behaviour of the test server. The mock returns a
// sqli_generic plan; Executor's baseline-diff confirms.
func TestInjectionReasonerEndToEnd(t *testing.T) {
	srv := vulnerableTestTarget(t)
	defer srv.Close()
	target := srv.URL
	db, scanID := testDB(t, target)

	searchURL := target + "/rest/products/search?q=hello"
	planJSON := fmt.Sprintf(`[
		{
			"technique":"sqli_generic",
			"target":{"url":%q,"method":"GET","field":"q"},
			"payloads":["' OR 1=1 -- "],
			"confirmation":{"status_codes":[200]},
			"rationale":"test: search q parameter is classic SQLi target",
			"confidence":0.8
		}
	]`, searchURL)
	mock := &mockProvider{content: planJSON, inTokens: 800, outTokens: 160}

	r := NewInjectionReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		ScanID: scanID, Target: target,
		QueryEndpoints: []DiscoveredEndpoint{
			{URL: searchURL, Method: "GET", Path: "/rest/products/search", Params: []string{"q"}},
		},
	}
	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plans))
	}
	if plans[0].SourceReasoner != "InjectionReasoner" {
		t.Errorf("SourceReasoner = %q", plans[0].SourceReasoner)
	}

	exec := NewExecutor(&http.Client{}, db, scanID, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	hit, err := exec.ExecutePlan(context.Background(), plans[0])
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if !hit {
		t.Fatal("Executor should have confirmed SQLi via baseline-diff (tautology payload returns 3× response)")
	}

	// Finding recorded.
	var count int
	if err := db.Conn().QueryRow(
		`SELECT COUNT(*) FROM findings WHERE scan_id = ? AND vuln_type = 'sqli'`,
		scanID).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 sqli finding, got %d", count)
	}
}

// ---------- Chain composition ----------

// TestChainReasonerComposesNarrative drives ChainReasoner with two
// previously-confirmed findings (SQLi + weak creds) and verifies it
// composes a narrative chain that the Executor stores as an
// attack_chain Finding.
func TestChainReasonerComposesNarrative(t *testing.T) {
	srv := vulnerableTestTarget(t)
	defer srv.Close()
	target := srv.URL
	db, scanID := testDB(t, target)

	// Pre-seed the DB with two confirmed ingredient findings — the
	// ChainReasoner's Evidence.Findings list will reflect them.
	db.InsertFinding(scanID, types.Finding{
		Title:      "Weak credentials demo:demo at /rest/user/login",
		Severity:   types.SeverityCritical,
		Confidence: types.ConfidenceConfirmed,
		VulnType:   "weak_credentials",
		EndpointID: "POST /rest/user/login",
	})
	db.InsertFinding(scanID, types.Finding{
		Title:      "SQL injection in q on /rest/products/search",
		Severity:   types.SeverityHigh,
		Confidence: types.ConfidenceConfirmed,
		VulnType:   "sqli",
		EndpointID: "GET /rest/products/search",
	})

	loginURL := target + "/rest/user/login"
	planJSON := fmt.Sprintf(`[
		{
			"technique":"chain_attack_narrative",
			"target":{"url":%q,"method":"POST"},
			"payloads":[
				"step 1: weak creds demo:demo on /rest/user/login — obtain session",
				"step 2: use session on /rest/products/search?q=' OR 1=1 -- — exfiltrate product table"
			],
			"confirmation":{"body_contains":["(narrative chain)"]},
			"rationale":"weak login + SQLi on search = full authenticated data exfil",
			"confidence":0.85
		}
	]`, loginURL)
	mock := &mockProvider{content: planJSON, inTokens: 900, outTokens: 400}

	r := NewChainReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev, err := BuildEvidence(context.Background(), db, scanID, target)
	if err != nil {
		t.Fatalf("BuildEvidence: %v", err)
	}
	if len(ev.Findings) < 2 {
		t.Fatalf("expected Evidence to carry 2 confirmed findings, got %d", len(ev.Findings))
	}
	// Ensure the plan's target URL IS in the loginEndpoints list so
	// validation passes. BuildEvidence's augment helper should have
	// pulled it in via the weak-creds finding.
	foundLoginURL := false
	for _, e := range ev.LoginEndpoints {
		if e.URL == loginURL {
			foundLoginURL = true
			break
		}
	}
	if !foundLoginURL {
		t.Fatalf("augmentLoginEndpointsFromFindings didn't surface %q; LoginEndpoints=%+v",
			loginURL, ev.LoginEndpoints)
	}

	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected 1 chain plan, got %d", len(plans))
	}
	if plans[0].Technique != "chain_attack_narrative" {
		t.Errorf("technique = %q", plans[0].Technique)
	}
	if len(plans[0].Payloads) != 2 {
		t.Errorf("steps count = %d", len(plans[0].Payloads))
	}

	// Executor stores the chain as an attack_chain Finding.
	exec := NewExecutor(&http.Client{}, db, scanID, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	hit, err := exec.ExecutePlan(context.Background(), plans[0])
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if !hit {
		t.Fatal("Executor should have stored the chain narrative as a finding")
	}
	var count int
	if err := db.Conn().QueryRow(
		`SELECT COUNT(*) FROM findings WHERE scan_id = ? AND vuln_type = 'attack_chain'`,
		scanID).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 attack_chain finding, got %d", count)
	}
	var steps string
	if err := db.Conn().QueryRow(
		`SELECT steps_to_reproduce FROM findings WHERE scan_id = ? AND vuln_type = 'attack_chain'`,
		scanID).Scan(&steps); err != nil {
		t.Fatalf("query chain steps: %v", err)
	}
	for _, want := range []string{
		"Retest and confirm each ingredient finding",
		"weak creds demo:demo",
		"composite chain finding",
	} {
		if !strings.Contains(steps, want) {
			t.Fatalf("chain steps missing %q:\n%s", want, steps)
		}
	}
}

// TestReasonerNoProviderIsNoOp verifies that every reasoner cleanly no-ops
// when no LLM provider is configured — important so the Phase 6.5 can run
// safely in --llm="" mode.
func TestReasonerNoProviderIsNoOp(t *testing.T) {
	ev := Evidence{ScanID: 1, Target: "http://x"}
	cases := []struct {
		name string
		r    Reasoner
	}{
		{"auth", NewAuthReasoner(nil, nil)},
		{"injection", NewInjectionReasoner(nil, nil)},
		{"access", NewAccessReasoner(nil, nil)},
		{"chain", NewChainReasoner(nil, nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plans, usage, err := tc.r.Apply(context.Background(), ev)
			if err != nil {
				t.Fatalf("%s: err %v", tc.name, err)
			}
			if len(plans) != 0 {
				t.Errorf("%s: expected 0 plans, got %d", tc.name, len(plans))
			}
			if usage.InputTokens != 0 || usage.OutputTokens != 0 {
				t.Errorf("%s: usage should be zero, got %+v", tc.name, usage)
			}
		})
	}
}

// newDiscardWriter returns an io.Writer that drops everything — used to
// silence test-side slog output.
func newDiscardWriter() *discardWriter { return &discardWriter{} }

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
