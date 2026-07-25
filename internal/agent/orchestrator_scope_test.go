package agent

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/policy"
)

func TestHostMatchesScope(t *testing.T) {
	tests := []struct {
		host    string
		allowed []string
		want    bool
	}{
		{host: "127.0.0.1:3000", allowed: []string{"127.0.0.1"}, want: true},
		{host: "api.example.test:443", allowed: []string{"example.test"}, want: true},
		{host: "example.test.", allowed: []string{"example.test"}, want: true},
		{host: "github.githubassets.com:443", allowed: []string{"127.0.0.1"}, want: false},
		{host: "evilexample.test", allowed: []string{"example.test"}, want: false},
	}

	for _, tt := range tests {
		if got := hostMatchesScope(tt.host, tt.allowed); got != tt.want {
			t.Errorf("hostMatchesScope(%q, %v) = %v, want %v", tt.host, tt.allowed, got, tt.want)
		}
	}
}

func TestOrchestratorBuildsExactOriginExecutionPolicy(t *testing.T) {
	db, scanID := newConvergenceTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	orch := NewOrchestrator(db, nil, OrchestratorConfig{
		Target:           "http://127.0.0.1:3000/app",
		ScanID:           scanID,
		Scope:            []string{"127.0.0.1", "api.example.test"},
		TestingAuthority: policy.AuthorityRecon,
	}, logger)
	if orch.policyErr != nil {
		t.Fatalf("NewOrchestrator policy error = %v", orch.policyErr)
	}
	if got := orch.executionPolicy.Authorize(policy.Action{
		TargetURL: "http://127.0.0.1:3000/read", Method: "GET",
	}); !got.Allowed {
		t.Fatalf("target origin denied: %+v", got)
	}
	if got := orch.executionPolicy.Authorize(policy.Action{
		TargetURL: "http://api.example.test:3000/read", Method: "GET",
	}); !got.Allowed {
		t.Fatalf("explicit legacy scope origin denied: %+v", got)
	}
	if got := orch.executionPolicy.Authorize(policy.Action{
		TargetURL: "http://admin.example.test:3000/read", Method: "GET",
	}); got.Allowed || got.Code != policy.CodeOutOfScope {
		t.Fatalf("unlisted subdomain decision = %+v", got)
	}
	if got := orch.executionPolicy.Authorize(policy.Action{
		TargetURL: "http://127.0.0.1:3000/write", Method: "POST",
	}); got.Allowed || got.Code != policy.CodeAuthorityDenied {
		t.Fatalf("recon POST decision = %+v", got)
	}
}

func TestOrchestratorPersistsPolicyDenialReason(t *testing.T) {
	db, scanID := newConvergenceTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	orch := NewOrchestrator(db, nil, OrchestratorConfig{
		Target: "https://example.test", ScanID: scanID,
		TestingAuthority: policy.AuthorityActive,
	}, logger)
	decision := orch.executionPolicy.Authorize(policy.Action{
		TargetURL: "https://example.test.evil/path", Method: "GET",
	})
	orch.auditPolicyDenial(decision)

	narrations, err := db.GetNarrations(scanID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(narrations) != 1 || narrations[0].Agent != "policy" || narrations[0].Action != "denied" {
		t.Fatalf("policy narrations = %+v", narrations)
	}
	if narrations[0].Metadata["code"] != string(policy.CodeOutOfScope) {
		t.Fatalf("denial metadata = %+v", narrations[0].Metadata)
	}
}

func TestOrchestratorCoalescesRepeatedPolicyDenials(t *testing.T) {
	db, scanID := newConvergenceTestDB(t)
	orch := NewOrchestrator(db, nil, OrchestratorConfig{
		Target: "https://example.test", ScanID: scanID,
		TestingAuthority: policy.AuthorityRecon,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	decision := orch.executionPolicy.Authorize(policy.Action{
		TargetURL: "https://example.test/update", Method: "POST",
	})
	for range 50 {
		orch.auditPolicyDenial(decision)
	}

	narrations, err := db.GetNarrations(scanID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(narrations) != 3 {
		t.Fatalf("policy narration count = %d, want milestones at 1, 10, and 50", len(narrations))
	}
	wantCounts := []float64{1, 10, 50}
	for i, narration := range narrations {
		if got := narration.Metadata["occurrence_count"]; got != wantCounts[i] {
			t.Fatalf("narration %d occurrence_count = %v, want %v", i, got, wantCounts[i])
		}
	}
}

func TestReconSkipsActiveVerificationPipeline(t *testing.T) {
	if shouldRunActiveVerification(policy.AuthorityRecon) {
		t.Fatal("recon authority would schedule active verification")
	}
	if shouldRunExplorerFollowUps(policy.AuthorityRecon) {
		t.Fatal("recon authority would execute Explorer follow-ups")
	}
	if shouldRunInteractiveAuthentication(policy.AuthorityRecon) {
		t.Fatal("recon authority would request or submit credentials")
	}
	for _, authority := range []policy.TestingAuthority{policy.AuthorityActive, policy.AuthorityFullControl} {
		if !shouldRunActiveVerification(authority) {
			t.Fatalf("%s authority unexpectedly skips active verification", authority)
		}
		if !shouldRunExplorerFollowUps(authority) {
			t.Fatalf("%s authority unexpectedly skips Explorer follow-ups", authority)
		}
		if !shouldRunInteractiveAuthentication(authority) {
			t.Fatalf("%s authority unexpectedly skips interactive authentication", authority)
		}
	}
}

func TestReconCopilotActionSupportedIsReadOnlyAndSourceBound(t *testing.T) {
	for _, action := range []string{"visit", "fetch", "reanalyze", " VISIT "} {
		if !reconCopilotActionSupported("copilot", action) {
			t.Fatalf("approved Copilot action %q was not supported", action)
		}
	}
	for _, tc := range []struct {
		source string
		action string
	}{
		{"strategist", "visit"},
		{"copilot", "probe_param"},
		{"copilot", "submit"},
		{"copilot", "POST"},
		{"", "visit"},
	} {
		if reconCopilotActionSupported(tc.source, tc.action) {
			t.Fatalf("unsafe/unowned action unexpectedly supported: source=%q action=%q", tc.source, tc.action)
		}
	}
}

func TestReconDefersAppSummaryUntilTerminalSynthesis(t *testing.T) {
	db, scanID := newConvergenceTestDB(t)
	orch := NewOrchestrator(db, nil, OrchestratorConfig{
		Target: "https://example.test", ScanID: scanID,
		Provider: fixedTokenProvider{}, Budget: llm.NewBudget(10_000, 20_000, 0, nil),
		TestingAuthority: policy.AuthorityRecon,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if analyzer := orch.newAnalyzerAgent(); analyzer.appSummaryEnabled {
		t.Fatal("recon endpoint pass would spend the terminal app-summary call early")
	}
	orch.testingAuthority = policy.AuthorityActive
	if analyzer := orch.newAnalyzerAgent(); !analyzer.appSummaryEnabled {
		t.Fatal("active analyzer unexpectedly deferred its app summary")
	}
}

func TestOrchestratorFailsBeforeExecutionWithInvalidPolicyTarget(t *testing.T) {
	db, scanID := newConvergenceTestDB(t)
	orch := NewOrchestrator(db, nil, OrchestratorConfig{
		Target: "not-an-absolute-url", ScanID: scanID,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := orch.Run(context.Background()); err == nil {
		t.Fatal("Run() accepted a target that could not form an execution policy")
	}
}
