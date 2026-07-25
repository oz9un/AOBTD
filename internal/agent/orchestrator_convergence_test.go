package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/browser"
	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestPostExplorerAnalysisEndpointLimit(t *testing.T) {
	tests := map[int]int{
		0:  0,
		4:  4,
		6:  6,
		7:  6,
		18: 6,
	}
	for input, want := range tests {
		if got := postExplorerAnalysisEndpointLimit(input); got != want {
			t.Fatalf("postExplorerAnalysisEndpointLimit(%d) = %d, want %d", input, got, want)
		}
	}
}

func TestSmallReconUsesFocusedAnalysisAndNavigationBudgets(t *testing.T) {
	if got := reconFocusedAnalysisEndpointLimit(6, 3); got != 4 {
		t.Fatalf("focused analysis limit = %d, want 4", got)
	}
	if got := reconFocusedAnalysisEndpointLimit(6, 20); got != 6 {
		t.Fatalf("normal analysis limit = %d, want 6", got)
	}
	if got := reconFollowUpAnalysisEndpointLimit(6, 3); got != 2 {
		t.Fatalf("small Recon follow-up analysis limit = %d, want 2", got)
	}
	if got := reconFollowUpAnalysisEndpointLimit(6, 20); got != 6 {
		t.Fatalf("normal follow-up analysis limit = %d, want 6", got)
	}
	if got := reconPrimaryNavigationStepLimit(3); got != 3 {
		t.Fatalf("small Recon navigation limit = %d, want 3", got)
	}
	if got := reconPrimaryNavigationStepLimit(20); got != 6 {
		t.Fatalf("normal Recon navigation limit = %d, want 6", got)
	}
	if got := earlyNavigationStepLimit(policy.AuthorityRecon, 3); got != 4 {
		t.Fatalf("small Recon early navigation limit = %d, want 4", got)
	}
	if got := earlyNavigationStepLimit(policy.AuthorityActive, 3); got != 8 {
		t.Fatalf("Active early navigation limit = %d, want 8", got)
	}
}

func TestReconFollowUpNavigationIsShorterThanInitialTour(t *testing.T) {
	tests := map[int]int{
		0: 0,
		2: 2,
		3: 2,
		6: 2,
		9: 2,
	}
	for initial, want := range tests {
		if got := reconFollowUpNavigationStepLimit(initial); got != want {
			t.Fatalf("reconFollowUpNavigationStepLimit(%d) = %d, want %d", initial, got, want)
		}
	}
}

func TestReconUsesPhaseBoundaryStrategistInsteadOfPeriodicLoop(t *testing.T) {
	if shouldRunPeriodicStrategist(policy.AuthorityRecon) {
		t.Fatal("Recon enabled periodic Strategist model calls")
	}
	if !shouldRunPeriodicStrategist(policy.AuthorityActive) {
		t.Fatal("Active scan lost periodic Strategist planning")
	}
}

func TestReconDefersDuplicateFinalSynthesisForQueuedCopilotDirective(t *testing.T) {
	if !shouldDeferReconFinalSynthesis(policy.AuthorityRecon, 1) {
		t.Fatal("Recon did not defer synthesis for an already-approved Copilot directive")
	}
	if shouldDeferReconFinalSynthesis(policy.AuthorityRecon, 0) {
		t.Fatal("Recon deferred synthesis without pending Copilot work")
	}
	if shouldDeferReconFinalSynthesis(policy.AuthorityActive, 1) {
		t.Fatal("Active scan used Recon-only synthesis deferral")
	}
}

func TestReconFollowUpAnalysisRequiresNewTraffic(t *testing.T) {
	if shouldAnalyzeReconFollowUp(20, 20) {
		t.Fatal("unchanged follow-up traffic triggered redundant analysis")
	}
	if !shouldAnalyzeReconFollowUp(20, 21) {
		t.Fatal("new follow-up traffic did not trigger analysis")
	}
}

func TestReconCopilotDirectiveLifecyclePersistsAttributedTrafficAndCompletes(t *testing.T) {
	db, scanID := newConvergenceTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := browser.NewController("127.0.0.1:1", true, logger)
	targetURL := "https://example.test/recon/jobs"
	followUpID, err := db.InsertFollowUp(scanID, store.FollowUp{
		SourceAgent:  "copilot",
		Action:       "visit",
		URL:          targetURL,
		Reason:       "Inspect the exact jobs route already discovered by Recon.",
		Priority:     9,
		HypothesisID: "h-jobs-boundary",
	})
	if err != nil || followUpID == 0 {
		t.Fatalf("InsertFollowUp() = (%d, %v), want queued directive", followUpID, err)
	}

	orch := NewOrchestrator(db, ctrl, OrchestratorConfig{
		Target: "https://example.test", ScanID: scanID, TestingAuthority: policy.AuthorityRecon,
	}, logger)
	orch.reconCopilotVisit = func(ctx context.Context, rawURL string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if rawURL != targetURL {
			t.Fatalf("visit URL = %q, want %q", rawURL, targetURL)
		}
		provenance := ctrl.TrafficProvenanceForRequest(rawURL, "")
		if provenance.SourceAgent != "copilot" || provenance.SourceActionID != followUpID || provenance.HypothesisID != "h-jobs-boundary" {
			t.Fatalf("active Copilot provenance = %+v", provenance)
		}
		entry := &types.TrafficEntry{
			Request: types.CapturedRequest{
				Method: "GET", URL: rawURL, Host: "example.test", Path: "/recon/jobs", Headers: map[string]string{},
			},
			Response: types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html"},
		}
		provenance.Apply(entry)
		_, err := db.InsertTraffic(scanID, entry)
		return err
	}

	processed, err := orch.runReconCopilotDirectives(context.Background())
	if err != nil || processed != 1 {
		t.Fatalf("runReconCopilotDirectives() = (%d, %v), want (1, nil)", processed, err)
	}
	followUps, err := db.ListFollowUps(scanID, 10)
	if err != nil || len(followUps) != 1 {
		t.Fatalf("ListFollowUps() = (%d, %v), want one directive", len(followUps), err)
	}
	if followUps[0].Status != store.FollowUpDone || !strings.Contains(followUps[0].Result, "Completed approved read-only VISIT") {
		t.Fatalf("terminal directive = status %q result %q", followUps[0].Status, followUps[0].Result)
	}
	traffic, err := db.GetTrafficByScan(scanID)
	if err != nil || len(traffic) != 1 {
		t.Fatalf("GetTrafficByScan() = (%d, %v), want one captured request", len(traffic), err)
	}
	if traffic[0].SourceAgent != "copilot" || traffic[0].SourceActionID != followUpID || traffic[0].HypothesisID != "h-jobs-boundary" {
		t.Fatalf("persisted traffic provenance = %+v", traffic[0])
	}
	if got := ctrl.TrafficProvenance(); got.SourceAgent != "capture" || got.SourceActionID != 0 {
		t.Fatalf("Copilot provenance leaked after completion: %+v", got)
	}
}

func TestFinalReconHandoffClosesFollowUpsCreatedAfterCopilotRefresh(t *testing.T) {
	db, scanID := newConvergenceTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	orch := NewOrchestrator(db, nil, OrchestratorConfig{
		Target: "https://example.test", ScanID: scanID, TestingAuthority: policy.AuthorityRecon,
	}, logger)
	if _, err := db.InsertFollowUp(scanID, store.FollowUp{
		SourceAgent: "analyzer", Action: "probe_param", URL: "https://example.test/search",
	}); err != nil {
		t.Fatal(err)
	}

	closed, err := orch.closeReconActiveFollowUps()
	if err != nil || closed != 1 {
		t.Fatalf("final Recon handoff = (%d,%v), want (1,nil)", closed, err)
	}
	var status string
	if err := db.Conn().QueryRow(`SELECT status FROM follow_ups WHERE scan_id=?`, scanID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != store.FollowUpSkipped {
		t.Fatalf("post-refresh follow-up status = %q, want skipped", status)
	}
}

func TestFinalConvergenceRequiresNoPendingOrRunningFollowUps(t *testing.T) {
	db, scanID := newConvergenceTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	orch := NewOrchestrator(db, nil, OrchestratorConfig{
		Target: "https://example.test",
		ScanID: scanID,
	}, logger)
	orch.finalConvergenceRounds = 1
	orch.finalConvergenceBudget = time.Second

	if err := orch.runFinalConvergence(context.Background()); err != nil {
		t.Fatalf("runFinalConvergence() error = %v", err)
	}

	narrations, err := db.GetNarrations(scanID, 0, 20)
	if err != nil {
		t.Fatalf("GetNarrations() error = %v", err)
	}
	var completed bool
	for _, n := range narrations {
		if n.Action == "convergence_complete" {
			completed = true
		}
	}
	if !completed {
		t.Fatal("final convergence did not persist its completed fixed point")
	}
}

func TestFinalConvergenceReportsUnownedRunningLease(t *testing.T) {
	db, scanID := newConvergenceTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := db.InsertFollowUp(scanID, store.FollowUp{
		Action: "fetch",
		URL:    "https://example.test/account",
	}); err != nil {
		t.Fatalf("InsertFollowUp() error = %v", err)
	}
	claimed, err := db.ClaimFollowUps(scanID, 1, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimFollowUps() = (%d, %v), want one active lease", len(claimed), err)
	}

	orch := NewOrchestrator(db, nil, OrchestratorConfig{
		Target: "https://example.test",
		ScanID: scanID,
	}, logger)
	orch.finalConvergenceRounds = 1
	orch.finalConvergenceBudget = time.Second
	orch.finalExplorerBudget = 100 * time.Millisecond

	err = orch.runFinalConvergence(context.Background())
	var convergenceErr *ConvergenceError
	if !errors.As(err, &convergenceErr) {
		t.Fatalf("runFinalConvergence() error = %v, want *ConvergenceError", err)
	}
	if convergenceErr.Pending != 0 || convergenceErr.Running != 1 {
		t.Fatalf("convergence counts = pending %d, running %d; want 0, 1",
			convergenceErr.Pending, convergenceErr.Running)
	}
}

func TestFinalConvergenceReclaimsExpiredRunningWork(t *testing.T) {
	db, scanID := newConvergenceTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	id, err := db.InsertFollowUp(scanID, store.FollowUp{
		Action: "obsolete_action",
		URL:    "https://example.test/legacy-task",
	})
	if err != nil {
		t.Fatalf("InsertFollowUp() error = %v", err)
	}
	if claimed, err := db.ClaimFollowUps(scanID, 1, time.Minute); err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimFollowUps() = (%d, %v), want one task", len(claimed), err)
	}
	if _, err := db.Conn().Exec(`
		UPDATE follow_ups SET lease_expires_at = datetime('now', '-1 second')
		WHERE scan_id = ? AND id = ?`, scanID, id); err != nil {
		t.Fatalf("expire follow-up lease: %v", err)
	}

	orch := NewOrchestrator(db, nil, OrchestratorConfig{
		Target: "https://example.test",
		ScanID: scanID,
	}, logger)
	orch.finalConvergenceRounds = 2
	orch.finalConvergenceBudget = 2 * time.Second
	orch.finalExplorerBudget = time.Second

	if err := orch.runFinalConvergence(context.Background()); err != nil {
		t.Fatalf("runFinalConvergence() error = %v", err)
	}
	counts, err := db.CountFollowUpsByStatus(scanID)
	if err != nil {
		t.Fatalf("CountFollowUpsByStatus() error = %v", err)
	}
	if counts[store.FollowUpSkipped] != 1 || counts[store.FollowUpRunning] != 0 {
		t.Fatalf("follow-up counts = %v, want one reclaimed/skipped task and none running", counts)
	}
}

func TestFinalConvergenceCompletesWhenLastRoundDrainsQueue(t *testing.T) {
	db, scanID := newConvergenceTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := db.InsertFollowUp(scanID, store.FollowUp{
		Action: "obsolete_action",
		URL:    "https://example.test/legacy-task",
	}); err != nil {
		t.Fatalf("InsertFollowUp() error = %v", err)
	}

	orch := NewOrchestrator(db, nil, OrchestratorConfig{
		Target: "https://example.test",
		ScanID: scanID,
	}, logger)
	orch.finalConvergenceRounds = 1
	orch.finalConvergenceBudget = time.Second
	orch.finalExplorerBudget = time.Second

	if err := orch.runFinalConvergence(context.Background()); err != nil {
		t.Fatalf("runFinalConvergence() error = %v", err)
	}
	counts, err := db.CountFollowUpsByStatus(scanID)
	if err != nil {
		t.Fatalf("CountFollowUpsByStatus() error = %v", err)
	}
	if counts[store.FollowUpPending] != 0 || counts[store.FollowUpRunning] != 0 {
		t.Fatalf("follow-up counts = %v, want no pending/running work", counts)
	}
}

func TestAwaitedStrategistCycleReportsInsufficientBudget(t *testing.T) {
	db, scanID := newConvergenceTestDB(t)
	for i := 0; i < 5; i++ {
		entry := &types.TrafficEntry{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://example.test/resource/" + string(rune('a'+i)),
			},
			Response:  types.CapturedResponse{StatusCode: 200},
			Timestamp: time.Now(),
		}
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatalf("InsertTraffic(%d) error = %v", i, err)
		}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	budget := llm.NewBudget(1, 100, 0, logger)
	strategist := NewStrategistAgent(db, scanID, fixedTokenProvider{}, budget,
		StrategistConfig{Period: time.Hour}, logger)
	err := strategist.RunCycle(context.Background(), "test_final")
	if !errors.Is(err, ErrStrategistBudgetLimited) {
		t.Fatalf("RunCycle() error = %v, want ErrStrategistBudgetLimited", err)
	}
}

func newConvergenceTestDB(t *testing.T) (*store.DB, int64) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "convergence.db"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	return db, scanID
}

type fixedTokenProvider struct{}

func (fixedTokenProvider) Complete(context.Context, *llm.Request) (*llm.Response, error) {
	return &llm.Response{Content: `{}`}, nil
}

func (fixedTokenProvider) CountTokens(string) int { return 100 }
func (fixedTokenProvider) ModelInfo() llm.ModelInfo {
	return llm.ModelInfo{Name: "fixed-token-test", SupportsJSON: true}
}
func (fixedTokenProvider) Name() string { return "fixed-token-test" }
