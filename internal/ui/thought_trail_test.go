package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestBuildThoughtTrailSummarizesWorkflowsAndGuardrails(t *testing.T) {
	db, scanID := seedThoughtTrailDB(t)
	defer db.Close()

	trail := buildThoughtTrail(db, scanID)
	if trail.Metrics.WorkflowCount != 3 {
		t.Fatalf("workflow count = %d, want 3", trail.Metrics.WorkflowCount)
	}
	if trail.Metrics.HighPriorityWorkflows != 2 {
		t.Fatalf("high-priority workflows = %d, want 2", trail.Metrics.HighPriorityWorkflows)
	}
	if trail.Metrics.GuardedActions != 1 {
		t.Fatalf("guarded actions = %d, want 1", trail.Metrics.GuardedActions)
	}
	if trail.Metrics.ActiveHypotheses != 0 {
		t.Fatalf("active hypotheses = %d, want 0 after linked proof", trail.Metrics.ActiveHypotheses)
	}
	if trail.Metrics.TargetedTests != 1 {
		t.Fatalf("targeted tests = %d, want 1", trail.Metrics.TargetedTests)
	}
	if trail.Metrics.ConfirmedFindings != 1 {
		t.Fatalf("confirmed findings = %d, want 1", trail.Metrics.ConfirmedFindings)
	}
	if !strings.Contains(trail.Summary, "held back from 1 sensitive action") {
		t.Fatalf("summary does not explain guarded action: %q", trail.Summary)
	}
	if len(trail.Workflows) == 0 || trail.Workflows[0].Name != "authentication" {
		t.Fatalf("workflows not priority-sorted: %+v", trail.Workflows)
	}
	if len(trail.Decisions) == 0 || trail.Decisions[0].Tone != "guarded" {
		t.Fatalf("guarded decision missing: %+v", trail.Decisions)
	}
	if len(trail.Hypotheses) != 1 || trail.Hypotheses[0].EvidenceGrade != "proven" || trail.Hypotheses[0].TestsCompleted != 1 {
		t.Fatalf("hypothesis evidence state = %+v", trail.Hypotheses)
	}
	if len(trail.OpenQuestions) == 0 || !strings.Contains(trail.OpenQuestions[0], "roles, ownership rules") {
		t.Fatalf("open questions = %+v", trail.OpenQuestions)
	}
}

func TestHandleStrategyIncludesThoughtTrail(t *testing.T) {
	db, scanID := seedThoughtTrailDB(t)
	defer db.Close()

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", nil)
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/strategy?scan_id=%d", scanID), nil)
	w := httptest.NewRecorder()
	s.handleStrategy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode strategy response: %v\n%s", err, w.Body.String())
	}
	trail, ok := body["thought_trail"].(map[string]any)
	if !ok {
		t.Fatalf("thought_trail missing: %#v", body)
	}
	metrics, ok := trail["metrics"].(map[string]any)
	if !ok || int(metrics["guarded_actions"].(float64)) != 1 {
		t.Fatalf("thought_trail metrics = %#v", trail["metrics"])
	}
}

func seedThoughtTrailDB(t *testing.T) (*store.DB, int64) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := db.CreateScan("https://target.example.test", "{}")
	if err != nil {
		t.Fatal(err)
	}
	areas := `[
		{"name":"search","endpoints":["h3"],"status":"partially_analyzed","priority":6},
		{"name":"authentication","endpoints":["h1"],"status":"partially_analyzed","priority":10},
		{"name":"transaction","endpoints":["h2"],"status":"partially_analyzed","priority":9}
	]`
	if err := db.UpsertAppUnderstanding(scanID, "general_web_app", "[]", areas, "{}", "Login and booking workflows observed."); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertNarration(scanID, "navigator", "thought",
		"Sensitive business controls visible but should not be activated automatically: Confirm booking(sensitive_state_change).",
		"https://target.example.test/book", nil); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertHypothesis(store.Hypothesis{
		ID:                 "H-1",
		ScanID:             scanID,
		Statement:          "Booking confirmation may trust client-controlled workflow state.",
		Confidence:         0.72,
		Status:             store.HypothesisActive,
		SupportingEvidence: []string{"transaction workflow exposes booking id"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertDirective(scanID, store.FollowUp{
		Action:   "probe_logic",
		URL:      "https://target.example.test/api/bookings/1",
		Reason:   "Test booking state invariant",
		Priority: 9,
		Status:   store.FollowUpDone,
	}, []string{"H-1"}, "H-1", "strategist"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertFinding(scanID, types.Finding{
		Title:        "BOLA confirmed on booking object",
		Severity:     types.SeverityHigh,
		Confidence:   types.ConfidenceConfirmed,
		VulnType:     "bola",
		EndpointID:   "GET /api/bookings/2",
		HypothesisID: "H-1",
	}); err != nil {
		t.Fatal(err)
	}
	return db, scanID
}
