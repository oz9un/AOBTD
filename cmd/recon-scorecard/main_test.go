package main

import (
	"slices"
	"testing"

	"github.com/ozzyw/aobtd/internal/extract"
)

func TestAssessFindsEvidenceCalibrationFailures(t *testing.T) {
	recon := extract.ReconModel{
		Identity:            extract.ReconIdentity{AppType: "community", Summary: "Sequential IDs suggest IDOR vulnerability."},
		Roles:               []extract.ReconRole{{ID: "member", Name: "Registered Member"}},
		Workflows:           []extract.BusinessWorkflow{{Steps: []extract.WorkflowStep{{StateChange: true}}}},
		OwnershipBoundaries: []extract.OwnershipBoundary{{ID: "owner-rule"}},
		Metrics:             extract.ReconMetrics{TargetsMet: 5, TargetsTotal: 8, OwnershipModeled: 1, OwnershipCoverage: .25},
	}
	got := assess(recon, false, false, false)
	for _, want := range []string{
		"security-hypothesis-in-summary",
		"authenticated-role-hypothesis",
		"state-change-without-request",
		"gaps-without-questions",
		"ownership-mostly-inferred",
	} {
		if !slices.Contains(got, want) {
			t.Fatalf("assess() = %v, missing %q", got, want)
		}
	}
}

func TestAssessClearPublicReadOnlyModel(t *testing.T) {
	recon := extract.ReconModel{
		Identity:  extract.ReconIdentity{AppType: "documentation", Summary: "Public language reference with security vulnerability reporting guidance."},
		Roles:     []extract.ReconRole{{ID: "visitor", Name: "Public Visitor", Description: "Unauthenticated user browsing public content"}},
		Workflows: []extract.BusinessWorkflow{{ID: "browse"}},
		Unknowns:  []extract.ReconUnknown{{ID: "search", Question: "How does search route?"}},
		Metrics:   extract.ReconMetrics{TargetsMet: 7, TargetsTotal: 8},
	}
	if got := assess(recon, false, false, false); len(got) != 0 {
		t.Fatalf("assess() = %v, want no quality flags", got)
	}
}

func TestAssessSeparatesUnavailableTargetFromMissingJourney(t *testing.T) {
	recon := extract.ReconModel{
		Identity: extract.ReconIdentity{AppType: "api_service", Summary: "Rate-limited map service."},
		Metrics:  extract.ReconMetrics{TargetsMet: 2, TargetsTotal: 8},
	}
	got := assess(recon, false, false, true)
	if !slices.Contains(got, "target-evidence-unavailable") || slices.Contains(got, "no-human-journey") {
		t.Fatalf("assess() = %v, want target access failure without model journey failure", got)
	}
}

func TestClassifyAccessDistinguishesRenderedShellFromMappedTarget(t *testing.T) {
	if got := classifyAccess(3, 0, 0, 1, 1, 1); got != "limited" {
		t.Fatalf("single rendered shell classified %q, want limited", got)
	}
	if got := classifyAccess(3, 0, 0, 4, 8, 3); got != "available" {
		t.Fatalf("mapped target classified %q, want available", got)
	}
}

func TestBenchmarkVerdictUsesDifferentGatesForAvailableAndConstrainedTargets(t *testing.T) {
	available := scorecard{Status: "completed", Access: "available", Score: 90, Confidence: 74, GatesMet: 6}
	if verdict, gaps := benchmarkVerdict(available); verdict != "PASS" || len(gaps) != 0 {
		t.Fatalf("available target verdict = %s %v", verdict, gaps)
	}
	available.Score = 79
	if verdict, gaps := benchmarkVerdict(available); verdict != "FAIL" || !slices.Contains(gaps, "understanding<85") {
		t.Fatalf("weak available target verdict = %s %v", verdict, gaps)
	}

	constrained := scorecard{
		Status: "completed", Access: "limited", Score: 18, Confidence: 6, GatesMet: 2,
		QualityFlags: []string{"target-evidence-limited"},
	}
	if verdict, gaps := benchmarkVerdict(constrained); verdict != "PASS" || len(gaps) != 0 {
		t.Fatalf("honest constrained target verdict = %s %v", verdict, gaps)
	}
	constrained.Score = 72
	if verdict, gaps := benchmarkVerdict(constrained); verdict != "FAIL" || !slices.Contains(gaps, "access-failure-score>40") {
		t.Fatalf("inflated constrained target verdict = %s %v", verdict, gaps)
	}
}

func TestRunningBenchmarkIsNotGradedAsFailure(t *testing.T) {
	verdict, gaps := benchmarkVerdict(scorecard{Status: "running", Access: "available"})
	if verdict != "IN PROGRESS" || len(gaps) != 0 {
		t.Fatalf("running verdict = %s %v", verdict, gaps)
	}
}

func TestLimitedEvidenceDoesNotAlsoBlameTheModelForMissingAJourney(t *testing.T) {
	flags := []string{"no-human-journey", "target-evidence-limited"}
	got := withoutQualityFlag(flags, "no-human-journey")
	if slices.Contains(got, "no-human-journey") || !slices.Contains(got, "target-evidence-limited") {
		t.Fatalf("limited-access flags = %v", got)
	}
}

func TestCopilotLatencyPercentileUsesNearestRank(t *testing.T) {
	values := []int{45, 27, 38, 12, 30}
	if got := percentileNearestRank(values, .50); got != 30 {
		t.Fatalf("p50 = %d, want 30", got)
	}
	if got := percentileNearestRank(values, .95); got != 45 {
		t.Fatalf("p95 = %d, want 45", got)
	}
}
