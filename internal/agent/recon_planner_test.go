package agent

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
)

func TestReconPlannerPrioritizesCriticalGateAndHighValueUnknown(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "planner.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	u := extract.NewAppUnderstanding()
	u.Recon.Unknowns = []extract.ReconUnknown{
		{ID: "low", Question: "What color is the footer?", Priority: 3},
		{ID: "workflow", Question: "Which pages form the state-changing checkout workflow?", SuggestedAction: "Navigate the primary journey", Priority: 8, Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /products"}}},
		{ID: "tenant", Question: "Is tenant isolation enforced?", Priority: 10},
	}
	if err := db.UpsertReconModel(scanID, u.ReconJSON()); err != nil {
		t.Fatal(err)
	}
	objectives, err := NewReconPlanner(db, scanID).Plan(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(objectives) != 2 || objectives[0].ID != "application_identity" || objectives[1].ID != "tenant" {
		t.Fatalf("objectives = %+v", objectives)
	}
	if !objectives[0].DerivedTarget || objectives[1].Kind != "ownership" {
		t.Fatalf("objective kinds = %+v", objectives)
	}
}

func TestRenderReconObjectivesConstrainsNavigator(t *testing.T) {
	rendered := renderReconObjectives([]ReconObjective{{
		ID: "workflow", Kind: "workflow", Priority: 9, Question: "Where is the order transition?",
		SuggestedAction: "Open the observed basket", EvidenceRefs: []string{"GET /basket"},
	}})
	for _, want := range []string{"P9 [workflow]", "highest expected information gain", "never guess a route", "GET /basket"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("objective prompt missing %q: %s", want, rendered)
		}
	}
}

func TestReconPlannerFallsBackToDeterministicUnderstandingTargets(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "target-planner.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	u := extract.NewAppUnderstanding()
	u.AppType = "saas"
	u.Summary = "A team application with account administration and shared project workflows."
	u.Recon.Pages = []extract.PagePurposeCard{{ID: "GET /login", Method: "GET", URL: "https://app.test/login", Purpose: "Login", Area: "authentication", Confidence: .9}}
	u.RecalculateReconMetrics()
	if err := db.UpsertAppUnderstanding(scanID, u.AppType, "[]", "[]", "{}", u.Summary); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertReconModel(scanID, u.ReconJSON()); err != nil {
		t.Fatal(err)
	}

	objectives, err := NewReconPlanner(db, scanID).Plan(3)
	if err != nil {
		t.Fatal(err)
	}
	var derived *ReconObjective
	for i := range objectives {
		if objectives[i].DerivedTarget {
			derived = &objectives[i]
			break
		}
	}
	if derived == nil {
		t.Fatalf("expected target-derived objective, got %+v", objectives)
	}
	if !strings.Contains(derived.Question, "target") {
		t.Fatalf("derived objective does not expose measurable target: %+v", derived)
	}
}

func TestBuildReconObjectivesDoesNotHideCriticalTargetBehindLowerPriorityQuestion(t *testing.T) {
	recon := extract.ReconModel{
		Unknowns: []extract.ReconUnknown{{ID: "nice-to-know", Question: "Which optional theme is selected?", Priority: 6}},
		Targets:  []extract.ReconTarget{{ID: "actor_model", Label: "Actor model", Priority: 10, Target: 1}},
	}
	objectives := BuildReconObjectives(recon, 2)
	if len(objectives) != 2 || objectives[0].ID != "actor_model" || !objectives[0].DerivedTarget {
		t.Fatalf("critical target was hidden by optional question: %+v", objectives)
	}
}
