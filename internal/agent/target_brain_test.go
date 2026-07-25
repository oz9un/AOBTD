package agent

import (
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
)

func TestTargetBrainBuildsEvidenceLinkedAdaptivePlan(t *testing.T) {
	recon := extract.ReconModel{
		Identity: extract.ReconIdentity{AppType: "e-commerce", Summary: "Observed catalog and account application."},
		Pages: []extract.PagePurposeCard{{
			ID: "GET /account", Method: "GET", URL: "https://shop.test/account",
			Purpose: "Account details", Area: "account", Confidence: .9,
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /account"}},
		}},
		Roles: []extract.ReconRole{{
			ID: "visitor", Name: "Public visitor", Confidence: .8,
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /account"}},
		}},
		Unknowns: []extract.ReconUnknown{{
			ID: "account_owner", Question: "Which account identifier binds the current user?",
			Priority: 9, SuggestedAction: "Analyze the captured account response.",
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /account"}, {Kind: "inference", Ref: "gap"}},
		}},
		Targets: []extract.ReconTarget{
			{ID: "application_identity", Label: "Application identity", Actual: 1, Target: 1, Met: true, EvidenceRefs: []string{"GET /account"}},
			{ID: "ownership_boundaries", Label: "Ownership boundaries", Actual: .2, Target: .5, Priority: 10},
		},
		Metrics: extract.ReconMetrics{UnderstandingScore: .72, OverallConfidence: .68, TargetsMet: 1, TargetsTotal: 2},
	}
	objectives := []ReconObjective{{
		ID: "ownership_boundaries", Kind: "ownership", Priority: 10,
		Question: "Which ownership boundary protects account records?", SuggestedAction: "Analyze the captured account response.",
	}}
	queue := []store.AnalysisQueueItem{{
		EndpointHash: "account", EvidenceID: 44, Method: "GET", URL: "https://shop.test/account", Path: "/account",
		Disposition: "analyze", EvidenceGain: 26,
		Impact: []store.AnalysisGapImpact{{Kind: "target", ID: "ownership_boundaries", Label: "Ownership boundaries", Score: 26, Priority: 10}},
	}}

	brain := BuildTargetBrain(recon, objectives, queue, nil)
	if brain.State != "adapting" || brain.Focus == nil || brain.Focus.ID != "ownership_boundaries" || !brain.Focus.EvidenceReady {
		t.Fatalf("adaptive focus = %+v state=%q", brain.Focus, brain.State)
	}
	if len(brain.Moves) != 1 {
		t.Fatalf("moves = %+v", brain.Moves)
	}
	move := brain.Moves[0]
	if move.Mode != "analyze" || move.State != "captured" || move.EvidenceID != 44 || move.URL != "https://shop.test/account" || move.EvidenceGain != 26 {
		t.Fatalf("grounded move = %+v", move)
	}
	if len(move.Expected) != 1 || move.Expected[0].ID != "ownership_boundaries" {
		t.Fatalf("expected impact = %+v", move.Expected)
	}
	if brain.Saturation.Verdict != "learning" || brain.Saturation.ExactMoves != 1 {
		t.Fatalf("saturation = %+v", brain.Saturation)
	}
	if brain.Fingerprint == "" || len(brain.Dimensions) != 7 {
		t.Fatalf("briefing fingerprint/dimensions missing: %+v", brain)
	}
	for _, ref := range brain.Thesis.EvidenceRefs {
		if ref == "gap" {
			t.Fatalf("inference-only gap leaked into thesis evidence: %+v", brain.Thesis.EvidenceRefs)
		}
	}
}

func TestTargetBrainLabelsBoundedLowConfidenceRecovery(t *testing.T) {
	recon := extract.ReconModel{
		Targets: []extract.ReconTarget{{
			ID: "claim_confidence", Label: "Evidence confidence", Priority: 9,
			Actual: .6, Target: .85,
		}},
		Metrics: extract.ReconMetrics{UnderstandingScore: .6, TargetsTotal: 1},
	}
	objectives := []ReconObjective{{
		ID: "claim_confidence", Kind: "general", Priority: 9,
		Question: "Which exact response can increase confidence?",
	}}
	queue := []store.AnalysisQueueItem{{
		EndpointHash: "login-recovery", EvidenceID: 77, Method: "GET",
		URL: "https://example.test/account/login", Path: "/account/login",
		Disposition: "analyze", Reanalysis: true, ProfileConfidence: .1,
		EvidenceGain: 12,
		Impact:       []store.AnalysisGapImpact{{Kind: "target", ID: "claim_confidence", Label: "Evidence confidence", Score: 12, Priority: 9}},
	}}
	brain := BuildTargetBrain(recon, objectives, queue, nil)
	if len(brain.Moves) == 0 || brain.Moves[0].State != "reanalysis" {
		t.Fatalf("bounded recovery was not visible in the plan: %+v", brain.Moves)
	}
	if !strings.Contains(brain.Moves[0].Why, "10% confidence") || !strings.Contains(brain.Moves[0].Why, "one bounded recovery pass") {
		t.Fatalf("recovery reason is not operator-legible: %+v", brain.Moves[0])
	}
}

func TestTargetBrainDoesNotInventMoveWhenEvidenceIsMissing(t *testing.T) {
	recon := extract.ReconModel{
		Identity: extract.ReconIdentity{AppType: "saas", Summary: "Observed public team workspace landing page."},
		Pages:    []extract.PagePurposeCard{{ID: "GET /", URL: "https://app.test/", Method: "GET", Purpose: "Landing page", Confidence: .8}},
		Targets:  []extract.ReconTarget{{ID: "actor_model", Label: "Actor model", Priority: 10, Actual: 0, Target: 1}},
		Metrics:  extract.ReconMetrics{UnderstandingScore: .35, TargetsTotal: 1},
	}
	objectives := []ReconObjective{{
		ID: "actor_model", Kind: "privilege", Priority: 10,
		Question: "Which authenticated actors exist?", SuggestedAction: "Use a second account and authenticated session.",
	}}
	brain := BuildTargetBrain(recon, objectives, nil, nil)
	if len(brain.Moves) != 1 || brain.Moves[0].Mode != "prerequisite" || brain.Moves[0].URL != "" || brain.Moves[0].EvidenceID != 0 {
		t.Fatalf("missing evidence became executable: %+v", brain.Moves)
	}
	if brain.State != "waiting" || brain.Saturation.Verdict != "needs_evidence" || brain.Focus == nil || brain.Focus.EvidenceReady {
		t.Fatalf("missing-evidence state = %+v", brain)
	}
	if !strings.Contains(brain.Saturation.Reason, "exact observed") {
		t.Fatalf("missing-evidence explanation not honest: %q", brain.Saturation.Reason)
	}
}

func TestTargetBrainFocusesEvidenceReadyGapBeforeBlockedPrerequisite(t *testing.T) {
	recon := extract.ReconModel{
		Pages: []extract.PagePurposeCard{{ID: "GET /catalog", URL: "https://app.test/catalog", Purpose: "Catalog"}},
		Targets: []extract.ReconTarget{
			{ID: "ownership_boundaries", Label: "Ownership", Priority: 10, Target: .5},
			{ID: "critical_purpose_coverage", Label: "Purpose", Priority: 8, Target: .8},
		},
		Metrics: extract.ReconMetrics{TargetsTotal: 2, UnderstandingScore: .4},
	}
	objectives := []ReconObjective{
		{ID: "ownership_boundaries", Kind: "ownership", Priority: 10, Question: "Can two accounts access the same object?", SuggestedAction: "Use a second account."},
		{ID: "critical_purpose_coverage", Kind: "general", Priority: 8, Question: "What does the catalog route do?", SuggestedAction: "Analyze its captured response."},
	}
	queue := []store.AnalysisQueueItem{{
		EndpointHash: "catalog", EvidenceID: 8, Method: "GET", URL: "https://app.test/catalog", Path: "/catalog",
		Disposition: "analyze", EvidenceGain: 20,
		Impact: []store.AnalysisGapImpact{{Kind: "target", ID: "critical_purpose_coverage", Label: "Critical purpose coverage", Score: 20}},
	}}
	brain := BuildTargetBrain(recon, objectives, queue, nil)
	if brain.Focus == nil || brain.Focus.ID != "critical_purpose_coverage" || !brain.Focus.EvidenceReady {
		t.Fatalf("brain did not pivot to reducible evidence: focus=%+v moves=%+v", brain.Focus, brain.Moves)
	}
	foundPrerequisite := false
	for _, move := range brain.Moves {
		foundPrerequisite = foundPrerequisite || (move.ObjectiveID == "ownership_boundaries" && move.Mode == "prerequisite")
	}
	if !foundPrerequisite {
		t.Fatalf("blocked higher-priority objective disappeared: %+v", brain.Moves)
	}
}

func TestTargetBrainReportsBatchScopedPlanRevision(t *testing.T) {
	history := []store.AnalysisLearningCheckpoint{{
		Sequence: 7, SelectedCount: 2,
		Movements: []store.AnalysisPriorityMovement{{
			Selected: true, EvidenceID: 91, Method: "GET", Path: "/orders",
			OutcomeStatus: "improved",
			Impact:        []store.AnalysisGapImpact{{Kind: "target", ID: "workflow_grounding", Label: "Grounded workflows"}},
		}},
	}}
	brain := BuildTargetBrain(extract.ReconModel{}, nil, nil, history)
	if len(brain.Revisions) != 1 || brain.Revisions[0].Status != "improved" || brain.Revisions[0].EvidenceID != 91 {
		t.Fatalf("revision = %+v", brain.Revisions)
	}
	if !strings.Contains(brain.Revisions[0].Detail, "batch-scoped correlation") {
		t.Fatalf("revision overstates causality: %q", brain.Revisions[0].Detail)
	}
}

func TestTargetBrainDoesNotBlendHypothesizedActorIntoGroundedDimension(t *testing.T) {
	recon := extract.ReconModel{
		Roles: []extract.ReconRole{{
			ID: "authenticated_member", Name: "Authenticated member", Confidence: .8,
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /login"}},
		}},
		Objects: []extract.BusinessObject{{
			ID: "profile", Name: "Profile", Confidence: .8,
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /profiles/42"}},
		}},
		OwnershipBoundaries: []extract.OwnershipBoundary{{
			ID: "own-profile", ObjectID: "profile", OwnerRoleID: "authenticated_member",
			Rule: "Members can update only their own profile.", Confidence: .7,
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /profiles/42"}},
		}},
		Targets: []extract.ReconTarget{{ID: "actor_model", Met: true, Actual: 1, Target: 1}},
		Metrics: extract.ReconMetrics{TargetsMet: 1, TargetsTotal: 1},
	}
	brain := BuildTargetBrain(recon, nil, nil, nil)
	byID := map[string]TargetBrainDimension{}
	for _, dimension := range brain.Dimensions {
		byID[dimension.ID] = dimension
	}
	if len(byID["actors"].Claims) != 1 || byID["actors"].Claims[0].Truth != "hypothesis" {
		t.Fatalf("authenticated page evidence became an observed actor: %+v", byID["actors"])
	}
	if len(byID["objects"].Claims) != 1 || byID["objects"].Claims[0].Truth != "observed" {
		t.Fatalf("direct object evidence lost: %+v", byID["objects"])
	}
	if len(byID["boundaries"].Claims) != 1 || byID["boundaries"].Claims[0].Truth != "hypothesis" {
		t.Fatalf("one-persona ownership rule was overstated: %+v", byID["boundaries"])
	}
}

func TestTargetBrainTreatsEvidenceBackedUnauthenticatedActorAsObserved(t *testing.T) {
	recon := extract.ReconModel{
		Roles: []extract.ReconRole{{
			ID: "unauthenticated_visitor", Name: "Unauthenticated visitor",
			Description: "Public visitor receives an anonymous session bootstrap cookie.",
			Evidence:    []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /login"}},
		}},
		Targets: []extract.ReconTarget{{ID: "actor_model", Met: true, Actual: 1, Target: 1}},
	}

	brain := BuildTargetBrain(recon, nil, nil, nil)
	var actors TargetBrainDimension
	for _, dimension := range brain.Dimensions {
		if dimension.ID == "actors" {
			actors = dimension
			break
		}
	}
	if len(actors.Claims) != 1 || actors.Claims[0].Truth != "observed" ||
		len(actors.Claims[0].EvidenceRefs) != 1 || actors.Claims[0].EvidenceRefs[0] != "GET /login" {
		t.Fatalf("evidence-backed unauthenticated actor truth = %+v", actors)
	}
}

func TestTargetBrainMarksFullyGroundedModelWithoutClaimingFinalTruth(t *testing.T) {
	recon := extract.ReconModel{
		Pages:   []extract.PagePurposeCard{{ID: "GET /", URL: "https://docs.test/", Purpose: "Documentation index"}},
		Targets: []extract.ReconTarget{{ID: "application_identity", Met: true, Actual: 1, Target: 1}},
		Metrics: extract.ReconMetrics{UnderstandingScore: 1, TargetsMet: 1, TargetsTotal: 1},
	}
	brain := BuildTargetBrain(recon, nil, nil, nil)
	if brain.State != "grounded" || brain.Saturation.Verdict != "evidence_target_met" {
		t.Fatalf("grounded state = %+v", brain.Saturation)
	}
	if !strings.Contains(brain.Saturation.Reason, "new evidence may still revise") {
		t.Fatalf("grounded state claims final truth: %q", brain.Saturation.Reason)
	}
}

func TestTargetBrainMarksPublicOnlyOwnershipAsNotApplicable(t *testing.T) {
	recon := extract.ReconModel{
		OwnershipBoundaries: []extract.OwnershipBoundary{{
			ID: "public-docs", Rule: "Documentation pages are publicly readable",
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /docs"}},
		}},
		Targets: []extract.ReconTarget{{
			ID: "ownership_boundaries", Label: "Ownership boundary coverage", Met: true, Actual: 1, Target: .5,
			SuggestedAction: "No per-user ownership proof is required for the modeled public read-only objects; revisit this gate only if authenticated evidence appears.",
		}},
	}
	brain := BuildTargetBrain(recon, nil, nil, nil)
	for _, dimension := range brain.Dimensions {
		if dimension.ID == "boundaries" {
			if dimension.Status != "not_applicable" {
				t.Fatalf("public-only ownership status = %q, want not_applicable", dimension.Status)
			}
			return
		}
	}
	t.Fatal("boundaries dimension missing")
}

func TestTargetBrainTreatsProtectionAsEvidenceCeilingNotSaturation(t *testing.T) {
	brain := BuildTargetBrain(extract.ReconModel{
		Targets: []extract.ReconTarget{{ID: "application_identity", Met: true, Actual: 1, Target: 1}},
		Metrics: extract.ReconMetrics{UnderstandingScore: 1, TargetsMet: 1, TargetsTotal: 1},
	}, nil, nil, nil)
	ApplyTargetBrainAccess(&brain, "protected", "protection interstitial", "Only a stable WAF response was captured.")
	if brain.State != "constrained" || brain.StateLabel != "protection interstitial" || brain.Saturation.Verdict != "access_constrained" {
		t.Fatalf("protected target looked saturated: %+v", brain)
	}
	if !brain.Access.Constrains || brain.Access.Detail == "" || brain.Fingerprint == "" {
		t.Fatalf("access ceiling missing: %+v", brain.Access)
	}
}
