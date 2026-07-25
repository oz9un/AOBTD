package store

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestAnalysisLearningCheckpointPersistsMovementAndConsecutiveAge(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "learning.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	first := []AnalysisQueueItem{
		{EndpointHash: "alpha", EvidenceID: 1, Method: "GET", Path: "/alpha", BaseScore: 90, LearnedBoost: 10, EvidenceGain: 10, PriorityScore: 100, Disposition: "analyze", Reasons: []string{"identity gap"}, Impact: []AnalysisGapImpact{{Kind: "target", ID: "application_identity", Label: "Application identity", Priority: 10, Score: 10}}},
		{EndpointHash: "beta", EvidenceID: 2, Method: "GET", Path: "/beta", BaseScore: 80, PriorityScore: 80, Disposition: "analyze"},
		{EndpointHash: "gamma", EvidenceID: 3, Method: "GET", Path: "/gamma", BaseScore: 70, PriorityScore: 70, Disposition: "analyze"},
	}
	if _, err := db.RecordAnalysisLearningCheckpoint(scanID, "model-a", []string{"application_identity"}, nil, first, first[:1]); err != nil {
		t.Fatal(err)
	}
	ages, err := db.GetAnalysisQueueAges(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if ages["alpha"] != 0 || ages["beta"] != 1 || ages["gamma"] != 1 {
		t.Fatalf("ages after first checkpoint = %#v", ages)
	}

	second := []AnalysisQueueItem{
		{EndpointHash: "gamma", EvidenceID: 3, Method: "GET", Path: "/gamma", BaseScore: 70, AgingBoost: 4, PriorityScore: 74, QueueAge: 1, FairnessLane: true, Disposition: "analyze", Reasons: []string{"deferred for 1 checkpoint"}},
		{EndpointHash: "beta", EvidenceID: 2, Method: "GET", Path: "/beta", BaseScore: 80, AgingBoost: 4, PriorityScore: 84, QueueAge: 1, Disposition: "analyze"},
	}
	if _, err := db.RecordAnalysisLearningCheckpoint(scanID, "model-b", []string{"business_object_coverage"}, nil, second, second[:1]); err != nil {
		t.Fatal(err)
	}
	ages, err = db.GetAnalysisQueueAges(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if ages["gamma"] != 0 || ages["beta"] != 2 {
		t.Fatalf("consecutive ages after fairness selection = %#v", ages)
	}

	history, err := db.ListAnalysisLearningCheckpoints(scanID, 4, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[0].Sequence != 2 || history[0].ModelFingerprint != "model-b" {
		t.Fatalf("history = %+v", history)
	}
	if len(history[0].Movements) != 2 || !history[0].Movements[0].Selected || !history[0].Movements[0].FairnessLane {
		t.Fatalf("latest movement selection = %+v", history[0].Movements)
	}
	if history[0].Movements[0].EndpointHash != "gamma" || history[0].Movements[0].PreviousRank != 3 || history[0].Movements[0].RankDelta != 2 {
		t.Fatalf("gamma movement = %+v", history[0].Movements[0])
	}
	if len(history[1].Movements) == 0 || history[1].Movements[0].EvidenceGain != 10 || len(history[1].Movements[0].Impact) != 1 || history[1].Movements[0].Impact[0].ID != "application_identity" {
		t.Fatalf("durable evidence impact = %+v", history[1].Movements)
	}
}

func TestResolveAnalysisPriorityMovementPersistsCompactionOutcome(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "resolved-learning.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://content.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	queue := []AnalysisQueueItem{{
		EndpointHash: "tag-books", EvidenceID: 9, Method: "GET", Path: "/tag/books/page/1/",
		BaseScore: 70, PriorityScore: 70, Disposition: "analyze", Reasons: []string{"capture relevance"},
	}}
	if _, err := db.RecordAnalysisLearningCheckpoint(scanID, "model", nil, nil, queue, queue); err != nil {
		t.Fatal(err)
	}
	if err := db.ResolveAnalysisPriorityMovement(scanID, "tag-books", "compacted", "equivalent route family already analyzed"); err != nil {
		t.Fatal(err)
	}
	history, err := db.ListAnalysisLearningCheckpoints(scanID, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || len(history[0].Movements) != 1 {
		t.Fatalf("history = %+v", history)
	}
	movement := history[0].Movements[0]
	if movement.Disposition != "compacted" || !movement.Selected || len(movement.Reasons) != 2 {
		t.Fatalf("resolved movement = %+v", movement)
	}
	summary, err := db.GetAnalysisEfficiencySummary(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.SemanticCallsSaved != 1 || summary.SemanticCallsSpent != 0 || summary.SelectedCandidates != 1 {
		t.Fatalf("efficiency summary after compaction = %+v", summary)
	}
}

func TestAnalysisEfficiencySummaryUsesFullDurableHistory(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "efficiency.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://content.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	for index := 0; index < 9; index++ {
		hash := fmt.Sprintf("route-%d", index)
		queue := []AnalysisQueueItem{{
			EndpointHash: hash, EvidenceID: int64(index + 1), Method: "GET",
			Path: fmt.Sprintf("/tag/topic-%d/", index), BaseScore: 70,
			PriorityScore: 70, Disposition: "analyze",
		}}
		if _, err := db.RecordAnalysisLearningCheckpoint(scanID, "model", nil, nil, queue, queue); err != nil {
			t.Fatal(err)
		}
		if index < 7 {
			if err := db.ResolveAnalysisPriorityMovement(scanID, hash, "compacted", "representative reused"); err != nil {
				t.Fatal(err)
			}
		}
	}

	summary, err := db.GetAnalysisEfficiencySummary(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.SemanticCallsSaved != 7 || summary.SemanticCallsSpent != 2 || summary.SelectedCandidates != 9 {
		t.Fatalf("full-history efficiency summary = %+v", summary)
	}
	history, err := db.ListAnalysisLearningCheckpoints(scanID, 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 4 || summary.SelectedCandidates <= len(history) {
		t.Fatalf("expected aggregate to exceed bounded history: summary=%+v history=%d", summary, len(history))
	}
}

func TestAnalysisEfficiencySummarySeparatesProtectionSpecimenFromSavedRepeats(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "protection-efficiency.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://protected.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	for index, outcome := range []struct {
		disposition string
		reason      string
	}{
		{"closed", "protection specimen retained: cloudflare interstitial shape abc"},
		{"compacted", "equivalent cloudflare protection interstitial already retained"},
		{"analyze", "representative application response"},
	} {
		hash := fmt.Sprintf("protected-%d", index)
		queue := []AnalysisQueueItem{{EndpointHash: hash, Method: "GET", Path: "/protected", Disposition: "analyze"}}
		if _, err := db.RecordAnalysisLearningCheckpoint(scanID, "model", nil, nil, queue, queue); err != nil {
			t.Fatal(err)
		}
		if outcome.disposition != "analyze" {
			if err := db.ResolveAnalysisPriorityMovement(scanID, hash, outcome.disposition, outcome.reason); err != nil {
				t.Fatal(err)
			}
		}
	}
	summary, err := db.GetAnalysisEfficiencySummary(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ProtectionSpecimens != 1 || summary.ProtectionCallsSaved != 1 ||
		summary.SemanticCallsSaved != 1 || summary.SemanticCallsSpent != 1 || summary.DeterministicClosures != 1 {
		t.Fatalf("protection efficiency summary = %+v", summary)
	}
}

func TestAnalysisImpactOutcomesAreBatchScopedAndCalibrateOnlyAfterRepeatedEvidence(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "impact-feedback.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://app.test", `{}`)
	initial := []AnalysisGapState{
		{Kind: "target", ID: "ownership_boundaries", Label: "Ownership", Value: .2, Present: true},
		{Kind: "unknown", ID: "owner-question", Label: "Which account owns this order?", Present: true},
	}
	first := []AnalysisQueueItem{
		{
			EndpointHash: "orders", EvidenceID: 1, Method: "GET", Path: "/orders/42", Disposition: "analyze",
			Impact: []AnalysisGapImpact{
				{Kind: "target", ID: "ownership_boundaries", Label: "Ownership", Score: 26},
				{Kind: "unknown", ID: "owner-question", Label: "Which account owns this order?", Score: 12},
			},
		},
		{
			EndpointHash: "account", EvidenceID: 2, Method: "GET", Path: "/accounts/7", Disposition: "analyze",
			Impact: []AnalysisGapImpact{{Kind: "target", ID: "ownership_boundaries", Label: "Ownership", Score: 26}},
		},
	}
	if _, err := db.RecordAnalysisLearningCheckpoint(scanID, "model-1", []string{"ownership_boundaries"}, initial, first, first); err != nil {
		t.Fatal(err)
	}
	afterFirst := []AnalysisGapState{{Kind: "target", ID: "ownership_boundaries", Label: "Ownership", Value: .5, Present: true}}
	resolved, err := db.ResolveLatestAnalysisImpactOutcomes(scanID, afterFirst)
	if err != nil || resolved != 2 {
		t.Fatalf("resolved movements=%d err=%v", resolved, err)
	}
	history, err := db.ListAnalysisLearningCheckpoints(scanID, 1, 6)
	if err != nil || len(history) != 1 || len(history[0].Movements) != 2 {
		t.Fatalf("impact history=%+v err=%v", history, err)
	}
	for _, movement := range history[0].Movements {
		if (movement.OutcomeStatus != "resolved" && movement.OutcomeStatus != "improved") || len(movement.Outcomes) == 0 {
			t.Fatalf("movement outcome not resolved: %+v", movement)
		}
		for _, outcome := range movement.Outcomes {
			if !outcome.BatchScoped {
				t.Fatalf("outcome overstated per-route causality: %+v", outcome)
			}
		}
	}
	calibration, err := db.ListAnalysisImpactCalibration(scanID)
	if err != nil {
		t.Fatal(err)
	}
	ownership := analysisCalibrationByID(calibration, "ownership_boundaries")
	if ownership.Successes != 1 || ownership.Misses != 0 || ownership.Adjustment != 0 {
		t.Fatalf("single batch should not calibrate despite two selected routes: %+v", calibration)
	}

	second := []AnalysisQueueItem{{
		EndpointHash: "orders-again", EvidenceID: 3, Method: "GET", Path: "/orders/43", Disposition: "analyze",
		Impact: []AnalysisGapImpact{{Kind: "target", ID: "ownership_boundaries", Label: "Ownership", Score: 26}},
	}}
	if _, err := db.RecordAnalysisLearningCheckpoint(scanID, "model-2", []string{"ownership_boundaries"}, afterFirst, second, second); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ResolveLatestAnalysisImpactOutcomes(scanID, afterFirst); err != nil {
		t.Fatal(err)
	}
	calibration, err = db.ListAnalysisImpactCalibration(scanID)
	if err != nil {
		t.Fatal(err)
	}
	ownership = analysisCalibrationByID(calibration, "ownership_boundaries")
	if ownership.Successes != 1 || ownership.Misses != 1 || ownership.Adjustment != -1 {
		t.Fatalf("two checkpoint outcomes did not calibrate conservatively: %+v", calibration)
	}
}

func analysisCalibrationByID(values []AnalysisImpactCalibration, id string) AnalysisImpactCalibration {
	for _, value := range values {
		if value.ID == id {
			return value
		}
	}
	return AnalysisImpactCalibration{}
}
