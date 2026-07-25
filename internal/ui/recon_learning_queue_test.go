package ui

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	scanagent "github.com/ozzyw/aobtd/internal/agent"
	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestReconLearningQueueExposesLearnedAnalysisPriority(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "learning.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	entry := &types.TrafficEntry{
		Request:   types.CapturedRequest{Method: "GET", URL: "https://app.test/login", Headers: map[string]string{}},
		Response:  types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html", Body: []byte(`<form><input name="email"></form>`)},
		Timestamp: time.Now(),
	}
	if _, err := db.InsertTraffic(scanID, entry); err != nil {
		t.Fatal(err)
	}
	challenge := &types.TrafficEntry{
		Request: types.CapturedRequest{Method: "GET", URL: "https://app.test/protected", Headers: map[string]string{}},
		Response: types.CapturedResponse{
			StatusCode: 403, ContentType: "text/html", Headers: map[string]string{"Server": "cloudflare"},
			Body: []byte(`<title>Just a moment...</title><p>Performing security verification</p>`),
		},
		Timestamp: time.Now(),
	}
	if _, err := db.InsertTraffic(scanID, challenge); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkEndpointAnalyzed(scanID, challenge.EndpointHash, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`UPDATE traffic SET relevance_score = 0.8, relevance_scored = TRUE WHERE scan_id = ?`, scanID); err != nil {
		t.Fatal(err)
	}
	u := extract.NewAppUnderstanding()
	u.Recon.Unknowns = []extract.ReconUnknown{{
		ID: "actor-gap", Question: "Which login boundary distinguishes anonymous and authenticated actors?",
		SuggestedAction: "Inspect the observed login page", Priority: 9,
	}}
	if err := db.UpsertReconModel(scanID, u.ReconJSON()); err != nil {
		t.Fatal(err)
	}
	queue, err := db.GetUnanalyzedEndpointQueue(scanID, 0.3, scanagent.AnalysisCandidateWindowSize)
	if err != nil || len(queue) != 1 {
		t.Fatalf("seed analysis queue = %+v err=%v", queue, err)
	}
	ranked := scanagent.RankAnalysisQueue(queue, u.Recon)
	if _, err := db.RecordAnalysisLearningCheckpoint(scanID, scanagent.AnalysisReconFingerprint(u.Recon), scanagent.AnalysisQueueFocusIDs(u.Recon), scanagent.AnalysisGapStateSnapshot(u.Recon), ranked, ranked); err != nil {
		t.Fatal(err)
	}
	if resolved, err := db.ResolveLatestAnalysisImpactOutcomes(scanID, nil); err != nil || resolved != 1 {
		t.Fatalf("resolve queue feedback=%d err=%v", resolved, err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleReconLearningQueue(w, httptest.NewRequest(http.MethodGet,
		"/api/recon-learning-queue?scan_id="+strconv.FormatInt(scanID, 10), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Analysis struct {
			FeedbackBatchSize int `json:"feedback_batch_size"`
			AIReady           int `json:"ai_ready"`
			Counts            struct {
				Ready int `json:"ready"`
			} `json:"counts"`
			Items []struct {
				Path           string                    `json:"path"`
				LearnedBoost   int                       `json:"learned_boost"`
				EvidenceGain   int                       `json:"evidence_gain"`
				LearnedReasons []string                  `json:"learned_reasons"`
				Impact         []store.AnalysisGapImpact `json:"impact"`
			} `json:"items"`
		} `json:"analysis"`
		Efficiency store.AnalysisEfficiencySummary `json:"efficiency"`
		Protection store.ProtectionEvidenceSummary `json:"protection"`
		Objectives []struct {
			ID string `json:"id"`
		} `json:"objectives"`
		Calibration []store.AnalysisImpactCalibration `json:"calibration"`
		History     []struct {
			Sequence      int `json:"sequence"`
			SelectedCount int `json:"selected_count"`
			Movements     []struct {
				OutcomeStatus string `json:"outcome_status"`
			} `json:"movements"`
		} `json:"history"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Analysis.Counts.Ready != 1 || response.Analysis.AIReady != 1 || response.Analysis.FeedbackBatchSize != 8 || len(response.Analysis.Items) != 1 {
		t.Fatalf("analysis payload = %+v body=%s", response.Analysis, w.Body.String())
	}
	item := response.Analysis.Items[0]
	if item.Path != "/login" || item.LearnedBoost <= 0 || item.EvidenceGain <= 0 || len(item.LearnedReasons) == 0 {
		t.Fatalf("learned queue item = %+v", item)
	}
	foundActorGap := false
	for _, impact := range item.Impact {
		if impact.ID == "actor-gap" && impact.Kind == "unknown" {
			foundActorGap = true
		}
	}
	if !foundActorGap {
		t.Fatalf("queue item omitted exact predicted gap impact: %+v", item)
	}
	if len(response.Objectives) == 0 {
		t.Fatalf("objective projection missing: %s", w.Body.String())
	}
	if len(response.History) != 1 || response.History[0].Sequence != 1 || response.History[0].SelectedCount != 1 || len(response.History[0].Movements) != 1 || response.History[0].Movements[0].OutcomeStatus != "resolved" {
		t.Fatalf("learning history missing: %+v body=%s", response.History, w.Body.String())
	}
	actorCalibration := store.AnalysisImpactCalibration{}
	for _, value := range response.Calibration {
		if value.ID == "actor-gap" {
			actorCalibration = value
		}
	}
	if actorCalibration.Successes != 1 || actorCalibration.Misses != 0 || actorCalibration.Adjustment != 0 {
		t.Fatalf("single successful checkpoint feedback should be visible but neutral: %+v body=%s", response.Calibration, w.Body.String())
	}
	if response.Efficiency.SemanticCallsSpent != 1 || response.Efficiency.SelectedCandidates != 1 {
		t.Fatalf("analysis efficiency missing: %+v body=%s", response.Efficiency, w.Body.String())
	}
	if response.Protection.InterstitialResponses != 1 || response.Protection.DistinctShapes != 1 || len(response.Protection.Vendors) != 1 {
		t.Fatalf("protection evidence missing: %+v body=%s", response.Protection, w.Body.String())
	}
}
