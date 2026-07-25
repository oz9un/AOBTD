package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AnalysisLearningCheckpoint is one durable capture -> understand -> reorder
// decision. Movements are the bounded candidate window as it appeared to the
// Analyzer, not reconstructed UI telemetry.
type AnalysisLearningCheckpoint struct {
	ID               int64                      `json:"id"`
	ScanID           int64                      `json:"scan_id"`
	Sequence         int                        `json:"sequence"`
	ModelFingerprint string                     `json:"model_fingerprint,omitempty"`
	Focus            []string                   `json:"focus"`
	CandidateCount   int                        `json:"candidate_count"`
	BatchSize        int                        `json:"batch_size"`
	SelectedCount    int                        `json:"selected_count"`
	CreatedAt        time.Time                  `json:"created_at"`
	GapState         []AnalysisGapState         `json:"gap_state,omitempty"`
	Movements        []AnalysisPriorityMovement `json:"movements"`
}

type AnalysisGapState struct {
	Kind    string  `json:"kind"`
	ID      string  `json:"id"`
	Label   string  `json:"label,omitempty"`
	Value   float64 `json:"value,omitempty"`
	Met     bool    `json:"met,omitempty"`
	Present bool    `json:"present"`
}

type AnalysisImpactOutcome struct {
	Kind        string  `json:"kind"`
	ID          string  `json:"id"`
	Label       string  `json:"label,omitempty"`
	Status      string  `json:"status"`
	Before      float64 `json:"before,omitempty"`
	After       float64 `json:"after,omitempty"`
	Delta       float64 `json:"delta,omitempty"`
	BatchScoped bool    `json:"batch_scoped"`
}

type AnalysisPriorityMovement struct {
	EndpointHash  string                  `json:"endpoint_hash"`
	EvidenceID    int64                   `json:"evidence_id"`
	Method        string                  `json:"method"`
	URL           string                  `json:"url"`
	Path          string                  `json:"path"`
	BaseScore     int                     `json:"base_score"`
	LearnedBoost  int                     `json:"learned_boost"`
	EvidenceGain  int                     `json:"evidence_gain"`
	AgingBoost    int                     `json:"aging_boost"`
	PriorityScore int                     `json:"priority_score"`
	QueueAge      int                     `json:"queue_age"`
	PreviousRank  int                     `json:"previous_rank"`
	CurrentRank   int                     `json:"current_rank"`
	RankDelta     int                     `json:"rank_delta"`
	Selected      bool                    `json:"selected"`
	FairnessLane  bool                    `json:"fairness_lane"`
	Disposition   string                  `json:"disposition"`
	Reasons       []string                `json:"reasons"`
	Impact        []AnalysisGapImpact     `json:"impact,omitempty"`
	OutcomeStatus string                  `json:"outcome_status,omitempty"`
	Outcomes      []AnalysisImpactOutcome `json:"outcomes,omitempty"`
}

// AnalysisEfficiencySummary is the complete, scan-wide outcome of candidates
// that reached an Analyzer checkpoint. It is intentionally calculated from
// every durable movement rather than the bounded history returned to the UI.
// A compacted candidate is a semantic call that the scanner did not need to
// make because an equivalent response-backed representative already existed.
type AnalysisEfficiencySummary struct {
	SemanticCallsSaved    int `json:"semantic_calls_saved"`
	SemanticCallsSpent    int `json:"semantic_calls_spent"`
	DeterministicClosures int `json:"deterministic_closures"`
	ProtectionSpecimens   int `json:"protection_specimens"`
	ProtectionCallsSaved  int `json:"protection_calls_saved"`
	SelectedCandidates    int `json:"selected_candidates"`
}

// GetAnalysisEfficiencySummary returns aggregate Analyzer decisions across the
// full scan. This must remain independent of ListAnalysisLearningCheckpoints:
// that method deliberately caps checkpoints and movements for presentation.
func (db *DB) GetAnalysisEfficiencySummary(scanID int64) (AnalysisEfficiencySummary, error) {
	var summary AnalysisEfficiencySummary
	err := db.conn.QueryRow(`
		SELECT
			COALESCE(SUM(CASE WHEN disposition = 'compacted' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN disposition = 'analyze' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN disposition = 'closed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN disposition = 'closed' AND reasons_json LIKE '%protection specimen retained:%' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN disposition = 'compacted' AND reasons_json LIKE '%protection interstitial%' THEN 1 ELSE 0 END), 0),
			COUNT(*)
		FROM analysis_priority_movements
		WHERE scan_id = ? AND selected = TRUE`, scanID).Scan(
		&summary.SemanticCallsSaved,
		&summary.SemanticCallsSpent,
		&summary.DeterministicClosures,
		&summary.ProtectionSpecimens,
		&summary.ProtectionCallsSaved,
		&summary.SelectedCandidates,
	)
	if err != nil {
		return AnalysisEfficiencySummary{}, fmt.Errorf("query analysis efficiency summary: %w", err)
	}
	return summary, nil
}

// GetAnalysisQueueAges returns consecutive eligible deferrals since the most
// recent selected checkpoint for each endpoint family. A re-captured family
// therefore starts fresh after an earlier analysis instead of inheriting stale
// age from a prior pass.
func (db *DB) GetAnalysisQueueAges(scanID int64) (map[string]int, error) {
	rows, err := db.conn.Query(`
		SELECT movement.endpoint_hash, COUNT(*)
		FROM analysis_priority_movements movement
		WHERE movement.scan_id = ?
		  AND movement.selected = FALSE
		  AND movement.disposition = 'analyze'
		  AND movement.id > COALESCE((
		    SELECT MAX(selected.id)
		    FROM analysis_priority_movements selected
		    WHERE selected.scan_id = movement.scan_id
		      AND selected.endpoint_hash = movement.endpoint_hash
		      AND selected.selected = TRUE
		  ), 0)
		GROUP BY movement.endpoint_hash`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query analysis queue ages: %w", err)
	}
	defer rows.Close()

	ages := make(map[string]int)
	for rows.Next() {
		var endpointHash string
		var age int
		if err := rows.Scan(&endpointHash, &age); err != nil {
			return nil, err
		}
		ages[endpointHash] = age
	}
	return ages, rows.Err()
}

// RecordAnalysisLearningCheckpoint persists the complete bounded candidate
// window and which small batch was actually chosen. Persisting all candidates
// is what makes starvation protection and rank movement auditable.
func (db *DB) RecordAnalysisLearningCheckpoint(
	scanID int64,
	modelFingerprint string,
	focus []string,
	gapState []AnalysisGapState,
	ranked []AnalysisQueueItem,
	selected []AnalysisQueueItem,
) (AnalysisLearningCheckpoint, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return AnalysisLearningCheckpoint{}, err
	}
	defer tx.Rollback()

	sequence := 1
	if err := tx.QueryRow(`
		SELECT COALESCE(MAX(sequence), 0) + 1
		FROM analysis_learning_checkpoints WHERE scan_id = ?`, scanID).Scan(&sequence); err != nil {
		return AnalysisLearningCheckpoint{}, fmt.Errorf("next analysis checkpoint sequence: %w", err)
	}

	previousRanks := make(map[string]int)
	var previousCheckpointID int64
	err = tx.QueryRow(`
		SELECT id FROM analysis_learning_checkpoints
		WHERE scan_id = ? ORDER BY sequence DESC LIMIT 1`, scanID).Scan(&previousCheckpointID)
	if err != nil && err != sql.ErrNoRows {
		return AnalysisLearningCheckpoint{}, fmt.Errorf("latest analysis checkpoint: %w", err)
	}
	if err == nil {
		rows, queryErr := tx.Query(`
			SELECT endpoint_hash, current_rank
			FROM analysis_priority_movements WHERE checkpoint_id = ?`, previousCheckpointID)
		if queryErr != nil {
			return AnalysisLearningCheckpoint{}, fmt.Errorf("previous analysis ranks: %w", queryErr)
		}
		for rows.Next() {
			var endpointHash string
			var rank int
			if scanErr := rows.Scan(&endpointHash, &rank); scanErr != nil {
				rows.Close()
				return AnalysisLearningCheckpoint{}, scanErr
			}
			previousRanks[endpointHash] = rank
		}
		if closeErr := rows.Close(); closeErr != nil {
			return AnalysisLearningCheckpoint{}, closeErr
		}
	}

	focusJSON, err := json.Marshal(focus)
	if err != nil {
		return AnalysisLearningCheckpoint{}, err
	}
	gapStateJSON, err := json.Marshal(gapState)
	if err != nil {
		return AnalysisLearningCheckpoint{}, err
	}
	selectedByHash := make(map[string]AnalysisQueueItem, len(selected))
	for _, item := range selected {
		selectedByHash[item.EndpointHash] = item
	}
	result, err := tx.Exec(`
		INSERT INTO analysis_learning_checkpoints
		(scan_id, sequence, model_fingerprint, focus_json, gap_state_json, candidate_count, batch_size, selected_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, sequence, modelFingerprint, string(focusJSON), string(gapStateJSON), len(ranked), len(selected), len(selectedByHash))
	if err != nil {
		return AnalysisLearningCheckpoint{}, fmt.Errorf("insert analysis checkpoint: %w", err)
	}
	checkpointID, err := result.LastInsertId()
	if err != nil {
		return AnalysisLearningCheckpoint{}, err
	}

	movements := make([]AnalysisPriorityMovement, 0, len(ranked))
	for index, rankedItem := range ranked {
		item := rankedItem
		selectedItem, isSelected := selectedByHash[item.EndpointHash]
		if isSelected {
			item.FairnessLane = selectedItem.FairnessLane
		}
		currentRank := index + 1
		previousRank := previousRanks[item.EndpointHash]
		rankDelta := 0
		if previousRank > 0 {
			rankDelta = previousRank - currentRank
		}
		reasonsJSON, marshalErr := json.Marshal(item.Reasons)
		if marshalErr != nil {
			return AnalysisLearningCheckpoint{}, marshalErr
		}
		impactJSON, marshalErr := json.Marshal(item.Impact)
		if marshalErr != nil {
			return AnalysisLearningCheckpoint{}, marshalErr
		}
		if _, err := tx.Exec(`
			INSERT INTO analysis_priority_movements
			(checkpoint_id, scan_id, endpoint_hash, evidence_id, method, url, path,
			 base_score, learned_boost, evidence_gain, aging_boost, priority_score, queue_age,
			 previous_rank, current_rank, rank_delta, selected, fairness_lane,
			 disposition, reasons_json, impact_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			checkpointID, scanID, item.EndpointHash, item.EvidenceID, item.Method, item.URL, item.Path,
			item.BaseScore, item.LearnedBoost, item.EvidenceGain, item.AgingBoost, item.PriorityScore, item.QueueAge,
			previousRank, currentRank, rankDelta, isSelected, item.FairnessLane,
			item.Disposition, string(reasonsJSON), string(impactJSON)); err != nil {
			return AnalysisLearningCheckpoint{}, fmt.Errorf("insert analysis priority movement: %w", err)
		}
		movements = append(movements, AnalysisPriorityMovement{
			EndpointHash: item.EndpointHash, EvidenceID: item.EvidenceID,
			Method: item.Method, URL: item.URL, Path: item.Path,
			BaseScore: item.BaseScore, LearnedBoost: item.LearnedBoost,
			EvidenceGain: item.EvidenceGain, AgingBoost: item.AgingBoost, PriorityScore: item.PriorityScore,
			QueueAge: item.QueueAge, PreviousRank: previousRank,
			CurrentRank: currentRank, RankDelta: rankDelta,
			Selected: isSelected, FairnessLane: item.FairnessLane,
			Disposition: item.Disposition, Reasons: append([]string(nil), item.Reasons...),
			Impact: append([]AnalysisGapImpact(nil), item.Impact...),
		})
	}
	if err := tx.Commit(); err != nil {
		return AnalysisLearningCheckpoint{}, err
	}
	return AnalysisLearningCheckpoint{
		ID: checkpointID, ScanID: scanID, Sequence: sequence,
		ModelFingerprint: modelFingerprint, Focus: append([]string(nil), focus...),
		GapState:       append([]AnalysisGapState(nil), gapState...),
		CandidateCount: len(ranked), BatchSize: len(selected), SelectedCount: len(selectedByHash),
		CreatedAt: time.Now().UTC(), Movements: movements,
	}, nil
}

func (db *DB) ListAnalysisLearningCheckpoints(scanID int64, checkpointLimit, movementLimit int) ([]AnalysisLearningCheckpoint, error) {
	if checkpointLimit <= 0 || checkpointLimit > 12 {
		checkpointLimit = 4
	}
	if movementLimit <= 0 || movementLimit > 24 {
		movementLimit = 6
	}
	rows, err := db.conn.Query(`
		SELECT id, sequence, model_fingerprint, focus_json, gap_state_json, candidate_count,
		       batch_size, selected_count, created_at
		FROM analysis_learning_checkpoints
		WHERE scan_id = ? ORDER BY sequence DESC LIMIT ?`, scanID, checkpointLimit)
	if err != nil {
		return nil, fmt.Errorf("list analysis checkpoints: %w", err)
	}
	defer rows.Close()

	checkpoints := make([]AnalysisLearningCheckpoint, 0, checkpointLimit)
	for rows.Next() {
		var checkpoint AnalysisLearningCheckpoint
		var focusJSON string
		var gapStateJSON string
		if err := rows.Scan(
			&checkpoint.ID, &checkpoint.Sequence, &checkpoint.ModelFingerprint, &focusJSON, &gapStateJSON,
			&checkpoint.CandidateCount, &checkpoint.BatchSize, &checkpoint.SelectedCount,
			&checkpoint.CreatedAt,
		); err != nil {
			return nil, err
		}
		checkpoint.ScanID = scanID
		_ = json.Unmarshal([]byte(focusJSON), &checkpoint.Focus)
		_ = json.Unmarshal([]byte(gapStateJSON), &checkpoint.GapState)
		if checkpoint.Focus == nil {
			checkpoint.Focus = []string{}
		}
		if checkpoint.GapState == nil {
			checkpoint.GapState = []AnalysisGapState{}
		}
		checkpoints = append(checkpoints, checkpoint)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for index := range checkpoints {
		movementRows, err := db.conn.Query(`
			SELECT endpoint_hash, evidence_id, method, url, path, base_score,
			       learned_boost, evidence_gain, aging_boost, priority_score, queue_age,
			       previous_rank, current_rank, rank_delta, selected,
			       fairness_lane, disposition, reasons_json, impact_json,
			       outcome_status, outcome_json
			FROM analysis_priority_movements
			WHERE checkpoint_id = ?
			ORDER BY selected DESC, fairness_lane DESC, ABS(rank_delta) DESC,
			         (learned_boost + aging_boost) DESC, current_rank ASC
			LIMIT ?`, checkpoints[index].ID, movementLimit)
		if err != nil {
			return nil, fmt.Errorf("list analysis movements: %w", err)
		}
		movements := make([]AnalysisPriorityMovement, 0, movementLimit)
		for movementRows.Next() {
			var movement AnalysisPriorityMovement
			var reasonsJSON string
			var impactJSON string
			var outcomeJSON string
			if err := movementRows.Scan(
				&movement.EndpointHash, &movement.EvidenceID, &movement.Method,
				&movement.URL, &movement.Path, &movement.BaseScore,
				&movement.LearnedBoost, &movement.EvidenceGain, &movement.AgingBoost, &movement.PriorityScore,
				&movement.QueueAge, &movement.PreviousRank, &movement.CurrentRank,
				&movement.RankDelta, &movement.Selected, &movement.FairnessLane,
				&movement.Disposition, &reasonsJSON, &impactJSON,
				&movement.OutcomeStatus, &outcomeJSON,
			); err != nil {
				movementRows.Close()
				return nil, err
			}
			_ = json.Unmarshal([]byte(reasonsJSON), &movement.Reasons)
			_ = json.Unmarshal([]byte(impactJSON), &movement.Impact)
			_ = json.Unmarshal([]byte(outcomeJSON), &movement.Outcomes)
			if movement.Reasons == nil {
				movement.Reasons = []string{}
			}
			if movement.Impact == nil {
				movement.Impact = []AnalysisGapImpact{}
			}
			if movement.Outcomes == nil {
				movement.Outcomes = []AnalysisImpactOutcome{}
			}
			movements = append(movements, movement)
		}
		if err := movementRows.Close(); err != nil {
			return nil, err
		}
		checkpoints[index].Movements = movements
	}
	return checkpoints, nil
}

// ResolveAnalysisPriorityMovement records what happened after a selected
// candidate reached the deterministic Analyzer guards. This closes the
// explainability gap between "selected" and "model call": equivalent route
// families can now show that a learned representative was reused instead.
func (db *DB) ResolveAnalysisPriorityMovement(scanID int64, endpointHash, disposition, reason string) error {
	endpointHash = strings.TrimSpace(endpointHash)
	disposition = strings.TrimSpace(disposition)
	reason = strings.TrimSpace(reason)
	if scanID == 0 || endpointHash == "" || disposition == "" {
		return nil
	}
	var id int64
	var reasonsJSON string
	err := db.conn.QueryRow(`
		SELECT id, reasons_json FROM analysis_priority_movements
		WHERE scan_id = ? AND endpoint_hash = ? AND selected = TRUE
		ORDER BY id DESC LIMIT 1`, scanID, endpointHash).Scan(&id, &reasonsJSON)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("resolve analysis priority movement: %w", err)
	}
	reasons := []string{}
	_ = json.Unmarshal([]byte(reasonsJSON), &reasons)
	if reason != "" {
		seen := false
		for _, existing := range reasons {
			seen = seen || existing == reason
		}
		if !seen {
			reasons = append(reasons, reason)
		}
	}
	updatedReasons, err := json.Marshal(reasons)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec(`
		UPDATE analysis_priority_movements
		SET disposition = ?, reasons_json = ? WHERE id = ?`,
		disposition, string(updatedReasons), id)
	if err != nil {
		return fmt.Errorf("update analysis priority movement: %w", err)
	}
	return nil
}
