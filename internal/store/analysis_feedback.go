package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type AnalysisImpactCalibration struct {
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	Successes  int    `json:"successes"`
	Misses     int    `json:"misses"`
	Adjustment int    `json:"adjustment"`
}

// ResolveLatestAnalysisImpactOutcomes compares the most recent unresolved
// selected batch with the newly normalized model. Every outcome is explicitly
// batch-scoped: movement after several reads is useful feedback, but it cannot
// prove which individual response caused the change.
func (db *DB) ResolveLatestAnalysisImpactOutcomes(scanID int64, current []AnalysisGapState) (int, error) {
	if scanID == 0 {
		return 0, nil
	}
	currentByKey := analysisGapStateMap(current)
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var checkpointID int64
	var priorJSON string
	err = tx.QueryRow(`
		SELECT checkpoint.id, checkpoint.gap_state_json
		FROM analysis_learning_checkpoints checkpoint
		WHERE checkpoint.scan_id = ?
		  AND EXISTS (
		    SELECT 1 FROM analysis_priority_movements movement
		    WHERE movement.checkpoint_id = checkpoint.id
		      AND movement.selected = TRUE
		      AND movement.disposition = 'analyze'
		      AND movement.impact_json != '[]'
		      AND movement.outcome_status = ''
		  )
		ORDER BY checkpoint.sequence DESC LIMIT 1`, scanID).Scan(&checkpointID, &priorJSON)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("latest unresolved impact checkpoint: %w", err)
	}
	var prior []AnalysisGapState
	_ = json.Unmarshal([]byte(priorJSON), &prior)
	priorByKey := analysisGapStateMap(prior)

	rows, err := tx.Query(`
		SELECT id, impact_json
		FROM analysis_priority_movements
		WHERE checkpoint_id = ? AND selected = TRUE AND disposition = 'analyze'
		  AND impact_json != '[]' AND outcome_status = ''`, checkpointID)
	if err != nil {
		return 0, fmt.Errorf("query unresolved impacts: %w", err)
	}
	type pendingOutcome struct {
		id      int64
		status  string
		outcome []AnalysisImpactOutcome
	}
	updates := []pendingOutcome{}
	for rows.Next() {
		var movementID int64
		var impactJSON string
		if err := rows.Scan(&movementID, &impactJSON); err != nil {
			rows.Close()
			return 0, err
		}
		var impacts []AnalysisGapImpact
		_ = json.Unmarshal([]byte(impactJSON), &impacts)
		outcomes := make([]AnalysisImpactOutcome, 0, len(impacts))
		for _, impact := range impacts {
			key := analysisImpactKey(impact.Kind, impact.ID)
			before, hadBefore := priorByKey[key]
			if !hadBefore {
				continue
			}
			after, hasAfter := currentByKey[key]
			outcomes = append(outcomes, compareAnalysisGapOutcome(impact, before, after, hasAfter))
		}
		updates = append(updates, pendingOutcome{id: movementID, status: summarizeAnalysisOutcomes(outcomes), outcome: outcomes})
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, update := range updates {
		outcomeJSON, err := json.Marshal(update.outcome)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`
			UPDATE analysis_priority_movements
			SET outcome_status = ?, outcome_json = ? WHERE id = ?`,
			update.status, string(outcomeJSON), update.id); err != nil {
			return 0, fmt.Errorf("resolve analysis impact outcome: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(updates), nil
}

func compareAnalysisGapOutcome(impact AnalysisGapImpact, before, after AnalysisGapState, hasAfter bool) AnalysisImpactOutcome {
	outcome := AnalysisImpactOutcome{
		Kind: impact.Kind, ID: impact.ID, Label: impact.Label,
		Before: before.Value, BatchScoped: true,
	}
	if impact.Kind == "unknown" {
		if !hasAfter || !after.Present {
			outcome.Status = "resolved"
		} else {
			outcome.Status = "unchanged"
		}
		return outcome
	}
	if !hasAfter {
		outcome.Status = "unmeasured"
		return outcome
	}
	outcome.After = after.Value
	outcome.Delta = after.Value - before.Value
	switch {
	case after.Met && !before.Met:
		outcome.Status = "resolved"
	case outcome.Delta > .005:
		outcome.Status = "improved"
	case outcome.Delta < -.005:
		outcome.Status = "regressed"
	default:
		outcome.Status = "unchanged"
	}
	return outcome
}

func summarizeAnalysisOutcomes(outcomes []AnalysisImpactOutcome) string {
	best := ""
	for _, outcome := range outcomes {
		switch outcome.Status {
		case "resolved":
			return "resolved"
		case "improved":
			best = "improved"
		case "regressed":
			if best == "" || best == "unchanged" || best == "unmeasured" {
				best = "regressed"
			}
		case "unchanged":
			if best == "" || best == "unmeasured" {
				best = "unchanged"
			}
		case "unmeasured":
			if best == "" {
				best = "unmeasured"
			}
		}
	}
	return best
}

func analysisGapStateMap(states []AnalysisGapState) map[string]AnalysisGapState {
	out := make(map[string]AnalysisGapState, len(states))
	for _, state := range states {
		if key := analysisImpactKey(state.Kind, state.ID); key != ":" {
			out[key] = state
		}
	}
	return out
}

func analysisImpactKey(kind, id string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + ":" + strings.TrimSpace(id)
}

// ListAnalysisImpactCalibration returns conservative scan-local adjustments.
// A single unchanged batch never penalizes a signal; at least two independent
// checkpoint outcomes are required, and adjustments remain much smaller than
// the base target-impact scores.
func (db *DB) ListAnalysisImpactCalibration(scanID int64) ([]AnalysisImpactCalibration, error) {
	rows, err := db.conn.Query(`
		SELECT checkpoint_id, outcome_json
		FROM analysis_priority_movements
		WHERE scan_id = ? AND selected = TRUE AND disposition = 'analyze'
		  AND outcome_status != '' AND outcome_json != '[]'
		ORDER BY checkpoint_id, id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query analysis impact calibration: %w", err)
	}
	defer rows.Close()
	type tally struct {
		kind, id          string
		successes, misses int
	}
	tallies := map[string]*tally{}
	seenCheckpointGap := map[string]bool{}
	for rows.Next() {
		var checkpointID int64
		var outcomeJSON string
		if err := rows.Scan(&checkpointID, &outcomeJSON); err != nil {
			return nil, err
		}
		var outcomes []AnalysisImpactOutcome
		_ = json.Unmarshal([]byte(outcomeJSON), &outcomes)
		for _, outcome := range outcomes {
			key := analysisImpactKey(outcome.Kind, outcome.ID)
			dedupe := fmt.Sprintf("%d:%s", checkpointID, key)
			if seenCheckpointGap[dedupe] {
				continue
			}
			seenCheckpointGap[dedupe] = true
			if outcome.Status != "resolved" && outcome.Status != "improved" && outcome.Status != "unchanged" && outcome.Status != "regressed" {
				continue
			}
			if tallies[key] == nil {
				tallies[key] = &tally{kind: outcome.Kind, id: outcome.ID}
			}
			if outcome.Status == "resolved" || outcome.Status == "improved" {
				tallies[key].successes++
			} else {
				tallies[key].misses++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]AnalysisImpactCalibration, 0, len(tallies))
	for _, value := range tallies {
		adjustment := 0
		if value.successes+value.misses >= 2 {
			adjustment = value.successes*3 - value.misses*4
			if adjustment > 6 {
				adjustment = 6
			}
			if adjustment < -12 {
				adjustment = -12
			}
		}
		out = append(out, AnalysisImpactCalibration{
			Kind: value.kind, ID: value.id, Successes: value.successes,
			Misses: value.misses, Adjustment: adjustment,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
