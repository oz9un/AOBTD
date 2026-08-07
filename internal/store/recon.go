package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// ReconObservation is one provenance-preserving external recon result.
type ReconObservation struct {
	ID         int64          `json:"id"`
	RunID      int64          `json:"run_id"`
	Target     string         `json:"target"`
	AssetType  string         `json:"asset_type"`
	Value      string         `json:"value"`
	Source     string         `json:"source"`
	State      string         `json:"state"`
	Confidence float64        `json:"confidence"`
	ObservedAt string         `json:"observed_at,omitempty"`
	InScope    bool           `json:"in_scope"`
	Evidence   map[string]any `json:"evidence"`
	CreatedAt  string         `json:"created_at,omitempty"`
}

type ReconRun struct {
	ID         int64            `json:"id"`
	ScanID     int64            `json:"scan_id"`
	Engine     string           `json:"engine"`
	Sources    []string         `json:"sources"`
	Options    map[string]any   `json:"options"`
	Status     string           `json:"status"`
	Errors     []map[string]any `json:"errors"`
	StartedAt  string           `json:"started_at"`
	FinishedAt string           `json:"finished_at,omitempty"`
}

func (db *DB) StartReconRun(scanID int64, engine string, sources []string, options map[string]any) (int64, error) {
	sourcesJSON, _ := json.Marshal(sources)
	optionsJSON, _ := json.Marshal(options)
	result, err := db.conn.Exec(`
		INSERT INTO recon_runs (scan_id, engine, sources_json, options_json)
		VALUES (?, ?, ?, ?)`, scanID, engine, string(sourcesJSON), string(optionsJSON))
	if err != nil {
		return 0, fmt.Errorf("start recon run: %w", err)
	}
	return result.LastInsertId()
}

func (db *DB) FinishReconRun(runID int64, status string, errors any) error {
	errorsJSON, _ := json.Marshal(errors)
	_, err := db.conn.Exec(`
		UPDATE recon_runs SET status=?, errors_json=?, finished_at=datetime('now') WHERE id=?`,
		status, string(errorsJSON), runID)
	return err
}

func (db *DB) UpsertReconObservation(scanID, runID int64, item ReconObservation) error {
	evidenceJSON, _ := json.Marshal(item.Evidence)
	_, err := db.conn.Exec(`
		INSERT INTO recon_observations
			(scan_id, run_id, target, asset_type, value, source, state, confidence, observed_at, in_scope, evidence_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, source, asset_type, value) DO UPDATE SET
			run_id=excluded.run_id,
			state=CASE
				WHEN recon_observations.state='confirmed' THEN recon_observations.state
				WHEN excluded.state='confirmed' THEN excluded.state
				ELSE excluded.state END,
			confidence=MAX(recon_observations.confidence, excluded.confidence),
			observed_at=COALESCE(NULLIF(excluded.observed_at,''), recon_observations.observed_at),
			in_scope=excluded.in_scope,
			evidence_json=excluded.evidence_json`,
		scanID, runID, item.Target, item.AssetType, item.Value, item.Source, item.State,
		item.Confidence, item.ObservedAt, item.InScope, string(evidenceJSON))
	if err != nil {
		return fmt.Errorf("upsert recon observation: %w", err)
	}
	return nil
}

func (db *DB) ListReconObservations(scanID int64, limit int) ([]ReconObservation, error) {
	if limit <= 0 || limit > 10000 {
		limit = 2000
	}
	rows, err := db.conn.Query(`
		SELECT id, run_id, target, asset_type, value, source, state, confidence,
		       COALESCE(observed_at,''), in_scope, evidence_json, created_at
		FROM recon_observations WHERE scan_id=?
		ORDER BY CASE state WHEN 'confirmed' THEN 0 WHEN 'candidate' THEN 1 ELSE 2 END,
		         source, value LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReconObservation
	for rows.Next() {
		var item ReconObservation
		var evidenceJSON string
		if err := rows.Scan(&item.ID, &item.RunID, &item.Target, &item.AssetType, &item.Value,
			&item.Source, &item.State, &item.Confidence, &item.ObservedAt, &item.InScope,
			&evidenceJSON, &item.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(evidenceJSON), &item.Evidence)
		if item.Evidence == nil {
			item.Evidence = map[string]any{}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (db *DB) LatestReconRun(scanID int64) (*ReconRun, error) {
	var run ReconRun
	var sourcesJSON, optionsJSON, errorsJSON string
	err := db.conn.QueryRow(`
		SELECT id, scan_id, engine, sources_json, options_json, status, errors_json,
		       started_at, COALESCE(finished_at,'')
		FROM recon_runs WHERE scan_id=? ORDER BY id DESC LIMIT 1`, scanID).Scan(
		&run.ID, &run.ScanID, &run.Engine, &sourcesJSON, &optionsJSON, &run.Status,
		&errorsJSON, &run.StartedAt, &run.FinishedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(sourcesJSON), &run.Sources)
	_ = json.Unmarshal([]byte(optionsJSON), &run.Options)
	_ = json.Unmarshal([]byte(errorsJSON), &run.Errors)
	return &run, nil
}
