package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type ReconMonitor struct {
	ID                int64          `json:"id"`
	Target            string         `json:"target"`
	Enabled           bool           `json:"enabled"`
	IntervalMinutes   int            `json:"interval_minutes"`
	IncludeSubdomains bool           `json:"include_subdomains"`
	Sources           []string       `json:"sources"`
	Options           map[string]any `json:"options"`
	LastScanID        int64          `json:"last_scan_id"`
	LastRunAt         string         `json:"last_run_at,omitempty"`
	NextRunAt         string         `json:"next_run_at"`
	LastError         string         `json:"last_error,omitempty"`
}

func (db *DB) UpsertReconMonitor(item ReconMonitor) error {
	if item.IntervalMinutes < 15 {
		item.IntervalMinutes = 15
	}
	if item.NextRunAt == "" {
		item.NextRunAt = time.Now().UTC().Add(time.Duration(item.IntervalMinutes) * time.Minute).Format(time.RFC3339)
	}
	sourcesJSON, _ := json.Marshal(item.Sources)
	optionsJSON, _ := json.Marshal(item.Options)
	_, err := db.conn.Exec(`
		INSERT INTO recon_monitors
			(target, enabled, interval_minutes, include_subdomains, sources_json, options_json, next_run_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(target) DO UPDATE SET
			enabled=excluded.enabled, interval_minutes=excluded.interval_minutes,
			include_subdomains=excluded.include_subdomains, sources_json=excluded.sources_json,
			options_json=excluded.options_json, next_run_at=excluded.next_run_at,
			updated_at=datetime('now')`,
		item.Target, item.Enabled, item.IntervalMinutes, item.IncludeSubdomains,
		string(sourcesJSON), string(optionsJSON), item.NextRunAt)
	return err
}

func (db *DB) GetReconMonitor(target string) (*ReconMonitor, error) {
	row := db.conn.QueryRow(`
		SELECT id, target, enabled, interval_minutes, include_subdomains, sources_json,
		       options_json, last_scan_id, COALESCE(last_run_at,''), next_run_at, COALESCE(last_error,'')
		FROM recon_monitors WHERE target=?`, target)
	item, err := scanReconMonitor(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return item, err
}

func (db *DB) ListDueReconMonitors(now time.Time, limit int) ([]ReconMonitor, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := db.conn.Query(`
		SELECT id, target, enabled, interval_minutes, include_subdomains, sources_json,
		       options_json, last_scan_id, COALESCE(last_run_at,''), next_run_at, COALESCE(last_error,'')
		FROM recon_monitors WHERE enabled=TRUE AND next_run_at<=? ORDER BY next_run_at LIMIT ?`,
		now.UTC().Format(time.RFC3339), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReconMonitor
	for rows.Next() {
		item, err := scanReconMonitor(rows)
		if err != nil {
			return nil, err
		}
		if item != nil {
			out = append(out, *item)
		}
	}
	return out, rows.Err()
}

type reconRowScanner interface {
	Scan(...any) error
}

func scanReconMonitor(row reconRowScanner) (*ReconMonitor, error) {
	var item ReconMonitor
	var sourcesJSON, optionsJSON string
	if err := row.Scan(&item.ID, &item.Target, &item.Enabled, &item.IntervalMinutes,
		&item.IncludeSubdomains, &sourcesJSON, &optionsJSON, &item.LastScanID,
		&item.LastRunAt, &item.NextRunAt, &item.LastError); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(sourcesJSON), &item.Sources)
	_ = json.Unmarshal([]byte(optionsJSON), &item.Options)
	return &item, nil
}

func (db *DB) FinishReconMonitorRun(id, scanID int64, runErr error, next time.Time) error {
	message := ""
	if runErr != nil {
		message = runErr.Error()
	}
	_, err := db.conn.Exec(`
		UPDATE recon_monitors SET last_scan_id=?, last_run_at=?, next_run_at=?, last_error=?, updated_at=datetime('now') WHERE id=?`,
		scanID, time.Now().UTC().Format(time.RFC3339), next.UTC().Format(time.RFC3339), message, id)
	return err
}

func (db *DB) DisableReconMonitor(target string) error {
	result, err := db.conn.Exec(`UPDATE recon_monitors SET enabled=FALSE, updated_at=datetime('now') WHERE target=?`, target)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("recon monitor not found")
	}
	return nil
}
