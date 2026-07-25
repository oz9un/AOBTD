package store

import (
	"encoding/json"
	"fmt"
)

// Narration is a single agent "thought" — a human-readable line explaining
// what the agent is doing and why. Used to drive the live/replay UI.
type Narration struct {
	ID        int64          `json:"id"`
	Agent     string         `json:"agent"`
	Action    string         `json:"action"`
	Message   string         `json:"message"`
	URL       string         `json:"url,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt string         `json:"created_at"`
}

// InsertNarration writes a narration row. Metadata is optional — pass nil to skip.
func (db *DB) InsertNarration(scanID int64, agent, action, message, url string, metadata map[string]any) (int64, error) {
	metaJSON := "{}"
	if metadata != nil {
		b, err := json.Marshal(metadata)
		if err == nil {
			metaJSON = string(b)
		}
	}

	res, err := db.conn.Exec(`
		INSERT INTO narrations (scan_id, agent, action, message, url, metadata_json)
		VALUES (?, ?, ?, ?, ?, ?)`,
		scanID, agent, action, message, url, metaJSON,
	)
	if err != nil {
		return 0, fmt.Errorf("insert narration: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// GetNarrations returns narrations for a scan, optionally only those with id > sinceID.
// Pass sinceID=0 to get all. Results ordered by id ASC (chronological).
func (db *DB) GetNarrations(scanID, sinceID int64, limit int) ([]Narration, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}

	rows, err := db.conn.Query(`
		SELECT id, agent, action, message, url, metadata_json, created_at
		FROM narrations
		WHERE scan_id = ? AND id > ?
		ORDER BY id ASC
		LIMIT ?`, scanID, sinceID, limit)
	if err != nil {
		return nil, fmt.Errorf("query narrations: %w", err)
	}
	defer rows.Close()

	var out []Narration
	for rows.Next() {
		var n Narration
		var metaJSON string
		if err := rows.Scan(&n.ID, &n.Agent, &n.Action, &n.Message, &n.URL, &metaJSON, &n.CreatedAt); err != nil {
			continue
		}
		if metaJSON != "" && metaJSON != "{}" {
			var m map[string]any
			if json.Unmarshal([]byte(metaJSON), &m) == nil {
				n.Metadata = m
			}
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// GetRecentNarrations returns the newest narration rows for a scan while
// preserving chronological order in the returned slice. Recon summaries use
// this instead of fetching the beginning of a long live-event stream and then
// discarding most of it in the browser.
func (db *DB) GetRecentNarrations(scanID int64, limit int) ([]Narration, error) {
	if limit <= 0 || limit > 5000 {
		limit = 100
	}

	rows, err := db.conn.Query(`
		SELECT id, agent, action, message, url, metadata_json, created_at
		FROM narrations
		WHERE scan_id = ?
		ORDER BY id DESC
		LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, fmt.Errorf("query recent narrations: %w", err)
	}
	defer rows.Close()

	out := make([]Narration, 0, limit)
	for rows.Next() {
		var n Narration
		var metaJSON string
		if err := rows.Scan(&n.ID, &n.Agent, &n.Action, &n.Message, &n.URL, &metaJSON, &n.CreatedAt); err != nil {
			continue
		}
		if metaJSON != "" && metaJSON != "{}" {
			var m map[string]any
			if json.Unmarshal([]byte(metaJSON), &m) == nil {
				n.Metadata = m
			}
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for left, right := 0, len(out)-1; left < right; left, right = left+1, right-1 {
		out[left], out[right] = out[right], out[left]
	}
	return out, nil
}

// LatestNarrationID returns the highest narration id for a scan, or 0 if none.
// Useful for an SSE client to catch up from a known point.
func (db *DB) LatestNarrationID(scanID int64) (int64, error) {
	var id int64
	err := db.conn.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM narrations WHERE scan_id = ?`, scanID).Scan(&id)
	return id, err
}

// CountNarrations returns how many narrations exist for a scan.
func (db *DB) CountNarrations(scanID int64) (int, error) {
	var n int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM narrations WHERE scan_id = ?`, scanID).Scan(&n)
	return n, err
}

// UpdateNarrationMessage rewrites a previously-inserted narration's
// message + metadata in place. Used by the path-label resolver's
// async upgrade path: an immediate "saturated /WORD/WORD" line goes
// in first so the operator sees something instantly, then a few
// hundred milliseconds later the LLM-labelled version replaces the
// message — same row id, no second narration to dedupe.
//
// metadata may be nil to leave the metadata_json column untouched.
// Pass an empty map to clear it. Errors are returned but callers
// typically log-and-continue: the UI is best-effort.
func (db *DB) UpdateNarrationMessage(id int64, message string, metadata map[string]any) error {
	if metadata == nil {
		_, err := db.conn.Exec(
			`UPDATE narrations SET message = ? WHERE id = ?`,
			message, id,
		)
		if err != nil {
			return fmt.Errorf("update narration message: %w", err)
		}
		return nil
	}
	metaJSON := "{}"
	if b, err := json.Marshal(metadata); err == nil {
		metaJSON = string(b)
	}
	_, err := db.conn.Exec(
		`UPDATE narrations SET message = ?, metadata_json = ? WHERE id = ?`,
		message, metaJSON, id,
	)
	if err != nil {
		return fmt.Errorf("update narration message+metadata: %w", err)
	}
	return nil
}
