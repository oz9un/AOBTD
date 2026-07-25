package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// AssetHash is a per-scan content snapshot of a single URL. The change
// detector stores one row per (scan_id, url) so a later scan of the same
// target can diff against this baseline.
type AssetHash struct {
	ID           int64
	ScanID       int64
	URL          string
	Host         string
	ContentHash  string
	ContentType  string
	ResponseSize int
	CapturedAt   string
}

// HashContent produces a hex SHA-256 of the content. Short-lived helper —
// kept here so both the capture side and the diff side agree on the algo.
func HashContent(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// UpsertAssetHash records/overwrites the hash for (scan_id, url). Using
// UPSERT (not INSERT OR IGNORE) so a re-run of the change detector picks
// up the latest body when traffic for the same URL appears more than once.
func (db *DB) UpsertAssetHash(scanID int64, h AssetHash) error {
	_, err := db.conn.Exec(`
		INSERT INTO asset_hashes (scan_id, url, host, content_hash, content_type, response_size)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, url) DO UPDATE SET
			content_hash  = excluded.content_hash,
			content_type  = excluded.content_type,
			response_size = excluded.response_size,
			captured_at   = datetime('now')`,
		scanID, h.URL, h.Host, h.ContentHash, h.ContentType, h.ResponseSize,
	)
	if err != nil {
		return fmt.Errorf("upsert asset_hash: %w", err)
	}
	return nil
}

// PriorAssetHash finds the most recent asset_hash row from any COMPLETED
// scan older than scanID whose scans.target matches the given target.
// Returns nil if no prior baseline exists for this URL.
func (db *DB) PriorAssetHash(target string, currentScanID int64, url string) (*AssetHash, error) {
	row := db.conn.QueryRow(`
		SELECT ah.id, ah.scan_id, ah.url, ah.host, ah.content_hash,
		       ah.content_type, ah.response_size, ah.captured_at
		FROM asset_hashes ah
		JOIN scans s ON s.id = ah.scan_id
		WHERE ah.url = ?
		  AND ah.scan_id != ?
		  AND s.target = ?
		  AND s.status IN ('completed', 'interrupted')
		ORDER BY ah.scan_id DESC
		LIMIT 1`, url, currentScanID, target)

	var a AssetHash
	if err := row.Scan(&a.ID, &a.ScanID, &a.URL, &a.Host, &a.ContentHash,
		&a.ContentType, &a.ResponseSize, &a.CapturedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

// AssetHashesForScan returns every asset hash recorded for a scan.
func (db *DB) AssetHashesForScan(scanID int64) ([]AssetHash, error) {
	rows, err := db.conn.Query(`
		SELECT id, scan_id, url, host, content_hash, content_type, response_size, captured_at
		FROM asset_hashes WHERE scan_id = ?
		ORDER BY url ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AssetHash
	for rows.Next() {
		var a AssetHash
		if err := rows.Scan(&a.ID, &a.ScanID, &a.URL, &a.Host, &a.ContentHash,
			&a.ContentType, &a.ResponseSize, &a.CapturedAt); err != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

// AssetChange is a detected diff between two scans of the same target.
type AssetChange struct {
	ID          int64  `json:"id"`
	ScanID      int64  `json:"scan_id"`
	PrevScanID  int64  `json:"prev_scan_id"`
	URL         string `json:"url"`
	Host        string `json:"host"`
	ContentType string `json:"content_type"`
	PrevHash    string `json:"prev_hash"`
	NewHash     string `json:"new_hash"`
	PrevSize    int    `json:"prev_size"`
	NewSize     int    `json:"new_size"`
	Kind        string `json:"kind"` // modified, added, removed
	DiffSnippet string `json:"diff_snippet,omitempty"`
	LLMComment  string `json:"llm_comment,omitempty"`
	Severity    string `json:"severity"`
	CreatedAt   string `json:"created_at"`
}

// InsertAssetChange records a detected diff. Upsert semantics so re-runs of
// the detector against the same scan pair don't duplicate rows.
func (db *DB) InsertAssetChange(c AssetChange) (int64, error) {
	res, err := db.conn.Exec(`
		INSERT INTO asset_changes
		  (scan_id, prev_scan_id, url, host, content_type,
		   prev_hash, new_hash, prev_size, new_size, kind,
		   diff_snippet, llm_comment, severity)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, prev_scan_id, url) DO UPDATE SET
			new_hash     = excluded.new_hash,
			new_size     = excluded.new_size,
			diff_snippet = excluded.diff_snippet,
			llm_comment  = excluded.llm_comment,
			severity     = excluded.severity`,
		c.ScanID, c.PrevScanID, c.URL, c.Host, c.ContentType,
		c.PrevHash, c.NewHash, c.PrevSize, c.NewSize, c.Kind,
		c.DiffSnippet, c.LLMComment, c.Severity,
	)
	if err != nil {
		return 0, fmt.Errorf("insert asset_change: %w", err)
	}
	return res.LastInsertId()
}

// ListAssetChanges returns the detected changes for a scan, most recent first.
func (db *DB) ListAssetChanges(scanID int64, limit int) ([]AssetChange, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.conn.Query(`
		SELECT id, scan_id, prev_scan_id, url, host, content_type,
		       prev_hash, new_hash, prev_size, new_size, kind,
		       COALESCE(diff_snippet,''), COALESCE(llm_comment,''), severity, created_at
		FROM asset_changes WHERE scan_id = ?
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
				WHEN 'low' THEN 4 ELSE 5 END,
			id DESC
		LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AssetChange
	for rows.Next() {
		var c AssetChange
		if err := rows.Scan(&c.ID, &c.ScanID, &c.PrevScanID, &c.URL, &c.Host, &c.ContentType,
			&c.PrevHash, &c.NewHash, &c.PrevSize, &c.NewSize, &c.Kind,
			&c.DiffSnippet, &c.LLMComment, &c.Severity, &c.CreatedAt); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// CountAssetChanges groups counts by severity for a scan.
func (db *DB) CountAssetChanges(scanID int64) (map[string]int, error) {
	rows, err := db.conn.Query(`
		SELECT severity, COUNT(*) FROM asset_changes WHERE scan_id = ? GROUP BY severity`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var s string
		var n int
		rows.Scan(&s, &n)
		out[s] = n
	}
	return out, nil
}

// TimelineEntry is one scan's slot on the change-detection timeline strip.
// It carries enough information for the UI to render a per-scan dot/bar
// without making N+1 follow-up requests for severity counts.
type TimelineEntry struct {
	ScanID        int64  `json:"scan_id"`
	Target        string `json:"target"`
	Status        string `json:"status"`
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`
	ChangesTotal  int    `json:"changes_total"`
	CountCritical int    `json:"count_critical"`
	CountHigh     int    `json:"count_high"`
	CountMedium   int    `json:"count_medium"`
	CountLow      int    `json:"count_low"`
	CountInfo     int    `json:"count_info"`
	IsBaseline    bool   `json:"is_baseline"` // first scan of this target — nothing to diff against
}

// TimelineForTarget returns every scan of `target` chronologically with its
// asset-change counts pre-bucketed by severity. Used by /api/changes/timeline
// to render the horizontal "you are here" strip in the Changes view.
func (db *DB) TimelineForTarget(target string) ([]TimelineEntry, error) {
	rows, err := db.conn.Query(`
		SELECT
			s.id, s.target, s.status,
			COALESCE(s.started_at, ''),
			COALESCE(s.finished_at, ''),
			COALESCE(SUM(CASE WHEN ac.severity = 'critical' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ac.severity = 'high'     THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ac.severity = 'medium'   THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ac.severity = 'low'      THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ac.severity NOT IN ('critical','high','medium','low') THEN 1 ELSE 0 END), 0),
			COALESCE(COUNT(ac.id), 0)
		FROM scans s
		LEFT JOIN asset_changes ac ON ac.scan_id = s.id
		WHERE s.target = ?
		GROUP BY s.id
		ORDER BY s.id ASC`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimelineEntry
	for rows.Next() {
		var e TimelineEntry
		if err := rows.Scan(&e.ScanID, &e.Target, &e.Status,
			&e.StartedAt, &e.FinishedAt,
			&e.CountCritical, &e.CountHigh, &e.CountMedium, &e.CountLow, &e.CountInfo,
			&e.ChangesTotal); err != nil {
			continue
		}
		out = append(out, e)
	}
	// First scan of a target has no prior to diff against — flag it so the
	// UI doesn't render its zero-count as a missing-data state.
	if len(out) > 0 {
		out[0].IsBaseline = true
	}
	return out, nil
}

// BodyForScanURL returns the response_body stored in the traffic table for
// the most recent hit on (scan_id, url). Used by the diff generator when it
// needs to compare actual content.
func (db *DB) BodyForScanURL(scanID int64, url string) ([]byte, string, error) {
	var body []byte
	var contentType string
	err := db.conn.QueryRow(`
		SELECT response_body, COALESCE(content_type,'')
		FROM traffic_resolved WHERE scan_id = ? AND url = ?
		ORDER BY id DESC LIMIT 1`, scanID, url).Scan(&body, &contentType)
	return body, contentType, err
}
