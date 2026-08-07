package store

import "fmt"

// Discovery kinds — agents use these strings when recording edges.
const (
	DiscoverySeed          = "seed"
	DiscoveryHTMLLink      = "html-link"
	DiscoveryFormAction    = "form-action"
	DiscoveryJSRoute       = "js-route"
	DiscoveryExplorer      = "explorer"
	DiscoveryNavigator     = "navigator"
	DiscoveryRedirect      = "redirect"
	DiscoveryExternalRecon = "external-recon"
)

// Discovery is one edge in the URL discovery graph: a source URL (or an
// agent, for seed/js) led us to a target URL.
type Discovery struct {
	ID        int64  `json:"id"`
	TargetURL string `json:"target_url"`
	SourceURL string `json:"source_url,omitempty"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail,omitempty"`
	FoundAt   string `json:"found_at"`
}

// InsertDiscovery records an edge. Duplicate edges (same source/target/kind)
// are silently ignored via ON CONFLICT, so callers don't need to dedupe.
func (db *DB) InsertDiscovery(scanID int64, d Discovery) error {
	_, err := db.conn.Exec(`
		INSERT INTO url_discoveries (scan_id, target_url, source_url, kind, detail)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, target_url, source_url, kind) DO NOTHING`,
		scanID, d.TargetURL, d.SourceURL, d.Kind, d.Detail,
	)
	if err != nil {
		return fmt.Errorf("insert discovery: %w", err)
	}
	return nil
}

// GetDiscoveriesForTarget returns all discovery edges whose target_url
// matches the given URL. Used for the "how did we find this endpoint"
// provenance panel. Returns the most recent edges first, capped at `limit`.
func (db *DB) GetDiscoveriesForTarget(scanID int64, targetURL string, limit int) ([]Discovery, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := db.conn.Query(`
		SELECT id, target_url, COALESCE(source_url,''), kind, COALESCE(detail,''), found_at
		FROM url_discoveries
		WHERE scan_id = ? AND target_url = ?
		ORDER BY id DESC LIMIT ?`, scanID, targetURL, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Discovery
	for rows.Next() {
		var d Discovery
		if err := rows.Scan(&d.ID, &d.TargetURL, &d.SourceURL, &d.Kind, &d.Detail, &d.FoundAt); err != nil {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

// GetVisitedClientRoutes returns browser-visited hash routes, not every hash
// link or JavaScript string that discovery happened to see. Fragments never
// reach the HTTP server, so navigator provenance is the direct evidence that
// the client-side page was actually opened.
func (db *DB) GetVisitedClientRoutes(scanID int64, limit int) ([]Discovery, error) {
	if limit <= 0 || limit > 200 {
		limit = 80
	}
	rows, err := db.conn.Query(`
		SELECT id, target_url, COALESCE(source_url,''), kind, COALESCE(detail,''), found_at
		FROM url_discoveries
		WHERE scan_id = ? AND kind = 'navigator'
		  AND (INSTR(target_url, '#/') > 0 OR INSTR(target_url, '#!/') > 0)
		ORDER BY id ASC
		LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Discovery
	for rows.Next() {
		var d Discovery
		if err := rows.Scan(&d.ID, &d.TargetURL, &d.SourceURL, &d.Kind, &d.Detail, &d.FoundAt); err != nil {
			continue
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDiscoveriesForTargets is a batch version — returns edges for any URL
// in the set (single round-trip). Useful when an endpoint detail needs
// provenance for multiple URLs in the same family.
func (db *DB) GetDiscoveriesForTargets(scanID int64, targets []string, limit int) ([]Discovery, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	// Build ?,?,? placeholders for the IN clause
	placeholders := ""
	args := []any{scanID}
	for i, u := range targets {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args = append(args, u)
	}
	args = append(args, limit)

	q := `SELECT id, target_url, COALESCE(source_url,''), kind, COALESCE(detail,''), found_at
	      FROM url_discoveries
	      WHERE scan_id = ? AND target_url IN (` + placeholders + `)
	      ORDER BY id DESC LIMIT ?`
	rows, err := db.conn.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Discovery
	for rows.Next() {
		var d Discovery
		if err := rows.Scan(&d.ID, &d.TargetURL, &d.SourceURL, &d.Kind, &d.Detail, &d.FoundAt); err != nil {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

// CountDiscoveries returns the total number of discovery edges for a scan.
// Useful for the UI to show graph size at a glance.
func (db *DB) CountDiscoveries(scanID int64) (int, error) {
	var n int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM url_discoveries WHERE scan_id = ?`, scanID).Scan(&n)
	return n, err
}

// GraphEdges returns discovery graph rows for projection. The UI pages the
// projected response, so this read ceiling is deliberately much higher than
// a single response page; otherwise scans above 5K discoveries silently lost
// vertices before response pagination had a chance to run.
func (db *DB) GraphEdges(scanID int64, limit int) ([]Discovery, error) {
	if limit <= 0 {
		limit = 2000
	} else if limit > 100000 {
		limit = 100000
	}
	rows, err := db.conn.Query(`
		SELECT id, target_url, COALESCE(source_url,''), kind, COALESCE(detail,''), found_at
		FROM url_discoveries WHERE scan_id = ?
		ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Discovery
	for rows.Next() {
		var d Discovery
		if err := rows.Scan(&d.ID, &d.TargetURL, &d.SourceURL, &d.Kind, &d.Detail, &d.FoundAt); err != nil {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}
