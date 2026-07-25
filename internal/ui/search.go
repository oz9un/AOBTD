package ui

import (
	"net/http"
	"strings"
)

// handleSearch powers the cmd-k command palette. Single endpoint, three
// SQL queries, results bucketed by kind (scans / endpoints / findings)
// so the frontend can group them in the modal.
//
// Cross-scan by design: the operator's value here is "I remember a
// finding from a few scans ago — find it again". Scoping search to the
// active scan would just be a worse version of the per-view tables.
//
// Match strategy: case-insensitive LIKE %q% on the most useful column
// per kind. We don't try to fuzzy-match in SQL — the result sets are
// already capped at `limit` per kind so the JS layer can re-rank if
// fancy ranking is ever wanted, but plain substring is what operators
// expect from a palette and it stays predictable.
//
// Shape:
//
//	{
//	  "q": "...",
//	  "scans":     [{"id":, "target":, "host":, "status":, "started_at":}, ...],
//	  "endpoints": [{"scan_id":, "endpoint_id":, "method":, "url":, "host":, "target":}, ...],
//	  "findings":  [{"id":, "scan_id":, "title":, "severity":, "vuln_type":, "endpoint_id":, "host":, "target":}, ...]
//	}
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		jsonResponse(w, map[string]any{
			"q":         q,
			"scans":     []any{},
			"endpoints": []any{},
			"findings":  []any{},
		})
		return
	}
	limit := intParam(r, "limit", 8)
	if limit <= 0 || limit > 50 {
		limit = 8
	}
	pat := "%" + q + "%"

	conn := s.db.Conn()

	// Scans — match on target. Most-recent first so a freshly-scanned
	// host floats to the top of "all my localhost scans".
	scans := []map[string]any{}
	if rows, err := conn.Query(`
		SELECT id, target, status, COALESCE(started_at,'')
		FROM scans
		WHERE target LIKE ? COLLATE NOCASE
		ORDER BY id DESC
		LIMIT ?`, pat, limit); err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			var target, status, startedAt string
			if err := rows.Scan(&id, &target, &status, &startedAt); err != nil {
				continue
			}
			scans = append(scans, map[string]any{
				"id":         id,
				"target":     target,
				"host":       hostOf(target),
				"status":     status,
				"started_at": startedAt,
			})
		}
	}

	// Endpoints — match on URL substring across all scans. We join scans
	// for the target so the result row can show "GET /admin · juice-shop".
	// DISTINCT keeps us from returning the same URL repeatedly when an
	// endpoint was hit on every scan; we collapse to the most recent.
	endpoints := []map[string]any{}
	if rows, err := conn.Query(`
		WITH ranked AS (
			SELECT e.scan_id, e.id, e.method, e.url_pattern, s.target,
			       ROW_NUMBER() OVER (
			           PARTITION BY e.method, e.url_pattern
			           ORDER BY e.scan_id DESC
			       ) AS recency_rank
			FROM endpoints e
			JOIN scans s ON s.id = e.scan_id
			WHERE e.url_pattern LIKE ? COLLATE NOCASE
		)
		SELECT scan_id, id, method, url_pattern, target
		FROM ranked
		WHERE recency_rank = 1
		ORDER BY scan_id DESC
		LIMIT ?`, pat, limit); err == nil {
		defer rows.Close()
		for rows.Next() {
			var scanID int64
			var endpointID, method, url, target string
			if err := rows.Scan(&scanID, &endpointID, &method, &url, &target); err != nil {
				continue
			}
			endpoints = append(endpoints, map[string]any{
				"scan_id":     scanID,
				"endpoint_id": endpointID,
				"method":      method,
				"url":         url,
				"host":        hostOf(target),
				"target":      target,
			})
		}
	}

	// Findings — match on title across all scans, confirmed first then
	// the rest so high-signal matches dominate the list.
	findings := []map[string]any{}
	if rows, err := conn.Query(`
		SELECT f.id, f.scan_id, f.title, f.severity, COALESCE(f.vuln_type,''),
		       COALESCE(f.endpoint_id,''), s.target,
		       CASE WHEN LOWER(COALESCE(f.confidence,'')) = 'confirmed' THEN 0 ELSE 1 END AS conf_rank
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		WHERE f.title LIKE ? COLLATE NOCASE
		ORDER BY conf_rank ASC, f.id DESC
		LIMIT ?`, pat, limit); err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, scanID int64
			var title, severity, vulnType, endpointID, target string
			var confRank int
			if err := rows.Scan(&id, &scanID, &title, &severity, &vulnType, &endpointID, &target, &confRank); err != nil {
				continue
			}
			findings = append(findings, map[string]any{
				"id":          id,
				"scan_id":     scanID,
				"title":       title,
				"severity":    severity,
				"vuln_type":   vulnType,
				"endpoint_id": endpointID,
				"host":        hostOf(target),
				"target":      target,
			})
		}
	}

	jsonResponse(w, map[string]any{
		"q":         q,
		"scans":     scans,
		"endpoints": endpoints,
		"findings":  findings,
	})
}
