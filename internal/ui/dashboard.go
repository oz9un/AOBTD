package ui

import (
	"database/sql"
	"net/http"
	"strings"
)

// handleDashboard returns the aggregated view of everything the tool
// has done across all scans, plus a recent-scans strip. Powers the Home
// landing page. Single DB round trip per metric, all SQL aggregates —
// no per-scan N+1 queries, so it stays cheap even with hundreds of
// historical scans.
//
// Shape:
//   {
//     "totals": {
//       "scans":              int,
//       "findings_total":     int,
//       "findings_confirmed": int,
//       "endpoints_analyzed": int,
//       "tokens_input":       int,
//       "tokens_output":      int,
//       "cost_usd":           float
//     },
//     "recent_scans": [
//       {
//         "id": 1, "target": "...", "status": "...",
//         "started_at": "...", "finished_at": "...",
//         "findings_total": N, "findings_confirmed": N, "findings_critical": N,
//         "findings_high": N, "endpoints": N, "profiles": N,
//         "cost_usd": float
//       }, ...
//     ],
//     "drifting_targets": [
//       {
//         "target": "...", "host": "...", "scan_id": int,
//         "started_at": "...", "change_count": N, "crit_high": N
//       }, ...
//     ]
//   }
//
// drifting_targets surfaces the "set and forget" story on Home: any target
// whose most-recent scan picked up content drift relative to its baseline.
// Sorted crit/high first, then total volume; capped at 5.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	limit := intParam(r, "limit", 12)
	if limit <= 0 || limit > 100 {
		limit = 12
	}

	totals := map[string]any{}

	// Total scans
	var totalScans int
	s.db.Conn().QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&totalScans)
	totals["scans"] = totalScans

	// Findings aggregates
	var totalFindings, confirmed int
	s.db.Conn().QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&totalFindings)
	s.db.Conn().QueryRow(`SELECT COUNT(*) FROM findings WHERE confidence='confirmed'`).Scan(&confirmed)
	totals["findings_total"] = totalFindings
	totals["findings_confirmed"] = confirmed

	// Endpoints analyzed (distinct endpoint_hashes that made it into page_profiles)
	var endpointsAnalyzed int
	s.db.Conn().QueryRow(`SELECT COUNT(*) FROM page_profiles`).Scan(&endpointsAnalyzed)
	totals["endpoints_analyzed"] = endpointsAnalyzed

	// LLM usage
	var tokIn, tokOut int
	var costUcents sql.NullInt64
	s.db.Conn().QueryRow(
		`SELECT COALESCE(SUM(tokens_in),0), COALESCE(SUM(tokens_out),0), COALESCE(SUM(cost_ucents),0) FROM ai_log`,
	).Scan(&tokIn, &tokOut, &costUcents)
	totals["tokens_input"] = tokIn
	totals["tokens_output"] = tokOut
	// cost_ucents is micro-cents; 1,000,000 µ¢ = $1
	totals["cost_usd"] = float64(costUcents.Int64) / 1_000_000.0

	// Recent scans — one query with LEFT JOINs so we still get rows for
	// scans that haven't produced findings / profiles / ai_log entries yet.
	recentRows, err := s.db.Conn().Query(`
		SELECT
			s.id, s.target, s.status,
			s.started_at, COALESCE(s.finished_at,''),
			(SELECT COUNT(*) FROM findings WHERE scan_id = s.id)                                   AS findings_total,
			(SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND confidence='confirmed')        AS findings_confirmed,
			(SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity='critical')          AS findings_critical,
			(SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity='high')              AS findings_high,
			(SELECT COUNT(*) FROM page_profiles WHERE scan_id = s.id)                             AS profiles_count,
			(SELECT COUNT(DISTINCT endpoint_hash) FROM traffic WHERE scan_id = s.id AND is_filtered=0) AS endpoints_count,
			(SELECT COALESCE(SUM(cost_ucents),0) FROM ai_log WHERE scan_id = s.id)                AS scan_cost_ucents
		FROM scans s
		ORDER BY s.id DESC
		LIMIT ?`, limit)
	if err != nil {
		jsonError(w, "load recent scans: "+err.Error(), 500)
		return
	}
	defer recentRows.Close()

	var recent []map[string]any
	for recentRows.Next() {
		var id int64
		var target, status, startedAt, finishedAt string
		var findTotal, findConfirmed, findCrit, findHigh int
		var profiles, endpoints int
		var scanCostU int64
		err := recentRows.Scan(&id, &target, &status, &startedAt, &finishedAt,
			&findTotal, &findConfirmed, &findCrit, &findHigh,
			&profiles, &endpoints, &scanCostU)
		if err != nil {
			continue
		}
		recent = append(recent, map[string]any{
			"id":                 id,
			"target":             target,
			"status":             status,
			"started_at":         startedAt,
			"finished_at":        finishedAt,
			"findings_total":     findTotal,
			"findings_confirmed": findConfirmed,
			"findings_critical":  findCrit,
			"findings_high":      findHigh,
			"profiles":           profiles,
			"endpoints":          endpoints,
			"cost_usd":           float64(scanCostU) / 1_000_000.0,
			// Derived host + path for display — lets the UI skip parsing.
			"host": hostOf(target),
		})
	}
	if recent == nil {
		recent = []map[string]any{}
	}

	// Drifting targets — for each distinct target, look at its latest scan
	// and surface those whose asset-changes count > 0. This is the Home-page
	// answer to "where should I look first when I come back to this tool
	// after a few days". CTE picks the latest scan per target; the outer
	// query buckets that scan's changes by severity. crit_high orders the
	// list so high-impact drift floats to the top.
	driftRows, err := s.db.Conn().Query(`
		WITH latest AS (
			SELECT target, MAX(id) AS scan_id FROM scans GROUP BY target
		)
		SELECT
			s.target,
			s.id,
			COALESCE(s.started_at, ''),
			COUNT(ac.id)                                                       AS change_count,
			SUM(CASE WHEN ac.severity IN ('critical','high') THEN 1 ELSE 0 END) AS crit_high
		FROM scans s
		JOIN latest l ON s.id = l.scan_id
		LEFT JOIN asset_changes ac ON ac.scan_id = s.id
		GROUP BY s.id
		HAVING change_count > 0
		ORDER BY crit_high DESC, change_count DESC
		LIMIT 5`)
	var drifting []map[string]any
	if err == nil {
		defer driftRows.Close()
		for driftRows.Next() {
			var (
				target, startedAt    string
				scanID               int64
				changeCount, critHi  int
				critHiNullable       sql.NullInt64
			)
			// crit_high comes through as NULLable when SUM has no rows even
			// though HAVING filters them out; defensive scan keeps it safe.
			if err := driftRows.Scan(&target, &scanID, &startedAt, &changeCount, &critHiNullable); err != nil {
				continue
			}
			critHi = int(critHiNullable.Int64)
			drifting = append(drifting, map[string]any{
				"target":       target,
				"host":         hostOf(target),
				"scan_id":      scanID,
				"started_at":   startedAt,
				"change_count": changeCount,
				"crit_high":    critHi,
			})
		}
	}
	if drifting == nil {
		drifting = []map[string]any{}
	}

	jsonResponse(w, map[string]any{
		"totals":           totals,
		"recent_scans":     recent,
		"drifting_targets": drifting,
	})
}

// hostOf returns the scheme+host portion of a URL for display tags in
// the dashboard. Falls back to the raw target if parsing fails.
func hostOf(rawURL string) string {
	// Cheap parse — we just want "http://host" out of "http://host/path?q=1".
	after := rawURL
	if i := strings.Index(after, "://"); i >= 0 {
		after = after[i+3:]
	}
	if i := strings.IndexAny(after, "/?#"); i >= 0 {
		after = after[:i]
	}
	return after
}
