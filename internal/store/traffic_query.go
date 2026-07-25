package store

import "fmt"

// HostPathSet is a per-host bag of distinct paths captured for a scan.
// Used by the path-label vocabulary primer to learn site conventions
// once enough URLs have been observed.
type HostPathSet struct {
	Host  string
	Paths []string
}

// DistinctPathsByHost returns up to perHostLimit distinct URL paths
// per host for the given scan, sorted by host then path. Filtered
// traffic (out-of-scope, dedup duplicates) is excluded — those don't
// represent the target site's actual conventions.
//
// Used by the orchestrator's vocabulary primer: as soon as a host has
// crossed the priming threshold (~20 distinct paths), one richer LLM
// call learns the site's URL grammar and seeds the resolver's
// vocabulary cache for that host.
func (db *DB) DistinctPathsByHost(scanID int64, perHostLimit int) ([]HostPathSet, error) {
	if perHostLimit <= 0 || perHostLimit > 1000 {
		perHostLimit = 100
	}
	// We pull host + path together and group in Go because the
	// DISTINCT path here means "distinct (host, path)" — the SQL
	// is straightforward and the result set is small.
	rows, err := db.conn.Query(`
		SELECT DISTINCT host, path
		FROM traffic
		WHERE scan_id = ?
		  AND is_filtered = FALSE
		  AND host != ''
		  AND path != ''
		ORDER BY host, path`, scanID)
	if err != nil {
		return nil, fmt.Errorf("distinct paths query: %w", err)
	}
	defer rows.Close()

	bucket := map[string][]string{}
	for rows.Next() {
		var host, path string
		if err := rows.Scan(&host, &path); err != nil {
			continue
		}
		if len(bucket[host]) >= perHostLimit {
			continue
		}
		bucket[host] = append(bucket[host], path)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("distinct paths iter: %w", err)
	}

	// Stable order keeps the priming prompt cache-friendly: the same
	// path set should produce the same prompt across runs.
	out := make([]HostPathSet, 0, len(bucket))
	for host, paths := range bucket {
		out = append(out, HostPathSet{Host: host, Paths: paths})
	}
	// Manual sort (no sort import here) — tiny n.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Host > out[j].Host; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out, nil
}
