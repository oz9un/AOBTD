package store

import (
	"database/sql"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/observation"
)

// ResolveEndpointHashes resolves any endpoint-reference shape currently
// emitted by AOBTD to the scan-local, origin-aware traffic hashes it denotes.
// Supported references are:
//   - a current v2 endpoint hash
//   - a pre-v2 legacy hash (via endpoint_identity_aliases)
//   - a page-profile ID such as "GET /orders/{id}"
//   - a persisted endpoints.id
//
// This is deliberately scan-scoped. A profile ID is only meaningful together
// with its scan, and resolving it globally could re-open another scan's
// traffic for analysis.
func (db *DB) ResolveEndpointHashes(scanID int64, endpointRef string) ([]string, error) {
	endpointRef = strings.TrimSpace(endpointRef)
	if endpointRef == "" {
		return nil, nil
	}

	resolved := make(map[string]struct{})
	addRows := func(rows *sql.Rows) error {
		defer rows.Close()
		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				return err
			}
			if hash = strings.TrimSpace(hash); hash != "" {
				resolved[hash] = struct{}{}
			}
		}
		return rows.Err()
	}

	rows, err := db.conn.Query(`
		SELECT DISTINCT endpoint_hash FROM traffic
		WHERE scan_id = ? AND endpoint_hash = ?`, scanID, endpointRef)
	if err != nil {
		return nil, err
	}
	if err := addRows(rows); err != nil {
		return nil, err
	}

	rows, err = db.conn.Query(`
		SELECT endpoint_hash FROM endpoint_identity_aliases
		WHERE scan_id = ? AND legacy_hash = ?`, scanID, endpointRef)
	if err != nil {
		return nil, err
	}
	if err := addRows(rows); err != nil {
		return nil, err
	}
	if len(resolved) > 0 {
		return sortedHashes(resolved), nil
	}

	// A profile stores a concrete sample URL alongside its display ID. That
	// sample is the strongest bridge from "GET /orders/{id}" to an
	// origin-aware traffic group, so prefer it over broad pattern matching.
	var profileMethod, profileURL string
	err = db.conn.QueryRow(`
		SELECT COALESCE(method,''), COALESCE(url,'')
		FROM page_profiles WHERE scan_id = ? AND id = ?`,
		scanID, endpointRef).Scan(&profileMethod, &profileURL)
	if err == nil && strings.TrimSpace(profileURL) != "" {
		if strings.TrimSpace(profileMethod) == "" {
			profileMethod, _ = splitEndpointReference(endpointRef)
		}
		rows, err = db.conn.Query(`
			SELECT DISTINCT endpoint_hash FROM traffic
			WHERE scan_id = ? AND upper(method) = upper(?) AND url = ?`,
			scanID, profileMethod, profileURL)
		if err != nil {
			return nil, err
		}
		if err := addRows(rows); err != nil {
			return nil, err
		}
		if len(resolved) > 0 {
			return sortedHashes(resolved), nil
		}
	} else if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// endpoints rows produced by the crawler contain an absolute URL pattern;
	// JS rows may contain a path. Either can still be matched against traffic.
	var endpointMethod, endpointPattern string
	err = db.conn.QueryRow(`
		SELECT method, url_pattern FROM endpoints
		WHERE scan_id = ? AND id = ?`, scanID, endpointRef).Scan(&endpointMethod, &endpointPattern)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if err == sql.ErrNoRows {
		endpointMethod, endpointPattern = splitEndpointReference(endpointRef)
	}
	if endpointMethod == "" || endpointPattern == "" {
		return nil, nil
	}

	matcher, origin, err := compileEndpointPattern(endpointPattern)
	if err != nil {
		return nil, fmt.Errorf("resolve endpoint reference %q: %w", endpointRef, err)
	}
	rows, err = db.conn.Query(`
		SELECT url, path, endpoint_hash FROM traffic
		WHERE scan_id = ? AND upper(method) = upper(?) AND endpoint_hash != ''`,
		scanID, endpointMethod)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var rawURL, path, hash string
		if err := rows.Scan(&rawURL, &path, &hash); err != nil {
			return nil, err
		}
		if origin != "" {
			if observation.CanonicalOrigin(rawURL) != origin {
				continue
			}
		}
		if matcher.MatchString(path) {
			resolved[hash] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sortedHashes(resolved), nil
}

func splitEndpointReference(endpointRef string) (method, pattern string) {
	parts := strings.SplitN(strings.TrimSpace(endpointRef), " ", 2)
	if len(parts) != 2 {
		// JS analyzer's historical ID shape was METHOD|/path.
		parts = strings.SplitN(strings.TrimSpace(endpointRef), "|", 2)
	}
	if len(parts) != 2 {
		return "", ""
	}
	return strings.ToUpper(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
}

var endpointPlaceholderRE = regexp.MustCompile(`\\\{[^/{}]+\\\}`)

func compileEndpointPattern(rawPattern string) (*regexp.Regexp, string, error) {
	pattern := strings.TrimSpace(rawPattern)
	origin := ""
	if parsed, err := url.Parse(pattern); err == nil && parsed.Host != "" {
		origin = observation.CanonicalOrigin(pattern)
		pattern = parsed.Path
	}
	if pattern == "" {
		pattern = "/"
	}
	quoted := regexp.QuoteMeta(pattern)
	quoted = endpointPlaceholderRE.ReplaceAllString(quoted, `[^/]+`)
	// Also accept Express/React style :id segments from JS route discovery.
	quoted = regexp.MustCompile(`:[A-Za-z_][A-Za-z0-9_]*`).ReplaceAllString(quoted, `[^/]+`)
	matcher, err := regexp.Compile(`^` + quoted + `$`)
	return matcher, origin, err
}

func sortedHashes(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
