package store

import (
	"encoding/json"
	"net/url"
	"strings"
)

// RecordCredentialHeaders stores operator-provided or login-derived
// credential headers for conservative same-origin replay. These are not
// traffic observations; they are scoped auth context hints used by Explorer
// and Verifier when the browser did not naturally emit a credential-bearing
// request before a probe needs one.
func (db *DB) RecordCredentialHeaders(scanID int64, rawURL string, headers map[string]string, source string) error {
	targetHost := normalizedURLHost(rawURL)
	if targetHost == "" {
		return nil
	}
	creds := CredentialHeaders(headers)
	if len(creds) == 0 {
		return nil
	}
	parsed, _ := url.Parse(rawURL)
	path := ""
	if parsed != nil {
		path = parsed.Path
	}
	headersJSON, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec(`
		INSERT INTO credential_contexts(scan_id, origin_host, url, path, headers_json, source)
		VALUES (?, ?, ?, ?, ?, ?)`,
		scanID, targetHost, rawURL, path, string(headersJSON), strings.TrimSpace(source))
	return err
}

// BestCredentialHeaders returns the strongest credential-bearing request
// headers observed for the same origin as rawURL. It is intentionally
// conservative: credentials are only replayed to the exact same host, and only
// auth/session-shaped headers are returned.
func (db *DB) BestCredentialHeaders(scanID int64, rawURL string) (map[string]string, string, error) {
	targetHost := normalizedURLHost(rawURL)
	if targetHost == "" {
		return nil, "", nil
	}
	targetFamily := pathFamilyFromURL(rawURL)
	if headers, source, err := db.bestCredentialHeaderContext(scanID, targetHost, targetFamily); err != nil {
		return nil, "", err
	} else if len(headers) > 0 {
		return headers, source, nil
	}
	rows, err := db.conn.Query(`
		SELECT id, url, host, path, request_headers, status_code, content_type
		FROM traffic_resolved
		WHERE scan_id = ?
		  AND is_filtered = FALSE
		  AND request_headers != ''
		  AND (
			request_headers LIKE '%Authorization%'
			OR request_headers LIKE '%authorization%'
			OR request_headers LIKE '%Cookie%'
			OR request_headers LIKE '%cookie%'
			OR request_headers LIKE '%X-Auth-Token%'
			OR request_headers LIKE '%X-Access-Token%'
			OR request_headers LIKE '%X-API-Key%'
			OR request_headers LIKE '%X-CSRF%'
			OR request_headers LIKE '%X-XSRF%'
		  )
		ORDER BY id DESC
		LIMIT 500`, scanID)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	bestScore := 0
	bestSource := ""
	var best map[string]string
	for rows.Next() {
		var (
			id          int64
			seenURL     string
			host        string
			path        string
			headersJSON string
			status      int
			contentType string
		)
		if err := rows.Scan(&id, &seenURL, &host, &path, &headersJSON, &status, &contentType); err != nil {
			continue
		}
		seenHost := normalizedHost(host)
		if seenHost == "" {
			seenHost = normalizedURLHost(seenURL)
		}
		if seenHost != targetHost {
			continue
		}
		var headers map[string]string
		if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
			continue
		}
		creds := CredentialHeaders(headers)
		if len(creds) == 0 {
			continue
		}
		score := credentialHeaderScore(creds)
		if status >= 200 && status < 400 {
			score += 30
		}
		if strings.Contains(strings.ToLower(contentType), "json") {
			score += 15
		}
		if targetFamily != "" && targetFamily == pathFamily(path) {
			score += 25
		}
		// Rows are already newest-first; keep the first winner on ties.
		if score > bestScore {
			bestScore = score
			best = creds
			bestSource = seenURL
		}
		_ = id
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return best, bestSource, nil
}

func (db *DB) bestCredentialHeaderContext(scanID int64, targetHost, targetFamily string) (map[string]string, string, error) {
	rows, err := db.conn.Query(`
		SELECT url, path, headers_json, source
		FROM credential_contexts
		WHERE scan_id = ? AND origin_host = ?
		ORDER BY id DESC
		LIMIT 100`, scanID, targetHost)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	bestScore := 0
	bestSource := ""
	var best map[string]string
	for rows.Next() {
		var rawURL, path, headersJSON, source string
		if err := rows.Scan(&rawURL, &path, &headersJSON, &source); err != nil {
			continue
		}
		var headers map[string]string
		if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
			continue
		}
		creds := CredentialHeaders(headers)
		if len(creds) == 0 {
			continue
		}
		score := credentialHeaderScore(creds) + 1000
		if targetFamily != "" && targetFamily == pathFamily(path) {
			score += 25
		}
		if score > bestScore {
			bestScore = score
			best = creds
			bestSource = strings.TrimSpace(source)
			if bestSource == "" {
				bestSource = rawURL
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return best, bestSource, nil
}

// CredentialHeaders extracts auth/session-shaped headers from a captured
// request header map. The returned map uses canonical-ish header names suitable
// for http.Request.Header.Set.
func CredentialHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string)
	for k, v := range headers {
		key := strings.TrimSpace(k)
		value := strings.TrimSpace(v)
		if key == "" || value == "" {
			continue
		}
		switch strings.ToLower(key) {
		case "authorization":
			out["Authorization"] = value
		case "cookie":
			if authLikelyCookie(value) {
				out["Cookie"] = value
			}
		case "x-api-key":
			out["X-API-Key"] = value
		case "x-auth-token":
			out["X-Auth-Token"] = value
		case "x-access-token":
			out["X-Access-Token"] = value
		case "x-csrf-token":
			out["X-CSRF-Token"] = value
		case "x-csrftoken":
			out["X-CSRFToken"] = value
		case "x-xsrf-token":
			out["X-XSRF-Token"] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func credentialHeaderScore(headers map[string]string) int {
	score := 0
	for k := range headers {
		switch strings.ToLower(k) {
		case "authorization":
			score += 500
		case "cookie":
			score += 250
		case "x-api-key", "x-auth-token", "x-access-token":
			score += 400
		case "x-csrf-token", "x-csrftoken", "x-xsrf-token":
			score += 80
		}
	}
	return score
}

func authLikelyCookie(cookie string) bool {
	lower := strings.ToLower(cookie)
	for _, marker := range []string{
		"session", "sessionid", "sid=", "connect.sid", "phpsessid",
		"jsessionid", "laravel_session", "token", "jwt", "auth",
		"xsrf-token", "csrf",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func normalizedURLHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return normalizedHost(u.Host)
}

func normalizedHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func pathFamilyFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return pathFamily(u.Path)
}

func pathFamily(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	first := strings.ToLower(parts[0])
	switch first {
	case "api", "rest", "graphql":
		return first
	default:
		return ""
	}
}
