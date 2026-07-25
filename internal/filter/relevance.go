package filter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ozzyw/aobtd/internal/store"
)

// RelevanceScorer assigns relevance scores (0.0-1.0) to traffic entries.
type RelevanceScorer struct {
	db     *store.DB
	logger *slog.Logger
}

// NewRelevanceScorer creates a new relevance scoring engine.
func NewRelevanceScorer(db *store.DB, logger *slog.Logger) *RelevanceScorer {
	return &RelevanceScorer{db: db, logger: logger}
}

// Run scores all unscored, non-filtered, non-duplicate traffic for a scan.
func (r *RelevanceScorer) Run(scanID int64) (int, error) {
	// Phase 1: Read all entries into memory (release the DB connection)
	rows, err := r.db.Conn().Query(`
		SELECT id, method, path, query, request_headers, request_body,
		       status_code, response_headers, content_type, response_size,
		       endpoint_hash
		FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE
		  AND relevance_scored = FALSE
		ORDER BY captured_at ASC`,
		scanID,
	)
	if err != nil {
		return 0, fmt.Errorf("query traffic: %w", err)
	}

	type scorableEntry struct {
		id           int64
		method       string
		path         string
		query        string
		reqHeaders   string
		reqBody      []byte
		statusCode   int
		resHeaders   string
		contentType  string
		responseSize int64
		endpointHash string
	}

	var entries []scorableEntry
	for rows.Next() {
		var e scorableEntry
		err := rows.Scan(&e.id, &e.method, &e.path, &e.query, &e.reqHeaders, &e.reqBody,
			&e.statusCode, &e.resHeaders, &e.contentType, &e.responseSize, &e.endpointHash)
		if err != nil {
			continue
		}
		entries = append(entries, e)
	}
	rows.Close() // Release the connection BEFORE doing updates

	if err := rows.Err(); err != nil {
		return 0, err
	}

	// Phase 2: Compute scores and write back in one transaction. A dedicated
	// relevance_scored flag distinguishes a real score of zero from "not run".
	seenEndpoints := make(map[string]bool)
	scored := 0
	tx, err := r.db.Conn().Begin()
	if err != nil {
		return 0, fmt.Errorf("begin relevance updates: %w", err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`UPDATE traffic SET relevance_score = ?, relevance_scored = TRUE WHERE id = ?`)
	if err != nil {
		return 0, fmt.Errorf("prepare relevance update: %w", err)
	}
	defer stmt.Close()

	for _, e := range entries {
		score := computeRelevance(
			e.method, e.path, e.query, e.reqHeaders, e.reqBody,
			e.statusCode, e.resHeaders, e.contentType, e.responseSize,
			e.endpointHash, seenEndpoints,
		)

		seenEndpoints[e.endpointHash] = true

		_, err = stmt.Exec(score, e.id)
		if err != nil {
			r.logger.Warn("failed to update score", "id", e.id, "error", err)
			continue
		}
		scored++
	}
	if err := tx.Commit(); err != nil {
		return scored, fmt.Errorf("commit relevance updates: %w", err)
	}

	r.logger.Info("relevance scoring complete", "scored", scored)
	return scored, nil
}

func computeRelevance(
	method, path, query, reqHeadersJSON string, reqBody []byte,
	statusCode int, resHeadersJSON, contentType string, responseSize int64,
	endpointHash string, seenEndpoints map[string]bool,
) float64 {
	var score float64

	ct := strings.ToLower(contentType)
	lowerPath := strings.ToLower(path)
	staticAsset := isStaticAssetPath(lowerPath) || isStaticAssetContentType(ct)

	// +0.30: has meaningful parameters (query string or request body).
	// Cache-busting tokens on passive assets should not out-rank real HTML
	// routes; JS/CSS route discovery is handled by the JS analyzer.
	if len(reqBody) > 0 || queryLooksLikeApplicationInput(lowerPath, query, staticAsset) {
		score += 0.30
	}

	// +0.20: returns structured data (JSON/XML)
	if strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "application/xml") ||
		strings.Contains(ct, "text/xml") {
		score += 0.20
	}

	// +0.25: navigable application page. Server-rendered apps and SPAs often
	// expose their business model through HTML routes without query params.
	if statusCode >= 200 && statusCode < 400 &&
		strings.Contains(ct, "text/html") &&
		!staticAsset &&
		!isLikelyBrowserChromePath(lowerPath) {
		score += 0.25
	}

	// +0.20: auth-related headers
	var reqHeaders map[string]string
	json.Unmarshal([]byte(reqHeadersJSON), &reqHeaders)
	for k := range reqHeaders {
		lower := strings.ToLower(k)
		if lower == "authorization" || lower == "cookie" ||
			lower == "x-api-key" || lower == "x-auth-token" ||
			lower == "x-csrf-token" {
			score += 0.20
			break
		}
	}

	// +0.15: error response (4xx/5xx)
	if statusCode >= 400 {
		score += 0.15
	}

	// +0.15: previously unseen URL pattern. Passive assets get a smaller
	// novelty bump so cache-busted scripts don't starve page routes.
	if !seenEndpoints[endpointHash] {
		if staticAsset {
			score += 0.05
		} else {
			score += 0.15
		}
	}

	// +0.10: state-changing method
	if method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH" {
		score += 0.10
	}

	// +0.10: response contains interesting keywords
	var resHeaders map[string]string
	json.Unmarshal([]byte(resHeadersJSON), &resHeaders)
	for k, v := range resHeaders {
		combined := strings.ToLower(k + ": " + v)
		if strings.Contains(combined, "set-cookie") ||
			strings.Contains(combined, "x-powered-by") ||
			strings.Contains(combined, "server:") {
			score += 0.05
			break
		}
	}

	// +0.10: path contains interesting segments
	interestingPaths := []string{
		"/admin", "/api/", "/auth", "/login", "/register",
		"/upload", "/settings", "/account", "/user", "/debug",
		"/internal", "/graphql", "/webhook",
	}
	for _, p := range interestingPaths {
		if strings.Contains(lowerPath, p) {
			score += 0.10
			break
		}
	}

	// -0.10: very large text response (likely not worth full analysis)
	if responseSize > 10*1024 && strings.Contains(ct, "text/html") {
		score -= 0.10
	}

	// Clamp to [0, 1]
	if score > 1.0 {
		score = 1.0
	}
	if score < 0 {
		score = 0
	}

	return score
}

func queryLooksLikeApplicationInput(path, query string, staticAsset bool) bool {
	query = strings.TrimSpace(query)
	if query == "" {
		return false
	}
	if !staticAsset {
		return true
	}
	if !strings.Contains(query, "=") {
		return false
	}
	pairs := strings.Split(query, "&")
	for _, pair := range pairs {
		name, value, _ := strings.Cut(pair, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		switch name {
		case "", "v", "ver", "version", "t", "ts", "time", "build", "hash", "cache", "cachebuster", "cb":
			continue
		}
		if value == "" && len(name) >= 8 {
			continue
		}
		return true
	}
	return false
}

func isStaticAssetPath(path string) bool {
	for _, suffix := range []string{
		".js", ".mjs", ".css", ".map",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
		".woff", ".woff2", ".ttf", ".eot",
		".mp3", ".mp4", ".webm",
	} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func isStaticAssetContentType(contentType string) bool {
	for _, marker := range []string{
		"javascript", "text/css", "image/", "font/", "audio/", "video/",
		"application/font", "application/octet-stream",
	} {
		if strings.Contains(contentType, marker) {
			return true
		}
	}
	return false
}

func isLikelyBrowserChromePath(path string) bool {
	switch path {
	case "/favicon.ico", "/robots.txt", "/sitemap.xml":
		return true
	default:
		return false
	}
}

// GetAboveThreshold returns traffic IDs with relevance above the threshold.
func (r *RelevanceScorer) GetAboveThreshold(scanID int64, threshold float64) ([]int64, error) {
	rows, err := r.db.Conn().Query(`
		SELECT id FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE
		  AND relevance_score >= ?
		ORDER BY relevance_score DESC`,
		scanID, threshold,
	)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Summary returns a human-readable summary of relevance distribution.
func (r *RelevanceScorer) Summary(scanID int64) (string, error) {
	var total, high, medium, low int
	err := r.db.Conn().QueryRow(`
		SELECT
			COUNT(*),
			SUM(CASE WHEN relevance_score >= 0.7 THEN 1 ELSE 0 END),
			SUM(CASE WHEN relevance_score >= 0.3 AND relevance_score < 0.7 THEN 1 ELSE 0 END),
			SUM(CASE WHEN relevance_score < 0.3 THEN 1 ELSE 0 END)
		FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE`,
		scanID,
	).Scan(&total, &high, &medium, &low)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("Relevance: %d high (>=0.7), %d medium (0.3-0.7), %d low (<0.3) out of %d total",
		high, medium, low, total), nil
}
