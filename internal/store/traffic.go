package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/internal/protection"
	"github.com/ozzyw/aobtd/pkg/types"
)

const bodyBlobThreshold = 16 * 1024

// CreateScan starts a new scan record.
func (db *DB) CreateScan(target, configJSON string) (int64, error) {
	res, err := db.conn.Exec(
		`INSERT INTO scans (target, config_json) VALUES (?, ?)`,
		target, configJSON,
	)
	if err != nil {
		return 0, fmt.Errorf("create scan: %w", err)
	}
	return res.LastInsertId()
}

// FinishScan marks a scan as completed.
func (db *DB) FinishScan(scanID int64, status string) error {
	_, err := db.conn.Exec(
		`UPDATE scans SET finished_at = datetime('now'), status = ? WHERE id = ?`,
		status, scanID,
	)
	return err
}

// MarkOutOfScopeFiltered flips is_filtered=TRUE on every captured traffic
// row whose host is not in scope. Third-party traffic (analytics beacons,
// ad-bidding cookie sync, CDN fetches) still gets captured by the MITM
// proxy — that's the firehose the Strategist needs to see — but we don't
// want the Analyzer or Verifier spending tokens reasoning about endpoints
// we're not authorized to test. Idempotent; safe to call multiple times.
//
// Matching rules (mirrors crawler.inScope()):
//   - exact host match, OR
//   - subdomain of an allowed host ("api.example.com" when "example.com" is allowed)
//
// Returns the count of rows newly marked filtered.
func (db *DB) MarkOutOfScopeFiltered(scanID int64, scope []string) (int, error) {
	if len(scope) == 0 {
		return 0, nil
	}
	// Build a predicate: host must NOT match scope AND NOT be a subdomain
	// AND NOT be the same host with a port suffix ("localhost:3000" matches
	// scope "localhost", "api.example.com:8080" matches "example.com").
	// Ports are a real issue on dev-server targets (Docker Juice Shop on
	// localhost:3000 was getting 100% filtered out before this branch).
	var conds []string
	var args []any
	args = append(args, scanID)
	for _, h := range scope {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		// Three patterns must all FAIL for the row to be marked out-of-scope:
		//   1. exact host match                       "example.com"
		//   2. exact host match with any port         "example.com:8080"
		//   3. subdomain (with or without port)       "api.example.com[:port]"
		conds = append(conds, `(
			lower(host) != ?
			AND lower(host) NOT LIKE ?
			AND lower(host) NOT LIKE ?
			AND lower(host) NOT LIKE ?
		)`)
		args = append(args,
			h,           // exact
			h+":%",      // exact + port
			"%."+h,      // subdomain, no port
			"%."+h+":%", // subdomain + port
		)
	}
	if len(conds) == 0 {
		return 0, nil
	}
	query := fmt.Sprintf(`
		UPDATE traffic
		SET is_filtered = TRUE
		WHERE scan_id = ?
		  AND is_filtered = FALSE
		  AND %s`, strings.Join(conds, " AND "))
	res, err := db.conn.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("mark out-of-scope: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// InsertTraffic stores a captured request/response pair.
func (db *DB) InsertTraffic(scanID int64, entry *types.TrafficEntry) (int64, error) {
	return insertTraffic(db.conn, scanID, entry)
}

type trafficExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func insertTraffic(execer trafficExecer, scanID int64, entry *types.TrafficEntry) (int64, error) {
	if err := observation.Normalize(entry); err != nil {
		return 0, fmt.Errorf("insert traffic: %w", err)
	}

	reqHeaders, _ := json.Marshal(entry.Request.Headers)
	resHeaders, _ := json.Marshal(entry.Response.Headers)

	hasParams := entry.Request.Query != "" || len(entry.Request.Body) > 0
	hasAuth := hasAuthHeaders(entry.Request.Headers)
	hasErrors := entry.Response.StatusCode >= 400
	isAPI := isAPIResponse(entry.Response.ContentType)
	hasInput := detectInputInBody(entry.Response.Body, entry.Response.ContentType)
	hasFileUpload := detectFileUpload(entry.Response.Body, entry.Response.ContentType)
	protectionEvidence := protection.ClassifyResponse(entry.Response)
	storedResponseBody := entry.Response.Body
	responseBodyHash := ""
	if len(entry.Response.Body) >= bodyBlobThreshold {
		responseBodyHash = fmt.Sprintf("%x", sha256.Sum256(entry.Response.Body))
		if _, err := execer.Exec(`INSERT OR IGNORE INTO body_blobs (hash, body, size) VALUES (?, ?, ?)`,
			responseBodyHash, entry.Response.Body, len(entry.Response.Body)); err != nil {
			return 0, fmt.Errorf("store response body blob: %w", err)
		}
		storedResponseBody = nil
	}

	res, err := execer.Exec(`
		INSERT INTO traffic (
			scan_id, method, url, host, path, query,
			request_headers, request_body,
			status_code, response_headers, response_body, response_body_hash,
			content_type, response_size,
			endpoint_hash, source_agent, source_action_id, hypothesis_id,
			has_params, has_input, has_file_upload,
			has_auth, has_errors, is_api,
			is_interstitial, protection_classified, protection_vendor, protection_fingerprint,
			is_filtered, captured_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID,
		entry.Request.Method, entry.Request.URL, entry.Request.Host,
		entry.Request.Path, entry.Request.Query,
		string(reqHeaders), entry.Request.Body,
		entry.Response.StatusCode, string(resHeaders), storedResponseBody, responseBodyHash,
		entry.Response.ContentType, entry.Response.Size,
		entry.EndpointHash, entry.SourceAgent, entry.SourceActionID, entry.HypothesisID,
		hasParams, hasInput, hasFileUpload,
		hasAuth, hasErrors, isAPI,
		protectionEvidence.IsInterstitial, true, protectionEvidence.Vendor, protectionEvidence.Fingerprint,
		entry.Filtered, entry.Timestamp,
	)
	if err != nil {
		return 0, fmt.Errorf("insert traffic: %w", err)
	}
	return res.LastInsertId()
}

// backfillProtectionEvidence upgrades only likely legacy challenge responses.
// It avoids a full body rewrite: SQL first bounds the candidate set to strong
// protection markers, then the same current classifier makes the final call.
// Future captures set protection_classified at insertion time.
func (db *DB) backfillProtectionEvidence() error {
	rows, err := db.conn.Query(`
		SELECT t.id, t.status_code, t.response_headers,
		       COALESCE(t.response_body,b.body), t.content_type
		FROM traffic t
		LEFT JOIN body_blobs b ON b.hash=t.response_body_hash
		WHERE t.protection_classified=FALSE
		  AND (LOWER(t.content_type) LIKE 'text/html%' OR LOWER(t.content_type)='')
		  AND (
		    LOWER(CAST(SUBSTR(COALESCE(t.response_body,b.body),1,32768) AS TEXT)) LIKE '%<title>just a moment%' OR
		    LOWER(CAST(SUBSTR(COALESCE(t.response_body,b.body),1,32768) AS TEXT)) LIKE '%/cdn-cgi/challenge-platform/%' OR
		    LOWER(CAST(SUBSTR(COALESCE(t.response_body,b.body),1,32768) AS TEXT)) LIKE '%checking your browser%' OR
		    LOWER(CAST(SUBSTR(COALESCE(t.response_body,b.body),1,32768) AS TEXT)) LIKE '%performing security verification%' OR
		    LOWER(CAST(SUBSTR(COALESCE(t.response_body,b.body),1,32768) AS TEXT)) LIKE '%verify you are human%' OR
		    LOWER(CAST(SUBSTR(COALESCE(t.response_body,b.body),1,32768) AS TEXT)) LIKE '%cf-turnstile%' OR
		    LOWER(CAST(SUBSTR(COALESCE(t.response_body,b.body),1,32768) AS TEXT)) LIKE '%captcha-delivery.com%'
		  )
		LIMIT 5000`)
	if err != nil {
		return err
	}
	type candidate struct {
		id          int64
		status      int
		headersJSON string
		body        []byte
		contentType string
	}
	candidates := make([]candidate, 0)
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.status, &item.headersJSON, &item.body, &item.contentType); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(candidates) == 0 {
		return nil
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range candidates {
		headers := map[string]string{}
		_ = json.Unmarshal([]byte(item.headersJSON), &headers)
		evidence := protection.ClassifyResponse(types.CapturedResponse{
			StatusCode: item.status, Headers: headers, Body: item.body, ContentType: item.contentType,
		})
		if _, err := tx.Exec(`
			UPDATE traffic SET protection_classified=TRUE, is_interstitial=?,
			protection_vendor=?, protection_fingerprint=? WHERE id=?`,
			evidence.IsInterstitial, evidence.Vendor, evidence.Fingerprint, item.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// InsertTrafficBatch persists captures under one transaction. It is used by
// the proxy-side writer so dozens of browser resources share one WAL commit.
func (db *DB) InsertTrafficBatch(scanID int64, entries []*types.TrafficEntry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin traffic batch: %w", err)
	}
	defer tx.Rollback()
	for i, entry := range entries {
		if entry == nil {
			return i, fmt.Errorf("insert traffic batch: nil entry at index %d", i)
		}
		if _, err := insertTraffic(tx, scanID, entry); err != nil {
			return i, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit traffic batch: %w", err)
	}
	return len(entries), nil
}

// GetUnanalyzedTraffic returns traffic entries that haven't been sent to the LLM.
func (db *DB) GetUnanalyzedTraffic(scanID int64, limit int) ([]types.TrafficEntry, error) {
	rows, err := db.conn.Query(`
		SELECT id, method, url, host, path, query,
		       request_headers, request_body,
		       status_code, response_headers, response_body,
		       content_type, response_size, endpoint_hash,
		       source_agent, source_action_id, hypothesis_id, captured_at
		FROM traffic_resolved
		WHERE scan_id = ? AND is_ai_analyzed = FALSE
		  AND is_filtered = FALSE AND is_duplicate = FALSE
		  AND endpoint_hash != ''
		ORDER BY relevance_score DESC
		LIMIT ?`,
		scanID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query unanalyzed traffic: %w", err)
	}
	defer rows.Close()

	return scanTrafficRows(rows)
}

// GetUnanalyzedTrafficAboveThreshold returns unanalyzed traffic above a relevance threshold.
func (db *DB) GetUnanalyzedTrafficAboveThreshold(scanID int64, threshold float64, limit int) ([]types.TrafficEntry, error) {
	rows, err := db.conn.Query(`
		SELECT id, method, url, host, path, query,
		       request_headers, request_body,
		       status_code, response_headers, response_body,
		       content_type, response_size, endpoint_hash,
		       source_agent, source_action_id, hypothesis_id, captured_at
		FROM traffic_resolved
		WHERE scan_id = ? AND is_ai_analyzed = FALSE
		  AND is_filtered = FALSE AND is_duplicate = FALSE
		  AND endpoint_hash != ''
		  AND relevance_score >= ?
		ORDER BY relevance_score DESC
		LIMIT ?`,
		scanID, threshold, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query unanalyzed traffic: %w", err)
	}
	defer rows.Close()

	return scanTrafficRows(rows)
}

// GetTrafficByScan returns all non-filtered traffic for a scan.
func (db *DB) GetTrafficByScan(scanID int64) ([]types.TrafficEntry, error) {
	rows, err := db.conn.Query(`
		SELECT id, method, url, host, path, query,
		       request_headers, request_body,
		       status_code, response_headers, response_body,
		       content_type, response_size, endpoint_hash,
		       source_agent, source_action_id, hypothesis_id, captured_at
		FROM traffic_resolved
		WHERE scan_id = ? AND is_filtered = FALSE
		ORDER BY captured_at ASC`,
		scanID,
	)
	if err != nil {
		return nil, fmt.Errorf("query traffic: %w", err)
	}
	defer rows.Close()

	return scanTrafficRows(rows)
}

const (
	profileEvidenceDefaultBodyBytes = 4096
	// Keep each hash-filter query below SQLite's portable parameter ceiling.
	// The caller walks every chunk, so this is a statement-size bound rather
	// than an evidence-count bound.
	profileEvidenceHashChunkSize = 400
)

// GetProfileEvidenceTraffic returns a bounded, response-aware sample used by
// deterministic semantic verification. It deliberately does not deserialize
// every response in a scan: SQL keeps at most the newest and the largest
// response for each endpoint/method/status tuple. There is intentionally no
// global route limit: dropping the 1025th identity would turn captured direct
// evidence into a false "profile only" verdict. Oversized bodies retain a
// split head/tail sample: status envelopes and titles tend to live at the
// head, while SPA bundle identity and closing shell markup often live at the
// tail.
func (db *DB) GetProfileEvidenceTraffic(scanID int64) ([]types.TrafficEntry, error) {
	return db.queryProfileEvidenceTraffic(scanID, nil, true, profileEvidenceDefaultBodyBytes)
}

// GetProfileEvidenceTrafficForHashes is the page-profile projection used by
// the UI. Callers pass only endpoint identities that back stored profiles, so
// a large asset/API crawl cannot make Knowledge or Recon retain thousands of
// unrelated body prefixes. Empty hashes intentionally return no rows.
func (db *DB) GetProfileEvidenceTrafficForHashes(scanID int64, endpointHashes []string) ([]types.TrafficEntry, error) {
	clean := make([]string, 0, len(endpointHashes))
	seen := make(map[string]struct{}, len(endpointHashes))
	for _, hash := range endpointHashes {
		hash = strings.TrimSpace(hash)
		if hash == "" {
			continue
		}
		if _, ok := seen[hash]; ok {
			continue
		}
		seen[hash] = struct{}{}
		clean = append(clean, hash)
	}
	if len(clean) == 0 {
		return []types.TrafficEntry{}, nil
	}

	// SQLite builds have different parameter ceilings. Chunk the requested
	// identities instead of silently truncating them: every requested endpoint
	// with captured evidence must receive a verdict. Legacy rows with an empty
	// hash are loaded only with the first chunk so they remain eligible without
	// being duplicated once per chunk.
	entries := make([]types.TrafficEntry, 0, len(clean))
	for start := 0; start < len(clean); start += profileEvidenceHashChunkSize {
		end := start + profileEvidenceHashChunkSize
		if end > len(clean) {
			end = len(clean)
		}
		chunk, err := db.queryProfileEvidenceTraffic(
			scanID,
			clean[start:end],
			start == 0,
			profileEvidenceDefaultBodyBytes,
		)
		if err != nil {
			return nil, err
		}
		entries = append(entries, chunk...)
	}
	// Each chunk is ordered by traffic id. Restore a deterministic global order
	// so callers see the same evidence sequence regardless of chunk boundaries.
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries, nil
}

// queryProfileEvidenceTraffic executes one safely-sized identity query. A nil
// endpointHashes slice means "all identities"; a non-nil slice is an exact
// hash filter. includeLegacyEmpty keeps imported pre-hash rows eligible and is
// enabled for only one requested-hash chunk to prevent duplicate evidence.
func (db *DB) queryProfileEvidenceTraffic(scanID int64, endpointHashes []string, includeLegacyEmpty bool, bodyBytes int) ([]types.TrafficEntry, error) {
	if bodyBytes <= 0 || bodyBytes > profileEvidenceDefaultBodyBytes {
		bodyBytes = profileEvidenceDefaultBodyBytes
	}

	hashFilter := ""
	args := make([]any, 0, len(endpointHashes)+7)
	args = append(args, scanID)
	if endpointHashes != nil {
		if len(endpointHashes) == 0 {
			return []types.TrafficEntry{}, nil
		}
		placeholders := make([]string, len(endpointHashes))
		for i, hash := range endpointHashes {
			placeholders[i] = "?"
			args = append(args, hash)
		}
		// Empty hashes are legacy/imported evidence. Keep them eligible so the
		// annotator can derive the canonical hash from method+URL; modern rows
		// remain tightly constrained to the requested profile identities.
		hashFilter = " AND endpoint_hash IN (" + strings.Join(placeholders, ",") + ")"
		if includeLegacyEmpty {
			hashFilter = " AND (endpoint_hash IN (" + strings.Join(placeholders, ",") + ") OR endpoint_hash = '')"
		}
	}
	// Favor the tail: JSON/status envelopes and document titles fit in a small
	// head window, while hashed SPA script tags can sit several kilobytes from
	// the end after the application mount and footer. For HTML with an explicit
	// framework/router bootstrap, reserve a small middle window around that
	// structural sentinel. This keeps the same 4 KiB transfer ceiling while
	// retaining soft-404 truth that a head/tail-only sample would erase.
	headBytes := bodyBytes / 4
	tailBytes := bodyBytes - headBytes
	// A structural response needs three useful regions inside the same hard
	// ceiling: enough of the head for document metadata, a 512-byte router/data
	// assignment window from the middle, and the full historical 3 KiB tail
	// budget for late SPA/auth bundle tags. Keeping that tail budget matters
	// because the auth shell and soft-error classifiers are independent gates.
	structuralHeadBytes := bodyBytes / 8
	structuralBytes := bodyBytes / 8
	structuralTailBytes := bodyBytes - structuralHeadBytes - structuralBytes
	args = append(args, bodyBytes, structuralHeadBytes, structuralBytes, structuralTailBytes, headBytes, tailBytes)

	// Rank using traffic metadata only. Exact URLs remain separate inside an
	// endpoint family: query values collapse visually, but a redirect/error on
	// one specimen must not disappear behind a sibling specimen's 200 content.
	// The body_blobs join occurs only after that reduction, preventing SQLite
	// from materializing every large response merely to choose bounded samples.
	query := `
		WITH ranked AS (
			SELECT id, UPPER(method) AS method, url, path, status_code,
			       COALESCE(response_headers, '{}') AS response_headers,
			       endpoint_hash, COALESCE(content_type, '') AS content_type,
			       COALESCE(response_size, 0) AS response_size,
			       ROW_NUMBER() OVER (
			         PARTITION BY CASE WHEN endpoint_hash != '' THEN endpoint_hash ELSE UPPER(method) || ' ' || url END,
			                      UPPER(method), url, status_code
			         ORDER BY COALESCE(response_size, 0) DESC, id DESC
			       ) AS size_rank,
			       ROW_NUMBER() OVER (
			         PARTITION BY CASE WHEN endpoint_hash != '' THEN endpoint_hash ELSE UPPER(method) || ' ' || url END,
			                      UPPER(method), url, status_code
			         ORDER BY id DESC
			       ) AS recent_rank
			  FROM traffic
			 WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE` + hashFilter + `
		), picked AS (
			SELECT id, method, url, path, status_code, response_headers,
			       endpoint_hash, content_type, response_size
			  FROM ranked
			 WHERE size_rank = 1 OR recent_rank = 1
			 ORDER BY id DESC
		), materialized AS (
			SELECT p.*, COALESCE(t.response_body, b.body, X'') AS body
			  FROM picked p
			  JOIN traffic t ON t.id = p.id
			  LEFT JOIN body_blobs b ON b.hash = t.response_body_hash
		), located AS (
			SELECT p.*, LOWER(CAST(p.body AS TEXT)) AS body_text
			  FROM materialized p
		), anchored AS (
			SELECT p.*,
			       CASE
			         WHEN INSTR(p.body_text, 'window.scrouter') > 0
			          AND INSTR(p.body_text, 'originalurl') > 0
			           THEN INSTR(p.body_text, 'originalurl')
			         ELSE INSTR(p.body_text, '__next_data__')
			       END AS structural_char_pos
			  FROM located p
		)
		SELECT p.id, p.method, p.url, p.path, p.status_code, p.response_headers,
		       p.endpoint_hash,
		       CASE
		         WHEN LENGTH(p.body) <= ? THEN p.body
		         WHEN LOWER(p.content_type) LIKE '%html%'
		          AND ((INSTR(p.body_text, 'window.scrouter') > 0
		                AND INSTR(p.body_text, 'originalurl') > 0)
		               OR INSTR(p.body_text, '__next_data__') > 0)
		           THEN SUBSTR(p.body, 1, ?)
		                || SUBSTR(
		                     p.body,
		                     LENGTH(CAST(SUBSTR(
		                       CAST(p.body AS TEXT), 1,
		                       MAX(0, p.structural_char_pos - 65)
		                     ) AS BLOB)) + 1,
		                     ?)
		                || SUBSTR(p.body, -?)
		         ELSE SUBSTR(p.body, 1, ?) || SUBSTR(p.body, -?)
		       END,
		       p.content_type, p.response_size
		  FROM anchored p
		 ORDER BY p.id ASC`
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query profile evidence traffic: %w", err)
	}
	defer rows.Close()

	entries := make([]types.TrafficEntry, 0)
	for rows.Next() {
		var entry types.TrafficEntry
		var responseHeaders string
		if err := rows.Scan(
			&entry.ID, &entry.Request.Method, &entry.Request.URL, &entry.Request.Path,
			&entry.Response.StatusCode, &responseHeaders, &entry.EndpointHash,
			&entry.Response.Body, &entry.Response.ContentType, &entry.Response.Size,
		); err != nil {
			return nil, err
		}
		entry.Response.Headers = make(map[string]string)
		_ = json.Unmarshal([]byte(responseHeaders), &entry.Response.Headers)
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// GetQueryRouteCandidates returns a deliberately bounded slice of page-like
// traffic whose query string may be acting as an application router. The body
// prefix is enough for structural/content classification while preventing the
// Recon UI from loading every full response in a large scan.
func (db *DB) GetQueryRouteCandidates(scanID int64, limit, maxBodyBytes int) ([]types.TrafficEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 160
	}
	if maxBodyBytes <= 0 || maxBodyBytes > 512*1024 {
		maxBodyBytes = 192 * 1024
	}
	rows, err := db.conn.Query(`
		SELECT t.id, t.method, t.url, t.host, t.path, t.query,
		       '{}', NULL,
		       t.status_code, '{}',
		       SUBSTR(COALESCE(t.response_body, b.body), 1, ?),
		       t.content_type, t.response_size, t.endpoint_hash,
		       '', 0, '', t.captured_at
		FROM traffic t
		LEFT JOIN body_blobs b ON b.hash = t.response_body_hash
		WHERE t.scan_id = ? AND t.method IN ('GET','HEAD')
		  AND t.query != '' AND t.is_filtered = FALSE
		  AND (
		    ('&' || LOWER(t.query) || '&') LIKE '%&content=%' OR
		    ('&' || LOWER(t.query) || '&') LIKE '%&page=%' OR
		    ('&' || LOWER(t.query) || '&') LIKE '%&view=%' OR
		    ('&' || LOWER(t.query) || '&') LIKE '%&screen=%' OR
		    ('&' || LOWER(t.query) || '&') LIKE '%&route=%' OR
		    ('&' || LOWER(t.query) || '&') LIKE '%&section=%' OR
		    ('&' || LOWER(t.query) || '&') LIKE '%&tab=%' OR
		    ('&' || LOWER(t.query) || '&') LIKE '%&module=%'
		  )
		ORDER BY t.captured_at ASC, t.id ASC
		LIMIT ?`, maxBodyBytes, scanID, limit)
	if err != nil {
		return nil, fmt.Errorf("query route candidates: %w", err)
	}
	defer rows.Close()
	return scanTrafficRows(rows)
}

// MarkTrafficAnalyzed marks a batch of traffic IDs as analyzed.
func (db *DB) MarkTrafficAnalyzed(ids []int64, batchNum int) error {
	if len(ids) == 0 {
		return nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids)+1)
	args[0] = batchNum
	for i, id := range ids {
		placeholders[i] = "?"
		args[i+1] = id
	}
	query := fmt.Sprintf(
		`UPDATE traffic SET is_ai_analyzed = TRUE, analysis_batch = ? WHERE id IN (%s)`,
		strings.Join(placeholders, ","),
	)
	_, err := db.conn.Exec(query, args...)
	return err
}

// TrafficStats returns summary statistics for a scan's traffic.
type TrafficStats struct {
	Total           int `json:"total"`
	Filtered        int `json:"filtered"`
	Duplicated      int `json:"duplicated"`
	Analyzed        int `json:"analyzed"`
	WithInput       int `json:"with_input"`
	WithAuth        int `json:"with_auth"`
	WithErrors      int `json:"with_errors"`
	UniqueEndpoints int `json:"unique_endpoints"`
	APIEndpoints    int `json:"api_endpoints"`
	// APICalls is the UI-facing alias for APIEndpoints. Keep the older JSON
	// field for API consumers while matching the dashboard's established key.
	APICalls int `json:"api_calls"`
}

// ProtectionEvidenceSummary is capture truth, independent of whether the
// Analyzer has already consumed the route family. It lets Recon distinguish a
// retained protection boundary from representative application content.
type ProtectionEvidenceSummary struct {
	InterstitialResponses int      `json:"interstitial_responses"`
	DistinctShapes        int      `json:"distinct_shapes"`
	RecoveredRoutes       int      `json:"recovered_routes"`
	RepresentativeID      int64    `json:"representative_id,omitempty"`
	Vendors               []string `json:"vendors"`
}

func (db *DB) GetProtectionEvidenceSummary(scanID int64) (ProtectionEvidenceSummary, error) {
	var summary ProtectionEvidenceSummary
	var vendors string
	err := db.conn.QueryRow(`
		SELECT
			COALESCE(SUM(CASE WHEN is_interstitial = TRUE THEN 1 ELSE 0 END), 0),
			COUNT(DISTINCT CASE WHEN is_interstitial = TRUE AND protection_fingerprint != '' THEN protection_fingerprint END),
			COALESCE(MIN(CASE WHEN is_interstitial = TRUE THEN id END), 0),
			COALESCE(GROUP_CONCAT(DISTINCT CASE WHEN is_interstitial = TRUE AND protection_vendor != '' THEN protection_vendor END), '')
		FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE`, scanID).Scan(
		&summary.InterstitialResponses, &summary.DistinctShapes,
		&summary.RepresentativeID, &vendors,
	)
	if err != nil {
		return ProtectionEvidenceSummary{}, fmt.Errorf("query protection evidence summary: %w", err)
	}
	if err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM (
			SELECT endpoint_hash
			FROM traffic
			WHERE scan_id = ? AND is_filtered = FALSE AND endpoint_hash != ''
			GROUP BY endpoint_hash
			HAVING MAX(is_interstitial) = 1 AND MAX(CASE WHEN
				is_interstitial = FALSE AND status_code >= 200 AND status_code < 400
				AND (LOWER(content_type) LIKE 'text/html%' OR LOWER(content_type) LIKE '%json%' OR LOWER(content_type) LIKE '%xml%')
			THEN 1 ELSE 0 END) = 1
		)`, scanID).Scan(&summary.RecoveredRoutes); err != nil {
		return ProtectionEvidenceSummary{}, fmt.Errorf("query recovered protection routes: %w", err)
	}
	seen := make(map[string]bool)
	for _, vendor := range strings.Split(vendors, ",") {
		vendor = strings.TrimSpace(vendor)
		if vendor != "" && !seen[vendor] {
			seen[vendor] = true
			summary.Vendors = append(summary.Vendors, vendor)
		}
	}
	sort.Strings(summary.Vendors)
	return summary, nil
}

func (db *DB) GetTrafficStats(scanID int64) (*TrafficStats, error) {
	var s TrafficStats
	err := db.conn.QueryRow(`
		SELECT
			COUNT(*),
			SUM(CASE WHEN is_filtered THEN 1 ELSE 0 END),
			SUM(CASE WHEN is_duplicate THEN 1 ELSE 0 END),
			SUM(CASE WHEN is_ai_analyzed THEN 1 ELSE 0 END),
			SUM(CASE WHEN has_input THEN 1 ELSE 0 END),
			SUM(CASE WHEN has_auth THEN 1 ELSE 0 END),
			SUM(CASE WHEN has_errors THEN 1 ELSE 0 END),
			COUNT(DISTINCT CASE WHEN is_filtered = FALSE THEN endpoint_hash END),
			SUM(CASE WHEN is_api THEN 1 ELSE 0 END)
		FROM traffic WHERE scan_id = ?`,
		scanID,
	).Scan(&s.Total, &s.Filtered, &s.Duplicated, &s.Analyzed,
		&s.WithInput, &s.WithAuth, &s.WithErrors, &s.UniqueEndpoints, &s.APIEndpoints)
	if err != nil {
		return nil, fmt.Errorf("traffic stats: %w", err)
	}
	s.APICalls = s.APIEndpoints
	return &s, nil
}

// AnalysisQueueItem is one endpoint family waiting for AI analysis. The store
// supplies direct capture facts and a deterministic base score; the Analyzer
// may add a learned boost after comparing the row with the current semantic
// Recon gaps. Keeping both scores makes every reorder explainable in the UI.
type AnalysisQueueItem struct {
	EndpointHash         string              `json:"endpoint_hash"`
	EvidenceID           int64               `json:"evidence_id"`
	Method               string              `json:"method"`
	URL                  string              `json:"url"`
	Host                 string              `json:"host"`
	Path                 string              `json:"path"`
	StatusCode           int                 `json:"status_code"`
	ContentType          string              `json:"content_type,omitempty"`
	Captures             int                 `json:"captures"`
	Relevance            float64             `json:"relevance"`
	HasParams            bool                `json:"has_params"`
	HasInput             bool                `json:"has_input"`
	HasFileUpload        bool                `json:"has_file_upload"`
	HasAuth              bool                `json:"has_auth"`
	HasErrors            bool                `json:"has_errors"`
	IsAPI                bool                `json:"is_api"`
	IsInterstitial       bool                `json:"is_interstitial"`
	ProtectionVendor     string              `json:"protection_vendor,omitempty"`
	ProtectionShapes     int                 `json:"protection_shapes,omitempty"`
	RecoveredApplication bool                `json:"recovered_application,omitempty"`
	HasHypothesis        bool                `json:"has_hypothesis"`
	CanonicalRedirect    bool                `json:"canonical_redirect_alias,omitempty"`
	Reanalysis           bool                `json:"reanalysis,omitempty"`
	ProfileConfidence    float64             `json:"profile_confidence,omitempty"`
	ProfileAnalysisCount int                 `json:"profile_analysis_count,omitempty"`
	BaseScore            int                 `json:"base_score"`
	LearnedBoost         int                 `json:"learned_boost"`
	EvidenceGain         int                 `json:"evidence_gain"`
	AgingBoost           int                 `json:"aging_boost"`
	PriorityScore        int                 `json:"priority_score"`
	QueueAge             int                 `json:"queue_age"`
	FairnessLane         bool                `json:"fairness_lane"`
	Reasons              []string            `json:"reasons"`
	LearnedReasons       []string            `json:"learned_reasons,omitempty"`
	Impact               []AnalysisGapImpact `json:"impact,omitempty"`
	Disposition          string              `json:"disposition"`
}

// AnalysisGapImpact explains which explicit model gap an already captured
// endpoint family can plausibly help ground. It is a deterministic ranking
// signal, not a claim that reading the candidate will close the gap.
type AnalysisGapImpact struct {
	Kind        string `json:"kind"`
	ID          string `json:"id"`
	Label       string `json:"label"`
	Priority    int    `json:"priority"`
	Score       int    `json:"score"`
	Calibration int    `json:"calibration,omitempty"`
}

// GetUnanalyzedEndpointQueue returns endpoint families that are ready for AI
// analysis. This is the real database-backed analysis backlog, not a display
// projection. A family normally leaves after Analyzer handles it; the one
// exception is a single bounded recovery pass for a <=20%-confidence stub
// produced when the model response could not be parsed.
func (db *DB) GetUnanalyzedEndpointQueue(scanID int64, threshold float64, limit int) ([]AnalysisQueueItem, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.conn.Query(`
		SELECT t.endpoint_hash, MIN(t.id), MIN(t.method), MIN(t.url), MIN(t.host), MIN(t.path),
		       MAX(t.status_code), MIN(t.content_type), COUNT(*), MAX(t.relevance_score),
		       MAX(t.has_params), MAX(t.has_input), MAX(t.has_file_upload), MAX(t.has_auth),
		       MAX(t.has_errors), MAX(t.is_api),
		       CASE WHEN MAX(t.is_interstitial) = 1 AND MAX(CASE WHEN
		         t.is_interstitial = FALSE AND t.status_code >= 200 AND t.status_code < 400
		         AND (LOWER(t.content_type) LIKE 'text/html%' OR LOWER(t.content_type) LIKE '%json%' OR LOWER(t.content_type) LIKE '%xml%')
		       THEN 1 ELSE 0 END) = 0 THEN 1 ELSE 0 END,
		       COALESCE(MIN(NULLIF(t.protection_vendor,'')), ''),
		       COUNT(DISTINCT CASE WHEN t.is_interstitial = TRUE AND t.protection_fingerprint != '' THEN t.protection_fingerprint END),
		       MAX(CASE WHEN t.is_interstitial = FALSE AND t.status_code >= 200 AND t.status_code < 400
		         AND (LOWER(t.content_type) LIKE 'text/html%' OR LOWER(t.content_type) LIKE '%json%' OR LOWER(t.content_type) LIKE '%xml%')
		       THEN 1 ELSE 0 END) * MAX(t.is_interstitial),
		       MAX(CASE WHEN TRIM(t.hypothesis_id) != '' THEN 1 ELSE 0 END),
		       MAX(CASE WHEN t.status_code >= 300 AND t.status_code < 400 AND EXISTS (
		         SELECT 1 FROM traffic landing
		         WHERE landing.scan_id = t.scan_id AND landing.method = t.method
		           AND landing.host = t.host AND landing.is_filtered = FALSE AND landing.is_duplicate = FALSE
		           AND landing.status_code >= 200 AND landing.status_code < 300
		           AND (landing.path = t.path || '/' OR t.path = landing.path || '/')
		       ) THEN 1 ELSE 0 END)
		FROM traffic t
		WHERE t.scan_id = ? AND t.is_ai_analyzed = FALSE
		  AND t.is_filtered = FALSE AND t.is_duplicate = FALSE
		  AND t.endpoint_hash != ''
		  AND t.relevance_score >= ?
		GROUP BY t.endpoint_hash
		ORDER BY MAX(t.has_input) DESC, MAX(t.is_api) DESC, MAX(t.has_auth) DESC,
		         MAX(t.has_errors) DESC, MAX(t.relevance_score) DESC, t.endpoint_hash ASC
		LIMIT ?`,
		scanID, threshold, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query unanalyzed endpoint queue: %w", err)
	}
	items := make([]AnalysisQueueItem, 0, limit)
	for rows.Next() {
		var item AnalysisQueueItem
		if err := rows.Scan(
			&item.EndpointHash, &item.EvidenceID, &item.Method, &item.URL, &item.Host, &item.Path,
			&item.StatusCode, &item.ContentType, &item.Captures, &item.Relevance,
			&item.HasParams, &item.HasInput, &item.HasFileUpload, &item.HasAuth,
			&item.HasErrors, &item.IsAPI, &item.IsInterstitial,
			&item.ProtectionVendor, &item.ProtectionShapes, &item.RecoveredApplication,
			&item.HasHypothesis, &item.CanonicalRedirect,
		); err != nil {
			return nil, err
		}
		item.BaseScore, item.Reasons = analysisQueueBaseScore(item)
		item.PriorityScore = item.BaseScore
		item.Disposition = "analyze"
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	// A provider-truncated or malformed answer may leave only the deterministic
	// 10%-confidence extraction stub. That captured body remains useful evidence
	// and deserves one retry; analysis_count <= 1 plus the durable movement
	// guard prevents a failed provider from creating an infinite loop.
	recoveryRows, err := db.conn.Query(`
		SELECT t.endpoint_hash, MIN(t.id), MIN(t.method), MIN(t.url), MIN(t.host), MIN(t.path),
		       MAX(t.status_code), MIN(t.content_type), COUNT(*), MAX(t.relevance_score),
		       MAX(t.has_params), MAX(t.has_input), MAX(t.has_file_upload), MAX(t.has_auth),
		       MAX(t.has_errors), MAX(t.is_api),
		       CASE WHEN MAX(t.is_interstitial) = 1 AND MAX(CASE WHEN
		         t.is_interstitial = FALSE AND t.status_code >= 200 AND t.status_code < 400
		         AND (LOWER(t.content_type) LIKE 'text/html%' OR LOWER(t.content_type) LIKE '%json%' OR LOWER(t.content_type) LIKE '%xml%')
		       THEN 1 ELSE 0 END) = 0 THEN 1 ELSE 0 END,
		       COALESCE(MIN(NULLIF(t.protection_vendor,'')), ''),
		       COUNT(DISTINCT CASE WHEN t.is_interstitial = TRUE AND t.protection_fingerprint != '' THEN t.protection_fingerprint END),
		       MAX(CASE WHEN t.is_interstitial = FALSE AND t.status_code >= 200 AND t.status_code < 400
		         AND (LOWER(t.content_type) LIKE 'text/html%' OR LOWER(t.content_type) LIKE '%json%' OR LOWER(t.content_type) LIKE '%xml%')
		       THEN 1 ELSE 0 END) * MAX(t.is_interstitial),
		       MAX(CASE WHEN TRIM(t.hypothesis_id) != '' THEN 1 ELSE 0 END),
		       MAX(CASE WHEN t.status_code >= 300 AND t.status_code < 400 AND EXISTS (
		         SELECT 1 FROM traffic landing
		         WHERE landing.scan_id = t.scan_id AND landing.method = t.method
		           AND landing.host = t.host AND landing.is_filtered = FALSE AND landing.is_duplicate = FALSE
		           AND landing.status_code >= 200 AND landing.status_code < 300
		           AND (landing.path = t.path || '/' OR t.path = landing.path || '/')
		       ) THEN 1 ELSE 0 END),
		       MIN(p.confidence), MAX(p.analysis_count)
		FROM traffic t
		JOIN page_profiles p ON p.scan_id = t.scan_id AND p.method = t.method AND p.url = t.url
		WHERE t.scan_id = ? AND t.is_ai_analyzed = TRUE
		  AND t.is_filtered = FALSE AND t.is_duplicate = FALSE
		  AND t.endpoint_hash != '' AND t.relevance_score >= ?
		  AND p.confidence <= 0.20 AND p.analysis_count <= 1
		  AND NOT EXISTS (
		    SELECT 1 FROM analysis_priority_movements movement
		    WHERE movement.scan_id = t.scan_id AND movement.endpoint_hash = t.endpoint_hash
		      AND movement.selected = TRUE
		      AND movement.reasons_json LIKE '%low-confidence profile recovery%'
		  )
		GROUP BY t.endpoint_hash
		ORDER BY MAX(t.relevance_score) DESC, t.endpoint_hash ASC
		LIMIT ?`, scanID, threshold, limit)
	if err != nil {
		return nil, fmt.Errorf("query low-confidence analysis recovery queue: %w", err)
	}
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		seen[item.EndpointHash] = true
	}
	for recoveryRows.Next() {
		var item AnalysisQueueItem
		if err := recoveryRows.Scan(
			&item.EndpointHash, &item.EvidenceID, &item.Method, &item.URL, &item.Host, &item.Path,
			&item.StatusCode, &item.ContentType, &item.Captures, &item.Relevance,
			&item.HasParams, &item.HasInput, &item.HasFileUpload, &item.HasAuth,
			&item.HasErrors, &item.IsAPI, &item.IsInterstitial,
			&item.ProtectionVendor, &item.ProtectionShapes, &item.RecoveredApplication,
			&item.HasHypothesis, &item.CanonicalRedirect, &item.ProfileConfidence, &item.ProfileAnalysisCount,
		); err != nil {
			recoveryRows.Close()
			return nil, err
		}
		if seen[item.EndpointHash] {
			continue
		}
		item.Reanalysis = true
		item.BaseScore, item.Reasons = analysisQueueBaseScore(item)
		item.PriorityScore = item.BaseScore
		item.Disposition = "analyze"
		items = append(items, item)
		seen[item.EndpointHash] = true
	}
	if err := recoveryRows.Err(); err != nil {
		recoveryRows.Close()
		return nil, err
	}
	if err := recoveryRows.Close(); err != nil {
		return nil, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].BaseScore != items[j].BaseScore {
			return items[i].BaseScore > items[j].BaseScore
		}
		return items[i].EndpointHash < items[j].EndpointHash
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

type AnalysisQueueCounts struct {
	Ready     int `json:"ready"`
	Deferred  int `json:"deferred"`
	Completed int `json:"completed"`
}

// GetAnalysisQueueCounts summarizes endpoint-family states using the same
// threshold and eligibility rules as GetUnanalyzedEndpointQueue.
func (db *DB) GetAnalysisQueueCounts(scanID int64, threshold float64) (AnalysisQueueCounts, error) {
	var counts AnalysisQueueCounts
	err := db.conn.QueryRow(`
		SELECT COALESCE(SUM(CASE WHEN ready = 1 OR recovery = 1 THEN 1 ELSE 0 END),0),
		       COALESCE(SUM(deferred),0),
		       COALESCE(SUM(CASE WHEN ready = 0 AND recovery = 0 AND deferred = 0 AND analyzed = 1 THEN 1 ELSE 0 END),0)
		FROM (
			SELECT t.endpoint_hash,
			       MAX(CASE WHEN t.is_ai_analyzed = FALSE AND t.relevance_score >= ? THEN 1 ELSE 0 END) AS ready,
			       MAX(CASE WHEN t.is_ai_analyzed = FALSE AND t.relevance_score < ? THEN 1 ELSE 0 END) AS deferred,
			       MAX(CASE WHEN t.is_ai_analyzed = TRUE THEN 1 ELSE 0 END) AS analyzed,
			       MAX(CASE WHEN t.is_ai_analyzed = TRUE AND t.relevance_score >= ?
			         AND p.confidence <= 0.20 AND p.analysis_count <= 1
			         AND NOT EXISTS (
			           SELECT 1 FROM analysis_priority_movements movement
			           WHERE movement.scan_id = t.scan_id AND movement.endpoint_hash = t.endpoint_hash
			             AND movement.selected = TRUE
			             AND movement.reasons_json LIKE '%low-confidence profile recovery%'
			         ) THEN 1 ELSE 0 END) AS recovery
			FROM traffic t
			LEFT JOIN page_profiles p ON p.scan_id = t.scan_id AND p.method = t.method AND p.url = t.url
			WHERE t.scan_id = ? AND t.is_filtered = FALSE AND t.is_duplicate = FALSE AND t.endpoint_hash != ''
			GROUP BY t.endpoint_hash
		)`, threshold, threshold, threshold, scanID).Scan(&counts.Ready, &counts.Deferred, &counts.Completed)
	if err != nil {
		return AnalysisQueueCounts{}, fmt.Errorf("count analysis queue: %w", err)
	}
	return counts, nil
}

func analysisQueueBaseScore(item AnalysisQueueItem) (int, []string) {
	score := int(item.Relevance * 100)
	reasons := make([]string, 0, 6)
	if item.HasInput {
		score += 24
		reasons = append(reasons, "input-bearing page")
	}
	if item.IsAPI {
		score += 18
		reasons = append(reasons, "API response")
	}
	if item.HasAuth {
		score += 16
		reasons = append(reasons, "auth evidence")
	}
	if item.HasErrors {
		score += 12
		reasons = append(reasons, "error behavior")
	}
	if item.HasFileUpload {
		score += 15
		reasons = append(reasons, "upload affordance")
	}
	if item.HasParams {
		score += 8
		reasons = append(reasons, "request parameters")
	}
	if item.Reanalysis {
		score += 36
		reasons = append(reasons, "low-confidence profile recovery")
	}
	if method := strings.ToUpper(strings.TrimSpace(item.Method)); method != "" && method != "GET" && method != "HEAD" && method != "OPTIONS" {
		score += 14
		reasons = append(reasons, "state-changing method")
	}
	if item.Captures > 0 {
		score += minInt(item.Captures, 5)
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "high capture relevance")
	}
	return score, reasons
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

// GetUnanalyzedEndpointHashes preserves the original compact API while using
// the same queue source now shown to the operator.
func (db *DB) GetUnanalyzedEndpointHashes(scanID int64, threshold float64, limit int) ([]string, error) {
	items, err := db.GetUnanalyzedEndpointQueue(scanID, threshold, limit)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(items))
	for _, item := range items {
		hashes = append(hashes, item.EndpointHash)
	}
	return hashes, nil
}

// GetTrafficByEndpointHash returns all non-filtered, non-duplicate traffic entries
// for a specific endpoint hash.
func (db *DB) GetTrafficByEndpointHash(scanID int64, endpointHash string) ([]types.TrafficEntry, error) {
	rows, err := db.conn.Query(`
		SELECT id, method, url, host, path, query,
		       request_headers, request_body,
		       status_code, response_headers, response_body,
		       content_type, response_size, endpoint_hash,
		       source_agent, source_action_id, hypothesis_id, captured_at
		FROM traffic_resolved
		WHERE scan_id = ? AND endpoint_hash = ?
		  AND is_filtered = FALSE AND is_duplicate = FALSE
		ORDER BY captured_at ASC`,
		scanID, endpointHash,
	)
	if err != nil {
		return nil, fmt.Errorf("query traffic by endpoint: %w", err)
	}
	defer rows.Close()

	return scanTrafficRows(rows)
}

// GetAnalyzedTrafficByEndpointHash returns the already-analyzed evidence for
// an endpoint hash. Analyzer convergence uses this to build replay fingerprints
// without accidentally including newly captured, still-unanalyzed rows.
func (db *DB) GetAnalyzedTrafficByEndpointHash(scanID int64, endpointHash string) ([]types.TrafficEntry, error) {
	rows, err := db.conn.Query(`
		SELECT id, method, url, host, path, query,
		       request_headers, request_body,
		       status_code, response_headers, response_body,
		       content_type, response_size, endpoint_hash,
		       source_agent, source_action_id, hypothesis_id, captured_at
		FROM traffic_resolved
		WHERE scan_id = ? AND endpoint_hash = ?
		  AND is_filtered = FALSE AND is_duplicate = FALSE
		  AND is_ai_analyzed = TRUE
		ORDER BY captured_at ASC`,
		scanID, endpointHash,
	)
	if err != nil {
		return nil, fmt.Errorf("query analyzed traffic by endpoint: %w", err)
	}
	defer rows.Close()

	return scanTrafficRows(rows)
}

// MarkEndpointAnalyzed marks ALL traffic entries for an endpoint_hash as analyzed.
func (db *DB) MarkEndpointAnalyzed(scanID int64, endpointHash string, batchNum int) error {
	_, err := db.conn.Exec(`
		UPDATE traffic SET is_ai_analyzed = TRUE, analysis_batch = ?
		WHERE scan_id = ? AND endpoint_hash = ?
		  AND is_filtered = FALSE AND is_duplicate = FALSE`,
		batchNum, scanID, endpointHash,
	)
	return err
}

// AcknowledgeEquivalentAnalyzedEvidence advances the analysis watermark for
// fresh captures that are materially identical to evidence already consumed
// for the same endpoint family. Changed status, response shape/body, auth,
// input/schema flags, API classification, or protection behavior remains
// unanalyzed and therefore re-enters the priority queue.
func (db *DB) AcknowledgeEquivalentAnalyzedEvidence(scanID int64) (int64, error) {
	result, err := db.conn.Exec(`
		UPDATE traffic AS fresh
		SET is_ai_analyzed = TRUE,
		    analysis_batch = COALESCE((
		      SELECT MAX(prior.analysis_batch)
		      FROM traffic prior
		      WHERE prior.scan_id = fresh.scan_id
		        AND prior.endpoint_hash = fresh.endpoint_hash
		        AND prior.is_ai_analyzed = TRUE
		    ), fresh.analysis_batch)
		WHERE fresh.scan_id = ?
		  AND fresh.is_ai_analyzed = FALSE
		  AND fresh.is_filtered = FALSE
		  AND fresh.is_duplicate = FALSE
		  AND fresh.endpoint_hash != ''
		  AND EXISTS (
		    SELECT 1
		    FROM traffic prior
		    WHERE prior.scan_id = fresh.scan_id
		      AND prior.endpoint_hash = fresh.endpoint_hash
		      AND prior.is_ai_analyzed = TRUE
		      AND prior.method = fresh.method
		      AND prior.status_code = fresh.status_code
		      AND LOWER(COALESCE(prior.content_type,'')) = LOWER(COALESCE(fresh.content_type,''))
		      AND prior.response_size = fresh.response_size
		      AND COALESCE(prior.response_body_hash,'') = COALESCE(fresh.response_body_hash,'')
		      AND prior.has_params = fresh.has_params
		      AND prior.has_input = fresh.has_input
		      AND prior.has_file_upload = fresh.has_file_upload
		      AND prior.has_auth = fresh.has_auth
		      AND prior.has_errors = fresh.has_errors
		      AND prior.is_api = fresh.is_api
		      AND prior.is_interstitial = fresh.is_interstitial
		      AND COALESCE(prior.protection_fingerprint,'') = COALESCE(fresh.protection_fingerprint,'')
		  )`, scanID)
	if err != nil {
		return 0, fmt.Errorf("acknowledge equivalent analyzed evidence: %w", err)
	}
	return result.RowsAffected()
}

func scanTrafficRows(rows *sql.Rows) ([]types.TrafficEntry, error) {
	var entries []types.TrafficEntry
	for rows.Next() {
		var e types.TrafficEntry
		var reqHeadersJSON, resHeadersJSON string
		var capturedAt time.Time

		err := rows.Scan(
			&e.ID,
			&e.Request.Method, &e.Request.URL, &e.Request.Host,
			&e.Request.Path, &e.Request.Query,
			&reqHeadersJSON, &e.Request.Body,
			&e.Response.StatusCode, &resHeadersJSON, &e.Response.Body,
			&e.Response.ContentType, &e.Response.Size,
			&e.EndpointHash, &e.SourceAgent, &e.SourceActionID, &e.HypothesisID,
			&capturedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		e.Request.Headers = make(map[string]string)
		json.Unmarshal([]byte(reqHeadersJSON), &e.Request.Headers)

		e.Response.Headers = make(map[string]string)
		json.Unmarshal([]byte(resHeadersJSON), &e.Response.Headers)

		e.Timestamp = capturedAt
		e.Request.Timestamp = capturedAt

		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// hasAuthHeaders records direct credential evidence. A Cookie header alone is
// deliberately insufficient: public sites routinely issue anonymous session,
// consent, experiment, and bot-management cookies. Treating those as proven
// authentication inflates queue priority and creates fictional signed-in
// actors. Operator/login-derived cookie context is tracked separately in
// credential_contexts.
func hasAuthHeaders(headers map[string]string) bool {
	for k := range headers {
		lower := strings.ToLower(k)
		if lower == "authorization" ||
			lower == "x-api-key" || lower == "x-auth-token" {
			return true
		}
	}
	return false
}

// isAPIResponse checks if the content type suggests an API response.
func isAPIResponse(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "application/xml") ||
		strings.Contains(ct, "text/xml") ||
		strings.Contains(ct, "application/graphql")
}

// detectInputInBody checks if HTML response contains form inputs.
func detectInputInBody(body []byte, contentType string) bool {
	if !strings.Contains(strings.ToLower(contentType), "text/html") {
		return false
	}
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "<input") ||
		strings.Contains(lower, "<textarea") ||
		strings.Contains(lower, "<select") ||
		strings.Contains(lower, "<form")
}

// detectFileUpload checks if HTML response contains file upload inputs.
func detectFileUpload(body []byte, contentType string) bool {
	if !strings.Contains(strings.ToLower(contentType), "text/html") {
		return false
	}
	return strings.Contains(strings.ToLower(string(body)), `type="file"`) ||
		strings.Contains(strings.ToLower(string(body)), `type='file'`)
}
