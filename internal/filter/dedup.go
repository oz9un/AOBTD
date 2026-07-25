package filter

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/store"
)

// Deduplicator marks duplicate traffic entries in the database.
type Deduplicator struct {
	db     *store.DB
	logger *slog.Logger
}

// NewDeduplicator creates a new deduplication engine.
func NewDeduplicator(db *store.DB, logger *slog.Logger) *Deduplicator {
	return &Deduplicator{db: db, logger: logger}
}

// Run scans all non-filtered traffic for a scan and marks duplicates.
// Keeps the first occurrence per endpoint hash + any with a structurally
// different response.
func (d *Deduplicator) Run(scanID int64) (int, error) {
	rows, err := d.db.Conn().Query(`
		SELECT id, endpoint_hash, status_code, response_headers, content_type,
		       has_auth, response_size, substr(response_body, 1, 65536),
		       source_agent, source_action_id, hypothesis_id
		FROM traffic_resolved
		WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE
		ORDER BY captured_at ASC`,
		scanID,
	)
	if err != nil {
		return 0, fmt.Errorf("query traffic: %w", err)
	}

	type seenEntry struct {
		responseHash string
		hasAuth      bool
	}

	// Track what we've seen per endpoint
	seen := make(map[string][]seenEntry) // endpoint_hash -> seen responses
	var dupIDs []int64

	for rows.Next() {
		var id int64
		var endpointHash, responseHeaders, contentType string
		var responseBody []byte
		var sourceAgent, hypothesisID string
		var sourceActionID int64
		var statusCode int
		var hasAuth bool
		var responseSize int64

		err := rows.Scan(&id, &endpointHash, &statusCode, &responseHeaders, &contentType,
			&hasAuth, &responseSize, &responseBody, &sourceAgent, &sourceActionID, &hypothesisID)
		if err != nil {
			continue
		}

		// Active observations are comparison evidence, not crawl noise. Keep them
		// even when the response matches a passive capture byte-for-byte.
		activeEvidence := sourceActionID != 0 || hypothesisID != "" ||
			sourceAgent == "explorer" || sourceAgent == "verifier" || sourceAgent == "reasoner"

		respFingerprint := responseFingerprint(statusCode, contentType, responseHeaders, responseSize, responseBody)

		entries := seen[endpointHash]
		isDup := false

		for _, e := range entries {
			// Same response structure AND same auth state = duplicate
			if e.responseHash == respFingerprint && e.hasAuth == hasAuth {
				isDup = true
				break
			}
		}

		if isDup && !activeEvidence {
			dupIDs = append(dupIDs, id)
		} else {
			seen[endpointHash] = append(entries, seenEntry{
				responseHash: respFingerprint,
				hasAuth:      hasAuth,
			})
		}
	}

	rowsErr := rows.Err()
	rows.Close() // Close BEFORE doing updates to release the connection
	if rowsErr != nil {
		return 0, rowsErr
	}

	// Mark duplicates in batches under one transaction so large scans pay one
	// commit/fsync instead of one per 100-row chunk.
	marked := 0
	batchSize := 100
	tx, err := d.db.Conn().Begin()
	if err != nil {
		return 0, fmt.Errorf("begin duplicate update: %w", err)
	}
	defer tx.Rollback()
	for i := 0; i < len(dupIDs); i += batchSize {
		end := i + batchSize
		if end > len(dupIDs) {
			end = len(dupIDs)
		}
		batch := dupIDs[i:end]

		placeholders := make([]string, len(batch))
		args := make([]any, len(batch))
		for j, id := range batch {
			placeholders[j] = "?"
			args[j] = id
		}

		query := fmt.Sprintf(
			`UPDATE traffic SET is_duplicate = TRUE WHERE id IN (%s)`,
			strings.Join(placeholders, ","),
		)
		_, err := tx.Exec(query, args...)
		if err != nil {
			return marked, fmt.Errorf("mark duplicates: %w", err)
		}
		marked += len(batch)
	}
	if err := tx.Commit(); err != nil {
		return marked, fmt.Errorf("commit duplicate updates: %w", err)
	}

	d.logger.Info("deduplication complete", "duplicates_marked", marked)
	return marked, nil
}

// responseFingerprint combines structural metadata with a bounded body prefix.
// Distinct records with the same schema and size must remain available for
// ownership/IDOR reasoning, while exact repeated assets still collapse.
func responseFingerprint(statusCode int, contentType, headersJSON string, size int64, bodyPrefix []byte) string {
	// Extract the set of response header keys (not values — those change)
	var headers map[string]string
	json.Unmarshal([]byte(headersJSON), &headers)

	var headerKeys []string
	for k := range headers {
		headerKeys = append(headerKeys, strings.ToLower(k))
	}
	sort.Strings(headerKeys)

	// Size bucket (responses of similar size are likely the same)
	sizeBucket := size / 1024 // round to nearest KB

	bodyHash := fmt.Sprintf("%x", md5.Sum(bodyPrefix))
	raw := fmt.Sprintf("%d|%s|%s|%d|%s",
		statusCode,
		strings.ToLower(contentType),
		strings.Join(headerKeys, ","),
		sizeBucket,
		bodyHash,
	)
	return fmt.Sprintf("%x", md5.Sum([]byte(raw)))
}
