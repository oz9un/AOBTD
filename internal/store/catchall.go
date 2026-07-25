package store

import (
	"fmt"
	"strings"

	"github.com/ozzyw/aobtd/internal/reconprojection"
)

const catchAllInlineBodyLimit = 16 * 1024

type catchAllCacheEntry struct {
	revision string
	index    *reconprojection.CatchAllIndex
}

// GetCatchAllIndex returns the scan's exact shared-shell evidence. Large
// responses use the full SHA-256 persisted by the traffic store. Inline bodies
// are hashed only when their complete value is bounded to 16 KiB; legacy large
// inline bodies without a full digest are skipped rather than compared through
// lossy samples.
func (db *DB) GetCatchAllIndex(scanID int64) (*reconprojection.CatchAllIndex, error) {
	if db == nil || db.conn == nil {
		return reconprojection.NewCatchAllIndex(nil), nil
	}
	db.catchAllMu.Lock()
	defer db.catchAllMu.Unlock()

	var count, maxID, statusTotal, sizeTotal, filteredTotal, duplicateTotal int64
	if err := db.conn.QueryRow(`
		SELECT COUNT(*), COALESCE(MAX(id), 0), COALESCE(SUM(status_code), 0),
		       COALESCE(SUM(response_size), 0),
		       COALESCE(SUM(CASE WHEN is_filtered THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN is_duplicate THEN 1 ELSE 0 END), 0)
		  FROM traffic WHERE scan_id = ?`, scanID,
	).Scan(&count, &maxID, &statusTotal, &sizeTotal, &filteredTotal, &duplicateTotal); err != nil {
		return nil, fmt.Errorf("catch-all revision: %w", err)
	}
	revision := fmt.Sprintf("%d:%d:%d:%d:%d:%d", count, maxID, statusTotal, sizeTotal, filteredTotal, duplicateTotal)
	if cached, ok := db.catchAllIndexes[scanID]; ok && cached.revision == revision && cached.index != nil {
		return cached.index, nil
	}

	rows, err := db.conn.Query(`
		SELECT UPPER(t.method), t.url, COALESCE(t.response_body_hash, ''),
		       CASE
		         WHEN COALESCE(t.response_body_hash, '') = ''
		          AND LENGTH(COALESCE(t.response_body, X'')) BETWEEN 1 AND ?
		           THEN COALESCE(t.response_body, X'')
		         ELSE X''
		       END,
		       LENGTH(COALESCE(t.response_body, X''))
		  FROM traffic t
		 WHERE t.scan_id = ? AND t.is_filtered = FALSE AND t.is_duplicate = FALSE
		   AND t.status_code BETWEEN 200 AND 299
		   AND LOWER(COALESCE(t.content_type, '')) LIKE '%html%'
		   AND (COALESCE(t.response_body_hash, '') != '' OR LENGTH(COALESCE(t.response_body, X'')) > 0)
		 ORDER BY t.id ASC`, catchAllInlineBodyLimit, scanID)
	if err != nil {
		return nil, fmt.Errorf("query catch-all evidence: %w", err)
	}
	observations := make([]reconprojection.CatchAllObservation, 0)
	for rows.Next() {
		var method, rawURL, storedDigest string
		var inlineBody []byte
		var inlineLength int
		if err := rows.Scan(&method, &rawURL, &storedDigest, &inlineBody, &inlineLength); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan catch-all evidence: %w", err)
		}
		digest := strings.TrimSpace(storedDigest)
		if digest == "" {
			// The CASE expression returns the entire body only inside the bound.
			// A legacy large inline value has no trustworthy bounded equivalent.
			if inlineLength <= 0 || inlineLength > catchAllInlineBodyLimit || len(inlineBody) != inlineLength {
				continue
			}
			digest = reconprojection.BodySHA256(inlineBody)
		}
		observations = append(observations, reconprojection.CatchAllObservation{
			Method: method, URL: rawURL, BodySHA256: digest,
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate catch-all evidence: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close catch-all evidence: %w", err)
	}
	index := reconprojection.NewCatchAllIndex(observations)
	if db.catchAllIndexes == nil {
		db.catchAllIndexes = make(map[int64]catchAllCacheEntry)
	}
	if len(db.catchAllIndexes) >= 8 {
		for cachedScanID := range db.catchAllIndexes {
			delete(db.catchAllIndexes, cachedScanID)
			break
		}
	}
	db.catchAllIndexes[scanID] = catchAllCacheEntry{revision: revision, index: index}
	return index, nil
}
