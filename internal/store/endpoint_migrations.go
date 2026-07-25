package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/observation"
)

const endpointIdentityVersion = "3"

// migrateEndpointsCompositePK rebuilds endpoints with PRIMARY KEY
// (scan_id, id). Endpoint IDs are stable within a scan, not globally: the
// crawler and JS analyzer intentionally rediscover the same endpoint on later
// scans. The old global key made the second scan collide with the first.
func (db *DB) migrateEndpointsCompositePK() error {
	rows, err := db.conn.Query(`SELECT name, pk FROM pragma_table_info('endpoints') WHERE pk > 0 ORDER BY pk`)
	if err != nil {
		return err
	}
	var pkCols []string
	for rows.Next() {
		var name string
		var position int
		if err := rows.Scan(&name, &position); err != nil {
			rows.Close()
			return err
		}
		pkCols = append(pkCols, name)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(pkCols) == 2 && pkCols[0] == "scan_id" && pkCols[1] == "id" {
		return nil
	}

	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	statements := []string{
		`CREATE TABLE endpoints_new (
			id              TEXT NOT NULL,
			scan_id         INTEGER NOT NULL REFERENCES scans(id),
			method          TEXT NOT NULL,
			url_pattern     TEXT NOT NULL,
			params_json     TEXT DEFAULT '[]',
			hit_count       INTEGER NOT NULL DEFAULT 1,
			has_params      BOOLEAN NOT NULL DEFAULT FALSE,
			has_input       BOOLEAN NOT NULL DEFAULT FALSE,
			has_file_upload BOOLEAN NOT NULL DEFAULT FALSE,
			has_auth        BOOLEAN NOT NULL DEFAULT FALSE,
			has_errors      BOOLEAN NOT NULL DEFAULT FALSE,
			is_api          BOOLEAN NOT NULL DEFAULT FALSE,
			is_ai_analyzed  BOOLEAN NOT NULL DEFAULT FALSE,
			first_seen_at   DATETIME NOT NULL DEFAULT (datetime('now')),
			last_seen_at    DATETIME NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (scan_id, id)
		)`,
		`INSERT INTO endpoints_new
		 (id, scan_id, method, url_pattern, params_json, hit_count,
		  has_params, has_input, has_file_upload, has_auth, has_errors,
		  is_api, is_ai_analyzed, first_seen_at, last_seen_at)
		 SELECT id, scan_id, method, url_pattern, COALESCE(params_json,'[]'), hit_count,
		        has_params, has_input, has_file_upload, has_auth, has_errors,
		        is_api, is_ai_analyzed, first_seen_at, last_seen_at
		 FROM endpoints`,
		`DROP TABLE endpoints`,
		`ALTER TABLE endpoints_new RENAME TO endpoints`,
		`CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_endpoints_analyzed ON endpoints(is_ai_analyzed)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("rebuild endpoints: %w", err)
		}
	}
	return tx.Commit()
}

type trafficIdentityMigration struct {
	id      int64
	scanID  int64
	method  string
	rawURL  string
	oldHash string
	newHash string
	origin  string
}

// migrateEndpointIdentity atomically upgrades all persisted traffic to the
// current endpoint identity. Version 2 added the canonical origin; version 3
// made opaque-segment detection conservative so readable long route names no
// longer collapse. It also records aliases and rewrites app-understanding hash
// references, preventing an active scan from splitting into old/new groups
// after a binary upgrade.
func (db *DB) migrateEndpointIdentity() error {
	var version string
	err := db.conn.QueryRow(`SELECT value FROM schema_metadata WHERE key = 'endpoint_identity_version'`).Scan(&version)
	if err == nil && version == endpointIdentityVersion {
		return nil
	}
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT id, scan_id, method, url, endpoint_hash FROM traffic ORDER BY id`)
	if err != nil {
		return err
	}
	var identities []trafficIdentityMigration
	for rows.Next() {
		var item trafficIdentityMigration
		if err := rows.Scan(&item.id, &item.scanID, &item.method, &item.rawURL, &item.oldHash); err != nil {
			rows.Close()
			return err
		}
		item.newHash = observation.EndpointHash(item.method, item.rawURL)
		item.origin = observation.CanonicalOrigin(item.rawURL)
		identities = append(identities, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}

	// scan -> prior hash -> current hashes. The set form is important: an
	// earlier coarse identity can fan out to multiple current endpoints.
	replacements := make(map[int64]map[string]map[string]struct{})
	for _, item := range identities {
		if item.newHash == "" {
			continue
		}
		if item.oldHash != item.newHash {
			if _, err := tx.Exec(`UPDATE traffic SET endpoint_hash = ? WHERE id = ?`, item.newHash, item.id); err != nil {
				return err
			}
		}
		if strings.TrimSpace(item.oldHash) == "" {
			continue
		}
		if _, err := tx.Exec(`
			INSERT OR IGNORE INTO endpoint_identity_aliases
			(scan_id, legacy_hash, endpoint_hash, origin) VALUES (?, ?, ?, ?)`,
			item.scanID, item.oldHash, item.newHash, item.origin); err != nil {
			return err
		}
		if replacements[item.scanID] == nil {
			replacements[item.scanID] = make(map[string]map[string]struct{})
		}
		if replacements[item.scanID][item.oldHash] == nil {
			replacements[item.scanID][item.oldHash] = make(map[string]struct{})
		}
		replacements[item.scanID][item.oldHash][item.newHash] = struct{}{}
	}

	if err := migrateEndpointRowsV2(tx, replacements); err != nil {
		return err
	}
	if err := migrateEndpointAliases(tx, replacements); err != nil {
		return err
	}
	if err := migrateUnderstandingHashesV2(tx, replacements); err != nil {
		return err
	}

	if _, err := tx.Exec(`
		INSERT INTO schema_metadata(key, value) VALUES ('endpoint_identity_version', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, endpointIdentityVersion); err != nil {
		return err
	}
	return tx.Commit()
}

// migrateEndpointAliases advances aliases created by an earlier identity
// migration. Without this, a v1 reference would still resolve to its stale v2
// hash after v3 rewrote the traffic. One prior hash may fan out to several
// current hashes, so replace each stale edge with all of its successors.
func migrateEndpointAliases(tx *sql.Tx, replacements map[int64]map[string]map[string]struct{}) error {
	rows, err := tx.Query(`
		SELECT scan_id, legacy_hash, endpoint_hash, origin
		FROM endpoint_identity_aliases`)
	if err != nil {
		return err
	}
	type aliasRow struct {
		scanID                           int64
		legacyHash, endpointHash, origin string
	}
	var aliases []aliasRow
	for rows.Next() {
		var alias aliasRow
		if err := rows.Scan(&alias.scanID, &alias.legacyHash, &alias.endpointHash, &alias.origin); err != nil {
			rows.Close()
			return err
		}
		aliases = append(aliases, alias)
	}
	if err := rows.Close(); err != nil {
		return err
	}

	for _, alias := range aliases {
		newHashes := sortedReplacementHashes(replacements[alias.scanID][alias.endpointHash])
		if len(newHashes) == 0 {
			continue
		}
		if _, err := tx.Exec(`
			DELETE FROM endpoint_identity_aliases
			WHERE scan_id = ? AND legacy_hash = ? AND endpoint_hash = ?`,
			alias.scanID, alias.legacyHash, alias.endpointHash); err != nil {
			return err
		}
		for _, newHash := range newHashes {
			if _, err := tx.Exec(`
				INSERT OR IGNORE INTO endpoint_identity_aliases
				(scan_id, legacy_hash, endpoint_hash, origin) VALUES (?, ?, ?, ?)`,
				alias.scanID, alias.legacyHash, newHash, alias.origin); err != nil {
				return err
			}
		}
	}
	return nil
}

// migrateEndpointRowsV2 rewrites crawler endpoint IDs that were v1 hashes.
// Non-hash IDs such as "GET|/api/users" are deliberately retained.
func migrateEndpointRowsV2(tx *sql.Tx, replacements map[int64]map[string]map[string]struct{}) error {
	rows, err := tx.Query(`SELECT scan_id, id, method, url_pattern FROM endpoints`)
	if err != nil {
		return err
	}
	type endpointRow struct {
		scanID             int64
		id, method, rawURL string
	}
	var endpoints []endpointRow
	for rows.Next() {
		var row endpointRow
		if err := rows.Scan(&row.scanID, &row.id, &row.method, &row.rawURL); err != nil {
			rows.Close()
			return err
		}
		endpoints = append(endpoints, row)
	}
	if err := rows.Close(); err != nil {
		return err
	}

	for _, endpoint := range endpoints {
		candidates := replacements[endpoint.scanID][endpoint.id]
		if len(candidates) == 0 {
			continue
		}
		newID := chooseEndpointReplacement(candidates, endpoint.method, endpoint.rawURL)
		if newID == "" || newID == endpoint.id {
			continue
		}
		if _, err := tx.Exec(`UPDATE endpoints SET id = ? WHERE scan_id = ? AND id = ?`,
			newID, endpoint.scanID, endpoint.id); err != nil {
			return fmt.Errorf("rewrite endpoint %s for scan %d: %w", endpoint.id, endpoint.scanID, err)
		}
	}
	return nil
}

func chooseEndpointReplacement(candidates map[string]struct{}, method, rawURL string) string {
	if len(candidates) == 1 {
		for candidate := range candidates {
			return candidate
		}
	}
	computed := observation.EndpointHash(method, rawURL)
	if _, ok := candidates[computed]; ok {
		return computed
	}
	// Ambiguous legacy identity with no trustworthy origin on the endpoint
	// row. Keep its old ID rather than assigning it to an arbitrary host.
	return ""
}

func migrateUnderstandingHashesV2(tx *sql.Tx, replacements map[int64]map[string]map[string]struct{}) error {
	rows, err := tx.Query(`SELECT scan_id, COALESCE(areas_json,'[]'), COALESCE(analyzed_hashes_json,'{}') FROM app_understanding`)
	if err != nil {
		return err
	}
	type understandingRow struct {
		scanID int64
		areas  string
		hashes string
	}
	var understandings []understandingRow
	for rows.Next() {
		var row understandingRow
		if err := rows.Scan(&row.scanID, &row.areas, &row.hashes); err != nil {
			rows.Close()
			return err
		}
		understandings = append(understandings, row)
	}
	if err := rows.Close(); err != nil {
		return err
	}

	type functionalArea struct {
		Name      string   `json:"name"`
		Endpoints []string `json:"endpoints"`
		Status    string   `json:"status"`
		Priority  int      `json:"priority"`
	}

	for _, row := range understandings {
		scanReplacements := replacements[row.scanID]
		if len(scanReplacements) == 0 {
			continue
		}

		// Older scans may contain partially-written JSON after an interrupted
		// process. Do not make the entire database unopenable in that case:
		// migrate each valid document independently and preserve malformed
		// text byte-for-byte for operator recovery.
		analyzedJSON := []byte(row.hashes)
		var analyzed map[string]string
		if err := json.Unmarshal([]byte(row.hashes), &analyzed); err == nil {
			if analyzed == nil {
				analyzed = make(map[string]string)
			}
			migratedAnalyzed := make(map[string]string, len(analyzed))
			for oldHash, templateID := range analyzed {
				newHashes := sortedReplacementHashes(scanReplacements[oldHash])
				if len(newHashes) == 0 {
					migratedAnalyzed[oldHash] = templateID
					continue
				}
				for _, newHash := range newHashes {
					migratedAnalyzed[newHash] = templateID
				}
			}
			analyzedJSON, err = json.Marshal(migratedAnalyzed)
			if err != nil {
				return err
			}
		}

		areasJSON := []byte(row.areas)
		var areas []functionalArea
		if err := json.Unmarshal([]byte(row.areas), &areas); err == nil {
			for i := range areas {
				var migrated []string
				seen := make(map[string]bool)
				for _, oldHash := range areas[i].Endpoints {
					newHashes := sortedReplacementHashes(scanReplacements[oldHash])
					if len(newHashes) == 0 {
						newHashes = []string{oldHash}
					}
					for _, newHash := range newHashes {
						if !seen[newHash] {
							seen[newHash] = true
							migrated = append(migrated, newHash)
						}
					}
				}
				areas[i].Endpoints = migrated
			}
			areasJSON, err = json.Marshal(areas)
			if err != nil {
				return err
			}
		}

		if _, err := tx.Exec(`UPDATE app_understanding SET areas_json = ?, analyzed_hashes_json = ? WHERE scan_id = ?`,
			string(areasJSON), string(analyzedJSON), row.scanID); err != nil {
			return err
		}
	}
	return nil
}

func sortedReplacementHashes(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
