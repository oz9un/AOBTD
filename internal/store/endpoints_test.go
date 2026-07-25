package store

import (
	"crypto/md5"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestMigrateEndpointsCompositePKPreservesRowsAndAllowsSameIDAcrossScans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-endpoints.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	_, err = raw.Exec(`
		CREATE TABLE scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			started_at DATETIME NOT NULL DEFAULT (datetime('now')),
			finished_at DATETIME,
			status TEXT NOT NULL DEFAULT 'running',
			config_json TEXT NOT NULL DEFAULT '{}'
		);
		CREATE TABLE endpoints (
			id TEXT PRIMARY KEY,
			scan_id INTEGER NOT NULL REFERENCES scans(id),
			method TEXT NOT NULL,
			url_pattern TEXT NOT NULL,
			params_json TEXT DEFAULT '[]',
			hit_count INTEGER NOT NULL DEFAULT 1,
			has_params BOOLEAN NOT NULL DEFAULT FALSE,
			has_input BOOLEAN NOT NULL DEFAULT FALSE,
			has_file_upload BOOLEAN NOT NULL DEFAULT FALSE,
			has_auth BOOLEAN NOT NULL DEFAULT FALSE,
			has_errors BOOLEAN NOT NULL DEFAULT FALSE,
			is_api BOOLEAN NOT NULL DEFAULT FALSE,
			is_ai_analyzed BOOLEAN NOT NULL DEFAULT FALSE,
			first_seen_at DATETIME NOT NULL DEFAULT (datetime('now')),
			last_seen_at DATETIME NOT NULL DEFAULT (datetime('now'))
		);
		INSERT INTO scans(id, target) VALUES (1, 'https://one.example.test');
		INSERT INTO endpoints(id, scan_id, method, url_pattern, hit_count)
		VALUES ('shared-endpoint-id', 1, 'GET', '/orders/{id}', 7);
	`)
	if err != nil {
		raw.Close()
		t.Fatalf("seed legacy schema: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("migrate legacy db: %v", err)
	}
	defer db.Close()

	var pkCount int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM pragma_table_info('endpoints') WHERE pk > 0`).Scan(&pkCount); err != nil {
		t.Fatalf("inspect endpoint PK: %v", err)
	}
	if pkCount != 2 {
		t.Fatalf("endpoint PK columns = %d, want 2", pkCount)
	}

	scanTwo, err := db.CreateScan("https://two.example.test", `{}`)
	if err != nil {
		t.Fatalf("create second scan: %v", err)
	}
	if _, err := db.Conn().Exec(`
		INSERT INTO endpoints(id, scan_id, method, url_pattern)
		VALUES ('shared-endpoint-id', ?, 'GET', '/orders/{id}')`, scanTwo); err != nil {
		t.Fatalf("insert same endpoint id in second scan: %v", err)
	}

	var count, originalHits int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM endpoints WHERE id = 'shared-endpoint-id'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("same endpoint ID rows = %d, want 2", count)
	}
	if err := db.Conn().QueryRow(`SELECT hit_count FROM endpoints WHERE scan_id = 1 AND id = 'shared-endpoint-id'`).Scan(&originalHits); err != nil {
		t.Fatal(err)
	}
	if originalHits != 7 {
		t.Fatalf("migrated hit_count = %d, want 7", originalHits)
	}
}

func TestMigrateEndpointIdentityV2RecomputesHistoryAndKeepsAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-v2.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	const (
		appURL = "https://app.example.test/orders/41?expand=items"
		apiURL = "https://api.example.test/orders/99?expand=other"
	)
	legacyHash := legacyEndpointHash("GET", appURL)
	if legacyHash != legacyEndpointHash("GET", apiURL) {
		t.Fatal("test fixture URLs must collide under the path-only v1 identity")
	}

	// Simulate a database written before v2: remove the migration marker and
	// insert path-only hashes directly, bypassing today's InsertTraffic guard.
	if _, err := db.Conn().Exec(`DELETE FROM schema_metadata WHERE key = 'endpoint_identity_version'`); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		rawURL, host, path string
	}{
		{appURL, "app.example.test", "/orders/41"},
		{apiURL, "api.example.test", "/orders/99"},
	} {
		if _, err := db.Conn().Exec(`
			INSERT INTO traffic(
				scan_id, method, url, host, path, request_headers,
				status_code, response_headers, endpoint_hash, is_ai_analyzed)
			VALUES (?, 'GET', ?, ?, ?, '{}', 200, '{}', ?, TRUE)`,
			scanID, fixture.rawURL, fixture.host, fixture.path, legacyHash); err != nil {
			t.Fatalf("seed legacy traffic: %v", err)
		}
	}
	if _, err := db.Conn().Exec(`
		INSERT INTO endpoints(id, scan_id, method, url_pattern)
		VALUES (?, ?, 'GET', ?)`, legacyHash, scanID, appURL); err != nil {
		t.Fatalf("seed legacy endpoint: %v", err)
	}
	areas := fmt.Sprintf(`[{"name":"checkout","endpoints":[%q],"status":"fully_analyzed","priority":9}]`, legacyHash)
	hashes := fmt.Sprintf(`{%q:"orders-template"}`, legacyHash)
	if _, err := db.Conn().Exec(`
		INSERT INTO app_understanding(scan_id, areas_json, analyzed_hashes_json)
		VALUES (?, ?, ?)`, scanID, areas, hashes); err != nil {
		t.Fatalf("seed understanding: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(path)
	if err != nil {
		t.Fatalf("reopen and migrate v2: %v", err)
	}
	defer db.Close()

	appHash := observation.EndpointHash("GET", appURL)
	apiHash := observation.EndpointHash("GET", apiURL)
	if appHash == apiHash {
		t.Fatal("v2 fixture endpoints must have distinct origin-aware hashes")
	}

	rows, err := db.Conn().Query(`SELECT DISTINCT endpoint_hash FROM traffic WHERE scan_id = ? ORDER BY endpoint_hash`, scanID)
	if err != nil {
		t.Fatal(err)
	}
	var gotHashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			t.Fatal(err)
		}
		gotHashes = append(gotHashes, hash)
	}
	rows.Close()
	wantHashes := []string{appHash, apiHash}
	sort.Strings(wantHashes)
	if fmt.Sprint(gotHashes) != fmt.Sprint(wantHashes) {
		t.Fatalf("migrated traffic hashes = %v, want %v", gotHashes, wantHashes)
	}

	aliases, err := db.ResolveEndpointHashes(scanID, legacyHash)
	if err != nil {
		t.Fatalf("resolve legacy hash: %v", err)
	}
	if fmt.Sprint(aliases) != fmt.Sprint(wantHashes) {
		t.Fatalf("legacy aliases = %v, want %v", aliases, wantHashes)
	}

	var endpointID, version string
	if err := db.Conn().QueryRow(`SELECT id FROM endpoints WHERE scan_id = ?`, scanID).Scan(&endpointID); err != nil {
		t.Fatal(err)
	}
	if endpointID != appHash {
		t.Fatalf("migrated endpoint id = %q, want app-origin hash %q", endpointID, appHash)
	}
	if err := db.Conn().QueryRow(`SELECT value FROM schema_metadata WHERE key = 'endpoint_identity_version'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != endpointIdentityVersion {
		t.Fatalf("identity version = %q, want %q", version, endpointIdentityVersion)
	}

	_, _, areasJSON, analyzedJSON, _, err := db.GetAppUnderstanding(scanID)
	if err != nil {
		t.Fatal(err)
	}
	var analyzed map[string]string
	if err := json.Unmarshal([]byte(analyzedJSON), &analyzed); err != nil {
		t.Fatal(err)
	}
	if len(analyzed) != 2 || analyzed[appHash] != "orders-template" || analyzed[apiHash] != "orders-template" {
		t.Fatalf("migrated analyzed hashes = %v", analyzed)
	}
	var migratedAreas []struct {
		Endpoints []string `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(areasJSON), &migratedAreas); err != nil {
		t.Fatal(err)
	}
	if len(migratedAreas) != 1 || fmt.Sprint(migratedAreas[0].Endpoints) != fmt.Sprint(wantHashes) {
		t.Fatalf("migrated functional-area endpoints = %+v, want %v", migratedAreas, wantHashes)
	}

	var analyzedCount int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM traffic WHERE scan_id = ? AND is_ai_analyzed = TRUE`, scanID).Scan(&analyzedCount); err != nil {
		t.Fatal(err)
	}
	if analyzedCount != 2 {
		t.Fatalf("migration changed analysis flags: analyzed rows = %d, want 2", analyzedCount)
	}
}

func TestMigrateEndpointIdentityV3SeparatesReadableLongRoutesAndAdvancesAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-v3.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	const (
		applicationURL = "https://app.example.test/rest/admin/application-configuration"
		privacyURL     = "https://app.example.test/rest/admin/privacy-policy-configuration"
		v1Alias       = "legacy-path-only-readable-route"
	)
	// Version 2 treated every 20+ character URL-safe segment as {id}, so
	// these two semantic routes shared this identity.
	v2Raw := "GET|https://app.example.test:443|/rest/admin/{id}|"
	v2Hash := fmt.Sprintf("%x", md5.Sum([]byte(v2Raw)))
	applicationHash := observation.EndpointHash("GET", applicationURL)
	privacyHash := observation.EndpointHash("GET", privacyURL)
	if applicationHash == privacyHash || applicationHash == v2Hash || privacyHash == v2Hash {
		t.Fatal("test fixtures do not distinguish v2 from v3 identities")
	}

	if _, err := db.Conn().Exec(`
		UPDATE schema_metadata SET value = '2' WHERE key = 'endpoint_identity_version'`); err != nil {
		db.Close()
		t.Fatalf("set v2 identity marker: %v", err)
	}
	if _, err := db.Conn().Exec(`
		INSERT INTO traffic(
			scan_id, method, url, host, path, request_headers,
			status_code, response_headers, endpoint_hash)
		VALUES
			(?, 'GET', ?, 'app.example.test', '/rest/admin/application-configuration', '{}', 200, '{}', ?),
			(?, 'GET', ?, 'app.example.test', '/rest/admin/privacy-policy-configuration', '{}', 200, '{}', ?)`,
		scanID, applicationURL, v2Hash,
		scanID, privacyURL, v2Hash); err != nil {
		db.Close()
		t.Fatalf("seed v2 traffic: %v", err)
	}
	if _, err := db.Conn().Exec(`
		INSERT INTO endpoints(id, scan_id, method, url_pattern)
		VALUES (?, ?, 'GET', ?)`, v2Hash, scanID, applicationURL); err != nil {
		db.Close()
		t.Fatalf("seed v2 endpoint: %v", err)
	}
	if _, err := db.Conn().Exec(`
		INSERT INTO endpoint_identity_aliases(scan_id, legacy_hash, endpoint_hash, origin)
		VALUES (?, ?, ?, 'https://app.example.test:443')`, scanID, v1Alias, v2Hash); err != nil {
		db.Close()
		t.Fatalf("seed v1 alias: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(path)
	if err != nil {
		t.Fatalf("migrate identity v3: %v", err)
	}
	defer db.Close()

	rows, err := db.Conn().Query(`
		SELECT DISTINCT endpoint_hash FROM traffic WHERE scan_id = ? ORDER BY endpoint_hash`, scanID)
	if err != nil {
		t.Fatal(err)
	}
	var gotHashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			t.Fatal(err)
		}
		gotHashes = append(gotHashes, hash)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	wantHashes := []string{applicationHash, privacyHash}
	sort.Strings(wantHashes)
	if fmt.Sprint(gotHashes) != fmt.Sprint(wantHashes) {
		t.Fatalf("migrated hashes = %v, want %v", gotHashes, wantHashes)
	}

	for _, ref := range []string{v2Hash, v1Alias} {
		resolved, err := db.ResolveEndpointHashes(scanID, ref)
		if err != nil {
			t.Fatalf("resolve %q: %v", ref, err)
		}
		if fmt.Sprint(resolved) != fmt.Sprint(wantHashes) {
			t.Fatalf("resolve %q = %v, want %v", ref, resolved, wantHashes)
		}
	}

	var endpointID, version string
	if err := db.Conn().QueryRow(`SELECT id FROM endpoints WHERE scan_id = ?`, scanID).Scan(&endpointID); err != nil {
		t.Fatal(err)
	}
	if endpointID != applicationHash {
		t.Fatalf("migrated endpoint ID = %q, want %q", endpointID, applicationHash)
	}
	if err := db.Conn().QueryRow(`SELECT value FROM schema_metadata WHERE key = 'endpoint_identity_version'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != endpointIdentityVersion {
		t.Fatalf("identity version = %q, want %q", version, endpointIdentityVersion)
	}
}

func TestResolveEndpointHashesUsesScanScopedProfileSample(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "resolve-profile.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanA, _ := db.CreateScan("https://a.example.test", `{}`)
	scanB, _ := db.CreateScan("https://b.example.test", `{}`)
	const profileID = "GET /orders/{id}"
	urlA := "https://a.example.test/orders/41"
	urlB := "https://b.example.test/orders/99"
	hashA := insertIdentityTestTraffic(t, db, scanA, urlA)
	hashB := insertIdentityTestTraffic(t, db, scanB, urlB)

	if err := db.UpsertProfile(scanA, &types.PageProfile{ID: profileID, URL: urlA, Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanB, &types.PageProfile{ID: profileID, URL: urlB, Method: "GET"}); err != nil {
		t.Fatal(err)
	}

	gotA, err := db.ResolveEndpointHashes(scanA, profileID)
	if err != nil {
		t.Fatal(err)
	}
	gotB, err := db.ResolveEndpointHashes(scanB, profileID)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotA) != 1 || gotA[0] != hashA {
		t.Fatalf("scan A resolved %v, want [%s]", gotA, hashA)
	}
	if len(gotB) != 1 || gotB[0] != hashB {
		t.Fatalf("scan B resolved %v, want [%s]", gotB, hashB)
	}
}

func insertIdentityTestTraffic(t *testing.T, db *DB, scanID int64, rawURL string) string {
	t.Helper()
	entry := &types.TrafficEntry{
		Request: types.CapturedRequest{Method: "GET", URL: rawURL},
		Response: types.CapturedResponse{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(`{"ok":true}`),
		},
	}
	if _, err := db.InsertTraffic(scanID, entry); err != nil {
		t.Fatal(err)
	}
	return entry.EndpointHash
}

func legacyEndpointHash(method, rawURL string) string {
	// These fixtures intentionally mirror v1's method/path/query-key input.
	// Both URLs used by the migration test normalize to this exact value.
	raw := method + "|/orders/{id}|expand"
	return fmt.Sprintf("%x", md5.Sum([]byte(raw)))
}
