package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite connection for scan data persistence.
type DB struct {
	conn            *sql.DB
	path            string
	profileMu       sync.Mutex
	catchAllMu      sync.Mutex
	catchAllIndexes map[int64]catchAllCacheEntry
}

// Open creates or opens a SQLite database at the given path.
//
// We use modernc.org/sqlite (pure Go), whose DSN-pragma syntax is
// `?_pragma=name(value)` — *not* the `?_journal_mode=…&_busy_timeout=…`
// shape that mattn/sqlite uses. Earlier versions of this file used the
// mattn syntax, which modernc silently ignored. The visible symptom was
// SQLITE_BUSY during scan-start whenever the UI was reading the DB at
// the same time the scanner subprocess tried to insert its scan row,
// because the connection was running with rollback-journal mode and a
// 0 ms busy timeout instead of WAL + 5 s.
//
// We also explicitly re-issue the pragmas after open as a belt-and-
// suspenders measure — if the URL parsing ever changes again we still
// get a loud error rather than silent corruption of the locking model.
func Open(path string) (*DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// WAL allows multiple concurrent readers + a single writer without
	// blocking — exactly what we need when the UI keeps a read connection
	// live while the scanner subprocess writes. Re-issue the pragma here so
	// the lock mode is verifiable from runtime (and so we fail loudly if a
	// future driver swap drops DSN-pragma support).
	for _, p := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA synchronous = NORMAL",
	} {
		if _, err := conn.Exec(p); err != nil {
			conn.Close()
			return nil, fmt.Errorf("apply %s: %w", p, err)
		}
	}

	// One connection from the writer side keeps schema migrations and bulk
	// inserts from interleaving. WAL handles the read concurrency on the
	// SQLite side regardless of MaxOpenConns.
	conn.SetMaxOpenConns(1)

	db := &DB{conn: conn, path: path}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := db.migrateTrafficProvenance(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate traffic provenance: %w", err)
	}

	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// Conn returns the underlying sql.DB for advanced queries.
func (db *DB) Conn() *sql.DB {
	return db.conn
}

// Path returns the directory containing the database file.
func (db *DB) Path() string {
	return filepath.Dir(db.path)
}

func (db *DB) migrate() error {
	if _, err := db.conn.Exec(schema); err != nil {
		return err
	}
	columns := []struct {
		table, name, definition string
	}{
		{"page_profiles", "template_id", "TEXT DEFAULT ''"},
		{"page_profiles", "extracted_inputs_json", "TEXT DEFAULT '[]'"},
		{"ai_log", "tokens_in", "INTEGER NOT NULL DEFAULT 0"},
		{"ai_log", "tokens_out", "INTEGER NOT NULL DEFAULT 0"},
		{"ai_log", "duration_ms", "INTEGER NOT NULL DEFAULT 0"},
		{"ai_log", "cost_ucents", "INTEGER NOT NULL DEFAULT 0"},
		{"ai_log", "model_id", "TEXT DEFAULT ''"},
		{"ai_log", "prompt", "TEXT DEFAULT ''"},
		{"ai_log", "response_full", "TEXT DEFAULT ''"},
		{"traffic", "source_agent", "TEXT NOT NULL DEFAULT 'capture'"},
		{"traffic", "source_action_id", "INTEGER NOT NULL DEFAULT 0"},
		{"traffic", "hypothesis_id", "TEXT NOT NULL DEFAULT ''"},
		{"traffic", "relevance_scored", "BOOLEAN NOT NULL DEFAULT FALSE"},
		{"traffic", "response_body_hash", "TEXT NOT NULL DEFAULT ''"},
		{"traffic", "is_interstitial", "BOOLEAN NOT NULL DEFAULT FALSE"},
		{"traffic", "protection_classified", "BOOLEAN NOT NULL DEFAULT FALSE"},
		{"traffic", "protection_vendor", "TEXT NOT NULL DEFAULT ''"},
		{"traffic", "protection_fingerprint", "TEXT NOT NULL DEFAULT ''"},
		{"findings", "vuln_type", "TEXT DEFAULT ''"},
		{"findings", "param_name", "TEXT DEFAULT ''"},
		{"findings", "payload", "TEXT DEFAULT ''"},
		{"findings", "poc_request", "TEXT DEFAULT ''"},
		{"findings", "poc_response", "TEXT DEFAULT ''"},
		{"findings", "steps_to_reproduce", "TEXT DEFAULT ''"},
		{"findings", "impact", "TEXT DEFAULT ''"},
		{"findings", "dedupe_key", "TEXT DEFAULT ''"},
		{"findings", "hypothesis_id", "TEXT DEFAULT ''"},
		{"follow_ups", "emitted_by", "TEXT DEFAULT 'analyzer'"},
		{"follow_ups", "hypothesis_id", "TEXT DEFAULT ''"},
		{"follow_ups", "grounded_in", "TEXT DEFAULT '[]'"},
		{"app_understanding", "recon_json", "TEXT DEFAULT '{}'"},
		{"analysis_priority_movements", "evidence_gain", "INTEGER NOT NULL DEFAULT 0"},
		{"analysis_priority_movements", "impact_json", "TEXT NOT NULL DEFAULT '[]'"},
		{"analysis_learning_checkpoints", "gap_state_json", "TEXT NOT NULL DEFAULT '[]'"},
		{"analysis_priority_movements", "outcome_status", "TEXT NOT NULL DEFAULT ''"},
		{"analysis_priority_movements", "outcome_json", "TEXT NOT NULL DEFAULT '[]'"},
	}
	relevanceAdded := false
	for _, column := range columns {
		added, err := db.ensureColumn(column.table, column.name, column.definition)
		if err != nil {
			return fmt.Errorf("migrate column %s.%s: %w", column.table, column.name, err)
		}
		if column.table == "traffic" && column.name == "relevance_scored" {
			relevanceAdded = added
		}
	}
	if relevanceAdded {
		if _, err := db.conn.Exec(`UPDATE traffic SET relevance_scored = TRUE WHERE relevance_score != 0`); err != nil {
			return fmt.Errorf("backfill relevance scoring state: %w", err)
		}
	}
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_traffic_source_action ON traffic(scan_id, source_action_id) WHERE source_action_id != 0`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_hypothesis ON traffic(scan_id, hypothesis_id) WHERE hypothesis_id != ''`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_analysis_queue ON traffic(scan_id, is_ai_analyzed, is_filtered, is_duplicate, relevance_score DESC, endpoint_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_scan_endpoint ON traffic(scan_id, endpoint_hash, is_filtered, is_duplicate, captured_at)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_scoring_queue ON traffic(scan_id, relevance_scored, is_filtered, is_duplicate, captured_at)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_protection ON traffic(scan_id, is_interstitial, protection_fingerprint) WHERE is_interstitial = TRUE`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedupe ON findings(scan_id, dedupe_key) WHERE dedupe_key != ''`,
		`CREATE INDEX IF NOT EXISTS idx_findings_hypothesis ON findings(scan_id, hypothesis_id) WHERE hypothesis_id != ''`,
		`CREATE INDEX IF NOT EXISTS idx_credential_contexts_origin ON credential_contexts(scan_id, origin_host, id DESC)`,
	}
	for _, stmt := range indexes {
		if _, err := db.conn.Exec(stmt); err != nil {
			return fmt.Errorf("migrate index: %w", err)
		}
	}
	if err := db.migrateFollowUpLeases(); err != nil {
		return fmt.Errorf("migrate follow-up leases: %w", err)
	}
	// Hypotheses PK migration: the initial schema used `id TEXT PRIMARY KEY`
	// alone, which silently cross-contaminated scans because the Strategist
	// reuses stable IDs like "h1"/"h2" across scans. Upgrade to composite
	// PK (scan_id, id). Detect by inspecting pragma_table_info — if only
	// one PK column (pk>0) and it's "id", rebuild the table.
	if err := db.migrateHypothesesCompositePK(); err != nil {
		return fmt.Errorf("migrate hypotheses PK: %w", err)
	}
	// Same bug class on page_profiles — id was TEXT PRIMARY KEY so scans
	// overwrote each other's profiles ("GET /api/Challenges/" in scan 37 got
	// replaced when scan 38 wrote the same id). Discovered during the Juice
	// Shop benchmark iteration when scan_38.profile_count regressed from 11
	// to 5. Migration pattern mirrors migrateHypothesesCompositePK.
	if err := db.migratePageProfilesCompositePK(); err != nil {
		return fmt.Errorf("migrate page_profiles PK: %w", err)
	}
	// Endpoint IDs are stable only inside a scan. The original global id
	// primary key made a later scan silently reuse/overwrite the earlier
	// scan's endpoint row. Rebuild before migrating hash identities so the
	// identity updater can safely rewrite endpoint IDs per scan.
	if err := db.migrateEndpointsCompositePK(); err != nil {
		return fmt.Errorf("migrate endpoints PK: %w", err)
	}
	// Endpoint identity migrations add canonical origin (v2) and conservative
	// opaque-segment detection (v3). Recompute existing rows atomically and
	// retain aliases so historical references keep resolving.
	if err := db.migrateEndpointIdentity(); err != nil {
		return fmt.Errorf("migrate endpoint identity: %w", err)
	}
	if err := db.refreshTrafficResolvedView(); err != nil {
		return fmt.Errorf("migrate traffic body view: %w", err)
	}
	if err := db.backfillProtectionEvidence(); err != nil {
		return fmt.Errorf("migrate protection evidence: %w", err)
	}
	return nil
}

func (db *DB) refreshTrafficResolvedView() error {
	if _, err := db.conn.Exec(`DROP VIEW IF EXISTS traffic_resolved`); err != nil {
		return err
	}
	_, err := db.conn.Exec(`
		CREATE VIEW traffic_resolved AS
		SELECT t.id, t.scan_id, t.method, t.url, t.host, t.path, t.query,
		       t.request_headers, t.request_body, t.status_code, t.response_headers,
		       COALESCE(t.response_body, b.body) AS response_body,
		       t.content_type, t.response_size, t.endpoint_hash,
		       t.source_agent, t.source_action_id, t.hypothesis_id,
		       t.has_params, t.has_input, t.has_file_upload, t.has_auth,
		       t.has_errors, t.is_api, t.relevance_score, t.relevance_scored,
		       t.is_interstitial, t.protection_classified, t.protection_vendor, t.protection_fingerprint,
		       t.is_filtered, t.is_duplicate, t.is_ai_analyzed, t.analysis_batch,
		       t.captured_at, t.response_body_hash
		FROM traffic t
		LEFT JOIN body_blobs b ON b.hash = t.response_body_hash`)
	return err
}

func (db *DB) ensureColumn(table, name, definition string) (bool, error) {
	rows, err := db.conn.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, err
	}
	found := false
	for rows.Next() {
		var cid, notNull, pk int
		var columnName, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultValue, &pk); err != nil {
			rows.Close()
			return false, err
		}
		if columnName == name {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	if found {
		return false, nil
	}
	_, err = db.conn.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, name, definition))
	return err == nil, err
}

// migratePageProfilesCompositePK rebuilds page_profiles with composite
// PRIMARY KEY (scan_id, id). Idempotent — runs once, then no-ops.
func (db *DB) migratePageProfilesCompositePK() error {
	rows, err := db.conn.Query(`SELECT name, pk FROM pragma_table_info('page_profiles') WHERE pk > 0`)
	if err != nil {
		return err
	}
	var pkCols []string
	for rows.Next() {
		var name string
		var pk int
		if err := rows.Scan(&name, &pk); err != nil {
			rows.Close()
			return err
		}
		pkCols = append(pkCols, name)
	}
	rows.Close()
	if len(pkCols) >= 2 {
		return nil // already composite
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Copy all columns including the post-migration ones added via ALTER TABLE
	// (template_id, extracted_inputs_json). SELECT * won't work because we
	// need to ensure column ordering matches the new CREATE, so enumerate.
	stmts := []string{
		`CREATE TABLE page_profiles_new (
			id              TEXT NOT NULL,
			scan_id         INTEGER NOT NULL REFERENCES scans(id),
			url             TEXT NOT NULL,
			method          TEXT DEFAULT '',
			purpose         TEXT DEFAULT '',
			inputs_json     TEXT DEFAULT '[]',
			auth_required   TEXT DEFAULT 'unknown',
			data_exposed    TEXT DEFAULT '[]',
			apis_called     TEXT DEFAULT '[]',
			behaviors       TEXT DEFAULT '[]',
			relationships   TEXT DEFAULT '[]',
			issues          TEXT DEFAULT '[]',
			tech_notes      TEXT DEFAULT '',
			has_input       BOOLEAN NOT NULL DEFAULT FALSE,
			has_file_upload BOOLEAN NOT NULL DEFAULT FALSE,
			has_auth        BOOLEAN NOT NULL DEFAULT FALSE,
			has_errors      BOOLEAN NOT NULL DEFAULT FALSE,
			is_api          BOOLEAN NOT NULL DEFAULT FALSE,
			confidence      REAL NOT NULL DEFAULT 0,
			analysis_count  INTEGER NOT NULL DEFAULT 0,
			created_at      DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at      DATETIME NOT NULL DEFAULT (datetime('now')),
			template_id     TEXT DEFAULT '',
			extracted_inputs_json TEXT DEFAULT '[]',
			PRIMARY KEY (scan_id, id)
		)`,
		`INSERT OR IGNORE INTO page_profiles_new
		 (id, scan_id, url, method, purpose, inputs_json, auth_required,
		  data_exposed, apis_called, behaviors, relationships, issues,
		  tech_notes, has_input, has_file_upload, has_auth, has_errors,
		  is_api, confidence, analysis_count, created_at, updated_at,
		  template_id, extracted_inputs_json)
		 SELECT id, scan_id, url, method, purpose, inputs_json, auth_required,
		        data_exposed, apis_called, behaviors, relationships, issues,
		        tech_notes, has_input, has_file_upload, has_auth, has_errors,
		        is_api, confidence, analysis_count, created_at, updated_at,
		        COALESCE(template_id,''), COALESCE(extracted_inputs_json,'[]')
		 FROM page_profiles`,
		`DROP TABLE page_profiles`,
		`ALTER TABLE page_profiles_new RENAME TO page_profiles`,
		`CREATE INDEX IF NOT EXISTS idx_profiles_scan ON page_profiles(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_profiles_confidence ON page_profiles(confidence)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("migrate page_profiles: %w", err)
		}
	}
	return tx.Commit()
}

// migrateHypothesesCompositePK rebuilds the hypotheses table with a
// composite PRIMARY KEY (scan_id, id) if the old single-column PK is
// detected. Idempotent: a no-op once the new schema is in place.
func (db *DB) migrateHypothesesCompositePK() error {
	// Count PK columns. Old schema: 1 column named "id" with pk=1.
	// New schema: 2 columns ("scan_id" pk=1, "id" pk=2).
	rows, err := db.conn.Query(`SELECT name, pk FROM pragma_table_info('hypotheses') WHERE pk > 0`)
	if err != nil {
		return err
	}
	var pkCols []string
	for rows.Next() {
		var name string
		var pk int
		if err := rows.Scan(&name, &pk); err != nil {
			rows.Close()
			return err
		}
		pkCols = append(pkCols, name)
	}
	rows.Close()
	// Already migrated (or brand-new DB where the schema CREATE already
	// used the composite PK)? Bail out.
	if len(pkCols) >= 2 {
		return nil
	}
	// Old schema detected. Rebuild in a transaction so we don't leave a
	// half-migrated DB if something blows up mid-way.
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmts := []string{
		`CREATE TABLE hypotheses_new (
			id               TEXT NOT NULL,
			scan_id          INTEGER NOT NULL REFERENCES scans(id),
			cycle_id         INTEGER NOT NULL,
			statement        TEXT NOT NULL,
			confidence       REAL NOT NULL DEFAULT 0,
			status           TEXT NOT NULL DEFAULT 'active',
			supporting_evidence TEXT DEFAULT '[]',
			resolved_by      TEXT DEFAULT '',
			notes            TEXT DEFAULT '',
			created_at       DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at       DATETIME NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (scan_id, id)
		)`,
		`INSERT OR IGNORE INTO hypotheses_new
		 (id, scan_id, cycle_id, statement, confidence, status, supporting_evidence, resolved_by, notes, created_at, updated_at)
		 SELECT id, scan_id, cycle_id, statement, confidence, status,
		        COALESCE(supporting_evidence,'[]'), COALESCE(resolved_by,''),
		        COALESCE(notes,''), created_at, updated_at
		 FROM hypotheses`,
		`DROP TABLE hypotheses`,
		`ALTER TABLE hypotheses_new RENAME TO hypotheses`,
		`CREATE INDEX IF NOT EXISTS idx_hypotheses_scan ON hypotheses(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(scan_id, status)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("migrate hypotheses: %w", err)
		}
	}
	return tx.Commit()
}

const schema = `
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    started_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    finished_at DATETIME,
    status      TEXT NOT NULL DEFAULT 'running',
    config_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS body_blobs (
    hash       TEXT PRIMARY KEY,
    body       BLOB NOT NULL,
    size       INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS traffic (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER NOT NULL REFERENCES scans(id),
    -- Request
    method           TEXT NOT NULL,
    url              TEXT NOT NULL,
    host             TEXT NOT NULL,
    path             TEXT NOT NULL,
    query            TEXT DEFAULT '',
    request_headers  TEXT NOT NULL DEFAULT '{}',
    request_body     BLOB,
    -- Response
    status_code      INTEGER NOT NULL,
    response_headers TEXT NOT NULL DEFAULT '{}',
    response_body    BLOB,
	response_body_hash TEXT NOT NULL DEFAULT '',
    content_type     TEXT DEFAULT '',
    response_size    INTEGER DEFAULT 0,
    -- Classification flags
    endpoint_hash    TEXT NOT NULL DEFAULT '',
	-- Provenance: the active agent/action that produced this evidence and
	-- the strategic hypothesis it was intended to test, when applicable.
	source_agent     TEXT NOT NULL DEFAULT 'capture',
	source_action_id INTEGER NOT NULL DEFAULT 0,
	hypothesis_id    TEXT NOT NULL DEFAULT '',
    has_params       BOOLEAN NOT NULL DEFAULT FALSE,
    has_input        BOOLEAN NOT NULL DEFAULT FALSE,
    has_file_upload  BOOLEAN NOT NULL DEFAULT FALSE,
    has_auth         BOOLEAN NOT NULL DEFAULT FALSE,
    has_errors       BOOLEAN NOT NULL DEFAULT FALSE,
    is_api           BOOLEAN NOT NULL DEFAULT FALSE,
	-- Response-aware protection classification is captured once so queue/UI
	-- reads do not repeatedly scan volatile challenge bodies.
	is_interstitial        BOOLEAN NOT NULL DEFAULT FALSE,
	protection_classified  BOOLEAN NOT NULL DEFAULT FALSE,
	protection_vendor      TEXT NOT NULL DEFAULT '',
	protection_fingerprint TEXT NOT NULL DEFAULT '',
    -- Analysis tracking
    relevance_score  REAL DEFAULT 0,
	relevance_scored BOOLEAN NOT NULL DEFAULT FALSE,
    is_filtered      BOOLEAN NOT NULL DEFAULT FALSE,
    is_duplicate     BOOLEAN NOT NULL DEFAULT FALSE,
    is_ai_analyzed   BOOLEAN NOT NULL DEFAULT FALSE,
    analysis_batch   INTEGER,
    captured_at      DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_traffic_scan ON traffic(scan_id);
CREATE INDEX IF NOT EXISTS idx_traffic_endpoint ON traffic(endpoint_hash);
CREATE INDEX IF NOT EXISTS idx_traffic_analyzed ON traffic(is_ai_analyzed);
CREATE INDEX IF NOT EXISTS idx_traffic_filtered ON traffic(is_filtered);
CREATE INDEX IF NOT EXISTS idx_traffic_analysis_queue ON traffic(scan_id, is_ai_analyzed, is_filtered, is_duplicate, relevance_score DESC, endpoint_hash);
CREATE INDEX IF NOT EXISTS idx_traffic_scan_endpoint ON traffic(scan_id, endpoint_hash, is_filtered, is_duplicate, captured_at);

-- analysis_learning_checkpoints records the explainable feedback loop between
-- captured traffic, the current Recon model, and the next small AI batch.
-- These rows are scanner-owned history, not UI projections.
CREATE TABLE IF NOT EXISTS analysis_learning_checkpoints (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans(id),
    sequence          INTEGER NOT NULL,
    model_fingerprint TEXT NOT NULL DEFAULT '',
    focus_json        TEXT NOT NULL DEFAULT '[]',
    candidate_count   INTEGER NOT NULL DEFAULT 0,
    batch_size        INTEGER NOT NULL DEFAULT 0,
    selected_count    INTEGER NOT NULL DEFAULT 0,
    gap_state_json    TEXT NOT NULL DEFAULT '[]',
    created_at        DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(scan_id, sequence)
);

-- Keep every bounded-window candidate so deferral age is real and a low-base
-- application route can eventually receive the reserved fairness slot.
CREATE TABLE IF NOT EXISTS analysis_priority_movements (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    checkpoint_id     INTEGER NOT NULL REFERENCES analysis_learning_checkpoints(id),
    scan_id           INTEGER NOT NULL REFERENCES scans(id),
    endpoint_hash     TEXT NOT NULL,
    evidence_id       INTEGER NOT NULL DEFAULT 0,
    method            TEXT NOT NULL DEFAULT 'GET',
    url               TEXT NOT NULL DEFAULT '',
    path              TEXT NOT NULL DEFAULT '',
    base_score        INTEGER NOT NULL DEFAULT 0,
    learned_boost     INTEGER NOT NULL DEFAULT 0,
    evidence_gain     INTEGER NOT NULL DEFAULT 0,
    aging_boost       INTEGER NOT NULL DEFAULT 0,
    priority_score    INTEGER NOT NULL DEFAULT 0,
    queue_age         INTEGER NOT NULL DEFAULT 0,
    previous_rank     INTEGER NOT NULL DEFAULT 0,
    current_rank      INTEGER NOT NULL DEFAULT 0,
    rank_delta        INTEGER NOT NULL DEFAULT 0,
    selected          BOOLEAN NOT NULL DEFAULT FALSE,
    fairness_lane     BOOLEAN NOT NULL DEFAULT FALSE,
    disposition       TEXT NOT NULL DEFAULT 'analyze',
    reasons_json      TEXT NOT NULL DEFAULT '[]',
    impact_json       TEXT NOT NULL DEFAULT '[]',
    outcome_status    TEXT NOT NULL DEFAULT '',
    outcome_json      TEXT NOT NULL DEFAULT '[]',
    created_at        DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(checkpoint_id, endpoint_hash)
);

CREATE INDEX IF NOT EXISTS idx_analysis_checkpoints_scan ON analysis_learning_checkpoints(scan_id, sequence DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_movements_checkpoint ON analysis_priority_movements(checkpoint_id, current_rank);
CREATE INDEX IF NOT EXISTS idx_analysis_movements_age ON analysis_priority_movements(scan_id, endpoint_hash, selected, disposition);

CREATE TABLE IF NOT EXISTS endpoints (
    id              TEXT NOT NULL,
    scan_id         INTEGER NOT NULL REFERENCES scans(id),
    method          TEXT NOT NULL,
    url_pattern     TEXT NOT NULL,
    params_json     TEXT DEFAULT '[]',
    hit_count       INTEGER NOT NULL DEFAULT 1,
    -- Classification flags
    has_params      BOOLEAN NOT NULL DEFAULT FALSE,
    has_input       BOOLEAN NOT NULL DEFAULT FALSE,
    has_file_upload BOOLEAN NOT NULL DEFAULT FALSE,
    has_auth        BOOLEAN NOT NULL DEFAULT FALSE,
    has_errors      BOOLEAN NOT NULL DEFAULT FALSE,
    is_api          BOOLEAN NOT NULL DEFAULT FALSE,
    -- Analysis tracking
    is_ai_analyzed  BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    last_seen_at    DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (scan_id, id)
);

CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_analyzed ON endpoints(is_ai_analyzed);

-- Legacy endpoint hashes remain resolvable after the origin-aware v2
-- migration. One v1 hash can map to multiple v2 hashes when an old scan saw
-- the same method/path on multiple origins, hence the three-column key.
CREATE TABLE IF NOT EXISTS endpoint_identity_aliases (
    scan_id       INTEGER NOT NULL REFERENCES scans(id),
    legacy_hash   TEXT NOT NULL,
    endpoint_hash TEXT NOT NULL,
    origin        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, legacy_hash, endpoint_hash)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_alias_lookup
    ON endpoint_identity_aliases(scan_id, legacy_hash);

CREATE TABLE IF NOT EXISTS schema_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credential_contexts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id),
    origin_host  TEXT NOT NULL,
    url          TEXT NOT NULL DEFAULT '',
    path         TEXT NOT NULL DEFAULT '',
    headers_json TEXT NOT NULL DEFAULT '{}',
    source       TEXT NOT NULL DEFAULT '',
    created_at   DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS page_profiles (
    -- Composite PK (scan_id, id) — id alone would collide across scans (the
    -- Strategist/Analyzer emit stable ids like "GET /api/Challenges/" every
    -- run, so a second scan would overwrite the first). See migration.
    id              TEXT NOT NULL,
    scan_id         INTEGER NOT NULL REFERENCES scans(id),
    url             TEXT NOT NULL,
    method          TEXT DEFAULT '',
    purpose         TEXT DEFAULT '',
    inputs_json     TEXT DEFAULT '[]',
    auth_required   TEXT DEFAULT 'unknown',
    data_exposed    TEXT DEFAULT '[]',
    apis_called     TEXT DEFAULT '[]',
    behaviors       TEXT DEFAULT '[]',
    relationships   TEXT DEFAULT '[]',
    issues          TEXT DEFAULT '[]',
    tech_notes      TEXT DEFAULT '',
    -- Classification flags
    has_input       BOOLEAN NOT NULL DEFAULT FALSE,
    has_file_upload BOOLEAN NOT NULL DEFAULT FALSE,
    has_auth        BOOLEAN NOT NULL DEFAULT FALSE,
    has_errors      BOOLEAN NOT NULL DEFAULT FALSE,
    is_api          BOOLEAN NOT NULL DEFAULT FALSE,
    -- Analysis tracking
    confidence      REAL NOT NULL DEFAULT 0,
    analysis_count  INTEGER NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at      DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (scan_id, id)
);

CREATE INDEX IF NOT EXISTS idx_profiles_scan ON page_profiles(scan_id);
CREATE INDEX IF NOT EXISTS idx_profiles_confidence ON page_profiles(confidence);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id),
    title        TEXT NOT NULL,
    description  TEXT NOT NULL,
    severity     TEXT NOT NULL,
    confidence   TEXT NOT NULL,
    -- Endpoint references are intentionally logical rather than a SQL FK:
    -- some agents cite a page-profile id ("GET /orders/{id}") while others
    -- cite a persisted endpoint hash. Resolver code handles both shapes.
    endpoint_id  TEXT DEFAULT '',
    traffic_ids  TEXT DEFAULT '[]',
    evidence     TEXT DEFAULT '',
    remediation  TEXT DEFAULT '',
	dedupe_key   TEXT DEFAULT '',
    created_at   DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS ai_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    agent       TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    from_url    TEXT DEFAULT '',
    to_url      TEXT DEFAULT '',
    result      TEXT DEFAULT '',
    tokens_in   INTEGER NOT NULL DEFAULT 0,
    tokens_out  INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    prompt        TEXT DEFAULT '',
    response_full TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ailog_scan ON ai_log(scan_id);
CREATE INDEX IF NOT EXISTS idx_ailog_agent ON ai_log(agent);

CREATE TABLE IF NOT EXISTS app_understanding (
    scan_id              INTEGER PRIMARY KEY REFERENCES scans(id),
    app_type             TEXT DEFAULT '',
    templates_json       TEXT DEFAULT '[]',
    areas_json           TEXT DEFAULT '[]',
    analyzed_hashes_json TEXT DEFAULT '{}',
    summary              TEXT DEFAULT '',
    updated_at           DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS narrations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id),
    agent         TEXT NOT NULL,
    action        TEXT NOT NULL,
    message       TEXT NOT NULL,
    url           TEXT DEFAULT '',
    metadata_json TEXT DEFAULT '{}',
    created_at    DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_narrations_scan ON narrations(scan_id);
CREATE INDEX IF NOT EXISTS idx_narrations_id   ON narrations(id);

-- prompts: interactive checkpoints raised by the scanner for the operator.
-- Each prompt is a "hey, I found a login form / register page / SSO flow,
-- what do you want me to do?" question surfaced to the UI as a notification.
-- The scanner does NOT block waiting on an answer — it continues unauth'd
-- and, if/when the user provides one (via clicking the notification), a
-- background poller in the scanner picks up the answer and acts on it
-- (e.g. running AuthAgent.AttemptDirectLogin with the supplied creds).
-- The 'handled' column flips once the scanner has consumed the answer,
-- so the poller doesn't act twice.
CREATE TABLE IF NOT EXISTS prompts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    kind        TEXT NOT NULL,                 -- 'login_found', 'register_found', …
    payload     TEXT NOT NULL DEFAULT '{}',    -- JSON — prompt-specific details (url, fields, etc.)
    answer      TEXT NOT NULL DEFAULT '',      -- JSON — operator-provided response, empty while pending
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    answered_at DATETIME,                      -- NULL while pending; set when UI posts an answer
    handled     BOOLEAN NOT NULL DEFAULT FALSE -- scanner sets to TRUE after consuming the answer
);
CREATE INDEX IF NOT EXISTS idx_prompts_scan ON prompts(scan_id);
CREATE INDEX IF NOT EXISTS idx_prompts_open ON prompts(scan_id, answered_at);

-- hypotheses: first-class "hunches" emitted by the Sovereign Strategist.
-- Each one is a short claim about the target (e.g. "sequential IDs in
-- /api/orders/{id} suggest IDOR"). Directives cite the hypothesis they're
-- testing via follow_ups.hypothesis_id; as directives resolve, we update
-- the hypothesis status.
CREATE TABLE IF NOT EXISTS hypotheses (
    id               TEXT NOT NULL,           -- "h1", "h2" or uuid-like; stable within a scan
    scan_id          INTEGER NOT NULL REFERENCES scans(id),
    cycle_id         INTEGER NOT NULL,        -- which strategist cycle first emitted it
    statement        TEXT NOT NULL,           -- one-sentence claim
    confidence       REAL NOT NULL DEFAULT 0,
    status           TEXT NOT NULL DEFAULT 'active',  -- active | confirmed | refuted | stale
    supporting_evidence TEXT DEFAULT '[]',    -- JSON array of "endpoint:…", "finding:…"
    resolved_by      TEXT DEFAULT '',         -- finding_id or directive_id that settled it
    notes            TEXT DEFAULT '',
    created_at       DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at       DATETIME NOT NULL DEFAULT (datetime('now')),
    -- Composite PK: the Strategist reuses stable IDs like "h1" across scans.
    -- Scoping the PK to (scan_id, id) prevents cross-scan contamination.
    PRIMARY KEY (scan_id, id)
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_scan ON hypotheses(scan_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(scan_id, status);

-- hypothesis_events: append-only belief history for the Strategy UI. The
-- hypotheses table stores the current state; this table stores how confidence,
-- status, and evidence changed over time.
CREATE TABLE IF NOT EXISTS hypothesis_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id),
    hypothesis_id   TEXT NOT NULL,
    event_type      TEXT NOT NULL,             -- created | revised | status_changed | directive_queued | directive_done
    old_status      TEXT DEFAULT '',
    new_status      TEXT DEFAULT '',
    old_confidence  REAL,
    new_confidence  REAL,
    reason          TEXT DEFAULT '',
    evidence_refs   TEXT DEFAULT '[]',
    related_ref     TEXT DEFAULT '',           -- strategist/cycle-7 | directive:42 | finding:9
    actor           TEXT DEFAULT '',
    created_at      DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hypevents_scan ON hypothesis_events(scan_id, id);
CREATE INDEX IF NOT EXISTS idx_hypevents_hyp ON hypothesis_events(scan_id, hypothesis_id, id);

-- strategist_cycles: one row per Strategist invocation. Captures redacted
-- model output for observability — this is what we render as the "reasoning
-- trace" the pentester uses to trust the tool.
CREATE TABLE IF NOT EXISTS strategist_cycles (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans(id),
    trigger_reason    TEXT NOT NULL DEFAULT 'periodic',   -- periodic | phase_end | event | manual
    model_id          TEXT NOT NULL DEFAULT '',
    world_model_size  INTEGER NOT NULL DEFAULT 0,         -- chars in world-model section of prompt
    raw_output        TEXT DEFAULT '',
    executive_summary TEXT DEFAULT '',
    hypothesis_count  INTEGER NOT NULL DEFAULT 0,
    directive_count   INTEGER NOT NULL DEFAULT 0,
    rejected_count    INTEGER NOT NULL DEFAULT 0,         -- directives dropped for missing grounded_in / invalid action
    tokens_in         INTEGER NOT NULL DEFAULT 0,
    tokens_out        INTEGER NOT NULL DEFAULT 0,
    duration_ms       INTEGER NOT NULL DEFAULT 0,
    cost_ucents       INTEGER NOT NULL DEFAULT 0,
    error             TEXT DEFAULT '',
    created_at        DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_stratcycles_scan ON strategist_cycles(scan_id);

-- asset_hashes: per-scan content-addressed snapshot of HTML/JS assets. One
-- row per (scan, url). Used to detect "what changed since last time we
-- scanned this target" across repeated scans of the same site.
CREATE TABLE IF NOT EXISTS asset_hashes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id),
    url            TEXT NOT NULL,
    host           TEXT NOT NULL DEFAULT '',
    content_hash   TEXT NOT NULL,
    content_type   TEXT NOT NULL DEFAULT '',
    response_size  INTEGER NOT NULL DEFAULT 0,
    captured_at    DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_hashes_unique
    ON asset_hashes(scan_id, url);
CREATE INDEX IF NOT EXISTS idx_asset_hashes_url_host ON asset_hashes(host, url);

-- asset_changes: detected differences between two scans of the same target.
-- One row = "URL X had hash A in scan N and hash B in scan M". The
-- change-detector agent records these and asks the LLM to comment on the
-- security implications of each diff.
CREATE TABLE IF NOT EXISTS asset_changes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id),   -- the current/new scan
    prev_scan_id  INTEGER NOT NULL REFERENCES scans(id),   -- the previous scan we diffed against
    url           TEXT NOT NULL,
    host          TEXT NOT NULL DEFAULT '',
    content_type  TEXT NOT NULL DEFAULT '',
    prev_hash     TEXT NOT NULL,
    new_hash      TEXT NOT NULL,
    prev_size     INTEGER NOT NULL DEFAULT 0,
    new_size      INTEGER NOT NULL DEFAULT 0,
    kind          TEXT NOT NULL DEFAULT 'modified',  -- "modified" | "added" | "removed"
    diff_snippet  TEXT DEFAULT '',                   -- short, bounded preview of the diff
    llm_comment   TEXT DEFAULT '',                   -- LLM's security take on the change
    severity      TEXT DEFAULT 'info',               -- info|low|medium|high|critical — LLM's call
    created_at    DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_changes_unique
    ON asset_changes(scan_id, prev_scan_id, url);
CREATE INDEX IF NOT EXISTS idx_asset_changes_scan ON asset_changes(scan_id);

-- url_discoveries: the discovery graph. Each row is an edge "source URL led
-- us to this target URL via some mechanism". The Referer header is too
-- unreliable for provenance (cross-origin navs strip it, top-level crawler
-- navigations never set it, rel=noreferrer kills it) so we record our own.
--
-- kind values:
--   "seed"         - the scan's starting URL (source_url is '')
--   "html-link"    - <a href> on a crawled page
--   "form-action"  - <form action> on a crawled page
--   "js-route"     - endpoint extracted from JS source
--   "explorer"     - Explorer agent follow-up
--   "navigator"    - LLM-guided navigator click/visit
--   "redirect"     - HTTP 3xx Location header from another URL
CREATE TABLE IF NOT EXISTS url_discoveries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id),
    target_url      TEXT NOT NULL,
    source_url      TEXT DEFAULT '',
    kind            TEXT NOT NULL,
    detail          TEXT DEFAULT '',  -- free-form: anchor text, form field name, JS file path, reason
    found_at        DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_urldisc_scan_target ON url_discoveries(scan_id, target_url);
CREATE INDEX IF NOT EXISTS idx_urldisc_scan_source ON url_discoveries(scan_id, source_url);

-- Prevent duplicate edges (same source→target→kind) from piling up.
CREATE UNIQUE INDEX IF NOT EXISTS idx_urldisc_unique
    ON url_discoveries(scan_id, target_url, source_url, kind);

-- follow_ups: a typed task queue produced by agents (currently the analyzer,
-- later others) and consumed by the Explorer agent. One row = one thing worth
-- investigating. Status transitions: pending -> running -> done|failed|skipped.
CREATE TABLE IF NOT EXISTS follow_ups (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id            INTEGER NOT NULL REFERENCES scans(id),
    source_agent       TEXT NOT NULL DEFAULT 'analyzer',
    source_profile_id  TEXT DEFAULT '',           -- profile the task was born from (if any)
    action             TEXT NOT NULL,             -- "fetch" | "visit" | "probe_param" | "reanalyze"
    url                TEXT DEFAULT '',
    params_json        TEXT DEFAULT '{}',         -- action-specific payload (param name, values, etc.)
    reason             TEXT DEFAULT '',           -- LLM's first-person reason for the task
    priority           INTEGER NOT NULL DEFAULT 0,-- higher = runs sooner
    status             TEXT NOT NULL DEFAULT 'pending',  -- pending, running, done, failed, skipped
    result             TEXT DEFAULT '',           -- short outcome summary (status code, error, etc.)
    dedupe_key         TEXT DEFAULT '',           -- used to prevent the same task being queued twice
    created_at         DATETIME NOT NULL DEFAULT (datetime('now')),
	claimed_at         DATETIME,
	lease_expires_at   DATETIME,
	lease_token        TEXT NOT NULL DEFAULT '',
	attempt_count      INTEGER NOT NULL DEFAULT 0,
    completed_at       DATETIME
);

CREATE INDEX IF NOT EXISTS idx_followups_scan   ON follow_ups(scan_id);
CREATE INDEX IF NOT EXISTS idx_followups_status ON follow_ups(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_followups_dedupe ON follow_ups(scan_id, dedupe_key) WHERE dedupe_key != '';

-- Target Copilot keeps one durable conversation per scan. Turns are stored
-- separately so the model can receive a bounded recent window while the UI
-- can restore the complete operator-visible thread after a refresh.
CREATE TABLE IF NOT EXISTS copilot_threads (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL UNIQUE REFERENCES scans(id),
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS copilot_turns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id       INTEGER NOT NULL REFERENCES copilot_threads(id),
    scan_id          INTEGER NOT NULL REFERENCES scans(id),
    question         TEXT NOT NULL,
    answer           TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'pending', -- pending|awaiting|completed|error
    steps_json       TEXT NOT NULL DEFAULT '[]',
    ui_actions_json  TEXT NOT NULL DEFAULT '[]',
    evidence_json    TEXT NOT NULL DEFAULT '[]',
    pending_json     TEXT NOT NULL DEFAULT '{}',
    resume_state     TEXT NOT NULL DEFAULT '',
    error            TEXT NOT NULL DEFAULT '',
    created_at       DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at       DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_copilot_turns_thread ON copilot_turns(thread_id, id);
CREATE INDEX IF NOT EXISTS idx_copilot_turns_scan ON copilot_turns(scan_id, id);

-- The raw approval token never enters this ledger; only its SHA-256 digest is
-- persisted. Atomic state transition from awaiting to approved/denied makes
-- every reviewed request or directive single-use, including concurrent
-- duplicate resume calls.
CREATE TABLE IF NOT EXISTS copilot_approvals (
    token_hash  TEXT PRIMARY KEY,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    turn_id     INTEGER NOT NULL REFERENCES copilot_turns(id),
    kind        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'awaiting', -- awaiting|approved|denied
    expires_at  DATETIME NOT NULL,
    consumed_at DATETIME,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_copilot_approvals_turn ON copilot_approvals(turn_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_copilot_approvals_one_awaiting
    ON copilot_approvals(turn_id) WHERE status = 'awaiting';
`
