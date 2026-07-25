package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/pkg/types"
)

// UpsertProfile inserts or updates a page profile in the knowledge base.
//
// Writes all structured fields including Smart-Analysis additions:
// `template_id` (template match identifier) and `extracted_inputs_json`
// (zero-LLM-cost HTML/param-extracted inputs). Those two columns are
// added by migrations in db.go; their INSERT/UPDATE here must stay in
// sync or the writes are silently lost (bug: profiles showed empty
// extracted_inputs even when the analyzer had populated them).
//
// UPDATE behavior for extracted inputs: ExtractedInputs is union-merged,
// not replaced, because the analyzer calls UpsertProfile twice per
// endpoint — once early from storeExtractedInputs (zero-cost) and once
// from mergeProfile after LLM analysis. A bare `excluded.x` overwrite
// would let a later partial write clobber earlier data. We keep the
// longer of the two JSON arrays as a pragmatic "fuller" heuristic.
func (db *DB) UpsertProfile(scanID int64, profile *types.PageProfile) error {
	if profile == nil {
		return fmt.Errorf("upsert profile: nil profile")
	}

	// Historical profile IDs were METHOD + path only. That shape is readable,
	// but it is not unique when one authorized scan covers multiple origins:
	// GET /admin on app.example and api.example would otherwise overwrite one
	// another and allow one origin's response to verify the other's semantics.
	// Serialize this small identity check with the write so concurrent analyzer
	// workers cannot race through the same legacy ID. We retain the compact ID
	// when it is unambiguous and qualify only the colliding origin, preserving
	// compatibility for existing single-origin scans.
	db.profileMu.Lock()
	defer db.profileMu.Unlock()
	if qualified, err := db.originDisambiguatedProfileID(scanID, profile); err != nil {
		return err
	} else if qualified != "" {
		profile.ID = qualified
	}

	inputsJSON, _ := json.Marshal(profile.Inputs)
	dataExposed, _ := json.Marshal(profile.DataExposed)
	apisCalled, _ := json.Marshal(profile.APIsCalled)
	behaviors, _ := json.Marshal(profile.Behaviors)
	relationships, _ := json.Marshal(profile.Relationships)
	issues, _ := json.Marshal(profile.Issues)
	extractedJSON, _ := json.Marshal(profile.ExtractedInputs)
	// Always persist a JSON array (not "null") — schema default is '[]'
	// and downstream readers / the UI expect a parseable array.
	if len(extractedJSON) == 0 || string(extractedJSON) == "null" {
		extractedJSON = []byte("[]")
	}
	clearUnsupportedSemantics := strings.HasSuffix(
		strings.ToLower(strings.TrimSpace(profile.EvidenceState)), "_unverified",
	)

	// ON CONFLICT targets the composite PK (scan_id, id). This used to be
	// ON CONFLICT(id) — which silently allowed one scan's profile to
	// overwrite an earlier scan's profile for the same endpoint, corrupting
	// benchmark comparisons. Fixed alongside the page_profiles composite-PK
	// migration in db.go.
	_, err := db.conn.Exec(`
		INSERT INTO page_profiles (
			id, scan_id, url, method, purpose, inputs_json,
			auth_required, data_exposed, apis_called, behaviors,
			relationships, issues, tech_notes,
			has_input, has_file_upload, has_auth, has_errors, is_api,
			confidence, template_id, extracted_inputs_json,
			analysis_count, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
		ON CONFLICT(scan_id, id) DO UPDATE SET
			purpose = excluded.purpose,
			inputs_json = excluded.inputs_json,
			auth_required = excluded.auth_required,
			data_exposed = excluded.data_exposed,
			apis_called = excluded.apis_called,
			behaviors = excluded.behaviors,
			relationships = excluded.relationships,
			issues = excluded.issues,
			tech_notes = excluded.tech_notes,
			has_input = excluded.has_input,
			has_file_upload = excluded.has_file_upload,
			has_auth = excluded.has_auth,
			has_errors = excluded.has_errors,
			is_api = excluded.is_api,
			confidence = excluded.confidence,
			-- template_id only clobbered when the new write actually has one
			-- (otherwise we'd lose the initial template assignment on the
			-- second write from mergeProfile).
			template_id = CASE
				WHEN ? THEN ''
				WHEN excluded.template_id != '' THEN excluded.template_id
				ELSE template_id
			END,
			-- Keep the richer extracted_inputs set (longer JSON wins).
			extracted_inputs_json = CASE
				WHEN ? THEN '[]'
				WHEN length(excluded.extracted_inputs_json) > length(extracted_inputs_json)
				     THEN excluded.extracted_inputs_json
				ELSE extracted_inputs_json
			END,
			analysis_count = analysis_count + 1,
			updated_at = excluded.updated_at`,
		profile.ID, scanID, profile.URL, profile.Method, profile.Purpose,
		string(inputsJSON), profile.AuthRequired,
		string(dataExposed), string(apisCalled), string(behaviors),
		string(relationships), string(issues), profile.TechNotes,
		profile.HasInput || len(profile.Inputs) > 0 || len(profile.ExtractedInputs) > 0,
		profile.HasFileUpload,
		profile.HasAuth || (profile.AuthRequired != "" && profile.AuthRequired != "none" && profile.AuthRequired != "unknown"),
		profile.HasErrors,
		profile.IsAPI || isAPIEndpoint(profile.Method, profile.URL),
		profile.Confidence,
		profile.TemplateID, string(extractedJSON),
		time.Now(), time.Now(),
		clearUnsupportedSemantics, clearUnsupportedSemantics,
	)
	if err != nil {
		return fmt.Errorf("upsert profile: %w", err)
	}
	return nil
}

func (db *DB) originDisambiguatedProfileID(scanID int64, profile *types.PageProfile) (string, error) {
	id := strings.TrimSpace(profile.ID)
	if id == "" || profile == nil {
		return id, nil
	}
	// These are intentionally scan-wide aggregate artifacts, not route
	// profiles, so they must continue to merge across origins.
	switch id {
	case "attack_surface", "js_discovered_routes":
		return id, nil
	}

	var existingURL string
	err := db.conn.QueryRow(`SELECT url FROM page_profiles WHERE scan_id = ? AND id = ?`, scanID, id).Scan(&existingURL)
	if err == sql.ErrNoRows {
		return id, nil
	}
	if err != nil {
		return "", fmt.Errorf("check profile identity: %w", err)
	}
	existingOrigin := canonicalProfileOrigin(existingURL)
	incomingOrigin := canonicalProfileOrigin(profile.URL)
	if existingOrigin == "" || incomingOrigin == "" || existingOrigin == incomingOrigin {
		return id, nil
	}

	method := strings.ToUpper(strings.TrimSpace(profile.Method))
	pattern := ""
	parts := strings.SplitN(id, " ", 2)
	if len(parts) == 2 {
		if method == "" {
			method = strings.ToUpper(strings.TrimSpace(parts[0]))
		}
		pattern = strings.TrimSpace(parts[1])
	} else if pipe := strings.SplitN(id, "|", 2); len(pipe) == 2 {
		if method == "" {
			method = strings.ToUpper(strings.TrimSpace(pipe[0]))
		}
		pattern = strings.TrimSpace(pipe[1])
	}
	if method == "" {
		method = "GET"
	}
	if strings.HasPrefix(pattern, "/") {
		return method + " " + incomingOrigin + pattern, nil
	}
	// A non-standard model ID still must not collide. Keep it visible while
	// binding the stored identity to the concrete observed origin.
	return method + " " + incomingOrigin + "/#profile=" + url.QueryEscape(id), nil
}

func canonicalProfileOrigin(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if parsed.Scheme == "" || host == "" {
		return ""
	}
	return parsed.Scheme + "://" + host
}

// profileColumns lists every column read by the scanProfile helpers.
// Keep synced with scanProfileRow below. Includes Smart-Analysis columns
// (template_id, extracted_inputs_json) so readers see what the analyzer
// wrote — an earlier version of this file SELECTed only 14 columns and
// silently dropped both extractor outputs on the read path.
const profileColumns = `id, url, method, purpose, inputs_json,
	auth_required, data_exposed, apis_called, behaviors,
	relationships, issues, tech_notes, confidence, updated_at,
	COALESCE(template_id,''), COALESCE(extracted_inputs_json,'[]'),
	has_input, has_file_upload, has_auth, has_errors, is_api`

// scanProfileRow scans one page_profiles row selected via profileColumns.
// Accepts any *sql.Row-compatible Scanner (QueryRow or rows from Query).
type rowScanner interface {
	Scan(dest ...any) error
}

func scanProfileRow(r rowScanner) (types.PageProfile, error) {
	var p types.PageProfile
	var inputsJSON, dataExposed, apisCalled, behaviors, relationships, issues string
	var templateID, extractedInputsJSON string

	err := r.Scan(&p.ID, &p.URL, &p.Method, &p.Purpose, &inputsJSON,
		&p.AuthRequired, &dataExposed, &apisCalled, &behaviors,
		&relationships, &issues, &p.TechNotes, &p.Confidence, &p.LastUpdated,
		&templateID, &extractedInputsJSON,
		&p.HasInput, &p.HasFileUpload, &p.HasAuth, &p.HasErrors, &p.IsAPI)
	if err != nil {
		return p, err
	}

	json.Unmarshal([]byte(inputsJSON), &p.Inputs)
	json.Unmarshal([]byte(dataExposed), &p.DataExposed)
	json.Unmarshal([]byte(apisCalled), &p.APIsCalled)
	json.Unmarshal([]byte(behaviors), &p.Behaviors)
	json.Unmarshal([]byte(relationships), &p.Relationships)
	// Synthetic Knowledge profiles historically stored structured analysis
	// blobs in `issues` (for example an array of JavaScript route objects).
	// Decoding that JSON into []string can leave a slice of empty strings,
	// which the UI then miscounts and renders as blank security issues.
	if err := json.Unmarshal([]byte(issues), &p.Issues); err != nil {
		p.Issues = nil
	}
	json.Unmarshal([]byte(extractedInputsJSON), &p.ExtractedInputs)
	p.TemplateID = templateID

	return p, nil
}

// GetProfile retrieves a page profile by its scan-local ID.
//
// Page profile IDs are only unique within a scan: page_profiles uses the
// composite primary key (scan_id, id). Requiring scanID here prevents a
// duplicate ID from another scan being returned nondeterministically.
func (db *DB) GetProfile(scanID int64, id string) (*types.PageProfile, error) {
	row := db.conn.QueryRow(
		`SELECT `+profileColumns+` FROM page_profiles WHERE scan_id = ? AND id = ?`,
		scanID, id)
	p, err := scanProfileRow(row)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// GetAllProfiles returns all profiles for a scan.
func (db *DB) GetAllProfiles(scanID int64) ([]types.PageProfile, error) {
	rows, err := db.conn.Query(
		`SELECT `+profileColumns+` FROM page_profiles
		 WHERE scan_id = ? ORDER BY confidence ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []types.PageProfile
	for rows.Next() {
		p, err := scanProfileRow(rows)
		if err != nil {
			continue
		}
		profiles = append(profiles, p)
	}
	return profiles, rows.Err()
}

// GetProfilesWithIssues returns profiles that have potential security issues.
func (db *DB) GetProfilesWithIssues(scanID int64) ([]types.PageProfile, error) {
	rows, err := db.conn.Query(
		`SELECT `+profileColumns+` FROM page_profiles
		 WHERE scan_id = ? AND issues != '[]' AND issues != ''
		 ORDER BY confidence DESC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []types.PageProfile
	for rows.Next() {
		p, err := scanProfileRow(rows)
		if err != nil {
			continue
		}
		profiles = append(profiles, p)
	}
	return profiles, rows.Err()
}

// ProfileStats returns summary stats about the knowledge base.
type ProfileStats struct {
	Total      int `json:"total"`
	WithIssues int `json:"with_issues"`
	WithInput  int `json:"with_input"`
	WithAuth   int `json:"with_auth"`
	LowConf    int `json:"low_confidence"`
}

func (db *DB) GetProfileStats(scanID int64) (*ProfileStats, error) {
	var s ProfileStats
	err := db.conn.QueryRow(`
		SELECT
			COUNT(*),
			SUM(CASE WHEN issues != '[]' AND issues != '' THEN 1 ELSE 0 END),
			SUM(CASE WHEN has_input THEN 1 ELSE 0 END),
			SUM(CASE WHEN has_auth THEN 1 ELSE 0 END),
			SUM(CASE WHEN confidence < 0.5 THEN 1 ELSE 0 END)
		FROM page_profiles WHERE scan_id = ?`, scanID,
	).Scan(&s.Total, &s.WithIssues, &s.WithInput, &s.WithAuth, &s.LowConf)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// UpsertAppUnderstanding persists the application understanding model.
func (db *DB) UpsertAppUnderstanding(scanID int64, appType, templatesJSON, areasJSON, analyzedHashesJSON, summary string) error {
	_, err := db.conn.Exec(`
		INSERT INTO app_understanding (scan_id, app_type, templates_json, areas_json, analyzed_hashes_json, summary, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(scan_id) DO UPDATE SET
			app_type = excluded.app_type,
			templates_json = excluded.templates_json,
			areas_json = excluded.areas_json,
			analyzed_hashes_json = excluded.analyzed_hashes_json,
			summary = excluded.summary,
			updated_at = datetime('now')`,
		scanID, appType, templatesJSON, areasJSON, analyzedHashesJSON, summary,
	)
	return err
}

// GetAppUnderstanding loads the application understanding for a scan.
// Returns empty strings if no understanding exists yet.
func (db *DB) GetAppUnderstanding(scanID int64) (appType, templatesJSON, areasJSON, analyzedHashesJSON, summary string, err error) {
	err = db.conn.QueryRow(`
		SELECT app_type, templates_json, areas_json, analyzed_hashes_json, summary
		FROM app_understanding WHERE scan_id = ?`, scanID,
	).Scan(&appType, &templatesJSON, &areasJSON, &analyzedHashesJSON, &summary)
	if err != nil {
		// No understanding yet — return empty defaults
		return "", "[]", "[]", "{}", "", nil
	}
	return
}

// UpsertReconModel stores the richer semantic recon layer separately from the
// legacy app-understanding columns. Keeping it in one versionable JSON document
// lets the model evolve without turning every new recon concept into a schema
// migration, while the scan_id row remains transactionally authoritative.
func (db *DB) UpsertReconModel(scanID int64, reconJSON string) error {
	if reconJSON == "" {
		reconJSON = "{}"
	}
	_, err := db.conn.Exec(`
		INSERT INTO app_understanding (scan_id, recon_json, updated_at)
		VALUES (?, ?, datetime('now'))
		ON CONFLICT(scan_id) DO UPDATE SET
			recon_json = excluded.recon_json,
			updated_at = datetime('now')`, scanID, reconJSON)
	return err
}

func (db *DB) GetReconModel(scanID int64) (string, error) {
	var raw string
	err := db.conn.QueryRow(`
		SELECT COALESCE(recon_json, '{}') FROM app_understanding WHERE scan_id = ?`, scanID).Scan(&raw)
	if err != nil {
		return "{}", nil
	}
	return raw, nil
}

func isAPIEndpoint(method, rawURL string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "DELETE", "PATCH":
		return true
	}
	path := strings.ToLower(strings.TrimSpace(rawURL))
	if parsed, err := url.Parse(path); err == nil && parsed.Path != "" {
		path = strings.ToLower(parsed.Path)
	}
	return strings.HasPrefix(path, "/api/") ||
		strings.HasPrefix(path, "/rest/") ||
		strings.HasSuffix(path, ".json") ||
		strings.Contains(path, "/graphql")
}
