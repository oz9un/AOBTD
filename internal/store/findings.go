package store

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/pkg/types"
)

// InsertFinding stores a verified finding. When the finding carries a
// HypothesisID and Confidence=="confirmed", the hypothesis is auto-
// transitioned to "confirmed" status inside the same call. This is the
// Verifier-side half of the A2A feedback loop: a specialist agent confirmed
// a vulnerability that a Strategist hypothesis predicted, so the Strategist
// should see that hypothesis resolved on the next cycle.
func (db *DB) InsertFinding(scanID int64, f types.Finding) (int64, error) {
	trafficJSON, _ := json.Marshal(f.TrafficIDs)
	dedupeKey := findingDedupeKey(f)
	insertVerb := "INSERT"
	if dedupeKey != "" {
		// The partial unique index is the concurrency boundary: two agents can
		// confirm the same issue at once and exactly one row wins.
		insertVerb = "INSERT OR IGNORE"
	}
	res, err := db.conn.Exec(fmt.Sprintf(`
		%s INTO findings (
			scan_id, title, description, severity, confidence,
			endpoint_id, traffic_ids, evidence, remediation,
			vuln_type, param_name, payload, poc_request, poc_response,
			steps_to_reproduce, impact, hypothesis_id, dedupe_key
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, insertVerb),
		scanID, f.Title, f.Description, string(f.Severity), string(f.Confidence),
		f.EndpointID, string(trafficJSON), f.Evidence, f.Remediation,
		f.VulnType, f.ParamName, f.Payload, f.PocRequest, f.PocResponse,
		f.StepsToReproduce, f.Impact, f.HypothesisID, dedupeKey,
	)
	if err != nil {
		return 0, fmt.Errorf("insert finding: %w", err)
	}
	id, _ := res.LastInsertId()
	if dedupeKey != "" {
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("inspect finding insert: %w", err)
		}
		if rowsAffected == 0 {
			if err := db.conn.QueryRow(`
				SELECT id FROM findings WHERE scan_id = ? AND dedupe_key = ?`,
				scanID, dedupeKey).Scan(&id); err != nil {
				return 0, fmt.Errorf("find duplicate finding: %w", err)
			}
			if err := db.mergeConfirmedFinding(scanID, id, f); err != nil {
				return 0, err
			}
		}
	}

	// Auto-confirm the originating hypothesis if this finding was driven by
	// a Strategist plan. The hypothesis only transitions if it's still
	// active — SetHypothesisStatus has a CASE guard that preserves terminal
	// states (confirmed/refuted) so re-running here is idempotent.
	if f.HypothesisID != "" && f.Confidence == types.ConfidenceConfirmed {
		resolvedBy := fmt.Sprintf("finding:%d", id)
		if err := db.SetHypothesisStatus(scanID, f.HypothesisID, HypothesisConfirmed, resolvedBy); err != nil {
			// Non-fatal: the finding was already persisted. Just log via return.
			// (we don't have a logger here; caller may inspect the err but
			//  typically doesn't, so keep it swallowed but document why)
			_ = err
		}
	}
	return id, nil
}

// mergeConfirmedFinding enriches the first confirmed row with independent
// confirmation from another agent. It deliberately keeps one operator-facing
// finding while preserving extra traffic, evidence, and reproduction detail.
func (db *DB) mergeConfirmedFinding(scanID, id int64, incoming types.Finding) error {
	var existing types.Finding
	var trafficJSON, severity string
	err := db.conn.QueryRow(`
		SELECT title, description, severity, endpoint_id, traffic_ids, evidence,
		       remediation, COALESCE(vuln_type,''), COALESCE(param_name,''),
		       COALESCE(payload,''), COALESCE(poc_request,''),
		       COALESCE(poc_response,''), COALESCE(steps_to_reproduce,''),
		       COALESCE(impact,''), COALESCE(hypothesis_id,'')
		FROM findings WHERE scan_id = ? AND id = ?`, scanID, id).Scan(
		&existing.Title, &existing.Description, &severity, &existing.EndpointID,
		&trafficJSON, &existing.Evidence, &existing.Remediation, &existing.VulnType,
		&existing.ParamName, &existing.Payload, &existing.PocRequest,
		&existing.PocResponse, &existing.StepsToReproduce, &existing.Impact,
		&existing.HypothesisID,
	)
	if err != nil {
		return fmt.Errorf("load duplicate finding: %w", err)
	}
	existing.Severity = types.Severity(severity)
	_ = json.Unmarshal([]byte(trafficJSON), &existing.TrafficIDs)

	mergedTraffic, _ := json.Marshal(mergeTrafficIDs(existing.TrafficIDs, incoming.TrafficIDs))
	endpointID := preferFindingEndpoint(existing.EndpointID, incoming.EndpointID)
	_, err = db.conn.Exec(`
		UPDATE findings SET
			description = ?, severity = ?, endpoint_id = ?, traffic_ids = ?,
			evidence = ?, remediation = ?, vuln_type = ?, param_name = ?,
			payload = ?, poc_request = ?, poc_response = ?,
			steps_to_reproduce = ?, impact = ?, hypothesis_id = ?
		WHERE scan_id = ? AND id = ?`,
		preferRicherText(existing.Description, incoming.Description),
		string(strongerSeverity(existing.Severity, incoming.Severity)),
		endpointID, string(mergedTraffic),
		mergeFindingEvidence(existing.Evidence, incoming.Evidence),
		preferRicherText(existing.Remediation, incoming.Remediation),
		preferNonEmpty(existing.VulnType, incoming.VulnType),
		preferNonEmpty(existing.ParamName, incoming.ParamName),
		preferRicherText(existing.Payload, incoming.Payload),
		preferRicherText(existing.PocRequest, incoming.PocRequest),
		preferRicherText(existing.PocResponse, incoming.PocResponse),
		preferRicherText(existing.StepsToReproduce, incoming.StepsToReproduce),
		preferRicherText(existing.Impact, incoming.Impact),
		preferNonEmpty(existing.HypothesisID, incoming.HypothesisID),
		scanID, id,
	)
	if err != nil {
		return fmt.Errorf("merge duplicate finding: %w", err)
	}
	return nil
}

var (
	findingMethodPrefix = regexp.MustCompile(`(?i)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+`)
	findingNumericID    = regexp.MustCompile(`^[0-9]+$`)
	findingUUID         = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	findingWhitespace   = regexp.MustCompile(`\s+`)
)

// findingDedupeKey identifies a confirmed vulnerability by security class,
// canonical endpoint, and parameter. Possible hypotheses remain independent:
// two unverified ideas on the same endpoint are useful competing beliefs, not
// duplicates. The resulting hash contains no credentials, payloads, or URLs.
func findingDedupeKey(f types.Finding) string {
	if f.Confidence != types.ConfidenceConfirmed {
		return ""
	}
	kind := canonicalFindingKind(f)
	endpoint := canonicalFindingEndpoint(f.EndpointID)
	if kind == "" {
		kind = canonicalFindingTitle(f.Title)
	}
	if endpoint == "" {
		endpoint = canonicalFindingEndpointFromTitle(f.Title)
	}
	endpoint = canonicalFindingEndpointForKind(kind, endpoint)
	param := canonicalFindingParam(kind, endpoint, f)
	if endpoint == "" {
		// Header findings and other target-wide issues need title identity so
		// unrelated classes with no endpoint do not collapse together.
		endpoint = "title:" + canonicalFindingTitle(f.Title)
	}
	raw := strings.Join([]string{kind, endpoint, param}, "\x00")
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("v1:%x", sum[:])
}

func canonicalFindingEndpointForKind(kind, endpoint string) string {
	if endpoint == "" {
		return endpoint
	}
	switch kind {
	case "idor":
		// IDOR/BOLA findings are about authorization on a resource family.
		// Different agents may confirm the same issue via a collection URL
		// (/api/orders) or an item template (/api/orders/{id}); merge those
		// into one operator-facing finding while query-param IDs remain
		// separated by canonicalFindingParam.
		for strings.HasSuffix(endpoint, "/{id}") {
			endpoint = strings.TrimSuffix(endpoint, "/{id}")
		}
	case "jwt_unsigned":
		// Signature validation is a token-verifier/root-cause failure, not a
		// separate vulnerability for every endpoint that accepts the token.
		// Merge independent acceptance proofs into one richer finding.
		endpoint = "@jwt-validation"
	}
	if endpoint == "" {
		return "/"
	}
	return endpoint
}

func canonicalFindingKind(f types.Finding) string {
	vulnType := strings.ToLower(strings.TrimSpace(f.VulnType))
	vulnType = strings.NewReplacer("-", "_", " ", "_").Replace(vulnType)
	switch vulnType {
	case "sql_injection":
		return "sqli"
	case "broken_object_level_authorization", "broken_object_access_recovered_id", "bola":
		return "idor"
	case "", "other", "unknown":
		title := strings.ToLower(f.Title)
		switch {
		case strings.Contains(title, "business-logic") || strings.Contains(title, "business logic"):
			return "business_logic"
		case strings.Contains(title, "missing security header"):
			return canonicalFindingTitle(f.Title)
		}
		return canonicalFindingTitle(f.Title)
	default:
		return vulnType
	}
}

func canonicalFindingEndpoint(raw string) string {
	raw = strings.TrimSpace(findingMethodPrefix.ReplaceAllString(raw, ""))
	if raw == "" {
		return ""
	}
	if path, ok := absoluteHTTPPath(raw); ok {
		raw = path
	} else if parsed, err := url.Parse(raw); err == nil && parsed.IsAbs() {
		raw = parsed.EscapedPath()
	}
	if cut := strings.IndexAny(raw, "?#"); cut >= 0 {
		raw = raw[:cut]
	}
	raw = strings.TrimRight(raw, "/")
	if raw == "" {
		return "/"
	}
	parts := strings.Split(raw, "/")
	for i, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err == nil {
			part = decoded
		}
		if findingNumericID.MatchString(part) || findingUUID.MatchString(part) || strings.EqualFold(part, "nan") {
			parts[i] = "{id}"
		}
	}
	return strings.ToLower(strings.Join(parts, "/"))
}

func absoluteHTTPPath(raw string) (string, bool) {
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "", false
	}
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 {
		return "", false
	}
	rest := raw[schemeEnd+3:]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return "/", true
	}
	return rest[slash:], true
}

func canonicalFindingParam(kind, endpoint string, f types.Finding) string {
	param := strings.ToLower(strings.TrimSpace(f.ParamName))
	if param == "" {
		param = firstQueryParamName(f.EndpointID)
	}
	title := strings.ToLower(f.Title)
	if kind == "sqli" && (strings.Contains(endpoint, "/login") || strings.Contains(title, "login bypass")) {
		return ""
	}
	return param
}

func canonicalFindingEndpointFromTitle(title string) string {
	for _, field := range strings.Fields(title) {
		candidate := strings.Trim(field, "\"'`()[]<>,.;:")
		if !strings.HasPrefix(candidate, "http://") && !strings.HasPrefix(candidate, "https://") && !strings.HasPrefix(candidate, "/") {
			continue
		}
		if endpoint := canonicalFindingEndpoint(candidate); endpoint != "" {
			return endpoint
		}
	}
	return ""
}

func firstQueryParamName(raw string) string {
	raw = strings.TrimSpace(findingMethodPrefix.ReplaceAllString(raw, ""))
	if raw == "" || !strings.Contains(raw, "?") {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	query := parsed.Query()
	if len(query) == 0 {
		return ""
	}
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, strings.ToLower(strings.TrimSpace(key)))
	}
	sort.Strings(keys)
	return keys[0]
}

func canonicalFindingTitle(title string) string {
	if cut := strings.Index(strings.ToLower(title), " [via "); cut >= 0 {
		title = title[:cut]
	}
	return strings.ToLower(strings.TrimSpace(findingWhitespace.ReplaceAllString(title, " ")))
}

func mergeTrafficIDs(a, b []int64) []int64 {
	seen := make(map[int64]struct{}, len(a)+len(b))
	for _, id := range append(append([]int64(nil), a...), b...) {
		seen[id] = struct{}{}
	}
	merged := make([]int64, 0, len(seen))
	for id := range seen {
		merged = append(merged, id)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i] < merged[j] })
	return merged
}

func preferFindingEndpoint(existing, incoming string) string {
	if existing == "" {
		return incoming
	}
	// A templated endpoint is more meaningful in reports than the concrete
	// malformed or numeric sample that happened to trigger the first agent.
	if strings.Contains(incoming, "{") && !strings.Contains(existing, "{") {
		return incoming
	}
	return existing
}

func preferNonEmpty(existing, incoming string) string {
	if strings.TrimSpace(existing) == "" {
		return incoming
	}
	return existing
}

func preferRicherText(existing, incoming string) string {
	if len(strings.TrimSpace(incoming)) > len(strings.TrimSpace(existing)) {
		return incoming
	}
	return existing
}

func mergeFindingEvidence(existing, incoming string) string {
	existing = strings.TrimSpace(existing)
	incoming = strings.TrimSpace(incoming)
	if incoming == "" || strings.Contains(existing, incoming) {
		return existing
	}
	if existing == "" {
		return incoming
	}
	return existing + "\n\nAdditional independent confirmation:\n" + incoming
}

func strongerSeverity(a, b types.Severity) types.Severity {
	rank := map[types.Severity]int{
		types.SeverityInfo: 1, types.SeverityLow: 2, types.SeverityMedium: 3,
		types.SeverityHigh: 4, types.SeverityCritical: 5,
	}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// ListFindings returns the persisted findings for a scan, sorted the same way
// the UI presents them: confirmed/high-impact issues first. The orchestrator
// uses this at shutdown so the CLI summary reflects verifier/reasoner findings
// that were written directly to SQLite, not only the older in-memory AppModel.
func (db *DB) ListFindings(scanID int64) ([]types.Finding, error) {
	rows, err := db.conn.Query(`
		SELECT id, title, description, severity, confidence,
		       endpoint_id, traffic_ids, evidence, remediation,
		       COALESCE(vuln_type,''), COALESCE(param_name,''), COALESCE(payload,''),
		       COALESCE(poc_request,''), COALESCE(poc_response,''),
		       COALESCE(steps_to_reproduce,''), COALESCE(impact,''),
		       COALESCE(hypothesis_id,''), created_at
		FROM findings WHERE scan_id = ?
		ORDER BY
			CASE confidence WHEN 'confirmed' THEN 0 WHEN 'likely' THEN 1 WHEN 'possible' THEN 2 ELSE 3 END,
			CASE severity
				WHEN 'critical' THEN 0
				WHEN 'high' THEN 1
				WHEN 'medium' THEN 2
				WHEN 'low' THEN 3
				ELSE 4
			END,
			id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var findings []types.Finding
	for rows.Next() {
		var f types.Finding
		var severity, confidence, trafficJSON, createdAt string
		if err := rows.Scan(
			&f.ID, &f.Title, &f.Description, &severity, &confidence,
			&f.EndpointID, &trafficJSON, &f.Evidence, &f.Remediation,
			&f.VulnType, &f.ParamName, &f.Payload, &f.PocRequest, &f.PocResponse,
			&f.StepsToReproduce, &f.Impact, &f.HypothesisID, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		f.Severity = types.Severity(severity)
		f.Confidence = types.Confidence(confidence)
		if trafficJSON != "" {
			_ = json.Unmarshal([]byte(trafficJSON), &f.TrafficIDs)
		}
		if ts, err := parseSQLiteTime(createdAt); err == nil {
			f.CreatedAt = ts
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}
	return findings, nil
}

func parseSQLiteTime(raw string) (time.Time, error) {
	for _, layout := range []string{
		"2006-01-02 15:04:05",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported sqlite time %q", raw)
}

// FindingExists checks if a finding with the same title and endpoint already exists.
func (db *DB) FindingExists(scanID int64, title, endpointID string) bool {
	var count int
	db.conn.QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id = ? AND title = ? AND endpoint_id = ?`,
		scanID, title, endpointID).Scan(&count)
	return count > 0
}
