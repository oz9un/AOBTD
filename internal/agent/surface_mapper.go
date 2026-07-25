package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/store"
)

// SurfaceMapper analyzes captured traffic to build a comprehensive
// attack surface map: parameter relationships, input types, auth boundaries.
type SurfaceMapper struct {
	db     *store.DB
	bus    *Bus
	state  *SharedState
	scanID int64
	logger *slog.Logger
}

// AttackSurface is the complete attack surface analysis.
type AttackSurface struct {
	Inputs          []InputSurface   `json:"inputs"`
	ParamRelations  []ParamRelation  `json:"param_relations"`
	IDORCandidates  []IDORCandidate  `json:"idor_candidates"`
	AuthBoundaries  []AuthBoundary   `json:"auth_boundaries"`
	ReflectedParams []ReflectedParam `json:"reflected_params"`
	Summary         SurfaceSummary   `json:"summary"`
}

// InputSurface describes a single input point and its attack classification.
type InputSurface struct {
	Endpoint   string `json:"endpoint"` // method + path
	ParamName  string `json:"param_name"`
	Location   string `json:"location"`    // query, body, path, header, cookie
	InputType  string `json:"input_type"`  // text, numeric_id, email, file, json, xml, path
	AttackType string `json:"attack_type"` // xss, sqli, idor, traversal, upload, ssti, ssrf
	Example    string `json:"example"`     // observed value
	Confidence string `json:"confidence"`  // high, medium, low
}

// ParamRelation tracks the same parameter appearing across endpoints.
type ParamRelation struct {
	ParamName string   `json:"param_name"`
	Endpoints []string `json:"endpoints"`  // list of endpoints using this param
	ParamType string   `json:"param_type"` // numeric_id, uuid, string, email
	Risk      string   `json:"risk"`       // "same ID used across 5 endpoints - IDOR surface"
}

// IDORCandidate flags an endpoint where IDOR is likely.
type IDORCandidate struct {
	Endpoint    string   `json:"endpoint"`
	ParamName   string   `json:"param_name"`
	Reason      string   `json:"reason"`
	ObservedIDs []string `json:"observed_ids"`
}

// AuthBoundary describes an endpoint's auth requirements.
type AuthBoundary struct {
	Endpoint    string `json:"endpoint"`
	HasAuth     bool   `json:"has_auth"`
	AuthType    string `json:"auth_type"`    // cookie, bearer, api_key, none
	ReturnsData bool   `json:"returns_data"` // returns user-specific data
	Risk        string `json:"risk"`
}

// ReflectedParam notes when a request parameter appears in the response.
type ReflectedParam struct {
	Endpoint  string `json:"endpoint"`
	ParamName string `json:"param_name"`
	Location  string `json:"location"` // where in response: html_body, json_value, header
	Risk      string `json:"risk"`     // "reflected in HTML without encoding - XSS candidate"
}

type SurfaceSummary struct {
	TotalInputs         int `json:"total_inputs"`
	XSSCandidates       int `json:"xss_candidates"`
	IDORCandidates      int `json:"idor_candidates"`
	SQLiCandidates      int `json:"sqli_candidates"`
	TraversalCandidates int `json:"traversal_candidates"`
	UploadEndpoints     int `json:"upload_endpoints"`
	UnauthEndpoints     int `json:"unauth_with_data"`
	SharedParams        int `json:"shared_params"`
}

func NewSurfaceMapper(db *store.DB, bus *Bus, state *SharedState, scanID int64, logger *slog.Logger) *SurfaceMapper {
	return &SurfaceMapper{db: db, bus: bus, state: state, scanID: scanID, logger: logger}
}

func (s *SurfaceMapper) Name() string              { return "surface_mapper" }
func (s *SurfaceMapper) Capabilities() []EventType { return nil }

// Start performs the full attack surface analysis.
func (s *SurfaceMapper) Start(ctx context.Context) error {
	s.logger.Info("surface mapper starting")

	surface := &AttackSurface{}

	// 1. Extract all inputs from traffic
	surface.Inputs = s.extractInputs()
	s.logger.Info("inputs extracted", "count", len(surface.Inputs))

	// 2. Map parameter relationships across endpoints
	surface.ParamRelations = s.mapParamRelations(surface.Inputs)
	s.logger.Info("param relations mapped", "shared_params", len(surface.ParamRelations))

	// 3. Identify IDOR candidates
	surface.IDORCandidates = s.findIDORCandidates(surface.Inputs)
	s.logger.Info("IDOR candidates found", "count", len(surface.IDORCandidates))

	// 4. Map auth boundaries
	surface.AuthBoundaries = s.mapAuthBoundaries()
	s.logger.Info("auth boundaries mapped", "count", len(surface.AuthBoundaries))

	// 5. Find reflected parameters
	surface.ReflectedParams = s.findReflectedParams()
	s.logger.Info("reflected params found", "count", len(surface.ReflectedParams))

	// 6. Build summary
	surface.Summary = s.buildSummary(surface)

	// Store the full attack surface in DB
	s.storeSurface(surface)

	// Log to AI log
	s.db.LogAI(s.scanID, "surface_mapper", "analysis_complete",
		fmt.Sprintf("Inputs: %d, IDOR candidates: %d, XSS candidates: %d, Unauth endpoints with data: %d",
			surface.Summary.TotalInputs, surface.Summary.IDORCandidates,
			surface.Summary.XSSCandidates, surface.Summary.UnauthEndpoints),
		"", "", "")

	s.logger.Info("surface mapping complete",
		"total_inputs", surface.Summary.TotalInputs,
		"idor", surface.Summary.IDORCandidates,
		"xss", surface.Summary.XSSCandidates,
		"unauth_data", surface.Summary.UnauthEndpoints,
	)

	return nil
}

func (s *SurfaceMapper) extractInputs() []InputSurface {
	var inputs []InputSurface

	rows, err := s.db.Conn().Query(`
		SELECT method, path, query, request_body, content_type, url
		FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE
		  AND (query != '' OR LENGTH(request_body) > 0)
		GROUP BY endpoint_hash
		LIMIT 200`, s.scanID)
	if err != nil {
		return inputs
	}
	defer rows.Close()

	type row struct {
		method, path, query, contentType, url string
		body                                  []byte
	}
	var rows2 []row
	for rows.Next() {
		var r row
		rows.Scan(&r.method, &r.path, &r.query, &r.body, &r.contentType, &r.url)
		rows2 = append(rows2, r)
	}
	rows.Close()

	for _, r := range rows2 {
		endpoint := r.method + " " + r.path

		// Parse query params
		if r.query != "" {
			for _, parameter := range parseSurfaceValues(r.query) {
				if ignoreSurfaceQueryParam(r.path, parameter.name, r.query) {
					continue
				}
				inputType, attackType := classifyInput(parameter.name, parameter.value)
				inputs = append(inputs, InputSurface{
					Endpoint: endpoint, ParamName: parameter.name, Location: "query",
					InputType: inputType, AttackType: attackType,
					Example: truncStr(parameter.value, 50), Confidence: "high",
				})
			}
		}

		// Parse body params
		if len(r.body) > 0 {
			ct := strings.ToLower(r.contentType)
			if strings.Contains(ct, "json") {
				// Preserve nested object paths. Authorization-sensitive identifiers
				// commonly live at order.customer.id or items[].productId; treating
				// only the top-level map as input hid those relationships.
				var jsonBody any
				decoder := json.NewDecoder(strings.NewReader(string(r.body)))
				decoder.UseNumber()
				if decoder.Decode(&jsonBody) == nil {
					for _, parameter := range flattenSurfaceJSON(jsonBody, "", 0, 100) {
						inputType, attackType := classifyInput(parameter.name, parameter.value)
						inputs = append(inputs, InputSurface{
							Endpoint: endpoint, ParamName: parameter.name, Location: "body",
							InputType: inputType, AttackType: attackType,
							Example: truncStr(parameter.value, 50), Confidence: "high",
						})
					}
				}
			} else if strings.Contains(ct, "form") {
				for _, parameter := range parseSurfaceValues(string(r.body)) {
					inputType, attackType := classifyInput(parameter.name, parameter.value)
					inputs = append(inputs, InputSurface{
						Endpoint: endpoint, ParamName: parameter.name, Location: "body",
						InputType: inputType, AttackType: attackType,
						Example: truncStr(parameter.value, 50), Confidence: "high",
					})
				}
			}
		}
	}

	return inputs
}

type surfaceValue struct {
	name  string
	value string
}

func parseSurfaceValues(raw string) []surfaceValue {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]surfaceValue, 0, len(keys))
	for _, key := range keys {
		observed := values[key]
		if len(observed) == 0 {
			observed = []string{""}
		}
		for _, value := range observed {
			out = append(out, surfaceValue{name: key, value: value})
		}
	}
	return out
}

func ignoreSurfaceQueryParam(path, name, rawQuery string) bool {
	if !isPassiveStaticResource(strings.ToLower(path)) {
		return false
	}
	if !strings.Contains(rawQuery, "=") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "v", "ver", "version", "t", "ts", "time", "build", "hash", "cache", "cachebuster", "cb":
		return true
	default:
		return false
	}
}

func flattenSurfaceJSON(value any, prefix string, depth, limit int) []surfaceValue {
	if limit <= 0 || depth > 6 {
		return nil
	}
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := make([]surfaceValue, 0)
		for _, key := range keys {
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			remaining := limit - len(out)
			if remaining <= 0 {
				break
			}
			out = append(out, flattenSurfaceJSON(typed[key], name, depth+1, remaining)...)
		}
		return out
	case []any:
		if len(typed) == 0 {
			return nil
		}
		return flattenSurfaceJSON(typed[0], prefix+"[]", depth+1, limit)
	case nil:
		return []surfaceValue{{name: prefix, value: "null"}}
	case string:
		return []surfaceValue{{name: prefix, value: typed}}
	case json.Number:
		return []surfaceValue{{name: prefix, value: typed.String()}}
	case bool:
		return []surfaceValue{{name: prefix, value: fmt.Sprintf("%t", typed)}}
	default:
		return []surfaceValue{{name: prefix, value: fmt.Sprintf("%v", typed)}}
	}
}

func (s *SurfaceMapper) mapParamRelations(inputs []InputSurface) []ParamRelation {
	// Group inputs by param name
	paramEndpoints := make(map[string]map[string]bool) // param -> set of endpoints
	paramTypes := make(map[string]string)

	for _, inp := range inputs {
		if _, ok := paramEndpoints[inp.ParamName]; !ok {
			paramEndpoints[inp.ParamName] = make(map[string]bool)
		}
		paramEndpoints[inp.ParamName][inp.Endpoint] = true
		paramTypes[inp.ParamName] = inp.InputType
	}

	var relations []ParamRelation
	for param, endpoints := range paramEndpoints {
		if len(endpoints) < 2 {
			continue // only interesting if shared across endpoints
		}
		eps := make([]string, 0, len(endpoints))
		for ep := range endpoints {
			eps = append(eps, ep)
		}

		risk := fmt.Sprintf("Parameter '%s' appears in %d endpoints", param, len(eps))
		if paramTypes[param] == "numeric_id" || paramTypes[param] == "uuid" {
			risk += " — potential IDOR surface"
		}

		relations = append(relations, ParamRelation{
			ParamName: param,
			Endpoints: eps,
			ParamType: paramTypes[param],
			Risk:      risk,
		})
	}

	return relations
}

func (s *SurfaceMapper) findIDORCandidates(inputs []InputSurface) []IDORCandidate {
	var candidates []IDORCandidate
	seenCandidate := make(map[string]bool)
	identifierInputs := make(map[string][]string)
	identifierNames := make(map[string]string)
	for _, input := range inputs {
		if input.InputType != "numeric_id" && input.InputType != "uuid" {
			continue
		}
		key := input.Endpoint + "\x00" + input.ParamName
		identifierInputs[key] = append(identifierInputs[key], input.Example)
		identifierNames[key] = input.ParamName
	}
	inputKeys := make([]string, 0, len(identifierInputs))
	for key := range identifierInputs {
		inputKeys = append(inputKeys, key)
	}
	sort.Strings(inputKeys)
	for _, key := range inputKeys {
		parts := strings.SplitN(key, "\x00", 2)
		endpoint := parts[0]
		param := identifierNames[key]
		candidateKey := endpoint + "\x00" + param
		seenCandidate[candidateKey] = true
		candidates = append(candidates, IDORCandidate{
			Endpoint: endpoint, ParamName: param,
			Reason:      fmt.Sprintf("Observed identifier input %q; compare authorization across object owners before changing it.", param),
			ObservedIDs: uniqueStrings(identifierInputs[key], 5),
		})
	}

	rows, err := s.db.Conn().Query(`
		SELECT method, path, query, request_body, url
		FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE
		ORDER BY endpoint_hash, captured_at
		LIMIT 500`, s.scanID)
	if err != nil {
		return candidates
	}
	defer rows.Close()

	type entry struct {
		method, path, query, url string
		body                     []byte
	}
	var entries []entry
	for rows.Next() {
		var e entry
		rows.Scan(&e.method, &e.path, &e.query, &e.body, &e.url)
		entries = append(entries, e)
	}
	rows.Close()

	// Look for sequential numeric IDs in paths
	idInPath := regexp.MustCompile(`/(\d{1,10})(/|$|\?)`)
	endpointIDs := make(map[string][]string) // normalized path -> observed IDs

	for _, e := range entries {
		matches := idInPath.FindAllStringSubmatch(e.path, -1)
		for _, m := range matches {
			normalized := idInPath.ReplaceAllString(e.path, "/{id}$2")
			key := e.method + " " + normalized
			endpointIDs[key] = append(endpointIDs[key], m[1])
		}
	}

	for endpoint, ids := range endpointIDs {
		if len(ids) >= 1 {
			candidateKey := endpoint + "\x00path_id"
			if seenCandidate[candidateKey] {
				continue
			}
			candidates = append(candidates, IDORCandidate{
				Endpoint:    endpoint,
				ParamName:   "path_id",
				Reason:      fmt.Sprintf("Numeric ID in path, %d values observed. Test with different user's IDs.", len(ids)),
				ObservedIDs: uniqueStrings(ids, 5),
			})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Endpoint != candidates[j].Endpoint {
			return candidates[i].Endpoint < candidates[j].Endpoint
		}
		return candidates[i].ParamName < candidates[j].ParamName
	})

	return candidates
}

func (s *SurfaceMapper) mapAuthBoundaries() []AuthBoundary {
	var boundaries []AuthBoundary

	rows, err := s.db.Conn().Query(`
		SELECT method, path,
		       MAX(has_auth) as has_auth,
		       MAX(is_api) as is_api,
		       MAX(CASE WHEN status_code BETWEEN 200 AND 299 THEN response_size ELSE 0 END) as success_size,
		       MAX(COALESCE(content_type,'')) as content_type,
		       MAX(COALESCE(request_headers,'{}')) as request_headers
		FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE
		GROUP BY endpoint_hash
		LIMIT 200`, s.scanID)
	if err != nil {
		return boundaries
	}
	defer rows.Close()

	type row struct {
		method, path, contentType, requestHeaders string
		hasAuth, isAPI                            bool
		successSize                               int64
	}
	var rows2 []row
	for rows.Next() {
		var r row
		rows.Scan(&r.method, &r.path, &r.hasAuth, &r.isAPI, &r.successSize, &r.contentType, &r.requestHeaders)
		rows2 = append(rows2, r)
	}
	rows.Close()

	for _, r := range rows2 {
		if isPassiveStaticResource(strings.ToLower(r.path)) || passiveStaticContentType(r.contentType) {
			continue
		}
		returnsData := (r.isAPI || strings.Contains(strings.ToLower(r.contentType), "json")) && r.successSize > 100
		risk := ""
		if !r.hasAuth && returnsData {
			risk = "API endpoint returns data without authentication"
		}

		boundaries = append(boundaries, AuthBoundary{
			Endpoint:    r.method + " " + r.path,
			HasAuth:     r.hasAuth,
			AuthType:    inferSurfaceAuthType(r.requestHeaders, r.hasAuth),
			ReturnsData: returnsData,
			Risk:        risk,
		})
	}

	return boundaries
}

func inferSurfaceAuthType(headersJSON string, observed bool) string {
	var headers map[string]string
	_ = json.Unmarshal([]byte(headersJSON), &headers)
	for key, value := range headers {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "authorization":
			lower := strings.ToLower(strings.TrimSpace(value))
			switch {
			case strings.HasPrefix(lower, "bearer "):
				return "bearer"
			case strings.HasPrefix(lower, "basic "):
				return "basic"
			default:
				return "authorization"
			}
		case "x-api-key", "api-key":
			return "api_key"
		case "x-auth-token":
			return "token"
		case "cookie":
			return "cookie"
		}
	}
	if observed {
		return "observed"
	}
	return "none"
}

func passiveStaticContentType(raw string) bool {
	lower := strings.ToLower(raw)
	for _, prefix := range []string{"text/css", "text/javascript", "application/javascript", "image/", "font/", "audio/", "video/"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func (s *SurfaceMapper) findReflectedParams() []ReflectedParam {
	var reflected []ReflectedParam

	rows, err := s.db.Conn().Query(`
		SELECT method, path, query, response_body, content_type
		FROM traffic_resolved
		WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE
		  AND query != '' AND LENGTH(response_body) > 0
		  AND content_type LIKE '%html%'
		LIMIT 100`, s.scanID)
	if err != nil {
		return reflected
	}
	defer rows.Close()

	type row struct {
		method, path, query, contentType string
		body                             []byte
	}
	var rows2 []row
	for rows.Next() {
		var r row
		rows.Scan(&r.method, &r.path, &r.query, &r.body, &r.contentType)
		rows2 = append(rows2, r)
	}
	rows.Close()

	for _, r := range rows2 {
		responseStr := string(r.body)
		for _, part := range strings.Split(r.query, "&") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) < 2 || len(kv[1]) < 3 {
				continue
			}
			value := kv[1]
			if strings.Contains(responseStr, value) {
				reflected = append(reflected, ReflectedParam{
					Endpoint:  r.method + " " + r.path,
					ParamName: kv[0],
					Location:  "html_body",
					Risk:      fmt.Sprintf("Parameter '%s' value reflected in HTML response — XSS candidate", kv[0]),
				})
			}
		}
	}

	return reflected
}

func (s *SurfaceMapper) buildSummary(surface *AttackSurface) SurfaceSummary {
	sum := SurfaceSummary{
		TotalInputs:    len(surface.Inputs),
		IDORCandidates: len(surface.IDORCandidates),
		SharedParams:   len(surface.ParamRelations),
	}

	for _, inp := range surface.Inputs {
		switch inp.AttackType {
		case "xss":
			sum.XSSCandidates++
		case "sqli":
			sum.SQLiCandidates++
		case "traversal":
			sum.TraversalCandidates++
		case "upload":
			sum.UploadEndpoints++
		}
	}

	for _, ab := range surface.AuthBoundaries {
		if !ab.HasAuth && ab.ReturnsData {
			sum.UnauthEndpoints++
		}
	}

	sum.XSSCandidates += len(surface.ReflectedParams)

	return sum
}

func (s *SurfaceMapper) storeSurface(surface *AttackSurface) {
	surfaceJSON, _ := json.Marshal(surface)
	_, err := s.db.Conn().Exec(`
		INSERT INTO page_profiles (id, scan_id, url, purpose, issues, confidence, created_at, updated_at)
		VALUES (?, ?, 'attack_surface_analysis', ?, ?, 0.9, datetime('now'), datetime('now'))
		ON CONFLICT(scan_id, id) DO UPDATE SET purpose=excluded.purpose, issues=excluded.issues, updated_at=datetime('now')`,
		"attack_surface", s.scanID,
		fmt.Sprintf("Attack surface: %d inputs, %d IDOR candidates, %d XSS candidates, %d unauth endpoints with data",
			surface.Summary.TotalInputs, surface.Summary.IDORCandidates,
			surface.Summary.XSSCandidates, surface.Summary.UnauthEndpoints),
		string(surfaceJSON),
	)
	if err != nil && s.logger != nil {
		s.logger.Warn("store attack-surface profile", "error", err)
	}
}

// classifyInput determines the input type and likely attack vector.
func classifyInput(name, value string) (inputType, attackType string) {
	nameLower := strings.ToLower(name)

	// ID-like params → IDOR
	if strings.HasSuffix(nameLower, "_id") || strings.HasSuffix(nameLower, "id") ||
		nameLower == "id" || nameLower == "uid" || nameLower == "userid" {
		if isNumeric(value) {
			return "numeric_id", "idor"
		}
		if isUUID(value) {
			return "uuid", "idor"
		}
	}

	// File-related → upload/traversal
	if strings.Contains(nameLower, "file") || strings.Contains(nameLower, "path") ||
		strings.Contains(nameLower, "dir") || strings.Contains(nameLower, "folder") ||
		strings.Contains(nameLower, "name") && strings.Contains(value, "/") {
		if strings.Contains(value, "/") || strings.Contains(value, "\\") {
			return "path", "traversal"
		}
		return "file", "upload"
	}

	// URL params → SSRF
	if strings.Contains(nameLower, "url") || strings.Contains(nameLower, "uri") ||
		strings.Contains(nameLower, "link") || strings.Contains(nameLower, "redirect") ||
		strings.HasPrefix(value, "http") {
		return "url", "ssrf"
	}

	// Email
	if strings.Contains(nameLower, "email") || strings.Contains(value, "@") {
		return "email", "xss"
	}

	// Search/query params → XSS/SQLi
	if nameLower == "q" || nameLower == "query" || nameLower == "search" ||
		nameLower == "keyword" || nameLower == "term" || nameLower == "filter" {
		return "text", "xss"
	}

	// SQL-like params
	if nameLower == "sort" || nameLower == "order" || nameLower == "orderby" ||
		nameLower == "column" || nameLower == "table" || nameLower == "where" {
		return "text", "sqli"
	}

	// Template-like
	if strings.Contains(value, "{{") || strings.Contains(value, "${") {
		return "template", "ssti"
	}

	// Default: text → XSS
	return "text", "xss"
}

var numericRe = regexp.MustCompile(`^\d+$`)
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isNumeric(s string) bool { return numericRe.MatchString(s) }
func isUUID(s string) bool    { return uuidRe.MatchString(strings.ToLower(s)) }

func uniqueStrings(s []string, max int) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
			if len(result) >= max {
				break
			}
		}
	}
	return result
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
