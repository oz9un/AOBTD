package extract

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/pkg/types"
)

// EndpointBundle groups all traffic for a single endpoint_hash into one coherent extraction.
type EndpointBundle struct {
	EndpointHash string  `json:"endpoint_hash"`
	Method       string  `json:"method"`
	URLPattern   string  `json:"url_pattern"`
	TrafficIDs   []int64 `json:"traffic_ids"`
	SampleURL    string  `json:"sample_url"` // one actual URL for context

	// SegmentSamples holds the distinct values observed at each path
	// segment position across the bundle's entries. Only populated for
	// positions the corpus-aware templater couldn't confidently classify
	// (i.e., the ones it marked `{seg}`). Used by the analyzer to decide
	// whether to spend an LLM call refining the template — pairs with
	// SegmentPositions below.
	SegmentSamples [][]string `json:"segment_samples,omitempty"`
	// SegmentPositions are the path-segment indexes (0-based, after the
	// leading slash split) corresponding to each entry in SegmentSamples.
	// Same length as SegmentSamples.
	SegmentPositions []int `json:"segment_positions,omitempty"`

	// URLSegments is the per-position labelling produced by the
	// path-label resolver after refinement. Populated by the analyzer
	// once the resolver returns. The UI uses this to render variable
	// positions as hoverable chips: the user sees `{boutique_id}` in
	// the URL line, hover reveals the label's reason + observed
	// example values.
	//
	// Defined inside extract (rather than imported from pathlabel) to
	// keep extract leaf-level — no LLM-package dependency. Structure
	// is intentionally identical to pathlabel.SegmentLabel so the
	// analyzer's wiring is a 1:1 copy.
	URLSegments []BundleSegmentLabel `json:"url_segments,omitempty"`

	// Request side
	QueryParams    []ParamVariant    `json:"query_params,omitempty"`
	BodyParams     []ParamVariant    `json:"body_params,omitempty"`
	RequestHeaders map[string]string `json:"request_headers,omitempty"`

	// Response side
	StatusCodes     []int             `json:"status_codes"`
	HTMLExtraction  *HTMLExtraction   `json:"html_extraction,omitempty"`
	JSONSchema      *JSONSchema       `json:"json_schema,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`

	// Flags (union across all entries)
	HasInput      bool `json:"has_input"`
	HasAuth       bool `json:"has_auth"`
	HasFileUpload bool `json:"has_file_upload"`
	HasErrors     bool `json:"has_errors"`
	IsAPI         bool `json:"is_api"`

	EntryCount int `json:"entry_count"`
}

// BundleSegmentLabel mirrors pathlabel.SegmentLabel — kept local so
// extract stays free of LLM-layer imports. The analyzer copies fields
// 1:1 from the resolver's response when refining the bundle. The UI
// reads these to render hoverable position chips with example values
// and the LLM's reasoning.
type BundleSegmentLabel struct {
	Position int      `json:"position"`
	Kind     string   `json:"kind"` // "literal" | "variable"
	Label    string   `json:"label"`
	Examples []string `json:"examples,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

// ParamVariant represents a parameter observed across multiple requests.
type ParamVariant struct {
	Name     string   `json:"name"`
	Location string   `json:"location"`           // query, body, path
	Type     string   `json:"type"`               // inferred: string, int, email, etc.
	Examples []string `json:"examples,omitempty"` // up to 3 observed values
	Required bool     `json:"required"`           // present in ALL requests
}

// SecurityRelevantRequestHeaders to extract.
var securityRelevantRequestHeaders = []string{
	"authorization", "cookie", "content-type",
	"x-api-key", "x-auth-token", "x-csrf-token",
	"origin", "referer",
}

// SecurityRelevantResponseHeaders to extract.
var securityRelevantResponseHeaders = []string{
	"content-type", "set-cookie", "location",
	"x-powered-by", "server", "x-frame-options",
	"content-security-policy", "access-control-allow-origin",
	"www-authenticate", "strict-transport-security",
	"x-content-type-options", "x-xss-protection",
}

// BuildEndpointBundle groups traffic entries (all sharing the same endpoint_hash)
// and produces a comprehensive extraction.
// Cap entries at maxEntries to avoid memory pressure (recommended: 20).
func BuildEndpointBundle(entries []types.TrafficEntry, maxEntries int) *EndpointBundle {
	if len(entries) == 0 {
		return nil
	}

	if maxEntries > 0 && len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}

	bundle := &EndpointBundle{
		EndpointHash:    entries[0].EndpointHash,
		Method:          entries[0].Request.Method,
		SampleURL:       entries[0].Request.URL,
		RequestHeaders:  make(map[string]string),
		ResponseHeaders: make(map[string]string),
		EntryCount:      len(entries),
	}

	// Build the URL pattern from the WHOLE corpus, not just the first
	// entry. With multiple aligned entries we know which segments are
	// actually variable (and thus belong as `{id}`/`{seg}`) vs. which
	// are stable literal path components. Single-entry bundles fall back
	// to per-URL regex normalization.
	pattern, samples, positions := buildCorpusTemplate(entries)
	bundle.URLPattern = pattern
	bundle.SegmentSamples = samples
	bundle.SegmentPositions = positions

	// Collect IDs
	for _, e := range entries {
		bundle.TrafficIDs = append(bundle.TrafficIDs, e.ID)
	}

	// Merge data across all entries
	queryParams := newParamCollector()
	bodyParams := newParamCollector()
	statusCodes := make(map[int]bool)
	var largestHTML []byte
	var largestHTMLURL string
	var bestJSON []byte

	for _, entry := range entries {
		// Flags (union)
		if hasAuth(entry.Request.Headers) {
			bundle.HasAuth = true
		}
		if entry.Response.StatusCode >= 400 {
			bundle.HasErrors = true
		}

		statusCodes[entry.Response.StatusCode] = true

		// Collect query params
		if entry.Request.Query != "" {
			params, _ := url.ParseQuery(entry.Request.Query)
			for k, vals := range params {
				if ignoreQueryParamForInput(entry.Request.Path, k, vals, entry.Request.Query) {
					continue
				}
				for _, v := range vals {
					queryParams.Add(k, v, "query")
				}
			}
		}

		// Collect body params
		if len(entry.Request.Body) > 0 {
			ct := strings.ToLower(getHeader(entry.Request.Headers, "content-type"))
			if strings.Contains(ct, "application/json") {
				extractJSONBodyParams(entry.Request.Body, bodyParams)
			} else if strings.Contains(ct, "application/x-www-form-urlencoded") {
				extractFormBodyParams(entry.Request.Body, bodyParams)
			}
		}

		// Collect security-relevant request headers
		for _, h := range securityRelevantRequestHeaders {
			if v := getHeader(entry.Request.Headers, h); v != "" {
				bundle.RequestHeaders[h] = truncateHeaderValue(v)
			}
		}

		// Collect security-relevant response headers
		for _, h := range securityRelevantResponseHeaders {
			if v := getHeader(entry.Response.Headers, h); v != "" {
				bundle.ResponseHeaders[h] = truncateHeaderValue(v)
			}
		}

		// Track largest HTML response for extraction
		ct := strings.ToLower(entry.Response.ContentType)
		if strings.Contains(ct, "text/html") {
			if len(entry.Response.Body) > len(largestHTML) {
				largestHTML = entry.Response.Body
				largestHTMLURL = entry.Request.URL
			}
		}

		// Track a 200 JSON response for schema extraction
		if strings.Contains(ct, "application/json") {
			if entry.Response.StatusCode >= 200 && entry.Response.StatusCode < 300 {
				if bestJSON == nil || len(entry.Response.Body) > len(bestJSON) {
					bestJSON = entry.Response.Body
				}
			} else if bestJSON == nil {
				bestJSON = entry.Response.Body
			}
			bundle.IsAPI = true
		}
	}

	// Build query/body param variants
	bundle.QueryParams = queryParams.Build(len(entries))
	bundle.BodyParams = bodyParams.Build(len(entries))

	// Run HTML extraction on the largest HTML response
	if len(largestHTML) > 0 {
		bundle.HTMLExtraction = ExtractHTML(largestHTML, largestHTMLURL)
		if bundle.HTMLExtraction.TotalInputCount() > 0 {
			bundle.HasInput = true
		}
		for _, f := range bundle.HTMLExtraction.Forms {
			for _, inp := range f.Inputs {
				if inp.Type == "file" {
					bundle.HasFileUpload = true
				}
			}
		}
	}

	// Run JSON schema extraction
	if len(bestJSON) > 0 {
		bundle.JSONSchema = ExtractJSONSchema(bestJSON)
	}

	// Collect status codes
	for code := range statusCodes {
		bundle.StatusCodes = append(bundle.StatusCodes, code)
	}

	// Any observable input — body OR query params — flips HasInput.
	// Earlier this check only fired on BodyParams which meant GET endpoints
	// like `/rest/products/search?q=…` falsely reported `has_input=false`
	// even though `q` is an obvious attack surface (XSS, SQLi).
	if len(bundle.BodyParams) > 0 || len(bundle.QueryParams) > 0 {
		bundle.HasInput = true
	}

	return bundle
}

// InputSignature returns a stable string for template matching.
// Combines HTML input signature + body param names.
func (b *EndpointBundle) InputSignature() string {
	var parts []string

	if b.HTMLExtraction != nil {
		sig := b.HTMLExtraction.InputSignature()
		if sig != "" {
			parts = append(parts, "html:"+sig)
		}
	}

	if b.JSONSchema != nil {
		// Use the shape as part of signature
		if rendered, err := json.Marshal(b.JSONSchema.Shape); err == nil {
			parts = append(parts, "json:"+string(rendered))
		}
	}

	for _, p := range b.BodyParams {
		parts = append(parts, "body:"+p.Name+":"+p.Type)
	}

	sortStrings(parts)
	return strings.Join(parts, ";")
}

// ResponseShapeSignature describes the stable, security-relevant skeleton of
// an HTML response without using page copy or identifiers. Link volume is not
// part of the shape: catalog and taxonomy pages naturally contain different
// numbers of items even when they use the same application surface. Instead we
// retain the distinct classes of routes exposed by the page, so a newly exposed
// auth, admin, API, taxonomy, entity, or external boundary still changes the
// signature. It is deliberately coarse: a match is only a candidate for the
// cheaper template-verification model call, never grounds a semantic claim or
// skips analysis by itself.
func (b *EndpointBundle) ResponseShapeSignature() string {
	if b == nil || b.HTMLExtraction == nil {
		return ""
	}
	html := b.HTMLExtraction
	linkKinds := make(map[string]struct{})
	for _, link := range html.Links {
		linkKinds[responseLinkKind(link)] = struct{}{}
	}
	linkKindNames := make([]string, 0, len(linkKinds))
	for kind := range linkKinds {
		linkKindNames = append(linkKindNames, kind)
	}
	sortStrings(linkKindNames)
	metaNames := make([]string, 0, len(html.MetaTags))
	for _, meta := range html.MetaTags {
		name := strings.ToLower(strings.TrimSpace(meta.Name))
		if name != "" {
			metaNames = append(metaNames, name)
		}
	}
	sortStrings(metaNames)
	return strings.Join([]string{
		"forms:" + shapeCountBucket(len(html.Forms)),
		"inputs:" + shapeCountBucket(html.TotalInputCount()),
		"link-kinds:" + strings.Join(linkKindNames, ","),
		"meta:" + strings.Join(metaNames, ","),
	}, "|")
}

func responseLinkKind(link ExtractedLink) string {
	if link.IsAPI {
		return "api"
	}
	if !link.SameOrigin {
		return "external"
	}
	parsed, err := url.Parse(strings.TrimSpace(link.Href))
	path := strings.ToLower(strings.TrimSpace(link.Href))
	if err == nil && parsed.Path != "" {
		path = strings.ToLower(parsed.Path)
	}
	segments := strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '-' || r == '_' || r == '.'
	})
	for _, segment := range segments {
		switch segment {
		case "login", "logout", "signin", "signout", "signup", "register", "oauth", "session", "account", "accounts":
			return "auth"
		case "admin", "administrator", "management", "manage":
			return "admin"
		}
	}
	for _, segment := range segments {
		switch segment {
		case "tag", "tags", "category", "categories", "catalog", "catalogue":
			return "taxonomy"
		case "author", "authors", "profile", "profiles", "member", "members", "user", "users":
			return "entity"
		}
	}
	return "application"
}

func shapeCountBucket(count int) string {
	switch {
	case count <= 0:
		return "0"
	case count == 1:
		return "1"
	case count <= 3:
		return "2-3"
	case count <= 7:
		return "4-7"
	case count <= 15:
		return "8-15"
	case count <= 31:
		return "16-31"
	case count <= 63:
		return "32-63"
	default:
		return "64+"
	}
}

func ignoreQueryParamForInput(path, name string, values []string, rawQuery string) bool {
	if !looksLikeStaticAsset(path) {
		return false
	}
	// URLs like /app.js?abc123 or /style.css?v=123 are cache/version keys,
	// not user-controlled application input. Keeping them out of
	// QueryParams lets the analyzer skip passive assets instead of spending
	// LLM calls on cache-busted JS/CSS.
	if !strings.Contains(rawQuery, "=") {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case "", "v", "ver", "version", "m", "t", "ts", "time", "build", "hash", "cache", "cachebuster", "cb":
		return true
	}
	if len(values) == 0 {
		return true
	}
	allEmpty := true
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			allEmpty = false
			break
		}
	}
	return allEmpty && len(lower) >= 8 && observation.IsOpaquePathSegment(lower)
}

func looksLikeStaticAsset(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	for _, suffix := range []string{
		".js", ".mjs", ".css", ".map",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
		".woff", ".woff2", ".ttf", ".eot",
		".mp3", ".mp4", ".webm",
	} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// --- paramCollector ---

type paramCollector struct {
	seen  map[string]*paramData
	order []string
}

type paramData struct {
	examples map[string]bool
	location string
	count    int
}

func newParamCollector() *paramCollector {
	return &paramCollector{
		seen: make(map[string]*paramData),
	}
}

func (pc *paramCollector) Add(name, value, location string) {
	if name == "" {
		return
	}
	pd, ok := pc.seen[name]
	if !ok {
		pd = &paramData{
			examples: make(map[string]bool),
			location: location,
		}
		pc.seen[name] = pd
		pc.order = append(pc.order, name)
	}
	pd.count++
	if len(pd.examples) < 3 && len(value) <= 100 {
		pd.examples[value] = true
	}
}

func (pc *paramCollector) Build(totalEntries int) []ParamVariant {
	var result []ParamVariant
	for _, name := range pc.order {
		pd := pc.seen[name]
		var examples []string
		for ex := range pd.examples {
			examples = append(examples, ex)
		}
		pv := ParamVariant{
			Name:     name,
			Location: pd.location,
			Type:     inferParamType(name, examples),
			Examples: examples,
			Required: pd.count >= totalEntries && totalEntries > 0,
		}
		result = append(result, pv)
	}
	return result
}

// --- helpers ---

func extractJSONBodyParams(body []byte, pc *paramCollector) {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return
	}
	flattenJSONParams(parsed, "", pc)
}

func flattenJSONParams(m map[string]any, prefix string, pc *paramCollector) {
	for k, v := range m {
		name := k
		if prefix != "" {
			name = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]any:
			flattenJSONParams(val, name, pc)
		case []any:
			pc.Add(name, "[array]", "body")
		default:
			pc.Add(name, stringify(val), "body")
		}
	}
}

func extractFormBodyParams(body []byte, pc *paramCollector) {
	params, _ := url.ParseQuery(string(body))
	for k, vals := range params {
		for _, v := range vals {
			pc.Add(k, v, "body")
		}
	}
}

func inferParamType(name string, examples []string) string {
	lower := strings.ToLower(name)

	// Name-based inference
	if strings.Contains(lower, "email") || strings.Contains(lower, "mail") {
		return "email"
	}
	if strings.Contains(lower, "password") || strings.Contains(lower, "passwd") {
		return "password"
	}
	if strings.Contains(lower, "token") || strings.Contains(lower, "csrf") {
		return "token"
	}
	if strings.HasSuffix(lower, "_id") || strings.HasSuffix(lower, "id") || lower == "id" {
		return "id"
	}
	if strings.Contains(lower, "url") || strings.Contains(lower, "uri") || strings.Contains(lower, "redirect") {
		return "url"
	}
	if strings.Contains(lower, "file") || strings.Contains(lower, "upload") {
		return "file"
	}
	if strings.Contains(lower, "phone") || strings.Contains(lower, "mobile") || strings.Contains(lower, "tel") {
		return "phone"
	}

	// Value-based inference from examples
	for _, ex := range examples {
		if emailRe.MatchString(ex) {
			return "email"
		}
		if uuidRe.MatchString(ex) {
			return "uuid"
		}
		if urlRe.MatchString(ex) {
			return "url"
		}
	}

	return "string"
}

func stringify(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func hasAuth(headers map[string]string) bool {
	// A browser Cookie header is session state, not proof of an authenticated
	// identity. Public anonymous sessions are extremely common; verified or
	// operator-provided cookie credentials live in the separate auth context.
	for _, h := range []string{"authorization", "x-api-key", "x-auth-token"} {
		if getHeader(headers, h) != "" {
			return true
		}
	}
	return false
}

func getHeader(headers map[string]string, key string) string {
	key = strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == key {
			return v
		}
	}
	return ""
}

func truncateHeaderValue(v string) string {
	if len(v) > 80 {
		return v[:40] + "...{truncated}"
	}
	return v
}

func normalizePathForDisplay(path string) string {
	// Reuse the same normalization patterns as the proxy interceptor
	// Replace numeric IDs, UUIDs, long tokens with placeholders.
	// NOTE: this is the SINGLE-URL fallback used when we don't have a
	// corpus to align (single-observation bundles or bundles whose paths
	// have differing segment counts). Multi-entry bundles go through
	// buildCorpusTemplate, which is corpus-aware and far less aggressive.
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		if observation.IsInvalidPathIdentifier(seg) {
			segments[i] = "{invalid_id}"
		} else if isNumericID(seg) {
			segments[i] = "{id}"
		} else if uuidRe.MatchString(seg) {
			segments[i] = "{id}"
		} else if observation.IsOpaquePathSegment(seg) {
			segments[i] = "{token}"
		}
	}
	return strings.Join(segments, "/")
}

// buildCorpusTemplate produces a URL template by aligning every entry's
// path position-by-position. A position whose value is identical across
// every entry stays literal — this is what makes BFF service names like
// `discovery-storefrontmarketing-marketinggw-service` survive. A position
// that varies is classified:
//
//   - all-numeric values across observations  → `{id}`
//   - all-UUID values                         → `{id}`
//   - everything else                         → `{seg}`  (analyzer may
//     refine this with an LLM)
//
// Returns the template plus, for each `{seg}` position, the distinct
// observed values (capped at 5) and the segment index — both used by the
// analyzer to decide whether to spend an LLM call labelling the position.
//
// Falls back to single-URL normalization when paths can't be aligned
// (different segment counts, single entry, …) so we never regress on the
// case the old code already handled.
func buildCorpusTemplate(entries []types.TrafficEntry) (string, [][]string, []int) {
	if len(entries) == 0 {
		return "", nil, nil
	}
	if len(entries) == 1 {
		return normalizePathForDisplay(entries[0].Request.Path), nil, nil
	}

	first := strings.Split(entries[0].Request.Path, "/")
	segCount := len(first)

	// Collect every entry's segments only if their lengths agree. If even
	// one entry has a different segment count we can't safely align, so
	// fall back to the per-URL normalizer on entry[0].
	all := make([][]string, 0, len(entries))
	all = append(all, first)
	for _, e := range entries[1:] {
		segs := strings.Split(e.Request.Path, "/")
		if len(segs) != segCount {
			return normalizePathForDisplay(entries[0].Request.Path), nil, nil
		}
		all = append(all, segs)
	}

	out := make([]string, segCount)
	var samples [][]string
	var positions []int
	for i := 0; i < segCount; i++ {
		seen := make(map[string]bool, len(all))
		for _, segs := range all {
			seen[segs[i]] = true
		}
		// Empty leading segment (path starts with "/") — preserve.
		if len(seen) == 1 {
			out[i] = first[i]
			continue
		}
		// Position varies across observations. Try regex classifiers
		// first, then fall back to {seg} for the analyzer to refine.
		allNumeric := true
		allUUID := true
		for v := range seen {
			if !isNumericID(v) {
				allNumeric = false
			}
			if !uuidRe.MatchString(v) {
				allUUID = false
			}
		}
		switch {
		case allNumeric:
			out[i] = "{id}"
		case allUUID:
			out[i] = "{id}"
		case len(seen) > 0 && allInvalidPathIdentifiers(seen):
			out[i] = "{invalid_id}"
		default:
			out[i] = "{seg}"
			distinct := make([]string, 0, len(seen))
			for v := range seen {
				distinct = append(distinct, v)
				if len(distinct) >= 5 {
					break
				}
			}
			samples = append(samples, distinct)
			positions = append(positions, i)
		}
	}
	return strings.Join(out, "/"), samples, positions
}

func allInvalidPathIdentifiers(seen map[string]bool) bool {
	for value := range seen {
		if !observation.IsInvalidPathIdentifier(value) {
			return false
		}
	}
	return true
}

func isNumericID(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0 && len(s) <= 10
}
