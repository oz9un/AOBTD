// Package discovery provides target-aware probe-target discovery. Helpers
// query captured traffic to find endpoints worth probing so probes operate
// on *observed surface area* instead of hardcoded application-specific
// paths.
//
// Design principle: each discovery function is a single SQL query over the
// traffic table, returning a list of probe targets. The probes themselves
// stay small and focused on the TECHNIQUE — the TARGETS come from here.
//
// Lives outside `internal/agent` so both the Verifier (agent package) and
// the Reasoner (reasoner package) can import it without creating a cycle.
package discovery

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/internal/store"
)

// emailRegex matches email-shaped tokens for username discovery.
// Intentionally permissive — false positives are filtered at callsite.
var emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// emailsInText extracts up to N email-shaped tokens from a text blob.
func emailsInText(s string) []string {
	matches := emailRegex.FindAllString(s, 50)
	// De-dupe preserving order; truncate to a reasonable cap.
	seen := make(map[string]struct{})
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		low := strings.ToLower(m)
		if _, ok := seen[low]; ok {
			continue
		}
		seen[low] = struct{}{}
		out = append(out, m)
		if len(out) >= 20 {
			break
		}
	}
	return out
}

// IsSensitivePath returns true when a URL path looks inherently sensitive
// by shape — VCS directory, backup file extension, env/config filename.
// Generic; no per-application knowledge.
func IsSensitivePath(p string) bool {
	p = strings.ToLower(p)
	// Backup / swap / editor-artifact extensions
	for _, ext := range []string{
		".bak", ".backup", ".old", ".orig", ".swp", ".swo",
		".save", ".tmp", "~", ".kdbx", ".pyc",
	} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	// VCS / credential / framework-config directories
	for _, prefix := range []string{
		"/.git/", "/.svn/", "/.hg/", "/.bzr/",
		"/.env", "/.aws", "/.ssh", "/.npmrc", "/.pypirc",
		"/actuator", "/_debug", "/server-status", "/server-info",
	} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	// Telltale filenames anywhere in the path
	for _, name := range []string{
		"/package.json", "/package-lock.json", "/composer.json",
		"/requirements.txt", "/gemfile", "/go.mod", "/yarn.lock",
		"/config.json", "/config.yaml", "/config.yml",
		"/application.properties", "/application.yml",
		"/appsettings.json", "/web.config",
		"/id_rsa", "/authorized_keys",
	} {
		if strings.HasSuffix(p, name) {
			return true
		}
	}
	return false
}

// DiscoveredEndpoint is a probe target extracted from captured traffic.
type DiscoveredEndpoint struct {
	URL    string
	Method string
	Path   string
	// Params carries query-string parameter names observed on this endpoint.
	Params []string
	// BodyFields carries top-level JSON keys observed in request bodies.
	BodyFields []string
	// RequestContentType helps mutation probes preserve JSON vs form body shape.
	RequestContentType string
	// ResponseContentType helps the probe decide what confirmation signal to use.
	ResponseContentType string
	// ExampleRequestBody is a snippet of a real request body (truncated).
	ExampleRequestBody string
	// AuthHeaders carries replayable auth/session headers for deterministic
	// local probes. Callers must not put this field into LLM prompts.
	AuthHeaders map[string]string
}

// DiscoverLoginEndpoints returns endpoints that look like authentication
// submission. Two discovery strategies combined, both generic:
//
//  1. POST endpoints whose request body references email/username +
//     password fields (JSON or form). Strongest signal — works when the
//     crawler actually submitted a login form.
//
//  2. Endpoints whose URL path shape matches common login conventions
//     (/login, /signin, /oauth/token, …) regardless of method/body.
//     Necessary for SPAs where the crawler never clicks the submit button
//     so the body never lands in the traffic table — but the GET for the
//     page or the OPTIONS pre-flight is still captured.
//
// Returns DiscoveredEndpoint entries with Method forced to POST, since
// that's what every technique in the auth domain submits with.
func DiscoverLoginEndpoints(db *store.DB, scanID int64) ([]DiscoveredEndpoint, error) {
	// Strategy 1: body-fingerprint discovery.
	rows, err := db.Conn().Query(`
		SELECT DISTINCT method, url, path, request_headers, request_body, content_type
		FROM traffic
		WHERE scan_id = ?
		  AND method = 'POST'
		  AND is_filtered = 0
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("discover login endpoints (body): %w", err)
	}
	defer rows.Close()

	seen := make(map[string]bool)
	var out []DiscoveredEndpoint
	for rows.Next() {
		var method, urlStr, path, reqHeaders, respCT string
		var body []byte
		if err := rows.Scan(&method, &urlStr, &path, &reqHeaders, &body, &respCT); err != nil {
			continue
		}
		reqCT := requestContentTypeFromHeaders(reqHeaders)
		bodyLower := strings.ToLower(string(body))
		hasCred := (strings.Contains(bodyLower, "password") ||
			strings.Contains(bodyLower, "passwd")) &&
			(strings.Contains(bodyLower, "email") ||
				strings.Contains(bodyLower, "username") ||
				strings.Contains(bodyLower, "user") ||
				strings.Contains(bodyLower, "login"))
		if !hasCred {
			continue
		}
		key := urlStr
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, DiscoveredEndpoint{
			URL:                 urlStr,
			Method:              "POST",
			Path:                path,
			RequestContentType:  reqCT,
			ResponseContentType: respCT,
			ExampleRequestBody:  truncateStr(string(body), 500),
			BodyFields:          extractRequestFieldNames(body, reqCT),
		})
	}
	rows.Close()

	// Strategy 2: path-shape discovery. Any observed URL (any method) whose
	// path looks like a login route becomes a POST-login candidate.
	rows2, err := db.Conn().Query(`
		SELECT DISTINCT url, path, content_type
		FROM traffic
		WHERE scan_id = ?
		  AND is_filtered = 0
	`, scanID)
	if err != nil {
		return out, nil // return what we have
	}
	defer rows2.Close()

	for rows2.Next() {
		var urlStr, path, ct string
		if err := rows2.Scan(&urlStr, &path, &ct); err != nil {
			continue
		}
		if !LooksLikeLoginPath(path) {
			continue
		}
		if seen[urlStr] {
			continue
		}
		seen[urlStr] = true
		out = append(out, DiscoveredEndpoint{
			URL:                 urlStr,
			Method:              "POST",
			Path:                path,
			ResponseContentType: ct,
		})
	}

	return out, nil
}

// LooksLikeLoginPath uses generic path-shape heuristics to identify
// login / authentication endpoints. Covers common REST / OAuth / SSO
// conventions; deliberately avoids vendor-specific paths.
func LooksLikeLoginPath(p string) bool {
	p = strings.ToLower(p)
	// Exact / suffix match for the usual conventions
	hints := []string{
		"/login", "/signin", "/sign-in", "/log-in", "/logon",
		"/authenticate", "/authentication",
		"/auth/token", "/auth/session",
		"/oauth/token", "/oauth2/token",
		"/api/login", "/api/auth", "/api/signin",
		"/user/login", "/users/login", "/user/signin",
		"/account/login", "/session", "/sessions",
	}
	for _, h := range hints {
		if strings.HasSuffix(p, h) || strings.HasSuffix(p, h+"/") {
			return true
		}
	}
	return false
}

// DiscoverQueryParamEndpoints returns GET endpoints that carry at least
// one query-string parameter. Used by reflected-input / open-redirect
// probes to find parameters worth testing.
func DiscoverQueryParamEndpoints(db *store.DB, scanID int64) ([]DiscoveredEndpoint, error) {
	rows, err := db.Conn().Query(`
		SELECT DISTINCT method, url, path, query, content_type
		FROM traffic
		WHERE scan_id = ?
		  AND method = 'GET'
		  AND query != ''
		  AND is_filtered = 0
		  AND is_duplicate = 0
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("discover query-param endpoints: %w", err)
	}
	defer rows.Close()

	var out []DiscoveredEndpoint
	seen := make(map[string]bool)
	for rows.Next() {
		var method, urlStr, path, query, ct string
		if err := rows.Scan(&method, &urlStr, &path, &query, &ct); err != nil {
			continue
		}
		// Parse the query string into distinct parameter names.
		params := parseQueryParamNames(query)
		if len(params) == 0 {
			continue
		}
		key := method + " " + path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, DiscoveredEndpoint{
			URL:                 urlStr,
			Method:              method,
			Path:                path,
			Params:              params,
			ResponseContentType: ct,
		})
	}
	return out, nil
}

// DiscoverRedirectCandidates returns endpoints where a query parameter's
// VALUE looks URL-like. These are the probe targets for open-redirect
// testing — any endpoint that takes a URL as input is a redirect candidate.
func DiscoverRedirectCandidates(db *store.DB, scanID int64) ([]DiscoveredEndpoint, error) {
	endpoints, err := DiscoverQueryParamEndpoints(db, scanID)
	if err != nil {
		return nil, err
	}
	var out []DiscoveredEndpoint
	for _, ep := range endpoints {
		// Parse the URL properly — earlier revision had a double-SplitN
		// chain that on URLs without `?` passed the entire path to
		// url.ParseQuery and parsed path segments as query params.
		parsedURL, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		parsed := parsedURL.Query()
		urlValued := []string{}
		for k, vs := range parsed {
			for _, v := range vs {
				lv := strings.ToLower(v)
				if strings.HasPrefix(lv, "http://") || strings.HasPrefix(lv, "https://") ||
					strings.HasPrefix(lv, "//") {
					urlValued = append(urlValued, k)
					break
				}
			}
		}
		if len(urlValued) > 0 {
			ep.Params = urlValued
			out = append(out, ep)
		}
	}
	return out, nil
}

// DiscoverStaticFileEndpoints returns endpoints that serve static files
// (responses with Content-Type other than text/html/json, OR paths with
// a file extension). These are the probe targets for null-byte / path-
// traversal probes.
func DiscoverStaticFileEndpoints(db *store.DB, scanID int64) ([]DiscoveredEndpoint, error) {
	rows, err := db.Conn().Query(`
		SELECT DISTINCT method, url, path, content_type
		FROM traffic
		WHERE scan_id = ?
		  AND method = 'GET'
		  AND status_code = 200
		  AND is_filtered = 0
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("discover static file endpoints: %w", err)
	}
	defer rows.Close()

	var out []DiscoveredEndpoint
	seen := make(map[string]bool)
	for rows.Next() {
		var method, urlStr, path, ct string
		if err := rows.Scan(&method, &urlStr, &path, &ct); err != nil {
			continue
		}
		if !looksLikeStaticFile(path, ct) {
			continue
		}
		key := method + " " + path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, DiscoveredEndpoint{
			URL:                 urlStr,
			Method:              method,
			Path:                path,
			ResponseContentType: ct,
		})
	}
	return out, nil
}

// DiscoverAuthenticatedAPIEndpoints returns API endpoints that require auth
// (observed 401 / 403 when accessed unauthenticated, OR has_auth=1 on
// some captured request). These are the probe targets for CORS checks
// and IDOR investigation.
func DiscoverAuthenticatedAPIEndpoints(db *store.DB, scanID int64) ([]DiscoveredEndpoint, error) {
	rows, err := db.Conn().Query(`
		SELECT DISTINCT method, url, path, request_headers, content_type, request_body
		FROM traffic
		WHERE scan_id = ?
		  AND is_api = 1
		  AND (has_auth = 1 OR status_code IN (401, 403))
		  AND is_filtered = 0
		LIMIT 100
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("discover authenticated API endpoints: %w", err)
	}
	defer rows.Close()

	var out []DiscoveredEndpoint
	seen := make(map[string]bool)
	for rows.Next() {
		var method, urlStr, path, reqHeaders, respCT string
		var body []byte
		if err := rows.Scan(&method, &urlStr, &path, &reqHeaders, &respCT, &body); err != nil {
			continue
		}
		reqCT := requestContentTypeFromHeaders(reqHeaders)
		key := method + " " + path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, DiscoveredEndpoint{
			URL:                 urlStr,
			Method:              method,
			Path:                path,
			RequestContentType:  reqCT,
			ResponseContentType: respCT,
			BodyFields:          extractRequestFieldNames(body, reqCT),
			ExampleRequestBody:  truncateStr(string(body), 500),
			AuthHeaders:         store.CredentialHeaders(parseHeaderMap(reqHeaders)),
		})
	}
	return out, nil
}

// DiscoverRecoveredObjectIDEndpoints repairs authenticated owned-object URLs
// whose captured path contains a client-side placeholder failure such as
// /basket/NaN, /orders/undefined, or /api/foo/[object Object].
//
// The recovery is deliberately evidence-driven rather than app-specific:
//   - the malformed endpoint must already be observed in authenticated API
//     traffic;
//   - the segment before the malformed id must look like a user-owned
//     resource family (basket/cart/order/user/account/etc.);
//   - the replacement id must come from the same captured request context
//     (JWT claims or JSON request/response bodies), never from a hardcoded
//     wordlist.
func DiscoverRecoveredObjectIDEndpoints(db *store.DB, scanID int64, limit int) ([]DiscoveredEndpoint, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := db.Conn().Query(`
		SELECT method, url, path, request_headers, request_body, response_body, content_type
		FROM traffic_resolved
		WHERE scan_id = ?
		  AND is_api = 1
		  AND has_auth = 1
		  AND is_filtered = 0
		ORDER BY id DESC
		LIMIT 500
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("discover recovered object endpoints: %w", err)
	}
	defer rows.Close()

	seen := make(map[string]bool)
	var out []DiscoveredEndpoint
	for rows.Next() {
		var method, urlStr, path, reqHeaders, contentType string
		var reqBody, respBody []byte
		if err := rows.Scan(&method, &urlStr, &path, &reqHeaders, &reqBody, &respBody, &contentType); err != nil {
			continue
		}
		recovered := recoverObjectIDEndpoints(method, urlStr, path, reqHeaders, reqBody, respBody, contentType)
		for _, ep := range recovered {
			key := ep.Method + " " + ep.URL
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ep)
			if len(out) >= limit {
				return out, rows.Err()
			}
		}
	}
	return out, rows.Err()
}

// DiscoverLikelyUsernames returns usernames / email addresses observed in
// captured response bodies. Used by weak-credentials / credential-stuffing
// probes: we discover likely accounts from the target's own output (leaked
// email lists, team directories, author metadata in /ftp files) rather
// than hardcoding vendor-specific admin accounts.
func DiscoverLikelyUsernames(db *store.DB, scanID int64, limit int) ([]string, error) {
	rows, err := db.Conn().Query(`
		SELECT response_body
		FROM traffic_resolved
		WHERE scan_id = ?
		  AND response_body IS NOT NULL
		  AND length(response_body) > 0
		  AND is_filtered = 0
		LIMIT 500
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("discover usernames: %w", err)
	}
	defer rows.Close()

	seen := make(map[string]struct{})
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			continue
		}
		for _, email := range emailsInText(string(body)) {
			low := strings.ToLower(email)
			// Filter obvious framework-author noise (we're looking for
			// actual application accounts, not bjoern.kimminich@owasp.org
			// appearing in a framework's package.json).
			if strings.HasSuffix(low, "@owasp.org") ||
				strings.HasSuffix(low, "@npmjs.com") ||
				strings.HasSuffix(low, "@github.com") {
				continue
			}
			seen[low] = struct{}{}
			if len(seen) >= limit {
				break
			}
		}
		if len(seen) >= limit {
			break
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out, nil
}

// ── Helpers ───────────────────────────────────────────────────────────

// looksLikeStaticFile decides whether a URL path + content-type combination
// looks like a served static file. Generic heuristic: path ends in a known
// file extension OR content-type isn't HTML/JSON.
func looksLikeStaticFile(path, contentType string) bool {
	p := strings.ToLower(path)
	// Known static extensions
	exts := []string{
		".md", ".pdf", ".txt", ".log", ".json", ".yaml", ".yml",
		".xml", ".csv", ".zip", ".tar", ".gz", ".bak", ".old",
		".env", ".config", ".properties",
	}
	for _, ext := range exts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	// Fallback: content-type heuristic
	ct := strings.ToLower(contentType)
	if ct != "" && !strings.Contains(ct, "html") && !strings.Contains(ct, "json") {
		return true
	}
	return false
}

// extractRequestFieldNames returns top-level JSON keys or URL-encoded form
// field names. Useful for detecting "this body has email+password fields" or
// choosing a bounded mutation field without full semantic parsing.
func extractRequestFieldNames(body []byte, contentType string) []string {
	if len(body) == 0 {
		return nil
	}
	if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil
		}
		out := make([]string, 0, len(values))
		for k := range values {
			out = append(out, k)
		}
		return out
	}
	// Parse just enough to get the top-level keys.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func requestContentTypeFromHeaders(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	var headers map[string]any
	if err := json.Unmarshal([]byte(raw), &headers); err != nil {
		return ""
	}
	for k, v := range headers {
		if !strings.EqualFold(k, "Content-Type") {
			continue
		}
		switch x := v.(type) {
		case string:
			return x
		case []any:
			if len(x) > 0 {
				if s, ok := x[0].(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

// parseQueryParamNames returns distinct parameter names from a raw query
// string (the `query` column, without the leading `?`).
func parseQueryParamNames(query string) []string {
	if query == "" {
		return nil
	}
	parsed, err := url.ParseQuery(query)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(parsed))
	for k := range parsed {
		out = append(out, k)
	}
	return out
}

type identityClaim struct {
	Key   string
	Value string
}

func recoverObjectIDEndpoints(method, rawURL, fallbackPath, headersJSON string, requestBody, responseBody []byte, contentType string) []DiscoveredEndpoint {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil
	}
	path := parsed.Path
	if path == "" {
		path = fallbackPath
	}
	segments := splitPathSegments(path)
	badIdx := invalidObjectIDSegmentIndex(segments)
	if badIdx < 0 {
		return nil
	}
	resource := nearestResourceSegment(segments, badIdx)
	if resource == "" || !ownedObjectResourceSegment(resource) {
		return nil
	}
	claims := identityClaimsFromRequestContext(headersJSON, requestBody, responseBody)
	ids := recoveredIDsForResource(resource, claims)
	if len(ids) == 0 {
		return nil
	}
	authHeaders := store.CredentialHeaders(parseHeaderMap(headersJSON))
	reqCT := requestContentTypeFromHeaders(headersJSON)
	var out []DiscoveredEndpoint
	for _, id := range ids {
		if id == "" || observation.IsInvalidPathIdentifier(id) {
			continue
		}
		recoveredSegments := append([]string(nil), segments...)
		recoveredSegments[badIdx] = id
		recoveredPath := "/" + strings.Join(recoveredSegments, "/")
		u := *parsed
		u.Path = recoveredPath
		u.RawPath = ""
		out = append(out, DiscoveredEndpoint{
			URL:                 u.String(),
			Method:              firstNonEmpty(method, "GET"),
			Path:                recoveredPath,
			RequestContentType:  reqCT,
			ResponseContentType: contentType,
			AuthHeaders:         cloneStringMap(authHeaders),
		})
		if len(out) >= 3 {
			break
		}
	}
	return out
}

func splitPathSegments(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

func invalidObjectIDSegmentIndex(segments []string) int {
	for i, segment := range segments {
		if observation.IsInvalidPathIdentifier(segment) {
			return i
		}
	}
	return -1
}

func nearestResourceSegment(segments []string, before int) string {
	for i := before - 1; i >= 0; i-- {
		segment := strings.ToLower(strings.TrimSpace(segments[i]))
		segment = strings.Trim(segment, "{}")
		if segment == "" || segment == "api" || segment == "rest" || segment == "graphql" || strings.HasPrefix(segment, "v") && isDigits(segment[1:]) {
			continue
		}
		return segment
	}
	return ""
}

func ownedObjectResourceSegment(segment string) bool {
	segment = strings.ToLower(strings.TrimSpace(segment))
	switch segment {
	case "user", "users", "account", "accounts", "customer", "customers",
		"profile", "profiles", "tenant", "tenants", "team", "teams",
		"organization", "organizations", "org", "orgs", "order", "orders",
		"booking", "bookings", "basket", "baskets", "cart", "carts",
		"address", "addresses", "payment", "payments", "wallet", "wallets",
		"invoice", "invoices", "message", "messages", "file", "files",
		"document", "documents":
		return true
	default:
		return false
	}
}

func identityClaimsFromRequestContext(headersJSON string, requestBody, responseBody []byte) []identityClaim {
	var claims []identityClaim
	for _, token := range jwtTokensInText(headersJSON) {
		claims = append(claims, identityClaimsFromJWT(token)...)
	}
	claims = append(claims, identityClaimsFromJSON(requestBody)...)
	claims = append(claims, identityClaimsFromJSON(responseBody)...)
	return claims
}

func identityClaimsFromJWT(token string) []identityClaim {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := decodeBase64URLSegment(parts[1])
	if err != nil {
		return nil
	}
	return identityClaimsFromJSON(payload)
}

func identityClaimsFromJSON(raw []byte) []identityClaim {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || (raw[0] != '{' && raw[0] != '[') {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	var out []identityClaim
	collectIdentityClaims(v, nil, &out)
	return out
}

func collectIdentityClaims(v any, path []string, out *[]identityClaim) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			collectIdentityClaims(child, append(path, k), out)
		}
	case []any:
		for i, child := range x {
			if i >= 20 {
				return
			}
			collectIdentityClaims(child, path, out)
		}
	case json.Number:
		appendIdentityClaim(path, x.String(), out)
	case float64:
		if x == float64(int64(x)) {
			appendIdentityClaim(path, strconv.FormatInt(int64(x), 10), out)
		}
	case string:
		appendIdentityClaim(path, x, out)
	}
}

func appendIdentityClaim(path []string, raw string, out *[]identityClaim) {
	if len(path) == 0 {
		return
	}
	key := path[len(path)-1]
	value, ok := cleanPositiveIntegerID(raw)
	if !ok {
		return
	}
	*out = append(*out, identityClaim{Key: key, Value: value})
}

func recoveredIDsForResource(resource string, claims []identityClaim) []string {
	var out []string
	addByKey := func(keys []string) {
		for _, want := range keys {
			want = normalizeClaimKey(want)
			for _, claim := range claims {
				if normalizeClaimKey(claim.Key) == want {
					out = appendUniqueString(out, claim.Value)
				}
			}
		}
	}
	addByKey(resourceSpecificIDClaimKeys(resource))
	addByKey([]string{"id", "uid", "sub", "userid", "ownerid", "accountid", "customerid"})
	if len(out) > 6 {
		return out[:6]
	}
	return out
}

func resourceSpecificIDClaimKeys(resource string) []string {
	resource = strings.ToLower(strings.TrimSpace(resource))
	switch resource {
	case "basket", "baskets":
		return []string{"bid", "basket_id", "basketId", "basketID", "cart_id", "cartId", "cartID"}
	case "cart", "carts":
		return []string{"cart_id", "cartId", "cartID", "basket_id", "basketId", "bid"}
	case "user", "users", "profile", "profiles":
		return []string{"id", "user_id", "userId", "uid", "sub"}
	case "account", "accounts":
		return []string{"account_id", "accountId", "id", "user_id", "userId", "sub"}
	case "customer", "customers":
		return []string{"customer_id", "customerId", "id", "user_id", "userId", "sub"}
	case "tenant", "tenants":
		return []string{"tenant_id", "tenantId", "tid", "id"}
	case "team", "teams":
		return []string{"team_id", "teamId", "id"}
	case "organization", "organizations", "org", "orgs":
		return []string{"organization_id", "organizationId", "org_id", "orgId", "id"}
	case "order", "orders":
		return []string{"order_id", "orderId", "oid", "id"}
	case "address", "addresses":
		return []string{"address_id", "addressId", "id", "user_id", "userId"}
	default:
		singular := strings.TrimSuffix(resource, "s")
		return []string{singular + "_id", singular + "Id", singular + "ID", "id"}
	}
}

func jwtTokensInText(s string) []string {
	var out []string
	for {
		i := strings.Index(s, "eyJ")
		if i < 0 {
			return out
		}
		end := i
		for end < len(s) && !jwtDelimiter(s[end]) {
			end++
		}
		token := strings.Trim(s[i:end], `"'`)
		if strings.Count(token, ".") == 2 {
			out = append(out, token)
			if len(out) >= 20 {
				return out
			}
		}
		s = s[end:]
	}
}

func jwtDelimiter(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '"', '\'', ',', ';', ')', ']', '}':
		return true
	default:
		return false
	}
}

func decodeBase64URLSegment(segment string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(segment); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(segment); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(segment)
}

func parseHeaderMap(raw string) map[string]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var headers map[string]any
	if err := json.Unmarshal([]byte(raw), &headers); err != nil {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		switch x := v.(type) {
		case string:
			out[k] = x
		case []any:
			if len(x) > 0 {
				if s, ok := x[0].(string); ok {
					out[k] = s
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cleanPositiveIntegerID(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 18 {
		return "", false
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 || n > 1_000_000_000 {
		return "", false
	}
	return strconv.FormatInt(n, 10), true
}

func normalizeClaimKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	key = strings.ReplaceAll(key, ".", "")
	return key
}

func appendUniqueString(values []string, candidate string) []string {
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// truncateStr shortens a string for log / prompt use. Duplicated rather
// than imported so this package has no agent-package dependency.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
