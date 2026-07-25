package observation

import (
	"bytes"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/ozzyw/aobtd/pkg/types"
)

// RedirectEvidence is the deterministic evidence ceiling for a directly
// requested route. A 3xx proves redirect behavior; it does not prove that the
// route named by the request exists behind the redirect or has the semantics
// suggested by its path.
type RedirectEvidence struct {
	RedirectOnly bool `json:"redirect_only"`
	// PureRedirect distinguishes a literal all-3xx capture set from a route
	// whose only positive evidence is a redirect plus non-content responses
	// (for example 302, then 404). RedirectOnly deliberately covers both: an
	// error, empty success, or generic auth/error shell cannot verify that the
	// requested route has backing application content.
	PureRedirect           bool     `json:"pure_redirect,omitempty"`
	RedirectObserved       bool     `json:"redirect_observed,omitempty"`
	ContentObserved        bool     `json:"content_observed,omitempty"`
	Locations              []string `json:"locations,omitempty"`
	StatusCodes            []int    `json:"status_codes,omitempty"`
	NonContentStatusCodes  []int    `json:"non_content_status_codes,omitempty"`
	EmptySuccessObserved   bool     `json:"empty_success_observed,omitempty"`
	AuthShellObserved      bool     `json:"auth_shell_observed,omitempty"`
	ErrorShellObserved     bool     `json:"error_shell_observed,omitempty"`
	PathPreservingAuthGate bool     `json:"path_preserving_auth_gate,omitempty"`
}

// SummarizeRedirectEvidence classifies direct responses for one endpoint
// family. Only a substantive direct 2xx response lifts a route out of
// redirect-only state. A failed follow-up, an empty success, or an obvious
// authentication/error shell is useful negative evidence, not proof that the
// requested application page exists. This is intentionally conservative: the
// classifier recognizes only strong shell markers and otherwise treats a
// non-empty 2xx response as content.
func SummarizeRedirectEvidence(entries []types.TrafficEntry) RedirectEvidence {
	var result RedirectEvidence
	if len(entries) == 0 {
		return result
	}

	locations := make(map[string]bool)
	statuses := make(map[int]bool)
	nonContentStatuses := make(map[int]bool)
	pureRedirect := true
	pathPreservingAuthGate := false
	for _, entry := range entries {
		status := entry.Response.StatusCode
		statuses[status] = true
		location := redirectHeaderValue(entry.Response.Headers, "Location")
		isRedirect := status >= 300 && status < 400 && status != 304 && strings.TrimSpace(location) != ""
		if !isRedirect {
			pureRedirect = false
		} else {
			result.RedirectObserved = true
			locations[location] = true
			if redirectsThroughPathPreservingAuthGate(entry.Request.URL, entry.Request.Path, location) {
				pathPreservingAuthGate = true
			}
		}

		classification := classifyResponseContent(entry.Response)
		// A password/SSO shell is substantive content when the operator
		// actually requested the canonical login surface. The same shell at
		// /admin, /forgot, or an arbitrary catch-all path is only gate evidence.
		if classification == responseAuthShell && authenticationShellMatchesRequest(entry.Request, entry.Response) {
			classification = responseContent
		}
		switch classification {
		case responseContent:
			result.ContentObserved = true
		case responseEmptySuccess:
			result.EmptySuccessObserved = true
		case responseAuthShell:
			result.AuthShellObserved = true
		case responseErrorShell:
			result.ErrorShellObserved = true
		case responseNonContentStatus:
			nonContentStatuses[status] = true
		}
	}

	for status := range statuses {
		result.StatusCodes = append(result.StatusCodes, status)
	}
	sort.Ints(result.StatusCodes)
	for location := range locations {
		result.Locations = append(result.Locations, location)
	}
	sort.Strings(result.Locations)
	for status := range nonContentStatuses {
		result.NonContentStatusCodes = append(result.NonContentStatusCodes, status)
	}
	sort.Ints(result.NonContentStatusCodes)
	result.PureRedirect = pureRedirect && result.RedirectObserved
	result.RedirectOnly = result.RedirectObserved && !result.ContentObserved
	result.PathPreservingAuthGate = result.RedirectOnly && pathPreservingAuthGate
	return result
}

func authenticationShellMatchesRequest(request types.CapturedRequest, response types.CapturedResponse) bool {
	// Only a directly rendered GET HTML login page is positive page evidence.
	// A POST login response or a JSON 401/error envelope on the same canonical
	// path is authentication behavior, not proof of a readable login page.
	if !strings.EqualFold(strings.TrimSpace(request.Method), http.MethodGet) {
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(response.ContentType))
	if contentType == "" {
		contentType = strings.ToLower(redirectHeaderValue(response.Headers, "Content-Type"))
	}
	if !strings.Contains(contentType, "html") {
		return false
	}
	path := strings.TrimSpace(request.Path)
	if path == "" {
		if parsed, err := url.Parse(strings.TrimSpace(request.URL)); err == nil {
			path = parsed.Path
		}
	}
	path = strings.ToLower(strings.TrimSuffix(normalizeObservedPath(path), "/"))
	switch path {
	case "/login", "/signin", "/sign-in", "/auth", "/auth/login", "/account/login", "/session/login", "/sso", "/saml/login":
		return true
	default:
		return false
	}
}

type responseContentClass uint8

const (
	responseNonContentStatus responseContentClass = iota
	responseContent
	responseEmptySuccess
	responseAuthShell
	responseErrorShell
)

const responseEvidenceBodyLimit = 256 << 10

// classifyResponseContent answers only whether a response proves substantive
// direct content for the requested route. It is not a general page-type
// classifier: ambiguous non-empty 2xx bodies intentionally remain content.
func classifyResponseContent(response types.CapturedResponse) responseContentClass {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseNonContentStatus
	}
	if response.StatusCode == 204 || response.StatusCode == 205 {
		return responseEmptySuccess
	}

	body := bytes.TrimSpace(response.Body)
	if len(body) == 0 {
		return responseEmptySuccess
	}
	if len(body) > responseEvidenceBodyLimit {
		body = body[:responseEvidenceBodyLimit]
	}
	body = bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})
	contentType := strings.ToLower(strings.TrimSpace(response.ContentType))
	if contentType == "" {
		contentType = strings.ToLower(redirectHeaderValue(response.Headers, "Content-Type"))
	}

	if strings.Contains(contentType, "json") || bodyStartsLikeJSON(body) {
		if classification, ok := classifyJSONEvidence(body); ok {
			return classification
		}
	}
	if !isTextualEvidence(contentType, body) {
		// Non-empty binary responses are still direct content. Shell heuristics
		// must never reinterpret arbitrary bytes as an error page.
		return responseContent
	}

	raw := strings.ToLower(string(body))
	shellRaw := stripNonVisibleEvidence(raw)
	visible := normalizedVisibleText(shellRaw)
	if visible == "" {
		return responseEmptySuccess
	}
	// Some server-rendered SPA fallbacks return a branded 200 document whose
	// visible DOM is only the ordinary application loader. The authoritative
	// soft-404 signal lives in a small router bootstrap (for example Seller
	// Center's scRouter.originalUrl = /errors/public/not-found). Recognize only
	// explicit framework/router assignments—not loose "not found" strings in
	// arbitrary scripts—so real pages and documentation remain content.
	if looksLikeStructuredErrorBootstrap(raw) {
		return responseErrorShell
	}
	// Authentication SPA identity often exists only on <script src=...>
	// attributes. Pass the original markup for structural checks while keeping
	// all prose checks bound to `visible`, which has script/style contents
	// removed and therefore cannot be tripped by JavaScript string literals.
	if looksLikeAuthenticationShell(raw, visible) {
		return responseAuthShell
	}
	if looksLikeErrorShell(shellRaw, visible) {
		return responseErrorShell
	}
	return responseContent
}

func bodyStartsLikeJSON(body []byte) bool {
	body = bytes.TrimSpace(body)
	return len(body) > 0 && (body[0] == '{' || body[0] == '[' || body[0] == '"')
}

func isTextualEvidence(contentType string, body []byte) bool {
	for _, marker := range []string{"text/", "html", "json", "xml", "javascript", "x-www-form-urlencoded"} {
		if strings.Contains(contentType, marker) {
			return true
		}
	}
	return contentType == "" && utf8.Valid(body)
}

func classifyJSONEvidence(body []byte) (responseContentClass, bool) {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return responseContent, false
	}
	switch typed := value.(type) {
	case nil:
		return responseEmptySuccess, true
	case []any:
		if len(typed) == 0 {
			return responseEmptySuccess, true
		}
		return responseContent, true
	case map[string]any:
		if len(typed) == 0 {
			return responseEmptySuccess, true
		}
		// An auth/error status wins unless a non-envelope field contains real
		// application data. Merely naming a field `data` is not evidence:
		// data:null, empty containers, blank strings, and false are common error
		// envelope furniture and must not promote the response to content.
		hasSubstantiveData := false
		for key, raw := range typed {
			if !jsonEnvelopeKey(key) && hasSubstantiveJSONValue(raw) {
				hasSubstantiveData = true
				break
			}
		}
		text := strings.ToLower(strings.Join(jsonScalarStrings(typed), " "))
		if !hasSubstantiveData && (jsonEnvelopeStatus(typed, 401) || jsonEnvelopeStatus(typed, 403) || containsAuthShellPhrase(text)) {
			return responseAuthShell, true
		}
		if !hasSubstantiveData && (jsonEnvelopeErrorStatus(typed) || containsErrorShellPhrase(text)) {
			return responseErrorShell, true
		}
		return responseContent, true
	case string:
		text := strings.ToLower(strings.TrimSpace(typed))
		if text == "" {
			return responseEmptySuccess, true
		}
		if containsAuthShellPhrase(text) {
			return responseAuthShell, true
		}
		if containsErrorShellPhrase(text) {
			return responseErrorShell, true
		}
		return responseContent, true
	default:
		return responseContent, true
	}
}

func hasSubstantiveJSONValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		text := strings.ToLower(strings.TrimSpace(typed))
		return text != "" && !containsAuthShellPhrase(text) && !containsErrorShellPhrase(text)
	case bool:
		return typed
	case []any:
		for _, item := range typed {
			if hasSubstantiveJSONValue(item) {
				return true
			}
		}
		return false
	case map[string]any:
		for key, item := range typed {
			if !jsonEnvelopeKey(key) && hasSubstantiveJSONValue(item) {
				return true
			}
		}
		return false
	default:
		// JSON numbers, including zero, are concrete application values.
		return true
	}
}

func jsonEnvelopeKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "error", "errors", "message", "detail", "title", "type", "status", "statuscode", "status_code", "code", "path", "timestamp", "success":
		return true
	default:
		return false
	}
}

func jsonScalarStrings(value any) []string {
	var result []string
	var visit func(any)
	visit = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for _, item := range typed {
				visit(item)
			}
		case []any:
			for _, item := range typed {
				visit(item)
			}
		case string:
			result = append(result, typed)
		}
	}
	visit(value)
	return result
}

func jsonEnvelopeStatus(value map[string]any, wanted int) bool {
	for key, raw := range value {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "status", "statuscode", "status_code", "code":
			switch typed := raw.(type) {
			case float64:
				if int(typed) == wanted {
					return true
				}
			case string:
				if strings.TrimSpace(typed) == strings.TrimSpace(httpStatusString(wanted)) {
					return true
				}
			}
		}
	}
	return false
}

func httpStatusString(status int) string {
	// Avoid accepting loose numeric substrings such as an application error
	// code containing "404". These are the only status strings needed by the
	// deterministic shell classifier.
	switch status {
	case 401:
		return "401"
	case 403:
		return "403"
	case 404:
		return "404"
	case 410:
		return "410"
	case 500:
		return "500"
	case 502:
		return "502"
	case 503:
		return "503"
	case 504:
		return "504"
	default:
		return ""
	}
}

func jsonEnvelopeErrorStatus(value map[string]any) bool {
	for _, status := range []int{404, 410, 500, 502, 503, 504} {
		if jsonEnvelopeStatus(value, status) {
			return true
		}
	}
	return false
}

func normalizedVisibleText(raw string) string {
	raw = stripNonVisibleEvidence(raw)
	var builder strings.Builder
	builder.Grow(len(raw))
	inTag := false
	for _, char := range raw {
		switch char {
		case '<':
			inTag = true
			builder.WriteByte(' ')
		case '>':
			inTag = false
			builder.WriteByte(' ')
		default:
			if !inTag {
				builder.WriteRune(char)
			}
		}
	}
	return strings.Join(strings.Fields(html.UnescapeString(builder.String())), " ")
}

func stripNonVisibleEvidence(raw string) string {
	raw = stripDelimitedCaseFolded(raw, "<!--", "-->")
	for _, tag := range []string{"script", "style", "template", "svg"} {
		raw = stripElementCaseFolded(raw, tag)
	}
	return raw
}

func stripElementCaseFolded(raw, tag string) string {
	open := "<" + tag
	close := "</" + tag + ">"
	for {
		start := strings.Index(raw, open)
		if start < 0 {
			return raw
		}
		end := strings.Index(raw[start:], close)
		if end < 0 {
			return raw[:start]
		}
		raw = raw[:start] + " " + raw[start+end+len(close):]
	}
}

func stripDelimitedCaseFolded(raw, open, close string) string {
	for {
		start := strings.Index(raw, open)
		if start < 0 {
			return raw
		}
		end := strings.Index(raw[start+len(open):], close)
		if end < 0 {
			return raw[:start]
		}
		raw = raw[:start] + " " + raw[start+len(open)+end+len(close):]
	}
}

func looksLikeAuthenticationShell(raw, visible string) bool {
	// Strong prose markers are considered shell evidence only on a compact
	// response. This avoids classifying a documentation or support page merely
	// because it explains what an "unauthorized" response means.
	if len(visible) <= 4096 && containsAuthShellPhrase(visible) {
		return true
	}
	hasAuthHeading := strings.Contains(raw, "<title>login") || strings.Contains(raw, "<title>log in") ||
		strings.Contains(raw, "<title>sign in") || strings.Contains(raw, "<h1>login") ||
		strings.Contains(raw, "<h1>log in") || strings.Contains(raw, "<h1>sign in")
	hasAuthControl := strings.Contains(raw, "<form") || strings.Contains(visible, "continue with") ||
		strings.Contains(visible, "single sign-on") || strings.Contains(visible, "single sign on") ||
		strings.Contains(visible, "sso")
	if hasAuthHeading && hasAuthControl {
		return true
	}
	// Modern authentication pages often ship only an empty SPA mount and a
	// login/auth bundle; the form is created after JavaScript starts. There is
	// no static <form>, password input, or useful visible text for the classic
	// checks above. Treat that combination as a generic auth shell so a catch-all
	// 200 at /admin or /auth/logout cannot masquerade as backing page content.
	// The canonical login path is promoted back to content by
	// authenticationShellMatchesRequest.
	hasSPAMount := (strings.Contains(raw, `id="app"`) || strings.Contains(raw, `id='app'`) ||
		strings.Contains(raw, `id="root"`) || strings.Contains(raw, `id='root'`)) &&
		(strings.Contains(raw, `id="initial-loading"`) || strings.Contains(raw, `id='initial-loading'`) ||
			strings.Contains(raw, "loading-overlay") || strings.Contains(raw, "loading-spinner"))
	authBundleRefs := 0
	for _, marker := range []string{
		"auth/bundle", "auth-bundle", "auth.bundle", "login/bundle",
		"login-bundle", "login.bundle", "signin/bundle", "sign-in/bundle",
	} {
		authBundleRefs += strings.Count(raw, marker)
	}
	// Bounded evidence keeps both document ends. The SPA mount can sit in the
	// omitted middle, so two independent auth bundle tags plus only compact
	// shell text is equivalent strong evidence without requiring that mount.
	if authBundleRefs > 0 && (hasSPAMount || (authBundleRefs >= 2 && len(visible) <= 1024)) {
		return true
	}
	hasPasswordField := strings.Contains(raw, "type=\"password\"") ||
		strings.Contains(raw, "type='password'") || strings.Contains(raw, "type=password")
	if !hasPasswordField {
		return false
	}
	hasLoginPurpose := strings.Contains(visible, "log in") || strings.Contains(visible, "login") ||
		strings.Contains(visible, "sign in") || strings.Contains(raw, "action=\"/login") ||
		strings.Contains(raw, "action='/login") || strings.Contains(raw, "action=\"/auth") ||
		strings.Contains(raw, "action='/auth")
	return hasLoginPurpose
}

func containsAuthShellPhrase(text string) bool {
	for _, phrase := range []string{
		"authentication required", "login required", "log in required", "please login",
		"please log in", "sign in to continue", "you must log in", "you must login",
		"session expired", "unauthorized", "unauthenticated", "access denied", "forbidden",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

func looksLikeErrorShell(raw, visible string) bool {
	for _, marker := range []string{
		"<title>404", "<title>not found", "<title>page not found",
		"<h1>404", "<h1>not found", "<h1>page not found",
		"<title>error</title>", "<title>application error",
		"<h1>internal server error", "<h1>application error",
	} {
		if strings.Contains(raw, marker) {
			return true
		}
	}
	return len(visible) <= 4096 && containsErrorShellPhrase(visible)
}

func looksLikeStructuredErrorBootstrap(raw string) bool {
	raw = strings.ToLower(html.UnescapeString(raw))
	compact := strings.Join(strings.Fields(raw), " ")

	// Example/internal BFF bootstrap. Requiring both the named router object
	// and an assignment to originalUrl prevents a harmless route constant or a
	// script template mentioning 404 from becoming negative evidence.
	if strings.Contains(compact, "window.scrouter") {
		for _, route := range []string{
			"/errors/public/not-found", "/errors/not-found", "/error/not-found", "/404",
		} {
			for _, quote := range []string{"'", `"`} {
				for _, declaration := range []string{"const", "let", "var"} {
					if strings.Contains(compact, declaration+" originalurl = "+quote+route+quote) {
						return true
					}
				}
				if strings.Contains(compact, "originalurl: "+quote+route+quote) ||
					strings.Contains(compact, quote+"originalurl"+quote+": "+quote+route+quote) {
					return true
				}
			}
		}
	}

	// Bounded support for framework-owned error bootstrap data. Both the
	// framework sentinel and an exact structured field are mandatory.
	if strings.Contains(compact, "__next_data__") {
		for _, marker := range []string{
			`"statuscode":404`, `"statuscode": 404`, `"page":"/_error"`, `"page": "/_error"`,
		} {
			if strings.Contains(compact, marker) {
				return true
			}
		}
	}
	return false
}

func containsErrorShellPhrase(text string) bool {
	for _, phrase := range []string{
		"404 not found", "404 page not found", "page not found", "route not found",
		"resource not found", "the page you are looking for does not exist", "cannot get /",
		"internal server error", "application error", "bad gateway", "service unavailable",
		"gateway timeout", "an unexpected error occurred", "something went wrong",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

func redirectsThroughPathPreservingAuthGate(requestURL, requestPath, location string) bool {
	base, _ := url.Parse(strings.TrimSpace(requestURL))
	destination, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return false
	}
	if base != nil {
		destination = base.ResolveReference(destination)
	}
	lowerPath := strings.ToLower(destination.Path)
	if !looksLikeAuthenticationGatePath(lowerPath) {
		return false
	}

	requestPath = normalizeObservedPath(requestPath)
	if requestPath == "/" && base != nil {
		requestPath = normalizeObservedPath(base.Path)
	}
	for _, key := range []string{
		"redirect", "redirect_uri", "redirect_url", "return", "return_to",
		"returnto", "returnurl", "next", "continue", "destination",
	} {
		for _, value := range destination.Query()[key] {
			if redirectedValueMatchesPath(value, requestPath) {
				return true
			}
		}
		// Query keys are case-sensitive by specification but frameworks are not
		// consistent. Check case-insensitively without losing repeated values.
		for actualKey, values := range destination.Query() {
			if !strings.EqualFold(actualKey, key) {
				continue
			}
			for _, value := range values {
				if redirectedValueMatchesPath(value, requestPath) {
					return true
				}
			}
		}
	}
	return false
}

func redirectedValueMatchesPath(value, requestPath string) bool {
	value = strings.TrimSpace(value)
	if parsed, err := url.Parse(value); err == nil && parsed.Path != "" {
		value = parsed.Path
	}
	return normalizeObservedPath(value) == normalizeObservedPath(requestPath)
}

func normalizeObservedPath(path string) string {
	path = strings.TrimSpace(path)
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func looksLikeAuthenticationGatePath(path string) bool {
	for _, marker := range []string{
		"/auth", "/login", "/logout", "/signin", "/sign-in", "/session",
		"/account/login", "/account/logout", "/oauth", "/saml",
	} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

func redirectHeaderValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
