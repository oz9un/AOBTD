package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// JSAnalyzer extracts API endpoints, routes, and parameters from captured JavaScript files.
// This discovers attack surface invisible to the crawler — API calls made by frontend code.
type JSAnalyzer struct {
	db       *store.DB
	provider llm.Provider
	budget   *llm.Budget
	bus      *Bus
	state    *SharedState
	scanID   int64
	logger   *slog.Logger
}

// DiscoveredRoute represents an API route found in JavaScript.
type DiscoveredRoute struct {
	Method   string   `json:"method"`
	Path     string   `json:"path"`
	Params   []string `json:"params,omitempty"`
	Source   string   `json:"source"`    // which JS file
	Context  string   `json:"context"`   // surrounding code snippet
	AuthType string   `json:"auth_type"` // bearer, cookie, api_key, none, unknown
	Kind     string   `json:"kind,omitempty"`
}

func NewJSAnalyzer(db *store.DB, provider llm.Provider, budget *llm.Budget, bus *Bus, state *SharedState, scanID int64, logger *slog.Logger) *JSAnalyzer {
	return &JSAnalyzer{db: db, provider: provider, budget: budget, bus: bus, state: state, scanID: scanID, logger: logger}
}

func (j *JSAnalyzer) Name() string              { return "js_analyzer" }
func (j *JSAnalyzer) Capabilities() []EventType { return nil }

// Start analyzes all captured JS files for hidden endpoints.
func (j *JSAnalyzer) Start(ctx context.Context) error {
	j.logger.Info("JS analyzer starting")

	// Fetch JS file traffic
	rows, err := j.db.Conn().Query(`
		SELECT id, url, response_body FROM traffic_resolved
		WHERE scan_id = ? AND is_filtered = FALSE
		  AND (content_type LIKE '%javascript%' OR url LIKE '%.js' OR url LIKE '%.js?%')
		  AND LENGTH(response_body) > 100
		  AND LENGTH(response_body) < 2000000
		ORDER BY response_size DESC
		LIMIT 20`, j.scanID)
	if err != nil {
		return fmt.Errorf("query JS files: %w", err)
	}
	defer rows.Close()

	type jsFile struct {
		id   int64
		url  string
		body string
	}

	var files []jsFile
	for rows.Next() {
		var f jsFile
		var bodyBytes []byte
		rows.Scan(&f.id, &f.url, &bodyBytes)
		f.body = string(bodyBytes)
		files = append(files, f)
	}
	rows.Close()

	if len(files) == 0 {
		j.logger.Info("no JS files to analyze")
		return nil
	}

	j.logger.Info("found JS files to analyze", "count", len(files))

	var allRoutes []DiscoveredRoute

	for _, f := range files {
		if ctx.Err() != nil {
			return nil
		}

		// Phase 1: Regex extraction (fast, free)
		regexRoutes := j.extractRoutesRegex(f.body, f.url)
		allRoutes = append(allRoutes, regexRoutes...)

		// Phase 2: LLM analysis for complex patterns (if budget allows).
		// The regex pass above is the baseline; a missing budget object should
		// not disable JS understanding entirely.
		if j.provider != nil && (j.budget == nil || j.budget.CanSpend(2000)) {
			llmRoutes := j.extractRoutesLLM(ctx, f.body, f.url)
			allRoutes = append(allRoutes, llmRoutes...)
		}
	}

	unique := dedupeJSRoutes(allRoutes)

	j.logger.Info("JS analysis complete", "routes_found", len(unique))

	// Store discovered routes in the database
	for _, r := range unique {
		j.db.LogAI(j.scanID, "js_analyzer", "route_discovered",
			fmt.Sprintf("%s %s kind=%s (params: %s)", r.Method, r.Path, routeKind(r), strings.Join(r.Params, ", ")),
			r.Source, r.Path, r.AuthType)

		// Record as a discovery edge: the JS file led us to this route.
		// Source is the JS file URL; target is the route path (may need a
		// host prefix downstream to fully resolve).
		j.db.InsertDiscovery(j.scanID, store.Discovery{
			TargetURL: resolvedRouteURL(r),
			SourceURL: r.Source,
			Kind:      store.DiscoveryJSRoute,
			Detail:    fmt.Sprintf("%s kind=%s (params: %s)", r.Method, routeKind(r), strings.Join(r.Params, ", ")),
		})

		// Add executable/network routes as endpoints to shared state. UI
		// routes are browser navigation candidates, not HTTP API endpoints;
		// they become analyzable once the SPA route primer visits them and
		// records the resulting traffic.
		if rk := routeKind(r); rk == "api" || rk == "ws" {
			j.state.AddEndpoint(endpointFromRoute(r))
		}
	}

	// Store routes as a JSON blob in the knowledge base
	if len(unique) > 0 {
		j.storeRoutes(unique)
	}

	return nil
}

func dedupeJSRoutes(routes []DiscoveredRoute) []DiscoveredRoute {
	mountedKeys := make(map[string]struct{}, len(routes))
	for _, r := range routes {
		if !usableJSRoute(r) {
			continue
		}
		mountedKeys[observation.EndpointHash(r.Method, resolvedRouteURL(r))] = struct{}{}
	}

	seen := make(map[string]bool)
	var unique []DiscoveredRoute
	for _, r := range routes {
		if !usableJSRoute(r) || rootDuplicateHasMountedEquivalent(r, mountedKeys) {
			continue
		}
		key := observation.EndpointHash(r.Method, resolvedRouteURL(r))
		if !seen[key] {
			seen[key] = true
			unique = append(unique, r)
		}
	}
	return unique
}

func usableJSRoute(r DiscoveredRoute) bool {
	r.Path = strings.TrimSpace(r.Path)
	if r.Path == "" || strings.ContainsAny(r.Path, "\"' \t\r\n<>") ||
		strings.Contains(r.Path, "$(") || strings.Contains(r.Path, "${") {
		return false
	}
	if jsRouteLooksLikeExpressionPath(r.Path) {
		return false
	}
	kind := routeKind(r)
	switch kind {
	case "api", "ui", "ws", "data":
		return true
	default:
		return false
	}
}

func jsRouteLooksLikeExpressionPath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	parsed, err := url.Parse(path)
	if err == nil && parsed.IsAbs() {
		return false
	}
	for _, segment := range strings.Split(strings.Trim(path, "/"), "/") {
		lower := strings.ToLower(strings.TrimSpace(segment))
		if lower == "" {
			continue
		}
		if strings.HasPrefix(lower, "this.") || strings.HasPrefix(lower, "window.") ||
			strings.HasPrefix(lower, "document.") || strings.HasSuffix(lower, ".url") {
			return true
		}
	}
	return false
}

func rootDuplicateHasMountedEquivalent(r DiscoveredRoute, mountedKeys map[string]struct{}) bool {
	route, err := url.Parse(strings.TrimSpace(r.Path))
	if err != nil || route.IsAbs() || !strings.HasPrefix(route.Path, "/") {
		return false
	}
	source, err := url.Parse(strings.TrimSpace(r.Source))
	if err != nil || source.Host == "" {
		return false
	}
	mount := appMountPathFromScriptSource(source.Path)
	if mount == "/" || strings.HasPrefix(route.Path, mount) {
		return false
	}
	mounted := r
	mounted.Path = strings.TrimRight(mount, "/") + route.Path
	if route.RawQuery != "" {
		mounted.Path += "?" + route.RawQuery
	}
	_, ok := mountedKeys[observation.EndpointHash(mounted.Method, resolvedRouteURL(mounted))]
	return ok
}

// extractRoutesRegex uses regex patterns to find API calls in JS code.
// This catches ~60-70% of routes without any LLM cost.
func (j *JSAnalyzer) extractRoutesRegex(jsCode, sourceURL string) []DiscoveredRoute {
	var routes []DiscoveredRoute
	routes = append(routes, extractAjaxObjectRoutes(jsCode, sourceURL)...)

	patterns := []struct {
		re          *regexp.Regexp
		method      string
		methodGroup int
		pathGroup   int
		context     string
	}{
		// fetch("/api/...", {method: "POST"})
		{regexp.MustCompile(`fetch\s*\(\s*["'` + "`" + `]((?:https?:\/\/|\/|[A-Za-z0-9_.-]+\/)[^"'` + "`" + `\s]{3,140})["'` + "`" + `]`), "GET", 0, 1, "fetch call"},
		// axios.get("/api/...")
		{regexp.MustCompile(`axios\.(get|post|put|delete|patch)\s*\(\s*["'` + "`" + `]((?:https?:\/\/|\/|[A-Za-z0-9_.-]+\/)[^"'` + "`" + `\s]{3,140})["'` + "`" + `]`), "", 1, 2, "axios call"},
		// $.get("relative/path") / $.post("relative/path")
		{regexp.MustCompile(`(?:\$|jQuery|[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.(get|post|put|delete|patch)\s*\(\s*["'` + "`" + `]((?:https?:\/\/|\/|[A-Za-z0-9_.-]+\/)[^"'` + "`" + `\s]{3,140})["'` + "`" + `]`), "", 1, 2, "jquery shorthand call"},
		// $("#target").load("relative/path")
		{regexp.MustCompile(`\.load\s*\(\s*["'` + "`" + `]((?:https?:\/\/|\/|[A-Za-z0-9_.-]+\/)[^"'` + "`" + `\s]{3,140})["'` + "`" + `]`), "GET", 0, 1, "jquery load call"},
		// $.ajax({url: "/api/..."})
		{regexp.MustCompile(`url\s*:\s*["'` + "`" + `](\/[^"'` + "`" + `\s]{3,80})["'` + "`" + `]`), "GET", 0, 1, "ajax url"},
		// XMLHttpRequest.open("POST", "/api/...")
		{regexp.MustCompile(`\.open\s*\(\s*["'](GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["'` + "`" + `]((?:https?:\/\/|\/|[A-Za-z0-9_.-]+\/)[^"'` + "`" + `\s]{3,140})["'` + "`" + `]`), "", 1, 2, "xhr open"},
		// "/api/v2/users" (standalone string that looks like API path)
		{regexp.MustCompile(`["'](\/api\/[^"'\s]{3,80})["']`), "GET", 0, 1, "api string"},
		// "/graphql"
		{regexp.MustCompile(`["'](\/graphql[^"'\s]{0,30})["']`), "POST", 0, 1, "graphql string"},
		// WebSocket: new WebSocket("wss://...")
		{regexp.MustCompile(`WebSocket\s*\(\s*["'` + "`" + `](wss?:\/\/[^"'` + "`" + `\s]{3,80})["'` + "`" + `]`), "WS", 0, 1, "websocket constructor"},
		// Route definitions: path: "/users/:id"
		{regexp.MustCompile(`path\s*:\s*["']([^"'\s{}(),]{1,80})["']`), "GET", 0, 1, "router path"},
		// Angular compiled templates: "routerLink","/score-board"
		{regexp.MustCompile(`["']routerLink["']\s*,\s*["'](\/[^"'\s),]{1,80})["']`), "GET", 0, 1, "routerLink literal"},
		// Angular compiled templates with dynamic helper: "routerLink",Dt("/address/edit/",id)
		{regexp.MustCompile(`["']routerLink["']\s*,\s*[A-Za-z_$][\w$]*\(\s*["'](\/[^"'\s),]{1,80})["']`), "GET", 0, 1, "routerLink dynamic prefix"},
		// Angular command arrays compiled from router.navigate(["privacy-security/privacy-policy"])
		// or small helper lambdas such as var go=()=>["privacy-security/privacy-policy"].
		{regexp.MustCompile(`=>\s*\[\s*["']([^"'\]\s]{2,100})["']\s*\]`), "GET", 0, 1, "router command array"},
		{regexp.MustCompile(`\.navigate(?:ByUrl)?\s*\(\s*(?:\[\s*)?["']([^"'\]\s]{2,100})["']`), "GET", 0, 1, "router navigate call"},
		// Direct hash-route hrefs in compiled templates.
		{regexp.MustCompile(`["']href["']\s*,\s*["'](?:\.?\/)?#\/([^"'\s),]{1,100})["']`), "GET", 0, 1, "hash href route"},
	}

	for _, p := range patterns {
		matches := p.re.FindAllStringSubmatch(jsCode, 50)
		for _, m := range matches {
			if p.pathGroup <= 0 || len(m) <= p.pathGroup {
				continue
			}
			path := m[p.pathGroup]
			method := p.method
			if p.methodGroup > 0 && len(m) > p.methodGroup {
				method = strings.ToUpper(m[p.methodGroup])
			}

			if path == "" || method == "" {
				continue
			}

			// Skip obviously non-API paths
			if strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".png") ||
				strings.HasSuffix(path, ".svg") || strings.HasSuffix(path, ".ico") ||
				strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/assets/") {
				continue
			}
			kind := classifyDiscoveredRoute(path, p.context)
			if kind == "" || kind == "static" {
				continue
			}

			// Extract path params
			params := extractPathParams(path)

			routes = append(routes, DiscoveredRoute{
				Method:  method,
				Path:    path,
				Params:  params,
				Source:  sourceURL,
				Context: p.context,
				Kind:    kind,
			})
		}
	}

	return routes
}

func extractAjaxObjectRoutes(jsCode, sourceURL string) []DiscoveredRoute {
	objectRe := regexp.MustCompile(`(?is)\.ajax\s*\(\s*\{(.{0,900}?)\}\s*\)`)
	urlRe := regexp.MustCompile(`(?is)\burl\s*:\s*["'` + "`" + `]((?:https?:\/\/|\/|[A-Za-z0-9_.-]+\/)[^"'` + "`" + `\s]{1,180})["'` + "`" + `]`)
	methodRe := regexp.MustCompile(`(?is)\b(?:method|type)\s*:\s*["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']`)
	contentTypeRe := regexp.MustCompile(`(?is)\bcontentType\s*:\s*["']([^"']{1,120})["']`)
	var routes []DiscoveredRoute
	for _, match := range objectRe.FindAllStringSubmatch(jsCode, 50) {
		if len(match) < 2 {
			continue
		}
		block := match[1]
		urlMatch := urlRe.FindStringSubmatch(block)
		if len(urlMatch) < 2 {
			continue
		}
		method := "GET"
		if methodMatch := methodRe.FindStringSubmatch(block); len(methodMatch) >= 2 {
			method = strings.ToUpper(methodMatch[1])
		}
		path := strings.TrimSpace(urlMatch[1])
		params := extractPathParams(path)
		if strings.Contains(block, "FormData") || strings.Contains(block, ".append(") {
			params = appendUniqueStrings(params, extractFormDataFields(jsCode)...)
		}
		context := "ajax object"
		if ctMatch := contentTypeRe.FindStringSubmatch(block); len(ctMatch) >= 2 {
			context += " contentType=" + strings.TrimSpace(ctMatch[1])
		}
		kind := classifyDiscoveredRoute(path, context)
		if kind == "" || kind == "static" {
			continue
		}
		routes = append(routes, DiscoveredRoute{
			Method:  method,
			Path:    path,
			Params:  params,
			Source:  sourceURL,
			Context: context,
			Kind:    kind,
		})
	}
	return routes
}

func extractFormDataFields(jsCode string) []string {
	appendRe := regexp.MustCompile(`\.append\s*\(\s*["']([A-Za-z0-9_.:-]{1,80})["']`)
	var fields []string
	seen := make(map[string]struct{})
	for _, match := range appendRe.FindAllStringSubmatch(jsCode, 100) {
		if len(match) < 2 {
			continue
		}
		field := strings.TrimSpace(match[1])
		if field == "" {
			continue
		}
		if _, ok := seen[field]; ok {
			continue
		}
		seen[field] = struct{}{}
		fields = append(fields, field)
	}
	return fields
}

func appendUniqueStrings(base []string, extra ...string) []string {
	seen := make(map[string]struct{}, len(base)+len(extra))
	var out []string
	for _, value := range append(append([]string{}, base...), extra...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// extractRoutesLLM uses the LLM to find routes that regex misses —
// template literals, concatenated strings, dynamic route builders.
func (j *JSAnalyzer) extractRoutesLLM(ctx context.Context, jsCode, sourceURL string) []DiscoveredRoute {
	// Only send interesting chunks, not the whole file
	chunks := extractInterestingChunks(jsCode, 3000)
	if chunks == "" {
		return nil
	}

	prompt := fmt.Sprintf(`Analyze this JavaScript code and extract ALL API endpoints, routes, and URLs.
Look for:
- fetch/axios/XMLHttpRequest calls
- API base URLs and path constants
- Client-side UI route definitions (React Router, Angular Router, Vue Router, hash routes)
- routerLink/href/navigation arrays that open app pages
- WebSocket connections
- GraphQL endpoints and operations
- Hardcoded URLs that look like API endpoints or app routes
- Dynamic URL construction (template literals, string concatenation)

Source file: %s

Code:
%s

Respond with a JSON array of objects: [{"method":"GET","path":"/api/users","params":["id"],"auth_type":"bearer","kind":"api"},{"method":"GET","path":"/admin","kind":"ui"}]
Only include API endpoints, WebSocket endpoints, GraphQL endpoints, and real client-side app routes. Skip static assets (.css, .js, .png, etc).`, sourceURL, chunks)

	start := time.Now()
	req := &llm.Request{
		SystemPrompt: "You are a JavaScript code analyzer specializing in finding API endpoints and routes. Output only valid JSON.",
		Messages:     []llm.Message{{Role: "user", Content: prompt}},
		Temperature:  0.1,
		MaxTokens:    2048,
		JSONMode:     true,
	}
	resp, err := llm.CompleteBudgeted(ctx, j.provider, j.budget, req, 0)
	durationMs := time.Since(start).Milliseconds()
	if err != nil {
		j.logger.Debug("LLM JS analysis failed", "error", err)
		return nil
	}

	modelID := llm.ResponseModel(resp, j.provider)
	costUcents := llm.CostMicroCents(modelID, resp.Usage)
	j.db.LogAIFull(j.scanID, "js_analyzer", "llm_analysis",
		sourceURL, "", sourceURL, "",
		resp.Usage.InputTokens, resp.Usage.OutputTokens, durationMs, costUcents, modelID,
		llm.RenderPrompt(req), resp.Content)

	var routes []DiscoveredRoute
	if err := json.Unmarshal([]byte(resp.Content), &routes); err != nil {
		// Try extracting JSON array
		cleaned := extractJSONArray(resp.Content)
		json.Unmarshal([]byte(cleaned), &routes)
	}

	for i := range routes {
		routes[i].Source = sourceURL
		routes[i].Context = "LLM analysis"
		if routes[i].Kind == "" {
			routes[i].Kind = classifyDiscoveredRoute(routes[i].Path, routes[i].Context)
		}
	}

	return routes
}

func (j *JSAnalyzer) storeRoutes(routes []DiscoveredRoute) {
	routesJSON, _ := json.Marshal(routes)

	_, err := j.db.Conn().Exec(`
		INSERT INTO page_profiles (id, scan_id, url, method, purpose, issues, confidence, created_at, updated_at)
		VALUES (?, ?, ?, '', ?, ?, 0.7, datetime('now'), datetime('now'))
		ON CONFLICT(scan_id, id) DO UPDATE SET
			purpose = excluded.purpose,
			issues = excluded.issues,
			updated_at = datetime('now')`,
		"js_discovered_routes", j.scanID,
		"JavaScript source analysis",
		fmt.Sprintf("Discovered %d routes from JavaScript analysis", len(routes)),
		string(routesJSON),
	)
	if err != nil && j.logger != nil {
		j.logger.Warn("store JS route profile", "error", err)
	}
}

// extractPathParams finds :param and {param} patterns in a path.
func extractPathParams(path string) []string {
	var params []string
	re := regexp.MustCompile(`[:{}]([a-zA-Z_][a-zA-Z0-9_]*)`)
	for _, m := range re.FindAllStringSubmatch(path, -1) {
		if len(m) >= 2 {
			params = append(params, m[1])
		}
	}
	return params
}

func routeKind(r DiscoveredRoute) string {
	if strings.TrimSpace(r.Kind) != "" {
		return strings.ToLower(strings.TrimSpace(r.Kind))
	}
	return classifyDiscoveredRoute(r.Path, r.Context)
}

func classifyDiscoveredRoute(path, context string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	if p == "*" || p == "**" {
		return ""
	}
	lower := strings.ToLower(p)
	switch {
	case strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://"):
		return "ws"
	case strings.HasSuffix(lower, ".css") || strings.HasSuffix(lower, ".js") ||
		strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".svg") ||
		strings.HasSuffix(lower, ".ico") || strings.HasPrefix(lower, "/static/") ||
		strings.HasPrefix(lower, "/assets/"):
		return "static"
	case strings.HasPrefix(lower, "/api/") || lower == "/api" ||
		strings.HasPrefix(lower, "/rest/") || lower == "/rest" ||
		strings.HasPrefix(lower, "/graphql") ||
		strings.HasPrefix(lower, "/socket.io") || strings.HasPrefix(lower, "/engine.io"):
		return "api"
	case strings.HasPrefix(lower, "//"):
		if strings.Contains(lower, "api.") || strings.Contains(lower, "/api/") {
			return "api"
		}
		return ""
	}
	if contextLooksLikeNetworkCall(context) && looksLikeNetworkRoutePath(p) {
		return "api"
	}
	if looksLikeUIRoutePath(p) {
		if contextLooksLikeNetworkCall(context) {
			return "api"
		}
		return "ui"
	}
	if strings.Contains(strings.ToLower(context), "router") {
		return "ui"
	}
	return ""
}

func contextLooksLikeNetworkCall(context string) bool {
	lower := strings.ToLower(strings.TrimSpace(context))
	for _, marker := range []string{
		"ajax", "fetch", "axios", "xhr", "xmlhttprequest", "jquery", "contenttype", "load call",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func looksLikeNetworkRoutePath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	if strings.ContainsAny(path, "<>{}\"' \t\r\n") || strings.Contains(path, "..") {
		return false
	}
	parsed, err := url.Parse(path)
	if err == nil && parsed.IsAbs() {
		return parsed.Scheme == "http" || parsed.Scheme == "https" || parsed.Scheme == "ws" || parsed.Scheme == "wss"
	}
	return strings.HasPrefix(path, "/") || strings.Contains(path, "/")
}

func looksLikeUIRoutePath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" || path == "**" {
		return false
	}
	if strings.ContainsAny(path, "{}?=&") || strings.Contains(path, "..") {
		return false
	}
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return false
	}
	for _, segment := range strings.Split(trimmed, "/") {
		if segment == "" {
			return false
		}
		if strings.HasPrefix(segment, ":") {
			continue
		}
		for _, r := range segment {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
				r == '-' || r == '_' || r == '.' {
				continue
			}
			return false
		}
	}
	return true
}

// extractInterestingChunks pulls out sections of JS that likely contain API calls.
func extractInterestingChunks(code string, maxLen int) string {
	keywords := []string{
		"fetch(", "axios.", ".ajax(", "XMLHttpRequest", ".open(",
		"/api/", "/graphql", "WebSocket", "endpoint", "baseUrl",
		"baseURL", "apiUrl", "API_URL", "route", "path:",
	}

	lines := strings.Split(code, "\n")
	var interesting []string
	totalLen := 0

	for i, line := range lines {
		for _, kw := range keywords {
			if strings.Contains(line, kw) {
				// Grab surrounding context (2 lines before/after)
				start := i - 2
				if start < 0 {
					start = 0
				}
				end := i + 3
				if end > len(lines) {
					end = len(lines)
				}
				chunk := strings.Join(lines[start:end], "\n")
				if totalLen+len(chunk) > maxLen {
					goto done
				}
				interesting = append(interesting, chunk)
				totalLen += len(chunk)
				break
			}
		}
	}
done:

	return strings.Join(interesting, "\n---\n")
}

func endpointFromRoute(r DiscoveredRoute) types.Endpoint {
	routeURL := resolvedRouteURL(r)
	return types.Endpoint{
		ID:         observation.EndpointHash(r.Method, routeURL),
		Method:     r.Method,
		URLPattern: routeURL,
		HitCount:   0,
		Purpose:    "Discovered in JS: " + r.Source,
	}
}

// resolvedRouteURL gives a JS-discovered route an origin before it enters the
// shared endpoint model. Without this, /api/users discovered on two scoped
// hosts collapsed into one endpoint even after traffic hashes became
// origin-aware. Most extracted paths are root-relative; absolute HTTP/WS URLs
// keep their own origin.
func resolvedRouteURL(r DiscoveredRoute) string {
	route, err := url.Parse(strings.TrimSpace(r.Path))
	if err != nil {
		return strings.TrimSpace(r.Path)
	}
	if route.IsAbs() {
		return route.String()
	}
	source, err := url.Parse(strings.TrimSpace(r.Source))
	if err != nil || source.Host == "" {
		return route.String()
	}
	if route.Path != "" && !strings.HasPrefix(route.Path, "/") {
		source.Path = appMountPathFromScriptSource(source.Path)
	} else {
		// Browser fetch("/api/users") is origin-root relative.
		source.Path = "/"
	}
	source.RawPath = ""
	source.RawQuery = ""
	source.Fragment = ""
	return source.ResolveReference(route).String()
}

func appMountPathFromScriptSource(sourcePath string) string {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" || sourcePath == "/" {
		return "/"
	}
	if !strings.HasPrefix(sourcePath, "/") {
		sourcePath = "/" + sourcePath
	}
	lower := strings.ToLower(sourcePath)
	for _, marker := range []string{
		"/lesson_js/", "/static/", "/assets/", "/asset/", "/js/", "/javascript/",
		"/scripts/", "/script/", "/dist/", "/build/", "/public/",
	} {
		if idx := strings.Index(lower, marker); idx >= 0 {
			prefix := sourcePath[:idx+1]
			if prefix == "" {
				return "/"
			}
			return prefix
		}
	}
	return "/"
}
