package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/ozzyw/aobtd/internal/browser"
	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/llm/prompts"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// Credentials holds login credentials provided by the pentester.
type Credentials struct {
	Username string
	Password string
	Extra    map[string]string // additional fields (MFA code, etc.)
}

// AuthAgent handles authentication flows — finds login forms,
// submits credentials, and manages sessions.
type AuthAgent struct {
	db          *store.DB
	ctrl        *browser.Controller
	nav         *browser.Navigator
	provider    llm.Provider
	budget      *llm.Budget
	bus         *Bus
	state       *SharedState
	scanID      int64
	logger      *slog.Logger
	credentials *Credentials
	interactor  Interactor
	// candidateLoginURLs are operator-supplied login pages (CLI/UI/env). They
	// seed findAuthPages alongside crawler-discovered login_found prompts.
	candidateLoginURLs []string
}

func (a *AuthAgent) SetBudget(budget *llm.Budget) { a.budget = budget }

// Interactor is the interface for asking the pentester questions.
type Interactor interface {
	Ask(question string) (string, error)
	Confirm(question string) (bool, error)
}

// NewAuthAgent creates an auth agent.
func NewAuthAgent(
	db *store.DB,
	ctrl *browser.Controller,
	provider llm.Provider,
	bus *Bus,
	state *SharedState,
	scanID int64,
	interactor Interactor,
	logger *slog.Logger,
) *AuthAgent {
	return &AuthAgent{
		db:         db,
		ctrl:       ctrl,
		nav:        browser.NewNavigator(ctrl, logger),
		provider:   provider,
		bus:        bus,
		state:      state,
		scanID:     scanID,
		logger:     logger,
		interactor: interactor,
	}
}

// SetCredentials lets the orchestrator preload creds collected non-interactively
// (via CLI flag or env var from the UI subprocess) so pre-crawl login doesn't
// need to block on a terminal prompt.
func (a *AuthAgent) SetCredentials(username, password string, extra map[string]string) {
	a.credentials = &Credentials{
		Username: username,
		Password: password,
		Extra:    extra,
	}
}

// SetCandidateLoginURLs preloads login-page candidates supplied by the
// operator. This is especially useful for hash-routed SPAs where the captured
// HTTP path is "/" but the real UI route is "/#/login".
func (a *AuthAgent) SetCandidateLoginURLs(urls ...string) {
	a.candidateLoginURLs = append(a.candidateLoginURLs[:0], urls...)
}

// AttemptDirectLogin runs a single login attempt against the given URL using
// whatever credentials were pre-provided. Unlike Start(), it doesn't scan
// captured traffic for candidate login pages — the caller tells us exactly
// where to go. Designed to run BEFORE the crawl so authenticated-only links
// can be discovered in the normal flow.
//
// Returns (true, nil) on apparent success, (false, nil) on apparent failure.
// Non-nil errors are for "couldn't even try" situations (browser down, etc.).
func (a *AuthAgent) AttemptDirectLogin(ctx context.Context, loginURL string) (bool, error) {
	endProvenance := a.ctrl.BeginTrafficProvenance(a.Name(), 0, "")
	defer endProvenance()

	if a.credentials == nil || a.credentials.Username == "" || a.credentials.Password == "" {
		return false, fmt.Errorf("no credentials provided")
	}
	if loginURL == "" {
		return false, fmt.Errorf("no login URL provided")
	}

	a.db.InsertNarration(a.scanID, "auth", "start",
		fmt.Sprintf("Attempting form login at %s as %s. Crawling will proceed as a logged-in user if this works.",
			loginURL, a.credentials.Username),
		loginURL, nil)
	a.logger.Info("pre-crawl login", "url", loginURL, "user", a.credentials.Username)

	// Snapshot the browser's cookie jar before we submit — we'll use the
	// before/after diff as a strong signal that we actually got a session.
	before := a.cookieJarSnapshot(loginURL)

	// Heavy SPAs (large e-commerce SPAs) take 10-30s just to settle on the
	// login page before we can even fill the form. Without a heartbeat the
	// operator stares at "running login now" wondering if the agent froze.
	// Without a hard timeout an unresponsive page hangs the whole scan
	// silently. Both fixes below.
	const loginAttemptTimeout = 45 * time.Second
	attemptCtx, cancel := context.WithTimeout(ctx, loginAttemptTimeout)
	defer cancel()

	heartbeatStop := make(chan struct{})
	go func() {
		// One heartbeat after 8s — the typical "form filled, waiting on
		// post-submit redirect" window. Beyond that we're either
		// genuinely stuck or the site is just slow; either way the
		// operator deserves a sign of life.
		select {
		case <-time.After(8 * time.Second):
			a.db.InsertNarration(a.scanID, "auth", "progress",
				fmt.Sprintf("Still working on login at %s — heavy SPAs take a while. Will give up after %s.",
					loginURL, loginAttemptTimeout),
				loginURL, nil)
		case <-heartbeatStop:
		}
	}()

	success, err := a.attemptLogin(attemptCtx, loginURL)
	close(heartbeatStop)
	if attemptCtx.Err() == context.DeadlineExceeded {
		a.db.InsertNarration(a.scanID, "auth", "timeout",
			fmt.Sprintf("Login on %s timed out after %s — couldn't tell if it worked. Continuing unauthenticated.",
				loginURL, loginAttemptTimeout),
			loginURL, nil)
		return false, nil
	}
	if err != nil {
		a.db.InsertNarration(a.scanID, "auth", "failed",
			fmt.Sprintf("Login attempt on %s errored: %s. Continuing unauthenticated.", loginURL, err.Error()),
			loginURL, nil)
		return false, nil
	}

	// Supplement the URL-based success check with cookie-jar diffing.
	// Filter aggressively — heavy SPAs (Next.js, Cloudflare-fronted, sites
	// with consent banners + analytics) drop dozens of cookies on plain
	// page-load that have nothing to do with auth. Counting any of them as
	// "we're logged in" produces false positives like the Example case
	// where the operator saw a "Login OK" with 25 _ga / NEXT_LOCALE /
	// __cf_bm cookies and zero session.
	after := a.cookieJarSnapshot(loginURL)
	newCookies := diffCookieNames(before, after)
	authCookies := filterAuthCookies(newCookies)
	if len(authCookies) > 0 {
		success = true
	}

	if success {
		// Note: session-cookie hardening now runs INSIDE attemptLogin's
		// defer, before page.Close(). That way Chrome still has an open
		// context when we re-write the cookies with explicit Expires —
		// session cookies can't be hardened after Chrome purges them
		// (which it does when the last pinning page closes).
		a.db.InsertNarration(a.scanID, "auth", "success",
			fmt.Sprintf("Login OK — new session cookie(s) acquired: %s. The rest of the scan runs as %s.",
				strings.Join(authCookies, ", "), a.credentials.Username),
			loginURL, map[string]any{"new_cookies": authCookies, "user": a.credentials.Username})
		a.bus.Publish(Event{
			Type:    EventAuthCompleted,
			Source:  a.Name(),
			Payload: map[string]string{"login_url": loginURL, "method": "form_submit"},
		})
		a.AddAuthFlow("form", loginURL, pickSessionCookie(authCookies))
	} else {
		a.db.InsertNarration(a.scanID, "auth", "failed",
			fmt.Sprintf("Login on %s did not succeed — no new session cookies observed and the page doesn't look authenticated. Continuing unauthenticated.", loginURL),
			loginURL, nil)
	}
	return success, nil
}

// AttemptAPILoginAndSeedBrowser logs in through a JSON API endpoint, extracts
// a bearer/JWT-style token from the response, and seeds the controlled browser's
// storage before crawling. This gives SPA targets a deterministic auth path
// when their Material/React login form is brittle but the API contract is known
// to the operator.
func (a *AuthAgent) AttemptAPILoginAndSeedBrowser(ctx context.Context, targetURL, loginAPIURL string) (bool, error) {
	endProvenance := a.ctrl.BeginTrafficProvenance(a.Name(), 0, "")
	defer endProvenance()

	if a.credentials == nil || a.credentials.Username == "" || a.credentials.Password == "" {
		return false, fmt.Errorf("no credentials provided")
	}
	if strings.TrimSpace(loginAPIURL) == "" {
		return false, fmt.Errorf("no API login URL provided")
	}
	a.db.InsertNarration(a.scanID, "auth", "api_login_start",
		fmt.Sprintf("Attempting API login at %s as %s, then seeding the browser session for the crawl.",
			loginAPIURL, a.credentials.Username),
		loginAPIURL, nil)

	body, status, err := postJSONLogin(ctx, loginAPIURL, map[string]string{
		"email":    a.credentials.Username,
		"password": a.credentials.Password,
	})
	if (err != nil || status < 200 || status >= 300 || extractAuthTokenFromJSON(body) == "") && !strings.Contains(a.credentials.Username, "@") {
		body, status, err = postJSONLogin(ctx, loginAPIURL, map[string]string{
			"username": a.credentials.Username,
			"password": a.credentials.Password,
		})
	}
	if err != nil {
		a.db.InsertNarration(a.scanID, "auth", "api_login_failed",
			fmt.Sprintf("API login at %s errored: %s.", loginAPIURL, err.Error()),
			loginAPIURL, nil)
		return false, nil
	}
	if status < 200 || status >= 300 {
		a.db.InsertNarration(a.scanID, "auth", "api_login_failed",
			fmt.Sprintf("API login at %s returned HTTP %d.", loginAPIURL, status),
			loginAPIURL, map[string]any{"status": status})
		return false, nil
	}

	token := extractAuthTokenFromJSON(body)
	if token == "" {
		a.db.InsertNarration(a.scanID, "auth", "api_login_failed",
			fmt.Sprintf("API login at %s succeeded but no token-like field was found in the response.", loginAPIURL),
			loginAPIURL, map[string]any{"status": status})
		return false, nil
	}
	storage := authStorageValuesFromLoginResponse(body, a.credentials.Username, token)
	if err := a.ctrl.SeedLocalStorage(ctx, targetURL, storage); err != nil {
		return false, err
	}
	if a.db != nil {
		if err := a.db.RecordCredentialHeaders(a.scanID, targetURL, map[string]string{
			"Authorization": "Bearer " + token,
		}, "api_login:"+loginAPIURL); err != nil {
			a.logger.Warn("record API login credential context failed", "error", err)
		}
	}

	a.db.InsertNarration(a.scanID, "auth", "api_login_success",
		"API login OK — token captured and seeded into the browser session before crawling.",
		loginAPIURL, map[string]any{
			"user":         a.credentials.Username,
			"storage_keys": sortedMapKeys(storage),
		})
	if a.bus != nil {
		a.bus.Publish(Event{
			Type:    EventAuthCompleted,
			Source:  a.Name(),
			Payload: map[string]string{"login_url": loginAPIURL, "method": "api_token_seed"},
		})
	}
	a.AddAuthFlow("api_token", loginAPIURL, "token")
	return true, nil
}

func postJSONLogin(ctx context.Context, loginURL string, payload map[string]string) ([]byte, int, error) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return data, resp.StatusCode, nil
}

func extractAuthTokenFromJSON(body []byte) string {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return ""
	}
	return findStringField(v, map[string]bool{
		"token": true, "access_token": true, "id_token": true,
		"jwt": true, "bearer": true,
	})
}

func authStorageValuesFromLoginResponse(body []byte, username, token string) map[string]string {
	out := map[string]string{
		"token":       token,
		"accessToken": token,
		"authToken":   token,
		"jwt":         token,
		"email":       username,
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		addPersistedReduxStorage(out)
		return out
	}
	for _, key := range []string{"bid", "umail", "role", "userId", "user_id", "id", "name", "number"} {
		if value := findStringField(v, map[string]bool{strings.ToLower(key): true}); value != "" {
			switch key {
			case "umail":
				out["email"] = value
			case "user_id":
				out["userId"] = value
			default:
				out[key] = value
			}
		}
	}
	addPersistedReduxStorage(out)
	return out
}

func addPersistedReduxStorage(out map[string]string) {
	user := map[string]any{
		"fetchingData":     false,
		"isLoggedIn":       true,
		"accessToken":      out["accessToken"],
		"id":               firstNonBlank(out["userId"], out["id"]),
		"name":             out["name"],
		"email":            out["email"],
		"number":           out["number"],
		"role":             out["role"],
		"available_credit": 0,
		"picture_url":      "",
		"video_url":        "",
		"video_id":         "",
		"video_name":       "",
	}
	userJSON, err := json.Marshal(user)
	if err != nil {
		return
	}
	persistJSON, err := json.Marshal(map[string]string{
		"userReducer": string(userJSON),
		"_persist":    `{"version":-1,"rehydrated":true}`,
	})
	if err != nil {
		return
	}
	// redux-persist stores this application under key "persist:reducers".
	// "persist:root" is included as a harmless common fallback for other SPAs.
	out["persist:reducers"] = string(persistJSON)
	out["persist:root"] = string(persistJSON)
}

func findStringField(v any, wanted map[string]bool) string {
	switch x := v.(type) {
	case map[string]any:
		for k, value := range x {
			if wanted[strings.ToLower(k)] {
				switch t := value.(type) {
				case string:
					return t
				case float64:
					return fmt.Sprintf("%.0f", t)
				case bool:
					return fmt.Sprintf("%t", t)
				}
			}
		}
		for _, value := range x {
			if got := findStringField(value, wanted); got != "" {
				return got
			}
		}
	case []any:
		for _, value := range x {
			if got := findStringField(value, wanted); got != "" {
				return got
			}
		}
	}
	return ""
}

func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// cookieJarSnapshot returns a map of cookie name -> value from the browser
// scoped to the login URL's origin. Used to detect "this request created a
// new session" without caring which specific cookie it was.
func (a *AuthAgent) cookieJarSnapshot(originURL string) map[string]string {
	snap := map[string]string{}
	if a.ctrl == nil {
		return snap
	}
	browser := a.ctrl.Browser()
	if browser == nil {
		return snap
	}
	cookies, err := browser.GetCookies()
	if err != nil {
		return snap
	}
	for _, c := range cookies {
		snap[c.Name] = c.Value
	}
	return snap
}

// diffCookieNames returns the cookie names whose values changed (or appeared)
// between two snapshots.
func diffCookieNames(before, after map[string]string) []string {
	var out []string
	for name, val := range after {
		if before[name] != val {
			out = append(out, name)
		}
	}
	return out
}

// filterAuthCookies keeps only cookie names that plausibly carry session
// state, dropping the analytics / CDN / consent / locale noise that any
// heavy SPA scatters on plain page load. Without this filter, the
// success-via-cookie-diff branch in AttemptDirectLogin treats a fresh
// __cf_bm or _ga as "logged in" — a hard false positive.
//
// The denylist below is the empirical noise floor we've seen on real
// targets (large e-commerce, Cloudflare-fronted
// sites). Anything not denied AND that looks session-y by name passes.
func filterAuthCookies(names []string) []string {
	out := names[:0:0] // fresh slice; never mutate caller
	for _, n := range names {
		if isLikelyAuthCookie(n) {
			out = append(out, n)
		}
	}
	return out
}

// noiseCookiePrefixes / noiseCookieNames are the static denylist. Match
// is case-insensitive and prefix-based for the prefixes, exact for names.
var noiseCookiePrefixes = []string{
	"_ga", "_gid", "_gcl", // Google Analytics / Ads
	"_fbp", "_fbc", // Facebook Pixel
	"_hj",                // Hotjar
	"__cf", "_cf", "cf_", // Cloudflare
	"ttcsid", "ki_", // Tealium / various analytics
	"next_", "__next", // Next.js locale + internal
	"cto_",                       // Criteo
	"_uetsid", "_uetvid", "muid", // Bing
	"intercom-", "amp_",
	"_pin_",
}
var noiseCookieNames = map[string]bool{
	"optanonconsent":        true,
	"optanonalertboxclosed": true,
	"currentlanguage":       true,
	"yashr":                 true, // Yahoo / Yandex routing
	"ty-lb-vid":             true, // load-balancer visitor id
	"x-tenantid":            true,
	"pi":                    true,
	"euconsent-v2":          true,
	"datadome":              true,
	"akacd_":                true,
}

// authCookieHints are name fragments that strongly suggest session state.
// We accept any cookie whose lowercased name contains one of these AND is
// not on the denylist.
var authCookieHints = []string{
	"session", "sessid", "sessionid",
	"auth", "token", "jwt",
	"sid", "phpsessid", "asp.net_sessionid",
	"connect.sid", "csrf", "xsrf",
	"login", "logged", "user", "remember",
}

func isLikelyAuthCookie(name string) bool {
	lower := strings.ToLower(name)
	if noiseCookieNames[lower] {
		return false
	}
	for _, p := range noiseCookiePrefixes {
		if strings.HasPrefix(lower, p) {
			return false
		}
	}
	for _, h := range authCookieHints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

// pickSessionCookie chooses the cookie name most likely to carry the session,
// for populating the app model's auth flow record.
func pickSessionCookie(names []string) string {
	for _, n := range names {
		lower := strings.ToLower(n)
		if strings.Contains(lower, "session") ||
			strings.Contains(lower, "auth") ||
			strings.Contains(lower, "token") ||
			strings.HasPrefix(lower, "sid") ||
			strings.Contains(lower, "jwt") {
			return n
		}
	}
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

func (a *AuthAgent) Name() string { return "auth" }

func (a *AuthAgent) Capabilities() []EventType {
	return []EventType{EventAuthRequired}
}

// Start runs the auth agent. It looks for login pages and attempts authentication.
func (a *AuthAgent) Start(ctx context.Context) error {
	endProvenance := a.ctrl.BeginTrafficProvenance(a.Name(), 0, "")
	defer endProvenance()

	a.logger.Info("auth agent starting")

	// Find login/register pages in captured traffic
	loginURLs := a.findAuthPages()
	if len(loginURLs) == 0 {
		a.logger.Info("no login pages found, skipping auth")
		return nil
	}

	a.logger.Info("found auth pages", "count", len(loginURLs))

	// Ask pentester for credentials unless the CLI/UI already supplied them.
	if a.credentials == nil || a.credentials.Username == "" || a.credentials.Password == "" {
		creds, err := a.askForCredentials(loginURLs)
		if err != nil {
			a.logger.Info("no credentials provided, skipping auth", "error", err)
			return nil
		}
		a.credentials = creds
	} else {
		a.logger.Info("using preconfigured credentials for auth phase", "user", a.credentials.Username)
	}

	// Try each login page
	for _, loginURL := range loginURLs {
		if ctx.Err() != nil {
			return nil
		}

		a.logger.Info("attempting login", "url", loginURL)

		success, err := a.attemptLogin(ctx, loginURL)
		if err != nil {
			a.logger.Warn("login attempt failed", "url", loginURL, "error", err)
			continue
		}

		if success {
			a.logger.Info("login successful!", "url", loginURL)
			a.bus.Publish(Event{
				Type:   EventAuthCompleted,
				Source: a.Name(),
				Payload: map[string]string{
					"login_url": loginURL,
					"method":    "form_submit",
				},
			})
			return nil
		}
	}

	a.logger.Warn("all login attempts failed")
	return nil
}

func (a *AuthAgent) findAuthPages() []string {
	var urls []string
	seen := make(map[string]bool)
	addURL := func(raw string) {
		u := strings.TrimSpace(raw)
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		urls = append(urls, u)
	}

	for _, u := range a.candidateLoginURLs {
		addURL(u)
	}

	// Browser-driven SPA crawls may discover a login form at a hash route
	// like /#/login even though every captured HTTP request has path "/".
	// The crawler records that as a login_found prompt; AuthAgent should treat
	// it as evidence, not rely only on traffic.path.
	a.appendPromptAuthPages(addURL)
	if len(urls) > 0 {
		return urls
	}

	rows, err := a.db.Conn().Query(`
		SELECT DISTINCT url FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE
		  AND (
		    LOWER(path) LIKE '%login%' OR
		    LOWER(path) LIKE '%signin%' OR
		    LOWER(path) LIKE '%sign-in%' OR
		    LOWER(path) LIKE '%auth%' OR
		    LOWER(path) LIKE '%account%' OR
		    LOWER(path) LIKE '%register%' OR
		    LOWER(path) LIKE '%signup%'
		  )
		  AND method = 'GET'
		  AND status_code = 200
		LIMIT 5`,
		a.scanID,
	)
	if err != nil {
		return urls
	}
	defer rows.Close()

	for rows.Next() {
		var url string
		rows.Scan(&url)
		if isLikelyAuthPageURL(url) {
			addURL(url)
		}
	}

	// Also check for pages with password inputs
	if len(urls) == 0 {
		rows2, err := a.db.Conn().Query(`
			SELECT DISTINCT url FROM traffic_resolved
			WHERE scan_id = ? AND is_filtered = FALSE
			  AND has_input = TRUE
			  AND LOWER(response_body) LIKE '%type="password"%'
			  AND method = 'GET'
			LIMIT 5`,
			a.scanID,
		)
		if err == nil {
			defer rows2.Close()
			for rows2.Next() {
				var url string
				rows2.Scan(&url)
				addURL(url)
			}
		}
	}

	return urls
}

func (a *AuthAgent) appendPromptAuthPages(addURL func(string)) {
	rows, err := a.db.Conn().Query(`
		SELECT payload FROM prompts
		WHERE scan_id = ? AND kind = 'login_found'
		ORDER BY id DESC
		LIMIT 10`,
		a.scanID,
	)
	if err != nil {
		return
	}
	defer rows.Close()

	type loginPromptPayload struct {
		PageURL   string `json:"page_url"`
		SubmitURL string `json:"submit_url"`
		URL       string `json:"url"`
		LoginURL  string `json:"login_url"`
	}
	for rows.Next() {
		var payloadJSON string
		if err := rows.Scan(&payloadJSON); err != nil {
			continue
		}
		var payload loginPromptPayload
		if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
			continue
		}
		// Page/login URLs are browser destinations. Submit URLs are commonly
		// JSON/API endpoints (for example Juice Shop's
		// /rest/user/authentication-details/) and must not be promoted into
		// "pages to visit and fill"; doing so can strand the auth agent on API
		// responses or SPA fallback routes.
		addURL(payload.PageURL)
		addURL(payload.LoginURL)
		addURL(payload.URL)
		if isLikelyAuthPageURL(payload.SubmitURL) {
			addURL(payload.SubmitURL)
		}
	}
}

func isLikelyAuthPageURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	fragment := strings.ToLower(u.Fragment)
	if containsAuthPageKeyword(fragment) {
		return true
	}
	if isLikelyNonPageAuthPath(path) {
		return false
	}
	return containsAuthPageKeyword(path)
}

func containsAuthPageKeyword(s string) bool {
	for _, needle := range []string{"login", "log-in", "signin", "sign-in", "auth", "account", "register", "signup", "sign-up"} {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func isLikelyNonPageAuthPath(path string) bool {
	path = strings.TrimSpace(strings.ToLower(path))
	if path == "" {
		return false
	}
	for _, prefix := range []string{"/api/", "/rest/", "/graphql", "/socket.io/", "/ws/", "/rpc/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	if strings.Contains(path, "/socket.io/") {
		return true
	}
	for _, suffix := range []string{".js", ".mjs", ".css", ".map", ".json", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func (a *AuthAgent) askForCredentials(loginURLs []string) (*Credentials, error) {
	if a.interactor == nil {
		return nil, fmt.Errorf("no interactor available")
	}

	fmt.Printf("\n=== Authentication Required ===\n")
	fmt.Printf("Found login pages:\n")
	for _, u := range loginURLs {
		fmt.Printf("  - %s\n", u)
	}
	fmt.Println()

	proceed, err := a.interactor.Confirm("Do you want to provide credentials for authenticated scanning?")
	if err != nil || !proceed {
		return nil, fmt.Errorf("user declined")
	}

	username, err := a.interactor.Ask("Username/email:")
	if err != nil {
		return nil, err
	}

	password, err := a.interactor.Ask("Password:")
	if err != nil {
		return nil, err
	}

	return &Credentials{
		Username: strings.TrimSpace(username),
		Password: strings.TrimSpace(password),
	}, nil
}

func (a *AuthAgent) attemptLogin(ctx context.Context, loginURL string) (bool, error) {
	// Navigate to the login page
	page, err := a.ctrl.Navigate(ctx, loginURL)
	if err != nil {
		return false, fmt.Errorf("navigate: %w", err)
	}
	// Cookie harden BEFORE the defer fires. PHP apps (bWAPP / DVWA)
	// issue a fresh PHPSESSID on login as a session-fixation defence;
	// those arrive as session-only cookies. When Rod closes the last
	// open page in the browser, Chrome's cookie storage purges session
	// cookies with no open context to pin them to — meaning the crawler's
	// next page boots with an empty jar. The fix is to re-write every
	// cookie in the jar with an explicit 24h Expires WHILE the login
	// page is still open. Controller.HardenSessionCookies handles the
	// read-set cycle; call it right before the page closes.
	defer func() {
		if _, err := a.ctrl.HardenSessionCookies(ctx); err != nil {
			a.logger.Warn("cookie-harden during login close failed", "error", err)
		}
		page.Close()
	}()

	time.Sleep(2 * time.Second)

	// Capture page state
	pageState, err := a.nav.CapturePageState(page)
	if err != nil {
		return false, fmt.Errorf("capture state: %w", err)
	}

	// Try standard form fill first (before using LLM)
	if a.tryStandardLogin(page, pageState) {
		if a.checkLoginSuccess(page) {
			return true, nil
		}
		if refreshed, err := a.nav.CapturePageState(page); err == nil {
			pageState = refreshed
		}
	}

	// Fall back to LLM-guided login
	if a.provider != nil {
		return a.llmGuidedLogin(ctx, page, pageState)
	}

	return false, fmt.Errorf("could not find login form")
}

func (a *AuthAgent) tryStandardLogin(page *rod.Page, state *browser.PageState) bool {
	pa := browser.NewPageAction(page, 4*time.Second)
	stateUserSelectors, statePasswordSelectors, stateSubmitSelectors := loginSelectorsFromPageState(state)

	// Look for common username/password field patterns
	usernameSelectors := appendUniqueSelectors(stateUserSelectors,
		"#email", "input#email",
		"input[formcontrolname='email']",
		"input[aria-label='Text field for the login email']",
		"#username", "input#username",
		"input[name='username']", "input[name='email']",
		"input[name='user']", "input[name='login']",
		"input[type='email']", "input[name='userId']",
		"input[id='username']", "input[id='email']",
	)

	passwordSelectors := appendUniqueSelectors(statePasswordSelectors,
		"#password", "input#password",
		"input[formcontrolname='password']",
		"input[aria-label='Text field for the login password']",
		"input[type='password']",
		"input[name='password']", "input[name='pass']",
	)

	submitSelectors := appendUniqueSelectors(stateSubmitSelectors,
		"#loginButton", "button#loginButton",
		"button[aria-label='Login']",
		"button[type='submit']", "input[type='submit']",
		"button:has-text('Login')", "button:has-text('Log in')", "button:has-text('Sign in')",
	)

	// Fast SPA path: querySelector + native value setter + input/change events
	// is much cheaper than trying a long selector list through Rod, where each
	// missing selector can consume the full action timeout. This path keeps
	// Angular/React bindings updated and fixes Juice Shop-style Material forms
	// that are visible but conservative interactability checks dislike.
	if a.fillLoginInputsWithDOMEvents(page, usernameSelectors, passwordSelectors) {
		if a.clickLoginSubmitWithDOM(page, submitSelectors) {
			a.logger.Debug("filled and submitted login form via DOM event fallback")
			time.Sleep(3 * time.Second)
			return true
		}
		if a.pressEnterOnLoginPasswordWithDOM(page, passwordSelectors) {
			a.logger.Debug("filled login form via DOM event fallback and submitted with Enter")
			time.Sleep(3 * time.Second)
			return true
		}
	}

	// Try to fill username
	userFilled := false
	for _, sel := range usernameSelectors {
		err := pa.Fill(sel, a.credentials.Username)
		if err == nil {
			userFilled = true
			a.logger.Debug("filled username", "selector", sel)
			break
		}
		if isInteractabilityBlock(err) {
			a.logger.Debug("username field exists but is blocked", "selector", sel, "error", err)
		}
	}

	// Fill password
	passFilled := false
	for _, sel := range passwordSelectors {
		err := pa.Fill(sel, a.credentials.Password)
		if err == nil {
			passFilled = true
			a.logger.Debug("filled password", "selector", sel)
			break
		}
		if isInteractabilityBlock(err) {
			a.logger.Debug("password field exists but is blocked", "selector", sel, "error", err)
		}
	}

	if !userFilled || !passFilled {
		if a.fillLoginInputsWithDOMEvents(page, usernameSelectors, passwordSelectors) {
			userFilled = true
			passFilled = true
			a.logger.Debug("filled login form via DOM input/change fallback")
		}
	}

	if !userFilled || !passFilled {
		return false
	}

	// Submit
	for _, sel := range submitSelectors {
		err := pa.Click(sel)
		if err == nil {
			a.logger.Debug("clicked submit", "selector", sel)
			time.Sleep(3 * time.Second)
			return true
		}
		if isInteractabilityBlock(err) {
			a.logger.Debug("submit control exists but is blocked", "selector", sel, "error", err)
		}
	}
	if a.clickLoginSubmitWithDOM(page, submitSelectors) {
		a.logger.Debug("clicked login submit via DOM fallback")
		time.Sleep(3 * time.Second)
		return true
	}

	// Try submitting via Enter key on password field
	if err := pa.Submit("input[type='password']"); err == nil {
		time.Sleep(3 * time.Second)
		return true
	}
	if a.pressEnterOnLoginPasswordWithDOM(page, passwordSelectors) {
		time.Sleep(3 * time.Second)
		return true
	}
	return false
}

func (a *AuthAgent) fillLoginInputsWithDOMEvents(page *rod.Page, usernameSelectors, passwordSelectors []string) bool {
	if a.credentials == nil {
		return false
	}
	cfg := map[string]any{
		"user_selectors":     usernameSelectors,
		"password_selectors": passwordSelectors,
		"username":           a.credentials.Username,
		"password":           a.credentials.Password,
	}
	cfgJSON, _ := json.Marshal(cfg)
	js := fmt.Sprintf(`() => {
		const cfg = %s;
		const visibleEnough = (el) => {
			if (!el) return false;
			const style = window.getComputedStyle(el);
			const rect = el.getBoundingClientRect();
			return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
		};
		const first = (selectors) => {
			for (const sel of selectors || []) {
				try {
					const el = document.querySelector(sel);
					if (visibleEnough(el) && !el.disabled && el.getAttribute('aria-disabled') !== 'true') return el;
				} catch (_) {}
			}
			return null;
		};
		const setNativeValue = (el, value) => {
			el.scrollIntoView({block: 'center', inline: 'nearest'});
			el.focus();
			const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
			const setter = Object.getOwnPropertyDescriptor(proto, 'value') && Object.getOwnPropertyDescriptor(proto, 'value').set;
			if (setter) setter.call(el, value);
			else el.value = value;
			el.dispatchEvent(new InputEvent('input', {bubbles: true, inputType: 'insertText', data: value}));
			el.dispatchEvent(new Event('change', {bubbles: true}));
			return String(el.value || '') === String(value);
		};
		const user = first(cfg.user_selectors);
		const pass = first(cfg.password_selectors);
		return {
			user_filled: !!user && setNativeValue(user, cfg.username),
			password_filled: !!pass && setNativeValue(pass, cfg.password)
		};
	}`, string(cfgJSON))

	result, err := page.Eval(js)
	if err != nil {
		a.logger.Debug("DOM login fill fallback failed", "error", err)
		return false
	}
	var out struct {
		UserFilled     bool `json:"user_filled"`
		PasswordFilled bool `json:"password_filled"`
	}
	if err := json.Unmarshal([]byte(result.Value.JSON("", "")), &out); err != nil {
		a.logger.Debug("DOM login fill fallback returned unreadable result", "error", err)
		return false
	}
	return out.UserFilled && out.PasswordFilled
}

func (a *AuthAgent) clickLoginSubmitWithDOM(page *rod.Page, submitSelectors []string) bool {
	cfgJSON, _ := json.Marshal(map[string]any{"submit_selectors": submitSelectors})
	js := fmt.Sprintf(`() => {
		const cfg = %s;
		const visibleEnough = (el) => {
			if (!el) return false;
			const style = window.getComputedStyle(el);
			const rect = el.getBoundingClientRect();
			return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
		};
		const candidates = [];
		for (const sel of cfg.submit_selectors || []) {
			try {
				const el = document.querySelector(sel);
				if (visibleEnough(el)) candidates.push(el);
			} catch (_) {}
		}
		if (!candidates.length) {
			for (const el of Array.from(document.querySelectorAll("button, input[type='submit'], [role='button']"))) {
				const text = String(el.innerText || el.value || el.getAttribute('aria-label') || '').toLowerCase();
				const type = String(el.getAttribute('type') || '').toLowerCase();
				if (visibleEnough(el) && (type === 'submit' || text.includes('login') || text.includes('log in') || text.includes('sign in'))) {
					candidates.push(el);
				}
			}
		}
		const el = candidates.find(el => !el.disabled && el.getAttribute('aria-disabled') !== 'true');
		if (!el) return false;
		el.scrollIntoView({block: 'center', inline: 'nearest'});
		el.click();
		return true;
	}`, string(cfgJSON))
	result, err := page.Eval(js)
	if err != nil {
		a.logger.Debug("DOM login click fallback failed", "error", err)
		return false
	}
	return result.Value.Bool()
}

func (a *AuthAgent) pressEnterOnLoginPasswordWithDOM(page *rod.Page, passwordSelectors []string) bool {
	cfgJSON, _ := json.Marshal(map[string]any{"password_selectors": passwordSelectors})
	js := fmt.Sprintf(`() => {
		const cfg = %s;
		let el = null;
		for (const sel of cfg.password_selectors || []) {
			try {
				el = document.querySelector(sel);
				if (el) break;
			} catch (_) {}
		}
		if (!el) el = document.querySelector("input[type='password']");
		if (!el) return false;
		el.focus();
		for (const type of ['keydown', 'keypress', 'keyup']) {
			el.dispatchEvent(new KeyboardEvent(type, {key: 'Enter', code: 'Enter', bubbles: true, cancelable: true}));
		}
		return true;
	}`, string(cfgJSON))
	result, err := page.Eval(js)
	if err != nil {
		a.logger.Debug("DOM login enter fallback failed", "error", err)
		return false
	}
	return result.Value.Bool()
}

func loginSelectorsFromPageState(state *browser.PageState) (userSelectors, passwordSelectors, submitSelectors []string) {
	if state == nil {
		return nil, nil, nil
	}

	for _, form := range state.Forms {
		for _, input := range form.Inputs {
			userSelectors, passwordSelectors = classifyLoginInputSelector(input, userSelectors, passwordSelectors)
		}
	}
	for _, input := range state.Inputs {
		userSelectors, passwordSelectors = classifyLoginInputSelector(input, userSelectors, passwordSelectors)
	}
	for _, button := range state.Buttons {
		if button.Selector == "" {
			continue
		}
		hint := strings.ToLower(strings.Join([]string{button.Text, button.Type, button.Selector}, " "))
		if strings.Contains(hint, "login") || strings.Contains(hint, "log in") ||
			strings.Contains(hint, "sign in") || button.Type == "submit" {
			submitSelectors = append(submitSelectors, button.Selector)
		}
	}

	return appendUniqueSelectors(userSelectors), appendUniqueSelectors(passwordSelectors), appendUniqueSelectors(submitSelectors)
}

func classifyLoginInputSelector(input browser.InputInfo, userSelectors, passwordSelectors []string) ([]string, []string) {
	if input.Selector == "" {
		return userSelectors, passwordSelectors
	}
	hint := strings.ToLower(strings.Join([]string{input.Name, input.Type, input.Value, input.Selector}, " "))
	switch {
	case input.Type == "password" || strings.Contains(hint, "password") || strings.Contains(hint, "pass"):
		passwordSelectors = append(passwordSelectors, input.Selector)
	case input.Type == "email" || strings.Contains(hint, "email") || strings.Contains(hint, "user") || strings.Contains(hint, "login"):
		userSelectors = append(userSelectors, input.Selector)
	}
	return userSelectors, passwordSelectors
}

func appendUniqueSelectors(base []string, extra ...string) []string {
	out := make([]string, 0, len(base)+len(extra))
	seen := map[string]bool{}
	for _, sel := range append(base, extra...) {
		sel = strings.TrimSpace(sel)
		if sel == "" || seen[sel] {
			continue
		}
		seen[sel] = true
		out = append(out, sel)
	}
	return out
}

func isInteractabilityBlock(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "wait interactable")
}

const maxLoginLLMRounds = 5

func (a *AuthAgent) llmGuidedLogin(ctx context.Context, page *rod.Page, state *browser.PageState) (bool, error) {
	current := state
	attempted := map[string]int{}
	var recentFailures []string

	for round := 1; round <= maxLoginLLMRounds; round++ {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if current == nil {
			refreshed, err := a.nav.CapturePageState(page)
			if err != nil {
				return false, fmt.Errorf("capture state round %d: %w", round, err)
			}
			current = refreshed
		}

		// After an LLM closes a modal/banner, the ordinary form selectors may
		// become usable. Re-try the deterministic path before spending another
		// model call.
		if round > 1 && a.tryStandardLogin(page, current) {
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-ctx.Done():
				return false, ctx.Err()
			}
			if a.checkLoginSuccess(page) {
				return true, nil
			}
			if refreshed, err := a.nav.CapturePageState(page); err == nil {
				current = refreshed
			}
		}

		actions, err := a.decideLoginActions(ctx, current, round, recentFailures)
		if err != nil {
			return false, err
		}
		if len(actions) == 0 {
			recentFailures = appendBounded(recentFailures, fmt.Sprintf("round %d: model returned no actions", round), 5)
			current = nil
			continue
		}

		executed := false
		for _, action := range actions {
			action.Action = strings.TrimSpace(strings.ToLower(action.Action))
			action = normalizeLoginActionCredentials(action, a.credentials)

			switch action.Action {
			case "done":
				if a.checkLoginSuccess(page) {
					return true, nil
				}
				recentFailures = appendBounded(recentFailures, "model said done, but the page still does not look authenticated", 5)
				continue
			case "ask_human":
				recentFailures = appendBounded(recentFailures, "model asked for human input during automated login", 5)
				continue
			}

			key := loginActionKey(action)
			attempted[key]++
			if attempted[key] > 2 {
				recentFailures = appendBounded(recentFailures,
					fmt.Sprintf("skipped repeated action %s on %s", action.Action, action.Selector), 5)
				continue
			}

			if err := a.nav.ExecuteAction(ctx, page, &action); err != nil {
				msg := fmt.Sprintf("round %d action %s %q failed: %s", round, action.Action, action.Selector, err.Error())
				recentFailures = appendBounded(recentFailures, msg, 5)
				a.logger.Warn("login action failed", "round", round, "action", action.Action, "selector", action.Selector, "error", err)
				continue
			}
			executed = true
		}

		if !executed {
			current = nil
			continue
		}

		select {
		case <-time.After(1500 * time.Millisecond):
		case <-ctx.Done():
			return false, ctx.Err()
		}

		if a.checkLoginSuccess(page) {
			return true, nil
		}
		refreshed, err := a.nav.CapturePageState(page)
		if err != nil {
			return false, fmt.Errorf("capture state after round %d: %w", round, err)
		}
		current = refreshed
	}

	a.db.InsertNarration(a.scanID, "auth", "failed",
		fmt.Sprintf("LLM-guided login stopped after %d rounds without reaching an authenticated page.", maxLoginLLMRounds),
		"", map[string]any{"recent_failures": recentFailures})
	return false, nil
}

func (a *AuthAgent) decideLoginActions(ctx context.Context, state *browser.PageState, round int, recentFailures []string) ([]browser.NavigatorAction, error) {
	stateJSON, _ := json.MarshalIndent(state, "", "  ")

	failures := "none"
	if len(recentFailures) > 0 {
		failures = strings.Join(recentFailures, "\n- ")
	}

	prompt := fmt.Sprintf(`I need to log into this page. This is round %d of at most %d.

Current page state:

%s

Credentials available:
- Username/email: %s
- Password: provided, but do not print it.

Recent failed/blocked attempts:
- %s

Return a JSON array of 1-3 browser actions.
Use only selectors that appear in the page state when possible.
If a modal, banner, or menu blocks the login form, close/open that first.
If the login form is visible, fill username/email, fill password, then submit.
Use placeholder values "USERNAME" and "PASSWORD" for credentials.
If the page already appears authenticated, return [{"action":"done","reason":"already authenticated"}].
Valid actions are click, fill, submit, navigate, scroll, done, ask_human.
Respond with JSON only.`,
		round, maxLoginLLMRounds, string(stateJSON), a.credentials.Username, failures)

	start := time.Now()
	req := &llm.Request{
		SystemPrompt: prompts.NavigatorSystemPrompt,
		Messages:     []llm.Message{{Role: "user", Content: prompt}},
		Temperature:  0.1,
		MaxTokens:    1024,
		JSONMode:     true,
	}
	resp, err := llm.CompleteBudgeted(ctx, a.provider, a.budget, req, 0)
	durationMs := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("LLM: %w", err)
	}

	modelID := llm.ResponseModel(resp, a.provider)
	costUcents := llm.CostMicroCents(modelID, resp.Usage)
	a.db.LogAIFull(a.scanID, "auth", "login_decide",
		fmt.Sprintf("llm-guided login round %d/%d", round, maxLoginLLMRounds), "", "", truncate(resp.Content, 200),
		resp.Usage.InputTokens, resp.Usage.OutputTokens, durationMs, costUcents, modelID,
		llm.RenderPrompt(req), resp.Content)

	actions, err := parseLoginActions(resp.Content)
	if err != nil {
		return nil, fmt.Errorf("parse actions: %w", err)
	}
	return actions, nil
}

func normalizeLoginActionCredentials(action browser.NavigatorAction, creds *Credentials) browser.NavigatorAction {
	if creds == nil {
		return action
	}
	lower := strings.ToLower(strings.TrimSpace(action.Value))
	switch {
	case lower == "username" || lower == "user" || lower == "email" || lower == "username/email" ||
		lower == "{{username}}" || lower == "{{email}}":
		action.Value = creds.Username
	case lower == "password" || lower == "{{password}}":
		action.Value = creds.Password
	case strings.Contains(lower, "username") || strings.Contains(lower, "email"):
		action.Value = creds.Username
	case strings.Contains(lower, "password"):
		action.Value = creds.Password
	}
	return action
}

func loginActionKey(action browser.NavigatorAction) string {
	return strings.Join([]string{
		action.Action,
		action.Selector,
		action.URL,
		action.Value,
	}, "\x00")
}

func appendBounded(in []string, item string, max int) []string {
	in = append(in, item)
	if len(in) > max {
		return in[len(in)-max:]
	}
	return in
}

func (a *AuthAgent) checkLoginSuccess(page *rod.Page) bool {
	info, err := page.Info()
	if err != nil {
		return false
	}

	url := strings.ToLower(info.URL)

	// If we're no longer on a login page, likely succeeded
	if !strings.Contains(url, "login") && !strings.Contains(url, "signin") &&
		!strings.Contains(url, "sign-in") && !strings.Contains(url, "auth") {
		a.logger.Info("redirected away from login, likely success", "new_url", info.URL)
		return true
	}

	// Check for error messages on page
	body, err := page.HTML()
	if err != nil {
		return false
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "invalid password") ||
		strings.Contains(lower, "incorrect") ||
		strings.Contains(lower, "failed") ||
		strings.Contains(lower, "error") {
		a.logger.Warn("login appears to have failed (error message detected)")
		return false
	}

	return false
}

// AddAuthFlow records a discovered auth flow in the app model.
func (a *AuthAgent) AddAuthFlow(flowType, loginURL, tokenName string) {
	a.state.UpdateModel(func(m *types.AppModel) {
		m.AuthFlows = append(m.AuthFlows, types.AuthFlow{
			Type:      flowType,
			LoginURL:  loginURL,
			TokenName: tokenName,
		})
	})
}

func extractJSONArray(s string) string {
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}

func parseLoginActions(content string) ([]browser.NavigatorAction, error) {
	raw := strings.TrimSpace(content)
	if strings.HasPrefix(raw, "```") {
		if i := strings.Index(raw, "\n"); i > 0 {
			raw = raw[i+1:]
		}
		if j := strings.LastIndex(raw, "```"); j > 0 {
			raw = raw[:j]
		}
		raw = strings.TrimSpace(raw)
	}

	var actions []browser.NavigatorAction
	if err := json.Unmarshal([]byte(raw), &actions); err == nil {
		return actions, nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	if err := decoder.Decode(&actions); err == nil {
		return actions, nil
	}

	if action, err := browser.ParseAction(raw); err == nil && action.Action != "" {
		return []browser.NavigatorAction{*action}, nil
	}

	cleaned := extractJSONArray(raw)
	if cleaned != raw {
		if err := json.Unmarshal([]byte(cleaned), &actions); err == nil {
			return actions, nil
		}
		decoder := json.NewDecoder(strings.NewReader(cleaned))
		if err := decoder.Decode(&actions); err == nil {
			return actions, nil
		}
	}

	return nil, fmt.Errorf("response is not a JSON action array or action object")
}
