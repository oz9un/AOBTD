package agent

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/browser"
	"github.com/ozzyw/aobtd/internal/store"
)

// exampleNoise is the exact 25-cookie set that the cookie-diff success
// heuristic mistakenly flagged as "Login OK" against example.com when the
// operator submitted invalid credentials. None of these are session
// cookies — they're the analytics / CDN / consent / locale soup that any
// heavy SPA drops on a plain page load.
var exampleNoise = []string{
	"ttcsid", "ki_t", "_ga_N1DYMXS48V", "NEXT_LOCALE", "NEXT_ALL_LANG_LIST",
	"NEXT_URL", "_ga", "cto_bundle", "NEXT_CURRENT_DOMAIN", "__cf_bm",
	"X-TenantId", "_gat_UA-13174585-49", "yashr", "CurrentLanguage",
	"_hjSession_2381650", "__cflb", "OptanonConsent",
	"NEXT_CURRENT_DOMAIN_NAME", "ttcsid_CJ94PP3C77U0073JONJ0", "_cfuvid",
	"pi", "_hjSessionUser_2381650", "ty-lb-vid", "_ga_E342GWJ9XV",
	"NEXT_CURRENT_LANG_LIST",
}

func TestFilterAuthCookies_ExampleFalsePositive(t *testing.T) {
	got := filterAuthCookies(exampleNoise)
	if len(got) != 0 {
		t.Fatalf("expected zero auth-likely cookies in Example noise set, got %d: %v",
			len(got), got)
	}
}

func TestFilterAuthCookies_AcceptsRealSessionNames(t *testing.T) {
	cases := []string{
		"PHPSESSID",
		"sessionid",
		"connect.sid",
		"JSESSIONID",
		"session",
		"auth_token",
		"jwt",
		"csrftoken",
		"user_session",
		"remember_me",
		"laravel_session",
	}
	got := filterAuthCookies(cases)
	if len(got) != len(cases) {
		t.Fatalf("expected all %d real session-cookie names to pass, got %d: %v",
			len(cases), len(got), got)
	}
}

func TestFilterAuthCookies_RejectsAnalyticsAndCDN(t *testing.T) {
	cases := []string{
		"_ga", "_ga_ABC123", "_gid", "_gcl_au",
		"_fbp", "_fbc",
		"_hjid", "_hjSession_42",
		"__cf_bm", "_cfuvid", "__cflb", "cf_clearance",
		"_uetsid", "_uetvid", "MUID",
		"OptanonConsent", "euconsent-v2",
		"NEXT_LOCALE", "NEXT_URL",
		"datadome",
	}
	got := filterAuthCookies(cases)
	if len(got) != 0 {
		t.Fatalf("expected zero analytics/CDN cookies to pass, got %d: %v",
			len(got), got)
	}
}

func TestFilterAuthCookies_DoesNotMutateInput(t *testing.T) {
	in := []string{"PHPSESSID", "_ga", "auth_token"}
	_ = filterAuthCookies(in)
	if in[0] != "PHPSESSID" || in[1] != "_ga" || in[2] != "auth_token" {
		t.Fatalf("filterAuthCookies mutated input: %v", in)
	}
}

func TestFindAuthPagesUsesLoginFoundPromptForSPARoute(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "auth-pages.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	scanID, err := db.CreateScan("http://127.0.0.1:3000", `{}`)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if _, err := db.InsertPrompt(scanID, "login_found", map[string]any{
		"page_url":   "http://127.0.0.1:3000#/login",
		"submit_url": "http://127.0.0.1:3000#/login",
		"user_field": "email",
		"pass_field": "password",
	}); err != nil {
		t.Fatalf("insert prompt: %v", err)
	}

	auth := &AuthAgent{db: db, scanID: scanID}
	got := auth.findAuthPages()
	if len(got) != 1 {
		t.Fatalf("findAuthPages() len = %d, want 1: %v", len(got), got)
	}
	if got[0] != "http://127.0.0.1:3000#/login" {
		t.Fatalf("findAuthPages()[0] = %q", got[0])
	}
}

func TestFindAuthPagesRejectsLoginPromptSubmitAPI(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "auth-pages-submit-api.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	scanID, err := db.CreateScan("http://127.0.0.1:3000", `{}`)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if _, err := db.InsertPrompt(scanID, "login_found", map[string]any{
		"page_url":   "http://127.0.0.1:3000/#/login",
		"submit_url": "http://127.0.0.1:3000/rest/user/authentication-details/",
		"user_field": "email",
		"pass_field": "password",
	}); err != nil {
		t.Fatalf("insert prompt: %v", err)
	}

	auth := &AuthAgent{db: db, scanID: scanID}
	got := auth.findAuthPages()
	if len(got) != 1 {
		t.Fatalf("findAuthPages() = %v, want only SPA login page", got)
	}
	if got[0] != "http://127.0.0.1:3000/#/login" {
		t.Fatalf("findAuthPages()[0] = %q", got[0])
	}
}

func TestFindAuthPagesIncludesCandidateLoginURL(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "auth-candidates.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	scanID, err := db.CreateScan("http://127.0.0.1:3000", `{}`)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}

	auth := &AuthAgent{db: db, scanID: scanID}
	auth.SetCandidateLoginURLs("", "  http://127.0.0.1:3000/#/login  ", "http://127.0.0.1:3000/#/login")

	got := auth.findAuthPages()
	if len(got) != 1 {
		t.Fatalf("findAuthPages() len = %d, want 1: %v", len(got), got)
	}
	if got[0] != "http://127.0.0.1:3000/#/login" {
		t.Fatalf("candidate URL = %q", got[0])
	}
}

func TestFindAuthPagesPrefersOperatorCandidateOverTrafficHeuristics(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "auth-candidate-priority.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	scanID, err := db.CreateScan("http://127.0.0.1:3000", `{}`)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if _, err := db.Conn().Exec(`
		INSERT INTO traffic (scan_id, method, url, host, path, status_code, response_body)
		VALUES (?, 'GET', 'http://127.0.0.1:3000/rest/user/authentication-details/', '127.0.0.1:3000', '/rest/user/authentication-details/', 200, ?)`,
		scanID, []byte(`{"status":"success"}`)); err != nil {
		t.Fatalf("insert traffic: %v", err)
	}

	auth := &AuthAgent{db: db, scanID: scanID}
	auth.SetCandidateLoginURLs("http://127.0.0.1:3000/#/login")

	got := auth.findAuthPages()
	if len(got) != 1 {
		t.Fatalf("findAuthPages() = %v, want only operator-provided login URL", got)
	}
	if got[0] != "http://127.0.0.1:3000/#/login" {
		t.Fatalf("candidate URL = %q", got[0])
	}
}

func TestLoginSelectorsFromPageStateCapturesMaterialLoginInputs(t *testing.T) {
	userSelectors, passwordSelectors, submitSelectors := loginSelectorsFromPageState(&browser.PageState{
		Inputs: []browser.InputInfo{
			{
				Name:     "email",
				Type:     "email",
				Selector: `input[aria-label="Text field for the login email"]`,
			},
			{
				Name:     "password",
				Type:     "password",
				Selector: `input[aria-label="Text field for the login password"]`,
			},
		},
		Buttons: []browser.ButtonInfo{
			{Text: "Login", Selector: "#loginButton", Type: "submit"},
		},
	})

	for _, tt := range []struct {
		name string
		got  []string
		want string
	}{
		{"user", userSelectors, `input[aria-label="Text field for the login email"]`},
		{"password", passwordSelectors, `input[aria-label="Text field for the login password"]`},
		{"submit", submitSelectors, "#loginButton"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, got := range tt.got {
				if got == tt.want {
					return
				}
			}
			t.Fatalf("selectors %v missing %q", tt.got, tt.want)
		})
	}
}

func TestAuthStorageValuesFromNestedLoginResponse(t *testing.T) {
	body := []byte(`{
		"authentication": {
			"token": "jwt-token",
			"bid": 8,
			"umail": "alice@example.test"
		}
	}`)
	token := extractAuthTokenFromJSON(body)
	if token != "jwt-token" {
		t.Fatalf("token = %q, want jwt-token", token)
	}
	storage := authStorageValuesFromLoginResponse(body, "fallback@example.test", token)
	for key, want := range map[string]string{
		"token":       "jwt-token",
		"accessToken": "jwt-token",
		"email":       "alice@example.test",
		"bid":         "8",
	} {
		if got := storage[key]; got != want {
			t.Fatalf("storage[%q] = %q, want %q (all=%v)", key, got, want, storage)
		}
	}
	persisted := storage["persist:reducers"]
	if !strings.Contains(persisted, `\"accessToken\":\"jwt-token\"`) ||
		!strings.Contains(persisted, `\"isLoggedIn\":true`) ||
		!strings.Contains(persisted, `\"email\":\"alice@example.test\"`) {
		t.Fatalf("persist:reducers did not include logged-in redux state: %s", persisted)
	}
}

func TestParseLoginActionsAcceptsSingleActionObject(t *testing.T) {
	in := `{"action":"click","selector":"[aria-label=\"Close Welcome Banner\"]","reason":"Dismissing the banner unblocks the login form."}`
	got, err := parseLoginActions(in)
	if err != nil {
		t.Fatalf("parseLoginActions() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("parseLoginActions() len = %d, want 1", len(got))
	}
	want := browser.NavigatorAction{
		Action:   "click",
		Selector: `[aria-label="Close Welcome Banner"]`,
		Reason:   "Dismissing the banner unblocks the login form.",
	}
	if got[0] != want {
		t.Fatalf("action = %+v, want %+v", got[0], want)
	}
}

func TestNormalizeLoginActionCredentials(t *testing.T) {
	creds := &Credentials{Username: "admin@juice-sh.op", Password: "secret"}

	user := normalizeLoginActionCredentials(browser.NavigatorAction{Action: "fill", Value: "USERNAME"}, creds)
	if user.Value != creds.Username {
		t.Fatalf("USERNAME placeholder = %q, want username", user.Value)
	}

	pass := normalizeLoginActionCredentials(browser.NavigatorAction{Action: "fill", Value: "{{password}}"}, creds)
	if pass.Value != creds.Password {
		t.Fatalf("password placeholder = %q, want password", pass.Value)
	}
}
