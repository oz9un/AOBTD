package observation

import (
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

func redirectEntry(rawURL, path string, status int, location string) types.TrafficEntry {
	return types.TrafficEntry{
		Request: types.CapturedRequest{Method: "GET", URL: rawURL, Path: path},
		Response: types.CapturedResponse{
			StatusCode: status,
			Headers:    map[string]string{"Location": location},
		},
	}
}

func responseEntry(rawURL, path string, status int, contentType, body string) types.TrafficEntry {
	return types.TrafficEntry{
		Request: types.CapturedRequest{Method: "GET", URL: rawURL, Path: path},
		Response: types.CapturedResponse{
			StatusCode:  status,
			Headers:     map[string]string{},
			ContentType: contentType,
			Body:        []byte(body),
			Size:        int64(len(body)),
		},
	}
}

func TestSummarizeRedirectEvidenceDetectsPathPreservingAuthenticationGate(t *testing.T) {
	evidence := SummarizeRedirectEvidence([]types.TrafficEntry{
		redirectEntry("https://partner.example.test/admin", "/admin", 302,
			"/account/logout?redirect=%2Fadmin"),
	})
	if !evidence.RedirectOnly || !evidence.PathPreservingAuthGate {
		t.Fatalf("evidence = %+v, want redirect-only path-preserving auth gate", evidence)
	}
	if !evidence.PureRedirect || !evidence.RedirectObserved || evidence.ContentObserved {
		t.Fatalf("pure redirect facts = %+v", evidence)
	}
	if len(evidence.Locations) != 1 || evidence.Locations[0] != "/account/logout?redirect=%2Fadmin" {
		t.Fatalf("locations = %#v", evidence.Locations)
	}
}

func TestSummarizeRedirectEvidenceDoesNotHideRecoveredContent(t *testing.T) {
	redirect := redirectEntry("https://app.test/register", "/register", 302, "/login")
	content := responseEntry("https://app.test/register", "/register", 200, "text/html",
		`<!doctype html><html><body><h1>Create account</h1><form><input name="email"></form></body></html>`)
	evidence := SummarizeRedirectEvidence([]types.TrafficEntry{redirect, content})
	if evidence.RedirectOnly || evidence.PathPreservingAuthGate {
		t.Fatalf("mixed redirect/content evidence = %+v", evidence)
	}
	if !evidence.RedirectObserved || !evidence.ContentObserved || evidence.PureRedirect {
		t.Fatalf("recovered content facts = %+v", evidence)
	}
}

func TestSummarizeRedirectEvidenceKeepsOrdinaryRedirectDistinct(t *testing.T) {
	evidence := SummarizeRedirectEvidence([]types.TrafficEntry{
		redirectEntry("https://app.test/old", "/old", 301, "/new"),
	})
	if !evidence.RedirectOnly {
		t.Fatal("ordinary redirect should still be classified as redirect-only transport")
	}
	if evidence.PathPreservingAuthGate {
		t.Fatal("ordinary route alias was mislabeled as an authentication catch-all")
	}
}

func TestRedirectPlusFailureStatusNeverBecomesContentEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "not found", status: 404, body: "not found"},
		{name: "gone", status: 410, body: "gone"},
		{name: "server error", status: 500, body: "internal server error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			redirect := redirectEntry("https://app.test/admin", "/admin", 302, "/login?next=%2Fadmin")
			failure := responseEntry("https://app.test/admin", "/admin", tc.status, "text/html", tc.body)
			evidence := SummarizeRedirectEvidence([]types.TrafficEntry{redirect, failure})
			if !evidence.RedirectOnly || !evidence.RedirectObserved || evidence.ContentObserved {
				t.Fatalf("redirect + %d evidence = %+v", tc.status, evidence)
			}
			if evidence.PureRedirect {
				t.Fatalf("redirect + %d was mislabeled as a pure redirect: %+v", tc.status, evidence)
			}
			if !containsInt(evidence.NonContentStatusCodes, tc.status) || !containsInt(evidence.NonContentStatusCodes, 302) {
				t.Fatalf("non-content statuses = %#v, want 302 and %d", evidence.NonContentStatusCodes, tc.status)
			}
		})
	}
}

func TestRedirectPlusAuthenticationChallengeNeverBecomesContentEvidence(t *testing.T) {
	for _, status := range []int{401, 403} {
		redirect := redirectEntry("https://app.test/private", "/private", 302, "/login?next=%2Fprivate")
		challenge := responseEntry("https://app.test/private", "/private", status, "application/json",
			`{"error":"authentication required"}`)
		evidence := SummarizeRedirectEvidence([]types.TrafficEntry{redirect, challenge})
		if !evidence.RedirectOnly || evidence.ContentObserved {
			t.Fatalf("redirect + %d challenge evidence = %+v", status, evidence)
		}
		if !containsInt(evidence.NonContentStatusCodes, status) {
			t.Fatalf("non-content statuses = %#v, want %d", evidence.NonContentStatusCodes, status)
		}
	}
}

func TestRedirectPlusEmptySuccessNeverBecomesContentEvidence(t *testing.T) {
	redirect := redirectEntry("https://app.test/admin", "/admin", 302, "/login")
	empty := responseEntry("https://app.test/admin", "/admin", 200, "text/html", " \n\t ")
	evidence := SummarizeRedirectEvidence([]types.TrafficEntry{redirect, empty})
	if !evidence.RedirectOnly || evidence.ContentObserved || !evidence.EmptySuccessObserved {
		t.Fatalf("redirect + empty 200 evidence = %+v", evidence)
	}
}

func TestRedirectPlusLoginShellNeverBecomesContentEvidence(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{
			name:        "html password form",
			contentType: "text/html; charset=utf-8",
			body:        `<!doctype html><html><head><title>Login</title></head><body><h1>Sign in</h1><form action="/auth/login"><input type="password"></form></body></html>`,
		},
		{
			name:        "json unauthorized envelope",
			contentType: "application/json",
			body:        `{"status":401,"error":"Unauthorized","message":"Please log in"}`,
		},
		{
			name:        "html sso shell without password",
			contentType: "text/html",
			body:        `<html><head><title>Sign in</title></head><body><h1>Sign in</h1><button>Continue with company SSO</button></body></html>`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			redirect := redirectEntry("https://app.test/admin", "/admin", 302, "/login")
			shell := responseEntry("https://app.test/admin", "/admin", 200, tc.contentType, tc.body)
			evidence := SummarizeRedirectEvidence([]types.TrafficEntry{redirect, shell})
			if !evidence.RedirectOnly || evidence.ContentObserved || !evidence.AuthShellObserved {
				t.Fatalf("redirect + login-shell evidence = %+v", evidence)
			}
		})
	}
}

func TestCanonicalLoginPageCountsAsContentButCatchAllLoginShellDoesNot(t *testing.T) {
	body := `<!doctype html><html><head><title>Login</title></head><body><h1>Sign in</h1><form action="/auth/login"><input name="email"><input type="password"></form></body></html>`
	login := responseEntry("https://app.test/auth/login", "/auth/login", 200, "text/html", body)
	loginEvidence := SummarizeRedirectEvidence([]types.TrafficEntry{login})
	if !loginEvidence.ContentObserved || loginEvidence.AuthShellObserved || loginEvidence.RedirectOnly {
		t.Fatalf("canonical login content = %+v", loginEvidence)
	}

	admin := responseEntry("https://app.test/admin", "/admin", 200, "text/html", body)
	adminEvidence := SummarizeRedirectEvidence([]types.TrafficEntry{admin})
	if adminEvidence.ContentObserved || !adminEvidence.AuthShellObserved {
		t.Fatalf("catch-all admin login shell = %+v", adminEvidence)
	}
}

func TestCanonicalLoginShellPromotionRequiresGETHTML(t *testing.T) {
	body := `<!doctype html><html><head><title>Login</title></head><body><h1>Sign in</h1><form action="/auth/login"><input type="password"></form></body></html>`

	post := responseEntry("https://app.test/auth/login", "/auth/login", 200, "text/html", body)
	post.Request.Method = "POST"
	postEvidence := SummarizeRedirectEvidence([]types.TrafficEntry{post})
	if postEvidence.ContentObserved || !postEvidence.AuthShellObserved {
		t.Fatalf("POST login shell was promoted to page content: %+v", postEvidence)
	}

	jsonLogin := responseEntry("https://app.test/auth/login", "/auth/login", 200, "application/json",
		`{"status":401,"error":"Unauthorized","data":null}`)
	jsonEvidence := SummarizeRedirectEvidence([]types.TrafficEntry{jsonLogin})
	if jsonEvidence.ContentObserved || !jsonEvidence.AuthShellObserved {
		t.Fatalf("JSON login error was promoted to page content: %+v", jsonEvidence)
	}

	unknownType := responseEntry("https://app.test/auth/login", "/auth/login", 200, "", body)
	unknownEvidence := SummarizeRedirectEvidence([]types.TrafficEntry{unknownType})
	if unknownEvidence.ContentObserved || !unknownEvidence.AuthShellObserved {
		t.Fatalf("untyped login shell was promoted without HTML evidence: %+v", unknownEvidence)
	}
}

func TestJSONErrorEnvelopeWinsWithoutSubstantiveApplicationData(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantAuth  bool
		wantError bool
		wantData  bool
	}{
		{name: "null auth data", body: `{"status":401,"error":"Unauthorized","data":null}`, wantAuth: true},
		{name: "empty auth list", body: `{"status":403,"message":"Forbidden","items":[]}`, wantAuth: true},
		{name: "false auth data", body: `{"status":401,"message":"Authentication required","data":false}`, wantAuth: true},
		{name: "nested auth envelope", body: `{"status":401,"data":{"error":"Unauthorized","message":"Please log in"}}`, wantAuth: true},
		{name: "empty error object", body: `{"status":500,"error":"Application error","result":{}}`, wantError: true},
		{name: "blank error payload", body: `{"status":404,"message":"Route not found","payload":"  "}`, wantError: true},
		{name: "substantive auth response", body: `{"status":401,"error":"Unauthorized","data":{"tenant_id":0}}`, wantData: true},
		{name: "substantive error response", body: `{"status":500,"error":"Partial failure","orders":[8172]}`, wantData: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := responseEntry("https://app.test/api/private", "/api/private", 200, "application/json", tt.body)
			evidence := SummarizeRedirectEvidence([]types.TrafficEntry{entry})
			if evidence.AuthShellObserved != tt.wantAuth || evidence.ErrorShellObserved != tt.wantError || evidence.ContentObserved != tt.wantData {
				t.Fatalf("JSON evidence = %+v, want auth=%v error=%v content=%v", evidence, tt.wantAuth, tt.wantError, tt.wantData)
			}
		})
	}
}

func TestCanonicalSPALoginCountsAsContentButSameShellOnAnotherPathDoesNot(t *testing.T) {
	body := `<!doctype html><html><head><title>Partner portal</title></head><body>
		<div id="app"><div id="initial-loading"><span class="spinner"></span></div></div>
		<script type="module" src="https://cdn.example.test/app-auth/bundles/production/js/app.123.js"></script>
	</body></html>`
	login := responseEntry("https://app.test/auth/login", "/auth/login", 200, "text/html", body)
	loginEvidence := SummarizeRedirectEvidence([]types.TrafficEntry{login})
	if !loginEvidence.ContentObserved || loginEvidence.AuthShellObserved {
		t.Fatalf("canonical SPA login content = %+v", loginEvidence)
	}

	logout := responseEntry("https://app.test/auth/logout?redirect=%2Fadmin", "/auth/logout", 200, "text/html", body)
	logoutEvidence := SummarizeRedirectEvidence([]types.TrafficEntry{logout})
	if logoutEvidence.ContentObserved || !logoutEvidence.AuthShellObserved {
		t.Fatalf("SPA auth shell returned on logout path = %+v", logoutEvidence)
	}

	boundedHeadTail := `<html><head><title>Partner portal</title></head><body>` +
		`<script src="/app-auth/bundles/app.123.js"></script>` +
		`<script src="/app-auth/bundles/chunk-vendors.456.js"></script>` +
		`<footer>Support</footer></body></html>`
	bounded := responseEntry("https://app.test/admin", "/admin", 200, "text/html", boundedHeadTail)
	boundedEvidence := SummarizeRedirectEvidence([]types.TrafficEntry{bounded})
	if boundedEvidence.ContentObserved || !boundedEvidence.AuthShellObserved {
		t.Fatalf("bounded head/tail SPA auth evidence = %+v", boundedEvidence)
	}

	ordersBody := `<html><body><div id="app"><h1>Partner orders</h1><table><tr><td>8172</td></tr></table></div>` +
		`<script src="/app-auth/bundles/shared.js"></script></body></html>`
	orders := responseEntry("https://app.test/orders", "/orders", 200, "text/html", ordersBody)
	ordersEvidence := SummarizeRedirectEvidence([]types.TrafficEntry{orders})
	if !ordersEvidence.ContentObserved || ordersEvidence.AuthShellObserved {
		t.Fatalf("substantive SPA page was mislabeled as auth shell: %+v", ordersEvidence)
	}
}

func TestRedirectPlusSoftErrorNeverBecomesContentEvidence(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{
			name:        "html soft not found",
			contentType: "text/html",
			body:        `<!doctype html><html><head><title>404 — Page not found</title></head><body><h1>Page not found</h1></body></html>`,
		},
		{
			name:        "json soft not found",
			contentType: "application/problem+json",
			body:        `{"statusCode":404,"error":"Not Found","message":"Route not found"}`,
		},
		{
			name:        "html soft application error",
			contentType: "text/html",
			body:        `<html><head><title>Application error</title></head><body><h1>Something went wrong</h1></body></html>`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			redirect := redirectEntry("https://app.test/admin", "/admin", 302, "/login")
			shell := responseEntry("https://app.test/admin", "/admin", 200, tc.contentType, tc.body)
			evidence := SummarizeRedirectEvidence([]types.TrafficEntry{redirect, shell})
			if !evidence.RedirectOnly || evidence.ContentObserved || !evidence.ErrorShellObserved {
				t.Fatalf("redirect + soft-error evidence = %+v", evidence)
			}
		})
	}
}

func TestStructuredSPASoft404BootstrapNeverBecomesContentEvidence(t *testing.T) {
	redirect := redirectEntry("https://partner.test/api/v1/auth/login", "/api/v1/auth/login", 302, "/errors/not-found")
	soft404 := responseEntry("https://partner.test/api/v1/auth/login", "/api/v1/auth/login", 200, "text/html", `
		<!doctype html><html><head><title>Partner portal</title></head><body>
		<div id="app"><div id="initial-loading"><span class="spinner"></span></div></div>
		<script>
			const originalUrl = '/errors/public/not-found'
			window.scRouter = { originalUrl: originalUrl }
		</script><script src="/main.bundle.js"></script></body></html>`)
	evidence := SummarizeRedirectEvidence([]types.TrafficEntry{redirect, soft404})
	if !evidence.RedirectOnly || evidence.ContentObserved || !evidence.ErrorShellObserved {
		t.Fatalf("structured SPA soft-404 evidence = %+v", evidence)
	}

	// A real page may ship the same router and mention an error-route constant
	// for navigation. Without an explicit originalUrl error assignment, that is
	// application content—not a soft 404.
	orders := responseEntry("https://partner.test/orders", "/orders", 200, "text/html", `
		<html><body><h1>Current orders</h1><table><tr><td>8172</td></tr></table>
		<script>const notFoundRoute='/errors/public/not-found'; window.scRouter={originalUrl:'/orders'};</script>
		</body></html>`)
	ordersEvidence := SummarizeRedirectEvidence([]types.TrafficEntry{orders})
	if !ordersEvidence.ContentObserved || ordersEvidence.ErrorShellObserved {
		t.Fatalf("substantive SPA page was mislabeled by router vocabulary: %+v", ordersEvidence)
	}
}

func TestSubstantiveHTMLAndJSONLiftRedirectOnlyEvidence(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{
			name:        "html application page",
			contentType: "text/html",
			body:        `<html><body><h1>Partner orders</h1><table><tr><td>Order 8172</td></tr></table></body></html>`,
		},
		{
			name:        "json application data",
			contentType: "application/json",
			body:        `{"partner":{"id":17,"name":"Demo restaurant"},"orders":[8172]}`,
		},
		{
			name:        "json data with harmless message field",
			contentType: "application/json",
			body:        `{"message":"Not found items are omitted","orders":[8172]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			redirect := redirectEntry("https://app.test/orders", "/orders", 302, "/login")
			content := responseEntry("https://app.test/orders", "/orders", 200, tc.contentType, tc.body)
			evidence := SummarizeRedirectEvidence([]types.TrafficEntry{redirect, content})
			if evidence.RedirectOnly || !evidence.RedirectObserved || !evidence.ContentObserved {
				t.Fatalf("redirect + substantive content evidence = %+v", evidence)
			}
		})
	}
}

func TestShellMarkersInsideScriptsDoNotOverrideSubstantiveHTML(t *testing.T) {
	redirect := redirectEntry("https://app.test/orders", "/orders", 302, "/login")
	content := responseEntry("https://app.test/orders", "/orders", 200, "text/html",
		`<html><body><h1>Orders</h1><p>Current partner orders</p><script>const template = "<title>404</title><form><input type='password'> unauthorized";</script></body></html>`)
	evidence := SummarizeRedirectEvidence([]types.TrafficEntry{redirect, content})
	if evidence.RedirectOnly || !evidence.ContentObserved {
		t.Fatalf("script-only shell vocabulary overrode substantive HTML: %+v", evidence)
	}
}

func TestLongSubstantiveDocumentationIsNotAnAuthenticationShell(t *testing.T) {
	redirect := redirectEntry("https://app.test/docs", "/docs", 302, "/login")
	body := `<html><body><h1>API documentation</h1><p>` + strings.Repeat("Application request and response documentation. ", 120) +
		`Unauthorized responses use status 401; access denied means the caller needs another role.</p></body></html>`
	content := responseEntry("https://app.test/docs", "/docs", 200, "text/html", body)
	evidence := SummarizeRedirectEvidence([]types.TrafficEntry{redirect, content})
	if evidence.RedirectOnly || !evidence.ContentObserved {
		t.Fatalf("substantive documentation was mislabeled as an auth shell: %+v", evidence)
	}
}

func containsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
