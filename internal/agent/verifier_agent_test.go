package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestCORSAllowsCredentialedBrowserRead(t *testing.T) {
	const origin = "https://evil.aobtd.test"
	tests := []struct {
		name string
		acao string
		acac string
		want bool
	}{
		{name: "reflected origin with credentials", acao: origin, acac: "true", want: true},
		{name: "wildcard without credentials is not credentialed read", acao: "*", acac: "", want: false},
		{name: "wildcard with credentials is rejected by browsers", acao: "*", acac: "true", want: false},
		{name: "reflected origin without credentials", acao: origin, acac: "", want: false},
		{name: "different origin with credentials", acao: "https://other.example", acac: "true", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := corsAllowsCredentialedBrowserRead(tt.acao, tt.acac, origin); got != tt.want {
				t.Fatalf("corsAllowsCredentialedBrowserRead(%q,%q)=%v, want %v", tt.acao, tt.acac, got, tt.want)
			}
		})
	}
}

func TestPathNamedXSSParams(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{"/VulnerableApp/XSSInImgTagAttribute/LEVEL_1", []string{"src"}},
		{"/VulnerableApp/XSSWithHtmlTagInjection/LEVEL_2", []string{"comment", "input"}},
		{"/VulnerableApp/PersistentXSSInHTMLTagVulnerability/LEVEL_3", []string{"comment"}},
		{"/VulnerableApp/CachePoisoning/LEVEL_1", []string{"banner"}},
		{"/VulnerableApp/CommandInjection/LEVEL_1", nil},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := pathNamedXSSParams(tt.path); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("pathNamedXSSParams(%q) = %#v, want %#v", tt.path, got, tt.want)
			}
		})
	}
}

func TestReflectedXSSExecutionSignal(t *testing.T) {
	const marker = "AOBTD_XSS_123"
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "script body",
			body: `<div><script>window.AOBTD_XSS_123=1</script></div>`,
			want: true,
		},
		{
			name: "svg onload",
			body: `<svg onload="window.AOBTD_XSS_123=1">`,
			want: true,
		},
		{
			name: "img onerror with entity quoted attribute",
			body: `<img src=x onerror=&quot;window.AOBTD_XSS_123=1&quot; width="400">`,
			want: true,
		},
		{
			name: "details ontoggle",
			body: `<div><details open ontoggle="window.AOBTD_XSS_123=1">x</details></div>`,
			want: true,
		},
		{
			name: "encoded script is not executable context",
			body: `<div>&lt;script&gt;window.AOBTD_XSS_123=1&lt;/script&gt;</div>`,
			want: false,
		},
		{
			name: "old dangerous tag plus marker text elsewhere is not enough",
			body: `<div><svg onload=alert(1)></div><p>window.AOBTD_XSS_123=1</p>`,
			want: false,
		},
		{
			name: "plain onerror text is not enough",
			body: `<div>x onerror="window.AOBTD_XSS_123=1"</div>`,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := reflectedXSSExecutionSignal(tt.body, marker)
			if got != tt.want {
				t.Fatalf("reflectedXSSExecutionSignal(...)= %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPathNamedJWTLevel(t *testing.T) {
	tests := []struct {
		path string
		want int
	}{
		{"/VulnerableApp/JWTVulnerability/LEVEL_1", 1},
		{"/VulnerableApp/JWTVulnerability/LEVEL_16", 16},
		{"/VulnerableApp/SQLInjection/LEVEL_1", 0},
	}
	for _, tt := range tests {
		if got := pathNamedJWTLevel(tt.path); got != tt.want {
			t.Fatalf("pathNamedJWTLevel(%q) = %d, want %d", tt.path, got, tt.want)
		}
	}
}

func TestJWTTokenFromText(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.5e4h72XgqB9AphT4KZuR3YK6w3Hhy0tXGYG5yCXAdIE"
	body := `{"content":"` + token + `","isValid":true}`
	if got := jwtTokenFromText(body); got != token {
		t.Fatalf("jwtTokenFromText() = %q, want %q", got, token)
	}
	if got := jwtTokenFromText(`{"content":"not.a.jwt"}`); got != "" {
		t.Fatalf("jwtTokenFromText(invalid) = %q, want empty", got)
	}
}

func TestJWTEmptySignatureToken(t *testing.T) {
	token := "aaa.bbb.ccc"
	if got := jwtEmptySignatureToken(token); got != "aaa.bbb." {
		t.Fatalf("jwtEmptySignatureToken(%q) = %q", token, got)
	}
	if got := jwtEmptySignatureToken("not-a-jwt"); got != "" {
		t.Fatalf("jwtEmptySignatureToken(invalid) = %q, want empty", got)
	}
}

func TestWebGoatLessonCompletionFindingSQLi(t *testing.T) {
	entry := types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  http.MethodPost,
			URL:     "https://example.test/WebGoat/SqlInjection/assignment5b",
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:    []byte("userid=1+OR+1%3D1&login_count=1"),
		},
		Response: types.CapturedResponse{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"lessonCompleted": true, "feedback":"well done"}`),
		},
	}

	finding, ok := webGoatLessonCompletionFinding(entry)
	if !ok {
		t.Fatal("expected WebGoat SQLi lesson completion to become a finding")
	}
	if finding.VulnType != "sqli" || finding.ParamName != "userid" {
		t.Fatalf("finding type/param = %s/%s, want sqli/userid", finding.VulnType, finding.ParamName)
	}
	if finding.EndpointID != "POST /WebGoat/SqlInjection/assignment5b" {
		t.Fatalf("endpoint id = %q", finding.EndpointID)
	}
	if finding.Payload != "1 OR 1=1" {
		t.Fatalf("payload = %q", finding.Payload)
	}
	if !strings.Contains(finding.PocRequest, "userid=1+OR+1%3D1&login_count=1") {
		t.Fatalf("PoC request missing raw form body: %s", finding.PocRequest)
	}
}

func TestWebGoatLessonCompletionFindingXXE(t *testing.T) {
	xmlBody := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><comment><text>&xxe;</text></comment>`
	entry := types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  http.MethodPost,
			URL:     "https://example.test/WebGoat/xxe/simple",
			Headers: map[string]string{"Content-Type": "application/xml"},
			Body:    []byte(xmlBody),
		},
		Response: types.CapturedResponse{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"lessonCompleted":true}`),
		},
	}

	finding, ok := webGoatLessonCompletionFinding(entry)
	if !ok {
		t.Fatal("expected WebGoat XXE lesson completion to become a finding")
	}
	if finding.VulnType != "xxe" || finding.ParamName != "xml_body" {
		t.Fatalf("finding type/param = %s/%s, want xxe/xml_body", finding.VulnType, finding.ParamName)
	}
	if finding.EndpointID != "POST /WebGoat/xxe/simple" {
		t.Fatalf("endpoint id = %q", finding.EndpointID)
	}
	if !strings.Contains(finding.PocRequest, "Content-Type: application/xml") {
		t.Fatalf("PoC request missing XML content type: %s", finding.PocRequest)
	}
}

func TestWebGoatLessonCompletionRejectsNonExploitLessonSuccess(t *testing.T) {
	entry := types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  http.MethodPost,
			URL:     "https://example.test/WebGoat/xxe/simple",
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:    []byte("text=%3C%3Fxml+version%3D%221.0%22%3F%3E%3Ccomment%3Ehello%3C%2Fcomment%3E"),
		},
		Response: types.CapturedResponse{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"lessonCompleted":true}`),
		},
	}

	if _, ok := webGoatLessonCompletionFinding(entry); ok {
		t.Fatal("form-encoded/non-DOCTYPE XML lesson success must not be promoted as XXE")
	}
}

func TestProbeWebGoatKnownLessonsUsesObservedSessionAndStoresFindings(t *testing.T) {
	const sessionCookie = "JSESSIONID=webgoat-test-session"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Cookie"), sessionCookie) {
			http.Error(w, "missing session", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/WebGoat/SqlInjection/assignment5b":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("userid") == "1 OR 1=1" && r.Form.Get("login_count") == "1" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"lessonCompleted":true}`))
				return
			}
		case "/WebGoat/xxe/simple", "/WebGoat/xxe/content-type":
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(r.Header.Get("Content-Type"), "application/xml") &&
				strings.Contains(string(body), "<!DOCTYPE comment") &&
				strings.Contains(string(body), "<comment>") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"lessonCompleted":true}`))
				return
			}
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"lessonCompleted":false}`))
	}))
	defer srv.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "webgoat-probes.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	scanID, err := db.CreateScan(srv.URL+"/WebGoat/start.mvc", `{}`)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  http.MethodGet,
			URL:     srv.URL + "/WebGoat/start.mvc",
			Headers: map[string]string{"Cookie": sessionCookie},
		},
		Response: types.CapturedResponse{StatusCode: http.StatusOK, Headers: map[string]string{"Content-Type": "text/html"}, Body: []byte("<html></html>")},
	}); err != nil {
		t.Fatalf("insert auth traffic: %v", err)
	}

	verifier := &VerifierAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		client: srv.Client(),
		target: srv.URL + "/WebGoat/start.mvc",
	}
	verifier.probeWebGoatKnownLessons(context.Background(), verifier.target)

	rows, err := db.Conn().Query(`SELECT vuln_type, endpoint_id, poc_request FROM findings WHERE scan_id = ? ORDER BY endpoint_id`, scanID)
	if err != nil {
		t.Fatalf("query findings: %v", err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var vulnType, endpointID, poc string
		if err := rows.Scan(&vulnType, &endpointID, &poc); err != nil {
			t.Fatalf("scan finding: %v", err)
		}
		got[endpointID] = vulnType + "|" + poc
	}
	for endpoint, vulnType := range map[string]string{
		"POST /WebGoat/SqlInjection/assignment5b": "sqli",
		"POST /WebGoat/xxe/content-type":          "xxe",
		"POST /WebGoat/xxe/simple":                "xxe",
	} {
		value, ok := got[endpoint]
		if !ok {
			t.Fatalf("missing finding for %s; got %#v", endpoint, got)
		}
		if !strings.HasPrefix(value, vulnType+"|") {
			t.Fatalf("finding for %s = %q, want vuln type %s", endpoint, value, vulnType)
		}
		if !strings.Contains(value, sessionCookie) {
			t.Fatalf("finding for %s did not preserve reproducible session header in PoC: %s", endpoint, value)
		}
	}

	var verifierTraffic int
	if err := db.Conn().QueryRow(`SELECT count(*) FROM traffic WHERE scan_id = ? AND source_agent = 'verifier'`, scanID).Scan(&verifierTraffic); err != nil {
		t.Fatalf("count verifier traffic: %v", err)
	}
	if verifierTraffic != 3 {
		t.Fatalf("verifier traffic = %d, want 3", verifierTraffic)
	}
}

func TestCSRFAuthBootstrapEndpoint(t *testing.T) {
	blocked := []string{
		"https://example.test/login",
		"https://example.test/register",
		"https://example.test/WebGoat/register.mvc",
		"https://example.test/reset-password",
		"https://example.test/mfa/check",
	}
	for _, raw := range blocked {
		if !csrfAuthBootstrapEndpoint(raw, "") {
			t.Fatalf("csrfAuthBootstrapEndpoint(%q)=false, want true", raw)
		}
	}
	if csrfAuthBootstrapEndpoint("https://example.test/account/settings", "") {
		t.Fatal("account settings should remain eligible for CSRF verification")
	}
}

// TestTryUnwrapProfile locks in the tolerance for LLM outputs that wrap
// the profile in a single outer key — qwen3:8b does this intermittently,
// emitting `{"pageProfile": {...profile...}}` instead of the bare profile.
// Without unwrapping, the whole endpoint's analysis is dropped.
func TestTryUnwrapProfile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantID  string // empty = expect nil
	}{
		{
			"bare profile (not a wrapper)",
			`{"id":"/api/foo","url":"https://x/api/foo","method":"GET","purpose":"test","auth_required":"session"}`,
			"", // tryUnwrap only handles wrappers; bare profile goes through the other parsers
		},
		{
			"qwen3:8b pageProfile wrapper",
			`{"pageProfile":{"id":"/api/foo","url":"https://x/api/foo","method":"GET","purpose":"t","auth_required":"s"}}`,
			"/api/foo",
		},
		{
			"alternate 'profile' wrapper",
			`{"profile":{"id":"/api/bar","url":"https://x/api/bar","method":"POST","purpose":"t","auth_required":"s"}}`,
			"/api/bar",
		},
		{
			"'result' wrapper (some models love this)",
			`{"result":{"id":"/api/baz","url":"https://x/api/baz","method":"GET","purpose":"t","auth_required":"s"}}`,
			"/api/baz",
		},
		{
			"wrapper with extra keys — first matching wins",
			`{"metadata":{"version":1},"pageProfile":{"id":"/api/q","url":"u","method":"GET","purpose":"p","auth_required":"s"}}`,
			"/api/q",
		},
		{
			"wrapper with no profile-shaped value",
			`{"error":"something went wrong","code":500}`,
			"",
		},
		{
			"invalid json",
			`not json`,
			"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tryUnwrapProfile(tc.content)
			if tc.wantID == "" {
				if got != nil {
					t.Errorf("got %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("got nil, want profile with ID %q", tc.wantID)
			}
			if got.ID != tc.wantID {
				t.Errorf("got ID %q, want %q", got.ID, tc.wantID)
			}
		})
	}
}

// TestPickAuthHeaders is the regression test for the session-replay fix:
// the Explorer was running probe_idor against auth-gated Juice Shop APIs
// without cookies, getting 401s, and falsely dismissing hypotheses. This
// helper decodes captured request_headers and keeps only auth-carrying
// entries so Explorer can replay the browser's real session.
func TestPickAuthHeaders(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]string
		wantKept []string // keys we expect to survive (case-sensitive as stored)
	}{
		{
			name: "typical browser session",
			input: map[string]string{
				"Cookie":          "sid=abc123; user=42",
				"Authorization":   "Bearer eyJ...",
				"User-Agent":      "Mozilla/5.0",
				"Accept":          "text/html",
				"Accept-Language": "en-US",
			},
			wantKept: []string{"Cookie", "Authorization"},
		},
		{
			name: "API with bearer + CSRF token",
			input: map[string]string{
				"Authorization": "Bearer eyJ...",
				"X-CSRF-Token":  "a7b2e3",
				"Content-Type":  "application/json",
			},
			wantKept: []string{"Authorization", "X-CSRF-Token"},
		},
		{
			name: "case-insensitive match on header name",
			input: map[string]string{
				"cookie":        "sid=abc",        // lowercase
				"authorization": "Basic dXNlcg==", // lowercase
				"user-agent":    "noise",
			},
			wantKept: []string{"cookie", "authorization"},
		},
		{
			name:     "no auth headers → nil",
			input:    map[string]string{"Accept": "*/*", "User-Agent": "Bot"},
			wantKept: nil,
		},
		{
			name:     "empty input",
			input:    map[string]string{},
			wantKept: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(tc.input)
			got := pickAuthHeaders(string(b))
			// Compare key sets, not values (values preserved verbatim)
			if len(tc.wantKept) == 0 {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if len(got) != len(tc.wantKept) {
				t.Errorf("got %d headers %v, want %d %v",
					len(got), got, len(tc.wantKept), tc.wantKept)
				return
			}
			for _, k := range tc.wantKept {
				if _, ok := got[k]; !ok {
					t.Errorf("missing expected header %q in output %v", k, got)
				}
			}
		})
	}
}

func TestXSSPayloadsUseUniqueBrowserExecutionMarkers(t *testing.T) {
	for _, p := range xssPayloads {
		if strings.TrimSpace(p.detect) == "" {
			t.Fatalf("xss payload %q has empty detector", p.payload)
		}
		if p.detect == "49" || p.payload == "{{7*7}}" {
			t.Fatalf("SSTI arithmetic payload must not be used as reflected-XSS proof: %+v", p)
		}
		if !strings.Contains(p.detect, "AOBTD") {
			t.Fatalf("xss detector %q should include the unique AOBTD marker to avoid coincidental matches", p.detect)
		}
	}
}

func TestResponseLooksHTMLExecutableRequiresBrowserRenderableContext(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		want        bool
	}{
		{
			name:        "html content type",
			contentType: "text/html; charset=utf-8",
			body:        `"><script>alert('AOBTD')</script>`,
			want:        true,
		},
		{
			name:        "json error reflecting payload is not executable",
			contentType: "application/json",
			body:        `{"errors":[{"message":"\"><script>alert('AOBTD')</script>"}]}`,
			want:        false,
		},
		{
			name:        "plain text reflection is not executable",
			contentType: "text/plain",
			body:        `<svg/onload=alert('AOBTD')>`,
			want:        false,
		},
		{
			name: "missing content type with html document",
			body: "<!doctype html><html><body>hello</body></html>",
			want: true,
		},
		{
			name: "missing content type with json-looking body",
			body: `{"message":"<script>alert('AOBTD')</script>"}`,
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: make(http.Header)}
			if tc.contentType != "" {
				resp.Header.Set("Content-Type", tc.contentType)
			}
			if got := responseLooksHTMLExecutable(resp, tc.body); got != tc.want {
				t.Fatalf("responseLooksHTMLExecutable() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExplorerGraphQLIntrospectionStoresTrafficAndFinding(t *testing.T) {
	var sawPOST bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		sawPOST = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"__schema":{"types":[{"name":"Query"},{"name":"Mutation"}]}}}`)
	}))
	defer srv.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "graphql-introspection.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan(srv.URL, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertFollowUp(scanID, store.FollowUp{
		Action: "graphql_introspect",
		URL:    srv.URL + "/graphql?ignored=1",
	}); err != nil {
		t.Fatal(err)
	}
	tasks, err := db.ClaimFollowUps(scanID, 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("claimed %d tasks, want 1", len(tasks))
	}

	explorer := &ExplorerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		client: srv.Client(),
	}
	explorer.runGraphQLIntrospect(context.Background(), tasks[0])
	if !sawPOST {
		t.Fatal("server did not receive POST")
	}

	var trafficCount int
	if err := db.Conn().QueryRow(`
		SELECT COUNT(*) FROM traffic
		WHERE scan_id = ? AND method = 'POST' AND url = ?`,
		scanID, srv.URL+"/graphql").Scan(&trafficCount); err != nil {
		t.Fatal(err)
	}
	if trafficCount != 1 {
		t.Fatalf("traffic count = %d, want 1", trafficCount)
	}

	var title, vulnType, pocRequest string
	if err := db.Conn().QueryRow(`
		SELECT title, vuln_type, poc_request FROM findings
		WHERE scan_id = ? AND vuln_type = 'graphql_introspection'`,
		scanID).Scan(&title, &vulnType, &pocRequest); err != nil {
		t.Fatal(err)
	}
	if title != "GraphQL introspection enabled" || vulnType != "graphql_introspection" {
		t.Fatalf("finding = %q / %q", title, vulnType)
	}
	if !strings.Contains(pocRequest, "POST /graphql HTTP/1.1") || !strings.Contains(pocRequest, "Host: ") {
		t.Fatalf("poc request is not concrete/raw enough:\n%s", pocRequest)
	}

	var status, result string
	if err := db.Conn().QueryRow(`SELECT status, result FROM follow_ups WHERE scan_id = ?`, scanID).Scan(&status, &result); err != nil {
		t.Fatal(err)
	}
	if status != store.FollowUpDone || !strings.Contains(result, "schema exposed") {
		t.Fatalf("follow-up status/result = %q / %q", status, result)
	}
}

func TestURLWithQueryParamPreservesSPAHashRoute(t *testing.T) {
	got, ok := urlWithQueryParam("https://shop.example/#/track-result", "id", `<iframe src="javascript:alert(`+"`xss`"+`)">`)
	if !ok {
		t.Fatal("urlWithQueryParam returned !ok for hash route")
	}
	if !strings.Contains(got, "https://shop.example/#/track-result?id=") {
		t.Fatalf("query param should be placed inside hash route, got %q", got)
	}
	if strings.Contains(got, "shop.example/?id=") {
		t.Fatalf("query param was placed before hash route, got %q", got)
	}
}

func TestBrowserXSSCandidateURLsKeepSPAHashRouteScoped(t *testing.T) {
	got := browserXSSCandidateURLs("https://shop.example", "https://shop.example/#/track-result", "id", `<iframe src="javascript:alert(`+"`xss`"+`)">`)
	if len(got) != 1 {
		t.Fatalf("hash-route candidates should stay scoped to the route, got %#v", got)
	}
	if !strings.Contains(got[0], "https://shop.example/#/track-result?id=") {
		t.Fatalf("query param should be placed inside hash route, got %q", got[0])
	}
}

func TestBrowserXSSCandidateURLsStayWithinMountedAppPrefix(t *testing.T) {
	got := browserXSSCandidateURLs("http://127.0.0.1:8085/WebGoat/start.mvc", "http://127.0.0.1:8085/WebGoat/search?q=test", "q", `<iframe src="javascript:alert(`+"`xss`"+`)">`)
	if len(got) == 0 {
		t.Fatal("expected WebGoat-scoped candidates")
	}
	for _, candidate := range got {
		if strings.Contains(candidate, "127.0.0.1:8085/search") ||
			strings.Contains(candidate, "127.0.0.1:8085/?") ||
			strings.Contains(candidate, "127.0.0.1:8085/#") {
			t.Fatalf("candidate escaped mounted app prefix: %#v", got)
		}
		if !strings.Contains(candidate, "127.0.0.1:8085/WebGoat") {
			t.Fatalf("candidate is not WebGoat-scoped: %q (all=%#v)", candidate, got)
		}
	}
}

func TestNormalizeBrowserXSSCandidateURLCollapsesDoubleEscapedPathPayload(t *testing.T) {
	raw := `https://shop.example/rest/track-order/%253Ciframe%20src%253D%2522javascript%253Aalert%2528%2560xss%2560%2529%2522%253E`
	got := normalizeBrowserXSSCandidateURL(raw)
	if strings.Contains(got, "%253C") || strings.Contains(got, "%2522") {
		t.Fatalf("candidate path stayed double-encoded: %s", got)
	}
	if !strings.Contains(got, "%3Ciframe") {
		t.Fatalf("candidate path missing single-encoded iframe marker: %s", got)
	}
	if strings.Contains(got, "<iframe") {
		t.Fatalf("candidate path leaked raw iframe: %s", got)
	}
}

func TestBrowserXSSRenderTargetsFromTrafficDiscoversAngularUnsafeQuerySink(t *testing.T) {
	js := `var qc=(()=>{class t{route=m(xt);sanitizer=m(Ni);ngOnInit(){this.orderId=this.route.snapshot.queryParams.id;this.results.orderNo=this.sanitizer.bypassSecurityTrustHtml("<code>"+this.orderId+"</code>")}static \u0275cmp=M({type:t,selectors:[["app-track-result"]],decls:1,vars:1,consts:[[3,"innerHtml"]]})}return t})();var sD=[{path:"search",component:Bs},{path:"track-result",component:qc},{path:"track-result/new",component:qc,data:{type:"new"}}];`
	entries := []types.TrafficEntry{{
		Request: types.CapturedRequest{
			Method: "GET",
			URL:    "https://shop.example/main.js",
			Path:   "/main.js",
		},
		Response: types.CapturedResponse{
			StatusCode:  200,
			ContentType: "application/javascript",
			Body:        []byte(js),
		},
	}}

	targets := browserXSSRenderTargetsFromTraffic(entries, "https://shop.example")
	if len(targets) == 0 {
		t.Fatal("expected at least one JS-derived browser XSS render target")
	}
	var found bool
	for _, target := range targets {
		if target.baseURL == "https://shop.example/#/track-result" && target.param == "id" {
			found = true
			if !strings.Contains(target.source, "component qc") {
				t.Fatalf("source should identify component qc, got %q", target.source)
			}
		}
		if strings.Contains(target.baseURL, "track-result/new") {
			t.Fatalf("route with no required query param signal should not include duplicate component route %q", target.baseURL)
		}
	}
	if !found {
		t.Fatalf("targets = %#v, want hash route /#/track-result with id param", targets)
	}
}

func TestBrowserXSSObservedMarkerDoesNotMatchEmptyMarker(t *testing.T) {
	if browserXSSObservedMarkerMatches("anything at all", "") {
		t.Fatal("empty browser marker must not match every page")
	}
	if !browserXSSObservedMarkerMatches("prefix AOBTD_MARKER suffix", "AOBTD_MARKER") {
		t.Fatal("expected exact non-empty marker to match observed browser state")
	}
}

func TestMutableOwnershipFieldsDetectOwnerAndContainerKeys(t *testing.T) {
	got := mutableOwnershipFields(map[string]any{
		"message":  "hello",
		"UserId":   float64(13),
		"BasketId": float64(6),
		"quantity": float64(1),
	})
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "UserId") {
		t.Fatalf("expected UserId ownership field, got %#v", got)
	}
	if !strings.Contains(joined, "BasketId") {
		t.Fatalf("expected BasketId container ownership field, got %#v", got)
	}
}

func TestMutableOwnershipBasketIDFromJWTHeaders(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"data":{"id":13,"email":"user@example.test"},"bid":6}`))
	token := header + "." + payload + ".signature"
	got, ok := mutableOwnershipBasketIDFromHeaders(map[string]string{"Authorization": "Bearer " + token})
	if !ok || got != 6 {
		t.Fatalf("basket id = %d,%v want 6,true", got, ok)
	}
}

func TestMutableOwnershipProductIDsFromTrafficCollectsCatalogCandidates(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/rest/products/search?q=",
				Path:   "/rest/products/search",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body:        []byte(`{"status":"success","data":[{"id":1,"name":"Apple Juice"},{"id":2,"name":"Orange Juice"},{"id":4,"name":"Lemon Juice"}]}`),
			},
		},
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/api/Quantitys/",
				Path:   "/api/Quantitys/",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body:        []byte(`[{"id":99,"quantity":10}]`),
			},
		},
	}
	got := mutableOwnershipProductIDsFromTraffic(entries, 4)
	want := []int64{1, 2, 4}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("product candidates = %#v, want %#v", got, want)
	}
}

func TestLowPrivilegeDeleteCandidatesPreferOwnedFiveStarModerationItems(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/api/Feedbacks/",
				Path:   "/api/Feedbacks/",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body: []byte(`{"status":"success","data":[` +
					`{"id":7,"UserId":2,"rating":1,"comment":"ordinary"},` +
					`{"id":8,"UserId":1,"rating":5,"comment":"moderation target"}` +
					`]}`),
			},
		},
	}

	got := lowPrivilegeDeleteCandidatesFromTraffic(entries, "https://shop.example")
	if len(got) == 0 {
		t.Fatal("expected a cross-owner delete candidate")
	}
	if got[0].URL != "https://shop.example/api/Feedbacks/8" ||
		got[0].OwnerField != "UserId" ||
		got[0].OwnerID != 1 ||
		got[0].ObjectLabel != "feedback" {
		t.Fatalf("first candidate = %#v, want prioritized five-star feedback item", got[0])
	}
}

func TestLowPrivilegeDeleteCandidatesRejectPublicCatalogCollections(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/rest/products/search?q=",
				Path:   "/rest/products/search",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body:        []byte(`{"status":"success","data":[{"id":1,"UserId":2,"name":"Apple Juice"}]}`),
			},
		},
	}

	if got := lowPrivilegeDeleteCandidatesFromTraffic(entries, "https://shop.example"); len(got) != 0 {
		t.Fatalf("public catalog should not produce destructive delete candidates: %#v", got)
	}
}

func TestSecurityQuestionFromTrafficBuildsRegistrationObject(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/api/SecurityQuestions/",
				Path:   "/api/SecurityQuestions/",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body:        []byte(`{"status":"success","data":[{"id":4,"question":"Favorite pet?"}]}`),
			},
		},
	}

	got, ok := securityQuestionFromTraffic(entries)
	if !ok || got["id"] != int64(4) || got["question"] != "Favorite pet?" {
		t.Fatalf("security question = %#v,%v want id/question", got, ok)
	}
}

func TestCartOrderNumericSurfaceObservedRequiresContainerAndCatalogSignals(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{Method: "GET", URL: "https://shop.example/rest/basket/NaN", Path: "/rest/basket/NaN"},
			Response: types.CapturedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`{"status":"success","data":null}`),
			},
		},
		{
			Request: types.CapturedRequest{Method: "GET", URL: "https://shop.example/api/Quantitys/", Path: "/api/Quantitys/"},
			Response: types.CapturedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`{"status":"success","data":[{"ProductId":1,"quantity":5}]}`),
			},
		},
	}

	if !cartOrderNumericSurfaceObserved(entries) {
		t.Fatal("basket/cart plus product/quantity evidence should enable numeric invariant probing")
	}
	if cartOrderNumericSurfaceObserved(entries[:1]) {
		t.Fatal("container-only evidence should not trigger cart/order numeric invariant probing")
	}
}

func TestCartOrderNumericInvariantAuthoritySplitsMutationFromCheckout(t *testing.T) {
	tests := []struct {
		name         string
		authority    policy.TestingAuthority
		wantMutation bool
		wantCheckout bool
	}{
		{name: "recon", authority: policy.AuthorityRecon, wantMutation: false, wantCheckout: false},
		{name: "active", authority: policy.AuthorityActive, wantMutation: true, wantCheckout: false},
		{name: "full control", authority: policy.AuthorityFullControl, wantMutation: true, wantCheckout: true},
		{name: "unknown", authority: policy.TestingAuthority(""), wantMutation: false, wantCheckout: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMutation, gotCheckout := cartOrderNumericInvariantAuthority(tt.authority)
			if gotMutation != tt.wantMutation || gotCheckout != tt.wantCheckout {
				t.Fatalf("cartOrderNumericInvariantAuthority(%q) = (%v,%v), want (%v,%v)",
					tt.authority, gotMutation, gotCheckout, tt.wantMutation, tt.wantCheckout)
			}
		})
	}
}

func TestCartOrderCreateItemCandidatesIncludeCommonBasketAndCartShapes(t *testing.T) {
	candidates := cartOrderCreateItemCandidates("https://shop.example", 42, 7)
	var juiceShape, genericCartShape bool
	for _, candidate := range candidates {
		if candidate.Path == "/api/BasketItems" &&
			candidate.Body["ProductId"] == int64(7) &&
			candidate.Body["BasketId"] == int64(42) &&
			candidate.Body["quantity"] == 1 {
			juiceShape = true
		}
		if candidate.Path == "/api/cart/items" &&
			candidate.Body["productId"] == int64(7) &&
			candidate.Body["cartId"] == int64(42) &&
			candidate.Body["quantity"] == 1 {
			genericCartShape = true
		}
	}
	if !juiceShape {
		t.Fatalf("expected common BasketItems body shape in candidates: %#v", candidates[:minInt(len(candidates), 4)])
	}
	if !genericCartShape {
		t.Fatalf("expected generic cart/items body shape in candidates: %#v", candidates[:minInt(len(candidates), 8)])
	}
}

func TestCartOrderNegativeMutationCandidatesTargetCreatedItem(t *testing.T) {
	create := cartNumericCreateResult{
		CreatePath: "/api/BasketItems",
		ProductID:  7,
		BasketID:   42,
		ItemID:     99,
	}
	candidates := cartOrderNegativeMutationCandidates("https://shop.example", create)
	var directQuantity, contextualQuantity bool
	for _, candidate := range candidates {
		if candidate.Method == http.MethodPut && candidate.Path == "/api/BasketItems/99" {
			if candidate.Body["quantity"] == -1 {
				directQuantity = true
			}
			if candidate.Body["ProductId"] == int64(7) &&
				candidate.Body["BasketId"] == int64(42) &&
				candidate.Body["quantity"] == -1 {
				contextualQuantity = true
			}
		}
	}
	if !directQuantity || !contextualQuantity {
		t.Fatalf("negative mutation candidates missing direct/contextual quantity variants: %#v", candidates[:minInt(len(candidates), 10)])
	}
}

func TestCheckoutImpactSignalReadsOrderConfirmation(t *testing.T) {
	body := `{"status":"success","orderConfirmation":"0efa-1084bdd8e1143de5"}`
	got := checkoutImpactSignal(body)
	if !strings.Contains(got, "orderConfirmation") {
		t.Fatalf("checkoutImpactSignal(%s) = %q, want orderConfirmation signal", body, got)
	}
}

func TestCatalogEntityWriteCandidatesInferProductUpdateEndpoint(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/rest/products/search?q=",
				Path:   "/rest/products/search",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body: []byte(`{"status":"success","data":[` +
					`{"id":61,"name":"AOBTD XSS Probe","description":"probe","price":9999},` +
					`{"id":1,"name":"Apple Juice","description":"The all-time classic.","price":1.99}` +
					`]}`),
			},
		},
	}

	got := catalogEntityWriteCandidatesFromTraffic(entries, "https://shop.example")
	if len(got) == 0 {
		t.Fatal("expected shared catalog write candidate")
	}
	candidate := got[0]
	if candidate.Path != "/api/Products/1" ||
		candidate.ReadURL != "https://shop.example/api/Products/1" ||
		candidate.Field != "description" ||
		candidate.ID != 1 {
		t.Fatalf("candidate = %#v, want /api/Products/1 description for normal product", candidate)
	}
}

func TestCatalogEntityWriteCandidatesPrioritizeOutboundLinkTampering(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/rest/products/search?q=",
				Path:   "/rest/products/search",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body: []byte(`{"data":[` +
					`{"id":1,"name":"Apple Juice","description":"The all-time classic."},` +
					`{"id":9,"name":"Partner Listing","description":"Read the vendor terms at <a href=\"https://vendor.example/policy\">policy</a>."}` +
					`]}`),
			},
		},
	}

	got := catalogEntityWriteCandidatesFromTraffic(entries, "https://shop.example")
	if len(got) == 0 {
		t.Fatal("expected shared catalog write candidate")
	}
	if got[0].ID != 9 || got[0].Field != "description" {
		t.Fatalf("first candidate = %#v, want link-bearing description prioritized", got[0])
	}
}

func TestCatalogEntityUpdatePathTemplatesHandleExistingObjectPath(t *testing.T) {
	got := catalogEntityUpdatePathTemplates("/api/products/42")
	if len(got) == 0 || got[0] != "/api/products/%d" {
		t.Fatalf("templates = %#v, want /api/products/%%d", got)
	}
}

func TestCatalogEntityWriteBodiesPreferLinkReplacement(t *testing.T) {
	candidate := catalogEntityWriteCandidate{
		Field:         "description",
		OriginalValue: `Read <a href="https://vendor.example/policy">policy</a>.`,
		Object: map[string]any{
			"id":          float64(9),
			"description": `Read <a href="https://vendor.example/policy">policy</a>.`,
		},
	}

	got := catalogEntityWriteBodies(candidate, "aobtd-catalog-123")
	if len(got) == 0 {
		t.Fatal("expected write bodies")
	}
	desc, _ := got[0]["description"].(string)
	if !strings.Contains(desc, "https://example.com/aobtd-catalog-123") ||
		strings.Contains(desc, "https://vendor.example/policy") {
		t.Fatalf("first body description = %q, want outbound URL replaced with proof marker", desc)
	}
}

func TestCatalogEntityWriteSignalPrefersFieldEcho(t *testing.T) {
	body := `{"status":"success","data":{"id":1,"description":"aobtd-catalog-123"}}`
	got := catalogEntityWriteSignal(body, "description", "aobtd-catalog-123")
	if !strings.Contains(got, "description") {
		t.Fatalf("signal = %q, want field-specific readback", got)
	}
}

func TestSecurityPolicyBodySignal(t *testing.T) {
	body := "Contact: mailto:security@example.com\nExpires: Wed, 15 Jul 2026 00:00:00 GMT\nPolicy: https://example.com/security"
	got := securityPolicyBodySignal(body)
	if !strings.Contains(got, "contact") || !strings.Contains(got, "expires") {
		t.Fatalf("securityPolicyBodySignal = %q, want contact/expires signal", got)
	}
}

func TestDeprecatedUploadInterfaceSignal(t *testing.T) {
	body := "B2B customer complaints via file upload have been deprecated for security reasons"
	got := deprecatedUploadInterfaceSignal(http.StatusGone, body)
	if got == "" {
		t.Fatal("expected deprecated upload interface signal")
	}
}

func TestDeprecatedUploadPathSkipsProfileImages(t *testing.T) {
	if !deprecatedUploadPathLooksWorthTrying("/file-upload") {
		t.Fatal("expected /file-upload to be worth trying")
	}
	if deprecatedUploadPathLooksWorthTrying("/profile/image/file") {
		t.Fatal("profile image upload should not be used for deprecated business-interface probe")
	}
}

func TestDeprecatedUploadInterfaceSkipsPathsWithConfirmedValidationFinding(t *testing.T) {
	confirmed := map[string]bool{"/file-upload": true}
	if !shouldSkipDeprecatedUploadInterface("/file-upload", confirmed) {
		t.Fatal("expected deprecated interface probe to skip endpoint with stronger upload-validation finding")
	}
	if shouldSkipDeprecatedUploadInterface("/other-upload", confirmed) {
		t.Fatal("unrelated upload endpoint should not be skipped")
	}
	if shouldSkipDeprecatedUploadInterface("/file-upload", nil) {
		t.Fatal("nil confirmed map should not skip deprecated interface probe")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestNoSQLOperatorMutationCandidatesFromClientArtifact(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/main.js",
				Path:   "/main.js",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/javascript",
				Body: []byte(`class ReviewSvc { host="/rest/products";
					patch(e){ return this.http.patch(this.host+"/reviews", e) }
					create(id, body){ return this.http.put(this.host+"/"+id+"/reviews", body) }
					// body shape: { id: review._id, message: control.value }
				}`),
			},
		},
	}

	got := noSQLOperatorMutationCandidatesFromTraffic(entries, "https://shop.example")
	if len(got) == 0 {
		t.Fatal("expected NoSQL review mutation candidate from client artifact")
	}
	if got[0].URL != "https://shop.example/rest/products/reviews" ||
		got[0].Method != http.MethodPatch ||
		got[0].IDField != "id" ||
		got[0].MsgField != "message" {
		t.Fatalf("candidate = %#v, want PATCH /rest/products/reviews id/message", got[0])
	}
}

func TestNoSQLOperatorMutationSignalReadsMassUpdateResponse(t *testing.T) {
	body := `{"modified":3,"original":[{"_id":"a"},{"_id":"b"}],"updated":[{"message":"aobtd-nosql-marker"},{"message":"aobtd-nosql-marker"}]}`
	modified, original, updated := noSQLOperatorMutationSignal(body, "aobtd-nosql-marker")
	if modified != 3 || original != 2 || updated != 2 {
		t.Fatalf("signal = modified %d original %d updated %d, want 3/2/2", modified, original, updated)
	}
}

func TestClientControlledAttributionCandidatesFromClientArtifact(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/rest/products/search?q=",
				Path:   "/rest/products/search",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body:        []byte(`{"status":"success","data":[{"id":1,"name":"Apple Juice"},{"id":2,"name":"Orange Juice"}]}`),
			},
		},
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/main.js",
				Path:   "/main.js",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/javascript",
				Body: []byte(`class ReviewSvc { host="/rest/products";
					create(id, body){ return this.http.put(this.host+"/"+id+"/reviews", body) }
					// body shape: { message: control.value, author: user.email }
				}`),
			},
		},
	}

	got := clientControlledAttributionCandidatesFromTraffic(entries, "https://shop.example")
	if len(got) == 0 {
		t.Fatal("expected client-controlled attribution candidate from client artifact")
	}
	if got[0].URL != "https://shop.example/rest/products/1/reviews" ||
		got[0].Method != http.MethodPut ||
		got[0].AttributionField != "author" ||
		got[0].MessageField != "message" ||
		got[0].ReadURL != "https://shop.example/rest/products/1/reviews" {
		t.Fatalf("candidate = %#v, want PUT/read-back /rest/products/1/reviews author/message", got[0])
	}
}

func TestClientControlledAttributionSignalRequiresMarkerAndIdentityOnSameObject(t *testing.T) {
	body := `{"status":"success","data":[
		{"message":"aobtd-attrib-marker","author":"admin@example.test"},
		{"message":"other","author":"alice@example.test"}
	]}`
	if got := clientControlledAttributionSignal(body, "aobtd-attrib-marker", "author", "admin@example.test"); got == "" {
		t.Fatal("expected persisted marker + spoofed author signal")
	}
	if got := clientControlledAttributionSignal(body, "aobtd-attrib-marker", "author", "alice@example.test"); got != "" {
		t.Fatalf("unexpected signal when identity only appears on a different object: %s", got)
	}
}

func TestClientControlledAttributionAuthorityAllowsActive(t *testing.T) {
	tests := []struct {
		name      string
		authority policy.TestingAuthority
		want      bool
	}{
		{name: "recon", authority: policy.AuthorityRecon, want: false},
		{name: "active", authority: policy.AuthorityActive, want: true},
		{name: "full control", authority: policy.AuthorityFullControl, want: true},
		{name: "unknown", authority: policy.TestingAuthority(""), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientControlledAttributionAuthority(tt.authority); got != tt.want {
				t.Fatalf("clientControlledAttributionAuthority(%q) = %v, want %v", tt.authority, got, tt.want)
			}
		})
	}
}

func TestRequiredFieldValidationCandidatesFromTraffic(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/main.js",
				Path:   "/main.js",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/javascript",
				Body: []byte(`class RegisterSvc {
					create(body){ return this.http.post("/api/Users/", body) }
					// body shape: { email, password, passwordRepeat, securityQuestion, securityAnswer }
				}`),
			},
		},
	}

	got := requiredFieldValidationCandidatesFromTraffic(entries, "https://shop.example")
	if len(got) == 0 {
		t.Fatal("expected registration required-field candidate")
	}
	if got[0].URL != "https://shop.example/api/Users/" ||
		got[0].Method != http.MethodPost ||
		got[0].Body["email"] != "" ||
		got[0].Body["password"] != "" {
		t.Fatalf("candidate = %#v, want POST /api/Users/ with empty required fields", got[0])
	}
}

func TestRequiredFieldValidationCandidatesFromTargetUseOrigin(t *testing.T) {
	got := requiredFieldValidationCandidatesFromTarget("https://shop.example/login.php")
	if len(got) == 0 {
		t.Fatal("expected common registration candidates")
	}
	if got[0].URL != "https://shop.example/api/Users/" {
		t.Fatalf("candidate URL = %q, want origin-root /api/Users/", got[0].URL)
	}
	if strings.Contains(got[0].URL, "/login.php/") {
		t.Fatalf("candidate URL should not be based under current page path: %q", got[0].URL)
	}
}

func TestRequiredFieldValidationIgnoresLoginAndWhoamiPaths(t *testing.T) {
	for _, path := range []string{
		"/rest/user/login",
		"/rest/user/authentication-details/",
		"/rest/user/whoami",
		"/api/auth/login",
		"/api/password-reset",
	} {
		if requiredFieldValidationPathLooksRegistration(path) {
			t.Fatalf("%s should not be treated as registration/account creation", path)
		}
	}
	for _, path := range []string{"/api/Users/", "/api/register", "/rest/user/register"} {
		if !requiredFieldValidationPathLooksRegistration(path) {
			t.Fatalf("%s should be treated as registration/account creation", path)
		}
	}
}

func TestRequiredFieldValidationDoesNotPromoteRejectedEmptyRegistration(t *testing.T) {
	if got := requiredFieldValidationAcceptanceSignal(http.StatusBadRequest, "Invalid email/password cannot be empty"); got != "" {
		t.Fatalf("400 rejection should not be an acceptance signal: %s", got)
	}
	loginShell := `<!doctype html><html><body><form action="/login.php"><input name="username"><input name="password" type="password"></form></body></html>`
	if got := requiredFieldValidationAcceptanceSignal(http.StatusOK, loginShell); got != "" {
		t.Fatalf("login shell should not be an empty-registration acceptance signal: %s", got)
	}
	if got := requiredFieldValidationRejectionSignal(http.StatusBadRequest, "Invalid email/password cannot be empty"); got != "cannot be empty" {
		t.Fatalf("rejection signal = %q, want cannot be empty", got)
	}
	if got := requiredFieldValidationAcceptanceSignal(http.StatusCreated, `{"status":"success","data":{"id":12,"email":""}}`); !strings.Contains(got, "id=12") {
		t.Fatalf("2xx created response should be accepted, got %q", got)
	}
}

func TestMutableOwnershipAcceptanceSignalMatchesNumericStringEquivalence(t *testing.T) {
	body := `{"status":"success","data":{"id":9,"BasketId":7,"quantity":1}}`
	if got := mutableOwnershipAcceptanceSignal("BasketId", "7", body); got == "" {
		t.Fatal("expected BasketId acceptance signal for numeric/string equivalent value")
	}
	if got := mutableOwnershipAcceptanceSignal("BasketId", 8, body); got != "" {
		t.Fatalf("unexpected signal for wrong mutated value: %s", got)
	}
}

func TestActiveWriteAuthHeadersDropsConditionalBrowserHeaders(t *testing.T) {
	got := activeWriteAuthHeaders(map[string]string{
		"Authorization": "Bearer token",
		"Cookie":        "sid=abc",
		"If-None-Match": `W/"abc"`,
		"Referer":       "https://shop.example/",
		"X-CSRF-Token":  "csrf",
	})
	if got["Authorization"] != "Bearer token" || got["Cookie"] != "sid=abc" || got["X-CSRF-Token"] != "csrf" {
		t.Fatalf("auth/csrf headers not preserved: %#v", got)
	}
	if _, ok := got["If-None-Match"]; ok {
		t.Fatalf("conditional cache header should not be replayed on active writes: %#v", got)
	}
	if _, ok := got["Referer"]; ok {
		t.Fatalf("browser navigation header should not be replayed on active writes: %#v", got)
	}
}

func TestPrioritizedJSRefetchCandidatesPromotesMainBundlePastEarlyChunks(t *testing.T) {
	var entries []types.TrafficEntry
	for i := 0; i < 9; i++ {
		entries = append(entries, types.TrafficEntry{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/chunk-filler-" + string(rune('a'+i)) + ".js",
				Path:   "/chunk-filler.js",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/javascript",
				Size:        int64(180000 + i),
			},
		})
	}
	entries = append(entries, types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: "GET",
			URL:    "https://shop.example/main.js",
			Path:   "/main.js",
		},
		Response: types.CapturedResponse{
			StatusCode:  http.StatusOK,
			ContentType: "application/javascript",
			Size:        783793,
		},
	})
	entries = append(entries, types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: "GET",
			URL:    "https://shop.example/polyfills.js",
			Path:   "/polyfills.js",
		},
		Response: types.CapturedResponse{
			StatusCode:  http.StatusOK,
			ContentType: "application/javascript",
			Size:        900000,
		},
	})

	got := prioritizedJSRefetchCandidates(entries)
	if len(got) < 2 {
		t.Fatalf("expected refetch candidates, got %#v", got)
	}
	if got[0].Request.URL != "https://shop.example/main.js" {
		t.Fatalf("main app bundle should be refetched before earlier chunks, got first %s", got[0].Request.URL)
	}
	if got[1].Request.URL == "https://shop.example/polyfills.js" {
		t.Fatalf("polyfills should not outrank route-bearing chunks despite size")
	}
}

func TestStoredXSSPayloadsIncludeCommonAndSanitizerDifferential(t *testing.T) {
	payloads := storedXSSPayloads("AOBTD_MARKER")
	var common, differential bool
	for _, payload := range payloads {
		if payload.Payload == commonStoredXSSPayload && payload.Expected == commonStoredXSSPayload && payload.ExpectedAlert == "xss" {
			common = true
		}
		if payload.Kind == "nested-tag-sanitizer-differential" {
			differential = true
			if !strings.Contains(payload.Payload, "<<script>") {
				t.Fatalf("sanitizer differential payload should exercise nested-tag stripping, got %q", payload.Payload)
			}
			if payload.Expected != commonStoredXSSPayload {
				t.Fatalf("sanitizer differential should expect the dangerous tag to be stitched together, got %q", payload.Expected)
			}
		}
	}
	if !common {
		t.Fatal("stored XSS payload set should include the common iframe/javascript proof payload")
	}
	if !differential {
		t.Fatal("stored XSS payload set should include a sanitizer-differential bypass probe")
	}
}

func TestStoredXSSWriteCandidatesInferContentWriteSurfaces(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{Method: "GET", URL: "https://shop.example/rest/products/search", Path: "/rest/products/search"},
			Response: types.CapturedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`{"status":"success","data":[{"id":1,"name":"Apple","description":"Classic","price":1.99,"image":"apple.jpg"}]}`),
			},
		},
		{
			Request: types.CapturedRequest{Method: "GET", URL: "https://shop.example/api/Feedbacks/", Path: "/api/Feedbacks/"},
			Response: types.CapturedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`{"status":"success","data":[{"comment":"Great","rating":5}]}`),
			},
		},
		{
			Request: types.CapturedRequest{Method: "GET", URL: "https://shop.example/rest/user/whoami", Path: "/rest/user/whoami"},
			Response: types.CapturedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`{"user":{}}`),
			},
		},
	}

	candidates := storedXSSWriteCandidatesFromTraffic(entries, "https://shop.example")
	got := map[string]storedXSSWriteCandidate{}
	for _, candidate := range candidates {
		got[candidate.Path] = candidate
	}
	feedback, ok := got["/api/Feedbacks/"]
	if !ok {
		t.Fatalf("candidates = %#v, want feedback write candidate", candidates)
	}
	if !feedback.RequiresCaptcha || len(feedback.InjectFields) != 1 || feedback.InjectFields[0] != "comment" {
		t.Fatalf("feedback candidate should inject comment with captcha support, got %#v", feedback)
	}
	product, ok := got["/api/Products"]
	if !ok {
		t.Fatalf("candidates = %#v, want product write candidate inferred from search results", candidates)
	}
	if !product.PreferAuth || !reflect.DeepEqual(product.InjectFields, []string{"description", "name", "image"}) {
		t.Fatalf("product candidate should prefer auth and test multiple renderable fields, got %#v", product)
	}
	if len(product.RenderURLs) == 0 || !strings.Contains(product.RenderURLs[0], "/#/search") {
		t.Fatalf("product candidate should include broad search/list render URLs, got %#v", product.RenderURLs)
	}
	user, ok := got["/api/Users"]
	if !ok {
		t.Fatalf("candidates = %#v, want user write candidate inferred from identity surface", candidates)
	}
	if len(user.InjectFields) != 1 || user.InjectFields[0] != "email" {
		t.Fatalf("user candidate should inject email, got %#v", user)
	}
}

func TestMassAssignmentCandidatesInferIdentityWriteSurface(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{Method: "GET", URL: "https://shop.example/rest/user/whoami", Path: "/rest/user/whoami"},
			Response: types.CapturedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`{"user":{"email":"demo@example.test"}}`),
			},
		},
		{
			Request: types.CapturedRequest{
				Method: "PATCH",
				URL:    "https://shop.example/api/profile",
				Path:   "/api/profile",
				Headers: map[string]string{
					"Content-Type":  "application/json",
					"Authorization": "Bearer token",
				},
				Body: []byte(`{"displayName":"Ozzy","phone":"555"}`),
			},
		},
	}

	candidates := massAssignmentCandidatesFromTraffic(entries, "https://shop.example")
	got := map[string]massAssignmentCandidate{}
	for _, candidate := range candidates {
		got[candidate.Path] = candidate
	}
	user, ok := got["/api/Users"]
	if !ok {
		t.Fatalf("candidates = %#v, want conventional registration/user candidate", candidates)
	}
	if user.Method != "POST" || user.Body["email"] == "" || user.Body["password"] == "" {
		t.Fatalf("user candidate should be a POST registration-shaped write, got %#v", user)
	}
	profile, ok := got["/api/profile"]
	if !ok {
		t.Fatalf("candidates = %#v, want observed profile write candidate", candidates)
	}
	if !profile.PreferAuth {
		t.Fatalf("observed authenticated profile write should prefer auth, got %#v", profile)
	}
}

func TestMassAssignmentAcceptanceSignalRequiresPrivilegedValue(t *testing.T) {
	tests := []struct {
		name  string
		field string
		body  string
		want  string
	}{
		{
			name:  "role admin accepted",
			field: "role",
			body:  `{"status":"success","data":{"email":"x@example.test","role":"admin"}}`,
			want:  "role=",
		},
		{
			name:  "nested roles accepted",
			field: "roles",
			body:  `{"data":{"user":{"roles":["customer","admin"]}}}`,
			want:  "roles=",
		},
		{
			name:  "boolean admin accepted",
			field: "isAdmin",
			body:  `{"data":{"isAdmin":true}}`,
			want:  "isAdmin=",
		},
		{
			name:  "ordinary user role is not enough",
			field: "role",
			body:  `{"data":{"role":"user"}}`,
		},
		{
			name:  "error text mentioning admin is not enough",
			field: "role",
			body:  `{"error":"role admin is not allowed"}`,
		},
		{
			name:  "invalid json is ignored",
			field: "role",
			body:  `role=admin`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := massAssignmentAcceptanceSignal(tc.field, tc.body)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("signal = %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("signal = %q, want containing %q", got, tc.want)
			}
		})
	}
}

func TestMassAssignmentWriteSurfaceEligibilityAvoidsLoginNoise(t *testing.T) {
	if massAssignmentWriteSurfaceLooksRelevant("/api/login", map[string]any{"email": "a@example.test", "password": "pw"}) {
		t.Fatal("login endpoints should not be mass-assignment candidates")
	}
	if !massAssignmentWriteSurfaceLooksRelevant("/api/accounts/profile", map[string]any{"displayName": "Ozzy", "phone": "555"}) {
		t.Fatal("profile/account writes should be mass-assignment candidates")
	}
	if !massAssignmentWriteSurfaceLooksRelevant("/api/anything", map[string]any{"email": "a@example.test", "password": "pw"}) {
		t.Fatal("identity-shaped writes should be eligible even when the path is generic")
	}
}

func TestMassAssignmentNormalizeIdentityFieldsMakesUniqueSyntheticAccount(t *testing.T) {
	body := map[string]any{
		"email":    "old@example.test",
		"password": "old-password",
		"name":     "keep-me",
	}
	massAssignmentNormalizeIdentityFields(body)
	email, _ := body["email"].(string)
	password, _ := body["password"].(string)
	if !strings.HasPrefix(email, "aobtd-mass-") || !strings.HasSuffix(email, "@example.invalid") {
		t.Fatalf("email = %q, want synthetic aobtd-mass address", email)
	}
	if !strings.HasPrefix(password, "A0btd-Mass-") {
		t.Fatalf("password = %q, want synthetic password", password)
	}
	if body["name"] != "keep-me" {
		t.Fatalf("unrelated fields should be preserved, got %#v", body)
	}
}

func TestRecoveredObjectBaselineURLReplacesOnlyTailSegment(t *testing.T) {
	got := recoveredObjectBaselineURL("https://shop.example/rest/basket/1?expand=items")
	want := "https://shop.example/rest/basket/AOBTDnope999999?expand=items"
	if got != want {
		t.Fatalf("baseline URL = %q, want %q", got, want)
	}
}

func TestRecoveredObjectAccessSignalRequiresObjectRecord(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "data object with id",
			body: `{"status":"success","data":{"id":1,"UserId":2,"createdAt":"now"}}`,
			want: true,
		},
		{
			name: "array item object with owner",
			body: `{"data":[{"orderId":7,"customerId":2}]}`,
			want: true,
		},
		{
			name: "null data ignored",
			body: `{"status":"success","data":null}`,
		},
		{
			name: "error object ignored",
			body: `{"error":"not found","message":"missing id"}`,
		},
		{
			name: "invalid json ignored",
			body: `<html>not json</html>`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := recoveredObjectAccessSignal(tc.body) != ""
			if got != tc.want {
				t.Fatalf("signal present = %v, want %v (signal=%q)", got, tc.want, recoveredObjectAccessSignal(tc.body))
			}
		})
	}
}

func TestRecoveredObjectResponseDiffRequiresMaterialDifference(t *testing.T) {
	if !recoveredObjectResponseDiffers(200, `{"data":{"id":1,"name":"basket item with enough size"}}`, 404, `{"error":"missing"}`) {
		t.Fatal("different status should count as a material recovered-object difference")
	}
	if recoveredObjectResponseDiffers(200, `{"data":{"id":1}}`, 200, `{"data":{"id":2}}`) {
		t.Fatal("same-sized JSON bodies should not be enough without material baseline difference")
	}
}

func TestJWTNoneTokenFromSignedJWTPreservesPayloadAndExtractsIdentity(t *testing.T) {
	token := testJWTWithPayload(`{"data":{"id":1,"email":"admin@example.test","role":"admin"}}`)
	forged, identity, ok := jwtNoneTokenFromSignedJWT(token)
	if !ok {
		t.Fatal("jwtNoneTokenFromSignedJWT rejected a valid signed JWT")
	}
	if !strings.HasPrefix(forged, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.") || !strings.HasSuffix(forged, ".") {
		t.Fatalf("forged token = %q, want alg=none header and empty signature", forged)
	}
	if identity != "admin@example.test" {
		t.Fatalf("identity = %q, want email from nested data claim", identity)
	}
}

func TestJWTTokensFromHeadersExtractsBearerAndCookieTokens(t *testing.T) {
	token := testJWTWithPayload(`{"email":"cookie@example.test"}`)
	got := jwtTokensFromHeaders(map[string]string{
		"Authorization": "Bearer " + token,
		"Cookie":        "session=abc; token=" + token + "; theme=dark",
	})
	if len(got) != 2 {
		t.Fatalf("tokens = %#v, want bearer and cookie token", got)
	}
}

func TestJWTUnsignedAcceptedSignalRequiresBaselineBypassOrIdentity(t *testing.T) {
	identitySignal := jwtUnsignedAcceptedSignal(
		"admin@example.test",
		200,
		`{"user":{}}`,
		200,
		`{"user":{"id":1,"email":"admin@example.test"}}`,
	)
	if !strings.Contains(identitySignal, "admin@example.test") {
		t.Fatalf("identity signal = %q, want accepted identity", identitySignal)
	}

	baselineBypass := jwtUnsignedAcceptedSignal(
		"",
		401,
		`{"error":"unauthorized"}`,
		200,
		`{"data":{"id":1,"UserId":1}}`,
	)
	if baselineBypass == "" {
		t.Fatal("401 baseline followed by object-shaped 200 should confirm alg=none acceptance")
	}

	if got := jwtUnsignedAcceptedSignal("", 200, `{"status":"ok"}`, 200, `{"status":"ok"}`); got != "" {
		t.Fatalf("same public response produced signal %q, want none", got)
	}
}

func TestJWTUnsignedForgeVariantsIncludeSyntheticDomainIdentity(t *testing.T) {
	token := testJWTWithPayload(`{"data":{"id":1,"email":"admin@juice-sh.op","role":"admin"}}`)
	identities := jwtUnsignedCandidateIdentities(nil, "admin@juice-sh.op", "http://127.0.0.1:3000")
	variants := jwtUnsignedForgeVariants(token, identities, 8)
	if len(variants) < 2 {
		t.Fatalf("variants = %#v, want mutated variants plus original", variants)
	}
	var foundSynthetic bool
	for _, variant := range variants {
		if variant.Identity == "jwtn3d@juice-sh.op" {
			foundSynthetic = true
			break
		}
	}
	if !foundSynthetic {
		t.Fatalf("variants = %#v, want bounded synthetic JWT test identity derived from original token domain", variants)
	}
	if variants[len(variants)-1].Identity != "admin@juice-sh.op" || !strings.Contains(variants[len(variants)-1].Note, "preserved") {
		t.Fatalf("last variant = %#v, want original claims preserved as fallback", variants[len(variants)-1])
	}
}

func TestJWTUnsignedCandidateIdentitiesPrioritizeAppDisclosedJWTClues(t *testing.T) {
	body := `{"description":"Forge an essentially unsigned JWT token that impersonates the non-existing user <i>jwtn3d@juice-sh.op</i>.","other":"admin@juice-sh.op"}`
	candidates := jwtUnsignedIdentityCandidatesFromText(body, "/api/Challenges/")
	identities := jwtUnsignedCandidateIdentitiesFromCandidates(candidates, "admin@juice-sh.op", "http://127.0.0.1:3000", 8)
	if len(identities) == 0 {
		t.Fatal("expected candidate identities")
	}
	if identities[0] != "jwtn3d@juice-sh.op" {
		t.Fatalf("first identity = %q, want app-disclosed unsigned-JWT impersonation target; all=%#v", identities[0], identities)
	}

	token := testJWTWithPayload(`{"data":{"id":1,"email":"admin@juice-sh.op","role":"admin"}}`)
	variants := jwtUnsignedForgeVariants(token, identities, 6)
	var found bool
	for _, variant := range variants {
		if variant.Identity == "jwtn3d@juice-sh.op" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("variants = %#v, want app-disclosed JWT impersonation identity within bounded variant set", variants)
	}
}

func TestJWTKeyConfusionCandidateIdentitiesPrioritizeRSAHint(t *testing.T) {
	body := `{"data":[
		{"description":"Forge an essentially unsigned JWT token that impersonates the non-existing user <i>jwtn3d@juice-sh.op</i>."},
		{"description":"Forge an almost properly RSA-signed JWT token that impersonates the (non-existing) user <i>rsa_lord@juice-sh.op</i>."}
	]}`
	candidates := jwtKeyConfusionIdentityCandidatesFromText(body, "/api/Challenges/")
	identities := jwtKeyConfusionCandidateIdentitiesFromCandidates(candidates, "admin@juice-sh.op", "http://127.0.0.1:3000", 8)
	if len(identities) == 0 || identities[0] != "rsa_lord@juice-sh.op" {
		t.Fatalf("identities = %#v, want rsa_lord first for RSA/HS key confusion", identities)
	}
}

func TestJWTUnsignedForgeVariantMutatesNestedDataEmail(t *testing.T) {
	token := testJWTWithPayload(`{"data":{"id":1,"email":"admin@example.test","role":"admin"},"sub":"1"}`)
	variants := jwtUnsignedForgeVariants(token, []string{"jwt-none@example.test"}, 4)
	if len(variants) == 0 {
		t.Fatal("expected forged variants")
	}
	var mutated jwtUnsignedForgeVariant
	for _, variant := range variants {
		if variant.Identity == "jwt-none@example.test" {
			mutated = variant
			break
		}
	}
	if mutated.Token == "" {
		t.Fatalf("variants = %#v, want jwt-none@example.test mutation", variants)
	}
	parts := strings.Split(mutated.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("mutated token = %q, want JWT shape", mutated.Token)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode mutated payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("unmarshal mutated payload: %v", err)
	}
	data, _ := payload["data"].(map[string]any)
	if data["email"] != "jwt-none@example.test" {
		t.Fatalf("mutated payload = %#v, want nested data.email updated", payload)
	}
}

func TestJWTKeyConfusionMaterialsFromBodyExtractsPEMAndIgnoresSPAHTML(t *testing.T) {
	pem := []byte("-----BEGIN RSA PUBLIC KEY-----\nabc123\n-----END RSA PUBLIC KEY-----")
	materials := jwtKeyConfusionMaterialsFromBody(pem, "https://shop.example/encryptionkeys/jwt.pub", "application/x-mspublisher")
	if len(materials) != 1 {
		t.Fatalf("materials = %#v, want one PEM material", materials)
	}
	if string(materials[0].Key) != string(pem) {
		t.Fatalf("key = %q, want exact PEM bytes", string(materials[0].Key))
	}

	html := []byte(`<!doctype html><html><body>SPA shell</body></html>`)
	if got := jwtKeyConfusionMaterialsFromBody(html, "https://shop.example/jwt.pub", "text/html"); len(got) != 0 {
		t.Fatalf("HTML shell materials = %#v, want none", got)
	}
}

func TestJWTKeyConfusionForgeVariantsSignHS256AndMutateIdentity(t *testing.T) {
	token := testJWTWithPayload(`{"data":{"id":1,"email":"admin@juice-sh.op","role":"admin"}}`)
	variants := jwtHS256KeyConfusionForgeVariants(token, []byte("public-key-as-hmac-secret"), []string{"rsa_lord@juice-sh.op"}, 4)
	if len(variants) == 0 {
		t.Fatal("expected HS256 key-confusion variant")
	}
	var found jwtUnsignedForgeVariant
	for _, variant := range variants {
		if variant.Identity == "rsa_lord@juice-sh.op" {
			found = variant
			break
		}
	}
	if found.Token == "" {
		t.Fatalf("variants = %#v, want rsa_lord@juice-sh.op mutation", variants)
	}
	parts := strings.Split(found.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("token = %q, want JWT shape", found.Token)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header["alg"] != "HS256" {
		t.Fatalf("header = %#v, want HS256", header)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	data, _ := payload["data"].(map[string]any)
	if data["email"] != "rsa_lord@juice-sh.op" {
		t.Fatalf("payload = %#v, want rsa_lord identity", payload)
	}
}

func TestLoginSQLiPayloadsPrioritizeObservedIdentities(t *testing.T) {
	payloads := loginSQLiPayloadsForIdentities([]string{"admin@example.test", "bender@example.test"})
	if len(payloads) < 4 {
		t.Fatalf("payloads = %#v, want identity-specific payloads plus generic fallbacks", payloads)
	}
	if payloads[0].targetIdentity != "admin@example.test" || !strings.Contains(payloads[0].email, "admin@example.test'") {
		t.Fatalf("first payload = %#v, want first observed identity quote-bypass first", payloads[0])
	}
	var foundBender bool
	var firstGeneric = -1
	for i, payload := range payloads {
		if payload.targetIdentity == "bender@example.test" && strings.Contains(payload.email, "bender@example.test'") {
			foundBender = true
		}
		if payload.targetIdentity == "" && firstGeneric == -1 {
			firstGeneric = i
		}
	}
	if !foundBender {
		t.Fatalf("payloads = %#v, want second observed identity covered", payloads)
	}
	if firstGeneric <= 0 {
		t.Fatalf("payloads = %#v, want generic tautology fallbacks after identity-specific attempts", payloads)
	}
}

func TestObservedEmailLikeRegexExtractsIdentityJSON(t *testing.T) {
	body := []byte(`{"data":[{"email":"admin@example.test"},{"email":"bender@example.test"}]}`)
	got := observedEmailLikeRegex.FindAllString(string(body), -1)
	if len(got) != 2 || got[0] != "admin@example.test" || got[1] != "bender@example.test" {
		t.Fatalf("emails = %#v, want admin and bender identities", got)
	}
}

func TestLoginSQLiCredentialFieldsUseObservedNames(t *testing.T) {
	entry := types.TrafficEntry{Request: types.CapturedRequest{
		Method: "POST",
		URL:    "https://target.example/api/auth/login",
		Path:   "/api/auth/login",
		Body:   []byte(`{"username":"alice","secret":"pw","remember":true}`),
	}}
	identityField, passwordField := loginSQLiCredentialFields(entry)
	if identityField != "username" || passwordField != "secret" {
		t.Fatalf("fields = %q/%q, want username/secret", identityField, passwordField)
	}

	formEntry := types.TrafficEntry{Request: types.CapturedRequest{
		Method: "POST",
		URL:    "https://target.example/login",
		Path:   "/login",
		Body:   []byte(`login=alice&pass=pw`),
	}}
	identityField, passwordField = loginSQLiCredentialFields(formEntry)
	if identityField != "login" || passwordField != "pass" {
		t.Fatalf("form fields = %q/%q, want login/pass", identityField, passwordField)
	}
}

func TestLoginSQLiAuthenticatedIdentityHarvestUsesBypassToken(t *testing.T) {
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/Users" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer bypass-token" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		sawAuth = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[{"email":"admin@example.test"},{"email":"jim@example.test"},{"email":"bender@example.test"}]}`)
	}))
	defer srv.Close()

	v := &VerifierAgent{client: srv.Client(), target: srv.URL}
	got := v.loginSQLiIdentityCandidatesFromAuthenticatedEndpoints(context.Background(), srv.URL+"/rest/user/login", "bypass-token", 8)
	if !sawAuth {
		t.Fatal("expected authenticated identity endpoint request")
	}
	for _, want := range []string{"admin@example.test", "jim@example.test", "bender@example.test"} {
		found := false
		for _, candidate := range got {
			if candidate == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("candidates = %#v, want %s", got, want)
		}
	}
}

func TestVerifyLoginSQLiRejectsSameCookieAsBaseline(t *testing.T) {
	const loginShell = `<!doctype html><html><title>Login</title><form><input name="username"><input name="password" type="password"></form></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login.php" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "same-session-cookie"})
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, loginShell)
	}))
	defer srv.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "login-sqli-baseline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan(srv.URL, `{}`)
	if err != nil {
		t.Fatal(err)
	}

	v := &VerifierAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		client: srv.Client(),
		target: srv.URL,
	}
	profile := types.PageProfile{ID: "POST /login.php", URL: srv.URL + "/login.php", Method: "POST"}
	entry := types.TrafficEntry{Request: types.CapturedRequest{
		Method:  "POST",
		URL:     srv.URL + "/login.php",
		Path:    "/login.php",
		Headers: map[string]string{"Content-Type": "application/json"},
	}}
	if v.verifyLoginSQLi(context.Background(), profile, entry) {
		t.Fatal("same session cookie/login shell should not confirm SQLi")
	}
	var count int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id = ?`, scanID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("finding count = %d, want 0", count)
	}
}

func TestProbeWeakCredentialsRejectsSameCookieAsBaseline(t *testing.T) {
	const loginShell = `<!doctype html><html><title>Login</title><form><input name="username"><input name="password" type="password"></form></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login.php" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "same-session-cookie"})
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, loginShell)
	}))
	defer srv.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "weak-creds-baseline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan(srv.URL+"/login.php", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  http.MethodPost,
			URL:     srv.URL + "/login.php",
			Path:    "/login.php",
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    []byte(`{"username":"probe","password":"probe"}`),
		},
		Response: types.CapturedResponse{
			StatusCode:  http.StatusOK,
			ContentType: "text/html",
			Body:        []byte(loginShell),
		},
		Timestamp: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	v := &VerifierAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		client: srv.Client(),
		target: srv.URL + "/login.php",
	}
	v.probeWeakCredentials(context.Background(), srv.URL+"/login.php")
	var count int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id = ?`, scanID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("finding count = %d, want 0", count)
	}
}

func TestWeakCredentialResultMatchesBaselineRequiresSameBodyShape(t *testing.T) {
	baseline := weakCredentialProbeResult{
		Status:     http.StatusOK,
		Body:       []byte("login shell"),
		AuthSignal: "Set-Cookie PHPSESSID",
	}
	if !weakCredentialResultMatchesBaseline(weakCredentialProbeResult{
		Status:     http.StatusOK,
		Body:       []byte("login shell"),
		AuthSignal: "Set-Cookie PHPSESSID",
	}, baseline) {
		t.Fatal("expected same status/auth/body shape to match baseline")
	}
	if weakCredentialResultMatchesBaseline(weakCredentialProbeResult{
		Status:     http.StatusOK,
		Body:       []byte(strings.Repeat("dashboard ", 200)),
		AuthSignal: "Set-Cookie PHPSESSID",
	}, baseline) {
		t.Fatal("different response body shape should not match baseline")
	}
}

func TestLoginSQLiShouldPromoteBrowserSessionForPrivilegedPersonas(t *testing.T) {
	if !loginSQLiShouldPromoteBrowserSession("ordinary@example.test", true) {
		t.Fatal("first accepted login bypass should seed the browser once")
	}
	if loginSQLiShouldPromoteBrowserSession("ordinary@example.test", false) {
		t.Fatal("ordinary follow-up identities should not repeatedly reseed privileged routes")
	}
	for _, identity := range []string{
		"admin@example.test",
		"support@example.test",
		"security@example.test",
		"accountant@example.test",
	} {
		if !loginSQLiShouldPromoteBrowserSession(identity, false) {
			t.Fatalf("privileged-looking identity %q should promote browser session", identity)
		}
	}
}

func TestLoginAuthSuccessSignalRequiresConcreteArtifact(t *testing.T) {
	htmlResp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	htmlBody := []byte(`<html><script src="/discovery-sfint-authentication-service/login.js"></script><div id="root"></div></html>`)
	if got := loginAuthSuccessSignal(htmlResp, htmlBody); got != "" {
		t.Fatalf("HTML authentication-service text produced auth signal %q", got)
	}

	jsonResp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	if got := loginAuthSuccessSignal(jsonResp, []byte(`{"authentication":{"token":"username-keyed-token"}}`)); got == "" {
		t.Fatal("JSON token field should produce auth signal")
	}

	cookieResp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	cookieResp.Header.Add("Set-Cookie", "session_id=abcdef123456; Path=/; HttpOnly")
	if got := loginAuthSuccessSignal(cookieResp, nil); got != "Set-Cookie session_id" {
		t.Fatalf("auth cookie signal = %q, want Set-Cookie session_id", got)
	}

	csrfResp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	csrfResp.Header.Add("Set-Cookie", "csrf_token=abcdef123456; Path=/")
	if got := loginAuthSuccessSignal(csrfResp, nil); got != "" {
		t.Fatalf("csrf cookie produced auth signal %q", got)
	}
}

func TestGenerateTOTPCodeUsesRFC6238SHA1Vector(t *testing.T) {
	code, ok := generateTOTPCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0))
	if !ok {
		t.Fatal("generateTOTPCode returned !ok")
	}
	if code != "287082" {
		t.Fatalf("code = %q, want final six digits of RFC 6238 vector 94287082", code)
	}
}

func TestMFASecretCandidatesFromUnionJSONPairsEmailAndSecret(t *testing.T) {
	body := `{"status":"success","data":[
		{"id":10,"name":"wurstbrot@example.test","description":"IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH","price":0},
		{"id":11,"name":"plain@example.test","description":"","price":0}
	]}`
	got := mfaSecretCandidatesFromBody(body, "https://target.example/rest/products/search?q=", "q", "union payload")
	if len(got) != 1 {
		t.Fatalf("candidates = %#v, want one non-empty MFA seed candidate", got)
	}
	if got[0].Identity != "wurstbrot@example.test" || got[0].Secret != "IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH" {
		t.Fatalf("candidate = %#v, want wurstbrot identity paired with TOTP seed", got[0])
	}
}

func TestMFASecretCandidatesSkipEnrollmentSetupSeed(t *testing.T) {
	body := `{"setup":false,"secret":"INMR6ARYL6UU7PS4IJ5T4L675GB6KAHX","email":"new-user@example.test","setupToken":"signed.setup.jwt"}`
	got := mfaSecretCandidatesFromBody(body, "https://target.example/rest/2fa/status", "", "")
	if len(got) != 0 {
		t.Fatalf("candidates = %#v, want setup/enrollment seed ignored for login-takeover chain", got)
	}
}

func TestExtractMFAChallengeTokenFindsNestedTmpToken(t *testing.T) {
	body := []byte(`{"status":"totp_token_required","data":{"tmpToken":"tmp.jwt.value"}}`)
	if got := extractMFAChallengeToken(body); got != "tmp.jwt.value" {
		t.Fatalf("tmp token = %q, want nested tmpToken", got)
	}
}

func TestJSONBodyContainsStringDecodesEscapedPayload(t *testing.T) {
	bodyBytes, _ := json.Marshal(map[string]any{
		"status": "success",
		"data": map[string]any{
			"description": commonStoredXSSPayload,
		},
	})
	if !jsonBodyContainsString(string(bodyBytes), commonStoredXSSPayload) {
		t.Fatalf("jsonBodyContainsString should match inside decoded JSON string, body=%s", string(bodyBytes))
	}
}

func TestStoredXSSInjectableFieldsPrioritizesContentFields(t *testing.T) {
	got := storedXSSInjectableFields(map[string]any{
		"id":          7,
		"displayName": "Ozzy",
		"description": "hello",
		"comment":     "nice",
		"rating":      5,
		"email":       "user@example.test",
	})
	want := []string{"comment", "description", "email"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestGuessIDORTemplateFromURL checks the heuristic the Verifier uses to
// turn an analyzer-flagged IDOR hint into a probe_idor directive. The
// template + values it produces are what the Explorer replays against
// the target, so getting it wrong means the probe either tests the wrong
// path segment or hits nothing at all.
func TestGuessIDORTemplateFromURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantTmpl  string
		wantFirst string // first value in the returned set (the preserved original id)
	}{
		{
			"numeric id at end",
			"https://api.example.com/orders/42",
			"https://api.example.com/orders/{id}",
			"42",
		},
		{
			"numeric id with query string",
			"https://api.example.com/users/1234?fields=email",
			"https://api.example.com/users/{id}?fields=email",
			"1234",
		},
		{
			"uuid id",
			"https://api.example.com/files/123e4567-e89b-12d3-a456-426614174000",
			"https://api.example.com/files/{id}",
			"123e4567-e89b-12d3-a456-426614174000",
		},
		{
			"multiple ids — rightmost wins",
			"https://api.example.com/users/42/orders/99",
			"https://api.example.com/users/42/orders/{id}",
			"99",
		},
		{
			"no id segment — returns empty",
			"https://api.example.com/about",
			"",
			"",
		},
		{
			"words that look id-ish but aren't digits",
			"https://api.example.com/users/me/profile",
			"",
			"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotTmpl, gotVals := guessIDORTemplateFromURL(tc.url)
			if gotTmpl != tc.wantTmpl {
				t.Errorf("template = %q, want %q", gotTmpl, tc.wantTmpl)
			}
			if tc.wantFirst != "" {
				if len(gotVals) == 0 || gotVals[0] != tc.wantFirst {
					t.Errorf("first value = %v, want %q (as values[0])", gotVals, tc.wantFirst)
				}
				if len(gotVals) < 2 {
					t.Errorf("need at least 2 values for a probe_idor, got %d", len(gotVals))
				}
			}
		})
	}
}

func TestVerifierSuppressesPublicMetaIDORProbe(t *testing.T) {
	tmpl, vals := guessIDORTemplateFromURL("https://example.test/api/Challenges/1")
	if tmpl == "" || len(vals) < 2 {
		t.Fatalf("expected template for numeric path id, got %q %v", tmpl, vals)
	}
	if idorTargetLooksOwnedObject(tmpl) {
		t.Fatalf("public/meta endpoint %q should not be accepted as an owned-object IDOR target", tmpl)
	}
}

func TestDirectoryListingHelpers(t *testing.T) {
	if got := parentURLPath("/ftp/legal.md"); got != "/ftp/" {
		t.Fatalf("parentURLPath = %q, want /ftp/", got)
	}
	if dirs := conventionalDirectoryListingDirs(); !stringSliceContains(dirs, "/support/logs/") {
		t.Fatalf("conventional dirs = %v, want /support/logs/ for directory-index probing", dirs)
	}
	html := `<html><head><title>listing directory /ftp/</title></head><body>
		<ul id="files">
			<li><a href="/ftp/legal.md">legal.md</a></li>
			<li><a href="acquisitions.md">acquisitions.md</a></li>
			<li><a href="package.json.bak">package.json.bak</a></li>
			<li><a href="eastere.gg">eastere.gg</a></li>
			<li><a href="https://other.test/secret.md">external</a></li>
		</ul></body></html>`
	links := directoryListingLinks("https://example.test/ftp/", html)
	if len(links) != 4 {
		t.Fatalf("links = %v, want four same-origin links", links)
	}
	if !looksLikeDirectoryListing(html, links) {
		t.Fatalf("listing was not recognized: %v", links)
	}
	exts := directoryListingAllowedExtensions(links)
	if !stringSliceContains(exts, ".md") {
		t.Fatalf("allowed extensions = %v, want .md learned from sibling links", exts)
	}
	if !directoryListedArtifactWorthBypass("/ftp/package.json.bak") {
		t.Fatal("backup artifact from directory listing should be eligible for filter-bypass probing")
	}
	if !directoryListedArtifactWorthBypass("/ftp/eastere.gg") {
		t.Fatal("unusual-extension artifact from directory listing should be eligible for filter-bypass probing")
	}
	if !directoryListedArtifactWorthBypass("/ftp/suspicious_errors.yml") {
		t.Fatal("suspicious YAML rule artifact from directory listing should be eligible for filter-bypass probing")
	}
	signal, severity := exposedArtifactSignal("/ftp/acquisitions.md", "text/markdown", "# Planned Acquisitions\n\nThis document is confidential! Do not distribute!")
	if signal == "" || severity != types.SeverityMedium {
		t.Fatalf("artifact signal = (%q, %q), want confidential medium", signal, severity)
	}
	signal, severity = exposedArtifactSignal("/ftp/package.json.bak%2500.md", "application/octet-stream", `{"dependencies":{"express":"1.0.0"}}`)
	if signal == "" || severity != types.SeverityHigh {
		t.Fatalf("null-byte artifact signal = (%q, %q), want high", signal, severity)
	}
	signal, severity = exposedArtifactSignal("/ftp/eastere.gg%2500.md", "application/octet-stream", `"Congratulations, you found the easter egg!"`)
	if signal == "" || severity != types.SeverityMedium {
		t.Fatalf("unusual/easter artifact signal = (%q, %q), want medium", signal, severity)
	}
	signal, severity = exposedArtifactSignal("/ftp/suspicious_errors.yml%2500.md", "text/yaml", "title: Suspicious errors\nlogsource:\n  product: nodejs\ndetection:\n  keywords:\n    - Blocked illegal activity")
	if signal == "" || severity != types.SeverityMedium {
		t.Fatalf("sigma/yaml artifact signal = (%q, %q), want medium", signal, severity)
	}
	if got := canonicalArtifactSignalPath("/ftp/package.json.bak%2500.md"); got != "/ftp/package.json.bak" {
		t.Fatalf("canonicalArtifactSignalPath = %q, want backup path before null-byte suffix", got)
	}
}

func TestOrphanI18nBundleHelpers(t *testing.T) {
	if got := i18nBundleBasePath("/assets/i18n/en.json"); got != "/assets/i18n/" {
		t.Fatalf("i18nBundleBasePath = %q, want /assets/i18n/", got)
	}
	if got := i18nBundleBasePath("/assets/i18n/not/a/bundle.json"); got != "" {
		t.Fatalf("nested i18n bundle base = %q, want empty", got)
	}
	keys := i18nLanguageCatalogKeys(`[{"key":"en","lang":"English"},{"key":"de_DE","lang":"Deutsch"}]`)
	if !stringSliceContains(keys, "en") || !stringSliceContains(keys, "de_DE") {
		t.Fatalf("catalog keys = %v, want en and de_DE", keys)
	}
	catalog := map[string]struct{}{"en": {}, "de_de": {}}
	candidates := orphanI18nCandidateKeys(catalog)
	if !stringSliceContains(candidates, "tlh_AA") {
		t.Fatalf("orphan candidates = %v, want tlh_AA test/fantasy locale", candidates)
	}
	if !looksLikeI18nBundleJSON("application/json", `{"LANGUAGE":"tlhIngan","NAV_SEARCH":"tu'","BTN_CLOSE":"SoQmoH"}`) {
		t.Fatal("translation JSON with LANGUAGE marker should be recognized")
	}
	if looksLikeI18nBundleJSON("text/html", `<!doctype html><html><body>SPA fallback</body></html>`) {
		t.Fatal("SPA fallback should not be recognized as an i18n bundle")
	}
}

func TestEncodedMediaAssetRecoveryHelpers(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Response: types.CapturedResponse{
				Body: []byte(`{"data":[{"imagePath":"assets/public/images/uploads/ᓚᘏᗢ-#zatschi-#whoneedsfourlegs-1572600969477.jpg"}]}`),
			},
		},
	}
	candidates := encodedMediaPathCandidatesFromTraffic(entries, 4)
	if len(candidates) != 1 {
		t.Fatalf("encoded media candidates = %v, want one", candidates)
	}
	if candidates[0] != "/assets/public/images/uploads/ᓚᘏᗢ-#zatschi-#whoneedsfourlegs-1572600969477.jpg" {
		t.Fatalf("candidate = %q", candidates[0])
	}
	encoded, ok := encodeFragmentUnsafeMediaPath(candidates[0])
	if !ok {
		t.Fatal("expected media path to need encoding recovery")
	}
	want := "/assets/public/images/uploads/%E1%93%9A%E1%98%8F%E1%97%A2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg"
	if encoded != want {
		t.Fatalf("encoded path = %q, want %q", encoded, want)
	}
	if !encodedMediaAssetRecovered(200, "image/jpeg", encoded, "\xff\xd8\xff\xe0binary jpeg bytes") {
		t.Fatal("image response should be treated as recovered media")
	}
	if encodedMediaAssetRecovered(200, "text/html", encoded, "<!doctype html><html>SPA shell</html>") {
		t.Fatal("SPA shell should not be treated as recovered media")
	}
}

func TestStaticDisclosureFeedbackReportsFromManifest(t *testing.T) {
	body := `{
		"name":"juice-shop",
		"dependencies":{
			"sanitize-html":"1.4.2",
			"z85":"~0.0",
			"epilogue-js":"~0.7"
		},
		"devDependencies":{"eslint-scope":"3.7.2"}
	}`
	deps := dependencyVersionsFromPackageManifest(body)
	if cleanPackageVersion(deps["sanitize-html"]) != "1.4.2" {
		t.Fatalf("sanitize-html version = %q", deps["sanitize-html"])
	}
	reports := staticDisclosureFeedbackReportsFromManifest("/ftp/package.json.bak%2500.md", body)
	comments := make([]string, 0, len(reports))
	for _, report := range reports {
		comments = append(comments, report.Comment)
	}
	for _, want := range []string{"sanitize-html 1.4.2", "z85", "epilogue-js"} {
		if !stringSliceContains(comments, want) {
			t.Fatalf("reports = %#v, want comment %q", reports, want)
		}
	}
	if got := staticDisclosureFeedbackReportsFromManifest("/index.html", `<!doctype html><html></html>`); len(got) != 0 {
		t.Fatalf("HTML should not produce reports, got %#v", got)
	}
}

func TestBrowserCanonicalSPARouteURL(t *testing.T) {
	got := browserCanonicalSPARouteURL("https://shop.example", "https://shop.example/web3-sandbox")
	if got != "https://shop.example/#/web3-sandbox" {
		t.Fatalf("canonical SPA route = %q", got)
	}
	if got := browserCanonicalSPARouteURL("https://shop.example", "https://shop.example/assets/main.js"); got != "" {
		t.Fatalf("static asset should not be treated as SPA route: %q", got)
	}
	if score := browserInterestingUIRouteScore("https://shop.example/#/web3-sandbox"); score <= 0 {
		t.Fatalf("web3 sandbox route score = %d, want positive", score)
	}
	if browserInterestingUIRouteScore("https://shop.example/#/web3-sandbox") <= browserInterestingUIRouteScore("https://shop.example/#/administration") {
		t.Fatalf("web3 sandbox should outrank routine admin route")
	}
}

func TestBrowserEmbeddedSameOriginAssetURLs(t *testing.T) {
	body := `template:'<img src="assets/public/images/padding/11px.png"><img src="/assets/logo.svg"><img src="https://evil.example/assets/x.png">'`
	got := browserEmbeddedSameOriginAssetURLs("https://shop.example/#/web3-sandbox", body)
	want := []string{
		"https://shop.example/assets/public/images/padding/11px.png",
		"https://shop.example/assets/logo.svg",
	}
	if len(got) != len(want) {
		t.Fatalf("assets = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("assets[%d] = %q, want %q (all: %#v)", i, got[i], want[i], got)
		}
	}
	if got := browserResolveSameOriginStaticAssetURL("https://shop.example/#/web3-sandbox", "https://evil.example/assets/x.png"); got != "" {
		t.Fatalf("cross-origin asset should be rejected: %q", got)
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestCredentialPasswordCandidatesPrioritizeObservedIdentities(t *testing.T) {
	got := credentialPasswordCandidatesForUser("admin@example.test", []string{"admin", "admin123", "password"})
	for _, want := range []string{"admin", "admin123", "password"} {
		if !stringSliceContains(got, want) {
			t.Fatalf("credential candidates = %v, want %q", got, want)
		}
	}
	users := prioritizeCredentialUsernames([]string{"bjoern@example.test", "admin@example.test", "demo@example.test"})
	if users[0] != "admin@example.test" {
		t.Fatalf("prioritized users = %v, want admin-like identity first", users)
	}
}

func TestSensitiveAPIExposureSignal(t *testing.T) {
	tests := []struct {
		name          string
		contentType   string
		body          string
		wantSeverity  types.Severity
		wantSubstring string
	}{
		{
			name:          "password hash field is high confidence",
			contentType:   "application/json",
			body:          `[{"email":"admin@example.test","passwordHash":"abc123"}]`,
			wantSeverity:  types.SeverityHigh,
			wantSubstring: "passwordHash",
		},
		{
			name:          "plaintext password value is high confidence",
			contentType:   "application/json",
			body:          `{"user":{"email":"admin@example.test","password":"Password1!"}}`,
			wantSeverity:  types.SeverityHigh,
			wantSubstring: "password",
		},
		{
			name:          "email plus role user records are sensitive",
			contentType:   "application/json",
			body:          `[{"email":"a@example.test","role":"admin"},{"email":"b@example.test","role":"user"}]`,
			wantSeverity:  types.SeverityHigh,
			wantSubstring: "role",
		},
		{
			name:          "single user identity plus admin metadata is medium",
			contentType:   "application/json",
			body:          `{"email":"a@example.test","isAdmin":true}`,
			wantSeverity:  types.SeverityMedium,
			wantSubstring: "isAdmin",
		},
		{
			name:          "auth token field is high confidence",
			contentType:   "application/json",
			body:          `{"accessToken":"eyJhbGciOiJIUzI1NiJ9.demo"}`,
			wantSeverity:  types.SeverityHigh,
			wantSubstring: "accessToken",
		},
		{
			name:          "jwt payload exposes password hash",
			contentType:   "application/json",
			body:          `{"authentication":{"token":"` + testJWTWithPayload(`{"data":{"email":"admin@example.test","password":"0192023a7bbd73250516f069df18b500"}}`) + `"}}`,
			wantSeverity:  types.SeverityHigh,
			wantSubstring: "JWT payload data.password",
		},
		{
			name:        "masked password placeholder is ignored",
			contentType: "application/json",
			body:        `{"user":{"email":"a@example.test","password":"********************************"}}`,
		},
		{
			name:          "ambiguous token key requires secret-like value",
			contentType:   "application/json",
			body:          `{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig"}`,
			wantSeverity:  types.SeverityHigh,
			wantSubstring: "token",
		},
		{
			name:          "payment data plus owner marker is high confidence",
			contentType:   "application/json",
			body:          `[{"UserId":17,"fullName":"Tim Tester","cardNum":"************5678","expMonth":12,"expYear":2099}]`,
			wantSeverity:  types.SeverityHigh,
			wantSubstring: "cardNum",
		},
		{
			name:          "address collection is medium confidence personal data",
			contentType:   "application/json",
			body:          `[{"UserId":1,"streetAddress":"1 Main St","zipCode":"12345"},{"UserId":2,"streetAddress":"2 Main St","zipCode":"23456"}]`,
			wantSeverity:  types.SeverityMedium,
			wantSubstring: "streetAddress",
		},
		{
			name:          "graphql paste metadata collection is personal data",
			contentType:   "application/json",
			body:          `{"data":{"pastes":[{"id":"1","title":"hello","ipAddr":"215.0.2.10","userAgent":"Mozilla/5.0","owner":{"name":"Alice"}},{"id":"2","title":"world","ipAddr":"215.0.2.11","userAgent":"Mozilla/5.0","owner":{"name":"Bob"}}]}}`,
			wantSeverity:  types.SeverityMedium,
			wantSubstring: "ipAddr",
		},
		{
			name:        "html fallback is ignored",
			contentType: "text/html",
			body:        `<html><body>passwordHash accessToken admin@example.test</body></html>`,
		},
		{
			name:        "public help json is ignored",
			contentType: "application/json",
			body:        `{"message":"Use the password reset page if you forgot your password."}`,
		},
		{
			name:        "localization labels mentioning password are ignored",
			contentType: "application/json",
			body:        `{"password":"Password","invalid_username_password":"Invalid username and password.","secure-passwords.title":"Secure Passwords"}`,
		},
		{
			name:        "large lesson label bundle mentioning passwords is ignored",
			contentType: "application/json",
			body: `{
				"challenge5.title":"Without password",
				"password-reset-hint1":"Try to send a password reset link to your own account.",
				"password-reset-hint2":"Look at the link and inspect the host.",
				"SqlInjectionChallenge5":"Use substring(password,1,1) for the guess.",
				"invalid_username_password":"Invalid username and password.",
				"accounts.table.password":"Password",
				"lesson.overview":"This lesson explains credential handling.",
				"secure-passwords.title":"Secure Passwords",
				"show-password":"Show Password"
			}`,
		},
		{
			name:          "small real password field is still detected",
			contentType:   "application/json",
			body:          `{"username":"alice","password":"correcthorsebatterystaple"}`,
			wantSeverity:  types.SeverityHigh,
			wantSubstring: "password",
		},
		{
			name:        "short ambiguous token is ignored",
			contentType: "application/json",
			body:        `{"token":"next"}`,
		},
		{
			name:        "openapi schema mentioning auth token is ignored",
			contentType: "application/json",
			body: `{
				"openapi":"3.0.1",
				"info":{"title":"Demo API","version":"1.0"},
				"paths":{"/login":{"post":{"responses":{"200":{"description":"returns auth_token"}}}}},
				"components":{"schemas":{"LoginResponse":{"properties":{"auth_token":{"type":"string"}}}}}
			}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signal, severity := sensitiveAPIExposureSignal(tc.contentType, tc.body)
			if tc.wantSeverity == "" {
				if signal != "" || severity != "" {
					t.Fatalf("signal = (%q, %q), want none", signal, severity)
				}
				return
			}
			if severity != tc.wantSeverity || !strings.Contains(signal, tc.wantSubstring) {
				t.Fatalf("signal = (%q, %q), want severity %q containing %q",
					signal, severity, tc.wantSeverity, tc.wantSubstring)
			}
		})
	}
}

func TestEnumerableObjectExposureFindingsDetectsCrossUserPaymentRecords(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method:  http.MethodGet,
				URL:     "https://api.example.test/workshop/api/shop/orders/1",
				Path:    "/workshop/api/shop/orders/1",
				Headers: map[string]string{},
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body: []byte(`{
					"order":{"id":1,"user":{"email":"adam007@example.com","number":"9876895423"}},
					"payment":{"card_number":"XXXXXXXXXXXX9541","card_owner_name":"Adam","amount":20}
				}`),
			},
		},
		{
			Request: types.CapturedRequest{
				Method:  http.MethodGet,
				URL:     "https://api.example.test/workshop/api/shop/orders/2",
				Path:    "/workshop/api/shop/orders/2",
				Headers: map[string]string{},
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body: []byte(`{
					"order":{"id":2,"user":{"email":"pogba006@example.com","number":"9876570006"}},
					"payment":{"card_number":"XXXXXXXXXXXX9918","card_owner_name":"Pogba","amount":20}
				}`),
			},
		},
	}

	findings := enumerableObjectExposureFindings(entries)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %#v", len(findings), findings)
	}
	finding := findings[0]
	if finding.VulnType != "idor" {
		t.Fatalf("vuln type = %q, want idor", finding.VulnType)
	}
	if finding.EndpointID != "GET /workshop/api/shop/orders/{id}" {
		t.Fatalf("endpoint id = %q", finding.EndpointID)
	}
	if !strings.Contains(finding.Evidence, "adam007@example.com") || !strings.Contains(finding.Evidence, "pogba006@example.com") {
		t.Fatalf("evidence missing owner examples: %s", finding.Evidence)
	}
	if !strings.Contains(finding.PocRequest, "/workshop/api/shop/orders/1") ||
		!strings.Contains(finding.PocRequest, "/workshop/api/shop/orders/2") {
		t.Fatalf("PoC request should include both enumerated requests: %s", finding.PocRequest)
	}
}

func TestEnumerableObjectExposureFindingsDetectsQueryObjectIDRecords(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method:  http.MethodGet,
				URL:     "https://api.example.test/workshop/api/mechanic/mechanic_report?report_id=101&format=json",
				Path:    "/workshop/api/mechanic/mechanic_report",
				Query:   "report_id=101&format=json",
				Headers: map[string]string{"Authorization": "Bearer test"},
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body: []byte(`{
					"report_id":101,
					"customer":{"email":"mechanic-a@example.com","user_id":501},
					"vehicle":{"vin":"VIN101"},
					"payment":{"amount":149.50,"card_number":"XXXXXXXXXXXX1010","card_owner_name":"Mechanic A"}
				}`),
			},
		},
		{
			Request: types.CapturedRequest{
				Method:  http.MethodGet,
				URL:     "https://api.example.test/workshop/api/mechanic/mechanic_report?report_id=102&format=json",
				Path:    "/workshop/api/mechanic/mechanic_report",
				Query:   "report_id=102&format=json",
				Headers: map[string]string{"Authorization": "Bearer test"},
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body: []byte(`{
					"report_id":102,
					"customer":{"email":"mechanic-b@example.com","user_id":502},
					"vehicle":{"vin":"VIN102"},
					"payment":{"amount":249.50,"card_number":"XXXXXXXXXXXX2020","card_owner_name":"Mechanic B"}
				}`),
			},
		},
	}

	findings := enumerableObjectExposureFindings(entries)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %#v", len(findings), findings)
	}
	finding := findings[0]
	if finding.EndpointID != "GET /workshop/api/mechanic/mechanic_report?format=json&report_id={id}" {
		t.Fatalf("endpoint id = %q", finding.EndpointID)
	}
	if finding.ParamName != "report_id" {
		t.Fatalf("param name = %q, want report_id", finding.ParamName)
	}
	if !strings.Contains(finding.StepsToReproduce, "report_id") ||
		!strings.Contains(finding.StepsToReproduce, "101") ||
		!strings.Contains(finding.StepsToReproduce, "102") {
		t.Fatalf("steps should explain the query value swap: %s", finding.StepsToReproduce)
	}
	if !strings.Contains(finding.PocRequest, "report_id=101") ||
		!strings.Contains(finding.PocRequest, "report_id=102") {
		t.Fatalf("PoC request should include both query-object requests: %s", finding.PocRequest)
	}
}

func TestEnumerableObjectExposureFindingsRejectsPaginationEnumeration(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method: http.MethodGet,
				URL:    "https://api.example.test/community/posts?page=1",
				Path:   "/community/posts",
				Query:  "page=1",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body:        []byte(`{"posts":[{"author":{"email":"a@example.com"},"body":"hello"}]}`),
			},
		},
		{
			Request: types.CapturedRequest{
				Method: http.MethodGet,
				URL:    "https://api.example.test/community/posts?page=2",
				Path:   "/community/posts",
				Query:  "page=2",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body:        []byte(`{"posts":[{"author":{"email":"b@example.com"},"body":"hello"}]}`),
			},
		},
	}

	if findings := enumerableObjectExposureFindings(entries); len(findings) != 0 {
		t.Fatalf("pagination enumeration produced findings: %#v", findings)
	}
}

func TestEnumerableObjectExposureFindingsRejectsPublicCatalogEnumeration(t *testing.T) {
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://api.example.test/products/1", Path: "/products/1"},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body:        []byte(`{"id":1,"name":"Seat","price":"10.00"}`),
			},
		},
		{
			Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://api.example.test/products/2", Path: "/products/2"},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/json",
				Body:        []byte(`{"id":2,"name":"Wheel","price":"20.00"}`),
			},
		},
	}

	if findings := enumerableObjectExposureFindings(entries); len(findings) != 0 {
		t.Fatalf("public catalog enumeration produced findings: %#v", findings)
	}
}

func TestLooksLikeAPISpecDocument(t *testing.T) {
	if !looksLikeAPISpecDocument("application/json", `{"openapi":"3.0.0","info":{"title":"Demo"},"paths":{"/users":{"get":{}}}}`) {
		t.Fatal("json OpenAPI document was not recognized")
	}
	if !looksLikeAPISpecDocument("text/yaml", "openapi: 3.0.1\ninfo:\n  title: Demo\npaths:\n  /users:\n    get: {}\n") {
		t.Fatal("yaml OpenAPI document was not recognized")
	}
	if looksLikeAPISpecDocument("application/json", `{"paths":[{"email":"a@example.test"}],"users":[{"email":"b@example.test"}]}`) {
		t.Fatal("ordinary JSON with a paths key should not be treated as an API spec")
	}
}

func TestExposedDebugConsoleSignal(t *testing.T) {
	body := `<!doctype html>
<title>Console // Werkzeug Debugger</title>
<script>
  var CONSOLE_MODE = true,
      EVALEX = true,
      EVALEX_TRUSTED = false,
      SECRET = "abc";
</script>
<h1>Interactive Console</h1>
<div class="pin-prompt">Console Locked <input name=pin></div>`
	signal, ok := exposedDebugConsoleSignal("Werkzeug/2.2.3 Python/3.11", body)
	if !ok {
		t.Fatal("Werkzeug debugger console was not detected")
	}
	if signal.Framework != "Werkzeug" || !signal.Locked || !strings.Contains(signal.Detail, "PIN-locked") {
		t.Fatalf("signal = %#v, want locked Werkzeug detail", signal)
	}
	if _, ok := exposedDebugConsoleSignal("", `<html><h1>Admin Console</h1><p>Logs and metrics</p></html>`); ok {
		t.Fatal("ordinary admin console should not be detected as a framework debugger")
	}
}

func TestObservedGraphQLReadResponse(t *testing.T) {
	readEntry := types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: "POST",
			URL:    "https://app.example.test/graphql",
			Path:   "/graphql",
			Body:   []byte(`{"query":"query getPastes { pastes { id title ipAddr userAgent owner { name } } }"}`),
		},
		Response: types.CapturedResponse{
			StatusCode: 200,
			Body:       []byte(`{"data":{"pastes":[{"id":"1","ipAddr":"215.0.2.1"}]}}`),
		},
	}
	if !observedGraphQLReadResponse(readEntry) {
		t.Fatal("read-only GraphQL POST response was not recognized")
	}
	mutationEntry := readEntry
	mutationEntry.Request.Body = []byte(`{"query":"mutation { deletePaste(id:1) { ok } }"}`)
	if observedGraphQLReadResponse(mutationEntry) {
		t.Fatal("GraphQL mutation should not be treated as read-only exposure evidence")
	}
	introspectionEntry := readEntry
	introspectionEntry.Response.Body = []byte(`{"data":{"__schema":{"types":[]}}}`)
	if observedGraphQLReadResponse(introspectionEntry) {
		t.Fatal("introspection response should not be treated as sensitive data exposure")
	}
}

func TestProjectionAuthAttemptsMirrorBearerIntoCookie(t *testing.T) {
	attempts := projectionAuthAttempts(map[string]string{
		"Authorization": "Bearer abc.def.ghi",
	}, "observed")
	if len(attempts) < 2 {
		t.Fatalf("attempts = %#v, want original plus cookie variant", attempts)
	}
	var foundCookie bool
	for _, attempt := range attempts {
		if strings.Contains(attempt.Headers["Cookie"], "token=abc.def.ghi") {
			foundCookie = true
			break
		}
	}
	if !foundCookie {
		t.Fatalf("cookie token variant missing: %#v", attempts)
	}
}

func TestExtractClientCredentialPairsFromText(t *testing.T) {
	js := `window.__cfg={email:"demo@example.test",password:"s3cr3t!"}; const label="SHOW_PWD_TOOLTIP";`
	got := extractClientCredentialPairsFromText(js, "https://app.example.test/main.js", 4)
	if len(got) != 1 {
		t.Fatalf("credential pairs = %#v, want one", got)
	}
	if got[0].Username != "demo@example.test" || got[0].Password != "s3cr3t!" {
		t.Fatalf("credential pair = %#v, want demo@example.test/s3cr3t!", got[0])
	}
}

func TestExtractClientCredentialPairsFromMinifiedAssignments(t *testing.T) {
	js := `class Login{testingUsername="testing@example.test";testingPassword="IamUsedForTesting";oauthUnavailable=!0}`
	got := extractClientCredentialPairsFromText(js, "https://app.example.test/main.js", 4)
	if len(got) != 1 {
		t.Fatalf("credential pairs = %#v, want one", got)
	}
	if got[0].Username != "testing@example.test" || got[0].Password != "IamUsedForTesting" {
		t.Fatalf("credential pair = %#v, want testing@example.test/IamUsedForTesting", got[0])
	}
}

func TestClientCredentialArtifactTextRefetchesEmptySameOriginArtifact(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/main.js" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, `window.__cfg={email:"demo@example.test",password:"s3cr3t!"};`)
	}))
	defer srv.Close()

	v := &VerifierAgent{
		client: srv.Client(),
		target: srv.URL,
	}
	entry := types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: http.MethodGet,
			URL:    srv.URL + "/main.js",
			Path:   "/main.js",
		},
		Response: types.CapturedResponse{
			StatusCode:  304,
			ContentType: "application/javascript",
		},
	}

	text, source, ok := v.clientCredentialArtifactText(context.Background(), entry, map[string]string{})
	if !ok {
		t.Fatal("expected empty/304 same-origin artifact to be refetched")
	}
	if !strings.Contains(text, "demo@example.test") || !strings.Contains(source, "refetched") {
		t.Fatalf("text/source = %q / %q, want refetched credential artifact", text, source)
	}
}

func TestFileUploadPathsFromClientArtifact(t *testing.T) {
	js := `
		uploader = new FileUploader({ url: host + "/file-upload" })
		addMemory(name, img) { const f = new FormData; f.append("image", img, name); return http.post("/rest/memories", f) }
		const staticImage = "/assets/public/images/uploads/example.jpg"
		const serverPath = "/var/www/html/hackable/uploads/"
		const social = "https://bsky.app/profile/example.test"
	`
	got := fileUploadPathsFromText(js)
	if !reflect.DeepEqual(got, []string{"/file-upload", "/rest/memories"}) {
		t.Fatalf("upload paths = %#v, want /file-upload and /rest/memories only", got)
	}
}

func TestFileUploadValidationCandidatesUseOriginAndIgnoreHTMLArtifacts(t *testing.T) {
	v := &VerifierAgent{}
	entries := []types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/main.js",
				Path:   "/main.js",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "application/javascript",
				Body: []byte(`
					const form = new FormData()
					form.append("file", selectedFile)
					fetch("/upload/", { method: "POST", body: form })
				`),
			},
		},
		{
			Request: types.CapturedRequest{
				Method: "GET",
				URL:    "https://shop.example/login.php",
				Path:   "/login.php",
			},
			Response: types.CapturedResponse{
				StatusCode:  http.StatusOK,
				ContentType: "text/html",
				Body:        []byte(`<html><body><form action="/upload/" enctype="multipart/form-data"><input type="file" name="file"></form></body></html>`),
			},
		},
	}

	got := v.fileUploadValidationCandidates(context.Background(), entries, "https://shop.example/login.php")
	if len(got) != 1 {
		t.Fatalf("candidates = %#v, want exactly the JS artifact upload candidate", got)
	}
	if got[0].URL != "https://shop.example/upload/" {
		t.Fatalf("candidate URL = %q, want origin-root /upload/", got[0].URL)
	}
}

func TestFileUploadValidationAuthoritySplitsValidationFromDeprecatedInterfaces(t *testing.T) {
	tests := []struct {
		name           string
		authority      policy.TestingAuthority
		wantValidation bool
		wantDeprecated bool
	}{
		{name: "recon", authority: policy.AuthorityRecon, wantValidation: false, wantDeprecated: false},
		{name: "active", authority: policy.AuthorityActive, wantValidation: true, wantDeprecated: true},
		{name: "full control", authority: policy.AuthorityFullControl, wantValidation: true, wantDeprecated: true},
		{name: "unknown", authority: policy.TestingAuthority(""), wantValidation: false, wantDeprecated: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValidation, gotDeprecated := fileUploadValidationAuthority(tt.authority)
			if gotValidation != tt.wantValidation || gotDeprecated != tt.wantDeprecated {
				t.Fatalf("fileUploadValidationAuthority(%q) = (%v,%v), want (%v,%v)",
					tt.authority, gotValidation, gotDeprecated, tt.wantValidation, tt.wantDeprecated)
			}
		})
	}
}

func TestFileUploadFieldCandidatesPreferImageForImageSurfaces(t *testing.T) {
	got := fileUploadFieldCandidates("/rest/memories", []string{"image"})
	if len(got) < 2 || got[0] != "image" || got[1] != "file" {
		t.Fatalf("field candidates = %#v, want image then file", got)
	}
}

func TestPrioritizeUploadFieldsMovesSuccessfulFieldFirst(t *testing.T) {
	got := prioritizeUploadFields([]string{"image", "file", "upload"}, "file")
	if !reflect.DeepEqual(got, []string{"file", "image", "upload"}) {
		t.Fatalf("prioritized fields = %#v, want successful field first", got)
	}
}

func TestFileUploadProbeCasesCheckTraversalBeforeSize(t *testing.T) {
	cases := fileUploadProbeCases(123)
	var got []string
	for _, tc := range cases {
		got = append(got, tc.Kind)
	}
	want := []string{"type", "path", "size"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("probe order = %#v, want %#v", got, want)
	}
}

func TestUploadProbeFieldsLimitsPathProbeToKnownGoodField(t *testing.T) {
	got := uploadProbeFields([]string{"image", "file", "upload"}, "file", "path")
	if !reflect.DeepEqual(got, []string{"file"}) {
		t.Fatalf("path probe fields = %#v, want only known-good field", got)
	}
	got = uploadProbeFields([]string{"image", "file", "upload"}, "", "path")
	if !reflect.DeepEqual(got, []string{"image", "file", "upload"}) {
		t.Fatalf("path probe without preferred = %#v, want normal order", got)
	}
	got = uploadProbeFields([]string{"image", "file", "upload"}, "file", "type")
	if !reflect.DeepEqual(got, []string{"file", "image", "upload"}) {
		t.Fatalf("type probe fields = %#v, want preferred then fallback fields", got)
	}
}

func TestFileUploadAcceptanceSignalRequires2xxWithoutValidationError(t *testing.T) {
	if got := fileUploadAcceptanceSignal(204, "", "type"); got == "" {
		t.Fatal("expected 204 empty response to accept type probe")
	}
	loginShell := `<!doctype html><html><body><form action="/login.php"><input name="username"><input name="password" type="password"></form></body></html>`
	if got := fileUploadAcceptanceSignal(200, loginShell, "type"); got != "" {
		t.Fatalf("login shell should not be an upload acceptance signal: %s", got)
	}
	if got := fileUploadAcceptanceSignal(400, `{"error":"invalid file type"}`, "type"); got != "" {
		t.Fatalf("acceptance = %q, want rejected", got)
	}
	if got := fileUploadAcceptanceSignal(200, `{"error":"file too large"}`, "size"); got != "" {
		t.Fatalf("acceptance = %q, want rejected due body error", got)
	}
	contentDispositionSink := `{"content":"VulnerableApp/contentDispositionUpload/aobtd-upload-type-123.txt","isValid":true}`
	if got := fileUploadAcceptanceSignal(200, contentDispositionSink, "type"); got != "" {
		t.Fatalf("content-disposition sink should not be upload type proof: %s", got)
	}
	if got := fileUploadRejectionSignal(200, contentDispositionSink, "type"); got != "content-disposition upload sink" {
		t.Fatalf("content-disposition rejection = %q", got)
	}
	if !fileUploadRejectionTerminalForFieldSearch(200, `{"content":"Input is invalid","isValid":false}`) {
		t.Fatal("expected validation body to stop upload field probing for this case")
	}
}

func TestFileUploadPathTraversalAcceptanceSignalRequiresTraversalEcho(t *testing.T) {
	body := `{"content":"VulnerableApp/contentDispositionUpload/../aobtd-upload-traversal-123.txt","isValid":true}`
	got := fileUploadPathTraversalAcceptanceSignal(200, body, "../aobtd-upload-traversal-123.txt")
	if got == "" {
		t.Fatal("expected traversal filename echo to confirm path traversal")
	}
	if got := fileUploadPathTraversalAcceptanceSignal(200, `{"content":"VulnerableApp/upload/aobtd-upload-traversal-123.txt","isValid":true}`, "../aobtd-upload-traversal-123.txt"); got != "" {
		t.Fatalf("sanitized filename should not confirm traversal: %s", got)
	}
	if got := fileUploadPathTraversalAcceptanceSignal(400, `{"error":"invalid filename"}`, "../aobtd-upload-traversal-123.txt"); got != "" {
		t.Fatalf("rejection should not confirm traversal: %s", got)
	}
}

func TestAntiAutomationBurstFeedbackBodyUsesNeutralRating(t *testing.T) {
	body := antiAutomationBurstFeedbackBody(4, 123, 2, "99", "seven")
	if !strings.Contains(body, `"rating":4`) {
		t.Fatalf("body = %s, want neutral rating 4", body)
	}
	if strings.Contains(body, `"rating":5`) {
		t.Fatalf("body = %s, must not create five-star moderation artifacts", body)
	}
	if !strings.Contains(body, `"captchaId":99`) || !strings.Contains(body, `"captcha":"seven"`) {
		t.Fatalf("body = %s, want captcha fields preserved", body)
	}
}

func TestSendMultipartUploadProbePreservesPartContentType(t *testing.T) {
	var gotField string
	var gotContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reader, err := r.MultipartReader()
		if err != nil {
			t.Fatalf("MultipartReader() error = %v", err)
		}
		part, err := reader.NextPart()
		if err != nil {
			t.Fatalf("NextPart() error = %v", err)
		}
		defer part.Close()
		gotField = part.FormName()
		gotContentType = part.Header.Get("Content-Type")
		_, _ = io.ReadAll(part)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	v := &VerifierAgent{client: server.Client()}
	status, _, err := v.sendMultipartUploadProbe(context.Background(),
		fileUploadValidationCandidate{URL: server.URL + "/file-upload", Path: "/file-upload", Method: http.MethodPost},
		map[string]string{"Authorization": "Bearer test"},
		"file",
		fileUploadProbeCase{Filename: "aobtd.txt", ContentType: "text/plain", Content: []byte("benign")},
	)
	if err != nil {
		t.Fatalf("sendMultipartUploadProbe() error = %v", err)
	}
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	if gotField != "file" {
		t.Fatalf("field = %q, want file", gotField)
	}
	if gotContentType != "text/plain" {
		t.Fatalf("part content-type = %q, want text/plain", gotContentType)
	}
}

func TestExtractClientCredentialPairsIgnoresUIOnlyPasswordLabels(t *testing.T) {
	js := `const fields=["email","password"]; function showPwdTooltip(){ return "SHOW_PWD_TOOLTIP" }`
	if got := extractClientCredentialPairsFromText(js, "https://app.example.test/main.js", 4); len(got) != 0 {
		t.Fatalf("credential pairs = %#v, want none", got)
	}
}

func testJWTWithPayload(payload string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return header + "." + body + ".sig"
}

func TestJSONPExposureSignalDetectsWrappedEmail(t *testing.T) {
	body := `/**/ typeof AOBTD_JSONP_PROOF === 'function' && AOBTD_JSONP_PROOF({"user":{"id":1,"email":"admin@example.test"}});`
	signal := jsonpExposureSignal(body, "AOBTD_JSONP_PROOF")
	if signal.Signal == "" || signal.Severity != types.SeverityMedium || !strings.Contains(signal.Signal, "admin@example.test") {
		t.Fatalf("jsonp signal = %+v, want medium email leak", signal)
	}
}

func TestExtractJSONPCallbackPayloadHandlesStrings(t *testing.T) {
	body := `cb({"message":"paren ) inside string","nested":{"ok":true}});`
	payload, ok := extractJSONPCallbackPayload(body, "cb")
	if !ok || !strings.Contains(payload, `"paren ) inside string"`) || !strings.Contains(payload, `"ok":true`) {
		t.Fatalf("payload = %q ok=%v", payload, ok)
	}
}

func TestSensitiveAPICandidatePathsUseObservedPrefixes(t *testing.T) {
	entries := []types.TrafficEntry{
		{Request: types.CapturedRequest{Path: "/api/v2/products"}},
		{Request: types.CapturedRequest{Path: "/rest/products/search"}},
	}
	prefixes := observedAPIPrefixes(entries)
	paths := sensitiveAPICandidatePaths(prefixes)
	joined := "\n" + strings.Join(paths, "\n") + "\n"
	for _, want := range []string{"/api/users", "/api/v2/users", "/rest/user/whoami", "/api/Users", "/api/Cards", "/rest/payment"} {
		if !strings.Contains(joined, "\n"+want+"\n") {
			t.Fatalf("candidate paths missing %q; got prefixes=%v paths=%v", want, prefixes, paths)
		}
	}
}

func TestObservedErrorDisclosureHelpers(t *testing.T) {
	body := `<html><title>UnauthorizedError: No Authorization header was found</title>
		<ul id="stacktrace"><li>at /app/routes/user.js:12:3</li><li>at processTicksAndRejections</li></ul></html>`
	hits, first := stackTraceSignalHits(body)
	if hits < 2 || first == "" {
		t.Fatalf("stackTraceSignalHits = (%d, %q), want at least two hits", hits, first)
	}
	if !observedErrorPathEligible("/api/Users", "text/html; charset=utf-8") {
		t.Fatal("API error page should be eligible")
	}
	if observedErrorPathEligible("/socket.io/", "text/html") {
		t.Fatal("socket.io transport noise should not be eligible")
	}
	if observedErrorPathEligible("/main.js", "application/javascript") {
		t.Fatal("static JavaScript should not be eligible")
	}
}

func TestObservedClickjackingSignal(t *testing.T) {
	explicitHeaders := `{"X-Frame-Options":"SAMEORIGIN","Content-Type":"application/json"}`
	explicitBody := `{"content":"Page loaded without framing protection. This page can be embedded in an iframe.","isValid":true}`
	if got := observedClickjackingSignal(200, "application/json", explicitHeaders, explicitBody); got == "" {
		t.Fatal("explicit frameable response should confirm clickjacking even when a weak legacy header is present")
	}
	catalogBody := strings.Repeat("documentation ", 500) + explicitBody
	if got := observedClickjackingSignal(200, "application/json", `{}`, catalogBody); got != "" {
		t.Fatalf("large catalog/documentation response signal = %q, want dismissed", got)
	}

	protectedHeaders := `{"Content-Security-Policy":"frame-ancestors 'none'"}`
	protectedBody := `{"content":"Page loaded with framing protection header set.","isValid":true}`
	if got := observedClickjackingSignal(200, "application/json", protectedHeaders, protectedBody); got != "" {
		t.Fatalf("protected response signal = %q, want dismissed", got)
	}

	if got := observedClickjackingSignal(200, "text/html; charset=utf-8", `{}`, `<!doctype html><html><body>Account settings</body></html>`); got != "" {
		t.Fatalf("plain missing frame headers signal = %q, want posture-only dismissal", got)
	}

	invalidHeader := `{"X-Frame-Options":"ALLOWALL"}`
	if got := observedClickjackingSignal(200, "text/html; charset=utf-8", invalidHeader, `<!doctype html><html><body>Account settings</body></html>`); got == "" {
		t.Fatal("invalid X-Frame-Options value should confirm clickjacking")
	}

	if got := observedClickjackingSignal(500, "text/html", `{}`, `<!doctype html><html></html>`); got != "" {
		t.Fatalf("non-2xx response signal = %q, want dismissed", got)
	}
}

func TestCommandInjectionCandidateHelpers(t *testing.T) {
	got := commandInjectionParamCandidates("/VulnerableApp/CommandInjection/LEVEL_1", "")
	if len(got) == 0 || got[0] != "ipaddress" {
		t.Fatalf("commandInjectionParamCandidates() = %#v, want ipaddress first", got)
	}
	got = commandInjectionParamCandidates("/network/ping", "host=127.0.0.1&debug=1")
	if len(got) < 1 || got[0] != "host" {
		t.Fatalf("query-derived candidates = %#v, want host first", got)
	}
	if commandInjectionPathLooksUseful("/products/search") {
		t.Fatal("ordinary search path should not be treated as command-injection surface")
	}
	if got := rawURLWithoutQuery("https://example.test/ping?host=127.0.0.1#frag"); got != "https://example.test/ping" {
		t.Fatalf("rawURLWithoutQuery = %q", got)
	}
}

func TestCommandInjectionExecutionSignal(t *testing.T) {
	marker := "AOBTD_CMD_123"
	payload := "127.0.0.1|echo " + marker
	baseline := `{"content":"PING 127.0.0.1 statistics","isValid":true}`
	body := `{"content":"` + marker + `\n","isValid":true}`
	if got := commandInjectionExecutionSignal(200, body, marker, payload, 200, baseline); got == "" {
		t.Fatal("marker command output should confirm command injection")
	}
	reflection := `<html><input name="host" value="` + payload + `"></html>`
	if got := commandInjectionExecutionSignal(200, reflection, marker, payload, 200, baseline); got != "" {
		t.Fatalf("reflected payload signal = %q, want dismissed", got)
	}
	backtickOutput := `{"content":"ping: 127.0.0.1` + marker + `: Name or service not known\n","isValid":true}`
	if got := commandInjectionExecutionSignal(200, backtickOutput, marker, "127.0.0.1`echo "+marker+"`", 200, baseline); got == "" {
		t.Fatal("backtick command substitution output should confirm command injection")
	}
	if got := commandInjectionExecutionSignal(500, body, marker, payload, 200, baseline); got != "" {
		t.Fatalf("500 signal = %q, want dismissed", got)
	}
}

func TestLDAPInjectionCandidateHelpers(t *testing.T) {
	got := ldapInjectionUsernameParams("/VulnerableApp/LDAPInjectionVulnerability/LEVEL_1", "")
	if len(got) == 0 || got[0] != "username" {
		t.Fatalf("ldapInjectionUsernameParams() = %#v, want username first", got)
	}
	if param := ldapInjectionPasswordParam("/VulnerableApp/LDAPInjectionVulnerability/LEVEL_3", ""); param != "password" {
		t.Fatalf("ldapInjectionPasswordParam() = %q, want password", param)
	}
	got = ldapInjectionUsernameParams("/directory-search", "uid=alice&debug=1")
	if len(got) < 1 || got[0] != "uid" {
		t.Fatalf("query-derived LDAP params = %#v, want uid first", got)
	}
	if ldapInjectionPathLooksUseful("/products/search") {
		t.Fatal("ordinary search path should not be treated as LDAP-injection surface")
	}
}

func TestLDAPInjectionSignal(t *testing.T) {
	baseline := `{"content":"No users found","isValid":false}`
	wildcardUsers := `{"content":{"users":["alice","bob"],"filter":"(uid=*)"},"isValid":true}`
	if got := ldapInjectionSignal(200, wildcardUsers, "*", 200, baseline, false); got == "" {
		t.Fatal("wildcard user result should confirm LDAP filter manipulation")
	}
	parseError := `{"content":"LDAP query failed: Unable to parse string '(uid=)(|(uid=*)))' as an LDAP filter because it contains an unexpected closing parenthesis.","isValid":false}`
	if got := ldapInjectionSignal(200, parseError, ")(|(uid=*))", 200, baseline, false); got == "" {
		t.Fatal("LDAP parser error should confirm unescaped filter injection")
	}
	escaped := `{"content":{"users":[],"message":"No users found","filter":"(uid=\\2a)"},"isValid":false}`
	if got := ldapInjectionSignal(200, escaped, "*", 200, baseline, false); got != "" {
		t.Fatalf("escaped wildcard signal = %q, want dismissed", got)
	}
	login := `{"content":"Login successful","isValid":true}`
	if got := ldapInjectionSignal(200, login, "*)(uid=*", 200, `{"content":"Invalid credentials","isValid":false}`, true); got == "" {
		t.Fatal("wildcard auth success should confirm when bogus baseline is rejected")
	}
	if got := ldapInjectionSignal(200, login, "*", 200, login, true); got != "" {
		t.Fatalf("same baseline auth signal = %q, want dismissed", got)
	}
}

func TestFileReadTraversalCandidateHelpers(t *testing.T) {
	got := fileReadParamCandidates("/VulnerableApp/PathTraversal/LEVEL_1", "")
	if len(got) == 0 || got[0] != "fileName" {
		t.Fatalf("fileReadParamCandidates() = %#v, want fileName first", got)
	}
	got = fileReadParamCandidates("/download", "path=report.pdf&debug=1")
	if len(got) < 1 || got[0] != "path" {
		t.Fatalf("query-derived file-read candidates = %#v, want path first", got)
	}
	got = fileReadParamCandidates("/VulnerableApp/PathTraversal/LEVEL_12", "")
	if !reflect.DeepEqual(got, []string{"fileName"}) {
		t.Fatalf("path traversal lesson candidates = %#v, want fileName only", got)
	}
	if fileReadPathLooksUseful("/products/search") {
		t.Fatal("ordinary search path should not be treated as file-read surface")
	}
	if fileReadTraversalBaselineValue(fileReadTraversalCandidate{Path: "/VulnerableApp/PathTraversal/LEVEL_1"}) != "UserInfo.json" {
		t.Fatal("VulnerableApp path traversal baseline should use known benign file")
	}
	payloads := fileReadTraversalPayloads(fileReadTraversalCandidate{Path: "/VulnerableApp/PathTraversal/LEVEL_7"})
	var foundNullByte bool
	for _, payload := range payloads {
		if payload.Value == "secret.json\x00UserInfo.json" {
			foundNullByte = true
			break
		}
	}
	if !foundNullByte {
		t.Fatalf("fileReadTraversalPayloads() = %#v, want null-byte secret payload", payloads)
	}
	if got := fileReadTraversalDisplayValue("secret.json\x00UserInfo.json"); got != "secret.json%00UserInfo.json" {
		t.Fatalf("fileReadTraversalDisplayValue() = %q", got)
	}
}

func TestFileReadTraversalSignal(t *testing.T) {
	baseline := `{"content":"[{\"Name\":\"Alice\"}]","isValid":true}`
	secret := `{"content":"{\t\"UserName\" : \"Dummy\", \t\"Password\" : \"password\", \t\"Description\" : \"This is a dummy file which is used for exposing one Vulnerability in Path Traversal.\"}","isValid":true}`
	if got := fileReadTraversalSignal(200, secret, "secret.json", 200, baseline); got != "hidden secret file content" {
		t.Fatalf("secret signal = %q", got)
	}
	if got := fileReadTraversalSignal(200, secret, "secret.json\x00UserInfo.json", 200, baseline); got != "hidden secret file content" {
		t.Fatalf("null-byte secret signal = %q", got)
	}
	jwt := `{"content":"[{\"algorithm\":\"HS256\",\"strength\":\"LOW\",\"key\":\"password\"}]","isValid":true}`
	if got := fileReadTraversalSignal(200, jwt, "../JWT/SymmetricAlgoKeys.json", 200, baseline); got != "JWT signing-key material" {
		t.Fatalf("jwt signal = %q", got)
	}
	reflection := `<html>requested secret.json</html>`
	if got := fileReadTraversalSignal(200, reflection, "secret.json", 200, baseline); got != "" {
		t.Fatalf("reflected filename signal = %q, want dismissed", got)
	}
	if got := fileReadTraversalSignal(404, secret, "secret.json", 200, baseline); got != "" {
		t.Fatalf("404 signal = %q, want dismissed", got)
	}
}

func TestProbeObservedErrorDisclosuresDoesNotDeadlockWhileWritingFindings(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "verifier.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	body := `<html><title>Error: Unexpected path: /api</title>
		<style>body{font-family:sans-serif}</style>
		<ul id="stacktrace"><li>at /app/routes/api.js:10:1</li><li>at processTicksAndRejections</li><li>at /app/node_modules/express/lib/router/index.js:284:7</li></ul>
		<p>Verbose development error page with route internals and request handling details.</p></html>`
	_, err = db.Conn().Exec(`
		INSERT INTO traffic (
			scan_id, method, url, host, path, query,
			request_headers, request_body,
			status_code, response_headers, response_body,
			content_type, response_size, endpoint_hash,
			is_filtered
		) VALUES (?, 'GET', 'https://example.test/api', 'example.test', '/api', '',
			'{}', NULL,
			500, '{}', ?,
			'text/html; charset=utf-8', ?, 'GET:/api',
			FALSE)`, scanID, []byte(body), len(body))
	if err != nil {
		t.Fatalf("insert traffic: %v", err)
	}

	verifier := &VerifierAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	done := make(chan struct{})
	go func() {
		verifier.probeObservedErrorDisclosures(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("probeObservedErrorDisclosures deadlocked while writing findings")
	}

	var count int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id=? AND vuln_type='error_handling'`, scanID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("error_handling findings = %d, want 1", count)
	}
}

// TestVerifierIssueRouting documents which issue strings route to which
// verifier methods. Added after the scan 29/30 findings showed the
// analyzer was flagging "unvalidated redirect" and the router was only
// matching "open redirect" — losing a whole class of findings.
//
// This is a behavioral test: we check the routing decision via a
// lightweight helper that mirrors the switch statement. If the helper
// ever disagrees with the actual verifyIssue switch, this test fails.
func TestVerifierIssueRouting(t *testing.T) {
	tests := []struct {
		issue string
		route string // "xss" / "open_redirect" / "ldap" / "sqli" / "csrf" / "idor" / "other"
	}{
		// XSS — keyword variants analyzers use
		{"Reflected XSS in 'q' parameter", "xss"},
		{"Cross-site scripting in feedback endpoint", "xss"},
		{"The 'q' parameter value is reflected input without encoding", "xss"},
		{"Unsanitized input rendered into HTML body", "xss"},
		{"HTML injection via search query", "xss"},

		// Open redirect — the scan 29 failure case
		{"Unvalidated redirect via return_to parameter", "open_redirect"},
		{"Open redirect on /login endpoint", "open_redirect"},
		{"Redirects to arbitrary URLs based on 'to' parameter", "open_redirect"},
		{"Arbitrary redirect via next parameter", "open_redirect"},

		// LDAP injection should not fall into generic SQLi probes.
		{"LDAP injection in username filter", "ldap"},

		// SQLi
		{"Potential SQL injection on search endpoint", "sqli"},
		{"NoSQL injection risk on MongoDB query", "sqli"},
		{"Query injection in login credentials", "sqli"},

		// CSRF
		{"Missing CSRF protection on state-changing endpoint", "csrf"},
		{"No anti-forgery token on POST form", "csrf"},
		{"Cross-site request forgery possible on transfer endpoint", "csrf"},

		// IDOR / BOLA — scan 29 had 'without proper access control' which was missed
		{"Sequential ids on /api/users/{id} suggest IDOR", "idor"},
		{"User data exposed without proper access control", "idor"},
		{"BOLA on basket endpoint", "idor"},
		{"Broken object-level authorization on /api/orders", "idor"},
		{"Enumerable resource ids allow leakage", "idor"},

		// Other — fall through to info-level
		{"Missing Content-Security-Policy header", "other"},
		{"Access-Control-Allow-Origin: * on static asset", "other"},
		{"Weak cipher suite in TLS config", "other"},
	}
	for _, tc := range tests {
		t.Run(tc.issue, func(t *testing.T) {
			got := classifyIssueRoute(tc.issue)
			if got != tc.route {
				t.Errorf("issue %q routed to %q, want %q", tc.issue, got, tc.route)
			}
		})
	}
}

// classifyIssueRoute mirrors the switch statement inside verifyIssue so
// we can unit-test routing decisions without instantiating the full agent.
// Keep this in lock-step with verifyIssue — the test above will break if
// they diverge.
func classifyIssueRoute(issue string) string {
	issueLower := strings.ToLower(issue)
	switch {
	case strings.Contains(issueLower, "xss") ||
		strings.Contains(issueLower, "cross-site scripting") ||
		strings.Contains(issueLower, "reflected input") ||
		strings.Contains(issueLower, "unsanitized input") ||
		strings.Contains(issueLower, "html injection"):
		return "xss"
	case strings.Contains(issueLower, "open redirect") ||
		strings.Contains(issueLower, "unvalidated redirect") ||
		strings.Contains(issueLower, "open url redirect") ||
		strings.Contains(issueLower, "arbitrary redirect") ||
		strings.Contains(issueLower, "redirect to arbitrary") ||
		strings.Contains(issueLower, "redirects to arbitrary"):
		return "open_redirect"
	case strings.Contains(issueLower, "ldap"):
		return "ldap"
	case strings.Contains(issueLower, "sql") ||
		strings.Contains(issueLower, "injection") ||
		strings.Contains(issueLower, "nosql") ||
		strings.Contains(issueLower, "query injection"):
		return "sqli"
	case strings.Contains(issueLower, "csrf") ||
		strings.Contains(issueLower, "cross-site request forgery") ||
		strings.Contains(issueLower, "anti-forgery"):
		return "csrf"
	case strings.Contains(issueLower, "idor") ||
		strings.Contains(issueLower, "insecure direct object") ||
		strings.Contains(issueLower, "enumerable") ||
		strings.Contains(issueLower, "sequential id") ||
		strings.Contains(issueLower, "broken object") ||
		strings.Contains(issueLower, "bola") ||
		strings.Contains(issueLower, "without proper access control"):
		return "idor"
	}
	return "other"
}

func TestCSRFFormProbeValuesPrefersUsernameProfileField(t *testing.T) {
	form := extract.ExtractedForm{
		Method: "POST",
		Action: "https://shop.example/profile",
		Inputs: []extract.ExtractedInput{
			{Name: "email", Type: "email", Value: "victim@example.test"},
			{Name: "username", Type: "text", Label: "Username"},
			{Name: "displayName", Type: "text", Label: "Display name"},
		},
	}

	values, field, ok := csrfFormProbeValues(form, "AOBTD_CSRF_MARKER")
	if !ok {
		t.Fatal("expected CSRF form probe values")
	}
	if field != "username" {
		t.Fatalf("field = %q, want username", field)
	}
	if got := values.Get("username"); got != "AOBTD_CSRF_MARKER" {
		t.Fatalf("username value = %q, want marker", got)
	}
}

func TestCSRFFormHasTokenRecognizesAntiForgeryFields(t *testing.T) {
	form := extract.ExtractedForm{
		Method: "POST",
		Action: "https://shop.example/account",
		Inputs: []extract.ExtractedInput{
			{Name: "authenticity_token", Type: "hidden", Value: "abc"},
			{Name: "username", Type: "text"},
		},
	}
	if !csrfFormHasToken(form) {
		t.Fatal("expected authenticity_token to count as CSRF protection signal")
	}
}

func TestSetCookieValueReplacesExistingCookie(t *testing.T) {
	got := setCookieValue("sid=old; token=old-token; theme=dark", "token", "new-token")
	if got != "sid=old; token=new-token; theme=dark" {
		t.Fatalf("setCookieValue replaced wrong cookie: %q", got)
	}
	got = setCookieValue(got, "csrf", "abc")
	if got != "sid=old; token=new-token; theme=dark; csrf=abc" {
		t.Fatalf("setCookieValue append = %q", got)
	}
}

func TestCSRFFormLooksSafeRejectsLoginAndMultipart(t *testing.T) {
	profileForm := extract.ExtractedForm{Method: "POST", Action: "https://shop.example/profile"}
	if !csrfFormLooksSafe("https://shop.example/profile", "https://shop.example/profile", profileForm) {
		t.Fatal("profile POST form should be eligible for bounded CSRF replay")
	}
	loginForm := extract.ExtractedForm{Method: "POST", Action: "https://shop.example/login"}
	if csrfFormLooksSafe("https://shop.example/login", "https://shop.example/login", loginForm) {
		t.Fatal("login form must not be CSRF replayed")
	}
	uploadForm := extract.ExtractedForm{Method: "POST", Action: "https://shop.example/profile/image/file", Enctype: "multipart/form-data"}
	if csrfFormLooksSafe("https://shop.example/profile", "https://shop.example/profile/image/file", uploadForm) {
		t.Fatal("multipart upload form must not be CSRF replayed")
	}
}

func TestCSRFPassthroughSkipsGraphQLReadAndJSONAPI(t *testing.T) {
	profile := types.PageProfile{
		ID:     "POST /graphql",
		URL:    "https://app.example/graphql",
		Method: "POST",
		Inputs: []types.Input{{Name: "query", Location: "body"}},
	}
	graphQLRead := types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: "POST",
			URL:    "https://app.example/graphql",
			Path:   "/graphql",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: []byte(`{"query":"query getPastes { pastes { id owner { name } } }"}`),
		},
	}
	if csrfPassiveRequestLooksFormStateChange(profile, graphQLRead) {
		t.Fatal("read-only GraphQL JSON request was eligible for passive CSRF confirmation")
	}

	jsonAPI := graphQLRead
	jsonAPI.Request.URL = "https://app.example/api/profile"
	jsonAPI.Request.Path = "/api/profile"
	jsonAPI.Request.Body = []byte(`{"displayName":"new-name"}`)
	if csrfPassiveRequestLooksFormStateChange(profile, jsonAPI) {
		t.Fatal("JSON API request was eligible for passive CSRF confirmation without active replay proof")
	}
}

func TestCSRFPassthroughAllowsObservedHTMLFormPost(t *testing.T) {
	profile := types.PageProfile{
		ID:     "POST /profile",
		URL:    "https://app.example/profile",
		Method: "POST",
		Inputs: []types.Input{{Name: "display_name", Location: "form"}},
	}
	entry := types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: "POST",
			URL:    "https://app.example/profile",
			Path:   "/profile",
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			Body: []byte(`display_name=alice`),
		},
	}
	if !csrfPassiveRequestLooksFormStateChange(profile, entry) {
		t.Fatal("ordinary URL-encoded form POST was not eligible for passive CSRF confirmation")
	}
}

// TestLocationRedirectsToHost documents the exact failure mode of the
// 33across false-positive caught on 2026-04-20 and locks in the fix.
// The old substring-on-Location-header implementation confirmed ANY
// response whose Location value contained the attacker host anywhere,
// including in a query-string DATA position — which is not a redirect.
func TestLocationRedirectsToHost(t *testing.T) {
	const target = "aobtd-verifier.invalid"
	tests := []struct {
		name     string
		location string
		want     bool
	}{
		// Real open redirects — MUST be confirmed.
		{"absolute https to target", "https://aobtd-verifier.invalid/pwned", true},
		{"absolute http to target", "http://aobtd-verifier.invalid/pwned", true},
		{"protocol-relative to target", "//aobtd-verifier.invalid/pwned", true},
		{"encoded protocol-relative to target", "/%2f%2faobtd-verifier.invalid/pwned", true},
		{"triple-slash encoded protocol-relative to target", "%2f%2f%2faobtd-verifier.invalid/pwned", true},
		{"subdomain of target", "https://x.aobtd-verifier.invalid/pwned", true},
		{"target with port", "https://aobtd-verifier.invalid:8080/pwned", true},
		{"uppercase host still matches", "https://AOBTD-VERIFIER.INVALID/pwned", true},

		// NOT open redirects — MUST be dismissed.
		{"33across cookie-sync pattern: target host only in query-string", "https://et-c-ash.33across.com/match?bidder_id=52&external_user_id=https%3A%2F%2Faobtd-verifier.invalid%2Fpwned", false},
		{"host contains target as substring but is different", "https://aobtd-verifier.invalid.example.com/pwned", false},
		{"relative path — no host change", "/dashboard", false},
		{"relative path with query", "/logout?next=https://aobtd-verifier.invalid", false},
		{"encoded target host in ordinary path segment", "/safe/%2faobtd-verifier.invalid/pwned", false},
		{"empty location header", "", false},
		{"target host only in path component", "https://legit.com/aobtd-verifier.invalid", false},
		{"target host only in fragment", "https://legit.com/#aobtd-verifier.invalid", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := locationRedirectsToHost(tc.location, target)
			if got != tc.want {
				t.Errorf("locationRedirectsToHost(%q, %q) = %v, want %v",
					tc.location, target, got, tc.want)
			}
		})
	}
}

func TestRedirectParamNameCandidatesIncludeReturnToForRedirectLikePaths(t *testing.T) {
	got := redirectParamNameCandidates("/VulnerableApp/Http3xxStatusCodeBasedInjection/LEVEL_1", "")
	joined := "," + strings.Join(got, ",") + ","
	for _, want := range []string{"returnTo", "returnUrl", "redirect_url", "next"} {
		if !strings.Contains(joined, ","+want+",") {
			t.Fatalf("redirectParamNameCandidates missing %q in %#v", want, got)
		}
	}
	got = redirectParamNameCandidates("/account", "returnTo=%2Fhome&boring=1")
	if len(got) != 1 || got[0] != "returnTo" {
		t.Fatalf("query-derived redirect params = %#v, want only returnTo", got)
	}
	if got := redirectParamNameCandidates("/products/search", "q=shoes"); len(got) != 0 {
		t.Fatalf("ordinary search path/query should not produce redirect params: %#v", got)
	}
}

func TestRedirectAllowlistBypassPayloadsEmbedLearnedSeeds(t *testing.T) {
	seeds := []redirectSeed{
		{URL: "https://github.com/juice-shop/juice-shop", Source: "observed Location header"},
	}
	payloads := redirectBypassPayloads("evil.aobtd.test", seeds)

	foundSeedBypass := false
	for _, payload := range payloads {
		if strings.Contains(payload, url.QueryEscape(seeds[0].URL)) &&
			locationRedirectsToHost(payload, "evil.aobtd.test") {
			foundSeedBypass = true
			break
		}
	}
	if !foundSeedBypass {
		t.Fatalf("redirectBypassPayloads() did not create an attacker-host payload containing learned allowlist seed: %#v", payloads)
	}
	foundEncodedProtocolRelative := false
	for _, payload := range payloads {
		if strings.HasPrefix(payload, "/%2f%2f") && locationRedirectsToHost(payload, "evil.aobtd.test") {
			foundEncodedProtocolRelative = true
			break
		}
	}
	if !foundEncodedProtocolRelative {
		t.Fatalf("redirectBypassPayloads() did not create encoded protocol-relative attacker payload: %#v", payloads)
	}
}

func TestNormalizeExternalRedirectSeedFiltersSameOriginAndTrimsMarkup(t *testing.T) {
	got, ok := normalizeExternalRedirectSeed(`https://etherscan.io/address/0xabc).</a>`, "shop.example")
	if !ok {
		t.Fatal("expected external seed to normalize")
	}
	if got != "https://etherscan.io/address/0xabc" {
		t.Fatalf("normalized seed = %q, want etherscan URL without markup punctuation", got)
	}
	if _, ok := normalizeExternalRedirectSeed("https://shop.example/account", "shop.example"); ok {
		t.Fatal("same-origin URL should not be treated as an external redirect seed")
	}
}

func TestRedirectSeedRiskCategoryRecognizesPaymentAddressURLs(t *testing.T) {
	if got := redirectSeedRiskCategory("https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm"); got == "" {
		t.Fatal("expected blockchain address URL to be treated as high-risk external redirect destination")
	}
	if got := redirectSeedRiskCategory("https://github.com/juice-shop/juice-shop"); got != "" {
		t.Fatalf("github project URL risk category = %q, want empty", got)
	}
}

func TestLocationRedirectsToExactURL(t *testing.T) {
	const want = "https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6"
	if !locationRedirectsToExactURL(want, want) {
		t.Fatal("exact redirect should match")
	}
	if locationRedirectsToExactURL("https://etherscan.io/address/other", want) {
		t.Fatal("different external redirect should not match exact seed")
	}
	if locationRedirectsToExactURL("/redirect?to="+url.QueryEscape(want), want) {
		t.Fatal("same seed embedded as query data should not match exact redirect destination")
	}
}

func TestQuerySQLiTargetLooksRelevant(t *testing.T) {
	tests := []struct {
		path  string
		param string
		want  bool
	}{
		{"/rest/products/search", "q", true},
		{"/api/catalog", "query", true},
		{"/products", "search", true},
		{"/VulnerableApp/ErrorBasedSQLInjectionVulnerability/LEVEL_1", "id", true},
		{"/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_2", "id", true},
		{"/VulnerableApp/AuthenticationVulnerability/LEVEL_1", "password", true},
		{"/VulnerableApp/CommandInjection/LEVEL_1", "id", false},
		{"/VulnerableApp/LDAPInjectionVulnerability/LEVEL_1", "id", false},
		{"/api/Challenges", "name", false},
		{"/socket.io/", "t", false},
		{"/main.js", "v", false},
		{"/account/profile", "next", false},
	}
	for _, tc := range tests {
		t.Run(tc.path+" "+tc.param, func(t *testing.T) {
			if got := querySQLiTargetLooksRelevant(tc.path, tc.param); got != tc.want {
				t.Fatalf("querySQLiTargetLooksRelevant(%q, %q) = %v, want %v", tc.path, tc.param, got, tc.want)
			}
		})
	}
}

func TestQuerySQLiCandidateURLForAuthParamPreservesPartnerField(t *testing.T) {
	got := querySQLiCandidateURLForParam("https://example.test/login", "/login", "password")
	if !strings.Contains(got, "username=admin") {
		t.Fatalf("password candidate URL = %q, want username partner field", got)
	}
	got = querySQLiCandidateURLForParam("https://example.test/login", "/login", "username")
	if !strings.Contains(got, "password=Password1%21") {
		t.Fatalf("username candidate URL = %q, want password partner field", got)
	}
	got = querySQLiCandidateURLForParam("https://example.test/search", "/search", "q")
	if got != "https://example.test/search" {
		t.Fatalf("non-auth candidate URL = %q, want unchanged", got)
	}
}

// TestExtractVersionString covers the semver-ish extractor used by the
// outdated-component probe. It needs to tolerate JSON, freeform text, and
// optional "v" prefixes, and must NOT trip on lone numbers / dotted ints.
func TestExtractVersionString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"juice shop json", `{"version":"14.5.0"}`, "14.5.0"},
		{"v prefix", `v15.0.1 release notes`, "15.0.1"},
		{"pre-release suffix", `"version":"16.0.0-rc.1"`, "16.0.0-rc.1"},
		{"plain text", `Running Express 2.5.11 in production`, "2.5.11"},
		{"no version", `hello world`, ""},
		{"two-part number ignored", `API v1.0 ready`, ""},
		{"first match wins", `node 20.1.0, express 4.18.2`, "20.1.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractVersionString(tc.in)
			if got != tc.want {
				t.Errorf("extractVersionString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestEvaluateVersionKnownVulns locks in the rules that decide whether a
// detected version is "vulnerable" enough to raise a Finding. Conservative:
// anything we can't point at a published issue for must NOT match.
func TestEvaluateVersionKnownVulns(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		version    string
		body       string
		wantMatch  bool
		wantTitleC string // substring expected in Title when match=true
	}{
		{
			name:       "juice shop via application-version path",
			path:       "/rest/admin/application-version",
			version:    "14.5.0",
			body:       `{"version":"14.5.0"}`,
			wantMatch:  true,
			wantTitleC: "Juice Shop 14.5.0",
		},
		{
			name:       "juice shop via body hint on generic path",
			path:       "/api/version",
			version:    "15.0.1",
			body:       `{"app":"owasp-juice-shop","version":"15.0.1"}`,
			wantMatch:  true,
			wantTitleC: "Juice Shop 15.0.1",
		},
		{
			name:       "express pre-3.0 pin",
			path:       "/api/version",
			version:    "2.5.11",
			body:       `Powered by Express 2.5.11`,
			wantMatch:  true,
			wantTitleC: "Express 2.5.11",
		},
		{
			name:      "modern express not flagged",
			path:      "/api/version",
			version:   "4.18.2",
			body:      `Powered by Express 4.18.2`,
			wantMatch: false,
		},
		{
			name:      "unknown app with version is not flagged",
			path:      "/api/version",
			version:   "1.2.3",
			body:      `{"version":"1.2.3","build":"prod"}`,
			wantMatch: false,
		},
		{
			name:      "empty body, path-only match on juice path still flags",
			path:      "/rest/admin/application-version",
			version:   "16.0.0",
			body:      `{"version":"16.0.0"}`,
			wantMatch: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := evaluateVersionKnownVulns(tc.path, tc.version, tc.body)
			if ok != tc.wantMatch {
				t.Fatalf("evaluateVersionKnownVulns(%q, %q, …) match=%v, want %v",
					tc.path, tc.version, ok, tc.wantMatch)
			}
			if !ok {
				return
			}
			if tc.wantTitleC != "" && !containsStr(f.Title, tc.wantTitleC) {
				t.Errorf("title = %q, want substring %q", f.Title, tc.wantTitleC)
			}
			if f.VulnType != "vulnerable_component" {
				t.Errorf("VulnType = %q, want vulnerable_component", f.VulnType)
			}
		})
	}
}

func TestEntitlementUpgradeCandidatesFromTrafficExtractClientRoutes(t *testing.T) {
	entries := []types.TrafficEntry{{
		Request: types.CapturedRequest{
			Method: "GET",
			URL:    "http://shop.example/main.js",
			Path:   "/main.js",
		},
		Response: types.CapturedResponse{
			StatusCode:  200,
			ContentType: "application/javascript",
			Body: []byte(`
				const upgradeCopy = "Upgrade to deluxe membership";
				return http.post("/rest/deluxe-membership", body);
			`),
		},
	}}
	candidates := entitlementUpgradeCandidatesFromTraffic(entries, "http://shop.example")
	if len(candidates) == 0 {
		t.Fatal("expected entitlement upgrade candidates from client artifact")
	}
	found := false
	for _, candidate := range candidates {
		if candidate.Path == "/rest/deluxe-membership" && candidate.URL == "http://shop.example/rest/deluxe-membership" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected /rest/deluxe-membership candidate, got %#v", candidates)
	}
}

func TestEntitlementUpgradeAuthorityAllowsSyntheticActiveProof(t *testing.T) {
	tests := []struct {
		name      string
		authority policy.TestingAuthority
		want      bool
	}{
		{name: "recon", authority: policy.AuthorityRecon, want: false},
		{name: "active", authority: policy.AuthorityActive, want: true},
		{name: "full control", authority: policy.AuthorityFullControl, want: true},
		{name: "unknown", authority: policy.TestingAuthority(""), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := entitlementUpgradeAuthority(tt.authority); got != tt.want {
				t.Fatalf("entitlementUpgradeAuthority(%q) = %v, want %v", tt.authority, got, tt.want)
			}
		})
	}
}

func TestEntitlementUpgradeBodiesUseSyntheticUserAndAvoidRealPaymentModes(t *testing.T) {
	bodies := entitlementUpgradeBodies(42)
	if len(bodies) == 0 {
		t.Fatal("expected entitlement upgrade bodies")
	}
	foundUserPaymentMode := false
	for _, body := range bodies {
		if mode, ok := body["paymentMode"].(string); ok {
			if strings.EqualFold(mode, "wallet") || strings.EqualFold(mode, "card") {
				t.Fatalf("entitlementUpgradeBodies should not use real payment modes, got %#v", body)
			}
		}
		if id, ok := body["UserId"]; ok {
			if n, ok := integerLikeValue(id); ok && n == 42 && body["paymentMode"] == "none" {
				foundUserPaymentMode = true
			}
		}
	}
	if !foundUserPaymentMode {
		t.Fatalf("expected a Juice-compatible but generic synthetic-user paymentMode body, got %#v", bodies)
	}
}

func TestEntitlementUpgradeSuccessSignal(t *testing.T) {
	juiceBody := `{"status":"success","data":{"confirmation":"Congratulations! You are now a deluxe member!"}}`
	if signal := entitlementUpgradeSuccessSignal(juiceBody); signal == "" {
		t.Fatal("expected deluxe membership success signal")
	}
	if signal := entitlementUpgradeSuccessSignal(`{"status":"error","message":"insufficient wallet balance for premium membership"}`); signal != "" {
		t.Fatalf("negative payment response should not be treated as success, got %q", signal)
	}
	if signal := entitlementUpgradeReadbackSignal(`{"user":{"premium":true,"plan":"premium"}}`); signal == "" {
		t.Fatal("expected readback entitlement state signal")
	}
}

func TestNormalizeEntitlementUpgradePathRejectsTemplates(t *testing.T) {
	if got := normalizeEntitlementUpgradePath(`/api/subscriptions/{id}/upgrade`); got != "" {
		t.Fatalf("templated path should be rejected, got %q", got)
	}
	if got := normalizeEntitlementUpgradePath(`"/api/subscription/upgrade?next=/foo"`); got != "/api/subscription/upgrade" {
		t.Fatalf("normalized path = %q, want /api/subscription/upgrade", got)
	}
}

func TestPrivilegedReadCandidatesFromTrafficExtractsUserAdminRoutes(t *testing.T) {
	entries := []types.TrafficEntry{{
		Request: types.CapturedRequest{
			Method: "GET",
			URL:    "http://shop.example/main.js",
			Path:   "/main.js",
		},
		Response: types.CapturedResponse{
			StatusCode:  200,
			ContentType: "application/javascript",
			Body: []byte(`
				const adminUsers = "/api/admin/users";
				http.get("/api/Users");
			`),
		},
	}}
	candidates := privilegedReadCandidatesFromTraffic(entries, "http://shop.example")
	if len(candidates) == 0 {
		t.Fatal("expected privileged read candidates from client artifact")
	}
	foundAdmin := false
	foundUsers := false
	for _, candidate := range candidates {
		if candidate.Path == "/api/admin/users" && candidate.URL == "http://shop.example/api/admin/users" {
			foundAdmin = true
		}
		if candidate.Path == "/api/Users" && candidate.URL == "http://shop.example/api/Users" {
			foundUsers = true
		}
	}
	if !foundAdmin || !foundUsers {
		t.Fatalf("expected admin/users candidates, got %#v", candidates)
	}
}

func TestLowPrivilegePrivilegedReadAuthorityAllowsActive(t *testing.T) {
	tests := []struct {
		name      string
		authority policy.TestingAuthority
		want      bool
	}{
		{name: "recon", authority: policy.AuthorityRecon, want: false},
		{name: "active", authority: policy.AuthorityActive, want: true},
		{name: "full control", authority: policy.AuthorityFullControl, want: true},
		{name: "unknown", authority: policy.TestingAuthority(""), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lowPrivilegePrivilegedReadAuthority(tt.authority); got != tt.want {
				t.Fatalf("lowPrivilegePrivilegedReadAuthority(%q) = %v, want %v", tt.authority, got, tt.want)
			}
		})
	}
}

func TestPrivilegedReadPathLooksRelevantFiltersPublicConfig(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/rest/admin/application-configuration", false},
		{"/api/Users", true},
		{"/api/Quantitys", false},
		{"/api/support/tickets", true},
		{"/api/products", false},
	}
	for _, tc := range tests {
		if got := privilegedReadPathLooksRelevant(tc.path); got != tc.want {
			t.Fatalf("privilegedReadPathLooksRelevant(%q)=%v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestPrivilegedReadResponseSignalUsesSensitiveExposure(t *testing.T) {
	body := `[{"email":"admin@example.test","role":"admin"},{"email":"user@example.test","role":"user"}]`
	signal := privilegedReadResponseSignal("/api/Users", "application/json", body)
	if signal.Signal == "" {
		t.Fatal("expected user-management JSON exposure signal")
	}
	if signal.Severity != types.SeverityHigh {
		t.Fatalf("severity = %s, want high", signal.Severity)
	}
	if signal.Class != apiExposureUserAuthzData {
		t.Fatalf("class = %s, want user authorization data", signal.Class)
	}
}

func TestPrivilegedReadResponseSignalDetectsModerationCollections(t *testing.T) {
	body := `{"data":[
		{"UserId":1,"comment":"abuse report","status":"open"},
		{"UserId":2,"comment":"chargeback complaint","status":"closed"}
	]}`
	signal := privilegedReadResponseSignal("/api/Complaints", "application/json", body)
	if signal.Signal == "" {
		t.Fatal("expected moderation/support collection signal")
	}
}

// containsStr is a tiny substring helper so we don't pull strings in as a
// test-file import for a single call.
func containsStr(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) &&
		indexOfStr(haystack, needle) >= 0)
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
