package reasoner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// TestMatchConfirmation covers the Executor's decision rule for treating a
// probe response as "confirmed". All four signal types are independently
// tested; combinations too.
func TestMatchConfirmation(t *testing.T) {
	mkResp := func(status int, headers map[string]string) *http.Response {
		h := make(http.Header)
		for k, v := range headers {
			h.Set(k, v)
		}
		return &http.Response{StatusCode: status, Header: h}
	}

	tests := []struct {
		name   string
		rule   ConfirmationRule
		resp   *http.Response
		body   []byte
		expect bool
	}{
		// status-codes only
		{
			name:   "status match",
			rule:   ConfirmationRule{StatusCodes: []int{200}},
			resp:   mkResp(200, nil),
			body:   []byte(""),
			expect: true,
		},
		{
			name:   "status mismatch",
			rule:   ConfirmationRule{StatusCodes: []int{200, 201}},
			resp:   mkResp(401, nil),
			body:   []byte("unauthorized"),
			expect: false,
		},

		// body-contains
		{
			name:   "body match (one keyword)",
			rule:   ConfirmationRule{BodyContains: []string{`"token"`, `"authentication"`}},
			resp:   mkResp(200, nil),
			body:   []byte(`{"authentication":{"token":"abc"}}`),
			expect: true,
		},
		{
			name:   "body does not contain keyword",
			rule:   ConfirmationRule{BodyContains: []string{"invalid_grant"}},
			resp:   mkResp(200, nil),
			body:   []byte(`{"authentication":{"token":"abc"}}`),
			expect: false,
		},
		{
			name:   "case-insensitive match",
			rule:   ConfirmationRule{BodyContains: []string{"TOKEN"}},
			resp:   mkResp(200, nil),
			body:   []byte(`{"token":"x"}`),
			expect: true,
		},

		// body-absent: must NOT appear
		{
			name:   "body absent hit — rejected",
			rule:   ConfirmationRule{StatusCodes: []int{200}, BodyAbsent: []string{"error"}},
			resp:   mkResp(200, nil),
			body:   []byte(`{"error":"bad creds"}`),
			expect: false,
		},
		{
			name:   "body absent miss — accepted",
			rule:   ConfirmationRule{StatusCodes: []int{200}, BodyAbsent: []string{"error"}},
			resp:   mkResp(200, nil),
			body:   []byte(`{"token":"ok"}`),
			expect: true,
		},

		// header-present
		{
			name:   "header present",
			rule:   ConfirmationRule{HeaderPresent: []string{"Location"}},
			resp:   mkResp(302, map[string]string{"Location": "http://evil/"}),
			body:   []byte(""),
			expect: true,
		},
		{
			name:   "header absent — rejected",
			rule:   ConfirmationRule{HeaderPresent: []string{"Location"}},
			resp:   mkResp(200, nil),
			body:   []byte(""),
			expect: false,
		},

		// min body bytes
		{
			name:   "body too small",
			rule:   ConfirmationRule{MinBodyBytes: 100},
			resp:   mkResp(200, nil),
			body:   []byte("short"),
			expect: false,
		},
		{
			name:   "body meets minimum",
			rule:   ConfirmationRule{MinBodyBytes: 10},
			resp:   mkResp(200, nil),
			body:   []byte("long enough to pass"),
			expect: true,
		},

		// combinations — status + body
		{
			name: "combined status+body both match",
			rule: ConfirmationRule{
				StatusCodes:  []int{200},
				BodyContains: []string{"success"},
			},
			resp:   mkResp(200, nil),
			body:   []byte(`{"result":"success"}`),
			expect: true,
		},
		{
			name: "combined status+body body fails",
			rule: ConfirmationRule{
				StatusCodes:  []int{200},
				BodyContains: []string{"success"},
			},
			resp:   mkResp(200, nil),
			body:   []byte(`{"result":"error"}`),
			expect: false,
		},
		// empty rule — accepts everything
		{
			name:   "empty rule accepts",
			rule:   ConfirmationRule{},
			resp:   mkResp(500, nil),
			body:   []byte("Internal Server Error"),
			expect: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchConfirmation(tc.rule, tc.resp, tc.body)
			if got != tc.expect {
				t.Errorf("matchConfirmation got %v, want %v", got, tc.expect)
			}
		})
	}
}

func TestExecutorAuthTechniquesRejectLoginShellSessionCookie(t *testing.T) {
	const loginShell = `<!doctype html><html><title>Login</title><form><input name="username"><input name="password" type="password"></form></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login.php" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "same-session-cookie"})
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(loginShell))
	}))
	defer srv.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "reasoner-auth-shell.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan(srv.URL, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	exec := NewExecutor(srv.Client(), db, scanID, nil)
	base := ProbePlan{
		Target: ProbeTarget{
			URL:      srv.URL + "/login.php",
			Method:   http.MethodPost,
			BodyType: "json",
		},
		Confirmation:   ConfirmationRule{StatusCodes: []int{http.StatusOK}},
		SourceReasoner: "AuthReasoner",
	}

	weak := base
	weak.Technique = "weak_credentials"
	weak.Payloads = []string{"admin:password"}
	hit, err := exec.ExecutePlan(context.Background(), weak)
	if err != nil {
		t.Fatal(err)
	}
	if hit {
		t.Fatal("weak_credentials should not confirm on same login shell/session cookie as bogus baseline")
	}

	sqli := base
	sqli.Technique = "sqli_login_bypass"
	sqli.Payloads = []string{"admin' OR '1'='1"}
	hit, err = exec.ExecutePlan(context.Background(), sqli)
	if err != nil {
		t.Fatal(err)
	}
	if hit {
		t.Fatal("sqli_login_bypass should not confirm on same login shell/session cookie as bogus baseline")
	}

	var count int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id = ?`, scanID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("finding count = %d, want 0", count)
	}
}

func TestExecutorApplyProbeHeadersReusesObservedAuth(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "executor-auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  "GET",
			URL:     "https://app.example.test/api/orders",
			Host:    "app.example.test",
			Path:    "/api/orders",
			Headers: map[string]string{"Authorization": "Bearer captured"},
		},
		Response: types.CapturedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`[]`)},
	})
	if err != nil {
		t.Fatal(err)
	}

	exec := NewExecutor(http.DefaultClient, db, scanID, nil)
	req, err := http.NewRequest("GET", "https://app.example.test/api/users", nil)
	if err != nil {
		t.Fatal(err)
	}
	exec.applyProbeHeaders(req, nil)
	if got := req.Header.Get("Authorization"); got != "Bearer captured" {
		t.Fatalf("Authorization = %q, want captured bearer", got)
	}

	req2, err := http.NewRequest("GET", "https://app.example.test/api/users", nil)
	if err != nil {
		t.Fatal(err)
	}
	exec.applyProbeHeaders(req2, map[string]string{"Authorization": "Bearer explicit"})
	if got := req2.Header.Get("Authorization"); got != "Bearer explicit" {
		t.Fatalf("explicit Authorization was overwritten: %q", got)
	}
}

func TestExecutorSQLiGenericPivotsToUnionCredentialExfil(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "executor-sqli.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(q, "FROM sqlite_master"):
			_, _ = w.Write([]byte(strings.Repeat("schema-prefix-", 80) + `{"data":[{"name":"CREATE TABLE users (id integer, email text, password text)"}]}`))
		case strings.Contains(q, "FROM users") && strings.Contains(q, "email") && strings.Contains(q, "password"):
			_, _ = w.Write([]byte(strings.Repeat("credential-prefix-", 80) + `{"data":[{"name":"admin@example.test","description":"0123456789abcdef0123456789abcdef"}]}`))
		case strings.Contains(q, "AOBTD_UNION_2") && strings.Contains(q, "AOBTD_UNION_3"):
			_, _ = w.Write([]byte(`{"data":[{"name":"AOBTD_UNION_2","description":"AOBTD_UNION_3"}]}`))
		case strings.Contains(q, "OR 1=1"):
			_, _ = w.Write([]byte(`{"data":[{"name":"product"}]}`))
		default:
			http.Error(w, "SQLITE_ERROR: wrong union shape", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	exec := NewExecutor(srv.Client(), db, scanID, nil)
	ok, err := exec.ExecutePlan(context.Background(), ProbePlan{
		Technique: "sqli_generic",
		Target: ProbeTarget{
			URL:    srv.URL + "/rest/products/search?q=",
			Method: "GET",
			Field:  "q",
		},
		Payloads: []string{"' OR 1=1 -- "},
		Confirmation: ConfirmationRule{
			StatusCodes:  []int{200},
			BodyContains: []string{"product"},
		},
		SourceReasoner: "test",
		Rationale:      "test confirmed SQLi and should pivot to bounded UNION exfil",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("ExecutePlan returned not confirmed")
	}
	var count int
	if err := db.Conn().QueryRow(`
		SELECT COUNT(*) FROM findings
		WHERE scan_id = ? AND confidence = 'confirmed'
		  AND title LIKE '%credential-like user data%'`, scanID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("credential exfil finding count = %d, want 1", count)
	}
	var schemaProof, credentialProof string
	if err := db.Conn().QueryRow(`
		SELECT poc_response FROM findings
		WHERE scan_id = ? AND vuln_type = 'sqli_schema_exposure'
		LIMIT 1`, scanID).Scan(&schemaProof); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(schemaProof, "CREATE TABLE users") {
		t.Fatalf("schema PoC response dropped the confirming evidence:\n%s", schemaProof)
	}
	if err := db.Conn().QueryRow(`
		SELECT poc_response FROM findings
		WHERE scan_id = ? AND vuln_type = 'sqli_credential_exfiltration'
		LIMIT 1`, scanID).Scan(&credentialProof); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(credentialProof, "admin@example.test") {
		t.Fatalf("credential PoC response dropped the confirming evidence:\n%s", credentialProof)
	}
	var poc string
	if err := db.Conn().QueryRow(`
		SELECT poc_request FROM findings
		WHERE scan_id = ? AND vuln_type = 'sqli' AND title LIKE 'SQL injection in%'
		LIMIT 1`, scanID).Scan(&poc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(poc, "GET /rest/products/search?") ||
		!strings.Contains(poc, "q=%27+OR+1%3D1+--+") ||
		strings.Contains(poc, "{payload=") {
		t.Fatalf("SQLi PoC should contain the mutated query URL, got:\n%s", poc)
	}
}

func TestProofResponseBodyFallsBackToPrefixWithoutKnownMarker(t *testing.T) {
	body := strings.Repeat("prefix", 100) + "important-tail"
	got := proofResponseBody("other", []byte(body), 80)
	if !strings.HasPrefix(got, strings.Repeat("prefix", 10)) || strings.Contains(got, "important-tail") {
		t.Fatalf("generic proof preview should preserve the response prefix, got %q", got)
	}
}

func TestExecutorSQLiGenericRejectsGraphQLSyntaxErrorConfirmation(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "executor-graphql-sqli.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://graphql.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Syntax Error GraphQL (1:2) Expected Name, found String \"query\""}]}`))
	}))
	defer srv.Close()

	exec := NewExecutor(srv.Client(), db, scanID, nil)
	ok, err := exec.ExecutePlan(context.Background(), ProbePlan{
		Technique: "sqli_generic",
		Target: ProbeTarget{
			URL:    srv.URL + "/graphql?query=",
			Method: "GET",
			Field:  "query",
		},
		Payloads: []string{`{"query":"{ pastes(search:\"' OR 1=1 -- \"){ id } }"}`},
		Confirmation: ConfirmationRule{
			StatusCodes:  []int{400},
			BodyContains: []string{"Syntax Error GraphQL"},
		},
		SourceReasoner: "test",
		Rationale:      "GraphQL parser error must not confirm SQL injection",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("GraphQL syntax error should not confirm SQLi")
	}
	var count int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id = ?`, scanID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("finding count = %d, want 0", count)
	}
}

func TestExecutorSQLiGenericRejectsStatusOnlyLoginShell(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "executor-sqli-status-only.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://webgoat.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	loginShell := strings.Repeat("<html><title>Login Page</title><form>login</form></html>", 20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(loginShell))
	}))
	defer srv.Close()

	exec := NewExecutor(srv.Client(), db, scanID, nil)
	ok, err := exec.ExecutePlan(context.Background(), ProbePlan{
		Technique: "sqli_generic",
		Target: ProbeTarget{
			URL:    srv.URL + "/WebGoat/start.mvc?username=aobtd-bench",
			Method: "GET",
			Field:  "username",
		},
		Payloads: []string{"aobtd-bench' OR '1'='1"},
		Confirmation: ConfirmationRule{
			StatusCodes:  []int{http.StatusOK},
			BodyContains: []string{"Login Page"},
		},
		SourceReasoner: "test",
		Rationale:      "status-only SQLi plan should not confirm on a login shell",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("status-only 200 response should not confirm generic SQLi without body/error/baseline signal")
	}
	var count int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id = ?`, scanID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("finding count = %d, want 0", count)
	}
}

func TestSQLiGenericConfirmationIntrinsicSignals(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	ruleWithPlannerMarker := ConfirmationRule{
		StatusCodes:  []int{http.StatusOK},
		BodyContains: []string{"planner-specific-marker"},
	}
	sqlError := []byte(`StatementCallback; SQL [select * from cars where id=']; nested exception is org.h2.jdbc.JdbcSQLSyntaxErrorException: Syntax error in SQL statement`)
	if !sqliGenericConfirmationHit(ruleWithPlannerMarker, resp, sqlError, 42, []byte(`{"ok":false}`)) {
		t.Fatal("SQL error body should confirm even when a planner marker is absent")
	}
	unionMarker := []byte(`{"id":1,"name":"AOBTD_SQLI_MARK","imagePath":"AOBTD_SQLI_MARK"}`)
	if !sqliGenericConfirmationHit(ruleWithPlannerMarker, resp, unionMarker, 42, []byte(`{"id":0,"name":null}`)) {
		t.Fatal("injected UNION marker should confirm SQLi")
	}
	blindTrue := []byte(`{"isCarPresent":true}`)
	blindFalse := []byte(`{"isCarPresent":false}`)
	if !sqliGenericConfirmationHit(ConfirmationRule{StatusCodes: []int{http.StatusOK}}, resp, blindTrue, len(blindFalse), blindFalse) {
		t.Fatal("boolean false→true differential should confirm blind SQLi")
	}
	loginShell := []byte(`<html><form><input name="username"><input name="password"></form></html>`)
	if sqliGenericConfirmationHit(ConfirmationRule{StatusCodes: []int{http.StatusOK}}, resp, loginShell, len(loginShell), loginShell) {
		t.Fatal("status-only identical login shell should not confirm SQLi")
	}
	emptyData := []byte(`{"status":"success","data":[]}`)
	if sqliGenericConfirmationHit(ConfirmationRule{
		StatusCodes:  []int{http.StatusOK},
		BodyContains: []string{"data"},
	}, resp, emptyData, len(emptyData), emptyData) {
		t.Fatal("planner marker already present in baseline should not confirm SQLi")
	}
	introducedRow := []byte(`{"status":"success","data":[{"email":"admin@example.test"}]}`)
	if !sqliGenericConfirmationHit(ConfirmationRule{
		StatusCodes:  []int{http.StatusOK},
		BodyContains: []string{"admin@example.test"},
	}, resp, introducedRow, len(emptyData), emptyData) {
		t.Fatal("new planner-specific response marker should confirm SQLi")
	}
	resp.Header.Set("Content-Type", "application/json")
	if sqliGenericConfirmationHit(ConfirmationRule{
		StatusCodes:   []int{http.StatusOK},
		HeaderPresent: []string{"Content-Type"},
	}, resp, emptyData, len(emptyData), emptyData) {
		t.Fatal("ordinary response header should not confirm SQLi")
	}
}

func TestSQLiBodyContainsRuleLooksSpecific(t *testing.T) {
	if sqliBodyContainsRuleLooksSpecific([]string{"Login Page", "<html>"}) {
		t.Fatal("generic login/html markers should not be specific SQLi confirmation")
	}
	if !sqliBodyContainsRuleLooksSpecific([]string{"product"}) {
		t.Fatal("domain data marker should remain usable for SQLi confirmation")
	}
	if !sqliBodyContainsRuleLooksSpecific([]string{"SQL syntax"}) {
		t.Fatal("SQL error marker should be specific")
	}
}

func TestBodyLooksLikeSQLErrorIgnoresDatabaseFooterLabels(t *testing.T) {
	body := `<html><title>Vulnerability: Brute Force</title><div>SQLi DB: mysql</div></html>`
	if bodyLooksLikeSQLError(body) {
		t.Fatal("bare database product label in a normal footer should not confirm SQLi")
	}
	if !bodyLooksLikeSQLError(`You have an error in your SQL syntax near "' OR 1=1"`) {
		t.Fatal("real SQL syntax error should be detected")
	}
}

func TestGraphQLSyntaxErrorResponseAllowsDatabaseEvidence(t *testing.T) {
	if !graphQLSyntaxErrorResponse("https://example.test/graphql", 400, []byte(`{"errors":[{"message":"Field \"owner\" of type \"OwnerObject\" must have a sub selection."}]}`)) {
		t.Fatal("GraphQL validation error should be negative evidence")
	}
	if graphQLSyntaxErrorResponse("https://example.test/graphql", 500, []byte(`{"errors":[{"message":"sqlite error near OR 1=1"}]}`)) {
		t.Fatal("database/SQL evidence should not be filtered as GraphQL validation noise")
	}
}

func TestBuildReasonerPocRequestUsesConcreteHost(t *testing.T) {
	got := buildReasonerPocRequest(ProbePlan{
		Target: ProbeTarget{Method: "GET", URL: "https://app.example.test/search?q=1"},
	}, "' OR 1=1 --")
	if strings.Contains(got, "<target>") {
		t.Fatalf("PoC still contains placeholder host:\n%s", got)
	}
	if !strings.Contains(got, "Host: app.example.test") || !strings.Contains(got, "GET /search?q=1 HTTP/1.1") {
		t.Fatalf("PoC request not concrete enough:\n%s", got)
	}
	if strings.Contains(got, "{payload=") {
		t.Fatalf("GET PoC should not put payload in a fake request body:\n%s", got)
	}
}

// TestRewriteQueryParam covers the query-param rewriter used by
// execSQLiGeneric. Must preserve other params, replace existing values,
// and add missing ones.
func TestRewriteQueryParam(t *testing.T) {
	tests := []struct {
		name    string
		inURL   string
		key     string
		value   string
		wantHas string // substring that must appear in result
	}{
		{
			name:    "replace existing param",
			inURL:   "http://x/api?q=hello&limit=10",
			key:     "q",
			value:   "' OR 1=1 --",
			wantHas: "q=%27+OR+1%3D1+--",
		},
		{
			name:    "preserve other params",
			inURL:   "http://x/api?q=hello&limit=10",
			key:     "q",
			value:   "new",
			wantHas: "limit=10",
		},
		{
			name:    "add missing param",
			inURL:   "http://x/api",
			key:     "q",
			value:   "new",
			wantHas: "q=new",
		},
		{
			name:    "add missing param with existing query",
			inURL:   "http://x/api?other=1",
			key:     "q",
			value:   "test",
			wantHas: "q=test",
		},
		{
			name:    "unparseable url falls back to naive append",
			inURL:   "://malformed",
			key:     "q",
			value:   "x",
			wantHas: "q=x",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rewriteQueryParam(tc.inURL, tc.key, tc.value)
			if !containsSS(got, tc.wantHas) {
				t.Errorf("rewriteQueryParam(%q,%q,%q) = %q; want to contain %q",
					tc.inURL, tc.key, tc.value, got, tc.wantHas)
			}
		})
	}
}

// containsSS is a tiny substring-checker helper so we don't pull
// `strings` into the test file just for this.
func containsSS(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestHS256VerifyJWT locks in the brute-force verifier used by
// execJWTWeakSecret. Must correctly accept matching secrets and reject
// everything else (no false positives — a single wrong accept could
// produce a critical-severity false finding).
func TestHS256VerifyJWT(t *testing.T) {
	// Locally-computed test vector. HMAC-SHA256 of the signing input
	// with secret="secret" produces the base64url signature below.
	// (Verified via `crypto/hmac` + `crypto/sha256` — using our own
	// output as the fixture keeps this test self-contained.)
	signingInput := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
	sigB64 := "XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"
	sigBytes, err := base64URL.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}

	tests := []struct {
		secret string
		want   bool
	}{
		{"secret", true},     // the actual signing secret
		{"wrong", false},     // wrong secret
		{"", false},          // empty
		{"Secret", false},    // case-sensitive
		{"secret_", false},   // near-miss
		{"passwords", false}, // unrelated
	}
	for _, tc := range tests {
		t.Run(tc.secret, func(t *testing.T) {
			got := hs256VerifyJWT(signingInput, sigBytes, []byte(tc.secret))
			if got != tc.want {
				t.Errorf("hs256VerifyJWT(secret=%q) = %v, want %v",
					tc.secret, got, tc.want)
			}
		})
	}
}

// TestBase64URLEncode covers the JWT-style URL-safe base64 encoder used
// when forging alg:none tokens. Must produce unpadded URL-safe output.
func TestBase64URLEncode(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		// {"alg":"none","typ":"JWT"} → known JWT header for alg:none
		{`{"alg":"none","typ":"JWT"}`, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"},
		// simple payload
		{`{"user":"admin"}`, "eyJ1c2VyIjoiYWRtaW4ifQ"},
		// empty object
		{`{}`, "e30"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got := base64URLEncode([]byte(tc.in))
			if got != tc.want {
				t.Errorf("base64URLEncode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestExpandJWTConfirmationReplacesIdentityPlaceholder(t *testing.T) {
	rule := ConfirmationRule{
		StatusCodes:  []int{200},
		BodyContains: []string{"{{jwt_identity}}"},
	}
	claims := `{"data":{"email":"jwtn3d@example.test","role":"admin"},"sub":"ignored@example.test"}`
	got := expandJWTConfirmation(rule, claims)
	if len(got.BodyContains) != 1 || got.BodyContains[0] != "jwtn3d@example.test" {
		t.Fatalf("expanded body_contains=%+v", got.BodyContains)
	}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	if !matchConfirmation(got, resp, []byte(`{"email":"jwtn3d@example.test"}`)) {
		t.Fatal("expanded confirmation should match reflected forged identity")
	}
	if matchConfirmation(got, resp, []byte(`{"email":"admin@example.test"}`)) {
		t.Fatal("expanded confirmation should not match a different identity")
	}
}

func TestJWTUnsignedBaselineBypassConfirmsAuthBoundaryCrossing(t *testing.T) {
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	if !jwtUnsignedBaselineBypass(401, []byte(`UnauthorizedError: No Authorization header was found`), resp, []byte(`{"status":"success","data":[1]}`)) {
		t.Fatal("401 anonymous baseline followed by 200 forged JWT should confirm auth bypass")
	}
	if jwtUnsignedBaselineBypass(200, []byte(`{"status":"success"}`), resp, []byte(`{"status":"success"}`)) {
		t.Fatal("public 200 baseline should not confirm auth bypass")
	}
}

// TestBuildIDORProbeURL covers path-tail replacement and query-param
// replacement modes used by execIDORSequentialID.
func TestBuildIDORProbeURL(t *testing.T) {
	tests := []struct {
		name    string
		inURL   string
		field   string
		value   string
		wantHas string
	}{
		{
			name:    "path mode replaces tail",
			inURL:   "http://x/api/users/1",
			field:   "",
			value:   "2",
			wantHas: "/api/users/2",
		},
		{
			name:    "path mode with explicit field",
			inURL:   "http://x/api/users/abc",
			field:   "path",
			value:   "42",
			wantHas: "/api/users/42",
		},
		{
			name:    "query mode replaces value",
			inURL:   "http://x/api/users?role=admin",
			field:   "role",
			value:   "superuser",
			wantHas: "role=superuser",
		},
		{
			name:    "path with trailing slash appends",
			inURL:   "http://x/api/users/",
			field:   "",
			value:   "99",
			wantHas: "/api/users/99",
		},
		{
			name:    "preserves host + scheme",
			inURL:   "https://example.com/api/users/1",
			field:   "",
			value:   "2",
			wantHas: "https://example.com/api/users/2",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildIDORProbeURL(tc.inURL, tc.field, tc.value)
			if !containsSS(got, tc.wantHas) {
				t.Errorf("buildIDORProbeURL(%q,%q,%q) = %q; want substring %q",
					tc.inURL, tc.field, tc.value, got, tc.wantHas)
			}
		})
	}
}

func TestBuildIDORProbeURLAvoidsDoubleEncodingPathPayload(t *testing.T) {
	payload := `%3Ciframe%20src%3D%22javascript%3Aalert%28%60xss%60%29%22%3E`
	got := buildIDORProbeURL("http://x/rest/track-order/123", "path", payload)
	if strings.Contains(got, "%253C") || strings.Contains(got, "%2520") {
		t.Fatalf("path payload was double-encoded: %s", got)
	}
	if !strings.Contains(got, "%3Ciframe") {
		t.Fatalf("path payload missing single-encoded iframe marker: %s", got)
	}
	if strings.Contains(got, "<iframe") {
		t.Fatalf("path payload leaked raw iframe into URL: %s", got)
	}
}

// TestApproxSameSize checks the IDOR baseline-diff fuzzy-compare.
// Responses that differ by just a few bytes should be "same"; a
// 3x-larger response is "different".
func TestApproxSameSize(t *testing.T) {
	tests := []struct {
		name string
		a, b int
		same bool
	}{
		{"identical", 1000, 1000, true},
		{"within 10 percent", 1000, 1080, true},
		{"well outside 10 percent", 1000, 3000, false},
		{"small absolute diff OK", 50, 70, true},
		{"both empty", 0, 0, true},
		{"empty vs small", 0, 20, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := approxSameSize(tc.a, tc.b); got != tc.same {
				t.Errorf("approxSameSize(%d,%d) = %v, want %v", tc.a, tc.b, got, tc.same)
			}
		})
	}
}

// TestSplitCredential covers the user:pass splitter, which must handle
// colons inside passwords (everything after the FIRST `:` is the password).
func TestSplitCredential(t *testing.T) {
	tests := []struct {
		in       string
		wantUser string
		wantPass string
		wantOK   bool
	}{
		{"admin:admin", "admin", "admin", true},
		{"admin:pass:with:colons", "admin", "pass:with:colons", true},
		{"user@example.com:Password1", "user@example.com", "Password1", true},
		{"", "", "", false},
		{"nocolon", "", "", false},
		{":", "", "", false},
		{":nopass", "", "", false}, // we accept empty password rejected
		{"nopass:", "", "", false}, // empty password
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			u, p, ok := splitCredential(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("splitCredential(%q) ok=%v, want %v", tc.in, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if u != tc.wantUser || p != tc.wantPass {
				t.Errorf("got (%q, %q), want (%q, %q)", u, p, tc.wantUser, tc.wantPass)
			}
		})
	}
}
