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
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/filter"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestExplorerStoresFileInclusionSourceDisclosureFromProbeParam(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "explorer.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	explorer := &ExplorerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	body := []byte(base64.StdEncoding.EncodeToString([]byte("<?php\ninclude($_GET['page']);\nini_get('allow_url_include');\n")))
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	task := store.FollowUp{
		URL:    "https://example.test/vulnerabilities/fi/",
		Action: "probe_param",
		Reason: "Test for Local File Inclusion by manipulating the page parameter",
	}
	rawURL := "https://example.test/vulnerabilities/fi/?page=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dinclude.php"
	explorer.maybeStoreFileInclusionSourceDisclosureFinding(task, "page", http.MethodGet, rawURL, "php://filter/convert.base64-encode/resource=include.php", nil, resp, body)

	var vulnType, confidence, pocRequest string
	if err := db.Conn().QueryRow(`
		SELECT vuln_type, confidence, poc_request
		FROM findings
		WHERE scan_id = ? AND vuln_type = 'file_inclusion'
		LIMIT 1`, scanID).Scan(&vulnType, &confidence, &pocRequest); err != nil {
		t.Fatalf("file inclusion finding not stored: %v", err)
	}
	if vulnType != "file_inclusion" || confidence != string(types.ConfidenceConfirmed) {
		t.Fatalf("finding = (%q,%q), want confirmed file_inclusion", vulnType, confidence)
	}
	if !strings.Contains(pocRequest, "php%3A%2F%2Ffilter") {
		t.Fatalf("PoC request missing php-filter payload: %s", pocRequest)
	}
}

func TestExplorerEscapePathSegmentPayloadAvoidsDoubleEncoding(t *testing.T) {
	payload := `%3Ciframe%20src%3D%22javascript%3Aalert%28%60xss%60%29%22%3E`
	got := escapePathSegmentPayload(payload)
	if strings.Contains(got, "%253C") || strings.Contains(got, "%2520") {
		t.Fatalf("path segment payload was double-encoded: %s", got)
	}
	if !strings.Contains(got, "%3Ciframe") {
		t.Fatalf("path segment payload missing single-encoded iframe marker: %s", got)
	}
	if strings.Contains(got, "<iframe") {
		t.Fatalf("path segment payload leaked raw iframe: %s", got)
	}
}

func TestBusinessLogicLooksLikeUserEnumeration(t *testing.T) {
	verdict := &businessLogicVerdict{
		IsVuln:    true,
		VulnClass: "other",
		Evidence:  "The server returns 'Given Email is not registered!' for one value and 'Invalid Credentials' for another, enabling user enumeration.",
	}
	probes := []logicProbe{
		{TestValue: "nobody@example.test", StatusCode: http.StatusUnauthorized, BodyBytes: []byte(`{"message":"Given Email is not registered!"}`)},
		{TestValue: "admin@example.com", StatusCode: http.StatusUnauthorized, BodyBytes: []byte(`{"message":"Invalid Credentials"}`)},
	}
	if !businessLogicLooksLikeUserEnumeration("https://api.example.test/identity/api/auth/login", "email", probes, verdict) {
		t.Fatal("auth identifier response differential should be classified as user enumeration")
	}
}

func TestBusinessLogicDoesNotTreatGenericRejectedValuesAsEnumeration(t *testing.T) {
	verdict := &businessLogicVerdict{
		IsVuln:    true,
		VulnClass: "other",
		Evidence:  "Different invalid quantities were rejected with validation errors.",
	}
	probes := []logicProbe{
		{TestValue: "-1", StatusCode: http.StatusBadRequest, BodyBytes: []byte(`{"error":"invalid quantity"}`)},
		{TestValue: "999999", StatusCode: http.StatusBadRequest, BodyBytes: []byte(`{"error":"quantity too large"}`)},
	}
	if businessLogicLooksLikeUserEnumeration("https://api.example.test/cart", "quantity", probes, verdict) {
		t.Fatal("non-auth validation differences must not be classified as user enumeration")
	}
}

func TestGenericGraphQLQueryLogicProbe(t *testing.T) {
	if !genericGraphQLQueryLogicProbe("https://app.example.test/graphql", "query") {
		t.Fatal("GraphQL query field should skip generic business-logic judgement")
	}
	if genericGraphQLQueryLogicProbe("https://app.example.test/graphql", "role") {
		t.Fatal("non-query GraphQL field should not use the generic query skip")
	}
	if genericGraphQLQueryLogicProbe("https://app.example.test/api/search", "query") {
		t.Fatal("non-GraphQL query field should remain eligible for generic business-logic judgement")
	}
}

func TestBusinessLogicFieldIsCSRFToken(t *testing.T) {
	for _, field := range []string{"user_token", "csrf", "csrf-token", "authenticity_token", "profile_token"} {
		if !businessLogicFieldIsCSRFToken(field) {
			t.Fatalf("%s should be treated as a CSRF/token field", field)
		}
	}
	if businessLogicFieldIsCSRFToken("username") {
		t.Fatal("username should not be treated as a CSRF/token field")
	}
}

func TestBusinessLogicLooksLikeCommandInjection(t *testing.T) {
	verdict := &businessLogicVerdict{
		IsVuln:    true,
		VulnClass: "other",
		Evidence:  "The shell payload returned command output including uid/gid information.",
	}
	probes := []logicProbe{
		{TestValue: "127.0.0.1;id", StatusCode: http.StatusOK, BodyBytes: []byte("uid=33(www-data) gid=33(www-data)")},
	}
	if !businessLogicLooksLikeCommandInjection("ip", probes, verdict) {
		t.Fatal("shell metacharacter payload with command output should be classified as command injection")
	}
	noOutput := []logicProbe{{TestValue: "127.0.0.1;id", StatusCode: http.StatusOK, BodyBytes: []byte("normal page")}}
	if businessLogicLooksLikeCommandInjection("ip", noOutput, &businessLogicVerdict{IsVuln: true}) {
		t.Fatal("payload without output evidence should not be classified as command injection")
	}
}

func TestLogicProbesAllCSRFRejected(t *testing.T) {
	probes := []logicProbe{
		{TestValue: "127.0.0.1;id", StatusCode: http.StatusOK, BodyBytes: []byte(`<div class="message">CSRF token is incorrect</div>`)},
		{TestValue: "127.0.0.1|whoami", StatusCode: http.StatusOK, BodyBytes: []byte(`token is incorrect`)},
	}
	if !logicProbesAllCSRFRejected(probes) {
		t.Fatal("all CSRF-rejected probes should be recognized")
	}
	mixed := append(probes, logicProbe{TestValue: "127.0.0.1", StatusCode: http.StatusOK, BodyBytes: []byte(`uid=33(www-data)`)})
	if logicProbesAllCSRFRejected(mixed) {
		t.Fatal("mixed CSRF rejection and command output should not be treated as all rejected")
	}
}

func TestUserEnumerationProbePairChoosesDifferentResponse(t *testing.T) {
	p1, p2, ok := userEnumerationProbePair([]logicProbe{
		{TestValue: "admin", StatusCode: http.StatusOK, BodyBytes: []byte("same login shell")},
		{TestValue: "guest", StatusCode: http.StatusOK, BodyBytes: []byte("same login shell")},
		{TestValue: "webgoat", StatusCode: http.StatusOK, BodyBytes: []byte("different known-user login shell")},
	})
	if !ok {
		t.Fatal("expected a probe pair")
	}
	if p1.TestValue != "admin" || p2.TestValue != "webgoat" {
		t.Fatalf("pair = %s/%s, want admin/webgoat", p1.TestValue, p2.TestValue)
	}
}

func TestExplorerTrafficReentersAnalyzerLearningLoop(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "explorer-learning.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	scanID, err := db.CreateScan("https://api.example.test", `{}`)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	explorer := &ExplorerAgent{db: db, scanID: scanID, logger: logger}

	body := []byte(`{"id":42,"owner":{"id":7},"state":"paid"}`)
	explorer.storeAsTraffic(
		"https://api.example.test/api/orders/42?expand=owner",
		"GET",
		&http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{"application/json; charset=utf-8"},
			},
		},
		body,
		map[string]string{"Authorization": "Bearer persona-a"},
		nil,
		71,
		"hypothesis-order-ownership",
	)

	if _, err := filter.NewDeduplicator(db, logger).Run(scanID); err != nil {
		t.Fatalf("deduplicate explorer traffic: %v", err)
	}
	if _, err := filter.NewRelevanceScorer(db, logger).Run(scanID); err != nil {
		t.Fatalf("score explorer traffic: %v", err)
	}

	hashes, err := db.GetUnanalyzedEndpointHashes(scanID, 0.3, 10)
	if err != nil {
		t.Fatalf("get analyzer-ready endpoint hashes: %v", err)
	}
	if len(hashes) != 1 || hashes[0] == "" {
		t.Fatalf("analyzer-ready hashes = %v, want one non-blank hash", hashes)
	}

	entries, err := db.GetTrafficByEndpointHash(scanID, hashes[0])
	if err != nil {
		t.Fatalf("load Explorer endpoint bundle traffic: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("traffic entries = %d, want 1", len(entries))
	}
	if got := entries[0].Response.ContentType; got != "application/json; charset=utf-8" {
		t.Errorf("content type = %q", got)
	}
	if got := entries[0].Response.Size; got != int64(len(body)) {
		t.Errorf("response size = %d, want %d", got, len(body))
	}
	if got := entries[0].SourceAgent; got != "explorer" {
		t.Errorf("source agent = %q, want explorer", got)
	}
	if got := entries[0].SourceActionID; got != 71 {
		t.Errorf("source action ID = %d, want 71", got)
	}
	if got := entries[0].HypothesisID; got != "hypothesis-order-ownership" {
		t.Errorf("hypothesis ID = %q", got)
	}

	bundle := extract.BuildEndpointBundle(entries, 20)
	if bundle == nil {
		t.Fatal("BuildEndpointBundle() = nil")
	}
	if bundle.EndpointHash != hashes[0] || !bundle.IsAPI {
		t.Errorf("bundle did not preserve Explorer evidence: hash=%q is_api=%v", bundle.EndpointHash, bundle.IsAPI)
	}
	if bundle.JSONSchema == nil {
		t.Error("Explorer JSON response did not reach deterministic schema extraction")
	}
}

func TestExplorerTrafficLookupsAreScanScoped(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "explorer.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	scanA, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}

	// Both scans observed the exact same endpoint. Scan B is inserted last so
	// an unscoped "ORDER BY id DESC" lookup would leak B's request and bearer
	// token into Explorer A.
	const rawURL = "https://example.test/orders/41"
	insertExplorerTestTraffic(t, db, scanA, rawURL,
		map[string]string{
			"Authorization": "Bearer scan-a",
			"Cookie":        "session=scan-a",
			"Content-Type":  "application/json",
		},
		`{"owner":"scan-a"}`)
	insertExplorerTestTraffic(t, db, scanB, rawURL,
		map[string]string{
			"Authorization": "Bearer scan-b",
			"Cookie":        "session=scan-b",
			"Content-Type":  "application/json",
		},
		`{"owner":"scan-b"}`)

	explorerA := &ExplorerAgent{db: db, scanID: scanA}
	explorerB := &ExplorerAgent{db: db, scanID: scanB}

	origA, err := explorerA.originalRequestFor(rawURL)
	if err != nil {
		t.Fatalf("load original request for scan A: %v", err)
	}
	if got, want := string(origA.Body), `{"owner":"scan-a"}`; got != want {
		t.Fatalf("scan A got request body %q, want %q", got, want)
	}
	if got, want := origA.Headers["Authorization"], "Bearer scan-a"; got != want {
		t.Fatalf("scan A got authorization %q, want %q", got, want)
	}

	origB, err := explorerB.originalRequestFor(rawURL)
	if err != nil {
		t.Fatalf("load original request for scan B: %v", err)
	}
	if got, want := string(origB.Body), `{"owner":"scan-b"}`; got != want {
		t.Fatalf("scan B got request body %q, want %q", got, want)
	}

	assertExplorerAuthHeader(t, explorerA.authHeadersForURL(rawURL), "Bearer scan-a")
	assertExplorerAuthHeader(t, explorerB.authHeadersForURL(rawURL), "Bearer scan-b")

	// Force the template helper down its LIKE fallback path. It must retain
	// the same scan boundary even though both scans match the same template.
	const template = "https://example.test/orders/{id}"
	assertExplorerAuthHeader(t, explorerA.authHeadersForTemplate(template, nil), "Bearer scan-a")
	assertExplorerAuthHeader(t, explorerB.authHeadersForTemplate(template, nil), "Bearer scan-b")
}

func TestExplorerAuthHeadersFallbackToSameOriginCredentials(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "explorer.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	scanID, err := db.CreateScan("https://example.test/WebGoat/start.mvc", `{}`)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}

	insertExplorerTestTraffic(t, db, scanID, "https://example.test/WebGoat/start.mvc",
		map[string]string{
			"Cookie":       "JSESSIONID=webgoat-session; Path=/WebGoat",
			"Content-Type": "text/html",
		},
		`<html>authenticated lesson shell</html>`)

	explorer := &ExplorerAgent{db: db, scanID: scanID}
	headers := explorer.authHeadersForURL("https://example.test/WebGoat/SqlInjection/attack2?query=test")

	if got := headers["Cookie"]; !strings.Contains(got, "JSESSIONID=webgoat-session") {
		t.Fatalf("same-origin auth fallback did not replay captured session cookie: %v", headers)
	}
}

func TestProbeParamRetriesMethodNotAllowedAsAuthenticatedFormPOST(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "unexpected method", http.StatusBadRequest)
			return
		}
		if !strings.Contains(r.Header.Get("Cookie"), "JSESSIONID=probe-session") {
			http.Error(w, "missing session", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if got := r.Form.Get("answer"); got != "42" {
			http.Error(w, "missing answer", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	defer srv.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "explorer.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	scanID, err := db.CreateScan(srv.URL+"/WebGoat/start.mvc", `{}`)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	insertExplorerTestTrafficForURL(t, db, scanID, srv.URL+"/WebGoat/start.mvc",
		map[string]string{"Cookie": "JSESSIONID=probe-session"},
		`<html>authenticated</html>`)
	followUpID, err := db.InsertFollowUp(scanID, store.FollowUp{
		SourceAgent: "analyzer",
		Action:      "probe_param",
		URL:         srv.URL + "/WebGoat/SqlInjection/assignment5b",
		Params: map[string]any{
			"param":  "answer",
			"values": []any{"42"},
		},
	})
	if err != nil {
		t.Fatalf("insert follow-up: %v", err)
	}
	tasks, err := db.PopPendingFollowUps(scanID, 1)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("claim follow-up: tasks=%d err=%v", len(tasks), err)
	}

	explorer := &ExplorerAgent{
		db:       db,
		scanID:   scanID,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		client:   srv.Client(),
		provider: nil,
		budget:   nil,
	}
	explorer.runProbeParam(context.Background(), tasks[0])

	var method, requestHeaders string
	var status int
	var requestBody []byte
	if err := db.Conn().QueryRow(`
		SELECT method, status_code, request_headers, request_body
		FROM traffic
		WHERE scan_id = ? AND source_action_id = ? AND method = 'POST'
		LIMIT 1`, scanID, followUpID).Scan(&method, &status, &requestHeaders, &requestBody); err != nil {
		t.Fatalf("POST fallback traffic not stored: %v", err)
	}
	if method != http.MethodPost || status != http.StatusOK {
		t.Fatalf("fallback traffic = %s %d, want POST 200", method, status)
	}
	if !strings.Contains(requestHeaders, "JSESSIONID=probe-session") {
		t.Fatalf("POST fallback did not replay session cookie: %s", requestHeaders)
	}
	if !strings.Contains(string(requestBody), "answer=42") {
		t.Fatalf("POST fallback body = %q, want answer=42", string(requestBody))
	}
}

func TestProbeParamRetriesSpringMissingRequiredFormParameter(t *testing.T) {
	var sawCompletePayload bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "unexpected method", http.StatusBadRequest)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("login_count") == "" {
			http.Error(w, "Required request parameter 'login_count' for method parameter type int is not present", http.StatusBadRequest)
			return
		}
		if got := r.Form.Get("userid"); got != "1 OR 1=1" {
			http.Error(w, "missing userid payload", http.StatusBadRequest)
			return
		}
		if got := r.Form.Get("login_count"); got != "1" {
			http.Error(w, "wrong default login_count", http.StatusBadRequest)
			return
		}
		sawCompletePayload = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"lessonCompleted":true}`))
	}))
	defer srv.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "explorer.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	scanID, err := db.CreateScan(srv.URL+"/WebGoat/start.mvc", `{}`)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	followUpID, err := db.InsertFollowUp(scanID, store.FollowUp{
		SourceAgent: "analyzer",
		Action:      "probe_param",
		URL:         srv.URL + "/WebGoat/SqlInjection/assignment5b",
		Params: map[string]any{
			"param":  "userid",
			"values": []any{"1 OR 1=1"},
		},
	})
	if err != nil {
		t.Fatalf("insert follow-up: %v", err)
	}
	tasks, err := db.PopPendingFollowUps(scanID, 1)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("claim follow-up: tasks=%d err=%v", len(tasks), err)
	}

	explorer := &ExplorerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		client: srv.Client(),
	}
	explorer.runProbeParam(context.Background(), tasks[0])

	if !sawCompletePayload {
		t.Fatal("server never received retry with userid payload plus default login_count")
	}
	var requestBody []byte
	if err := db.Conn().QueryRow(`
		SELECT request_body
		FROM traffic
		WHERE scan_id = ? AND source_action_id = ? AND method = 'POST' AND status_code = 200
		LIMIT 1`, scanID, followUpID).Scan(&requestBody); err != nil {
		t.Fatalf("retry traffic not stored: %v", err)
	}
	body := string(requestBody)
	if !strings.Contains(body, "userid=1+OR+1%3D1") || !strings.Contains(body, "login_count=1") {
		t.Fatalf("retry body = %q, want userid payload and login_count=1", body)
	}
}

func TestProbeParamReplaysObservedPOSTFormWithHiddenTokenAndSubmit(t *testing.T) {
	var sawFormReplay bool
	const formHTML = `<html><body>
		<form name="ping" action="#" method="post">
			<input type="text" name="ip" size="30">
			<input type="submit" name="Submit" value="Submit">
			<input type="hidden" name="user_token" value="token-123">
		</form>
	</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if !strings.Contains(r.Header.Get("Cookie"), "PHPSESSID=dvwa-session") {
				http.Error(w, "missing session", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(formHTML))
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "unexpected method", http.StatusBadRequest)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if got := r.Form.Get("ip"); got != "127.0.0.1; id" {
			http.Error(w, "missing command payload", http.StatusBadRequest)
			return
		}
		if got := r.Form.Get("Submit"); got != "Submit" {
			http.Error(w, "missing submit control", http.StatusBadRequest)
			return
		}
		if got := r.Form.Get("user_token"); got != "token-123" {
			http.Error(w, "missing hidden token", http.StatusBadRequest)
			return
		}
		sawFormReplay = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("uid=33(www-data) gid=33(www-data)"))
	}))
	defer srv.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "explorer.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	scanID, err := db.CreateScan(srv.URL+"/vulnerabilities/exec/", `{}`)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	insertExplorerTestTrafficForURL(t, db, scanID, srv.URL+"/vulnerabilities/exec/",
		map[string]string{"Cookie": "PHPSESSID=dvwa-session"},
		formHTML)
	followUpID, err := db.InsertFollowUp(scanID, store.FollowUp{
		SourceAgent: "analyzer",
		Action:      "probe_param",
		URL:         srv.URL + "/vulnerabilities/exec/",
		Params: map[string]any{
			"param":  "ip",
			"values": []any{"127.0.0.1; id"},
		},
	})
	if err != nil {
		t.Fatalf("insert follow-up: %v", err)
	}
	tasks, err := db.PopPendingFollowUps(scanID, 1)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("claim follow-up: tasks=%d err=%v", len(tasks), err)
	}

	explorer := &ExplorerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		client: srv.Client(),
	}
	explorer.runProbeParam(context.Background(), tasks[0])

	if !sawFormReplay {
		t.Fatal("server never received form replay with payload, submit control, and hidden token")
	}
	var requestHeaders string
	var requestBody []byte
	if err := db.Conn().QueryRow(`
		SELECT request_headers, request_body
		FROM traffic
		WHERE scan_id = ? AND source_action_id = ? AND method = 'POST' AND status_code = 200
		LIMIT 1`, scanID, followUpID).Scan(&requestHeaders, &requestBody); err != nil {
		t.Fatalf("form replay traffic not stored: %v", err)
	}
	body := string(requestBody)
	if !strings.Contains(requestHeaders, "PHPSESSID=dvwa-session") {
		t.Fatalf("form replay did not preserve session cookie: %s", requestHeaders)
	}
	for _, want := range []string{"ip=127.0.0.1%3B+id", "Submit=Submit", "user_token=token-123"} {
		if !strings.Contains(body, want) {
			t.Fatalf("form replay body = %q, missing %q", body, want)
		}
	}

	var vulnType, confidence, pocRequest string
	if err := db.Conn().QueryRow(`
		SELECT vuln_type, confidence, poc_request
		FROM findings
		WHERE scan_id = ? AND vuln_type = 'command_injection'
		LIMIT 1`, scanID).Scan(&vulnType, &confidence, &pocRequest); err != nil {
		t.Fatalf("deterministic command-injection finding not stored: %v", err)
	}
	if vulnType != "command_injection" || confidence != string(types.ConfidenceConfirmed) {
		t.Fatalf("finding = (%q,%q), want confirmed command_injection", vulnType, confidence)
	}
	if !strings.Contains(pocRequest, "POST /vulnerabilities/exec/ HTTP/1.1") ||
		!strings.Contains(pocRequest, "ip=127.0.0.1%3B+id") {
		t.Fatalf("PoC request missing form payload: %s", pocRequest)
	}
}

func TestProbeParamReplaysObservedGETFormWithHiddenTokenAndSubmit(t *testing.T) {
	const formHTML = `<html><body>
		<form action="#" method="GET">
			<input type="text" name="id">
			<input type="submit" name="Submit" value="Submit">
			<input type="hidden" name="user_token" value="token-456">
		</form>
	</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(formHTML))
			return
		}
		if got := r.URL.Query().Get("id"); got != "1' OR '1'='1" {
			http.Error(w, "missing SQLi payload", http.StatusBadRequest)
			return
		}
		if got := r.URL.Query().Get("Submit"); got != "Submit" {
			http.Error(w, "missing submit control", http.StatusBadRequest)
			return
		}
		if got := r.URL.Query().Get("user_token"); got != "token-456" {
			http.Error(w, "missing hidden token", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<b>Fatal error</b>: Uncaught mysqli_sql_exception: You have an error in your SQL syntax near \"'\""))
	}))
	defer srv.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "explorer.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	scanID, err := db.CreateScan(srv.URL+"/vulnerabilities/sqli/", `{}`)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	insertExplorerTestTrafficForURL(t, db, scanID, srv.URL+"/vulnerabilities/sqli/",
		map[string]string{"Cookie": "PHPSESSID=dvwa-session"},
		formHTML)
	followUpID, err := db.InsertFollowUp(scanID, store.FollowUp{
		SourceAgent: "analyzer",
		Action:      "probe_param",
		URL:         srv.URL + "/vulnerabilities/sqli/",
		Params: map[string]any{
			"param":  "id",
			"values": []any{"1' OR '1'='1"},
		},
	})
	if err != nil {
		t.Fatalf("insert follow-up: %v", err)
	}
	tasks, err := db.PopPendingFollowUps(scanID, 1)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("claim follow-up: tasks=%d err=%v", len(tasks), err)
	}

	explorer := &ExplorerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		client: srv.Client(),
	}
	explorer.runProbeParam(context.Background(), tasks[0])

	var storedURL string
	if err := db.Conn().QueryRow(`
		SELECT url
		FROM traffic
		WHERE scan_id = ? AND source_action_id = ? AND method = 'GET' AND status_code = 200
		ORDER BY id DESC
		LIMIT 1`, scanID, followUpID).Scan(&storedURL); err != nil {
		t.Fatalf("form GET traffic not stored: %v", err)
	}
	parsed, err := url.Parse(storedURL)
	if err != nil {
		t.Fatalf("parse stored URL: %v", err)
	}
	q := parsed.Query()
	if q.Get("id") != "1' OR '1'='1" || q.Get("Submit") != "Submit" || q.Get("user_token") != "token-456" {
		t.Fatalf("stored URL query = %s, want payload + submit + token", parsed.RawQuery)
	}

	var vulnType, confidence, pocRequest string
	if err := db.Conn().QueryRow(`
		SELECT vuln_type, confidence, poc_request
		FROM findings
		WHERE scan_id = ? AND vuln_type = 'sqli'
		LIMIT 1`, scanID).Scan(&vulnType, &confidence, &pocRequest); err != nil {
		t.Fatalf("deterministic SQLi finding not stored: %v", err)
	}
	if vulnType != "sqli" || confidence != string(types.ConfidenceConfirmed) {
		t.Fatalf("finding = (%q,%q), want confirmed sqli", vulnType, confidence)
	}
	if !strings.Contains(pocRequest, "GET /vulnerabilities/sqli/?") ||
		!strings.Contains(pocRequest, "Submit=Submit") ||
		!strings.Contains(pocRequest, "id=1%27+OR+%271%27%3D%271") {
		t.Fatalf("PoC request missing form GET payload: %s", pocRequest)
	}
}

func TestProbeParamSendsRawXMLPOSTForWebGoatXXE(t *testing.T) {
	xmlPayload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><comment><text>&xxe;</text></comment>`
	var sawRawXML bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "unexpected method", http.StatusBadRequest)
			return
		}
		bodyBytes, _ := io.ReadAll(r.Body)
		if strings.Contains(r.Header.Get("Content-Type"), "application/xml") && string(bodyBytes) == xmlPayload {
			sawRawXML = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"lessonCompleted":true}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"lessonCompleted":false}`))
	}))
	defer srv.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "explorer.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	scanID, err := db.CreateScan(srv.URL+"/WebGoat/start.mvc", `{}`)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	followUpID, err := db.InsertFollowUp(scanID, store.FollowUp{
		SourceAgent: "analyzer",
		Action:      "probe_param",
		URL:         srv.URL + "/WebGoat/xxe/simple",
		Params: map[string]any{
			"param":  "text",
			"values": []any{xmlPayload},
		},
	})
	if err != nil {
		t.Fatalf("insert follow-up: %v", err)
	}
	tasks, err := db.PopPendingFollowUps(scanID, 1)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("claim follow-up: tasks=%d err=%v", len(tasks), err)
	}

	explorer := &ExplorerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		client: srv.Client(),
	}
	explorer.runProbeParam(context.Background(), tasks[0])

	if !sawRawXML {
		t.Fatal("server never received raw XML application/xml POST")
	}
	var requestHeaders string
	var requestBody []byte
	if err := db.Conn().QueryRow(`
		SELECT request_headers, request_body
		FROM traffic
		WHERE scan_id = ? AND source_action_id = ? AND method = 'POST' AND status_code = 200
		  AND request_headers LIKE '%application/xml%'
		LIMIT 1`, scanID, followUpID).Scan(&requestHeaders, &requestBody); err != nil {
		t.Fatalf("raw XML traffic not stored: %v", err)
	}
	if !strings.Contains(requestHeaders, "application/xml") {
		t.Fatalf("raw XML request headers = %s", requestHeaders)
	}
	if got := string(requestBody); got != xmlPayload {
		t.Fatalf("raw XML body = %q, want %q", got, xmlPayload)
	}
}

func insertExplorerTestTraffic(
	t *testing.T,
	db *store.DB,
	scanID int64,
	rawURL string,
	headers map[string]string,
	body string,
) {
	t.Helper()
	headerJSON, err := json.Marshal(headers)
	if err != nil {
		t.Fatalf("marshal request headers: %v", err)
	}
	_, err = db.Conn().Exec(`
		INSERT INTO traffic (
			scan_id, method, url, host, path, query,
			request_headers, request_body,
			status_code, response_headers, response_body,
			content_type, response_size, endpoint_hash, is_filtered
		) VALUES (?, 'POST', ?, 'example.test', '/orders/41', '', ?, ?,
			200, '{}', '{}', 'application/json', 2, 'POST:/orders/{id}', FALSE)`,
		scanID, rawURL, string(headerJSON), []byte(body))
	if err != nil {
		t.Fatalf("insert traffic for scan %d: %v", scanID, err)
	}
}

func insertExplorerTestTrafficForURL(
	t *testing.T,
	db *store.DB,
	scanID int64,
	rawURL string,
	headers map[string]string,
	body string,
) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse test url: %v", err)
	}
	headerJSON, err := json.Marshal(headers)
	if err != nil {
		t.Fatalf("marshal request headers: %v", err)
	}
	_, err = db.Conn().Exec(`
		INSERT INTO traffic (
			scan_id, method, url, host, path, query,
			request_headers, request_body,
			status_code, response_headers, response_body,
			content_type, response_size, endpoint_hash, is_filtered
		) VALUES (?, 'GET', ?, ?, ?, ?, ?, NULL,
			200, '{}', ?, 'text/html', ?, 'GET:/WebGoat/start.mvc', FALSE)`,
		scanID, rawURL, parsed.Host, parsed.Path, parsed.RawQuery, string(headerJSON), []byte(body), len(body))
	if err != nil {
		t.Fatalf("insert auth traffic for scan %d: %v", scanID, err)
	}
}

func assertExplorerAuthHeader(t *testing.T, headers map[string]string, want string) {
	t.Helper()
	if got := headers["Authorization"]; got != want {
		t.Fatalf("got authorization %q from headers %v, want %q", got, headers, want)
	}
}

func TestExplorerIDORValueFilterRejectsSentinelValues(t *testing.T) {
	values := cleanIDORProbeValuesAny([]any{"NaN", "undefined", "7", "8", "[object Object]", float64(9), "7"})
	if got, want := strings.Join(values, ","), "7,8,9"; got != want {
		t.Fatalf("values = %q, want %q", got, want)
	}
}
