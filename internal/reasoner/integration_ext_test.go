// Additional end-to-end integration tests covering the executor
// primitives the original integration_test.go didn't reach:
//
//   - jwt_unsigned (alg:none acceptance)
//   - jwt_weak_secret (HS256 brute-force against wordlist)
//   - idor_sequential_id (path-tail IDOR with baseline-diff)
//   - chain_auth_then_access (executable chain: login → token → IDOR)
//
// Same test harness as integration_test.go: mock LLM returning canned JSON
// plans, httptest.Server target, real store.DB for findings.
package reasoner

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

// jwtTestServer returns an httptest.Server with three auth-style routes:
//   - /whoami-unsigned: accepts JWT with alg:none in the Authorization
//     header, echoes the claims. Classic alg:none bug.
//   - /whoami-hs256: accepts an HS256 JWT signed with secret "secret".
//   - /api/users/<id>: returns different JSON body per id so IDOR via
//     path-tail mutation is detectable.
func jwtTestServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/whoami-unsigned", func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(authz, "Bearer ")
		parts := strings.Split(tok, ".")
		w.Header().Set("Content-Type", "application/json")
		if len(parts) != 3 {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"no token"}`))
			return
		}
		hdr, err := base64URL.DecodeString(parts[0])
		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"bad header"}`))
			return
		}
		var h map[string]string
		if err := json.Unmarshal(hdr, &h); err != nil {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"parse header"}`))
			return
		}
		// The actual bug we're emulating: server only checks alg field
		// and happily accepts "none" without verifying a signature.
		if h["alg"] != "none" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"signature required"}`))
			return
		}
		payloadB, _ := base64URL.DecodeString(parts[1])
		w.WriteHeader(200)
		w.Write([]byte(`{"user":` + string(payloadB) + `}`))
	})

	mux.HandleFunc("/whoami-hs256", func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(authz, "Bearer ")
		parts := strings.Split(tok, ".")
		w.Header().Set("Content-Type", "application/json")
		if len(parts) != 3 {
			w.WriteHeader(401)
			return
		}
		sig, err := base64URL.DecodeString(parts[2])
		if err != nil {
			w.WriteHeader(401)
			return
		}
		m := hmac.New(sha256.New, []byte("secret"))
		m.Write([]byte(parts[0] + "." + parts[1]))
		if !hmac.Equal(m.Sum(nil), sig) {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"user":"authenticated"}`))
	})

	// /api/users/<id>: different body per id so IDOR confirms.
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := strings.TrimPrefix(r.URL.Path, "/api/users/")
		// Return deliberately-divergent sizes per id, so the IDOR primitive's
		// baseline-diff guard triggers (identifier 1 vs 2 produce wildly
		// different bodies, identifier AOBTDnope999999 produces a 404).
		switch id {
		case "1":
			w.WriteHeader(200)
			w.Write([]byte(`{"id":1,"email":"admin@target","role":"admin","notes":"` +
				strings.Repeat("x", 200) + `"}`))
		case "2":
			w.WriteHeader(200)
			w.Write([]byte(`{"id":2,"email":"b@target","role":"user"}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"not found"}`))
		}
	})

	// Login endpoint used by the chain_auth_then_access test.
	mux.HandleFunc("/rest/user/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var body struct{ Email, Password string }
		json.NewDecoder(r.Body).Decode(&body)
		if body.Email == "demo" && body.Password == "demo" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			// The key thing: include an eyJ-looking token the executor will
			// extract and replay on step 2.
			w.Write([]byte(`{"authentication":{"token":"` + chainTokenHS256() + `"}}`))
			return
		}
		w.WriteHeader(401)
	})

	// API endpoint used by chain step 2 — auth required + IDOR-able.
	mux.HandleFunc("/api/basket/", func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasPrefix(authz, "Bearer ") || len(authz) < 20 {
			w.WriteHeader(401)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/basket/")
		// Vary by id so baseline-diff confirms.
		switch id {
		case "1":
			w.Write([]byte(`{"basket":{"id":1,"items":[{"name":"apple juice"}]}}`))
		case "2":
			w.Write([]byte(`{"basket":{"id":2,"items":[{"name":"eggfruit"},{"name":"raspberry"}, {"name":"lemon"},{"name":"melon"}]}}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"not found"}`))
		}
	})

	return httptest.NewServer(mux)
}

// chainTokenHS256 returns a static JWT-shaped token the login handler
// issues. The chain executor only cares that the response body contains
// an `eyJ...` token it can extract; the signature isn't re-verified here.
func chainTokenHS256() string {
	return "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.sig"
}

// bolaOwnershipTestServer returns a two-persona API:
//   - Alice owns order 1
//   - Bob owns order 2
//   - anonymous requests are blocked
//   - when enforceOwnerCheck=false, any authenticated user can read any order
func bolaOwnershipTestServer(t *testing.T, enforceOwnerCheck bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	type loginBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	tokens := map[string]string{
		"alice-token": "1",
		"bob-token":   "2",
	}
	creds := map[string]struct {
		pass  string
		token string
		owner string
	}{
		"alice@example.test": {pass: "alicepass", token: "alice-token", owner: "1"},
		"bob@example.test":   {pass: "bobpass", token: "bob-token", owner: "2"},
	}
	orders := map[string]struct {
		owner string
		body  string
	}{
		"1": {owner: "1", body: `{"order":{"id":1,"owner_id":1,"item":"apple juice","private_note":"alice-only"}}`},
		"2": {owner: "2", body: `{"order":{"id":2,"owner_id":2,"item":"raspberry juice","private_note":"bob-only"}}`},
	}

	mux.HandleFunc("/rest/user/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var body loginBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(400)
			return
		}
		account, ok := creds[body.Email]
		if !ok || account.pass != body.Password {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprintf(w, `{"authentication":{"token":"%s"},"user":{"id":%s,"email":%q}}`,
			account.token, account.owner, body.Email)
	})

	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		authz := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		callerOwner := tokens[authz]
		w.Header().Set("Content-Type", "application/json")
		if callerOwner == "" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"auth required"}`))
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/orders/")
		order, ok := orders[id]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"not found"}`))
			return
		}
		if enforceOwnerCheck && callerOwner != order.owner {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(order.body))
	})

	return httptest.NewServer(mux)
}

func bolaTwoPersonaPlan(loginURL, objectAURL, objectBURL string) ProbePlan {
	return ProbePlan{
		Technique: "bola_two_persona_ownership",
		Target: ProbeTarget{
			URL:      loginURL,
			Method:   "POST",
			BodyType: "json",
			Headers: map[string]string{
				"bola_user_a":       "alice@example.test",
				"bola_pass_a":       "alicepass",
				"bola_owner_a":      "1",
				"bola_object_a_url": objectAURL,
				"bola_user_b":       "bob@example.test",
				"bola_pass_b":       "bobpass",
				"bola_owner_b":      "2",
				"bola_object_b_url": objectBURL,
			},
		},
		Payloads: []string{"two-persona-owner-readback"},
		Confirmation: ConfirmationRule{
			StatusCodes:  []int{200},
			BodyContains: []string{"owner_id", "order"},
			MinBodyBytes: 20,
		},
		Rationale:      "test: two-persona owner readback across orders",
		Confidence:     0.95,
		SourceReasoner: "AccessReasoner",
	}
}

func bolaOwnershipMutationTestServer(t *testing.T, enforceOwnerCheck bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	type loginBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	tokens := map[string]string{
		"alice-token": "1",
		"bob-token":   "2",
	}
	creds := map[string]struct {
		pass  string
		token string
		owner string
	}{
		"alice@example.test": {pass: "alicepass", token: "alice-token", owner: "1"},
		"bob@example.test":   {pass: "bobpass", token: "bob-token", owner: "2"},
	}
	orders := map[string]struct {
		owner string
		item  string
		note  string
	}{
		"1": {owner: "1", item: "apple juice", note: "alice-only"},
		"2": {owner: "2", item: "raspberry juice", note: "bob-only"},
	}

	mux.HandleFunc("/rest/user/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var body loginBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(400)
			return
		}
		account, ok := creds[body.Email]
		if !ok || account.pass != body.Password {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"authentication":{"token":"%s"},"user":{"id":%s,"email":%q}}`,
			account.token, account.owner, body.Email)
	})

	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		authz := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		callerOwner := tokens[authz]
		w.Header().Set("Content-Type", "application/json")
		if callerOwner == "" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"auth required"}`))
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/orders/")
		order, ok := orders[id]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"not found"}`))
			return
		}
		if enforceOwnerCheck && callerOwner != order.owner {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		if r.Method == http.MethodPatch {
			var patch struct {
				Note string `json:"note"`
			}
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil || patch.Note == "" {
				w.WriteHeader(400)
				return
			}
			order.note = patch.Note
			orders[id] = order
		} else if r.Method != http.MethodGet {
			w.WriteHeader(405)
			return
		}
		fmt.Fprintf(w, `{"order":{"id":%q,"owner_id":%q,"item":%q,"note":%q}}`,
			id, order.owner, order.item, order.note)
	})

	return httptest.NewServer(mux)
}

func bolaTwoPersonaMutationPlan(loginURL, objectAURL, objectBURL, mutationURL string) ProbePlan {
	return ProbePlan{
		Technique: "bola_two_persona_mutation",
		Target: ProbeTarget{
			URL:      loginURL,
			Method:   "POST",
			BodyType: "json",
			Headers: map[string]string{
				"bola_user_a":             "alice@example.test",
				"bola_pass_a":             "alicepass",
				"bola_owner_a":            "1",
				"bola_object_a_url":       objectAURL,
				"bola_user_b":             "bob@example.test",
				"bola_pass_b":             "bobpass",
				"bola_owner_b":            "2",
				"bola_object_b_url":       objectBURL,
				"bola_mutation_url":       mutationURL,
				"bola_mutation_method":    "PATCH",
				"bola_mutation_field":     "note",
				"bola_mutation_value":     "aobtd-proof",
				"bola_mutation_body_type": "json",
			},
		},
		Payloads: []string{"two-persona-owner-mutation"},
		Confirmation: ConfirmationRule{
			StatusCodes:  []int{200},
			BodyContains: []string{"aobtd-proof"},
		},
		Rationale:      "test: two-persona owner mutation across orders",
		Confidence:     0.9,
		SourceReasoner: "AccessReasoner",
	}
}

// ---------- jwt_unsigned ----------

func TestJWTUnsignedEndToEnd(t *testing.T) {
	srv := jwtTestServer(t)
	defer srv.Close()
	target := srv.URL
	db, scanID := testDB(t, target)

	whoamiURL := target + "/whoami-unsigned"

	// Reasoner proposes a jwt_unsigned plan with claim payloads.
	planJSON := fmt.Sprintf(`[
		{
			"technique":"jwt_unsigned",
			"target":{"url":%q,"method":"GET"},
			"payloads":[
				"{\"user\":\"admin\",\"role\":\"admin\"}"
			],
			"confirmation":{"status_codes":[200],"body_contains":["admin"]},
			"rationale":"test: alg:none bypass",
			"confidence":0.9
		}
	]`, whoamiURL)
	mock := &mockProvider{content: planJSON, inTokens: 400, outTokens: 80}

	// Use AuthReasoner as the vehicle (its allowlist includes jwt_unsigned).
	r := NewAuthReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		ScanID: scanID, Target: target,
		LoginEndpoints: []DiscoveredEndpoint{
			{URL: whoamiURL, Method: "GET", Path: "/whoami-unsigned"},
		},
		JWTSamples: []JWTSample{
			{Alg: "HS256", PayloadPreview: "{\"sub\":\"someone\"}", Source: whoamiURL},
		},
	}
	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 1 || plans[0].Technique != "jwt_unsigned" {
		t.Fatalf("expected 1 jwt_unsigned plan, got %+v", plans)
	}

	exec := NewExecutor(&http.Client{}, db, scanID, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	hit, err := exec.ExecutePlan(context.Background(), plans[0])
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if !hit {
		t.Fatal("alg:none should have been accepted by the test server")
	}
	var count int
	if err := db.Conn().QueryRow(
		`SELECT COUNT(*) FROM findings WHERE scan_id=? AND vuln_type='jwt_unsigned'`,
		scanID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected 1 jwt_unsigned finding, got %d (err=%v)", count, err)
	}
}

// ---------- jwt_weak_secret ----------

func TestJWTWeakSecretEndToEnd(t *testing.T) {
	srv := jwtTestServer(t)
	defer srv.Close()
	target := srv.URL
	db, scanID := testDB(t, target)

	// Build a valid HS256 token signed with "secret" — the same wordlist
	// entry the executor's primitive will try.
	hdr := base64URL.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64URL.EncodeToString([]byte(`{"sub":"admin"}`))
	m := hmac.New(sha256.New, []byte("secret"))
	m.Write([]byte(hdr + "." + payload))
	sig := base64URL.EncodeToString(m.Sum(nil))
	token := hdr + "." + payload + "." + sig

	whoamiURL := target + "/whoami-hs256"
	planJSON := fmt.Sprintf(`[
		{
			"technique":"jwt_weak_secret",
			"target":{"url":%q,"method":"GET"},
			"payloads":[%q],
			"confirmation":{"status_codes":[200]},
			"rationale":"test: weak HS256 secret",
			"confidence":0.85
		}
	]`, whoamiURL, token)
	mock := &mockProvider{content: planJSON, inTokens: 300, outTokens: 60}

	r := NewAuthReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		ScanID: scanID, Target: target,
		LoginEndpoints: []DiscoveredEndpoint{
			{URL: whoamiURL, Method: "GET", Path: "/whoami-hs256"},
		},
		JWTSamples: []JWTSample{
			{Alg: "HS256", PayloadPreview: "...", Source: whoamiURL},
		},
	}
	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 1 || plans[0].Technique != "jwt_weak_secret" {
		t.Fatalf("expected 1 jwt_weak_secret plan, got %+v", plans)
	}

	exec := NewExecutor(&http.Client{}, db, scanID, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	hit, err := exec.ExecutePlan(context.Background(), plans[0])
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if !hit {
		t.Fatal("wordlist-backed secret should have matched")
	}
	var count int
	if err := db.Conn().QueryRow(
		`SELECT COUNT(*) FROM findings WHERE scan_id=? AND vuln_type='jwt_weak_secret'`,
		scanID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected 1 jwt_weak_secret finding, got %d", count)
	}
}

func TestWeakCredentialsUsesObservedUsernameField(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Username string `json:"username"`
			Secret   string `json:"secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Username == "demo" && body.Secret == "demo" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"username-keyed-token"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, scanID := testDB(t, srv.URL)
	plan := ProbePlan{
		Technique: "weak_credentials",
		Target: ProbeTarget{
			URL:      srv.URL + "/api/session",
			Method:   "POST",
			BodyType: "json",
			Headers: map[string]string{
				"auth_username_field": "username",
				"auth_password_field": "secret",
			},
		},
		Payloads: []string{"demo:demo"},
		Confirmation: ConfirmationRule{
			StatusCodes:  []int{200},
			BodyContains: []string{"token"},
		},
		Rationale:      "test: observed login body uses username/secret fields",
		Confidence:     0.9,
		SourceReasoner: "AuthReasoner",
	}

	exec := NewExecutor(&http.Client{}, db, scanID, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	hit, err := exec.ExecutePlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if !hit {
		t.Fatal("weak_credentials should confirm with observed username/secret field names")
	}
}

func TestAuthReasonerFallsBackToDeterministicPlanOnFormatError(t *testing.T) {
	loginURL := "https://example.test/api/session"
	mock := &mockProvider{
		content:   `{"error":"Output must be a JSON array. Re-run the request to receive the plan as a JSON array."}`,
		inTokens:  120,
		outTokens: 16,
	}
	r := NewAuthReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		ScanID: 1, Target: "https://example.test",
		LoginEndpoints: []DiscoveredEndpoint{{
			URL:                loginURL,
			Method:             "POST",
			RequestContentType: "application/json",
			BodyFields:         []string{"username", "secret"},
		}},
		ObservedEmails: []string{"demo@example.test"},
	}
	plans, usage, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply returned error instead of deterministic fallback: %v", err)
	}
	if usage.InputTokens != 120 || usage.OutputTokens != 16 {
		t.Fatalf("usage=%+v, want model usage preserved", usage)
	}
	if len(plans) != 1 || plans[0].Technique != "weak_credentials" {
		t.Fatalf("expected deterministic weak credential plan, got %+v", plans)
	}
	if plans[0].Target.Headers["auth_username_field"] != "username" ||
		plans[0].Target.Headers["auth_password_field"] != "secret" {
		t.Fatalf("fallback did not preserve login fields: %+v", plans[0])
	}
	if plans[0].SourceReasoner != "AuthReasoner" {
		t.Fatalf("SourceReasoner=%q", plans[0].SourceReasoner)
	}
}

// ---------- idor_sequential_id ----------

func TestIDORSequentialIDEndToEnd(t *testing.T) {
	srv := jwtTestServer(t)
	defer srv.Close()
	target := srv.URL
	db, scanID := testDB(t, target)

	usersURL := target + "/api/users/1"
	planJSON := fmt.Sprintf(`[
		{
			"technique":"idor_sequential_id",
			"target":{"url":%q,"method":"GET","field":"path"},
			"payloads":["1","2","3","100"],
			"confirmation":{"status_codes":[200],"body_contains":["email"]},
			"rationale":"test: sequential ids in /api/users/:id",
			"confidence":0.85
		}
	]`, usersURL)
	mock := &mockProvider{content: planJSON, inTokens: 450, outTokens: 90}

	r := NewAccessReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		ScanID: scanID, Target: target,
		APIEndpoints: []DiscoveredEndpoint{
			{URL: usersURL, Method: "GET", Path: "/api/users/1"},
		},
	}
	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 1 || plans[0].Technique != "idor_sequential_id" {
		t.Fatalf("expected 1 idor plan, got %+v", plans)
	}

	exec := NewExecutor(&http.Client{}, db, scanID, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	hit, err := exec.ExecutePlan(context.Background(), plans[0])
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if !hit {
		t.Fatal("IDOR primitive should have confirmed per-id response difference")
	}
	var count int
	if err := db.Conn().QueryRow(
		`SELECT COUNT(*) FROM findings WHERE scan_id=? AND vuln_type='idor'`,
		scanID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected 1 idor finding, got %d", count)
	}
}

// ---------- bola_two_persona_ownership ----------

func TestBOLATwoPersonaOwnershipEndToEnd(t *testing.T) {
	srv := bolaOwnershipTestServer(t, false)
	defer srv.Close()
	target := srv.URL
	db, scanID := testDB(t, target)

	loginURL := target + "/rest/user/login"
	objectAURL := target + "/api/orders/1"
	objectBURL := target + "/api/orders/2"

	llmPlan := bolaTwoPersonaPlan(loginURL, objectAURL, objectBURL)
	llmPlan.SourceReasoner = ""
	planBytes, _ := json.Marshal([]ProbePlan{llmPlan})
	mock := &mockProvider{content: string(planBytes), inTokens: 700, outTokens: 220}

	r := NewAccessReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		ScanID: scanID, Target: target,
		LoginEndpoints: []DiscoveredEndpoint{
			{URL: loginURL, Method: "POST", Path: "/rest/user/login"},
		},
		APIEndpoints: []DiscoveredEndpoint{
			{URL: objectAURL, Method: "GET", Path: "/api/orders/1"},
			{URL: objectBURL, Method: "GET", Path: "/api/orders/2"},
		},
	}
	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 1 || plans[0].Technique != "bola_two_persona_ownership" {
		t.Fatalf("expected 1 bola_two_persona_ownership plan, got %+v", plans)
	}

	exec := NewExecutor(&http.Client{}, db, scanID, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	hit, err := exec.ExecutePlan(context.Background(), plans[0])
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if !hit {
		t.Fatal("two-persona BOLA primitive should confirm A can read B-owned order")
	}

	var count int
	var evidence, endpoint string
	if err := db.Conn().QueryRow(
		`SELECT COUNT(*), COALESCE(MAX(evidence),''), COALESCE(MAX(endpoint_id),'') FROM findings WHERE scan_id=? AND vuln_type='bola'`,
		scanID).Scan(&count, &evidence, &endpoint); err != nil {
		t.Fatalf("query bola finding: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 bola finding, got %d", count)
	}
	if endpoint != "GET "+objectBURL {
		t.Fatalf("endpoint=%q, want GET %s", endpoint, objectBURL)
	}
	for _, want := range []string{"Positive control B→B", "Positive control A→A", "Anonymous control", "Attack A→B", "owner proof"} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("finding evidence missing %q:\n%s", want, evidence)
		}
	}
}

func TestBOLATwoPersonaMutationEndToEnd(t *testing.T) {
	srv := bolaOwnershipMutationTestServer(t, false)
	defer srv.Close()
	target := srv.URL
	db, scanID := testDB(t, target)

	loginURL := target + "/rest/user/login"
	objectAURL := target + "/api/orders/1"
	objectBURL := target + "/api/orders/2"
	mutationURL := objectBURL

	llmPlan := bolaTwoPersonaMutationPlan(loginURL, objectAURL, objectBURL, mutationURL)
	llmPlan.SourceReasoner = ""
	planBytes, _ := json.Marshal([]ProbePlan{llmPlan})
	mock := &mockProvider{content: string(planBytes), inTokens: 800, outTokens: 260}

	r := NewAccessReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		ScanID: scanID, Target: target,
		LoginEndpoints: []DiscoveredEndpoint{
			{URL: loginURL, Method: "POST", Path: "/rest/user/login"},
		},
		APIEndpoints: []DiscoveredEndpoint{
			{URL: objectAURL, Method: "GET", Path: "/api/orders/1"},
			{URL: objectBURL, Method: "GET", Path: "/api/orders/2"},
			{URL: mutationURL, Method: "PATCH", Path: "/api/orders/2", BodyFields: []string{"note"}},
		},
	}
	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 1 || plans[0].Technique != "bola_two_persona_mutation" {
		t.Fatalf("expected 1 bola_two_persona_mutation plan, got %+v", plans)
	}

	exec := NewExecutor(&http.Client{}, db, scanID, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	hit, err := exec.ExecutePlan(context.Background(), plans[0])
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if !hit {
		t.Fatal("two-persona BOLA mutation primitive should confirm A can mutate B-owned order")
	}

	var count int
	var evidence, endpoint string
	if err := db.Conn().QueryRow(
		`SELECT COUNT(*), COALESCE(MAX(evidence),''), COALESCE(MAX(endpoint_id),'') FROM findings WHERE scan_id=? AND vuln_type='bola'`,
		scanID).Scan(&count, &evidence, &endpoint); err != nil {
		t.Fatalf("query bola finding: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 bola finding, got %d", count)
	}
	if endpoint != "PATCH "+mutationURL {
		t.Fatalf("endpoint=%q, want PATCH %s", endpoint, mutationURL)
	}
	for _, want := range []string{"Two-persona BOLA mutation confirmation", "Attack A→B mutation", "aobtd-proof", "owner proof"} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("finding evidence missing %q:\n%s", want, evidence)
		}
	}
}

func TestAccessReasonerHydratesBOLAPersonaSecretsOutOfBand(t *testing.T) {
	target := "https://example.test"
	loginURL := target + "/rest/user/login"
	objectAURL := target + "/api/orders/1"
	objectBURL := target + "/api/orders/2"
	planJSON := fmt.Sprintf(`[
		{
			"technique":"bola_two_persona_ownership",
			"target":{
				"url":%q,
				"method":"POST",
				"body_type":"json",
				"headers":{
					"bola_user_a":"alice@example.test",
					"bola_pass_a":"<provided-secret>",
					"bola_owner_a":"1",
					"bola_object_a_url":%q,
					"bola_user_b":"bob@example.test",
					"bola_pass_b":"<provided-secret>",
					"bola_owner_b":"2",
					"bola_object_b_url":%q
				}
			},
			"payloads":["two-persona-owner-readback"],
			"confirmation":{"status_codes":[200],"body_contains":["owner_id"]},
			"rationale":"test: configured personas",
			"confidence":0.9
		}
	]`, loginURL, objectAURL, objectBURL)
	mock := &mockProvider{content: planJSON, inTokens: 700, outTokens: 220}
	r := NewAccessReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		ScanID: 1, Target: target,
		LoginEndpoints: []DiscoveredEndpoint{{URL: loginURL, Method: "POST", Path: "/rest/user/login"}},
		APIEndpoints: []DiscoveredEndpoint{
			{URL: objectAURL, Method: "GET", Path: "/api/orders/1"},
			{URL: objectBURL, Method: "GET", Path: "/api/orders/2"},
		},
		AuthPersonas: []AuthPersona{
			{Label: "primary", LoginURL: loginURL, Username: "alice@example.test", Password: "alice-secret", OwnerMarker: "1", ObjectURL: objectAURL},
			{Label: "secondary", LoginURL: loginURL, Username: "bob@example.test", Password: "bob-secret", OwnerMarker: "2", ObjectURL: objectBURL},
		},
	}
	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %+v", plans)
	}
	if strings.Contains(mock.lastUser, "alice-secret") || strings.Contains(mock.lastUser, "bob-secret") {
		t.Fatalf("AccessReasoner leaked persona password into LLM prompt:\n%s", mock.lastUser)
	}
	if !strings.Contains(mock.lastUser, "provided out-of-band") {
		t.Fatalf("AccessReasoner prompt did not explain out-of-band persona secrets:\n%s", mock.lastUser)
	}
	if got := plans[0].Target.Headers["bola_pass_a"]; got != "alice-secret" {
		t.Fatalf("bola_pass_a = %q, want hydrated secret", got)
	}
	if got := plans[0].Target.Headers["bola_pass_b"]; got != "bob-secret" {
		t.Fatalf("bola_pass_b = %q, want hydrated secret", got)
	}
}

func TestAccessReasonerEmitsConfiguredBOLAPlanWithoutLLM(t *testing.T) {
	target := "https://example.test"
	loginURL := target + "/rest/user/login"
	objectAURL := target + "/rest/basket/7"
	objectBURL := target + "/rest/basket/8"
	r := NewAccessReasoner(nil, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		ScanID: 1, Target: target,
		AuthPersonas: []AuthPersona{
			{Label: "primary", LoginURL: loginURL, Username: "alice@example.test", Password: "alice-secret", OwnerMarker: "24", ObjectURL: objectAURL},
			{Label: "secondary", LoginURL: loginURL, Username: "bob@example.test", Password: "bob-secret", OwnerMarker: "25", ObjectURL: objectBURL},
		},
	}
	plans, usage, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if usage.InputTokens != 0 || usage.OutputTokens != 0 {
		t.Fatalf("usage = %+v, want zero for deterministic fallback", usage)
	}
	if len(plans) != 1 || plans[0].Technique != "bola_two_persona_ownership" {
		t.Fatalf("expected deterministic BOLA plan, got %+v", plans)
	}
	if plans[0].SourceReasoner != "AccessReasoner" ||
		plans[0].Target.Headers["bola_pass_a"] != "alice-secret" ||
		plans[0].Target.Headers["bola_pass_b"] != "bob-secret" {
		t.Fatalf("configured BOLA plan not hydrated/source-tagged: %+v", plans[0])
	}
}

func TestAccessReasonerEmitsConfiguredBOLAMutationPlanFromObservedEndpoint(t *testing.T) {
	target := "https://example.test"
	loginURL := target + "/rest/user/login"
	objectAURL := target + "/api/orders/7"
	objectBURL := target + "/api/orders/8"
	r := NewAccessReasoner(nil, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		ScanID: 1, Target: target,
		APIEndpoints: []DiscoveredEndpoint{
			{URL: objectBURL, Method: "PATCH", Path: "/api/orders/8", RequestContentType: "application/json", BodyFields: []string{"owner_id", "note"}},
		},
		AuthPersonas: []AuthPersona{
			{Label: "primary", LoginURL: loginURL, Username: "alice@example.test", Password: "alice-secret", OwnerMarker: "7", ObjectURL: objectAURL},
			{Label: "secondary", LoginURL: loginURL, Username: "bob@example.test", Password: "bob-secret", OwnerMarker: "8", ObjectURL: objectBURL},
		},
	}
	plans, usage, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if usage.InputTokens != 0 || usage.OutputTokens != 0 {
		t.Fatalf("usage = %+v, want zero for deterministic fallback", usage)
	}
	if len(plans) != 2 {
		t.Fatalf("expected read + mutation plans, got %+v", plans)
	}
	mutation := plans[1]
	if mutation.Technique != "bola_two_persona_mutation" {
		t.Fatalf("second technique=%q, want bola_two_persona_mutation in %+v", mutation.Technique, plans)
	}
	if got := mutation.Target.Headers["bola_mutation_field"]; got != "note" {
		t.Fatalf("mutation field=%q, want safe field note", got)
	}
	if got := mutation.Target.Headers["bola_mutation_url"]; got != objectBURL {
		t.Fatalf("mutation url=%q, want %s", got, objectBURL)
	}
	if got := mutation.Target.Headers["bola_mutation_body_type"]; got != "json" {
		t.Fatalf("mutation body type=%q, want json", got)
	}
}

func TestAccessReasonerKeepsConfiguredBOLAPlanWhenModelReturnsFormatError(t *testing.T) {
	target := "https://example.test"
	loginURL := target + "/rest/user/login"
	objectAURL := target + "/api/orders/100"
	objectBURL := target + "/api/orders/200"
	mock := &mockProvider{
		content:   `{"error":"Output must be a JSON array. Re-run the request to receive the plan as a JSON array."}`,
		inTokens:  250,
		outTokens: 20,
	}
	r := NewAccessReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		ScanID: 1, Target: target,
		APIEndpoints: []DiscoveredEndpoint{{URL: objectAURL, Method: "GET"}},
		AuthPersonas: []AuthPersona{
			{Label: "primary", LoginURL: loginURL, Username: "alice@example.test", Password: "alice-secret", OwnerMarker: "user-1", ObjectURL: objectAURL},
			{Label: "secondary", LoginURL: loginURL, Username: "bob@example.test", Password: "bob-secret", OwnerMarker: "user-2", ObjectURL: objectBURL},
		},
	}

	plans, usage, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply returned parse error instead of deterministic plan: %v", err)
	}
	if usage.InputTokens != 250 || usage.OutputTokens != 20 {
		t.Fatalf("usage = %+v, want model usage preserved", usage)
	}
	if len(plans) != 1 || plans[0].Technique != "bola_two_persona_ownership" {
		t.Fatalf("expected configured BOLA plan, got %+v", plans)
	}
	if plans[0].Target.Headers["bola_object_b_url"] != objectBURL {
		t.Fatalf("configured plan lost secondary object URL: %+v", plans[0])
	}
}

func TestBOLATwoPersonaOwnershipRequiresCrossOwnerReadback(t *testing.T) {
	srv := bolaOwnershipTestServer(t, true)
	defer srv.Close()
	target := srv.URL
	db, scanID := testDB(t, target)

	plan := bolaTwoPersonaPlan(
		target+"/rest/user/login",
		target+"/api/orders/1",
		target+"/api/orders/2",
	)
	exec := NewExecutor(&http.Client{}, db, scanID, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	hit, err := exec.ExecutePlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if hit {
		t.Fatal("BOLA should not confirm when the server enforces object ownership")
	}
	var count int
	if err := db.Conn().QueryRow(
		`SELECT COUNT(*) FROM findings WHERE scan_id=? AND vuln_type='bola'`,
		scanID).Scan(&count); err != nil {
		t.Fatalf("query bola finding: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no bola findings, got %d", count)
	}
}

func TestBOLATwoPersonaMutationRequiresCrossOwnerWrite(t *testing.T) {
	srv := bolaOwnershipMutationTestServer(t, true)
	defer srv.Close()
	target := srv.URL
	db, scanID := testDB(t, target)

	plan := bolaTwoPersonaMutationPlan(
		target+"/rest/user/login",
		target+"/api/orders/1",
		target+"/api/orders/2",
		target+"/api/orders/2",
	)
	exec := NewExecutor(&http.Client{}, db, scanID, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	hit, err := exec.ExecutePlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if hit {
		t.Fatal("BOLA mutation should not confirm when the server enforces object ownership")
	}
	var count int
	if err := db.Conn().QueryRow(
		`SELECT COUNT(*) FROM findings WHERE scan_id=? AND vuln_type='bola'`,
		scanID).Scan(&count); err != nil {
		t.Fatalf("query bola finding: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no bola findings, got %d", count)
	}
}

// ---------- chain_auth_then_access (executable chain) ----------

// TestChainAuthThenAccessEndToEnd covers the most ambitious primitive:
// ChainReasoner emits an executable chain plan, the Executor actually
// performs the login, captures the token, and replays it against a second
// endpoint with different IDs — all end-to-end.
func TestChainAuthThenAccessEndToEnd(t *testing.T) {
	srv := jwtTestServer(t)
	defer srv.Close()
	target := srv.URL
	db, scanID := testDB(t, target)

	loginURL := target + "/rest/user/login"

	// ChainReasoner plan: login with demo:demo, then IDOR /api/basket/.
	// Technically Target.URL is the login endpoint (step 1), and
	// Target.Headers carries the chain step-2 configuration.
	planJSON := fmt.Sprintf(`[
		{
			"technique":"chain_auth_then_access",
			"target":{
				"url":%q,
				"method":"POST",
				"body_type":"json",
				"headers":{
					"chain_auth_user":"demo",
					"chain_auth_pass":"demo",
					"chain_access_urls":%q
				}
			},
			"payloads":["1","2"],
			"confirmation":{"status_codes":[200],"body_contains":["basket"]},
			"rationale":"test: weak creds + IDOR basket",
			"confidence":0.9
		}
	]`, loginURL, target+"/api/basket/1")
	mock := &mockProvider{content: planJSON, inTokens: 800, outTokens: 320}

	// Pre-seed ingredient findings so ChainReasoner's fast-reject passes.
	db.InsertFinding(scanID, types.Finding{
		Title: "Weak credentials", Severity: types.SeverityCritical,
		Confidence: types.ConfidenceConfirmed, VulnType: "weak_credentials",
		EndpointID: "POST /rest/user/login",
	})
	db.InsertFinding(scanID, types.Finding{
		Title: "IDOR-shaped endpoint", Severity: types.SeverityHigh,
		Confidence: types.ConfidenceConfirmed, VulnType: "idor",
		EndpointID: "GET /api/basket/1",
	})

	r := NewChainReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev, err := BuildEvidence(context.Background(), db, scanID, target)
	if err != nil {
		t.Fatalf("BuildEvidence: %v", err)
	}
	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected 1 chain plan, got %d", len(plans))
	}
	if plans[0].Technique != "chain_auth_then_access" {
		t.Fatalf("technique=%q, want chain_auth_then_access", plans[0].Technique)
	}

	exec := NewExecutor(&http.Client{}, db, scanID, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	hit, err := exec.ExecutePlan(context.Background(), plans[0])
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if !hit {
		t.Fatal("executable chain should have: logged in → gotten token → replayed against basket with different ids → confirmed size-diff")
	}
	var count int
	if err := db.Conn().QueryRow(
		`SELECT COUNT(*) FROM findings WHERE scan_id=? AND vuln_type='chain_auth_then_access'`,
		scanID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected 1 chain_auth_then_access finding, got %d", count)
	}
}
