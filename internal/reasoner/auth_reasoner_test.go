package reasoner

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

// TestIsKnownTechnique covers the allowlist gate. Anything not in
// KnownTechniques must be rejected; anything in it must pass.
func TestIsKnownTechnique(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"weak_credentials", true},
		{"sqli_login_bypass", true},
		{"jwt_unsigned", true},
		{"jwt_weak_secret", true},
		{"password_reset_abuse", true},
		{"bola_two_persona_ownership", true},
		{"bola_two_persona_mutation", true},

		{"", false},
		{"session_role_flip", false}, // not emitted until an executor primitive exists
		{"xss", false},
		{"sqli_generic_FAKE", false},
		{"exec_command", false},
		{"Weak_Credentials", false}, // case-sensitive
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsKnownTechnique(tc.name); got != tc.want {
				t.Errorf("IsKnownTechnique(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestValidatePlans ensures safety filters reject: unknown techniques,
// fabricated URLs (not in evidence), missing payloads, missing
// confirmation rules.
func TestValidatePlans(t *testing.T) {
	ev := Evidence{
		LoginEndpoints: []DiscoveredEndpoint{
			{URL: "http://target.test/api/login", Method: "POST"},
		},
		APIEndpoints: []DiscoveredEndpoint{
			{URL: "http://target.test/api/Users", Method: "GET"},
		},
	}

	tests := []struct {
		name  string
		plan  ProbePlan
		valid bool
	}{
		{
			name: "valid weak_credentials plan",
			plan: ProbePlan{
				Technique: "weak_credentials",
				Target:    ProbeTarget{URL: "http://target.test/api/login", Method: "POST"},
				Payloads:  []string{"admin:admin"},
				Confirmation: ConfirmationRule{
					StatusCodes:  []int{200},
					BodyContains: []string{`"token"`},
				},
				Confidence: 0.8,
			},
			valid: true,
		},
		{
			name: "unknown technique rejected",
			plan: ProbePlan{
				Technique: "rce_shell_exec",
				Target:    ProbeTarget{URL: "http://target.test/api/login", Method: "POST"},
				Payloads:  []string{"`id`"},
				Confirmation: ConfirmationRule{
					BodyContains: []string{"uid="},
				},
			},
			valid: false,
		},
		{
			name: "fabricated URL rejected",
			plan: ProbePlan{
				Technique: "weak_credentials",
				Target:    ProbeTarget{URL: "http://target.test/hallucinated/login", Method: "POST"},
				Payloads:  []string{"a:b"},
				Confirmation: ConfirmationRule{
					BodyContains: []string{`"token"`},
				},
			},
			valid: false,
		},
		{
			name: "empty payloads rejected",
			plan: ProbePlan{
				Technique: "weak_credentials",
				Target:    ProbeTarget{URL: "http://target.test/api/login", Method: "POST"},
				Payloads:  []string{},
				Confirmation: ConfirmationRule{
					BodyContains: []string{`"token"`},
				},
			},
			valid: false,
		},
		{
			name: "no confirmation signal rejected",
			plan: ProbePlan{
				Technique:    "weak_credentials",
				Target:       ProbeTarget{URL: "http://target.test/api/login", Method: "POST"},
				Payloads:     []string{"a:b"},
				Confirmation: ConfirmationRule{},
			},
			valid: false,
		},
		{
			name: "empty target URL rejected",
			plan: ProbePlan{
				Technique: "weak_credentials",
				Target:    ProbeTarget{URL: "", Method: "POST"},
				Payloads:  []string{"a:b"},
				Confirmation: ConfirmationRule{
					BodyContains: []string{`"token"`},
				},
			},
			valid: false,
		},
		{
			name: "API endpoint URL accepted (cross-list match)",
			plan: ProbePlan{
				Technique: "weak_credentials",
				Target:    ProbeTarget{URL: "http://target.test/api/Users", Method: "GET"},
				Payloads:  []string{"x:y"},
				Confirmation: ConfirmationRule{
					StatusCodes: []int{200},
				},
			},
			valid: true,
		},
		{
			name: "out-of-range confidence normalised to 0.5",
			plan: ProbePlan{
				Technique: "weak_credentials",
				Target:    ProbeTarget{URL: "http://target.test/api/login", Method: "POST"},
				Payloads:  []string{"a:b"},
				Confirmation: ConfirmationRule{
					BodyContains: []string{`"token"`},
				},
				Confidence: 5.0,
			},
			valid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validatePlans([]ProbePlan{tc.plan}, ev)
			if tc.valid && len(got) != 1 {
				t.Fatalf("expected plan to pass validation, got %d plans", len(got))
			}
			if !tc.valid && len(got) != 0 {
				t.Fatalf("expected plan to be rejected, got %d plans", len(got))
			}
			if tc.valid && got[0].Confidence > 1.0 {
				t.Errorf("out-of-range confidence not normalised: %v", got[0].Confidence)
			}
		})
	}
}

func TestSelectHarmlessMutationFieldAvoidsOwnershipAndMoneyFields(t *testing.T) {
	got := selectHarmlessMutationField([]string{"owner_id", "price", "role", "note"})
	if got != "note" {
		t.Fatalf("selected field=%q, want note", got)
	}
	if got := selectHarmlessMutationField([]string{"owner_id", "price", "role"}); got != "" {
		t.Fatalf("selected dangerous field=%q, want empty", got)
	}
}

func TestTrimAPIEndpointsPrioritizesStateChangingBodyEndpoints(t *testing.T) {
	var eps []DiscoveredEndpoint
	for i := 0; i < 25; i++ {
		eps = append(eps, DiscoveredEndpoint{
			URL:    "https://example.test/api/noise/" + string(rune('a'+i)),
			Method: "GET",
			Path:   "/api/noise",
		})
	}
	important := DiscoveredEndpoint{
		URL:        "https://example.test/api/orders/8",
		Method:     "PATCH",
		Path:       "/api/orders/8",
		BodyFields: []string{"note"},
	}
	eps = append(eps, important)

	got := trimAPIEndpoints(eps, 20)
	if len(got) != 20 {
		t.Fatalf("trimmed len=%d, want 20", len(got))
	}
	if got[0].URL != important.URL {
		t.Fatalf("first endpoint=%+v, want important PATCH endpoint", got[0])
	}
}

func TestDeterministicAuthPlanInfersObservedLoginFields(t *testing.T) {
	ev := Evidence{
		LoginEndpoints: []DiscoveredEndpoint{{
			URL:                "https://example.test/api/session",
			Method:             "POST",
			RequestContentType: "application/json",
			BodyFields:         []string{"username", "secret"},
		}},
		ObservedEmails: []string{"demo@example.test"},
	}
	plans := deterministicAuthPlans(ev)
	if len(plans) != 1 {
		t.Fatalf("deterministic plans = %+v, want one", plans)
	}
	if plans[0].Technique != "weak_credentials" {
		t.Fatalf("technique=%q, want weak_credentials", plans[0].Technique)
	}
	if got := plans[0].Target.Headers["auth_username_field"]; got != "username" {
		t.Fatalf("username field=%q, want username", got)
	}
	if got := plans[0].Target.Headers["auth_password_field"]; got != "secret" {
		t.Fatalf("password field=%q, want secret", got)
	}
	if len(plans[0].Payloads) == 0 {
		t.Fatal("expected bounded default credential payloads")
	}
}

func TestDeterministicAuthPlansIncludeJWTUnsignedWithMinedIdentity(t *testing.T) {
	ev := Evidence{
		APIEndpoints: []DiscoveredEndpoint{{
			URL:                 "https://example.test/rest/user/whoami",
			Method:              "GET",
			Path:                "/rest/user/whoami",
			ResponseContentType: "application/json",
			AuthHeaders:         map[string]string{"Authorization": "Bearer original"},
		}},
		JWTSamples: []JWTSample{{
			Alg:            "RS256",
			PayloadPreview: `{"data":{"email":"admin@example.test","role":"admin"},"bid":1}`,
			Source:         "https://example.test/rest/user/login",
		}},
		ObservedEmails: []string{
			"customer@example.test",
			"jwtn3d@example.test",
		},
	}
	plans := deterministicAuthPlans(ev)
	var jwtPlan *ProbePlan
	for i := range plans {
		if plans[i].Technique == "jwt_unsigned" {
			jwtPlan = &plans[i]
			break
		}
	}
	if jwtPlan == nil {
		t.Fatalf("deterministic plans = %+v, want jwt_unsigned", plans)
	}
	if jwtPlan.Target.URL != "https://example.test/rest/user/whoami" {
		t.Fatalf("jwt target=%q", jwtPlan.Target.URL)
	}
	if len(jwtPlan.Payloads) == 0 || !strings.Contains(jwtPlan.Payloads[0], "admin@example.test") {
		t.Fatalf("first jwt payload should preserve identity from captured JWT, got %+v", jwtPlan.Payloads)
	}
	foundMined := false
	for _, payload := range jwtPlan.Payloads {
		if strings.Contains(payload, "jwtn3d@example.test") {
			foundMined = true
			break
		}
	}
	if !foundMined {
		t.Fatalf("jwt payloads did not include mined app identity: %+v", jwtPlan.Payloads)
	}
	if len(jwtPlan.Confirmation.BodyContains) != 1 || jwtPlan.Confirmation.BodyContains[0] != "{{jwt_identity}}" {
		t.Fatalf("jwt confirmation=%+v, want identity placeholder", jwtPlan.Confirmation)
	}
}

func TestAuthReasonerAppendsDeterministicJWTPlanAlongsideLLMWeakPlan(t *testing.T) {
	loginURL := "https://example.test/api/session"
	whoamiURL := "https://example.test/api/me"
	mock := &mockProvider{content: `[
		{
			"technique":"weak_credentials",
			"target":{"url":"` + loginURL + `","method":"POST","body_type":"json","headers":{"auth_username_field":"email","auth_password_field":"password"}},
			"payloads":["demo:demo"],
			"confirmation":{"status_codes":[200],"body_contains":["token"]},
			"rationale":"observed login endpoint",
			"confidence":0.8
		}
	]`}
	r := NewAuthReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		LoginEndpoints: []DiscoveredEndpoint{{
			URL:        loginURL,
			Method:     "POST",
			BodyFields: []string{"email", "password"},
		}},
		APIEndpoints: []DiscoveredEndpoint{{
			URL:                 whoamiURL,
			Method:              "GET",
			Path:                "/api/me",
			ResponseContentType: "application/json",
			AuthHeaders:         map[string]string{"Authorization": "Bearer original"},
		}},
		JWTSamples: []JWTSample{{
			Alg:            "RS256",
			PayloadPreview: `{"email":"admin@example.test","role":"admin"}`,
			Source:         loginURL,
		}},
		ObservedEmails: []string{"jwt-user@example.test"},
	}
	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var sawWeak, sawJWT bool
	for _, plan := range plans {
		if plan.Technique == "weak_credentials" {
			sawWeak = true
		}
		if plan.Technique == "jwt_unsigned" {
			sawJWT = true
		}
		if plan.SourceReasoner != "AuthReasoner" {
			t.Fatalf("plan source=%q", plan.SourceReasoner)
		}
	}
	if !sawWeak || !sawJWT {
		t.Fatalf("plans=%+v, want both LLM weak plan and deterministic jwt plan", plans)
	}
}

func TestAuthReasonerAppendsDeterministicJWTPlanAlongsideIncompleteLLMJWTPlan(t *testing.T) {
	whoamiURL := "https://example.test/rest/user/authentication-details/"
	mock := &mockProvider{content: `[
		{
			"technique":"jwt_unsigned",
			"target":{"url":"` + whoamiURL + `","method":"GET"},
			"payloads":["{\"data\":{\"id\":1,\"email\":\"admin@example.test\",\"role\":\"admin\"}}"],
			"confirmation":{"status_codes":[200],"body_contains":["admin@example.test"]},
			"rationale":"model tried the currently observed admin identity",
			"confidence":0.8
		}
	]`}
	r := NewAuthReasoner(mock, slog.New(slog.NewTextHandler(newDiscardWriter(), nil)))
	ev := Evidence{
		APIEndpoints: []DiscoveredEndpoint{{
			URL:                 whoamiURL,
			Method:              "GET",
			Path:                "/rest/user/authentication-details/",
			ResponseContentType: "application/json",
			AuthHeaders:         map[string]string{"Authorization": "Bearer original"},
		}},
		JWTSamples: []JWTSample{{
			Alg:            "RS256",
			PayloadPreview: `{"data":{"email":"admin@example.test","role":"admin"}}`,
			Source:         whoamiURL,
		}},
		ObservedEmails: []string{"jwtn3d@example.test"},
	}
	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	jwtCount := 0
	foundMined := false
	for _, plan := range plans {
		if plan.Technique != "jwt_unsigned" {
			continue
		}
		jwtCount++
		for _, payload := range plan.Payloads {
			if strings.Contains(payload, "jwtn3d@example.test") {
				foundMined = true
			}
		}
	}
	if jwtCount < 2 || !foundMined {
		t.Fatalf("plans=%+v, want model jwt plus deterministic jwt carrying mined identity", plans)
	}
}

// TestParsePlans covers markdown-fence handling and JSON array extraction
// from LLM responses that may include surrounding prose.
func TestParsePlans(t *testing.T) {
	bare := `[{"technique":"weak_credentials","target":{"url":"x"},"payloads":["a:b"],"confirmation":{"body_contains":["t"]},"confidence":0.7}]`
	single := `{"technique":"weak_credentials","target":{"url":"x"},"payloads":["a:b"],"confirmation":{"body_contains":["t"]},"confidence":0.7}`

	tests := []struct {
		name string
		in   string
		want int
	}{
		{"bare JSON array", bare, 1},
		{"fenced code block", "```json\n" + bare + "\n```", 1},
		{"fence without language", "```\n" + bare + "\n```", 1},
		{"leading prose", "Here are the plans:\n" + bare, 1},
		{"trailing prose", bare + "\n\nThese cover the main cases.", 1},
		{"duplicate top-level array", bare + ",\n" + bare, 1},
		{"array inside response object", `{"plans":` + bare + `,"note":"done"}`, 1},
		{"probe_plans response object", `{"probe_plans":` + bare + `,"note":"done"}`, 1},
		{"chains response object", `{"chains":` + bare + `,"note":"done"}`, 1},
		{"data response object", `{"data":` + bare + `,"note":"done"}`, 1},
		{"items response object", `{"items":` + bare + `,"note":"done"}`, 1},
		{"result response object", `{"result":` + bare + `,"note":"done"}`, 1},
		{"plan response object", `{"plan":` + single + `,"note":"done"}`, 1},
		{"chain response object", `{"chain":` + single + `,"note":"done"}`, 1},
		{"model format error object", `{"error":"Output must be a JSON array. Re-run the request to receive the plan as a JSON array."}`, 0},
		{"empty object abstention", `{}`, 0},
		{"single plan object", single, 1},
		{"single plan object with prose", "Here is the highest-value plan:\n" + single + "\nDone.", 1},
		{"indexed object", `{"[0]":` + single + `}`, 1},
		{"brackets inside strings", strings.Replace(bare, `"a:b"`, `"a:[b]"`, 1) + ` trailing [example]`, 1},
		{"empty array", "[]", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plans, err := parsePlans(tc.in)
			if err != nil {
				t.Fatalf("parsePlans(%q) error: %v", tc.in, err)
			}
			if len(plans) != tc.want {
				t.Errorf("got %d plans, want %d", len(plans), tc.want)
			}
		})
	}
}

// TestFindJWTsIn verifies the scanner can extract Bearer-token-looking
// substrings from headers / bodies.
func TestFindJWTsIn(t *testing.T) {
	sampleJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	tests := []struct {
		name string
		in   string
		want int
	}{
		{"Authorization header style",
			`{"Authorization":"Bearer ` + sampleJWT + `"}`, 1},
		{"set-cookie style",
			`Set-Cookie: token=` + sampleJWT + `; Path=/`, 1},
		{"inside JSON body",
			`{"authentication":{"token":"` + sampleJWT + `"}}`, 1},
		{"no JWT", `nothing here`, 0},
		{"malformed JWT (2 segments)",
			`Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0`, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findJWTsIn(tc.in)
			if len(got) != tc.want {
				t.Errorf("findJWTsIn got %d tokens, want %d", len(got), tc.want)
			}
		})
	}
}

// TestDecodeJWTSample covers the header-alg extraction that JWT-reasoning
// depends on (knowing alg=HS256 vs alg=none is the central decision).
func TestDecodeJWTSample(t *testing.T) {
	// Classic HS256 token (none of this is a real secret; it's the canonical
	// jwt.io example).
	hs256 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature"
	// alg=none token: header {"alg":"none","typ":"JWT"}
	algNone := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.sig"

	tests := []struct {
		name    string
		token   string
		wantOK  bool
		wantAlg string
	}{
		{"hs256", hs256, true, "HS256"},
		{"alg none", algNone, true, "none"},
		{"garbage", "not.a.jwt", false, ""},
		{"too few segments", "onlytwo.segments", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, ok := decodeJWTSample(tc.token, "http://target/x")
			if ok != tc.wantOK {
				t.Fatalf("decodeJWTSample ok=%v, want %v", ok, tc.wantOK)
			}
			if tc.wantOK && !strings.EqualFold(s.Alg, tc.wantAlg) {
				t.Errorf("alg = %q, want %q", s.Alg, tc.wantAlg)
			}
		})
	}
}
