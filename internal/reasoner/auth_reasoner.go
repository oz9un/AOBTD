package reasoner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/corpus"
	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/pkg/types"
)

// AuthReasoner is a domain-specialised reasoner for authentication
// vulnerabilities. It takes evidence from the scan (observed login
// endpoints, emails mined from responses, captured JWTs) and emits
// targeted probe plans for the Verifier.
//
// The specialization value: rather than running a generic corpus of
// default credentials blindly, AuthReasoner picks payloads based on what
// the scan has actually seen. If an email like `demo@target` appears in
// a captured response, AuthReasoner prioritises that email in the probe
// plan — which a generic probe library has no mechanism to do.
type AuthReasoner struct {
	llm    llm.Provider
	logger *slog.Logger
}

// NewAuthReasoner constructs an AuthReasoner bound to an LLM provider.
// A nil provider disables the reasoner — Apply returns (nil, nil) so
// the orchestrator can call it unconditionally.
func NewAuthReasoner(provider llm.Provider, logger *slog.Logger) *AuthReasoner {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuthReasoner{llm: provider, logger: logger}
}

// Name identifies the reasoner in logs / narrations.
func (r *AuthReasoner) Name() string { return "AuthReasoner" }

// Apply turns Evidence into auth-focused ProbePlans. Behaviour:
//   - Returns nil plans (no error) when no LLM is configured.
//   - Returns nil plans (no error) when the evidence contains no
//     plausible auth surface (no login endpoints, no JWTs).
//   - On LLM error, logs and returns error so the orchestrator decides
//     whether to fall back to the generic probe library.
//   - All returned plans are validated: unknown techniques rejected,
//     fabricated URLs (not in evidence) rejected.
func (r *AuthReasoner) Apply(ctx context.Context, ev Evidence) ([]ProbePlan, ReasonerUsage, error) {
	deterministic := deterministicAuthPlans(ev)
	if r.llm == nil {
		for i := range deterministic {
			deterministic[i].SourceReasoner = r.Name()
		}
		return deterministic, ReasonerUsage{}, nil
	}
	// Fast-reject: no auth surface at all.
	if len(ev.LoginEndpoints) == 0 && len(ev.JWTSamples) == 0 {
		r.logger.Info("AuthReasoner: no auth surface in evidence, skipping",
			"scan_id", ev.ScanID)
		return nil, ReasonerUsage{}, nil
	}

	userMessage := r.buildUserMessage(ev)
	req := &llm.Request{
		SystemPrompt: authSystemPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: userMessage},
		},
		Temperature: 0.2,  // tight — we want reproducible plans
		MaxTokens:   3500, // headroom so JSON isn't truncated mid-field
		JSONMode:    true,
	}

	resp, err := r.llm.Complete(ctx, req)
	if err != nil {
		return nil, ReasonerUsage{}, fmt.Errorf("auth reasoner LLM: %w", err)
	}
	usage := ReasonerUsage{
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
		ModelID:      llm.ResponseModel(resp, r.llm),
	}

	plans, err := parsePlans(resp.Content)
	if err != nil {
		r.logger.Warn("AuthReasoner: plan parse failed",
			"err", err,
			"content_preview", truncate(resp.Content, 300))
		if len(deterministic) == 0 {
			return nil, usage, fmt.Errorf("parse plans: %w", err)
		}
		for i := range deterministic {
			deterministic[i].SourceReasoner = r.Name()
		}
		return deterministic, usage, nil
	}

	validated := validatePlans(plans, ev)
	if len(validated) == 0 {
		validated = append(validated, deterministic...)
	} else {
		validated = appendSupplementalAuthPlans(validated, deterministic)
	}
	for i := range validated {
		validated[i].SourceReasoner = r.Name()
	}
	r.logger.Info("AuthReasoner: emitted plans",
		"scan_id", ev.ScanID,
		"input_tokens", usage.InputTokens,
		"output_tokens", usage.OutputTokens,
		"raw_count", len(plans),
		"validated_count", len(validated),
		"raw_response_preview", truncate(resp.Content, 400))

	return validated, usage, nil
}

func appendSupplementalAuthPlans(plans []ProbePlan, supplemental []ProbePlan) []ProbePlan {
	for _, candidate := range supplemental {
		if candidate.Technique != "jwt_unsigned" {
			continue
		}
		if jwtUnsignedPayloadsCovered(plans, candidate) {
			continue
		}
		plans = append(plans, candidate)
	}
	return plans
}

func jwtUnsignedPayloadsCovered(plans []ProbePlan, candidate ProbePlan) bool {
	if len(candidate.Payloads) == 0 {
		return true
	}
	existing := make(map[string]struct{})
	for _, plan := range plans {
		if plan.Technique != "jwt_unsigned" {
			continue
		}
		for _, payload := range plan.Payloads {
			existing[strings.TrimSpace(payload)] = struct{}{}
		}
	}
	if len(existing) == 0 {
		return false
	}
	for _, payload := range candidate.Payloads {
		if _, ok := existing[strings.TrimSpace(payload)]; !ok {
			return false
		}
	}
	return true
}

func deterministicAuthPlans(ev Evidence) []ProbePlan {
	var plans []ProbePlan
	if plan, ok := deterministicWeakCredentialPlan(ev); ok {
		plans = append(plans, plan)
	}
	plans = append(plans, deterministicJWTUnsignedPlans(ev)...)
	return plans
}

func deterministicWeakCredentialPlan(ev Evidence) (ProbePlan, bool) {
	if len(ev.LoginEndpoints) == 0 {
		return ProbePlan{}, false
	}
	ep := ev.LoginEndpoints[0]
	if strings.TrimSpace(ep.URL) == "" {
		return ProbePlan{}, false
	}
	usernameField, passwordField := inferLoginFields(ep.BodyFields)
	bodyType := "json"
	if strings.Contains(strings.ToLower(ep.RequestContentType), "form") {
		bodyType = "form"
	}
	payloads := deterministicWeakCredentialPayloads(ev.ObservedEmails, 12)
	if len(payloads) == 0 {
		return ProbePlan{}, false
	}
	return ProbePlan{
		Technique: "weak_credentials",
		Target: ProbeTarget{
			URL:      ep.URL,
			Method:   "POST",
			BodyType: bodyType,
			Headers: map[string]string{
				"auth_username_field": usernameField,
				"auth_password_field": passwordField,
			},
		},
		Payloads: payloads,
		Confirmation: ConfirmationRule{
			StatusCodes:  []int{200},
			BodyContains: []string{`"token"`, `"authentication"`, "bearer "},
			MinBodyBytes: 5,
		},
		Rationale:  "deterministic auth fallback: observed login endpoint and login field names allow bounded weak-credential checks without relying on model output",
		Confidence: 0.7,
	}, true
}

func deterministicJWTUnsignedPlans(ev Evidence) []ProbePlan {
	if len(ev.JWTSamples) == 0 {
		return nil
	}
	target, ok := selectJWTUnsignedTarget(ev)
	if !ok {
		return nil
	}
	identities := candidateJWTIdentities(ev, 12)
	if len(identities) == 0 {
		return nil
	}
	payloads := jwtUnsignedPayloadsForIdentities(identities, 12)
	if len(payloads) == 0 {
		return nil
	}
	method := firstNonEmpty(target.Method, "GET")
	if !strings.EqualFold(method, "GET") && !strings.EqualFold(method, "POST") {
		method = "GET"
	}
	return []ProbePlan{{
		Technique: "jwt_unsigned",
		Target: ProbeTarget{
			URL:    target.URL,
			Method: method,
		},
		Payloads: payloads,
		Confirmation: ConfirmationRule{
			StatusCodes:  []int{200},
			BodyContains: []string{"{{jwt_identity}}"},
			MinBodyBytes: 2,
		},
		Rationale:  "deterministic auth fallback: captured JWTs and observed app identities allow a bounded alg:none forgery probe against an auth-dependent JSON endpoint",
		Confidence: 0.75,
	}}
}

func selectJWTUnsignedTarget(ev Evidence) (DiscoveredEndpoint, bool) {
	endpoints := append([]DiscoveredEndpoint{}, ev.APIEndpoints...)
	endpoints = append(endpoints, ev.QueryEndpoints...)
	var best DiscoveredEndpoint
	bestScore := -1
	for _, ep := range endpoints {
		if strings.TrimSpace(ep.URL) == "" {
			continue
		}
		method := strings.ToUpper(firstNonEmpty(ep.Method, "GET"))
		if method != "GET" && method != "POST" {
			continue
		}
		path := strings.ToLower(firstNonEmpty(ep.Path, ep.URL))
		if strings.Contains(path, "/login") || strings.Contains(path, "/logout") {
			continue
		}
		score := 0
		if method == "GET" {
			score += 10
		}
		if len(ep.AuthHeaders) > 0 {
			score += 20
		}
		if strings.Contains(strings.ToLower(ep.ResponseContentType), "json") {
			score += 5
		}
		for _, marker := range []string{"whoami", "/me", "profile", "account", "session", "authentication", "/auth", "/user"} {
			if strings.Contains(path, marker) {
				score += 30
				break
			}
		}
		for _, marker := range []string{"/admin", "/config", "/challenge", "/metrics", "/swagger", "/docs"} {
			if strings.Contains(path, marker) {
				score -= 25
				break
			}
		}
		if score > bestScore {
			bestScore = score
			best = ep
		}
	}
	return best, bestScore >= 10
}

func candidateJWTIdentities(ev Evidence, limit int) []string {
	type candidate struct {
		value string
		score int
		order int
	}
	seen := make(map[string]int)
	var candidates []candidate
	add := func(value string, score int) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || !strings.Contains(value, "@") {
			return
		}
		if idx, ok := seen[value]; ok {
			if score > candidates[idx].score {
				candidates[idx].score = score
			}
			return
		}
		seen[value] = len(candidates)
		candidates = append(candidates, candidate{value: value, score: score, order: len(candidates)})
	}
	for _, sample := range ev.JWTSamples {
		for _, email := range emailsFromText(sample.PayloadPreview) {
			add(email, 80+identityJWTScore(email))
		}
	}
	for _, email := range ev.ObservedEmails {
		add(email, 40+identityJWTScore(email))
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score == candidates[j].score {
			return candidates[i].order < candidates[j].order
		}
		return candidates[i].score > candidates[j].score
	})
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.value)
	}
	return out
}

func identityJWTScore(identity string) int {
	low := strings.ToLower(identity)
	score := 0
	for _, marker := range []string{"jwt", "token", "admin", "root", "support", "security"} {
		if strings.Contains(low, marker) {
			score += 25
		}
	}
	return score
}

func emailsFromText(s string) []string {
	var out []string
	for _, token := range strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case '"', '\'', '<', '>', '(', ')', '[', ']', '{', '}', ',', ';', ':':
			return true
		default:
			return r <= ' '
		}
	}) {
		token = strings.Trim(token, " \t\r\n\"'<>.,;:()[]{}")
		if strings.Contains(token, "@") && strings.Contains(token, ".") {
			out = append(out, token)
		}
	}
	return out
}

func jwtUnsignedPayloadsForIdentities(identities []string, limit int) []string {
	payloads := make([]string, 0, len(identities))
	for i, identity := range identities {
		if limit > 0 && len(payloads) >= limit {
			break
		}
		id := i + 1
		claims := map[string]any{
			"sub":      identity,
			"email":    identity,
			"username": identity,
			"role":     "admin",
			"roles":    []string{"admin"},
			"bid":      id,
			"data": map[string]any{
				"id":       id,
				"username": "",
				"email":    identity,
				"role":     "admin",
				"isActive": true,
			},
			"user": map[string]any{
				"id":    id,
				"email": identity,
				"role":  "admin",
			},
		}
		b, err := json.Marshal(claims)
		if err != nil {
			continue
		}
		payloads = append(payloads, string(b))
	}
	return payloads
}

func inferLoginFields(fields []string) (usernameField, passwordField string) {
	usernameField = "email"
	passwordField = "password"
	for _, field := range fields {
		normalized := normalizePlanField(field)
		switch normalized {
		case "email", "username", "user", "login":
			if usernameField == "email" || normalized == "email" {
				usernameField = strings.TrimSpace(field)
			}
		case "password", "passwd", "pass", "secret":
			passwordField = strings.TrimSpace(field)
		}
	}
	return usernameField, passwordField
}

func normalizePlanField(field string) string {
	field = strings.ToLower(strings.TrimSpace(field))
	field = strings.ReplaceAll(field, "_", "")
	field = strings.ReplaceAll(field, "-", "")
	return field
}

func deterministicWeakCredentialPayloads(observedEmails []string, limit int) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(user, pass string) {
		if len(out) >= limit {
			return
		}
		user, pass = strings.TrimSpace(user), strings.TrimSpace(pass)
		if user == "" || pass == "" {
			return
		}
		key := user + ":" + pass
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	for _, c := range corpus.DefaultCredentials() {
		if c.Username == "demo" || c.Username == "admin" || c.Username == "user" || c.Username == "test" {
			add(c.Username, c.Password)
		}
	}
	commonPasswords := []string{"admin", "admin123", "password", "demo", "test", "Password1"}
	for _, email := range observedEmails {
		for _, pass := range commonPasswords {
			add(email, pass)
		}
	}
	return out
}

// buildUserMessage formats the Evidence into a compact JSON document for
// the LLM. Keeps the payload small — no full request / response bodies.
func (r *AuthReasoner) buildUserMessage(ev Evidence) string {
	type endpointLite struct {
		URL         string   `json:"url"`
		Method      string   `json:"method"`
		ContentType string   `json:"content_type,omitempty"`
		ExampleBody string   `json:"example_body,omitempty"`
		Fields      []string `json:"fields,omitempty"`
	}
	toLite := func(eps []DiscoveredEndpoint) []endpointLite {
		out := make([]endpointLite, 0, len(eps))
		for _, e := range eps {
			out = append(out, endpointLite{
				URL:         e.URL,
				Method:      e.Method,
				ContentType: firstNonEmpty(e.RequestContentType, e.ResponseContentType),
				ExampleBody: truncate(e.ExampleRequestBody, 220),
				Fields:      e.BodyFields,
			})
		}
		return out
	}

	doc := map[string]any{
		"target":            ev.Target,
		"login_endpoints":   toLite(ev.LoginEndpoints),
		"observed_emails":   ev.ObservedEmails,
		"jwt_samples":       ev.JWTSamples,
		"existing_findings": summariseFindings(ev.Findings),
	}
	if ev.Hypothesis != nil {
		doc["strategist_hypothesis"] = ev.Hypothesis.Statement
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

// summariseFindings reduces findings to (title, severity, vuln_type) tuples
// — the reasoner doesn't need the full evidence body.
func summariseFindings(findings []types.Finding) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, map[string]any{
			"title":     f.Title,
			"severity":  f.Severity,
			"vuln_type": f.VulnType,
		})
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ── parsing / validation ──────────────────────────────────────────────

// parsePlans extracts plans from the LLM response. Tolerant of markdown
// fences, leading/trailing prose, a bare single plan object, and common
// wrapper objects. Most providers emit bare JSON when JSONMode is requested,
// but model families differ just enough that the parser needs to accept the
// first complete JSON value instead of blindly grabbing the first nested array.
func parsePlans(content string) ([]ProbePlan, error) {
	raw := strings.TrimSpace(content)
	// Strip ```json ... ``` fences if present.
	if strings.HasPrefix(raw, "```") {
		if i := strings.Index(raw, "\n"); i > 0 {
			raw = raw[i+1:]
		}
		if j := strings.LastIndex(raw, "```"); j > 0 {
			raw = raw[:j]
		}
		raw = strings.TrimSpace(raw)
	}

	if plans, err := decodePlanJSON(raw); err == nil {
		return plans, nil
	}

	// Extract the first complete JSON value. This handles surrounding prose
	// and duplicate top-level answers (`[...] , [...]`) while avoiding the old
	// failure mode where a single object caused us to parse its nested
	// "payloads" array as the whole answer.
	if value, ok := firstBalancedJSONValue(raw); ok && value != raw {
		return decodePlanJSON(value)
	}

	_, err := decodePlanJSON(raw)
	return nil, err
}

func decodePlanJSON(raw string) ([]ProbePlan, error) {
	var plans []ProbePlan
	if err := json.Unmarshal([]byte(raw), &plans); err == nil {
		return plans, nil
	}

	var wrapped struct {
		Plans      []ProbePlan `json:"plans"`
		ProbePlans []ProbePlan `json:"probe_plans"`
		Chains     []ProbePlan `json:"chains"`
		Data       []ProbePlan `json:"data"`
		Items      []ProbePlan `json:"items"`
		Result     []ProbePlan `json:"result"`
		Plan       *ProbePlan  `json:"plan"`
		Chain      *ProbePlan  `json:"chain"`
		Error      string      `json:"error"`
		Message    string      `json:"message"`
	}
	if err := json.Unmarshal([]byte(raw), &wrapped); err == nil {
		switch {
		case wrapped.Plans != nil:
			return wrapped.Plans, nil
		case wrapped.ProbePlans != nil:
			return wrapped.ProbePlans, nil
		case wrapped.Chains != nil:
			return wrapped.Chains, nil
		case wrapped.Data != nil:
			return wrapped.Data, nil
		case wrapped.Items != nil:
			return wrapped.Items, nil
		case wrapped.Result != nil:
			return wrapped.Result, nil
		case wrapped.Plan != nil && wrapped.Plan.Technique != "":
			return []ProbePlan{*wrapped.Plan}, nil
		case wrapped.Chain != nil && wrapped.Chain.Technique != "":
			return []ProbePlan{*wrapped.Chain}, nil
		case looksLikeModelFormatError(wrapped.Error) || looksLikeModelFormatError(wrapped.Message):
			return []ProbePlan{}, nil
		}
	}

	var plan ProbePlan
	if err := json.Unmarshal([]byte(raw), &plan); err == nil && plan.Technique != "" {
		return []ProbePlan{plan}, nil
	}

	var keyed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &keyed); err == nil {
		if len(keyed) == 0 {
			return []ProbePlan{}, nil
		}
		keys := make([]string, 0, len(keyed))
		for k := range keyed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		indexed := make([]ProbePlan, 0, len(keys))
		for _, k := range keys {
			var p ProbePlan
			if err := json.Unmarshal(keyed[k], &p); err != nil || p.Technique == "" {
				continue
			}
			indexed = append(indexed, p)
		}
		if len(indexed) > 0 {
			return indexed, nil
		}
	}

	return nil, fmt.Errorf("response is not a plan array, wrapped plan array/chains array, indexed plan object, or single plan object")
}

func looksLikeModelFormatError(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return false
	}
	return strings.Contains(s, "json array") ||
		strings.Contains(s, "output must") ||
		strings.Contains(s, "re-run") ||
		strings.Contains(s, "schema")
}

// firstBalancedJSONValue returns the first syntactically balanced JSON value
// that starts with an object or array while respecting quoted strings and
// escapes. json.Unmarshal remains the authority on semantic validity.
func firstBalancedJSONValue(raw string) (string, bool) {
	start := -1
	for i := 0; i < len(raw); i++ {
		if raw[i] == '{' || raw[i] == '[' {
			start = i
			break
		}
	}
	if start < 0 {
		return "", false
	}
	stack := make([]byte, 0, 8)
	inString := false
	escaped := false
	for i := start; i < len(raw); i++ {
		c := raw[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch c {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			stack = append(stack, c)
		case '}', ']':
			if len(stack) == 0 {
				return "", false
			}
			open := stack[len(stack)-1]
			if (open == '{' && c != '}') || (open == '[' && c != ']') {
				return "", false
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return raw[start : i+1], true
			}
		}
	}
	return "", false
}

// validatePlans filters plans to only those that pass safety + correctness
// checks:
//   - technique must be in the allowlist
//   - Target.URL must appear in evidence (no fabrication)
//   - at least one payload
//   - at least one confirmation signal
func validatePlans(plans []ProbePlan, ev Evidence) []ProbePlan {
	evidenceURLs := make(map[string]bool)
	for _, ep := range ev.LoginEndpoints {
		evidenceURLs[ep.URL] = true
	}
	for _, ep := range ev.APIEndpoints {
		evidenceURLs[ep.URL] = true
	}
	for _, ep := range ev.QueryEndpoints {
		evidenceURLs[ep.URL] = true
	}
	for _, p := range ev.AuthPersonas {
		if p.LoginURL != "" {
			evidenceURLs[p.LoginURL] = true
		}
		if p.ObjectURL != "" {
			evidenceURLs[p.ObjectURL] = true
		}
	}

	valid := make([]ProbePlan, 0, len(plans))
	for _, p := range plans {
		if !IsKnownTechnique(p.Technique) {
			continue
		}
		if p.Target.URL == "" || !evidenceURLs[p.Target.URL] {
			continue
		}
		if (p.Technique == "bola_two_persona_ownership" || p.Technique == "bola_two_persona_mutation") && !validBOLAPlanTargets(p, evidenceURLs) {
			continue
		}
		if (p.Technique == "idor_sequential_id" || p.Technique == "bola_tenant_crossing") && !validAccessTarget(p, ev) {
			continue
		}
		if len(p.Payloads) == 0 {
			continue
		}
		if len(p.Confirmation.StatusCodes) == 0 &&
			len(p.Confirmation.BodyContains) == 0 &&
			len(p.Confirmation.BodyAbsent) == 0 &&
			len(p.Confirmation.HeaderPresent) == 0 &&
			p.Confirmation.MinBodyBytes == 0 {
			continue
		}
		if p.Confidence < 0 || p.Confidence > 1.0 {
			p.Confidence = 0.5
		}
		valid = append(valid, p)
	}
	return valid
}

func validAccessTarget(p ProbePlan, ev Evidence) bool {
	for _, ep := range ev.APIEndpoints {
		if ep.URL == p.Target.URL {
			return accessEndpointLooksOwnedObject(ep)
		}
	}
	for _, ep := range ev.QueryEndpoints {
		if ep.URL == p.Target.URL {
			return accessEndpointLooksOwnedObject(ep)
		}
	}
	return false
}

func validBOLAPlanTargets(p ProbePlan, evidenceURLs map[string]bool) bool {
	if p.Target.Headers == nil {
		return false
	}
	for _, key := range []string{"bola_object_a_url", "bola_object_b_url"} {
		raw := strings.TrimSpace(p.Target.Headers[key])
		if raw == "" || !evidenceURLs[raw] {
			return false
		}
	}
	if loginURL := strings.TrimSpace(p.Target.Headers["bola_login_url"]); loginURL != "" && !evidenceURLs[loginURL] {
		return false
	}
	if p.Technique == "bola_two_persona_mutation" {
		raw := strings.TrimSpace(p.Target.Headers["bola_mutation_url"])
		if raw == "" || !evidenceURLs[raw] {
			return false
		}
		if strings.TrimSpace(p.Target.Headers["bola_mutation_field"]) == "" ||
			strings.TrimSpace(p.Target.Headers["bola_mutation_value"]) == "" {
			return false
		}
	}
	return true
}

// truncate shortens a string for log / prompt use.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
