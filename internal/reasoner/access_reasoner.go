package reasoner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"

	"github.com/ozzyw/aobtd/internal/llm"
)

// AccessReasoner is the third domain specialist in the hybrid
// architecture. Focused on broken access control: IDOR, BOLA, BFLA,
// privilege escalation. Mirrors the AuthReasoner + InjectionReasoner
// pattern: focused prompt, same Evidence contract, same Executor.
//
// The specialization value: while InjectionReasoner thinks about
// "how do I inject into this parameter", AccessReasoner thinks about
// "who else's data can I read by changing the identifier". Two
// different mental models even when the target URLs overlap.
type AccessReasoner struct {
	llm    llm.Provider
	logger *slog.Logger
}

// NewAccessReasoner constructs the access-control reasoner.
func NewAccessReasoner(provider llm.Provider, logger *slog.Logger) *AccessReasoner {
	if logger == nil {
		logger = slog.Default()
	}
	return &AccessReasoner{llm: provider, logger: logger}
}

// Name identifies the reasoner in logs / narrations.
func (r *AccessReasoner) Name() string { return "AccessReasoner" }

// Apply produces IDOR / BOLA / role-flip plans from scan evidence.
//
// Fast-reject condition: no API endpoints (no /api/...-shaped paths
// captured). If the target isn't a REST-style API, there's nothing for
// the access reasoner to do.
func (r *AccessReasoner) Apply(ctx context.Context, ev Evidence) ([]ProbePlan, ReasonerUsage, error) {
	configuredBOLA := configuredBOLAPlans(ev)
	accessEv := accessCandidateEvidence(ev)
	var deterministicPlans []ProbePlan
	if len(configuredBOLA) == 0 {
		deterministicPlans = deterministicAccessPlans(accessEv)
	}
	fallbackPlans := appendSupplementalPlans(append([]ProbePlan(nil), configuredBOLA...), deterministicPlans)
	if r.llm == nil {
		setPlanSource(fallbackPlans, r.Name())
		return fallbackPlans, ReasonerUsage{}, nil
	}
	if len(ev.APIEndpoints) == 0 && len(ev.QueryEndpoints) == 0 {
		if len(fallbackPlans) > 0 {
			setPlanSource(fallbackPlans, r.Name())
			return fallbackPlans, ReasonerUsage{}, nil
		}
		r.logger.Info("AccessReasoner: no API surface in evidence, skipping",
			"scan_id", ev.ScanID)
		return nil, ReasonerUsage{}, nil
	}
	if len(accessEv.APIEndpoints) == 0 && len(accessEv.QueryEndpoints) == 0 && len(fallbackPlans) == 0 {
		r.logger.Info("AccessReasoner: no ownership-shaped API surface in evidence, skipping",
			"scan_id", ev.ScanID)
		return nil, ReasonerUsage{}, nil
	}

	userMessage := r.buildUserMessage(accessEv)
	req := &llm.Request{
		SystemPrompt: accessSystemPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: userMessage},
		},
		Temperature: 0.2,
		MaxTokens:   3500,
		JSONMode:    true,
	}

	resp, err := r.llm.Complete(ctx, req)
	if err != nil {
		if len(fallbackPlans) > 0 {
			setPlanSource(fallbackPlans, r.Name())
			r.logger.Warn("AccessReasoner: model failed; using deterministic fallback",
				"err", err, "fallback_plans", len(fallbackPlans))
			return fallbackPlans, ReasonerUsage{}, nil
		}
		return nil, ReasonerUsage{}, fmt.Errorf("access reasoner LLM: %w", err)
	}
	usage := ReasonerUsage{
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
		ModelID:      llm.ResponseModel(resp, r.llm),
	}

	plans, err := parsePlans(resp.Content)
	if err != nil {
		if emptyPlanResponse(resp.Content) {
			setPlanSource(fallbackPlans, r.Name())
			r.logger.Info("AccessReasoner: model emitted no plans",
				"scan_id", ev.ScanID,
				"fallback_plans", len(fallbackPlans))
			return fallbackPlans, usage, nil
		}
		if len(fallbackPlans) > 0 {
			setPlanSource(fallbackPlans, r.Name())
			r.logger.Warn("AccessReasoner: plan parse failed; using deterministic fallback",
				"err", err,
				"content_preview", truncate(resp.Content, 300),
				"fallback_plans", len(fallbackPlans))
			return fallbackPlans, usage, nil
		}
		r.logger.Warn("AccessReasoner: plan parse failed",
			"err", err,
			"content_preview", truncate(resp.Content, 300))
		return nil, usage, fmt.Errorf("parse plans: %w", err)
	}

	hydrateConfiguredBOLAPlans(plans, ev)
	validated := validatePlans(plans, ev)
	validated = appendSupplementalPlans(validated, configuredBOLA)
	if !hasAnyBOLAPlan(validated) {
		validated = appendSupplementalPlans(validated, deterministicPlans)
	}
	for i := range validated {
		validated[i].SourceReasoner = r.Name()
	}
	r.logger.Info("AccessReasoner: emitted plans",
		"scan_id", ev.ScanID,
		"input_tokens", usage.InputTokens,
		"output_tokens", usage.OutputTokens,
		"raw_count", len(plans),
		"validated_count", len(validated),
		"raw_response_preview", truncate(resp.Content, 400))

	return validated, usage, nil
}

func appendSupplementalPlans(plans []ProbePlan, supplemental []ProbePlan) []ProbePlan {
	for _, candidate := range supplemental {
		if hasEquivalentPlan(plans, candidate) {
			continue
		}
		plans = append(plans, candidate)
	}
	return plans
}

func hasEquivalentPlan(plans []ProbePlan, candidate ProbePlan) bool {
	for _, plan := range plans {
		if plan.Technique == candidate.Technique &&
			plan.Target.URL == candidate.Target.URL &&
			plan.Target.Field == candidate.Target.Field {
			return true
		}
	}
	return false
}

func hasAnyBOLAPlan(plans []ProbePlan) bool {
	for _, plan := range plans {
		if plan.Technique == "bola_two_persona_ownership" || plan.Technique == "bola_two_persona_mutation" {
			return true
		}
	}
	return false
}

func setPlanSource(plans []ProbePlan, source string) {
	for i := range plans {
		plans[i].SourceReasoner = source
	}
}

func deterministicAccessPlans(ev Evidence) []ProbePlan {
	var plans []ProbePlan
	endpoints := append(append([]DiscoveredEndpoint{}, ev.APIEndpoints...), ev.QueryEndpoints...)
	for _, ep := range endpoints {
		plan, ok := deterministicIDORPlan(ep)
		if !ok {
			continue
		}
		plans = append(plans, plan)
		if len(plans) >= 4 {
			break
		}
	}
	return plans
}

func deterministicIDORPlan(ep DiscoveredEndpoint) (ProbePlan, bool) {
	if !strings.EqualFold(firstNonEmpty(ep.Method, "GET"), "GET") {
		return ProbePlan{}, false
	}
	field, payloads, ok := idorMutationPoint(ep)
	if !ok || len(payloads) < 2 {
		return ProbePlan{}, false
	}
	return ProbePlan{
		Technique: "idor_sequential_id",
		Target: ProbeTarget{
			URL:     ep.URL,
			Method:  "GET",
			Field:   field,
			Headers: cloneStringMap(ep.AuthHeaders),
		},
		Payloads: payloads,
		Confirmation: ConfirmationRule{
			StatusCodes:  []int{200},
			MinBodyBytes: 20,
		},
		Rationale:  fmt.Sprintf("deterministic fallback: observed owned-object endpoint %s carries a scalar identifier; test adjacent identifiers with baseline-diff confirmation", ep.URL),
		Confidence: 0.65,
	}, true
}

func idorMutationPoint(ep DiscoveredEndpoint) (field string, payloads []string, ok bool) {
	parsed, err := url.Parse(ep.URL)
	if err != nil {
		return "", nil, false
	}
	for _, param := range append([]string{}, ep.Params...) {
		values := parsed.Query()[param]
		if len(values) == 0 || !accessFieldLooksOwnershipRelevant(param) {
			continue
		}
		if payloads := neighbouringIntegerPayloads(values[0]); len(payloads) >= 2 {
			return param, payloads, true
		}
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for i := len(segments) - 1; i >= 0; i-- {
		if payloads := neighbouringIntegerPayloads(segments[i]); len(payloads) >= 2 {
			return "path", payloads, true
		}
	}
	return "", nil, false
}

func neighbouringIntegerPayloads(raw string) []string {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 {
		return nil
	}
	seen := make(map[int]bool)
	var out []string
	add := func(v int) {
		if v < 0 || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, strconv.Itoa(v))
	}
	add(n + 1)
	if n > 0 {
		add(n - 1)
	}
	add(n + 2)
	return out
}

// buildUserMessage packs the access-relevant slice of evidence: API
// endpoints (where objects live) and query endpoints (where IDOR-in-
// query-params lives). Persona passwords are never included.
func (r *AccessReasoner) buildUserMessage(ev Evidence) string {
	type endpointLite struct {
		URL                string   `json:"url"`
		Method             string   `json:"method"`
		Params             []string `json:"params,omitempty"`
		BodyFields         []string `json:"body_fields,omitempty"`
		RequestContentType string   `json:"request_content_type,omitempty"`
	}
	type personaLite struct {
		Label       string `json:"label,omitempty"`
		LoginURL    string `json:"login_url,omitempty"`
		Username    string `json:"username,omitempty"`
		OwnerMarker string `json:"owner_marker,omitempty"`
		ObjectURL   string `json:"object_url,omitempty"`
		Password    string `json:"password,omitempty"`
	}
	toLite := func(eps []DiscoveredEndpoint) []endpointLite {
		out := make([]endpointLite, 0, len(eps))
		for _, e := range eps {
			out = append(out, endpointLite{
				URL:                e.URL,
				Method:             e.Method,
				Params:             e.Params,
				BodyFields:         e.BodyFields,
				RequestContentType: e.RequestContentType,
			})
		}
		return out
	}
	personas := make([]personaLite, 0, len(ev.AuthPersonas))
	for _, p := range ev.AuthPersonas {
		personas = append(personas, personaLite{
			Label:       p.Label,
			LoginURL:    p.LoginURL,
			Username:    p.Username,
			OwnerMarker: p.OwnerMarker,
			ObjectURL:   p.ObjectURL,
			Password:    "<provided out-of-band; do not guess>",
		})
	}
	doc := map[string]any{
		"target":            ev.Target,
		"login_endpoints":   toLite(ev.LoginEndpoints),
		"api_endpoints":     toLite(ev.APIEndpoints),
		"query_endpoints":   toLite(ev.QueryEndpoints),
		"existing_findings": summariseFindings(ev.Findings),
	}
	if len(personas) > 0 {
		doc["auth_personas"] = personas
	}
	if ev.Hypothesis != nil {
		doc["strategist_hypothesis"] = ev.Hypothesis.Statement
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

func emptyPlanResponse(content string) bool {
	content = strings.TrimSpace(content)
	if content == "" || content == "null" {
		return true
	}
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(content), &arr); err == nil {
		return len(arr) == 0
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &obj); err != nil {
		return false
	}
	if len(obj) == 0 {
		return true
	}
	for _, key := range []string{"plans", "result", "probe_plans"} {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		var nested []json.RawMessage
		if err := json.Unmarshal(raw, &nested); err == nil && len(nested) == 0 {
			return true
		}
	}
	return false
}

func hydrateConfiguredBOLAPlans(plans []ProbePlan, ev Evidence) {
	if len(ev.AuthPersonas) < 2 {
		return
	}
	a, b := ev.AuthPersonas[0], ev.AuthPersonas[1]
	if !personaReadyForBOLA(a) || !personaReadyForBOLA(b) {
		return
	}
	loginURL := a.LoginURL
	if loginURL == "" {
		loginURL = b.LoginURL
	}
	for i := range plans {
		if plans[i].Technique != "bola_two_persona_ownership" && plans[i].Technique != "bola_two_persona_mutation" {
			continue
		}
		if plans[i].Target.Headers == nil {
			plans[i].Target.Headers = map[string]string{}
		}
		if plans[i].Target.URL == "" || strings.Contains(plans[i].Target.URL, "<") {
			plans[i].Target.URL = loginURL
		}
		if plans[i].Target.Method == "" {
			plans[i].Target.Method = "POST"
		}
		if plans[i].Target.BodyType == "" {
			plans[i].Target.BodyType = "json"
		}
		plans[i].Target.Headers["bola_login_url"] = loginURL
		plans[i].Target.Headers["bola_user_a"] = a.Username
		plans[i].Target.Headers["bola_pass_a"] = a.Password
		plans[i].Target.Headers["bola_owner_a"] = a.OwnerMarker
		plans[i].Target.Headers["bola_object_a_url"] = a.ObjectURL
		plans[i].Target.Headers["bola_user_b"] = b.Username
		plans[i].Target.Headers["bola_pass_b"] = b.Password
		plans[i].Target.Headers["bola_owner_b"] = b.OwnerMarker
		plans[i].Target.Headers["bola_object_b_url"] = b.ObjectURL
		if len(plans[i].Payloads) == 0 {
			plans[i].Payloads = []string{"two-persona-owner-readback"}
		}
	}
}

func configuredBOLAPlans(ev Evidence) []ProbePlan {
	if len(ev.AuthPersonas) < 2 {
		return nil
	}
	a, b := ev.AuthPersonas[0], ev.AuthPersonas[1]
	if !personaReadyForBOLA(a) || !personaReadyForBOLA(b) {
		return nil
	}
	loginURL := a.LoginURL
	if loginURL == "" {
		loginURL = b.LoginURL
	}
	if loginURL == "" {
		return nil
	}
	readPlan := ProbePlan{
		Technique: "bola_two_persona_ownership",
		Target: ProbeTarget{
			URL:      loginURL,
			Method:   "POST",
			BodyType: "json",
			Headers: map[string]string{
				"bola_login_url":    loginURL,
				"bola_user_a":       a.Username,
				"bola_pass_a":       a.Password,
				"bola_owner_a":      a.OwnerMarker,
				"bola_object_a_url": a.ObjectURL,
				"bola_user_b":       b.Username,
				"bola_pass_b":       b.Password,
				"bola_owner_b":      b.OwnerMarker,
				"bola_object_b_url": b.ObjectURL,
			},
		},
		Payloads: []string{"two-persona-owner-readback"},
		Confirmation: ConfirmationRule{
			StatusCodes:  []int{200},
			BodyContains: []string{"id"},
			MinBodyBytes: 20,
		},
		Rationale:  "operator provided two personas with owned object URLs; run positive controls, anonymous boundary control, then cross-owner readback",
		Confidence: 0.95,
	}
	plans := []ProbePlan{readPlan}
	if mutation, ok := configuredBOLAMutationPlan(ev, a, b, loginURL); ok {
		plans = append(plans, mutation)
	}
	return plans
}

func hasTechniquePlan(plans []ProbePlan, technique string) bool {
	for _, p := range plans {
		if p.Technique == technique {
			return true
		}
	}
	return false
}

func configuredBOLAMutationPlan(ev Evidence, a, b AuthPersona, loginURL string) (ProbePlan, bool) {
	candidate, field, ok := selectOwnershipMutationCandidate(ev.APIEndpoints, b.ObjectURL)
	if !ok {
		return ProbePlan{}, false
	}
	method := strings.ToUpper(strings.TrimSpace(candidate.Method))
	if method == "" {
		method = "PATCH"
	}
	return ProbePlan{
		Technique: "bola_two_persona_mutation",
		Target: ProbeTarget{
			URL:      loginURL,
			Method:   "POST",
			BodyType: "json",
			Headers: map[string]string{
				"bola_login_url":          loginURL,
				"bola_user_a":             a.Username,
				"bola_pass_a":             a.Password,
				"bola_owner_a":            a.OwnerMarker,
				"bola_object_a_url":       a.ObjectURL,
				"bola_user_b":             b.Username,
				"bola_pass_b":             b.Password,
				"bola_owner_b":            b.OwnerMarker,
				"bola_object_b_url":       b.ObjectURL,
				"bola_mutation_url":       candidate.URL,
				"bola_mutation_method":    method,
				"bola_mutation_field":     field,
				"bola_mutation_value":     "aobtd-proof",
				"bola_mutation_body_type": mutationBodyType(candidate),
			},
		},
		Payloads: []string{"two-persona-owner-mutation"},
		Confirmation: ConfirmationRule{
			StatusCodes:  []int{200, 201, 204},
			BodyContains: []string{"aobtd-proof"},
		},
		Rationale:  "operator provided two personas and AOBTD observed a state-changing endpoint for the secondary-owned object; run a bounded cross-owner mutation check on one harmless field",
		Confidence: 0.9,
	}, true
}

func selectOwnershipMutationCandidate(endpoints []DiscoveredEndpoint, objectURL string) (DiscoveredEndpoint, string, bool) {
	objectKey := normalizedURLKey(objectURL)
	if objectKey == "" {
		return DiscoveredEndpoint{}, "", false
	}
	for _, ep := range endpoints {
		if !isStateChangingMethod(ep.Method) {
			continue
		}
		if normalizedURLKey(ep.URL) != objectKey {
			continue
		}
		if field := selectHarmlessMutationField(ep.BodyFields); field != "" {
			return ep, field, true
		}
	}
	return DiscoveredEndpoint{}, "", false
}

func normalizedURLKey(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host + strings.TrimRight(parsed.EscapedPath(), "/"))
}

func isStateChangingMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

func selectHarmlessMutationField(fields []string) string {
	preferred := []string{"note", "title", "displayName", "display_name", "nickname", "description", "comment", "message", "name"}
	for _, want := range preferred {
		for _, field := range fields {
			if strings.EqualFold(strings.TrimSpace(field), want) && !dangerousMutationField(field) {
				return strings.TrimSpace(field)
			}
		}
	}
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" && !dangerousMutationField(field) {
			return field
		}
	}
	return ""
}

func dangerousMutationField(field string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(field), "_", ""), "-", ""))
	if normalized == "" {
		return true
	}
	switch normalized {
	case "id", "userid", "ownerid", "customerid", "accountid", "tenantid", "organizationid",
		"orgid", "role", "roles", "admin", "isadmin", "password", "pass", "token", "jwt",
		"email", "price", "amount", "balance", "credit", "quantity", "status", "state",
		"paid", "payment", "total", "csrf", "xsrf":
		return true
	default:
		return false
	}
}

func mutationBodyType(ep DiscoveredEndpoint) string {
	if strings.Contains(strings.ToLower(ep.RequestContentType), "form") {
		return "form"
	}
	return "json"
}

func personaReadyForBOLA(p AuthPersona) bool {
	return p.Username != "" && p.Password != "" && p.OwnerMarker != "" && p.ObjectURL != ""
}
