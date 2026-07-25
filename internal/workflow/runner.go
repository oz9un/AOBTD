package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Runner executes domain-agnostic workflow plans with HTTP primitives. It does
// not create findings or make policy decisions; callers own reporting and the
// policy-wrapped HTTP client.
type Runner struct {
	client *http.Client
}

// NewRunner constructs a workflow runner. The caller may pass a policy-wrapped
// client to enforce scope, authority, redirect, and credential-origin rules.
func NewRunner(client *http.Client) *Runner {
	if client == nil {
		client = http.DefaultClient
	}
	return &Runner{client: client}
}

// AuthConfig describes the login/session mechanics needed by a workflow.
type AuthConfig struct {
	BodyType         string // login body: "json" or "form"; default "json"
	MutationBodyType string // mutation body: "json" or "form"; default BodyType
	UsernameField    string // default "email"
	PasswordField    string // default "password"
	AuthHeader       string // default "Authorization"
	AuthScheme       string // default "Bearer"; "raw" sends the token as-is
	UserAgent        string
}

// OwnershipReadResult records the controls for a two-actor ownership check.
type OwnershipReadResult struct {
	Confirmed bool
	Reason    string

	LoginPrimaryStatus   int
	LoginSecondaryStatus int

	SelfPrimary   ResourceResult
	SelfSecondary ResourceResult
	Anonymous     ResourceResult
	Attack        ResourceResult
}

// OwnershipMutationResult records the controls for a two-actor ownership
// mutation check.
type OwnershipMutationResult struct {
	Confirmed bool
	Reason    string

	LoginPrimaryStatus   int
	LoginSecondaryStatus int

	BeforeSecondary ResourceResult
	Attack          ResourceResult
	AfterSecondary  ResourceResult
}

// ResourceResult is one HTTP observation in a workflow run.
type ResourceResult struct {
	URL                string
	Status             int
	Body               []byte
	OwnerProofVisible  bool
	OwnerProofEvidence string
}

// RunOwnershipRead executes the common access-control invariant:
//
//  1. primary actor can read primary-owned object
//  2. secondary actor can read secondary-owned object
//  3. anonymous cannot read secondary-owned object
//  4. primary actor must not read secondary-owned object
//
// A confirmation requires the first two positive controls to prove ownership,
// the anonymous boundary to hold, and the attack response to expose the
// secondary owner marker while authenticated as the primary actor.
func (r *Runner) RunOwnershipRead(ctx context.Context, plan Plan, cfg AuthConfig) (OwnershipReadResult, error) {
	if err := plan.Validate(); err != nil {
		return OwnershipReadResult{}, err
	}
	primary, secondary, err := ownershipActors(plan)
	if err != nil {
		return OwnershipReadResult{}, err
	}
	primaryObj, secondaryObj, err := ownershipResources(plan, primary.OwnerMarker, secondary.OwnerMarker)
	if err != nil {
		return OwnershipReadResult{}, err
	}
	cfg = normalizeAuthConfig(cfg)

	tokenPrimary, loginPrimaryStatus, _, err := r.login(ctx, primary, cfg)
	if err != nil {
		return OwnershipReadResult{}, err
	}
	tokenSecondary, loginSecondaryStatus, _, err := r.login(ctx, secondary, cfg)
	if err != nil {
		return OwnershipReadResult{}, err
	}
	result := OwnershipReadResult{
		LoginPrimaryStatus:   loginPrimaryStatus,
		LoginSecondaryStatus: loginSecondaryStatus,
	}
	if loginPrimaryStatus < 200 || loginPrimaryStatus >= 300 || tokenPrimary == "" ||
		loginSecondaryStatus < 200 || loginSecondaryStatus >= 300 || tokenSecondary == "" {
		result.Reason = "one or both actors failed to obtain a session token"
		return result, nil
	}

	result.SelfPrimary, err = r.fetchResource(ctx, primaryObj.URL, tokenPrimary, primary.OwnerMarker, cfg)
	if err != nil {
		return result, err
	}
	result.SelfSecondary, err = r.fetchResource(ctx, secondaryObj.URL, tokenSecondary, secondary.OwnerMarker, cfg)
	if err != nil {
		return result, err
	}
	result.Anonymous, err = r.fetchResource(ctx, secondaryObj.URL, "", secondary.OwnerMarker, cfg)
	if err != nil {
		return result, err
	}
	result.Attack, err = r.fetchResource(ctx, secondaryObj.URL, tokenPrimary, secondary.OwnerMarker, cfg)
	if err != nil {
		return result, err
	}

	selfPrimaryOK := isObjectSuccess(result.SelfPrimary.Status) && result.SelfPrimary.OwnerProofVisible
	selfSecondaryOK := isObjectSuccess(result.SelfSecondary.Status) && result.SelfSecondary.OwnerProofVisible
	anonymousOK := anonymousBoundaryOK(result.Anonymous.Status, result.Anonymous.OwnerProofVisible)
	attackOK := isObjectSuccess(result.Attack.Status) && result.Attack.OwnerProofVisible
	result.Confirmed = selfPrimaryOK && selfSecondaryOK && anonymousOK && attackOK
	if !result.Confirmed {
		result.Reason = fmt.Sprintf("controls not satisfied: primary_self=%v secondary_self=%v anonymous_boundary=%v attack=%v",
			selfPrimaryOK, selfSecondaryOK, anonymousOK, attackOK)
		return result, nil
	}
	result.Reason = "primary actor could read secondary-owned object while the response still proved secondary ownership"
	return result, nil
}

// RunOwnershipMutation executes the common state-changing access-control
// invariant:
//
//  1. primary and secondary actors can authenticate
//  2. secondary actor can read the secondary-owned object before the attempt
//  3. primary actor attempts a bounded field mutation against that object
//  4. secondary actor reads the object again to verify whether the mutation
//     crossed the ownership boundary
//
// A confirmation requires the positive ownership control to prove secondary
// ownership, the attack response to succeed, and either the attack response or
// the post-fetch response to show the attacker-controlled value while still
// proving secondary ownership.
func (r *Runner) RunOwnershipMutation(ctx context.Context, plan Plan, cfg AuthConfig) (OwnershipMutationResult, error) {
	if err := plan.Validate(); err != nil {
		return OwnershipMutationResult{}, err
	}
	primary, secondary, err := ownershipActors(plan)
	if err != nil {
		return OwnershipMutationResult{}, err
	}
	_, secondaryObj, err := ownershipResources(plan, primary.OwnerMarker, secondary.OwnerMarker)
	if err != nil {
		return OwnershipMutationResult{}, err
	}
	mutation, err := ownershipMutationStep(plan, primary.Label)
	if err != nil {
		return OwnershipMutationResult{}, err
	}
	cfg = normalizeAuthConfig(cfg)

	tokenPrimary, loginPrimaryStatus, _, err := r.login(ctx, primary, cfg)
	if err != nil {
		return OwnershipMutationResult{}, err
	}
	tokenSecondary, loginSecondaryStatus, _, err := r.login(ctx, secondary, cfg)
	if err != nil {
		return OwnershipMutationResult{}, err
	}
	result := OwnershipMutationResult{
		LoginPrimaryStatus:   loginPrimaryStatus,
		LoginSecondaryStatus: loginSecondaryStatus,
	}
	if loginPrimaryStatus < 200 || loginPrimaryStatus >= 300 || tokenPrimary == "" ||
		loginSecondaryStatus < 200 || loginSecondaryStatus >= 300 || tokenSecondary == "" {
		result.Reason = "one or both actors failed to obtain a session token"
		return result, nil
	}

	result.BeforeSecondary, err = r.fetchResource(ctx, secondaryObj.URL, tokenSecondary, secondary.OwnerMarker, cfg)
	if err != nil {
		return result, err
	}
	result.Attack, err = r.mutateResource(ctx, mutation, tokenPrimary, secondary.OwnerMarker, cfg)
	if err != nil {
		return result, err
	}
	result.AfterSecondary, err = r.fetchResource(ctx, secondaryObj.URL, tokenSecondary, secondary.OwnerMarker, cfg)
	if err != nil {
		return result, err
	}

	beforeOK := isObjectSuccess(result.BeforeSecondary.Status) && result.BeforeSecondary.OwnerProofVisible
	attackSuccess := isObjectSuccess(result.Attack.Status)
	attackValueVisible := BodyContainsMutationValue(result.Attack.Body, mutation.Field, mutation.Value) && result.Attack.OwnerProofVisible
	afterValueVisible := BodyContainsMutationValue(result.AfterSecondary.Body, mutation.Field, mutation.Value) && result.AfterSecondary.OwnerProofVisible
	result.Confirmed = beforeOK && attackSuccess && (attackValueVisible || afterValueVisible)
	if !result.Confirmed {
		result.Reason = fmt.Sprintf("controls not satisfied: secondary_before=%v attack_success=%v attack_value_visible=%v after_value_visible=%v",
			beforeOK, attackSuccess, attackValueVisible, afterValueVisible)
		return result, nil
	}
	result.Reason = "primary actor could mutate secondary-owned object and the changed value remained associated with secondary ownership"
	return result, nil
}

func normalizeAuthConfig(cfg AuthConfig) AuthConfig {
	if cfg.BodyType == "" {
		cfg.BodyType = "json"
	}
	if cfg.MutationBodyType == "" {
		cfg.MutationBodyType = cfg.BodyType
	}
	if cfg.UsernameField == "" {
		cfg.UsernameField = "email"
	}
	if cfg.PasswordField == "" {
		cfg.PasswordField = "password"
	}
	if cfg.AuthHeader == "" {
		cfg.AuthHeader = "Authorization"
	}
	if cfg.AuthScheme == "" {
		cfg.AuthScheme = "Bearer"
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "AOBTD/Workflow"
	}
	return cfg
}

func ownershipActors(plan Plan) (Actor, Actor, error) {
	var primary, secondary Actor
	for _, actor := range plan.Actors {
		switch actor.Role {
		case ActorPrimary:
			primary = actor
		case ActorSecondary:
			secondary = actor
		}
	}
	if primary.Label == "" || primary.LoginURL == "" || primary.Username == "" || primary.Secret == "" || primary.OwnerMarker == "" {
		return Actor{}, Actor{}, fmt.Errorf("ownership workflow missing complete primary actor")
	}
	if secondary.Label == "" || secondary.LoginURL == "" || secondary.Username == "" || secondary.Secret == "" || secondary.OwnerMarker == "" {
		return Actor{}, Actor{}, fmt.Errorf("ownership workflow missing complete secondary actor")
	}
	if primary.OwnerMarker == secondary.OwnerMarker {
		return Actor{}, Actor{}, fmt.Errorf("ownership workflow actors have identical owner markers")
	}
	return primary, secondary, nil
}

func ownershipMutationStep(plan Plan, primaryLabel string) (Step, error) {
	for _, step := range plan.Steps {
		if step.Actor != primaryLabel {
			continue
		}
		if step.Action != StepMutateBody && step.Action != StepMutateParam {
			continue
		}
		if strings.TrimSpace(step.Field) == "" {
			return Step{}, fmt.Errorf("ownership mutation workflow needs a mutation field")
		}
		if strings.TrimSpace(step.Value) == "" {
			return Step{}, fmt.Errorf("ownership mutation workflow needs a mutation value")
		}
		if strings.TrimSpace(step.Method) == "" {
			step.Method = "PATCH"
		}
		return step, nil
	}
	return Step{}, fmt.Errorf("ownership mutation workflow needs a primary actor mutation step")
}

func ownershipResources(plan Plan, primaryOwner, secondaryOwner string) (ResourceRef, ResourceRef, error) {
	var primary, secondary ResourceRef
	for _, resource := range plan.Resources {
		switch strings.TrimSpace(resource.OwnerMarker) {
		case strings.TrimSpace(primaryOwner):
			primary = resource
		case strings.TrimSpace(secondaryOwner):
			secondary = resource
		}
	}
	if primary.URL == "" || secondary.URL == "" {
		return ResourceRef{}, ResourceRef{}, fmt.Errorf("ownership workflow needs one resource for each actor")
	}
	return primary, secondary, nil
}

func (r *Runner) login(ctx context.Context, actor Actor, cfg AuthConfig) (string, int, []byte, error) {
	var body []byte
	contentType := "application/json"
	if cfg.BodyType == "form" {
		values := url.Values{}
		values.Set(cfg.UsernameField, actor.Username)
		values.Set(cfg.PasswordField, actor.Secret)
		body = []byte(values.Encode())
		contentType = "application/x-www-form-urlencoded"
	} else {
		payload := map[string]string{
			cfg.UsernameField: actor.Username,
			cfg.PasswordField: actor.Secret,
		}
		body, _ = json.Marshal(payload)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", actor.LoginURL, bytes.NewReader(body))
	if err != nil {
		return "", 0, nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := r.client.Do(req)
	if err != nil || resp == nil {
		return "", 0, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return ExtractBearerToken(string(respBody)), resp.StatusCode, respBody, nil
}

func (r *Runner) fetchResource(ctx context.Context, rawURL, token, ownerMarker string, cfg AuthConfig) (ResourceResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return ResourceResult{}, err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	applyWorkflowAuth(req, token, cfg)
	resp, err := r.client.Do(req)
	if err != nil || resp == nil {
		return ResourceResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	ownerOK, ownerEvidence := BodyContainsOwnershipMarker(body, ownerMarker)
	return ResourceResult{
		URL:                rawURL,
		Status:             resp.StatusCode,
		Body:               body,
		OwnerProofVisible:  ownerOK,
		OwnerProofEvidence: ownerEvidence,
	}, nil
}

func (r *Runner) mutateResource(ctx context.Context, step Step, token, ownerMarker string, cfg AuthConfig) (ResourceResult, error) {
	method := strings.ToUpper(strings.TrimSpace(step.Method))
	if method == "" {
		method = "PATCH"
	}
	rawURL := step.URL
	var body io.Reader
	contentType := ""
	switch step.Action {
	case StepMutateParam:
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return ResourceResult{}, err
		}
		q := parsed.Query()
		q.Set(step.Field, step.Value)
		parsed.RawQuery = q.Encode()
		rawURL = parsed.String()
	case StepMutateBody:
		if strings.EqualFold(cfg.MutationBodyType, "form") {
			values := url.Values{}
			values.Set(step.Field, step.Value)
			body = strings.NewReader(values.Encode())
			contentType = "application/x-www-form-urlencoded"
		} else {
			payload := map[string]string{step.Field: step.Value}
			encoded, _ := json.Marshal(payload)
			body = bytes.NewReader(encoded)
			contentType = "application/json"
		}
	default:
		return ResourceResult{}, fmt.Errorf("unsupported mutation action %q", step.Action)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return ResourceResult{}, err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	applyWorkflowAuth(req, token, cfg)
	resp, err := r.client.Do(req)
	if err != nil || resp == nil {
		return ResourceResult{}, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	ownerOK, ownerEvidence := BodyContainsOwnershipMarker(respBody, ownerMarker)
	return ResourceResult{
		URL:                rawURL,
		Status:             resp.StatusCode,
		Body:               respBody,
		OwnerProofVisible:  ownerOK,
		OwnerProofEvidence: ownerEvidence,
	}, nil
}

func applyWorkflowAuth(req *http.Request, token string, cfg AuthConfig) {
	if token == "" || cfg.AuthHeader == "" {
		return
	}
	if strings.EqualFold(cfg.AuthScheme, "raw") {
		req.Header.Set(cfg.AuthHeader, token)
		return
	}
	req.Header.Set(cfg.AuthHeader, cfg.AuthScheme+" "+token)
}

func isObjectSuccess(status int) bool {
	return status >= 200 && status < 300
}

func anonymousBoundaryOK(status int, ownerProofVisible bool) bool {
	if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound {
		return true
	}
	if status >= 300 && status < 400 {
		return true
	}
	return !ownerProofVisible
}

// BodyContainsOwnershipMarker looks for an expected owner/user/tenant/customer
// marker in JSON or text. It is intentionally generic and conservative: a
// match requires ownership-like keys or ownership-like surrounding words.
func BodyContainsOwnershipMarker(body []byte, expected string) (bool, string) {
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

// BodyContainsMutationValue looks for a bounded attacker-controlled value in a
// response or verification fetch. JSON matching requires the named field/value
// pair. Text fallback requires the value and either the field or a quoted JSON-
// looking occurrence, avoiding a loose substring-only confirmation.
func BodyContainsMutationValue(body []byte, field, expected string) bool {
	field = strings.TrimSpace(field)
	expected = strings.TrimSpace(expected)
	if field == "" || expected == "" || len(body) == 0 {
		return false
	}
	var v any
	if err := json.Unmarshal(body, &v); err == nil {
		if jsonFieldValueMatches(v, normalizeOwnerKey(field), expected) {
			return true
		}
	}
	lowerBody := strings.ToLower(string(body))
	lowerField := strings.ToLower(field)
	lowerExpected := strings.ToLower(expected)
	return strings.Contains(lowerBody, lowerExpected) && strings.Contains(lowerBody, lowerField)
}

func jsonFieldValueMatches(v any, normalizedField, expected string) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if normalizeOwnerKey(k) == normalizedField {
				if scalar, ok := scalarString(child); ok && ownershipMarkerMatches(scalar, expected) {
					return true
				}
			}
			if jsonFieldValueMatches(child, normalizedField, expected) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if jsonFieldValueMatches(child, normalizedField, expected) {
				return true
			}
		}
	}
	return false
}

// ExtractBearerToken pulls a JWT / bearer-looking string from a login response
// body. Covers common JSON shapes: token, access_token, jwt, id_token, and
// nested authentication objects.
func ExtractBearerToken(body string) string {
	if token := extractBearerTokenFromJSON(body); token != "" {
		return token
	}
	for _, key := range []string{`"token":"`, `"access_token":"`, `"jwt":"`, `"id_token":"`} {
		if i := strings.Index(body, key); i >= 0 {
			start := i + len(key)
			if j := strings.Index(body[start:], `"`); j > 0 {
				return body[start : start+j]
			}
		}
	}
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

func isWhitespaceOrQuote(b byte) bool {
	switch b {
	case ' ', '\n', '\r', '\t', '"', '\'', ',', '}', ']', '<', '>':
		return true
	default:
		return false
	}
}
