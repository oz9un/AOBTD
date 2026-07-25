package policy

import (
	"fmt"
	"net/url"
	"strings"
)

// DecisionCode is stable enough to persist in an audit trail; Reason remains
// the human-readable explanation shown to the operator.
type DecisionCode string

const (
	CodeAllowed                  DecisionCode = "allowed"
	CodeInvalidTarget            DecisionCode = "invalid_target"
	CodeOutOfScope               DecisionCode = "out_of_scope"
	CodeActionClassRequired      DecisionCode = "action_class_required"
	CodeInvalidActionClass       DecisionCode = "invalid_action_class"
	CodeUnsupportedMethod        DecisionCode = "unsupported_method"
	CodeAuthorityDenied          DecisionCode = "authority_denied"
	CodeCredentialOriginRequired DecisionCode = "credential_origin_required"
	CodeInvalidCredentialOrigin  DecisionCode = "invalid_credential_origin"
	CodeCredentialOriginMismatch DecisionCode = "credential_origin_mismatch"
	CodeInvalidRedirectSource    DecisionCode = "invalid_redirect_source"
	CodeRedirectSourceOutOfScope DecisionCode = "redirect_source_out_of_scope"
	CodeInvalidRedirectLocation  DecisionCode = "invalid_redirect_location"
	CodeHostOverrideMismatch     DecisionCode = "host_override_mismatch"
)

// CredentialContext contains only where a credential is allowed to travel,
// never the secret itself. A non-nil context marks an action credential-
// bearing and activates the invariant same-origin check.
type CredentialContext struct {
	Origin string `json:"origin"`
}

// Action is a target-directed operation proposed by trusted application code.
// Class may raise the method-implied impact (for a mutating GET, for example),
// but Authorize never lets it lower that minimum.
type Action struct {
	TargetURL   string             `json:"target_url"`
	Method      string             `json:"method,omitempty"`
	Class       ActionClass        `json:"class,omitempty"`
	Credentials *CredentialContext `json:"credentials,omitempty"`
}

// Decision is an explicit, auditable allow or deny result.
type Decision struct {
	Allowed         bool             `json:"allowed"`
	Code            DecisionCode     `json:"code"`
	Reason          string           `json:"reason"`
	Authority       TestingAuthority `json:"testing_authority"`
	TargetURL       string           `json:"target_url"`
	CanonicalOrigin string           `json:"canonical_origin,omitempty"`
	Classes         []ActionClass    `json:"classes,omitempty"`
}

// Engine is an immutable authority + exact-origin policy boundary.
type Engine struct {
	authority TestingAuthority
	scope     Scope
}

// New constructs a policy engine from explicit operator authority and scope.
func New(authority TestingAuthority, rawOrigins []string) (*Engine, error) {
	if !authority.Valid() {
		return nil, fmt.Errorf("invalid testing authority %q", authority)
	}
	scope, err := NewScope(rawOrigins)
	if err != nil {
		return nil, err
	}
	return &Engine{authority: authority, scope: scope}, nil
}

func (e *Engine) Authority() TestingAuthority { return e.authority }
func (e *Engine) Scope() Scope                { return e.scope }

// Authorize applies scope, credential-origin, method-impact, and authority
// checks in one place. All denials include a stable code and operator-facing
// reason; no caller needs to infer why an action was blocked.
func (e *Engine) Authorize(action Action) Decision {
	decision := Decision{
		Authority: e.authority,
		TargetURL: strings.TrimSpace(action.TargetURL),
	}
	targetOrigin, err := CanonicalOrigin(decision.TargetURL)
	if err != nil {
		return decision.deny(CodeInvalidTarget, fmt.Sprintf("target URL is invalid: %v", err))
	}
	decision.CanonicalOrigin = targetOrigin.String()
	if !e.scope.Contains(targetOrigin) {
		return decision.deny(CodeOutOfScope,
			fmt.Sprintf("target origin %s is not in the operator-declared scope", targetOrigin))
	}

	impact, code, reason := effectiveImpact(action)
	if code != "" {
		return decision.deny(code, reason)
	}
	decision.Classes = []ActionClass{impact}

	if action.Credentials != nil {
		decision.Classes = append(decision.Classes, ActionCredentialBearing)
		if strings.TrimSpace(action.Credentials.Origin) == "" {
			return decision.deny(CodeCredentialOriginRequired,
				"credential-bearing action must declare the credential's bound origin")
		}
		credentialOrigin, err := CanonicalOrigin(action.Credentials.Origin)
		if err != nil {
			return decision.deny(CodeInvalidCredentialOrigin,
				fmt.Sprintf("credential origin is invalid: %v", err))
		}
		if credentialOrigin != targetOrigin {
			return decision.deny(CodeCredentialOriginMismatch,
				fmt.Sprintf("credentials bound to %s cannot be sent to %s", credentialOrigin, targetOrigin))
		}
	}

	for _, class := range decision.Classes {
		if !e.authority.Allows(class) {
			return decision.deny(CodeAuthorityDenied,
				fmt.Sprintf("testing authority %s does not permit %s actions", e.authority, class))
		}
	}
	return decision.allow(fmt.Sprintf("testing authority %s permits %s action inside %s",
		e.authority, impact, targetOrigin))
}

func effectiveImpact(action Action) (ActionClass, DecisionCode, string) {
	method := strings.TrimSpace(action.Method)
	explicit := action.Class
	if explicit != "" && !isImpactClass(explicit) {
		return "", CodeInvalidActionClass,
			fmt.Sprintf("%q is not a valid impact class", explicit)
	}

	if method == "" {
		if explicit == "" {
			return "", CodeActionClassRequired,
				"non-HTTP action must declare an impact class"
		}
		return explicit, "", ""
	}

	methodClass, ok := ClassifyMethod(method)
	if !ok {
		return "", CodeUnsupportedMethod,
			fmt.Sprintf("HTTP method %q has no trusted classification", method)
	}
	if explicit == "" || impactRank(methodClass) >= impactRank(explicit) {
		return methodClass, "", ""
	}
	return explicit, "", ""
}

func (d Decision) allow(reason string) Decision {
	d.Allowed = true
	d.Code = CodeAllowed
	d.Reason = reason
	return d
}

func (d Decision) deny(code DecisionCode, reason string) Decision {
	d.Allowed = false
	d.Code = code
	d.Reason = reason
	return d
}

// RedirectHop describes one specific redirect transition. Callers must invoke
// AuthorizeRedirectHop for every hop, passing the actual redirected method and
// whether credentials would be retained on that request.
type RedirectHop struct {
	FromURL     string             `json:"from_url"`
	Location    string             `json:"location"`
	Method      string             `json:"method,omitempty"`
	Class       ActionClass        `json:"class,omitempty"`
	Credentials *CredentialContext `json:"credentials,omitempty"`
}

// AuthorizeRedirectHop resolves a relative Location against FromURL, verifies
// that the source itself is still in scope, then runs the full policy against
// the destination. Repeating this call per hop prevents an allowed first hop
// from laundering a later off-scope redirect.
func (e *Engine) AuthorizeRedirectHop(hop RedirectHop) Decision {
	fromURL := strings.TrimSpace(hop.FromURL)
	fromOrigin, err := CanonicalOrigin(fromURL)
	if err != nil {
		return Decision{Authority: e.authority, TargetURL: fromURL}.deny(
			CodeInvalidRedirectSource, fmt.Sprintf("redirect source URL is invalid: %v", err))
	}
	if !e.scope.Contains(fromOrigin) {
		return Decision{
			Authority:       e.authority,
			TargetURL:       fromURL,
			CanonicalOrigin: fromOrigin.String(),
		}.deny(CodeRedirectSourceOutOfScope,
			fmt.Sprintf("redirect source origin %s is not in scope", fromOrigin))
	}

	base, err := url.Parse(fromURL)
	if err != nil {
		return Decision{Authority: e.authority, TargetURL: fromURL}.deny(
			CodeInvalidRedirectSource, fmt.Sprintf("redirect source URL is invalid: %v", err))
	}
	rawLocation := strings.TrimSpace(hop.Location)
	if strings.Contains(rawLocation, `\`) {
		return Decision{Authority: e.authority, TargetURL: hop.Location}.deny(
			CodeInvalidRedirectLocation, "redirect Location contains an ambiguous backslash")
	}
	location, err := url.Parse(rawLocation)
	if err != nil {
		return Decision{Authority: e.authority, TargetURL: hop.Location}.deny(
			CodeInvalidRedirectLocation, fmt.Sprintf("redirect Location is invalid: %v", err))
	}
	resolved := base.ResolveReference(location)
	resolved.Fragment = ""
	decision := e.Authorize(Action{
		TargetURL:   resolved.String(),
		Method:      hop.Method,
		Class:       hop.Class,
		Credentials: hop.Credentials,
	})
	if !decision.Allowed {
		decision.Reason = "redirect hop denied: " + decision.Reason
	}
	return decision
}
