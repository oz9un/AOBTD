package policy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type requestContextKey uint8

const (
	actionClassContextKey requestContextKey = iota + 1
	credentialOriginContextKey
)

// WithActionClass raises the impact classification for a request whose HTTP
// method alone understates its effect (for example a destructive GET route).
// Engine.Authorize still prevents callers from lowering the method minimum.
func WithActionClass(ctx context.Context, class ActionClass) context.Context {
	return context.WithValue(ctx, actionClassContextKey, class)
}

// WithCredentialOrigin marks a request as credential-bearing and binds the
// credential to its source origin. The secret itself never enters policy.
func WithCredentialOrigin(ctx context.Context, origin string) context.Context {
	return context.WithValue(ctx, credentialOriginContextKey, strings.TrimSpace(origin))
}

// DecisionAudit receives denied decisions for persistence in the scan audit
// trail. Allowed requests are intentionally not emitted here: traffic capture
// is already the high-volume positive audit path.
type DecisionAudit func(Decision)

// HTTPOptions configures HTTP enforcement without coupling policy to storage.
// CredentialOrigin is the fallback binding for sensitive headers on clients
// dedicated to one operator-selected target origin.
type HTTPOptions struct {
	CredentialOrigin string
	Audit            DecisionAudit
}

// DeniedError carries the exact policy decision back through net/http.
type DeniedError struct {
	Decision Decision
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("policy denied request (%s): %s", e.Decision.Code, e.Decision.Reason)
}

// DecisionFromError unwraps net/http's url.Error and returns a policy denial.
func DecisionFromError(err error) (Decision, bool) {
	var denied *DeniedError
	if !errors.As(err, &denied) {
		return Decision{}, false
	}
	return denied.Decision, true
}

// ProtectHTTPClient returns a shallow clone that enforces policy before the
// first network byte and at every redirect hop. The caller's timeout,
// transport, cookie jar, and existing CheckRedirect behavior are preserved.
func ProtectHTTPClient(base *http.Client, engine *Engine, opts HTTPOptions) *http.Client {
	if engine == nil {
		panic("policy: ProtectHTTPClient requires a non-nil engine")
	}
	if base == nil {
		base = &http.Client{}
	}
	protected := *base
	next := base.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	protected.Transport = &policyTransport{
		engine: engine,
		next:   next,
		opts:   opts,
	}

	existingRedirect := base.CheckRedirect
	protected.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 {
			decision := engine.AuthorizeRedirectHop(RedirectHop{
				FromURL:     via[len(via)-1].URL.String(),
				Location:    req.URL.String(),
				Method:      req.Method,
				Class:       actionClassFromContext(req.Context()),
				Credentials: credentialContextForRequest(req, opts.CredentialOrigin),
			})
			if !decision.Allowed {
				auditDenied(opts.Audit, decision)
				return &DeniedError{Decision: decision}
			}
		}
		if existingRedirect != nil {
			return existingRedirect(req, via)
		}
		return nil
	}
	return &protected
}

type policyTransport struct {
	engine *Engine
	next   http.RoundTripper
	opts   HTTPOptions
}

func (t *policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	decision := t.engine.AuthorizeHTTPRequest(req, t.opts.CredentialOrigin)
	if !decision.Allowed {
		auditDenied(t.opts.Audit, decision)
		return nil, &DeniedError{Decision: decision}
	}
	return t.next.RoundTrip(req)
}

// AuthorizeHTTPRequest is the shared net/http and MITM-proxy boundary. It
// derives an absolute URL for origin-form proxy requests, validates Host
// overrides, classifies the method/context, and binds sensitive headers.
func (e *Engine) AuthorizeHTTPRequest(req *http.Request, fallbackCredentialOrigin string) Decision {
	if req == nil || req.URL == nil {
		return Decision{Authority: e.Authority()}.deny(CodeInvalidTarget, "HTTP request has no target URL")
	}
	targetURL, urlErr := absoluteRequestURL(req)
	if urlErr != nil {
		return Decision{Authority: e.Authority(), TargetURL: req.URL.String()}.
			deny(CodeInvalidTarget, urlErr.Error())
	}
	if strings.TrimSpace(req.Host) != "" && req.URL.IsAbs() && req.URL.Host != "" {
		requestOrigin, requestErr := CanonicalOrigin(targetURL)
		overrideOrigin, overrideErr := CanonicalOrigin(req.URL.Scheme + "://" + req.Host)
		if requestErr != nil || overrideErr != nil || requestOrigin != overrideOrigin {
			reason := fmt.Sprintf("HTTP Host override %q does not match request origin", req.Host)
			if overrideErr != nil {
				reason = fmt.Sprintf("HTTP Host override %q is invalid: %v", req.Host, overrideErr)
			}
			decision := Decision{Authority: e.Authority(), TargetURL: targetURL}.
				deny(CodeHostOverrideMismatch, reason)
			if requestErr == nil {
				decision.CanonicalOrigin = requestOrigin.String()
			}
			return decision
		}
	}
	return e.Authorize(Action{
		TargetURL:   targetURL,
		Method:      req.Method,
		Class:       actionClassFromContext(req.Context()),
		Credentials: credentialContextForRequest(req, fallbackCredentialOrigin),
	})
}

func absoluteRequestURL(req *http.Request) (string, error) {
	if req.URL.IsAbs() && req.URL.Host != "" {
		return req.URL.String(), nil
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		host = strings.TrimSpace(req.URL.Host)
	}
	if host == "" {
		return "", fmt.Errorf("HTTP request target has no host")
	}
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	relative := *req.URL
	relative.Scheme = ""
	relative.Host = ""
	base, err := url.Parse(scheme + "://" + host)
	if err != nil {
		return "", fmt.Errorf("HTTP request target is invalid: %w", err)
	}
	return base.ResolveReference(&relative).String(), nil
}

func actionClassFromContext(ctx context.Context) ActionClass {
	class, _ := ctx.Value(actionClassContextKey).(ActionClass)
	return class
}

func credentialContextForRequest(req *http.Request, fallbackOrigin string) *CredentialContext {
	origin, explicitlyBound := req.Context().Value(credentialOriginContextKey).(string)
	if !explicitlyBound && !HasSensitiveRequestHeaders(req.Header) {
		return nil
	}
	if strings.TrimSpace(origin) == "" {
		origin = strings.TrimSpace(fallbackOrigin)
	}
	return &CredentialContext{Origin: origin}
}

// HasSensitiveRequestHeaders reports whether headers carry authentication or
// session material that must be bound to an origin.
func HasSensitiveRequestHeaders(headers http.Header) bool {
	for name, values := range headers {
		if len(values) == 0 {
			continue
		}
		normalized := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		switch {
		case normalized == "authorization",
			normalized == "proxy-authorization",
			normalized == "cookie",
			normalized == "x-api-key",
			strings.Contains(normalized, "csrf"),
			strings.HasSuffix(normalized, "-token"):
			return true
		}
	}
	return false
}

func auditDenied(audit DecisionAudit, decision Decision) {
	if audit != nil {
		audit(decision)
	}
}
