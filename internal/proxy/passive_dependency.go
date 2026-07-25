package proxy

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/ozzyw/aobtd/internal/policy"
)

// passiveRenderDestinations is deliberately narrower than the Fetch
// specification. These four destinations are sufficient to paint the target
// page while excluding documents, frames, workers, media, manifests, beacons,
// XHR, and fetch (the latter two use the "empty" destination).
var passiveRenderDestinations = map[string]struct{}{
	"font":   {},
	"image":  {},
	"script": {},
	"style":  {},
}

// sensitivePassiveURLKeys are credentials or credential-like signatures that
// must never use the passive-render exception to cross the scope boundary.
// Keys are normalized by removing '-', '_', and '.' before comparison.
var sensitivePassiveURLKeys = map[string]struct{}{
	"accesstoken":        {},
	"apikey":             {},
	"awsaccesskeyid":     {},
	"auth":               {},
	"authorization":      {},
	"credential":         {},
	"credentials":        {},
	"csrftoken":          {},
	"idtoken":            {},
	"jwt":                {},
	"key":                {},
	"password":           {},
	"passwd":             {},
	"privatekey":         {},
	"pwd":                {},
	"refreshtoken":       {},
	"session":            {},
	"sessionid":          {},
	"sig":                {},
	"signature":          {},
	"secret":             {},
	"token":              {},
	"xamzcredential":     {},
	"xamzsecuritytoken":  {},
	"xamzsignature":      {},
	"xgoogcredential":    {},
	"xgoogsecuritytoken": {},
	"xgoogsignature":     {},
	"xsrftoken":          {},
}

// allowPassiveRenderDependency recognizes the only proxy-local exception to
// an HTTP policy denial. It does not expand the policy Engine's declared
// scope: it only lets Chromium retrieve a credential-free static dependency
// needed to paint an already-authorized page. Callers MUST force-filter the
// corresponding traffic entry before invoking the capture callback.
func allowPassiveRenderDependency(
	req *http.Request,
	decision policy.Decision,
	executionPolicy *policy.Engine,
) bool {
	return allowPassiveRenderDependencyWithRegistry(req, decision, executionPolicy, nil)
}

func allowPassiveRenderDependencyWithRegistry(
	req *http.Request,
	decision policy.Decision,
	executionPolicy *policy.Engine,
	registry *passiveRenderAssetRegistry,
) bool {
	if req == nil || req.URL == nil || executionPolicy == nil ||
		decision.Allowed || decision.Code != policy.CodeOutOfScope {
		return false
	}

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	// GET-with-body is legal HTTP but it is not a passive browser paint fetch.
	if (req.Body != nil && req.Body != http.NoBody) || req.ContentLength > 0 || len(req.TransferEncoding) > 0 {
		return false
	}
	if !passiveRenderTargetAllowed(req.URL) {
		return false
	}

	destination := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Dest")))
	if _, ok := passiveRenderDestinations[destination]; !ok {
		return false
	}
	if hasSensitivePassiveHeaders(req.Header) || urlHasSensitivePassiveMaterial(req.URL) {
		return false
	}

	refererRaw := strings.TrimSpace(req.Header.Get("Referer"))
	if refererRaw == "" {
		return registry != nil && registry.AllowsExact(req.URL, destination)
	}
	if strings.Contains(refererRaw, `\`) {
		return false
	}
	referer, err := url.Parse(refererRaw)
	if err != nil || referer == nil || !referer.IsAbs() || referer.Host == "" ||
		referer.User != nil || referer.Fragment != "" || urlHasSensitivePassiveMaterial(referer) {
		return false
	}

	// Authorize a fresh, credential-free GET to the referring page. This proves
	// both that its origin is operator-declared and that the current authority
	// permits reading it. We intentionally do not trust Origin or Sec-Fetch-Site.
	refererDecision := executionPolicy.Authorize(policy.Action{
		TargetURL: referer.String(),
		Method:    http.MethodGet,
	})
	return refererDecision.Allowed
}

// passiveRenderTargetAllowed keeps the render-only exception away from local,
// link-local, and private network services. Operator-declared scope may
// intentionally contain such a target, but an off-scope page dependency must
// never turn an <img> or <script> tag into a browser-side metadata/internal
// network fetch.
func passiveRenderTargetAllowed(target *url.URL) bool {
	if target == nil || target.User != nil || target.Host == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(target.Scheme)) {
	case "http", "https":
	default:
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target.Hostname()), "."))
	if host == "" || host == "localhost" || host == "metadata.google.internal" ||
		strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".home.arpa") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
			!ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
	}
	return true
}

func hasSensitivePassiveHeaders(headers http.Header) bool {
	if policy.HasSensitiveRequestHeaders(headers) {
		return true
	}
	for name, values := range headers {
		if len(values) == 0 {
			continue
		}
		normalized := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		switch {
		case normalized == "api-key",
			normalized == "authentication",
			normalized == "key",
			normalized == "password",
			normalized == "passwd",
			normalized == "secret",
			normalized == "session",
			normalized == "signature",
			normalized == "token",
			normalized == "x-auth",
			normalized == "x-session",
			normalized == "session-id",
			strings.Contains(normalized, "api-key"),
			strings.Contains(normalized, "credential"),
			strings.Contains(normalized, "session-id"),
			strings.HasSuffix(normalized, "-password"),
			strings.HasSuffix(normalized, "-passwd"),
			strings.HasSuffix(normalized, "-secret"),
			strings.HasSuffix(normalized, "-signature"):
			return true
		}
	}
	return false
}

func urlHasSensitivePassiveMaterial(parsed *url.URL) bool {
	if parsed == nil || parsed.RawQuery == "" {
		return false
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return true
	}
	for key := range query {
		normalized := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(key))
		if _, sensitive := sensitivePassiveURLKeys[normalized]; sensitive {
			return true
		}
		if strings.HasSuffix(normalized, "token") ||
			strings.HasSuffix(normalized, "secret") ||
			strings.Contains(normalized, "password") ||
			strings.HasSuffix(normalized, "signature") {
			return true
		}
	}
	return false
}
