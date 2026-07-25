package target

import (
	"fmt"
	"net/url"
	"strings"
)

// StartDeclaration is the normalized form of the operator's target input.
// Target is always a concrete, DNS-reachable URL. ScopeRule is populated when
// the operator entered a wildcard declaration such as *.example.com.
type StartDeclaration struct {
	Target      string
	ScopeRule   string
	WasWildcard bool
}

// NormalizeStartDeclaration accepts a URL, a bare host, or a wildcard domain.
// Wildcards are authorization rules, not DNS names, so *.example.com becomes
// the concrete seed https://example.com plus the explicit scope rule
// https://*.example.com. Canonical apex/www resolution happens afterwards.
func NormalizeStartDeclaration(raw string) (StartDeclaration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return StartDeclaration{}, fmt.Errorf("target is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return StartDeclaration{}, fmt.Errorf("invalid target URL %q", raw)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return StartDeclaration{}, fmt.Errorf("unsupported target scheme %q", parsed.Scheme)
	}

	hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if !strings.Contains(hostname, "*") {
		return StartDeclaration{Target: parsed.String()}, nil
	}
	if !strings.HasPrefix(hostname, "*.") || strings.Count(hostname, "*") != 1 {
		return StartDeclaration{}, fmt.Errorf("wildcard must be the complete left-most host label")
	}

	suffix := strings.TrimPrefix(hostname, "*.")
	if suffix == "" || !strings.Contains(suffix, ".") {
		return StartDeclaration{}, fmt.Errorf("wildcard scope requires a domain suffix")
	}
	seedHost := suffix
	if port := parsed.Port(); port != "" {
		seedHost += ":" + port
	}
	parsed.Host = seedHost

	scopeHost := "*." + suffix
	if port := parsed.Port(); port != "" {
		// parsed.Port still reflects the seed host set immediately above.
		scopeHost += ":" + port
	}
	return StartDeclaration{
		Target:      parsed.String(),
		ScopeRule:   parsed.Scheme + "://" + scopeHost,
		WasWildcard: true,
	}, nil
}
