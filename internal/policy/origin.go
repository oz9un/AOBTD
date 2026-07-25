package policy

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Origin is a strict, comparable HTTP(S) origin. The effective port is always
// present, which makes implicit and explicit default ports equivalent.
type Origin struct {
	scheme string
	host   string
	port   uint16
}

func (o Origin) Scheme() string { return o.scheme }
func (o Origin) Host() string   { return o.host }
func (o Origin) Port() uint16   { return o.port }

// String returns a canonical origin with an explicit effective port.
func (o Origin) String() string {
	if o.scheme == "" || o.host == "" || o.port == 0 {
		return ""
	}
	return o.scheme + "://" + net.JoinHostPort(o.host, strconv.Itoa(int(o.port)))
}

// CanonicalOrigin parses an absolute HTTP(S) URL and returns its strict
// origin. Userinfo and encoded/ambiguous hosts are rejected: credentials must
// be supplied through explicit credential context, never embedded in a URL.
func CanonicalOrigin(rawURL string) (Origin, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return Origin{}, fmt.Errorf("empty URL")
	}
	if strings.Contains(rawURL, `\`) {
		return Origin{}, fmt.Errorf("backslash in HTTP URL is forbidden")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Origin{}, fmt.Errorf("parse URL: %w", err)
	}
	if parsed.Opaque != "" || !parsed.IsAbs() || parsed.Host == "" {
		return Origin{}, fmt.Errorf("URL must be absolute HTTP(S) URL")
	}
	if parsed.User != nil {
		return Origin{}, fmt.Errorf("URL userinfo is forbidden")
	}
	if strings.Contains(parsed.Host, "%") {
		return Origin{}, fmt.Errorf("encoded or zone-qualified host is forbidden")
	}

	scheme := strings.ToLower(parsed.Scheme)
	var defaultPort uint16
	switch scheme {
	case "http":
		defaultPort = 80
	case "https":
		defaultPort = 443
	default:
		return Origin{}, fmt.Errorf("unsupported URL scheme %q", parsed.Scheme)
	}

	host, err := canonicalHost(parsed.Hostname())
	if err != nil {
		return Origin{}, err
	}
	port := defaultPort
	if rawPort := parsed.Port(); rawPort != "" {
		value, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || value == 0 {
			return Origin{}, fmt.Errorf("invalid URL port %q", rawPort)
		}
		port = uint16(value)
	} else if strings.HasSuffix(parsed.Host, ":") {
		return Origin{}, fmt.Errorf("empty URL port")
	}

	return Origin{scheme: scheme, host: host, port: port}, nil
}

func canonicalHost(rawHost string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(rawHost, "."))
	if host == "" {
		return "", fmt.Errorf("empty URL host")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", fmt.Errorf("zone-qualified IP host is forbidden")
		}
		return addr.String(), nil
	}
	if len(host) > 253 {
		return "", fmt.Errorf("URL host is too long")
	}
	if numericHostLike(host) {
		return "", fmt.Errorf("non-canonical numeric host %q", rawHost)
	}
	for _, r := range host {
		if r > 127 || !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.') {
			return "", fmt.Errorf("invalid URL host %q", rawHost)
		}
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid URL host label in %q", rawHost)
		}
	}
	return host, nil
}

func numericHostLike(host string) bool {
	for _, r := range host {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// Scope is an allowlist of canonical origins. Exact entries remain exact;
// subdomains are authorized only through an explicit wildcard origin such as
// https://*.example.com. Alternate schemes and ports require separate entries.
type Scope struct {
	origins   map[Origin]struct{}
	wildcards []wildcardOrigin
}

type wildcardOrigin struct {
	scheme string
	host   string
	port   uint16
}

// NewScope validates and canonicalizes the operator-declared origin scope.
// Paths in entries are ignored because the Day 3 invariant is origin-scoped.
func NewScope(rawOrigins []string) (Scope, error) {
	if len(rawOrigins) == 0 {
		return Scope{}, fmt.Errorf("scope must contain at least one origin")
	}
	scope := Scope{origins: make(map[Origin]struct{}, len(rawOrigins))}
	for i, raw := range rawOrigins {
		if wildcard, ok, err := parseWildcardOrigin(raw); ok || err != nil {
			if err != nil {
				return Scope{}, fmt.Errorf("scope entry %d: %w", i, err)
			}
			scope.wildcards = append(scope.wildcards, wildcard)
			continue
		}
		origin, err := CanonicalOrigin(raw)
		if err != nil {
			return Scope{}, fmt.Errorf("scope entry %d: %w", i, err)
		}
		scope.origins[origin] = struct{}{}
	}
	return scope, nil
}

// Contains reports exact or explicitly wildcarded canonical-origin membership.
func (s Scope) Contains(origin Origin) bool {
	if _, ok := s.origins[origin]; ok {
		return true
	}
	for _, wildcard := range s.wildcards {
		if origin.scheme == wildcard.scheme && origin.port == wildcard.port &&
			origin.host != wildcard.host && strings.HasSuffix(origin.host, "."+wildcard.host) {
			return true
		}
	}
	return false
}

func parseWildcardOrigin(raw string) (wildcardOrigin, bool, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://*.") {
		return wildcardOrigin{}, false, nil
	}
	// Replacing the wildcard label with a valid throwaway label lets the same
	// strict parser validate scheme, port, userinfo, and host syntax.
	origin, err := CanonicalOrigin(strings.Replace(raw, "://*.", "://wildcard.", 1))
	if err != nil {
		return wildcardOrigin{}, true, fmt.Errorf("invalid wildcard origin: %w", err)
	}
	if !strings.HasPrefix(origin.host, "wildcard.") {
		return wildcardOrigin{}, true, fmt.Errorf("wildcard must be the complete left-most host label")
	}
	host := strings.TrimPrefix(origin.host, "wildcard.")
	if host == "" || !strings.Contains(host, ".") {
		return wildcardOrigin{}, true, fmt.Errorf("wildcard scope requires a domain suffix")
	}
	return wildcardOrigin{scheme: origin.scheme, host: host, port: origin.port}, true, nil
}

// MatchURL canonicalizes a URL and reports whether its origin is in scope.
func (s Scope) MatchURL(rawURL string) (Origin, bool, error) {
	origin, err := CanonicalOrigin(rawURL)
	if err != nil {
		return Origin{}, false, err
	}
	return origin, s.Contains(origin), nil
}

// Origins returns a deterministic copy of the configured origins.
func (s Scope) Origins() []Origin {
	origins := make([]Origin, 0, len(s.origins))
	for origin := range s.origins {
		origins = append(origins, origin)
	}
	sort.Slice(origins, func(i, j int) bool { return origins[i].String() < origins[j].String() })
	return origins
}
