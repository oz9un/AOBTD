package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type graphProjectionOrigin struct {
	scheme string
	host   string
	port   string
}

type graphProjectionWildcard struct {
	scheme string
	host   string
	port   string
}

type graphProjectionScope struct {
	origins   map[graphProjectionOrigin]struct{}
	wildcards []graphProjectionWildcard
}

// graphProjectionScopeFromConfig reconstructs the operator-declared origin
// allowlist used by the scanner. Discovery records may include off-scope
// provenance, so projection must use the authorization boundary instead of
// guessing from registrable domains or observed traffic.
func graphProjectionScopeFromConfig(target, configJSON string) graphProjectionScope {
	var persisted struct {
		Scope []string `json:"scope"`
		Scan  struct {
			Scope []string `json:"scope"`
		} `json:"scan"`
	}
	_ = json.Unmarshal([]byte(configJSON), &persisted)
	rules := persisted.Scan.Scope
	if len(rules) == 0 {
		rules = persisted.Scope
	}
	if len(rules) == 0 {
		rules = []string{target}
	}
	if scope, err := newGraphProjectionScope(rules); err == nil {
		return scope
	}
	scope, _ := newGraphProjectionScope([]string{target})
	return scope
}

func newGraphProjectionScope(rules []string) (graphProjectionScope, error) {
	scope := graphProjectionScope{origins: make(map[graphProjectionOrigin]struct{}, len(rules))}
	for _, raw := range rules {
		trimmed := strings.TrimSpace(raw)
		wildcard := strings.Contains(trimmed, "://*.")
		if wildcard {
			trimmed = strings.Replace(trimmed, "://*.", "://graph-wildcard.", 1)
		}
		origin, err := graphProjectionOriginForURL(trimmed)
		if err != nil {
			return graphProjectionScope{}, err
		}
		if wildcard {
			host := strings.TrimPrefix(origin.host, "graph-wildcard.")
			if host == origin.host || host == "" || !strings.Contains(host, ".") {
				return graphProjectionScope{}, fmt.Errorf("invalid wildcard scope %q", raw)
			}
			scope.wildcards = append(scope.wildcards, graphProjectionWildcard{
				scheme: origin.scheme,
				host:   host,
				port:   origin.port,
			})
			continue
		}
		scope.origins[origin] = struct{}{}
	}
	if len(scope.origins) == 0 && len(scope.wildcards) == 0 {
		return graphProjectionScope{}, fmt.Errorf("scope must contain at least one origin")
	}
	return scope, nil
}

func graphProjectionOriginForURL(raw string) (graphProjectionOrigin, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !parsed.IsAbs() || parsed.User != nil || parsed.Hostname() == "" {
		return graphProjectionOrigin{}, fmt.Errorf("invalid absolute scope URL %q", raw)
	}
	scheme := strings.ToLower(parsed.Scheme)
	port := parsed.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return graphProjectionOrigin{}, fmt.Errorf("unsupported scope scheme %q", parsed.Scheme)
		}
	} else if value, err := strconv.ParseUint(port, 10, 16); err != nil || value == 0 {
		return graphProjectionOrigin{}, fmt.Errorf("invalid scope port %q", port)
	}
	return graphProjectionOrigin{
		scheme: scheme,
		host:   strings.ToLower(strings.TrimSuffix(parsed.Hostname(), ".")),
		port:   port,
	}, nil
}

func (s graphProjectionScope) MatchURL(raw string) (graphProjectionOrigin, bool, error) {
	origin, err := graphProjectionOriginForURL(raw)
	if err != nil {
		return graphProjectionOrigin{}, false, err
	}
	if _, ok := s.origins[origin]; ok {
		return origin, true, nil
	}
	for _, wildcard := range s.wildcards {
		if origin.scheme == wildcard.scheme && origin.port == wildcard.port &&
			origin.host != wildcard.host && strings.HasSuffix(origin.host, "."+wildcard.host) {
			return origin, true, nil
		}
	}
	return origin, false, nil
}

type graphFindingContext struct {
	Method      string
	Path        string
	EndpointURL string
}

// graphFindingTargetContext resolves both finding endpoint shapes used by
// agents: "METHOD /path" and an absolute URL. It is intentionally local to
// graph projection so the API does not depend on finding-detail presentation.
func graphFindingTargetContext(scanTarget, endpointID, pocRequest string) graphFindingContext {
	method, endpoint := graphSplitFindingEndpoint(endpointID)
	if method == "" {
		method, endpoint = graphRequestLineParts(pocRequest, endpoint)
	}
	if method == "" {
		method = http.MethodGet
	}
	ctx := graphFindingContext{Method: method}
	if endpoint == "" {
		return ctx
	}
	resolved := endpoint
	if parsed, err := url.Parse(endpoint); err != nil || !parsed.IsAbs() {
		base, baseErr := url.Parse(scanTarget)
		ref, refErr := url.Parse(endpoint)
		if baseErr == nil && refErr == nil && base.Scheme != "" && base.Host != "" {
			resolved = base.ResolveReference(ref).String()
		}
	}
	ctx.EndpointURL = resolved
	if parsed, err := url.Parse(resolved); err == nil {
		ctx.Path = parsed.RequestURI()
	}
	if ctx.Path == "" {
		ctx.Path = endpoint
	}
	return ctx
}

func graphSplitFindingEndpoint(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	parts := strings.Fields(raw)
	if len(parts) >= 2 && graphHTTPMethod(parts[0]) {
		return strings.ToUpper(parts[0]), strings.TrimSpace(strings.TrimPrefix(raw, parts[0]))
	}
	return "", raw
}

func graphRequestLineParts(raw, fallbackEndpoint string) (string, string) {
	line := strings.TrimSpace(raw)
	if index := strings.IndexByte(line, '\n'); index >= 0 {
		line = strings.TrimSpace(line[:index])
	}
	parts := strings.Fields(line)
	if len(parts) >= 2 && graphHTTPMethod(parts[0]) {
		endpoint := fallbackEndpoint
		if endpoint == "" {
			endpoint = parts[1]
		}
		return strings.ToUpper(parts[0]), endpoint
	}
	return "", fallbackEndpoint
}

func graphHTTPMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
