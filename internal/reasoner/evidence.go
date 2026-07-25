package reasoner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/discovery"
	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// BuildEvidence snapshots the scan DB into the reasoner-facing Evidence.
// Called by the orchestrator before dispatching to a reasoner. Keeps the
// payload tight — no full request / response bodies.
func BuildEvidence(ctx context.Context, db *store.DB, scanID int64, target string) (Evidence, error) {
	ev := Evidence{
		ScanID:     scanID,
		Target:     target,
		CapturedAt: time.Now(),
	}

	// Login endpoints
	if eps, err := discovery.DiscoverLoginEndpoints(db, scanID); err == nil {
		ev.LoginEndpoints = convertEndpoints(eps)
	}
	// Query-param endpoints (may help JWTForgery / session-fixation
	// reasoners look at ?token=... etc.)
	if eps, err := discovery.DiscoverQueryParamEndpoints(db, scanID); err == nil {
		ev.QueryEndpoints = convertEndpoints(eps)
		if len(ev.QueryEndpoints) > 20 {
			ev.QueryEndpoints = ev.QueryEndpoints[:20]
		}
	}
	// Authenticated API endpoints (CORS / IDOR targets)
	if eps, err := discovery.DiscoverAuthenticatedAPIEndpoints(db, scanID); err == nil {
		ev.APIEndpoints = convertEndpoints(eps)
		if recovered, recErr := discovery.DiscoverRecoveredObjectIDEndpoints(db, scanID, 20); recErr == nil {
			ev.APIEndpoints = appendDiscoveredEndpoints(ev.APIEndpoints, convertEndpoints(recovered)...)
		}
		ev.APIEndpoints = trimAPIEndpoints(ev.APIEndpoints, 20)
	}
	// Emails mined from response bodies
	if emails, err := discovery.DiscoverLikelyUsernames(db, scanID, 30); err == nil {
		ev.ObservedEmails = emails
	}
	// JWT samples
	ev.JWTSamples = discoverJWTSamples(db, scanID, 10)

	// Recent findings (for reasoner context — "these are already known").
	ev.Findings = loadRecentFindings(db, scanID, 40)

	// Augment login endpoints from findings. The Verifier's proactive-probe
	// phase synthesizes POSTs to candidate login URLs without writing to
	// the traffic table; the resulting findings carry the real endpoint
	// URL. Pulling those back in bridges the evidence gap on SPA targets
	// where the crawler never captured the login POST.
	augmentLoginEndpointsFromFindings(&ev)

	return ev, nil
}

func trimAPIEndpoints(eps []DiscoveredEndpoint, limit int) []DiscoveredEndpoint {
	if limit <= 0 || len(eps) <= limit {
		return eps
	}
	out := append([]DiscoveredEndpoint(nil), eps...)
	sort.SliceStable(out, func(i, j int) bool {
		return endpointPriority(out[i]) > endpointPriority(out[j])
	})
	return out[:limit]
}

func endpointPriority(ep DiscoveredEndpoint) int {
	score := 0
	switch strings.ToUpper(strings.TrimSpace(ep.Method)) {
	case "PATCH", "PUT":
		score += 50
	case "POST":
		score += 40
	case "GET":
		score += 10
	}
	if len(ep.BodyFields) > 0 {
		score += 20
	}
	if accessEndpointLooksOwnedObject(ep) {
		score += 25
	}
	path := strings.ToLower(ep.Path)
	for _, marker := range []string{"/user", "/account", "/order", "/booking", "/profile", "/tenant", "/team", "/basket", "/cart"} {
		if strings.Contains(path, marker) {
			score += 5
			break
		}
	}
	return score
}

// augmentLoginEndpointsFromFindings looks at recent findings that are
// specifically AUTH findings on paths that look login-shaped, and adds
// their endpoint URLs to Evidence.LoginEndpoints when absent.
//
// Tightening vs earlier revision: we now require BOTH
//
//	(a) vuln_type ∈ {weak_credentials, sqli_login_bypass} — NOT bare "sqli",
//	    because a generic SQLi finding on /rest/products/search shouldn't
//	    trick AuthReasoner into POSTing credentials to a product-search URL.
//	(b) the endpoint path LooksLikeLoginPath — a second gate that catches
//	    the rare case where we misclassified a weak-credentials finding
//	    onto a non-login URL.
//
// Both conditions must hold. Previously only (a) was checked with a loose
// allowlist that included generic "sqli", which was flagged by the
// architectural review as a URL-injection vector into LoginEndpoints.
func augmentLoginEndpointsFromFindings(ev *Evidence) {
	seen := make(map[string]bool)
	for _, e := range ev.LoginEndpoints {
		seen[e.URL] = true
	}
	for _, f := range ev.Findings {
		low := strings.ToLower(f.VulnType)
		if low != "weak_credentials" && low != "sqli_login_bypass" {
			continue
		}
		// f.EndpointID format: "METHOD /path" (any verb).
		parts := strings.SplitN(f.EndpointID, " ", 2)
		if len(parts) != 2 {
			continue
		}
		method := parts[0]
		pth := parts[1]
		// Second gate: the path must look login-shaped. Catches any mis-
		// classified finding and keeps this strictly an auth-domain helper.
		if !discovery.LooksLikeLoginPath(pth) {
			continue
		}
		fullURL := strings.TrimRight(ev.Target, "/") + pth
		if seen[fullURL] {
			continue
		}
		seen[fullURL] = true
		ev.LoginEndpoints = append(ev.LoginEndpoints, DiscoveredEndpoint{
			URL:                 fullURL,
			Method:              method,
			Path:                pth,
			ExampleRequestBody:  `(confirmed by Verifier — ` + f.Title + `)`,
			ResponseContentType: "application/json",
		})
	}
}

// loadRecentFindings returns up to `limit` findings for the scan, trimmed
// to just the fields the reasoner consumes.
func loadRecentFindings(db *store.DB, scanID int64, limit int) []types.Finding {
	rows, err := db.Conn().Query(`
		SELECT title, severity, confidence, vuln_type, endpoint_id
		FROM findings
		WHERE scan_id = ?
		ORDER BY id DESC
		LIMIT ?
	`, scanID, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []types.Finding
	for rows.Next() {
		var f types.Finding
		if err := rows.Scan(&f.Title, &f.Severity, &f.Confidence, &f.VulnType, &f.EndpointID); err == nil {
			out = append(out, f)
		}
	}
	return out
}

// convertEndpoints translates discovery.DiscoveredEndpoint (internal type
// with DB-coupled fields) into the reasoner-local DiscoveredEndpoint
// (trimmed for LLM consumption).
func convertEndpoints(in []discovery.DiscoveredEndpoint) []DiscoveredEndpoint {
	out := make([]DiscoveredEndpoint, 0, len(in))
	for _, e := range in {
		if endpointContainsInvalidSentinel(e.URL) || endpointContainsInvalidSentinel(e.Path) {
			continue
		}
		out = append(out, DiscoveredEndpoint{
			URL:                 e.URL,
			Method:              e.Method,
			Path:                e.Path,
			Params:              e.Params,
			BodyFields:          e.BodyFields,
			RequestContentType:  e.RequestContentType,
			ResponseContentType: e.ResponseContentType,
			ExampleRequestBody:  e.ExampleRequestBody,
			AuthHeaders:         cloneStringMap(e.AuthHeaders),
		})
	}
	return out
}

func appendDiscoveredEndpoints(existing []DiscoveredEndpoint, candidates ...DiscoveredEndpoint) []DiscoveredEndpoint {
	seen := make(map[string]bool, len(existing)+len(candidates))
	for _, ep := range existing {
		seen[strings.ToUpper(strings.TrimSpace(ep.Method))+" "+ep.URL] = true
	}
	for _, ep := range candidates {
		if ep.URL == "" {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(ep.Method)) + " " + ep.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		existing = append(existing, ep)
	}
	return existing
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func endpointContainsInvalidSentinel(raw string) bool {
	if raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := parsed.Path
	if path == "" {
		path = raw
	}
	for _, segment := range strings.Split(path, "/") {
		if observation.IsInvalidPathIdentifier(segment) {
			return true
		}
	}
	for _, values := range parsed.Query() {
		for _, value := range values {
			if observation.IsInvalidPathIdentifier(value) {
				return true
			}
		}
	}
	return false
}

// discoverJWTSamples looks for JWTs in Authorization headers / Set-Cookie
// values across captured traffic and returns up to `limit` samples with
// the header (alg) + a short payload preview. No secrets exposed — we do
// not return signatures, which the LLM couldn't do anything with anyway.
func discoverJWTSamples(db *store.DB, scanID int64, limit int) []JWTSample {
	rows, err := db.Conn().Query(`
		SELECT request_headers, response_headers, url
		FROM traffic_resolved
		WHERE scan_id = ?
		  AND (request_headers LIKE '%Bearer%' OR response_headers LIKE '%Bearer%'
		       OR response_body LIKE '%eyJ%')
		  AND is_filtered = 0
		LIMIT 200
	`, scanID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	seen := make(map[string]bool)
	samples := make([]JWTSample, 0, limit)
	for rows.Next() {
		var reqH, respH, urlStr string
		if err := rows.Scan(&reqH, &respH, &urlStr); err != nil {
			continue
		}
		for _, token := range findJWTsIn(reqH + " " + respH) {
			if seen[token] {
				continue
			}
			seen[token] = true
			if s, ok := decodeJWTSample(token, urlStr); ok {
				samples = append(samples, s)
				if len(samples) >= limit {
					return samples
				}
			}
		}
	}
	return samples
}

// findJWTsIn extracts Bearer-token-looking substrings from a text blob.
// JWTs are three base64url segments separated by dots.
func findJWTsIn(s string) []string {
	var out []string
	// Simple scanner: look for "eyJ" (base64 of `{"`) followed by non-whitespace.
	for {
		i := strings.Index(s, "eyJ")
		if i < 0 {
			return out
		}
		end := i
		for end < len(s) && !isWhitespaceOrQuote(s[end]) {
			end++
		}
		token := s[i:end]
		// Must look like a JWT (3 dot-separated segments).
		if strings.Count(token, ".") == 2 {
			out = append(out, token)
			if len(out) > 10 {
				return out
			}
		}
		s = s[end:]
	}
}

func isWhitespaceOrQuote(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '"', '\'', ',', ';', '}', ']':
		return true
	}
	return false
}

// decodeJWTSample decodes the header + payload segments of a JWT into a
// summary. Ignores the signature. Returns (sample, true) only if both
// header and payload parse cleanly.
func decodeJWTSample(token, sourceURL string) (JWTSample, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return JWTSample{}, false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		// Try padded
		headerBytes, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return JWTSample{}, false
		}
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return JWTSample{}, false
	}
	alg, _ := header["alg"].(string)

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payloadBytes, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			// Still useful — we have the header.
			payloadBytes = []byte(fmt.Sprintf("(payload not decodable: %v)", err))
		}
	}
	preview := string(payloadBytes)
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}
	return JWTSample{
		Alg:            alg,
		PayloadPreview: preview,
		Source:         sourceURL,
	}, true
}
