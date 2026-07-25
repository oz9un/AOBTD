package reconprojection

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/pkg/types"
)

// CatchAllObservation is a bounded, body-free response fingerprint used to
// identify branded 200 catch-all shells. BodySHA256 must be the digest of the
// complete response body; truncated samples are deliberately not accepted.
type CatchAllObservation struct {
	Method     string
	URL        string
	BodySHA256 string
}

// CatchAllMatch explains which observed invalid route proved that a response
// is a shared shell rather than route-specific backing content.
type CatchAllMatch struct {
	NegativeControlPath string
	BodySHA256          string
}

type catchAllRouteKey struct {
	origin   string
	method   string
	path     string
	specimen string
}

type catchAllShellKey struct {
	origin string
	method string
	digest string
}

// CatchAllIndex is immutable after construction and safe for concurrent reads.
// It preserves method, canonical origin, and exact query specimen identity;
// logical-route consumers aggregate those specimen verdicts separately.
type CatchAllIndex struct {
	routes map[catchAllRouteKey]CatchAllMatch
	shells map[catchAllShellKey]CatchAllMatch
}

// NewCatchAllIndex builds an exact shared-shell index. A response fingerprint
// becomes a catch-all only when the same method+origin body was observed on at
// least two different paths and one path is an explicit invalid/probe route.
func NewCatchAllIndex(observations []CatchAllObservation) *CatchAllIndex {
	index := &CatchAllIndex{
		routes: make(map[catchAllRouteKey]CatchAllMatch),
		shells: make(map[catchAllShellKey]CatchAllMatch),
	}
	type cluster struct {
		paths  map[string]bool
		routes map[catchAllRouteKey]bool
	}
	clusters := make(map[catchAllShellKey]*cluster)
	for _, item := range observations {
		route, ok := catchAllRouteIdentity(item.Method, item.URL)
		if !ok {
			continue
		}
		digest := normalizeBodySHA256(item.BodySHA256)
		if digest == "" {
			continue
		}
		key := catchAllShellKey{origin: route.origin, method: route.method, digest: digest}
		if clusters[key] == nil {
			clusters[key] = &cluster{paths: make(map[string]bool), routes: make(map[catchAllRouteKey]bool)}
		}
		clusters[key].paths[route.path] = true
		clusters[key].routes[route] = true
	}

	keys := make([]catchAllShellKey, 0, len(clusters))
	for key := range clusters {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].origin != keys[j].origin {
			return keys[i].origin < keys[j].origin
		}
		if keys[i].method != keys[j].method {
			return keys[i].method < keys[j].method
		}
		return keys[i].digest < keys[j].digest
	})
	for _, key := range keys {
		paths := clusters[key].paths
		if len(paths) < 2 {
			continue
		}
		negativePaths := make([]string, 0, len(paths))
		for path := range paths {
			if LooksLikeNegativeControlPath(path) {
				negativePaths = append(negativePaths, path)
			}
		}
		if len(negativePaths) == 0 {
			continue
		}
		sort.Strings(negativePaths)
		match := CatchAllMatch{NegativeControlPath: negativePaths[0], BodySHA256: key.digest}
		index.shells[key] = match
		for route := range clusters[key].routes {
			// A canonical GET login page remains a real authentication surface
			// even when the application renders that same page as its fallback.
			// The fallback proves nothing about /admin; it does not erase /login.
			if isCanonicalAuthenticationRoute(key.method, route.path) {
				continue
			}
			if existing, exists := index.routes[route]; !exists || match.NegativeControlPath < existing.NegativeControlPath {
				index.routes[route] = match
			}
		}
	}
	return index
}

func normalizeBodySHA256(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(raw, "sha256:")))
	if len(raw) != sha256.Size*2 {
		return ""
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != sha256.Size {
		return ""
	}
	return raw
}

// BodySHA256 returns the full-body digest shape accepted by CatchAllObservation.
func BodySHA256(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func catchAllRouteIdentity(method, rawURL string) (catchAllRouteKey, bool) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Hostname() == "" {
		return catchAllRouteKey{}, false
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	origin := observation.CanonicalOrigin(rawURL)
	if origin == "" {
		return catchAllRouteKey{}, false
	}
	specimen := observation.CanonicalEvidenceURL(rawURL)
	if specimen == "" {
		return catchAllRouteKey{}, false
	}
	return catchAllRouteKey{origin: origin, method: method, path: path, specimen: specimen}, true
}

// MatchRoute reports a catch-all verdict for an exact URL specimen already
// represented in the scan index. Method, origin, and query values all bind it.
func (index *CatchAllIndex) MatchRoute(method, rawURL string) (CatchAllMatch, bool) {
	if index == nil {
		return CatchAllMatch{}, false
	}
	route, ok := catchAllRouteIdentity(method, rawURL)
	if !ok || isCanonicalAuthenticationRoute(route.method, route.path) {
		return CatchAllMatch{}, false
	}
	match, ok := index.routes[route]
	return match, ok
}

// MatchResponse compares a newly captured full response body with the invalid
// control shells already observed on the same method and canonical origin.
func (index *CatchAllIndex) MatchResponse(method, rawURL string, body []byte) (CatchAllMatch, bool) {
	if index == nil || len(body) == 0 {
		return CatchAllMatch{}, false
	}
	route, ok := catchAllRouteIdentity(method, rawURL)
	if !ok || isCanonicalAuthenticationRoute(route.method, route.path) {
		return CatchAllMatch{}, false
	}
	key := catchAllShellKey{origin: route.origin, method: route.method, digest: BodySHA256(body)}
	match, ok := index.shells[key]
	return match, ok
}

// ApplyCatchAllCeiling removes route semantics when exact shared-shell
// evidence contradicts a content_observed verdict. It returns true when the
// ceiling was applied.
func ApplyCatchAllCeiling(profile *types.PageProfile, index *CatchAllIndex) bool {
	if profile == nil || index == nil {
		return false
	}
	state := strings.ToLower(strings.TrimSpace(profile.EvidenceState))
	if state != "" && state != "content_observed" {
		return false
	}
	match, ok := index.MatchRoute(profile.Method, profile.URL)
	if !ok {
		return false
	}
	MarkResponseUnverified(profile, catchAllEvidenceNote(match))
	return true
}

// ApplyCatchAllResponseCeiling is the capture-time counterpart used before an
// exact response is turned into an action or screenshot.
func ApplyCatchAllResponseCeiling(profile *types.PageProfile, entries []types.TrafficEntry, index *CatchAllIndex) bool {
	if profile == nil || index == nil {
		return false
	}
	if ApplyCatchAllCeiling(profile, index) {
		return true
	}
	state := strings.ToLower(strings.TrimSpace(profile.EvidenceState))
	if state != "" && state != "content_observed" {
		return false
	}
	for _, entry := range entries {
		if match, ok := index.MatchResponse(entry.Request.Method, entry.Request.URL, entry.Response.Body); ok {
			MarkResponseUnverified(profile, catchAllEvidenceNote(match))
			return true
		}
	}
	return false
}

func catchAllEvidenceNote(match CatchAllMatch) string {
	return "The direct 2xx response is byte-equivalent to invalid negative-control route " +
		match.NegativeControlPath + " on the same method and origin. It is a shared catch-all shell, not route-specific backing content."
}

// LooksLikeNegativeControlPath recognizes explicit invalid/probe route names.
// It is exported so capture and persistence boundaries use the same rule.
func LooksLikeNegativeControlPath(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if decoded, err := url.PathUnescape(lower); err == nil {
		lower = decoded
	}
	compact := strings.NewReplacer("/", "", "-", "", "_", "", ".", "").Replace(lower)
	for _, marker := range []string{
		"asdasd", "asdf", "qwerty", "zxcv", "nonexistent", "doesnotexist",
		"notfound", "invalidpath", "randompath", "missingroute", "404test",
	} {
		if strings.Contains(compact, marker) {
			return true
		}
	}
	segments := strings.Split(strings.Trim(lower, "/"), "/")
	if len(segments) == 0 {
		return false
	}
	last := segments[len(segments)-1]
	return len(last) >= 20 && observation.IsOpaquePathSegment(last)
}

func isCanonicalAuthenticationRoute(method, path string) bool {
	if method != http.MethodGet {
		return false
	}
	path = strings.ToLower(strings.TrimSuffix(path, "/"))
	switch path {
	case "/login", "/signin", "/sign-in", "/auth", "/auth/login", "/account/login", "/session/login", "/sso", "/saml/login":
		return true
	default:
		return false
	}
}
