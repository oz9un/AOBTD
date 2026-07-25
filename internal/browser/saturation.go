package browser

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/ozzyw/aobtd/internal/observation"
)

// urlShape classifies each path segment of a URL into a small set of
// categories so that structurally-identical URLs collapse to the same shape.
//
// Examples:
//
//	/swarovski              -> "WORD"
//	/derimod                -> "WORD"
//	/victoriasecret         -> "WORD"
//	/admin                  -> "WORD"
//	/api/users/123          -> "WORD/WORD/INT"
//	/products/air-max-90    -> "WORD/SLUG"
//	/p/1234                 -> "WORD/INT"
//	/dv/23-nisan-a-ozel-cocuk-senligi?trackingId=18931423 -> "WORD/SLUG?INT"
//
// The shape buckets many superficially-different URLs together when they are
// likely to produce the same template — letting the crawler say "I've seen
// enough of these" after N samples.
func urlShape(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Hash-mode SPA routes (Angular/Vue with HashLocationStrategy) carry
	// the actual route segment in the fragment, NOT the path. Build the
	// shape from the fragment in that case so /#/login and /#/score-board
	// each get their own saturation bucket — otherwise every hash route
	// would collapse to the bare host shape and saturate after one visit.
	pathToShape := parsed.Path
	if isHashRoute(parsed.Fragment) {
		pathToShape = parsed.Fragment
	}

	// Split path into non-empty segments.
	var segs []string
	for _, s := range strings.Split(pathToShape, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}

	var parts []string
	for i, seg := range segs {
		// Root-segment precision: the first path segment is almost always the
		// app "section" (/admin, /api, /account, /products, ...). Treating
		// every one-word first segment as generic WORD collapses unrelated
		// areas into the same bucket and risks skipping /admin just because
		// we've already seen /hesabim N times. Keep the literal first segment
		// when it's short and wordy so each section saturates independently.
		if i == 0 && looksLikeSection(seg) {
			parts = append(parts, strings.ToLower(seg))
			continue
		}
		parts = append(parts, classifySegment(seg))
	}

	shape := "/" + strings.Join(parts, "/")
	// Tag hash-route shapes so they don't collide with real-path shapes —
	// /admin (path) and /#/admin (hash) might both render but they reach
	// totally different code paths on the server side.
	if isHashRoute(parsed.Fragment) {
		shape = "#" + shape
	}

	// If there are query params, include a "shape" of the query too —
	// same query-shape, same likely template. We only care whether there
	// ARE params, not their full structure, so keep this coarse.
	if parsed.RawQuery != "" {
		shape += "?" + classifyQueryShape(parsed.RawQuery)
	}

	return shape
}

// looksLikeSection returns true when a path segment is short, alphabetic,
// and word-like — the sort of segment that names an app area rather than
// an individual resource slug/id. We keep these literal so shapes like
// "/admin/WORD" and "/hesabim/WORD" are never collapsed together.
func looksLikeSection(s string) bool {
	if len(s) == 0 || len(s) > 14 {
		return false
	}
	// reject: digits, UUIDs, dashed slugs, file-like
	if isAllDigits(s) || strings.Count(s, "-") >= 2 || strings.Contains(s, ".") {
		return false
	}
	// require at least one letter
	hasLetter := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
			break
		}
	}
	return hasLetter
}

// interestingPathTokens are substrings that, when present in a URL, cause us
// to bypass the saturation-skip check — even if the URL's shape is already
// marked saturated. These are areas where every single endpoint deserves
// attention from a pentester's perspective. Matched case-insensitively.
var interestingPathTokens = []string{
	"/admin", "/administrator", "/api/", "/v1/", "/v2/", "/v3/", "/graphql",
	"/auth", "/login", "/signin", "/sign-in", "/signup", "/sign-up", "/register",
	"/logout", "/signout", "/password", "/reset", "/forgot", "/verify",
	"/oauth", "/sso", "/saml", "/token", "/jwt",
	"/account", "/profile", "/settings", "/me", "/user", "/users",
	"/upload", "/uploads", "/file", "/files", "/import", "/export", "/download",
	"/webhook", "/callback", "/internal", "/debug", "/trace", "/metrics",
	"/config", "/setup", "/install",
	"/.well-known", "/.env", "/.git", "/actuator", "/swagger", "/openapi",
	"/phpmyadmin", "/adminer",
}

// IsInterestingPath returns true when a URL path contains one of the tokens
// we never want to saturate away — e.g. anything that smells like auth,
// admin, or API surface. Caller should always visit these.
func IsInterestingPath(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	paths := []string{parsed.Path}
	if strings.HasPrefix(parsed.Fragment, "/") || strings.HasPrefix(parsed.Fragment, "!/") {
		paths = append(paths, strings.TrimPrefix(parsed.Fragment, "!"))
	}
	for _, candidate := range paths {
		segments := strings.FieldsFunc(strings.ToLower(candidate), func(r rune) bool { return r == '/' })
		for _, segment := range segments {
			if decoded, decodeErr := url.PathUnescape(segment); decodeErr == nil {
				segment = decoded
			}
			for _, token := range interestingPathTokens {
				marker := strings.Trim(strings.ToLower(token), "/")
				if segment == marker || strings.HasPrefix(segment, marker+"-") {
					return true
				}
			}
		}
	}
	return false
}

var (
	rxUUID    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	rxMongoID = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)
	rxHex     = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
)

// classifySegment returns a shape token for a single path segment.
//
// Order matters: more-specific patterns first. SLUG (many-dashed human-
// readable) is checked before TOKEN (opaque blob) so category/product URLs
// like "/iphone-ios-telefonlar-c-60005202" don't get mislabeled.
func classifySegment(s string) string {
	switch {
	case isAllDigits(s):
		return "INT"
	case rxUUID.MatchString(s):
		return "UUID"
	case rxMongoID.MatchString(s):
		return "MONGO"
	case rxHex.MatchString(s):
		return "HEX"
	case strings.Count(s, "-") >= 2 && len(s) >= 10:
		// "air-max-90", "iphone-ios-telefonlar-c-60005202"
		return "SLUG"
	case observation.IsOpaquePathSegment(s) && strings.Count(s, "-") <= 1:
		// Opaque tokens: "eyJhbGciOiJIUzI1NiIs..." or "abcdef123456789"
		return "TOKEN"
	case strings.Contains(s, "."):
		// file-like segment: "settings.js", "site.css"
		dot := strings.LastIndex(s, ".")
		ext := s[dot+1:]
		if len(ext) <= 5 {
			return "FILE." + strings.ToUpper(ext)
		}
		return "WORD"
	default:
		return "WORD"
	}
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// classifyQueryShape returns a stable summary of which query params are
// present, without their values. "q=foo&page=2" -> "page,q".
func classifyQueryShape(raw string) string {
	q, err := url.ParseQuery(raw)
	if err != nil || len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	// Stable order
	sortStrings(keys)
	return strings.Join(keys, ",")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
