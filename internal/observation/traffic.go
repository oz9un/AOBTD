// Package observation canonicalizes HTTP evidence before it enters the
// persisted learning loop.
package observation

import (
	"crypto/md5"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/pkg/types"
)

var idPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\d+$`),
	regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	regexp.MustCompile(`^[0-9a-f]{24}$`),
}

var opaqueHexSegment = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)

// IsInvalidPathIdentifier reports path/query values that come from client-side
// placeholder failures rather than real application resources. Treating these
// as candidate object ids poisons authorization analysis: `/basket/NaN` is
// evidence that the UI calculated a bad id, not evidence of a basket resource
// worth IDOR probing.
func IsInvalidPathIdentifier(segment string) bool {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return false
	}
	if decoded, err := url.PathUnescape(segment); err == nil {
		segment = decoded
	}
	normalized := strings.ToLower(strings.TrimSpace(segment))
	normalized = strings.Trim(normalized, `"'`)
	compact := strings.Join(strings.Fields(normalized), " ")
	switch compact {
	case "nan", "undefined", "null", "none", "<nil>", "nil",
		"[object object]", "object object", "[object%20object]":
		return true
	}
	return false
}

// IsOpaquePathSegment reports whether a long URL path segment looks like a
// generated identifier rather than a human-readable route name.
//
// Length alone is not enough: names such as "application-configuration" and
// BFF service routes routinely exceed 20 characters. We retain those literals
// and require strong opacity evidence instead: a long hex identifier, a
// high-entropy URL-safe value, or a mixed-case/digit token with moderately
// high entropy. This deliberately prefers an occasional false negative over
// collapsing two meaningful application routes into one endpoint identity.
func IsOpaquePathSegment(segment string) bool {
	if len(segment) < 20 {
		return false
	}
	if opaqueHexSegment.MatchString(segment) {
		return true
	}
	if readableDelimitedSegment(segment) {
		return false
	}

	counts := make(map[byte]int, len(segment))
	compactLen := 0
	lower, upper, digits := 0, 0, 0
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		switch {
		case c >= 'a' && c <= 'z':
			lower++
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= '0' && c <= '9':
			digits++
		case c == '-' || c == '_':
			continue
		default:
			return false
		}
		counts[c]++
		compactLen++
	}
	if compactLen < 20 {
		return false
	}

	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(compactLen)
		entropy -= p * math.Log2(p)
	}
	if lower > 0 && upper > 0 && digits > 0 && entropy >= 3.5 {
		return true
	}
	return entropy >= 4.0
}

// readableDelimitedSegment recognizes route/service names built from
// alphabetic words separated by '-' or '_'. These are semantic labels, not
// per-request identifiers, regardless of their total length.
func readableDelimitedSegment(segment string) bool {
	if !strings.ContainsAny(segment, "-_") {
		return false
	}
	parts := strings.FieldsFunc(segment, func(r rune) bool { return r == '-' || r == '_' })
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if len(part) < 2 {
			return false
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
				return false
			}
		}
	}
	return true
}

// Normalize fills the canonical fields required by AOBTD's analysis loop.
// Producers should populate everything they know; this function is the final
// defensive boundary that derives safe, deterministic values for omissions.
func Normalize(entry *types.TrafficEntry) error {
	if entry == nil {
		return errors.New("normalize traffic: nil entry")
	}

	entry.Request.Method = strings.ToUpper(strings.TrimSpace(entry.Request.Method))
	if entry.Request.Method == "" {
		return errors.New("normalize traffic: empty request method")
	}

	entry.Request.URL = strings.TrimSpace(entry.Request.URL)
	if entry.Request.URL == "" {
		return errors.New("normalize traffic: empty request URL")
	}
	parsed, err := url.Parse(entry.Request.URL)
	if err != nil {
		return fmt.Errorf("normalize traffic URL: %w", err)
	}
	if (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host == "" {
		return errors.New("normalize traffic: HTTP URL has no host")
	}

	// The URL is the canonical request identity. Overwrite producer-supplied
	// components when the URL carries them so internally inconsistent rows
	// cannot enter the learning loop.
	if parsed.Host != "" {
		entry.Request.Host = parsed.Host
	}
	if entry.Request.Host == "" {
		return errors.New("normalize traffic: request has no host")
	}
	entry.Request.Path = parsed.Path
	if entry.Request.Path == "" {
		entry.Request.Path = "/"
	}
	entry.Request.Query = parsed.RawQuery
	if entry.Request.Headers == nil {
		entry.Request.Headers = make(map[string]string)
	}
	if entry.Response.Headers == nil {
		entry.Response.Headers = make(map[string]string)
	}

	if entry.Response.ContentType == "" {
		entry.Response.ContentType = headerValue(entry.Response.Headers, "Content-Type")
	}
	if entry.Response.Body != nil {
		// Size describes the evidence AOBTD actually captured. This remains
		// truthful when an execution path intentionally truncates a response.
		entry.Response.Size = int64(len(entry.Response.Body))
	} else if entry.Response.Size < 0 {
		entry.Response.Size = 0
	}

	entry.EndpointHash = EndpointHash(entry.Request.Method, entry.Request.URL)
	if strings.TrimSpace(entry.SourceAgent) == "" {
		entry.SourceAgent = "capture"
	}

	if entry.Timestamp.IsZero() {
		entry.Timestamp = entry.Request.Timestamp
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	if entry.Request.Timestamp.IsZero() {
		entry.Request.Timestamp = entry.Timestamp
	}

	return nil
}

// EndpointHash creates AOBTD's v2 endpoint identity:
// method + canonical origin + normalized path + sorted query parameter names.
//
// The origin is part of the identity because a single scan may legitimately
// cover multiple hosts or ports. Treating GET /api/users on app.example.test
// and api.example.test as one endpoint mixes credentials, response schemas,
// and conclusions. Default ports are canonicalized to their effective value,
// so https://example.test and https://example.test:443 remain equivalent.
func EndpointHash(method, rawURL string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Sprintf("%x", md5.Sum([]byte(method+rawURL)))
	}

	path := parsed.Path
	if path == "" {
		path = "/"
	}
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		isID := false
		for _, pattern := range idPatterns {
			if pattern.MatchString(segment) {
				segments[i] = "{id}"
				isID = true
				break
			}
		}
		if !isID && IsInvalidPathIdentifier(segment) {
			segments[i] = "{invalid_id}"
		} else if !isID && IsOpaquePathSegment(segment) {
			segments[i] = "{id}"
		}
	}

	paramKeys := make([]string, 0, len(parsed.Query()))
	for key := range parsed.Query() {
		paramKeys = append(paramKeys, key)
	}
	sort.Strings(paramKeys)

	raw := method + "|" + canonicalOrigin(parsed) + "|" + strings.Join(segments, "/") + "|" + strings.Join(paramKeys, ",")
	return fmt.Sprintf("%x", md5.Sum([]byte(raw)))
}

// CanonicalOrigin returns the scheme/host/effective-port tuple used by
// EndpointHash. It is exported so migrations and identity-aware callers can
// resolve relative discoveries without reimplementing URL canonicalization.
func CanonicalOrigin(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return canonicalOrigin(parsed)
}

// CanonicalEvidenceURL is the exact HTTP specimen identity used when a live
// action or semantic claim must remain bound to one query value set. It
// normalizes origin/default ports and query ordering, but preserves every
// query value. Fragments are excluded because they are not sent in HTTP.
func CanonicalEvidenceURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.User != nil || parsed.Hostname() == "" {
		return ""
	}
	origin := canonicalOrigin(parsed)
	if origin == "" {
		return ""
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	result := origin + path
	if query := parsed.Query().Encode(); query != "" {
		result += "?" + query
	}
	return result
}

func canonicalOrigin(parsed *url.URL) string {
	if parsed == nil {
		return ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if scheme == "" || host == "" {
		return ""
	}

	port := parsed.Port()
	if port == "" {
		switch scheme {
		case "http", "ws":
			port = "80"
		case "https", "wss":
			port = "443"
		}
	}
	if port != "" {
		// JoinHostPort adds the required brackets for IPv6 literals.
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}
