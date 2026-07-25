// Package protection recognizes browser/WAF interstitial responses without
// confusing application endpoints whose business vocabulary includes words
// such as "challenge" or "captcha". The classifier is deterministic and
// deliberately feature-based: volatile ray IDs and challenge tokens never
// become part of its response-shape fingerprint.
package protection

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/pkg/types"
)

const inspectionLimit = 32 * 1024

// Evidence describes one response that is demonstrably a protection page.
type Evidence struct {
	IsInterstitial bool     `json:"is_interstitial"`
	Vendor         string   `json:"vendor,omitempty"`
	Kind           string   `json:"kind,omitempty"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
	Markers        []string `json:"markers,omitempty"`
}

// FamilySummary distinguishes a challenge-only endpoint family from a route
// that eventually yielded real application content. Analyzer compaction is
// safe only for ChallengeOnly; server errors and recovered content stay live.
type FamilySummary struct {
	InterstitialResponses int
	ApplicationResponses  int
	ServerErrors          int
	ChallengeOnly         bool
	RecoveredApplication  bool
	Fingerprints          []string
	Vendors               []string
	PrimaryFingerprint    string
	PrimaryVendor         string
}

// ClassifyResponse detects strong protection evidence and returns a stable
// shape fingerprint. A generic 403 or the word "challenge" alone is never
// enough: those are common application behaviors and business object names.
func ClassifyResponse(response types.CapturedResponse) Evidence {
	body := strings.ToLower(string(response.Body))
	if len(body) > inspectionLimit {
		body = body[:inspectionLimit]
	}
	contentType := normalizeContentType(response.ContentType)
	headers := lowerHeaders(response.Headers)
	vendor := protectionVendor(headers, body)
	markers := make([]string, 0, 8)
	add := func(marker string, present bool) {
		if present {
			markers = append(markers, marker)
		}
	}

	add("just-a-moment-title", containsAny(body, "<title>just a moment", "<title>attention required"))
	add("challenge-platform", containsAny(body, "/cdn-cgi/challenge-platform/", "cf-chl-", "__cf_chl_"))
	add("browser-check", containsAny(body, "checking your browser", "checking if the site connection is secure"))
	add("security-verification", containsAny(body, "performing security verification", "security verification required"))
	add("javascript-cookie-gate", containsAny(body, "enable javascript and cookies to continue", "please enable cookies"))
	add("human-verification", containsAny(body, "verify you are human", "verify that you are human", "are you a human"))
	add("captcha-widget", containsAny(body, "cf-turnstile", "h-captcha", "hcaptcha", "recaptcha", "captcha-delivery.com"))
	add("access-boundary", response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 429)

	strongMarker := hasMarker(markers,
		"just-a-moment-title", "challenge-platform", "browser-check",
		"security-verification", "javascript-cookie-gate")
	humanGate := hasMarker(markers, "human-verification") &&
		(hasMarker(markers, "captcha-widget") || vendor != "")
	vendorBoundary := vendor != "" && hasMarker(markers, "access-boundary") &&
		containsAny(body, "access denied", "request unsuccessful", "temporarily blocked", "automated requests")
	isHTML := strings.HasPrefix(contentType, "text/html") || containsAny(body, "<!doctype html", "<html", "<title")
	isInterstitial := isHTML && (strongMarker || humanGate || vendorBoundary)
	if !isInterstitial {
		return Evidence{}
	}

	kind := "browser_challenge"
	if hasMarker(markers, "captcha-widget") || hasMarker(markers, "human-verification") {
		kind = "human_verification"
	} else if vendorBoundary && !strongMarker {
		kind = "access_boundary"
	}
	sort.Strings(markers)
	shapeMaterial := strings.Join([]string{
		vendor, kind, fmt.Sprintf("status:%d", response.StatusCode),
		"content:" + contentType, strings.Join(markers, ","),
		"headers:" + protectionHeaderShape(headers),
	}, "|")
	sum := sha256.Sum256([]byte(shapeMaterial))
	return Evidence{
		IsInterstitial: true,
		Vendor:         vendor,
		Kind:           kind,
		Fingerprint:    fmt.Sprintf("%x", sum[:8]),
		Markers:        markers,
	}
}

// SummarizeTraffic reports whether an endpoint family is challenge-only.
// A successful non-interstitial HTML/JSON response proves that the route
// recovered and must remain eligible for semantic application analysis.
func SummarizeTraffic(entries []types.TrafficEntry) FamilySummary {
	var summary FamilySummary
	shapeSet := make(map[string]bool)
	vendorSet := make(map[string]bool)
	for _, entry := range entries {
		evidence := ClassifyResponse(entry.Response)
		if evidence.IsInterstitial {
			summary.InterstitialResponses++
			if evidence.Fingerprint != "" {
				shapeSet[evidence.Fingerprint] = true
			}
			if evidence.Vendor != "" {
				vendorSet[evidence.Vendor] = true
			}
		}
		if entry.Response.StatusCode >= 500 {
			summary.ServerErrors++
		}
		if !evidence.IsInterstitial && responseLooksLikeApplication(entry.Response) {
			summary.ApplicationResponses++
		}
	}
	for fingerprint := range shapeSet {
		summary.Fingerprints = append(summary.Fingerprints, fingerprint)
	}
	for vendor := range vendorSet {
		summary.Vendors = append(summary.Vendors, vendor)
	}
	sort.Strings(summary.Fingerprints)
	sort.Strings(summary.Vendors)
	if len(summary.Fingerprints) > 0 {
		summary.PrimaryFingerprint = summary.Fingerprints[0]
	}
	if len(summary.Vendors) > 0 {
		summary.PrimaryVendor = summary.Vendors[0]
	}
	summary.RecoveredApplication = summary.InterstitialResponses > 0 && summary.ApplicationResponses > 0
	summary.ChallengeOnly = summary.InterstitialResponses > 0 && summary.ApplicationResponses == 0 && summary.ServerErrors == 0
	return summary
}

func responseLooksLikeApplication(response types.CapturedResponse) bool {
	if response.StatusCode < 200 || response.StatusCode >= 400 || response.StatusCode == 304 {
		return false
	}
	contentType := normalizeContentType(response.ContentType)
	return strings.HasPrefix(contentType, "text/html") ||
		strings.Contains(contentType, "json") || strings.Contains(contentType, "xml")
}

func protectionVendor(headers map[string]string, body string) string {
	server := headers["server"]
	switch {
	case headers["cf-ray"] != "" || strings.Contains(server, "cloudflare") ||
		containsAny(body, "/cdn-cgi/challenge-platform/", "cf-chl-", "cf-turnstile"):
		return "cloudflare"
	case strings.Contains(server, "akamai") || headers["akamai-grn"] != "" ||
		containsAny(body, "akamai bot manager", "akamaihd.net"):
		return "akamai"
	case containsAny(body, "datadome", "captcha-delivery.com") || headers["x-datadome"] != "":
		return "datadome"
	case strings.Contains(server, "imperva") || containsAny(body, "incapsula", "imperva"):
		return "imperva"
	case containsAny(body, "h-captcha", "hcaptcha"):
		return "hcaptcha"
	case strings.Contains(body, "recaptcha"):
		return "recaptcha"
	default:
		return ""
	}
}

func protectionHeaderShape(headers map[string]string) string {
	names := make([]string, 0, 5)
	for _, name := range []string{"cf-ray", "cf-mitigated", "akamai-grn", "x-datadome", "x-iinfo"} {
		if headers[name] != "" {
			names = append(names, name)
		}
	}
	return strings.Join(names, ",")
}

func lowerHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		out[strings.ToLower(strings.TrimSpace(name))] = strings.ToLower(strings.TrimSpace(value))
	}
	return out
}

func normalizeContentType(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if index := strings.IndexByte(raw, ';'); index >= 0 {
		raw = strings.TrimSpace(raw[:index])
	}
	return raw
}

func hasMarker(markers []string, wanted ...string) bool {
	for _, marker := range markers {
		for _, want := range wanted {
			if marker == want {
				return true
			}
		}
	}
	return false
}

func containsAny(value string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}
