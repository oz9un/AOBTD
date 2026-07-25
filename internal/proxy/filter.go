package proxy

import (
	"net/url"
	"path"
	"strings"
)

// knownCDNHosts that serve static assets we can skip.
var knownCDNHosts = map[string]bool{
	"cdnjs.cloudflare.com":       true,
	"cdn.jsdelivr.net":           true,
	"unpkg.com":                  true,
	"ajax.googleapis.com":        true,
	"fonts.googleapis.com":       true,
	"fonts.gstatic.com":          true,
	"stackpath.bootstrapcdn.com": true,
	"maxcdn.bootstrapcdn.com":    true,
	"code.jquery.com":            true,
}

// chromeInternalHosts are Chrome's own background requests — always skip.
var chromeInternalHosts = map[string]bool{
	"accounts.google.com":                  true,
	"update.googleapis.com":                true,
	"optimizationguide-pa.googleapis.com":  true,
	"content-autofill.googleapis.com":      true,
	"safebrowsing.googleapis.com":          true,
	"clientservices.googleapis.com":        true,
	"clients2.google.com":                  true,
	"clients4.google.com":                  true,
	"translate.googleapis.com":             true,
	"play.googleapis.com":                  true,
	"firebaseinstallations.googleapis.com": true,
	"www.google.com":                       true,
	"www.google.com.tr":                    true,
	"www.gstatic.com":                      true,
	"ssl.gstatic.com":                      true,
	"www.googleadservices.com":             true,
	"googleads.g.doubleclick.net":          true,
	"chrome.google.com":                    true,
	"analytics.google.com":                 true,
	// Ad/tracking networks
	"cm.g.doubleclick.net": true,
	"ad.doubleclick.net":   true,
	"ib.adnxs.com":         true,
	"ad.yieldlab.net":      true,
	"sync.outbrain.com":    true,
	"sync-t1.taboola.com":  true,
	"eb2.3lift.com":        true,
	"aa.agkn.com":          true,
	"dpm.demdex.net":       true,
	"gum.criteo.com":       true,
	"dis.criteo.com":       true,
	"dntcl.qualaroo.com":   true,
	// Analytics/tracking SDKs
	"hit.api.useinsider.com":        true,
	"segment.api.useinsider.com":    true,
	"locationv2.api.useinsider.com": true,
	"assets.api.useinsider.com":     true,
	"eitri.api.useinsider.com":      true,
	"wp-log.api.useinsider.com":     true,
}

// IsBrowserInternalHost reports whether host belongs to browser-owned
// background services rather than the page being inspected. Keeping this
// identity check separate from ShouldFilter lets projections hide scanner
// noise without also hiding real CDNs, analytics, or application dependencies.
func IsBrowserInternalHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	return chromeInternalHosts[host]
}

// droppedExtensions are file extensions we always skip.
var droppedExtensions = map[string]bool{
	".css": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".svg": true, ".ico": true, ".bmp": true, ".tiff": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".mp4": true, ".webm": true, ".avi": true, ".mov": true, ".mkv": true,
	".mp3": true, ".wav": true, ".ogg": true, ".flac": true,
	".wasm": true, ".map": true,
	".zip": true, ".tar": true, ".gz": true, ".rar": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
}

// droppedContentTypes that indicate binary/static content.
var droppedContentTypes = map[string]bool{
	"text/css":                 true,
	"image/":                   true,
	"font/":                    true,
	"audio/":                   true,
	"video/":                   true,
	"application/octet-stream": true,
	"application/wasm":         true,
}

// ShouldFilter returns true if this request/response should be dropped
// from analysis. This is the coarse filter — fast and stateless.
func ShouldFilter(reqURL string, contentType string, responseSize int64) bool {
	// Drop responses over 1MB
	if responseSize > 1<<20 {
		return true
	}

	parsed, err := url.Parse(reqURL)
	if err != nil {
		return false // keep if we can't parse
	}

	host := strings.ToLower(parsed.Hostname())

	// Drop Chrome internal traffic
	if IsBrowserInternalHost(host) {
		return true
	}

	// Drop known CDN hosts
	if knownCDNHosts[host] {
		return true
	}

	// Drop common tracking/analytics domain patterns
	if strings.Contains(host, ".doubleclick.") ||
		strings.Contains(host, ".criteo.") ||
		strings.Contains(host, ".adnxs.") ||
		strings.Contains(host, ".demdex.") ||
		strings.Contains(host, ".taboola.") ||
		strings.Contains(host, ".outbrain.") ||
		strings.Contains(host, "analytics.") ||
		strings.Contains(host, ".hotjar.") ||
		strings.Contains(host, ".newrelic.") ||
		strings.Contains(host, ".sentry.") {
		return true
	}

	// Drop by file extension
	ext := strings.ToLower(path.Ext(parsed.Path))
	if droppedExtensions[ext] {
		return true
	}

	// Drop known static paths
	lowerPath := strings.ToLower(parsed.Path)
	if strings.Contains(lowerPath, "socket.io") {
		return true
	}
	if lowerPath == "/favicon.ico" || lowerPath == "/robots.txt" ||
		lowerPath == "/sitemap.xml" {
		return true
	}

	// Drop by content type prefix
	ct := strings.ToLower(contentType)
	for prefix := range droppedContentTypes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}

	return false
}

// IsInterestingContentType returns true if the content type suggests
// content worth analyzing (HTML, JSON, XML, JS, plain text).
func IsInterestingContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "application/xml") ||
		strings.Contains(ct, "text/xml") ||
		strings.Contains(ct, "text/javascript") ||
		strings.Contains(ct, "application/javascript") ||
		strings.Contains(ct, "text/plain") ||
		strings.Contains(ct, "application/x-www-form-urlencoded")
}
