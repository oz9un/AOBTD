package proxy

import (
	"bytes"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/pkg/types"
	"golang.org/x/net/html"
)

const maxPassiveRenderAssetGrants = 4096

var (
	cssURLPattern          = regexp.MustCompile(`(?i)url\(\s*(?:'([^']+)'|"([^"]+)"|([^'"\s][^)]*?))\s*\)`)
	cssImportQuotedPattern = regexp.MustCompile(`(?i)@import\s+['"]([^'"]+)['"]`)
)

// passiveRenderAssetRegistry is a scan-local set of exact, destination-bound
// static resources named by an already-observed in-scope HTML document. It is
// the safe fallback for Referrer-Policy values such as same-origin/no-referrer:
// the browser can omit Referer without turning the exception into a wildcard.
//
// The registry never learns from an off-scope asset body. Filtered response
// bodies therefore remain unread and unpersisted; only an HTTP redirect from an
// already granted exact asset may add one exact successor URL.
type passiveRenderAssetRegistry struct {
	executionPolicy *policy.Engine

	mu     sync.RWMutex
	assets map[string]passiveRenderAssetGrant
}

type passiveRenderAssetGrant struct {
	documentURL  string
	destinations map[string]struct{}
}

func newPassiveRenderAssetRegistry(executionPolicy *policy.Engine) *passiveRenderAssetRegistry {
	return &passiveRenderAssetRegistry{
		executionPolicy: executionPolicy,
		assets:          make(map[string]passiveRenderAssetGrant),
	}
}

// ObserveAuthorizedDocument learns only static resource attributes from a
// successful GET document that independently remains allowed by policy.
func (r *passiveRenderAssetRegistry) ObserveAuthorizedDocument(entry *types.TrafficEntry) {
	if r == nil || r.executionPolicy == nil || entry == nil ||
		!strings.EqualFold(strings.TrimSpace(entry.Request.Method), http.MethodGet) ||
		entry.Response.StatusCode < http.StatusOK || entry.Response.StatusCode >= http.StatusMultipleChoices ||
		len(entry.Response.Body) == 0 {
		return
	}

	destination := strings.ToLower(strings.TrimSpace(capturedHeader(entry.Request.Headers, "Sec-Fetch-Dest")))
	if destination != "document" && destination != "iframe" {
		return
	}
	mediaType, _, err := mime.ParseMediaType(entry.Response.ContentType)
	if err != nil || (mediaType != "text/html" && mediaType != "application/xhtml+xml") {
		return
	}

	documentURL, err := url.Parse(strings.TrimSpace(entry.Request.URL))
	if err != nil || documentURL == nil || !documentURL.IsAbs() || documentURL.Host == "" || documentURL.User != nil {
		return
	}
	decision := r.executionPolicy.Authorize(policy.Action{
		TargetURL: documentURL.String(),
		Method:    http.MethodGet,
	})
	if !decision.Allowed {
		return
	}

	doc, err := html.Parse(bytes.NewReader(entry.Response.Body))
	if err != nil {
		return
	}
	baseURL := firstDocumentBaseURL(doc, documentURL)
	r.walkDocumentAssets(doc, baseURL, documentURL.String())
}

func (r *passiveRenderAssetRegistry) walkDocumentAssets(node *html.Node, baseURL *url.URL, documentURL string) {
	if node == nil {
		return
	}
	if node.Type == html.ElementNode {
		tag := strings.ToLower(node.Data)
		if style := htmlAttribute(node, "style"); style != "" {
			r.registerCSSAssets(style, baseURL, documentURL)
		}
		switch tag {
		case "script":
			r.registerCandidate(htmlAttribute(node, "src"), []string{"script"}, baseURL, documentURL)
		case "link":
			r.registerLinkAsset(node, baseURL, documentURL)
		case "img":
			r.registerCandidate(htmlAttribute(node, "src"), []string{"image"}, baseURL, documentURL)
			r.registerSrcset(htmlAttribute(node, "srcset"), baseURL, documentURL)
		case "source":
			if node.Parent != nil && strings.EqualFold(node.Parent.Data, "picture") {
				r.registerCandidate(htmlAttribute(node, "src"), []string{"image"}, baseURL, documentURL)
				r.registerSrcset(htmlAttribute(node, "srcset"), baseURL, documentURL)
			}
		case "input":
			if strings.EqualFold(strings.TrimSpace(htmlAttribute(node, "type")), "image") {
				r.registerCandidate(htmlAttribute(node, "src"), []string{"image"}, baseURL, documentURL)
			}
		case "image": // Inline SVG <image href=...>.
			r.registerCandidate(firstNonEmpty(htmlAttribute(node, "href"), htmlAttribute(node, "xlink:href")), []string{"image"}, baseURL, documentURL)
		case "body", "table", "td", "th": // Legacy background image attributes.
			r.registerCandidate(htmlAttribute(node, "background"), []string{"image"}, baseURL, documentURL)
		case "style":
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				if child.Type == html.TextNode {
					r.registerCSSAssets(child.Data, baseURL, documentURL)
				}
			}
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		r.walkDocumentAssets(child, baseURL, documentURL)
	}
}

func (r *passiveRenderAssetRegistry) registerLinkAsset(node *html.Node, baseURL *url.URL, documentURL string) {
	href := htmlAttribute(node, "href")
	if href == "" {
		return
	}
	rels := tokenSet(htmlAttribute(node, "rel"))
	destinations := make([]string, 0, 2)
	if rels["stylesheet"] {
		destinations = append(destinations, "style")
	}
	if rels["icon"] || rels["apple-touch-icon"] || rels["apple-touch-startup-image"] {
		destinations = append(destinations, "image")
	}
	if rels["modulepreload"] {
		destinations = append(destinations, "script")
	}
	if rels["preload"] {
		if as := strings.ToLower(strings.TrimSpace(htmlAttribute(node, "as"))); as != "" {
			if _, allowed := passiveRenderDestinations[as]; allowed {
				destinations = append(destinations, as)
			}
		}
	}
	r.registerCandidate(href, destinations, baseURL, documentURL)
}

func (r *passiveRenderAssetRegistry) registerCSSAssets(css string, baseURL *url.URL, documentURL string) {
	for _, match := range cssURLPattern.FindAllStringSubmatch(css, -1) {
		candidate := firstNonEmpty(match[1], match[2], match[3])
		// A CSS url() can produce either an image or a font fetch. Binding it to
		// only these destinations still excludes scripts and stylesheets.
		r.registerCandidate(candidate, []string{"image", "font"}, baseURL, documentURL)
	}
	for _, match := range cssImportQuotedPattern.FindAllStringSubmatch(css, -1) {
		if len(match) > 1 {
			r.registerCandidate(match[1], []string{"style"}, baseURL, documentURL)
		}
	}
}

func (r *passiveRenderAssetRegistry) registerSrcset(srcset string, baseURL *url.URL, documentURL string) {
	for _, candidate := range srcsetURLs(srcset) {
		r.registerCandidate(candidate, []string{"image"}, baseURL, documentURL)
	}
}

func (r *passiveRenderAssetRegistry) registerCandidate(raw string, destinations []string, baseURL *url.URL, documentURL string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(destinations) == 0 || strings.Contains(raw, `\`) {
		return
	}
	reference, err := url.Parse(raw)
	if err != nil || reference == nil {
		return
	}
	target := reference
	if baseURL != nil {
		target = baseURL.ResolveReference(reference)
	}
	r.registerExact(target, destinations, documentURL)
}

func (r *passiveRenderAssetRegistry) registerExact(target *url.URL, destinations []string, documentURL string) {
	if r == nil || r.executionPolicy == nil || target == nil || target.User != nil ||
		!passiveRenderTargetAllowed(target) || urlHasSensitivePassiveMaterial(target) {
		return
	}
	key, ok := exactPassiveRenderURLKey(target)
	if !ok {
		return
	}
	decision := r.executionPolicy.Authorize(policy.Action{TargetURL: key, Method: http.MethodGet})
	if decision.Allowed || decision.Code != policy.CodeOutOfScope {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	grant, exists := r.assets[key]
	if !exists {
		if len(r.assets) >= maxPassiveRenderAssetGrants {
			return
		}
		grant = passiveRenderAssetGrant{
			documentURL:  documentURL,
			destinations: make(map[string]struct{}),
		}
	}
	for _, destination := range destinations {
		destination = strings.ToLower(strings.TrimSpace(destination))
		if _, allowed := passiveRenderDestinations[destination]; allowed {
			grant.destinations[destination] = struct{}{}
		}
	}
	r.assets[key] = grant
}

func (r *passiveRenderAssetRegistry) AllowsExact(target *url.URL, destination string) bool {
	if r == nil || target == nil {
		return false
	}
	key, ok := exactPassiveRenderURLKey(target)
	if !ok {
		return false
	}
	r.mu.RLock()
	grant, found := r.assets[key]
	_, destinationAllowed := grant.destinations[strings.ToLower(strings.TrimSpace(destination))]
	r.mu.RUnlock()
	return found && destinationAllowed
}

// ObserveAllowedRedirect permits only the exact Location successor of a
// previously registered asset, retaining the request's destination binding.
// It inspects headers only; the filtered response body remains untouched.
func (r *passiveRenderAssetRegistry) ObserveAllowedRedirect(captured *types.CapturedRequest, resp *http.Response) {
	if r == nil || captured == nil || resp == nil || resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return
	}
	destination := strings.ToLower(strings.TrimSpace(capturedHeader(captured.Headers, "Sec-Fetch-Dest")))
	source, err := url.Parse(captured.URL)
	if err != nil || !r.AllowsExact(source, destination) {
		return
	}
	location := strings.TrimSpace(resp.Header.Get("Location"))
	if location == "" || strings.Contains(location, `\`) {
		return
	}
	ref, err := url.Parse(location)
	if err != nil {
		return
	}
	r.mu.RLock()
	sourceKey, _ := exactPassiveRenderURLKey(source)
	documentURL := r.assets[sourceKey].documentURL
	r.mu.RUnlock()
	r.registerExact(source.ResolveReference(ref), []string{destination}, documentURL)
}

func firstDocumentBaseURL(doc *html.Node, fallback *url.URL) *url.URL {
	var found *url.URL
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node == nil || found != nil {
			return
		}
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "base") {
			raw := strings.TrimSpace(htmlAttribute(node, "href"))
			if raw != "" && !strings.Contains(raw, `\`) {
				if ref, err := url.Parse(raw); err == nil {
					candidate := fallback.ResolveReference(ref)
					if candidate.IsAbs() && candidate.Host != "" && candidate.User == nil {
						found = candidate
						return
					}
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	if found != nil {
		return found
	}
	return fallback
}

func htmlAttribute(node *html.Node, name string) string {
	for _, attribute := range node.Attr {
		if strings.EqualFold(attribute.Key, name) {
			return strings.TrimSpace(attribute.Val)
		}
	}
	return ""
}

func capturedHeader(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func tokenSet(value string) map[string]bool {
	tokens := make(map[string]bool)
	for _, token := range strings.Fields(strings.ToLower(value)) {
		tokens[token] = true
	}
	return tokens
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func srcsetURLs(value string) []string {
	var results []string
	for remaining := strings.TrimSpace(value); remaining != ""; {
		remaining = strings.TrimLeft(remaining, " \t\r\n,")
		if remaining == "" {
			break
		}
		end := strings.IndexAny(remaining, " \t\r\n")
		candidate := remaining
		if end >= 0 {
			candidate = remaining[:end]
			remaining = remaining[end:]
		} else {
			remaining = ""
		}
		candidate = strings.TrimRight(strings.TrimSpace(candidate), ",")
		if candidate != "" && !strings.HasPrefix(strings.ToLower(candidate), "data:") {
			results = append(results, candidate)
		}
		if comma := strings.IndexByte(remaining, ','); comma >= 0 {
			remaining = remaining[comma+1:]
		} else {
			remaining = ""
		}
	}
	return results
}

func exactPassiveRenderURLKey(parsed *url.URL) (string, bool) {
	if parsed == nil || parsed.User != nil || parsed.Host == "" {
		return "", false
	}
	clone := *parsed
	clone.Scheme = strings.ToLower(strings.TrimSpace(clone.Scheme))
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(clone.Hostname()), "."))
	port := clone.Port()
	if host == "" {
		return "", false
	}
	// Chromium's MITM request URL can retain the CONNECT port (`:443`) even
	// when the HTML used the equivalent origin without an explicit port. Exact
	// grants must canonicalize that representation difference or a declared
	// stylesheet/script is denied despite being the same URL. Non-default ports
	// remain part of the key and therefore cannot borrow a grant.
	if (clone.Scheme == "https" && port == "443") || (clone.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		clone.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		clone.Host = "[" + host + "]"
	} else {
		clone.Host = host
	}
	clone.Fragment = ""
	clone.RawFragment = ""
	if clone.Scheme != "http" && clone.Scheme != "https" {
		return "", false
	}
	if clone.Path == "" {
		clone.Path = "/"
	}
	return clone.String(), true
}
