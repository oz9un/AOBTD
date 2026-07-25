package ui

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/pkg/types"
)

// pageOverviewPage is the exported shape for a single "page" in the
// Overview response — a URL that either served HTML or was referenced
// by other requests.
type pageOverviewPage struct {
	URL                string                   `json:"url"`
	Path               string                   `json:"path"`
	Title              string                   `json:"title,omitempty"`
	StatusCode         int                      `json:"status_code,omitempty"`
	Purpose            string                   `json:"purpose,omitempty"` // LLM profile purpose if we have one
	// FunctionalArea is the page's role in the application, e.g.
	// "authentication", "admin", "checkout", "catalog" (from
	// extract.ClassifyFunctionalArea). Used by the UI to colour-code
	// pages and visually group them into a surface map.
	FunctionalArea     string                   `json:"functional_area,omitempty"`
	AreaPriority       int                      `json:"area_priority,omitempty"` // higher = more security-relevant
	Forms              []pageOverviewForm       `json:"forms,omitempty"`
	InputCount         int                      `json:"input_count"`
	LinkCount          int                      `json:"link_count"`
	TriggeredEndpoints []pageOverviewTriggered  `json:"triggered_endpoints,omitempty"`
	HasAuth            bool                     `json:"has_auth"`
}

// pageOverviewForm represents a visible form on the page.
type pageOverviewForm struct {
	Action string                    `json:"action"`
	Method string                    `json:"method"`
	Inputs []pageOverviewInput       `json:"inputs"`
}

// pageOverviewInput carries the per-input heuristic explanation so the
// UI can show "what does this field do" inline.
type pageOverviewInput struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Label       string `json:"label,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Explanation string `json:"explanation,omitempty"`
}

// pageOverviewTriggered summarises an endpoint that was hit while the
// user was on this page (detected via Referer). Collapsed by
// method+path+status so ?cachebuster variants don't explode.
type pageOverviewTriggered struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
	IsAPI    bool   `json:"is_api,omitempty"`
	HasInput bool   `json:"has_input,omitempty"`
	Count    int    `json:"count"`
}

// handlePageOverview returns a page-centric view of the scan: "here's
// what a human would see on each page, and what clicking around there
// talks to." Powers the Overview tab's "Pages & their features" section.
//
// For each HTML page captured during the scan, we compute:
//   - title, path, status
//   - visible forms + their inputs (with heuristic explanations)
//   - non-form inputs on the page (standalone search boxes etc.)
//   - all endpoints triggered while on this page (grouped from Referer)
//   - whether we've analyzed the page with an LLM yet (shows the purpose)
//
// This reframes the scan data from "list of endpoints" to "the
// application as a user would navigate it" — a much more natural mental
// model for explaining what the target does to a new viewer.
func (s *Server) handlePageOverview(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	entries, err := s.db.GetTrafficByScan(scanID)
	if err != nil {
		jsonError(w, "load traffic: "+err.Error(), 500)
		return
	}
	if len(entries) == 0 {
		jsonResponse(w, map[string]any{"pages": []any{}, "total": 0})
		return
	}

	// Pre-load profiles so we can attach an LLM-authored purpose to each
	// page where we have one. Indexed by BOTH the full URL and the
	// normalized URL (scheme+host+path). The profile table stores a
	// "sample URL" which is usually one specific capture with query
	// strings baked in, so the normalized key is the reliable match.
	profiles, _ := s.db.GetAllProfiles(scanID)
	profileByURL := make(map[string]*types.PageProfile, len(profiles)*2)
	for i := range profiles {
		if profiles[i].URL == "" {
			continue
		}
		profileByURL[profiles[i].URL] = &profiles[i]
		profileByURL[normalizePageURL(profiles[i].URL)] = &profiles[i]
	}

	// Group traffic by *normalized* URL (scheme://host/path, query stripped).
	// Different ?cache-buster / ?sid= values pointing at the same page should
	// collapse into one entry — otherwise the Overview is drowning in
	// near-identical dupes like 3x /admin/socket.io/ with different sids.
	referenced := make(map[string][]*types.TrafficEntry)
	htmlEntriesByURL := make(map[string]*types.TrafficEntry)

	for i := range entries {
		e := &entries[i]
		if e.Filtered {
			continue
		}

		if isHTMLPage(e) {
			key := normalizePageURL(e.Request.URL)
			cur, ok := htmlEntriesByURL[key]
			if !ok || len(e.Response.Body) > len(cur.Response.Body) {
				htmlEntriesByURL[key] = e
			}
		}

		if ref := extractReferer(e.Request.Headers); ref != "" {
			key := normalizePageURL(ref)
			referenced[key] = append(referenced[key], e)
		}
	}

	// Union: a URL is a "page" if it served HTML OR was someone's Referer.
	pageURLs := make(map[string]bool)
	for u := range htmlEntriesByURL {
		pageURLs[u] = true
	}
	for u := range referenced {
		pageURLs[u] = true
	}

	pages := make([]pageOverviewPage, 0, len(pageURLs))
	for pageURL := range pageURLs {
		page := pageOverviewPage{
			URL:  pageURL,
			Path: urlPath(pageURL),
		}

		// HTML extraction — forms, standalone inputs, title, link count.
		if ent, ok := htmlEntriesByURL[pageURL]; ok {
			page.StatusCode = ent.Response.StatusCode
			ext := extract.ExtractHTML(ent.Response.Body, pageURL)
			page.Title = ext.Title
			page.LinkCount = len(ext.Links)

			for _, f := range ext.Forms {
				fo := pageOverviewForm{Action: f.Action, Method: f.Method}
				for _, inp := range f.Inputs {
					fo.Inputs = append(fo.Inputs, pageOverviewInput{
						Name:        inp.Name,
						Type:        inp.Type,
						Label:       inp.Label,
						Required:    inp.Required,
						Explanation: extract.ExplainInput(inp.Name, inp.Type, "form", inp.Label, inp.Placeholder),
					})
				}
				page.Forms = append(page.Forms, fo)
				page.InputCount += len(fo.Inputs)
			}

			if len(ext.StandaloneInputs) > 0 {
				fo := pageOverviewForm{Action: "(standalone)", Method: "—"}
				for _, inp := range ext.StandaloneInputs {
					fo.Inputs = append(fo.Inputs, pageOverviewInput{
						Name:        inp.Name,
						Type:        inp.Type,
						Label:       inp.Label,
						Required:    inp.Required,
						Explanation: extract.ExplainInput(inp.Name, inp.Type, "form", inp.Label, inp.Placeholder),
					})
				}
				page.Forms = append(page.Forms, fo)
				page.InputCount += len(fo.Inputs)
			}

			// Auth signal: request to the page carried Authorization / Cookie
			if getHeaderCI(ent.Request.Headers, "authorization") != "" ||
				getHeaderCI(ent.Request.Headers, "cookie") != "" {
				page.HasAuth = true
			}
		}

		if p, ok := profileByURL[pageURL]; ok {
			page.Purpose = p.Purpose
		}

		// Classify the page by URL pattern — auth/admin/api/checkout
		// etc. This is the same heuristic the analyzer uses for
		// AppUnderstanding.FunctionalAreas, applied per-page so the
		// Overview can colour-code and sort by security priority.
		page.FunctionalArea, page.AreaPriority = extract.ClassifyFunctionalArea(page.Path)

		// Triggered endpoints — other requests whose Referer was this page.
		if refd, ok := referenced[pageURL]; ok {
			type triggerKey struct {
				method, path string
				status       int
			}
			agg := make(map[triggerKey]*pageOverviewTriggered)
			for _, e := range refd {
				if e.Request.URL == pageURL {
					continue // page reloading itself
				}
				if isStaticAsset(e.Response.ContentType) {
					continue
				}
				k := triggerKey{e.Request.Method, e.Request.Path, e.Response.StatusCode}
				if t, exists := agg[k]; exists {
					t.Count++
					continue
				}
				agg[k] = &pageOverviewTriggered{
					Method:   e.Request.Method,
					Path:     e.Request.Path,
					Status:   e.Response.StatusCode,
					IsAPI:    strings.Contains(strings.ToLower(e.Response.ContentType), "application/json"),
					HasInput: e.Request.Query != "" || len(e.Request.Body) > 0,
					Count:    1,
				}
			}
			for _, t := range agg {
				page.TriggeredEndpoints = append(page.TriggeredEndpoints, *t)
			}
			// APIs first, then path alpha. Makes the business surface show first.
			sort.Slice(page.TriggeredEndpoints, func(i, j int) bool {
				if page.TriggeredEndpoints[i].IsAPI != page.TriggeredEndpoints[j].IsAPI {
					return page.TriggeredEndpoints[i].IsAPI
				}
				return page.TriggeredEndpoints[i].Path < page.TriggeredEndpoints[j].Path
			})
		}

		pages = append(pages, page)
	}

	// Page-level ranking — what floats to the top for a human reviewer:
	//   1. Analyzed pages (have an LLM-authored purpose).
	//   2. High-security-priority functional areas (auth=10, admin=9,
	//      checkout=9, file_handling=8) — these are the demo-worthy targets.
	//   3. Pages with more input surface (forms, fields).
	//   4. Pages that trigger more endpoints (busier = more to attack).
	sort.Slice(pages, func(i, j int) bool {
		if (pages[i].Purpose != "") != (pages[j].Purpose != "") {
			return pages[i].Purpose != ""
		}
		if pages[i].AreaPriority != pages[j].AreaPriority {
			return pages[i].AreaPriority > pages[j].AreaPriority
		}
		if pages[i].InputCount != pages[j].InputCount {
			return pages[i].InputCount > pages[j].InputCount
		}
		return len(pages[i].TriggeredEndpoints) > len(pages[j].TriggeredEndpoints)
	})

	// Summary counts for the card strip
	withForms := 0
	withInputs := 0
	for _, p := range pages {
		if len(p.Forms) > 0 {
			withForms++
		}
		if p.InputCount > 0 {
			withInputs++
		}
	}

	jsonResponse(w, map[string]any{
		"pages":       pages,
		"total":       len(pages),
		"with_forms":  withForms,
		"with_inputs": withInputs,
	})
}

// isHTMLPage returns true for 2xx/3xx HTML responses — the kind of thing
// a user would navigate to in their browser bar.
func isHTMLPage(e *types.TrafficEntry) bool {
	if !strings.Contains(strings.ToLower(e.Response.ContentType), "text/html") {
		return false
	}
	return e.Response.StatusCode >= 200 && e.Response.StatusCode < 400
}

// isStaticAsset hides noise like scripts, CSS, images, and fonts from
// the "triggered endpoints" list so humans see meaningful calls only.
func isStaticAsset(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "text/css") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "image/") ||
		strings.Contains(ct, "font/") ||
		strings.Contains(ct, "video/") ||
		strings.Contains(ct, "audio/")
}

// extractReferer pulls the Referer value out of the headers map. The
// proxy stores headers case-sensitively so we check the canonical form
// first, then fall back to a case-insensitive sweep.
func extractReferer(headers map[string]string) string {
	if v, ok := headers["Referer"]; ok && v != "" {
		return v
	}
	return getHeaderCI(headers, "referer")
}

// getHeaderCI is a case-insensitive lookup helper for the headers map.
func getHeaderCI(headers map[string]string, key string) string {
	key = strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == key {
			return v
		}
	}
	return ""
}

// urlPath extracts the path portion of a URL for display. Returns "/"
// on error or when the URL has no path component.
func urlPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return "/"
	}
	return u.Path
}

// normalizePageURL collapses a URL to scheme://host/path (no query, no
// fragment) so cache-busters and session ids don't fan out into dozens
// of near-identical "pages" in the Overview.
func normalizePageURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	// Preserve scheme + host; drop query, fragment, and trailing slash
	// on non-root paths (so "/login" and "/login/" aren't shown twice).
	path := u.Path
	if path == "" {
		path = "/"
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	return u.Scheme + "://" + u.Host + path
}
