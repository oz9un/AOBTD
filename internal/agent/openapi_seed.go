package agent

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

type openAPIOperationTarget struct {
	Method string
	Path   string
	URL    string
	Reason string
}

type openAPIDocument struct {
	OpenAPI string                    `json:"openapi"`
	Swagger string                    `json:"swagger"`
	Servers []openAPIServer           `json:"servers"`
	Paths   map[string]map[string]any `json:"paths"`
}

type openAPIServer struct {
	URL string `json:"url"`
}

func (a *AnalyzerAgent) enqueueOpenAPIFollowUps(entries []types.TrafficEntry, bundle *extract.EndpointBundle) {
	if a == nil || a.db == nil || bundle == nil || len(entries) == 0 {
		return
	}
	sourceProfileID := fmt.Sprintf("%s %s", bundle.Method, bundle.URLPattern)
	queued := 0
	for _, entry := range entries {
		if !looksLikeOpenAPISpecEntry(entry) {
			continue
		}
		targets := openAPISafeGETTargets(entry.Response.Body, entry.Request.URL, 24)
		for _, target := range targets {
			id, err := a.db.InsertFollowUp(a.scanID, store.FollowUp{
				SourceAgent:     "analyzer",
				SourceProfileID: sourceProfileID,
				Action:          "fetch",
				URL:             target.URL,
				Reason:          target.Reason,
				Priority:        8,
			})
			if err != nil {
				a.logger.Warn("openapi follow-up queue failed", "url", target.URL, "error", err)
				continue
			}
			if id > 0 {
				queued++
			}
		}
		if queued > 0 {
			a.db.InsertNarration(a.scanID, "analyzer", "openapi_seed",
				fmt.Sprintf("Queued %d safe GET operation(s) from OpenAPI spec %s.", queued, bundle.URLPattern),
				entry.Request.URL, map[string]any{"queued": queued, "source_profile_id": sourceProfileID})
			return
		}
	}
}

func looksLikeOpenAPISpecEntry(entry types.TrafficEntry) bool {
	if entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 300 {
		return false
	}
	lowerPath := strings.ToLower(strings.TrimSpace(entry.Request.Path))
	lowerCT := strings.ToLower(strings.TrimSpace(entry.Response.ContentType))
	if strings.Contains(lowerPath, "openapi") || strings.Contains(lowerPath, "swagger") ||
		strings.Contains(lowerPath, "api-docs") {
		return len(entry.Response.Body) > 0
	}
	return strings.Contains(lowerCT, "json") && len(entry.Response.Body) > 0 &&
		(strings.Contains(string(entry.Response.Body[:openAPIMinInt(len(entry.Response.Body), 256)]), `"openapi"`) ||
			strings.Contains(string(entry.Response.Body[:openAPIMinInt(len(entry.Response.Body), 256)]), `"swagger"`))
}

func openAPISafeGETTargets(raw []byte, sourceURL string, limit int) []openAPIOperationTarget {
	if limit <= 0 {
		limit = 24
	}
	var doc openAPIDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	if strings.TrimSpace(doc.OpenAPI) == "" && strings.TrimSpace(doc.Swagger) == "" {
		return nil
	}
	if len(doc.Paths) == 0 {
		return nil
	}
	base := openAPIBaseURL(sourceURL, doc.Servers)
	if base == "" {
		return nil
	}

	paths := make([]string, 0, len(doc.Paths))
	for path := range doc.Paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	out := make([]openAPIOperationTarget, 0, openAPIMinInt(limit, len(paths)))
	seen := make(map[string]struct{})
	for _, path := range paths {
		ops := doc.Paths[path]
		if ops == nil {
			continue
		}
		if _, ok := ops["get"]; !ok {
			continue
		}
		if !openAPIPathLooksSafeGET(path, ops["get"]) {
			continue
		}
		targetURL := resolveOpenAPIPath(base, path)
		if targetURL == "" {
			continue
		}
		key := "GET " + targetURL
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, openAPIOperationTarget{
			Method: "GET",
			Path:   path,
			URL:    targetURL,
			Reason: fmt.Sprintf("OpenAPI safe GET operation discovered from spec: GET %s", path),
		})
		if len(out) >= limit {
			break
		}
	}
	return out
}

func openAPIBaseURL(sourceURL string, servers []openAPIServer) string {
	source, err := url.Parse(sourceURL)
	if err != nil || source.Scheme == "" || source.Host == "" {
		return ""
	}
	base := &url.URL{Scheme: source.Scheme, Host: source.Host, Path: "/"}
	if len(servers) == 0 || strings.TrimSpace(servers[0].URL) == "" {
		return base.String()
	}
	rawServer := strings.TrimSpace(servers[0].URL)
	parsed, err := url.Parse(rawServer)
	if err != nil {
		return base.String()
	}
	if parsed.IsAbs() {
		if !sameOpenAPIOrigin(source, parsed) {
			return base.String()
		}
		return parsed.String()
	}
	return base.ResolveReference(parsed).String()
}

func resolveOpenAPIPath(base, path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	if strings.Contains(path, "{") || strings.Contains(path, "}") {
		return ""
	}
	baseURL, err := url.Parse(base)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return ""
	}
	ref, err := url.Parse(path)
	if err != nil {
		return ""
	}
	return baseURL.ResolveReference(ref).String()
}

func openAPIPathLooksSafeGET(path string, operation any) bool {
	if strings.Contains(path, "{") || strings.Contains(path, "}") {
		return false
	}
	lower := strings.ToLower(path + " " + openAPIOperationText(operation))
	for _, marker := range []string{
		"createdb", "create db", "reset", "delete", "drop", "truncate", "flush", "purge",
		"destroy", "logout", "signout", "sign out", "remove", "disable",
	} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func openAPIOperationText(operation any) string {
	m, ok := operation.(map[string]any)
	if !ok {
		return ""
	}
	var parts []string
	for _, key := range []string{"operationId", "summary", "description"} {
		if value, ok := m[key].(string); ok {
			parts = append(parts, value)
		}
	}
	if tags, ok := m["tags"].([]any); ok {
		for _, tag := range tags {
			if s, ok := tag.(string); ok {
				parts = append(parts, s)
			}
		}
	}
	return strings.Join(parts, " ")
}

func sameOpenAPIOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func openAPIMinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
