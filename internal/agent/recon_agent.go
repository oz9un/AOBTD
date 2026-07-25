package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// ReconAgent analyzes captured traffic headers and responses to detect
// the tech stack, security headers, and server configuration.
// This agent does NOT use LLMs — it's pure fingerprinting.
type ReconAgent struct {
	db     *store.DB
	bus    *Bus
	state  *SharedState
	scanID int64
	logger *slog.Logger
}

// NewReconAgent creates a recon agent.
func NewReconAgent(db *store.DB, bus *Bus, state *SharedState, scanID int64, logger *slog.Logger) *ReconAgent {
	return &ReconAgent{
		db:     db,
		bus:    bus,
		state:  state,
		scanID: scanID,
		logger: logger,
	}
}

func (a *ReconAgent) Name() string { return "recon" }

func (a *ReconAgent) Capabilities() []EventType {
	return []EventType{EventPageCrawled}
}

// Start runs the recon analysis on all captured traffic.
func (a *ReconAgent) Start(ctx context.Context) error {
	a.logger.Info("recon agent starting")

	ts, findings := a.analyzeTraffic()

	a.state.SetTechStack(ts)
	for _, f := range findings {
		a.state.AddFinding(f)
		// Also persist to DB so the Juice Shop scorer / UI / export pipeline
		// sees these. Previously they lived only in in-memory shared state,
		// which meant the terminal summary listed them but they never made
		// it into findings.scan_id for downstream tooling.
		if !a.db.FindingExists(a.scanID, f.Title, f.EndpointID) {
			a.db.InsertFinding(a.scanID, f)
		}
	}

	a.bus.Publish(Event{
		Type:    EventReconComplete,
		Source:  a.Name(),
		Payload: ts,
	})

	a.logger.Info("recon agent finished",
		"server", ts.Server,
		"framework", ts.Framework,
		"findings", len(findings),
	)
	return nil
}

func (a *ReconAgent) analyzeTraffic() (types.TechStack, []types.Finding) {
	var ts types.TechStack
	var findings []types.Finding
	jsLibs := make(map[string]bool)

	rows, err := a.db.Conn().Query(`
		SELECT response_headers, content_type, path, status_code
		FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE
		LIMIT 500`,
		a.scanID,
	)
	if err != nil {
		a.logger.Error("recon query failed", "error", err)
		return ts, findings
	}
	defer rows.Close()

	securityHeaders := map[string]bool{
		"strict-transport-security": false,
		"content-security-policy":   false,
		"x-frame-options":           false,
		"x-content-type-options":    false,
		"referrer-policy":           false,
	}
	framingProtectedByCSP := false

	for rows.Next() {
		var headersJSON, contentType, path string
		var statusCode int
		rows.Scan(&headersJSON, &contentType, &path, &statusCode)

		var headers map[string]string
		json.Unmarshal([]byte(headersJSON), &headers)

		// Detect server
		if v, ok := headers["Server"]; ok && ts.Server == "" {
			ts.Server = v
		}

		// Detect framework from headers
		if v, ok := headers["X-Powered-By"]; ok {
			ts.Framework = v
		}

		// Check for common framework fingerprints in headers
		for k, v := range headers {
			lower := strings.ToLower(k + ": " + v)

			if strings.Contains(lower, "x-aspnet") || strings.Contains(lower, "asp.net") {
				ts.Framework = "ASP.NET"
				ts.Language = "C#"
			}
			if strings.Contains(lower, "x-drupal") {
				ts.Framework = "Drupal"
				ts.Language = "PHP"
			}
			if strings.Contains(lower, "x-generator: wordpress") {
				ts.Framework = "WordPress"
				ts.Language = "PHP"
			}

			// Track security headers presence
			lowerK := strings.ToLower(k)
			if _, exists := securityHeaders[lowerK]; exists {
				securityHeaders[lowerK] = true
			}
			if lowerK == "content-security-policy" && strings.Contains(strings.ToLower(v), "frame-ancestors") {
				framingProtectedByCSP = true
			}
		}

		// Detect CDN
		if v, ok := headers["Cf-Ray"]; ok && v != "" {
			ts.CDN = "Cloudflare"
		}
		if v, ok := headers["X-Amz-Cf-Id"]; ok && v != "" {
			ts.CDN = "CloudFront"
		}
		if _, ok := headers["X-Fastly-Request-Id"]; ok {
			ts.CDN = "Fastly"
		}

		// Detect WAF
		if v, ok := headers["X-Sucuri-Id"]; ok && v != "" {
			ts.WAF = "Sucuri"
		}
		if v, ok := headers["X-Cdn-Waf"]; ok && v != "" {
			ts.WAF = v
		}

		// Detect JS libraries from script paths
		lowerPath := strings.ToLower(path)
		jsDetections := map[string]string{
			"react":   "React",
			"angular": "Angular",
			"vue":     "Vue.js",
			"jquery":  "jQuery",
			"next":    "Next.js",
			"nuxt":    "Nuxt.js",
			"svelte":  "Svelte",
		}
		for pattern, name := range jsDetections {
			if strings.Contains(lowerPath, pattern) && strings.HasSuffix(lowerPath, ".js") {
				jsLibs[name] = true
			}
		}

		// Detect language from cookies/headers
		for k := range headers {
			lower := strings.ToLower(k)
			if strings.Contains(lower, "phpsessid") || strings.Contains(lower, "x-php") {
				ts.Language = "PHP"
			}
			if strings.Contains(lower, "jsessionid") {
				ts.Language = "Java"
			}
		}
	}

	// Convert JS libs map to slice
	for lib := range jsLibs {
		ts.JSLibraries = append(ts.JSLibraries, lib)
	}

	// Generate findings for missing security headers
	for header, present := range securityHeaders {
		if header == "x-frame-options" && framingProtectedByCSP {
			continue
		}
		if !present {
			findings = append(findings, types.Finding{
				Title:       fmt.Sprintf("Security posture observation: missing %s", header),
				Description: fmt.Sprintf("The %s header was not observed on the sampled in-scope responses. Review applicability and compensating controls before treating this as a vulnerability.", header),
				Severity:    types.SeverityInfo,
				Confidence:  types.ConfidencePossible,
			})
		}
	}

	return ts, findings
}
