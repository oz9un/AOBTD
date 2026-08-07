package reasoner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/pkg/types"
)

// ChainReasoner is the 4th domain specialist — the "thinker" in the
// ensemble. Other reasoners (Auth, Injection, Access) identify SINGLE
// vulnerabilities in their domain. ChainReasoner COMPOSES confirmed
// findings across all domains into multi-step attack narratives.
//
// Design notes:
//   - Runs LAST in Phase 6.5 so it sees everything the other reasoners
//     confirmed.
//   - Doesn't make HTTP probes of its own (its primitive is a
//     narrative); instead the Executor emits a chain-observation
//     Finding so the attack story lands in the findings table.
//   - Fast-reject when the scan has fewer than 2 confirmed findings —
//     chains need ingredients.
type ChainReasoner struct {
	llm    llm.Provider
	logger *slog.Logger
}

// NewChainReasoner constructs the chain-composition reasoner.
func NewChainReasoner(provider llm.Provider, logger *slog.Logger) *ChainReasoner {
	if logger == nil {
		logger = slog.Default()
	}
	return &ChainReasoner{llm: provider, logger: logger}
}

// Name identifies the reasoner in logs / narrations.
func (r *ChainReasoner) Name() string { return "ChainReasoner" }

// Apply composes chain narratives from the scan's confirmed findings.
// Fast-rejects when there are fewer than 2 confirmed findings to chain.
func (r *ChainReasoner) Apply(ctx context.Context, ev Evidence) ([]ProbePlan, ReasonerUsage, error) {
	if r.llm == nil {
		return nil, ReasonerUsage{}, nil
	}
	// Count confirmed ingredients.
	confirmed := 0
	for _, f := range ev.Findings {
		if string(f.Confidence) == "confirmed" {
			confirmed++
		}
	}
	if confirmed < 2 {
		r.logger.Info("ChainReasoner: insufficient confirmed findings (need 2+), skipping",
			"scan_id", ev.ScanID, "confirmed_count", confirmed)
		return nil, ReasonerUsage{}, nil
	}

	userMessage := r.buildUserMessage(ev)
	req := &llm.Request{
		SystemPrompt: chainSystemPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: userMessage},
		},
		Temperature: 0.3, // slightly higher — creative chain composition
		MaxTokens:   llm.StructuredOutputTokenLimit(r.llm, 3500, 10240),
		JSONMode:    true,
	}

	resp, err := r.llm.Complete(ctx, req)
	if err != nil {
		return nil, reasonerUsageFromError(err, r.llm), fmt.Errorf("chain reasoner LLM: %w", err)
	}
	usage := ReasonerUsage{
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
		ModelID:      llm.ResponseModel(resp, r.llm),
	}

	plans, err := parsePlans(resp.Content)
	if err != nil {
		r.logger.Warn("ChainReasoner: plan parse failed",
			"err", err,
			"content_preview", truncate(resp.Content, 300))
		return nil, usage, fmt.Errorf("parse plans: %w", err)
	}

	validated := validateChainPlans(plans, ev)
	for i := range validated {
		validated[i].SourceReasoner = r.Name()
	}
	r.logger.Info("ChainReasoner: emitted plans",
		"scan_id", ev.ScanID,
		"input_tokens", usage.InputTokens,
		"output_tokens", usage.OutputTokens,
		"raw_count", len(plans),
		"validated_count", len(validated),
		"raw_response_preview", truncate(resp.Content, 400))

	return validated, usage, nil
}

// buildUserMessage feeds the ChainReasoner the SET of confirmed
// findings (its primary inputs) plus the target + any relevant
// endpoints. No observed_emails / JWT samples — those are other
// reasoners' domain.
func (r *ChainReasoner) buildUserMessage(ev Evidence) string {
	type findingLite struct {
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		VulnType    string `json:"vuln_type"`
		EndpointID  string `json:"endpoint_id,omitempty"`
		Impact      string `json:"impact,omitempty"`
		Evidence    string `json:"evidence,omitempty"`
		ChainSignal string `json:"chain_signal,omitempty"`
	}
	var confirmed []findingLite
	for _, f := range ev.Findings {
		if string(f.Confidence) != "confirmed" {
			continue
		}
		confirmed = append(confirmed, findingLite{
			Title:       f.Title,
			Severity:    string(f.Severity),
			VulnType:    f.VulnType,
			EndpointID:  f.EndpointID,
			Impact:      truncate(f.Impact, 240),
			Evidence:    truncate(f.Evidence, 240),
			ChainSignal: chainSignalForFinding(f),
		})
	}

	doc := map[string]any{
		"target":             ev.Target,
		"confirmed_findings": confirmed,
		"login_endpoints":    toLiteEndpoints(ev.LoginEndpoints),
		"api_endpoints":      toLiteEndpoints(ev.APIEndpoints),
		"chain_priorities": []string{
			"Prefer BOLA/IDOR/access-control findings when composing narratives; they demonstrate application understanding and business-logic impact.",
			"If weak credentials or auth bypass exist with BOLA/IDOR, explain the full attacker path from login/session acquisition to cross-user data access.",
			"Use Impact/Evidence fields to make the chain specific rather than generic.",
		},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

func chainSignalForFinding(f types.Finding) string {
	haystack := strings.ToLower(strings.Join([]string{
		f.Title,
		f.Description,
		f.VulnType,
		f.Evidence,
		f.Impact,
	}, " "))
	switch {
	case strings.Contains(haystack, "bola") ||
		strings.Contains(haystack, "idor") ||
		strings.Contains(haystack, "object level") ||
		strings.Contains(haystack, "cross-owner") ||
		strings.Contains(haystack, "another user") ||
		strings.Contains(haystack, "other user"):
		return "priority_access_control_business_logic"
	case strings.Contains(haystack, "weak credential") ||
		strings.Contains(haystack, "default credential") ||
		strings.Contains(haystack, "login bypass") ||
		strings.Contains(haystack, "jwt"):
		return "auth_capability"
	case strings.Contains(haystack, "sqli") ||
		strings.Contains(haystack, "sql injection"):
		return "data_extraction_capability"
	case strings.Contains(haystack, "swagger") ||
		strings.Contains(haystack, "metrics") ||
		strings.Contains(haystack, "stack trace"):
		return "recon_or_disclosure_capability"
	default:
		return ""
	}
}

// toLiteEndpoints is a small helper for ChainReasoner's context — just
// URL + method, nothing else. The reasoner is reasoning over confirmed
// findings, endpoints are auxiliary.
func toLiteEndpoints(eps []DiscoveredEndpoint) []map[string]string {
	out := make([]map[string]string, 0, len(eps))
	for _, e := range eps {
		out = append(out, map[string]string{
			"url":    e.URL,
			"method": e.Method,
		})
	}
	return out
}

// validateChainPlans enforces the chain-specific constraints on top of
// the standard ProbePlan validation:
//   - technique MUST be "chain_attack_narrative"
//   - payloads MUST have ≥ 2 entries (a chain needs ≥ 2 steps)
//   - rationale MUST be non-empty
//   - Target.URL may be any URL from evidence OR any endpoint_id from
//     confirmed findings (chains often reference endpoints captured
//     earlier, not live in the current evidence lookup)
func validateChainPlans(plans []ProbePlan, ev Evidence) []ProbePlan {
	// Build set of URLs the reasoner is allowed to target. Includes:
	// evidence endpoints + endpoint_ids from confirmed findings.
	allowed := make(map[string]bool)
	for _, ep := range ev.LoginEndpoints {
		allowed[ep.URL] = true
	}
	for _, ep := range ev.APIEndpoints {
		allowed[ep.URL] = true
	}
	for _, ep := range ev.QueryEndpoints {
		allowed[ep.URL] = true
	}
	for _, f := range ev.Findings {
		if f.EndpointID != "" {
			// endpoint_id is "METHOD /path" — synthesize the on-target
			// URL for ANY verb (previous impl only matched GET, which
			// missed POST/PUT/DELETE endpoints and left most chain-plan
			// targets unvalidated). Use SplitN like evidence.go does.
			parts := strings.SplitN(f.EndpointID, " ", 2)
			if len(parts) == 2 {
				allowed[strings.TrimRight(ev.Target, "/")+parts[1]] = true
			}
			allowed[f.EndpointID] = true // also match raw endpoint-id shape
		}
	}
	// In chain mode any URL matching target prefix counts (chains
	// reference multiple endpoints; we permit anything on-target).
	out := make([]ProbePlan, 0, len(plans))
	for _, p := range plans {
		// ChainReasoner can emit either a narrative (no HTTP) or an
		// executable chain (login → IDOR). Both are chain-level plans.
		if p.Technique != "chain_attack_narrative" &&
			p.Technique != "chain_auth_then_access" {
			continue
		}
		if len(p.Payloads) < 2 {
			continue
		}
		if p.Rationale == "" {
			continue
		}
		if p.Technique == "chain_auth_then_access" && !validExecutableChainPlan(p) {
			continue
		}
		// Lenient URL check: allow on-target URLs even if not in strict
		// evidence list, since chains cite multi-step paths.
		if !allowed[p.Target.URL] && !urlOnTarget(p.Target.URL, ev.Target) {
			continue
		}
		if p.Confidence < 0 || p.Confidence > 1 {
			p.Confidence = 0.6
		}
		out = append(out, p)
	}
	return out
}

func validExecutableChainPlan(p ProbePlan) bool {
	if p.Target.Headers == nil {
		return false
	}
	required := []string{"chain_auth_user", "chain_auth_pass", "chain_access_urls"}
	for _, key := range required {
		if strings.TrimSpace(p.Target.Headers[key]) == "" {
			return false
		}
	}
	if strings.TrimSpace(p.Target.BodyType) == "" {
		return false
	}
	return true
}

// urlOnTarget returns true when a URL's origin matches the scan target's
// origin. Prevents chain narratives from referencing off-target hosts.
// Uses strings.TrimRight to avoid the guarded-but-fragile empty-string
// indexing the earlier revision had.
func urlOnTarget(u, target string) bool {
	if u == "" || target == "" {
		return false
	}
	t := strings.TrimRight(target, "/")
	if t == "" {
		return false
	}
	return strings.HasPrefix(u, t)
}
