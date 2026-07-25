package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
)

// FallbackProvider tries a preferred model first and transparently retries
// the same request with a more reliable fallback model when the preferred
// provider errors or violates a requested JSON contract.
//
// It is intentionally small: task routing belongs to the orchestrator, while
// this wrapper only provides resilience at the provider boundary.
type FallbackProvider struct {
	primary  Provider
	fallback Provider
	logger   *slog.Logger
}

func NewFallbackProvider(primary, fallback Provider, logger *slog.Logger) Provider {
	if primary == nil {
		return fallback
	}
	if fallback == nil || (primary.Name() == fallback.Name() && primary.ModelInfo().Name == fallback.ModelInfo().Name) {
		return primary
	}
	return &FallbackProvider{primary: primary, fallback: fallback, logger: logger}
}

func (p *FallbackProvider) Complete(ctx context.Context, req *Request) (*Response, error) {
	resp, primaryErr := p.primary.Complete(ctx, req)
	if primaryErr == nil && jsonContractSatisfied(req, resp) {
		if resp.Model == "" {
			resp.Model = p.primary.ModelInfo().Name
		}
		return resp, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if p.logger != nil {
		reason := "invalid JSON response"
		if primaryErr != nil {
			reason = primaryErr.Error()
		}
		p.logger.Warn("LLM primary failed; retrying with fallback",
			"primary_model", p.primary.ModelInfo().Name,
			"fallback_model", p.fallback.ModelInfo().Name,
			"reason", reason)
	}
	fallbackResp, fallbackErr := p.fallback.Complete(ctx, req)
	if fallbackErr != nil {
		primaryReason := "invalid JSON response"
		if primaryErr != nil {
			primaryReason = primaryErr.Error()
		}
		return nil, fmt.Errorf("primary model %s failed (%v); fallback model %s failed: %w",
			p.primary.ModelInfo().Name, primaryReason,
			p.fallback.ModelInfo().Name, fallbackErr)
	}
	if !jsonContractSatisfied(req, fallbackResp) {
		return nil, fmt.Errorf("primary and fallback models returned invalid JSON")
	}
	if fallbackResp.Model == "" {
		fallbackResp.Model = p.fallback.ModelInfo().Name
	}
	return fallbackResp, nil
}

func (p *FallbackProvider) CountTokens(text string) int { return p.primary.CountTokens(text) }
func (p *FallbackProvider) ModelInfo() ModelInfo        { return p.primary.ModelInfo() }
func (p *FallbackProvider) Name() string                { return p.primary.Name() + "+fallback" }

func jsonContractSatisfied(req *Request, resp *Response) bool {
	if resp == nil {
		return false
	}
	if req == nil || !req.JSONMode {
		return true
	}
	body := strings.TrimSpace(resp.Content)
	if strings.HasPrefix(body, "```") {
		lines := strings.Split(body, "\n")
		if len(lines) >= 3 {
			lines = lines[1 : len(lines)-1]
			body = strings.TrimSpace(strings.Join(lines, "\n"))
		}
	}
	return json.Valid([]byte(body))
}
