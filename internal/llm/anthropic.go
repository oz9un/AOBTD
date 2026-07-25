package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AnthropicConfig configures the Anthropic Messages API provider.
type AnthropicConfig struct {
	BaseURL string // defaults to https://api.anthropic.com
	APIKey  string
	Model   string // e.g. "claude-sonnet-4-6-20250514"
}

// Anthropic is an LLM provider that calls the Messages API directly (no SDK).
type Anthropic struct {
	config AnthropicConfig
	client *http.Client
}

// NewAnthropic creates an Anthropic provider.
func NewAnthropic(cfg AnthropicConfig) (*Anthropic, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("anthropic: API key is required")
	}
	if cfg.Model == "" {
		return nil, fmt.Errorf("anthropic: model is required")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.anthropic.com"
	}
	return &Anthropic{
		config: cfg,
		client: &http.Client{Timeout: 5 * time.Minute},
	}, nil
}

func (a *Anthropic) Name() string { return "anthropic" }

func (a *Anthropic) ModelInfo() ModelInfo {
	// Conservative defaults — Anthropic models have large context windows.
	return ModelInfo{
		Name:             a.config.Model,
		MaxContextTokens: 200000,
		MaxOutputTokens:  8192,
		SupportsJSON:     true, // we instruct in the system prompt
	}
}

func (a *Anthropic) CountTokens(text string) int {
	// Rough approximation — matches the OpenAI compat estimate. Close enough
	// for budget gating; actual usage is reported in Usage after each call.
	return len(text) / 4
}

func (a *Anthropic) Complete(ctx context.Context, req *Request) (*Response, error) {
	req = RedactedRequest(req)
	// Anthropic expects the system prompt as a top-level `system` field, not
	// a system role message. Only user/assistant messages go in `messages`.
	sys := req.SystemPrompt
	if req.JSONMode {
		// Anthropic doesn't have response_format; steer via the prompt.
		jsonRule := "\n\nRespond with valid JSON only. No markdown, no prose outside the JSON."
		if sys == "" {
			sys = strings.TrimSpace(jsonRule)
		} else if !strings.Contains(sys, "valid JSON") {
			sys = sys + jsonRule
		}
	}

	var messages []anthropicMessage
	for _, m := range req.Messages {
		if m.Role == "system" {
			// System-role messages get folded into the top-level system block.
			if sys != "" {
				sys += "\n\n" + m.Content
			} else {
				sys = m.Content
			}
			continue
		}
		messages = append(messages, anthropicMessage{Role: m.Role, Content: m.Content})
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}
	temperature := req.Temperature
	if temperature == 0 {
		temperature = 0.2
	}

	body := anthropicRequest{
		Model:       a.config.Model,
		MaxTokens:   maxTokens,
		Temperature: temperature,
		System:      sys,
		Messages:    messages,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("anthropic: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		a.config.BaseURL+"/v1/messages", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("anthropic: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("anthropic: read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("anthropic: API error %d: %s", resp.StatusCode, string(respBody))
	}

	var aresp anthropicResponse
	if err := json.Unmarshal(respBody, &aresp); err != nil {
		return nil, fmt.Errorf("anthropic: parse response: %w", err)
	}

	// Concatenate all text blocks (usually just one).
	var text strings.Builder
	for _, block := range aresp.Content {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}

	return &Response{
		Content: text.String(),
		Model:   a.config.Model,
		Usage: Usage{
			InputTokens:  aresp.Usage.InputTokens,
			OutputTokens: aresp.Usage.OutputTokens,
		},
		StopReason: aresp.StopReason,
	}, nil
}

// ── Anthropic API types ──

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature,omitempty"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicResponse struct {
	Content    []anthropicContentBlock `json:"content"`
	StopReason string                  `json:"stop_reason"`
	Usage      anthropicUsage          `json:"usage"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}
