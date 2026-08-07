package llm

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ozzyw/aobtd/internal/redact"
)

// Provider is the interface for LLM backends.
type Provider interface {
	// Complete sends a prompt and returns a response.
	Complete(ctx context.Context, req *Request) (*Response, error)

	// CountTokens estimates token count for the given text.
	// Returns an approximation (4 chars per token) for providers
	// that don't have a tokenizer.
	CountTokens(text string) int

	// ModelInfo returns the model's capabilities.
	ModelInfo() ModelInfo

	// Name returns the provider name (e.g., "ollama", "anthropic").
	Name() string
}

// Request represents an LLM completion request.
type Request struct {
	SystemPrompt string
	Messages     []Message
	Temperature  float64
	MaxTokens    int
	JSONMode     bool // request structured JSON output
}

// Message is a single message in the conversation.
type Message struct {
	Role    string `json:"role"` // system, user, assistant
	Content string `json:"content"`
}

// RenderPrompt formats a Request's system prompt and messages into a single
// human-readable transcript, used to persist the raw conversation for the
// AI Log viewer (ai_log.prompt column).
func RenderPrompt(req *Request) string {
	var sb strings.Builder
	if req.SystemPrompt != "" {
		sb.WriteString("### SYSTEM\n")
		sb.WriteString(redact.Text(req.SystemPrompt))
		sb.WriteString("\n\n")
	}
	for _, m := range req.Messages {
		sb.WriteString("### ")
		sb.WriteString(strings.ToUpper(m.Role))
		sb.WriteString("\n")
		sb.WriteString(redact.Text(m.Content))
		sb.WriteString("\n\n")
	}
	return strings.TrimSpace(sb.String())
}

func RedactedRequest(req *Request) *Request {
	if req == nil {
		return nil
	}
	out := *req
	out.SystemPrompt = redact.Text(req.SystemPrompt)
	if len(req.Messages) > 0 {
		out.Messages = make([]Message, len(req.Messages))
		for i, m := range req.Messages {
			out.Messages[i] = Message{
				Role:    m.Role,
				Content: redact.Text(m.Content),
			}
		}
	}
	return &out
}

// Response represents an LLM completion response.
type Response struct {
	Content    string
	Usage      Usage
	StopReason string
	// Model is the model that actually produced this response. It matters for
	// routed/fallback calls where Provider.ModelInfo() names the preferred
	// model but the fallback may have answered instead.
	Model string
}

// ResponseModel returns the actual responding model when available and falls
// back to provider metadata for legacy/custom providers.
func ResponseModel(resp *Response, provider Provider) string {
	if resp != nil && resp.Model != "" {
		return resp.Model
	}
	if provider != nil {
		return provider.ModelInfo().Name
	}
	return ""
}

// Usage tracks token consumption.
type Usage struct {
	InputTokens  int
	OutputTokens int
}

// CompletionError represents a provider response that consumed tokens but did
// not produce a usable assistant answer. Keeping billed usage on the error is
// important for reasoning models: they can exhaust their completion allowance
// entirely on internal reasoning and return no final content.
type CompletionError struct {
	Message    string
	Usage      Usage
	Model      string
	StopReason string
}

func (e *CompletionError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// UsageFromError recovers billed usage from an unsuccessful provider call.
// Callers use this to reconcile scan budgets and observability instead of
// treating every provider error as a free request.
func UsageFromError(err error) (Usage, string, bool) {
	var completionErr *CompletionError
	if !errors.As(err, &completionErr) || completionErr == nil {
		return Usage{}, "", false
	}
	usage := completionErr.Usage
	return usage, completionErr.Model, usage.InputTokens > 0 || usage.OutputTokens > 0
}

// ModelInfo describes a model's capabilities.
type ModelInfo struct {
	Name             string
	MaxContextTokens int
	MaxOutputTokens  int
	SupportsJSON     bool
}

// StructuredOutputTokenLimit gives reasoning-first MiniMax models enough
// completion room to finish their JSON after internal reasoning. Other models
// retain the caller's established limit. The advertised provider cap remains
// the final ceiling.
func StructuredOutputTokenLimit(provider Provider, standard, miniMaxReasoning int) int {
	limit := standard
	if provider != nil {
		name := strings.ToLower(strings.TrimSpace(provider.ModelInfo().Name))
		if strings.Contains(name, "minimax-m2") || strings.Contains(name, "minimax-m3") {
			limit = miniMaxReasoning
		}
		if providerLimit := provider.ModelInfo().MaxOutputTokens; providerLimit > 0 && limit > providerLimit {
			limit = providerLimit
		}
	}
	return limit
}

// DefaultBaseURL returns the canonical API URL for the given provider name.
// Used so the caller can pass "" and still hit the right host.
func DefaultBaseURL(providerName string) string {
	switch providerName {
	case "ollama":
		return "http://localhost:11434/v1"
	case "openai":
		return "https://api.openai.com/v1"
	case "anthropic":
		return "https://api.anthropic.com"
	}
	return ""
}

// NewProvider creates a provider based on the provider name. If baseURL is
// empty, the canonical URL for the provider is used.
func NewProvider(providerName, baseURL, apiKey, model string) (Provider, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL(providerName)
	}
	switch providerName {
	case "ollama":
		return NewOpenAICompatible(OpenAICompatibleConfig{
			BaseURL: baseURL,
			APIKey:  "", // Ollama doesn't need a key
			Model:   model,
			Name:    "ollama",
		})
	case "openai":
		if apiKey == "" {
			return nil, fmt.Errorf("openai: API key is required (pass --llm-key)")
		}
		return NewOpenAICompatible(OpenAICompatibleConfig{
			BaseURL:                baseURL,
			APIKey:                 apiKey,
			Model:                  model,
			Name:                   "openai",
			UseMaxCompletionTokens: true,
			OmitTemperature:        openAIOmitsTemperature(model),
		})
	case "anthropic":
		return NewAnthropic(AnthropicConfig{
			BaseURL: baseURL,
			APIKey:  apiKey,
			Model:   model,
		})
	case "openai-compatible":
		return NewOpenAICompatible(OpenAICompatibleConfig{
			BaseURL: baseURL,
			APIKey:  apiKey,
			Model:   model,
			Name:    "openai-compatible",
		})
	default:
		return nil, fmt.Errorf("unknown provider: %s (use ollama, openai, or anthropic)", providerName)
	}
}

func openAIOmitsTemperature(model string) bool {
	lower := strings.ToLower(model)
	return strings.HasPrefix(lower, "gpt-5")
}

// ModelPricing is the per-million-token cost of input and output tokens,
// expressed in micro-cents (1¢ = 10,000 micro-cents) so we can stay in
// integer math and still track fractions of a cent.
type ModelPricing struct {
	InputPerMTokUcents  int64 // micro-cents per 1M input tokens
	OutputPerMTokUcents int64 // micro-cents per 1M output tokens
}

// PricingTable maps model id (or a prefix) to pricing. The lookup matches
// on the longest prefix in `Models` below to tolerate dated-suffix IDs like
// "claude-sonnet-4-6-20250514".
var Models = []struct {
	Prefix  string
	Pricing ModelPricing
}{
	// Prices in $/MTok converted to micro-cents: $1 = 1,000,000 µ¢.
	{"claude-opus", ModelPricing{InputPerMTokUcents: 15000000, OutputPerMTokUcents: 75000000}},  // $15 / $75
	{"claude-sonnet", ModelPricing{InputPerMTokUcents: 3000000, OutputPerMTokUcents: 15000000}}, // $3  / $15
	{"claude-haiku", ModelPricing{InputPerMTokUcents: 1000000, OutputPerMTokUcents: 5000000}},   // $1  / $5

	// OpenAI
	{"gpt-5-mini", ModelPricing{InputPerMTokUcents: 250000, OutputPerMTokUcents: 2000000}},      // $0.25 / $2.00
	{"gpt-5", ModelPricing{InputPerMTokUcents: 1250000, OutputPerMTokUcents: 10000000}},         // $1.25 / $10.00
	{"gpt-5.6-sol", ModelPricing{InputPerMTokUcents: 5000000, OutputPerMTokUcents: 30000000}},   // $5.00 / $30.00
	{"gpt-5.6-terra", ModelPricing{InputPerMTokUcents: 2500000, OutputPerMTokUcents: 15000000}}, // $2.50 / $15.00
	{"gpt-5.6-luna", ModelPricing{InputPerMTokUcents: 1000000, OutputPerMTokUcents: 6000000}},   // $1.00 / $6.00
	{"gpt-5.4-mini", ModelPricing{InputPerMTokUcents: 750000, OutputPerMTokUcents: 4500000}},    // $0.75 / $4.50
	{"gpt-5.4-nano", ModelPricing{InputPerMTokUcents: 200000, OutputPerMTokUcents: 1250000}},    // $0.20 / $1.25
	{"gpt-4o-mini", ModelPricing{InputPerMTokUcents: 150000, OutputPerMTokUcents: 600000}},      // $0.15 / $0.60
	{"gpt-4o", ModelPricing{InputPerMTokUcents: 2500000, OutputPerMTokUcents: 10000000}},        // $2.50 / $10
	{"gpt-4.1-mini", ModelPricing{InputPerMTokUcents: 400000, OutputPerMTokUcents: 1600000}},    // $0.40 / $1.60
	{"gpt-4.1", ModelPricing{InputPerMTokUcents: 2000000, OutputPerMTokUcents: 8000000}},        // $2.00 / $8.00

	// MiniMax — global API (api.minimax.io). Prices current as of 2026-04
	// from the pricing console on platform.minimax.io. All values in
	// micro-cents per 1M tokens ($1 = 1,000,000 µ¢). Match is prefix-based
	// so "MiniMax-M2" and "MiniMax-Text-01" both resolve here. Longer
	// prefixes win (longest-prefix match).
	{"minimax-m2.7-highspeed", ModelPricing{InputPerMTokUcents: 300000, OutputPerMTokUcents: 1200000}}, // Plus-plan model, same tier as M2
	{"minimax-m2", ModelPricing{InputPerMTokUcents: 300000, OutputPerMTokUcents: 1200000}},             // ~$0.30 / $1.20 per M
	{"minimax-text", ModelPricing{InputPerMTokUcents: 200000, OutputPerMTokUcents: 800000}},            // ~$0.20 / $0.80 per M
	{"minimax", ModelPricing{InputPerMTokUcents: 250000, OutputPerMTokUcents: 1000000}},                // fallback for unlisted MiniMax variants

	// DeepSeek — open-weight models served via their hosted API. Free tier-ish.
	{"deepseek-r1", ModelPricing{InputPerMTokUcents: 55000, OutputPerMTokUcents: 219000}}, // ~$0.055 / $0.219 per M (cache miss)
	{"deepseek", ModelPricing{InputPerMTokUcents: 27000, OutputPerMTokUcents: 110000}},    // v3/chat ~$0.027 / $0.11 per M

	// Local models — free (served via Ollama / LM Studio / vLLM)
	{"qwen", ModelPricing{InputPerMTokUcents: 0, OutputPerMTokUcents: 0}},
	{"llama", ModelPricing{InputPerMTokUcents: 0, OutputPerMTokUcents: 0}},
	{"mistral", ModelPricing{InputPerMTokUcents: 0, OutputPerMTokUcents: 0}},
	{"starcoder", ModelPricing{InputPerMTokUcents: 0, OutputPerMTokUcents: 0}},
}

// PricingFor returns the pricing for the given model id, matching by the
// longest prefix in the Models table. Returns zero pricing for unknown models
// (we assume local / free).
func PricingFor(modelID string) ModelPricing {
	best := ModelPricing{}
	bestLen := -1
	lower := strings.ToLower(modelID)
	for _, m := range Models {
		if strings.HasPrefix(lower, strings.ToLower(m.Prefix)) && len(m.Prefix) > bestLen {
			best = m.Pricing
			bestLen = len(m.Prefix)
		}
	}
	return best
}

// CostMicroCents computes the total cost in micro-cents (integer) for a
// given token usage under the given model.
func CostMicroCents(modelID string, u Usage) int64 {
	p := PricingFor(modelID)
	return (int64(u.InputTokens)*p.InputPerMTokUcents + int64(u.OutputTokens)*p.OutputPerMTokUcents) / 1_000_000
}
