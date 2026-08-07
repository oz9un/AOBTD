package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// reasoningTagRe strips <think>…</think> / <reasoning>…</reasoning> blocks
// that reasoning models (DeepSeek-R1, MiniMax-M2, Qwen reasoners) emit
// before their actual answer. The parser chain downstream (JSON object
// extractor, profile parser) can't tolerate the block because it often
// contains quoted brace-bearing text that confuses naive `{…}` scanners.
var reasoningTagRe = regexp.MustCompile(`(?s)<(think|reasoning)>.*?</(think|reasoning)>`)

// OpenAICompatibleConfig configures an OpenAI-compatible provider.
type OpenAICompatibleConfig struct {
	BaseURL                string // e.g. "http://localhost:11434/v1" for Ollama
	APIKey                 string // empty for Ollama
	Model                  string // e.g. "qwen3:8b"
	Name                   string // display name: "ollama", "openai", etc.
	UseMaxCompletionTokens bool   // modern OpenAI models reject legacy max_tokens
	OmitTemperature        bool   // some reasoning models accept only their default temperature
}

// OpenAICompatible is an LLM provider that speaks the OpenAI chat completions API.
// Works with Ollama, LM Studio, vLLM, OpenAI, and any compatible server.
type OpenAICompatible struct {
	config OpenAICompatibleConfig
	client *http.Client
}

// NewOpenAICompatible creates a new OpenAI-compatible provider.
func NewOpenAICompatible(cfg OpenAICompatibleConfig) (*OpenAICompatible, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:11434/v1"
	}
	if cfg.Model == "" {
		return nil, fmt.Errorf("model is required")
	}

	return &OpenAICompatible{
		config: cfg,
		client: &http.Client{Timeout: 5 * time.Minute},
	}, nil
}

func (o *OpenAICompatible) Name() string {
	return o.config.Name
}

func (o *OpenAICompatible) ModelInfo() ModelInfo {
	maxContextTokens := 32768
	maxOutputTokens := 4096
	// MiniMax M2/M3 completion usage includes internal reasoning tokens. Its
	// documented context window is substantially larger than the generic
	// OpenAI-compatible fallback, and structured answers need enough completion
	// room for both reasoning and visible JSON.
	normalizedModel := strings.ToLower(strings.TrimSpace(o.config.Model))
	if strings.HasPrefix(normalizedModel, "minimax-m2") ||
		strings.HasPrefix(normalizedModel, "minimax-m3") {
		maxContextTokens = 204800
		maxOutputTokens = 10240
	}
	return ModelInfo{
		Name:             o.config.Model,
		MaxContextTokens: maxContextTokens,
		MaxOutputTokens:  maxOutputTokens,
		SupportsJSON:     true,
	}
}

func (o *OpenAICompatible) CountTokens(text string) int {
	// Rough approximation: ~4 chars per token
	return len(text) / 4
}

func (o *OpenAICompatible) Complete(ctx context.Context, req *Request) (*Response, error) {
	req = RedactedRequest(req)
	// Build messages
	var messages []oaiMessage
	if req.SystemPrompt != "" {
		messages = append(messages, oaiMessage{Role: "system", Content: req.SystemPrompt})
	}
	for _, m := range req.Messages {
		messages = append(messages, oaiMessage{Role: m.Role, Content: m.Content})
	}

	body := oaiRequest{
		Model:    o.config.Model,
		Messages: messages,
	}
	if !o.config.OmitTemperature {
		body.Temperature = req.Temperature
		if body.Temperature == 0 {
			body.Temperature = 0.2
		}
	}

	if req.JSONMode {
		body.ResponseFormat = &oaiResponseFormat{Type: "json_object"}
	}
	if o.disablesReasoningForGLM() {
		body.Thinking = &oaiThinking{Type: "disabled"}
		body.ReasoningEffort = "none"
	}
	if o.isMiniMaxReasoningModel() {
		// MiniMax otherwise embeds <think> blocks in content. Keeping reasoning
		// separate gives downstream JSON parsers only the final answer and also
		// lets a length-exhausted request continue from the reasoning it already
		// paid for instead of starting the whole analysis over.
		body.ReasoningSplit = true
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}
	continuationTokens := miniMaxContinuationTokenAllowance(o, maxTokens)
	initialMaxTokens := maxTokens - continuationTokens
	if o.config.UseMaxCompletionTokens {
		body.MaxCompletionTokens = initialMaxTokens
	} else {
		body.MaxTokens = initialMaxTokens
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		o.config.BaseURL+"/chat/completions",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if o.config.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+o.config.APIKey)
	}

	// Retry with exponential backoff on transient overload/rate-limit codes.
	// MiniMax returns 529 "overloaded_error" during peak hours; OpenAI and
	// most compat backends return 429 or 503. We do up to 4 attempts with
	// 1s, 3s, 7s, 15s delays — total worst case ~26s before giving up. The
	// caller's budget check already decided this call is worth making;
	// a 1-minute outage shouldn't make us drop the whole endpoint.
	var resp *http.Response
	var respBody []byte
	var retriedUsage oaiUsage
	emptyCompletionRetried := false
	lengthContinuationAttempted := false
	retryImmediately := false
	const maxAttempts = 4
	backoffs := []time.Duration{0, 1 * time.Second, 3 * time.Second, 7 * time.Second}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 && !retryImmediately {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoffs[attempt]):
			}
		}
		retryImmediately = false
		if attempt > 0 {
			// Rebuild request — bodies are consumed on first send.
			httpReq, err = http.NewRequestWithContext(ctx, "POST",
				o.config.BaseURL+"/chat/completions",
				bytes.NewReader(jsonBody))
			if err != nil {
				return nil, fmt.Errorf("create request: %w", err)
			}
			httpReq.Header.Set("Content-Type", "application/json")
			if o.config.APIKey != "" {
				httpReq.Header.Set("Authorization", "Bearer "+o.config.APIKey)
			}
		}
		var err2 error
		resp, err2 = o.client.Do(httpReq)
		if err2 != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if isTransientTransportError(err2) && attempt < maxAttempts-1 {
				continue
			}
			return nil, fmt.Errorf("request failed: %w", err2)
		}
		var readErr error
		respBody, readErr = io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if isTransientTransportError(readErr) && attempt < maxAttempts-1 {
				continue
			}
			return nil, fmt.Errorf("read response: %w", readErr)
		}
		if resp.StatusCode == 200 {
			var candidate oaiResponse
			candidateParsed := json.Unmarshal(respBody, &candidate) == nil
			if candidateParsed && responseEndedByLength(candidate) &&
				continuationTokens > 0 && !lengthContinuationAttempted &&
				len(candidate.Choices) > 0 && attempt < maxAttempts-1 {
				// Reserve part of the caller's original output allowance for a
				// cheap final-answer continuation. MiniMax can otherwise spend
				// the whole allowance in reasoning and return either no content
				// or a JSON object cut off near its closing fields. Reusing its
				// assistant reasoning avoids another full world-model pass.
				retriedUsage.PromptTokens += candidate.Usage.PromptTokens
				retriedUsage.CompletionTokens += candidate.Usage.CompletionTokens
				continuationBody := body
				continuationBody.Messages = append(append([]oaiMessage(nil), body.Messages...),
					candidate.Choices[0].Message,
					oaiMessage{
						Role: "user",
						Content: "Continue from the analysis above. Return the requested final answer now. " +
							"Do not repeat the reasoning or add prose. If JSON was requested, output one complete valid JSON object from the beginning.",
					})
				if o.config.UseMaxCompletionTokens {
					continuationBody.MaxCompletionTokens = continuationTokens
					continuationBody.MaxTokens = 0
				} else {
					continuationBody.MaxTokens = continuationTokens
					continuationBody.MaxCompletionTokens = 0
				}
				jsonBody, err = json.Marshal(continuationBody)
				if err != nil {
					return nil, fmt.Errorf("marshal continuation request: %w", err)
				}
				lengthContinuationAttempted = true
				retryImmediately = true
				continue
			}
			// Some OpenAI-compatible providers occasionally return a formally
			// successful completion with no usable assistant content. Treat one
			// such response as transient and retry immediately. Limiting this to
			// one retry avoids turning persistent provider bugs into a request
			// storm while repairing the common MiniMax empty-stop response.
			if candidateParsed && responseContentEmpty(candidate) &&
				!responseEndedByLength(candidate) &&
				!emptyCompletionRetried && attempt < maxAttempts-1 {
				retriedUsage.PromptTokens += candidate.Usage.PromptTokens
				retriedUsage.CompletionTokens += candidate.Usage.CompletionTokens
				emptyCompletionRetried = true
				retryImmediately = true
				continue
			}
			break
		}
		// Retry only on transient codes. All other failures (400/401/403/404/500)
		// are permanent and retrying wastes time + tokens + quota.
		if resp.StatusCode != 429 && resp.StatusCode != 503 && resp.StatusCode != 529 {
			return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
		}
		if attempt == maxAttempts-1 {
			return nil, fmt.Errorf("API error %d after %d attempts: %s",
				resp.StatusCode, maxAttempts, string(respBody))
		}
	}

	var oaiResp oaiResponse
	if err := json.Unmarshal(respBody, &oaiResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if len(oaiResp.Choices) == 0 {
		usage := Usage{
			InputTokens:  retriedUsage.PromptTokens + oaiResp.Usage.PromptTokens,
			OutputTokens: retriedUsage.CompletionTokens + oaiResp.Usage.CompletionTokens,
		}
		return nil, &CompletionError{
			Message: fmt.Sprintf("empty response from model %s", o.config.Model),
			Usage:   usage,
			Model:   o.config.Model,
		}
	}

	choice := oaiResp.Choices[0]
	content := choice.Message.Content
	// Strip reasoning tags so the Analyzer / Strategist parsers see only the
	// model's actual JSON/text output. The cost of reasoning tokens is
	// already counted against the usage total, so we don't refund anything —
	// we just hide the internal monologue from downstream consumers.
	content = reasoningTagRe.ReplaceAllString(content, "")
	content = strings.TrimSpace(content)
	if content == "" {
		usage := Usage{
			InputTokens:  retriedUsage.PromptTokens + oaiResp.Usage.PromptTokens,
			OutputTokens: retriedUsage.CompletionTokens + oaiResp.Usage.CompletionTokens,
		}
		message := ""
		if strings.TrimSpace(choice.Message.ReasoningContent) != "" {
			message = fmt.Sprintf("model returned reasoning_content but no final content (model=%s, finish_reason=%q, completion_tokens=%d)",
				o.config.Model, choice.FinishReason, oaiResp.Usage.CompletionTokens)
		} else {
			message = fmt.Sprintf("empty response content from model %s (finish_reason=%q, completion_tokens=%d)",
				o.config.Model, choice.FinishReason, oaiResp.Usage.CompletionTokens)
		}
		return nil, &CompletionError{
			Message:    message,
			Usage:      usage,
			Model:      o.config.Model,
			StopReason: choice.FinishReason,
		}
	}

	return &Response{
		Content: content,
		Model:   o.config.Model,
		Usage: Usage{
			InputTokens:  retriedUsage.PromptTokens + oaiResp.Usage.PromptTokens,
			OutputTokens: retriedUsage.CompletionTokens + oaiResp.Usage.CompletionTokens,
		},
		StopReason: choice.FinishReason,
	}, nil
}

func responseContentEmpty(resp oaiResponse) bool {
	if len(resp.Choices) == 0 {
		return true
	}
	content := reasoningTagRe.ReplaceAllString(resp.Choices[0].Message.Content, "")
	return strings.TrimSpace(content) == ""
}

func responseEndedByLength(resp oaiResponse) bool {
	return len(resp.Choices) > 0 &&
		strings.EqualFold(strings.TrimSpace(resp.Choices[0].FinishReason), "length")
}

func (o *OpenAICompatible) disablesReasoningForGLM() bool {
	model := strings.ToLower(strings.TrimSpace(o.config.Model))
	if !strings.HasPrefix(model, "glm-") {
		return false
	}
	base := strings.ToLower(strings.TrimSpace(o.config.BaseURL))
	return o.config.Name == "openai-compatible" || strings.Contains(base, "z.ai") || strings.Contains(base, "bigmodel")
}

func (o *OpenAICompatible) isMiniMaxReasoningModel() bool {
	if o == nil {
		return false
	}
	model := strings.ToLower(strings.TrimSpace(o.config.Model))
	return strings.HasPrefix(model, "minimax-m2") || strings.HasPrefix(model, "minimax-m3")
}

func miniMaxContinuationTokenAllowance(provider *OpenAICompatible, maxTokens int) int {
	if provider == nil || !provider.isMiniMaxReasoningModel() || maxTokens < 2048 {
		return 0
	}
	// Keep the total allowance unchanged: 75% is available to the initial
	// reasoning pass and 25% is held for the short "emit the answer" turn.
	return maxTokens / 4
}

func isTransientTransportError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "connection reset by peer") ||
		strings.Contains(lower, "use of closed network connection") ||
		strings.Contains(lower, "broken pipe") ||
		strings.Contains(lower, "unexpected eof") ||
		strings.Contains(lower, "server closed idle connection")
}

// OpenAI API types

type oaiMessage struct {
	Role             string `json:"role"`
	Content          string `json:"content"`
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

type oaiRequest struct {
	Model               string             `json:"model"`
	Messages            []oaiMessage       `json:"messages"`
	Temperature         float64            `json:"temperature,omitempty"`
	MaxTokens           int                `json:"max_tokens,omitempty"`
	MaxCompletionTokens int                `json:"max_completion_tokens,omitempty"`
	ResponseFormat      *oaiResponseFormat `json:"response_format,omitempty"`
	Thinking            *oaiThinking       `json:"thinking,omitempty"`
	ReasoningEffort     string             `json:"reasoning_effort,omitempty"`
	ReasoningSplit      bool               `json:"reasoning_split,omitempty"`
}

type oaiResponseFormat struct {
	Type string `json:"type"`
}

type oaiThinking struct {
	Type string `json:"type"`
}

type oaiResponse struct {
	Choices []oaiChoice `json:"choices"`
	Usage   oaiUsage    `json:"usage"`
}

type oaiChoice struct {
	Message      oaiMessage `json:"message"`
	FinishReason string     `json:"finish_reason"`
}

type oaiUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}
