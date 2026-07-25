package llm

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIGPT5UsesModernCompletionParameters(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"gpt-5-mini","choices":[{"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`))
	}))
	defer srv.Close()

	p, err := NewProvider("openai", srv.URL, "test-key", "gpt-5-mini")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Complete(t.Context(), &Request{
		Messages:  []Message{{Role: "user", Content: "test"}},
		MaxTokens: 123, Temperature: 0.2, JSONMode: true,
	}); err != nil {
		t.Fatal(err)
	}
	if got := captured["max_completion_tokens"]; got != float64(123) {
		t.Fatalf("max_completion_tokens=%v, want 123", got)
	}
	if _, exists := captured["max_tokens"]; exists {
		t.Fatal("legacy max_tokens must not be sent to OpenAI GPT-5")
	}
	if _, exists := captured["temperature"]; exists {
		t.Fatal("temperature must be omitted for GPT-5")
	}
	if _, exists := captured["reasoning_effort"]; exists {
		t.Fatal("reasoning_effort must be opt-in, not forced by the provider")
	}
}

func TestIsTransientTransportError(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{errors.New("read: connection reset by peer"), true},
		{errors.New("unexpected EOF"), true},
		{errors.New("server closed idle connection"), true},
		{errors.New("API error 401"), false},
		{nil, false},
	}
	for _, tt := range tests {
		if got := isTransientTransportError(tt.err); got != tt.want {
			t.Fatalf("isTransientTransportError(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestOpenAICompatibleGLMDisablesThinking(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"glm-5.2","choices":[{"message":{"role":"assistant","content":"{\"ok\":true}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4}}`))
	}))
	defer srv.Close()

	p, err := NewProvider("openai-compatible", srv.URL, "test-key", "glm-5.2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Complete(t.Context(), &Request{
		Messages:  []Message{{Role: "user", Content: "return json"}},
		MaxTokens: 321, Temperature: 0.2, JSONMode: true,
	}); err != nil {
		t.Fatal(err)
	}
	thinking, ok := captured["thinking"].(map[string]any)
	if !ok {
		t.Fatalf("thinking=%#v, want object", captured["thinking"])
	}
	if got := thinking["type"]; got != "disabled" {
		t.Fatalf("thinking.type=%v, want disabled", got)
	}
	if got := captured["reasoning_effort"]; got != "none" {
		t.Fatalf("reasoning_effort=%v, want none", got)
	}
}

func TestOpenAICompatibleMiniMaxM2AdvertisesReasoningHeadroom(t *testing.T) {
	provider, err := NewOpenAICompatible(OpenAICompatibleConfig{Model: "MiniMax-M2.7-highspeed"})
	if err != nil {
		t.Fatal(err)
	}
	info := provider.ModelInfo()
	if info.MaxContextTokens != 204800 || info.MaxOutputTokens != 10240 {
		t.Fatalf("MiniMax model info = %+v", info)
	}
}

func TestOpenAICompatibleEmptyContentIsError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"glm-5.2","choices":[{"message":{"role":"assistant","content":"","reasoning_content":"thinking only"},"finish_reason":"length"}],"usage":{"prompt_tokens":3,"completion_tokens":2048}}`))
	}))
	defer srv.Close()

	p, err := NewProvider("openai-compatible", srv.URL, "test-key", "glm-5.2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Complete(t.Context(), &Request{
		Messages: []Message{{Role: "user", Content: "return json"}},
		JSONMode: true,
	})
	if err == nil {
		t.Fatal("Complete() error = nil, want empty-content error")
	}
	if msg := err.Error(); !strings.Contains(msg, "reasoning_content") || !strings.Contains(msg, "finish_reason") {
		t.Fatalf("Complete() error = %q, want reasoning_content + finish_reason context", msg)
	}
	if calls != 2 {
		t.Fatalf("provider calls = %d, want one immediate retry", calls)
	}
}

func TestOpenAICompatibleRetriesEmptySuccessfulCompletion(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_, _ = w.Write([]byte(`{"model":"MiniMax-M3","choices":[{"message":{"role":"assistant","content":""},"finish_reason":"stop"}],"usage":{"prompt_tokens":6200,"completion_tokens":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"model":"MiniMax-M3","choices":[{"message":{"role":"assistant","content":"{\"action\":\"answer\",\"text\":\"Recovered\"}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":6200,"completion_tokens":12}}`))
	}))
	defer srv.Close()

	p, err := NewProvider("openai-compatible", srv.URL, "test-key", "MiniMax-M3")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Complete(t.Context(), &Request{
		Messages: []Message{{Role: "user", Content: "answer from the graph"}},
		JSONMode: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !strings.Contains(resp.Content, "Recovered") {
		t.Fatalf("calls=%d response=%+v", calls, resp)
	}
	if resp.Usage.InputTokens != 12400 || resp.Usage.OutputTokens != 14 {
		t.Fatalf("retry usage = %+v, want both billed attempts", resp.Usage)
	}
}
