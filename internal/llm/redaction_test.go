package llm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderPromptRedactsSecrets(t *testing.T) {
	req := &Request{
		SystemPrompt: "Use the app context.",
		Messages: []Message{{
			Role:    "user",
			Content: "POST /login\nAuthorization: Bearer provider-secret-token\n{\"password\":\"hunter2\"}",
		}},
	}
	got := RenderPrompt(req)
	for _, secret := range []string{"provider-secret-token", "hunter2"} {
		if strings.Contains(got, secret) {
			t.Fatalf("rendered prompt still contains %q:\n%s", secret, got)
		}
	}
	for _, marker := range []string{"[REDACTED:authorization:", "[REDACTED:password:"} {
		if !strings.Contains(got, marker) {
			t.Fatalf("rendered prompt missing marker %q:\n%s", marker, got)
		}
	}
}

func TestOpenAICompatibleCompleteRedactsProviderPayload(t *testing.T) {
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		raw, _ := json.Marshal(body)
		captured = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`))
	}))
	defer srv.Close()

	p, err := NewOpenAICompatible(OpenAICompatibleConfig{
		BaseURL: srv.URL,
		APIKey:  "provider-key",
		Model:   "test-model",
		Name:    "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	req := &Request{Messages: []Message{{
		Role:    "user",
		Content: "Cookie: sid=provider-cookie-secret\n{\"api_key\":\"target-api-secret\"}",
	}}}
	if _, err := p.Complete(t.Context(), req); err != nil {
		t.Fatal(err)
	}

	for _, secret := range []string{"provider-cookie-secret", "target-api-secret"} {
		if strings.Contains(captured, secret) {
			t.Fatalf("provider payload still contains %q:\n%s", secret, captured)
		}
	}
	for _, marker := range []string{"[REDACTED:cookie:", "[REDACTED:api-key:"} {
		if !strings.Contains(captured, marker) {
			t.Fatalf("provider payload missing marker %q:\n%s", marker, captured)
		}
	}
	if req.Messages[0].Content != "Cookie: sid=provider-cookie-secret\n{\"api_key\":\"target-api-secret\"}" {
		t.Fatalf("Complete mutated caller request: %q", req.Messages[0].Content)
	}
}
