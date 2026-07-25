package llm

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOpenAILiveSmoke(t *testing.T) {
	if os.Getenv("AOBTD_OPENAI_SMOKE") != "1" {
		t.Skip("set AOBTD_OPENAI_SMOKE=1 to run live OpenAI smoke test")
	}
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		key = os.Getenv("AOBTD_LLM_KEY")
	}
	if key == "" {
		t.Fatal("OPENAI_API_KEY or AOBTD_LLM_KEY is required")
	}

	for _, model := range []string{"gpt-4.1-mini", "gpt-5-mini"} {
		t.Run(model, func(t *testing.T) {
			provider, err := NewProvider("openai", "", key, model)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			resp, err := provider.Complete(ctx, &Request{
				SystemPrompt: "Return only compact JSON.",
				Messages: []Message{{
					Role:    "user",
					Content: `Classify GET /rest/basket/8 returning {"UserId":25,"Products":[]} as {"purpose":string,"risk":string}.`,
				}},
				Temperature: 0.2,
				MaxTokens:   1024,
				JSONMode:    true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if resp.Usage.InputTokens == 0 || resp.Usage.OutputTokens == 0 {
				t.Fatalf("usage not populated: %+v", resp.Usage)
			}
			if !strings.Contains(resp.Content, "{") {
				t.Fatalf("response did not look like JSON: %q", resp.Content)
			}
		})
	}
}
