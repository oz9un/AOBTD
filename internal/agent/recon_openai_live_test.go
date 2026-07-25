package agent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/store"
)

// TestReconOpenAILiveSynthesis is an opt-in semantic regression harness. It
// re-synthesizes ReconModel from an already captured scan DB, so prompt/model
// quality can be iterated without crawling or probing the target again.
func TestReconOpenAILiveSynthesis(t *testing.T) {
	if os.Getenv("AOBTD_OPENAI_RECON_SMOKE") != "1" {
		t.Skip("set AOBTD_OPENAI_RECON_SMOKE=1 to run live recon synthesis")
	}
	path := os.Getenv("AOBTD_RECON_DB")
	if path == "" {
		t.Fatal("AOBTD_RECON_DB is required")
	}
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		key = os.Getenv("AOBTD_LLM_KEY")
	}
	if key == "" {
		t.Fatal("OPENAI_API_KEY or AOBTD_LLM_KEY is required")
	}
	model := os.Getenv("AOBTD_RECON_MODEL")
	if model == "" {
		model = "gpt-4.1-mini"
	}

	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	provider, err := llm.NewProvider("openai", "", key, model)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	budget := llm.NewBudget(200_000, 20_000, 25, logger)
	budget.SetModel(model)
	a := NewAnalyzerAgent(db, provider, budget, NewBus(logger), NewSharedState("recon-smoke"), 1, nil, logger)
	a.loadUnderstanding()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := a.summarizeApp(ctx); err != nil {
		t.Fatal(err)
	}
	a.saveUnderstanding()
	u := a.understanding
	if u == nil || len(u.Recon.Pages) == 0 || len(u.Recon.Unknowns) == 0 {
		t.Fatalf("incomplete recon model: %+v", u)
	}
	for _, workflow := range u.Recon.Workflows {
		for _, step := range workflow.Steps {
			if step.StateChange {
				grounded := false
				for _, pageID := range step.PageIDs {
					for _, page := range u.Recon.Pages {
						if page.ID == pageID && (page.Method == "POST" || page.Method == "PUT" || page.Method == "PATCH" || page.Method == "DELETE") {
							grounded = true
						}
					}
				}
				if !grounded {
					t.Fatalf("ungrounded state-changing step: %+v", step)
				}
			}
		}
	}
	t.Logf("app=%s pages=%d roles=%d objects=%d workflows=%d ownership=%d unknowns=%d confidence=%.2f cost=%s",
		u.AppType, len(u.Recon.Pages), len(u.Recon.Roles), len(u.Recon.Objects), len(u.Recon.Workflows),
		len(u.Recon.OwnershipBoundaries), len(u.Recon.Unknowns), u.Recon.Metrics.OverallConfidence, budget.Summary())
}
