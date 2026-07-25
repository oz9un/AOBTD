// strategist-prototype is a throwaway CLI that runs ONE Sovereign Strategist
// cycle against an existing scan's state. Used to compare prompt shapes and
// LLM models before we wire the Strategist into the orchestrator for real.
//
//   go run ./cmd/strategist-prototype --scan 15 --model qwen3:8b
//   go run ./cmd/strategist-prototype --scan 15 --model qwen2.5:14b --max-tokens 4096
//
// It does NOT modify the DB. It just reads state, builds the prompt, calls
// the model, prints the raw response + parsed directives + timing/cost.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/store"
)

func main() {
	var (
		scanID    int64
		model     string
		provider  string
		baseURL   string
		apiKey    string
		outputDir string
		maxTokens int
		saveFile  string
	)
	flag.Int64Var(&scanID, "scan", 0, "Scan id to analyze (required)")
	flag.StringVar(&model, "model", "qwen3:8b", "LLM model id")
	flag.StringVar(&provider, "provider", "ollama", "LLM provider: ollama, openai, anthropic")
	flag.StringVar(&baseURL, "llm-url", "", "Override provider base URL")
	flag.StringVar(&apiKey, "llm-key", "", "API key (or set AOBTD_LLM_KEY)")
	flag.StringVar(&outputDir, "output", "./aobtd-output", "Scan output dir (where scan.db lives)")
	flag.IntVar(&maxTokens, "max-tokens", 2048, "Max output tokens")
	flag.StringVar(&saveFile, "save", "", "If set, write the full JSON output to this file for later comparison")
	flag.Parse()

	if scanID == 0 {
		fmt.Fprintln(os.Stderr, "--scan is required")
		os.Exit(1)
	}
	if apiKey == "" {
		apiKey = os.Getenv("AOBTD_LLM_KEY")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	_ = logger

	dbPath := filepath.Join(outputDir, "scan.db")
	db, err := store.Open(dbPath)
	if err != nil {
		exitf("open db: %v", err)
	}
	defer db.Close()

	// Build the world-model prompt from scan state
	wm, err := buildWorldModel(db, scanID)
	if err != nil {
		exitf("build world model: %v", err)
	}

	userPrompt := buildPrompt(wm)

	fmt.Printf("═══ Strategist prototype ═══\n")
	fmt.Printf("Scan:      #%d (%s, target=%s, %s)\n", wm.ScanID, wm.Status, wm.Target, wm.Duration)
	fmt.Printf("Model:     %s via %s\n", model, provider)
	fmt.Printf("Endpoints: %d  profiles: %d (w/ issues: %d)  findings: %d  narrations: %d\n",
		wm.EndpointCount, wm.ProfileCount, wm.ProfilesWithIssues, wm.FindingCount, wm.NarrationCount)
	fmt.Printf("Prompt:    system=%d chars  user=%d chars\n",
		len(strategistSystemPrompt), len(userPrompt))
	fmt.Println()

	prov, err := llm.NewProvider(provider, baseURL, apiKey, model)
	if err != nil {
		exitf("provider: %v", err)
	}

	start := time.Now()
	resp, err := prov.Complete(context.Background(), &llm.Request{
		SystemPrompt: strategistSystemPrompt,
		Messages:     []llm.Message{{Role: "user", Content: userPrompt}},
		Temperature:  0.2,
		MaxTokens:    maxTokens,
		JSONMode:     true,
	})
	dur := time.Since(start)
	if err != nil {
		exitf("LLM call: %v", err)
	}

	costU := llm.CostMicroCents(model, resp.Usage)
	fmt.Printf("Response:  %d in / %d out tokens · %.2fs · $%.4f\n",
		resp.Usage.InputTokens, resp.Usage.OutputTokens, dur.Seconds(),
		float64(costU)/1_000_000.0)
	fmt.Println()

	// Try to parse the JSON output
	parsed := parseStrategistOutput(resp.Content)
	if parsed != nil {
		fmt.Println("─── Parsed output ──────────────────────────────")
		fmt.Printf("Hypotheses (%d):\n", len(parsed.Hypotheses))
		for _, h := range parsed.Hypotheses {
			fmt.Printf("  [%.2f] %s: %s\n", h.Confidence, h.ID, h.Statement)
			if len(h.SupportingEvidence) > 0 {
				fmt.Printf("         evidence: %s\n", strings.Join(h.SupportingEvidence, ", "))
			}
		}
		fmt.Printf("\nDirectives (%d):\n", len(parsed.Directives))
		for _, d := range parsed.Directives {
			fmt.Printf("  [pri=%d] %s\n", d.Priority, d.Action)
			if d.URL != "" {
				fmt.Printf("    url: %s\n", d.URL)
			}
			if d.URLTemplate != "" {
				fmt.Printf("    template: %s  values: %v\n", d.URLTemplate, d.Values)
			}
			if d.Field != "" {
				fmt.Printf("    field: %s  values: %v\n", d.Field, d.Values)
			}
			if d.EndpointID != "" {
				fmt.Printf("    endpoint: %s\n", d.EndpointID)
			}
			if d.Reason != "" {
				fmt.Printf("    reason: %s\n", d.Reason)
			}
			if len(d.GroundedIn) > 0 {
				fmt.Printf("    grounded_in: %s\n", strings.Join(d.GroundedIn, ", "))
			}
			if d.HypothesisID != "" {
				fmt.Printf("    hypothesis: %s\n", d.HypothesisID)
			}
		}
		fmt.Println()
		if parsed.ExecutiveSummary != "" {
			fmt.Printf("Executive summary: %s\n\n", parsed.ExecutiveSummary)
		}
		if parsed.NextCycleMinutes > 0 {
			fmt.Printf("Next cycle in: %d min\n", parsed.NextCycleMinutes)
		}
		if len(parsed.StopIf) > 0 {
			fmt.Printf("Stop if: %s\n", strings.Join(parsed.StopIf, "; "))
		}
	} else {
		fmt.Println("─── Raw output (could not parse as JSON) ──")
		fmt.Println(resp.Content)
	}

	if saveFile != "" {
		combined := map[string]any{
			"meta": map[string]any{
				"model":      model,
				"scan_id":    scanID,
				"duration_s": dur.Seconds(),
				"tokens_in":  resp.Usage.InputTokens,
				"tokens_out": resp.Usage.OutputTokens,
				"cost_usd":   float64(costU) / 1_000_000.0,
			},
			"raw":    resp.Content,
			"parsed": parsed,
		}
		b, _ := json.MarshalIndent(combined, "", "  ")
		os.WriteFile(saveFile, b, 0o644)
		fmt.Printf("\nSaved full output to %s\n", saveFile)
	}
}

func exitf(fmtStr string, args ...any) {
	fmt.Fprintf(os.Stderr, fmtStr+"\n", args...)
	os.Exit(1)
}
