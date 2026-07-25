package llm

import "testing"

// TestCostMicroCents checks pricing for the models we actively use,
// with special attention to MiniMax since scan 23/26/27 all reported
// $0.00 cost because the model wasn't in the pricing table.
func TestCostMicroCents(t *testing.T) {
	tests := []struct {
		name        string
		modelID     string
		usage       Usage
		wantGTZero  bool    // is cost > 0?
		approxCents float64 // rough expected value in cents (for non-zero models)
	}{
		{
			name:        "gpt-4.1-mini benchmark request exact cost",
			modelID:     "gpt-4.1-mini-2025-04-14",
			usage:       Usage{InputTokens: 351, OutputTokens: 1608},
			wantGTZero:  true,
			approxCents: 0.2713,
		},
		{
			name:        "gpt-5-mini benchmark request exact cost",
			modelID:     "gpt-5-mini-2025-08-07",
			usage:       Usage{InputTokens: 351, OutputTokens: 1608},
			wantGTZero:  true,
			approxCents: 0.3304,
		},
		{
			name:        "gpt-5.6-luna benchmark request exact cost",
			modelID:     "gpt-5.6-luna",
			usage:       Usage{InputTokens: 351, OutputTokens: 2032},
			wantGTZero:  true,
			approxCents: 1.2543,
		},
		{
			name:       "MiniMax-M2 small request",
			modelID:    "MiniMax-M2",
			usage:      Usage{InputTokens: 1000, OutputTokens: 500},
			wantGTZero: true,
			// $0.30/M input + $1.20/M output = $0.0009 = 0.09 cents.
			approxCents: 0.09,
		},
		{
			name:       "MiniMax-Text-01 (prefix match on minimax-text)",
			modelID:    "MiniMax-Text-01",
			usage:      Usage{InputTokens: 1000, OutputTokens: 500},
			wantGTZero: true,
		},
		{
			name:       "claude-sonnet-4 (longest-prefix match)",
			modelID:    "claude-sonnet-4-6-20250514",
			usage:      Usage{InputTokens: 1000, OutputTokens: 500},
			wantGTZero: true,
		},
		{
			name:       "qwen3:8b (local, free)",
			modelID:    "qwen3:8b",
			usage:      Usage{InputTokens: 100000, OutputTokens: 50000},
			wantGTZero: false,
		},
		{
			name:       "qwen2.5:14b (local, free)",
			modelID:    "qwen2.5:14b",
			usage:      Usage{InputTokens: 100000, OutputTokens: 50000},
			wantGTZero: false,
		},
		{
			name:       "unknown model (assumed free)",
			modelID:    "some-local-model-we-havent-listed",
			usage:      Usage{InputTokens: 1000, OutputTokens: 500},
			wantGTZero: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CostMicroCents(tc.modelID, tc.usage)
			if tc.wantGTZero && got <= 0 {
				t.Errorf("CostMicroCents(%q, ...) = %d µ¢, want > 0", tc.modelID, got)
			}
			if !tc.wantGTZero && got > 0 {
				t.Errorf("CostMicroCents(%q, ...) = %d µ¢, want 0 for free model", tc.modelID, got)
			}
			if tc.approxCents > 0 {
				gotCents := float64(got) / 10_000
				if delta := gotCents - tc.approxCents; delta < -0.0002 || delta > 0.0002 {
					t.Errorf("CostMicroCents(%q) = %.4f cents, want ~%.4f", tc.modelID, gotCents, tc.approxCents)
				}
			}
		})
	}
}

func TestBudgetPricesEachRoutedModel(t *testing.T) {
	b := NewBudget(0, 0, 1000, nil)
	b.SetModel("gpt-4.1-mini")
	b.RecordForModel("gpt-4.1-mini", Usage{InputTokens: 351, OutputTokens: 1608})
	b.RecordForModel("gpt-5-mini", Usage{InputTokens: 351, OutputTokens: 2032})

	// Benchmark calls cost 2,713 + 4,151 = 6,864 micro-cents.
	if got := b.UsedCostMicroCents(); got != 6864 {
		t.Fatalf("mixed-model cost=%d micro-cents, want 6864", got)
	}
}
