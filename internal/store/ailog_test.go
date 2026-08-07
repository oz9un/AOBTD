package store

import (
	"path/filepath"
	"testing"
)

func TestAILogPhaseStatsAttributeOnlyModelCompute(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "ailog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range []struct {
		agent     string
		tokensIn  int
		tokensOut int
		duration  int64
	}{
		{agent: "navigator", tokensIn: 200, tokensOut: 20, duration: 4_000},
		{agent: "analyzer", tokensIn: 500, tokensOut: 50, duration: 7_000},
		{agent: "analyzer", tokensIn: 300, tokensOut: 30, duration: 5_000},
		{agent: "strategist", tokensOut: 2400, duration: 60_000}, // billed failed completion
		{agent: "analyzer", duration: 99_000},                    // audit-only row, not a model call
	} {
		if err := db.LogAIFull(scanID, call.agent, "test", "", "", "", "",
			call.tokensIn, call.tokensOut, call.duration, 0, "model", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.InsertStrategistCycle(StrategistCycle{
		ScanID: scanID, TriggerReason: "final_convergence", ModelID: "MiniMax-M3",
		DurationMs: 6_000, Error: `empty response content (finish_reason="length")`,
	}); err != nil {
		t.Fatal(err)
	}

	stats, err := db.GetAILogPhaseStats(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 3 {
		t.Fatalf("phase stats = %+v, want strategist, analyzer, and navigator", stats)
	}
	if stats[0].Agent != "strategist" || stats[0].Calls != 2 || stats[0].Tokens != 2400 || stats[0].DurationMs != 66_000 {
		t.Fatalf("strategist attribution = %+v", stats[0])
	}
	if stats[1].Agent != "analyzer" || stats[1].Calls != 2 || stats[1].Tokens != 880 || stats[1].DurationMs != 12_000 {
		t.Fatalf("analyzer attribution = %+v", stats[1])
	}
	if stats[2].Agent != "navigator" || stats[2].Calls != 1 || stats[2].Tokens != 220 || stats[2].DurationMs != 4_000 {
		t.Fatalf("navigator attribution = %+v", stats[2])
	}
	totalIn, totalOut, totalDuration, calls, _, err := db.GetAILogStats(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if totalIn != 1000 || totalOut != 2500 || totalDuration != 82_000 || calls != 5 {
		t.Fatalf("aggregate stats = %d/%d %dms %d calls", totalIn, totalOut, totalDuration, calls)
	}
	entries, err := db.GetAILog(scanID, 20)
	if err != nil {
		t.Fatal(err)
	}
	foundSyntheticFailure := false
	for _, entry := range entries {
		if entry.ID < 0 && entry.Agent == "strategist" && entry.Action == "plan_failed" {
			foundSyntheticFailure = true
		}
	}
	if !foundSyntheticFailure {
		t.Fatalf("historical strategist failure missing from AI log: %+v", entries)
	}
}
