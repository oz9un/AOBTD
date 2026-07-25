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
		{agent: "analyzer", duration: 99_000}, // audit-only row, not a model call
	} {
		if err := db.LogAIFull(scanID, call.agent, "test", "", "", "", "",
			call.tokensIn, call.tokensOut, call.duration, 0, "model", "", ""); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := db.GetAILogPhaseStats(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("phase stats = %+v, want analyzer and navigator only", stats)
	}
	if stats[0].Agent != "analyzer" || stats[0].Calls != 2 || stats[0].Tokens != 880 || stats[0].DurationMs != 12_000 {
		t.Fatalf("analyzer attribution = %+v", stats[0])
	}
	if stats[1].Agent != "navigator" || stats[1].Calls != 1 || stats[1].Tokens != 220 || stats[1].DurationMs != 4_000 {
		t.Fatalf("navigator attribution = %+v", stats[1])
	}
}
