package store

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestGetRecentNarrationsReturnsTailInChronologicalOrder(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "narrations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 8; i++ {
		if _, err := db.InsertNarration(scanID, "navigator", "plan", fmt.Sprintf("event-%d", i), "", nil); err != nil {
			t.Fatal(err)
		}
	}

	got, err := db.GetRecentNarrations(scanID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("recent narration count = %d, want 3", len(got))
	}
	for i, want := range []string{"event-6", "event-7", "event-8"} {
		if got[i].Message != want {
			t.Fatalf("recent narration %d = %q, want %q", i, got[i].Message, want)
		}
	}
}
