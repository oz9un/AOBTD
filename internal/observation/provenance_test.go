package observation

import "testing"

func TestProvenanceTrackerNestedAndOutOfOrderCleanup(t *testing.T) {
	tracker := NewProvenanceTracker()
	if got := tracker.Snapshot().SourceAgent; got != "capture" {
		t.Fatalf("initial source = %q, want capture", got)
	}

	endCrawler := tracker.Begin(Provenance{SourceAgent: "crawler"})
	endProbe := tracker.Begin(Provenance{
		SourceAgent:    "explorer",
		SourceActionID: 42,
		HypothesisID:   " h-object-owner ",
	})

	endCrawler()
	got := tracker.Snapshot()
	if got.SourceAgent != "explorer" || got.SourceActionID != 42 || got.HypothesisID != "h-object-owner" {
		t.Fatalf("active provenance = %+v", got)
	}

	endProbe()
	endProbe() // cleanup is idempotent
	if got := tracker.Snapshot().SourceAgent; got != "capture" {
		t.Fatalf("final source = %q, want capture", got)
	}
}

func TestProvenanceNormalizeRejectsNegativeActionID(t *testing.T) {
	got := (Provenance{SourceActionID: -7}).Normalize()
	if got.SourceAgent != "capture" || got.SourceActionID != 0 {
		t.Fatalf("normalized provenance = %+v", got)
	}
}

func TestProvenanceTrackerDisambiguatesConcurrentTargets(t *testing.T) {
	tracker := NewProvenanceTracker()
	endAgent := tracker.Begin(Provenance{SourceAgent: "crawler"})
	defer endAgent()
	endA := tracker.BeginTargeted(Provenance{SourceAgent: "crawler", SourceActionID: 10}, "https://example.test/a")
	defer endA()
	endB := tracker.BeginTargeted(Provenance{SourceAgent: "crawler", SourceActionID: 20}, "https://example.test/b")
	defer endB()

	if got := tracker.SnapshotForRequest("https://example.test/a", ""); got.SourceActionID != 10 {
		t.Fatalf("target A action = %d, want 10", got.SourceActionID)
	}
	if got := tracker.SnapshotForRequest("https://example.test/api/data", "https://example.test/b"); got.SourceActionID != 20 {
		t.Fatalf("target B referer action = %d, want 20", got.SourceActionID)
	}
	if got := tracker.SnapshotForRequest("https://cdn.example.test/app.js", ""); got.SourceAgent != "crawler" || got.SourceActionID != 0 {
		t.Fatalf("ambiguous subresource provenance = %+v, want crawler agent-level", got)
	}
}
