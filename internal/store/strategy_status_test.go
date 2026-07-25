package store

import "testing"

func TestSetHypothesisStatusPreservesEvidenceTerminalStates(t *testing.T) {
	db, err := Open(t.TempDir() + "/scan.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	for _, terminal := range []string{HypothesisConfirmed, HypothesisRefuted} {
		id := "h-" + terminal
		if err := db.UpsertHypothesis(Hypothesis{
			ID: id, ScanID: scanID, Statement: "test", Status: terminal,
		}); err != nil {
			t.Fatal(err)
		}
		if err := db.SetHypothesisStatus(scanID, id, HypothesisStale, "strategist/cycle-2"); err != nil {
			t.Fatal(err)
		}
		hyps, err := db.ListHypotheses(scanID)
		if err != nil {
			t.Fatal(err)
		}
		var got string
		for _, h := range hyps {
			if h.ID == id {
				got = h.Status
			}
		}
		if got != terminal {
			t.Fatalf("status for %s = %q, want preserved %q", id, got, terminal)
		}
	}

	if err := db.UpsertHypothesis(Hypothesis{
		ID: "h-active", ScanID: scanID, Statement: "test", Status: HypothesisActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetHypothesisStatus(scanID, "h-active", HypothesisStale, "strategist/cycle-3"); err != nil {
		t.Fatal(err)
	}
	hyps, err := db.ListHypotheses(scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hyps {
		if h.ID == "h-active" && (h.Status != HypothesisStale || h.ResolvedBy != "strategist/cycle-3") {
			t.Fatalf("active transition = status %q resolved_by %q", h.Status, h.ResolvedBy)
		}
	}
}

func TestHypothesisEventsTrackBeliefHistory(t *testing.T) {
	db, err := Open(t.TempDir() + "/events.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.UpsertHypothesis(Hypothesis{
		ID: "h1", ScanID: scanID, CycleID: 1, Statement: "orders may be enumerable",
		Status: HypothesisActive, Confidence: 0.4, SupportingEvidence: []string{"endpoint:GET /orders/1"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertHypothesis(Hypothesis{
		ID: "h1", ScanID: scanID, CycleID: 2, Statement: "orders may be enumerable",
		Status: HypothesisActive, Confidence: 0.7, SupportingEvidence: []string{"endpoint:GET /orders/1", "traffic:12"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetHypothesisStatus(scanID, "h1", HypothesisStale, "strategist/cycle-3"); err != nil {
		t.Fatal(err)
	}

	events, err := db.ListHypothesisEvents(scanID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events len = %d, want 3: %+v", len(events), events)
	}
	if events[0].EventType != "created" || events[0].NewStatus != HypothesisActive {
		t.Fatalf("created event = %+v", events[0])
	}
	if events[1].EventType != "revised" || events[1].OldConfidence == nil || events[1].NewConfidence == nil ||
		*events[1].OldConfidence != 0.4 || *events[1].NewConfidence != 0.7 {
		t.Fatalf("revised event = %+v", events[1])
	}
	if events[2].EventType != "status_changed" || events[2].OldStatus != HypothesisActive || events[2].NewStatus != HypothesisStale {
		t.Fatalf("status event = %+v", events[2])
	}
}

func TestUpsertHypothesisRevisesStatementAndCycle(t *testing.T) {
	db, err := Open(t.TempDir() + "/revision.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertHypothesis(Hypothesis{
		ID: "h1", ScanID: scanID, CycleID: 1, Statement: "Orders may be enumerable",
		Status: HypothesisActive, Confidence: .4,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertHypothesis(Hypothesis{
		ID: "h1", ScanID: scanID, CycleID: 2, Statement: "Order objects appear owner-scoped; test cross-owner access",
		Status: HypothesisActive, Confidence: .7,
	}); err != nil {
		t.Fatal(err)
	}
	hyps, err := db.ListHypotheses(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hyps) != 1 || hyps[0].CycleID != 2 || hyps[0].Statement != "Order objects appear owner-scoped; test cross-owner access" {
		t.Fatalf("revised hypothesis = %+v", hyps)
	}
}
