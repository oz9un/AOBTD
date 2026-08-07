package store

import (
	"path/filepath"
	"testing"
)

func TestReconObservationPersistsProvenanceAndPromotion(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	runID, err := db.StartReconRun(scanID, "enumeraite", []string{"crtsh"}, map[string]any{"dns": true})
	if err != nil {
		t.Fatal(err)
	}
	item := ReconObservation{Target: "example.test", AssetType: "hostname", Value: "api.example.test", Source: "crtsh", State: "historical", Confidence: 1, InScope: true, Evidence: map[string]any{"certificate_id": 7}}
	if err := db.UpsertReconObservation(scanID, runID, item); err != nil {
		t.Fatal(err)
	}
	item.State = "confirmed"
	item.Confidence = .9
	if err := db.UpsertReconObservation(scanID, runID, item); err != nil {
		t.Fatal(err)
	}
	if err := db.FinishReconRun(runID, "complete", []any{}); err != nil {
		t.Fatal(err)
	}
	items, err := db.ListReconObservations(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].State != "confirmed" || items[0].Evidence["certificate_id"] != float64(7) {
		t.Fatalf("observations = %+v", items)
	}
	run, err := db.LatestReconRun(scanID)
	if err != nil || run == nil || run.Status != "complete" {
		t.Fatalf("run=%+v err=%v", run, err)
	}
}
