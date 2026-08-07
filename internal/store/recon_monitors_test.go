package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestReconMonitorPersistsAndBecomesDue(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	monitor := ReconMonitor{Target: "https://example.test", Enabled: true, IntervalMinutes: 60, IncludeSubdomains: true, Sources: []string{"crtsh"}, Options: map[string]any{"dns": true}, NextRunAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)}
	if err := db.UpsertReconMonitor(monitor); err != nil {
		t.Fatal(err)
	}
	due, err := db.ListDueReconMonitors(time.Now(), 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due=%+v err=%v", due, err)
	}
	if err := db.FinishReconMonitorRun(due[0].ID, 9, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetReconMonitor(monitor.Target)
	if err != nil || got.LastScanID != 9 {
		t.Fatalf("monitor=%+v err=%v", got, err)
	}
}
