package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrafficActionLifecycle(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "traffic-actions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	actionID, err := db.BeginTrafficAction(scanID, "navigator", "click",
		"open the account menu", "https://example.test/", "", "h-account")
	if err != nil || actionID == 0 {
		t.Fatalf("BeginTrafficAction() = (%d, %v)", actionID, err)
	}
	if err := db.CompleteTrafficAction(scanID, actionID, TrafficActionSucceeded,
		"menu opened", "https://example.test/account"); err != nil {
		t.Fatal(err)
	}

	actions, err := db.ListTrafficActions(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 {
		t.Fatalf("actions = %d, want 1", len(actions))
	}
	got := actions[0]
	if got.SourceAgent != "navigator" || got.Action != "click" ||
		got.Reason != "open the account menu" || got.HypothesisID != "h-account" ||
		got.Status != TrafficActionSucceeded || got.ToURL != "https://example.test/account" ||
		got.CompletedAt == "" {
		t.Fatalf("action = %+v", got)
	}
	if err := db.CompleteTrafficAction(scanID, actionID, TrafficActionSucceeded, "again", ""); err == nil {
		t.Fatal("second completion unexpectedly succeeded")
	}
}

func TestBeginTrafficActionRejectsPassiveCapture(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "traffic-actions-invalid.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://example.test", `{}`)
	if _, err := db.BeginTrafficAction(scanID, "capture", "navigate", "", "", "", ""); err == nil {
		t.Fatal("passive capture action unexpectedly succeeded")
	}
}

func TestTrafficActionMetadataRedactsCredentialValues(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	actionID, err := db.BeginTrafficAction(
		scanID, "navigator", "navigate", "use token=topsecret",
		"https://alice:password@example.test/?api_key=keyvalue", "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteTrafficAction(scanID, actionID, TrafficActionFailed, "Authorization: Bearer abcdefghijklmnop", ""); err != nil {
		t.Fatal(err)
	}
	actions, err := db.ListTrafficActions(scanID)
	if err != nil {
		t.Fatal(err)
	}
	serialized := fmt.Sprintf("%+v", actions)
	for _, secret := range []string{"topsecret", "password", "keyvalue", "abcdefghijklmnop"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("action metadata retained %q: %s", secret, serialized)
		}
	}
}
