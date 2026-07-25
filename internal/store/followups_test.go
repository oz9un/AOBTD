package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openFollowUpTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// Keep the tests runnable while the queue migration hook is being wired
	// into DB.migrate in a separate change. The helper is idempotent.
	if err := db.migrateFollowUpLeases(); err != nil {
		t.Fatalf("migrateFollowUpLeases() error = %v", err)
	}
	return db
}

func createFollowUpTestScan(t *testing.T, db *DB, target string) int64 {
	t.Helper()
	id, err := db.CreateScan(target, `{}`)
	if err != nil {
		t.Fatalf("CreateScan(%q) error = %v", target, err)
	}
	return id
}

func TestComputeDedupeKeyCanonicalParamsAndHypothesis(t *testing.T) {
	base := FollowUp{
		Action: "probe_param",
		URL:    "https://example.test/api/users/7",
		Params: map[string]any{
			"field":  "role",
			"values": []any{"user", "admin"},
			"nested": map[string]any{"enabled": true, "count": 2},
		},
		HypothesisID: "h-access-control",
	}
	sameMeaningDifferentMapOrder := FollowUp{
		Action:       base.Action,
		URL:          base.URL,
		HypothesisID: base.HypothesisID,
		Params: map[string]any{
			"nested": map[string]any{"count": 2, "enabled": true},
			"values": []any{"user", "admin"},
			"field":  "role",
		},
	}

	key, err := computeDedupeKey(base)
	if err != nil {
		t.Fatalf("computeDedupeKey(base) error = %v", err)
	}
	sameKey, err := computeDedupeKey(sameMeaningDifferentMapOrder)
	if err != nil {
		t.Fatalf("computeDedupeKey(same) error = %v", err)
	}
	if key != sameKey {
		t.Fatalf("canonical map order changed key: %q != %q", key, sameKey)
	}
	if len(key) != 64 {
		t.Fatalf("dedupe key length = %d, want SHA-256 hex length 64", len(key))
	}

	differentValue := base
	differentValue.Params = map[string]any{
		"field":  "role",
		"values": []any{"guest", "admin"},
		"nested": map[string]any{"enabled": true, "count": 2},
	}
	valueKey, err := computeDedupeKey(differentValue)
	if err != nil {
		t.Fatalf("computeDedupeKey(different value) error = %v", err)
	}
	if key == valueKey {
		t.Fatal("different parameter values produced the same dedupe key")
	}

	differentHypothesis := base
	differentHypothesis.HypothesisID = "h-tenant-boundary"
	hypothesisKey, err := computeDedupeKey(differentHypothesis)
	if err != nil {
		t.Fatalf("computeDedupeKey(different hypothesis) error = %v", err)
	}
	if key == hypothesisKey {
		t.Fatal("different hypotheses produced the same dedupe key")
	}

	reanalyzeKey, err := computeDedupeKey(FollowUp{
		Action: "reanalyze",
		URL:    base.URL,
		Params: base.Params,
	})
	if err != nil {
		t.Fatalf("computeDedupeKey(reanalyze) error = %v", err)
	}
	if reanalyzeKey != "" {
		t.Fatalf("reanalyze dedupe key = %q, want empty", reanalyzeKey)
	}
}

func TestInsertDirectiveDedupeKeepsHypothesisIdentity(t *testing.T) {
	db := openFollowUpTestDB(t)
	scanID := createFollowUpTestScan(t, db, "https://example.test")
	f := FollowUp{
		Action: "probe_param",
		URL:    "https://example.test/api/orders/42",
		Params: map[string]any{"field": "owner_id", "values": []any{7, 8}},
	}

	firstID, err := db.InsertDirective(scanID, f, []string{"traffic:1"}, "h-owner", "strategist")
	if err != nil || firstID == 0 {
		t.Fatalf("InsertDirective(first) = (%d, %v), want inserted row", firstID, err)
	}
	duplicateID, err := db.InsertDirective(scanID, f, []string{"traffic:2"}, "h-owner", "strategist")
	if err != nil {
		t.Fatalf("InsertDirective(duplicate) error = %v", err)
	}
	if duplicateID != 0 {
		t.Fatalf("duplicate directive id = %d, want 0", duplicateID)
	}
	secondHypothesisID, err := db.InsertDirective(scanID, f, []string{"traffic:1"}, "h-tenant", "strategist")
	if err != nil || secondHypothesisID == 0 {
		t.Fatalf("InsertDirective(second hypothesis) = (%d, %v), want inserted row", secondHypothesisID, err)
	}

	rows, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatalf("ListFollowUps() error = %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("ListFollowUps() len = %d, want 2", len(rows))
	}
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row.HypothesisID] = true
	}
	if !seen["h-owner"] || !seen["h-tenant"] {
		t.Fatalf("stored hypothesis identities = %v, want h-owner and h-tenant", seen)
	}
}

func TestInsertFollowUpNormalizesMethodPrefixedTargets(t *testing.T) {
	db := openFollowUpTestDB(t)
	scanID := createFollowUpTestScan(t, db, "https://example.test")

	id, err := db.InsertFollowUp(scanID, FollowUp{
		Action: "probe_param",
		URL:    "POST /WebGoat/PathTraversal/profile-upload",
		Params: map[string]any{
			"param":        "uploadedFile",
			"url_template": "GET /WebGoat/IDOR/profile/{id}",
			"values":       []string{"../test.txt"},
		},
	})
	if err != nil || id == 0 {
		t.Fatalf("InsertFollowUp(method-prefixed) = (%d, %v), want inserted row", id, err)
	}
	duplicateID, err := db.InsertFollowUp(scanID, FollowUp{
		Action: "probe_param",
		URL:    "/WebGoat/PathTraversal/profile-upload",
		Params: map[string]any{
			"param":        "uploadedFile",
			"url_template": "/WebGoat/IDOR/profile/{id}",
			"values":       []string{"../test.txt"},
		},
	})
	if err != nil {
		t.Fatalf("InsertFollowUp(duplicate normalized) error = %v", err)
	}
	if duplicateID != 0 {
		t.Fatalf("duplicate normalized follow-up id = %d, want 0", duplicateID)
	}

	rows, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatalf("ListFollowUps() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("ListFollowUps() len = %d, want 1", len(rows))
	}
	if rows[0].URL != "/WebGoat/PathTraversal/profile-upload" {
		t.Fatalf("stored URL = %q, want method stripped", rows[0].URL)
	}
	if got := rows[0].Params["url_template"]; got != "/WebGoat/IDOR/profile/{id}" {
		t.Fatalf("stored url_template = %#v, want method stripped", got)
	}
}

func TestInsertFollowUpPersistsActualEmitter(t *testing.T) {
	db := openFollowUpTestDB(t)
	scanID := createFollowUpTestScan(t, db, "https://example.test")
	id, err := db.InsertFollowUp(scanID, FollowUp{
		SourceAgent: "copilot", Action: "visit", URL: "https://example.test/catalog", Status: FollowUpPending,
	})
	if err != nil || id == 0 {
		t.Fatalf("InsertFollowUp() = (%d, %v)", id, err)
	}
	var sourceAgent, emittedBy string
	if err := db.Conn().QueryRow(`SELECT source_agent, emitted_by FROM follow_ups WHERE id=?`, id).Scan(&sourceAgent, &emittedBy); err != nil {
		t.Fatal(err)
	}
	if sourceAgent != "copilot" || emittedBy != "copilot" {
		t.Fatalf("source_agent=%q emitted_by=%q", sourceAgent, emittedBy)
	}
}

func TestClaimFollowUpsOrdersAndReclaimsExpiredLease(t *testing.T) {
	db := openFollowUpTestDB(t)
	scanID := createFollowUpTestScan(t, db, "https://example.test")

	for _, task := range []FollowUp{
		{Action: "fetch", URL: "https://example.test/low", Priority: 1},
		{Action: "fetch", URL: "https://example.test/high", Priority: 10},
		{Action: "fetch", URL: "https://example.test/mid", Priority: 5},
	} {
		if id, err := db.InsertFollowUp(scanID, task); err != nil || id == 0 {
			t.Fatalf("InsertFollowUp(%s) = (%d, %v), want inserted row", task.URL, id, err)
		}
	}

	claimed, err := db.ClaimFollowUps(scanID, 2, 90*time.Second)
	if err != nil {
		t.Fatalf("ClaimFollowUps() error = %v", err)
	}
	if len(claimed) != 2 {
		t.Fatalf("ClaimFollowUps() len = %d, want 2", len(claimed))
	}
	if claimed[0].Priority != 10 || claimed[1].Priority != 5 {
		t.Fatalf("claim priorities = [%d %d], want [10 5]", claimed[0].Priority, claimed[1].Priority)
	}
	for _, task := range claimed {
		if task.ScanID != scanID || task.Status != FollowUpRunning {
			t.Errorf("claimed task identity/status = scan %d status %q", task.ScanID, task.Status)
		}
		if task.ClaimedAt == "" || task.LeaseExpiresAt == "" || task.LeaseToken == "" {
			t.Errorf("claim metadata incomplete: %+v", task)
		}
		if task.AttemptCount != 1 {
			t.Errorf("attempt count = %d, want 1", task.AttemptCount)
		}
	}
	if claimed[0].LeaseToken == claimed[1].LeaseToken {
		t.Fatal("separate tasks received the same lease token")
	}

	oldToken := claimed[0].LeaseToken
	if _, err := db.Conn().Exec(`
		UPDATE follow_ups SET lease_expires_at = datetime('now', '-1 second')
		WHERE scan_id = ? AND id = ?`, scanID, claimed[0].ID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	reclaimed, err := db.ClaimFollowUps(scanID, 1, time.Minute)
	if err != nil {
		t.Fatalf("ClaimFollowUps(reclaim) error = %v", err)
	}
	if len(reclaimed) != 1 || reclaimed[0].ID != claimed[0].ID {
		t.Fatalf("reclaimed = %+v, want task id %d", reclaimed, claimed[0].ID)
	}
	if reclaimed[0].AttemptCount != 2 {
		t.Fatalf("reclaimed attempt count = %d, want 2", reclaimed[0].AttemptCount)
	}
	if reclaimed[0].LeaseToken == "" || reclaimed[0].LeaseToken == oldToken {
		t.Fatalf("reclaimed lease token = %q, want a new non-empty token", reclaimed[0].LeaseToken)
	}

	if err := db.CompleteFollowUp(scanID, reclaimed[0].ID, oldToken, FollowUpDone, "stale worker"); !errors.Is(err, ErrFollowUpNotRunning) {
		t.Fatalf("CompleteFollowUp(stale token) error = %v, want ErrFollowUpNotRunning", err)
	}
	if err := db.CompleteFollowUp(scanID, reclaimed[0].ID, reclaimed[0].LeaseToken, FollowUpDone, "fresh worker"); err != nil {
		t.Fatalf("CompleteFollowUp(fresh token) error = %v", err)
	}
}

func TestClaimFollowUpsRotatesAcrossHypothesesWithinRiskBand(t *testing.T) {
	db := openFollowUpTestDB(t)
	scanID := createFollowUpTestScan(t, db, "https://example.test")
	insert := func(hypothesis, path string, priority int) {
		t.Helper()
		id, err := db.InsertDirective(scanID, FollowUp{
			Action: "fetch", URL: "https://example.test/" + path, Priority: priority,
		}, []string{"host:example.test"}, hypothesis, "strategist")
		if err != nil || id == 0 {
			t.Fatalf("InsertDirective(%s/%s) = (%d, %v)", hypothesis, path, id, err)
		}
	}
	insert("h-one", "one-a", 10)
	insert("h-one", "one-b", 10)
	insert("h-two", "two-a", 9)

	first, err := db.ClaimFollowUps(scanID, 1, time.Minute)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim = (%+v, %v)", first, err)
	}
	if first[0].HypothesisID != "h-one" {
		t.Fatalf("first hypothesis = %q, want highest-priority h-one", first[0].HypothesisID)
	}
	if err := db.CompleteFollowUp(scanID, first[0].ID, first[0].LeaseToken, FollowUpDone, "observed"); err != nil {
		t.Fatal(err)
	}

	second, err := db.ClaimFollowUps(scanID, 1, time.Minute)
	if err != nil || len(second) != 1 {
		t.Fatalf("second claim = (%+v, %v)", second, err)
	}
	if second[0].HypothesisID != "h-two" {
		t.Fatalf("second hypothesis = %q, want less-tested h-two within same risk band", second[0].HypothesisID)
	}
}

func TestCompleteFollowUpRequiresScanLeaseAndTerminalStatus(t *testing.T) {
	db := openFollowUpTestDB(t)
	scanA := createFollowUpTestScan(t, db, "https://a.example.test")
	scanB := createFollowUpTestScan(t, db, "https://b.example.test")

	id, err := db.InsertFollowUp(scanA, FollowUp{Action: "fetch", URL: "https://a.example.test/me"})
	if err != nil || id == 0 {
		t.Fatalf("InsertFollowUp() = (%d, %v), want inserted row", id, err)
	}
	claimed, err := db.ClaimFollowUps(scanA, 1, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimFollowUps() = (%+v, %v), want one task", claimed, err)
	}
	task := claimed[0]

	if err := db.CompleteFollowUp(scanA, task.ID, task.LeaseToken, FollowUpRunning, "not terminal"); !errors.Is(err, ErrInvalidFollowUpStatus) {
		t.Fatalf("CompleteFollowUp(running) error = %v, want ErrInvalidFollowUpStatus", err)
	}
	if err := db.CompleteFollowUp(scanB, task.ID, task.LeaseToken, FollowUpFailed, "wrong scan"); !errors.Is(err, ErrFollowUpNotRunning) {
		t.Fatalf("CompleteFollowUp(wrong scan) error = %v, want ErrFollowUpNotRunning", err)
	}
	if err := db.CompleteFollowUp(scanA, task.ID, "", FollowUpFailed, "empty token"); !errors.Is(err, ErrFollowUpNotRunning) {
		t.Fatalf("CompleteFollowUp(empty token) error = %v, want ErrFollowUpNotRunning", err)
	}

	if err := db.CompleteFollowUp(scanA, task.ID, task.LeaseToken, FollowUpFailed, "request rejected"); err != nil {
		t.Fatalf("CompleteFollowUp(valid) error = %v", err)
	}
	if err := db.CompleteFollowUp(scanA, task.ID, task.LeaseToken, FollowUpDone, "second finish"); !errors.Is(err, ErrFollowUpNotRunning) {
		t.Fatalf("CompleteFollowUp(already terminal) error = %v, want ErrFollowUpNotRunning", err)
	}

	var status, result, completedAt string
	var leaseExpiresAt, leaseToken *string
	if err := db.Conn().QueryRow(`
		SELECT status, result, COALESCE(completed_at,''), lease_expires_at, lease_token
		FROM follow_ups WHERE scan_id = ? AND id = ?`, scanA, task.ID).
		Scan(&status, &result, &completedAt, &leaseExpiresAt, &leaseToken); err != nil {
		t.Fatalf("read completed task: %v", err)
	}
	if status != FollowUpFailed || result != "request rejected" || completedAt == "" {
		t.Fatalf("terminal row = status %q result %q completed %q", status, result, completedAt)
	}
	if leaseExpiresAt != nil {
		t.Fatalf("terminal lease_expires_at = %v, want NULL", *leaseExpiresAt)
	}
	if leaseToken == nil || *leaseToken != "" {
		t.Fatalf("terminal lease_token = %v, want empty string", leaseToken)
	}
}

func TestSkipNonCopilotReconFollowUpsLeavesOnlySafeSteering(t *testing.T) {
	db := openFollowUpTestDB(t)
	scanID := createFollowUpTestScan(t, db, "https://app.example.test")
	for _, task := range []FollowUp{
		{SourceAgent: "analyzer", Action: "probe_param", URL: "https://app.example.test/search"},
		{SourceAgent: "copilot", Action: "probe_param", URL: "https://app.example.test/filter"},
		{SourceAgent: "copilot", Action: "visit", URL: "https://app.example.test/docs"},
	} {
		if _, err := db.InsertFollowUp(scanID, task); err != nil {
			t.Fatal(err)
		}
	}
	skipped, err := db.SkipNonCopilotReconFollowUps(scanID)
	if err != nil || skipped != 2 {
		t.Fatalf("SkipNonCopilotReconFollowUps() = (%d,%v), want (2,nil)", skipped, err)
	}
	claimed, err := db.ClaimFollowUps(scanID, 10, time.Minute)
	if err != nil || len(claimed) != 1 || claimed[0].SourceAgent != "copilot" || claimed[0].Action != "visit" {
		t.Fatalf("remaining Recon steering = (%+v,%v)", claimed, err)
	}
}
