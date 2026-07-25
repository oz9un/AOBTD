package store

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCopilotThreadPersistsBoundedCompletedHistory(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "copilot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://example.test", `{}`)
	for _, q := range []string{"first", "second", "third"} {
		id, err := db.CreateCopilotTurn(scanID, q)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.UpdateCopilotTurn(id, CopilotTurnUpdate{Status: "completed", Answer: q + " answer"}); err != nil {
			t.Fatal(err)
		}
	}
	history, err := db.CopilotHistory(scanID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[0].Question != "second" || history[1].Question != "third" {
		t.Fatalf("bounded history = %+v", history)
	}
	thread, err := db.CopilotThread(scanID, 20)
	if err != nil || len(thread) != 3 {
		t.Fatalf("thread = (%+v, %v)", thread, err)
	}
	if err := db.ClearCopilotThread(scanID); err != nil {
		t.Fatal(err)
	}
	thread, err = db.CopilotThread(scanID, 20)
	if err != nil || len(thread) != 0 {
		t.Fatalf("cleared thread = (%+v, %v)", thread, err)
	}
}

func TestFailCopilotTurnPreservesExistingAuditTrace(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "copilot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://example.test", `{}`)
	turnID, _ := db.CreateCopilotTurn(scanID, "review this action")
	if err := db.UpdateCopilotTurn(turnID, CopilotTurnUpdate{
		Status: "awaiting", StepsJSON: `[{"sql":"SELECT id FROM findings"}]`,
		PendingJSON: `{"kind":"request","why":"verify"}`, ResumeState: "signed-token",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.FailCopilotTurn(turnID, "provider unavailable"); err != nil {
		t.Fatal(err)
	}
	turns, err := db.CopilotThread(scanID, 10)
	if err != nil || len(turns) != 1 {
		t.Fatalf("thread = (%+v, %v)", turns, err)
	}
	turn := turns[0]
	if turn.Status != "error" || turn.ResumeState != "" || !strings.Contains(turn.StepsJSON, "SELECT id") || !strings.Contains(turn.PendingJSON, "verify") {
		t.Fatalf("failed turn lost its trace: %+v", turn)
	}
}

func TestCopilotResumeSigningKeyPersistsAndIsDatabaseScoped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "copilot.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := db.CopilotResumeSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	second, err := reopened.CopilotResumeSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || len(second) != 32 {
		t.Fatalf("reopened signing key changed: first=%x second=%x", first, second)
	}

	other, err := Open(filepath.Join(t.TempDir(), "other.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otherKey, err := other.CopilotResumeSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) == string(otherKey) {
		t.Fatal("independent databases unexpectedly share a Copilot signing key")
	}
}

func TestCopilotApprovalIsSingleUseScanBoundAndExpiring(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "copilot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanA, _ := db.CreateScan("https://a.example.test", `{}`)
	scanB, _ := db.CreateScan("https://b.example.test", `{}`)
	turnID, _ := db.CreateCopilotTurn(scanA, "visit it")
	if err := db.RegisterCopilotApproval("valid-hash", scanA, turnID, "directive", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConsumeCopilotApproval("valid-hash", scanB, true); !errors.Is(err, ErrCopilotApprovalUnavailable) {
		t.Fatalf("cross-scan consume error = %v", err)
	}
	if got, err := db.ConsumeCopilotApproval("valid-hash", scanA, true); err != nil || got != turnID {
		t.Fatalf("first consume = (%d, %v)", got, err)
	}
	if _, err := db.ConsumeCopilotApproval("valid-hash", scanA, true); !errors.Is(err, ErrCopilotApprovalUnavailable) {
		t.Fatalf("replay consume error = %v", err)
	}

	expiredTurn, _ := db.CreateCopilotTurn(scanA, "expired")
	if err := db.RegisterCopilotApproval("expired-hash", scanA, expiredTurn, "request", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConsumeCopilotApproval("expired-hash", scanA, true); !errors.Is(err, ErrCopilotApprovalUnavailable) {
		t.Fatalf("expired consume error = %v", err)
	}

	concurrentTurn, _ := db.CreateCopilotTurn(scanA, "concurrent")
	if err := db.RegisterCopilotApproval("concurrent-hash", scanA, concurrentTurn, "request", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.ConsumeCopilotApproval("concurrent-hash", scanA, true); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrCopilotApprovalUnavailable) {
				t.Errorf("concurrent consume error = %v", err)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("concurrent approval successes = %d, want 1", got)
	}
}

func TestCopilotAwaitingTurnAndApprovalPersistAtomically(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "copilot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://a.example.test", `{}`)
	turnID, _ := db.CreateCopilotTurn(scanID, "send it")
	update := CopilotTurnUpdate{
		Status: "awaiting", PendingJSON: `{"kind":"request"}`, ResumeState: "signed-token",
	}
	if err := db.UpdateCopilotTurnWithApproval(turnID, update, "valid-hash", scanID, "request", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	turns, err := db.CopilotThread(scanID, 10)
	if err != nil || len(turns) != 1 || turns[0].Status != "awaiting" || turns[0].ResumeState != "signed-token" {
		t.Fatalf("awaiting turn = (%+v, %v)", turns, err)
	}

	if err := db.UpdateCopilotTurnWithApproval(turnID+999, update, "orphan-hash", scanID, "request", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("missing turn unexpectedly accepted an approval")
	}
	var orphanCount int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM copilot_approvals WHERE token_hash = 'orphan-hash'`).Scan(&orphanCount); err != nil {
		t.Fatal(err)
	}
	if orphanCount != 0 {
		t.Fatalf("orphan approval survived rollback: %d", orphanCount)
	}
}
