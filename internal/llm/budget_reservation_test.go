package llm

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestBudgetReservationIsAtomicAcrossConcurrentCallers(t *testing.T) {
	budget := NewBudget(100, 100, 0, nil)
	var accepted atomic.Int32
	var reservationsMu sync.Mutex
	var reservations []*BudgetReservation
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reservation, ok := budget.Reserve("gpt-4.1-mini", 60, 20)
			if ok {
				accepted.Add(1)
				reservationsMu.Lock()
				reservations = append(reservations, reservation)
				reservationsMu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted reservations = %d, want 1", accepted.Load())
	}
	reservations[0].Release()
	if _, ok := budget.Reserve("gpt-4.1-mini", 60, 20); !ok {
		t.Fatal("released capacity was not reusable")
	}
}

func TestBudgetReservationCommitsActualUsageOnce(t *testing.T) {
	budget := NewBudget(1000, 1000, 0, nil)
	reservation, ok := budget.Reserve("gpt-4.1-mini", 500, 400)
	if !ok {
		t.Fatal("reservation denied")
	}
	reservation.Commit("gpt-4.1-mini", Usage{InputTokens: 120, OutputTokens: 30})
	reservation.Commit("gpt-4.1-mini", Usage{InputTokens: 999, OutputTokens: 999})
	if budget.UsedInput() != 120 || budget.UsedOutput() != 30 {
		t.Fatalf("usage = %d/%d, want 120/30", budget.UsedInput(), budget.UsedOutput())
	}
	if _, ok := budget.Reserve("gpt-4.1-mini", 800, 900); !ok {
		t.Fatal("actual usage did not replace worst-case reservation")
	}
}

func TestBudgetReservationIncludesOutputCap(t *testing.T) {
	budget := NewBudget(0, 100, 0, nil)
	if _, ok := budget.Reserve("gpt-4.1-mini", 1, 101); ok {
		t.Fatal("reservation exceeding output cap was accepted")
	}
}

func TestCompleteBudgetedCommitsBilledUsageFromError(t *testing.T) {
	provider := &fallbackTestProvider{
		model: "MiniMax-M3",
		err: &CompletionError{
			Message: "reasoning exhausted completion allowance",
			Usage:   Usage{InputTokens: 6200, OutputTokens: 2400},
			Model:   "MiniMax-M3",
		},
	}
	budget := NewBudget(100_000, 100_000, 0, nil)
	_, err := CompleteBudgeted(context.Background(), provider, budget, &Request{
		Messages:  []Message{{Role: "user", Content: "return JSON"}},
		MaxTokens: 8192,
	}, 6200)
	if err == nil {
		t.Fatal("CompleteBudgeted() error = nil")
	}
	if budget.UsedInput() != 6200 || budget.UsedOutput() != 2400 {
		t.Fatalf("billed error usage = %d/%d, want 6200/2400",
			budget.UsedInput(), budget.UsedOutput())
	}
	if _, ok := budget.Reserve("MiniMax-M3", 1, 97_601); ok {
		t.Fatal("failed-call output usage was incorrectly refunded")
	}
}
