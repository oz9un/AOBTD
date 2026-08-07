package agent

import (
	"context"
	"testing"
	"time"
)

func TestExplorerPassContextCancelsInflightWorkAtBudget(t *testing.T) {
	const budget = 25 * time.Millisecond
	start := time.Now()
	ctx, cancel := explorerPassContext(context.Background(), start.Add(budget))
	defer cancel()

	select {
	case <-ctx.Done():
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Explorer pass context did not cancel in-flight work")
	}
	elapsed := time.Since(start)
	if elapsed < budget/2 {
		t.Fatalf("Explorer pass cancelled too early after %s", elapsed)
	}
	if elapsed > 150*time.Millisecond {
		t.Fatalf("Explorer pass exceeded its %s budget by too much: %s", budget, elapsed)
	}
}

func TestExplorerPassContextKeepsEarlierParentDeadline(t *testing.T) {
	parent, cancelParent := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelParent()
	ctx, cancel := explorerPassContext(parent, time.Now().Add(time.Second))
	defer cancel()

	select {
	case <-ctx.Done():
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Explorer pass ignored earlier parent deadline")
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("Explorer pass error = %v, want deadline exceeded", ctx.Err())
	}
}
