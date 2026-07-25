package llm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// BudgetLevel indicates how much budget remains.
type BudgetLevel string

const (
	BudgetOK        BudgetLevel = "ok"        // <75% used
	BudgetWarning   BudgetLevel = "warning"   // 75-90% used
	BudgetCritical  BudgetLevel = "critical"  // 90-100% used
	BudgetExhausted BudgetLevel = "exhausted" // 100%+ used
)

// Budget tracks token and cost consumption for a scan. It enforces the
// tightest-binding cap — whichever of token-cap or dollar-cap is hit first
// wins. Cost is tracked in micro-cents (1¢ = 10,000 µ¢) so we can do integer
// math on fractional-cent model calls.
type Budget struct {
	mu              sync.Mutex
	maxInputTokens  int
	maxOutputTokens int
	maxCostUcents   int64 // hard cap in micro-cents; 0 = unlimited
	usedInput       int
	usedOutput      int
	usedCostUcents  int64
	reservedInput   int
	reservedOutput  int
	reservedCost    int64
	modelID         string // used to look up pricing for cost estimates
	logger          *slog.Logger
}

var ErrBudgetExceeded = errors.New("LLM budget reservation denied")

type BudgetReservation struct {
	budget     *Budget
	input      int
	output     int
	costUcents int64
	once       sync.Once
}

// NewBudget creates a budget tracker. maxCostCents is the hard dollar cap
// (in whole cents). Pass 0 to disable the cost cap.
func NewBudget(maxInput, maxOutput, maxCostCents int, logger *slog.Logger) *Budget {
	return &Budget{
		maxInputTokens:  maxInput,
		maxOutputTokens: maxOutput,
		maxCostUcents:   int64(maxCostCents) * 10_000,
		logger:          logger,
	}
}

// SetModel tells the budget which model's pricing to use for cost tracking.
// Call once after the provider is configured.
func (b *Budget) SetModel(modelID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.modelID = modelID
}

// Record adds token usage from a completed request and accrues cost.
func (b *Budget) Record(usage Usage) {
	b.RecordForModel("", usage)
}

// RecordForModel records a request using the model that actually answered.
// An empty modelID preserves the configured default for legacy callers.
func (b *Budget) RecordForModel(modelID string, usage Usage) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.usedInput += usage.InputTokens
	b.usedOutput += usage.OutputTokens
	if modelID == "" {
		modelID = b.modelID
	}
	if modelID != "" {
		b.usedCostUcents += CostMicroCents(modelID, usage)
	}

	b.logLevelLocked()
}

func (b *Budget) logLevelLocked() {
	if b.logger == nil {
		return
	}
	level := b.levelLocked()
	switch level {
	case BudgetWarning:
		b.logger.Warn("budget at 75%",
			"used_input", b.usedInput,
			"max_input", b.maxInputTokens,
			"used_cents", b.usedCostUcents/10_000,
			"max_cents", b.maxCostUcents/10_000,
		)
	case BudgetCritical:
		b.logger.Warn("budget at 90% — critical findings only",
			"used_input", b.usedInput,
			"used_cents", b.usedCostUcents/10_000,
		)
	case BudgetExhausted:
		b.logger.Error("budget exhausted — stopping LLM analysis",
			"used_input", b.usedInput,
			"used_cents", b.usedCostUcents/10_000,
		)
	}
}

// Reserve atomically claims worst-case room for one model call.
func (b *Budget) Reserve(modelID string, estimatedInput, maxOutput int) (*BudgetReservation, bool) {
	if b == nil {
		return nil, true
	}
	if estimatedInput < 0 {
		estimatedInput = 0
	}
	if maxOutput < 0 {
		maxOutput = 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if modelID == "" {
		modelID = b.modelID
	}
	cost := int64(0)
	if modelID != "" {
		cost = CostMicroCents(modelID, Usage{InputTokens: estimatedInput, OutputTokens: maxOutput})
	}
	if b.maxInputTokens > 0 && b.usedInput+b.reservedInput+estimatedInput > b.maxInputTokens {
		return nil, false
	}
	if b.maxOutputTokens > 0 && b.usedOutput+b.reservedOutput+maxOutput > b.maxOutputTokens {
		return nil, false
	}
	if b.maxCostUcents > 0 && b.usedCostUcents+b.reservedCost+cost > b.maxCostUcents {
		return nil, false
	}
	b.reservedInput += estimatedInput
	b.reservedOutput += maxOutput
	b.reservedCost += cost
	return &BudgetReservation{budget: b, input: estimatedInput, output: maxOutput, costUcents: cost}, true
}

func (r *BudgetReservation) Commit(modelID string, usage Usage) {
	if r == nil || r.budget == nil {
		return
	}
	r.once.Do(func() {
		b := r.budget
		b.mu.Lock()
		defer b.mu.Unlock()
		b.releaseReservationLocked(r)
		b.usedInput += usage.InputTokens
		b.usedOutput += usage.OutputTokens
		if modelID == "" {
			modelID = b.modelID
		}
		if modelID != "" {
			b.usedCostUcents += CostMicroCents(modelID, usage)
		}
		b.logLevelLocked()
	})
}

func (r *BudgetReservation) Release() {
	if r == nil || r.budget == nil {
		return
	}
	r.once.Do(func() {
		r.budget.mu.Lock()
		defer r.budget.mu.Unlock()
		r.budget.releaseReservationLocked(r)
	})
}

func (b *Budget) releaseReservationLocked(r *BudgetReservation) {
	b.reservedInput -= r.input
	b.reservedOutput -= r.output
	b.reservedCost -= r.costUcents
}

// CompleteBudgeted reserves, dispatches, and reconciles one model call.
func CompleteBudgeted(ctx context.Context, provider Provider, budget *Budget, req *Request, estimatedInput int) (*Response, error) {
	if budget == nil {
		return provider.Complete(ctx, req)
	}
	if estimatedInput <= 0 {
		var prompt strings.Builder
		prompt.WriteString(req.SystemPrompt)
		for _, message := range req.Messages {
			prompt.WriteString(message.Content)
		}
		estimatedInput = provider.CountTokens(prompt.String())
	}
	reservation, ok := budget.Reserve(provider.ModelInfo().Name, estimatedInput, req.MaxTokens)
	if !ok {
		return nil, ErrBudgetExceeded
	}
	resp, err := provider.Complete(ctx, req)
	if err != nil {
		reservation.Release()
		return nil, err
	}
	reservation.Commit(ResponseModel(resp, provider), resp.Usage)
	return resp, nil
}

// CanSpend returns true if the estimated tokens fit within both token and
// cost budgets. A blocked call does NOT decrement the budget.
func (b *Budget) CanSpend(estimatedInputTokens int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Token cap
	if b.maxInputTokens > 0 && b.usedInput+b.reservedInput+estimatedInputTokens > b.maxInputTokens {
		return false
	}
	// Cost cap — estimate what this request will add (input tokens only; output
	// is unknown at call time but bounded by max_tokens which we ignore here
	// to keep the estimate conservative on the input side).
	if b.maxCostUcents > 0 && b.modelID != "" {
		addU := CostMicroCents(b.modelID, Usage{InputTokens: estimatedInputTokens})
		if b.usedCostUcents+b.reservedCost+addU > b.maxCostUcents {
			return false
		}
	}
	return true
}

// Level returns the current budget level based on whichever cap is closer
// to being breached.
func (b *Budget) Level() BudgetLevel {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.levelLocked()
}

func (b *Budget) levelLocked() BudgetLevel {
	tokenRatio := 0.0
	if b.maxInputTokens > 0 {
		tokenRatio = float64(b.usedInput+b.reservedInput) / float64(b.maxInputTokens)
	}
	costRatio := 0.0
	if b.maxCostUcents > 0 {
		costRatio = float64(b.usedCostUcents+b.reservedCost) / float64(b.maxCostUcents)
	}
	ratio := tokenRatio
	if costRatio > ratio {
		ratio = costRatio
	}
	switch {
	case ratio >= 1.0 && (b.maxInputTokens > 0 || b.maxCostUcents > 0):
		return BudgetExhausted
	case ratio >= 0.9:
		return BudgetCritical
	case ratio >= 0.75:
		return BudgetWarning
	default:
		return BudgetOK
	}
}

// UsedInput returns total input tokens consumed.
func (b *Budget) UsedInput() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.usedInput
}

// UsedOutput returns total output tokens consumed.
func (b *Budget) UsedOutput() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.usedOutput
}

// UsedCostCents returns the scan's running spend in whole cents.
func (b *Budget) UsedCostCents() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.usedCostUcents / 10_000
}

// UsedCostMicroCents returns the scan's running spend in micro-cents.
func (b *Budget) UsedCostMicroCents() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.usedCostUcents
}

// MaxCostCents returns the configured dollar cap in cents (0 = unlimited).
func (b *Budget) MaxCostCents() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maxCostUcents / 10_000
}

// Summary returns a human-readable budget summary.
func (b *Budget) Summary() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	tokenPct := 0.0
	if b.maxInputTokens > 0 {
		tokenPct = float64(b.usedInput) / float64(b.maxInputTokens) * 100
	}
	if b.maxCostUcents > 0 {
		usedDollars := float64(b.usedCostUcents) / 1_000_000.0
		maxDollars := float64(b.maxCostUcents) / 1_000_000.0
		costPct := usedDollars / maxDollars * 100
		return fmt.Sprintf("Tokens: %d/%d input (%.1f%%), %d output | Cost: $%.4f/$%.2f (%.1f%%)",
			b.usedInput, b.maxInputTokens, tokenPct, b.usedOutput,
			usedDollars, maxDollars, costPct)
	}
	return fmt.Sprintf("Tokens: %d/%d input (%.1f%%), %d output",
		b.usedInput, b.maxInputTokens, tokenPct, b.usedOutput)
}

// RelevanceThreshold returns the dynamic threshold based on budget level.
// As budget depletes, only higher-relevance traffic gets analyzed.
func (b *Budget) RelevanceThreshold() float64 {
	switch b.Level() {
	case BudgetCritical:
		return 0.7 // only high-relevance
	case BudgetWarning:
		return 0.5 // medium and above
	default:
		return 0.3 // default threshold
	}
}
