package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/reasoner"
	"github.com/ozzyw/aobtd/pkg/types"
)

// runReasonerPhase dispatches the evidence accumulated by the scan to the
// registered domain reasoners (currently just AuthReasoner), then runs any
// validated ProbePlans through the shared Executor.
//
// Called from Orchestrator.Run after the Verifier's proactive-probe pass.
// No-op if no LLM provider is configured (handled at the call-site).
//
// This is a spike: one reasoner (auth), two technique primitives wired
// (weak_credentials, sqli_login_bypass). Additional reasoners (injection,
// access, chain) slot in by appending to the `reasoners` slice below once
// built. Their techniques extend `reasoner.KnownTechniques` and the
// Executor's dispatch switch.
func (o *Orchestrator) runReasonerPhase(ctx context.Context) {
	o.logger.Info("=== Phase: Reasoner Planning ===")
	o.db.InsertNarration(o.scanID, "orchestrator", "phase",
		"Phase 6.5: Reasoner Planning — domain-specialised LLM agents review scan evidence "+
			"and produce targeted probe plans. Plans execute via the shared Executor; "+
			"findings flow into the same pipeline as Verifier output.",
		"", nil)

	evidence, err := reasoner.BuildEvidence(ctx, o.db, o.scanID, o.target)
	if err != nil {
		o.logger.Warn("reasoner: building evidence failed", "error", err)
		return
	}
	o.attachBOLAPersonasToEvidence(&evidence)
	o.logger.Info("reasoner: evidence summary",
		"login_endpoints", len(evidence.LoginEndpoints),
		"observed_emails", len(evidence.ObservedEmails),
		"jwt_samples", len(evidence.JWTSamples),
		"existing_findings", len(evidence.Findings),
		"auth_personas", len(evidence.AuthPersonas))

	reasoners := []reasoner.Reasoner{
		reasoner.NewAuthReasoner(o.reasoningProvider, o.logger),
		reasoner.NewInjectionReasoner(o.reasoningProvider, o.logger),
		reasoner.NewAccessReasoner(o.reasoningProvider, o.logger),
		// ChainReasoner runs LAST so its Evidence.Findings includes any
		// new findings the per-domain reasoners just confirmed earlier
		// in this phase. It composes multi-step attack narratives from
		// the cross-domain set of confirmed findings.
		reasoner.NewChainReasoner(o.reasoningProvider, o.logger),
	}

	// Shared HTTP client — same TLS config as Verifier.
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	executor := reasoner.NewPolicyExecutor(client, o.db, o.scanID, o.logger,
		o.executionPolicy, o.target, o.auditPolicyDenial)

	totalPlans := 0
	confirmed := 0
	for _, r := range reasoners {
		if ctx.Err() != nil {
			return
		}
		// Rebuild evidence for ChainReasoner so it sees findings the
		// other reasoners just produced in this same phase. The per-
		// domain reasoners use the initial evidence snapshot (faster).
		reasonerEvidence := evidence
		if r.Name() == "ChainReasoner" {
			if fresh, err := reasoner.BuildEvidence(ctx, o.db, o.scanID, o.target); err == nil {
				o.attachBOLAPersonasToEvidence(&fresh)
				reasonerEvidence = fresh
				o.logger.Info("ChainReasoner: rebuilt evidence",
					"confirmed_findings", countConfirmed(fresh.Findings))
			}
		}
		// Budget gate before every reasoner LLM call. Reviewer flagged
		// (C1) that this phase otherwise bypassed llm.Budget entirely.
		// Skip critically / exhausted — reasoner output is additive, it's
		// OK to drop a reasoner when budget is tight.
		var budgetReservation *llm.BudgetReservation
		if o.budget != nil {
			lvl := o.budget.Level()
			if lvl == llm.BudgetExhausted {
				o.logger.Info("reasoner skipped — budget exhausted",
					"reasoner", r.Name(), "level", lvl)
				o.db.InsertNarration(o.scanID, "reasoner", "no_plans",
					r.Name()+" skipped — LLM budget exhausted.", "", nil)
				continue
			}
			// Reasoners' messages are small (~2 KB evidence + 2-3 KB
			// system prompt ≈ 2000 input tokens worst case). Check the
			// budget can absorb that.
			modelID := ""
			if o.reasoningProvider != nil {
				modelID = o.reasoningProvider.ModelInfo().Name
			}
			var ok bool
			outputAllowance := llm.StructuredOutputTokenLimit(o.reasoningProvider, 3500, 10240)
			budgetReservation, ok = o.budget.Reserve(modelID, 2500, outputAllowance)
			if !ok {
				o.logger.Info("reasoner skipped — insufficient budget headroom",
					"reasoner", r.Name(), "level", lvl)
				o.db.InsertNarration(o.scanID, "reasoner", "no_plans",
					r.Name()+" skipped — insufficient budget.", "", nil)
				continue
			}
		}

		reasonerStarted := time.Now()
		plans, usage, err := r.Apply(ctx, reasonerEvidence)
		reasonerDurationMs := time.Since(reasonerStarted).Milliseconds()
		if budgetReservation != nil && (usage.InputTokens > 0 || usage.OutputTokens > 0) {
			budgetReservation.Commit(usage.ModelID, llm.Usage{
				InputTokens:  usage.InputTokens,
				OutputTokens: usage.OutputTokens,
			})
		} else if budgetReservation != nil {
			budgetReservation.Release()
		}
		if usage.InputTokens > 0 || usage.OutputTokens > 0 {
			action := "plan"
			result := fmt.Sprintf("%d plan(s) returned", len(plans))
			if err != nil {
				action = "plan_failed"
				result = err.Error()
			}
			_ = o.db.LogAIWithCost(o.scanID, r.Name(), action,
				"reasoner planning pass", "", "", result,
				usage.InputTokens, usage.OutputTokens, reasonerDurationMs,
				llm.CostMicroCents(usage.ModelID, llm.Usage{
					InputTokens: usage.InputTokens, OutputTokens: usage.OutputTokens,
				}), usage.ModelID)
		}
		usageMeta := map[string]any{
			"reasoner":      r.Name(),
			"input_tokens":  usage.InputTokens,
			"output_tokens": usage.OutputTokens,
			"model_id":      usage.ModelID,
		}
		if err != nil {
			o.logger.Warn("reasoner apply failed", "reasoner", r.Name(), "error", err)
			o.db.InsertNarration(o.scanID, "reasoner", "error",
				r.Name()+" failed: "+err.Error(), "", usageMeta)
			continue
		}
		if len(plans) == 0 {
			o.logger.Info("reasoner produced no plans", "reasoner", r.Name(),
				"input_tokens", usage.InputTokens, "output_tokens", usage.OutputTokens)
			o.db.InsertNarration(o.scanID, "reasoner", "no_plans",
				r.Name()+" reviewed the evidence and didn't emit any probe plans — "+
					"either the domain surface wasn't present in captured traffic or "+
					"validation rejected all proposed plans.",
				"", usageMeta)
			continue
		}
		o.logger.Info("reasoner produced plans", "reasoner", r.Name(),
			"count", len(plans),
			"input_tokens", usage.InputTokens, "output_tokens", usage.OutputTokens)
		emitMeta := map[string]any{
			"reasoner":      r.Name(),
			"plan_count":    len(plans),
			"input_tokens":  usage.InputTokens,
			"output_tokens": usage.OutputTokens,
			"model_id":      usage.ModelID,
		}
		o.db.InsertNarration(o.scanID, "reasoner", "plans_emitted",
			fmt.Sprintf("%s produced %d probe plan(s) from the scan evidence (%d in / %d out tokens).",
				r.Name(), len(plans), usage.InputTokens, usage.OutputTokens),
			"", emitMeta)
		totalPlans += len(plans)

		for _, plan := range plans {
			if ctx.Err() != nil {
				return
			}
			hit, err := executor.ExecutePlan(ctx, plan)
			if err != nil {
				o.logger.Warn("plan execution error", "reasoner", r.Name(), "error", err)
				continue
			}
			if hit {
				confirmed++
			}
		}
	}

	o.logger.Info("=== Phase: Reasoner Planning complete ===",
		"total_plans", totalPlans,
		"confirmed", confirmed)
}

// countConfirmed reports how many findings in the slice have
// confidence="confirmed". Helper for log messages only.
func countConfirmed(findings []types.Finding) int {
	n := 0
	for _, f := range findings {
		if string(f.Confidence) == "confirmed" {
			n++
		}
	}
	return n
}

func (o *Orchestrator) attachBOLAPersonasToEvidence(ev *reasoner.Evidence) {
	if len(o.bolaPersonas) < 2 {
		return
	}
	ev.AuthPersonas = ev.AuthPersonas[:0]
	for _, p := range o.bolaPersonas {
		rp := reasoner.AuthPersona{
			Label:       p.Label,
			LoginURL:    p.LoginURL,
			Username:    p.Username,
			Password:    p.Password,
			OwnerMarker: p.OwnerMarker,
			ObjectURL:   p.ObjectURL,
		}
		ev.AuthPersonas = append(ev.AuthPersonas, rp)
		if rp.LoginURL != "" {
			appendDiscoveredEndpointIfMissing(&ev.LoginEndpoints, reasoner.DiscoveredEndpoint{
				URL:    rp.LoginURL,
				Method: "POST",
				Path:   pathOnly(rp.LoginURL),
			})
		}
		if rp.ObjectURL != "" {
			appendDiscoveredEndpointIfMissing(&ev.APIEndpoints, reasoner.DiscoveredEndpoint{
				URL:    rp.ObjectURL,
				Method: "GET",
				Path:   pathOnly(rp.ObjectURL),
			})
		}
	}
}

func appendDiscoveredEndpointIfMissing(eps *[]reasoner.DiscoveredEndpoint, candidate reasoner.DiscoveredEndpoint) {
	if candidate.URL == "" {
		return
	}
	for _, ep := range *eps {
		if ep.URL == candidate.URL {
			return
		}
	}
	*eps = append(*eps, candidate)
}

func pathOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return raw
	}
	return u.Path
}
