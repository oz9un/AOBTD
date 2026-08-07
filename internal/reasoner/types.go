// Package reasoner provides domain-specialised LLM agents that translate
// scan evidence into targeted probe plans. The reasoners sit between the
// Strategist (generalist planner) and the Verifier (generic executor).
//
// This is the "Option C" hybrid architecture from ARCHITECTURE.md § 9:
// shared execution substrate + per-domain LLM reasoning.
package reasoner

import (
	"context"
	"time"

	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// DiscoveredEndpoint is the reasoner-local view of a probe target. The
// agent package has a richer version; the orchestrator converts at the
// callsite so we don't create an import cycle here (reasoner → agent AND
// agent → reasoner would close a loop).
type DiscoveredEndpoint struct {
	URL                 string
	Method              string
	Path                string
	Params              []string
	BodyFields          []string
	RequestContentType  string
	ResponseContentType string
	ExampleRequestBody  string
	// AuthHeaders are replayable credential/session headers observed for this
	// endpoint. They are for deterministic local executors only; reasoner
	// prompts intentionally omit them.
	AuthHeaders map[string]string
}

// ProbePlan is a specialised reasoner's recommendation for the Verifier.
// Each plan names a technique the Verifier knows how to execute, a target
// (URL + method + optional field), payload variants to try, and a
// confirmation rule for deciding whether a response counts as exploited.
type ProbePlan struct {
	// Technique — one of the allowlisted technique names the Verifier
	// supports (see agent.KnownTechniques). Rejects anything else.
	Technique string `json:"technique"`

	// Target — where to apply the technique.
	Target ProbeTarget `json:"target"`

	// Payloads — candidate values to try. The Verifier may iterate all of
	// them, stop on first confirmation, or sample depending on cost budget.
	Payloads []string `json:"payloads"`

	// Confirmation — rule for deciding a response indicates exploitation.
	// At least one of the fields must be non-empty.
	Confirmation ConfirmationRule `json:"confirmation"`

	// Rationale — short LLM explanation for the narration timeline.
	// Must reference evidence ("endpoint X observed in traffic returned Y
	// with header Z").
	Rationale string `json:"rationale"`

	// Confidence — reasoner's self-reported priority (0.0-1.0). Used to
	// order plans when budget is limited.
	Confidence float64 `json:"confidence"`

	// SourceReasoner — e.g. "AuthReasoner". Set by the reasoner package
	// itself; LLM output for this field is ignored.
	SourceReasoner string `json:"source_reasoner,omitempty"`
}

// ProbeTarget names the endpoint + mutation point for a plan.
type ProbeTarget struct {
	URL      string            `json:"url"`
	Method   string            `json:"method"`
	Field    string            `json:"field,omitempty"`     // param / body field to mutate
	Headers  map[string]string `json:"headers,omitempty"`   // baseline headers (e.g. observed Auth)
	BodyType string            `json:"body_type,omitempty"` // "json" | "form" | "" (GET)
}

// ConfirmationRule tells the Verifier how to decide whether an executed
// plan landed a hit. Evaluated as: status-match AND (body-contains OR
// header-present). Missing fields default to "any".
type ConfirmationRule struct {
	StatusCodes   []int    `json:"status_codes,omitempty"`
	BodyContains  []string `json:"body_contains,omitempty"`
	BodyAbsent    []string `json:"body_absent,omitempty"`
	HeaderPresent []string `json:"header_present,omitempty"`
	MinBodyBytes  int      `json:"min_body_bytes,omitempty"`
}

// Evidence is the input a reasoner receives: a curated snapshot of what
// the scan has learned so far, trimmed to keep the token cost small.
type Evidence struct {
	ScanID         int64
	Target         string
	CapturedAt     time.Time
	LoginEndpoints []DiscoveredEndpoint
	QueryEndpoints []DiscoveredEndpoint
	APIEndpoints   []DiscoveredEndpoint
	ObservedEmails []string
	JWTSamples     []JWTSample
	Findings       []types.Finding
	AuthPersonas   []AuthPersona
	Hypothesis     *store.Hypothesis // the Strategist hypothesis this is scoped to (may be nil)
}

// AuthPersona is operator-provided context for ownership-aware access-control
// testing. Password is intentionally excluded from JSON marshalling so LLM
// prompts can include persona context without leaking secrets; AccessReasoner
// hydrates executable plans with the password after the model returns.
type AuthPersona struct {
	Label       string `json:"label,omitempty"`
	LoginURL    string `json:"login_url,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"-"`
	OwnerMarker string `json:"owner_marker,omitempty"`
	ObjectURL   string `json:"object_url,omitempty"`
}

// JWTSample is a compact snapshot of a JWT seen in captured traffic.
// Preserves the header (so reasoners can see alg), a redacted payload
// preview, and the endpoint that returned / accepted it.
type JWTSample struct {
	Alg            string `json:"alg"`
	PayloadPreview string `json:"payload_preview"` // first ~200 chars of decoded payload
	Source         string `json:"source"`          // URL that issued / received the token
}

// Reasoner is a per-domain agent: given Evidence, emit ProbePlans.
type Reasoner interface {
	// Name returns the reasoner's identifier (e.g. "AuthReasoner").
	Name() string

	// Apply inspects the evidence and returns 0-N probe plans plus the
	// LLM usage of the call. Implementations MUST:
	//   - never fabricate URLs / endpoints not in the evidence
	//   - only emit techniques in KnownTechniques
	//   - populate SourceReasoner on each plan they return
	// Usage is (0,0) for LLM-less runs or fast-reject no-ops.
	Apply(ctx context.Context, ev Evidence) ([]ProbePlan, ReasonerUsage, error)
}

// ReasonerUsage is a compact summary of the LLM resources consumed by a
// single Reasoner.Apply call. Surfaced to the UI so the operator can see
// which reasoners are expensive and which are cheap.
type ReasonerUsage struct {
	InputTokens  int
	OutputTokens int
	ModelID      string
}

func reasonerUsageFromError(err error, provider llm.Provider) ReasonerUsage {
	usage, modelID, billed := llm.UsageFromError(err)
	if !billed {
		return ReasonerUsage{}
	}
	if modelID == "" && provider != nil {
		modelID = provider.ModelInfo().Name
	}
	return ReasonerUsage{
		InputTokens:  usage.InputTokens,
		OutputTokens: usage.OutputTokens,
		ModelID:      modelID,
	}
}

// KnownTechniques is the allowlist of technique names a reasoner may
// emit. Anything else is rejected during plan validation. Each entry
// corresponds to an execution path the Verifier already knows.
//
// Categories:
//   - auth: weak credentials, SQLi login bypass, JWT forgery
//   - injection: SQLi, NoSQL, LDAP, command injection
//   - access: IDOR, BOLA, role escalation
var KnownTechniques = map[string]string{
	"weak_credentials":           "Try (user, pass) pairs against a login endpoint.",
	"sqli_login_bypass":          "SQL injection payloads in login email/username field.",
	"jwt_unsigned":               "Forge a JWT with alg:none and submit to an auth endpoint.",
	"jwt_weak_secret":            "Brute-force HS256 secret against a captured JWT using a wordlist.",
	"password_reset_abuse":       "Skip / bypass security question on password-reset endpoint.",
	"sqli_generic":               "SQL injection on a non-login parameter.",
	"idor_sequential_id":         "Substitute adjacent numeric IDs on an auth-gated endpoint.",
	"bola_tenant_crossing":       "Swap tenant / user ID in an auth-gated request.",
	"bola_two_persona_ownership": "Log in as two personas and prove user A can read user B's object while the response still belongs to B.",
	"bola_two_persona_mutation":  "Log in as two personas and prove user A can mutate user B's object while the changed state remains owned by B.",
	// Chain-level "technique" — ChainReasoner combines confirmed findings
	// into a narrative. No HTTP action; the Executor narrates the chain
	// and emits an info-level finding so the attack story lands in the UI.
	"chain_attack_narrative": "Multi-step attack chain combining two or more confirmed findings.",
	// Executable chain: weak-credentials login → use captured session as
	// Authorization for a subsequent IDOR / BOLA probe. End-to-end attack
	// automation, not just narration.
	"chain_auth_then_access": "Chain: log in with weak creds, then use the session token to run an IDOR probe — proves the full attack path works.",
}

// IsKnownTechnique reports whether a technique name is on the allowlist.
func IsKnownTechnique(name string) bool {
	_, ok := KnownTechniques[name]
	return ok
}
