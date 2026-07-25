// Package pathlabel turns observed URL paths into human-readable templates.
//
// It is the single source of truth for path naming across the codebase —
// crawler saturation, endpoint bundle display, analyzer cluster
// labelling, findings, exports all route through here so they share
// one cache, one vocabulary, and one canonical form per pattern.
//
// Why it exists:
//
// Before this package, three independent layers each invented their own
// path-naming scheme:
//
//   - browser/saturation.urlShape() → "/us/WORD/WORD/WORD" for crawler
//     bucket decisions, surfaced in narrations.
//   - extract/endpoint_bundle.normalizePathForDisplay() → "/api/v1/{id}"
//     for the Endpoints view.
//   - agent/analyzer_path_refine.refineURLPattern() → LLM-labelled
//     {seg} placeholders for analyzer narrations.
//
// They produced different placeholders for the same URL. The crawler's
// "WORD" leaked into the AI Log. The analyzer's regex couldn't tell a
// 52-char BFF service name from an opaque token. There was no shared
// cache, so the same site could pay for two LLM calls labelling the
// same pattern.
//
// pathlabel collapses this into one component with three behaviours:
//
//  1. Cache: a (skeleton, sorted-samples) → Label memo. Once a
//     pattern is labelled, every call site reuses the result for free.
//
//  2. Vocabulary: after seeing N distinct skeletons on a host, fire a
//     single richer "learn this site" prompt that identifies stable
//     BFF service names, position patterns ("/butik/liste/<N>/<gender>"),
//     and naming conventions. Every subsequent label call gets that
//     vocabulary as system context, so individual labels are small AND
//     consistent.
//
//  3. LLM-first labelling: the regex classifier survives only as a
//     fallback for when no provider is configured or the budget is
//     exhausted. With a provider available we send paths to the LLM
//     with rich context (titles, content-types, sibling paths) and
//     let it produce semantic labels (`{boutique_id}`, `{gender}`) and
//     a short purpose sentence.
package pathlabel

import "context"

// Label is the produced labelling for a URL pattern. It's what every
// call site in the codebase will display instead of raw "/WORD/WORD"
// shapes or cryptic regex placeholders.
type Label struct {
	// Display is the templated path with placeholders filled in,
	// e.g. "/discovery-storefrontmarketing-marketinggw-service/butik/liste/{boutique_id}/{gender}".
	// This is what the user sees in narrations, the Endpoints view,
	// findings, and exports.
	Display string `json:"display"`

	// Purpose is a single sentence describing what the endpoint is for,
	// when the LLM was confident enough to give one. Empty otherwise.
	// Shown on hover / in detail panes, never in the route line itself.
	Purpose string `json:"purpose,omitempty"`

	// Segments carries per-position metadata for "explain this URL"
	// hover features and exports. Aligned with the Display path's
	// segments left-to-right (skipping the empty leading split).
	Segments []SegmentLabel `json:"segments,omitempty"`

	// Source records how this label was produced — useful for
	// telemetry and debugging when a label looks wrong.
	Source LabelSource `json:"source"`
}

// SegmentLabel describes one path-segment position in a labelled URL.
type SegmentLabel struct {
	// Position is the zero-based segment index after splitting on "/"
	// and dropping the empty leading segment.
	Position int `json:"position"`

	// Kind is "literal" when the segment is a fixed value (and Label
	// holds that literal value), or "variable" when the segment varies
	// across observations (and Label holds the placeholder name like
	// "boutique_id" without braces).
	Kind string `json:"kind"`

	// Label holds either the literal segment value (for literals) or
	// the snake_case placeholder name (for variables, no braces).
	Label string `json:"label"`

	// Examples are up to ~5 distinct observed values for this position.
	// Useful for explain-on-hover and for the operator to spot when a
	// label looks wrong ("position 6 says {gender} but values are
	// kadin, erkek, men, women — looks mixed, investigate").
	Examples []string `json:"examples,omitempty"`

	// Reason is the LLM's terse justification for the chosen label.
	// Empty for regex-fallback labels.
	Reason string `json:"reason,omitempty"`
}

// LabelSource records the provenance of a label.
type LabelSource string

const (
	// SourceLLM means the label came from a successful LLM call (with
	// or without vocabulary hits).
	SourceLLM LabelSource = "llm"

	// SourceLLMVocab means the label came from the vocabulary cache
	// without an LLM call — the position pattern was already known.
	SourceLLMVocab LabelSource = "llm_vocab"

	// SourceSemanticRule means an unambiguous route convention such as
	// /tag/<tag>/page/<page> was labelled deterministically. No model call is
	// useful for these grammar-level positions.
	SourceSemanticRule LabelSource = "semantic_rule"

	// SourceCache means we returned a previously-computed label
	// without re-running the LLM.
	SourceCache LabelSource = "cache"

	// SourceFallback means we returned the regex-classifier result
	// because no provider was configured or the budget was exhausted.
	// Display will still be a clean template, just less specific.
	SourceFallback LabelSource = "fallback"
)

// LabelContext carries the side-channel information the resolver feeds
// to the LLM along with the path skeleton. None of these fields are
// required — the resolver works fine when they're zero — but every
// piece of context the caller can supply makes the labelling more
// accurate.
type LabelContext struct {
	// Host is the URL host the paths belong to. Used to scope the
	// vocabulary cache (one vocab per host per scan) and to include
	// in the LLM prompt for site-level reasoning.
	Host string

	// Method, when non-empty, is included in the prompt — POST endpoints
	// often have different naming conventions than GETs (action-named
	// vs resource-named).
	Method string

	// PageTitles are titles seen at any of the sample URLs. Strong
	// signal for "what is this page for" and dramatically improves
	// Purpose accuracy.
	PageTitles []string

	// ContentType is the response Content-Type if known
	// (application/json, text/html, etc.). Helps disambiguate
	// page-template clusters from API endpoints.
	ContentType string

	// Discovery is how the URL was found ("link", "form", "js-route",
	// "navigator", "seed"). Optional but useful — a form-action POST
	// labels differently than an XHR.
	Discovery string

	// Sibling is up to ~5 other paths seen on the same host. Helps the
	// LLM apply consistent naming across related endpoints in one call.
	Sibling []string
}

// Resolver is the public API. Both the crawler agent and the analyzer
// route their path-labelling through one Resolver instance per scan
// (created in agent.NewOrchestrator). Cache + vocabulary are scoped to
// the Resolver, so they're scan-scoped: a fresh scan starts with a
// clean cache and re-learns the site's vocabulary.
type Resolver interface {
	// Label produces a Label for the given paths. paths must be 1+
	// raw URL paths (e.g. "/api/v1/users/42") observed in traffic;
	// the resolver derives the corpus skeleton from them.
	//
	// The first call for a (skeleton, samples) signature blocks on the
	// LLM (typically 200-800ms on Haiku/Mini/Ollama). Subsequent calls
	// for the same signature return from cache instantly.
	//
	// A nil error is returned even when the LLM call fails — the
	// resolver always produces SOMETHING (regex fallback) so callers
	// don't need defensive code at every site. Errors are logged
	// internally for telemetry.
	Label(ctx context.Context, paths []string, lc LabelContext) Label

	// PrimeVocabulary fires the "learn this site" pass for a host.
	// Called once per host per scan by the orchestrator's primer
	// goroutine, after enough representative paths have been
	// captured. The learned Vocabulary is stored on the resolver
	// and consulted on every subsequent Label call for that host.
	//
	// Returns the learned Vocabulary plus an error from the LLM
	// call. On error the resolver continues to work with no vocab
	// for the host — labels just stay slightly less consistent.
	PrimeVocabulary(ctx context.Context, host string, samplePaths []string) (*Vocabulary, error)

	// SetVocabulary is the test/seed hook — direct vocabulary
	// injection without an LLM round-trip. Used in tests and
	// reserved for a future "remember last scan's vocab across
	// re-scans of the same host" feature.
	SetVocabulary(host string, v *Vocabulary)
}
