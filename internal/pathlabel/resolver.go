package pathlabel

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"

	"github.com/ozzyw/aobtd/internal/llm"
)

// resolver is the concrete Resolver. Constructed with NewResolver and
// shared across the crawler agent + analyzer agent for one scan, so
// they hit the same cache and the same vocabulary.
type resolver struct {
	provider llm.Provider
	budget   *llm.Budget
	logger   *slog.Logger

	// mu guards both cache and vocab. The crawler and analyzer can
	// call Label concurrently (they run in separate goroutines), so
	// mutual exclusion is required around both maps.
	mu    sync.RWMutex
	cache map[string]Label
	vocab map[string]*Vocabulary // host -> vocabulary

	// pending tracks signatures that have an LLM call in flight, so
	// concurrent callers for the same pattern don't all dispatch
	// duplicate LLM requests. Each pending entry is a closed-when-done
	// channel; latecomers wait on it then read from cache.
	pending map[string]chan struct{}
}

// Vocabulary is the per-host knowledge the priming pass produces. See
// vocabulary.go for the priming logic; this struct is populated there
// and consulted on every Label call so individual labels stay
// consistent across the scan.
type Vocabulary struct {
	SiteType          string                 `json:"site_type"`
	StableBFFPrefixes []string               `json:"stable_bff_prefixes"`
	PositionPatterns  []VocabPositionPattern `json:"position_patterns"`
	VariableTypes     map[string]string      `json:"variable_types"`
	Notes             string                 `json:"notes,omitempty"`
}

// VocabPositionPattern is one learned skeleton-with-labels — when a
// new path matches this shape, the labels at the variable positions
// can be reused without an LLM round-trip.
type VocabPositionPattern struct {
	Shape  string   `json:"shape"`  // e.g. "/butik/liste/<N>/<gender>"
	Labels []string `json:"labels"` // labels for each <…> position, left to right
}

// NewResolver constructs a Resolver. provider may be nil — in that
// case Label always returns SourceFallback labels (the regex result).
// budget may also be nil (used by tests). The logger is required
// (use slog.New(slog.NewTextHandler(io.Discard, nil)) in tests).
func NewResolver(provider llm.Provider, budget *llm.Budget, logger *slog.Logger) Resolver {
	return &resolver{
		provider: provider,
		budget:   budget,
		logger:   logger,
		cache:    map[string]Label{},
		vocab:    map[string]*Vocabulary{},
		pending:  map[string]chan struct{}{},
	}
}

// Label is the public entry point. See Resolver interface for contract.
func (r *resolver) Label(ctx context.Context, paths []string, lc LabelContext) Label {
	if len(paths) == 0 {
		return Label{Source: SourceFallback}
	}
	// Sanitize: drop empty paths and strip any URL prefix the caller
	// may have included (we want just the path component).
	cleaned := normalizePaths(paths)
	if len(cleaned) == 0 {
		return Label{Source: SourceFallback}
	}

	// Always start from the regex fallback. It's free, deterministic,
	// and gives us:
	//   - a baseline Label to return immediately on any failure path,
	//   - the per-position sample arrays the LLM needs as input.
	fallback, varSamples := regexFallbackLabel(cleaned)

	// Cache lookup. Same signature → same label, regardless of which
	// call site asked. The signature includes both the skeleton and
	// the sorted distinct samples so we don't conflate clusters that
	// happen to share a regex skeleton but have different value sets.
	sig := signatureKey(fallback.Display, varSamples)
	if cached, ok := r.cacheGet(sig); ok {
		// Mark the source as cache so telemetry can tell hits apart
		// from fresh LLM calls; the actual content is unchanged.
		cached.Source = SourceCache
		return cached
	}
	if semantic, ok := semanticRouteFamilyLabel(cleaned); ok {
		r.cacheSet(sig, semantic)
		return semantic
	}
	if learned, ok := labelFromVocabulary(cleaned, r.vocabFor(lc.Host)); ok {
		r.cacheSet(sig, learned)
		return learned
	}

	// No provider, no budget headroom, or only literal positions to
	// label → return the fallback as-is. The fallback Label is still
	// useful: stable segments stay literal, numeric/UUID positions get
	// {id}, only ambiguous positions show {seg}.
	if r.provider == nil {
		return fallback
	}
	if r.budget != nil && r.budget.Level() == llm.BudgetExhausted {
		r.logger.Debug("pathlabel: budget exhausted, using fallback", "skeleton", fallback.Display)
		return fallback
	}
	if !needsLLM(fallback) {
		// Nothing variable — every position is literal. Skip the LLM.
		fallback.Source = SourceLLMVocab
		r.cacheSet(sig, fallback)
		return fallback
	}

	// In-flight de-dup: if another goroutine is already labelling the
	// same signature, wait for it instead of firing a parallel call.
	if waitCh, racing := r.acquirePending(sig); racing {
		select {
		case <-waitCh:
		case <-ctx.Done():
			return fallback
		}
		if cached, ok := r.cacheGet(sig); ok {
			cached.Source = SourceCache
			return cached
		}
		// Pending finished but produced no cache entry (LLM error).
		return fallback
	}
	defer r.releasePending(sig)

	labeled, err := r.callLLM(ctx, fallback, varSamples, lc)
	if err != nil {
		r.logger.Warn("pathlabel: LLM call failed, using fallback",
			"skeleton", fallback.Display, "error", err)
		return fallback
	}
	r.cacheSet(sig, labeled)
	return labeled
}

// needsLLM returns true when the fallback label has at least one
// variable position. If everything is literal, the LLM has nothing to
// improve and we save the call.
func needsLLM(l Label) bool {
	for _, s := range l.Segments {
		if s.Kind == "variable" {
			return true
		}
	}
	return false
}

// signatureKey builds a stable cache key from the fallback skeleton
// plus the sorted samples per variable position. Sorting makes the
// key resilient to observation order across call sites. The leading
// skeleton anchors on shape so two clusters with the same samples
// but different skeletons don't collide.
func signatureKey(skeleton string, varSamples [][]string) string {
	if len(varSamples) == 0 {
		return skeleton
	}
	parts := make([]string, 0, 1+len(varSamples))
	parts = append(parts, skeleton)
	for _, s := range varSamples {
		// distinctValues() in the fallback already sorts, but defend
		// against callers that bypass it.
		joined := strings.Join(s, "|")
		parts = append(parts, joined)
	}
	return strings.Join(parts, "\x00")
}

// normalizePaths strips host/scheme prefixes if present and drops
// empty entries. The resolver works in path-space.
func normalizePaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		// If a full URL was passed in, take just the path. Tolerates
		// callers that didn't pre-parse.
		if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
			if u, err := url.Parse(p); err == nil {
				p = u.Path
			}
		}
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// cacheGet / cacheSet / acquirePending / releasePending are the small
// concurrency primitives. Public Label() is the only call site for
// these so the locking discipline is centralised.
func (r *resolver) cacheGet(sig string) (Label, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	l, ok := r.cache[sig]
	return l, ok
}

func (r *resolver) cacheSet(sig string, l Label) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[sig] = l
}

// acquirePending atomically reserves the signature for an LLM call.
// Returns (nil, false) when this caller now owns the slot and must
// fire the LLM; returns (waitCh, true) when another caller is already
// in flight and this one should wait on the channel.
func (r *resolver) acquirePending(sig string) (chan struct{}, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ch, ok := r.pending[sig]; ok {
		return ch, true
	}
	ch := make(chan struct{})
	r.pending[sig] = ch
	return ch, false
}

func (r *resolver) releasePending(sig string) {
	r.mu.Lock()
	ch, ok := r.pending[sig]
	if ok {
		delete(r.pending, sig)
	}
	r.mu.Unlock()
	if ok {
		close(ch)
	}
}

// callLLM is the prompt + response-parsing layer. Builds the user
// prompt from the fallback skeleton + samples + LabelContext, calls
// the provider, parses the JSON response into a Label.
//
// The system prompt is short and pins JSON output; the user prompt
// is where the per-call context goes.
func (r *resolver) callLLM(
	ctx context.Context,
	fallback Label,
	varSamples [][]string,
	lc LabelContext,
) (Label, error) {
	userPrompt := buildLabelPrompt(fallback, varSamples, lc, r.vocabFor(lc.Host))

	resp, err := llm.CompleteBudgeted(ctx, r.provider, r.budget, &llm.Request{
		SystemPrompt: labelSystemPrompt,
		Messages:     []llm.Message{{Role: "user", Content: userPrompt}},
		Temperature:  0.1,
		MaxTokens:    400,
		JSONMode:     true,
	}, 0)
	if err != nil {
		return Label{}, fmt.Errorf("provider: %w", err)
	}
	parsed, err := parseLabelResponse(resp.Content)
	if err != nil {
		return Label{}, err
	}
	return mergeLabels(fallback, parsed), nil
}

// vocabFor returns the host's learned vocabulary if any, or nil.
// Locking is local; callers don't see the lock.
func (r *resolver) vocabFor(host string) *Vocabulary {
	if host == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.vocab[host]
}

// labelSystemPrompt pins JSON output. The user prompt carries all
// per-call detail (vocab, samples, context).
const labelSystemPrompt = `You label URL path segments for a security testing tool.
You answer with a single JSON object only — no commentary, no markdown.
Schema:
{
  "display": "/literal/and/{snake_case}/template",
  "purpose": "one short sentence (optional)",
  "segments": [
    {"position": 0, "kind": "literal" | "variable", "label": "literal-value or snake_case_name", "reason": "short justification"}
  ]
}
Rules:
- "literal" means the segment is the same across every observation; "label" is the literal value.
- "variable" means the segment varies; "label" is a snake_case placeholder name (no braces).
- Prefer specific labels (boutique_id, lang, country_code, slug) over generic ones (id, seg).
- A long hyphenated lowercase segment that's stable across observations is almost always a service name (BFF) or routing module — keep it literal.
- A path segment that's clearly a numeric or UUID identifier in a known parent ("users/<id>") should use the parent's name (user_id, not id).`

// parseLabelResponse pulls the labelled output from the LLM's reply.
// Tolerates JSON-mode wrapping ({"label": {...}}), bare JSON objects,
// and stray text by extracting the first {...} block.
func parseLabelResponse(content string) (Label, error) {
	content = strings.TrimSpace(content)
	var l Label
	if err := json.Unmarshal([]byte(content), &l); err == nil && l.Display != "" {
		l.Source = SourceLLM
		return l, nil
	}
	// Some providers wrap responses; try a couple of common shapes.
	var wrapped struct {
		Label  *Label `json:"label"`
		Result *Label `json:"result"`
	}
	if err := json.Unmarshal([]byte(content), &wrapped); err == nil {
		if wrapped.Label != nil && wrapped.Label.Display != "" {
			wrapped.Label.Source = SourceLLM
			return *wrapped.Label, nil
		}
		if wrapped.Result != nil && wrapped.Result.Display != "" {
			wrapped.Result.Source = SourceLLM
			return *wrapped.Result, nil
		}
	}
	// Last-ditch: extract the first {...} block.
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start >= 0 && end > start {
		var l2 Label
		if err := json.Unmarshal([]byte(content[start:end+1]), &l2); err == nil && l2.Display != "" {
			l2.Source = SourceLLM
			return l2, nil
		}
	}
	return Label{}, fmt.Errorf("unparseable LLM response: %q", truncate(content, 200))
}

// mergeLabels reconciles the LLM-produced label with the fallback's
// known examples. The LLM doesn't know the full sample list — we feed
// it a capped-at-5 view — so we keep the fallback's per-position
// Examples in the final SegmentLabel. The LLM owns Display, Purpose,
// per-position Kind/Label/Reason; we own Examples and overall ordering.
func mergeLabels(fallback, parsed Label) Label {
	out := Label{
		Display:  parsed.Display,
		Purpose:  parsed.Purpose,
		Segments: make([]SegmentLabel, 0, len(parsed.Segments)),
		Source:   SourceLLM,
	}
	// Build a position → fallback-segment lookup for O(1) example reuse.
	fb := map[int]SegmentLabel{}
	for _, s := range fallback.Segments {
		fb[s.Position] = s
	}
	for _, ps := range parsed.Segments {
		merged := ps
		if fbs, ok := fb[ps.Position]; ok {
			if len(merged.Examples) == 0 {
				merged.Examples = fbs.Examples
			}
		}
		out.Segments = append(out.Segments, merged)
	}
	// If the parsed response didn't carry segments (some models skip
	// them), inherit the fallback's.
	if len(out.Segments) == 0 {
		out.Segments = fallback.Segments
	}
	if rebuilt := displayFromSegments(fallback.Display, out.Segments); rebuilt != "" {
		out.Display = rebuilt
	}
	return out
}

func displayFromSegments(fallbackDisplay string, segments []SegmentLabel) string {
	if fallbackDisplay == "" || len(segments) == 0 {
		return ""
	}
	parts := strings.Split(fallbackDisplay, "/")
	offset := 0
	if strings.HasPrefix(fallbackDisplay, "/") {
		offset = 1
	}
	for _, segment := range segments {
		idx := segment.Position + offset
		if idx < 0 || idx >= len(parts) {
			continue
		}
		label := strings.TrimSpace(segment.Label)
		if label == "" {
			continue
		}
		label = strings.TrimPrefix(strings.TrimSuffix(label, "}"), "{")
		switch strings.ToLower(strings.TrimSpace(segment.Kind)) {
		case "variable":
			parts[idx] = "{" + label + "}"
		}
	}
	return strings.Join(parts, "/")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
