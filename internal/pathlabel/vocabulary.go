package pathlabel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ozzyw/aobtd/internal/llm"
)

// PrimeVocabulary fires the "learn this site" pass for a host. The
// caller supplies a representative set of paths (typically 20-40
// distinct skeletons captured early in the scan); the resolver makes
// a single richer LLM call to identify stable BFF prefixes, position
// patterns, and naming conventions, then stores the result in the
// vocabulary cache for that host.
//
// Subsequent Label() calls for the same host will see the vocabulary
// in their prompt and produce dramatically more consistent labels —
// /butik/liste/47/erkek and /butik/liste/103/cocuk both get
// {boutique_id}/{gender} because the priming pass already learned the
// position pattern.
//
// Idempotent: re-priming a host overwrites the previous vocabulary.
// Returns the learned Vocabulary plus an error from the LLM call.
// On error the resolver continues to work — vocabulary is a
// performance/quality multiplier, not a correctness requirement.
func (r *resolver) PrimeVocabulary(ctx context.Context, host string, samplePaths []string) (*Vocabulary, error) {
	if r.provider == nil {
		return nil, fmt.Errorf("no provider configured")
	}
	if r.budget != nil && r.budget.Level() == llm.BudgetExhausted {
		return nil, fmt.Errorf("budget exhausted")
	}
	if len(samplePaths) == 0 {
		return nil, fmt.Errorf("no sample paths provided")
	}

	prompt := buildVocabPrompt(host, samplePaths)
	resp, err := llm.CompleteBudgeted(ctx, r.provider, r.budget, &llm.Request{
		SystemPrompt: vocabSystemPrompt,
		Messages:     []llm.Message{{Role: "user", Content: prompt}},
		Temperature:  0.1,
		MaxTokens:    llm.StructuredOutputTokenLimit(r.provider, 800, 4096),
		JSONMode:     true,
	}, 0)
	if err != nil {
		return nil, fmt.Errorf("provider: %w", err)
	}
	v, err := parseVocabResponse(resp.Content)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.vocab[host] = v
	r.mu.Unlock()

	r.logger.Info("pathlabel: vocabulary primed",
		"host", host,
		"site_type", v.SiteType,
		"bff_prefixes", len(v.StableBFFPrefixes),
		"position_patterns", len(v.PositionPatterns),
	)
	return v, nil
}

// SetVocabulary lets callers seed a vocabulary directly (used by
// tests, and by the orchestrator if it wants to persist+reload
// vocabulary across scans of the same host in a future iteration).
func (r *resolver) SetVocabulary(host string, v *Vocabulary) {
	if host == "" || v == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vocab[host] = v
}

const vocabSystemPrompt = `You analyze URL conventions on a website to help label paths consistently.
Reply with a single JSON object only — no commentary, no markdown.
Schema:
{
  "site_type": "short description, e.g. 'e-commerce — Turkish marketplace, Next.js + Java BFF'",
  "stable_bff_prefixes": ["service-names", "that-stay-literal", "across-paths"],
  "position_patterns": [
    {"shape": "/butik/liste/<N>/<word>", "labels": ["boutique_id", "gender"]},
    {"shape": "/api/v<N>/users/<N>",     "labels": ["api_version", "user_id"]}
  ],
  "variable_types": {
    "boutique_id": "numeric, in /butik/liste/<id>/...",
    "gender":      "categorical: kadin / erkek / cocuk / bebek"
  },
  "notes": "anything else worth knowing (optional)"
}
Rules:
- A "stable BFF prefix" is a long hyphenated lowercase segment that recurs across many paths unchanged. Don't list one-off matches.
- "position_patterns" should generalize observed shapes; the placeholders <N>/<word>/<slug>/<uuid> mark variable positions. The "labels" array names them in order.
- "variable_types" describes the values you'd expect to see at each named position.
- Keep all of this short — a security operator will read it.`

func buildVocabPrompt(host string, paths []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "I'm scanning %s. Here are representative URL paths captured so far:\n\n", host)
	// Cap at 40 — beyond that the prompt gets expensive and the marginal
	// signal is low (most sites repeat their conventions in <30 paths).
	cap := 40
	if len(paths) < cap {
		cap = len(paths)
	}
	for _, p := range paths[:cap] {
		fmt.Fprintf(&b, "  %s\n", p)
	}
	b.WriteString(`
Identify the site's URL conventions: stable service-name prefixes, position patterns
("/butik/liste/<N>/<gender>" → boutique listing), variable types, and overall site
character. The result will be reused to label every path on this host consistently.`)
	return b.String()
}

func parseVocabResponse(content string) (*Vocabulary, error) {
	content = strings.TrimSpace(content)
	candidates := []string{content}
	// Some JSON-mode compatible providers still wrap the object in a fence or
	// double-escape its quotes. Try those bounded normalizations before giving
	// up on a vocabulary pass that has already consumed model time.
	if strings.HasPrefix(content, "```") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(content, "```json"))
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
		trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, "```"))
		candidates = append(candidates, trimmed)
	}
	for _, candidate := range append([]string(nil), candidates...) {
		if strings.Contains(candidate, `\"`) {
			candidates = append(candidates, strings.ReplaceAll(candidate, `\"`, `"`))
		}
	}
	for _, candidate := range append([]string(nil), candidates...) {
		trimmed := strings.TrimSpace(candidate)
		// MiniMax occasionally drops only the opening object brace while
		// preserving the schema's first key and a complete closing brace.
		// Keep this exact so arbitrary prose cannot become vocabulary.
		if strings.HasPrefix(trimmed, `"site_type"`) {
			candidates = append(candidates, "{"+trimmed)
		}
	}
	for _, candidate := range candidates {
		if v, ok := decodeVocabulary(candidate); ok {
			return v, nil
		}
	}
	return nil, fmt.Errorf("unparseable vocab response: %q", truncate(content, 200))
}

func decodeVocabulary(content string) (*Vocabulary, bool) {
	content = strings.TrimSpace(content)
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start >= 0 && end > start {
		content = content[start : end+1]
	}
	var v Vocabulary
	if err := json.Unmarshal([]byte(content), &v); err != nil {
		return nil, false
	}
	if v.SiteType == "" && len(v.PositionPatterns) == 0 && len(v.StableBFFPrefixes) == 0 {
		return nil, false
	}
	return &v, true
}
