package pathlabel

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ozzyw/aobtd/internal/llm"
)

// stubProvider returns a fixed JSON response and counts Complete calls
// so cache-hit tests can assert "called once."
type stubProvider struct {
	response string
	calls    int64
}

func (s *stubProvider) Complete(_ context.Context, _ *llm.Request) (*llm.Response, error) {
	atomic.AddInt64(&s.calls, 1)
	return &llm.Response{Content: s.response, Usage: llm.Usage{InputTokens: 50, OutputTokens: 20}}, nil
}
func (s *stubProvider) CountTokens(t string) int { return len(t) / 4 }
func (s *stubProvider) ModelInfo() llm.ModelInfo {
	return llm.ModelInfo{Name: "stub", MaxContextTokens: 8192, MaxOutputTokens: 1024, SupportsJSON: true}
}
func (s *stubProvider) Name() string { return "stub" }

func newTestResolver(p llm.Provider) *resolver {
	return &resolver{
		provider: p,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		cache:    map[string]Label{},
		vocab:    map[string]*Vocabulary{},
		pending:  map[string]chan struct{}{},
	}
}

// TestLabel_FallbackOnNoProvider: with no provider configured the
// resolver returns the regex fallback unchanged. The Example BFF
// case stays literal in the corpus-aligned variant.
func TestLabel_FallbackOnNoProvider(t *testing.T) {
	r := newTestResolver(nil)
	const svc = "/discovery-storefrontmarketing-marketinggw-service/internal-linking-seo"
	paths := []string{
		svc + "/butik/liste/1/kadin",
		svc + "/butik/liste/47/erkek",
		svc + "/butik/liste/103/cocuk",
	}
	got := r.Label(context.Background(), paths, LabelContext{Host: "www.example.com"})
	want := svc + "/butik/liste/{id}/{seg}"
	if got.Display != want {
		t.Errorf("Display: got %q, want %q", got.Display, want)
	}
	if got.Source != SourceFallback {
		t.Errorf("Source: got %q, want fallback", got.Source)
	}
}

// TestLabel_CallsLLMForVariablePositions: with a provider available
// and variable positions present, the resolver dispatches an LLM call
// and applies the parsed labels to the Display.
func TestLabel_CallsLLMForVariablePositions(t *testing.T) {
	p := &stubProvider{response: `{
		"display": "/api/{lang}/products",
		"purpose": "localized product listing",
		"segments": [
			{"position": 0, "kind": "literal", "label": "api"},
			{"position": 1, "kind": "variable", "label": "lang", "reason": "ISO codes"},
			{"position": 2, "kind": "literal", "label": "products"}
		]
	}`}
	r := newTestResolver(p)
	got := r.Label(context.Background(), []string{
		"/api/en/products",
		"/api/tr/products",
		"/api/de/products",
	}, LabelContext{})
	if got.Display != "/api/{lang}/products" {
		t.Fatalf("Display: got %q, want %q", got.Display, "/api/{lang}/products")
	}
	if got.Purpose != "localized product listing" {
		t.Errorf("Purpose: got %q", got.Purpose)
	}
	if got.Source != SourceLLM {
		t.Errorf("Source: got %q, want llm", got.Source)
	}
	if p.calls != 1 {
		t.Errorf("calls: got %d, want 1", p.calls)
	}
}

func TestLabel_RebuildsDisplayFromSegmentsWhenModelDropsBraces(t *testing.T) {
	p := &stubProvider{response: `{
		"display": "/rest/memories/memory_id",
		"purpose": "memory detail",
		"segments": [
			{"position": 0, "kind": "literal", "label": "rest"},
			{"position": 1, "kind": "literal", "label": "memories"},
			{"position": 2, "kind": "variable", "label": "memory_id"}
		]
	}`}
	r := newTestResolver(p)
	got := r.Label(context.Background(), []string{
		"/rest/memories/1",
		"/rest/memories/-1",
		"/rest/memories/999999",
	}, LabelContext{})
	if got.Display != "/rest/memories/{memory_id}" {
		t.Fatalf("Display: got %q, want %q", got.Display, "/rest/memories/{memory_id}")
	}
}

func TestLabel_RebuildPreservesLiteralFallbackCasing(t *testing.T) {
	p := &stubProvider{response: `{
		"display": "/api/deliverys/delivery_id",
		"purpose": "delivery detail",
		"segments": [
			{"position": 0, "kind": "literal", "label": "api"},
			{"position": 1, "kind": "literal", "label": "deliverys"},
			{"position": 2, "kind": "variable", "label": "delivery_id"}
		]
	}`}
	r := newTestResolver(p)
	got := r.Label(context.Background(), []string{
		"/api/Deliverys/1",
		"/api/Deliverys/2",
		"/api/Deliverys/9999",
	}, LabelContext{})
	if got.Display != "/api/Deliverys/{delivery_id}" {
		t.Fatalf("Display: got %q, want %q", got.Display, "/api/Deliverys/{delivery_id}")
	}
}

// TestLabel_CacheHitsAcrossCallers: the same signature reused (perhaps
// from a different call site) hits the cache and does NOT spend an
// extra LLM call. This is the key cost-discipline test.
func TestLabel_CacheHitsAcrossCallers(t *testing.T) {
	p := &stubProvider{response: `{"display": "/api/{lang}/products", "segments": [
		{"position": 0, "kind": "literal", "label": "api"},
		{"position": 1, "kind": "variable", "label": "lang"},
		{"position": 2, "kind": "literal", "label": "products"}
	]}`}
	r := newTestResolver(p)
	paths := []string{"/api/en/products", "/api/tr/products"}
	r.Label(context.Background(), paths, LabelContext{})
	r.Label(context.Background(), paths, LabelContext{})
	r.Label(context.Background(), paths, LabelContext{})
	if p.calls != 1 {
		t.Fatalf("calls: got %d, want 1 (cache should absorb the rest)", p.calls)
	}
	// The third call's source should reflect cache.
	got := r.Label(context.Background(), paths, LabelContext{})
	if got.Source != SourceCache {
		t.Errorf("Source: got %q, want cache", got.Source)
	}
}

// TestLabel_AllLiteralSkipsLLM: when every position is identical
// across observations (or there's a single observation with no
// numeric/UUID/long segments), there's nothing for the LLM to label —
// we save the call.
func TestLabel_AllLiteralSkipsLLM(t *testing.T) {
	p := &stubProvider{response: `{"display": "ignored"}`}
	r := newTestResolver(p)
	paths := []string{"/login", "/login", "/login"}
	got := r.Label(context.Background(), paths, LabelContext{})
	if got.Display != "/login" {
		t.Errorf("Display: got %q, want %q", got.Display, "/login")
	}
	if p.calls != 0 {
		t.Errorf("calls: got %d, want 0 — no variable positions, no LLM needed", p.calls)
	}
}

// TestLabel_SingleObservationLabelsLiterally: one path with
// human-readable segments yields a literal label; numeric IDs become
// {id}; long opaque segments become {token} (which the LLM can later
// reclassify as literal BFF names if a follow-up observation is added
// — but not on first sight).
func TestLabel_SingleObservationLabelsLiterally(t *testing.T) {
	r := newTestResolver(nil)
	paths := []string{"/users/42/preferences/notifications"}
	got := r.Label(context.Background(), paths, LabelContext{})
	want := "/users/{id}/preferences/notifications"
	if got.Display != want {
		t.Errorf("Display: got %q, want %q", got.Display, want)
	}
}

// TestLabel_TolerantOfMalformedLLMResponse: when the LLM returns
// non-JSON, the resolver falls back gracefully and doesn't poison the
// cache with a broken label.
func TestLabel_TolerantOfMalformedLLMResponse(t *testing.T) {
	p := &stubProvider{response: "I am not JSON, sorry."}
	r := newTestResolver(p)
	got := r.Label(context.Background(), []string{
		"/api/en/products", "/api/tr/products",
	}, LabelContext{})
	// The fallback Display should survive the broken response.
	if got.Source == SourceLLM {
		t.Errorf("Source: got llm, expected fallback when LLM response is malformed")
	}
	// A second call should re-attempt rather than read a poisoned cache.
	r.Label(context.Background(), []string{
		"/api/en/products", "/api/tr/products",
	}, LabelContext{})
	if p.calls < 2 {
		t.Errorf("calls: got %d, want >=2 (retry on malformed)", p.calls)
	}
}

// TestLabel_VocabContextInPrompt: when a vocabulary is set for the
// host, the prompt includes its hints. This is exercised indirectly
// by checking that vocab presence doesn't break anything; the
// content-of-prompt check would couple to wording and is brittle.
func TestLabel_VocabSeedDoesNotBreakLabelling(t *testing.T) {
	p := &stubProvider{response: `{"display": "/butik/liste/{boutique_id}/{gender}", "segments": [
		{"position": 0, "kind": "literal", "label": "butik"},
		{"position": 1, "kind": "literal", "label": "liste"},
		{"position": 2, "kind": "variable", "label": "boutique_id"},
		{"position": 3, "kind": "variable", "label": "gender"}
	]}`}
	r := newTestResolver(p)
	r.SetVocabulary("www.example.com", &Vocabulary{
		SiteType: "e-commerce",
		PositionPatterns: []VocabPositionPattern{
			{Shape: "/butik/liste/<N>/<word>", Labels: []string{"boutique_id", "gender"}},
		},
	})
	got := r.Label(context.Background(), []string{
		"/butik/liste/1/kadin",
		"/butik/liste/47/erkek",
	}, LabelContext{Host: "www.example.com"})
	if got.Display != "/butik/liste/{boutique_id}/{gender}" {
		t.Errorf("Display: got %q", got.Display)
	}
	if got.Source != SourceLLMVocab || p.calls != 0 {
		t.Fatalf("vocabulary pattern did not bypass per-route LLM call: source=%q calls=%d", got.Source, p.calls)
	}
}

func TestLabel_SemanticTaxonomyFamiliesConsumeNoModelCalls(t *testing.T) {
	p := &stubProvider{response: `{"display":"should-not-run"}`}
	r := newTestResolver(p)
	for index, path := range []string{
		"/tag/humor/page/1/",
		"/tag/books/page/2/",
		"/author/Albert-Einstein/",
		"/author/J-K-Rowling/",
		"/catalogue/category/books/history/index.html",
		"/catalogue/category/fiction/classics/index.html",
	} {
		got := r.Label(context.Background(), []string{path}, LabelContext{Host: "content.test"})
		if got.Source != SourceSemanticRule {
			t.Fatalf("route %d source = %q, want semantic rule", index, got.Source)
		}
		if !strings.Contains(got.Display, "{") {
			t.Fatalf("route %d did not produce a compact family label: %q", index, got.Display)
		}
	}
	if p.calls != 0 {
		t.Fatalf("deterministic taxonomy/entity routes spent %d model calls", p.calls)
	}
}

func TestLabel_SemanticValueCannotBecomeNestedRouteMarker(t *testing.T) {
	p := &stubProvider{response: `{"display":"should-not-run"}`}
	r := newTestResolver(p)
	got := r.Label(context.Background(), []string{"/tag/authors/page/1/"}, LabelContext{Host: "content.test"})
	if got.Display != "/tag/{tag}/page/{page}" {
		t.Fatalf("tag value reinterpreted the route grammar: %q", got.Display)
	}
	if got.Source != SourceSemanticRule || p.calls != 0 {
		t.Fatalf("ambiguous taxonomy route spent a model call: source=%q calls=%d", got.Source, p.calls)
	}
}

// TestRegexFallback_ExampleBFFSurvives: corpus alignment keeps long
// stable BFF service names literal even at the regex-only level.
// This is the test that protected the original buildCorpusTemplate
// behaviour and we want it to survive the migration.
func TestRegexFallback_ExampleBFFSurvives(t *testing.T) {
	const svc = "/discovery-storefrontmarketing-marketinggw-service/internal-linking-seo"
	paths := []string{
		svc + "/butik/liste/1/kadin",
		svc + "/butik/liste/47/erkek",
		svc + "/butik/liste/103/cocuk",
	}
	got, _ := regexFallbackLabel(paths)
	want := svc + "/butik/liste/{id}/{seg}"
	if got.Display != want {
		t.Errorf("Display: got %q, want %q", got.Display, want)
	}
}

// TestRegexFallback_SingleReadableLongSegmentStaysLiteral: length alone must
// not turn a semantic service/route name into a token placeholder.
func TestRegexFallback_SingleReadableLongSegmentStaysLiteral(t *testing.T) {
	got, _ := regexFallbackLabel([]string{
		"/discovery-storefrontmarketing-marketinggw-service/x",
	})
	if got.Display != "/discovery-storefrontmarketing-marketinggw-service/x" {
		t.Errorf("Display: got %q", got.Display)
	}

	got, _ = regexFallbackLabel([]string{
		"/rest/admin/application-configuration",
	})
	if got.Display != "/rest/admin/application-configuration" {
		t.Errorf("Display: got %q", got.Display)
	}
}

func TestRegexFallback_SingleOpaqueTokenIsMasked(t *testing.T) {
	got, _ := regexFallbackLabel([]string{
		"/session/dGhpcy1pc19hX2xvbmdfdG9rZW4",
	})
	if got.Display != "/session/{token}" {
		t.Errorf("Display: got %q, want %q", got.Display, "/session/{token}")
	}
}
