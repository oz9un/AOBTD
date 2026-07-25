package agent

import (
	"testing"

	"github.com/ozzyw/aobtd/internal/browser"
)

func TestSemanticSaturationSharesCrawlerEvidenceWithoutCountingErrors(t *testing.T) {
	state := NewSemanticSaturationState()
	state.Observe("https://quotes.test/tag/humor/page/1/?utm=x", "", "tag-template", "crawler", 200)
	state.Observe("https://quotes.test/tag/change/page/1/?utm=y", "", "tag-template", "crawler", 200)
	state.Observe("https://quotes.test/tag/books/page/1/", "", "tag-template", "crawler", 200)
	state.Observe("https://quotes.test/tag/error/page/1/", "", "error-template", "crawler", 500)

	snapshot := state.Snapshot("taxonomy")
	if snapshot.Routes != 3 || snapshot.ResponseShapes != 1 || len(snapshot.Sources) != 1 || snapshot.Sources[0] != "crawler" {
		t.Fatalf("shared saturation snapshot = %+v", snapshot)
	}
	if !state.SuppressibleTaxonomy("https://quotes.test/tag/life/page/1/", "") {
		t.Fatal("three successful crawler representatives did not saturate Navigator taxonomy inventory")
	}
}

func TestSemanticSaturationPreservesInterestingAndNovelErrorRoutes(t *testing.T) {
	state := NewSemanticSaturationState()
	for _, route := range []string{"a", "b", "c"} {
		state.Observe("https://app.test/category/"+route, "", "catalog", "crawler", 200)
	}
	if state.SuppressibleTaxonomy("https://app.test/category/login", "") {
		t.Fatal("security-interesting login route was hidden by taxonomy saturation")
	}
	if state.SuppressibleTaxonomy("https://app.test/category/admin", "") {
		t.Fatal("security-interesting admin route was hidden by taxonomy saturation")
	}
	state.Observe("https://app.test/category/failure", "", "error", "crawler", 503)
	if got := state.Snapshot("taxonomy").Routes; got != 3 {
		t.Fatalf("error route affected successful saturation count: %d", got)
	}
}

func TestSemanticSaturationDeduplicatesRouteValuesAndHidesQueryValues(t *testing.T) {
	state := NewSemanticSaturationState()
	state.Observe("https://app.test/tag/a?page=1&utm=secret", "", "one", "navigator", 0)
	state.Observe("https://app.test/tag/a?page=2&utm=other", "", "one", "navigator", 0)
	snapshot := state.Snapshot("taxonomy")
	if snapshot.Routes != 1 || snapshot.ResponseShapes != 1 {
		t.Fatalf("same route/query shape counted twice: %+v", snapshot)
	}
}

func TestSemanticSaturationKeepsTaxonomyValuesInOneFamily(t *testing.T) {
	state := NewSemanticSaturationState()
	for _, raw := range []string{
		"https://content.test/tag/love/page/1/",
		"https://content.test/tag/books/page/1/",
		"https://content.test/tag/authors/page/1/",
	} {
		state.Observe(raw, "", "listing-shell", "crawler", 200)
	}
	if !state.SuppressibleTaxonomy("https://content.test/tag/history/page/1/", "History") {
		t.Fatal("loaded taxonomy labels split one route family or bypassed saturation")
	}
}

func TestSemanticSaturationRecognizesAuthorEntityRoutes(t *testing.T) {
	state := NewSemanticSaturationState()
	state.Observe("https://content.test/author/Ada-Lovelace/", "", "bio-shell-a", "crawler", 200)
	state.Observe("https://content.test/author/Grace-Hopper/", "", "bio-shell-b", "navigator", 0)
	if !state.Saturated("entity") {
		t.Fatal("author detail response shapes did not saturate the shared entity family")
	}
	if browser.IsInterestingPath("https://content.test/author/Grace-Hopper/") {
		t.Fatal("author entity route was still mistaken for authentication")
	}
}
