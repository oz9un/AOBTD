package extract

import (
	"fmt"
	"strings"
	"testing"
)

func TestResponseSemanticSketchClassifiesOpaqueCapturedPages(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		title     string
		headings  []string
		pre       int
		fragments int
		want      string
	}{
		{
			name: "opaque full text extension", path: "/fts3.html",
			title: "SQLite FTS3 and FTS4 Extensions", headings: []string{"Introduction to FTS3 and FTS4"},
			pre: 4, fragments: 8, want: "developer",
		},
		{
			name: "opaque c interface reference", path: "/c3ref/config.html",
			title:    "Database Connection Configuration Options",
			headings: []string{"C-language Interface Specification for SQLite"},
			pre:      2, fragments: 12, want: "developer",
		},
		{
			name: "opaque support filename", path: "/prosupport.html",
			title: "SQLite Professional Support", want: "support",
		},
		{
			name: "neutral homepage remains unknown", path: "/index.html",
			title: "SQLite Home Page", want: "",
		},
		{
			name: "security primary route", path: "/security.html",
			title: "Defense Against The Dark Arts", want: "security",
		},
		{
			name: "localized download primary route", path: "/en-US/download.html",
			title: "Get SQLite", want: "distribution",
		},
		{
			name: "nested security keeps account route", path: "/account/security",
			title: "Security", want: "account",
		},
		{
			name: "conflicting route and title remains ambiguous", path: "/news.html",
			title: "API Reference", want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := semanticSketchBundle(tt.path, tt.title, tt.headings, tt.pre, tt.fragments)
			got := bundle.SemanticSketch()
			if got.Family != tt.want {
				t.Fatalf("SemanticSketch() = %+v, want family %q", got, tt.want)
			}
			if tt.want != "" && (got.Confidence < 70 || len(got.Signals) == 0) {
				t.Fatalf("classified sketch lacks bounded evidence: %+v", got)
			}
		})
	}
}

func TestResponseSemanticSketchIgnoresSharedNavigationLabels(t *testing.T) {
	bundle := semanticSketchBundle("/index.html", "Example Home", nil, 0, 0)
	bundle.HTMLExtraction.Links = []ExtractedLink{
		{Href: "https://example.test/docs", Text: "Documentation", SameOrigin: true},
		{Href: "https://example.test/news", Text: "News", SameOrigin: true},
		{Href: "https://example.test/support", Text: "Support", SameOrigin: true},
	}
	if got := bundle.SemanticSketch(); got.Family != "" {
		t.Fatalf("shared navigation classified the page: %+v", got)
	}
}

func TestResponseSemanticSketchStructureCannotClassifyWithoutLexicalSignal(t *testing.T) {
	bundle := semanticSketchBundle("/opaque.html", "Example", []string{"Overview", "Details", "Examples"}, 12, 20)
	if got := bundle.SemanticSketch(); got.Family != "" {
		t.Fatalf("structure alone became a semantic claim: %+v", got)
	}
}

func TestSemanticSketchIsBoundedAndDeterministic(t *testing.T) {
	headings := make([]string, 40)
	for i := range headings {
		headings[i] = fmt.Sprintf("API Reference Section %02d %s", i, strings.Repeat("x", 240))
	}
	bundle := semanticSketchBundle("/opaque.html", "API Reference", headings, 200, 100)
	left := bundle.SemanticSketch()
	right := bundle.SemanticSketch()
	if left.Family != "developer" || fmt.Sprintf("%+v", left) != fmt.Sprintf("%+v", right) {
		t.Fatalf("sketch is not deterministic: left=%+v right=%+v", left, right)
	}
	if len(left.Signals) > 6 || left.Confidence > 95 {
		t.Fatalf("sketch exceeded bounds: %+v", left)
	}
}

func semanticSketchBundle(path, title string, headings []string, pre, fragments int) *EndpointBundle {
	pageURL := "https://example.test" + path
	links := make([]ExtractedLink, 0, fragments)
	for i := 0; i < fragments; i++ {
		links = append(links, ExtractedLink{
			Href: fmt.Sprintf("%s#section-%d", pageURL, i), Text: fmt.Sprintf("Section %d", i), SameOrigin: true,
		})
	}
	return &EndpointBundle{
		Method: "GET", URLPattern: path, SampleURL: pageURL,
		HTMLExtraction: &HTMLExtraction{
			Title: title, Headings: headings, PreformattedBlocks: pre, Links: links,
		},
	}
}
