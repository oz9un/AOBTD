package browser

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestAdaptiveConvergenceRequiresWarmupAndConsecutiveStalePages(t *testing.T) {
	crawler := NewCrawler(nil, []string{"example.test"}, 2, 0, time.Second, "",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	crawler.EnableAdaptiveConvergence(0, 3, 2)
	result := CrawlResult{
		URL:          "https://example.test/catalog/1",
		TemplateHash: "catalog-template",
		Links:        []string{"https://example.test/account"},
		Forms:        []FormInfo{{Method: "GET", Action: "/search"}},
	}

	for i := 0; i < 2; i++ {
		crawler.results = append(crawler.results, result)
		if crawler.observeAdaptiveNovelty(result, "/catalog/INT") {
			t.Fatalf("adaptive crawl converged before warmup at page %d", i+1)
		}
	}
	crawler.results = append(crawler.results, result)
	if !crawler.observeAdaptiveNovelty(result, "/catalog/INT") {
		t.Fatal("adaptive crawl did not converge after its warmup and stale-page window")
	}
	if reason := crawler.AdaptiveStopReason(); !strings.Contains(reason, "last 2 pages") {
		t.Fatalf("stop reason = %q", reason)
	}
}

func TestAdaptiveConvergenceResetsWhenMaterialSurfaceChanges(t *testing.T) {
	crawler := NewCrawler(nil, []string{"example.test"}, 2, 0, time.Second, "",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	crawler.EnableAdaptiveConvergence(0, 3, 2)
	base := CrawlResult{TemplateHash: "catalog", Forms: []FormInfo{{Method: "GET", Action: "/search"}}}
	for i := 0; i < 2; i++ {
		crawler.results = append(crawler.results, base)
		crawler.observeAdaptiveNovelty(base, "/catalog/INT")
	}
	changed := CrawlResult{TemplateHash: "account", Forms: []FormInfo{{Method: "POST", Action: "/account"}}}
	crawler.results = append(crawler.results, changed)
	if crawler.observeAdaptiveNovelty(changed, "/account") {
		t.Fatal("new template/form/shape did not reset adaptive convergence")
	}
	if crawler.adaptiveStalePages != 0 {
		t.Fatalf("stale pages = %d, want reset to zero", crawler.adaptiveStalePages)
	}
}
