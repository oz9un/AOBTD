package browser

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestCrawlerRunsBoundedBatchesInBFSOrder(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	crawler := NewCrawler(nil, []string{"example.test"}, 1, 10, time.Second, "", logger)
	crawler.maxConcurrency = 3

	var mu sync.Mutex
	active := 0
	maxActive := 0
	crawler.visitPageFn = func(ctx context.Context, targetURL string) (CrawlResult, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()

		select {
		case <-ctx.Done():
			return CrawlResult{}, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}

		mu.Lock()
		active--
		mu.Unlock()

		result := CrawlResult{URL: targetURL, TemplateHash: targetURL}
		if targetURL == "https://example.test/" {
			result.Links = []string{
				"https://example.test/a",
				"https://example.test/b",
				"https://example.test/a",
				"https://example.test/c",
			}
		}
		return result, nil
	}

	results, err := crawler.Crawl(t.Context(), "https://example.test/")
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	want := []string{
		"https://example.test/",
		"https://example.test/a",
		"https://example.test/b",
		"https://example.test/c",
	}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d: %#v", len(results), len(want), results)
	}
	for i := range want {
		if results[i].URL != want[i] {
			t.Fatalf("result %d = %q, want %q", i, results[i].URL, want[i])
		}
	}
	if maxActive != 3 {
		t.Fatalf("maximum concurrent visits = %d, want 3", maxActive)
	}
}
