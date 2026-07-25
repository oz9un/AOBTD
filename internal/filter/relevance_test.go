package filter

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
)

func TestComputeRelevancePrioritizesHTMLRoutesOverCacheBustedAssets(t *testing.T) {
	seen := map[string]bool{}

	htmlScore := computeRelevance(
		"GET", "/hemen", "", "{}", nil,
		200, `{"server":"cloudflare"}`, "text/html; charset=utf-8", 166315,
		"html-route", seen,
	)
	if htmlScore < 0.3 {
		t.Fatalf("HTML app route score %.2f, want >= 0.30", htmlScore)
	}

	assetScore := computeRelevance(
		"GET", "/hn.js", "yA0A6US9hEWWKqts9LqU", "{}", nil,
		200, `{"server":"nginx"}`, "text/javascript; charset=utf-8", 5217,
		"asset-route", seen,
	)
	if assetScore >= 0.3 {
		t.Fatalf("cache-busted static asset score %.2f, want < 0.30", assetScore)
	}
}

func TestQueryLooksLikeApplicationInputKeepsRealStaticAssetParams(t *testing.T) {
	if queryLooksLikeApplicationInput("/asset.js", "v=123", true) {
		t.Fatal("version query on static asset should not count as app input")
	}
	if !queryLooksLikeApplicationInput("/asset.js", "redirect=https%3A%2F%2Fexample.test", true) {
		t.Fatal("semantic query on static asset should still count as app input")
	}
	if !queryLooksLikeApplicationInput("/search", "q=milk", false) {
		t.Fatal("HTML route query should count as app input")
	}
}

func TestRelevanceScorerDoesNotRescoreCompletedRows(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "relevance.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://example.test", `{}`)
	insertDedupTraffic(t, db, scanID, "https://example.test/api/users/1", `{"id":1}`, "capture", 0)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	scorer := NewRelevanceScorer(db, logger)

	if scored, err := scorer.Run(scanID); err != nil || scored != 1 {
		t.Fatalf("first Run = (%d, %v), want (1, nil)", scored, err)
	}
	if scored, err := scorer.Run(scanID); err != nil || scored != 0 {
		t.Fatalf("second Run = (%d, %v), want (0, nil)", scored, err)
	}
}
