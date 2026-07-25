package browser

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestUnknownFingerprintDoesNotSaturateShape(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	crawler := NewCrawler(nil, []string{"example.test"}, 2, 20, time.Second, "", logger)
	fired := 0
	crawler.OnSaturation(func(SaturationEvent) { fired++ })

	for i := 0; i < 20; i++ {
		crawler.recordShapeVisit("/products/INT", "https://example.test/products/1", "unknown")
		crawler.recordShapeVisit("/products/INT", "https://example.test/products/1", "")
	}
	if fired != 0 || crawler.shapeSaturated["/products/INT"] {
		t.Fatalf("unknown fingerprints saturated shape: fired=%d saturated=%v", fired, crawler.shapeSaturated["/products/INT"])
	}
	if len(crawler.shapeVisits["/products/INT"]) != 0 {
		t.Fatalf("unknown fingerprints were recorded: %+v", crawler.shapeVisits["/products/INT"])
	}
}
