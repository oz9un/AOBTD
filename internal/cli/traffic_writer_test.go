package cli

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestTrafficCaptureWriterFlushesOnClose(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "writer.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://example.test", `{}`)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := newTrafficCaptureWriter(db, scanID, logger)

	for i := 0; i < 137; i++ {
		w.Enqueue(&types.TrafficEntry{
			Request: types.CapturedRequest{
				Method: "GET", URL: "https://example.test/page", Headers: map[string]string{}, Timestamp: time.Now(),
			},
			Response: types.CapturedResponse{
				StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html", Body: []byte("ok"), Size: 2,
			},
			Timestamp: time.Now(),
		})
	}
	w.Close()

	var count int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM traffic WHERE scan_id = ?`, scanID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 137 {
		t.Fatalf("traffic rows = %d, want 137", count)
	}
}
