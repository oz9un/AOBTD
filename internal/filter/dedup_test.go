package filter

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func insertDedupTraffic(t *testing.T, db *store.DB, scanID int64, rawURL, body, source string, actionID int64) int64 {
	t.Helper()
	entry := &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: "GET", URL: rawURL, Headers: map[string]string{}, Timestamp: time.Now(),
		},
		Response: types.CapturedResponse{
			StatusCode: 200, Headers: map[string]string{"Content-Type": "application/json"},
			Body: []byte(body), ContentType: "application/json", Size: int64(len(body)),
		},
		EndpointHash:   observation.EndpointHash("GET", rawURL),
		SourceAgent:    source,
		SourceActionID: actionID,
		Timestamp:      time.Now(),
	}
	id, err := db.InsertTraffic(scanID, entry)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDeduplicatorKeepsContentDistinctAndActiveEvidence(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "dedup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://example.test", `{}`)

	insertDedupTraffic(t, db, scanID, "https://example.test/users/1", `{"id":1}`, "capture", 0)
	insertDedupTraffic(t, db, scanID, "https://example.test/users/2", `{"id":2}`, "capture", 0)
	passiveDuplicate := insertDedupTraffic(t, db, scanID, "https://example.test/users/1", `{"id":1}`, "capture", 0)
	activeDuplicate := insertDedupTraffic(t, db, scanID, "https://example.test/users/1", `{"id":1}`, "explorer", 42)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	marked, err := NewDeduplicator(db, logger).Run(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if marked != 1 {
		t.Fatalf("marked = %d, want 1", marked)
	}

	for id, want := range map[int64]bool{passiveDuplicate: true, activeDuplicate: false} {
		var duplicate bool
		if err := db.Conn().QueryRow(`SELECT is_duplicate FROM traffic WHERE id = ?`, id).Scan(&duplicate); err != nil {
			t.Fatal(err)
		}
		if duplicate != want {
			t.Errorf("traffic %d duplicate=%v want=%v", id, duplicate, want)
		}
	}
}
