package agent

import (
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
)

func TestExplorerTrafficCarriesFollowUpProvenance(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "explorer-provenance.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	explorer := &ExplorerAgent{
		db: db, scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	explorer.storeAsTraffic(
		"https://example.test/api/orders/7", http.MethodGet,
		&http.Response{StatusCode: http.StatusOK, Header: make(http.Header)},
		[]byte(`{"id":7}`), map[string]string{}, nil, 73, "h-order-owner",
	)

	var sourceAgent, hypothesisID, endpointHash string
	var sourceActionID int64
	if err := db.Conn().QueryRow(`
		SELECT source_agent, source_action_id, hypothesis_id, endpoint_hash
		FROM traffic WHERE scan_id = ?`, scanID,
	).Scan(&sourceAgent, &sourceActionID, &hypothesisID, &endpointHash); err != nil {
		t.Fatal(err)
	}
	if sourceAgent != "explorer" || sourceActionID != 73 || hypothesisID != "h-order-owner" {
		t.Fatalf("provenance = agent=%q action=%d hypothesis=%q",
			sourceAgent, sourceActionID, hypothesisID)
	}
	if endpointHash == "" {
		t.Fatal("explorer traffic has no endpoint hash")
	}
}
