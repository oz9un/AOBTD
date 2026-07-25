package store

import (
	"path/filepath"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

func TestTrafficProvenanceRoundTripAndPassiveDefault(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "provenance.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	entries := []*types.TrafficEntry{
		{
			Request: types.CapturedRequest{
				Method: "GET", URL: "https://example.test/api/orders/7",
				Host: "example.test", Path: "/api/orders/7", Headers: map[string]string{},
			},
			Response:     types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}},
			EndpointHash: "orders",
			SourceAgent:  "explorer", SourceActionID: 91, HypothesisID: "h-orders",
		},
		{
			Request: types.CapturedRequest{
				Method: "GET", URL: "https://example.test/",
				Host: "example.test", Path: "/", Headers: map[string]string{},
			},
			Response:     types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}},
			EndpointHash: "root",
		},
	}
	for _, entry := range entries {
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := db.Conn().Query(`
		SELECT source_agent, source_action_id, hypothesis_id
		FROM traffic WHERE scan_id = ? ORDER BY id`, scanID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type persistedProvenance struct {
		agent      string
		actionID   int64
		hypothesis string
	}
	var got []persistedProvenance
	for rows.Next() {
		var item persistedProvenance
		if err := rows.Scan(&item.agent, &item.actionID, &item.hypothesis); err != nil {
			t.Fatal(err)
		}
		got = append(got, item)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("traffic rows = %d, want 2", len(got))
	}
	if got[0].agent != "explorer" || got[0].actionID != 91 || got[0].hypothesis != "h-orders" {
		t.Fatalf("attributed row = %+v", got[0])
	}
	if got[1].agent != "capture" || got[1].actionID != 0 || got[1].hypothesis != "" {
		t.Fatalf("passive row = %+v", got[1])
	}
}
