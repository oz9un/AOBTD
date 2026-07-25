package ui

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
)

func TestSearchUsesEndpointSchemaAndReturnsMostRecentDuplicate(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "search.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanA, _ := db.CreateScan("https://old.example.test", `{}`)
	scanB, _ := db.CreateScan("https://new.example.test", `{}`)
	for _, scanID := range []int64{scanA, scanB} {
		if _, err := db.Conn().Exec(`
			INSERT INTO endpoints(id, scan_id, method, url_pattern)
			VALUES ('admin-endpoint', ?, 'GET', '/admin/users')`, scanID); err != nil {
			t.Fatalf("insert endpoint for scan %d: %v", scanID, err)
		}
	}

	server := NewServer(db, t.TempDir(), "127.0.0.1:0", nil)
	req := httptest.NewRequest("GET", "/api/search?q=admin", nil)
	res := httptest.NewRecorder()
	server.handleSearch(res, req)

	if res.Code != 200 {
		t.Fatalf("search status = %d, body=%s", res.Code, res.Body.String())
	}
	var payload struct {
		Endpoints []struct {
			ScanID     int64  `json:"scan_id"`
			EndpointID string `json:"endpoint_id"`
			Method     string `json:"method"`
			URL        string `json:"url"`
			Target     string `json:"target"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode search response: %v", err)
	}
	if len(payload.Endpoints) != 1 {
		t.Fatalf("endpoint results = %+v, want one deduplicated result", payload.Endpoints)
	}
	got := payload.Endpoints[0]
	if got.ScanID != scanB || got.EndpointID != "admin-endpoint" || got.Method != "GET" || got.URL != "/admin/users" || got.Target != "https://new.example.test" {
		t.Fatalf("unexpected endpoint result: %+v", got)
	}
}
