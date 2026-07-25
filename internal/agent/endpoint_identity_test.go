package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestJSRouteIdentityIncludesSourceOrigin(t *testing.T) {
	appRoute := DiscoveredRoute{
		Method: "GET",
		Path:   "/api/users",
		Source: "https://app.example.test/assets/app.js",
	}
	adminRoute := appRoute
	adminRoute.Source = "https://admin.example.test/assets/app.js"

	app := endpointFromRoute(appRoute)
	admin := endpointFromRoute(adminRoute)
	if app.ID == admin.ID {
		t.Fatal("same JS route on different source origins collapsed to one endpoint")
	}
	if app.URLPattern != "https://app.example.test/api/users" {
		t.Fatalf("resolved app route = %q", app.URLPattern)
	}
	if admin.URLPattern != "https://admin.example.test/api/users" {
		t.Fatalf("resolved admin route = %q", admin.URLPattern)
	}
}

func TestRunReanalyzeBridgesProfileIDToScanLocalTrafficHash(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "reanalyze.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanA, _ := db.CreateScan("https://a.example.test", `{}`)
	scanB, _ := db.CreateScan("https://b.example.test", `{}`)
	const profileID = "GET /orders/{id}"
	urlA := "https://a.example.test/orders/41"
	urlB := "https://b.example.test/orders/99"
	insertReanalyzeTraffic(t, db, scanA, urlA)
	insertReanalyzeTraffic(t, db, scanB, urlB)
	if err := db.UpsertProfile(scanA, &types.PageProfile{ID: profileID, URL: urlA, Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanB, &types.PageProfile{ID: profileID, URL: urlB, Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`UPDATE traffic SET is_ai_analyzed = TRUE WHERE scan_id IN (?, ?)`, scanA, scanB); err != nil {
		t.Fatal(err)
	}

	if _, err := db.InsertFollowUp(scanA, store.FollowUp{
		Action: "reanalyze",
		Params: map[string]any{"endpoint_id": profileID},
	}); err != nil {
		t.Fatal(err)
	}
	tasks, err := db.PopPendingFollowUps(scanA, 1)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("claim reanalyze task: tasks=%v err=%v", tasks, err)
	}

	explorer := &ExplorerAgent{db: db, scanID: scanA}
	explorer.runReanalyze(context.Background(), tasks[0])

	var analyzedA, analyzedB bool
	if err := db.Conn().QueryRow(`SELECT is_ai_analyzed FROM traffic WHERE scan_id = ?`, scanA).Scan(&analyzedA); err != nil {
		t.Fatal(err)
	}
	if err := db.Conn().QueryRow(`SELECT is_ai_analyzed FROM traffic WHERE scan_id = ?`, scanB).Scan(&analyzedB); err != nil {
		t.Fatal(err)
	}
	if analyzedA {
		t.Fatal("profile-ID reanalyze did not invalidate scan A traffic")
	}
	if !analyzedB {
		t.Fatal("profile-ID reanalyze crossed the scan boundary into scan B")
	}

	var status, result string
	if err := db.Conn().QueryRow(`SELECT status, result FROM follow_ups WHERE id = ?`, tasks[0].ID).Scan(&status, &result); err != nil {
		t.Fatal(err)
	}
	if status != store.FollowUpDone || !strings.Contains(result, "1 observation") {
		t.Fatalf("reanalyze completion = status %q result %q", status, result)
	}
}

func insertReanalyzeTraffic(t *testing.T, db *store.DB, scanID int64, rawURL string) {
	t.Helper()
	entry := &types.TrafficEntry{
		Request: types.CapturedRequest{Method: "GET", URL: rawURL},
		Response: types.CapturedResponse{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(`{"ok":true}`),
		},
	}
	if _, err := db.InsertTraffic(scanID, entry); err != nil {
		t.Fatal(err)
	}
}

func TestSyntheticProfilesUpsertIndependentlyPerScan(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "synthetic-profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanA, _ := db.CreateScan("https://a.example.test", `{}`)
	scanB, _ := db.CreateScan("https://b.example.test", `{}`)
	jsA := &JSAnalyzer{db: db, scanID: scanA}
	jsB := &JSAnalyzer{db: db, scanID: scanB}

	jsA.storeRoutes([]DiscoveredRoute{{Method: "GET", Path: "/api/a"}})
	jsB.storeRoutes([]DiscoveredRoute{{Method: "POST", Path: "/api/b"}})
	// Updating scan A must hit only (scanA, js_discovered_routes), not scan B.
	jsA.storeRoutes([]DiscoveredRoute{
		{Method: "GET", Path: "/api/a"},
		{Method: "DELETE", Path: "/api/a/{id}"},
	})

	assertProfileIssueContains(t, db, scanA, "js_discovered_routes", "DELETE")
	assertProfileIssueContains(t, db, scanB, "js_discovered_routes", "POST")
	var jsCount int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM page_profiles WHERE id = 'js_discovered_routes'`).Scan(&jsCount); err != nil {
		t.Fatal(err)
	}
	if jsCount != 2 {
		t.Fatalf("JS synthetic profile rows = %d, want one per scan", jsCount)
	}

	surfaceA := &SurfaceMapper{db: db, scanID: scanA}
	surfaceB := &SurfaceMapper{db: db, scanID: scanB}
	surfaceA.storeSurface(&AttackSurface{Summary: SurfaceSummary{TotalInputs: 1}})
	surfaceB.storeSurface(&AttackSurface{Summary: SurfaceSummary{TotalInputs: 9}})
	surfaceA.storeSurface(&AttackSurface{Summary: SurfaceSummary{TotalInputs: 2}})

	assertProfileIssueContains(t, db, scanA, "attack_surface", `"total_inputs":2`)
	assertProfileIssueContains(t, db, scanB, "attack_surface", `"total_inputs":9`)
	var surfaceCount int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM page_profiles WHERE id = 'attack_surface'`).Scan(&surfaceCount); err != nil {
		t.Fatal(err)
	}
	if surfaceCount != 2 {
		t.Fatalf("surface synthetic profile rows = %d, want one per scan", surfaceCount)
	}
}

func assertProfileIssueContains(t *testing.T, db *store.DB, scanID int64, id, want string) {
	t.Helper()
	var issues string
	if err := db.Conn().QueryRow(`
		SELECT issues FROM page_profiles WHERE scan_id = ? AND id = ?`,
		scanID, id).Scan(&issues); err != nil {
		t.Fatalf("load profile %s for scan %d: %v", id, scanID, err)
	}
	// Ensure the stored value remains valid JSON as well as containing the
	// scan-specific fixture marker.
	var decoded any
	if err := json.Unmarshal([]byte(issues), &decoded); err != nil {
		t.Fatalf("profile %s issues are invalid JSON: %v", id, err)
	}
	if !strings.Contains(issues, want) {
		t.Fatalf("profile %s issues = %s, want substring %q", id, issues, want)
	}
}
