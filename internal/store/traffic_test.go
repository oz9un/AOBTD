package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestLargeResponseBodiesAreContentAddressedAndResolved(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "bodies.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://example.test", `{}`)
	body := bytes.Repeat([]byte("large-response-"), bodyBlobThreshold/15+100)
	for _, rawURL := range []string{"https://example.test/a", "https://example.test/b"} {
		_, err := db.InsertTraffic(scanID, &types.TrafficEntry{
			Request: types.CapturedRequest{Method: "GET", URL: rawURL, Headers: map[string]string{}},
			Response: types.CapturedResponse{
				StatusCode: 200, Headers: map[string]string{}, Body: body,
				ContentType: "application/json", Size: int64(len(body)),
			},
			Timestamp: time.Now(),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var blobs, references int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM body_blobs`).Scan(&blobs); err != nil {
		t.Fatal(err)
	}
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM traffic WHERE response_body IS NULL AND response_body_hash != ''`).Scan(&references); err != nil {
		t.Fatal(err)
	}
	if blobs != 1 || references != 2 {
		t.Fatalf("blobs=%d references=%d, want 1/2", blobs, references)
	}
	entries, err := db.GetTrafficByScan(scanID)
	if err != nil || len(entries) != 2 {
		t.Fatalf("GetTrafficByScan = (%d, %v)", len(entries), err)
	}
	for _, entry := range entries {
		if !bytes.Equal(entry.Response.Body, body) {
			t.Fatalf("resolved body length=%d, want %d", len(entry.Response.Body), len(body))
		}
	}
}

func TestGetAnalyzedTrafficByEndpointHashExcludesFreshRows(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "analyzed-traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://example.test", `{}`)

	firstID, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: "GET", URL: "https://example.test/api/orders/1", Headers: map[string]string{}},
		Response: types.CapturedResponse{
			StatusCode: 200, Headers: map[string]string{}, ContentType: "application/json", Body: []byte(`{"id":1}`),
		},
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: "GET", URL: "https://example.test/api/orders/2", Headers: map[string]string{}},
		Response: types.CapturedResponse{
			StatusCode: 200, Headers: map[string]string{}, ContentType: "application/json", Body: []byte(`{"id":2}`),
		},
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}

	var hash string
	if err := db.Conn().QueryRow(`SELECT endpoint_hash FROM traffic WHERE id = ?`, firstID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`UPDATE traffic SET endpoint_hash = ? WHERE id = ?`, hash, secondID); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkTrafficAnalyzed([]int64{firstID}, 7); err != nil {
		t.Fatal(err)
	}

	entries, err := db.GetAnalyzedTrafficByEndpointHash(scanID, hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want only the already-analyzed row", len(entries))
	}
	if entries[0].ID != firstID {
		t.Fatalf("entry ID = %d, want %d", entries[0].ID, firstID)
	}
}

func TestAcknowledgeEquivalentAnalyzedEvidenceKeepsMaterialChangesQueued(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "analysis-watermark.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://example.test", `{}`)
	insert := func(status int, body string) int64 {
		t.Helper()
		id, insertErr := db.InsertTraffic(scanID, &types.TrafficEntry{
			Request: types.CapturedRequest{Method: "GET", URL: "https://example.test/api/me", Headers: map[string]string{}},
			Response: types.CapturedResponse{
				StatusCode: status, Headers: map[string]string{}, ContentType: "application/json",
				Body: []byte(body), Size: int64(len(body)),
			},
			Timestamp: time.Now(),
		})
		if insertErr != nil {
			t.Fatal(insertErr)
		}
		return id
	}
	priorID := insert(200, `{"id":1}`)
	equivalentID := insert(200, `{"id":1}`)
	changedID := insert(403, `{"error":"forbidden"}`)
	if err := db.MarkTrafficAnalyzed([]int64{priorID}, 3); err != nil {
		t.Fatal(err)
	}
	acknowledged, err := db.AcknowledgeEquivalentAnalyzedEvidence(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if acknowledged != 1 {
		t.Fatalf("acknowledged rows = %d, want 1", acknowledged)
	}
	var equivalentAnalyzed, changedAnalyzed bool
	if err := db.Conn().QueryRow(`SELECT is_ai_analyzed FROM traffic WHERE id = ?`, equivalentID).Scan(&equivalentAnalyzed); err != nil {
		t.Fatal(err)
	}
	if err := db.Conn().QueryRow(`SELECT is_ai_analyzed FROM traffic WHERE id = ?`, changedID).Scan(&changedAnalyzed); err != nil {
		t.Fatal(err)
	}
	if !equivalentAnalyzed || changedAnalyzed {
		t.Fatalf("equivalent analyzed=%v changed analyzed=%v, want true/false", equivalentAnalyzed, changedAnalyzed)
	}
}

func TestOpenMigratesTrafficProvenanceColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacySchema := schema
	for _, column := range []string{
		"\tsource_agent     TEXT NOT NULL DEFAULT 'capture',\n",
		"\tsource_action_id INTEGER NOT NULL DEFAULT 0,\n",
		"\thypothesis_id    TEXT NOT NULL DEFAULT '',\n",
		"\trelevance_scored BOOLEAN NOT NULL DEFAULT FALSE,\n",
	} {
		legacySchema = strings.Replace(legacySchema, column, "", 1)
	}
	if legacySchema == schema {
		t.Fatal("test setup did not remove provenance columns")
	}

	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(legacySchema); err != nil {
		_ = legacy.Close()
		t.Fatalf("create legacy schema: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open() legacy database error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var columns int
	if err := db.Conn().QueryRow(`
		SELECT COUNT(*) FROM pragma_table_info('traffic')
		WHERE name IN ('source_agent', 'source_action_id', 'hypothesis_id', 'relevance_scored')`).Scan(&columns); err != nil {
		t.Fatalf("inspect migrated columns: %v", err)
	}
	if columns != 4 {
		t.Fatalf("migrated traffic columns = %d, want 4", columns)
	}

	var indexes int
	if err := db.Conn().QueryRow(`
		SELECT COUNT(*) FROM sqlite_master
		WHERE type = 'index'
		  AND name IN ('idx_traffic_source_action', 'idx_traffic_hypothesis')`).Scan(&indexes); err != nil {
		t.Fatalf("inspect migrated indexes: %v", err)
	}
	if indexes != 2 {
		t.Fatalf("migrated provenance indexes = %d, want 2", indexes)
	}
}

func TestInsertTrafficCanonicalizesIncompleteProducerEntry(t *testing.T) {
	db, err := Open(t.TempDir() + "/scan.db")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	scanID, err := db.CreateScan("https://api.example.test", `{}`)
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	capturedAt := time.Date(2026, time.July, 10, 8, 30, 0, 0, time.UTC)
	entry := &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  "POST",
			URL:     "https://api.example.test/v1/orders/123?notify=true",
			Headers: map[string]string{"Authorization": "Bearer scan-one"},
			Body:    []byte(`{"status":"approved"}`),
		},
		Response: types.CapturedResponse{
			StatusCode: 200,
			Headers:    map[string]string{"CONTENT-TYPE": "application/json"},
			Body:       []byte(`{"id":123,"status":"approved"}`),
		},
		Timestamp: capturedAt,
	}

	if _, err := db.InsertTraffic(scanID, entry); err != nil {
		t.Fatalf("InsertTraffic() error = %v", err)
	}
	if entry.EndpointHash == "" {
		t.Fatal("InsertTraffic() left producer entry with blank endpoint hash")
	}

	entries, err := db.GetUnanalyzedTraffic(scanID, 10)
	if err != nil {
		t.Fatalf("GetUnanalyzedTraffic() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("GetUnanalyzedTraffic() len = %d, want 1", len(entries))
	}
	got := entries[0]
	if got.EndpointHash != entry.EndpointHash {
		t.Errorf("endpoint hash = %q, want %q", got.EndpointHash, entry.EndpointHash)
	}
	if got.Request.Host != "api.example.test" || got.Request.Path != "/v1/orders/123" || got.Request.Query != "notify=true" {
		t.Errorf("request identity not canonical: host=%q path=%q query=%q", got.Request.Host, got.Request.Path, got.Request.Query)
	}
	if got.Response.ContentType != "application/json" {
		t.Errorf("content type = %q, want application/json", got.Response.ContentType)
	}
	if got.Response.Size != int64(len(entry.Response.Body)) {
		t.Errorf("response size = %d, want %d", got.Response.Size, len(entry.Response.Body))
	}
	if got.SourceAgent != "capture" {
		t.Errorf("source agent = %q, want capture", got.SourceAgent)
	}
	if !got.Timestamp.Equal(capturedAt) {
		t.Errorf("captured_at = %v, want %v", got.Timestamp, capturedAt)
	}

	hashes, err := db.GetUnanalyzedEndpointHashes(scanID, 0, 10)
	if err != nil {
		t.Fatalf("GetUnanalyzedEndpointHashes() error = %v", err)
	}
	if len(hashes) != 1 || hashes[0] != entry.EndpointHash {
		t.Fatalf("unanalyzed hashes = %v, want [%s]", hashes, entry.EndpointHash)
	}
}

func TestInsertTrafficRejectsInvalidObservation(t *testing.T) {
	db, err := Open(t.TempDir() + "/scan.db")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{}); err == nil {
		t.Fatal("InsertTraffic() error = nil, want invalid observation error")
	}
}

func TestAnalysisQueueExposesRealEndpointFamilyStates(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "analysis-queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	entries := []*types.TrafficEntry{
		{
			Request:   types.CapturedRequest{Method: "GET", URL: "https://app.test/login", Headers: map[string]string{}},
			Response:  types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html", Body: []byte(`<form><input name="email"></form>`)},
			Timestamp: time.Now(),
		},
		{
			Request:   types.CapturedRequest{Method: "GET", URL: "https://app.test/logo.svg", Headers: map[string]string{}},
			Response:  types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "image/svg+xml", Body: []byte(`<svg/>`)},
			Timestamp: time.Now(),
		},
	}
	for _, entry := range entries {
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Conn().Exec(`UPDATE traffic SET relevance_score = CASE WHEN path = '/login' THEN 0.8 ELSE 0.1 END, relevance_scored = TRUE WHERE scan_id = ?`, scanID); err != nil {
		t.Fatal(err)
	}
	queue, err := db.GetUnanalyzedEndpointQueue(scanID, .3, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(queue) != 1 || queue[0].Path != "/login" || !queue[0].HasInput || queue[0].EvidenceID == 0 {
		t.Fatalf("analysis queue = %+v", queue)
	}
	if queue[0].PriorityScore != queue[0].BaseScore || !containsQueueReason(queue[0].Reasons, "input-bearing page") {
		t.Fatalf("base queue explanation = %+v", queue[0])
	}
	counts, err := db.GetAnalysisQueueCounts(scanID, .3)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Ready != 1 || counts.Deferred != 1 || counts.Completed != 0 {
		t.Fatalf("initial queue counts = %+v", counts)
	}
	if err := db.MarkEndpointAnalyzed(scanID, queue[0].EndpointHash, 1); err != nil {
		t.Fatal(err)
	}
	counts, err = db.GetAnalysisQueueCounts(scanID, .3)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Ready != 0 || counts.Deferred != 1 || counts.Completed != 1 {
		t.Fatalf("completed queue counts = %+v", counts)
	}
}

func TestAnalysisQueueRetriesOneLowConfidenceParseStub(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "analysis-recovery.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	entry := &types.TrafficEntry{
		Request:   types.CapturedRequest{Method: "GET", URL: "https://app.test/account/login/?next=/account/", Headers: map[string]string{}},
		Response:  types.CapturedResponse{StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html", Body: []byte(`<form><input name="next"></form>`)},
		Timestamp: time.Now(),
	}
	if _, err := db.InsertTraffic(scanID, entry); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`UPDATE traffic SET relevance_score=.85, relevance_scored=TRUE WHERE scan_id=?`, scanID); err != nil {
		t.Fatal(err)
	}
	initial, err := db.GetUnanalyzedEndpointQueue(scanID, .3, 10)
	if err != nil || len(initial) != 1 {
		t.Fatalf("initial queue = %+v, err=%v", initial, err)
	}
	if err := db.MarkEndpointAnalyzed(scanID, initial[0].EndpointHash, 1); err != nil {
		t.Fatal(err)
	}
	stub := &types.PageProfile{
		ID: "GET /account/login/", URL: entry.Request.URL, Method: "GET",
		Purpose: "Captured login page awaiting semantic recovery", Confidence: .1,
	}
	if err := db.UpsertProfile(scanID, stub); err != nil {
		t.Fatal(err)
	}

	recovery, err := db.GetUnanalyzedEndpointQueue(scanID, .3, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovery) != 1 || !recovery[0].Reanalysis || recovery[0].EvidenceID == 0 {
		t.Fatalf("low-confidence recovery queue = %+v", recovery)
	}
	if recovery[0].ProfileConfidence != .1 || !containsQueueReason(recovery[0].Reasons, "low-confidence profile recovery") {
		t.Fatalf("recovery explanation = %+v", recovery[0])
	}
	counts, err := db.GetAnalysisQueueCounts(scanID, .3)
	if err != nil || counts.Ready != 1 || counts.Completed != 0 {
		t.Fatalf("recovery counts = %+v, err=%v", counts, err)
	}

	// A second upsert is the bounded retry attempt. Even if its semantic
	// confidence remains low, the same captured body must not loop forever.
	if err := db.UpsertProfile(scanID, stub); err != nil {
		t.Fatal(err)
	}
	recovery, err = db.GetUnanalyzedEndpointQueue(scanID, .3, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovery) != 0 {
		t.Fatalf("recovery was not bounded after one retry: %+v", recovery)
	}
}

func TestAmbientCookieDoesNotBecomeDirectAuthEvidence(t *testing.T) {
	if hasAuthHeaders(map[string]string{"Cookie": "session=anonymous; consent=yes"}) {
		t.Fatal("ambient browser cookie became direct authentication evidence")
	}
	for _, headers := range []map[string]string{
		{"Authorization": "Bearer observed"},
		{"X-API-Key": "observed"},
		{"X-Auth-Token": "observed"},
	} {
		if !hasAuthHeaders(headers) {
			t.Fatalf("direct credential header was not recognized: %v", headers)
		}
	}
}

func TestAnalysisQueuePersistsProtectionShapeAndKeepsRecoveredApplication(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "protection.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(status int, body string) {
		t.Helper()
		entry := &types.TrafficEntry{
			Request: types.CapturedRequest{Method: "GET", URL: "https://app.test/reviews", Headers: map[string]string{}},
			Response: types.CapturedResponse{
				StatusCode: status, ContentType: "text/html",
				Headers: map[string]string{"Server": "cloudflare", "CF-Ray": "ray-value"},
				Body:    []byte(body),
			},
			Timestamp: time.Now(),
		}
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}
	insert(403, `<title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/x"></script><p>Enable JavaScript and cookies to continue</p>`)
	if _, err := db.Conn().Exec(`UPDATE traffic SET relevance_score=.9, relevance_scored=TRUE WHERE scan_id=?`, scanID); err != nil {
		t.Fatal(err)
	}
	queue, err := db.GetUnanalyzedEndpointQueue(scanID, .3, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(queue) != 1 || !queue[0].IsInterstitial || queue[0].ProtectionVendor != "cloudflare" || queue[0].ProtectionShapes != 1 {
		t.Fatalf("challenge-only queue = %+v", queue)
	}
	summary, err := db.GetProtectionEvidenceSummary(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.InterstitialResponses != 1 || summary.DistinctShapes != 1 || len(summary.Vendors) != 1 || summary.RecoveredRoutes != 0 {
		t.Fatalf("protection summary = %+v", summary)
	}

	insert(200, `<title>Popular reviews</title><main>Member reviews</main>`)
	if _, err := db.Conn().Exec(`UPDATE traffic SET relevance_score=.9, relevance_scored=TRUE WHERE scan_id=?`, scanID); err != nil {
		t.Fatal(err)
	}
	queue, err = db.GetUnanalyzedEndpointQueue(scanID, .3, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(queue) != 1 || queue[0].IsInterstitial || !queue[0].RecoveredApplication {
		t.Fatalf("recovered application queue = %+v", queue)
	}
	summary, err = db.GetProtectionEvidenceSummary(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.RecoveredRoutes != 1 {
		t.Fatalf("recovered route summary = %+v", summary)
	}
}

func TestOpenBackfillsLikelyLegacyProtectionResponses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-protection.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := db.CreateScan("https://legacy.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`
		INSERT INTO traffic(scan_id,method,url,host,path,status_code,response_headers,response_body,content_type,endpoint_hash)
		VALUES (?,'GET','https://legacy.test/','legacy.test','/',403,?,?,'text/html','legacy-root')`,
		scanID, `{"Server":"cloudflare","CF-Ray":"old-ray"}`,
		[]byte(`<title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/x"></script>`)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	summary, err := db.GetProtectionEvidenceSummary(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.InterstitialResponses != 1 || summary.DistinctShapes != 1 || len(summary.Vendors) != 1 || summary.Vendors[0] != "cloudflare" {
		t.Fatalf("legacy protection backfill = %+v", summary)
	}
}

func containsQueueReason(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestGetTrafficStatsIncludesDashboardKeys(t *testing.T) {
	db, err := Open(t.TempDir() + "/scan.db")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	scanID, err := db.CreateScan("https://target.test", `{}`)
	if err != nil {
		t.Fatalf("CreateScan() error = %v", err)
	}
	insert := func(rawURL string, filtered bool) {
		t.Helper()
		entry := &types.TrafficEntry{
			Request: types.CapturedRequest{
				Method:  "GET",
				URL:     rawURL,
				Headers: map[string]string{},
			},
			Response: types.CapturedResponse{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       []byte(`{"ok":true}`),
			},
			Filtered:  filtered,
			Timestamp: time.Now().UTC(),
		}
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatalf("InsertTraffic(%q) error = %v", rawURL, err)
		}
	}

	insert("https://target.test/api/items", false)
	insert("https://target.test/api/items", false)
	insert("https://target.test/api/users", false)
	insert("https://third-party.test/api/beacon", true)

	stats, err := db.GetTrafficStats(scanID)
	if err != nil {
		t.Fatalf("GetTrafficStats() error = %v", err)
	}
	if stats.Total != 4 {
		t.Errorf("Total = %d, want 4", stats.Total)
	}
	if stats.UniqueEndpoints != 2 {
		t.Errorf("UniqueEndpoints = %d, want 2 in-scope endpoint identities", stats.UniqueEndpoints)
	}
	if stats.APIEndpoints != 4 || stats.APICalls != stats.APIEndpoints {
		t.Errorf("API counts = endpoints:%d calls:%d, want 4/4", stats.APIEndpoints, stats.APICalls)
	}
	encoded, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("json.Marshal(stats) error = %v", err)
	}
	for _, dashboardField := range []string{`"unique_endpoints":2`, `"api_calls":4`} {
		if !strings.Contains(string(encoded), dashboardField) {
			t.Errorf("stats JSON %s does not contain dashboard field %s", encoded, dashboardField)
		}
	}
}

func TestProfileEvidenceTrafficIsSQLDedupedAndBodyBounded(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://target.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	rawURL := "https://target.test/account"
	insert := func(body []byte) string {
		t.Helper()
		entry := &types.TrafficEntry{
			Request: types.CapturedRequest{Method: "GET", URL: rawURL, Headers: map[string]string{}},
			Response: types.CapturedResponse{
				StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html",
				Body: body, Size: int64(len(body)),
			},
			Timestamp: time.Now(),
		}
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
		return entry.EndpointHash
	}
	largeBody := append([]byte("HEAD-EVIDENCE|"), bytes.Repeat([]byte("middle-"), 3000)...)
	largeBody = append(largeBody, []byte("|TAIL-EVIDENCE")...)
	hash := insert(largeBody)
	for i := 0; i < 20; i++ {
		hash = insert([]byte("small repeated response"))
	}

	entries, err := db.GetProfileEvidenceTrafficForHashes(scanID, []string{hash})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("evidence samples=%d, want newest+largest rather than all 21", len(entries))
	}
	foundSplitSample := false
	for _, entry := range entries {
		if len(entry.Response.Body) > profileEvidenceDefaultBodyBytes {
			t.Fatalf("body sample=%d, ceiling=%d", len(entry.Response.Body), profileEvidenceDefaultBodyBytes)
		}
		if bytes.Contains(entry.Response.Body, []byte("HEAD-EVIDENCE")) && bytes.Contains(entry.Response.Body, []byte("TAIL-EVIDENCE")) {
			foundSplitSample = true
		}
	}
	if !foundSplitSample {
		t.Fatal("oversized response sample did not retain both head and tail evidence")
	}
}

func TestProfileEvidenceTrafficRetainsBoundedStructuralSoft404Bootstrap(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "structural-soft404.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://partner.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`<html><head><title>Partner portal</title></head><body><div id="app">`)
	body = append(body, bytes.Repeat([]byte("head-filler-"), 900)...)
	// A large multibyte prefix proves the TEXT marker position is converted back
	// to a BLOB byte offset before slicing the bounded sample.
	body = append(body, bytes.Repeat([]byte("ş"), 700)...)
	body = append(body, []byte(`<script>const originalUrl = '/errors/public/not-found'; window.scRouter = { originalUrl: originalUrl };</script>`)...)
	body = append(body, bytes.Repeat([]byte("tail-filler-"), 620)...)
	// This marker begins roughly 2.8 KiB from the end, matching Partner's late
	// authentication bundles. The structural middle sample must not steal the
	// tail budget that makes an independent auth-shell verdict possible.
	body = append(body, []byte(`<script src="/app-auth/bundles/app.123.js"></script>`)...)
	body = append(body, bytes.Repeat([]byte("footer-filler-"), 190)...)
	body = append(body, []byte(`</div><script src="/main.bundle.js"></script></body></html>`)...)
	entry := &types.TrafficEntry{
		Request: types.CapturedRequest{Method: "GET", URL: "https://partner.test/api/v1/auth/login", Headers: map[string]string{}},
		Response: types.CapturedResponse{
			StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html",
			Body: body, Size: int64(len(body)),
		},
		Timestamp: time.Now(),
	}
	if _, err := db.InsertTraffic(scanID, entry); err != nil {
		t.Fatal(err)
	}
	entries, err := db.GetProfileEvidenceTrafficForHashes(scanID, []string{entry.EndpointHash})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("evidence samples=%d, want 1", len(entries))
	}
	sample := entries[0].Response.Body
	if len(sample) > profileEvidenceDefaultBodyBytes {
		t.Fatalf("structural sample=%d, ceiling=%d", len(sample), profileEvidenceDefaultBodyBytes)
	}
	for _, marker := range [][]byte{
		[]byte("originalUrl"), []byte("/errors/public/not-found"), []byte("window.scRouter"),
		[]byte("app-auth/bundles/app.123.js"),
	} {
		if !bytes.Contains(sample, marker) {
			t.Fatalf("bounded structural sample omitted %q", marker)
		}
	}
	evidence := observation.SummarizeRedirectEvidence(entries)
	if evidence.ContentObserved || !evidence.ErrorShellObserved {
		t.Fatalf("bounded structural soft-404 evidence = %+v", evidence)
	}

	// A Next.js document can contain an unrelated application originalUrl long
	// before its framework-owned error payload. The sampler must anchor on
	// __NEXT_DATA__ unless a internal BFF scRouter pair is actually present.
	nextBody := []byte(`<html><head><title>Portal</title><script>const originalUrl='/orders';</script></head><body>`)
	nextBody = append(nextBody, bytes.Repeat([]byte("application-filler-"), 700)...)
	nextBody = append(nextBody, []byte(`<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"statusCode":404}},"page":"/_error"}</script>`)...)
	nextBody = append(nextBody, bytes.Repeat([]byte("next-tail-"), 700)...)
	nextBody = append(nextBody, []byte(`</body></html>`)...)
	nextEntry := &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: "GET", URL: "https://partner.test/missing-next-page", Headers: map[string]string{},
		},
		Response: types.CapturedResponse{
			StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html",
			Body: nextBody, Size: int64(len(nextBody)),
		},
		Timestamp: time.Now(),
	}
	if _, err := db.InsertTraffic(scanID, nextEntry); err != nil {
		t.Fatal(err)
	}
	nextEntries, err := db.GetProfileEvidenceTrafficForHashes(scanID, []string{nextEntry.EndpointHash})
	if err != nil {
		t.Fatal(err)
	}
	if len(nextEntries) != 1 || len(nextEntries[0].Response.Body) > profileEvidenceDefaultBodyBytes {
		t.Fatalf("bounded Next evidence samples=%d body=%d", len(nextEntries), len(nextEntries[0].Response.Body))
	}
	for _, marker := range [][]byte{[]byte("__NEXT_DATA__"), []byte(`"statusCode":404`), []byte(`"page":"/_error"`)} {
		if !bytes.Contains(nextEntries[0].Response.Body, marker) {
			t.Fatalf("bounded Next sample omitted %q", marker)
		}
	}
	nextEvidence := observation.SummarizeRedirectEvidence(nextEntries)
	if nextEvidence.ContentObserved || !nextEvidence.ErrorShellObserved {
		t.Fatalf("bounded Next soft-404 evidence = %+v", nextEvidence)
	}
}

func TestProfileEvidenceTrafficRetainsBoundedStructuralAuthTail(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "structural-auth-tail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://partner.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`<html><head><title>Partner portal</title></head><body><div id="app"><div id="initial-loading">Loading</div></div>`)
	body = append(body, bytes.Repeat([]byte("head-filler-"), 900)...)
	body = append(body, []byte(`<script>const originalUrl = '/account/logout?redirect=%2Fadmin'; window.scRouter = { originalUrl: originalUrl };</script>`)...)
	body = append(body, bytes.Repeat([]byte("tail-filler-"), 620)...)
	body = append(body, []byte(`<script src="/app-auth/bundles/app.123.js"></script>`)...)
	body = append(body, []byte(`<script src="/app-auth/bundles/chunk-vendors.456.js"></script>`)...)
	body = append(body, bytes.Repeat([]byte("footer-filler-"), 185)...)
	body = append(body, []byte(`</body></html>`)...)
	entry := &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: "GET", URL: "https://partner.test/account/logout?redirect=%2Fadmin",
			Headers: map[string]string{},
		},
		Response: types.CapturedResponse{
			StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html",
			Body: body, Size: int64(len(body)),
		},
		Timestamp: time.Now(),
	}
	if _, err := db.InsertTraffic(scanID, entry); err != nil {
		t.Fatal(err)
	}
	entries, err := db.GetProfileEvidenceTrafficForHashes(scanID, []string{entry.EndpointHash})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("evidence samples=%d, want 1", len(entries))
	}
	sample := entries[0].Response.Body
	if len(sample) > profileEvidenceDefaultBodyBytes {
		t.Fatalf("structural sample=%d, ceiling=%d", len(sample), profileEvidenceDefaultBodyBytes)
	}
	for _, marker := range [][]byte{
		[]byte("originalUrl"), []byte("window.scRouter"),
		[]byte("app-auth/bundles/app.123.js"),
		[]byte("app-auth/bundles/chunk-vendors.456.js"),
	} {
		if !bytes.Contains(sample, marker) {
			t.Fatalf("bounded structural auth sample omitted %q", marker)
		}
	}
	evidence := observation.SummarizeRedirectEvidence(entries)
	if evidence.ContentObserved || !evidence.AuthShellObserved || evidence.ErrorShellObserved {
		t.Fatalf("bounded structural auth-shell evidence = %+v", evidence)
	}
}

func TestProfileEvidenceTrafficDoesNotDropRequestedOrHighCardinalityIdentities(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "evidence-cardinality.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://target.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	// This is deliberately above both historical ceilings: requested hashes
	// used to be truncated at 800, and the SQL picker then dropped every route
	// after the first 1024 representative rows.
	const identityCount = 1105
	batch := make([]*types.TrafficEntry, 0, identityCount)
	for i := 0; i < identityCount; i++ {
		body := []byte(fmt.Sprintf(`{"route":%d}`, i))
		batch = append(batch, &types.TrafficEntry{
			Request: types.CapturedRequest{
				Method: "GET", URL: fmt.Sprintf("https://target.test/routes/route-%04d", i),
				Headers: map[string]string{},
			},
			Response: types.CapturedResponse{
				StatusCode: 200, Headers: map[string]string{}, ContentType: "application/json",
				Body: body, Size: int64(len(body)),
			},
			Timestamp: time.Now(),
		})
	}
	if inserted, err := db.InsertTrafficBatch(scanID, batch); err != nil || inserted != identityCount {
		t.Fatalf("InsertTrafficBatch = (%d, %v), want (%d, nil)", inserted, err, identityCount)
	}
	hashes := make([]string, 0, identityCount)
	for _, entry := range batch {
		if entry.EndpointHash == "" {
			t.Fatal("normalized batch entry has an empty endpoint hash")
		}
		hashes = append(hashes, entry.EndpointHash)
	}

	// Preserve the legacy/import path too. It is intentionally selected only
	// once even though the modern requested identities span multiple chunks.
	legacyID, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: "GET", URL: "https://target.test/legacy", Headers: map[string]string{},
		},
		Response: types.CapturedResponse{
			StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html",
			Body: []byte("legacy evidence"), Size: int64(len("legacy evidence")),
		},
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`UPDATE traffic SET endpoint_hash='' WHERE id=?`, legacyID); err != nil {
		t.Fatal(err)
	}

	// Reverse the request order and add duplicates/whitespace so correctness is
	// independent of chunk position and input cleanup.
	requested := make([]string, len(hashes))
	for i := range hashes {
		requested[len(hashes)-1-i] = hashes[i]
	}
	requested = append(requested, " ", hashes[0], hashes[profileEvidenceHashChunkSize])
	filtered, err := db.GetProfileEvidenceTrafficForHashes(scanID, requested)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != identityCount+1 {
		t.Fatalf("requested evidence rows=%d, want %d modern identities + one legacy row", len(filtered), identityCount)
	}
	seen := make(map[string]int, identityCount)
	legacyRows := 0
	for i, entry := range filtered {
		if i > 0 && filtered[i-1].ID >= entry.ID {
			t.Fatalf("evidence order is not globally deterministic at indexes %d/%d: %d then %d", i-1, i, filtered[i-1].ID, entry.ID)
		}
		if len(entry.Response.Body) > profileEvidenceDefaultBodyBytes {
			t.Fatalf("body sample=%d, ceiling=%d", len(entry.Response.Body), profileEvidenceDefaultBodyBytes)
		}
		if entry.EndpointHash == "" {
			legacyRows++
			continue
		}
		seen[entry.EndpointHash]++
	}
	if legacyRows != 1 {
		t.Fatalf("legacy evidence rows=%d, want exactly one across hash chunks", legacyRows)
	}
	for _, hash := range hashes {
		if seen[hash] != 1 {
			t.Fatalf("requested identity %s returned %d evidence rows, want 1", hash, seen[hash])
		}
	}

	all, err := db.GetProfileEvidenceTraffic(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != identityCount+1 {
		t.Fatalf("all-profile evidence rows=%d, want %d; a global route ceiling dropped evidence", len(all), identityCount+1)
	}
}
