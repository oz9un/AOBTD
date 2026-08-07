package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/oast"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestVerifySSRFConfirmsCorrelatedHTTPCallback(t *testing.T) {
	const apiToken = "poll-secret"
	var mu sync.Mutex
	events := make(map[string]int64)
	oastServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/c/"):
			token := strings.TrimPrefix(r.URL.Path, "/c/")
			mu.Lock()
			events[token] = time.Now().UnixMilli()
			mu.Unlock()
			fmt.Fprintf(w, "AOBTD_OAST_PROOF:%s\n", token)
		case strings.HasPrefix(r.URL.Path, "/api/v1/probes/"):
			if r.Header.Get("Authorization") != "Bearer "+apiToken {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			token := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/probes/"), "/events")
			mu.Lock()
			receivedAt := events[token]
			mu.Unlock()
			payload := map[string]any{"probe_token": token, "events": []any{}}
			if receivedAt > 0 {
				payload["events"] = []map[string]any{{
					"id": 1, "received_at_ms": receivedAt, "method": "GET",
					"path": "/c/" + token, "source_ip": "203.0.113.10", "colo": "LAX",
				}}
			}
			_ = json.NewEncoder(w).Encode(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer oastServer.Close()

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbackURL := r.URL.Query().Get("url")
		resp, err := http.Get(callbackURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("fetch queued"))
	}))
	defer targetServer.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "ssrf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan(targetServer.URL, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.New(policy.AuthorityActive, []string{targetServer.URL})
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewVerifierAgent(db, scanID, engine, targetServer.URL, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	oastClient, err := oast.New(oastServer.URL, apiToken, "signing-secret", oastServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	verifier.SetOASTClient(oastClient)

	profile := types.PageProfile{
		ID: "GET /fetch", URL: targetServer.URL + "/fetch", Method: http.MethodGet,
		Inputs: []types.Input{{Name: "url", Location: "query"}},
	}
	entry := types.TrafficEntry{
		ID: 99,
		Request: types.CapturedRequest{
			Method: http.MethodGet, URL: targetServer.URL + "/fetch?url=https%3A%2F%2Fexample.test",
			Path: "/fetch", Headers: map[string]string{},
		},
	}
	verifier.verifySSRF(context.Background(), profile, entry, "Potential SSRF in 'url' parameter")

	var confidence, vulnType, param, payload, evidence string
	err = db.Conn().QueryRow(`
		SELECT confidence, vuln_type, param_name, payload, evidence
		FROM findings WHERE scan_id=? AND vuln_type='ssrf'`, scanID).
		Scan(&confidence, &vulnType, &param, &payload, &evidence)
	if err != nil {
		t.Fatal(err)
	}
	if confidence != "confirmed" || vulnType != "ssrf" || param != "url" {
		t.Fatalf("finding = confidence:%q type:%q param:%q", confidence, vulnType, param)
	}
	if !strings.HasPrefix(payload, oastServer.URL+"/c/v1.") {
		t.Fatalf("payload = %q", payload)
	}
	if !strings.Contains(evidence, "203.0.113.10") || !strings.Contains(evidence, "LAX") {
		t.Fatalf("evidence = %q", evidence)
	}
}

func TestSSRFCandidateParamsRejectsTelemetryAndRecognizesURLFields(t *testing.T) {
	profile := types.PageProfile{
		Inputs: []types.Input{{Name: "avatar_url"}, {Name: "display_name"}},
	}
	entry := types.TrafficEntry{Request: types.CapturedRequest{URL: "https://app.test/import?feed=https%3A%2F%2Fexample.test"}}
	params := ssrfCandidateParams(profile, entry)
	joined := strings.Join(params, ",")
	if !strings.Contains(joined, "avatar_url") || !strings.Contains(joined, "feed") || strings.Contains(joined, "display_name") {
		t.Fatalf("params = %#v", params)
	}
	if !ssrfTelemetryLikePath("/awe/api/v2/rum") || ssrfTelemetryLikePath("/api/import") {
		t.Fatal("telemetry path classification is incorrect")
	}
}
