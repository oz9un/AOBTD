package ui

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	scanagent "github.com/ozzyw/aobtd/internal/agent"
	"github.com/ozzyw/aobtd/internal/ask"
	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/internal/policy"
	scanproxy "github.com/ozzyw/aobtd/internal/proxy"
	"github.com/ozzyw/aobtd/internal/reconprojection"
	"github.com/ozzyw/aobtd/internal/store"
	targetresolver "github.com/ozzyw/aobtd/internal/target"
	"github.com/ozzyw/aobtd/pkg/types"
)

//go:embed static/*
var staticFiles embed.FS

// Server serves the AOBTD web UI.
type Server struct {
	db        *store.DB
	outputDir string
	addr      string
	logger    *slog.Logger

	// activeScan tracks a scan subprocess started via /api/scan/start.
	// Only one scan can run at a time (they'd otherwise fight for the proxy port).
	activeMu   sync.Mutex
	activeProc *exec.Cmd
	activeInfo *activeScanInfo
	activeDone chan struct{}

	// copilotKeys keeps credentials supplied in the New Scan modal available
	// to the scan-scoped Copilot without ever persisting or returning them to
	// the browser. CLI-launched scans fall back to the process environment.
	copilotMu   sync.RWMutex
	copilotKeys map[string]string

	// devStaticDir, when non-empty, makes the server read frontend files
	// from disk instead of the embedded FS. Set by `aobtd ui --dev` so
	// CSS/JS edits land without rebuilding the binary.
	devStaticDir string

	// Profiles, Recon, Graph, Target Brain, and Copilot all apply the same
	// direct-response evidence ceiling. A running UI used to make each handler
	// reread up to 64 KiB from every response independently on the same refresh
	// tick. Cache by a cheap traffic revision so one bounded read serves every
	// projection while new captures invalidate it immediately.
	profileEvidenceMu    sync.Mutex
	profileEvidenceCache map[int64]*profileEvidenceCacheEntry

	graphRouteCountMu    sync.Mutex
	graphRouteCountCache map[int64]*graphRouteCountCacheEntry
}

type profileEvidenceCacheEntry struct {
	mu       sync.Mutex
	revision string
	entries  []types.TrafficEntry
}

type graphRouteCountCacheEntry struct {
	mu       sync.Mutex
	revision string
	count    int
}

// SetDevStaticDir enables dev mode: serve the frontend from this on-disk
// directory instead of the embedded FS. Call before Start.
func (s *Server) SetDevStaticDir(dir string) {
	s.devStaticDir = dir
}

type activeScanInfo struct {
	Target           string                  `json:"target"`
	MaxPages         int                     `json:"max_pages"`
	LLM              string                  `json:"llm"`
	TestingAuthority policy.TestingAuthority `json:"testing_authority"`
	StartedAt        time.Time               `json:"started_at"`
	PID              int                     `json:"pid"`
	Authenticated    bool                    `json:"authenticated"` // true when the scan was started with a session cookie
	MaxIDBefore      int64                   `json:"-"`             // spawn watermark; canonical redirects may change the stored target
}

// NewServer creates a new UI server.
func NewServer(db *store.DB, outputDir, addr string, logger *slog.Logger) *Server {
	return &Server{
		db:                   db,
		outputDir:            outputDir,
		addr:                 addr,
		logger:               logger,
		copilotKeys:          make(map[string]string),
		profileEvidenceCache: make(map[int64]*profileEvidenceCacheEntry),
		graphRouteCountCache: make(map[int64]*graphRouteCountCacheEntry),
	}
}

// Start starts the HTTP server. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	// Clean up *clearly stale* "running" scans on startup. The previous
	// version of this query stomped EVERY running scan on UI boot, which
	// broke the most common workflow: operator runs `aobtd scan` from one
	// shell, opens `aobtd ui` from another to watch it live. Within a
	// second of opening the UI, the live scan row got flipped to
	// 'interrupted' and the dashboard showed misleading state until the
	// scan eventually called FinishScan.
	//
	// Threshold: only mark interrupted if started_at is more than 4 hours
	// in the past — well beyond any plausible scan runtime. This keeps the
	// "true crash recovery" use case (UI was killed mid-scan, scanner died
	// too, scan is genuinely orphaned) working, while the CLI-scan +
	// UI-monitor flow keeps the row in 'running' until FinishScan owns
	// the transition.
	if _, err := s.db.Conn().Exec(`
		UPDATE scans SET status = 'interrupted',
		                 finished_at = COALESCE(finished_at, datetime('now'))
		WHERE status = 'running'
		  AND (finished_at IS NULL OR finished_at = '')
		  AND started_at IS NOT NULL
		  AND started_at != ''
		  AND datetime(started_at) < datetime('now', '-4 hours')`); err != nil {
		s.logger.Warn("could not clean up stale scans", "error", err)
	}

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/scans", s.handleScans) // list all scans
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/traffic", s.handleTraffic)
	mux.HandleFunc("/api/traffic/", s.handleTrafficDetail)
	mux.HandleFunc("/api/discovery/", s.handleDiscoveryDetail)
	mux.HandleFunc("/api/endpoints", s.handleEndpoints)
	mux.HandleFunc("/api/profiles", s.handleProfiles)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/sitemap", s.handleSitemap)
	mux.HandleFunc("/api/graph", s.handleGraph)
	mux.HandleFunc("/api/discovery-graph", s.handleDiscoveryGraph)
	mux.HandleFunc("/api/causal-flows", s.handleCausalFlows)
	mux.HandleFunc("/api/recon-graph", s.handleReconGraph)
	mux.HandleFunc("/api/ailog", s.handleAILog)
	mux.HandleFunc("/api/ailog/stats", s.handleAILogStats)
	mux.HandleFunc("/api/ailog/full", s.handleAILogFull)
	mux.HandleFunc("/api/ask", s.handleAsk)
	mux.HandleFunc("/api/ask/resume", s.handleAskResume)
	mux.HandleFunc("/api/copilot/thread", s.handleCopilotThread)
	mux.HandleFunc("/api/surface", s.handleSurface)
	mux.HandleFunc("/api/understanding", s.handleUnderstanding)
	mux.HandleFunc("/api/screenshot", s.handleScreenshotCapture)
	mux.HandleFunc("/api/endpoint/detail", s.handleEndpointDetail)
	mux.HandleFunc("/api/repeater", s.handleRepeater)
	mux.HandleFunc("/api/narrations", s.handleNarrations)
	mux.HandleFunc("/api/narrations/stream", s.handleNarrationsStream)
	mux.HandleFunc("/api/live/frame", s.handleLiveFrame)
	mux.HandleFunc("/api/live/frames", s.handleLiveFrames)
	mux.HandleFunc("/api/scan/start", s.handleScanStart)
	mux.HandleFunc("/api/scan/stop", s.handleScanStop)
	mux.HandleFunc("/api/scan/active", s.handleScanActive)
	mux.HandleFunc("/api/followups", s.handleFollowUps)
	mux.HandleFunc("/api/recon-learning-queue", s.handleReconLearningQueue)
	mux.HandleFunc("/api/target-brain", s.handleTargetBrain)
	mux.HandleFunc("/api/changes", s.handleChanges)
	mux.HandleFunc("/api/scan/export", s.handleExport)
	mux.HandleFunc("/api/strategy", s.handleStrategy)
	// Page-centric overview: "what does the target look like from a user's
	// POV" — groups endpoints by the page that triggered them (via Referer).
	mux.HandleFunc("/api/page-overview", s.handlePageOverview)
	// Cross-scan dashboard powering the Home view — aggregate totals + a
	// recent-scans list with per-scan finding counts so the landing page
	// doesn't need to fire one request per scan.
	mux.HandleFunc("/api/dashboard", s.handleDashboard)
	// Cmd-K command palette — substring search across scans, endpoints,
	// and findings, returned grouped so the modal can render per-kind.
	mux.HandleFunc("/api/search", s.handleSearch)
	// Interactive-prompt endpoints — the notification bell. List open
	// prompts, deliver an answer from the operator's modal back to the
	// scanner's poll loop.
	mux.HandleFunc("/api/prompts", s.handlePromptsList)
	mux.HandleFunc("/api/prompts/", s.handlePromptAnswer)

	// Screenshot files from disk
	ssDir := filepath.Join(s.outputDir, "screenshots")
	mux.Handle("/screenshots/", http.StripPrefix("/screenshots/",
		http.FileServer(http.Dir(ssDir))))

	// Static frontend files. In dev mode, serve from disk so HTML/CSS/JS
	// edits show up on browser refresh without rebuilding the binary. In
	// release mode, serve from the embedded FS so the binary is one file.
	if s.devStaticDir != "" {
		mux.Handle("/", noCacheHandler(http.FileServer(http.Dir(s.devStaticDir))))
	} else {
		staticFS, _ := fs.Sub(staticFiles, "static")
		mux.Handle("/", http.FileServer(http.FS(staticFS)))
	}

	server := &http.Server{
		Addr:              s.addr,
		Handler:           limitAPIRequestBodies(mux, 2<<20),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	s.logger.Info("UI server started", "addr", s.addr)
	fmt.Printf("\n  AOBTD UI: http://%s\n\n", s.addr)

	err := server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func limitAPIRequestBodies(next http.Handler, limit int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Body != nil &&
			(r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// noCacheHandler defeats browser caching for the wrapped handler. Used in
// dev mode so that frontend edits show up on a plain refresh — without it,
// Chrome happily serves the cached index.html and you wonder why your CSS
// change didn't appear.
func noCacheHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	reqScanID := s.scanIDFromRequest(r)

	var scanID int64
	var target, status, startedAt, finishedAt string
	var configJSON string

	err := s.db.Conn().QueryRow(`
		SELECT id, target, status, started_at, COALESCE(finished_at,''), config_json
		FROM scans WHERE id = ?`, reqScanID,
	).Scan(&scanID, &target, &status, &startedAt, &finishedAt, &configJSON)
	if err != nil {
		jsonError(w, "no scans found", 404)
		return
	}
	testingAuthority := testingAuthorityFromConfig(configJSON)
	copilotModel := copilotModelFromConfig(configJSON)

	// Get tech stack from traffic headers
	var server, framework string
	s.db.Conn().QueryRow(`
		SELECT
			COALESCE(json_extract(response_headers, '$.Server'), ''),
			COALESCE(json_extract(response_headers, '$."X-Powered-By"'), '')
		FROM traffic WHERE scan_id = ? AND json_extract(response_headers, '$.Server') != ''
		LIMIT 1`, scanID,
	).Scan(&server, &framework)

	jsonResponse(w, map[string]any{
		"scan_id":              scanID,
		"target":               target,
		"status":               status,
		"started_at":           startedAt,
		"finished_at":          finishedAt,
		"server":               server,
		"framework":            framework,
		"testing_authority":    testingAuthority,
		"copilot_provider":     copilotModel.Provider,
		"copilot_model":        copilotModel.Model,
		"copilot_model_source": copilotModel.Source,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	stats, err := s.db.GetTrafficStats(scanID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	pStats, _ := s.db.GetProfileStats(scanID)

	// Count findings by severity and confidence
	var critical, high, medium, low, info int
	var confirmed, dismissed int
	s.db.Conn().QueryRow(`
		SELECT
			SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END),
			SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END),
			SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END),
			SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END),
			SUM(CASE WHEN severity='info' THEN 1 ELSE 0 END),
			SUM(CASE WHEN confidence='confirmed' THEN 1 ELSE 0 END),
			SUM(CASE WHEN confidence='dismissed' THEN 1 ELSE 0 END)
		FROM findings WHERE scan_id = ?`, scanID,
	).Scan(&critical, &high, &medium, &low, &info, &confirmed, &dismissed)

	// Sidebar counters refresh frequently while a scan is running. Return the
	// four cheap counts here so the browser does not download thousands of
	// narration/AI rows or whole Strategy/Changes payloads just to print badges.
	var narrationCount, strategyCount, changesCount, aiLogCount int
	_ = s.db.Conn().QueryRow(`SELECT COUNT(*) FROM narrations WHERE scan_id = ?`, scanID).Scan(&narrationCount)
	_ = s.db.Conn().QueryRow(`SELECT COUNT(*) FROM hypotheses WHERE scan_id = ?`, scanID).Scan(&strategyCount)
	_ = s.db.Conn().QueryRow(`SELECT COUNT(*) FROM asset_changes WHERE scan_id = ?`, scanID).Scan(&changesCount)
	_ = s.db.Conn().QueryRow(`SELECT COUNT(*) FROM ai_log WHERE scan_id = ?`, scanID).Scan(&aiLogCount)

	// Graph boxes are logical origin+path routes, not endpoint hashes. Keep the
	// navigation badge exact while remaining cheap: the metadata-only projector
	// reads URL/method columns and never loads response bodies, profiles' model
	// prose, or discovery edge payloads.
	graphRouteCount := 0
	var scanTarget, configJSON string
	if scanErr := s.db.Conn().QueryRow(`SELECT target, config_json FROM scans WHERE id = ?`, scanID).Scan(&scanTarget, &configJSON); scanErr == nil {
		graphScope := graphProjectionScopeFromConfig(scanTarget, configJSON)
		if count, countErr := s.fastGraphLogicalRouteCount(scanID, scanTarget, graphScope); countErr == nil {
			graphRouteCount = count
		}
	}

	result := map[string]any{
		"traffic":           stats,
		"graph_route_count": graphRouteCount,
		"narration_count":   narrationCount,
		"strategy_count":    strategyCount,
		"changes_count":     changesCount,
		"ai_log_count":      aiLogCount,
		"findings": map[string]int{
			"critical":  critical,
			"high":      high,
			"medium":    medium,
			"low":       low,
			"info":      info,
			"confirmed": confirmed,
			"dismissed": dismissed,
		},
	}
	if pStats != nil {
		result["knowledge"] = pStats
	}

	jsonResponse(w, result)
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	filter := r.URL.Query().Get("filter") // all, api, input, auth, errors
	limit := intParam(r, "limit", 200)

	query := `
		SELECT id, method, url, path, status_code, content_type,
		       response_size, has_params, has_input, has_file_upload,
		       has_auth, has_errors, is_api, is_filtered, is_duplicate,
		       is_ai_analyzed, relevance_score, endpoint_hash, captured_at
		FROM traffic WHERE scan_id = ? AND is_filtered = FALSE`

	switch filter {
	case "api":
		query += " AND is_api = TRUE"
	case "input":
		query += " AND has_input = TRUE"
	case "auth":
		query += " AND has_auth = TRUE"
	case "errors":
		query += " AND has_errors = TRUE"
	case "analyzed":
		query += " AND is_ai_analyzed = TRUE"
	}

	query += " ORDER BY captured_at DESC LIMIT ?"

	rows, err := s.db.Conn().Query(query, scanID, limit)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var entries []map[string]any
	for rows.Next() {
		var id int64
		var method, url, path, contentType, endpointHash, capturedAt string
		var statusCode int
		var responseSize int64
		var hasParams, hasInput, hasFileUpload, hasAuth, hasErrors, isAPI bool
		var isFiltered, isDuplicate, isAnalyzed bool
		var relevanceScore float64

		rows.Scan(&id, &method, &url, &path, &statusCode, &contentType,
			&responseSize, &hasParams, &hasInput, &hasFileUpload,
			&hasAuth, &hasErrors, &isAPI, &isFiltered, &isDuplicate,
			&isAnalyzed, &relevanceScore, &endpointHash, &capturedAt)

		entries = append(entries, map[string]any{
			"id": id, "method": method, "url": url, "path": path,
			"status_code": statusCode, "content_type": contentType,
			"response_size": responseSize, "has_params": hasParams,
			"has_input": hasInput, "has_file_upload": hasFileUpload,
			"has_auth": hasAuth, "has_errors": hasErrors, "is_api": isAPI,
			"is_duplicate": isDuplicate, "is_analyzed": isAnalyzed,
			"relevance_score": relevanceScore, "endpoint_hash": endpointHash,
			"captured_at": capturedAt,
		})
	}

	jsonResponse(w, entries)
}

func (s *Server) handleTrafficDetail(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/traffic/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, "invalid id", 400)
		return
	}

	var method, url, path, query string
	var reqHeaders, reqBody []byte
	var statusCode int
	var resHeaders, resBody []byte
	var contentType string
	scanID, err := strconv.ParseInt(r.URL.Query().Get("scan_id"), 10, 64)
	if err != nil || scanID <= 0 {
		jsonError(w, "scan_id required", http.StatusBadRequest)
		return
	}

	err = s.db.Conn().QueryRow(`
		SELECT method, url, path, query, request_headers, request_body,
		       status_code, response_headers, response_body, content_type
		FROM traffic_resolved WHERE scan_id = ? AND id = ?`, scanID, id,
	).Scan(&method, &url, &path, &query, &reqHeaders, &reqBody,
		&statusCode, &resHeaders, &resBody, &contentType)
	if err != nil {
		jsonError(w, "not found", 404)
		return
	}

	// Truncate large bodies for the UI
	reqBodyStr := string(reqBody)
	resBodyStr := string(resBody)
	if len(resBodyStr) > 50000 {
		resBodyStr = resBodyStr[:50000] + "\n...truncated..."
	}

	jsonResponse(w, map[string]any{
		"method":           method,
		"url":              url,
		"path":             path,
		"query":            query,
		"request_headers":  json.RawMessage(reqHeaders),
		"request_body":     reqBodyStr,
		"status_code":      statusCode,
		"response_headers": json.RawMessage(resHeaders),
		"response_body":    resBodyStr,
		"content_type":     contentType,
	})
}

func (s *Server) handleDiscoveryDetail(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/discovery/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	scanID := s.scanIDFromRequest(r)
	var discovery store.Discovery
	err = s.db.Conn().QueryRow(`
		SELECT id, target_url, COALESCE(source_url,''), kind, COALESCE(detail,''), found_at
		FROM url_discoveries
		WHERE scan_id = ? AND id = ?`, scanID, id,
	).Scan(&discovery.ID, &discovery.TargetURL, &discovery.SourceURL,
		&discovery.Kind, &discovery.Detail, &discovery.FoundAt)
	if err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	jsonResponse(w, discovery)
}

func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)

	rows, err := s.db.Conn().Query(`
		SELECT endpoint_hash, method, path, host,
		       COUNT(*) as hit_count,
		       MAX(has_input) as has_input,
		       MAX(has_auth) as has_auth,
		       MAX(is_api) as is_api,
		       MAX(has_errors) as has_errors,
		       MAX(has_file_upload) as has_file_upload,
		       MAX(relevance_score) as max_relevance,
		       MAX(is_ai_analyzed) as is_analyzed,
		       MAX(has_params) as has_params,
		       MAX(status_code) as max_status,
		       MAX(content_type) as content_type
		FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE
		GROUP BY endpoint_hash
		ORDER BY max_relevance DESC`, scanID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var endpoints []map[string]any
	for rows.Next() {
		var hash, method, path, host, contentType string
		var hitCount, maxStatus int
		var hasInput, hasAuth, isAPI, hasErrors, hasFileUpload, isAnalyzed, hasParams bool
		var maxRelevance float64

		rows.Scan(&hash, &method, &path, &host, &hitCount, &hasInput, &hasAuth,
			&isAPI, &hasErrors, &hasFileUpload, &maxRelevance, &isAnalyzed,
			&hasParams, &maxStatus, &contentType)

		// Build score breakdown
		scoreReasons := []string{}
		if hasParams || hasInput {
			scoreReasons = append(scoreReasons, "has params +0.3")
		}
		if strings.Contains(contentType, "json") || strings.Contains(contentType, "xml") {
			scoreReasons = append(scoreReasons, "structured data +0.2")
		}
		if hasAuth {
			scoreReasons = append(scoreReasons, "auth headers +0.2")
		}
		if maxStatus >= 400 {
			scoreReasons = append(scoreReasons, "error response +0.15")
		}
		if method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH" {
			scoreReasons = append(scoreReasons, "state-changing +0.1")
		}
		for _, seg := range []string{"/admin", "/api/", "/auth", "/login", "/register", "/upload", "/settings", "/account", "/user", "/graphql", "/webhook"} {
			if strings.Contains(strings.ToLower(path), seg) {
				scoreReasons = append(scoreReasons, "interesting path +0.1")
				break
			}
		}

		endpoints = append(endpoints, map[string]any{
			"hash": hash, "method": method, "path": path, "host": host,
			"hit_count": hitCount, "has_input": hasInput, "has_auth": hasAuth,
			"is_api": isAPI, "has_errors": hasErrors,
			"has_file_upload": hasFileUpload, "relevance": maxRelevance,
			"is_analyzed": isAnalyzed, "score_reasons": scoreReasons,
		})
	}

	jsonResponse(w, endpoints)
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	profiles, err := s.db.GetAllProfiles(scanID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	s.annotateProfilesWithEvidence(scanID, profiles)
	jsonResponse(w, profiles)
}

// annotateProfilesWithEvidence projects the current direct HTTP evidence over
// stored model prose. This keeps historical scans honest after deterministic
// verification rules improve: a redirect-only /admin card can no longer keep
// presenting an old route-name guess as an observed dashboard.
func (s *Server) annotateProfilesWithEvidence(scanID int64, profiles []types.PageProfile) {
	if len(profiles) == 0 {
		return
	}
	entries, err := s.profileEvidenceTraffic(scanID)
	if err != nil {
		return
	}
	reconprojection.AnnotateProfiles(profiles, entries)
	s.applyLegacyProfileOriginCeiling(scanID, profiles)
	s.applySharedCatchAllCeiling(scanID, profiles, entries)
}

// applyLegacyProfileOriginCeiling protects historical scans created before
// profile IDs were disambiguated on cross-origin collisions. A path-only ID
// could have had its model prose overwritten by another authorized origin
// with the same METHOD/path; the surviving URL alone cannot prove which
// origin produced those semantics. Fail closed on reads instead of lending
// one origin's content to another origin's prose.
func (s *Server) applyLegacyProfileOriginCeiling(scanID int64, profiles []types.PageProfile) {
	if len(profiles) == 0 {
		return
	}
	type routeKey struct{ method, path string }
	candidates := make(map[routeKey]bool)
	profileKeys := make(map[int]routeKey)
	for i, profile := range profiles {
		if reconprojection.IsSyntheticSummaryProfile(profile) || strings.Contains(profile.ID, "://") {
			continue
		}
		parsed, err := url.Parse(strings.TrimSpace(profile.URL))
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(profile.Method))
		if method == "" {
			method = http.MethodGet
		}
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		key := routeKey{method: method, path: path}
		candidates[key] = true
		profileKeys[i] = key
	}
	if len(candidates) == 0 {
		return
	}

	origins := make(map[routeKey]map[string]bool)
	rows, err := s.db.Conn().Query(`
		SELECT UPPER(method), url, path
		  FROM traffic
		 WHERE scan_id = ? AND is_filtered = FALSE
		 GROUP BY UPPER(method), url, path`, scanID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var method, rawURL, path string
		if rows.Scan(&method, &rawURL, &path) != nil {
			return
		}
		if parsed, parseErr := url.Parse(rawURL); parseErr == nil && parsed.EscapedPath() != "" {
			path = parsed.EscapedPath()
		}
		if path == "" {
			path = "/"
		}
		key := routeKey{method: method, path: path}
		if !candidates[key] {
			continue
		}
		origin := observation.CanonicalOrigin(rawURL)
		if origin == "" {
			continue
		}
		if origins[key] == nil {
			origins[key] = make(map[string]bool)
		}
		origins[key][origin] = true
	}
	for i, key := range profileKeys {
		if len(origins[key]) < 2 {
			continue
		}
		values := make([]string, 0, len(origins[key]))
		for origin := range origins[key] {
			values = append(values, origin)
		}
		sort.Strings(values)
		reconprojection.MarkResponseUnverified(&profiles[i], fmt.Sprintf(
			"Legacy path-only profile identity %s %s collides across origins %s. Stored model semantics cannot be attributed safely; rescan with origin-aware identities.",
			key.method, key.path, strings.Join(values, ", "),
		))
	}
}

// applySharedCatchAllCeiling uses an already-observed negative-control route
// to reject branded 200 catch-all shells. It is intentionally conservative:
// exact response fingerprints alone are not enough (real SPAs reuse an HTML
// bootstrap); one member path must also carry a strong invalid/probe marker.
// This catches `/admin` == `/adminasdasd` without downgrading ordinary client
// routes merely because they share a bundle shell.
func (s *Server) applySharedCatchAllCeiling(scanID int64, profiles []types.PageProfile, entries []types.TrafficEntry) {
	index, err := s.db.GetCatchAllIndex(scanID)
	if err != nil {
		return
	}
	byHash := make(map[string][]types.TrafficEntry)
	for _, entry := range entries {
		hash := strings.TrimSpace(entry.EndpointHash)
		if hash == "" {
			hash = observation.EndpointHash(entry.Request.Method, entry.Request.URL)
		}
		byHash[hash] = append(byHash[hash], entry)
	}
	for i := range profiles {
		if reconprojection.IsSyntheticSummaryProfile(profiles[i]) {
			continue
		}
		reconprojection.ApplyCatchAllCeiling(&profiles[i], index)
		method := strings.ToUpper(strings.TrimSpace(profiles[i].Method))
		if method == "" {
			method = http.MethodGet
		}
		hash := observation.EndpointHash(method, profiles[i].URL)
		reconprojection.ApplyQueryVariantCeiling(&profiles[i], byHash[hash], index)
	}
}

// profileEvidenceTraffic loads only route-verdict metadata plus a bounded
// head/tail body sample. That sample distinguishes substantive content from
// empty/login/error shells—including SPA bundle identity near the document
// tail—without deserializing every full response in a large scan.
func (s *Server) profileEvidenceTraffic(scanID int64) ([]types.TrafficEntry, error) {
	// The map lock protects only the tiny scan->entry registry. Take the
	// per-scan lock before even calculating the revision so simultaneous
	// Profiles/Understanding/Graph handlers coalesce both aggregate checks and
	// the bounded body-prefix load. Unrelated scans remain independent.
	s.profileEvidenceMu.Lock()
	if s.profileEvidenceCache == nil {
		s.profileEvidenceCache = make(map[int64]*profileEvidenceCacheEntry)
	}
	entry := s.profileEvidenceCache[scanID]
	if entry == nil {
		if len(s.profileEvidenceCache) >= 8 {
			for cachedScanID := range s.profileEvidenceCache {
				delete(s.profileEvidenceCache, cachedScanID)
				break
			}
		}
		entry = &profileEvidenceCacheEntry{}
		s.profileEvidenceCache[scanID] = entry
	}
	s.profileEvidenceMu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	// The revision includes mutable filtering/deduplication state, not only
	// newly inserted rows. A deduper can invalidate a previously selected
	// response without advancing MAX(id), so is_duplicate/is_filtered must be
	// explicit inputs. Profile additions are included because they change which
	// endpoint identities the UI should sample.
	var count, maxID, statusTotal, sizeTotal, filteredTotal, duplicateTotal int64
	if err := s.db.Conn().QueryRow(`
		SELECT COUNT(*), COALESCE(MAX(id), 0),
		       COALESCE(SUM(status_code), 0), COALESCE(SUM(response_size), 0),
		       COALESCE(SUM(CASE WHEN is_filtered THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN is_duplicate THEN 1 ELSE 0 END), 0)
		  FROM traffic
		 WHERE scan_id = ?`, scanID,
	).Scan(&count, &maxID, &statusTotal, &sizeTotal, &filteredTotal, &duplicateTotal); err != nil {
		return nil, err
	}
	var profileCount, profileAnalysisTotal, profileShapeTotal int64
	var profileUpdated string
	if err := s.db.Conn().QueryRow(`
		SELECT COUNT(*), COALESCE(MAX(updated_at), ''),
		       COALESCE(SUM(analysis_count), 0),
		       COALESCE(SUM(LENGTH(id) + LENGTH(url) + LENGTH(method)), 0)
		  FROM page_profiles WHERE scan_id = ?`, scanID,
	).Scan(&profileCount, &profileUpdated, &profileAnalysisTotal, &profileShapeTotal); err != nil {
		return nil, err
	}
	revision := fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d:%s:%d:%d",
		count, maxID, statusTotal, sizeTotal, filteredTotal, duplicateTotal,
		profileCount, profileUpdated, profileAnalysisTotal, profileShapeTotal)

	if entry.revision == revision {
		return entry.entries, nil
	}

	rows, err := s.db.Conn().Query(`
		SELECT method, url
		  FROM page_profiles
		 WHERE scan_id = ?
		 ORDER BY updated_at DESC, id ASC`, scanID)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, profileCount)
	profileRoutes := make(map[string]bool, profileCount)
	type profileRoutePair struct{ host, path string }
	profileRoutePairs := make([]profileRoutePair, 0, profileCount)
	seenRoutePairs := make(map[profileRoutePair]bool, profileCount)
	for rows.Next() {
		var method, rawURL string
		if err := rows.Scan(&method, &rawURL); err != nil {
			rows.Close()
			return nil, err
		}
		if strings.TrimSpace(method) == "" {
			method = http.MethodGet
		}
		hashes = append(hashes, observation.EndpointHash(method, rawURL))
		if canonical, ok := canonicalGraphURL(rawURL); ok {
			profileRoutes[discoveryGraphRouteIdentity(canonical)] = true
			if parsed, parseErr := url.Parse(canonical); parseErr == nil {
				pair := profileRoutePair{host: parsed.Host, path: parsed.Path}
				if pair.host != "" && !seenRoutePairs[pair] {
					seenRoutePairs[pair] = true
					profileRoutePairs = append(profileRoutePairs, pair)
				}
			}
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// One Graph box can carry independent GET/POST/etc evidence. Include every
	// observed method for a profiled logical route so a redirecting GET cannot
	// borrow a POST's content (or vice versa), without loading bodies from
	// unrelated routes.
	if len(profileRoutePairs) > 0 {
		// Constrain SQL to the host/path pairs represented by profiles. Chunking
		// stays below SQLite's portable parameter limit; canonical comparison in
		// Go then preserves scheme/port/hash-route identity exactly.
		const routePairChunk = 200
		for start := 0; start < len(profileRoutePairs); start += routePairChunk {
			end := start + routePairChunk
			if end > len(profileRoutePairs) {
				end = len(profileRoutePairs)
			}
			conditions := make([]string, 0, end-start)
			args := make([]any, 0, 1+(end-start)*2)
			args = append(args, scanID)
			for _, pair := range profileRoutePairs[start:end] {
				conditions = append(conditions, "(host = ? AND path = ?)")
				args = append(args, pair.host, pair.path)
			}
			routeRows, routeErr := s.db.Conn().Query(`
				SELECT DISTINCT endpoint_hash, url
				  FROM traffic
				 WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE
				   AND endpoint_hash != '' AND (`+strings.Join(conditions, " OR ")+`)`, args...)
			if routeErr != nil {
				return nil, routeErr
			}
			for routeRows.Next() {
				var hash, rawURL string
				if scanErr := routeRows.Scan(&hash, &rawURL); scanErr != nil {
					routeRows.Close()
					return nil, scanErr
				}
				if canonical, ok := canonicalGraphURL(rawURL); ok && profileRoutes[discoveryGraphRouteIdentity(canonical)] {
					hashes = append(hashes, hash)
				}
			}
			if closeErr := routeRows.Close(); closeErr != nil {
				return nil, closeErr
			}
		}
	}
	entries, err := s.db.GetProfileEvidenceTrafficForHashes(scanID, hashes)
	if err != nil {
		return nil, err
	}
	entry.revision = revision
	entry.entries = entries
	return entry.entries, nil
}

func annotateProfileRedirectEvidence(profile *types.PageProfile, entries []types.TrafficEntry) {
	reconprojection.AnnotateProfile(profile, entries)
}

// directResponseEvidenceState is the UI-facing verdict for a set of known
// direct responses. A route is verified only when the shared classifier saw
// substantive content. Redirects, negative statuses, empty successes, and
// generic authentication/error shells all remain unverified even though only
// the first category is literally redirect-only.
func directResponseEvidenceState(evidence observation.RedirectEvidence) string {
	if evidence.ContentObserved {
		return "content_observed"
	}
	if evidence.RedirectOnly {
		if evidence.PathPreservingAuthGate {
			return "auth_gate_unverified"
		}
		return "redirect_only_unverified"
	}
	return "response_unverified"
}

// projectUnderstandingRedirectEvidence applies the same direct-response
// ceiling used by Knowledge to the read-only Recon snapshot. Older scans may
// have persisted a semantic guess such as "administrative dashboard" before
// redirect verification existed. A request path plus a path-preserving auth
// redirect proves the gate behavior, not the backing page or its purpose.
func (s *Server) projectUnderstandingRedirectEvidence(scanID int64, u *extract.AppUnderstanding) {
	if u == nil {
		return
	}
	profiles, err := s.db.GetAllProfiles(scanID)
	if err != nil || len(profiles) == 0 {
		return
	}
	s.annotateProfilesWithEvidence(scanID, profiles)
	reconprojection.ApplyRedirectEvidence(u, profiles)
}

// projectRedirectOnlyReconDependencies removes semantic claims whose complete
// support set is made of redirect-only page references. Mixed claims retain
// their independently supported branch, but the redirect-only evidence and
// step links are removed so the UI cannot imply that a gate proved a role,
// business object, or workflow behind it.
func projectRedirectOnlyReconDependencies(model *extract.ReconModel, unverifiedPageIDs map[string]bool, unverifiedPagePaths map[string]string) {
	if model == nil || len(unverifiedPageIDs) == 0 {
		return
	}

	removedRoles := make(map[string]bool)
	roles := make([]extract.ReconRole, 0, len(model.Roles))
	for _, role := range model.Roles {
		if reconSupportExclusivelyUnverified(role.Evidence, nil, unverifiedPageIDs) {
			removedRoles[role.ID] = true
			continue
		}
		role.Evidence = withoutUnverifiedReconEvidence(role.Evidence, unverifiedPageIDs)
		roles = append(roles, role)
	}
	model.Roles = roles

	removedObjects := make(map[string]bool)
	objects := make([]extract.BusinessObject, 0, len(model.Objects))
	for _, object := range model.Objects {
		if reconSupportExclusivelyUnverified(object.Evidence, nil, unverifiedPageIDs) {
			removedObjects[object.ID] = true
			continue
		}
		object.Evidence = withoutUnverifiedReconEvidence(object.Evidence, unverifiedPageIDs)
		object.OwnerRoleIDs = withoutRemovedReconIDs(object.OwnerRoleIDs, removedRoles)
		objects = append(objects, object)
	}
	model.Objects = objects

	workflows := make([]extract.BusinessWorkflow, 0, len(model.Workflows))
	for _, workflow := range model.Workflows {
		pageRefs := make([]string, 0)
		for _, step := range workflow.Steps {
			pageRefs = append(pageRefs, step.PageIDs...)
		}
		if reconSupportExclusivelyUnverified(workflow.Evidence, pageRefs, unverifiedPageIDs) {
			continue
		}
		workflow.Evidence = withoutUnverifiedReconEvidence(workflow.Evidence, unverifiedPageIDs)
		steps := make([]extract.WorkflowStep, 0, len(workflow.Steps))
		for _, step := range workflow.Steps {
			hadPageRefs := len(step.PageIDs) > 0
			step.PageIDs = withoutRemovedReconIDs(step.PageIDs, unverifiedPageIDs)
			if hadPageRefs && len(step.PageIDs) == 0 {
				continue
			}
			step.RoleIDs = withoutRemovedReconIDs(step.RoleIDs, removedRoles)
			step.ObjectIDs = withoutRemovedReconIDs(step.ObjectIDs, removedObjects)
			steps = append(steps, step)
		}
		workflow.Steps = steps
		if len(workflow.Steps) == 0 {
			continue
		}
		workflows = append(workflows, workflow)
	}
	model.Workflows = workflows

	boundaries := make([]extract.OwnershipBoundary, 0, len(model.OwnershipBoundaries))
	for _, boundary := range model.OwnershipBoundaries {
		if reconSupportExclusivelyUnverified(boundary.Evidence, boundary.EnforcedAt, unverifiedPageIDs) {
			continue
		}
		if removedObjects[boundary.ObjectID] || removedRoles[boundary.OwnerRoleID] {
			continue
		}
		hadEnforcementRefs := len(boundary.EnforcedAt) > 0
		boundary.EnforcedAt = withoutRemovedReconIDs(boundary.EnforcedAt, unverifiedPageIDs)
		if hadEnforcementRefs && len(boundary.EnforcedAt) == 0 {
			continue
		}
		boundary.Evidence = withoutUnverifiedReconEvidence(boundary.Evidence, unverifiedPageIDs)
		boundaries = append(boundaries, boundary)
	}
	model.OwnershipBoundaries = boundaries

	type unverifiedRouteRef struct {
		pageID string
		path   string
	}
	unverifiedRoutes := make([]unverifiedRouteRef, 0, len(unverifiedPageIDs))
	for pageID, path := range unverifiedPagePaths {
		if unverifiedPageIDs[pageID] && path != "" && path != "/" {
			unverifiedRoutes = append(unverifiedRoutes, unverifiedRouteRef{pageID: pageID, path: path})
		}
	}
	sort.Slice(unverifiedRoutes, func(i, j int) bool {
		if len(unverifiedRoutes[i].path) == len(unverifiedRoutes[j].path) {
			return unverifiedRoutes[i].pageID < unverifiedRoutes[j].pageID
		}
		return len(unverifiedRoutes[i].path) > len(unverifiedRoutes[j].path)
	})

	for i := range model.Unknowns {
		unknown := &model.Unknowns[i]
		var refs []string
		if reconSupportExclusivelyUnverified(unknown.Evidence, nil, unverifiedPageIDs) {
			refs = unverifiedReconEvidenceRefs(unknown.Evidence, unverifiedPageIDs)
		}
		if len(refs) == 0 {
			// Older saved models sometimes grounded a route-semantic question in
			// the generic `gap` sentinel rather than the page it named. Match only
			// exact redirect-only route tokens and leave redirect-mechanics
			// questions intact; a generic gap must not preserve a claim that an
			// admin page or role boundary exists behind a wildcard auth gate.
			text := strings.Join([]string{unknown.Question, unknown.WhyItMatters, unknown.SuggestedAction}, " ")
			if redirectMechanicsQuestion(text) {
				continue
			}
			for _, route := range unverifiedRoutes {
				if textMentionsRoutePath(text, route.path) {
					refs = append(refs, route.pageID)
				}
			}
		}
		if len(refs) == 0 {
			continue
		}
		sort.Strings(refs)
		refs = compactSortedStrings(refs)
		refLabel := strings.Join(refs, " and ")
		unknown.Question = "What, if anything, is verified by the unverified direct-response evidence for " + refLabel + "?"
		unknown.WhyItMatters = "A redirect, negative response, empty body, or generic shell does not verify a backing page, role boundary, or business behavior."
		unknown.SuggestedAction = "Capture a substantive direct response for " + refLabel + " before assigning route semantics."
	}

	for i := range model.Pages {
		model.Pages[i].ObjectIDs = withoutRemovedReconIDs(model.Pages[i].ObjectIDs, removedObjects)
	}
}

func redirectMechanicsQuestion(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range []string{
		"open redirect", "redirect parameter", "redirect target", "redirect chain",
		"redirect behavior", "redirect-only route", "location header",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func textMentionsRoutePath(text, path string) bool {
	text = strings.ToLower(text)
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" || path == "/" {
		return false
	}
	for offset := 0; offset < len(text); {
		index := strings.Index(text[offset:], path)
		if index < 0 {
			return false
		}
		index += offset
		end := index + len(path)
		beforeOK := index == 0 || !routePathTokenByte(text[index-1])
		afterOK := end == len(text) || !routePathTokenByte(text[end])
		if beforeOK && afterOK {
			return true
		}
		offset = index + 1
	}
	return false
}

func routePathTokenByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' ||
		value == '/' || value == '_' || value == '-' || value == '.' || value == '%'
}

func compactSortedStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func reconSupportExclusivelyUnverified(evidence []extract.ReconEvidence, pageRefs []string, unverifiedPageIDs map[string]bool) bool {
	hasSupport := false
	for _, item := range evidence {
		ref := strings.TrimSpace(item.Ref)
		if ref == "" {
			return false
		}
		hasSupport = true
		if !unverifiedPageIDs[ref] {
			return false
		}
	}
	for _, ref := range pageRefs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		hasSupport = true
		if !unverifiedPageIDs[ref] {
			return false
		}
	}
	return hasSupport
}

func withoutUnverifiedReconEvidence(evidence []extract.ReconEvidence, unverifiedPageIDs map[string]bool) []extract.ReconEvidence {
	kept := make([]extract.ReconEvidence, 0, len(evidence))
	for _, item := range evidence {
		if !unverifiedPageIDs[strings.TrimSpace(item.Ref)] {
			kept = append(kept, item)
		}
	}
	return kept
}

func unverifiedReconEvidenceRefs(evidence []extract.ReconEvidence, unverifiedPageIDs map[string]bool) []string {
	seen := make(map[string]bool)
	refs := make([]string, 0, len(evidence))
	for _, item := range evidence {
		ref := strings.TrimSpace(item.Ref)
		if ref == "" || !unverifiedPageIDs[ref] || seen[ref] {
			continue
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

func withoutRemovedReconIDs(ids []string, removed map[string]bool) []string {
	kept := make([]string, 0, len(ids))
	for _, id := range ids {
		if !removed[id] {
			kept = append(kept, id)
		}
	}
	return kept
}

func appendRedirectEvidenceOnce(evidence []extract.ReconEvidence, ref, detail string) []extract.ReconEvidence {
	for _, item := range evidence {
		if item.Kind == "redirect" && item.Ref == ref && item.Detail == detail {
			return evidence
		}
	}
	return append(evidence, extract.ReconEvidence{Kind: "redirect", Ref: ref, Detail: detail})
}

// redirectSemanticTerms is intentionally narrow. These route names are
// commonly treated as high-value pages by language models, while a redirect
// alone supplies no evidence that such a page exists. Generic paths such as
// /api are not used to rewrite an otherwise useful application identity.
func redirectSemanticTerms(rawURL string) []string {
	path := strings.ToLower(redirectEvidencePath(rawURL))
	terms := make([]string, 0, 2)
	for _, segment := range strings.Split(path, "/") {
		switch segment {
		case "admin", "administrator", "administration":
			terms = append(terms, "admin")
		case "dashboard":
			terms = append(terms, "dashboard")
		}
	}
	return terms
}

func redirectEvidencePath(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err == nil && parsed.Path != "" {
		return parsed.Path
	}
	if strings.HasPrefix(strings.TrimSpace(rawURL), "/") {
		return strings.TrimSpace(rawURL)
	}
	return ""
}

func sanitizeRedirectSemanticSummary(summary string, terms, paths map[string]bool) (string, bool) {
	if strings.TrimSpace(summary) == "" || len(terms) == 0 {
		return summary, false
	}
	claimsTerm := func(sentence string) bool {
		lower := strings.ToLower(sentence)
		if terms["admin"] && (strings.Contains(lower, "admin") || strings.Contains(lower, "administrative")) {
			return true
		}
		return terms["dashboard"] && strings.Contains(lower, "dashboard")
	}

	parts := strings.FieldsFunc(summary, func(r rune) bool {
		return r == '.' || r == '!' || r == '?'
	})
	kept := make([]string, 0, len(parts))
	changed := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if claimsTerm(part) {
			changed = true
			continue
		}
		kept = append(kept, part)
	}
	if !changed {
		return summary, false
	}

	orderedPaths := make([]string, 0, len(paths))
	for path := range paths {
		orderedPaths = append(orderedPaths, path)
	}
	sort.Strings(orderedPaths)
	subject := "The suggestive route"
	verb := "was"
	if len(orderedPaths) == 1 {
		subject = "The request for " + orderedPaths[0]
	} else if len(orderedPaths) > 1 {
		subject = "Requests for " + strings.Join(orderedPaths[:len(orderedPaths)-1], ", ") + " and " + orderedPaths[len(orderedPaths)-1]
		verb = "were"
	}
	note := fmt.Sprintf("%s %s observed only as path-preserving authentication redirects; backing route existence and business purpose remain unverified.", subject, verb)
	if len(kept) == 0 {
		return note, true
	}
	return strings.Join(kept, ". ") + ". " + note, true
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	var scanTarget string
	_ = s.db.Conn().QueryRow(`SELECT target FROM scans WHERE id = ?`, scanID).Scan(&scanTarget)

	rows, err := s.db.Conn().Query(`
		SELECT id, title, description, severity, confidence,
		       endpoint_id, evidence, COALESCE(remediation,''),
		       COALESCE(vuln_type,''), COALESCE(param_name,''), COALESCE(payload,''),
		       COALESCE(poc_request,''), COALESCE(poc_response,''),
		       COALESCE(steps_to_reproduce,''), COALESCE(impact,''),
		       created_at
		FROM findings WHERE scan_id = ?
		ORDER BY
			CASE confidence WHEN 'confirmed' THEN 0 WHEN 'possible' THEN 1 ELSE 2 END,
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END`, scanID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var findings []map[string]any
	for rows.Next() {
		var id int64
		var title, description, severity, confidence, endpointID, evidence, remediation string
		var vulnType, paramName, payload, pocReq, pocResp, steps, impact, createdAt string

		rows.Scan(&id, &title, &description, &severity, &confidence,
			&endpointID, &evidence, &remediation,
			&vulnType, &paramName, &payload,
			&pocReq, &pocResp, &steps, &impact,
			&createdAt)

		targetContext := findingTargetContext(scanTarget, endpointID, pocReq)
		findings = append(findings, map[string]any{
			"id": id, "title": title, "description": description,
			"severity": severity, "confidence": confidence,
			"endpoint_id": endpointID, "evidence": evidence,
			"remediation": remediation, "created_at": createdAt,
			"vuln_type": vulnType, "param_name": paramName, "payload": payload,
			"poc_request": pocReq, "poc_response": pocResp,
			"steps_to_reproduce": steps, "impact": impact,
			"target_context":       targetContext,
			"poc_request_resolved": resolveFindingPOCRequest(pocReq, targetContext),
			"finding_story":        findingStoryFor(vulnType, evidence, description),
		})
	}

	jsonResponse(w, findings)
}

type findingReproContext struct {
	ScanTarget  string `json:"scan_target"`
	Origin      string `json:"origin"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Endpoint    string `json:"endpoint"`
	EndpointURL string `json:"endpoint_url"`
}

func findingTargetContext(scanTarget, endpointID, pocReq string) findingReproContext {
	method, endpoint := splitFindingEndpoint(endpointID)
	if method == "" {
		method = methodFromRawRequest(pocReq)
	}
	if method == "" {
		method = "GET"
	}

	ctx := findingReproContext{
		ScanTarget: scanTarget,
		Method:     method,
		Endpoint:   endpointID,
	}
	if target, err := url.Parse(scanTarget); err == nil && target.Host != "" {
		ctx.Origin = target.Scheme + "://" + target.Host
		ctx.Host = target.Host
	}

	if endpoint == "" {
		endpoint = endpointPathFromRawRequest(pocReq)
	}
	if endpoint == "" {
		return ctx
	}
	ctx.Path = endpoint
	if resolved := resolveFindingEndpointURL(scanTarget, endpoint); resolved != "" {
		ctx.EndpointURL = resolved
		if parsed, err := url.Parse(resolved); err == nil {
			if parsed.Host != "" {
				ctx.Host = parsed.Host
			}
			if parsed.Scheme != "" && parsed.Host != "" {
				ctx.Origin = parsed.Scheme + "://" + parsed.Host
			}
			if parsed.Path != "" {
				ctx.Path = parsed.RequestURI()
			}
		}
	}
	return ctx
}

func splitFindingEndpoint(raw string) (method, endpoint string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	parts := strings.Fields(raw)
	if len(parts) >= 2 && isHTTPMethod(parts[0]) {
		return strings.ToUpper(parts[0]), strings.TrimSpace(strings.TrimPrefix(raw, parts[0]))
	}
	return "", raw
}

func isHTTPMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func methodFromRawRequest(raw string) string {
	first := firstRawRequestLine(raw)
	parts := strings.Fields(first)
	if len(parts) > 0 && isHTTPMethod(parts[0]) {
		return strings.ToUpper(parts[0])
	}
	return ""
}

func endpointPathFromRawRequest(raw string) string {
	first := firstRawRequestLine(raw)
	parts := strings.Fields(first)
	if len(parts) >= 2 && isHTTPMethod(parts[0]) {
		return parts[1]
	}
	return ""
}

func firstRawRequestLine(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if idx := strings.IndexByte(raw, '\n'); idx >= 0 {
		return strings.TrimSpace(raw[:idx])
	}
	return raw
}

func resolveFindingEndpointURL(scanTarget, endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if parsed, err := url.Parse(endpoint); err == nil && parsed.IsAbs() {
		return parsed.String()
	}
	base, err := url.Parse(scanTarget)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return endpoint
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	ref, err := url.Parse(endpoint)
	if err != nil {
		return base.Scheme + "://" + base.Host + endpoint
	}
	return base.ResolveReference(ref).String()
}

func resolveFindingPOCRequest(raw string, ctx findingReproContext) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	out := raw
	if ctx.Host != "" {
		out = strings.ReplaceAll(out, "Host: <target>", "Host: "+ctx.Host)
		out = strings.ReplaceAll(out, "host: <target>", "Host: "+ctx.Host)
		out = strings.ReplaceAll(out, "<target>", ctx.Host)
	}
	return out
}

func (s *Server) handleSitemap(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)

	rows, err := s.db.Conn().Query(`
		SELECT DISTINCT path, method, MAX(has_input), MAX(is_api),
		       MAX(has_auth), MAX(has_errors)
		FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE
		GROUP BY path, method
		ORDER BY path`, scanID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var paths []map[string]any
	for rows.Next() {
		var path, method string
		var hasInput, isAPI, hasAuth, hasErrors bool
		rows.Scan(&path, &method, &hasInput, &isAPI, &hasAuth, &hasErrors)

		paths = append(paths, map[string]any{
			"path": path, "method": method,
			"has_input": hasInput, "is_api": isAPI,
			"has_auth": hasAuth, "has_errors": hasErrors,
		})
	}

	// List screenshots
	var screenshots []string
	ssDir := filepath.Join(s.outputDir, "screenshots")
	if entries, err := os.ReadDir(ssDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".png") {
				screenshots = append(screenshots, e.Name())
			}
		}
	}

	jsonResponse(w, map[string]any{
		"paths":       paths,
		"screenshots": screenshots,
	})
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)

	rows, err := s.db.Conn().Query(`
		SELECT method, path, host,
		       MAX(has_input) as has_input,
		       MAX(has_auth) as has_auth,
		       MAX(is_api) as is_api,
		       MAX(has_errors) as has_errors,
		       MAX(has_file_upload) as has_file_upload,
		       COUNT(*) as hit_count,
		       MAX(relevance_score) as relevance,
		       MAX(is_ai_analyzed) as is_analyzed
		FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE
		GROUP BY method, path, host
		ORDER BY relevance DESC
		LIMIT 200`, scanID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	type endpointInfo struct {
		Method    string
		Path      string
		Host      string
		HasInput  bool
		HasAuth   bool
		IsAPI     bool
		HasErrors bool
		HasUpload bool
		HitCount  int
		Relevance float64
		Analyzed  bool
	}

	var endpoints []endpointInfo
	for rows.Next() {
		var e endpointInfo
		rows.Scan(&e.Method, &e.Path, &e.Host,
			&e.HasInput, &e.HasAuth, &e.IsAPI, &e.HasErrors, &e.HasUpload,
			&e.HitCount, &e.Relevance, &e.Analyzed)
		endpoints = append(endpoints, e)
	}

	type graphNode struct {
		ID        string  `json:"id"`
		Label     string  `json:"label"`
		FullPath  string  `json:"full_path"`
		Host      string  `json:"host"`
		Group     string  `json:"group"`
		Size      int     `json:"size"`
		Depth     int     `json:"depth"`
		IsLeaf    bool    `json:"is_leaf"`
		HasInput  bool    `json:"has_input"`
		HasAuth   bool    `json:"has_auth"`
		IsAPI     bool    `json:"is_api"`
		HasErrors bool    `json:"has_errors"`
		HasUpload bool    `json:"has_file_upload"`
		Relevance float64 `json:"relevance"`
		Analyzed  bool    `json:"is_analyzed"`
		Method    string  `json:"method,omitempty"`
	}

	type graphEdge struct {
		From string `json:"from"`
		To   string `json:"to"`
	}

	// Build a path trie — each unique path segment becomes a node
	nodeMap := make(map[string]*graphNode) // nodeID -> node
	edgeSeen := make(map[string]bool)
	var edges []graphEdge

	// Create host root nodes
	hosts := make(map[string]bool)
	for _, ep := range endpoints {
		hosts[ep.Host] = true
	}
	for host := range hosts {
		id := "h:" + host
		label := host
		if parts := strings.Split(host, "."); len(parts) > 2 {
			label = strings.Join(parts[:len(parts)-2], ".")
			if label == "" || label == "www" {
				label = parts[len(parts)-2]
			}
		}
		nodeMap[id] = &graphNode{
			ID: id, Label: label, FullPath: host,
			Host: host, Group: "host", Size: 30, Depth: 0,
		}
	}

	// Build path segment nodes
	for _, ep := range endpoints {
		hostID := "h:" + ep.Host
		segments := strings.Split(strings.Trim(ep.Path, "/"), "/")
		parentID := hostID

		for i, seg := range segments {
			if seg == "" {
				continue
			}
			// Truncate long segments for the node ID
			segKey := seg
			if len(segKey) > 60 {
				segKey = segKey[:60]
			}
			nodeID := parentID + "/" + segKey
			depth := i + 1
			isLeaf := i == len(segments)-1

			if existing, ok := nodeMap[nodeID]; ok {
				// Merge flags from this endpoint
				if ep.HasInput {
					existing.HasInput = true
				}
				if ep.HasAuth {
					existing.HasAuth = true
				}
				if ep.IsAPI {
					existing.IsAPI = true
				}
				if ep.HasErrors {
					existing.HasErrors = true
				}
				if ep.HasUpload {
					existing.HasUpload = true
				}
				if ep.Relevance > existing.Relevance {
					existing.Relevance = ep.Relevance
				}
				if ep.Analyzed {
					existing.Analyzed = true
				}
				existing.Size++
			} else {
				label := seg
				if len(label) > 25 {
					label = label[:22] + "..."
				}
				group := "page"
				if ep.HasErrors {
					group = "error"
				}
				if ep.HasInput || ep.HasUpload {
					group = "input"
				}
				if ep.HasAuth {
					group = "auth"
				}
				if ep.IsAPI {
					group = "api"
				}

				fullPath := "/" + strings.Join(segments[:i+1], "/")
				nodeMap[nodeID] = &graphNode{
					ID: nodeID, Label: label, FullPath: fullPath,
					Host: ep.Host, Group: group, Depth: depth, IsLeaf: isLeaf,
					Size:     12 + ep.HitCount,
					HasInput: ep.HasInput, HasAuth: ep.HasAuth, IsAPI: ep.IsAPI,
					HasErrors: ep.HasErrors, HasUpload: ep.HasUpload,
					Relevance: ep.Relevance, Analyzed: ep.Analyzed,
					Method: ep.Method,
				}
			}

			// Edge from parent to this node
			edgeKey := parentID + "->" + nodeID
			if !edgeSeen[edgeKey] {
				edgeSeen[edgeKey] = true
				edges = append(edges, graphEdge{From: parentID, To: nodeID})
			}

			parentID = nodeID
		}
	}

	// Cap node sizes
	for _, n := range nodeMap {
		if n.Size > 40 {
			n.Size = 40
		}
		if n.Size < 8 {
			n.Size = 8
		}
	}

	// Collect nodes
	var nodes []graphNode
	for _, n := range nodeMap {
		nodes = append(nodes, *n)
	}

	// Collect unique hosts for filter
	var hostList []string
	for h := range hosts {
		hostList = append(hostList, h)
	}

	jsonResponse(w, map[string]any{
		"nodes": nodes,
		"edges": edges,
		"hosts": hostList,
	})
}

const (
	discoveryGraphSchemaVersion = 1
	discoveryGraphMaxPageSize   = 2000
)

type discoveryGraphEndpointRef struct {
	Hash   string `json:"hash"`
	Method string `json:"method"`
}

type discoveryGraphMethodEvidence struct {
	Method             string                              `json:"method"`
	State              string                              `json:"state"`
	Note               string                              `json:"note,omitempty"`
	ObservedStatuses   []int                               `json:"observed_statuses,omitempty"`
	RedirectLocations  []string                            `json:"redirect_locations,omitempty"`
	QueryVariants      int                                 `json:"query_variants,omitempty"`
	ContentVariants    int                                 `json:"content_variants,omitempty"`
	UnverifiedVariants int                                 `json:"unverified_variants,omitempty"`
	VariantStates      []reconprojection.VariantStateCount `json:"variant_states,omitempty"`
}

type discoveryGraphNodeMeta struct {
	URL                 string                         `json:"url"`
	Label               string                         `json:"label"`
	Host                string                         `json:"host"`
	Path                string                         `json:"path"`
	Methods             []string                       `json:"methods"`
	EndpointRefs        []discoveryGraphEndpointRef    `json:"endpoint_refs"`
	ProfileIDs          []string                       `json:"profile_ids"`
	HitCount            int                            `json:"hit_count"`
	MaxStatus           int                            `json:"max_status"`
	HasIssues           bool                           `json:"has_issues"`
	IsAnalyzed          bool                           `json:"is_analyzed"`
	Observed            bool                           `json:"observed"`
	FindingCount        int                            `json:"finding_count"`
	Interesting         bool                           `json:"interesting"`
	KindTags            []string                       `json:"kind_tags"`
	InScope             bool                           `json:"in_scope"`
	FunctionalArea      string                         `json:"functional_area,omitempty"`
	AreaPriority        int                            `json:"area_priority,omitempty"`
	WorstSeverity       string                         `json:"worst_severity,omitempty"`
	QueryKeys           []string                       `json:"query_keys,omitempty"`
	QueryVariants       int                            `json:"query_variants,omitempty"`
	QueryVariantsCapped bool                           `json:"query_variants_capped,omitempty"`
	URLSamples          []string                       `json:"url_samples,omitempty"`
	EvidenceState       string                         `json:"evidence_state,omitempty"`
	EvidenceNote        string                         `json:"evidence_note,omitempty"`
	ObservedStatuses    []int                          `json:"observed_statuses,omitempty"`
	RedirectLocations   []string                       `json:"redirect_locations,omitempty"`
	MethodEvidence      []discoveryGraphMethodEvidence `json:"method_evidence,omitempty"`
}

type discoveryGraphEdgeOut struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Kind     string `json:"kind"`
	Type     string `json:"type"`
	Evidence string `json:"evidence"`
	Method   string `json:"method,omitempty"`
	Count    int    `json:"count,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type discoveryGraphPage struct {
	Offset     int  `json:"offset"`
	Limit      int  `json:"limit"`
	Returned   int  `json:"returned"`
	Total      int  `json:"total"`
	HasMore    bool `json:"has_more"`
	NextOffset int  `json:"next_offset,omitempty"`
}

// discoveryGraphOriginOut is the bounded origin-level projection used by the
// Recon Command Center. It intentionally includes linked-only origins so an
// operator can see first-party subdomains that were discovered but not placed
// in scope, without promoting those hosts into authorized target surface.
type discoveryGraphOriginOut struct {
	Origin        string   `json:"origin"`
	Host          string   `json:"host"`
	Hostname      string   `json:"hostname"`
	InScope       bool     `json:"in_scope"`
	FirstParty    bool     `json:"first_party"`
	Subdomain     bool     `json:"subdomain"`
	Target        bool     `json:"target"`
	URLs          int      `json:"urls"`
	Observed      int      `json:"observed"`
	Analyzed      int      `json:"analyzed"`
	EndpointRefs  int      `json:"endpoint_refs"`
	Profiles      int      `json:"profiles"`
	Findings      int      `json:"findings"`
	APINodes      int      `json:"api_nodes"`
	AuthNodes     int      `json:"auth_nodes"`
	Methods       []string `json:"methods"`
	KindTags      []string `json:"kind_tags"`
	WorstSeverity string   `json:"worst_severity,omitempty"`
}

func discoveryGraphEdgeType(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "seed":
		return "entry"
	case "html-link", "navigator", "explorer":
		return "navigation"
	case "form-action":
		return "form"
	case "redirect":
		return "redirect"
	case "js-route":
		return "static-reference"
	case "api-call":
		return "api"
	case "auth-call":
		return "authentication"
	default:
		return "provenance"
	}
}

func discoveryGraphReferer(headersJSON string) string {
	if strings.TrimSpace(headersJSON) == "" {
		return ""
	}
	var headers map[string]any
	if json.Unmarshal([]byte(headersJSON), &headers) != nil {
		return ""
	}
	for key, value := range headers {
		if strings.EqualFold(key, "referer") || strings.EqualFold(key, "referrer") {
			if referer, ok := value.(string); ok {
				return strings.TrimSpace(referer)
			}
		}
	}
	return ""
}

func discoveryGraphAuthPath(path string) bool {
	lower := strings.ToLower(path)
	for _, marker := range []string{"/auth", "/login", "/signin", "/sign-in", "/session", "/oauth", "/saml", "/token"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// canonicalGraphURL is the shared identity boundary for Graph data. It keeps
// path/query/hash-route detail, but normalizes case, query ordering, and
// implicit/default ports so https://host/path and https://host:443/path enrich
// the same node.
func canonicalGraphURL(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.User != nil || parsed.Hostname() == "" {
		return "", false
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	parsed.Host = host
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	parsed.RawQuery = parsed.Query().Encode()
	return parsed.String(), true
}

// discoveryGraphRouteIdentity deliberately stops at origin + path (+ fragment
// for client-side routers). Query strings are parameters of a route, not new
// top-level boxes.
func discoveryGraphRouteIdentity(canonical string) string {
	parsed, err := url.Parse(canonical)
	if err != nil {
		return canonical
	}
	parsed.RawQuery = ""
	return parsed.String()
}

const (
	discoveryGraphMaxQueryKeys                = 32
	discoveryGraphMaxQuerySpecimens           = 5
	discoveryGraphMaxQueryVariantFingerprints = 2048
)

func discoveryGraphQueryKeys(canonical string) []string {
	parsed, err := url.Parse(canonical)
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(parsed.Query()))
	for key := range parsed.Query() {
		if runes := []rune(key); len(runes) > 96 {
			key = string(runes[:96])
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	keys = compactSortedStrings(keys)
	if len(keys) > discoveryGraphMaxQueryKeys {
		keys = keys[:discoveryGraphMaxQueryKeys]
	}
	return keys
}

// discoveryGraphQuerySpecimen deliberately retains only the parameter names.
// Query values routinely carry OAuth codes, reset tokens, referral IDs, and
// user searches; putting those values in a Recon response is both noisy and a
// secret-disclosure footgun. The exact URL still contributes a one-way digest
// to the variant count below, so redaction does not collapse coverage metrics.
func discoveryGraphQuerySpecimen(canonical string) string {
	parsed, err := url.Parse(canonical)
	if err != nil {
		return ""
	}
	keys := discoveryGraphQueryKeys(canonical)
	fragment := parsed.Fragment
	parsed.RawQuery = ""
	parsed.Fragment = ""
	specimen := parsed.String()
	if len(keys) > 0 {
		pairs := make([]string, 0, len(keys))
		for _, key := range keys {
			pairs = append(pairs, url.QueryEscape(key)+"={redacted}")
		}
		specimen += "?" + strings.Join(pairs, "&")
	}
	if fragment != "" {
		specimen += "#" + fragment
	}
	return specimen
}

type discoveryGraphQueryFacet struct {
	fingerprints map[[sha256.Size]byte]struct{}
	saturated    bool
}

// observe counts distinct exact query variants without retaining their raw
// values. Once the bounded fingerprint set fills, max+1 is a truthful lower
// bound and QueryVariantsCapped tells API clients the count is not exact.
func (f *discoveryGraphQueryFacet) observe(canonical string) int {
	if f.fingerprints == nil {
		f.fingerprints = make(map[[sha256.Size]byte]struct{})
	}
	fingerprint := sha256.Sum256([]byte(canonical))
	if _, exists := f.fingerprints[fingerprint]; exists {
		if f.saturated {
			return discoveryGraphMaxQueryVariantFingerprints + 1
		}
		return len(f.fingerprints)
	}
	if len(f.fingerprints) < discoveryGraphMaxQueryVariantFingerprints {
		f.fingerprints[fingerprint] = struct{}{}
		return len(f.fingerprints)
	}
	f.saturated = true
	return discoveryGraphMaxQueryVariantFingerprints + 1
}

func discoveryGraphRouteLabel(node *discoveryGraphNodeMeta) string {
	if node == nil {
		return ""
	}
	label := node.Path
	if len(node.QueryKeys) > 0 {
		parts := make([]string, 0, len(node.QueryKeys))
		for _, key := range node.QueryKeys {
			parts = append(parts, key+"={…}")
		}
		label += "?" + strings.Join(parts, "&")
	}
	if parsed, err := url.Parse(node.URL); err == nil && parsed.Fragment != "" {
		label += "#" + parsed.Fragment
	}
	if label == "" || label == "/" {
		label = node.Host
	}
	if len(label) > 80 {
		label = label[:77] + "..."
	}
	return label
}

// handleDiscoveryGraph returns the target graph used by all three Graph
// representations. Discovery edges remain the authoritative provenance layer,
// while nodes are the union of discoveries, observed traffic/endpoints,
// analyzed profiles, and confirmed finding targets.
func (s *Server) handleDiscoveryGraph(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	limit := intParam(r, "limit", 100000)
	maxNodes := intParam(r, "max_nodes", 400)
	pageOffset := intParam(r, "offset", 0)
	pageSize := intParam(r, "page_size", 0)
	inScopeOnly := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("scope")), "in")
	originsOnly := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("origins_only")), "1") ||
		strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("origins_only")), "true")
	statsOnly := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("stats_only")), "1") ||
		strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("stats_only")), "true")
	if maxNodes <= 0 {
		maxNodes = 1000000
	}
	if pageOffset < 0 {
		pageOffset = 0
	}
	if pageSize < 0 {
		pageSize = 0
	}
	if pageSize > discoveryGraphMaxPageSize {
		pageSize = discoveryGraphMaxPageSize
	}

	var scanTarget, configJSON string
	if err := s.db.Conn().QueryRow(`SELECT target, config_json FROM scans WHERE id = ?`, scanID).
		Scan(&scanTarget, &configJSON); err != nil {
		jsonError(w, "no scans found", http.StatusNotFound)
		return
	}
	graphScope := graphProjectionScopeFromConfig(scanTarget, configJSON)
	if originsOnly {
		// Recon needs only an origin strip. Return before GraphEdges, traffic body
		// evidence, profiles, findings semantics, or node/edge construction.
		if err := s.writeFastDiscoveryOrigins(w, scanID, scanTarget, graphScope); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	edges, err := s.db.GraphEdges(scanID, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	nodes := make(map[string]*discoveryGraphNodeMeta)
	queryFacets := make(map[string]*discoveryGraphQueryFacet)
	touch := func(raw string) (*discoveryGraphNodeMeta, string, bool) {
		canonical, ok := canonicalGraphURL(raw)
		if !ok {
			return nil, "", false
		}
		identity := discoveryGraphRouteIdentity(canonical)
		facet := queryFacets[identity]
		if facet == nil {
			facet = &discoveryGraphQueryFacet{}
			queryFacets[identity] = facet
		}
		variantCount := facet.observe(canonical)
		specimen := discoveryGraphQuerySpecimen(canonical)
		if existing := nodes[identity]; existing != nil {
			for _, key := range discoveryGraphQueryKeys(canonical) {
				existing.QueryKeys = appendUnique(existing.QueryKeys, key)
			}
			existing.QueryVariants = variantCount
			existing.QueryVariantsCapped = facet.saturated
			if specimen != "" && len(existing.URLSamples) < discoveryGraphMaxQuerySpecimens {
				existing.URLSamples = appendUnique(existing.URLSamples, specimen)
			}
			existing.Label = discoveryGraphRouteLabel(existing)
			return existing, identity, true
		}
		parsed, _ := url.Parse(identity)
		_, inScope, _ := graphScope.MatchURL(canonical)
		node := &discoveryGraphNodeMeta{
			URL: identity, Host: parsed.Host, Path: parsed.Path, InScope: inScope,
			QueryKeys: discoveryGraphQueryKeys(canonical), QueryVariants: variantCount,
			QueryVariantsCapped: facet.saturated,
		}
		if specimen != "" {
			node.URLSamples = []string{specimen}
		}
		node.Label = discoveryGraphRouteLabel(node)
		nodes[identity] = node
		return node, identity, true
	}
	addEndpointRef := func(node *discoveryGraphNodeMeta, hash, method string) {
		if node == nil {
			return
		}
		method = strings.ToUpper(strings.TrimSpace(method))
		if method != "" {
			node.Methods = appendUnique(node.Methods, method)
		}
		if hash == "" {
			return
		}
		for _, ref := range node.EndpointRefs {
			if ref.Hash == hash {
				return
			}
		}
		node.EndpointRefs = append(node.EndpointRefs, discoveryGraphEndpointRef{Hash: hash, Method: method})
	}

	edgesOut := make([]discoveryGraphEdgeOut, 0, len(edges))
	edgeIndexes := make(map[string]int, len(edges))
	addGraphEdge := func(source, target, kind, detail, evidence, method string, count int) {
		method = strings.ToUpper(strings.TrimSpace(method))
		key := source + "\x00" + target + "\x00" + kind + "\x00" + method
		if index, exists := edgeIndexes[key]; exists {
			edgesOut[index].Count += count
			if edgesOut[index].Detail == "" {
				edgesOut[index].Detail = detail
			}
			return
		}
		edgeIndexes[key] = len(edgesOut)
		edgesOut = append(edgesOut, discoveryGraphEdgeOut{
			Source: source, Target: target, Kind: kind, Type: discoveryGraphEdgeType(kind),
			Evidence: evidence, Method: method, Count: count, Detail: detail,
		})
	}
	for _, edge := range edges {
		targetNode, target, ok := touch(edge.TargetURL)
		if !ok {
			continue
		}
		source := ""
		if _, canonical, sourceOK := touch(edge.SourceURL); sourceOK {
			source = canonical
		}
		addGraphEdge(source, target, edge.Kind, edge.Detail, "discovery", "", 1)
		targetNode.KindTags = appendUnique(targetNode.KindTags, edge.Kind)
	}

	// Observed traffic is first-class target surface even when no crawler link
	// produced a discovery edge (XHR/API calls are the common case).
	trafficRows, trafficErr := s.db.Conn().Query(`
		SELECT endpoint_hash, UPPER(method), url, COUNT(*),
		       MAX(status_code), MAX(is_ai_analyzed), MAX(is_api),
		       MAX(CASE WHEN lower(request_headers) LIKE '%referer%' THEN request_headers ELSE '' END)
		  FROM traffic
		 WHERE scan_id = ? AND is_filtered = FALSE
		 GROUP BY endpoint_hash, UPPER(method), url`, scanID)
	if trafficErr != nil {
		jsonError(w, trafficErr.Error(), http.StatusInternalServerError)
		return
	}
	for trafficRows.Next() {
		var hash, method, rawURL, headersJSON string
		var hits, status int
		var analyzed, isAPI bool
		if err := trafficRows.Scan(&hash, &method, &rawURL, &hits, &status, &analyzed, &isAPI, &headersJSON); err != nil {
			trafficRows.Close()
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if strings.TrimSpace(hash) == "" {
			hash = observation.EndpointHash(method, rawURL)
		}
		if node, target, ok := touch(rawURL); ok {
			node.HitCount += hits
			if status > node.MaxStatus {
				node.MaxStatus = status
			}
			node.IsAnalyzed = node.IsAnalyzed || analyzed
			node.Observed = true
			node.KindTags = appendUnique(node.KindTags, "traffic")
			addEndpointRef(node, hash, method)
			source := ""
			if referer := discoveryGraphReferer(headersJSON); referer != "" {
				if _, canonical, sourceOK := touch(referer); sourceOK {
					source = canonical
				}
			}
			if isAPI {
				addGraphEdge(source, target, "api-call", "Observed API request", "traffic", method, hits)
				node.KindTags = appendUnique(node.KindTags, "api-call")
			}
			if discoveryGraphAuthPath(node.Path) {
				addGraphEdge(source, target, "auth-call", "Observed authentication boundary", "traffic", method, hits)
				node.KindTags = appendUnique(node.KindTags, "auth-call")
			}
		}
	}
	trafficRows.Close()

	// Endpoint records add method/hash metadata for routes learned outside the
	// traffic aggregation path and give the UI a stable detail-panel target.
	endpointRows, endpointErr := s.db.Conn().Query(`
		SELECT id, method, url_pattern, hit_count, is_ai_analyzed
		  FROM endpoints WHERE scan_id = ?`, scanID)
	if endpointErr == nil {
		for endpointRows.Next() {
			var hash, method, rawURL string
			var hits int
			var analyzed bool
			if endpointRows.Scan(&hash, &method, &rawURL, &hits, &analyzed) != nil {
				continue
			}
			if node, _, ok := touch(rawURL); ok {
				if hits > node.HitCount {
					node.HitCount = hits
				}
				node.IsAnalyzed = node.IsAnalyzed || analyzed
				node.Observed = node.Observed || hits > 0 || analyzed
				node.KindTags = appendUnique(node.KindTags, "endpoint")
				addEndpointRef(node, hash, method)
			}
		}
		endpointRows.Close()
	}

	// Profiles are analyzed evidence, not optional decoration. Their methods
	// become part of the route evidence inventory now; issue semantics are added
	// only after the shared direct-response projection below.
	graphProfiles, profileErr := s.db.GetAllProfiles(scanID)
	if profileErr == nil {
		for _, profile := range graphProfiles {
			if node, _, ok := touch(profile.URL); ok {
				method := strings.ToUpper(strings.TrimSpace(profile.Method))
				if method == "" {
					method = http.MethodGet
				}
				node.ProfileIDs = appendUnique(node.ProfileIDs, profile.ID)
				node.Methods = appendUnique(node.Methods, method)
				node.IsAnalyzed = true
				node.Observed = true
				node.KindTags = appendUnique(node.KindTags, "profile")
			}
		}
	}

	sevRank := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
	rankToSev := map[int]string{5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}
	severityOf := func(node *discoveryGraphNodeMeta) int {
		return sevRank[strings.ToLower(node.WorstSeverity)]
	}
	hasMethod := func(node *discoveryGraphNodeMeta, method string) bool {
		if method == "" || len(node.Methods) == 0 {
			return true
		}
		for _, candidate := range node.Methods {
			if candidate == method {
				return true
			}
		}
		return false
	}
	findingRows, findingErr := s.db.Conn().Query(`
		SELECT endpoint_id, severity, COALESCE(poc_request, '')
		  FROM findings
		 WHERE scan_id = ? AND confidence = 'confirmed'`, scanID)
	if findingErr == nil {
		for findingRows.Next() {
			var endpointID, severity, pocRequest string
			if findingRows.Scan(&endpointID, &severity, &pocRequest) != nil {
				continue
			}
			rank := sevRank[strings.ToLower(severity)]
			if rank == 0 {
				continue
			}
			ctx := graphFindingTargetContext(scanTarget, endpointID, pocRequest)
			method := strings.ToUpper(strings.TrimSpace(ctx.Method))
			var matches []*discoveryGraphNodeMeta
			for _, node := range nodes {
				if ctx.Path != "" && node.Path == ctx.Path && hasMethod(node, method) {
					matches = append(matches, node)
				}
			}
			if len(matches) > 1 && ctx.EndpointURL != "" {
				if canonical, ok := canonicalGraphURL(ctx.EndpointURL); ok {
					if exact := nodes[discoveryGraphRouteIdentity(canonical)]; exact != nil {
						matches = []*discoveryGraphNodeMeta{exact}
					}
				}
			}
			if len(matches) == 0 && ctx.EndpointURL != "" {
				if node, _, ok := touch(ctx.EndpointURL); ok {
					matches = []*discoveryGraphNodeMeta{node}
				}
			}
			for _, node := range matches {
				node.Methods = appendUnique(node.Methods, method)
				node.Observed = true
				node.FindingCount++
				node.KindTags = appendUnique(node.KindTags, "finding")
				if rank > severityOf(node) {
					node.WorstSeverity = rankToSev[rank]
				}
			}
		}
		findingRows.Close()
	}

	// Re-project direct response evidence on every read. Evidence must cover
	// every observed logical route, not only routes that already have a semantic
	// page_profile. Otherwise a traffic-only GET /admin redirect can acquire
	// privileged-area semantics during the window before Analyzer creates its
	// profile. Bodies remain bounded by the store loader; requested identities
	// are chunked there rather than silently truncated.
	graphEvidenceHashes := make([]string, 0)
	seenGraphEvidenceHashes := make(map[string]bool)
	for _, node := range nodes {
		for _, ref := range node.EndpointRefs {
			hash := strings.TrimSpace(ref.Hash)
			if hash == "" || seenGraphEvidenceHashes[hash] {
				continue
			}
			seenGraphEvidenceHashes[hash] = true
			graphEvidenceHashes = append(graphEvidenceHashes, hash)
		}
	}
	if profileErr == nil {
		for _, profile := range graphProfiles {
			if reconprojection.IsSyntheticSummaryProfile(profile) {
				continue
			}
			method := strings.ToUpper(strings.TrimSpace(profile.Method))
			if method == "" {
				method = http.MethodGet
			}
			hash := observation.EndpointHash(method, profile.URL)
			if hash != "" && !seenGraphEvidenceHashes[hash] {
				seenGraphEvidenceHashes[hash] = true
				graphEvidenceHashes = append(graphEvidenceHashes, hash)
			}
		}
	}
	graphEvidenceEntries, evidenceErr := s.db.GetProfileEvidenceTrafficForHashes(scanID, graphEvidenceHashes)
	if evidenceErr != nil {
		jsonError(w, evidenceErr.Error(), http.StatusInternalServerError)
		return
	}
	catchAllIndex, catchAllErr := s.db.GetCatchAllIndex(scanID)
	if catchAllErr != nil {
		jsonError(w, catchAllErr.Error(), http.StatusInternalServerError)
		return
	}
	graphEvidence := make(map[string]map[string][]types.TrafficEntry)
	graphEvidenceByHash := make(map[string][]types.TrafficEntry)
	for _, entry := range graphEvidenceEntries {
		hash := strings.TrimSpace(entry.EndpointHash)
		if hash == "" {
			hash = observation.EndpointHash(entry.Request.Method, entry.Request.URL)
		}
		graphEvidenceByHash[hash] = append(graphEvidenceByHash[hash], entry)
		canonical, ok := canonicalGraphURL(entry.Request.URL)
		if !ok {
			continue
		}
		identity := discoveryGraphRouteIdentity(canonical)
		method := strings.ToUpper(strings.TrimSpace(entry.Request.Method))
		if method == "" {
			method = http.MethodGet
		}
		if graphEvidence[identity] == nil {
			graphEvidence[identity] = make(map[string][]types.TrafficEntry)
		}
		graphEvidence[identity][method] = append(graphEvidence[identity][method], entry)
	}
	if profileErr == nil {
		reconprojection.AnnotateProfiles(graphProfiles, graphEvidenceEntries)
		for i := range graphProfiles {
			reconprojection.ApplyCatchAllCeiling(&graphProfiles[i], catchAllIndex)
			method := strings.ToUpper(strings.TrimSpace(graphProfiles[i].Method))
			if method == "" {
				method = http.MethodGet
			}
			hash := observation.EndpointHash(method, graphProfiles[i].URL)
			reconprojection.ApplyQueryVariantCeiling(&graphProfiles[i], graphEvidenceByHash[hash], catchAllIndex)
			profile := graphProfiles[i]
			if strings.HasSuffix(strings.ToLower(strings.TrimSpace(profile.EvidenceState)), "_unverified") || len(profile.Issues) == 0 {
				continue
			}
			if canonical, ok := canonicalGraphURL(profile.URL); ok {
				if node := nodes[discoveryGraphRouteIdentity(canonical)]; node != nil {
					node.HasIssues = true
				}
			}
		}
	}

	for _, node := range nodes {
		byMethod := graphEvidence[node.URL]
		for method := range byMethod {
			node.Methods = appendUnique(node.Methods, method)
		}
		cleanMethods := node.Methods[:0]
		for _, method := range node.Methods {
			if method != "" {
				cleanMethods = append(cleanMethods, method)
			}
		}
		node.Methods = cleanMethods
		sort.Strings(node.Methods)
		if node.Methods == nil {
			node.Methods = []string{}
		}
		sort.Slice(node.EndpointRefs, func(i, j int) bool {
			if node.EndpointRefs[i].Method == node.EndpointRefs[j].Method {
				return node.EndpointRefs[i].Hash < node.EndpointRefs[j].Hash
			}
			return node.EndpointRefs[i].Method < node.EndpointRefs[j].Method
		})
		if node.EndpointRefs == nil {
			node.EndpointRefs = []discoveryGraphEndpointRef{}
		}
		sort.Strings(node.ProfileIDs)
		if node.ProfileIDs == nil {
			node.ProfileIDs = []string{}
		}
		sort.Strings(node.KindTags)
		if node.KindTags == nil {
			node.KindTags = []string{}
		}
		sort.Strings(node.QueryKeys)
		sort.Strings(node.URLSamples)
		node.Label = discoveryGraphRouteLabel(node)
		lower := strings.ToLower(node.Path)
		for _, token := range []string{"/admin", "/api/", "/auth", "/login", "/signup", "/settings", "/account", "/upload", "/graphql", "/webhook", "/.well-known"} {
			if strings.Contains(lower, token) {
				node.Interesting = true
				break
			}
		}
		node.FunctionalArea, node.AreaPriority = extract.ClassifyFunctionalArea(node.Path)
		if len(node.Methods) == 0 {
			node.EvidenceState = "response_unverified"
			node.EvidenceNote = "No direct HTTP response was captured for this discovered route. Route existence, access, purpose, and business semantics are unverified."
			node.FunctionalArea = "unverified"
			node.AreaPriority = 0
			node.Interesting = node.FindingCount > 0
			node.HasIssues = false
			node.KindTags = appendUnique(node.KindTags, "route-unverified")
			sort.Strings(node.KindTags)
		} else {
			allUnverified, anyUnverified, anyContent, anyQueryMixed := true, false, false, false
			allStatuses := make(map[int]bool)
			allLocations := make(map[string]bool)
			for _, method := range node.Methods {
				variant := reconprojection.SummarizeQueryVariantEvidence(method, node.URL, byMethod[method], catchAllIndex)
				state, note := variant.State, variant.Note
				statuses := variant.ObservedStatuses
				locations := variant.RedirectLocations
				methodHasContent := variant.ContentVariants > 0
				methodHasUnverified := variant.UnverifiedVariants > 0
				if variant.Variants == 0 {
					projection := types.PageProfile{URL: node.URL, Method: method}
					annotateProfileRedirectEvidence(&projection, nil)
					state, note = projection.EvidenceState, projection.EvidenceNote
					statuses, locations = projection.ObservedStatuses, projection.RedirectLocations
					methodHasUnverified = true
				}
				state = strings.ToLower(strings.TrimSpace(state))
				allUnverified = allUnverified && !methodHasContent
				anyUnverified = anyUnverified || methodHasUnverified
				anyContent = anyContent || methodHasContent
				anyQueryMixed = anyQueryMixed || (methodHasContent && methodHasUnverified)
				for _, status := range statuses {
					allStatuses[status] = true
				}
				for _, location := range locations {
					allLocations[location] = true
				}
				node.MethodEvidence = append(node.MethodEvidence, discoveryGraphMethodEvidence{
					Method: method, State: state, Note: note,
					ObservedStatuses: append([]int(nil), statuses...), RedirectLocations: append([]string(nil), locations...),
					QueryVariants: variant.Variants, ContentVariants: variant.ContentVariants,
					UnverifiedVariants: variant.UnverifiedVariants, VariantStates: append([]reconprojection.VariantStateCount(nil), variant.States...),
				})
			}
			for status := range allStatuses {
				node.ObservedStatuses = append(node.ObservedStatuses, status)
			}
			for location := range allLocations {
				node.RedirectLocations = append(node.RedirectLocations, location)
			}
			sort.Ints(node.ObservedStatuses)
			sort.Strings(node.RedirectLocations)

			if anyQueryMixed && len(node.Methods) == 1 {
				node.EvidenceState = "query_mixed_unverified"
				node.EvidenceNote = node.MethodEvidence[0].Note
				node.FunctionalArea = "mixed_evidence"
				node.AreaPriority = 0
				node.Interesting = node.FindingCount > 0
				node.HasIssues = false
				node.KindTags = appendUnique(node.KindTags, "query-mixed")
			} else if allUnverified {
				node.EvidenceState = "response_unverified"
				for _, evidence := range node.MethodEvidence {
					if evidence.State == "query_mixed_unverified" {
						node.EvidenceState = "query_mixed_unverified"
						break
					}
					if evidence.State == "auth_gate_unverified" {
						node.EvidenceState = "auth_gate_unverified"
						break
					}
					if evidence.State == "redirect_only_unverified" {
						node.EvidenceState = "redirect_only_unverified"
					}
				}
				if len(node.MethodEvidence) == 1 {
					node.EvidenceNote = node.MethodEvidence[0].Note
				} else {
					node.EvidenceNote = "Every observed HTTP method remains unverified; method semantics were evaluated separately and were not transferred across the logical route."
				}
				// Keep the observation as a route, but never visually promote the
				// unproved path-name semantics into a privileged/security area.
				if node.EvidenceState == "query_mixed_unverified" {
					node.FunctionalArea = "mixed_evidence"
				} else if node.EvidenceState == "response_unverified" {
					node.FunctionalArea = "unverified"
				} else {
					node.FunctionalArea = "redirect_unverified"
				}
				node.AreaPriority = 0
				node.Interesting = node.FindingCount > 0
				node.HasIssues = false
				node.KindTags = appendUnique(node.KindTags, "route-unverified")
			} else if anyUnverified && anyContent {
				node.EvidenceState = "method_mixed"
				node.EvidenceNote = "Direct evidence differs by HTTP method. Content observed for one method does not verify the purpose, access model, or response of another method."
				node.FunctionalArea = "mixed_evidence"
				node.AreaPriority = 0
				node.KindTags = appendUnique(node.KindTags, "method-mixed")
			} else if anyContent {
				node.EvidenceState = "content_observed"
			}
			sort.Strings(node.KindTags)
		}
	}
	sort.Slice(edgesOut, func(i, j int) bool {
		left, right := edgesOut[i], edgesOut[j]
		if left.Target != right.Target {
			return left.Target < right.Target
		}
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		if left.Type != right.Type {
			return left.Type < right.Type
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.Method < right.Method
	})

	nodesOut := make([]*discoveryGraphNodeMeta, 0, len(nodes))
	externalHosts := make(map[string]bool)
	inScopeNodeCount := 0
	for _, node := range nodes {
		nodesOut = append(nodesOut, node)
		if node.InScope {
			inScopeNodeCount++
		} else if parsed, parseErr := url.Parse(node.URL); parseErr == nil && parsed.Host != "" {
			externalHosts[parsed.Scheme+"://"+parsed.Host] = true
		}
	}
	sort.Slice(nodesOut, func(i, j int) bool { return nodesOut[i].URL < nodesOut[j].URL })
	allNodeCount := len(nodesOut)
	allEdgeCount := len(edgesOut)
	if originsOnly {
		targetRoot, _ := targetresolver.RegistrableDomain(scanTarget)
		targetOrigin := ""
		if canonical, ok := canonicalGraphURL(scanTarget); ok {
			if parsed, parseErr := url.Parse(canonical); parseErr == nil {
				targetOrigin = parsed.Scheme + "://" + parsed.Host
			}
		}
		type originAccumulator struct {
			discoveryGraphOriginOut
			endpointSet map[string]bool
			profileSet  map[string]bool
		}
		origins := make(map[string]*originAccumulator)
		for _, node := range nodesOut {
			parsed, parseErr := url.Parse(node.URL)
			if parseErr != nil || parsed.Hostname() == "" {
				continue
			}
			origin := parsed.Scheme + "://" + parsed.Host
			item := origins[origin]
			if item == nil {
				nodeRoot, _ := targetresolver.RegistrableDomain(node.URL)
				firstParty := targetRoot != "" && strings.EqualFold(nodeRoot, targetRoot)
				hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
				item = &originAccumulator{
					discoveryGraphOriginOut: discoveryGraphOriginOut{
						Origin: origin, Host: parsed.Host, Hostname: hostname,
						FirstParty: firstParty,
						Subdomain:  firstParty && !strings.EqualFold(hostname, targetRoot) && !strings.EqualFold(hostname, "www."+targetRoot),
						Target:     strings.EqualFold(origin, targetOrigin),
					},
					endpointSet: make(map[string]bool), profileSet: make(map[string]bool),
				}
				origins[origin] = item
			}
			item.URLs++
			item.InScope = item.InScope || node.InScope
			if node.Observed {
				item.Observed++
			}
			if node.IsAnalyzed {
				item.Analyzed++
			}
			item.Findings += node.FindingCount
			for _, ref := range node.EndpointRefs {
				if ref.Hash != "" {
					item.endpointSet[ref.Hash+"\x00"+ref.Method] = true
				}
			}
			for _, profileID := range node.ProfileIDs {
				if profileID != "" {
					item.profileSet[profileID] = true
				}
			}
			for _, method := range node.Methods {
				item.Methods = appendUnique(item.Methods, method)
			}
			for _, tag := range node.KindTags {
				item.KindTags = appendUnique(item.KindTags, tag)
				if tag == "api-call" {
					item.APINodes++
				}
			}
			if discoveryGraphAuthPath(node.Path) {
				item.AuthNodes++
			}
			if sevRank[strings.ToLower(node.WorstSeverity)] > sevRank[strings.ToLower(item.WorstSeverity)] {
				item.WorstSeverity = node.WorstSeverity
			}
		}
		// A blocked browser dependency is still valuable Recon evidence. It is
		// not target surface and must never be promoted into scope, but hiding it
		// makes JS-shell applications look mysteriously empty. Preserve the
		// exact canonical origin from the policy audit as a boundary-only card.
		boundaryRows, boundaryErr := s.db.Conn().Query(`
			SELECT metadata_json
			FROM narrations
			WHERE scan_id=? AND agent='policy' AND action='denied'
			ORDER BY id ASC
			LIMIT 200`, scanID)
		if boundaryErr == nil {
			for boundaryRows.Next() {
				var raw string
				if boundaryRows.Scan(&raw) != nil {
					continue
				}
				var meta map[string]any
				if json.Unmarshal([]byte(raw), &meta) != nil {
					continue
				}
				canonical, _ := meta["canonical_origin"].(string)
				canonicalURL, canonicalOK := canonicalGraphURL(strings.TrimSpace(canonical))
				parsed, parseErr := url.Parse(canonicalURL)
				if !canonicalOK || parseErr != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
					continue
				}
				// Chrome's update, autofill, safe-browsing, and account services
				// are scanner environment noise, not application dependencies.
				// Preserve every other denied origin as a truthful scope boundary.
				if scanproxy.IsBrowserInternalHost(parsed.Hostname()) {
					continue
				}
				origin := parsed.Scheme + "://" + parsed.Host
				if origins[origin] != nil {
					origins[origin].KindTags = appendUnique(origins[origin].KindTags, "policy-boundary")
					continue
				}
				nodeRoot, _ := targetresolver.RegistrableDomain(origin)
				firstParty := targetRoot != "" && strings.EqualFold(nodeRoot, targetRoot)
				hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
				origins[origin] = &originAccumulator{
					discoveryGraphOriginOut: discoveryGraphOriginOut{
						Origin: origin, Host: parsed.Host, Hostname: hostname,
						FirstParty: firstParty,
						Subdomain:  firstParty && !strings.EqualFold(hostname, targetRoot) && !strings.EqualFold(hostname, "www."+targetRoot),
						KindTags:   []string{"policy-boundary"},
					},
					endpointSet: make(map[string]bool), profileSet: make(map[string]bool),
				}
			}
			_ = boundaryRows.Close()
		}
		out := make([]discoveryGraphOriginOut, 0, len(origins))
		originStats := map[string]int{"origin_count": len(origins)}
		for _, item := range origins {
			item.EndpointRefs = len(item.endpointSet)
			item.Profiles = len(item.profileSet)
			sort.Strings(item.Methods)
			sort.Strings(item.KindTags)
			if item.InScope {
				originStats["in_scope_origins"]++
			}
			if item.FirstParty {
				originStats["first_party_origins"]++
				if !item.InScope {
					originStats["linked_only_first_party"]++
				}
			} else {
				originStats["external_origins"]++
			}
			if item.Subdomain {
				originStats["first_party_subdomains"]++
			}
			out = append(out, item.discoveryGraphOriginOut)
		}
		sort.Slice(out, func(i, j int) bool {
			left, right := out[i], out[j]
			leftRank, rightRank := 4, 4
			switch {
			case left.Target:
				leftRank = 0
			case left.InScope && left.FirstParty:
				leftRank = 1
			case left.FirstParty:
				leftRank = 2
			case left.InScope:
				leftRank = 3
			}
			switch {
			case right.Target:
				rightRank = 0
			case right.InScope && right.FirstParty:
				rightRank = 1
			case right.FirstParty:
				rightRank = 2
			case right.InScope:
				rightRank = 3
			}
			if leftRank != rightRank {
				return leftRank < rightRank
			}
			if left.Observed != right.Observed {
				return left.Observed > right.Observed
			}
			return left.Origin < right.Origin
		})
		jsonResponse(w, map[string]any{
			"schema_version": discoveryGraphSchemaVersion,
			"origins_only":   true,
			"origins":        out,
			"stats":          originStats,
		})
		return
	}
	if inScopeOnly {
		keep := make(map[string]bool, inScopeNodeCount)
		filteredNodes := make([]*discoveryGraphNodeMeta, 0, inScopeNodeCount)
		for _, node := range nodesOut {
			if node.InScope {
				keep[node.URL] = true
				filteredNodes = append(filteredNodes, node)
			}
		}
		nodesOut = filteredNodes
		filteredEdges := make([]discoveryGraphEdgeOut, 0, len(edgesOut))
		for _, edge := range edgesOut {
			if keep[edge.Target] && (edge.Source == "" || keep[edge.Source]) {
				filteredEdges = append(filteredEdges, edge)
			}
		}
		edgesOut = filteredEdges
	}
	totalNodes := len(nodesOut)
	totalEdges := len(edgesOut)
	stats := map[string]int{
		"node_count": totalNodes, "edge_count": totalEdges,
		"total_nodes": totalNodes, "total_edges": totalEdges,
		"all_nodes": allNodeCount, "all_edges": allEdgeCount,
		"in_scope_nodes": inScopeNodeCount,
		"external_nodes": allNodeCount - inScopeNodeCount,
		"external_hosts": len(externalHosts), "trimmed": 0,
	}
	if statsOnly {
		jsonResponse(w, map[string]any{
			"schema_version": discoveryGraphSchemaVersion,
			"nodes":          []*discoveryGraphNodeMeta{}, "edges": []discoveryGraphEdgeOut{},
			"stats_only": true, "stats": stats,
			"page": discoveryGraphPage{Total: totalNodes},
		})
		return
	}

	score := func(node *discoveryGraphNodeMeta) int {
		score := 0
		if node.InScope {
			score += 2000
		}
		for _, tag := range node.KindTags {
			if tag == "seed" {
				score += 1000
				break
			}
		}
		if node.WorstSeverity != "" {
			score += 750
		} else if node.HasIssues {
			score += 500
		}
		if node.Interesting {
			score += 200
		}
		score += node.HitCount
		if node.IsAnalyzed {
			score += 10
		}
		return score
	}
	if len(nodesOut) > maxNodes {
		sort.SliceStable(nodesOut, func(i, j int) bool {
			left, right := score(nodesOut[i]), score(nodesOut[j])
			if left == right {
				return nodesOut[i].URL < nodesOut[j].URL
			}
			return left > right
		})
		nodesOut = nodesOut[:maxNodes]
		keep := make(map[string]bool, len(nodesOut))
		for _, node := range nodesOut {
			keep[node.URL] = true
		}
		filteredEdges := edgesOut[:0]
		for _, edge := range edgesOut {
			if keep[edge.Target] && (edge.Source == "" || keep[edge.Source]) {
				filteredEdges = append(filteredEdges, edge)
			}
		}
		edgesOut = filteredEdges
	}
	trimmed := totalNodes > len(nodesOut)
	page := discoveryGraphPage{Offset: 0, Limit: len(nodesOut), Returned: len(nodesOut), Total: len(nodesOut)}
	if pageSize > 0 {
		pageTotal := len(nodesOut)
		start := pageOffset
		if start > pageTotal {
			start = pageTotal
		}
		end := start + pageSize
		if end > pageTotal {
			end = pageTotal
		}
		nodesOut = nodesOut[start:end]
		keepTargets := make(map[string]bool, len(nodesOut))
		for _, node := range nodesOut {
			keepTargets[node.URL] = true
		}
		pagedEdges := make([]discoveryGraphEdgeOut, 0, len(edgesOut))
		for _, edge := range edgesOut {
			// An edge belongs to the page containing its target. Its source may
			// arrive on a later page; clients merge pages by canonical URL.
			if keepTargets[edge.Target] {
				pagedEdges = append(pagedEdges, edge)
			}
		}
		edgesOut = pagedEdges
		page = discoveryGraphPage{
			Offset: start, Limit: pageSize, Returned: len(nodesOut), Total: pageTotal,
			HasMore: end < pageTotal,
		}
		if page.HasMore {
			page.NextOffset = end
		}
	}
	stats["node_count"] = len(nodesOut)
	stats["edge_count"] = len(edgesOut)
	stats["trimmed"] = boolToInt(trimmed)
	stats["paged"] = boolToInt(pageSize > 0)
	jsonResponse(w, map[string]any{
		"schema_version": discoveryGraphSchemaVersion,
		"nodes":          nodesOut, "edges": edgesOut, "stats": stats, "page": page,
	})
}

// boolToInt flattens a bool to 0/1 for JSON consumption by consumers that
// don't want to deal with a mixed-type stat map.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// appendUnique adds s to list only if it isn't already there.
func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Conn().Query(`
		SELECT id, target, status, started_at, finished_at, config_json
		FROM scans ORDER BY id DESC`)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var scans []map[string]any
	for rows.Next() {
		var id int64
		var target, status, startedAt, configJSON string
		var finishedAt *string
		rows.Scan(&id, &target, &status, &startedAt, &finishedAt, &configJSON)
		fin := ""
		if finishedAt != nil {
			fin = *finishedAt
		}
		scans = append(scans, map[string]any{
			"id": id, "target": target, "status": status,
			"started_at": startedAt, "finished_at": fin,
			"testing_authority": testingAuthorityFromConfig(configJSON),
		})
	}
	jsonResponse(w, scans)
}

func (s *Server) handleSurface(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	queryRoutes := s.reconQueryRoutes(scanID)
	clientRoutes := s.reconClientRoutes(scanID)

	// Get the attack surface data from the profile
	var issuesJSON string
	err := s.db.Conn().QueryRow(`
		SELECT issues FROM page_profiles
		WHERE scan_id = ? AND id = 'attack_surface'`, scanID,
	).Scan(&issuesJSON)
	if err != nil {
		jsonResponse(w, map[string]any{"inputs": nil, "summary": nil, "query_routes": queryRoutes, "client_routes": clientRoutes})
		return
	}

	// Parse the stored attack surface
	var surface map[string]any
	if json.Unmarshal([]byte(issuesJSON), &surface) == nil {
		surface["query_routes"] = queryRoutes
		surface["client_routes"] = clientRoutes
		jsonResponse(w, surface)
		return
	}

	jsonResponse(w, map[string]any{"inputs": nil, "summary": nil, "query_routes": queryRoutes, "client_routes": clientRoutes})
}

type reconQueryRoute struct {
	Path         string `json:"path"`
	Parameter    string `json:"parameter"`
	Label        string `json:"label"`
	Status       int    `json:"status"`
	Observations int    `json:"observations"`
	Aliases      int    `json:"aliases,omitempty"`
	ResponseKind string `json:"response_kind"`
	ShapeID      string `json:"shape_id"`
	EvidenceID   int64  `json:"evidence_id,omitempty"`
}

// reconQueryRoutes surfaces applications whose real page router lives in a
// query parameter (for example index.jsp?content=inside_jobs.htm). Candidate
// bodies are bounded before parsing; repeated captures and response-equivalent
// aliases are collapsed. The raw query value is never returned to the UI.
func (s *Server) reconQueryRoutes(scanID int64) []reconQueryRoute {
	views := s.reconQueryRouteViews(scanID)
	out := make([]reconQueryRoute, 0, len(views))
	for _, view := range views {
		var evidenceID int64
		if len(view.TrafficIDs) > 0 {
			evidenceID = view.TrafficIDs[0]
		}
		out = append(out, reconQueryRoute{
			Path: view.Path, Parameter: view.Parameter, Label: view.Label,
			Status: view.Status, Observations: view.Observations, Aliases: view.Aliases,
			ResponseKind: view.ResponseKind, ShapeID: view.ShapeID, EvidenceID: evidenceID,
		})
	}
	return out
}

func (s *Server) reconQueryRouteViews(scanID int64) []extract.QueryRoutedView {
	entries, err := s.db.GetQueryRouteCandidates(scanID, 160, 192*1024)
	if err != nil {
		return nil
	}
	return extract.DiscoverQueryRoutedViews(entries, 12)
}

func safeReconRouteLabel(value string) (string, bool) {
	return extract.SafeQueryRouteLabel(value)
}

type reconClientRoute struct {
	Label        string `json:"label"`
	URL          string `json:"url"`
	Route        string `json:"route"`
	Observations int    `json:"observations"`
	EvidenceID   int64  `json:"evidence_id,omitempty"`
}

func (s *Server) reconClientRouteViews(scanID int64) []extract.ClientRoutedView {
	discoveries, err := s.db.GetVisitedClientRoutes(scanID, 80)
	if err != nil {
		return nil
	}
	evidence := make([]extract.ClientRouteEvidence, 0, len(discoveries))
	for _, discovery := range discoveries {
		evidence = append(evidence, extract.ClientRouteEvidence{ID: discovery.ID, URL: discovery.TargetURL})
	}
	return extract.DiscoverVisitedClientRoutes(evidence, 16)
}

func (s *Server) reconClientRoutes(scanID int64) []reconClientRoute {
	views := s.reconClientRouteViews(scanID)
	out := make([]reconClientRoute, 0, len(views))
	for _, view := range views {
		var evidenceID int64
		if len(view.DiscoveryIDs) > 0 {
			evidenceID = view.DiscoveryIDs[0]
		}
		out = append(out, reconClientRoute{
			Label: view.Label, URL: view.URL, Route: view.Route,
			Observations: view.Observations, EvidenceID: evidenceID,
		})
	}
	return out
}

func (s *Server) handleUnderstanding(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	appType, templatesJSON, areasJSON, _, summary, _ := s.db.GetAppUnderstanding(scanID)
	reconJSON, _ := s.db.GetReconModel(scanID)
	routeViews := s.reconQueryRouteViews(scanID)
	clientViews := s.reconClientRouteViews(scanID)
	var reconModel extract.ReconModel
	access := s.reconAccessState(scanID, 0)
	if json.Unmarshal([]byte(reconJSON), &reconModel) == nil {
		u := extract.NewAppUnderstanding()
		u.AppType = appType
		u.Summary = summary
		u.Recon = reconModel
		u.NormalizeReconModel()
		// Retrofit response-backed router views at read time so completed scans
		// benefit immediately; new scans also receive these cards before the
		// terminal synthesis pass in AnalyzerAgent.
		u.RefreshQueryRoutedPagePurposeCards(routeViews)
		u.RefreshClientRoutedPagePurposeCards(clientViews)
		u.NormalizeReconModel()
		access = s.reconAccessState(scanID, len(u.Recon.Pages))
		u.ApplyReconAccessCeiling(access["state"])
		// Reconcile persisted semantic prose with today's direct redirect
		// evidence before serving historical scans. This is deliberately a
		// read-time projection: no stored model is rewritten or lost.
		s.projectUnderstandingRedirectEvidence(scanID, u)
		// The compact top-level fields power the hero and sidebar while the
		// nested Recon identity powers Target DNA. Return one normalized truth;
		// otherwise a saved generic "other" label can contradict a correctly
		// normalized community/documentation identity in the same response.
		appType = u.Recon.Identity.AppType
		if strings.TrimSpace(u.Recon.Identity.Summary) != "" {
			summary = u.Recon.Identity.Summary
		}
		reconJSON = u.ReconJSON()
	}

	jsonResponse(w, map[string]any{
		"app_type":          appType,
		"templates":         json.RawMessage(templatesJSON),
		"areas":             json.RawMessage(areasJSON),
		"summary":           summary,
		"recon":             json.RawMessage(reconJSON),
		"evidence_ceiling":  s.reconEvidenceCeiling(scanID),
		"discovery_quality": s.reconDiscoveryQualityWithViews(scanID, routeViews, clientViews),
		"access":            access,
	})
}

type reconDiscoveryQuality struct {
	Profiles          int            `json:"profiles"`
	SemanticSurfaces  []string       `json:"semantic_surfaces"`
	SurfaceCounts     map[string]int `json:"surface_counts"`
	ResponseTemplates int            `json:"response_templates"`
	DominantSurface   string         `json:"dominant_surface,omitempty"`
	Spread            string         `json:"spread"`
}

// reconDiscoveryQuality summarizes how diverse the captured application
// evidence is. It does not infer unvisited behavior: semantic surfaces come
// from persisted profiles plus response-backed query-routed views, and shape
// counts come from stored templates plus the routed response classifier. The
// UI uses this to explain whether a model is broad or account/help-heavy
// without displaying another raw inventory.
func (s *Server) reconDiscoveryQuality(scanID int64) reconDiscoveryQuality {
	return s.reconDiscoveryQualityWithViews(scanID, s.reconQueryRouteViews(scanID), s.reconClientRouteViews(scanID))
}

func (s *Server) reconDiscoveryQualityWithViews(scanID int64, routeViews []extract.QueryRoutedView, clientViews []extract.ClientRoutedView) reconDiscoveryQuality {
	quality := reconDiscoveryQuality{SurfaceCounts: make(map[string]int), Spread: "forming"}
	templates := make(map[string]struct{})
	profiles, err := s.db.GetAllProfiles(scanID)
	if err != nil {
		return quality
	}
	s.annotateProfilesWithEvidence(scanID, profiles)
	// GetAllProfiles is optimized for the Knowledge list, not canonical URL
	// deduplication. Prefer the richest/highest-confidence representative so a
	// low-confidence alias cannot hide the real response template or purpose.
	sort.SliceStable(profiles, func(i, j int) bool {
		if profiles[i].Confidence != profiles[j].Confidence {
			return profiles[i].Confidence > profiles[j].Confidence
		}
		if len(strings.TrimSpace(profiles[i].Purpose)) != len(strings.TrimSpace(profiles[j].Purpose)) {
			return len(strings.TrimSpace(profiles[i].Purpose)) > len(strings.TrimSpace(profiles[j].Purpose))
		}
		if (profiles[i].TemplateID != "") != (profiles[j].TemplateID != "") {
			return profiles[i].TemplateID != ""
		}
		return profiles[i].ID < profiles[j].ID
	})
	seenURLs := make(map[string]struct{})
	for _, profile := range profiles {
		if profile.ID == "attack_surface" || profile.ID == "js_discovered_routes" {
			continue
		}
		canonical, ok := canonicalGraphURL(profile.URL)
		if !ok {
			canonical = strings.TrimSpace(profile.URL)
		}
		if _, duplicate := seenURLs[canonical]; duplicate {
			continue
		}
		seenURLs[canonical] = struct{}{}
		quality.Profiles++
		// A route name, login/error shell, empty 200, or negative response is not
		// an application surface. Keep it in the profile count as an observation,
		// but only substantive direct content may influence semantic diversity.
		if profile.EvidenceState != "content_observed" {
			continue
		}
		if family := targetresolver.SurfaceFamily(profile.URL, profile.Purpose); family != "" {
			quality.SurfaceCounts[family]++
		}
		if templateID := strings.TrimSpace(profile.TemplateID); templateID != "" {
			templates[templateID] = struct{}{}
		}
	}
	for _, view := range routeViews {
		if shape := strings.TrimSpace(view.ShapeID); shape != "" {
			templates["query-route:"+shape] = struct{}{}
		}
		if family := targetresolver.SurfaceFamily(view.URL, view.Label); family != "" {
			quality.SurfaceCounts[family]++
		}
	}
	for _, view := range clientViews {
		if family := targetresolver.SurfaceFamily(view.URL, view.Label); family != "" {
			quality.SurfaceCounts[family]++
		}
	}
	quality.ResponseTemplates = len(templates)
	for family, count := range quality.SurfaceCounts {
		quality.SemanticSurfaces = append(quality.SemanticSurfaces, family)
		if count > quality.SurfaceCounts[quality.DominantSurface] ||
			(count == quality.SurfaceCounts[quality.DominantSurface] && family < quality.DominantSurface) {
			quality.DominantSurface = family
		}
	}
	sort.Strings(quality.SemanticSurfaces)
	switch len(quality.SemanticSurfaces) {
	case 0, 1:
		quality.Spread = "narrow"
	case 2, 3:
		quality.Spread = "developing"
	default:
		quality.Spread = "broad"
	}
	return quality
}

func (s *Server) reconAccessState(scanID int64, modeledPages int) map[string]string {
	var successfulHTML, rateLimited, accessDenied, observedURLs, discoveries int
	_ = s.db.Conn().QueryRow(`
		SELECT COALESCE(SUM(CASE WHEN status_code BETWEEN 200 AND 399 AND content_type LIKE 'text/html%' AND is_interstitial=FALSE THEN 1 ELSE 0 END),0),
		       COALESCE(SUM(CASE WHEN status_code=429 THEN 1 ELSE 0 END),0),
		       COALESCE(SUM(CASE WHEN status_code IN (401,403) THEN 1 ELSE 0 END),0),
		       COUNT(DISTINCT url)
		FROM traffic WHERE scan_id=? AND is_filtered=0`, scanID).
		Scan(&successfulHTML, &rateLimited, &accessDenied, &observedURLs)
	_ = s.db.Conn().QueryRow(`SELECT COUNT(DISTINCT target_url) FROM url_discoveries WHERE scan_id=?`, scanID).Scan(&discoveries)
	protectionEvidence, _ := s.db.GetProtectionEvidenceSummary(scanID)
	switch {
	case successfulHTML > 0 && observedURLs <= 1 && discoveries <= 1 && modeledPages <= 1:
		return map[string]string{
			"state": "limited", "label": "limited capture",
			"detail": "Only one rendered target page was captured. Dependency, rendering, or scope boundaries prevented representative route coverage.",
		}
	case successfulHTML > 0:
		return map[string]string{"state": "available", "label": "target available"}
	case protectionEvidence.InterstitialResponses > 0:
		vendor := "browser/WAF"
		if len(protectionEvidence.Vendors) > 0 {
			vendor = strings.Join(protectionEvidence.Vendors, ", ")
		}
		return map[string]string{
			"state": "protected", "label": "protection interstitial",
			"detail": fmt.Sprintf("Captured %d %s protection response(s) across %d stable shape(s), but no representative application page was recovered.", protectionEvidence.InterstitialResponses, vendor, protectionEvidence.DistinctShapes),
		}
	case rateLimited > 0:
		return map[string]string{"state": "rate_limited", "label": "rate limited", "detail": "The target returned HTTP 429, so the model is intentionally capped by unavailable evidence."}
	case accessDenied > 0:
		return map[string]string{"state": "blocked", "label": "access blocked", "detail": "The target returned an access-denied response, so application claims remain intentionally sparse."}
	default:
		return map[string]string{"state": "unavailable", "label": "evidence unavailable", "detail": "No successful target HTML was captured; the scanner will not infer a complete application model."}
	}
}

func (s *Server) reconEvidenceCeiling(scanID int64) map[string]bool {
	var authenticated, stateChanging int
	_ = s.db.Conn().QueryRow(`
		SELECT EXISTS(SELECT 1 FROM narrations WHERE scan_id=?1 AND agent='auth' AND action IN ('success','api_login_success')),
		       EXISTS(SELECT 1 FROM traffic WHERE scan_id=?1 AND is_filtered=0 AND method IN ('POST','PUT','PATCH','DELETE'))`, scanID).
		Scan(&authenticated, &stateChanging)
	return map[string]bool{
		"authenticated_request_observed":  authenticated == 1,
		"state_changing_request_observed": stateChanging == 1,
	}
}

// handleReconGraph projects the semantic recon model into a graph designed
// for operators: actors use workflows, workflows touch pages, pages operate
// on business objects, and ownership rules connect actors to those objects.
// It complements (rather than replaces) the discovery URL graph.
func (s *Server) handleReconGraph(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	raw, _ := s.db.GetReconModel(scanID)
	var model extract.ReconModel
	if err := json.Unmarshal([]byte(raw), &model); err != nil {
		jsonError(w, "invalid recon model", http.StatusInternalServerError)
		return
	}
	u := extract.NewAppUnderstanding()
	if appType, _, _, _, summary, err := s.db.GetAppUnderstanding(scanID); err == nil {
		u.AppType = appType
		u.Summary = summary
	}
	u.Recon = model
	u.NormalizeReconModel()
	u.RefreshQueryRoutedPagePurposeCards(s.reconQueryRouteViews(scanID))
	u.RefreshClientRoutedPagePurposeCards(s.reconClientRouteViews(scanID))
	u.NormalizeReconModel()
	access := s.reconAccessState(scanID, len(u.Recon.Pages))
	u.ApplyReconAccessCeiling(access["state"])
	// The semantic Graph is another explanation of the same application model,
	// so it must obey the same direct-response ceiling as Recon, Knowledge, and
	// Target Brain. A saved /admin guess backed only by a redirect/404/shell may
	// remain as an unverified page observation, but cannot create roles,
	// workflows, objects, or trust-boundary edges here.
	s.projectUnderstandingRedirectEvidence(scanID, u)
	model = u.Recon

	type node struct {
		ID            string  `json:"id"`
		Kind          string  `json:"kind"`
		Label         string  `json:"label"`
		Subtitle      string  `json:"subtitle,omitempty"`
		Confidence    float64 `json:"confidence,omitempty"`
		ProfileID     string  `json:"profile_id,omitempty"`
		Priority      int     `json:"priority,omitempty"`
		EvidenceCount int     `json:"evidence_count,omitempty"`
	}
	type edge struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Kind   string `json:"kind"`
		Label  string `json:"label,omitempty"`
	}

	nodes := make([]node, 0)
	edges := make([]edge, 0)
	seenNode := map[string]bool{}
	seenEdge := map[string]bool{}
	addNode := func(n node) {
		if n.ID == "" || seenNode[n.ID] {
			return
		}
		seenNode[n.ID] = true
		nodes = append(nodes, n)
	}
	addEdge := func(e edge) {
		if e.Source == "" || e.Target == "" || e.Source == e.Target {
			return
		}
		key := e.Source + "\x00" + e.Target + "\x00" + e.Kind
		if seenEdge[key] {
			return
		}
		seenEdge[key] = true
		edges = append(edges, e)
	}

	for _, role := range model.Roles {
		addNode(node{ID: "role:" + role.ID, Kind: "role", Label: role.Name, Subtitle: role.Description, Confidence: role.Confidence, EvidenceCount: len(role.Evidence)})
	}
	for _, object := range model.Objects {
		addNode(node{ID: "object:" + object.ID, Kind: "object", Label: object.Name, Subtitle: object.Sensitivity, Confidence: object.Confidence, EvidenceCount: len(object.Evidence)})
	}
	// The semantic graph is a decision surface, not an endpoint dump. Rank
	// grounded cards by participation in workflows/trust boundaries and show a
	// bounded set; the complete URL inventory remains in the Site Map tab.
	pageScore := map[string]int{}
	for _, workflow := range model.Workflows {
		for _, step := range workflow.Steps {
			for _, id := range step.PageIDs {
				pageScore[id] += 100
			}
		}
	}
	for _, boundary := range model.OwnershipBoundaries {
		for _, id := range boundary.EnforcedAt {
			pageScore[id] += 90
		}
	}
	for _, object := range model.Objects {
		for _, ev := range object.Evidence {
			if ev.Kind == "endpoint" {
				pageScore[ev.Ref] += 70
			}
		}
	}
	pages := append([]extract.PagePurposeCard(nil), model.Pages...)
	sort.SliceStable(pages, func(i, j int) bool {
		si := pageScore[pages[i].ID] + len(pages[i].SecurityInterest)*10
		sj := pageScore[pages[j].ID] + len(pages[j].SecurityInterest)*10
		if si != sj {
			return si > sj
		}
		if pages[i].Confidence != pages[j].Confidence {
			return pages[i].Confidence > pages[j].Confidence
		}
		return pages[i].ID < pages[j].ID
	})
	maxPages := intParam(r, "max_pages", 18)
	if maxPages < 1 {
		maxPages = 18
	}
	if len(pages) > maxPages {
		pages = pages[:maxPages]
	}
	for _, page := range pages {
		label := strings.TrimSpace(page.Purpose)
		if label == "" {
			label = page.Method + " " + page.URL
		}
		addNode(node{ID: "page:" + page.ID, Kind: "page", Label: label, Subtitle: page.Method + " " + page.URL, Confidence: page.Confidence, ProfileID: page.ID, EvidenceCount: len(page.Evidence)})
		for _, objectID := range page.ObjectIDs {
			addEdge(edge{Source: "page:" + page.ID, Target: "object:" + objectID, Kind: "operates_on", Label: "operates on"})
		}
	}
	for _, workflow := range model.Workflows {
		wid := "workflow:" + workflow.ID
		addNode(node{ID: wid, Kind: "workflow", Label: workflow.Name, Subtitle: workflow.Description, Confidence: workflow.Confidence, EvidenceCount: len(workflow.Evidence)})
		for _, step := range workflow.Steps {
			for _, roleID := range step.RoleIDs {
				addEdge(edge{Source: "role:" + roleID, Target: wid, Kind: "performs", Label: "performs"})
			}
			for _, pageID := range step.PageIDs {
				addEdge(edge{Source: wid, Target: "page:" + pageID, Kind: "step", Label: step.Label})
			}
			for _, objectID := range step.ObjectIDs {
				kind := "uses"
				if step.StateChange {
					kind = "changes"
				}
				addEdge(edge{Source: wid, Target: "object:" + objectID, Kind: kind, Label: step.Label})
			}
		}
	}
	for _, boundary := range model.OwnershipBoundaries {
		if boundary.OwnerRoleID != "" {
			addEdge(edge{Source: "role:" + boundary.OwnerRoleID, Target: "object:" + boundary.ObjectID, Kind: "owns", Label: boundary.Rule})
		}
		for _, pageID := range boundary.EnforcedAt {
			addEdge(edge{Source: "page:" + pageID, Target: "object:" + boundary.ObjectID, Kind: "enforces", Label: "authorization boundary"})
		}
	}
	for _, unknown := range model.Unknowns {
		uid := "unknown:" + unknown.ID
		addNode(node{ID: uid, Kind: "unknown", Label: unknown.Question, Subtitle: unknown.SuggestedAction, Priority: unknown.Priority, EvidenceCount: len(unknown.Evidence)})
		for _, ev := range unknown.Evidence {
			if seenNode["page:"+ev.Ref] {
				addEdge(edge{Source: "page:" + ev.Ref, Target: uid, Kind: "unknown", Label: "unanswered"})
			}
		}
	}

	jsonResponse(w, map[string]any{
		"nodes":   nodes,
		"edges":   edges,
		"metrics": model.Metrics,
		"targets": model.Targets,
	})
}

func (s *Server) handleAILog(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	limit := intParam(r, "limit", 500)

	entries, err := s.db.GetAILog(scanID, limit)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	jsonResponse(w, entries)
}

func (s *Server) handleAILogStats(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	totalIn, totalOut, totalDurationMs, callCount, totalCostUcents, err := s.db.GetAILogStats(scanID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	phaseStats, err := s.db.GetAILogPhaseStats(scanID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	jsonResponse(w, map[string]any{
		"total_tokens_in":   totalIn,
		"total_tokens_out":  totalOut,
		"total_tokens":      totalIn + totalOut,
		"total_duration_ms": totalDurationMs,
		"llm_calls":         callCount,
		"total_cost_ucents": totalCostUcents,
		"total_cost_cents":  totalCostUcents / 10_000,
		"total_cost_usd":    float64(totalCostUcents) / 1_000_000.0,
		"phase_breakdown":   phaseStats,
	})
}

type copilotModelConfig struct {
	Provider string
	Model    string
	BaseURL  string
	Source   string
}

// copilotModelFromConfig resolves the provider used by the scan. New scans
// persist provider, model, and non-secret base URL; legacy/crawl-only scans
// retain the previous local Copilot fallback.
func copilotModelFromConfig(configJSON string) copilotModelConfig {
	var persisted struct {
		Provider     string `json:"provider"`
		Model        string `json:"model"`
		BaseURL      string
		BaseURLSnake string `json:"base_url"`
		LLM          struct {
			Provider     string `json:"provider"`
			Model        string `json:"model"`
			BaseURL      string
			BaseURLSnake string `json:"base_url"`
		} `json:"llm"`
	}
	_ = json.Unmarshal([]byte(configJSON), &persisted)

	provider := strings.ToLower(strings.TrimSpace(persisted.LLM.Provider))
	model := strings.TrimSpace(persisted.LLM.Model)
	baseURL := strings.TrimSpace(persisted.LLM.BaseURL)
	if baseURL == "" {
		baseURL = strings.TrimSpace(persisted.LLM.BaseURLSnake)
	}
	if provider == "" {
		provider = strings.ToLower(strings.TrimSpace(persisted.Provider))
	}
	if model == "" {
		model = strings.TrimSpace(persisted.Model)
	}
	if baseURL == "" {
		baseURL = strings.TrimSpace(persisted.BaseURL)
	}
	if baseURL == "" {
		baseURL = strings.TrimSpace(persisted.BaseURLSnake)
	}

	source := "scan"
	if provider == "" {
		provider = "ollama"
		model = "qwen2.5:32b"
		source = "fallback"
	}
	if model == "" {
		model = defaultCopilotModel(provider, baseURL)
	}
	if provider == "openai-compatible" && baseURL == "" {
		baseURL = defaultOpenAICompatibleBaseURL(model)
	}
	return copilotModelConfig{Provider: provider, Model: model, BaseURL: baseURL, Source: source}
}

func defaultCopilotModel(provider, baseURL string) string {
	switch provider {
	case "openai":
		return "gpt-4.1-mini"
	case "anthropic":
		return "claude-sonnet-4-6-20250514"
	case "openai-compatible":
		if strings.Contains(strings.ToLower(baseURL), "z.ai") {
			return "glm-5.2"
		}
		return "MiniMax-M3"
	default:
		return "qwen2.5:32b"
	}
}

func copilotCredentialKey(provider, baseURL string) string {
	return strings.ToLower(strings.TrimSpace(provider)) + "\x00" + strings.TrimSpace(baseURL)
}

func (s *Server) rememberCopilotCredential(provider, baseURL, apiKey string) {
	if strings.TrimSpace(provider) == "" || apiKey == "" {
		return
	}
	s.copilotMu.Lock()
	defer s.copilotMu.Unlock()
	if s.copilotKeys == nil {
		s.copilotKeys = make(map[string]string)
	}
	s.copilotKeys[copilotCredentialKey(provider, baseURL)] = apiKey
}

func (s *Server) cachedCopilotCredential(provider, baseURL string) string {
	s.copilotMu.RLock()
	defer s.copilotMu.RUnlock()
	return s.copilotKeys[copilotCredentialKey(provider, baseURL)]
}

func providerNeedsAPIKey(provider string) bool {
	switch provider {
	case "openai", "anthropic", "openai-compatible":
		return true
	default:
		return false
	}
}

// resolveCopilotModel inherits the scan model unless the API caller supplied
// an explicit override. Credentials are resolved separately and never come
// from persisted config or the browser-facing scan response.
func (s *Server) resolveCopilotModel(scanID int64, providerOverride, modelOverride, baseURLOverride, apiKeyOverride string) (copilotModelConfig, string, error) {
	var configJSON string
	if err := s.db.Conn().QueryRow(`SELECT config_json FROM scans WHERE id = ?`, scanID).Scan(&configJSON); err != nil {
		return copilotModelConfig{}, "", fmt.Errorf("load scan model: %w", err)
	}
	modelConfig := copilotModelFromConfig(configJSON)
	if strings.TrimSpace(providerOverride) != "" {
		modelConfig.Provider = strings.ToLower(strings.TrimSpace(providerOverride))
		modelConfig.Source = "request"
	}
	if strings.TrimSpace(modelOverride) != "" {
		modelConfig.Model = strings.TrimSpace(modelOverride)
		modelConfig.Source = "request"
	}
	if strings.TrimSpace(baseURLOverride) != "" {
		modelConfig.BaseURL = strings.TrimSpace(baseURLOverride)
		modelConfig.Source = "request"
	}
	if modelConfig.Model == "" {
		modelConfig.Model = defaultCopilotModel(modelConfig.Provider, modelConfig.BaseURL)
	}
	if modelConfig.Provider == "openai-compatible" && modelConfig.BaseURL == "" {
		modelConfig.BaseURL = defaultOpenAICompatibleBaseURL(modelConfig.Model)
	}

	apiKey := apiKeyOverride
	if apiKey == "" {
		apiKey = s.cachedCopilotCredential(modelConfig.Provider, modelConfig.BaseURL)
	}
	if apiKey == "" {
		loadUIDotEnvLocal(".env.local")
		apiKey = resolveScanStartAPIKey(modelConfig.Provider, "", modelConfig.BaseURL, modelConfig.Model)
	}
	if providerNeedsAPIKey(modelConfig.Provider) && apiKey == "" {
		return copilotModelConfig{}, "", fmt.Errorf(
			"%s credential unavailable; configure the matching environment variable or start the scan from this UI again",
			modelConfig.Provider,
		)
	}
	return modelConfig, apiKey, nil
}

// handleAsk runs the scan-scoped Target Copilot. In addition to the user's
// question it accepts a small workspace context (current view/graph node),
// which is situational input only and never authorization or scope.
func (s *Server) handleAsk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}
	var req struct {
		ScanID   int64       `json:"scan_id"`
		Question string      `json:"question"`
		Provider string      `json:"provider"` // optional API override; UI inherits the scan
		Model    string      `json:"model"`    // optional API override; UI inherits the scan
		APIKey   string      `json:"api_key"`  // for openai/anthropic/openai-compatible
		BaseURL  string      `json:"base_url"`
		History  []ask.Turn  `json:"history"`
		Context  ask.Context `json:"context"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), 400)
		return
	}
	if req.ScanID == 0 {
		req.ScanID = s.scanIDFromRequest(r)
	}
	if strings.TrimSpace(req.Question) == "" {
		jsonError(w, "question required", 400)
		return
	}
	turnID, err := s.db.CreateCopilotTurn(req.ScanID, req.Question)
	if err != nil {
		jsonError(w, "copilot thread: "+err.Error(), 400)
		return
	}
	failTurn := func(message string) {
		_ = s.db.FailCopilotTurn(turnID, message)
	}
	modelConfig, apiKey, err := s.resolveCopilotModel(req.ScanID, req.Provider, req.Model, req.BaseURL, req.APIKey)
	if err != nil {
		failTurn("copilot model: " + err.Error())
		jsonError(w, "copilot model: "+err.Error(), 400)
		return
	}
	provider, err := llm.NewProvider(modelConfig.Provider, modelConfig.BaseURL, apiKey, modelConfig.Model)
	if err != nil {
		failTurn("provider: " + err.Error())
		jsonError(w, "provider: "+err.Error(), 400)
		return
	}

	storedHistory, err := s.db.CopilotHistory(req.ScanID, 8)
	if err != nil {
		failTurn("history: " + err.Error())
		jsonError(w, "copilot history: "+err.Error(), 500)
		return
	}
	history := make([]ask.Turn, 0, len(storedHistory))
	for _, turn := range storedHistory {
		history = append(history, ask.Turn{Question: turn.Question, Answer: turn.Answer})
	}
	engine := ask.New(provider, s.db)
	res, err := engine.AskWithContext(r.Context(), req.ScanID, req.Question, history, req.Context)
	if err != nil {
		_ = s.persistCopilotErrorResult(turnID, res, err.Error())
		jsonError(w, err.Error(), 500)
		return
	}
	res.TurnID = turnID
	if err := s.persistCopilotResult(req.ScanID, turnID, res); err != nil {
		failTurn(err.Error())
		jsonError(w, "persist copilot result: "+err.Error(), 500)
		return
	}
	jsonResponse(w, res)
}

// handleAskResume continues a paused Copilot loop after the pentester approves
// or denies a proposed live request or scan directive. Both action kinds are
// revalidated from the opaque state before any effect is allowed.
func (s *Server) handleAskResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}
	var req struct {
		ScanID      int64  `json:"scan_id"`
		ResumeState string `json:"resume_state"`
		Approved    bool   `json:"approved"`
		Provider    string `json:"provider"`
		Model       string `json:"model"`
		APIKey      string `json:"api_key"`
		BaseURL     string `json:"base_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), 400)
		return
	}
	if req.ScanID == 0 {
		req.ScanID = s.scanIDFromRequest(r)
	}
	if req.ResumeState == "" {
		jsonError(w, "resume_state required", 400)
		return
	}
	modelConfig, apiKey, err := s.resolveCopilotModel(req.ScanID, req.Provider, req.Model, req.BaseURL, req.APIKey)
	if err != nil {
		jsonError(w, "copilot model: "+err.Error(), 400)
		return
	}
	provider, err := llm.NewProvider(modelConfig.Provider, modelConfig.BaseURL, apiKey, modelConfig.Model)
	if err != nil {
		jsonError(w, "provider: "+err.Error(), 400)
		return
	}
	turnID, err := s.db.ConsumeCopilotApproval(copilotTokenHash(req.ResumeState), req.ScanID, req.Approved)
	if err != nil {
		jsonError(w, "approval is expired or was already used", http.StatusConflict)
		return
	}
	engine := ask.New(provider, s.db)
	res, err := engine.Resume(r.Context(), req.ScanID, req.ResumeState, req.Approved)
	if err != nil {
		_ = s.persistCopilotErrorResult(turnID, res, err.Error())
		jsonError(w, err.Error(), 500)
		return
	}
	res.TurnID = turnID
	if err := s.persistCopilotResult(req.ScanID, turnID, res); err != nil {
		_ = s.db.FailCopilotTurn(turnID, err.Error())
		jsonError(w, "persist copilot result: "+err.Error(), 500)
		return
	}
	jsonResponse(w, res)
}

func copilotTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum[:])
}

func (s *Server) persistCopilotErrorResult(turnID int64, res *ask.Result, message string) error {
	if res == nil {
		return s.db.FailCopilotTurn(turnID, message)
	}
	stepsJSON, err := json.Marshal(res.Steps)
	if err != nil {
		return s.db.FailCopilotTurn(turnID, message)
	}
	actionsJSON, err := json.Marshal(res.UIActions)
	if err != nil {
		return s.db.FailCopilotTurn(turnID, message)
	}
	evidenceJSON, err := json.Marshal(res.Evidence)
	if err != nil {
		return s.db.FailCopilotTurn(turnID, message)
	}
	return s.db.UpdateCopilotTurn(turnID, store.CopilotTurnUpdate{
		Answer: res.Answer, Status: "error", Error: message,
		StepsJSON: string(stepsJSON), UIActionsJSON: string(actionsJSON), EvidenceJSON: string(evidenceJSON),
	})
}

func (s *Server) persistCopilotResult(scanID, turnID int64, res *ask.Result) error {
	stepsJSON, err := json.Marshal(res.Steps)
	if err != nil {
		return err
	}
	actionsJSON, err := json.Marshal(res.UIActions)
	if err != nil {
		return err
	}
	evidenceJSON, err := json.Marshal(res.Evidence)
	if err != nil {
		return err
	}
	update := store.CopilotTurnUpdate{
		Answer:        res.Answer,
		Status:        "completed",
		StepsJSON:     string(stepsJSON),
		UIActionsJSON: string(actionsJSON),
		EvidenceJSON:  string(evidenceJSON),
	}
	if res.Pending != nil {
		pendingJSON, err := json.Marshal(res.Pending)
		if err != nil {
			return err
		}
		update.Status = "awaiting"
		update.PendingJSON = string(pendingJSON)
		update.ResumeState = res.ResumeState
		return s.db.UpdateCopilotTurnWithApproval(turnID, update, copilotTokenHash(res.ResumeState), scanID,
			res.Pending.Kind, time.Now().Add(ask.ApprovalTTL))
	}
	return s.db.UpdateCopilotTurn(turnID, update)
}

func (s *Server) handleCopilotThread(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	if scanID <= 0 {
		jsonError(w, "scan_id required", 400)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.db.ClearCopilotThread(scanID); err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		jsonResponse(w, map[string]any{"cleared": true})
	case http.MethodGet:
		turns, err := s.db.CopilotThread(scanID, intParam(r, "limit", 200))
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		followUpStatus := make(map[int64]string)
		if followUps, listErr := s.db.ListFollowUps(scanID, 500); listErr == nil {
			for _, followUp := range followUps {
				followUpStatus[followUp.ID] = followUp.Status
			}
		}
		// Saved answers are useful conversation history, but they may predate a
		// stronger deterministic evidence ceiling. Project the current route
		// verdicts before displaying history so an old model claim such as
		// "/admin is auth-required" cannot survive beside current redirect-only
		// evidence merely because it was persisted earlier.
		historyProfiles, _ := s.db.GetAllProfiles(scanID)
		s.annotateProfilesWithEvidence(scanID, historyProfiles)
		out := make([]map[string]any, 0, len(turns))
		for _, turn := range turns {
			var steps []ask.Step
			var actions []ask.UIAction
			var evidence []ask.EvidenceRef
			var pending *ask.PendingAction
			_ = json.Unmarshal([]byte(turn.StepsJSON), &steps)
			_ = json.Unmarshal([]byte(turn.UIActionsJSON), &actions)
			_ = json.Unmarshal([]byte(turn.EvidenceJSON), &evidence)
			for i := range steps {
				if status := followUpStatus[steps[i].DirectiveID]; status != "" {
					steps[i].DirectiveStatus = status
				}
			}
			if turn.Status == "awaiting" && turn.ResumeState != "" {
				var value ask.PendingAction
				if json.Unmarshal([]byte(turn.PendingJSON), &value) == nil {
					pending = &value
				}
			}
			answer := turn.Answer
			answer, historyCorrected := reconprojection.SanitizeHistoricalAnswer(answer, historyProfiles)
			out = append(out, map[string]any{
				"id": turn.ID, "question": turn.Question, "answer": answer,
				"status": turn.Status, "steps": steps, "ui_actions": actions,
				"evidence_refs": evidence, "pending": pending,
				"resume_state": turn.ResumeState, "error": turn.Error,
				"historical_corrected": historyCorrected,
				"created_at":           turn.CreatedAt, "updated_at": turn.UpdatedAt,
			})
		}
		jsonResponse(w, map[string]any{"scan_id": scanID, "turns": out})
	default:
		jsonError(w, "GET or DELETE required", 405)
	}
}

// handleAILogFull returns the raw prompt + response text for a single
// ai_log entry. Split from handleAILog (which stays lightweight — a scan
// can have thousands of entries) so the full conversation text is only
// fetched when the operator expands a specific row in the UI.
func (s *Server) handleAILogFull(w http.ResponseWriter, r *http.Request) {
	id := int64(intParam(r, "id", 0))
	if id == 0 {
		jsonError(w, "missing id", 400)
		return
	}
	prompt, responseFull, err := s.db.GetAILogFull(id)
	if err != nil {
		jsonError(w, "not found", 404)
		return
	}
	jsonResponse(w, map[string]any{
		"prompt":        prompt,
		"response_full": responseFull,
	})
}

func (s *Server) handleEndpointDetail(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	hash := r.URL.Query().Get("hash")
	if hash == "" {
		jsonError(w, "hash parameter required", 400)
		return
	}
	profileID := strings.TrimSpace(r.URL.Query().Get("profile_id"))
	var requestedProfile *types.PageProfile
	var err error
	if profileID != "" {
		requestedProfile, err = s.db.GetProfile(scanID, profileID)
		if err != nil {
			jsonError(w, "profile not found", 404)
			return
		}
	}

	// A Knowledge card is an assertion about one exact scan-local profile.
	// Never let its caller-supplied hash select the evidence: otherwise
	// `profile_id=GET /admin&hash=<orders>` could lend /orders content to a
	// stale /admin card. Resolve profile evidence from its own method+URL and
	// then re-check canonical endpoint identity. Endpoint-only callers retain
	// the historical hash/alias path.
	var entries []types.TrafficEntry
	var profileFamilyEntries []types.TrafficEntry
	if requestedProfile != nil {
		profileFamilyEntries, err = s.trafficForKnowledgeProfile(scanID, requestedProfile)
		entries = reconprojection.EntriesForExactSpecimen(
			profileFamilyEntries, requestedProfile.Method, requestedProfile.URL,
		)
	} else {
		entries, err = s.db.GetTrafficByEndpointHash(scanID, hash)
	}
	if requestedProfile == nil && err == nil && len(entries) == 0 {
		resolvedHashes, resolveErr := s.db.ResolveEndpointHashes(scanID, hash)
		if resolveErr != nil {
			err = resolveErr
		} else {
			for _, resolvedHash := range resolvedHashes {
				resolvedEntries, getErr := s.db.GetTrafficByEndpointHash(scanID, resolvedHash)
				if getErr != nil {
					err = getErr
					break
				}
				entries = append(entries, resolvedEntries...)
			}
		}
	}
	if err != nil {
		jsonError(w, "no traffic found", 404)
		return
	}
	catchAllIndex, catchAllErr := s.db.GetCatchAllIndex(scanID)
	if catchAllErr != nil {
		jsonError(w, catchAllErr.Error(), http.StatusInternalServerError)
		return
	}
	if requestedProfile != nil {
		// A stored profile without a matching direct response is analysis
		// inventory, not an observed page. Project that verdict before the
		// profile-only early return so Knowledge cannot retain an OPEN badge or
		// arbitrary model semantics merely because no endpoint row was found.
		annotateProfileRedirectEvidence(requestedProfile, entries)
		reconprojection.ApplyCatchAllCeiling(requestedProfile, catchAllIndex)
		reconprojection.ApplyQueryVariantCeiling(requestedProfile, profileFamilyEntries, catchAllIndex)
	}
	if len(entries) == 0 && requestedProfile != nil {
		jsonResponse(w, map[string]any{
			"profile_only":   true,
			"evidence_state": requestedProfile.EvidenceState,
			"profile":        pageProfileDetailPayload(requestedProfile),
			"artifact":       s.knowledgeProfileArtifact(scanID, requestedProfile.ID),
		})
		return
	}
	if len(entries) == 0 {
		jsonError(w, "no traffic found", 404)
		return
	}
	actionEntries := reconprojection.EntriesForExactSpecimen(entries, entries[0].Request.Method, entries[0].Request.URL)
	if len(actionEntries) > 0 {
		// Endpoint hashes intentionally collapse query values into one logical
		// route. A detail/action response must still represent one exact URL
		// specimen; otherwise its bundle, raw request, and preview could combine
		// content from id=1 with a redirect or error from id=2.
		entries = actionEntries
	}
	redirectEvidence := observation.SummarizeRedirectEvidence(actionEntries)
	endpointProjection := types.PageProfile{Method: entries[0].Request.Method, URL: entries[0].Request.URL}
	annotateProfileRedirectEvidence(&endpointProjection, actionEntries)
	reconprojection.ApplyCatchAllCeiling(&endpointProjection, catchAllIndex)

	// Build endpoint bundle (runs extractors)
	bundle := extract.BuildEndpointBundle(entries, 20)
	if bundle == nil {
		jsonError(w, "extraction failed", 500)
		return
	}

	// Build extracted inputs list. Each entry gets an `explanation` field
	// populated by extract.ExplainInput — zero-cost heuristic description
	// ("Password field — credential", "Search query — often reflected")
	// shown inline in the UI so users see what each input does without
	// spending an LLM call. The analyzer stores the same explanation on
	// profile.ExtractedInputs; this path re-computes it because the UI
	// also shows inputs for endpoints not yet analyzed.
	var inputs []map[string]any
	if bundle.HTMLExtraction != nil {
		for _, form := range bundle.HTMLExtraction.Forms {
			for _, inp := range form.Inputs {
				inputs = append(inputs, map[string]any{
					"name": inp.Name, "type": inp.Type, "location": "form:" + form.Action,
					"required": inp.Required, "label": inp.Label, "value": inp.Value,
					"placeholder": inp.Placeholder,
					"explanation": extract.ExplainInput(inp.Name, inp.Type, "form", inp.Label, inp.Placeholder),
				})
			}
		}
		for _, inp := range bundle.HTMLExtraction.StandaloneInputs {
			inputs = append(inputs, map[string]any{
				"name": inp.Name, "type": inp.Type, "location": "standalone",
				"required": inp.Required, "label": inp.Label,
				"explanation": extract.ExplainInput(inp.Name, inp.Type, "form", inp.Label, inp.Placeholder),
			})
		}
		for _, inp := range bundle.HTMLExtraction.HiddenFields {
			inputs = append(inputs, map[string]any{
				"name": inp.Name, "type": "hidden", "location": "hidden",
				"value":       inp.Value,
				"explanation": extract.ExplainInput(inp.Name, "hidden", "form", inp.Label, inp.Placeholder),
			})
		}
	}
	for _, p := range bundle.QueryParams {
		examples := p.Examples
		if len(examples) > 3 {
			examples = examples[:3]
		}
		inputs = append(inputs, map[string]any{
			"name": p.Name, "type": p.Type, "location": "query",
			"required": p.Required, "examples": examples,
			"explanation": extract.ExplainInput(p.Name, p.Type, "query", "", ""),
		})
	}
	for _, p := range bundle.BodyParams {
		examples := p.Examples
		if len(examples) > 3 {
			examples = examples[:3]
		}
		inputs = append(inputs, map[string]any{
			"name": p.Name, "type": p.Type, "location": "body",
			"required": p.Required, "examples": examples,
			"explanation": extract.ExplainInput(p.Name, p.Type, "body", "", ""),
		})
	}

	// Build forms info
	var forms []map[string]any
	if bundle.HTMLExtraction != nil {
		for _, f := range bundle.HTMLExtraction.Forms {
			formInputs := make([]map[string]string, 0)
			for _, inp := range f.Inputs {
				formInputs = append(formInputs, map[string]string{
					"name": inp.Name, "type": inp.Type, "label": inp.Label,
				})
			}
			forms = append(forms, map[string]any{
				"action": f.Action, "method": f.Method, "enctype": f.Enctype,
				"inputs": formInputs,
			})
		}
	}

	// Links
	var links []map[string]any
	if bundle.HTMLExtraction != nil {
		for _, l := range bundle.HTMLExtraction.Links {
			if len(links) >= 30 {
				break
			}
			links = append(links, map[string]any{
				"href": l.Href, "text": l.Text, "is_api": l.IsAPI, "same_origin": l.SameOrigin,
			})
		}
	}

	// JSON schema
	var jsonSchema map[string]any
	if bundle.JSONSchema != nil {
		jsonSchema = map[string]any{
			"sensitive_fields": bundle.JSONSchema.SensitiveFields,
			"total_fields":     bundle.JSONSchema.TotalFields,
		}
	}

	// A Knowledge card supplies profile_id so the purpose and issues shown in
	// the modal come from that exact card. Endpoint-only callers omit it and
	// retain the historical best-effort matching below.
	profile := requestedProfile

	// Find a matching profile for endpoint-only callers.
	profiles, _ := s.db.GetAllProfiles(scanID)
	entryPath := entries[0].Request.Path
	bundleID := fmt.Sprintf("%s %s", bundle.Method, bundle.URLPattern)

	// Score each profile for match quality, pick the best
	bestScore := 0
	for i, p := range profiles {
		if profile != nil {
			break
		}
		// Endpoint-only callers select one deterministic exact specimen above.
		// Do not attach a profile learned from a query sibling: its purpose and
		// access model are not evidence for this response.
		if strings.TrimSpace(p.URL) != "" && !sameEvidenceSpecimenURL(p.URL, entries[0].Request.URL) {
			continue
		}
		score := 0
		// Exact ID match
		if p.ID == bundleID {
			score = 100
		}
		// Profile URL contains the request path
		if entryPath != "" && strings.Contains(p.URL, entryPath) {
			score = 80
		}
		// Profile ID (which is a URL pattern) matches the request path
		if entryPath != "" && strings.Contains(entryPath, p.ID) {
			score = 70
		}
		// Profile ID is a subpath of the bundle URL pattern
		if strings.Contains(bundle.URLPattern, p.ID) || strings.Contains(p.ID, bundle.URLPattern) {
			score = 60
		}
		// Normalize and compare: strip scheme/host from profile URL, compare paths
		if score == 0 && p.URL != "" {
			profilePath := p.URL
			if idx := strings.Index(profilePath, "://"); idx != -1 {
				if sl := strings.Index(profilePath[idx+3:], "/"); sl != -1 {
					profilePath = profilePath[idx+3+sl:]
				}
			}
			if profilePath != "" && entryPath != "" {
				if strings.TrimRight(profilePath, "/") == strings.TrimRight(entryPath, "/") {
					score = 90
				}
			}
		}
		if score > bestScore {
			bestScore = score
			profile = &profiles[i]
		}
	}

	// Pick a representative response content-type. The bundle merges
	// headers across all entries; whatever is sitting in
	// ResponseHeaders["content-type"] is one of the captured values.
	// Used by the frontend to decide whether the action button should
	// be "Screenshot" (HTML — meaningful re-fetch) or "Preview
	// Response" (JSON/API — render the captured body, no re-fetch).
	contentType := ""
	for k, v := range bundle.ResponseHeaders {
		if strings.EqualFold(k, "content-type") {
			contentType = v
			break
		}
	}

	result := map[string]any{
		"hash":            hash,
		"method":          bundle.Method,
		"url_pattern":     bundle.URLPattern,
		"sample_url":      bundle.SampleURL,
		"entry_count":     bundle.EntryCount,
		"status_codes":    bundle.StatusCodes,
		"content_type":    contentType,
		"has_input":       bundle.HasInput,
		"has_auth":        bundle.HasAuth,
		"is_api":          bundle.IsAPI,
		"has_file_upload": bundle.HasFileUpload,
		"inputs":          inputs,
		"forms":           forms,
		"links":           links,
		"json_schema":     jsonSchema,
		"title":           "",
		// url_segments carries per-position labelling metadata produced
		// by the path-label resolver. The frontend uses it to render
		// variable positions as hoverable chips that reveal the LLM's
		// reason + observed example values on hover.
		"url_segments":       bundle.URLSegments,
		"evidence_state":     endpointProjection.EvidenceState,
		"evidence_note":      endpointProjection.EvidenceNote,
		"redirect_only":      redirectEvidence.RedirectOnly,
		"redirect_locations": redirectEvidence.Locations,
	}

	if bundle.HTMLExtraction != nil {
		result["title"] = bundle.HTMLExtraction.Title
		result["comments"] = bundle.HTMLExtraction.Comments
		result["meta_tags"] = bundle.HTMLExtraction.MetaTags
	}

	if profile != nil {
		annotateProfileRedirectEvidence(profile, entries)
		reconprojection.ApplyCatchAllCeiling(profile, catchAllIndex)
		if requestedProfile != nil {
			reconprojection.ApplyQueryVariantCeiling(profile, profileFamilyEntries, catchAllIndex)
		}
		result["profile"] = pageProfileDetailPayload(profile)
	}

	// Build raw HTTP requests from the best traffic entries
	var rawRequests []map[string]string
	seen := make(map[string]bool)
	for _, e := range entries {
		if len(rawRequests) >= 3 {
			break
		}
		// Deduplicate by method+path+body length
		key := fmt.Sprintf("%s|%s|%d", e.Request.Method, e.Request.Path, len(e.Request.Body))
		if seen[key] {
			continue
		}
		seen[key] = true

		raw := buildRawRequest(e)
		rawResp := buildRawResponseHead(e)
		rawRequests = append(rawRequests, map[string]string{
			"request":  raw,
			"response": rawResp,
			"url":      e.Request.URL,
		})
	}
	result["raw_requests"] = rawRequests

	// Provenance — where did this endpoint come from? We inspect every traffic
	// entry's Referer header and count unique referrers. The top referrer is
	// the most likely "discovered from" page.
	result["provenance"] = buildProvenance(s.db, scanID, entries)

	jsonResponse(w, result)
}

func (s *Server) trafficForKnowledgeProfile(scanID int64, profile *types.PageProfile) ([]types.TrafficEntry, error) {
	if profile == nil || strings.TrimSpace(profile.URL) == "" {
		return []types.TrafficEntry{}, nil
	}
	method := strings.ToUpper(strings.TrimSpace(profile.Method))
	if method == "" {
		method = http.MethodGet
	}
	expectedHash := observation.EndpointHash(method, profile.URL)
	hashes := []string{expectedHash}
	resolved, err := s.db.ResolveEndpointHashes(scanID, profile.ID)
	if err != nil {
		return nil, err
	}
	hashes = append(hashes, resolved...)

	seenHash := make(map[string]bool, len(hashes))
	seenEntry := make(map[int64]bool)
	entries := make([]types.TrafficEntry, 0)
	for _, candidateHash := range hashes {
		candidateHash = strings.TrimSpace(candidateHash)
		if candidateHash == "" || seenHash[candidateHash] {
			continue
		}
		seenHash[candidateHash] = true
		candidateEntries, getErr := s.db.GetTrafficByEndpointHash(scanID, candidateHash)
		if getErr != nil {
			return nil, getErr
		}
		for _, entry := range candidateEntries {
			entryMethod := strings.ToUpper(strings.TrimSpace(entry.Request.Method))
			if entryMethod != method || observation.EndpointHash(entryMethod, entry.Request.URL) != expectedHash {
				continue
			}
			if entry.ID != 0 && seenEntry[entry.ID] {
				continue
			}
			seenEntry[entry.ID] = true
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func pageProfileDetailPayload(profile *types.PageProfile) map[string]any {
	return map[string]any{
		"id":                 profile.ID,
		"url":                profile.URL,
		"method":             profile.Method,
		"purpose":            profile.Purpose,
		"auth_required":      profile.AuthRequired,
		"issues":             profile.Issues,
		"data_exposed":       profile.DataExposed,
		"apis_called":        profile.APIsCalled,
		"behaviors":          profile.Behaviors,
		"relationships":      profile.Relationships,
		"tech_notes":         profile.TechNotes,
		"confidence":         profile.Confidence,
		"inputs":             profile.Inputs,
		"evidence_state":     profile.EvidenceState,
		"evidence_note":      profile.EvidenceNote,
		"observed_statuses":  profile.ObservedStatuses,
		"redirect_locations": profile.RedirectLocations,
	}
}

func (s *Server) knowledgeProfileArtifact(scanID int64, profileID string) map[string]any {
	var issuesJSON, techNotes string
	if err := s.db.Conn().QueryRow(`
		SELECT COALESCE(issues, '[]'), COALESCE(tech_notes, '')
		FROM page_profiles WHERE scan_id = ? AND id = ?`, scanID, profileID,
	).Scan(&issuesJSON, &techNotes); err != nil {
		return nil
	}

	decodeObjectArray := func(candidates ...string) []map[string]any {
		for _, candidate := range candidates {
			var values []map[string]any
			if json.Unmarshal([]byte(candidate), &values) == nil && len(values) > 0 {
				return values
			}
		}
		return nil
	}

	switch profileID {
	case "js_discovered_routes":
		routes := decodeObjectArray(techNotes, issuesJSON)
		return map[string]any{
			"kind":   "javascript_routes",
			"title":  "JavaScript-discovered routes",
			"routes": routes,
		}
	case "attack_surface":
		for _, candidate := range []string{techNotes, issuesJSON} {
			var data map[string]any
			if json.Unmarshal([]byte(candidate), &data) == nil && len(data) > 0 {
				return map[string]any{
					"kind":  "attack_surface",
					"title": "Attack surface summary",
					"data":  data,
				}
			}
		}
	}
	return nil
}

// provenanceSource describes one way we learned about an endpoint.
type provenanceSource struct {
	Kind    string `json:"kind"`               // see store.Discovery* constants
	URL     string `json:"url,omitempty"`      // the source URL (or empty for seed/unknown)
	Detail  string `json:"detail,omitempty"`   // anchor text, form fields, reason, etc.
	Count   int    `json:"count"`              // how many edges collapsed into this source
	FirstAt string `json:"first_at,omitempty"` // timestamp of the first edge
}

func buildProvenance(db *store.DB, scanID int64, entries []types.TrafficEntry) map[string]any {
	if len(entries) == 0 {
		return nil
	}

	// Collect the unique URLs this endpoint has been hit at (usually just one,
	// but for probed variants there can be several).
	urlSet := map[string]bool{}
	var urls []string
	var firstSeen string
	for _, e := range entries {
		if !urlSet[e.Request.URL] {
			urlSet[e.Request.URL] = true
			urls = append(urls, e.Request.URL)
		}
		if !e.Timestamp.IsZero() {
			ts := e.Timestamp.Format(time.RFC3339)
			if firstSeen == "" || ts < firstSeen {
				firstSeen = ts
			}
		}
	}

	// Query the discovery graph for edges whose target is any of these URLs.
	// This is our authoritative "how did we find this" — independent of the
	// unreliable HTTP Referer header.
	edges, _ := db.GetDiscoveriesForTargets(scanID, urls, 30)

	// Group edges by (source_url, kind). The count shows how many times we
	// recorded that edge — e.g. a link listed on 5 different pages still
	// collapses to one row per source page.
	type key struct{ source, kind string }
	grouped := make(map[key]*provenanceSource)
	var orderedKeys []key
	for _, e := range edges {
		k := key{e.SourceURL, e.Kind}
		p, ok := grouped[k]
		if !ok {
			p = &provenanceSource{
				Kind:    e.Kind,
				URL:     e.SourceURL,
				Detail:  e.Detail,
				FirstAt: e.FoundAt,
			}
			grouped[k] = p
			orderedKeys = append(orderedKeys, k)
		}
		p.Count++
		if e.FoundAt != "" && (p.FirstAt == "" || e.FoundAt < p.FirstAt) {
			p.FirstAt = e.FoundAt
		}
	}

	var sources []provenanceSource
	for _, k := range orderedKeys {
		sources = append(sources, *grouped[k])
	}
	// Sort descending by count
	for i := 1; i < len(sources); i++ {
		for j := i; j > 0 && sources[j-1].Count < sources[j].Count; j-- {
			sources[j-1], sources[j] = sources[j], sources[j-1]
		}
	}
	if len(sources) > 8 {
		sources = sources[:8]
	}

	// Build narration hints from the same time window so the UI can also show
	// what the agents were saying at the moment of discovery.
	var hints []string
	if firstSeen != "" {
		rows, err := db.Conn().Query(`
			SELECT agent, action, message
			FROM narrations
			WHERE scan_id = ?
			  AND datetime(created_at) BETWEEN datetime(?, '-5 seconds') AND datetime(?, '+2 seconds')
			  AND (agent = 'crawler' OR agent = 'js_analyzer' OR agent = 'explorer'
			       OR action = 'visit' OR action = 'form_found')
			LIMIT 3`, scanID, firstSeen, firstSeen)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var agent, action, message string
				rows.Scan(&agent, &action, &message)
				if message != "" {
					hints = append(hints, fmt.Sprintf("%s [%s]: %s", agent, action, message))
				}
			}
		}
	}

	// If we have NO edges recorded but we have traffic, this URL was captured
	// by the MITM proxy without the crawler queueing it — e.g. an XHR fired
	// by a page we visited but whose JS we haven't yet analyzed. Fall back
	// to Referer in that case, so we give SOMETHING rather than "unknown".
	if len(sources) == 0 {
		refCounts := make(map[string]int)
		refFirst := make(map[string]string)
		for _, e := range entries {
			for k, v := range e.Request.Headers {
				if !strings.EqualFold(k, "Referer") && !strings.EqualFold(k, "Referrer") {
					continue
				}
				if v == "" {
					continue
				}
				refCounts[v]++
				if _, ok := refFirst[v]; !ok && !e.Timestamp.IsZero() {
					refFirst[v] = e.Timestamp.Format(time.RFC3339)
				}
				break
			}
		}
		for url, n := range refCounts {
			sources = append(sources, provenanceSource{
				Kind: "referrer", URL: url, Count: n, FirstAt: refFirst[url],
			})
		}
		if len(sources) == 0 {
			sources = append(sources, provenanceSource{
				Kind:    "unknown",
				URL:     "Captured by the proxy but no discovery edge was recorded — likely a background XHR or redirect.",
				Count:   1,
				FirstAt: firstSeen,
			})
		}
	}

	return map[string]any{
		"sources":     sources,
		"first_seen":  firstSeen,
		"hint_events": hints,
	}
}

func (s *Server) handleScreenshotCapture(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		jsonError(w, "url parameter required", 400)
		return
	}

	// Sanitize: only allow http/https
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		jsonError(w, "invalid URL scheme", 400)
		return
	}
	scanID := s.scanIDFromRequest(r)
	catchAllIndex, catchAllErr := s.db.GetCatchAllIndex(scanID)
	if catchAllErr != nil {
		jsonError(w, catchAllErr.Error(), http.StatusInternalServerError)
		return
	}
	knownRoute := types.PageProfile{Method: http.MethodGet, URL: targetURL, EvidenceState: "content_observed"}
	if reconprojection.ApplyCatchAllCeiling(&knownRoute, catchAllIndex) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{
			"error":          "screenshot withheld: requested route matches an observed invalid-path catch-all shell",
			"evidence_state": knownRoute.EvidenceState,
			"evidence_note":  knownRoute.EvidenceNote,
			"requested_url":  targetURL,
		})
		return
	}
	// A screenshot follows redirects and can render generic login/error shells,
	// so it cannot repair already-known non-content evidence. Return the direct
	// response verdict instead of producing (and caching) a misleading image
	// under the requested route's name. An arbitrary operator-entered URL with
	// no prior record may still use the policy-controlled capture path, but a
	// stored route profile with no matching GET response is explicitly known to
	// be inventory-only and must not gain apparent proof through this action.
	endpointEntries, redirectErr := s.db.GetTrafficByEndpointHash(
		scanID, observation.EndpointHash(http.MethodGet, targetURL),
	)
	redirectEntries := exactGETEvidenceForURL(endpointEntries, targetURL)
	priorContentVerified := false
	if redirectErr == nil && len(redirectEntries) > 0 {
		evidence := observation.SummarizeRedirectEvidence(redirectEntries)
		evidenceState := directResponseEvidenceState(evidence)
		if evidenceState != "content_observed" {
			reason := "requested route has no substantive directly observed page content"
			if evidence.RedirectOnly {
				reason = "requested route is redirect-only and has no directly observed page content"
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]any{
				"error":                "screenshot withheld: " + reason,
				"evidence_state":       evidenceState,
				"requested_url":        targetURL,
				"status_codes":         evidence.StatusCodes,
				"redirect_locations":   evidence.Locations,
				"empty_success":        evidence.EmptySuccessObserved,
				"authentication_shell": evidence.AuthShellObserved,
				"error_shell":          evidence.ErrorShellObserved,
			})
			return
		}
		priorContentVerified = true
	}
	if redirectErr == nil && len(redirectEntries) == 0 {
		profiles, profilesErr := s.db.GetAllProfiles(scanID)
		if profilesErr == nil {
			targetHash := observation.EndpointHash(http.MethodGet, targetURL)
			for _, profile := range profiles {
				if reconprojection.IsSyntheticSummaryProfile(profile) {
					continue
				}
				method := strings.ToUpper(strings.TrimSpace(profile.Method))
				if method == "" {
					method = http.MethodGet
				}
				if method != http.MethodGet || observation.EndpointHash(method, profile.URL) != targetHash ||
					!sameEvidenceSpecimenURL(profile.URL, targetURL) {
					continue
				}
				reconprojection.AnnotateProfile(&profile, nil)
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]any{
					"error":          "screenshot withheld: stored route profile has no matching directly observed response",
					"evidence_state": profile.EvidenceState,
					"evidence_note":  profile.EvidenceNote,
					"requested_url":  targetURL,
				})
				return
			}
		}
	}
	executionPolicy, credentialOrigin, err := s.executionPolicyForScan(scanID)
	if err != nil {
		jsonError(w, "execution policy unavailable: "+err.Error(), http.StatusBadRequest)
		return
	}
	decision := executionPolicy.Authorize(policy.Action{TargetURL: targetURL, Method: http.MethodGet})
	if !decision.Allowed {
		s.auditPolicyDenial(scanID, decision)
		jsonError(w, fmt.Sprintf("policy denied (%s): %s", decision.Code, decision.Reason), http.StatusForbidden)
		return
	}

	ssDir := filepath.Join(s.outputDir, "screenshots")
	os.MkdirAll(ssDir, 0o755)

	// Screenshot evidence is scan-scoped: a page may have different authority,
	// credentials, scope boundaries, or content in another run.
	filename := screenshotCacheFilename(scanID, targetURL)
	ssPath := filepath.Join(ssDir, filename)

	// Never resurrect an old all-white render. It carries no page evidence and
	// commonly means required dependencies were denied or the final shell never
	// painted. A valid cached image remains a cheap deterministic fast path.
	if cached, readErr := os.ReadFile(ssPath); priorContentVerified && readErr == nil && !browserScreenshotLooksEmpty(cached) {
		jsonResponse(w, map[string]any{
			"filename": filename,
			"url":      "/screenshots/" + filename,
			"cached":   true,
		})
		return
	}

	// Launch a headless browser through the same policy-enforcing MITM used by
	// scans. This covers redirects, subresources, fetch/XHR, and WebSockets;
	// target-controlled page code cannot use the screenshot tool as an
	// off-scope network primitive.
	s.logger.Info("capturing screenshot", "url", targetURL)
	var captureMu sync.Mutex
	var capturedNavigation []types.TrafficEntry
	policyProxy, err := scanproxy.New("127.0.0.1", 0,
		filepath.Join(s.outputDir, "screenshot-proxy-certs"),
		func(entry *types.TrafficEntry) {
			if entry == nil || strings.ToUpper(strings.TrimSpace(entry.Request.Method)) != http.MethodGet ||
				!sameEvidenceSpecimenURL(entry.Request.URL, targetURL) {
				return
			}
			captureMu.Lock()
			capturedNavigation = append(capturedNavigation, *entry)
			captureMu.Unlock()
		}, executionPolicy, credentialOrigin,
		func(decision policy.Decision) { s.auditPolicyDenial(scanID, decision) }, s.logger)
	if err != nil {
		jsonError(w, "create screenshot policy proxy: "+err.Error(), http.StatusInternalServerError)
		return
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		jsonError(w, "start screenshot policy proxy: "+err.Error(), http.StatusInternalServerError)
		return
	}
	proxyCtx, stopProxy := context.WithCancel(r.Context())
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- policyProxy.Serve(proxyCtx, listener) }()
	defer func() {
		stopProxy()
		select {
		case <-proxyDone:
		case <-time.After(2 * time.Second):
		}
	}()

	path, _ := launcher.LookPath()
	u := launcher.New().Bin(path).Headless(true).
		Proxy("http://"+listener.Addr().String()).
		Set("proxy-bypass-list", "<-loopback>").
		Set("ignore-certificate-errors").
		Set("disable-background-networking").
		MustLaunch()
	browser := rod.New().ControlURL(u).MustConnect()
	defer browser.MustClose()

	page := browser.MustPage(targetURL)
	defer page.MustClose()

	// Wait for load with timeout
	page.Timeout(15 * time.Second).WaitLoad()
	time.Sleep(1 * time.Second) // let JS render
	finalURL := targetURL
	if info, infoErr := page.Info(); infoErr == nil && info != nil && strings.TrimSpace(info.URL) != "" {
		finalURL = info.URL
	}
	requestedCanonical, requestedOK := canonicalGraphURL(targetURL)
	finalCanonical, finalOK := canonicalGraphURL(finalURL)
	if requestedOK && finalOK && requestedCanonical != finalCanonical {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{
			"error":          "screenshot withheld: navigation landed on a different URL; showing it as the requested route would be misleading",
			"evidence_state": "redirect_landing",
			"requested_url":  targetURL,
			"final_url":      finalURL,
		})
		return
	}
	captureMu.Lock()
	directNavigation := append([]types.TrafficEntry(nil), capturedNavigation...)
	captureMu.Unlock()
	if len(directNavigation) == 0 {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{
			"error":          "screenshot withheld: the browser produced no exact top-level response for the requested URL",
			"evidence_state": "response_unverified",
			"requested_url":  targetURL,
			"final_url":      finalURL,
		})
		return
	}
	directEvidence := observation.SummarizeRedirectEvidence(directNavigation)
	if state := directResponseEvidenceState(directEvidence); state != "content_observed" {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{
			"error":                "screenshot withheld: the newly captured top-level response did not contain substantive page content",
			"evidence_state":       state,
			"requested_url":        targetURL,
			"final_url":            finalURL,
			"status_codes":         directEvidence.StatusCodes,
			"redirect_locations":   directEvidence.Locations,
			"empty_success":        directEvidence.EmptySuccessObserved,
			"authentication_shell": directEvidence.AuthShellObserved,
			"error_shell":          directEvidence.ErrorShellObserved,
		})
		return
	}
	capturedRoute := types.PageProfile{Method: http.MethodGet, URL: targetURL, EvidenceState: "content_observed"}
	if reconprojection.ApplyCatchAllResponseCeiling(&capturedRoute, directNavigation, catchAllIndex) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{
			"error":          "screenshot withheld: newly captured response matches an observed invalid-path catch-all shell",
			"evidence_state": capturedRoute.EvidenceState,
			"evidence_note":  capturedRoute.EvidenceNote,
			"requested_url":  targetURL,
			"final_url":      finalURL,
		})
		return
	}

	data, err := page.Screenshot(true, nil)
	if err != nil {
		s.logger.Warn("screenshot capture failed", "url", targetURL, "error", err)
		jsonError(w, "screenshot capture failed: "+err.Error(), 500)
		return
	}
	if browserScreenshotLooksEmpty(data) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]any{
			"error":          "render unavailable: the page produced an empty image, often because required browser dependencies were blocked or never painted",
			"evidence_state": "render_unavailable",
			"requested_url":  targetURL,
			"final_url":      finalURL,
		})
		return
	}

	if err := os.WriteFile(ssPath, data, 0o644); err != nil {
		jsonError(w, "save failed: "+err.Error(), 500)
		return
	}

	s.logger.Info("screenshot captured", "url", targetURL, "file", filename)
	jsonResponse(w, map[string]any{
		"filename":      filename,
		"url":           "/screenshots/" + filename,
		"cached":        false,
		"requested_url": targetURL,
		"final_url":     finalURL,
	})
}

func exactGETEvidenceForURL(entries []types.TrafficEntry, targetURL string) []types.TrafficEntry {
	filtered := make([]types.TrafficEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.EqualFold(strings.TrimSpace(entry.Request.Method), http.MethodGet) &&
			sameEvidenceSpecimenURL(entry.Request.URL, targetURL) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func sameEvidenceSpecimenURL(left, right string) bool {
	canonical := func(raw string) (string, bool) {
		value, ok := canonicalGraphURL(raw)
		if !ok {
			return "", false
		}
		parsed, err := url.Parse(value)
		if err != nil {
			return "", false
		}
		// Fragments are not carried by an HTTP request. Query values are carried
		// and therefore remain part of the exact specimen identity.
		parsed.Fragment = ""
		return parsed.String(), true
	}
	a, okA := canonical(left)
	b, okB := canonical(right)
	return okA && okB && a == b
}

func screenshotCacheFilename(scanID int64, targetURL string) string {
	return fmt.Sprintf("%x.png", md5.Sum([]byte(fmt.Sprintf("%d|%s", scanID, targetURL))))
}

// browserScreenshotLooksEmpty rejects only effectively all-white PNGs. Sparse
// pages with even small visible text/control pixels remain valid evidence.
func browserScreenshotLooksEmpty(data []byte) bool {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return false
	}
	bounds := img.Bounds()
	if bounds.Dx() == 0 || bounds.Dy() == 0 {
		return true
	}
	stepX := bounds.Dx() / 96
	stepY := bounds.Dy() / 60
	if stepX < 1 {
		stepX = 1
	}
	if stepY < 1 {
		stepY = 1
	}
	nearWhite, sampled := 0, 0
	for y := bounds.Min.Y; y < bounds.Max.Y; y += stepY {
		for x := bounds.Min.X; x < bounds.Max.X; x += stepX {
			r, g, b, _ := img.At(x, y).RGBA()
			sampled++
			if r >= 0xfafa && g >= 0xfafa && b >= 0xfafa {
				nearWhite++
			}
		}
	}
	return sampled > 0 && float64(nearWhite)/float64(sampled) >= 0.999
}

func (s *Server) handleRepeater(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST required", 405)
		return
	}

	var req struct {
		RawRequest string `json:"raw_request"`
		TargetURL  string `json:"target_url"` // full URL like https://example.com/path
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), 400)
		return
	}
	if req.TargetURL == "" {
		jsonError(w, "target_url required", 400)
		return
	}
	scanID := s.scanIDFromRequest(r)
	executionPolicy, credentialOrigin, err := s.executionPolicyForScan(scanID)
	if err != nil {
		jsonError(w, "execution policy unavailable: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Parse the raw request
	lines := strings.Split(strings.ReplaceAll(req.RawRequest, "\r\n", "\n"), "\n")
	if len(lines) < 1 {
		jsonError(w, "empty request", 400)
		return
	}

	// Parse request line: METHOD /path HTTP/1.1
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		jsonError(w, "invalid request line", 400)
		return
	}
	method := parts[0]
	path := parts[1]

	// Parse headers and body
	headers := make(map[string]string)
	bodyStart := -1
	host := ""
	for i := 1; i < len(lines); i++ {
		if lines[i] == "" {
			bodyStart = i + 1
			break
		}
		kv := strings.SplitN(lines[i], ": ", 2)
		if len(kv) == 2 {
			headers[kv[0]] = kv[1]
			if strings.ToLower(kv[0]) == "host" {
				host = kv[1]
			}
		}
	}
	var body string
	if bodyStart > 0 && bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}

	// Build the full URL
	targetURL := req.TargetURL
	parsed, err := url.Parse(targetURL)
	if err != nil {
		jsonError(w, "invalid target_url", 400)
		return
	}
	// If the user edited the path in the raw request, use that
	if path != parsed.RequestURI() && !strings.HasPrefix(path, "http") {
		parsed.Path = path
		parsed.RawQuery = ""
		if idx := strings.Index(path, "?"); idx != -1 {
			parsed.Path = path[:idx]
			parsed.RawQuery = path[idx+1:]
		}
		targetURL = parsed.String()
	}

	// Send the request
	s.logger.Info("repeater sending request", "method", method, "url", targetURL)
	start := time.Now()

	httpReq, err := http.NewRequest(method, targetURL, bytes.NewBufferString(body))
	if err != nil {
		jsonError(w, "build request failed: "+err.Error(), 500)
		return
	}
	for k, v := range headers {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" {
			continue
		}
		httpReq.Header.Set(k, v)
	}
	if host != "" {
		httpReq.Host = host
	}

	baseClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	client := policy.ProtectHTTPClient(baseClient, executionPolicy, policy.HTTPOptions{
		CredentialOrigin: credentialOrigin,
		Audit: func(decision policy.Decision) {
			s.auditPolicyDenial(scanID, decision)
		},
	})

	resp, err := client.Do(httpReq)
	duration := time.Since(start).Milliseconds()
	if err != nil {
		if decision, denied := policy.DecisionFromError(err); denied {
			jsonError(w, fmt.Sprintf("policy denied (%s): %s", decision.Code, decision.Reason), http.StatusForbidden)
			return
		}
		jsonError(w, "request failed: "+err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	// Read response body (limit to 500KB)
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	// Build raw response
	var rawResp strings.Builder
	fmt.Fprintf(&rawResp, "HTTP/%d.%d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
	for k, vals := range resp.Header {
		for _, v := range vals {
			fmt.Fprintf(&rawResp, "%s: %s\r\n", k, v)
		}
	}
	rawResp.WriteString("\r\n")
	rawResp.Write(respBody)

	jsonResponse(w, map[string]any{
		"status_code":  resp.StatusCode,
		"duration_ms":  duration,
		"raw_response": rawResp.String(),
		"body_size":    len(respBody),
		"headers":      resp.Header,
	})
}

func buildRawRequest(e types.TrafficEntry) string {
	var b strings.Builder

	// Request line
	path := e.Request.Path
	if e.Request.Query != "" {
		path += "?" + e.Request.Query
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", e.Request.Method, path)

	// Host header first
	if e.Request.Host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", e.Request.Host)
	}

	// Other headers
	for k, v := range e.Request.Headers {
		lower := strings.ToLower(k)
		if lower == "host" {
			continue // already printed
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}

	// Body
	body := string(e.Request.Body)
	if len(body) > 0 {
		if _, ok := e.Request.Headers["Content-Length"]; !ok {
			fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
		}
		b.WriteString("\r\n")
		b.WriteString(body)
	} else {
		b.WriteString("\r\n")
	}

	return b.String()
}

func buildRawResponseHead(e types.TrafficEntry) string {
	var b strings.Builder

	// Status line
	fmt.Fprintf(&b, "HTTP/1.1 %d\r\n", e.Response.StatusCode)

	// Headers
	for k, v := range e.Response.Headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")

	// Truncated body preview
	body := string(e.Response.Body)
	if len(body) > 2000 {
		b.WriteString(body[:2000])
		fmt.Fprintf(&b, "\n\n[...truncated, %d bytes total]", len(body))
	} else if len(body) > 0 {
		b.WriteString(body)
	}

	return b.String()
}

// scanIDFromRequest reads ?scan_id= from the request, falls back to latest.
func (s *Server) scanIDFromRequest(r *http.Request) int64 {
	if v := r.URL.Query().Get("scan_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err == nil && id > 0 {
			return id
		}
	}
	return s.latestScanID()
}

func (s *Server) latestScanID() int64 {
	var id int64
	s.db.Conn().QueryRow(`SELECT id FROM scans ORDER BY id DESC LIMIT 1`).Scan(&id)
	return id
}

func jsonResponse(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func intParam(r *http.Request, key string, defaultVal int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return n
}

// appendStrategistArgs preserves the UI API's three planner states:
// omitted/negative uses the scanner's default, zero disables it explicitly,
// and a positive duration overrides the cadence.
func appendStrategistArgs(args []string, model string, periodSeconds *int) []string {
	if model != "" {
		args = append(args, "--strategist-model="+model)
	}
	if periodSeconds != nil && *periodSeconds >= 0 {
		args = append(args, "--strategist-period="+strconv.Itoa(*periodSeconds))
	}
	return args
}

func resolveTestingAuthority(raw string) (policy.TestingAuthority, error) {
	if strings.TrimSpace(raw) == "" {
		return policy.AuthorityActive, nil
	}
	return policy.ParseTestingAuthority(raw)
}

func appendTestingAuthorityArg(args []string, authority policy.TestingAuthority) []string {
	return append(args, "--testing-authority="+string(authority))
}

// appendUIReconAnalysisLimit keeps browser-visible public Recon runs
// responsive on asset-heavy sites. Analyzer already orders endpoint families
// by relevance and runs again after navigation, so a bounded per-pass window
// preserves representative coverage without spending model calls on hundreds
// of near-identical fragments before the operator sees a target model.
func appendUIReconAnalysisLimit(args []string, authority policy.TestingAuthority, maxPages int) []string {
	if authority != policy.AuthorityRecon {
		return args
	}
	limit := 24
	if maxPages > 0 {
		limit = max(8, min(32, maxPages*3))
		if maxPages <= 3 {
			limit = 8
		}
	}
	return append(args, "--analysis-endpoint-limit="+strconv.Itoa(limit))
}

// testingAuthorityFromConfig keeps legacy scans (which predate the field)
// visible as the recommended Active Pentest default while reading new config
// JSON from Config.Scan.testing_authority.
func testingAuthorityFromConfig(configJSON string) policy.TestingAuthority {
	var persisted struct {
		TestingAuthority policy.TestingAuthority `json:"testing_authority"`
		Scan             struct {
			TestingAuthority policy.TestingAuthority `json:"testing_authority"`
		} `json:"scan"`
	}
	if json.Unmarshal([]byte(configJSON), &persisted) == nil {
		raw := persisted.TestingAuthority
		if raw == "" {
			raw = persisted.Scan.TestingAuthority
		}
		if authority, err := resolveTestingAuthority(string(raw)); err == nil {
			return authority
		}
	}
	return policy.AuthorityActive
}

// scanScopeRulesFromConfig returns the persisted operator-declared scope, with
// the concrete scan target as the fail-closed default for legacy scans.
func scanScopeRulesFromConfig(target, configJSON string) []string {
	var persisted struct {
		Scope []string `json:"scope"`
		Scan  struct {
			Scope []string `json:"scope"`
		} `json:"scan"`
	}
	_ = json.Unmarshal([]byte(configJSON), &persisted)
	rules := persisted.Scan.Scope
	if len(rules) == 0 {
		rules = persisted.Scope
	}
	if len(rules) == 0 {
		rules = []string{target}
	}
	return rules
}

// graphScopeFromConfig reconstructs the operator-declared origin allowlist
// used by the scanner. Discovery records may legitimately include off-scope
// links, so Graph projection must use this authorization boundary instead of
// guessing from registrable domains, response status, or request counts.
// Invalid or legacy config fails closed to the scan's concrete target origin.
func graphScopeFromConfig(target, configJSON string) policy.Scope {
	rules := scanScopeRulesFromConfig(target, configJSON)
	scope, err := policy.NewScope(rules)
	if err == nil {
		return scope
	}
	// The target was already validated when the scan was created. Ignore the
	// error here because a zero-value Scope is the stricter fallback if a
	// hand-edited legacy row somehow contains an invalid target too.
	scope, _ = policy.NewScope([]string{target})
	return scope
}

func (s *Server) executionPolicyForScan(scanID int64) (*policy.Engine, string, error) {
	var target, configJSON string
	if err := s.db.Conn().QueryRow(`SELECT target, config_json FROM scans WHERE id = ?`, scanID).
		Scan(&target, &configJSON); err != nil {
		return nil, "", fmt.Errorf("load scan policy: %w", err)
	}
	authority := testingAuthorityFromConfig(configJSON)
	engine, err := policy.New(authority, scanScopeRulesFromConfig(target, configJSON))
	if err != nil {
		// Fail closed for malformed or hand-edited legacy configuration: the
		// concrete scan target remains usable, but no additional origin is
		// authorized from an invalid persisted scope declaration.
		engine, err = policy.New(authority, []string{target})
	}
	if err != nil {
		return nil, "", err
	}
	return engine, target, nil
}

func (s *Server) auditPolicyDenial(scanID int64, decision policy.Decision) {
	if decision.Allowed {
		return
	}
	_, _ = s.db.InsertNarration(scanID, "policy", "denied", decision.Reason,
		decision.TargetURL, map[string]any{
			"code":              decision.Code,
			"testing_authority": decision.Authority,
			"canonical_origin":  decision.CanonicalOrigin,
			"classes":           decision.Classes,
		})
}

type scanStartRequest struct {
	Target            string   `json:"target"`
	MaxPages          int      `json:"max_pages"`
	IncludeSubdomains bool     `json:"include_subdomains"`
	Scope             []string `json:"scope"`
	LLM               string   `json:"llm"`               // "ollama", "openai", "anthropic", "openai-compatible", or "" for crawl-only
	Model             string   `json:"model"`             // model id (optional — provider default used if empty)
	ReasoningModel    string   `json:"reasoning_model"`   // optional stronger model for semantic analysis/planning
	APIKey            string   `json:"api_key"`           // required for openai / anthropic / openai-compatible
	BaseURL           string   `json:"base_url"`          // optional: openai-compatible endpoint (MiniMax, DeepSeek, self-hosted vLLM, …)
	BudgetCents       int      `json:"budget_cents"`      // dollar cap in cents; 0 = unlimited
	SessionCookie     string   `json:"session_cookie"`    // optional: cookie injected into browser before crawl
	LoginURL          string   `json:"login_url"`         // optional: form-login URL
	LoginUser         string   `json:"login_user"`        // optional: form-login username
	LoginPass         string   `json:"login_pass"`        // optional: form-login password
	TestingAuthority  string   `json:"testing_authority"` // recon, active, or full_control; omitted = active

	BOLAPrimaryOwner       string `json:"bola_primary_owner"`
	BOLAPrimaryLoginURL    string `json:"bola_primary_login_url"`
	BOLAPrimaryObjectURL   string `json:"bola_primary_object_url"`
	BOLASecondaryLoginURL  string `json:"bola_secondary_login_url"`
	BOLASecondaryUser      string `json:"bola_secondary_user"`
	BOLASecondaryPass      string `json:"bola_secondary_pass"`
	BOLASecondaryOwner     string `json:"bola_secondary_owner"`
	BOLASecondaryObjectURL string `json:"bola_secondary_object_url"`

	// Sovereign Strategist options
	StrategistModel string `json:"strategist_model"` // separate model for the Strategist; defaults to analyzer model
	// Pointer preserves omitted vs explicit zero. Omitted/negative uses
	// the CLI default; zero is the operator's deliberate disable choice.
	StrategistPeriodS *int `json:"strategist_period_s"`
}

func appendBOLAEnv(env []string, req scanStartRequest) []string {
	pairs := []struct {
		key string
		val string
	}{
		{"AOBTD_BOLA_PRIMARY_OWNER", req.BOLAPrimaryOwner},
		{"AOBTD_BOLA_PRIMARY_LOGIN_URL", req.BOLAPrimaryLoginURL},
		{"AOBTD_BOLA_PRIMARY_OBJECT_URL", req.BOLAPrimaryObjectURL},
		{"AOBTD_BOLA_SECONDARY_LOGIN_URL", req.BOLASecondaryLoginURL},
		{"AOBTD_BOLA_SECONDARY_USER", req.BOLASecondaryUser},
		{"AOBTD_BOLA_SECONDARY_PASS", req.BOLASecondaryPass},
		{"AOBTD_BOLA_SECONDARY_OWNER", req.BOLASecondaryOwner},
		{"AOBTD_BOLA_SECONDARY_OBJECT_URL", req.BOLASecondaryObjectURL},
	}
	for _, p := range pairs {
		if strings.TrimSpace(p.val) != "" {
			env = append(env, p.key+"="+p.val)
		}
	}
	return env
}

func loadUIDotEnvLocal(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" || os.Getenv(key) != "" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		_ = os.Setenv(key, value)
	}
}

func resolveScanStartAPIKey(providerName, explicit, baseURL, model string) string {
	if explicit != "" {
		return explicit
	}
	if v := os.Getenv("AOBTD_LLM_KEY"); v != "" {
		return v
	}
	switch strings.ToLower(strings.TrimSpace(providerName)) {
	case "openai":
		return os.Getenv("OPENAI_API_KEY")
	case "anthropic":
		return os.Getenv("ANTHROPIC_API_KEY")
	case "openai-compatible":
		for _, name := range openAICompatibleKeyNames(baseURL, model) {
			if v := os.Getenv(name); v != "" {
				return v
			}
		}
	}
	return ""
}

func openAICompatibleKeyNames(baseURL, model string) []string {
	lowerURL := strings.ToLower(strings.TrimSpace(baseURL))
	lowerModel := strings.ToLower(strings.TrimSpace(model))
	if strings.Contains(lowerURL, "minimax") || strings.HasPrefix(lowerModel, "minimax") {
		return []string{"MINIMAX_API_KEY", "ZAI_API_KEY", "Z_AI_API_KEY", "GLM_API_KEY"}
	}
	if strings.Contains(lowerURL, "z.ai") || strings.Contains(lowerURL, "bigmodel") || strings.HasPrefix(lowerModel, "glm-") {
		return []string{"ZAI_API_KEY", "Z_AI_API_KEY", "GLM_API_KEY", "MINIMAX_API_KEY"}
	}
	return []string{"ZAI_API_KEY", "Z_AI_API_KEY", "GLM_API_KEY", "MINIMAX_API_KEY"}
}

func defaultOpenAICompatibleBaseURL(model string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(model)), "glm-") {
		return "https://api.z.ai/api/coding/paas/v4"
	}
	return "https://api.minimax.io/v1"
}

func validateRequestedScope(target string, includeSubdomains bool, extra []string) error {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid target URL")
	}
	if strings.Contains(parsed.Hostname(), "*") {
		return fmt.Errorf("target must be a reachable start URL without wildcards; add %q as an authorized scope rule instead", parsed.Hostname())
	}
	rules := []string{target}
	if includeSubdomains {
		root, rootErr := targetresolver.RegistrableDomain(target)
		if rootErr != nil {
			return rootErr
		}
		rootHost := root
		if parsed.Port() != "" {
			rootHost += ":" + parsed.Port()
		}
		if !strings.EqualFold(parsed.Hostname(), root) {
			rules = append(rules, parsed.Scheme+"://"+rootHost)
		}
		rules = append(rules, parsed.Scheme+"://*."+rootHost)
	}
	for _, raw := range extra {
		rule := strings.TrimSpace(raw)
		if rule == "" {
			continue
		}
		if !strings.Contains(rule, "://") {
			rule = parsed.Scheme + "://" + rule
		}
		rules = append(rules, rule)
	}
	_, err = policy.New(policy.AuthorityRecon, rules)
	return err
}

func normalizeScanStartTarget(req *scanStartRequest) error {
	declared, err := targetresolver.NormalizeStartDeclaration(req.Target)
	if err != nil {
		return err
	}
	req.Target = declared.Target
	if !declared.WasWildcard {
		return nil
	}
	for _, existing := range req.Scope {
		if strings.EqualFold(strings.TrimSpace(existing), declared.ScopeRule) {
			return nil
		}
	}
	req.Scope = append(req.Scope, declared.ScopeRule)
	return nil
}

// handleScanStart kicks off a new scan in a subprocess. We only allow one at
// a time because the scanner binds to a fixed proxy port.
func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}

	var req scanStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body: "+err.Error(), 400)
		return
	}
	if req.Target == "" {
		jsonError(w, "target is required", 400)
		return
	}
	testingAuthority, err := resolveTestingAuthority(req.TestingAuthority)
	if err != nil {
		jsonError(w, "invalid testing_authority: "+err.Error(), 400)
		return
	}
	if err := normalizeScanStartTarget(&req); err != nil {
		jsonError(w, "invalid target: "+err.Error(), 400)
		return
	}
	if err := validateRequestedScope(req.Target, req.IncludeSubdomains, req.Scope); err != nil {
		jsonError(w, "invalid scope: "+err.Error(), 400)
		return
	}
	// 0 → unlimited (the crawler treats MaxPages==0 as "no cap").
	// Negative values normalize to 0. Clamp huge numbers to a sane ceiling
	// so a stray test doesn't try to crawl a million pages by mistake.
	if req.MaxPages < 0 {
		req.MaxPages = 0
	}
	if req.MaxPages > 50000 {
		req.MaxPages = 50000
	}
	loadUIDotEnvLocal(".env.local")
	// openai-compatible providers need a base URL too (MiniMax, DeepSeek,
	// self-hosted vLLM, …). Default before credential resolution so a MiniMax
	// model/base URL can prefer MINIMAX_API_KEY over other compatible keys.
	if req.LLM == "openai-compatible" && req.BaseURL == "" {
		req.BaseURL = defaultOpenAICompatibleBaseURL(req.Model)
	}
	resolvedAPIKey := resolveScanStartAPIKey(req.LLM, req.APIKey, req.BaseURL, req.Model)
	// Validate LLM config — must have a key for paid / openai-compatible providers.
	if (req.LLM == "openai" || req.LLM == "anthropic" || req.LLM == "openai-compatible") && resolvedAPIKey == "" {
		jsonError(w, "api_key is required for "+req.LLM+" (or configure a matching environment variable / .env.local)", 400)
		return
	}
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.activeProc != nil && s.activeProc.Process != nil {
		// Check if it's still alive
		if err := s.activeProc.Process.Signal(os.Signal(nil)); err == nil {
			jsonError(w, "a scan is already running", 409)
			return
		}
	}

	exe, err := os.Executable()
	if err != nil || exe == "" {
		jsonError(w, "cannot locate aobtd executable: "+fmt.Sprint(err), 500)
		return
	}

	// UI-launched scans run headless — the user is watching via the Live tab's
	// browser frame, so popping an extra Chrome window is just noise.
	//
	// CRITICAL: pass --output=<s.outputDir> so the scanner writes to the SAME
	// scan.db the UI is reading. Without this the scanner defaults to
	// ./aobtd-output and the UI (reading from, say, ./aobtd-bwapp-notif) never
	// sees the new scan — the frontend's switchToNewScan then falls back to
	// the newest scan in the UI's DB, which is an unrelated old one. Classic
	// "wrong DB, wrong scan" bug.
	args := []string{
		"scan",
		"--target", req.Target,
		"--output", s.outputDir,
		"--max-pages", strconv.Itoa(req.MaxPages),
		"--headless",
	}
	if req.IncludeSubdomains {
		args = append(args, "--include-subdomains")
	}
	for _, scopeEntry := range req.Scope {
		if scopeEntry = strings.TrimSpace(scopeEntry); scopeEntry != "" {
			args = append(args, "--scope", scopeEntry)
		}
	}
	args = appendTestingAuthorityArg(args, testingAuthority)
	args = appendUIReconAnalysisLimit(args, testingAuthority, req.MaxPages)
	if req.LLM != "" {
		args = append(args, "--llm="+req.LLM)
	}
	if req.Model != "" {
		args = append(args, "--model="+req.Model)
	}
	if req.ReasoningModel != "" {
		args = append(args, "--reasoning-model="+req.ReasoningModel)
	}
	if req.BaseURL != "" {
		args = append(args, "--llm-url="+req.BaseURL)
	}
	// ALWAYS pass --budget — including 0, which means "no cap". Without
	// this the subprocess falls back to the CLI default of $5, so picking
	// "unlimited" in the UI for a token-based subscription (Minimax, etc.)
	// would silently cap the scan at $5. Negative values normalize to 0.
	bc := req.BudgetCents
	if bc < 0 {
		bc = 0
	}
	args = append(args, "--budget="+strconv.Itoa(bc))
	args = appendStrategistArgs(args, req.StrategistModel, req.StrategistPeriodS)

	cmd := exec.Command(exe, args...)
	configureScanProcess(cmd)
	// Pass the API key AND session cookie via environment rather than argv
	// so they stay out of process listings. The scan command falls back to
	// AOBTD_LLM_KEY / AOBTD_SESSION_COOKIE if the respective --flag isn't set.
	cmd.Env = os.Environ()
	if resolvedAPIKey != "" {
		cmd.Env = append(cmd.Env, "AOBTD_LLM_KEY="+resolvedAPIKey)
	}
	if req.SessionCookie != "" {
		cmd.Env = append(cmd.Env, "AOBTD_SESSION_COOKIE="+req.SessionCookie)
	}
	if req.LoginURL != "" && req.LoginUser != "" && req.LoginPass != "" {
		cmd.Env = append(cmd.Env,
			"AOBTD_LOGIN_URL="+req.LoginURL,
			"AOBTD_LOGIN_USER="+req.LoginUser,
			"AOBTD_LOGIN_PASS="+req.LoginPass,
		)
	}
	cmd.Env = appendBOLAEnv(cmd.Env, req)
	// Inherit output dir / working dir — runs from wherever the UI was launched.
	cmd.Stdout = nil
	cmd.Stderr = nil

	// Snapshot the highest scan id BEFORE we spawn. The frontend uses this
	// watermark to disambiguate the just-started scan from any previous scan
	// of the same target (without it, scans.find(target==t) would match an
	// old completed run for the same site — the "I got dropped into a random
	// previous example scan" bug).
	var maxIDBefore int64
	if err := s.db.Conn().QueryRow(`SELECT COALESCE(MAX(id), 0) FROM scans`).Scan(&maxIDBefore); err != nil {
		s.logger.Warn("failed to read max scan id before spawn", "error", err)
	}

	if err := cmd.Start(); err != nil {
		jsonError(w, "failed to start scan: "+err.Error(), 500)
		return
	}
	// Keep a UI-supplied cloud credential in server memory so the Copilot can
	// inherit this scan's provider without asking the browser to resend a key.
	// The key is intentionally never written into config_json. Remember it
	// only after a scan actually starts so a rejected start cannot replace the
	// credential used by the current scan.
	s.rememberCopilotCredential(req.LLM, req.BaseURL, resolvedAPIKey)

	s.activeProc = cmd
	done := make(chan struct{})
	s.activeDone = done
	s.activeInfo = &activeScanInfo{
		Target:           req.Target,
		MaxPages:         req.MaxPages,
		LLM:              req.LLM,
		TestingAuthority: testingAuthority,
		StartedAt:        time.Now(),
		PID:              cmd.Process.Pid,
		Authenticated:    req.SessionCookie != "" || (req.LoginURL != "" && req.LoginUser != "" && req.LoginPass != ""),
		MaxIDBefore:      maxIDBefore,
	}
	s.logger.Info("scan started from UI",
		"target", req.Target, "pid", cmd.Process.Pid, "max_id_before", maxIDBefore,
		"testing_authority", testingAuthority)

	// Wait in the background, clear state when done.
	go func(c *exec.Cmd, done chan struct{}) {
		_ = c.Wait()
		close(done)
		s.activeMu.Lock()
		defer s.activeMu.Unlock()
		if s.activeProc == c {
			s.activeProc = nil
			s.activeInfo = nil
			s.activeDone = nil
			s.logger.Info("scan subprocess exited", "pid", c.Process.Pid)
		}
	}(cmd, done)

	jsonResponse(w, map[string]any{
		"status":             "started",
		"pid":                cmd.Process.Pid,
		"target":             req.Target,
		"max_pages":          req.MaxPages,
		"llm":                req.LLM,
		"testing_authority":  testingAuthority,
		"started_at":         s.activeInfo.StartedAt.Format(time.RFC3339),
		"max_scan_id_before": maxIDBefore,
	})
}

// handleScanStop terminates the currently running UI-launched scan. Returns
// 404 if no scan is active.
func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}

	s.activeMu.Lock()
	proc := s.activeProc
	info := s.activeInfo
	done := s.activeDone
	s.activeMu.Unlock()

	if proc == nil || proc.Process == nil {
		jsonError(w, "no scan is running", 404)
		return
	}

	s.logger.Info("stopping scan from UI", "pid", proc.Process.Pid)

	// Give the scanner a chance to cancel its orchestrator and close Chrome.
	// Some platforms do not support os.Interrupt for child processes; those
	// fall back to Kill immediately. Otherwise force-kill after a short grace.
	interruptErr := interruptScanProcess(proc)
	if interruptErr == nil && done != nil {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			interruptErr = fmt.Errorf("interrupt grace period elapsed")
		}
	}
	if interruptErr != nil {
		if err := killScanProcess(proc); err != nil {
			select {
			case <-done:
			default:
				jsonError(w, "failed to stop scan: "+err.Error(), 500)
				return
			}
		}
	}

	// Best effort: mark the scan row as interrupted so the dropdown updates
	// immediately without waiting 30 minutes for the stale-scan sweep. Match
	// by spawn watermark rather than target text: canonical resolution may
	// change example.com into www.example.com/path inside the subprocess.
	if info != nil {
		if err := markSpawnedScanInterrupted(s.db, info.MaxIDBefore); err != nil {
			s.logger.Warn("failed to finalize stopped scan row", "error", err, "max_id_before", info.MaxIDBefore)
		}
	}

	jsonResponse(w, map[string]any{"status": "stopped", "pid": proc.Process.Pid})
}

func markSpawnedScanInterrupted(db *store.DB, maxIDBefore int64) error {
	result, err := db.Conn().Exec(`
		UPDATE scans SET status = 'interrupted', finished_at = datetime('now')
		WHERE status = 'running'
		  AND id = (SELECT MAX(id) FROM scans WHERE id > ? AND status = 'running')`,
		maxIDBefore)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("no running scan found above spawn watermark %d", maxIDBefore)
	}
	return nil
}

// handleStrategy returns the full Sovereign Strategist state — hypotheses,
// recent planning cycles, and the directives the Strategist has emitted
// (filtered from follow_ups by emitted_by='strategist'). Powers the
// Strategy nav tab.
func (s *Server) handleStrategy(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)

	hyps, _ := s.db.ListHypotheses(scanID)
	cycles, _ := s.db.ListStrategistCycles(scanID, 30)
	events, _ := s.db.ListHypothesisEvents(scanID, 500)

	// Directives the Strategist emitted. We pull from follow_ups with
	// emitted_by='strategist', carrying status, priority, reason, and the
	// hypothesis it's testing.
	rows, err := s.db.Conn().Query(`
		SELECT id, action, COALESCE(url,''), COALESCE(params_json,'{}'),
		       COALESCE(reason,''), priority, status, COALESCE(result,''),
		       COALESCE(hypothesis_id,''), COALESCE(grounded_in,'[]'),
		       created_at, COALESCE(completed_at,'')
		FROM follow_ups
		WHERE scan_id = ? AND emitted_by = 'strategist'
		ORDER BY
			CASE status WHEN 'running' THEN 0 WHEN 'pending' THEN 1
			           WHEN 'done' THEN 2 WHEN 'failed' THEN 3 ELSE 4 END,
			priority DESC, id DESC
		LIMIT 200`, scanID)
	type directiveOut struct {
		ID           int64          `json:"id"`
		Action       string         `json:"action"`
		URL          string         `json:"url,omitempty"`
		Params       map[string]any `json:"params,omitempty"`
		Reason       string         `json:"reason,omitempty"`
		Priority     int            `json:"priority"`
		Status       string         `json:"status"`
		Result       string         `json:"result,omitempty"`
		HypothesisID string         `json:"hypothesis_id,omitempty"`
		GroundedIn   []string       `json:"grounded_in,omitempty"`
		CreatedAt    string         `json:"created_at"`
		CompletedAt  string         `json:"completed_at,omitempty"`
	}
	var directives []directiveOut
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var d directiveOut
			var paramsJSON, groundedJSON string
			if err := rows.Scan(&d.ID, &d.Action, &d.URL, &paramsJSON, &d.Reason,
				&d.Priority, &d.Status, &d.Result, &d.HypothesisID, &groundedJSON,
				&d.CreatedAt, &d.CompletedAt); err != nil {
				continue
			}
			if paramsJSON != "" && paramsJSON != "{}" {
				var p map[string]any
				if json.Unmarshal([]byte(paramsJSON), &p) == nil {
					d.Params = p
				}
			}
			if groundedJSON != "" && groundedJSON != "[]" {
				json.Unmarshal([]byte(groundedJSON), &d.GroundedIn)
			}
			directives = append(directives, d)
		}
	}

	// Counts for badges
	var hypActive, hypConfirmed, hypRefuted int
	for _, h := range hyps {
		switch h.Status {
		case store.HypothesisActive:
			hypActive++
		case store.HypothesisConfirmed:
			hypConfirmed++
		case store.HypothesisRefuted:
			hypRefuted++
		}
	}

	jsonResponse(w, map[string]any{
		"hypotheses":    hyps,
		"cycles":        cycles,
		"directives":    directives,
		"events":        events,
		"thought_trail": buildThoughtTrail(s.db, scanID),
		"counts": map[string]int{
			"hypotheses_active":    hypActive,
			"hypotheses_confirmed": hypConfirmed,
			"hypotheses_refuted":   hypRefuted,
			"directives_total":     len(directives),
			"cycles_total":         len(cycles),
		},
	})
}

// handleChanges returns the asset-change list for a scan — one row per
// JS/HTML file that differs from the most recent prior scan of the same
// target. Each row includes an LLM comment + severity when available.
//
// Also returns the timeline of every prior scan of the same target so the
// Changes view can render a "you are here" strip without a second request.
func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	limit := intParam(r, "limit", 200)

	list, err := s.db.ListAssetChanges(scanID, limit)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	counts, _ := s.db.CountAssetChanges(scanID)
	if list == nil {
		list = []store.AssetChange{}
	}

	// Pull the scan target so we can attach the cross-scan timeline.
	var target string
	_ = s.db.Conn().QueryRow(`SELECT target FROM scans WHERE id = ?`, scanID).Scan(&target)

	var timeline []store.TimelineEntry
	if target != "" {
		timeline, _ = s.db.TimelineForTarget(target)
	}
	if timeline == nil {
		timeline = []store.TimelineEntry{}
	}

	jsonResponse(w, map[string]any{
		"changes":    list,
		"counts":     counts,
		"target":     target,
		"current_id": scanID,
		"timeline":   timeline,
	})
}

// handleFollowUps returns the follow-up queue for a scan, optionally
// filtered by status (?status=pending|running|done|failed|skipped).
// Also returns counts by status so the UI can render a mini dashboard.
func (s *Server) handleFollowUps(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	limit := intParam(r, "limit", 50)

	list, err := s.db.ListFollowUps(scanID, limit)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	counts, _ := s.db.CountFollowUpsByStatus(scanID)
	if list == nil {
		list = []store.FollowUp{}
	}

	jsonResponse(w, map[string]any{
		"tasks":  list,
		"counts": counts,
	})
}

// handleReconLearningQueue exposes the scanner's actual evidence-processing
// loop: captured endpoint families waiting for AI analysis, the semantic
// reasons that changed their order, and the separate execution follow-up
// queue. It is deliberately read-only and never fabricates progress rows.
func (s *Server) handleReconLearningQueue(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	const threshold = 0.3

	queue, err := s.db.GetUnanalyzedEndpointQueue(scanID, threshold, scanagent.AnalysisCandidateWindowSize)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u := extract.NewAppUnderstanding()
	if raw, loadErr := s.db.GetReconModel(scanID); loadErr == nil {
		u.LoadReconJSON(raw)
	}
	ages, _ := s.db.GetAnalysisQueueAges(scanID)
	calibration, _ := s.db.ListAnalysisImpactCalibration(scanID)
	queue = scanagent.RankAnalysisQueueWithFeedback(queue, u.Recon, ages, scanagent.AnalysisImpactCalibrationMap(calibration))
	aiReady := 0
	autoSkip := 0
	for _, item := range queue {
		if item.Disposition == "skip" {
			autoSkip++
		} else {
			aiReady++
		}
	}
	visibleQueue := queue
	if len(visibleQueue) > 12 {
		visibleQueue = visibleQueue[:12]
	}
	counts, _ := s.db.GetAnalysisQueueCounts(scanID, threshold)
	objectives, _ := scanagent.NewReconPlanner(s.db, scanID).Plan(3)
	followUps, _ := s.db.ListFollowUps(scanID, 12)
	followUpCounts, _ := s.db.CountFollowUpsByStatus(scanID)
	history, _ := s.db.ListAnalysisLearningCheckpoints(scanID, 4, 6)
	efficiency, _ := s.db.GetAnalysisEfficiencySummary(scanID)
	protectionEvidence, _ := s.db.GetProtectionEvidenceSummary(scanID)
	if followUps == nil {
		followUps = []store.FollowUp{}
	}
	if objectives == nil {
		objectives = []scanagent.ReconObjective{}
	}
	if history == nil {
		history = []store.AnalysisLearningCheckpoint{}
	}

	jsonResponse(w, map[string]any{
		"analysis": map[string]any{
			"threshold": threshold, "counts": counts, "items": visibleQueue,
			"feedback_batch_size": scanagent.AnalysisLearningBatchSize,
			"candidate_window":    scanagent.AnalysisCandidateWindowSize,
			"candidate_count":     len(queue), "window_truncated": counts.Ready > len(queue),
			"ai_ready": aiReady, "auto_skip": autoSkip,
		},
		"efficiency":  efficiency,
		"protection":  protectionEvidence,
		"history":     history,
		"calibration": calibration,
		"objectives":  objectives,
		"follow_ups":  map[string]any{"counts": followUpCounts, "tasks": followUps},
	})
}

// handleTargetBrain unifies the normalized application model, the real
// capture-backed analysis queue, and durable learning outcomes into one
// compact adaptive plan. It is read-only: observe/prerequisite rows are not
// executable actions, and analysis rows can only reference captured evidence.
func (s *Server) handleTargetBrain(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	const threshold = 0.3

	u := extract.NewAppUnderstanding()
	if appType, _, _, _, summary, err := s.db.GetAppUnderstanding(scanID); err == nil {
		u.AppType = appType
		u.Summary = summary
	}
	if raw, err := s.db.GetReconModel(scanID); err == nil {
		u.LoadReconJSON(raw)
	}
	u.RefreshQueryRoutedPagePurposeCards(s.reconQueryRouteViews(scanID))
	u.RefreshClientRoutedPagePurposeCards(s.reconClientRouteViews(scanID))
	u.NormalizeReconModel()
	access := s.reconAccessState(scanID, len(u.Recon.Pages))
	u.ApplyReconAccessCeiling(access["state"])
	// Target Brain objectives and claims must use the same redirect evidence
	// ceiling as /api/understanding; otherwise a historical route-name guess
	// can keep steering the live plan after the visible Recon card is fixed.
	s.projectUnderstandingRedirectEvidence(scanID, u)

	queue, err := s.db.GetUnanalyzedEndpointQueue(scanID, threshold, scanagent.AnalysisCandidateWindowSize)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ages, _ := s.db.GetAnalysisQueueAges(scanID)
	calibration, _ := s.db.ListAnalysisImpactCalibration(scanID)
	queue = scanagent.RankAnalysisQueueWithFeedback(queue, u.Recon, ages, scanagent.AnalysisImpactCalibrationMap(calibration))
	history, _ := s.db.ListAnalysisLearningCheckpoints(scanID, 6, 12)
	objectives := scanagent.BuildReconObjectives(u.Recon, 6)
	brain := scanagent.BuildTargetBrain(u.Recon, objectives, queue, history)
	brain.ScanID = scanID
	scanagent.ApplyTargetBrainAccess(&brain, access["state"], access["label"], access["detail"])
	jsonResponse(w, brain)
}

// handleScanActive returns info about the currently running scan (if any).
func (s *Server) handleScanActive(w http.ResponseWriter, r *http.Request) {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.activeInfo == nil {
		jsonResponse(w, map[string]any{"active": false})
		return
	}
	jsonResponse(w, map[string]any{
		"active":            true,
		"target":            s.activeInfo.Target,
		"max_pages":         s.activeInfo.MaxPages,
		"llm":               s.activeInfo.LLM,
		"testing_authority": s.activeInfo.TestingAuthority,
		"pid":               s.activeInfo.PID,
		"started_at":        s.activeInfo.StartedAt.Format(time.RFC3339),
		"authenticated":     s.activeInfo.Authenticated,
	})
}

type liveFrameMetadata struct {
	ID             string                        `json:"id"`
	URL            string                        `json:"url"`
	LastAction     string                        `json:"last_action,omitempty"`
	UpdatedAt      time.Time                     `json:"updated_at"`
	Active         bool                          `json:"active"`
	Status         string                        `json:"status"`
	HasImage       bool                          `json:"has_image"`
	ImageVersion   string                        `json:"image_version,omitempty"`
	ImageUpdatedAt *time.Time                    `json:"image_updated_at,omitempty"`
	Interaction    *liveFrameInteractionMetadata `json:"interaction,omitempty"`
}

type liveFrameInteractionMetadata struct {
	Agent       string     `json:"agent,omitempty"`
	Action      string     `json:"action"`
	Selector    string     `json:"selector,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	URL         string     `json:"url,omitempty"`
	State       string     `json:"state"`
	X           float64    `json:"x,omitempty"`
	Y           float64    `json:"y,omitempty"`
	Width       float64    `json:"width,omitempty"`
	Height      float64    `json:"height,omitempty"`
	HasBounds   bool       `json:"has_bounds,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type liveFrameManifest struct {
	Frames           []liveFrameMetadata `json:"frames"`
	CapturedAt       time.Time           `json:"captured_at"`
	Status           string              `json:"status"`
	SessionActive    bool                `json:"session_active"`
	BrowserConnected bool                `json:"browser_connected"`
	HasTabs          bool                `json:"has_tabs"`
	HasImages        bool                `json:"has_images"`
	Active           bool                `json:"active"`
}

const liveFrameManifestStaleAfter = 5 * time.Second

// handleLiveFrames returns the active-tab manifest written by the browser
// controller. A legacy scanner without a manifest is represented as a single
// frame so new UIs remain backwards-compatible with scans already in flight.
func (s *Server) handleLiveFrames(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	framesDir := filepath.Join(s.outputDir, "frames")
	manifestPath := filepath.Join(framesDir, fmt.Sprintf("scan-%d.json", scanID))

	data, err := os.ReadFile(manifestPath)
	if err == nil {
		var manifest liveFrameManifest
		if json.Unmarshal(data, &manifest) == nil {
			// The capture loop only updates a manifest while a browser page is
			// alive. Preserve its last useful image for operator context, but mark
			// it idle instead of claiming the closed tab is still active during a
			// long analysis phase.
			// Manifests written before explicit session state existed implied an
			// active capture loop while their heartbeat was fresh.
			legacyManifest := manifest.Status == ""
			fresh := !manifest.CapturedAt.IsZero() && time.Since(manifest.CapturedAt) <= liveFrameManifestStaleAfter
			if legacyManifest {
				manifest.Status = "legacy"
				// Old manifests did not carry lifecycle fields. Their heartbeat is
				// the only evidence that a browser session still exists, so a stale
				// replay image must never be described as connected or reasoning.
				manifest.SessionActive = fresh
				manifest.BrowserConnected = fresh && len(manifest.Frames) > 0
				manifest.HasTabs = fresh && len(manifest.Frames) > 0
				for i := range manifest.Frames {
					framePath := filepath.Join(framesDir, fmt.Sprintf("scan-%d-frame-%s.jpg", scanID, manifest.Frames[i].ID))
					if _, statErr := os.Stat(framePath); statErr == nil {
						manifest.Frames[i].HasImage = true
						manifest.Frames[i].Status = "legacy_image"
						manifest.HasImages = true
					}
				}
			}
			// Explicit lifecycle fields are still heartbeat claims, not durable
			// proof. A crashed/old writer can leave `session_active: true` behind;
			// once the manifest is stale (or explicitly stopped), expose its images
			// only as replay and never say the browser is connected or reasoning.
			if !fresh || !manifest.SessionActive {
				manifest.SessionActive = false
				manifest.BrowserConnected = false
				manifest.HasTabs = false
			}
			if legacyManifest {
				manifest.Active = manifest.SessionActive && manifest.HasTabs && fresh
				for i := range manifest.Frames {
					manifest.Frames[i].Active = manifest.Active
				}
			} else {
				// A fresh capture heartbeat means the browser worker is still
				// reasoning; it does not mean a retained bitmap is a live tab. New
				// manifests must assert both a tab and at least one active frame.
				anyActiveFrame := false
				for _, frame := range manifest.Frames {
					anyActiveFrame = anyActiveFrame || frame.Active
				}
				manifest.Active = manifest.SessionActive && manifest.HasTabs && anyActiveFrame && fresh
				if !manifest.Active {
					for i := range manifest.Frames {
						manifest.Frames[i].Active = false
						manifest.Frames[i].Interaction = nil
					}
				}
			}
			if manifest.Frames == nil {
				manifest.Frames = []liveFrameMetadata{}
			}
			w.Header().Set("Cache-Control", "no-store")
			jsonResponse(w, manifest)
			return
		}
	}

	for _, ext := range []string{"jpg", "png"} {
		legacyPath := filepath.Join(framesDir, fmt.Sprintf("scan-%d.%s", scanID, ext))
		if info, statErr := os.Stat(legacyPath); statErr == nil {
			w.Header().Set("Cache-Control", "no-store")
			jsonResponse(w, liveFrameManifest{
				Frames: []liveFrameMetadata{{
					ID:        "legacy",
					UpdatedAt: info.ModTime().UTC(), Active: time.Since(info.ModTime()) <= liveFrameManifestStaleAfter,
					Status: "legacy_image", HasImage: true,
				}},
				CapturedAt: info.ModTime().UTC(), Status: "legacy",
				SessionActive:    time.Since(info.ModTime()) <= liveFrameManifestStaleAfter,
				BrowserConnected: time.Since(info.ModTime()) <= liveFrameManifestStaleAfter,
				HasTabs:          time.Since(info.ModTime()) <= liveFrameManifestStaleAfter,
				HasImages:        true,
				Active:           time.Since(info.ModTime()) <= liveFrameManifestStaleAfter,
			})
			return
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, liveFrameManifest{Frames: []liveFrameMetadata{}, Status: "not_started", Active: false})
}

// handleLiveFrame serves one browser frame for a scan. frame_id selects an
// active tab; omitting it keeps the original newest-tab endpoint contract.
// Returns 204 when no frame is ready.
func (s *Server) handleLiveFrame(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	framesDir := filepath.Join(s.outputDir, "frames")
	frameID := r.URL.Query().Get("frame_id")
	if frameID != "" && frameID != "legacy" {
		if !validLiveFrameID(frameID) {
			jsonError(w, "invalid frame id", http.StatusBadRequest)
			return
		}
		// New manifests explicitly say whether the current URL has a matching
		// bitmap. Consult that state before touching the frame file so the tiny
		// manifest/file cleanup window cannot expose an image from the tab's
		// previous navigation.
		manifestPath := filepath.Join(framesDir, fmt.Sprintf("scan-%d.json", scanID))
		frameVersion := ""
		manifestStatus := ""
		manifestSessionActive := true
		frameActive := true
		manifestStateKnown := false
		if data, err := os.ReadFile(manifestPath); err == nil {
			var manifest liveFrameManifest
			if json.Unmarshal(data, &manifest) == nil && manifest.Status != "" {
				manifestStateKnown = true
				manifestStatus = strings.ToLower(strings.TrimSpace(manifest.Status))
				manifestSessionActive = manifest.SessionActive
				hasCurrentImage := false
				for _, frame := range manifest.Frames {
					if frame.ID == frameID {
						hasCurrentImage = frame.HasImage
						frameVersion = frame.ImageVersion
						frameActive = frame.Active
						break
					}
				}
				if !hasCurrentImage {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}
		if frameVersion != "" {
			requestedVersion := strings.TrimSpace(r.URL.Query().Get("v"))
			// The manifest-selected immutable file is safe when an older UI does
			// not know about generations yet. A supplied generation, however,
			// must match exactly so stale metadata can never receive new pixels.
			if !validLiveFrameVersion(frameVersion) || (requestedVersion != "" && requestedVersion != frameVersion) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			versionedPath := filepath.Join(framesDir,
				fmt.Sprintf("scan-%d-frame-%s-%s.jpg", scanID, frameID, frameVersion))
			if _, err := os.Stat(versionedPath); err == nil {
				serveLiveFrameFile(w, versionedPath, "jpg")
				return
			}
			// Mixed-era manifests already carried an image_version but wrote only
			// scan-<id>-frame-<frame>.jpg. Restore those stopped/replay scans only
			// when the actual stable file hashes to the manifest's generation. New
			// active captures never fall back to a mutable filename.
			historicalReplay := manifestStateKnown && !frameActive &&
				(!manifestSessionActive || manifestStatus == "stopped" || manifestStatus == "saved_frames")
			if historicalReplay {
				stablePath := filepath.Join(framesDir, fmt.Sprintf("scan-%d-frame-%s.jpg", scanID, frameID))
				if serveHistoricalLiveFrameGeneration(w, stablePath, frameVersion) {
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		serveLiveFrameFile(w, filepath.Join(framesDir,
			fmt.Sprintf("scan-%d-frame-%s.jpg", scanID, frameID)), "jpg")
		return
	}

	// Check both extensions — earlier builds wrote .png, current writes .jpg.
	for _, ext := range []string{"jpg", "png"} {
		path := filepath.Join(framesDir, fmt.Sprintf("scan-%d.%s", scanID, ext))
		if _, err := os.Stat(path); err == nil {
			serveLiveFrameFile(w, path, ext)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// serveHistoricalLiveFrameGeneration serves a mixed-era stable frame only
// when its bytes prove the immutable generation declared by the manifest.
// Reading and writing the same byte slice avoids a hash-then-open race with an
// older writer that may still be replacing the stable path.
func serveHistoricalLiveFrameGeneration(w http.ResponseWriter, path, version string) bool {
	if !validLiveFrameVersion(version) {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return false
	}
	digest := sha256.Sum256(data)
	if fmt.Sprintf("%x", digest[:8]) != version {
		return false
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
	return true
}

func serveLiveFrameFile(w http.ResponseWriter, path, ext string) {
	f, err := os.Open(path)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	defer f.Close()
	if ext == "png" {
		w.Header().Set("Content-Type", "image/png")
	} else {
		w.Header().Set("Content-Type", "image/jpeg")
	}
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}

func validLiveFrameID(frameID string) bool {
	if len(frameID) != 12 {
		return false
	}
	for _, r := range frameID {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func validLiveFrameVersion(version string) bool {
	if len(version) != 16 {
		return false
	}
	for _, r := range version {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// handleNarrations returns narrations for a scan. Supports ?since=<id> to get
// only narrations newer than a given id (used for polling fallback).
func (s *Server) handleNarrations(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	since := int64(intParam(r, "since", 0))
	limit := intParam(r, "limit", 500)

	var (
		narrations []store.Narration
		err        error
	)
	if r.URL.Query().Get("latest") == "1" && since == 0 {
		narrations, err = s.db.GetRecentNarrations(scanID, limit)
	} else {
		narrations, err = s.db.GetNarrations(scanID, since, limit)
	}
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if narrations == nil {
		narrations = []store.Narration{}
	}
	jsonResponse(w, narrations)
}

// handleNarrationsStream streams narrations over Server-Sent Events.
// The client specifies ?since=<id> to resume from a known point. New narrations
// are pushed every ~500ms while the connection is open.
func (s *Server) handleNarrationsStream(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	since := int64(intParam(r, "since", 0))

	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, "streaming not supported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering if proxied

	// Initial comment to establish stream
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ctx := r.Context()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// Heartbeat every 15s to keep connection alive
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-ticker.C:
			narrations, err := s.db.GetNarrations(scanID, since, 200)
			if err != nil {
				continue
			}
			for _, n := range narrations {
				data, err := json.Marshal(n)
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "id: %d\nevent: narration\ndata: %s\n\n", n.ID, string(data))
				if n.ID > since {
					since = n.ID
				}
			}
			if len(narrations) > 0 {
				flusher.Flush()
			}
		}
	}
}
