package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/store"
)

// ChangeDetector diffs the current scan's JS/HTML assets against the most
// recent prior scan of the same target and (if an LLM is configured) asks
// the LLM to comment on the security implications of each diff.
//
// This is the "scan for a week, tell me what changed" feature — the cleanest
// differentiator from traditional DAST. Humans can't watch a site for drift
// and reason about every change; an LLM can.
type ChangeDetector struct {
	db       *store.DB
	scanID   int64
	target   string
	provider llm.Provider // nil OK — detection still runs, just without commentary
	budget   *llm.Budget
	logger   *slog.Logger

	maxDiffsToComment int // cap LLM calls per scan
}

// NewChangeDetector creates a change detector for one scan.
func NewChangeDetector(db *store.DB, scanID int64, target string, provider llm.Provider, budget *llm.Budget, logger *slog.Logger) *ChangeDetector {
	return &ChangeDetector{
		db:                db,
		scanID:            scanID,
		target:            target,
		provider:          provider,
		budget:            budget,
		logger:            logger,
		maxDiffsToComment: 15, // per-scan LLM commentary budget
	}
}

func (d *ChangeDetector) Name() string { return "change-detector" }

// Start runs the detector. It:
//  1. Scans the traffic table and records a hash for every HTML/JS response.
//  2. For each hashed URL, looks up the most recent prior scan of the same
//     target and compares hashes.
//  3. For URLs where hashes differ, generates a line-level diff snippet.
//  4. For each substantive diff, calls the LLM to produce natural-language
//     commentary and a suggested severity.
func (d *ChangeDetector) Start(ctx context.Context) error {
	// Step 1: hash every interesting asset captured in this scan
	hashed, err := d.hashScanAssets()
	if err != nil {
		return fmt.Errorf("hash assets: %w", err)
	}
	if hashed == 0 {
		d.logger.Info("change-detector: no hashable assets in this scan")
		return nil
	}

	d.logger.Info("change-detector: hashed assets", "count", hashed)

	// Step 2: compare against prior scans of the same target
	current, err := d.db.AssetHashesForScan(d.scanID)
	if err != nil {
		return fmt.Errorf("load current hashes: %w", err)
	}

	var diffs []assetDiff
	for _, cur := range current {
		if ctx.Err() != nil {
			break
		}
		prior, err := d.db.PriorAssetHash(d.target, d.scanID, cur.URL)
		if err != nil {
			continue // no baseline — nothing to compare
		}
		if prior.ContentHash == cur.ContentHash {
			continue // unchanged
		}

		// Different hash — build a diff snippet from actual bodies
		prevBody, _, _ := d.db.BodyForScanURL(prior.ScanID, cur.URL)
		newBody, _, _ := d.db.BodyForScanURL(cur.ScanID, cur.URL)
		snippet := buildDiffSnippet(prevBody, newBody, 4000)

		diffs = append(diffs, assetDiff{
			URL:         cur.URL,
			Host:        cur.Host,
			ContentType: cur.ContentType,
			PrevScanID:  prior.ScanID,
			PrevHash:    prior.ContentHash,
			NewHash:     cur.ContentHash,
			PrevSize:    prior.ResponseSize,
			NewSize:     cur.ResponseSize,
			Snippet:     snippet,
		})
	}

	if len(diffs) == 0 {
		d.db.InsertNarration(d.scanID, "change-detector", "complete",
			fmt.Sprintf("Compared %d asset(s) against prior scans — nothing changed.", len(current)),
			"", nil)
		d.logger.Info("change-detector: no changes detected")
		return nil
	}

	d.db.InsertNarration(d.scanID, "change-detector", "start",
		fmt.Sprintf("Detected %d changed asset(s) since the last scan of %s. Reviewing each one.",
			len(diffs), d.target),
		"", map[string]any{"changed_count": len(diffs)})

	// Step 3: for each diff, persist it and (if LLM available) ask for commentary
	commented := 0
	for i, diff := range diffs {
		if ctx.Err() != nil {
			break
		}

		// Default: store without LLM comment
		change := store.AssetChange{
			ScanID:      d.scanID,
			PrevScanID:  diff.PrevScanID,
			URL:         diff.URL,
			Host:        diff.Host,
			ContentType: diff.ContentType,
			PrevHash:    diff.PrevHash,
			NewHash:     diff.NewHash,
			PrevSize:    diff.PrevSize,
			NewSize:     diff.NewSize,
			Kind:        "modified",
			DiffSnippet: diff.Snippet,
			Severity:    "info",
		}

		// Ask the LLM for commentary on the first N diffs
		if d.provider != nil && d.budget != nil && i < d.maxDiffsToComment && d.budget.Level() != llm.BudgetExhausted {
			if verdict, err := d.commentOnDiff(ctx, diff); err == nil && verdict != nil {
				change.LLMComment = verdict.Comment
				change.Severity = strings.ToLower(verdict.Severity)
				commented++

				// Narrate: show the LLM's take in the Live feed so it looks
				// like the agent is reasoning about evolution of the app.
				d.db.InsertNarration(d.scanID, "change-detector", "diff",
					fmt.Sprintf("[%s] %s — %s", strings.ToUpper(change.Severity),
						shortenURLForChange(diff.URL), verdict.Comment),
					diff.URL, map[string]any{
						"severity":     change.Severity,
						"prev_scan_id": diff.PrevScanID,
					})
			}
		}

		if _, err := d.db.InsertAssetChange(change); err != nil {
			d.logger.Warn("insert asset_change failed", "error", err, "url", diff.URL)
		}
	}

	d.db.InsertNarration(d.scanID, "change-detector", "complete",
		fmt.Sprintf("Change detection complete: %d change(s) recorded, %d commented by the LLM.",
			len(diffs), commented),
		"", nil)
	d.logger.Info("change-detector done", "changes", len(diffs), "commented", commented)
	return nil
}

// hashScanAssets reads the traffic table for the current scan, picks out
// HTML/JS responses, and writes one asset_hashes row per unique URL.
//
// IMPORTANT: the DB pool is configured with MaxOpenConns(1), so we MUST
// fully drain and close the SELECT cursor before issuing the UpsertAssetHash
// writes. The previous version did the writes inside `for rows.Next()` which
// deadlocked the single connection (SELECT cursor held it, UPSERT waited for
// it, forever). This is what caused scan 23 to hang in Change Detection for
// 70+ minutes.
func (d *ChangeDetector) hashScanAssets() (int, error) {
	// Phase 1: read every candidate row into memory. We filter+dedup here so
	// the memory footprint stays bounded (at most one entry per unique URL).
	rows, err := d.db.Conn().Query(`
		SELECT url, host, COALESCE(content_type,''), COALESCE(response_body, X''), response_size
		FROM traffic_resolved
		WHERE scan_id = ?
		  AND is_filtered = FALSE
		  AND status_code BETWEEN 200 AND 299
		ORDER BY id DESC`, d.scanID)
	if err != nil {
		return 0, err
	}

	type pending struct {
		URL, Host, ContentType string
		Hash                   string
		Size                   int
	}
	seen := make(map[string]bool)
	var queue []pending
	for rows.Next() {
		var u, host, contentType string
		var body []byte
		var size int
		if err := rows.Scan(&u, &host, &contentType, &body, &size); err != nil {
			continue
		}
		if seen[u] {
			continue // most recent wins — we iterate DESC
		}
		if !isHashable(contentType, u, body) {
			continue
		}
		seen[u] = true
		queue = append(queue, pending{
			URL:         u,
			Host:        host,
			ContentType: contentType,
			Hash:        store.HashContent(body),
			Size:        size,
		})
	}
	rows.Close() // MUST be before we start writing

	// Phase 2: now that the cursor is freed, issue the upserts.
	var n int
	for _, p := range queue {
		if err := d.db.UpsertAssetHash(d.scanID, store.AssetHash{
			URL:          p.URL,
			Host:         p.Host,
			ContentHash:  p.Hash,
			ContentType:  p.ContentType,
			ResponseSize: p.Size,
		}); err != nil {
			continue
		}
		n++
	}
	return n, nil
}

// isHashable gates which responses we track. We care about HTML, JS, and
// well-known config endpoints — anything that typically drives client
// behavior and can change between deploys.
func isHashable(contentType, u string, body []byte) bool {
	if len(body) == 0 {
		return false
	}
	// Skip anything too big — the proxy's response-body cap should already
	// prevent this, but be defensive.
	if len(body) > 2*1024*1024 {
		return false
	}
	lower := strings.ToLower(contentType)
	if strings.Contains(lower, "html") || strings.Contains(lower, "javascript") ||
		strings.Contains(lower, "ecmascript") || strings.Contains(lower, "/json") {
		// JSON is noisy (dynamic data) — only hash it for URLs that look like
		// config endpoints, not query responses.
		if strings.Contains(lower, "/json") {
			lu := strings.ToLower(u)
			return strings.Contains(lu, "config") ||
				strings.Contains(lu, "manifest") ||
				strings.Contains(lu, "/.well-known/") ||
				strings.Contains(lu, "openapi") ||
				strings.Contains(lu, "swagger")
		}
		return true
	}
	// File extension fallback (some servers don't set content-type correctly)
	lu := strings.ToLower(u)
	for _, ext := range []string{".js", ".mjs", ".html", ".htm"} {
		if strings.HasSuffix(strings.SplitN(lu, "?", 2)[0], ext) {
			return true
		}
	}
	return false
}

// assetDiff is an in-memory holder used while we walk candidates.
type assetDiff struct {
	URL         string
	Host        string
	ContentType string
	PrevScanID  int64
	PrevHash    string
	NewHash     string
	PrevSize    int
	NewSize     int
	Snippet     string
}

// shortenURLForChange returns a pathname-only form of a URL for narrations.
func shortenURLForChange(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Path == "" {
		return u
	}
	return parsed.Path
}

// ── Diff snippet generation ──

// buildDiffSnippet returns a bounded line-diff between two bodies. We keep
// it cheap — no proper diffing, just lines that are in the new version but
// not the previous one (and vice versa). Good enough for LLM context and
// dodges the cost of a real Myers diff on hundred-KB JS bundles.
func buildDiffSnippet(prev, next []byte, maxLen int) string {
	prevLines := splitAndNormalize(prev)
	nextLines := splitAndNormalize(next)

	prevSet := make(map[string]bool, len(prevLines))
	for _, l := range prevLines {
		prevSet[l] = true
	}
	nextSet := make(map[string]bool, len(nextLines))
	for _, l := range nextLines {
		nextSet[l] = true
	}

	var added, removed []string
	for _, l := range nextLines {
		if !prevSet[l] && strings.TrimSpace(l) != "" {
			added = append(added, l)
		}
	}
	for _, l := range prevLines {
		if !nextSet[l] && strings.TrimSpace(l) != "" {
			removed = append(removed, l)
		}
	}

	// Cap so the prompt stays sane
	const maxLinesEach = 80
	if len(added) > maxLinesEach {
		added = added[:maxLinesEach]
	}
	if len(removed) > maxLinesEach {
		removed = removed[:maxLinesEach]
	}

	var b strings.Builder
	if len(added) > 0 {
		b.WriteString("# Added or changed lines (+):\n")
		for _, l := range added {
			b.WriteString("+ ")
			b.WriteString(l)
			b.WriteByte('\n')
			if b.Len() > maxLen {
				b.WriteString("... [truncated]\n")
				return b.String()
			}
		}
	}
	if len(removed) > 0 {
		b.WriteString("\n# Removed lines (-):\n")
		for _, l := range removed {
			b.WriteString("- ")
			b.WriteString(l)
			b.WriteByte('\n')
			if b.Len() > maxLen {
				b.WriteString("... [truncated]\n")
				return b.String()
			}
		}
	}
	if len(added) == 0 && len(removed) == 0 {
		return "Identical line sets but different hashes — likely whitespace/order changes only."
	}
	return b.String()
}

// splitAndNormalize breaks a body into lines, trims whitespace, and drops
// noise like blank lines so the LLM sees signal.
func splitAndNormalize(body []byte) []string {
	s := string(body)
	// Normalize CRLF/CR to LF
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	out := make([]string, 0, 128)
	for _, ln := range strings.Split(s, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" {
			continue
		}
		// For very long lines (minified JS), split further so set comparison
		// is meaningful. Break on semicolons as a rough statement boundary.
		if len(t) > 240 {
			for _, chunk := range strings.Split(t, ";") {
				chunk = strings.TrimSpace(chunk)
				if chunk != "" {
					out = append(out, chunk)
				}
			}
			continue
		}
		out = append(out, t)
	}
	return out
}

// ── LLM commentary ──

// diffVerdict is the LLM's judgement on a single asset diff.
type diffVerdict struct {
	Severity string `json:"severity"`
	Comment  string `json:"comment"`
}

const diffCommentaryPrompt = `You are a pentester monitoring a target over time. The automated crawler just noticed that a JS or HTML file CHANGED compared to the previous scan. You will get:
  - The URL of the asset
  - Size before and after
  - A diff snippet showing added and removed lines

Your job: decide what the change MEANS from a security perspective. Short, honest answers only — if it's boring, say so.

Things to notice:
  - NEW URL references, fetch()/axios calls, API paths → new attack surface worth crawling
  - NEW form fields, hidden inputs, or auth-related logic → changed auth flow
  - REMOVED validation, null-checks, CSP headers → weakened defenses
  - NEW "debug" / "admin" / "internal" strings
  - ADDED third-party scripts or SDKs → supply-chain expansion
  - Version/build-hash changes with no functional diff → boring (severity "info")

Output strict JSON:
{
  "severity": "info"|"low"|"medium"|"high"|"critical",
  "comment": "one short paragraph (2-3 sentences) explaining what changed and why a pentester should care (or not)"
}

Severity calibration:
  - "critical" — new auth endpoint, removed CSRF token, exposed secrets
  - "high"     — new admin/debug surface, removed access control
  - "medium"   — new attack surface (new XHR/API paths), new form inputs
  - "low"      — new third-party dep, minor UI/auth tweak
  - "info"     — version bump, whitespace/build-hash only, cosmetic`

func (d *ChangeDetector) commentOnDiff(ctx context.Context, diff assetDiff) (*diffVerdict, error) {
	sb := strings.Builder{}
	fmt.Fprintf(&sb, "Asset: %s\nContent-Type: %s\nSize: %d → %d bytes\n\nDiff:\n%s\n\nJudge this change.",
		diff.URL, diff.ContentType, diff.PrevSize, diff.NewSize, diff.Snippet)
	user := sb.String()

	est := d.provider.CountTokens(diffCommentaryPrompt + user)
	if !d.budget.CanSpend(est) {
		return nil, fmt.Errorf("budget exhausted")
	}

	start := time.Now()
	req := &llm.Request{
		SystemPrompt: diffCommentaryPrompt,
		Messages:     []llm.Message{{Role: "user", Content: user}},
		Temperature:  0.1,
		MaxTokens:    llm.StructuredOutputTokenLimit(d.provider, 256, 1024),
		JSONMode:     true,
	}
	resp, err := llm.CompleteBudgeted(ctx, d.provider, d.budget, req, est)
	dur := time.Since(start).Milliseconds()
	if err != nil {
		return nil, err
	}
	modelID := llm.ResponseModel(resp, d.provider)
	cost := llm.CostMicroCents(modelID, resp.Usage)
	d.db.LogAIFull(d.scanID, "change-detector", "diff_comment",
		diff.URL, "", diff.URL, "",
		resp.Usage.InputTokens, resp.Usage.OutputTokens, dur, cost, modelID,
		llm.RenderPrompt(req), resp.Content)

	var v diffVerdict
	if err := json.Unmarshal([]byte(resp.Content), &v); err != nil {
		// tolerate mixed output
		start := strings.Index(resp.Content, "{")
		end := strings.LastIndex(resp.Content, "}")
		if start >= 0 && end > start {
			if err2 := json.Unmarshal([]byte(resp.Content[start:end+1]), &v); err2 != nil {
				return nil, fmt.Errorf("parse verdict: %w", err2)
			}
		} else {
			return nil, fmt.Errorf("parse verdict: %w", err)
		}
	}
	if v.Severity == "" {
		v.Severity = "info"
	}
	if v.Comment == "" {
		v.Comment = "(no comment produced)"
	}
	return &v, nil
}
