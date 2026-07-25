// ask-prototype evaluates whether an LLM can answer natural-language
// questions about a scan by generating SQLite queries over the scan.db
// schema. This is the "question bar" the pentester will use:
//   "show me all endpoints with a 'token' parameter that returned 200"
//   "which confirmed findings involve the admin API?"
//   "how many probes has the Explorer run on paginated endpoints?"
//
// Approach: text-to-SQL with a schema-anchored prompt. We hard-guard the
// generated SQL to be a single read-only SELECT. Anything else gets
// refused without execution.
//
// Usage:
//   go run ./cmd/ask-prototype --scan 15 --model qwen2.5:14b -q "top 5 hosts by endpoint count"
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/llm"
	_ "modernc.org/sqlite"
)

const askSystem = `You are a penetration-test data assistant. The pentester will ask questions in plain English about a scan; you translate the question into ONE SQLite query against the schema below, then interpret the result.

## Schema (read-only; SELECT queries only)

- scans(id, target, started_at, finished_at, status)
- traffic(id, scan_id, method, url, host, path, query, request_headers, request_body, status_code, response_headers, response_body, content_type, response_size, endpoint_hash, has_params, has_input, has_file_upload, has_auth, has_errors, is_api, relevance_score, is_filtered, is_duplicate, is_ai_analyzed, captured_at)
- endpoints(id, scan_id, method, url_pattern, params_json, hit_count, has_params, has_input, has_file_upload, has_auth, has_errors, is_api, is_ai_analyzed, first_seen_at, last_seen_at)
- page_profiles(id, scan_id, url, method, purpose, inputs_json, auth_required, data_exposed, apis_called, behaviors, issues, tech_notes, has_input, has_auth, is_api, confidence, analysis_count, created_at, updated_at)
- findings(id, scan_id, title, description, severity, confidence, endpoint_id, evidence, remediation, vuln_type, param_name, payload, poc_request, poc_response, steps_to_reproduce, impact, created_at)
- narrations(id, scan_id, agent, action, message, url, metadata_json, created_at)
- follow_ups(id, scan_id, source_agent, source_profile_id, action, url, params_json, reason, priority, status, result, created_at, completed_at)
- url_discoveries(id, scan_id, target_url, source_url, kind, detail, found_at)
- asset_hashes(id, scan_id, url, host, content_hash, content_type, response_size, captured_at)
- asset_changes(id, scan_id, prev_scan_id, url, host, content_type, prev_hash, new_hash, prev_size, new_size, kind, diff_snippet, llm_comment, severity, created_at)
- ai_log(id, scan_id, agent, action, detail, from_url, to_url, result, tokens_in, tokens_out, duration_ms, cost_ucents, model_id, created_at)

## Rules

1. The question is ALWAYS scoped to scan_id = ? — reference this as a placeholder and never hardcode a scan id.
2. Emit ONE SELECT statement. No DDL, no DML, no multi-statement.
3. Use LIMIT if the result might be huge (default 50).
4. If the question cannot be answered from the schema, return {"error": "explanation"} and no sql.
5. Prefer joins over subqueries when natural. JSON fields (issues, inputs_json, metadata_json, params_json) can be queried with json_extract(...).

## Output schema

Return STRICT JSON, nothing else:

{
  "sql": "SELECT ... WHERE scan_id = ?",
  "explanation": "one-sentence explanation of what the query does"
}

OR, when the question is unanswerable:

{
  "error": "can't answer because ..."
}`

// Only these prefixes are allowed — defense in depth against prompt injection
// that tries to get the model to emit DELETE/UPDATE/ATTACH etc.
var allowedStart = regexp.MustCompile(`(?i)^\s*(WITH\s+.*\s+SELECT|SELECT)\b`)

// Blocklist of obviously dangerous tokens even inside a SELECT.
var bannedTokens = []string{
	"ATTACH", "PRAGMA", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
	"CREATE", "REPLACE", "LOAD_EXTENSION", "VACUUM",
}

func main() {
	var (
		scanID   int64
		model    string
		provider string
		output   string
		question string
	)
	flag.Int64Var(&scanID, "scan", 0, "Scan id (required)")
	flag.StringVar(&model, "model", "qwen2.5:14b", "LLM model")
	flag.StringVar(&provider, "provider", "ollama", "Provider")
	flag.StringVar(&output, "output", "./aobtd-output", "Scan output dir")
	flag.StringVar(&question, "q", "", "Natural language question (required)")
	flag.Parse()

	if scanID == 0 || question == "" {
		fmt.Fprintln(os.Stderr, "--scan and -q both required")
		os.Exit(1)
	}

	prov, err := llm.NewProvider(provider, "", "", model)
	if err != nil {
		exitf("provider: %v", err)
	}

	fmt.Printf("═══ Ask prototype ═══\n")
	fmt.Printf("Scan: #%d  model: %s\n", scanID, model)
	fmt.Printf("Q: %s\n\n", question)

	start := time.Now()
	resp, err := prov.Complete(context.Background(), &llm.Request{
		SystemPrompt: askSystem,
		Messages: []llm.Message{
			{Role: "user", Content: "Question: " + question + "\nEmit the JSON."},
		},
		Temperature: 0.1,
		MaxTokens:   600,
		JSONMode:    true,
	})
	dur := time.Since(start)
	if err != nil {
		exitf("LLM: %v", err)
	}

	var parsed struct {
		SQL         string `json:"sql"`
		Explanation string `json:"explanation"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &parsed); err != nil {
		// try to peel out JSON
		s := strings.Index(resp.Content, "{")
		e := strings.LastIndex(resp.Content, "}")
		if s >= 0 && e > s {
			json.Unmarshal([]byte(resp.Content[s:e+1]), &parsed)
		}
	}

	fmt.Printf("Plan (%.1fs, %d→%d tok):\n", dur.Seconds(), resp.Usage.InputTokens, resp.Usage.OutputTokens)
	if parsed.Error != "" {
		fmt.Printf("  error: %s\n", parsed.Error)
		os.Exit(0)
	}
	if parsed.SQL == "" {
		fmt.Printf("  (could not parse a SQL query from the response)\n\nRaw: %s\n", resp.Content)
		os.Exit(1)
	}
	fmt.Printf("  sql: %s\n", parsed.SQL)
	fmt.Printf("  explanation: %s\n\n", parsed.Explanation)

	// Safety check
	if !allowedStart.MatchString(parsed.SQL) {
		fmt.Println("REFUSED: query does not start with SELECT / WITH")
		os.Exit(1)
	}
	upper := strings.ToUpper(parsed.SQL)
	for _, bad := range bannedTokens {
		if strings.Contains(upper, bad) {
			fmt.Printf("REFUSED: banned token %q in query\n", bad)
			os.Exit(1)
		}
	}

	// Execute read-only
	dbPath := filepath.Join(output, "scan.db")
	rdb, err := sql.Open("sqlite", dbPath+"?mode=ro&immutable=1")
	if err != nil {
		exitf("open db readonly: %v", err)
	}
	defer rdb.Close()

	rows, err := rdb.Query(parsed.SQL, scanID)
	if err != nil {
		fmt.Printf("SQL ERROR: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	cols, _ := rows.Columns()
	fmt.Printf("─── Result: %s ──\n", strings.Join(cols, " | "))
	rowNum := 0
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		rows.Scan(ptrs...)
		parts := make([]string, len(cols))
		for i, v := range vals {
			s := fmt.Sprintf("%v", v)
			if len(s) > 80 {
				s = s[:80] + "…"
			}
			parts[i] = s
		}
		fmt.Printf("  %s\n", strings.Join(parts, " | "))
		rowNum++
	}
	fmt.Printf("\n(%d rows)\n", rowNum)
}

func exitf(s string, args ...any) {
	fmt.Fprintf(os.Stderr, s+"\n", args...)
	os.Exit(1)
}
