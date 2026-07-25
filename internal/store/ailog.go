package store

import (
	"fmt"

	"github.com/ozzyw/aobtd/internal/redact"
)

// AILogPhaseStat attributes model compute to one agent phase. The Recon UI
// uses this to show where time is going instead of presenting only an opaque
// aggregate duration.
type AILogPhaseStat struct {
	Agent      string `json:"agent"`
	Calls      int    `json:"calls"`
	Tokens     int    `json:"tokens"`
	DurationMs int64  `json:"duration_ms"`
}

// AILogEntry represents a single AI decision/action log entry.
type AILogEntry struct {
	ID         int64  `json:"id"`
	Agent      string `json:"agent"`
	Action     string `json:"action"`
	Detail     string `json:"detail"`
	FromURL    string `json:"from_url,omitempty"`
	ToURL      string `json:"to_url,omitempty"`
	Result     string `json:"result,omitempty"`
	TokensIn   int    `json:"tokens_in"`
	TokensOut  int    `json:"tokens_out"`
	DurationMs int64  `json:"duration_ms"`
	CostUcents int64  `json:"cost_ucents"` // cost in micro-cents (1¢ = 10,000 µ¢)
	ModelID    string `json:"model_id,omitempty"`
	CreatedAt  string `json:"created_at"`
}

// LogAI inserts an AI decision log entry with no cost/metrics.
func (db *DB) LogAI(scanID int64, agent, action, detail, fromURL, toURL, result string) error {
	return db.LogAIWithCost(scanID, agent, action, detail, fromURL, toURL, result, 0, 0, 0, 0, "")
}

// LogAIWithMetrics inserts an AI log entry with token usage and duration
// but no cost (backward compatible with older callers).
func (db *DB) LogAIWithMetrics(scanID int64, agent, action, detail, fromURL, toURL, result string, tokensIn, tokensOut int, durationMs int64) error {
	return db.LogAIWithCost(scanID, agent, action, detail, fromURL, toURL, result, tokensIn, tokensOut, durationMs, 0, "")
}

// LogAIWithCost inserts a fully-annotated AI log entry including cost in
// micro-cents and the model id that served the request. No raw prompt/
// response text is stored — use LogAIFull for actual LLM calls.
func (db *DB) LogAIWithCost(scanID int64, agent, action, detail, fromURL, toURL, result string, tokensIn, tokensOut int, durationMs, costUcents int64, modelID string) error {
	return db.LogAIFull(scanID, agent, action, detail, fromURL, toURL, result, tokensIn, tokensOut, durationMs, costUcents, modelID, "", "")
}

// LogAIFull inserts an AI log entry including the redacted prompt sent to the
// model and its redacted response text, for the AI Log viewer's conversation
// drill-down (see GetAILogFull).
func (db *DB) LogAIFull(scanID int64, agent, action, detail, fromURL, toURL, result string, tokensIn, tokensOut int, durationMs, costUcents int64, modelID, prompt, responseFull string) error {
	_, err := db.conn.Exec(`
		INSERT INTO ai_log (scan_id, agent, action, detail, from_url, to_url, result, tokens_in, tokens_out, duration_ms, cost_ucents, model_id, prompt, response_full)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, agent, action,
		redact.Text(detail), redact.Text(fromURL), redact.Text(toURL), redact.Text(result),
		tokensIn, tokensOut, durationMs, costUcents, modelID,
		redact.Text(prompt), redact.Text(responseFull),
	)
	return err
}

// GetAILogFull returns the raw prompt and response text for a single ai_log
// entry. Kept as a separate lazy-loaded lookup (see the schema comment in
// db.go) rather than part of GetAILog's list query.
func (db *DB) GetAILogFull(id int64) (prompt, responseFull string, err error) {
	err = db.conn.QueryRow(`
		SELECT COALESCE(prompt, ''), COALESCE(response_full, '')
		FROM ai_log WHERE id = ?`, id,
	).Scan(&prompt, &responseFull)
	return
}

// GetAILog returns AI log entries for a scan.
func (db *DB) GetAILog(scanID int64, limit int) ([]AILogEntry, error) {
	if limit == 0 {
		limit = 500
	}

	rows, err := db.conn.Query(`
		SELECT id, agent, action, detail, from_url, to_url, result,
		       COALESCE(tokens_in, 0), COALESCE(tokens_out, 0), COALESCE(duration_ms, 0),
		       COALESCE(cost_ucents, 0), COALESCE(model_id, ''),
		       created_at
		FROM ai_log WHERE scan_id = ?
		ORDER BY created_at ASC, id ASC
		LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, fmt.Errorf("query ai_log: %w", err)
	}
	defer rows.Close()

	var entries []AILogEntry
	for rows.Next() {
		var e AILogEntry
		rows.Scan(&e.ID, &e.Agent, &e.Action, &e.Detail,
			&e.FromURL, &e.ToURL, &e.Result,
			&e.TokensIn, &e.TokensOut, &e.DurationMs,
			&e.CostUcents, &e.ModelID,
			&e.CreatedAt)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// GetAILogStats returns aggregate token usage and cost for a scan.
func (db *DB) GetAILogStats(scanID int64) (totalIn, totalOut int, totalDurationMs int64, callCount int, totalCostUcents int64, err error) {
	err = db.conn.QueryRow(`
		SELECT COALESCE(SUM(tokens_in),0), COALESCE(SUM(tokens_out),0),
		       COALESCE(SUM(duration_ms),0), COUNT(*),
		       COALESCE(SUM(cost_ucents),0)
		FROM ai_log WHERE scan_id = ? AND tokens_in > 0`, scanID,
	).Scan(&totalIn, &totalOut, &totalDurationMs, &callCount, &totalCostUcents)
	return
}

// GetAILogPhaseStats returns model-backed calls grouped by agent and sorted by
// total compute time. Non-model audit rows have tokens_in=0 and stay out of the
// performance attribution just as they do in GetAILogStats.
func (db *DB) GetAILogPhaseStats(scanID int64) ([]AILogPhaseStat, error) {
	rows, err := db.conn.Query(`
		SELECT agent, COUNT(*), COALESCE(SUM(tokens_in + tokens_out), 0),
		       COALESCE(SUM(duration_ms), 0)
		FROM ai_log
		WHERE scan_id = ? AND tokens_in > 0
		GROUP BY agent
		ORDER BY SUM(duration_ms) DESC, COUNT(*) DESC, agent ASC`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query ai_log phase stats: %w", err)
	}
	defer rows.Close()
	stats := make([]AILogPhaseStat, 0)
	for rows.Next() {
		var stat AILogPhaseStat
		if err := rows.Scan(&stat.Agent, &stat.Calls, &stat.Tokens, &stat.DurationMs); err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}
	return stats, rows.Err()
}
