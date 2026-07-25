package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// FollowUp is a typed task queued by one agent and consumed by another.
// Today the analyzer produces them and the Explorer consumes; eventually any
// agent can produce/consume.
type FollowUp struct {
	ID              int64          `json:"id"`
	ScanID          int64          `json:"scan_id"`
	SourceAgent     string         `json:"source_agent"`
	SourceProfileID string         `json:"source_profile_id,omitempty"`
	Action          string         `json:"action"` // "fetch" | "visit" | "probe_param" | "reanalyze"
	URL             string         `json:"url,omitempty"`
	Params          map[string]any `json:"params,omitempty"` // action-specific payload
	Reason          string         `json:"reason,omitempty"`
	Priority        int            `json:"priority"`
	Status          string         `json:"status"` // pending, running, done, failed, skipped
	Result          string         `json:"result,omitempty"`
	CreatedAt       string         `json:"created_at"`
	CompletedAt     string         `json:"completed_at,omitempty"`
	ClaimedAt       string         `json:"claimed_at,omitempty"`
	LeaseExpiresAt  string         `json:"lease_expires_at,omitempty"`
	LeaseToken      string         `json:"-"`
	AttemptCount    int            `json:"attempt_count"`

	// HypothesisID is non-empty for directives emitted by the Strategist to
	// test a specific hypothesis. The Explorer passes this through to any
	// Finding it produces, which lets InsertFinding auto-confirm the
	// hypothesis when the directive validates the hunch.
	HypothesisID string `json:"hypothesis_id,omitempty"`
}

// FollowUpStatus constants.
const (
	FollowUpPending = "pending"
	FollowUpRunning = "running"
	FollowUpDone    = "done"
	FollowUpFailed  = "failed"
	FollowUpSkipped = "skipped"
)

// A single LLM-assisted probe may make several HTTP requests and one model
// call. Keep the production lease longer than the Explorer's normal task
// budget; deterministic tests use ClaimFollowUps with a shorter duration.
const defaultFollowUpLease = 15 * time.Minute

var (
	// ErrInvalidFollowUpStatus means a caller attempted to finish a task with
	// a non-terminal state. Queue consumers may only finish tasks as done,
	// failed, or skipped; pending/running are owned by the claim path.
	ErrInvalidFollowUpStatus = errors.New("invalid follow-up terminal status")
	// ErrFollowUpNotRunning covers a stale claim, a task from another scan,
	// an already-finished task, and a task that was never claimed. Keeping
	// these cases behind one error avoids leaking cross-scan row existence.
	ErrFollowUpNotRunning = errors.New("follow-up is not running in this scan")
)

// InsertFollowUp queues a new task. Duplicate tasks (same dedupe_key within
// the same scan) silently return the existing row's id without inserting.
func (db *DB) InsertFollowUp(scanID int64, f FollowUp) (int64, error) {
	f = normalizeFollowUpForInsert(f)
	paramsJSON, err := encodeFollowUpParams(f.Params)
	if err != nil {
		return 0, fmt.Errorf("encode follow_up params: %w", err)
	}
	dedupe, err := computeDedupeKey(f)
	if err != nil {
		return 0, fmt.Errorf("compute follow_up dedupe key: %w", err)
	}

	// Use INSERT OR IGNORE rather than ON CONFLICT(...) DO NOTHING because
	// the modernc.org/sqlite build rejects the targeted ON CONFLICT form
	// against a partial unique index ("WHERE dedupe_key != ''"). OR IGNORE
	// respects the partial index and silently drops duplicates.
	sourceAgent := strOr(f.SourceAgent, "analyzer")
	res, err := db.conn.Exec(`
		INSERT OR IGNORE INTO follow_ups (scan_id, source_agent, source_profile_id,
		                       action, url, params_json, reason,
		                       priority, status, dedupe_key, hypothesis_id, emitted_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, sourceAgent, f.SourceProfileID,
		f.Action, f.URL, paramsJSON, f.Reason,
		f.Priority, strOr(f.Status, FollowUpPending), dedupe, f.HypothesisID, sourceAgent,
	)
	if err != nil {
		return 0, fmt.Errorf("insert follow_up: %w", err)
	}
	// LastInsertId() returns the new rowid on insert, 0 when IGNORE ate it.
	// Callers use id > 0 to mean "actually queued."
	id, _ := res.LastInsertId()
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, nil
	}
	return id, nil
}

func normalizeFollowUpForInsert(f FollowUp) FollowUp {
	f.URL = normalizeFollowUpTarget(f.URL)
	if tmpl, ok := f.Params["url_template"].(string); ok {
		normalized := normalizeFollowUpTarget(tmpl)
		if normalized != tmpl {
			params := make(map[string]any, len(f.Params))
			for k, v := range f.Params {
				params[k] = v
			}
			params["url_template"] = normalized
			f.Params = params
		}
	}
	return f
}

func normalizeFollowUpTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	fields := strings.Fields(raw)
	if len(fields) >= 2 && isHTTPMethodToken(fields[0]) {
		return strings.TrimSpace(fields[1])
	}
	return raw
}

func isHTTPMethodToken(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

// computeDedupeKey creates a stable hash so the same action, URL, complete
// parameter payload, and hypothesis is only queued once per scan. Parameter
// values matter: probing {"role":"admin"} is not the same experiment as
// probing {"role":"user"}. encoding/json sorts map keys recursively, so
// producer map iteration order cannot change the identity.
//
// Empty is reserved for actions that should always run (for example, a user
// may explicitly request reanalysis of the same endpoint multiple times).
func computeDedupeKey(f FollowUp) (string, error) {
	if f.Action == "reanalyze" {
		return "", nil // never dedupe — user may explicitly want another pass
	}
	paramsJSON, err := encodeFollowUpParams(f.Params)
	if err != nil {
		return "", err
	}
	parts := []string{
		"v2",
		strings.TrimSpace(f.Action),
		strings.TrimSpace(f.URL),
		paramsJSON,
		strings.TrimSpace(f.HypothesisID),
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:]), nil
}

func encodeFollowUpParams(params map[string]any) (string, error) {
	if params == nil {
		return "{}", nil
	}
	b, err := json.Marshal(params)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func strOr(a, fallback string) string {
	if a == "" {
		return fallback
	}
	return a
}

// SkipNonCopilotReconFollowUps closes Analyzer/Strategist probe work that a
// Recon scan can never execute. Approved Copilot steering remains pending, but
// only for the bounded read-only vocabulary consumed by the orchestrator.
func (db *DB) SkipNonCopilotReconFollowUps(scanID int64) (int64, error) {
	res, err := db.conn.Exec(`
		UPDATE follow_ups
		SET status=?, result='Separate operator-authorized Active run required under the selected Recon authority.',
		    completed_at=datetime('now'), lease_expires_at=NULL, lease_token=''
		WHERE scan_id=? AND status=?
		  AND NOT (source_agent='copilot' AND action IN ('fetch','visit','reanalyze'))`,
		FollowUpSkipped, scanID, FollowUpPending)
	if err != nil {
		return 0, fmt.Errorf("skip non-Copilot Recon follow-ups: %w", err)
	}
	return res.RowsAffected()
}

// PopPendingFollowUps claims pending work with the production lease duration.
// A claimed task that is abandoned becomes eligible again after its lease.
func (db *DB) PopPendingFollowUps(scanID int64, limit int) ([]FollowUp, error) {
	return db.ClaimFollowUps(scanID, limit, defaultFollowUpLease)
}

// ClaimFollowUps atomically claims up to limit tasks for a scan. Work is
// ordered by two-point priority bands, then by how many experiments have
// already completed for the same hypothesis. This preserves risk ordering
// while preventing one belief from monopolizing every Explorer turn.
// In addition
// to pending tasks it reclaims running tasks whose lease expired (including
// legacy running rows with no lease). The single UPDATE ... RETURNING statement
// is its own SQLite transaction, so separate scanner processes cannot claim the
// same row in between a SELECT and UPDATE.
//
// lease is injectable so tests and callers with different execution budgets do
// not need sleeps. Durations are rounded up to whole seconds because SQLite's
// datetime function has second precision.
func (db *DB) ClaimFollowUps(scanID int64, limit int, lease time.Duration) ([]FollowUp, error) {
	if scanID <= 0 {
		return nil, fmt.Errorf("claim follow-ups: invalid scan id %d", scanID)
	}
	if limit <= 0 {
		limit = 10
	}
	if lease <= 0 {
		lease = defaultFollowUpLease
	}
	leaseSeconds := int64((lease + time.Second - 1) / time.Second)
	if leaseSeconds < 1 {
		leaseSeconds = 1
	}
	leaseModifier := fmt.Sprintf("+%d seconds", leaseSeconds)

	rows, err := db.conn.Query(`
		UPDATE follow_ups
		SET status = ?,
		    claimed_at = datetime('now'),
		    lease_expires_at = datetime('now', ?),
		    lease_token = lower(hex(randomblob(16))),
		    attempt_count = COALESCE(attempt_count, 0) + 1,
		    result = '',
		    completed_at = NULL
		WHERE scan_id = ?
		  AND id IN (
		      SELECT candidate.id
		      FROM follow_ups AS candidate
		      WHERE candidate.scan_id = ?
		        AND (
		            candidate.status = ?
		            OR (candidate.status = ? AND (
		                candidate.lease_expires_at IS NULL
		                OR candidate.lease_expires_at <= datetime('now')
		            ))
		        )
		      ORDER BY
		        ((candidate.priority + 1) / 2) DESC,
		        CASE WHEN COALESCE(candidate.hypothesis_id, '') = '' THEN 0 ELSE (
		          SELECT COUNT(*) FROM follow_ups AS prior
		          WHERE prior.scan_id = candidate.scan_id
		            AND prior.hypothesis_id = candidate.hypothesis_id
		            AND prior.status IN ('done','failed','skipped')
		        ) END ASC,
		        candidate.priority DESC,
		        candidate.id ASC
		      LIMIT ?
		  )
		  AND (
		      status = ?
		      OR (status = ? AND (
		          lease_expires_at IS NULL
		          OR lease_expires_at <= datetime('now')
		      ))
		  )
		RETURNING id, scan_id, source_agent, COALESCE(source_profile_id,''), action,
		          COALESCE(url,''), COALESCE(params_json,'{}'),
		          COALESCE(reason,''), priority, status, created_at,
		          COALESCE(hypothesis_id,''), COALESCE(claimed_at,''),
		          COALESCE(lease_expires_at,''), COALESCE(lease_token,''),
		          COALESCE(attempt_count,0)`,
		FollowUpRunning, leaseModifier, scanID, scanID,
		FollowUpPending, FollowUpRunning, limit,
		FollowUpPending, FollowUpRunning)
	if err != nil {
		return nil, fmt.Errorf("claim follow-ups: %w", err)
	}
	defer rows.Close()

	var list []FollowUp
	for rows.Next() {
		var f FollowUp
		var paramsJSON string
		if err := rows.Scan(&f.ID, &f.ScanID, &f.SourceAgent, &f.SourceProfileID, &f.Action,
			&f.URL, &paramsJSON, &f.Reason, &f.Priority, &f.Status, &f.CreatedAt,
			&f.HypothesisID, &f.ClaimedAt, &f.LeaseExpiresAt, &f.LeaseToken,
			&f.AttemptCount); err != nil {
			return nil, fmt.Errorf("scan claimed follow-up: %w", err)
		}
		if paramsJSON != "" && paramsJSON != "{}" {
			var p map[string]any
			if err := json.Unmarshal([]byte(paramsJSON), &p); err != nil {
				return nil, fmt.Errorf("decode claimed follow-up %d params: %w", f.ID, err)
			}
			f.Params = p
		}
		list = append(list, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claimed follow-ups: %w", err)
	}
	// SQLite does not guarantee RETURNING row order. Preserve the queue's
	// documented priority ordering for deterministic consumers and tests.
	sort.Slice(list, func(i, j int) bool {
		if list[i].Priority != list[j].Priority {
			return list[i].Priority > list[j].Priority
		}
		return list[i].ID < list[j].ID
	})
	return list, nil
}

// CompleteFollowUp moves a currently running task to a terminal state. Both
// scan id and running state are part of the predicate: a stale/wrong-scan
// caller cannot mutate another scan's queue, and terminal rows are immutable.
func (db *DB) CompleteFollowUp(scanID, id int64, leaseToken, status, result string) error {
	if status != FollowUpDone && status != FollowUpFailed && status != FollowUpSkipped {
		return fmt.Errorf("%w: %q", ErrInvalidFollowUpStatus, status)
	}
	if leaseToken == "" {
		return fmt.Errorf("%w: scan=%d id=%d", ErrFollowUpNotRunning, scanID, id)
	}
	var hypothesisID, emittedBy, action string
	_ = db.conn.QueryRow(`
		SELECT COALESCE(hypothesis_id,''), COALESCE(emitted_by, source_agent), action
		FROM follow_ups
		WHERE scan_id = ? AND id = ?`, scanID, id).Scan(&hypothesisID, &emittedBy, &action)
	res, err := db.conn.Exec(`
		UPDATE follow_ups
		SET status = ?, result = ?, completed_at = datetime('now'),
		    lease_expires_at = NULL, lease_token = ''
		WHERE scan_id = ? AND id = ? AND status = ? AND lease_token = ?
		  AND lease_expires_at > datetime('now')`,
		status, result, scanID, id, FollowUpRunning, leaseToken)
	if err != nil {
		return fmt.Errorf("complete follow-up: %w", err)
	}
	updated, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("complete follow-up rows affected: %w", err)
	}
	if updated != 1 {
		return fmt.Errorf("%w: scan=%d id=%d", ErrFollowUpNotRunning, scanID, id)
	}
	if hypothesisID != "" {
		eventReason := strings.TrimSpace(result)
		if eventReason == "" {
			eventReason = fmt.Sprintf("%s directive completed with status %s.", action, status)
		}
		_ = db.InsertHypothesisEvent(HypothesisEvent{
			ScanID:       scanID,
			HypothesisID: hypothesisID,
			EventType:    "directive_done",
			NewStatus:    status,
			Reason:       eventReason,
			RelatedRef:   fmt.Sprintf("directive:%d", id),
			Actor:        emittedBy,
		})
	}
	return nil
}

// CountFollowUpsByStatus groups pending/running/done counts for a scan.
// Returned map keys match the status constants.
func (db *DB) CountFollowUpsByStatus(scanID int64) (map[string]int, error) {
	rows, err := db.conn.Query(`
		SELECT status, COUNT(*) FROM follow_ups WHERE scan_id = ? GROUP BY status`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var s string
		var n int
		rows.Scan(&s, &n)
		out[s] = n
	}
	return out, nil
}

// ListFollowUps returns recent tasks for UI display. Returns up to `limit` rows
// ordered newest first.
func (db *DB) ListFollowUps(scanID int64, limit int) ([]FollowUp, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := db.conn.Query(`
		SELECT id, scan_id, source_agent, COALESCE(source_profile_id,''), action,
		       COALESCE(url,''), COALESCE(params_json,'{}'),
		       COALESCE(reason,''), priority, status,
		       COALESCE(result,''), created_at, COALESCE(completed_at,''),
		       COALESCE(hypothesis_id,''), COALESCE(claimed_at,''),
		       COALESCE(lease_expires_at,''), COALESCE(attempt_count,0)
		FROM follow_ups WHERE scan_id = ?
		ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []FollowUp
	for rows.Next() {
		var f FollowUp
		var paramsJSON string
		if err := rows.Scan(&f.ID, &f.ScanID, &f.SourceAgent, &f.SourceProfileID, &f.Action,
			&f.URL, &paramsJSON, &f.Reason, &f.Priority, &f.Status,
			&f.Result, &f.CreatedAt, &f.CompletedAt, &f.HypothesisID,
			&f.ClaimedAt, &f.LeaseExpiresAt, &f.AttemptCount); err != nil {
			return nil, fmt.Errorf("scan follow-up list row: %w", err)
		}
		if paramsJSON != "" && paramsJSON != "{}" {
			var p map[string]any
			if err := json.Unmarshal([]byte(paramsJSON), &p); err != nil {
				return nil, fmt.Errorf("decode follow-up %d params: %w", f.ID, err)
			}
			f.Params = p
		}
		list = append(list, f)
	}
	return list, rows.Err()
}
