package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/ozzyw/aobtd/internal/redact"
)

var ErrCopilotApprovalUnavailable = errors.New("copilot approval is unavailable, expired, or already used")

const copilotResumeSigningKeyMetadata = "copilot_resume_hmac_key_v1"

type CopilotTurn struct {
	ID            int64  `json:"id"`
	ThreadID      int64  `json:"thread_id"`
	ScanID        int64  `json:"scan_id"`
	Question      string `json:"question"`
	Answer        string `json:"answer,omitempty"`
	Status        string `json:"status"`
	StepsJSON     string `json:"-"`
	UIActionsJSON string `json:"-"`
	EvidenceJSON  string `json:"-"`
	PendingJSON   string `json:"-"`
	ResumeState   string `json:"-"`
	Error         string `json:"error,omitempty"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type CopilotTurnUpdate struct {
	Answer        string
	Status        string
	StepsJSON     string
	UIActionsJSON string
	EvidenceJSON  string
	PendingJSON   string
	ResumeState   string
	Error         string
}

type copilotSQLExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// CopilotResumeSigningKey returns a stable, database-scoped HMAC key. The
// resume state itself is already persisted so an awaiting approval can be
// restored; persisting its signing key makes that restored card verifiable
// after a server restart and prevents tokens from one database being accepted
// by another database that happens to use the same scan id.
func (db *DB) CopilotResumeSigningKey() ([]byte, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var encoded string
	err = tx.QueryRow(`SELECT value FROM schema_metadata WHERE key = ?`, copilotResumeSigningKeyMetadata).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate copilot signing key: %w", err)
		}
		encoded = base64.RawURLEncoding.EncodeToString(key)
		if _, err := tx.Exec(`INSERT INTO schema_metadata(key, value) VALUES (?, ?)`, copilotResumeSigningKeyMetadata, encoded); err != nil {
			return nil, fmt.Errorf("persist copilot signing key: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("load copilot signing key: %w", err)
	}
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.RawURLEncoding.EncodeToString(key) != encoded {
		return nil, fmt.Errorf("load copilot signing key: invalid stored key")
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return key, nil
}

func (db *DB) CreateCopilotTurn(scanID int64, question string) (int64, error) {
	if scanID <= 0 {
		return 0, fmt.Errorf("create copilot turn: invalid scan id")
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO copilot_threads(scan_id) VALUES (?)`, scanID); err != nil {
		return 0, fmt.Errorf("ensure copilot thread: %w", err)
	}
	var threadID int64
	if err := tx.QueryRow(`SELECT id FROM copilot_threads WHERE scan_id = ?`, scanID).Scan(&threadID); err != nil {
		return 0, fmt.Errorf("load copilot thread: %w", err)
	}
	res, err := tx.Exec(`
		INSERT INTO copilot_turns(thread_id, scan_id, question, status)
		VALUES (?, ?, ?, 'pending')`, threadID, scanID, redact.Text(question))
	if err != nil {
		return 0, fmt.Errorf("insert copilot turn: %w", err)
	}
	turnID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE copilot_threads SET updated_at = datetime('now') WHERE id = ?`, threadID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return turnID, nil
}

func (db *DB) UpdateCopilotTurn(turnID int64, update CopilotTurnUpdate) error {
	normalizeCopilotTurnUpdate(&update)
	return execCopilotTurnUpdate(db.conn, turnID, update)
}

func normalizeCopilotTurnUpdate(update *CopilotTurnUpdate) {
	if update.Status == "" {
		update.Status = "completed"
	}
	for dst, fallback := range map[*string]string{
		&update.StepsJSON:     "[]",
		&update.UIActionsJSON: "[]",
		&update.EvidenceJSON:  "[]",
		&update.PendingJSON:   "{}",
	} {
		if *dst == "" {
			*dst = fallback
		}
	}
}

func execCopilotTurnUpdate(exec copilotSQLExecer, turnID int64, update CopilotTurnUpdate) error {
	res, err := exec.Exec(`
		UPDATE copilot_turns
		SET answer = ?, status = ?, steps_json = ?, ui_actions_json = ?,
		    evidence_json = ?, pending_json = ?, resume_state = ?, error = ?,
		    updated_at = datetime('now')
		WHERE id = ?`,
		redact.Text(update.Answer), update.Status, redact.Text(update.StepsJSON),
		redact.Text(update.UIActionsJSON), redact.Text(update.EvidenceJSON),
		redact.Text(update.PendingJSON), update.ResumeState, redact.Text(update.Error), turnID)
	if err != nil {
		return fmt.Errorf("update copilot turn: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("update copilot turn: turn not found")
	}
	return nil
}

// UpdateCopilotTurnWithApproval atomically persists an awaiting result and
// its single-use approval ledger entry. Neither record is visible unless both
// writes succeed.
func (db *DB) UpdateCopilotTurnWithApproval(turnID int64, update CopilotTurnUpdate, tokenHash string, scanID int64, kind string, expiresAt time.Time) error {
	normalizeCopilotTurnUpdate(&update)
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
		INSERT INTO copilot_approvals(token_hash, scan_id, turn_id, kind, expires_at)
		VALUES (?, ?, ?, ?, ?)`, tokenHash, scanID, turnID, kind,
		expiresAt.UTC().Format("2006-01-02 15:04:05")); err != nil {
		return fmt.Errorf("register copilot approval: %w", err)
	}
	if err := execCopilotTurnUpdate(tx, turnID, update); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

// FailCopilotTurn marks a turn failed without erasing an already persisted
// query trace or approval proposal. It is used when a resume token cannot be
// decoded or another failure occurs before a replacement Result is available.
func (db *DB) FailCopilotTurn(turnID int64, message string) error {
	res, err := db.conn.Exec(`
		UPDATE copilot_turns
		SET status = 'error', error = ?, resume_state = '', updated_at = datetime('now')
		WHERE id = ?`, redact.Text(message), turnID)
	if err != nil {
		return fmt.Errorf("fail copilot turn: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("fail copilot turn: turn not found")
	}
	return nil
}

func (db *DB) CopilotHistory(scanID int64, limit int) ([]CopilotTurn, error) {
	if limit <= 0 {
		limit = 8
	}
	rows, err := db.conn.Query(`
		SELECT id, thread_id, scan_id, question, answer, status,
		       steps_json, ui_actions_json, evidence_json, pending_json,
		       resume_state, error, created_at, updated_at
		FROM (
			SELECT * FROM copilot_turns
			WHERE scan_id = ? AND status = 'completed' AND answer != ''
			ORDER BY id DESC LIMIT ?
		) ORDER BY id ASC`, scanID, limit)
	if err != nil {
		return nil, fmt.Errorf("query copilot history: %w", err)
	}
	defer rows.Close()
	return scanCopilotTurns(rows)
}

func (db *DB) CopilotThread(scanID int64, limit int) ([]CopilotTurn, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := db.conn.Query(`
		SELECT t.id, t.thread_id, t.scan_id, t.question, t.answer,
		       CASE WHEN t.status = 'awaiting' AND a.token_hash IS NULL THEN 'expired' ELSE t.status END,
		       t.steps_json, t.ui_actions_json, t.evidence_json, t.pending_json,
		       CASE WHEN a.token_hash IS NULL THEN '' ELSE t.resume_state END,
		       CASE WHEN t.status = 'awaiting' AND a.token_hash IS NULL AND t.error = ''
		            THEN 'Approval expired; ask the Copilot to propose it again.' ELSE t.error END,
		       t.created_at, t.updated_at
		FROM copilot_turns t
		LEFT JOIN copilot_approvals a
		  ON a.turn_id = t.id AND a.status = 'awaiting' AND a.expires_at >= datetime('now')
		WHERE t.scan_id = ?
		ORDER BY t.id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, fmt.Errorf("query copilot thread: %w", err)
	}
	defer rows.Close()
	turns, err := scanCopilotTurns(rows)
	if err != nil {
		return nil, err
	}
	for left, right := 0, len(turns)-1; left < right; left, right = left+1, right-1 {
		turns[left], turns[right] = turns[right], turns[left]
	}
	return turns, nil
}

func scanCopilotTurns(rows *sql.Rows) ([]CopilotTurn, error) {
	var turns []CopilotTurn
	for rows.Next() {
		var turn CopilotTurn
		if err := rows.Scan(&turn.ID, &turn.ThreadID, &turn.ScanID, &turn.Question, &turn.Answer,
			&turn.Status, &turn.StepsJSON, &turn.UIActionsJSON, &turn.EvidenceJSON,
			&turn.PendingJSON, &turn.ResumeState, &turn.Error, &turn.CreatedAt, &turn.UpdatedAt); err != nil {
			return nil, err
		}
		turns = append(turns, turn)
	}
	return turns, rows.Err()
}

func (db *DB) RegisterCopilotApproval(tokenHash string, scanID, turnID int64, kind string, expiresAt time.Time) error {
	_, err := db.conn.Exec(`
		INSERT INTO copilot_approvals(token_hash, scan_id, turn_id, kind, expires_at)
		VALUES (?, ?, ?, ?, ?)`, tokenHash, scanID, turnID, kind,
		expiresAt.UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		return fmt.Errorf("register copilot approval: %w", err)
	}
	return nil
}

func (db *DB) ConsumeCopilotApproval(tokenHash string, scanID int64, approved bool) (int64, error) {
	status := "denied"
	if approved {
		status = "approved"
	}
	var turnID int64
	err := db.conn.QueryRow(`
		UPDATE copilot_approvals
		SET status = ?, consumed_at = datetime('now')
		WHERE token_hash = ? AND scan_id = ? AND status = 'awaiting'
		  AND expires_at >= datetime('now')
		RETURNING turn_id`, status, tokenHash, scanID).Scan(&turnID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrCopilotApprovalUnavailable
	}
	if err != nil {
		return 0, fmt.Errorf("consume copilot approval: %w", err)
	}
	return turnID, nil
}

func (db *DB) ClearCopilotThread(scanID int64) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM copilot_approvals WHERE turn_id IN (SELECT id FROM copilot_turns WHERE scan_id = ?)`, scanID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM copilot_turns WHERE scan_id = ?`, scanID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM copilot_threads WHERE scan_id = ?`, scanID); err != nil {
		return err
	}
	return tx.Commit()
}
