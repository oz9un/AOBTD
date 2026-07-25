package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Prompt is an interactive checkpoint the scanner raises for the operator.
// Lives in the `prompts` table. The scanner never blocks on these — it
// continues its work and lets a background goroutine pick up the answer
// if/when the user provides one via the UI.
type Prompt struct {
	ID         int64     `json:"id"`
	ScanID     int64     `json:"scan_id"`
	Kind       string    `json:"kind"`         // e.g. "login_found"
	Payload    string    `json:"payload"`      // raw JSON string; use PayloadAs[T] to unmarshal
	Answer     string    `json:"answer"`       // raw JSON string; empty while pending
	CreatedAt  time.Time `json:"created_at"`
	AnsweredAt *time.Time `json:"answered_at,omitempty"`
	Handled    bool      `json:"handled"`
}

// PayloadAs decodes the prompt's payload JSON into the given type.
// Convenience wrapper so callers don't juggle json.Unmarshal themselves.
func PayloadAs[T any](p Prompt) (T, error) {
	var out T
	if p.Payload == "" {
		return out, nil
	}
	err := json.Unmarshal([]byte(p.Payload), &out)
	return out, err
}

// AnswerAs decodes the prompt's answer JSON into the given type.
func AnswerAs[T any](p Prompt) (T, error) {
	var out T
	if p.Answer == "" {
		return out, nil
	}
	err := json.Unmarshal([]byte(p.Answer), &out)
	return out, err
}

// InsertPrompt emits a new prompt. `payload` can be any JSON-marshallable
// struct — this is the structured information the UI will render (e.g.
// for login_found it's {url, user_field, pass_field, submit_url}).
// Returns the new prompt's id.
func (db *DB) InsertPrompt(scanID int64, kind string, payload any) (int64, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal payload: %w", err)
	}
	res, err := db.conn.Exec(
		`INSERT INTO prompts (scan_id, kind, payload) VALUES (?, ?, ?)`,
		scanID, kind, string(payloadJSON))
	if err != nil {
		return 0, fmt.Errorf("insert prompt: %w", err)
	}
	return res.LastInsertId()
}

// ListOpenPrompts returns prompts for the scan that haven't been
// answered yet. Powers the UI notification bell.
func (db *DB) ListOpenPrompts(scanID int64) ([]Prompt, error) {
	return db.scanPrompts(`
		SELECT id, scan_id, kind, payload, answer, created_at, answered_at, handled
		  FROM prompts
		 WHERE scan_id = ? AND answered_at IS NULL
		 ORDER BY id DESC`, scanID)
}

// ListPendingAnswers returns prompts that HAVE been answered by the user
// but NOT yet handled by the scanner. The scanner's background poller
// calls this every few seconds; once it acts on an answer it marks
// the prompt handled.
func (db *DB) ListPendingAnswers(scanID int64) ([]Prompt, error) {
	return db.scanPrompts(`
		SELECT id, scan_id, kind, payload, answer, created_at, answered_at, handled
		  FROM prompts
		 WHERE scan_id = ? AND answered_at IS NOT NULL AND handled = FALSE
		 ORDER BY id ASC`, scanID)
}

// AnswerPrompt records the operator's answer for the prompt. `answer` is
// any JSON-marshallable payload (e.g. {username, password} for login).
// Idempotent — second call on the same prompt overwrites the answer.
func (db *DB) AnswerPrompt(promptID int64, answer any) error {
	answerJSON, err := json.Marshal(answer)
	if err != nil {
		return fmt.Errorf("marshal answer: %w", err)
	}
	_, err = db.conn.Exec(
		`UPDATE prompts SET answer = ?, answered_at = datetime('now'), handled = FALSE
		  WHERE id = ?`, string(answerJSON), promptID)
	return err
}

// MarkPromptHandled is called by the scanner after it's consumed the
// answer (e.g. run the login with the supplied creds). Prevents the
// poller from acting on it again.
func (db *DB) MarkPromptHandled(promptID int64) error {
	_, err := db.conn.Exec(`UPDATE prompts SET handled = TRUE WHERE id = ?`, promptID)
	return err
}

// GetPrompt returns a single prompt by id (used by the UI when the user
// clicks the notification to render its form).
func (db *DB) GetPrompt(promptID int64) (*Prompt, error) {
	rows, err := db.scanPrompts(`
		SELECT id, scan_id, kind, payload, answer, created_at, answered_at, handled
		  FROM prompts WHERE id = ?`, promptID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, sql.ErrNoRows
	}
	return &rows[0], nil
}

// scanPrompts is the shared row-scanner used by the list helpers.
func (db *DB) scanPrompts(query string, args ...any) ([]Prompt, error) {
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Prompt
	for rows.Next() {
		var p Prompt
		var answeredAt sql.NullTime
		if err := rows.Scan(&p.ID, &p.ScanID, &p.Kind, &p.Payload, &p.Answer,
			&p.CreatedAt, &answeredAt, &p.Handled); err != nil {
			continue
		}
		if answeredAt.Valid {
			t := answeredAt.Time
			p.AnsweredAt = &t
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
