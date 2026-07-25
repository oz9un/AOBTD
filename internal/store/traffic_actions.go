package store

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	TrafficActionRunning   = "running"
	TrafficActionSucceeded = "succeeded"
	TrafficActionFailed    = "failed"
)

const maxTrafficActionMetadataRunes = 4096

var (
	trafficActionPairSecret = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|access_token|refresh_token|id_token|api[_-]?key|session(?:id|_id)?|sid|csrf|xsrf|authorization|cookie)\s*([:=])\s*([^&;\s"'<>]+)`)
	trafficActionAuthSecret = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	trafficActionURLSecret  = regexp.MustCompile(`(?i)(https?://[^:/\s]+):([^@\s/]+)@`)
)

// TrafficAction is a browser operation that may cause one or more captured
// HTTP requests. Traffic.source_action_id points here for browser-produced
// evidence; Explorer traffic continues to point at its follow-up row.
type TrafficAction struct {
	ID           int64  `json:"id"`
	ScanID       int64  `json:"scan_id"`
	SourceAgent  string `json:"source_agent"`
	Action       string `json:"action"`
	Reason       string `json:"reason,omitempty"`
	FromURL      string `json:"from_url,omitempty"`
	ToURL        string `json:"to_url,omitempty"`
	HypothesisID string `json:"hypothesis_id,omitempty"`
	Status       string `json:"status"`
	Result       string `json:"result,omitempty"`
	StartedAt    string `json:"started_at"`
	CompletedAt  string `json:"completed_at,omitempty"`
}

// BeginTrafficAction persists an action before browser execution so requests
// emitted during the action can reference a stable ID immediately.
func (db *DB) BeginTrafficAction(scanID int64, sourceAgent, action, reason, fromURL, toURL, hypothesisID string) (int64, error) {
	sourceAgent = strings.TrimSpace(sourceAgent)
	action = strings.TrimSpace(action)
	if sourceAgent == "" || sourceAgent == "capture" {
		return 0, fmt.Errorf("begin traffic action: attributed source agent is required")
	}
	if action == "" {
		return 0, fmt.Errorf("begin traffic action: action is required")
	}
	result, err := db.conn.Exec(`
		INSERT INTO traffic_actions (
			scan_id, source_agent, action, reason, from_url, to_url,
			hypothesis_id, status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, sourceAgent, action,
		sanitizeTrafficActionMetadata(reason), sanitizeTrafficActionMetadata(fromURL), sanitizeTrafficActionMetadata(toURL),
		strings.TrimSpace(hypothesisID), TrafficActionRunning,
	)
	if err != nil {
		return 0, fmt.Errorf("begin traffic action: %w", err)
	}
	return result.LastInsertId()
}

// CompleteTrafficAction records the outcome of a browser action.
func (db *DB) CompleteTrafficAction(scanID, actionID int64, status, result, toURL string) error {
	status = strings.TrimSpace(status)
	if status != TrafficActionSucceeded && status != TrafficActionFailed {
		return fmt.Errorf("complete traffic action: invalid status %q", status)
	}
	updated, err := db.conn.Exec(`
		UPDATE traffic_actions
		   SET status = ?, result = ?,
		       to_url = CASE WHEN ? != '' THEN ? ELSE to_url END,
		       completed_at = datetime('now')
		 WHERE scan_id = ? AND id = ? AND status = ?`,
		status, sanitizeTrafficActionMetadata(result), sanitizeTrafficActionMetadata(toURL), sanitizeTrafficActionMetadata(toURL),
		scanID, actionID, TrafficActionRunning,
	)
	if err != nil {
		return fmt.Errorf("complete traffic action: %w", err)
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return fmt.Errorf("complete traffic action rows: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("complete traffic action: action %d is missing or already complete", actionID)
	}
	return nil
}

func sanitizeTrafficActionMetadata(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = trafficActionAuthSecret.ReplaceAllString(value, "$1 [REDACTED]")
	value = trafficActionPairSecret.ReplaceAllString(value, "$1$2[REDACTED]")
	value = trafficActionURLSecret.ReplaceAllString(value, "$1:[REDACTED]@")
	runes := []rune(value)
	if len(runes) > maxTrafficActionMetadataRunes {
		value = string(runes[:maxTrafficActionMetadataRunes])
	}
	return value
}

// ListTrafficActions returns persisted browser actions in execution order.
func (db *DB) ListTrafficActions(scanID int64) ([]TrafficAction, error) {
	rows, err := db.conn.Query(`
		SELECT id, scan_id, source_agent, action, reason, from_url, to_url,
		       hypothesis_id, status, result, CAST(started_at AS TEXT),
		       COALESCE(CAST(completed_at AS TEXT), '')
		  FROM traffic_actions
		 WHERE scan_id = ?
		 ORDER BY id ASC`, scanID)
	if err != nil {
		return nil, fmt.Errorf("list traffic actions: %w", err)
	}
	defer rows.Close()
	actions := make([]TrafficAction, 0)
	for rows.Next() {
		var action TrafficAction
		if err := rows.Scan(
			&action.ID, &action.ScanID, &action.SourceAgent, &action.Action,
			&action.Reason, &action.FromURL, &action.ToURL, &action.HypothesisID,
			&action.Status, &action.Result, &action.StartedAt, &action.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("scan traffic action: %w", err)
		}
		actions = append(actions, action)
	}
	return actions, rows.Err()
}
