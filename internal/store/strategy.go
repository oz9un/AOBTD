package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/ozzyw/aobtd/internal/redact"
)

// Hypothesis is a first-class claim the Strategist makes about the target.
// Directives carry a hypothesis_id so we can roll up "which hypotheses are
// still being tested" vs "which are resolved."
type Hypothesis struct {
	ID                 string   `json:"id"`
	ScanID             int64    `json:"scan_id"`
	CycleID            int64    `json:"cycle_id"`
	Statement          string   `json:"statement"`
	Confidence         float64  `json:"confidence"`
	Status             string   `json:"status"` // active | confirmed | refuted | stale
	SupportingEvidence []string `json:"supporting_evidence,omitempty"`
	ResolvedBy         string   `json:"resolved_by,omitempty"`
	Notes              string   `json:"notes,omitempty"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
}

// Hypothesis status constants.
const (
	HypothesisActive    = "active"
	HypothesisConfirmed = "confirmed"
	HypothesisRefuted   = "refuted"
	HypothesisStale     = "stale"
)

// HypothesisEvent is an append-only belief-history entry for one Strategist
// hypothesis. The current hypotheses table answers "what do we believe now?";
// this table answers "how did we get there?" for the Strategy UI.
type HypothesisEvent struct {
	ID            int64    `json:"id"`
	ScanID        int64    `json:"scan_id"`
	HypothesisID  string   `json:"hypothesis_id"`
	EventType     string   `json:"event_type"`
	OldStatus     string   `json:"old_status,omitempty"`
	NewStatus     string   `json:"new_status,omitempty"`
	OldConfidence *float64 `json:"old_confidence,omitempty"`
	NewConfidence *float64 `json:"new_confidence,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	EvidenceRefs  []string `json:"evidence_refs,omitempty"`
	RelatedRef    string   `json:"related_ref,omitempty"`
	Actor         string   `json:"actor,omitempty"`
	CreatedAt     string   `json:"created_at"`
}

// UpsertHypothesis creates or updates a hypothesis. The Strategist may emit
// the same hypothesis across cycles; we keep the earliest creation time
// and overwrite the confidence + evidence.
func (db *DB) UpsertHypothesis(h Hypothesis) error {
	evidenceJSON := "[]"
	if len(h.SupportingEvidence) > 0 {
		if b, err := json.Marshal(h.SupportingEvidence); err == nil {
			evidenceJSON = string(b)
		}
	}
	if h.Status == "" {
		h.Status = HypothesisActive
	}
	prev, err := db.getHypothesis(h.ScanID, h.ID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("load previous hypothesis: %w", err)
	}
	// ON CONFLICT targets the composite PK (scan_id, id) — the Strategist
	// reuses stable ids like "h1"/"h2" per scan, so we scope uniqueness
	// per-scan to prevent cross-scan overwrites.
	_, err = db.conn.Exec(`
		INSERT INTO hypotheses (id, scan_id, cycle_id, statement, confidence, status, supporting_evidence, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, id) DO UPDATE SET
			cycle_id             = excluded.cycle_id,
			statement            = excluded.statement,
			confidence          = excluded.confidence,
			status              = CASE WHEN hypotheses.status IN ('confirmed','refuted')
			                           THEN hypotheses.status
			                           ELSE excluded.status END,
			supporting_evidence = excluded.supporting_evidence,
			notes               = excluded.notes,
			updated_at          = datetime('now')`,
		h.ID, h.ScanID, h.CycleID, h.Statement, h.Confidence, h.Status, evidenceJSON, h.Notes,
	)
	if err != nil {
		return fmt.Errorf("upsert hypothesis: %w", err)
	}

	current, err := db.getHypothesis(h.ScanID, h.ID)
	if err != nil {
		return fmt.Errorf("load current hypothesis: %w", err)
	}
	if prev == nil {
		conf := current.Confidence
		_ = db.InsertHypothesisEvent(HypothesisEvent{
			ScanID:        h.ScanID,
			HypothesisID:  h.ID,
			EventType:     "created",
			NewStatus:     current.Status,
			NewConfidence: &conf,
			Reason:        fmt.Sprintf("Strategist cycle %d created this hypothesis.", h.CycleID),
			EvidenceRefs:  current.SupportingEvidence,
			RelatedRef:    fmt.Sprintf("strategist/cycle-%d", h.CycleID),
			Actor:         "strategist",
		})
		return nil
	}
	if prev.Status != current.Status ||
		prev.Confidence != current.Confidence ||
		!reflect.DeepEqual(prev.SupportingEvidence, current.SupportingEvidence) ||
		prev.Notes != current.Notes {
		oldConf := prev.Confidence
		newConf := current.Confidence
		_ = db.InsertHypothesisEvent(HypothesisEvent{
			ScanID:        h.ScanID,
			HypothesisID:  h.ID,
			EventType:     "revised",
			OldStatus:     prev.Status,
			NewStatus:     current.Status,
			OldConfidence: &oldConf,
			NewConfidence: &newConf,
			Reason:        fmt.Sprintf("Strategist cycle %d revised confidence or evidence.", h.CycleID),
			EvidenceRefs:  current.SupportingEvidence,
			RelatedRef:    fmt.Sprintf("strategist/cycle-%d", h.CycleID),
			Actor:         "strategist",
		})
	}
	return nil
}

// SetHypothesisStatus transitions a hypothesis to a terminal state. Used when
// a finding confirms it or a verifier result refutes it. Scoped by scan_id
// because hypothesis ids ("h1", "h2") are only unique within a scan.
func (db *DB) SetHypothesisStatus(scanID int64, id, status, resolvedBy string) error {
	prev, err := db.getHypothesis(scanID, id)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("load previous hypothesis: %w", err)
	}
	res, err := db.conn.Exec(`
		UPDATE hypotheses
		SET status = CASE WHEN status IN ('confirmed','refuted') THEN status ELSE ? END,
		    resolved_by = CASE WHEN status IN ('confirmed','refuted') THEN resolved_by ELSE ? END,
		    updated_at = datetime('now')
		WHERE scan_id = ? AND id = ?`, status, resolvedBy, scanID, id)
	if err != nil {
		return err
	}
	updated, _ := res.RowsAffected()
	if updated == 0 || prev == nil {
		return nil
	}
	current, err := db.getHypothesis(scanID, id)
	if err != nil {
		return fmt.Errorf("load current hypothesis: %w", err)
	}
	if prev.Status == current.Status && prev.ResolvedBy == current.ResolvedBy {
		return nil
	}
	oldConf := prev.Confidence
	newConf := current.Confidence
	_ = db.InsertHypothesisEvent(HypothesisEvent{
		ScanID:        scanID,
		HypothesisID:  id,
		EventType:     "status_changed",
		OldStatus:     prev.Status,
		NewStatus:     current.Status,
		OldConfidence: &oldConf,
		NewConfidence: &newConf,
		Reason:        fmt.Sprintf("Resolved by %s.", resolvedBy),
		EvidenceRefs:  current.SupportingEvidence,
		RelatedRef:    resolvedBy,
		Actor:         "store",
	})
	return nil
}

// ListHypotheses returns all hypotheses for a scan, active first.
func (db *DB) ListHypotheses(scanID int64) ([]Hypothesis, error) {
	rows, err := db.conn.Query(`
		SELECT id, scan_id, cycle_id, statement, confidence, status,
		       COALESCE(supporting_evidence,'[]'), COALESCE(resolved_by,''), COALESCE(notes,''),
		       created_at, updated_at
		FROM hypotheses WHERE scan_id = ?
		ORDER BY
			CASE status WHEN 'active' THEN 0 WHEN 'confirmed' THEN 1
			           WHEN 'refuted' THEN 2 ELSE 3 END,
			confidence DESC, id ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Hypothesis
	for rows.Next() {
		var h Hypothesis
		var evidenceJSON string
		if err := rows.Scan(&h.ID, &h.ScanID, &h.CycleID, &h.Statement, &h.Confidence, &h.Status,
			&evidenceJSON, &h.ResolvedBy, &h.Notes, &h.CreatedAt, &h.UpdatedAt); err != nil {
			continue
		}
		if evidenceJSON != "" {
			json.Unmarshal([]byte(evidenceJSON), &h.SupportingEvidence)
		}
		out = append(out, h)
	}
	return out, nil
}

func (db *DB) getHypothesis(scanID int64, id string) (*Hypothesis, error) {
	row := db.conn.QueryRow(`
		SELECT id, scan_id, cycle_id, statement, confidence, status,
		       COALESCE(supporting_evidence,'[]'), COALESCE(resolved_by,''), COALESCE(notes,''),
		       created_at, updated_at
		FROM hypotheses WHERE scan_id = ? AND id = ?`, scanID, id)
	var h Hypothesis
	var evidenceJSON string
	if err := row.Scan(&h.ID, &h.ScanID, &h.CycleID, &h.Statement, &h.Confidence, &h.Status,
		&evidenceJSON, &h.ResolvedBy, &h.Notes, &h.CreatedAt, &h.UpdatedAt); err != nil {
		return nil, err
	}
	if evidenceJSON != "" {
		_ = json.Unmarshal([]byte(evidenceJSON), &h.SupportingEvidence)
	}
	return &h, nil
}

func (db *DB) InsertHypothesisEvent(e HypothesisEvent) error {
	evidenceJSON := "[]"
	if len(e.EvidenceRefs) > 0 {
		if b, err := json.Marshal(e.EvidenceRefs); err == nil {
			evidenceJSON = string(b)
		}
	}
	var oldConf any
	if e.OldConfidence != nil {
		oldConf = *e.OldConfidence
	}
	var newConf any
	if e.NewConfidence != nil {
		newConf = *e.NewConfidence
	}
	if e.Actor == "" {
		e.Actor = "aobtd"
	}
	_, err := db.conn.Exec(`
		INSERT INTO hypothesis_events (
			scan_id, hypothesis_id, event_type,
			old_status, new_status, old_confidence, new_confidence,
			reason, evidence_refs, related_ref, actor
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ScanID, e.HypothesisID, e.EventType,
		e.OldStatus, e.NewStatus, oldConf, newConf,
		redact.Text(e.Reason), evidenceJSON, e.RelatedRef, e.Actor,
	)
	if err != nil {
		return fmt.Errorf("insert hypothesis event: %w", err)
	}
	return nil
}

func (db *DB) ListHypothesisEvents(scanID int64, limit int) ([]HypothesisEvent, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := db.conn.Query(`
		SELECT id, scan_id, hypothesis_id, event_type,
		       COALESCE(old_status,''), COALESCE(new_status,''),
		       old_confidence, new_confidence,
		       COALESCE(reason,''), COALESCE(evidence_refs,'[]'),
		       COALESCE(related_ref,''), COALESCE(actor,''), created_at
		FROM hypothesis_events
		WHERE scan_id = ?
		ORDER BY id ASC
		LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HypothesisEvent
	for rows.Next() {
		var e HypothesisEvent
		var oldConf, newConf sql.NullFloat64
		var evidenceJSON string
		if err := rows.Scan(&e.ID, &e.ScanID, &e.HypothesisID, &e.EventType,
			&e.OldStatus, &e.NewStatus, &oldConf, &newConf,
			&e.Reason, &evidenceJSON, &e.RelatedRef, &e.Actor, &e.CreatedAt); err != nil {
			continue
		}
		if oldConf.Valid {
			v := oldConf.Float64
			e.OldConfidence = &v
		}
		if newConf.Valid {
			v := newConf.Float64
			e.NewConfidence = &v
		}
		if evidenceJSON != "" {
			_ = json.Unmarshal([]byte(evidenceJSON), &e.EvidenceRefs)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── Strategist cycles ─────────────────────────────────────────────

// StrategistCycle is one run of the Strategist agent. Every directive emitted
// links back via follow_ups.emitted_by + strategist cycle id in its metadata.
type StrategistCycle struct {
	ID               int64  `json:"id"`
	ScanID           int64  `json:"scan_id"`
	TriggerReason    string `json:"trigger_reason"`
	ModelID          string `json:"model_id"`
	WorldModelSize   int    `json:"world_model_size"`
	RawOutput        string `json:"raw_output"`
	ExecutiveSummary string `json:"executive_summary"`
	HypothesisCount  int    `json:"hypothesis_count"`
	DirectiveCount   int    `json:"directive_count"`
	RejectedCount    int    `json:"rejected_count"`
	TokensIn         int    `json:"tokens_in"`
	TokensOut        int    `json:"tokens_out"`
	DurationMs       int64  `json:"duration_ms"`
	CostUcents       int64  `json:"cost_ucents"`
	Error            string `json:"error,omitempty"`
	CreatedAt        string `json:"created_at"`
}

// InsertStrategistCycle logs one Strategist invocation. Returns the cycle's id
// which the caller uses to tag hypotheses it emits.
func (db *DB) InsertStrategistCycle(c StrategistCycle) (int64, error) {
	res, err := db.conn.Exec(`
		INSERT INTO strategist_cycles
		  (scan_id, trigger_reason, model_id, world_model_size, raw_output,
		   executive_summary, hypothesis_count, directive_count, rejected_count,
		   tokens_in, tokens_out, duration_ms, cost_ucents, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ScanID, c.TriggerReason, c.ModelID, c.WorldModelSize, redact.Text(c.RawOutput),
		redact.Text(c.ExecutiveSummary), c.HypothesisCount, c.DirectiveCount, c.RejectedCount,
		c.TokensIn, c.TokensOut, c.DurationMs, c.CostUcents, redact.Text(c.Error),
	)
	if err != nil {
		return 0, fmt.Errorf("insert strategist cycle: %w", err)
	}
	return res.LastInsertId()
}

// ListStrategistCycles returns recent cycles for the reasoning-trace UI.
func (db *DB) ListStrategistCycles(scanID int64, limit int) ([]StrategistCycle, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.conn.Query(`
		SELECT id, scan_id, trigger_reason, model_id, world_model_size,
		       COALESCE(raw_output,''), COALESCE(executive_summary,''),
		       hypothesis_count, directive_count, rejected_count,
		       tokens_in, tokens_out, duration_ms, cost_ucents,
		       COALESCE(error,''), created_at
		FROM strategist_cycles WHERE scan_id = ?
		ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StrategistCycle
	for rows.Next() {
		var c StrategistCycle
		if err := rows.Scan(&c.ID, &c.ScanID, &c.TriggerReason, &c.ModelID, &c.WorldModelSize,
			&c.RawOutput, &c.ExecutiveSummary, &c.HypothesisCount, &c.DirectiveCount,
			&c.RejectedCount, &c.TokensIn, &c.TokensOut, &c.DurationMs, &c.CostUcents,
			&c.Error, &c.CreatedAt); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// ── Extended directive (follow_up) insert carrying strategic metadata ──

// InsertDirective is the Strategist-aware version of InsertFollowUp. It
// accepts grounded_in / hypothesis_id / emitted_by fields and stores them
// on the underlying follow_ups row. Existing InsertFollowUp callers keep
// working; new Strategist code uses this.
func (db *DB) InsertDirective(scanID int64, f FollowUp, groundedIn []string, hypothesisID, emittedBy string) (int64, error) {
	f = normalizeFollowUpForInsert(f)
	paramsJSON, err := encodeFollowUpParams(f.Params)
	if err != nil {
		return 0, fmt.Errorf("encode directive params: %w", err)
	}
	groundedJSON := "[]"
	if len(groundedIn) > 0 {
		if b, err := json.Marshal(groundedIn); err == nil {
			groundedJSON = string(b)
		}
	}
	if emittedBy == "" {
		emittedBy = "strategist"
	}
	// The hypothesis is part of experiment identity. Two hypotheses may ask
	// for the same request for different reasons and both results must remain
	// attributable to the belief they test.
	f.HypothesisID = hypothesisID
	dedupe, err := computeDedupeKey(f)
	if err != nil {
		return 0, fmt.Errorf("compute directive dedupe key: %w", err)
	}

	// INSERT OR IGNORE works with the partial unique index on
	// (scan_id, dedupe_key) WHERE dedupe_key != ''. The ON CONFLICT(col,col)
	// form is rejected by modernc.org/sqlite against a partial index.
	res, err := db.conn.Exec(`
		INSERT OR IGNORE INTO follow_ups (
			scan_id, source_agent, source_profile_id,
			action, url, params_json, reason,
			priority, status, dedupe_key,
			emitted_by, hypothesis_id, grounded_in
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, strOr(f.SourceAgent, emittedBy), f.SourceProfileID,
		f.Action, f.URL, paramsJSON, f.Reason,
		f.Priority, strOr(f.Status, FollowUpPending), dedupe,
		emittedBy, hypothesisID, groundedJSON,
	)
	if err != nil {
		return 0, fmt.Errorf("insert directive: %w", err)
	}
	id, _ := res.LastInsertId()
	if n, _ := res.RowsAffected(); n == 0 {
		// Row dropped by OR IGNORE (duplicate dedupe_key). Not an error.
		return 0, nil
	}
	if hypothesisID != "" {
		_ = db.InsertHypothesisEvent(HypothesisEvent{
			ScanID:       scanID,
			HypothesisID: hypothesisID,
			EventType:    "directive_queued",
			NewStatus:    HypothesisActive,
			Reason:       f.Reason,
			EvidenceRefs: groundedIn,
			RelatedRef:   fmt.Sprintf("directive:%d", id),
			Actor:        emittedBy,
		})
	}
	return id, nil
}

// ActiveDirectives returns pending/running directives so the Strategist can
// read the current queue before planning (avoids emitting the same thing
// twice).
func (db *DB) ActiveDirectives(scanID int64) ([]FollowUp, error) {
	rows, err := db.conn.Query(`
		SELECT id, source_agent, COALESCE(source_profile_id,''), action,
		       COALESCE(url,''), COALESCE(params_json,'{}'),
		       COALESCE(reason,''), priority, status, created_at
		FROM follow_ups
		WHERE scan_id = ? AND status IN ('pending','running')
		ORDER BY priority DESC, id ASC
		LIMIT 200`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FollowUp
	for rows.Next() {
		var f FollowUp
		var paramsJSON string
		rows.Scan(&f.ID, &f.SourceAgent, &f.SourceProfileID, &f.Action,
			&f.URL, &paramsJSON, &f.Reason, &f.Priority, &f.Status, &f.CreatedAt)
		if paramsJSON != "" && paramsJSON != "{}" {
			var p map[string]any
			if json.Unmarshal([]byte(paramsJSON), &p) == nil {
				f.Params = p
			}
		}
		out = append(out, f)
	}
	return out, nil
}
