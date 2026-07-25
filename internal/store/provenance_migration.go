package store

import (
	"fmt"
	"strings"
)

// migrateTrafficProvenance is deliberately separate from the main schema
// migration so older scan databases and fresh databases get the same additive
// columns without coupling provenance to unrelated schema work.
func (db *DB) migrateTrafficProvenance() error {
	columns := []struct {
		name       string
		definition string
	}{
		{name: "source_agent", definition: "TEXT NOT NULL DEFAULT 'capture'"},
		{name: "source_action_id", definition: "INTEGER NOT NULL DEFAULT 0"},
		{name: "hypothesis_id", definition: "TEXT NOT NULL DEFAULT ''"},
	}
	for _, column := range columns {
		if _, err := db.conn.Exec(fmt.Sprintf(
			"ALTER TABLE traffic ADD COLUMN %s %s", column.name, column.definition,
		)); err != nil && !isDuplicateColumnError(err) {
			return fmt.Errorf("add traffic.%s: %w", column.name, err)
		}
	}

	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_traffic_source_action
		 ON traffic(scan_id, source_action_id) WHERE source_action_id != 0`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_hypothesis
		 ON traffic(scan_id, hypothesis_id) WHERE hypothesis_id != ''`,
	}
	for _, statement := range indexes {
		if _, err := db.conn.Exec(statement); err != nil {
			return fmt.Errorf("create traffic provenance index: %w", err)
		}
	}
	if _, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS traffic_actions (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id        INTEGER NOT NULL REFERENCES scans(id),
			source_agent   TEXT NOT NULL,
			action         TEXT NOT NULL,
			reason         TEXT NOT NULL DEFAULT '',
			from_url       TEXT NOT NULL DEFAULT '',
			to_url         TEXT NOT NULL DEFAULT '',
			hypothesis_id  TEXT NOT NULL DEFAULT '',
			status         TEXT NOT NULL DEFAULT 'running',
			result         TEXT NOT NULL DEFAULT '',
			started_at     DATETIME NOT NULL DEFAULT (datetime('now')),
			completed_at   DATETIME
		)`); err != nil {
		return fmt.Errorf("create traffic_actions: %w", err)
	}
	if _, err := db.conn.Exec(`
		CREATE INDEX IF NOT EXISTS idx_traffic_actions_scan
		ON traffic_actions(scan_id, id)`); err != nil {
		return fmt.Errorf("create traffic_actions scan index: %w", err)
	}
	return nil
}

func isDuplicateColumnError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "duplicate column name")
}
