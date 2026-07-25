package store

import (
	"fmt"
)

// migrateFollowUpLeases upgrades a pre-lease queue in place. It lives next
// to the queue implementation so the schema contract stays visible here;
// DB.migrate calls it after creating the base schema.
func (db *DB) migrateFollowUpLeases() error {
	columns := []struct {
		name string
		ddl  string
	}{
		{"claimed_at", `ALTER TABLE follow_ups ADD COLUMN claimed_at DATETIME`},
		{"lease_expires_at", `ALTER TABLE follow_ups ADD COLUMN lease_expires_at DATETIME`},
		{"lease_token", `ALTER TABLE follow_ups ADD COLUMN lease_token TEXT NOT NULL DEFAULT ''`},
		{"attempt_count", `ALTER TABLE follow_ups ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0`},
	}
	for _, column := range columns {
		var exists int
		if err := db.conn.QueryRow(`
			SELECT COUNT(*) FROM pragma_table_info('follow_ups') WHERE name = ?`,
			column.name).Scan(&exists); err != nil {
			return fmt.Errorf("inspect follow_ups.%s: %w", column.name, err)
		}
		if exists != 0 {
			continue
		}
		if _, err := db.conn.Exec(column.ddl); err != nil {
			return fmt.Errorf("add follow_ups.%s: %w", column.name, err)
		}
	}
	if _, err := db.conn.Exec(`
		CREATE INDEX IF NOT EXISTS idx_followups_claimable
		ON follow_ups(scan_id, status, lease_expires_at, priority, id)`); err != nil {
		return fmt.Errorf("create follow-up claim index: %w", err)
	}
	return nil
}
