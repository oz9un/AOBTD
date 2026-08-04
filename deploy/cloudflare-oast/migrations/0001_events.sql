CREATE TABLE IF NOT EXISTS callback_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_token TEXT NOT NULL,
    received_at_ms INTEGER NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    raw_query TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    colo TEXT NOT NULL DEFAULT '',
    headers_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_callback_events_probe_time
    ON callback_events(probe_token, received_at_ms);

CREATE INDEX IF NOT EXISTS idx_callback_events_received
    ON callback_events(received_at_ms);
