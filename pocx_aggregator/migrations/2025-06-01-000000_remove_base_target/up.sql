-- Remove base_target column and rename quality -> raw_quality
-- SQLite requires table recreation to drop/rename columns
CREATE TABLE submissions_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    height BIGINT NOT NULL,
    raw_quality BIGINT NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(account_id, machine_id, height)
);

INSERT INTO submissions_new (id, account_id, machine_id, height, raw_quality, timestamp)
    SELECT id, account_id, machine_id, height, quality, timestamp FROM submissions;

DROP TABLE submissions;
ALTER TABLE submissions_new RENAME TO submissions;

CREATE INDEX idx_submissions_account_height ON submissions(account_id, height DESC);
CREATE INDEX idx_submissions_timestamp ON submissions(timestamp DESC);
