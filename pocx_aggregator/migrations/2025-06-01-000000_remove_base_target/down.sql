-- Revert: re-add base_target column and rename raw_quality -> quality
CREATE TABLE submissions_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    height BIGINT NOT NULL,
    quality BIGINT NOT NULL,
    base_target BIGINT NOT NULL DEFAULT 0,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(account_id, machine_id, height)
);

INSERT INTO submissions_new (id, account_id, machine_id, height, quality, timestamp)
    SELECT id, account_id, machine_id, height, raw_quality, timestamp FROM submissions;

DROP TABLE submissions;
ALTER TABLE submissions_new RENAME TO submissions;

CREATE INDEX idx_submissions_account_height ON submissions(account_id, height DESC);
CREATE INDEX idx_submissions_timestamp ON submissions(timestamp DESC);
