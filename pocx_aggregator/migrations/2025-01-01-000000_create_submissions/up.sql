-- Submissions table - stores BEST submission per block per machine
-- Minimal schema: only persistent data, stats tracked in memory
CREATE TABLE submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    height BIGINT NOT NULL,
    quality BIGINT NOT NULL,          -- Lower is better
    base_target BIGINT NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(account_id, machine_id, height)
);

-- Index for querying by account + height (for capacity calculation)
CREATE INDEX idx_submissions_account_height ON submissions(account_id, height DESC);

-- Index for querying by timestamp (for loading recent submissions)
CREATE INDEX idx_submissions_timestamp ON submissions(timestamp DESC);
