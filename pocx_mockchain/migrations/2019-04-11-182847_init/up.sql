CREATE TABLE IF NOT EXISTS block (
       height INTEGER NOT NULL PRIMARY KEY,
       base_target BIGINT NOT NULL,
       generation_signature TEXT NOT NULL,
       cumulative_difficulty INTEGER NOT NULL,
       generator TEXT NOT NULL,
       creation_time TIMESTAMP NOT NULL,
       nonce INTEGER NOT NULL,
       seed TEXT NOT NULL,
       poc_time INTEGER NOT NULL
);