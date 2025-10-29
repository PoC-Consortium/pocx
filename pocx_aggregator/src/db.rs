// Copyright (c) 2025 Proof of Capacity Consortium
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::error::{Error, Result};
use crate::schema::submissions;
use chrono::NaiveDateTime;
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use log::{error, info};
use tokio::sync::mpsc;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

#[derive(Debug)]
enum DbCommand {
    SaveSubmission {
        account_id: String,
        machine_id: Option<String>,
        quality: u64,
        base_target: u64,
        height: u64,
    },
    Cleanup {
        current_height: u64,
        retention_blocks: u64,
    },
}

#[derive(Clone)]
pub struct Database {
    tx: mpsc::UnboundedSender<DbCommand>,
    pool: Pool<ConnectionManager<SqliteConnection>>,
}

#[derive(Queryable, Debug)]
#[diesel(table_name = submissions)]
pub struct Submission {
    pub id: i32,
    pub account_id: String,
    pub machine_id: String,
    pub height: i64,
    pub quality: i64,
    pub base_target: i64,
    pub timestamp: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = submissions)]
pub struct NewSubmission {
    pub account_id: String,
    pub machine_id: String,
    pub height: i64,
    pub quality: i64,
    pub base_target: i64,
}

impl Database {
    /// Create or open database and spawn dedicated writer task
    pub fn new(path: &str) -> Result<Self> {
        info!("Opening database at: {}", path);

        let manager = ConnectionManager::<SqliteConnection>::new(path);
        let pool = Pool::builder()
            .max_size(1)
            .build(manager)
            .map_err(|e| Error::Config(format!("Failed to create connection pool: {}", e)))?;

        // Run migrations and configure SQLite
        let mut conn = pool
            .get()
            .map_err(|e| Error::Config(format!("Failed to get connection: {}", e)))?;

        conn.batch_execute("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .map_err(|e| Error::Config(format!("Failed to configure database: {}", e)))?;

        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| Error::Config(format!("Failed to run migrations: {}", e)))?;

        drop(conn);

        info!("Database initialized successfully");

        // Create channel and spawn writer task
        let (tx, rx) = mpsc::unbounded_channel();

        tokio::spawn(Self::writer_task(pool.clone(), rx));

        Ok(Self { tx, pool })
    }

    /// Dedicated writer task that processes all database writes sequentially
    async fn writer_task(
        pool: Pool<ConnectionManager<SqliteConnection>>,
        mut rx: mpsc::UnboundedReceiver<DbCommand>,
    ) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                DbCommand::SaveSubmission {
                    account_id,
                    machine_id,
                    quality,
                    base_target,
                    height,
                } => {
                    if let Err(e) = Self::do_save_submission(
                        &pool,
                        &account_id,
                        machine_id,
                        quality,
                        base_target,
                        height,
                    ) {
                        error!("Failed to save submission to database: {}", e);
                    }
                }
                DbCommand::Cleanup {
                    current_height,
                    retention_blocks,
                } => {
                    if let Err(e) = Self::do_cleanup(&pool, current_height, retention_blocks) {
                        error!("Failed to cleanup old submissions: {}", e);
                    }
                }
            }
        }
    }

    fn do_save_submission(
        pool: &Pool<ConnectionManager<SqliteConnection>>,
        account_id_param: &str,
        machine_id_param: Option<String>,
        quality_param: u64,
        base_target_param: u64,
        height_param: u64,
    ) -> Result<()> {
        let mut conn = pool
            .get()
            .map_err(|e| Error::Config(format!("Failed to get connection: {}", e)))?;

        let machine_id_str = machine_id_param.unwrap_or_else(|| "unknown".to_string());

        conn.batch_execute(&format!(
            "INSERT INTO submissions (account_id, machine_id, height, quality, base_target, timestamp)
             VALUES ('{}', '{}', {}, {}, {}, CURRENT_TIMESTAMP)
             ON CONFLICT(account_id, machine_id, height)
             DO UPDATE SET
                quality = CASE WHEN excluded.quality < quality THEN excluded.quality ELSE quality END,
                base_target = CASE WHEN excluded.quality < quality THEN excluded.base_target ELSE base_target END,
                timestamp = CASE WHEN excluded.quality < quality THEN CURRENT_TIMESTAMP ELSE timestamp END",
            account_id_param.replace('\'', "''"),
            machine_id_str.replace('\'', "''"),
            height_param,
            quality_param,
            base_target_param
        ))
        .map_err(|e| Error::Config(format!("Failed to save submission: {}", e)))?;

        Ok(())
    }

    fn do_cleanup(
        pool: &Pool<ConnectionManager<SqliteConnection>>,
        current_height: u64,
        retention_blocks: u64,
    ) -> Result<usize> {
        if retention_blocks == 0 {
            return Ok(0);
        }

        use crate::schema::submissions::dsl::*;

        let cutoff_height = current_height.saturating_sub(retention_blocks);

        let mut conn = pool
            .get()
            .map_err(|e| Error::Config(format!("Failed to get connection: {}", e)))?;

        let deleted = diesel::delete(submissions.filter(height.lt(cutoff_height as i64)))
            .execute(&mut conn)
            .map_err(|e| Error::Config(format!("Failed to cleanup old submissions: {}", e)))?;

        if deleted > 0 {
            info!(
                "Cleaned up {} old submissions (height < {})",
                deleted, cutoff_height
            );
        }

        Ok(deleted)
    }

    /// Clean up old submissions (non-blocking, queued)
    pub fn cleanup_old_submissions(
        &self,
        current_height: u64,
        retention_blocks: u64,
    ) -> Result<()> {
        self.tx
            .send(DbCommand::Cleanup {
                current_height,
                retention_blocks,
            })
            .map_err(|e| Error::Config(format!("Failed to send cleanup command: {}", e)))?;
        Ok(())
    }

    /// Save a submission (non-blocking, queued)
    pub fn save_submission(
        &self,
        account_id: &str,
        machine_id: Option<String>,
        quality: u64,
        base_target: u64,
        height: u64,
    ) -> Result<()> {
        self.tx
            .send(DbCommand::SaveSubmission {
                account_id: account_id.to_string(),
                machine_id,
                quality,
                base_target,
                height,
            })
            .map_err(|e| Error::Config(format!("Failed to send save command: {}", e)))?;
        Ok(())
    }

    /// Load recent submissions for a specific account
    pub fn load_submissions(&self, account_id_filter: &str, limit: i64) -> Result<Vec<Submission>> {
        use crate::schema::submissions::dsl::*;

        let mut conn = self
            .pool
            .get()
            .map_err(|e| Error::Config(format!("Failed to get connection: {}", e)))?;

        let results = submissions
            .filter(account_id.eq(account_id_filter))
            .order(timestamp.desc())
            .limit(limit)
            .load::<Submission>(&mut conn)
            .map_err(|e| Error::Config(format!("Failed to load submissions: {}", e)))?;

        Ok(results)
    }

    /// Get all recent submissions (for loading on startup)
    pub fn get_all_recent_submissions(&self, limit_overall: i64) -> Result<Vec<Submission>> {
        use crate::schema::submissions::dsl::*;

        let mut conn = self
            .pool
            .get()
            .map_err(|e| Error::Config(format!("Failed to get connection: {}", e)))?;

        let results = submissions
            .order(timestamp.desc())
            .limit(limit_overall)
            .load::<Submission>(&mut conn)
            .map_err(|e| Error::Config(format!("Failed to load submissions: {}", e)))?;

        Ok(results)
    }
}
