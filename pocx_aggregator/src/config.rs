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
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address to listen on for miner connections
    #[serde(default = "default_listen_address")]
    pub listen_address: String,

    /// Upstream pool or wallet configuration
    pub upstream: UpstreamConfig,

    /// Expected block time in seconds (used for capacity estimation and
    /// database retention)
    #[serde(default = "default_block_time")]
    pub block_time_secs: u64,

    /// Cache settings
    #[serde(default)]
    pub cache: CacheConfig,

    /// Database settings
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Dashboard settings (optional)
    #[serde(default)]
    pub dashboard: Option<DashboardConfig>,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubmissionMode {
    /// Per-account tracking and submission (default for pool aggregators)
    Pool,
    /// Global best tracking and submission (for solo mining aggregators)
    Wallet,
}

impl Default for SubmissionMode {
    fn default() -> Self {
        Self::Pool
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Pool/wallet name
    pub name: String,

    /// Pool/wallet URL (e.g., "http://pool.example.com:8080/pocx")
    pub url: String,

    /// Optional authentication token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,

    /// Submission mode: Pool (per-account best) or Wallet (global best)
    #[serde(default)]
    pub submission_mode: SubmissionMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// How long to cache mining info (in seconds)
    #[serde(default = "default_mining_info_ttl")]
    pub mining_info_ttl_secs: u64,

    /// Pool request timeout (in seconds)
    #[serde(default = "default_pool_timeout")]
    pub pool_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database file path
    #[serde(default = "default_database_path")]
    pub path: String,

    /// Database retention period in days (0 = keep forever)
    /// Submissions older than this will be automatically deleted
    #[serde(default = "default_db_retention_days")]
    pub retention_days: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_database_path(),
            retention_days: default_db_retention_days(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            mining_info_ttl_secs: default_mining_info_ttl(),
            pool_timeout_secs: default_pool_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Enable dashboard
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Dashboard listen address
    #[serde(default = "default_dashboard_address")]
    pub listen_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log file path
    #[serde(default = "default_log_file")]
    pub file: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: default_log_file(),
        }
    }
}

impl Config {
    /// Load configuration from a YAML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Calculate genesis base target from block time
    /// Formula: 2^42 / block_time_seconds (for 1 TiB starting network capacity)
    pub fn genesis_base_target(&self) -> u64 {
        2u64.pow(42) / self.block_time_secs
    }

    /// Calculate retention period in blocks from retention days
    /// Formula: days × 86400 / block_time_secs
    /// Returns 0 if retention_days is 0 (keep forever)
    pub fn retention_blocks(&self) -> u64 {
        if self.database.retention_days == 0 {
            return 0;
        }
        self.database.retention_days * 86400 / self.block_time_secs
    }

    /// Validate configuration
    fn validate(&self) -> Result<()> {
        // Validate upstream config
        if self.upstream.name.is_empty() {
            return Err(Error::Config("Upstream name cannot be empty".to_string()));
        }
        if self.upstream.url.is_empty() {
            return Err(Error::Config("Upstream URL cannot be empty".to_string()));
        }

        // Validate URL format
        if let Err(e) = url::Url::parse(&self.upstream.url) {
            return Err(Error::Config(format!(
                "Upstream has invalid URL '{}': {}",
                self.upstream.url, e
            )));
        }

        // Validate cache TTL
        if self.cache.mining_info_ttl_secs == 0 {
            return Err(Error::Config(
                "mining_info_ttl_secs must be greater than 0".to_string(),
            ));
        }

        // Validate timeout
        if self.cache.pool_timeout_secs == 0 {
            return Err(Error::Config(
                "pool_timeout_secs must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}

// Default values
fn default_listen_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_mining_info_ttl() -> u64 {
    5
}

fn default_pool_timeout() -> u64 {
    30
}

fn default_block_time() -> u64 {
    120 // PoCX uses 120 seconds (Burst uses 240)
}

fn default_database_path() -> String {
    "aggregator.db".to_string()
}

fn default_db_retention_days() -> u64 {
    7 // Keep submissions for 7 days by default
}

fn default_true() -> bool {
    true
}

fn default_dashboard_address() -> String {
    "0.0.0.0:8081".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_file() -> String {
    "aggregator.log".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = Config {
            listen_address: "0.0.0.0:8080".to_string(),
            upstream: UpstreamConfig {
                name: "".to_string(),
                url: "http://localhost:8080".to_string(),
                auth_token: None,
                submission_mode: SubmissionMode::Pool,
            },
            block_time_secs: 120,
            cache: CacheConfig::default(),
            database: DatabaseConfig::default(),
            dashboard: None,
            logging: LoggingConfig::default(),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_valid_config() {
        let config = Config {
            listen_address: "0.0.0.0:8080".to_string(),
            upstream: UpstreamConfig {
                name: "test".to_string(),
                url: "http://localhost:8080".to_string(),
                auth_token: None,
                submission_mode: SubmissionMode::Pool,
            },
            block_time_secs: 120,
            cache: CacheConfig::default(),
            database: DatabaseConfig::default(),
            dashboard: None,
            logging: LoggingConfig::default(),
        };

        assert!(config.validate().is_ok());
    }
}
