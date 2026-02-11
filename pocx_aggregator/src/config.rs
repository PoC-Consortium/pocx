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

// Re-export shared types from pocx_protocol for convenience
pub use pocx_protocol::{BasicAuthConfig, RpcAuth, RpcServerAuth, RpcTransport, SubmissionMode};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration for downstream miner connections
    #[serde(default)]
    pub server: ServerConfig,

    /// Upstream pool or wallet configuration
    pub upstream: UpstreamConfig,

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

/// Server configuration for downstream connections (miners connecting to aggregator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on for miner connections
    #[serde(default = "default_listen_address")]
    pub listen_address: String,

    /// Optional authentication for downstream connections
    #[serde(default)]
    pub auth: RpcServerAuth,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_address: default_listen_address(),
            auth: RpcServerAuth::default(),
        }
    }
}

/// Upstream configuration - aligned with miner's Chain config style.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Pool/wallet name
    pub name: String,

    /// Transport protocol (http, https)
    #[serde(default)]
    pub rpc_transport: RpcTransport,

    /// RPC host address
    #[serde(default = "default_rpc_host")]
    pub rpc_host: String,

    /// RPC port
    #[serde(default = "default_rpc_port")]
    pub rpc_port: u16,

    /// Authentication configuration
    #[serde(default)]
    pub rpc_auth: RpcAuth,

    /// Submission mode: Pool (per-account best) or Wallet (global best)
    #[serde(default)]
    pub submission_mode: SubmissionMode,

    /// Expected block time in seconds (used for capacity estimation and poc_time)
    #[serde(default = "default_block_time")]
    pub block_time_secs: u64,
}

impl UpstreamConfig {
    /// Build URL for HTTP/HTTPS transport.
    pub fn build_url(&self) -> Option<String> {
        match self.rpc_transport {
            RpcTransport::Http => Some(format!("http://{}:{}", self.rpc_host, self.rpc_port)),
            RpcTransport::Https => Some(format!("https://{}:{}", self.rpc_host, self.rpc_port)),
        }
    }

    /// Get endpoint description for logging.
    pub fn endpoint(&self) -> String {
        match self.rpc_transport {
            RpcTransport::Http => format!("http://{}:{}", self.rpc_host, self.rpc_port),
            RpcTransport::Https => format!("https://{}:{}", self.rpc_host, self.rpc_port),
        }
    }

    /// Validate upstream configuration.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::Config("Upstream name cannot be empty".to_string()));
        }

        if self.rpc_host.is_empty() {
            return Err(Error::Config("rpc_host cannot be empty".to_string()));
        }
        if self.rpc_port == 0 {
            return Err(Error::Config("rpc_port cannot be 0".to_string()));
        }
        // Validate URL format
        let url_str = self.build_url().unwrap();
        if let Err(e) = url::Url::parse(&url_str) {
            return Err(Error::Config(format!(
                "Upstream has invalid URL '{}': {}",
                url_str, e
            )));
        }

        Ok(())
    }

    /// Get auth token or exit on failure.
    pub fn get_auth_token_or_exit(&self) -> Option<String> {
        self.rpc_auth.get_token_or_exit(&self.name)
    }
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
        2u64.pow(42) / self.upstream.block_time_secs
    }

    /// Calculate retention period in blocks from retention days
    /// Formula: days × 86400 / block_time_secs
    /// Returns 0 if retention_days is 0 (keep forever)
    pub fn retention_blocks(&self) -> u64 {
        if self.database.retention_days == 0 {
            return 0;
        }
        self.database.retention_days * 86400 / self.upstream.block_time_secs
    }

    /// Validate configuration
    fn validate(&self) -> Result<()> {
        // Validate upstream config
        self.upstream.validate()?;

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

        // Validate server auth if enabled
        if self.server.auth.enabled && self.server.auth.basic_auth.is_none() {
            return Err(Error::Config(
                "Server auth is enabled but no credentials configured".to_string(),
            ));
        }

        Ok(())
    }
}

// Default values
fn default_listen_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_rpc_host() -> String {
    "127.0.0.1".to_string()
}

fn default_rpc_port() -> u16 {
    8080
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
    fn test_config_validation_empty_name() {
        let upstream = UpstreamConfig {
            name: "".to_string(),
            rpc_transport: RpcTransport::Http,
            rpc_host: "localhost".to_string(),
            rpc_port: 8080,
            rpc_auth: RpcAuth::None,
            submission_mode: SubmissionMode::Pool,
            block_time_secs: 120,
        };

        assert!(upstream.validate().is_err());
    }

    #[test]
    fn test_valid_http_upstream() {
        let upstream = UpstreamConfig {
            name: "test".to_string(),
            rpc_transport: RpcTransport::Http,
            rpc_host: "localhost".to_string(),
            rpc_port: 8080,
            rpc_auth: RpcAuth::None,
            submission_mode: SubmissionMode::Pool,
            block_time_secs: 120,
        };

        assert!(upstream.validate().is_ok());
        assert_eq!(upstream.endpoint(), "http://localhost:8080");
    }

    #[test]
    fn test_invalid_upstream_empty_host() {
        let upstream = UpstreamConfig {
            name: "test".to_string(),
            rpc_transport: RpcTransport::Http,
            rpc_host: "".to_string(),
            rpc_port: 8080,
            rpc_auth: RpcAuth::None,
            submission_mode: SubmissionMode::Pool,
            block_time_secs: 120,
        };

        assert!(upstream.validate().is_err());
    }

    #[test]
    fn test_full_config_validation() {
        let config = Config {
            server: ServerConfig::default(),
            upstream: UpstreamConfig {
                name: "test".to_string(),
                rpc_transport: RpcTransport::Http,
                rpc_host: "localhost".to_string(),
                rpc_port: 8080,
                rpc_auth: RpcAuth::None,
                submission_mode: SubmissionMode::Pool,
                block_time_secs: 120,
            },
            cache: CacheConfig::default(),
            database: DatabaseConfig::default(),
            dashboard: None,
            logging: LoggingConfig::default(),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_with_enabled_auth_but_no_credentials() {
        let config = Config {
            server: ServerConfig {
                listen_address: "0.0.0.0:8080".to_string(),
                auth: RpcServerAuth {
                    enabled: true,
                    basic_auth: None, // No credentials
                },
            },
            upstream: UpstreamConfig {
                name: "test".to_string(),
                rpc_transport: RpcTransport::Http,
                rpc_host: "localhost".to_string(),
                rpc_port: 8080,
                rpc_auth: RpcAuth::None,
                submission_mode: SubmissionMode::Pool,
                block_time_secs: 120,
            },
            cache: CacheConfig::default(),
            database: DatabaseConfig::default(),
            dashboard: None,
            logging: LoggingConfig::default(),
        };

        assert!(config.validate().is_err());
    }
}
