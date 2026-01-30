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

//! Shared RPC configuration types for PoCX components.
//!
//! This module provides unified configuration structures for RPC connections
//! used by the miner, aggregator, and other PoCX components.

use log::{error, info};
use serde::{Deserialize, Serialize};

/// Transport protocol for RPC connections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RpcTransport {
    /// HTTP transport (default)
    #[default]
    Http,
    /// HTTPS transport
    Https,
}

/// Authentication mechanism for RPC connections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RpcAuth {
    /// No authentication
    #[default]
    None,
    /// Username/password basic authentication
    UserPass { username: String, password: String },
    /// Cookie-based authentication (reads credentials from file)
    Cookie {
        /// Path to cookie file. If None, will attempt auto-discovery.
        #[serde(default)]
        cookie_path: Option<String>,
    },
}

impl RpcAuth {
    /// Get the authentication token string for use in HTTP Basic auth.
    /// Returns `username:password` format suitable for Base64 encoding.
    pub fn get_token(&self) -> Option<String> {
        match self {
            RpcAuth::None => None,
            RpcAuth::UserPass { username, password } => Some(format!("{}:{}", username, password)),
            RpcAuth::Cookie { cookie_path } => {
                if let Some(path) = cookie_path {
                    std::fs::read_to_string(path)
                        .ok()
                        .map(|s| s.trim().to_string())
                } else {
                    None
                }
            }
        }
    }

    /// Get the authentication token or exit the process on failure.
    /// Use this when authentication is required and failure is fatal.
    pub fn get_token_or_exit(&self, context: &str) -> Option<String> {
        match self {
            RpcAuth::None => {
                info!("[{}] Auth: none", context);
                None
            }
            RpcAuth::UserPass { username, password } => {
                info!("[{}] Auth: user_pass (user={})", context, username);
                Some(format!("{}:{}", username, password))
            }
            RpcAuth::Cookie { cookie_path } => {
                if let Some(path) = cookie_path {
                    match std::fs::read_to_string(path) {
                        Ok(content) => {
                            info!("[{}] Auth: cookie loaded from '{}'", context, path);
                            Some(content.trim().to_string())
                        }
                        Err(e) => {
                            error!(
                                "[{}] Auth: cookie FAILED - cannot read '{}': {}",
                                context, path, e
                            );
                            error!("Cannot start without valid authentication. Exiting.");
                            std::process::exit(1);
                        }
                    }
                } else {
                    error!(
                        "[{}] Auth: cookie type requires cookie_path to be specified",
                        context
                    );
                    error!("Cannot start without valid authentication. Exiting.");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Submission mode for mining operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SubmissionMode {
    /// Per-account tracking and submission (pool mining)
    #[default]
    Pool,
    /// Global best tracking and submission (solo mining)
    Wallet,
}

// Default value functions for serde
fn default_rpc_host() -> String {
    "127.0.0.1".to_string()
}

fn default_rpc_port() -> u16 {
    8080
}

fn default_timeout_ms() -> u64 {
    30000
}

/// RPC client configuration for connecting to upstream servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcClientConfig {
    /// Transport protocol (http, https)
    #[serde(default)]
    pub rpc_transport: RpcTransport,

    /// Host address
    #[serde(default = "default_rpc_host")]
    pub rpc_host: String,

    /// Port number
    #[serde(default = "default_rpc_port")]
    pub rpc_port: u16,

    /// Authentication configuration
    #[serde(default)]
    pub rpc_auth: RpcAuth,

    /// Request timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for RpcClientConfig {
    fn default() -> Self {
        Self {
            rpc_transport: RpcTransport::default(),
            rpc_host: default_rpc_host(),
            rpc_port: default_rpc_port(),
            rpc_auth: RpcAuth::default(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

impl RpcClientConfig {
    /// Build URL string from configuration.
    pub fn build_url(&self) -> Option<String> {
        match self.rpc_transport {
            RpcTransport::Http => Some(format!("http://{}:{}", self.rpc_host, self.rpc_port)),
            RpcTransport::Https => Some(format!("https://{}:{}", self.rpc_host, self.rpc_port)),
        }
    }

    /// Validate the configuration.
    pub fn validate(&self, context: &str) -> Result<(), String> {
        if self.rpc_host.is_empty() {
            return Err(format!("[{}] rpc_host cannot be empty", context));
        }
        if self.rpc_port == 0 {
            return Err(format!("[{}] rpc_port cannot be 0", context));
        }
        Ok(())
    }
}

/// Basic authentication configuration for RPC servers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BasicAuthConfig {
    pub username: String,
    pub password: String,
}

/// Server authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RpcServerAuth {
    /// Enable authentication for incoming connections
    #[serde(default)]
    pub enabled: bool,

    /// Basic auth credentials (required if enabled)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuthConfig>,
}

impl RpcServerAuth {
    /// Validate incoming credentials against configured auth.
    /// Returns true if auth is disabled or credentials match.
    pub fn validate_credentials(&self, username: &str, password: &str) -> bool {
        if !self.enabled {
            return true;
        }
        match &self.basic_auth {
            Some(config) => config.username == username && config.password == password,
            None => false, // Auth enabled but no credentials configured
        }
    }

    /// Check if authentication is required.
    pub fn is_required(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_transport_default() {
        let transport: RpcTransport = Default::default();
        assert_eq!(transport, RpcTransport::Http);
    }

    #[test]
    fn test_rpc_auth_none() {
        let auth = RpcAuth::None;
        assert_eq!(auth.get_token(), None);
    }

    #[test]
    fn test_rpc_auth_userpass() {
        let auth = RpcAuth::UserPass {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        assert_eq!(auth.get_token(), Some("user:pass".to_string()));
    }

    #[test]
    fn test_rpc_client_config_build_url() {
        let config = RpcClientConfig {
            rpc_transport: RpcTransport::Http,
            rpc_host: "localhost".to_string(),
            rpc_port: 8080,
            ..Default::default()
        };
        assert_eq!(
            config.build_url(),
            Some("http://localhost:8080".to_string())
        );

        let config_https = RpcClientConfig {
            rpc_transport: RpcTransport::Https,
            rpc_host: "example.com".to_string(),
            rpc_port: 443,
            ..Default::default()
        };
        assert_eq!(
            config_https.build_url(),
            Some("https://example.com:443".to_string())
        );
    }

    #[test]
    fn test_rpc_client_config_validate() {
        // Valid HTTP config
        let config = RpcClientConfig::default();
        assert!(config.validate("test").is_ok());

        // Invalid config (empty host)
        let config_empty_host = RpcClientConfig {
            rpc_host: "".to_string(),
            ..Default::default()
        };
        assert!(config_empty_host.validate("test").is_err());

        // Invalid config (zero port)
        let config_zero_port = RpcClientConfig {
            rpc_port: 0,
            ..Default::default()
        };
        assert!(config_zero_port.validate("test").is_err());
    }

    #[test]
    fn test_rpc_server_auth() {
        // Disabled auth
        let auth = RpcServerAuth::default();
        assert!(auth.validate_credentials("any", "thing"));
        assert!(!auth.is_required());

        // Enabled auth with credentials
        let auth_enabled = RpcServerAuth {
            enabled: true,
            basic_auth: Some(BasicAuthConfig {
                username: "admin".to_string(),
                password: "secret".to_string(),
            }),
        };
        assert!(auth_enabled.validate_credentials("admin", "secret"));
        assert!(!auth_enabled.validate_credentials("admin", "wrong"));
        assert!(!auth_enabled.validate_credentials("wrong", "secret"));
        assert!(auth_enabled.is_required());
    }

    #[test]
    fn test_submission_mode_default() {
        let mode: SubmissionMode = Default::default();
        assert_eq!(mode, SubmissionMode::Pool);
    }

    #[test]
    fn test_config_serialization() {
        let config = RpcClientConfig {
            rpc_transport: RpcTransport::Https,
            rpc_host: "pool.example.com".to_string(),
            rpc_port: 443,
            rpc_auth: RpcAuth::UserPass {
                username: "miner".to_string(),
                password: "secret".to_string(),
            },
            timeout_ms: 5000,
        };

        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(yaml.contains("https"));
        assert!(yaml.contains("pool.example.com"));
        assert!(yaml.contains("user_pass"));

        let parsed: RpcClientConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.rpc_transport, RpcTransport::Https);
        assert_eq!(parsed.rpc_host, "pool.example.com");
    }
}
