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

use serde::{Deserialize, Serialize};

/// Custom serde module for NetworkId
mod network_id_serde {
    use pocx_address::NetworkId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(network_id: &NetworkId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match network_id {
            NetworkId::Base58(version) => {
                #[derive(Serialize)]
                struct Base58Variant {
                    #[serde(rename = "Base58")]
                    version: u8,
                }
                Base58Variant { version: *version }.serialize(serializer)
            }
            NetworkId::Bech32(hrp) => {
                #[derive(Serialize)]
                struct Bech32Variant {
                    #[serde(rename = "Bech32")]
                    hrp: String,
                }
                Bech32Variant { hrp: hrp.clone() }.serialize(serializer)
            }
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<NetworkId, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum NetworkIdRepr {
            Base58 {
                #[serde(rename = "Base58")]
                version: u8,
            },
            Bech32 {
                #[serde(rename = "Bech32")]
                hrp: String,
            },
        }

        match NetworkIdRepr::deserialize(deserializer)? {
            NetworkIdRepr::Base58 { version } => Ok(NetworkId::Base58(version)),
            NetworkIdRepr::Bech32 { hrp } => Ok(NetworkId::Bech32(hrp)),
        }
    }
}

// Default configuration constants
/// Default block time in seconds for PoC networks
pub const DEFAULT_BLOCK_TIME_SECONDS: u64 = 120;
/// Default minimum compression level for PoC networks
pub const DEFAULT_MINIMUM_COMPRESSION_LEVEL: u8 = 1;
/// Default target compression level for PoC networks
pub const DEFAULT_TARGET_COMPRESSION_LEVEL: u8 = 1;
/// Default mockchain server port
pub const DEFAULT_MOCKCHAIN_PORT: u16 = 8081;

/// Configuration for PoCX Mockchain - mock blockchain for testing PoC miners
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoCXConfig {
    /// Network configuration
    pub network: NetworkConfig,
    /// Server configuration
    pub server: ServerConfig,
    /// Database configuration
    pub database: DatabaseConfig,
}

/// Network-specific configuration for different PoC cryptocurrencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network name (e.g., "PoCX", "CustomPoC")
    pub name: String,
    /// Network ID - determines address format and validation
    /// Examples:
    /// - Base58 with version byte: {"Base58": 127} for testnet
    /// - Bech32 with HRP: {"Bech32": "tpocx"} for testnet
    #[serde(with = "network_id_serde")]
    pub network_id: pocx_address::NetworkId,
    /// Block time in seconds
    pub block_time_seconds: u64,
    /// Minimum compression level accepted by the network
    /// Plotfiles below this level are rejected
    #[serde(default = "default_minimum_compression_level")]
    pub minimum_compression_level: u8,
    /// Target compression level for optimal network participation
    /// New plotfiles should use this level
    #[serde(default = "default_target_compression_level")]
    pub target_compression_level: u8,
    /// Genesis block signature
    pub genesis_signature: String,
    /// Difficulty adjustment parameters
    #[serde(default = "default_difficulty_config")]
    pub difficulty_adjustment: DifficultyAdjustmentConfig,
}

/// Difficulty adjustment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifficultyAdjustmentConfig {
    /// Number of blocks to look back for difficulty adjustment
    pub lookback_blocks: i64,
    /// Minimum adjustment ratio per block (e.g., 0.8 for -20%)
    pub min_adjustment_ratio: f64,
    /// Maximum adjustment ratio per block (e.g., 1.2 for +20%)
    pub max_adjustment_ratio: f64,
}

fn default_difficulty_config() -> DifficultyAdjustmentConfig {
    DifficultyAdjustmentConfig {
        lookback_blocks: 24,
        min_adjustment_ratio: 0.8,
        max_adjustment_ratio: 1.2,
    }
}

fn default_minimum_compression_level() -> u8 {
    DEFAULT_MINIMUM_COMPRESSION_LEVEL
}

fn default_target_compression_level() -> u8 {
    DEFAULT_TARGET_COMPRESSION_LEVEL
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server bind address
    pub host: String,
    /// Server port
    pub port: u16,
    /// Enable CORS
    pub enable_cors: bool,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL (SQLite path or connection string)
    pub url: String,
}

impl Default for PoCXConfig {
    /// Default configuration for PoCX mockchain
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                name: "PoCX Mockchain".to_string(),
                network_id: pocx_address::NetworkId::Bech32("tpocx".to_string()),
                block_time_seconds: DEFAULT_BLOCK_TIME_SECONDS,
                minimum_compression_level: DEFAULT_MINIMUM_COMPRESSION_LEVEL,
                target_compression_level: DEFAULT_TARGET_COMPRESSION_LEVEL,
                genesis_signature:
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                difficulty_adjustment: default_difficulty_config(),
            },
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: DEFAULT_MOCKCHAIN_PORT,
                enable_cors: true,
            },
            database: DatabaseConfig {
                url: "mockchain.db".to_string(),
            },
        }
    }
}

impl PoCXConfig {
    /// Load configuration from file or environment variables
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let mut config =
            if let Ok(config_content) = std::fs::read_to_string("mockchain_config.toml") {
                let config: PoCXConfig = toml::from_str(&config_content)?;
                println!("Loaded configuration from mockchain_config.toml");
                config
            } else if let Ok(config_content) = std::fs::read_to_string("mockchain_config.json") {
                let config: PoCXConfig = serde_json::from_str(&config_content)?;
                println!("Loaded configuration from mockchain_config.json");
                config
            } else {
                println!("No config file found, using default configuration");
                PoCXConfig::default()
            };

        // Apply environment variable overrides

        if let Ok(network_name) = std::env::var("POCX_NETWORK_NAME") {
            config.network.name = network_name;
        }

        // Support network ID override via environment variable
        // Format: "Base58:127" or "Bech32:tpocx"
        if let Ok(network_id_str) = std::env::var("POCX_NETWORK_ID") {
            if let Some((format, value)) = network_id_str.split_once(':') {
                match format {
                    "Base58" | "base58" => {
                        if let Ok(version) = value.parse::<u8>() {
                            config.network.network_id = pocx_address::NetworkId::Base58(version);
                        }
                    }
                    "Bech32" | "bech32" => {
                        config.network.network_id =
                            pocx_address::NetworkId::Bech32(value.to_string());
                    }
                    _ => {
                        eprintln!(
                            "Invalid POCX_NETWORK_ID format. Use 'Base58:127' or 'Bech32:tpocx'"
                        );
                    }
                }
            }
        }

        if let Ok(min_compression_str) = std::env::var("POCX_MINIMUM_COMPRESSION_LEVEL") {
            if let Ok(min_compression) = min_compression_str.parse::<u8>() {
                if (1..=32).contains(&min_compression) {
                    config.network.minimum_compression_level = min_compression;
                }
            }
        }

        if let Ok(target_compression_str) = std::env::var("POCX_TARGET_COMPRESSION_LEVEL") {
            if let Ok(target_compression) = target_compression_str.parse::<u8>() {
                if (1..=32).contains(&target_compression) {
                    config.network.target_compression_level = target_compression;
                    // Ensure minimum <= target
                    if config.network.minimum_compression_level > target_compression {
                        config.network.minimum_compression_level = target_compression;
                    }
                }
            }
        }

        if let Ok(host) = std::env::var("POCX_HOST") {
            config.server.host = host;
        }

        if let Ok(port_str) = std::env::var("POCX_PORT") {
            if let Ok(port) = port_str.parse::<u16>() {
                config.server.port = port;
            }
        }

        if let Ok(db_url) = std::env::var("POCX_DATABASE_URL") {
            config.database.url = db_url;
        }

        if std::env::var("POCX_NETWORK_ID").is_ok() {
            println!("Applied environment variable overrides");
        }

        Ok(config)
    }

    /// Create a sample configuration file
    pub fn create_sample_config() -> Result<(), Box<dyn std::error::Error>> {
        let sample_config = PoCXConfig::default();

        // Create TOML version
        let toml_content = toml::to_string_pretty(&sample_config)?;
        std::fs::write("mockchain_config.sample.toml", toml_content)?;

        // Create JSON version
        let json_content = serde_json::to_string_pretty(&sample_config)?;
        std::fs::write("mockchain_config.sample.json", json_content)?;

        println!("Created sample configuration files:");
        println!("  - mockchain_config.sample.toml");
        println!("  - mockchain_config.sample.json");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_serialization_toml() {
        let config = PoCXConfig::default();

        // Test TOML serialization
        let toml_result = toml::to_string(&config);
        assert!(toml_result.is_ok());

        let toml_content = toml_result.unwrap();
        assert!(toml_content.contains("name = \"PoCX Mockchain\""));
        assert!(toml_content.contains("Bech32"));
        assert!(toml_content.contains("tpocx"));

        // Test TOML deserialization
        let deserialized: Result<PoCXConfig, _> = toml::from_str(&toml_content);
        assert!(deserialized.is_ok());

        let deserialized_config = deserialized.unwrap();
        assert_eq!(deserialized_config.network.name, config.network.name);
        assert_eq!(
            deserialized_config.network.network_id,
            config.network.network_id
        );
    }

    #[test]
    fn test_config_serialization_json() {
        let config = PoCXConfig::default();

        // Test JSON serialization
        let json_result = serde_json::to_string_pretty(&config);
        assert!(json_result.is_ok());

        let json_content = json_result.unwrap();
        assert!(json_content.contains("\"name\": \"PoCX Mockchain\""));
        assert!(json_content.contains("\"Bech32\""));
        assert!(json_content.contains("\"tpocx\""));

        // Test JSON deserialization
        let deserialized: Result<PoCXConfig, _> = serde_json::from_str(&json_content);
        assert!(deserialized.is_ok());

        let deserialized_config = deserialized.unwrap();
        assert_eq!(deserialized_config.network.name, config.network.name);
        assert_eq!(deserialized_config.server.port, config.server.port);
    }
}
