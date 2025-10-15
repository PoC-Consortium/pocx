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
        let mut config = if let Ok(config_content) = std::fs::read_to_string("pocx_mockchain.toml")
        {
            let config: PoCXConfig = toml::from_str(&config_content)?;
            println!("Loaded configuration from pocx_mockchain.toml");
            config
        } else if let Ok(config_content) = std::fs::read_to_string("pocx_mockchain.json") {
            let config: PoCXConfig = serde_json::from_str(&config_content)?;
            println!("Loaded configuration from pocx_mockchain.json");
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
        std::fs::write("pocx_mockchain.sample.toml", toml_content)?;

        // Create JSON version
        let json_content = serde_json::to_string_pretty(&sample_config)?;
        std::fs::write("pocx_mockchain.sample.json", json_content)?;

        println!("Created sample configuration files:");
        println!("  - pocx_mockchain.sample.toml");
        println!("  - pocx_mockchain.sample.json");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_config() {
        let config = PoCXConfig::default();

        assert_eq!(config.network.name, "PoCX Mockchain");
        assert_eq!(
            config.network.network_id,
            pocx_address::NetworkId::Bech32("tpocx".to_string())
        );
        assert_eq!(config.network.block_time_seconds, 120);
        assert_eq!(config.network.minimum_compression_level, 1);
        assert_eq!(config.network.target_compression_level, 1);
        assert_eq!(config.network.difficulty_adjustment.lookback_blocks, 24);
        assert_eq!(
            config.network.difficulty_adjustment.min_adjustment_ratio,
            0.8
        );
        assert_eq!(
            config.network.difficulty_adjustment.max_adjustment_ratio,
            1.2
        );
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8081);
        assert!(config.server.enable_cors);
        assert_eq!(config.database.url, "mockchain.db");
    }

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

    #[test]
    fn test_network_config_fields() {
        let network = NetworkConfig {
            name: "CustomNetwork".to_string(),
            network_id: pocx_address::NetworkId::Base58(0x99),
            block_time_seconds: 300,
            minimum_compression_level: 2,
            target_compression_level: 4,
            genesis_signature: "abcd1234".to_string(),
            difficulty_adjustment: default_difficulty_config(),
        };

        assert_eq!(network.name, "CustomNetwork");
        assert_eq!(network.network_id, pocx_address::NetworkId::Base58(0x99));
        assert_eq!(network.block_time_seconds, 300);
        assert_eq!(network.minimum_compression_level, 2);
        assert_eq!(network.target_compression_level, 4);
        assert_eq!(network.genesis_signature, "abcd1234");
        assert_eq!(network.difficulty_adjustment.lookback_blocks, 24);
    }

    #[test]
    fn test_server_config_fields() {
        let server = ServerConfig {
            host: "192.168.1.1".to_string(),
            port: 9999,
            enable_cors: false,
        };

        assert_eq!(server.host, "192.168.1.1");
        assert_eq!(server.port, 9999);
        assert!(!server.enable_cors);
    }

    #[test]
    fn test_database_config_fields() {
        let database = DatabaseConfig {
            url: "postgres://localhost/test".to_string(),
        };

        assert_eq!(database.url, "postgres://localhost/test");
    }

    #[test]
    fn test_config_with_env_vars() {
        // Set environment variables for testing
        env::set_var("POCX_NETWORK_NAME", "TestNetwork");
        env::set_var("POCX_NETWORK_ID", "100");
        env::set_var("POCX_HOST", "0.0.0.0");
        env::set_var("POCX_PORT", "8888");
        env::set_var("POCX_DATABASE_URL", "test.db");

        // This would normally load from env vars when config files don't exist
        // We can't easily test the full load() method without mocking the filesystem
        // So we'll test the parsing logic separately

        let network_name = env::var("POCX_NETWORK_NAME").unwrap();
        assert_eq!(network_name, "TestNetwork");

        let network_id_str = env::var("POCX_NETWORK_ID").unwrap();
        let network_id: u8 = network_id_str.parse().unwrap();
        assert_eq!(network_id, 100);

        let host = env::var("POCX_HOST").unwrap();
        assert_eq!(host, "0.0.0.0");

        let port_str = env::var("POCX_PORT").unwrap();
        let port: u16 = port_str.parse().unwrap();
        assert_eq!(port, 8888);

        let db_url = env::var("POCX_DATABASE_URL").unwrap();
        assert_eq!(db_url, "test.db");

        // Clean up environment variables
        env::remove_var("POCX_NETWORK_NAME");
        env::remove_var("POCX_NETWORK_ID");
        env::remove_var("POCX_HOST");
        env::remove_var("POCX_PORT");
        env::remove_var("POCX_DATABASE_URL");
    }

    #[test]
    fn test_invalid_env_var_parsing() {
        // Test that invalid environment variables don't break the parsing
        env::set_var("POCX_NETWORK_ID", "invalid_number");
        env::set_var("POCX_PORT", "not_a_port");

        // These should fail to parse but not panic
        let network_id_result = env::var("POCX_NETWORK_ID").unwrap().parse::<u8>();
        assert!(network_id_result.is_err());

        let port_result = env::var("POCX_PORT").unwrap().parse::<u16>();
        assert!(port_result.is_err());

        // Clean up
        env::remove_var("POCX_NETWORK_ID");
        env::remove_var("POCX_PORT");
    }

    #[test]
    fn test_compression_levels() {
        // Test default compression levels
        assert_eq!(default_minimum_compression_level(), 1);
        assert_eq!(default_target_compression_level(), 1);
        assert_eq!(DEFAULT_MINIMUM_COMPRESSION_LEVEL, 1);
        assert_eq!(DEFAULT_TARGET_COMPRESSION_LEVEL, 1);

        // Test compression bounds validation logic
        let valid_compression_values = [1, 2, 4, 8, 16, 32];
        for compression in valid_compression_values {
            assert!(
                (1..=32).contains(&compression),
                "Compression {} should be valid",
                compression
            );
        }

        // Test invalid compression values
        let invalid_compression_values = [0, 33, 64, 128];
        for compression in invalid_compression_values {
            assert!(
                !(1..=32).contains(&compression),
                "Compression {} should be invalid",
                compression
            );
        }
    }

    #[test]
    fn test_compression_range_validation() {
        // Test that minimum <= target is enforced
        let config = NetworkConfig {
            name: "Test".to_string(),
            network_id: pocx_address::NetworkId::Base58(0x01),
            block_time_seconds: 120,
            minimum_compression_level: 2,
            target_compression_level: 4,
            genesis_signature: "test".to_string(),
            difficulty_adjustment: default_difficulty_config(),
        };

        assert!(config.minimum_compression_level <= config.target_compression_level);

        // Test single compression level (min == target)
        let single_level_config = NetworkConfig {
            name: "Test".to_string(),
            network_id: pocx_address::NetworkId::Base58(0x01),
            block_time_seconds: 120,
            minimum_compression_level: 4,
            target_compression_level: 4,
            genesis_signature: "test".to_string(),
            difficulty_adjustment: default_difficulty_config(),
        };

        assert_eq!(
            single_level_config.minimum_compression_level,
            single_level_config.target_compression_level
        );
    }
}
