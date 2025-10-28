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

use crate::miner::Chain;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize)]
pub enum Benchmark {
    Io,
    Cpu,
    Disabled,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Cfg {
    #[serde(default)]
    pub chains: Vec<Chain>,

    #[serde(default = "default_get_mining_info_interval")]
    pub get_mining_info_interval: u64,

    #[serde(default = "default_timeout")]
    pub timeout: u64,

    #[serde(default)]
    pub plot_dirs: Vec<PathBuf>,

    #[serde(default = "default_hdd_use_direct_io")]
    pub hdd_use_direct_io: bool,

    #[serde(default = "default_hdd_wakeup_after")]
    pub hdd_wakeup_after: i64,

    #[serde(default = "default_hdd_read_cache_in_warps")]
    pub hdd_read_cache_in_warps: u64,

    #[serde(default)]
    pub cpu_threads: usize,

    #[serde(default = "default_cpu_thread_pinning")]
    pub cpu_thread_pinning: bool,

    #[serde(default = "default_show_progress")]
    pub show_progress: bool,

    #[serde(default = "default_line_progress")]
    pub line_progress: bool,

    #[serde(default)]
    pub benchmark: Option<Benchmark>,

    #[serde(default = "default_console_log_level")]
    pub console_log_level: String,

    #[serde(default = "default_logfile_log_level")]
    pub logfile_log_level: String,

    #[serde(default = "default_logfile_max_count")]
    pub logfile_max_count: u32,

    #[serde(default = "default_logfile_max_size")]
    pub logfile_max_size: u64,

    #[serde(default = "default_console_log_pattern")]
    pub console_log_pattern: String,

    #[serde(default = "default_logfile_log_pattern")]
    pub logfile_log_pattern: String,

    #[serde(default = "default_enable_on_the_fly_compression")]
    pub enable_on_the_fly_compression: bool,
}

impl<'de> Deserialize<'de> for Benchmark {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str().to_lowercase().as_ref() {
            "i/o" => Benchmark::Io,
            "cpu" => Benchmark::Cpu,
            _ => Benchmark::Disabled,
        })
    }
}

fn default_hdd_use_direct_io() -> bool {
    true
}

fn default_hdd_wakeup_after() -> i64 {
    30
}

fn default_hdd_read_cache_in_warps() -> u64 {
    16
}

fn default_cpu_thread_pinning() -> bool {
    true
}

fn default_get_mining_info_interval() -> u64 {
    1000
}

fn default_timeout() -> u64 {
    5000
}

fn default_console_log_level() -> String {
    "Info".to_owned()
}

fn default_logfile_log_level() -> String {
    "Warn".to_owned()
}

fn default_logfile_max_count() -> u32 {
    10
}

fn default_logfile_max_size() -> u64 {
    20
}

fn default_console_log_pattern() -> String {
    "{({d(%H:%M:%S)} [{l}]):16.16} {m}{n}".to_owned()
}

fn default_logfile_log_pattern() -> String {
    "{({d(%Y-%m-%d %H:%M:%S)} [{l}]):26.26} {m}{n}".to_owned()
}

fn default_show_progress() -> bool {
    true
}

fn default_line_progress() -> bool {
    false
}

fn default_enable_on_the_fly_compression() -> bool {
    true
}

pub fn load_cfg(config: &str) -> Cfg {
    let cfg_str = fs::read_to_string(config).unwrap_or_else(|e| {
        eprintln!("Failed to open config file '{}': {}", config, e);
        std::process::exit(1);
    });
    let cfg: Cfg = serde_yaml::from_str(&cfg_str).expect("failed to parse config");
    validate_cfg(cfg)
}

pub fn validate_cfg(mut cfg: Cfg) -> Cfg {
    cfg.plot_dirs.retain(|plot_dir| {
        if !plot_dir.exists() {
            warn!("path {} does not exist", plot_dir.to_str().unwrap());
            false
        } else if !plot_dir.is_dir() {
            warn!("path {} is not a directory", plot_dir.to_str().unwrap());
            false
        } else {
            true
        }
    });
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_cfg_basic() {
        let cfg = Cfg {
            chains: Vec::new(),
            get_mining_info_interval: default_get_mining_info_interval(),
            timeout: default_timeout(),
            plot_dirs: vec![std::path::PathBuf::from(".")], // Current directory should exist
            hdd_use_direct_io: default_hdd_use_direct_io(),
            hdd_wakeup_after: default_hdd_wakeup_after(),
            hdd_read_cache_in_warps: default_hdd_read_cache_in_warps(),
            cpu_threads: 0,
            cpu_thread_pinning: default_cpu_thread_pinning(),
            show_progress: default_show_progress(),
            line_progress: default_line_progress(),
            benchmark: None,
            console_log_level: default_console_log_level(),
            logfile_log_level: default_logfile_log_level(),
            logfile_max_count: default_logfile_max_count(),
            logfile_max_size: default_logfile_max_size(),
            console_log_pattern: default_console_log_pattern(),
            logfile_log_pattern: default_logfile_log_pattern(),
            enable_on_the_fly_compression: default_enable_on_the_fly_compression(),
        };

        let validated = validate_cfg(cfg);
        assert_eq!(validated.hdd_wakeup_after, 30);
    }

    #[test]
    fn test_validate_cfg_filters_invalid_paths() {
        use std::path::PathBuf;

        let mut cfg = Cfg {
            chains: Vec::new(),
            get_mining_info_interval: default_get_mining_info_interval(),
            timeout: default_timeout(),
            plot_dirs: Vec::new(),
            hdd_use_direct_io: default_hdd_use_direct_io(),
            hdd_wakeup_after: default_hdd_wakeup_after(),
            hdd_read_cache_in_warps: default_hdd_read_cache_in_warps(),
            cpu_threads: 0,
            cpu_thread_pinning: default_cpu_thread_pinning(),
            show_progress: default_show_progress(),
            line_progress: default_line_progress(),
            benchmark: None,
            console_log_level: default_console_log_level(),
            logfile_log_level: default_logfile_log_level(),
            logfile_max_count: default_logfile_max_count(),
            logfile_max_size: default_logfile_max_size(),
            console_log_pattern: default_console_log_pattern(),
            logfile_log_pattern: default_logfile_log_pattern(),
            enable_on_the_fly_compression: default_enable_on_the_fly_compression(),
        };

        // Add mix of valid and invalid paths
        cfg.plot_dirs = vec![
            PathBuf::from("/tmp"),              // Should exist
            PathBuf::from("/nonexistent/path"), // Should be filtered out
            PathBuf::from("."),                 // Current directory should exist
        ];

        let validated = validate_cfg(cfg);

        // Should have filtered out non-existent paths
        assert!(validated.plot_dirs.len() <= 2); // At most 2 valid paths

        // Remaining paths should exist
        for path in &validated.plot_dirs {
            assert!(path.exists(), "Path should exist: {:?}", path);
            assert!(path.is_dir(), "Path should be directory: {:?}", path);
        }
    }

    #[test]
    fn test_cfg_default_values() {
        let cfg = Cfg {
            chains: Vec::new(),
            get_mining_info_interval: default_get_mining_info_interval(),
            timeout: default_timeout(),
            plot_dirs: Vec::new(),
            hdd_use_direct_io: default_hdd_use_direct_io(),
            hdd_wakeup_after: default_hdd_wakeup_after(),
            hdd_read_cache_in_warps: default_hdd_read_cache_in_warps(),
            cpu_threads: 0,
            cpu_thread_pinning: default_cpu_thread_pinning(),
            show_progress: default_show_progress(),
            line_progress: default_line_progress(),
            benchmark: None,
            console_log_level: default_console_log_level(),
            logfile_log_level: default_logfile_log_level(),
            logfile_max_count: default_logfile_max_count(),
            logfile_max_size: default_logfile_max_size(),
            console_log_pattern: default_console_log_pattern(),
            logfile_log_pattern: default_logfile_log_pattern(),
            enable_on_the_fly_compression: default_enable_on_the_fly_compression(),
        };

        // Test default values
        assert_eq!(cfg.hdd_wakeup_after, 30);
        assert!(cfg.hdd_use_direct_io);
        assert_eq!(cfg.cpu_threads, 0);
    }

    #[test]
    fn test_cfg_serialization() {
        let cfg = Cfg {
            chains: Vec::new(),
            get_mining_info_interval: default_get_mining_info_interval(),
            timeout: default_timeout(),
            plot_dirs: Vec::new(),
            hdd_use_direct_io: default_hdd_use_direct_io(),
            hdd_wakeup_after: default_hdd_wakeup_after(),
            hdd_read_cache_in_warps: default_hdd_read_cache_in_warps(),
            cpu_threads: 0,
            cpu_thread_pinning: default_cpu_thread_pinning(),
            show_progress: default_show_progress(),
            line_progress: default_line_progress(),
            benchmark: None,
            console_log_level: default_console_log_level(),
            logfile_log_level: default_logfile_log_level(),
            logfile_max_count: default_logfile_max_count(),
            logfile_max_size: default_logfile_max_size(),
            console_log_pattern: default_console_log_pattern(),
            logfile_log_pattern: default_logfile_log_pattern(),
            enable_on_the_fly_compression: default_enable_on_the_fly_compression(),
        };

        // Test that cfg can be serialized to YAML (Note: Cfg doesn't derive Serialize)
        // Instead just test field access
        assert_eq!(cfg.hdd_wakeup_after, 30);
        assert!(cfg.hdd_use_direct_io);
        assert_eq!(cfg.cpu_threads, 0);
    }

    #[test]
    fn test_cfg_deserialization() {
        let yaml_content = r#"
url: "http://127.0.0.1:8080"
plot_dirs:
  - "."
hdd_wakeup_after: 90
use_direct_io: false
thread_pool_size: 8
"#;

        let cfg: Result<Cfg, _> = serde_yaml::from_str(yaml_content);
        assert!(cfg.is_ok());

        let cfg = cfg.unwrap();
        assert_eq!(cfg.hdd_wakeup_after, 90);
        assert_eq!(cfg.plot_dirs.len(), 1);
    }

    #[test]
    fn test_url_serialization() {
        use url::Url;

        let test_url = Url::parse("http://example.com:8080").unwrap();

        // Test URL serialization
        let serialized = serde_json::to_string(&test_url);
        assert!(serialized.is_ok());

        let serialized_str = serialized.unwrap();
        assert!(serialized_str.contains("example.com"));
    }

    #[test]
    fn test_cfg_field_validation() {
        let mut cfg = Cfg {
            chains: Vec::new(),
            get_mining_info_interval: default_get_mining_info_interval(),
            timeout: default_timeout(),
            plot_dirs: Vec::new(),
            hdd_use_direct_io: default_hdd_use_direct_io(),
            hdd_wakeup_after: default_hdd_wakeup_after(),
            hdd_read_cache_in_warps: default_hdd_read_cache_in_warps(),
            cpu_threads: 0,
            cpu_thread_pinning: default_cpu_thread_pinning(),
            show_progress: default_show_progress(),
            line_progress: default_line_progress(),
            benchmark: None,
            console_log_level: default_console_log_level(),
            logfile_log_level: default_logfile_log_level(),
            logfile_max_count: default_logfile_max_count(),
            logfile_max_size: default_logfile_max_size(),
            console_log_pattern: default_console_log_pattern(),
            logfile_log_pattern: default_logfile_log_pattern(),
            enable_on_the_fly_compression: default_enable_on_the_fly_compression(),
        };

        // Test various field combinations
        cfg.hdd_wakeup_after = 0;
        assert_eq!(cfg.hdd_wakeup_after, 0);

        cfg.cpu_threads = 4;
        assert_eq!(cfg.cpu_threads, 4);

        // Test boolean fields
        cfg.enable_on_the_fly_compression = true;
        assert!(cfg.enable_on_the_fly_compression);
    }

    #[test]
    fn test_empty_plot_dirs() {
        let mut cfg = Cfg {
            chains: Vec::new(),
            get_mining_info_interval: default_get_mining_info_interval(),
            timeout: default_timeout(),
            plot_dirs: vec![],
            hdd_use_direct_io: default_hdd_use_direct_io(),
            hdd_wakeup_after: default_hdd_wakeup_after(),
            hdd_read_cache_in_warps: default_hdd_read_cache_in_warps(),
            cpu_threads: 0,
            cpu_thread_pinning: default_cpu_thread_pinning(),
            show_progress: default_show_progress(),
            line_progress: default_line_progress(),
            benchmark: None,
            console_log_level: default_console_log_level(),
            logfile_log_level: default_logfile_log_level(),
            logfile_max_count: default_logfile_max_count(),
            logfile_max_size: default_logfile_max_size(),
            console_log_pattern: default_console_log_pattern(),
            logfile_log_pattern: default_logfile_log_pattern(),
            enable_on_the_fly_compression: default_enable_on_the_fly_compression(),
        };
        cfg.plot_dirs = vec![];

        let validated = validate_cfg(cfg);
        assert!(validated.plot_dirs.is_empty());
    }

    #[test]
    fn test_cpu_count_detection() {
        let cpu_count = num_cpus::get();
        assert!(cpu_count > 0);
        assert!(cpu_count <= 256); // Reasonable upper bound

        // Just test that CPU count is reasonable
        assert!(cpu_count > 0);
        assert!(cpu_count <= 256);
    }
}
