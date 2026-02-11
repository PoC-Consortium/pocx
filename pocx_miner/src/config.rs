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

// CfgBuilder is a library export used by external crates (e.g., Tauri backend)
#![allow(dead_code)]

pub use crate::miner::Chain;
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

// ============================================================================
// CfgBuilder for Programmatic Configuration
// ============================================================================

/// Builder for creating miner configuration programmatically
///
/// This is used by GUI applications (like Phoenix wallet) to configure
/// the miner without needing a YAML config file.
#[derive(Debug, Clone)]
pub struct CfgBuilder {
    chains: Vec<Chain>,
    plot_dirs: Vec<PathBuf>,
    hdd_use_direct_io: bool,
    hdd_wakeup_after: i64,
    hdd_read_cache_in_warps: u64,
    cpu_threads: usize,
    cpu_thread_pinning: bool,
    get_mining_info_interval: u64,
    timeout: u64,
    enable_on_the_fly_compression: bool,
    line_progress: bool,
}

impl Default for CfgBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CfgBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            chains: Vec::new(),
            plot_dirs: Vec::new(),
            hdd_use_direct_io: default_hdd_use_direct_io(),
            hdd_wakeup_after: default_hdd_wakeup_after(),
            hdd_read_cache_in_warps: default_hdd_read_cache_in_warps(),
            cpu_threads: 0, // 0 = auto-detect
            cpu_thread_pinning: default_cpu_thread_pinning(),
            get_mining_info_interval: default_get_mining_info_interval(),
            timeout: default_timeout(),
            enable_on_the_fly_compression: default_enable_on_the_fly_compression(),
            line_progress: true, // GUI mode uses line progress
        }
    }

    /// Add a chain configuration
    pub fn add_chain(mut self, chain: Chain) -> Self {
        self.chains.push(chain);
        self
    }

    /// Add multiple chains
    pub fn chains(mut self, chains: Vec<Chain>) -> Self {
        self.chains = chains;
        self
    }

    /// Add a plot directory
    pub fn add_plot_dir<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.plot_dirs.push(path.into());
        self
    }

    /// Add multiple plot directories
    pub fn plot_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.plot_dirs = dirs;
        self
    }

    /// Set number of CPU threads (0 = auto-detect)
    pub fn cpu_threads(mut self, threads: usize) -> Self {
        self.cpu_threads = threads;
        self
    }

    /// Enable/disable direct I/O for HDDs
    pub fn direct_io(mut self, enabled: bool) -> Self {
        self.hdd_use_direct_io = enabled;
        self
    }

    /// Set HDD wakeup interval in seconds (0 = disabled)
    pub fn hdd_wakeup_after(mut self, seconds: i64) -> Self {
        self.hdd_wakeup_after = seconds;
        self
    }

    /// Set read cache size in warps (must be power of 2)
    pub fn read_cache_warps(mut self, warps: u64) -> Self {
        self.hdd_read_cache_in_warps = warps;
        self
    }

    /// Enable/disable CPU thread pinning
    pub fn thread_pinning(mut self, enabled: bool) -> Self {
        self.cpu_thread_pinning = enabled;
        self
    }

    /// Set mining info poll interval in milliseconds
    pub fn mining_info_interval(mut self, ms: u64) -> Self {
        self.get_mining_info_interval = ms;
        self
    }

    /// Set request timeout in milliseconds
    pub fn timeout(mut self, ms: u64) -> Self {
        self.timeout = ms;
        self
    }

    /// Enable/disable on-the-fly compression
    pub fn on_the_fly_compression(mut self, enabled: bool) -> Self {
        self.enable_on_the_fly_compression = enabled;
        self
    }

    /// Enable/disable line progress protocol (for GUI)
    pub fn line_progress(mut self, enabled: bool) -> Self {
        self.line_progress = enabled;
        self
    }

    /// Build the configuration
    ///
    /// Note: This does NOT validate plot directories. Call `validate_cfg()`
    /// on the result if you want to filter out non-existent directories.
    pub fn build(self) -> Cfg {
        Cfg {
            chains: self.chains,
            get_mining_info_interval: self.get_mining_info_interval,
            timeout: self.timeout,
            plot_dirs: self.plot_dirs,
            hdd_use_direct_io: self.hdd_use_direct_io,
            hdd_wakeup_after: self.hdd_wakeup_after,
            hdd_read_cache_in_warps: self.hdd_read_cache_in_warps,
            cpu_threads: self.cpu_threads,
            cpu_thread_pinning: self.cpu_thread_pinning,
            show_progress: false, // GUI mode doesn't use progress bar
            line_progress: self.line_progress,
            benchmark: None,
            console_log_level: default_console_log_level(),
            logfile_log_level: default_logfile_log_level(),
            logfile_max_count: default_logfile_max_count(),
            logfile_max_size: default_logfile_max_size(),
            console_log_pattern: default_console_log_pattern(),
            logfile_log_pattern: default_logfile_log_pattern(),
            enable_on_the_fly_compression: self.enable_on_the_fly_compression,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
