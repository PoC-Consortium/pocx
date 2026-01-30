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

//! Callback system for miner integration
//!
//! This module provides a callback trait that allows external applications
//! (like Phoenix wallet) to receive miner events without coupling to the
//! miner's internal implementation.

// These are library exports used by external crates (e.g., Tauri backend)
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};

// ============================================================================
// Data Structures for Callbacks
// ============================================================================

/// Block info (from "new block : \[chain:height\], ...")
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockInfo {
    pub chain: String,
    pub height: u64,
    pub base_target: u64,
    pub gen_sig: String,
    pub network_capacity: String,
    pub compression_range: String,
    pub scoop: u64,
}

/// Queue item (from "queue : \[chain:height\]:XX%>")
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueItem {
    pub position: u32,
    pub chain: String,
    pub height: u64,
    pub progress_percent: f64,
}

/// Accepted deadline info - simplified for accepted callbacks
/// Contains only data available at submission acceptance time
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptedDeadline {
    pub chain: String,
    pub account: String, // Hex payload
    pub height: u64,
    pub nonce: u64,
    pub quality_raw: u64, // For effective capacity calculation
    pub compression: u8,
    pub poc_time: u64, // Deadline in seconds (from server response)
}

/// Scan status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum ScanStatus {
    Scanning,
    Resuming,
    Finished { duration_secs: f64 },
    Paused { progress_percent: f64 },
    Interrupted { progress_percent: f64 },
}

/// Capacity loaded event data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapacityInfo {
    pub drives: u32,
    pub total_warps: u64,
    pub capacity_tib: f64,
}

/// Scan started event data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStartedInfo {
    pub chain: String,
    pub height: u64,
    pub total_warps: u64,
    pub resuming: bool,
}

/// Miner configuration info for on_started
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MinerStartedInfo {
    pub chains: Vec<String>,
    pub version: String,
}

// ============================================================================
// Callback Trait
// ============================================================================

/// Callback trait for miner integration
///
/// Implement this trait to receive miner events. All methods have default
/// no-op implementations, so you only need to override the ones you care about.
pub trait MinerCallback: Send + Sync {
    // === Startup ===

    /// Called when miner starts
    fn on_started(&self, _info: &MinerStartedInfo) {}

    /// Called when all plots loaded
    fn on_capacity_loaded(&self, _info: &CapacityInfo) {}

    // === Block Processing ===

    /// Called when new block arrives on a chain
    fn on_new_block(&self, _block: &BlockInfo) {}

    // === Queue Status ===

    /// Called when queue status changes
    fn on_queue_updated(&self, _queue: &[QueueItem]) {}

    /// Called when miner is idle (queue empty)
    fn on_idle(&self) {}

    // === Scanning ===

    /// Called when scan starts/resumes
    fn on_scan_started(&self, _info: &ScanStartedInfo) {}

    /// Called with scan progress delta
    fn on_scan_progress(&self, _warps_delta: u64) {}

    /// Called when scan status changes
    fn on_scan_status(&self, _chain: &str, _height: u64, _status: &ScanStatus) {}

    // === Deadlines ===

    /// Called when deadline is accepted by pool/node
    fn on_deadline_accepted(&self, _deadline: &AcceptedDeadline) {}

    /// Called when deadline submission fails but will retry
    fn on_deadline_retry(&self, _deadline: &AcceptedDeadline, _reason: &str) {}

    /// Called when deadline is rejected
    fn on_deadline_rejected(&self, _deadline: &AcceptedDeadline, _code: i32, _message: &str) {}

    // === HDD ===

    /// Called when HDD wakeup occurs
    fn on_hdd_wakeup(&self) {}

    // === Lifecycle ===

    /// Called when miner stops
    fn on_stopped(&self) {}
}

// ============================================================================
// Global Callback Registration
// ============================================================================

static MINER_CALLBACK: OnceLock<Arc<dyn MinerCallback>> = OnceLock::new();

/// Set the global miner callback
///
/// This should be called once at startup before the miner is created.
/// Returns Err if a callback was already set.
pub fn set_miner_callback(callback: Arc<dyn MinerCallback>) -> Result<(), Arc<dyn MinerCallback>> {
    MINER_CALLBACK.set(callback)
}

/// Get the global miner callback, if set
pub fn get_miner_callback() -> Option<Arc<dyn MinerCallback>> {
    MINER_CALLBACK.get().cloned()
}

/// Helper to invoke callback if set
#[inline]
pub fn with_callback<F>(f: F)
where
    F: FnOnce(&dyn MinerCallback),
{
    if let Some(cb) = MINER_CALLBACK.get() {
        f(cb.as_ref());
    }
}

// ============================================================================
// Default No-Op Implementation
// ============================================================================

/// Default no-op callback for standalone CLI usage
pub struct NoOpCallback;

impl MinerCallback for NoOpCallback {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TestCallback {
        started_count: AtomicU32,
    }

    impl MinerCallback for TestCallback {
        fn on_started(&self, _info: &MinerStartedInfo) {
            self.started_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_callback_invocation() {
        let cb = TestCallback {
            started_count: AtomicU32::new(0),
        };

        let info = MinerStartedInfo {
            chains: vec!["test".to_string()],
            version: "1.0.0".to_string(),
        };

        cb.on_started(&info);
        assert_eq!(cb.started_count.load(Ordering::SeqCst), 1);
    }
}
