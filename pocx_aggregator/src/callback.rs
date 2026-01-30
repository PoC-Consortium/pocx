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

//! Callback system for aggregator integration
//!
//! Provides an event-driven callback trait for external applications
//! (like Phoenix wallet) to receive aggregator events.

use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};

// ============================================================================
// Data Structures
// ============================================================================

/// Aggregator started event data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregatorStartedInfo {
    pub listen_address: String,
    pub upstream_name: String,
}

/// New block event data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockUpdate {
    pub height: u64,
    pub base_target: u64,
}

/// Submission received event data (full solution details)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmissionInfo {
    pub height: u64,
    pub account_id: String,
    pub machine_id: Option<String>,
    pub generation_signature: String,
    pub seed: String,
    pub nonce: u64,
    pub compression: u8,
    pub quality: u64,
}

/// Submission accepted event data (with calculated poc_time)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptedInfo {
    pub height: u64,
    pub account_id: String,
    pub machine_id: Option<String>,
    pub generation_signature: String,
    pub seed: String,
    pub nonce: u64,
    pub compression: u8,
    pub quality: u64,
    pub poc_time: u64,
}

/// Submission rejected event data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RejectedInfo {
    pub height: u64,
    pub account_id: String,
    pub machine_id: Option<String>,
    pub reason: String,
}

/// Submission forwarded event data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardedInfo {
    pub account_id: String,
    pub quality: u64,
    pub pool_name: String,
}

// ============================================================================
// Callback Trait
// ============================================================================

/// Callback trait for aggregator integration
///
/// All methods have default no-op implementations. Override only the
/// events you need.
pub trait AggregatorCallback: Send + Sync {
    /// Called when the aggregator server starts listening
    fn on_started(&self, _info: &AggregatorStartedInfo) {}

    /// Called when a new block is received from upstream
    fn on_new_block(&self, _block: &BlockUpdate) {}

    /// Called when a miner submits a nonce
    fn on_submission_received(&self, _info: &SubmissionInfo) {}

    /// Called when the best nonce is forwarded to upstream
    fn on_submission_forwarded(&self, _info: &ForwardedInfo) {}

    /// Called when upstream accepts a submission
    fn on_submission_accepted(&self, _info: &AcceptedInfo) {}

    /// Called when upstream rejects a submission
    fn on_submission_rejected(&self, _info: &RejectedInfo) {}

    /// Called when a new miner connects or sends a heartbeat
    fn on_miner_connected(&self, _account_id: &str, _machine_id: &str) {}

    /// Called with periodic stats refresh
    fn on_stats_updated(&self, _snapshot: &crate::stats::StatsSnapshot) {}

    /// Called on errors
    fn on_error(&self, _error: &str) {}

    /// Called when the aggregator shuts down
    fn on_stopped(&self) {}
}

// ============================================================================
// Global Callback Registration
// ============================================================================

static AGGREGATOR_CALLBACK: OnceLock<Arc<dyn AggregatorCallback>> = OnceLock::new();

/// Set the global aggregator callback (call once at startup before running)
pub fn set_aggregator_callback(
    callback: Arc<dyn AggregatorCallback>,
) -> Result<(), Arc<dyn AggregatorCallback>> {
    AGGREGATOR_CALLBACK.set(callback)
}

/// Get the global aggregator callback, if set
pub fn get_aggregator_callback() -> Option<Arc<dyn AggregatorCallback>> {
    AGGREGATOR_CALLBACK.get().cloned()
}

/// Invoke callback if set
#[inline]
pub fn with_callback<F>(f: F)
where
    F: FnOnce(&dyn AggregatorCallback),
{
    if let Some(cb) = AGGREGATOR_CALLBACK.get() {
        f(cb.as_ref());
    }
}

/// Default no-op callback
pub struct NoOpCallback;

impl AggregatorCallback for NoOpCallback {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TestCallback {
        started_count: AtomicU32,
        block_count: AtomicU32,
    }

    impl AggregatorCallback for TestCallback {
        fn on_started(&self, _info: &AggregatorStartedInfo) {
            self.started_count.fetch_add(1, Ordering::SeqCst);
        }

        fn on_new_block(&self, _block: &BlockUpdate) {
            self.block_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_callback_invocation() {
        let cb = TestCallback {
            started_count: AtomicU32::new(0),
            block_count: AtomicU32::new(0),
        };

        let info = AggregatorStartedInfo {
            listen_address: "0.0.0.0:8080".to_string(),
            upstream_name: "test-pool".to_string(),
        };

        cb.on_started(&info);
        assert_eq!(cb.started_count.load(Ordering::SeqCst), 1);

        let block = BlockUpdate {
            height: 100,
            base_target: 5000,
        };
        cb.on_new_block(&block);
        assert_eq!(cb.block_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_noop_callback() {
        let cb = NoOpCallback;
        cb.on_started(&AggregatorStartedInfo {
            listen_address: String::new(),
            upstream_name: String::new(),
        });
        cb.on_stopped();
        // No panic = pass
    }

    #[test]
    fn test_data_serialization() {
        let info = SubmissionInfo {
            height: 12345,
            account_id: "POCX-AB12".to_string(),
            machine_id: Some("192.168.1.50".to_string()),
            generation_signature: "abc123def456".to_string(),
            seed: "seed789".to_string(),
            nonce: 987654,
            compression: 5,
            quality: 42,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: SubmissionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.quality, 42);
        assert_eq!(deserialized.account_id, "POCX-AB12");
        assert_eq!(deserialized.height, 12345);
        assert_eq!(deserialized.nonce, 987654);
    }
}
