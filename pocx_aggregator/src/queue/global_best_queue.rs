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

use futures::channel::mpsc;
use futures::StreamExt;
use pocx_protocol::{JsonRpcClient, ProtocolError, SubmitNonceParams, SubmitNonceResult};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Queued submission for global best tracking (wallet mode)
#[derive(Debug, Clone)]
struct GlobalQueuedSubmission {
    params: SubmitNonceParams,
}

/// Global best submission queue for wallet/solo mining mode
/// Tracks best quality for the last 3 block hashes
#[derive(Clone)]
pub struct GlobalBestQueue {
    block_hashes: Arc<RwLock<VecDeque<String>>>, // Max 3 blocks (FIFO)
    best_qualities: Arc<RwLock<HashMap<String, u64>>>, // block_hash -> best_quality
    tx_submit: mpsc::UnboundedSender<GlobalQueuedSubmission>,
}

impl GlobalBestQueue {
    /// Create a new global best queue
    pub fn new(client: JsonRpcClient) -> Self {
        let (tx_submit, rx_submit) = mpsc::unbounded();

        let block_hashes = Arc::new(RwLock::new(VecDeque::new()));
        let best_qualities = Arc::new(RwLock::new(HashMap::new()));

        // Start the simple handler (no retry, just send)
        Self::start_handler(client, rx_submit);

        Self {
            block_hashes,
            best_qualities,
            tx_submit,
        }
    }

    /// Submit a nonce to the queue (non-blocking)
    /// Returns true if submission was queued, false if filtered out
    pub async fn submit(
        &self,
        params: SubmitNonceParams,
        block_hash: String,
        quality: u64,
    ) -> bool {
        const MAX_BLOCKS: usize = 3;

        let mut hashes = self.block_hashes.write().await;
        let mut qualities = self.best_qualities.write().await;

        // Check if this is a known block hash
        if let Some(&best_quality) = qualities.get(&block_hash) {
            // Known block: check if this submission is better
            if quality >= best_quality {
                log::debug!(
                    "Filtered submission: quality {} not better than best {} for block {}",
                    quality,
                    best_quality,
                    &block_hash[..16]
                );
                return false;
            }

            // Better quality for known block - update and forward
            qualities.insert(block_hash.clone(), quality);
        } else {
            // New block hash
            if hashes.len() >= MAX_BLOCKS {
                // Evict oldest block
                if let Some(oldest_hash) = hashes.pop_front() {
                    qualities.remove(&oldest_hash);
                    log::debug!("Evicted oldest block hash: {}", &oldest_hash[..16]);
                }
            }

            // Add new block
            hashes.push_back(block_hash.clone());
            qualities.insert(block_hash.clone(), quality);
        }

        // Queue submission
        let submission = GlobalQueuedSubmission {
            params: params.clone(),
        };

        self.tx_submit.unbounded_send(submission).is_ok()
    }

    /// Simple handler - no retry, just send to wallet and log results
    fn start_handler(
        client: JsonRpcClient,
        mut rx: mpsc::UnboundedReceiver<GlobalQueuedSubmission>,
    ) {
        tokio::task::spawn(async move {
            while let Some(submission) = rx.next().await {
                match client.submit_nonce(submission.params.clone()).await {
                    Ok(result) => {
                        log_submission_accepted(&submission.params, &result);
                    }
                    Err(ProtocolError::RateLimited) => {
                        log_server_busy(&submission.params);
                    }
                    Err(ProtocolError::InvalidSubmission(msg)) => {
                        log_submission_not_accepted(
                            &submission.params,
                            &format!("Rejected: {}", msg),
                        );
                    }
                    Err(ProtocolError::StaleSubmission) => {
                        log_submission_not_accepted(&submission.params, "Stale submission");
                    }
                    Err(e) => {
                        log_submission_failed(&submission.params, &e.to_string());
                    }
                }
            }
        });
    }
}

fn log_submission_accepted(params: &SubmitNonceParams, result: &SubmitNonceResult) {
    log::info!(
        "Submitted: height={}, account=...{}, quality={}, poc_time={}s",
        params.height,
        &params.account_id[params.account_id.len().saturating_sub(8)..],
        result.quality,
        result.poc_time
    );
}

fn log_submission_failed(params: &SubmitNonceParams, err: &str) {
    log::warn!(
        "Upstream submission failed (global best): height={}, account={}, nonce={}, error={}",
        params.height,
        params.account_id,
        params.nonce,
        err
    );
}

fn log_submission_not_accepted(params: &SubmitNonceParams, msg: &str) {
    log::error!(
        "Upstream rejected submission (global best): height={}, account={}, nonce={}, message={}",
        params.height,
        params.account_id,
        params.nonce,
        msg
    );
}

fn log_server_busy(params: &SubmitNonceParams) {
    log::info!(
        "Upstream server busy (global best): height={}, account={}, nonce={}",
        params.height,
        params.account_id,
        params.nonce
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_queued_submission_creation() {
        let sub = GlobalQueuedSubmission {
            params: SubmitNonceParams::new(
                100,
                "gensig1".to_string(),
                "acc1".to_string(),
                "seed1".to_string(),
                1000,
                5,
            ),
        };

        assert_eq!(sub.params.height, 100);
    }
}
