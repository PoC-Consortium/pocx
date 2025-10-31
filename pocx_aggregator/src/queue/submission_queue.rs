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
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;

/// Queued submission with metadata
#[derive(Debug, Clone)]
pub struct QueuedSubmission {
    pub params: SubmitNonceParams,
    pub block_hash: String,
    pub quality: u64,
}

/// Timestamped submission for queue tracking
#[derive(Debug, Clone)]
struct TimestampedSubmission {
    submission: QueuedSubmission,
    queued_at: Instant,
    retry_count: u32,
}

/// Per-account filter for tracking best qualities across last 3 blocks
#[derive(Debug)]
struct AccountFilter {
    block_hashes: VecDeque<String>,
    best_qualities: HashMap<String, u64>,
}

/// Submission queue with per-account 3-block tracking and retry logic
#[derive(Clone)]
pub struct SubmissionQueue {
    // Per-account filters (3-block tracking)
    account_filters: Arc<RwLock<HashMap<String, AccountFilter>>>,

    // Submission channel
    tx_submit: mpsc::UnboundedSender<QueuedSubmission>,
}

impl SubmissionQueue {
    /// Create a new submission queue with per-account 3-block filter
    pub fn new(client: JsonRpcClient) -> Self {
        let (tx_submit, rx_submit) = mpsc::unbounded();

        let account_filters = Arc::new(RwLock::new(HashMap::new()));

        // Start the single handler
        Self::start_handler(client, rx_submit);

        Self {
            account_filters,
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

        let account_id = &params.account_id;
        let mut filters = self.account_filters.write().await;

        // Get or create filter for this account
        let account_filter = filters
            .entry(account_id.clone())
            .or_insert_with(|| AccountFilter {
                block_hashes: VecDeque::new(),
                best_qualities: HashMap::new(),
            });

        // Check if this is a known block hash
        if let Some(&best_quality) = account_filter.best_qualities.get(&block_hash) {
            // Known block: check if this submission is better
            if quality >= best_quality {
                log::debug!(
                    "Filtered submission: account={}, quality {} not better than best {} for block {}",
                    &account_id[..8.min(account_id.len())],
                    quality,
                    best_quality,
                    &block_hash[..8]
                );
                return false;
            }

            // Better quality for known block - update and forward
            account_filter
                .best_qualities
                .insert(block_hash.clone(), quality);
            log::info!(
                "Updated best quality for account={}, block {}: {} -> {}",
                &account_id[..8.min(account_id.len())],
                &block_hash[..8],
                best_quality,
                quality
            );
        } else {
            // New block hash
            if account_filter.block_hashes.len() >= MAX_BLOCKS {
                // Evict oldest block
                if let Some(oldest_hash) = account_filter.block_hashes.pop_front() {
                    account_filter.best_qualities.remove(&oldest_hash);
                    log::debug!(
                        "Evicted oldest block hash for account={}: {}",
                        &account_id[..8.min(account_id.len())],
                        &oldest_hash[..8]
                    );
                }
            }

            // Add new block
            account_filter.block_hashes.push_back(block_hash.clone());
            account_filter
                .best_qualities
                .insert(block_hash.clone(), quality);
            log::info!(
                "New block hash detected for account={}: {} with quality {}",
                &account_id[..8.min(account_id.len())],
                &block_hash[..8],
                quality
            );
        }

        // Queue submission
        let submission = QueuedSubmission {
            params,
            block_hash,
            quality,
        };

        self.tx_submit.unbounded_send(submission).is_ok()
    }

    /// Single handler with exponential backoff retry
    fn start_handler(client: JsonRpcClient, mut rx: mpsc::UnboundedReceiver<QueuedSubmission>) {
        tokio::task::spawn(async move {
            let mut pending_queue: VecDeque<TimestampedSubmission> = VecDeque::new();
            let mut in_queue_best: HashMap<(String, String), u64> = HashMap::new();

            const STALE_TIMEOUT: Duration = Duration::from_secs(240); // 4 minutes
            const MAX_RETRIES: u32 = 5;
            const BASE_DELAY_MS: u64 = 1000; // 1 second

            log::info!("SubmissionQueue handler task started");

            loop {
                let now = Instant::now();

                // 1. Drain channel and enqueue new items (non-blocking)
                loop {
                    match rx.try_next() {
                        Ok(Some(new_submission)) => {
                            let key = (
                                new_submission.params.account_id.clone(),
                                new_submission.block_hash.clone(),
                            );

                            let should_add = if let Some(&best_in_queue) = in_queue_best.get(&key) {
                                if new_submission.quality < best_in_queue {
                                    in_queue_best.insert(key, new_submission.quality);
                                    true
                                } else {
                                    log::debug!(
                                        "Dropping new submission: worse than queued ({}  >= {})",
                                        new_submission.quality,
                                        best_in_queue
                                    );
                                    false
                                }
                            } else {
                                in_queue_best.insert(key, new_submission.quality);
                                true
                            };

                            if should_add {
                                pending_queue.push_back(TimestampedSubmission {
                                    submission: new_submission,
                                    queued_at: now,
                                    retry_count: 0,
                                });
                            }
                        }
                        Ok(None) => break, // Channel closed
                        Err(_) => break,   // Would block, no more items
                    }
                }

                // 2. Process one item from queue
                if let Some(mut item) = pending_queue.pop_front() {
                    let key = (
                        item.submission.params.account_id.clone(),
                        item.submission.block_hash.clone(),
                    );

                    // Check if item is stale (older than 4 minutes)
                    let age = now.duration_since(item.queued_at);
                    if age > STALE_TIMEOUT {
                        log::warn!(
                            "Dropping stale submission: account={}, block={}, age={}s",
                            &item.submission.params.account_id
                                [..8.min(item.submission.params.account_id.len())],
                            &item.submission.block_hash[..8],
                            age.as_secs()
                        );
                        in_queue_best.remove(&key);
                        continue;
                    }

                    // Check if better submission came in while this was queued
                    if let Some(&best_in_queue) = in_queue_best.get(&key) {
                        if item.submission.quality > best_in_queue {
                            log::debug!(
                                "Dropping queued item: better submission in queue ({} > {})",
                                item.submission.quality,
                                best_in_queue
                            );
                            continue;
                        }
                    }

                    // Try to submit
                    log::debug!(
                        "Processing submission: account={}, block={}, quality={}, retry={}/{}",
                        &item.submission.params.account_id
                            [..8.min(item.submission.params.account_id.len())],
                        &item.submission.block_hash[..8],
                        item.submission.quality,
                        item.retry_count,
                        MAX_RETRIES
                    );

                    match client.submit_nonce(item.submission.params.clone()).await {
                        Ok(result) => {
                            log_submission_accepted(&item.submission.params, &result);
                            in_queue_best.remove(&key);
                        }

                        Err(ProtocolError::RateLimited) => {
                            log_server_busy(&item.submission.params);

                            // Check retry limit
                            item.retry_count += 1;
                            if item.retry_count > MAX_RETRIES {
                                log::warn!(
                                    "Max retries exceeded: account={}, block={}",
                                    &item.submission.params.account_id
                                        [..8.min(item.submission.params.account_id.len())],
                                    &item.submission.block_hash[..8]
                                );
                                in_queue_best.remove(&key);
                            } else {
                                // Exponential backoff
                                let delay_ms = BASE_DELAY_MS * 2u64.pow(item.retry_count - 1);
                                log::info!(
                                    "Retrying in {}ms (attempt {}/{})",
                                    delay_ms,
                                    item.retry_count,
                                    MAX_RETRIES
                                );
                                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                pending_queue.push_front(item);
                            }
                        }

                        Err(ProtocolError::InvalidSubmission(msg)) => {
                            log_submission_not_accepted(
                                &item.submission.params,
                                &format!("Rejected: {}", msg),
                            );
                            in_queue_best.remove(&key);
                        }

                        Err(ProtocolError::StaleSubmission) => {
                            log_submission_not_accepted(
                                &item.submission.params,
                                "Stale submission",
                            );
                            in_queue_best.remove(&key);
                        }

                        Err(e) => {
                            log::warn!("Network error: {}", e);

                            // Check retry limit
                            item.retry_count += 1;
                            if item.retry_count > MAX_RETRIES {
                                log::warn!(
                                    "Max retries exceeded after network errors: account={}, block={}",
                                    &item.submission.params.account_id[..8.min(item.submission.params.account_id.len())],
                                    &item.submission.block_hash[..8]
                                );
                                in_queue_best.remove(&key);
                            } else {
                                // Exponential backoff
                                let delay_ms = BASE_DELAY_MS * 2u64.pow(item.retry_count - 1);
                                log::info!(
                                    "Retrying after network error in {}ms (attempt {}/{})",
                                    delay_ms,
                                    item.retry_count,
                                    MAX_RETRIES
                                );
                                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                pending_queue.push_front(item);
                            }
                        }
                    }
                } else {
                    // Queue empty - wait for new item (blocking)
                    if let Some(new_submission) = rx.next().await {
                        let key = (
                            new_submission.params.account_id.clone(),
                            new_submission.block_hash.clone(),
                        );
                        in_queue_best.insert(key, new_submission.quality);
                        pending_queue.push_back(TimestampedSubmission {
                            submission: new_submission,
                            queued_at: Instant::now(),
                            retry_count: 0,
                        });
                    } else {
                        break; // Channel closed
                    }
                }
            }

            log::warn!("SubmissionQueue handler task exited - stream ended");
        });
    }
}

fn log_submission_accepted(params: &SubmitNonceParams, result: &SubmitNonceResult) {
    log::info!(
        "Submitted to upstream: height={}, account={}, nonce={}, quality={}, poc_time={}",
        params.height,
        params.account_id,
        params.nonce,
        result.quality,
        result.poc_time
    );
}

fn log_submission_not_accepted(params: &SubmitNonceParams, msg: &str) {
    log::error!(
        "Upstream rejected submission: height={}, account={}, nonce={}, message={}",
        params.height,
        params.account_id,
        params.nonce,
        msg
    );
}

fn log_server_busy(params: &SubmitNonceParams) {
    log::info!(
        "Upstream server busy (will retry): height={}, account={}, nonce={}",
        params.height,
        params.account_id,
        params.nonce
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queued_submission_creation() {
        let sub = QueuedSubmission {
            params: SubmitNonceParams::new(
                100,
                "gensig1".to_string(),
                "acc1".to_string(),
                "seed1".to_string(),
                1000,
                5,
            ),
            block_hash: "hash1".to_string(),
            quality: 500,
        };

        assert_eq!(sub.block_hash, "hash1");
        assert_eq!(sub.quality, 500);
        assert_eq!(sub.params.height, 100);
    }
}
