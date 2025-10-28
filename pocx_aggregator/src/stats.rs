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

use bytesize::ByteSize;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Calculate genesis base target for given block time
fn genesis_base_target(block_time: u64) -> u64 {
    2u64.pow(42) / block_time
}

/// Calculate estimated network capacity from base target and block time
fn calculate_network_capacity_bytes(base_target: u64, block_time: u64) -> u64 {
    let genesis_bt = genesis_base_target(block_time);
    let capacity_ratio = genesis_bt as f64 / base_target as f64;
    (capacity_ratio * (1u64 << 40) as f64) as u64
}

/// Best submission for a specific block
#[derive(Debug, Clone)]
pub(crate) struct BestSubmission {
    quality: u64,
    #[allow(dead_code)]
    base_target: u64, // Stored but not currently used in capacity calc
    timestamp: DateTime<Utc>,
}

/// Statistics tracker for the aggregator
#[derive(Debug, Clone)]
pub struct Stats {
    inner: Arc<RwLock<StatsInner>>,
    block_time_secs: u64,
}

#[derive(Debug, Default)]
struct StatsInner {
    unique_miners: HashSet<String>, // Track unique account IDs
    active_connections: HashMap<String, MinerInfo>, // Account ID -> info
    current_height: u64,
    current_base_target: Option<u64>, // Current network base target
    started_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct MinerInfo {
    pub account_id: String,
    pub machine_id: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub best_quality: Option<u64>,
    pub best_base_target: Option<u64>,
    pub current_height: u64,
    best_per_block: HashMap<u64, BestSubmission>,
}

impl MinerInfo {
    /// Estimate capacity in TiB using PoC formula
    /// Formula: capacity_TiB = 2^42 / avg(deadline)
    /// Uses only BEST submission per block from lookback window
    pub fn estimate_capacity_tib(&self, current_height: u64, lookback_blocks: u64) -> f64 {
        if self.best_per_block.is_empty() {
            return 0.0;
        }

        let cutoff_height = current_height.saturating_sub(lookback_blocks);
        const POC_CONSTANT: f64 = 4_398_046_511_104.0; // 2^42

        let mut deadline_sum = 0.0;
        let mut count = 0;

        for (h, best) in self.best_per_block.iter() {
            if *h > cutoff_height {
                let deadline = best.quality as f64 * best.base_target as f64;
                deadline_sum += deadline;
                count += 1;
            }
        }

        if count == 0 {
            return 0.0;
        }

        let avg_deadline = deadline_sum / count as f64;
        POC_CONSTANT / avg_deadline
    }

    /// Count blocks with submissions in the last 24 hours
    pub fn submissions_last_24h(&self) -> usize {
        let cutoff = Utc::now() - Duration::hours(24);
        self.best_per_block
            .values()
            .filter(|best| best.timestamp > cutoff)
            .count()
    }

    /// Calculate submission percentage (submissions_24h / blocks_per_day * 100)
    pub fn submission_percentage(&self, block_time_secs: u64) -> f64 {
        let submissions = self.submissions_last_24h();
        let blocks_per_day = 86400 / block_time_secs; // seconds per day / block time

        if blocks_per_day == 0 {
            return 0.0;
        }

        (submissions as f64 / blocks_per_day as f64) * 100.0
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsSnapshot {
    pub unique_miners: usize,   // Unique account IDs
    pub unique_machines: usize, // Unique machine IDs (IPs)
    pub active_machines: usize, // Machines seen in last 5 minutes
    pub current_height: u64,
    pub uptime_secs: i64,
    pub total_capacity: String,   // Total miner capacity (ByteSize formatted)
    pub network_capacity: String, // Network capacity from base_target (ByteSize formatted)
    pub miners: Vec<MinerSnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MinerSnapshot {
    pub account_id: String,
    pub machine_id: Option<String>,
    pub last_seen_secs_ago: i64,
    pub submissions_24h: usize,
    pub submission_percentage: f64,
    pub best_quality: Option<u64>,
    pub best_poc_time: Option<u64>,
    pub estimated_capacity_tib: f64,
}

impl Stats {
    pub fn new(block_time_secs: u64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StatsInner {
                started_at: Some(Utc::now()),
                ..Default::default()
            })),
            block_time_secs,
        }
    }

    /// Calculate poc_time from quality using time-bending formula
    pub fn calculate_poc_time(&self, quality: u64, base_target: u64) -> u64 {
        crate::time_bending::calculate_time_bended_deadline(
            quality,
            base_target,
            self.block_time_secs,
        )
    }

    /// Record a nonce submission from a miner
    /// Only stores the BEST submission per block per machine
    pub async fn record_submission(
        &self,
        account_id: &str,
        machine_id: Option<String>,
        quality: u64,
        base_target: u64,
        height: u64,
    ) {
        let mut inner = self.inner.write().await;
        inner.unique_miners.insert(account_id.to_string());

        let now = Utc::now();

        // Update miner info
        inner
            .active_connections
            .entry(account_id.to_string())
            .and_modify(|info| {
                info.last_seen = now;
                info.machine_id = machine_id.clone().or(info.machine_id.clone());

                // Reset per-round stats if new block
                if height != info.current_height {
                    info.current_height = height;
                    info.best_quality = Some(quality);
                    info.best_base_target = Some(base_target);
                } else {
                    // Update best for current round
                    if quality < info.best_quality.unwrap_or(u64::MAX) {
                        info.best_quality = Some(quality);
                        info.best_base_target = Some(base_target);
                    }
                }

                // Store only the best submission for this block
                info.best_per_block
                    .entry(height)
                    .and_modify(|best| {
                        // Update if this is better (lower quality/deadline)
                        if quality < best.quality {
                            best.quality = quality;
                            best.timestamp = now;
                        }
                    })
                    .or_insert(BestSubmission {
                        quality,
                        base_target,
                        timestamp: now,
                    });

                // Clean up old blocks (keep last 720 blocks = ~24h at 120s blocks)
                let cutoff_height = height.saturating_sub(720);
                info.best_per_block.retain(|h, _| *h > cutoff_height);
            })
            .or_insert(MinerInfo {
                account_id: account_id.to_string(),
                machine_id,
                last_seen: now,
                best_quality: Some(quality),
                best_base_target: Some(base_target),
                current_height: height,
                best_per_block: {
                    let mut map = HashMap::new();
                    map.insert(
                        height,
                        BestSubmission {
                            quality,
                            base_target,
                            timestamp: now,
                        },
                    );
                    map
                },
            });
    }

    /// Update the current blockchain height
    pub async fn update_height(&self, height: u64) {
        let mut inner = self.inner.write().await;
        inner.current_height = height;
    }

    /// Update the current base target (from mining info)
    pub async fn update_base_target(&self, base_target: u64) {
        let mut inner = self.inner.write().await;
        inner.current_base_target = Some(base_target);
    }

    /// Record a mining info request from a miner (keeps connection alive)
    pub async fn record_miner_heartbeat(&self, account_id: &str, machine_id: Option<String>) {
        let mut inner = self.inner.write().await;
        inner.unique_miners.insert(account_id.to_string());

        let now = Utc::now();
        let current_height = inner.current_height;

        inner
            .active_connections
            .entry(account_id.to_string())
            .and_modify(|info| {
                info.last_seen = now;
                info.machine_id = machine_id.clone().or(info.machine_id.clone());
            })
            .or_insert(MinerInfo {
                account_id: account_id.to_string(),
                machine_id,
                last_seen: now,
                best_quality: None,
                best_base_target: None,
                current_height,
                best_per_block: HashMap::new(),
            });
    }

    /// Get a snapshot of current statistics
    pub async fn snapshot(&self) -> StatsSnapshot {
        const LOOKBACK_BLOCKS: u64 = 30; // 30 blocks = ~1 hour for 120s block time

        let inner = self.inner.read().await;
        let now = Utc::now();
        let current_height = inner.current_height;

        let uptime_secs = inner
            .started_at
            .map(|start| (now - start).num_seconds())
            .unwrap_or(0);

        // Count unique machines (by machine_id/IP)
        let unique_machine_ids: HashSet<String> = inner
            .active_connections
            .values()
            .filter_map(|info| info.machine_id.clone())
            .collect();

        // Clean up stale connections (>5 minutes old) and count active miners
        let active_threshold = chrono::Duration::minutes(5);
        let mut miners: Vec<MinerSnapshot> = inner
            .active_connections
            .values()
            .map(|info| {
                let last_seen_secs_ago = (now - info.last_seen).num_seconds();
                let estimated_capacity_tib =
                    info.estimate_capacity_tib(current_height, LOOKBACK_BLOCKS);
                let submissions_24h = info.submissions_last_24h();
                let submission_percentage = info.submission_percentage(self.block_time_secs);
                let best_poc_time = match (info.best_quality, info.best_base_target) {
                    (Some(adjusted_quality), Some(bt)) => {
                        // best_quality is adjusted quality, multiply back to get raw quality
                        let raw_quality = adjusted_quality * bt;
                        Some(self.calculate_poc_time(raw_quality, bt))
                    }
                    _ => None,
                };

                MinerSnapshot {
                    account_id: info.account_id.clone(),
                    machine_id: info.machine_id.clone(),
                    last_seen_secs_ago,
                    submissions_24h,
                    submission_percentage,
                    best_quality: info.best_quality,
                    best_poc_time,
                    estimated_capacity_tib,
                }
            })
            .collect();

        // Sort by last seen (most recent first)
        miners.sort_by_key(|m| m.last_seen_secs_ago);

        // Count active machines (unique IPs seen in last 5 minutes)
        let active_machine_ids: HashSet<String> = miners
            .iter()
            .filter(|m| m.last_seen_secs_ago < active_threshold.num_seconds())
            .filter_map(|m| m.machine_id.clone())
            .collect();

        let active_miners = active_machine_ids.len();

        // Calculate total miner capacity in bytes
        let total_capacity_tib: f64 = miners.iter().map(|m| m.estimated_capacity_tib).sum();
        let total_capacity_bytes = (total_capacity_tib * 1_099_511_627_776.0) as u64; // TiB to bytes
        let total_capacity = ByteSize::b(total_capacity_bytes).to_string();

        // Calculate network capacity from base target
        let network_capacity = inner
            .current_base_target
            .map(|bt| {
                let bytes = calculate_network_capacity_bytes(bt, self.block_time_secs);
                ByteSize::b(bytes).to_string()
            })
            .unwrap_or_else(|| "N/A".to_string());

        StatsSnapshot {
            unique_miners: inner.unique_miners.len(),
            unique_machines: unique_machine_ids.len(),
            active_machines: active_miners,
            current_height: inner.current_height,
            uptime_secs,
            total_capacity,
            network_capacity,
            miners,
        }
    }
}

impl Default for Stats {
    fn default() -> Self {
        // Default to PoCX parameters (120s block time)
        Self::new(120)
    }
}
