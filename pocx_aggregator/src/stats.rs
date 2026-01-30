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
    base_target: u64, // Used in estimate_capacity_tib() to calculate deadline
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
    active_connections: HashMap<(String, String), MinerInfo>, // (Account ID, Machine ID) -> info
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
    /// Uses a sliding 30-block window: if current block present, use blocks
    /// (current-30 to current-1), if current block not present, use blocks
    /// (current-31 to current-1)
    pub fn estimate_capacity_tib(&self, current_height: u64, lookback_blocks: u64) -> f64 {
        if self.best_per_block.is_empty() {
            return 0.0;
        }

        // Check if miner has submitted for current height
        let has_current_block = self.best_per_block.contains_key(&current_height);

        // If current block is present, use window [current-29, current] (30 blocks:
        // 71-100) If current block is absent, use window [current-30,
        // current-1] (30 blocks: 70-99)
        let (window_start, window_end) = if has_current_block {
            (
                current_height.saturating_sub(lookback_blocks - 1),
                current_height,
            )
        } else {
            (
                current_height.saturating_sub(lookback_blocks),
                current_height.saturating_sub(1),
            )
        };

        const POC_CONSTANT: f64 = 4_398_046_511_104.0; // 2^42

        let mut deadline_sum = 0.0;
        let mut count = 0;

        for (h, best) in self.best_per_block.iter() {
            if *h >= window_start && *h <= window_end {
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
#[serde(rename_all = "camelCase")]
pub struct CurrentBlockBest {
    pub height: u64,
    pub best_poc_time: Option<u64>, // in seconds
    pub best_quality: Option<u64>,  // raw quality value
    pub best_account_id: Option<String>,
    pub best_machine_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSummary {
    pub account_id: String,
    pub machine_count: usize,
    pub total_capacity_tib: f64,
    pub submissions_24h: usize,
    pub submission_percentage: f64,
    pub last_seen_secs_ago: i64,
    pub is_active: bool,
    pub machines: Vec<MachineInAccount>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineInAccount {
    pub machine_id: String,
    pub capacity_tib: f64,
    pub submissions_24h: usize,
    pub submission_percentage: f64,
    pub last_seen_secs_ago: i64,
    pub is_active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineSummary {
    pub machine_id: String,
    pub account_count: usize,
    pub total_capacity_tib: f64,
    pub submissions_24h: usize,
    pub submission_percentage: f64,
    pub last_seen_secs_ago: i64,
    pub is_active: bool,
    pub accounts: Vec<AccountInMachine>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInMachine {
    pub account_id: String,
    pub capacity_tib: f64,
    pub submissions_24h: usize,
    pub submission_percentage: f64,
    pub last_seen_secs_ago: i64,
    pub is_active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsSnapshot {
    pub unique_miners: usize,   // Unique account IDs
    pub unique_machines: usize, // Unique machine IDs (IPs)
    pub active_machines: usize, // Machines seen in last 5 minutes
    pub current_height: u64,
    pub uptime_secs: i64,
    pub total_capacity: String, // Total miner capacity (ByteSize formatted)
    pub network_capacity: String, // Network capacity from base_target (ByteSize formatted)
    pub current_block_best: CurrentBlockBest,
    pub machines: Vec<MachineSummary>,
    pub accounts: Vec<AccountSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
    /// Only stores the BEST submission per block per (account, machine) pair
    pub async fn record_submission(
        &self,
        account_id: &str,
        machine_id: Option<String>,
        quality: u64,
        base_target: u64,
        height: u64,
    ) {
        let machine_id = machine_id.unwrap_or_else(|| "unknown".to_string());
        let mut inner = self.inner.write().await;
        inner.unique_miners.insert(account_id.to_string());

        let now = Utc::now();
        let key = (account_id.to_string(), machine_id.clone());

        // Update miner info
        inner
            .active_connections
            .entry(key)
            .and_modify(|info| {
                info.last_seen = now;

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
                machine_id: Some(machine_id),
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
        let machine_id = machine_id.unwrap_or_else(|| "unknown".to_string());
        let mut inner = self.inner.write().await;
        inner.unique_miners.insert(account_id.to_string());

        let now = Utc::now();
        let current_height = inner.current_height;
        let key = (account_id.to_string(), machine_id.clone());

        inner
            .active_connections
            .entry(key)
            .and_modify(|info| {
                info.last_seen = now;
            })
            .or_insert(MinerInfo {
                account_id: account_id.to_string(),
                machine_id: Some(machine_id),
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
        const ACTIVE_THRESHOLD_SECS: i64 = 300; // 5 minutes

        let inner = self.inner.read().await;
        let now = Utc::now();
        let current_height = inner.current_height;

        let uptime_secs = inner
            .started_at
            .map(|start| (now - start).num_seconds())
            .unwrap_or(0);

        // Count unique machines
        let unique_machine_ids: HashSet<String> = inner
            .active_connections
            .values()
            .filter_map(|info| info.machine_id.clone())
            .collect();

        // Build intermediate data for each (account, machine) pair
        // Filter out stale connections (>24 hours old)
        let pair_data: Vec<_> = inner
            .active_connections
            .values()
            .filter(|info| {
                let secs_ago = (now - info.last_seen).num_seconds();
                secs_ago < 86400 // 24 hours
            })
            .map(|info| {
                let last_seen_secs_ago = (now - info.last_seen).num_seconds();
                let estimated_capacity_tib =
                    info.estimate_capacity_tib(current_height, LOOKBACK_BLOCKS);
                let submissions_24h = info.submissions_last_24h();
                let submission_percentage = info.submission_percentage(self.block_time_secs);
                let is_active = last_seen_secs_ago < ACTIVE_THRESHOLD_SECS;

                (
                    info.account_id.clone(),
                    info.machine_id
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    last_seen_secs_ago,
                    estimated_capacity_tib,
                    submissions_24h,
                    submission_percentage,
                    is_active,
                    info.best_quality,
                    info.best_base_target,
                )
            })
            .collect();

        // Find current block best submission
        let mut current_block_best = CurrentBlockBest {
            height: current_height,
            best_poc_time: None,
            best_quality: None,
            best_account_id: None,
            best_machine_id: None,
        };

        for (account_id, machine_id, _, _, _, _, _, best_quality, best_base_target) in &pair_data {
            if let (Some(quality), Some(bt)) = (best_quality, best_base_target) {
                let raw_quality = quality * bt;
                let current_best_raw = current_block_best
                    .best_quality
                    .and_then(|q| current_block_best.best_poc_time.map(|_| q));

                if current_best_raw.is_none() || raw_quality < current_best_raw.unwrap() {
                    current_block_best.best_quality = Some(raw_quality);
                    current_block_best.best_poc_time =
                        Some(self.calculate_poc_time(raw_quality, *bt));
                    current_block_best.best_account_id = Some(account_id.clone());
                    current_block_best.best_machine_id = Some(machine_id.clone());
                }
            }
        }

        // Aggregate by machine: group by machine_id
        let mut machine_map: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, (_, machine_id, _, _, _, _, _, _, _)) in pair_data.iter().enumerate() {
            machine_map.entry(machine_id.clone()).or_default().push(idx);
        }

        let mut machines: Vec<MachineSummary> = machine_map
            .into_iter()
            .map(|(machine_id, indices)| {
                let mut accounts = Vec::new();
                let mut total_capacity_tib = 0.0;
                let mut total_submissions_24h = 0;
                let mut last_seen_secs_ago = i64::MAX;
                let mut is_active = false;

                for &idx in &indices {
                    let (account_id, _, last_seen, capacity_tib, subs_24h, sub_pct, active, _, _) =
                        &pair_data[idx];
                    total_capacity_tib += capacity_tib;
                    total_submissions_24h += subs_24h;
                    last_seen_secs_ago = last_seen_secs_ago.min(*last_seen);
                    is_active = is_active || *active;

                    accounts.push(AccountInMachine {
                        account_id: account_id.clone(),
                        capacity_tib: *capacity_tib,
                        submissions_24h: *subs_24h,
                        submission_percentage: *sub_pct,
                        last_seen_secs_ago: *last_seen,
                        is_active: *active,
                    });
                }

                // Calculate average submission percentage instead of sum
                let avg_submission_percentage = if !indices.is_empty() {
                    let total_pct: f64 = indices.iter().map(|&idx| pair_data[idx].5).sum();
                    total_pct / indices.len() as f64
                } else {
                    0.0
                };

                MachineSummary {
                    machine_id,
                    account_count: indices.len(),
                    total_capacity_tib,
                    submissions_24h: total_submissions_24h,
                    submission_percentage: avg_submission_percentage,
                    last_seen_secs_ago,
                    is_active,
                    accounts,
                }
            })
            .collect();

        // Sort machines: active first, then by machine_id for stability
        machines.sort_by(|a, b| match b.is_active.cmp(&a.is_active) {
            std::cmp::Ordering::Equal => a.machine_id.cmp(&b.machine_id),
            other => other,
        });

        // Aggregate by account: group by account_id
        let mut account_map: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, (account_id, _, _, _, _, _, _, _, _)) in pair_data.iter().enumerate() {
            account_map.entry(account_id.clone()).or_default().push(idx);
        }

        let mut accounts: Vec<AccountSummary> = account_map
            .into_iter()
            .map(|(account_id, indices)| {
                let mut machine_list = Vec::new();
                let mut total_capacity_tib = 0.0;
                let mut total_submissions_24h = 0;
                let mut last_seen_secs_ago = i64::MAX;
                let mut is_active = false;

                for &idx in &indices {
                    let (_, machine_id, last_seen, capacity_tib, subs_24h, sub_pct, active, _, _) =
                        &pair_data[idx];
                    total_capacity_tib += capacity_tib;
                    total_submissions_24h += subs_24h;
                    last_seen_secs_ago = last_seen_secs_ago.min(*last_seen);
                    is_active = is_active || *active;

                    machine_list.push(MachineInAccount {
                        machine_id: machine_id.clone(),
                        capacity_tib: *capacity_tib,
                        submissions_24h: *subs_24h,
                        submission_percentage: *sub_pct,
                        last_seen_secs_ago: *last_seen,
                        is_active: *active,
                    });
                }

                // Calculate average submission percentage instead of sum
                let avg_submission_percentage = if !indices.is_empty() {
                    let total_pct: f64 = indices.iter().map(|&idx| pair_data[idx].5).sum();
                    total_pct / indices.len() as f64
                } else {
                    0.0
                };

                AccountSummary {
                    account_id,
                    machine_count: indices.len(),
                    total_capacity_tib,
                    submissions_24h: total_submissions_24h,
                    submission_percentage: avg_submission_percentage,
                    last_seen_secs_ago,
                    is_active,
                    machines: machine_list,
                }
            })
            .collect();

        // Sort accounts: active first, then by account_id for stability
        accounts.sort_by(|a, b| match b.is_active.cmp(&a.is_active) {
            std::cmp::Ordering::Equal => a.account_id.cmp(&b.account_id),
            other => other,
        });

        // Count active machines
        let active_machines = unique_machine_ids
            .iter()
            .filter(|machine_id| {
                machines
                    .iter()
                    .any(|m| &m.machine_id == *machine_id && m.is_active)
            })
            .count();

        // Calculate total capacity
        let total_capacity_tib: f64 = pair_data
            .iter()
            .map(|(_, _, _, cap, _, _, _, _, _)| cap)
            .sum();
        let total_capacity_bytes = (total_capacity_tib * 1_099_511_627_776.0) as u64;
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
            active_machines,
            current_height: inner.current_height,
            uptime_secs,
            total_capacity,
            network_capacity,
            current_block_best,
            machines,
            accounts,
        }
    }
}

impl Default for Stats {
    fn default() -> Self {
        // Default to PoCX parameters (120s block time)
        Self::new(120)
    }
}
