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

use crate::config::{SubmissionMode, UpstreamConfig};
use crate::error::{Error, Result};
use crate::queue::{GlobalBestQueue, SubmissionQueue};
use log::{debug, error, info};
use pocx_protocol::{JsonRpcClient, MiningInfo, SubmitNonceParams, SubmitNonceResult};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Duration, Instant};

/// Submission handler - either per-account (Pool) or global best (Wallet)
#[derive(Clone)]
enum SubmissionHandler {
    Pool(SubmissionQueue),
    Wallet(GlobalBestQueue),
}

impl SubmissionHandler {
    async fn submit(&self, params: SubmitNonceParams, block_hash: String, quality: u64) -> bool {
        match self {
            Self::Pool(queue) => queue.submit(params, block_hash, quality).await,
            Self::Wallet(queue) => queue.submit(params, block_hash, quality).await,
        }
    }
}

/// Pool manager handles connection to upstream pool/wallet
#[derive(Clone)]
pub struct PoolManager {
    upstream_name: String,
    client: JsonRpcClient,
    current_mining_info: Arc<RwLock<Option<CachedMiningInfo>>>,
    cache_ttl: Duration,
    fetch_lock: Arc<Mutex<()>>, // Prevents thundering herd on cache miss
    submission_handler: SubmissionHandler,
}

struct CachedMiningInfo {
    info: MiningInfo,
    cached_at: Instant,
}

impl PoolManager {
    /// Create a new pool manager
    pub fn new(upstream: &UpstreamConfig, cache_ttl_secs: u64, timeout_secs: u64) -> Result<Self> {
        let timeout = Duration::from_secs(timeout_secs);

        // Create client for upstream based on transport type
        let mut client = if upstream.is_ipc() {
            let ipc_path = upstream
                .ipc_path
                .as_ref()
                .ok_or_else(|| Error::Config("IPC transport requires ipc_path".to_string()))?;
            info!(
                "Connecting to upstream '{}' via IPC: {}",
                upstream.name, ipc_path
            );
            JsonRpcClient::new_ipc(ipc_path)
                .map_err(|e| {
                    Error::Pool(format!(
                        "Failed to create IPC client for {}: {}",
                        upstream.name, e
                    ))
                })?
                .with_timeout(timeout)
        } else {
            let url = upstream.build_url().ok_or_else(|| {
                Error::Config("HTTP/HTTPS transport requires valid URL".to_string())
            })?;
            info!(
                "Connecting to upstream '{}' via HTTP: {}",
                upstream.name, url
            );
            JsonRpcClient::new(&url)
                .map_err(|e| {
                    Error::Pool(format!(
                        "Failed to create HTTP client for {}: {}",
                        upstream.name, e
                    ))
                })?
                .with_timeout(timeout)
        };

        // Get auth token if configured (supports None, UserPass, Cookie)
        if let Some(token) = upstream.get_auth_token_or_exit() {
            client = client.with_auth_token(token);
        }

        // Create submission handler based on mode
        let submission_handler = match upstream.submission_mode {
            SubmissionMode::Pool => {
                info!("Using Pool submission mode (per-account best tracking)");
                SubmissionHandler::Pool(SubmissionQueue::new(client.clone()))
            }
            SubmissionMode::Wallet => {
                info!("Using Wallet submission mode (global best tracking)");
                SubmissionHandler::Wallet(GlobalBestQueue::new(client.clone()))
            }
        };

        Ok(Self {
            upstream_name: upstream.name.clone(),
            client,
            current_mining_info: Arc::new(RwLock::new(None)),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            fetch_lock: Arc::new(Mutex::new(())),
            submission_handler,
        })
    }

    /// Get mining information (cached or fresh from pool)
    pub async fn get_mining_info(&self) -> Result<MiningInfo> {
        // Fast path: check cache first (read lock only)
        {
            let cached = self.current_mining_info.read().await;
            if let Some(cached_info) = cached.as_ref() {
                if cached_info.cached_at.elapsed() < self.cache_ttl {
                    debug!(
                        "Returning cached mining info (age: {:?})",
                        cached_info.cached_at.elapsed()
                    );
                    return Ok(cached_info.info.clone());
                }
            }
        }

        // Cache miss or expired - acquire fetch lock to prevent thundering herd
        let _fetch_guard = self.fetch_lock.lock().await;

        // Double-check cache in case another task just updated it
        {
            let cached = self.current_mining_info.read().await;
            if let Some(cached_info) = cached.as_ref() {
                if cached_info.cached_at.elapsed() < self.cache_ttl {
                    debug!("Cache updated by another task, returning cached info");
                    return Ok(cached_info.info.clone());
                }
            }
        }

        // Fetch from upstream
        let info = self.fetch_mining_info_from_upstream().await?;

        // Update cache and invalidate if generation signature changed
        {
            let mut cached = self.current_mining_info.write().await;

            // Check if generation signature changed (new block)
            let signature_changed = cached
                .as_ref()
                .map(|c| c.info.generation_signature != info.generation_signature)
                .unwrap_or(true);

            if signature_changed {
                info!(
                    "New block detected: height={}, gen_sig={}",
                    info.height,
                    &info.generation_signature[..16]
                );
            }

            *cached = Some(CachedMiningInfo {
                info: info.clone(),
                cached_at: Instant::now(),
            });
        }

        Ok(info)
    }

    /// Submit a nonce to the pool
    pub async fn submit_nonce(
        &self,
        params: SubmitNonceParams,
        block_hash: String,
    ) -> Result<SubmitNonceResult> {
        // Extract quality from params (required for filtering)
        let quality = params
            .quality
            .ok_or_else(|| Error::Pool("Quality field is required for submission".to_string()))?;

        // Queue submission using configured handler (Pool or Wallet mode)
        let queued = self
            .submission_handler
            .submit(params.clone(), block_hash, quality)
            .await;

        if queued {
            // Return immediate success response (actual submission happens async)
            // The quality returned is what the miner calculated, poc_time is estimated
            // block time
            Ok(SubmitNonceResult::new(quality, 240))
        } else {
            // Still return success to miner (submission was filtered as duplicate)
            Ok(SubmitNonceResult::new(quality, 240))
        }
    }

    /// Fetch mining info from upstream
    async fn fetch_mining_info_from_upstream(&self) -> Result<MiningInfo> {
        debug!("Fetching mining info from upstream: {}", self.upstream_name);
        match self.client.get_mining_info().await {
            Ok(info) => {
                debug!(
                    "Got mining info from '{}': height={}, base_target={}",
                    self.upstream_name, info.height, info.base_target
                );
                Ok(info)
            }
            Err(e) => {
                error!(
                    "Failed to get mining info from '{}': {}",
                    self.upstream_name, e
                );
                Err(Error::Protocol(e))
            }
        }
    }
}
