// Copyright (c) 2025 Proof of Capacity Consortium

use async_trait::async_trait;
use chrono::prelude::*;
use futures::channel::oneshot;
use pocx_protocol::{
    JsonRpcHandler, MiningInfo as JsonRpcMiningInfo, ProtocolError, Result, SubmitNonceParams,
    SubmitNonceResult,
};
use std::convert::TryInto;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::config::PoCXConfig;
use crate::db::DB;

pub struct MockchainJsonRpcHandler {
    db: Arc<DB>,
    config: Arc<PoCXConfig>,
    tripwire: Arc<std::sync::Mutex<Option<oneshot::Sender<()>>>>,
    best_quality: Arc<std::sync::Mutex<u64>>,
}

impl MockchainJsonRpcHandler {
    pub fn new(
        db: Arc<DB>,
        config: Arc<PoCXConfig>,
        tripwire: Arc<std::sync::Mutex<Option<oneshot::Sender<()>>>>,
        best_quality: Arc<std::sync::Mutex<u64>>,
    ) -> Self {
        Self {
            db,
            config,
            tripwire,
            best_quality,
        }
    }
}

#[async_trait]
impl JsonRpcHandler for MockchainJsonRpcHandler {
    async fn get_mining_info(&self, _auth_token: Option<&str>) -> Result<JsonRpcMiningInfo> {
        let mining_info = self.db.get_mining_info();

        Ok(JsonRpcMiningInfo::new(
            mining_info.generation_signature,
            mining_info.base_target,
            mining_info.height,
            mining_info.block_hash,
        )
        .with_compression(
            self.config.network.minimum_compression_level,
            self.config.network.target_compression_level,
        )
        .with_target_quality(mining_info.target_quality))
    }

    async fn submit_nonce(
        &self,
        params: SubmitNonceParams,
        _auth_token: Option<&str>,
    ) -> Result<SubmitNonceResult> {
        let mining_info = self.db.get_mining_info();

        // Validate block height
        if params.height != mining_info.height {
            return Err(ProtocolError::WrongHeight {
                expected: mining_info.height,
                submitted: params.height,
            });
        }

        // Validate generation signature
        if params.generation_signature.to_lowercase()
            != mining_info.generation_signature.to_lowercase()
        {
            return Err(ProtocolError::InvalidSubmission(
                "unexpected generation signature, fork?".to_string(),
            ));
        }

        // No need to validate compression level - it's computed automatically

        // Validate address payload (hex-encoded 20-byte payload only)
        let address_payload = if params.account_id.len() == 40 {
            // Hex-encoded 20-byte payload format (40 hex characters)
            match hex::decode(&params.account_id) {
                Ok(payload_bytes) if payload_bytes.len() == 20 => {
                    let mut payload_array = [0u8; 20];
                    payload_array.copy_from_slice(&payload_bytes);
                    payload_array
                }
                _ => {
                    return Err(ProtocolError::InvalidParams(
                        "Invalid address payload! Expected 40 hex characters (20 bytes)."
                            .to_string(),
                    ));
                }
            }
        } else {
            return Err(ProtocolError::InvalidParams(format!(
                "Invalid address payload length! Expected 40 hex characters, got {}.",
                params.account_id.len()
            )));
        };

        // For storage, we'll encode the payload with the configured network ID
        let account_id_for_storage =
            pocx_address::encode_address(&address_payload, self.config.network.network_id.clone())
                .map_err(|e| {
                    ProtocolError::InvalidParams(format!("Failed to encode address: {}", e))
                })?;

        let seed: [u8; 32] = hex::decode(&params.seed)
            .map_err(|_| ProtocolError::InvalidParams("Invalid seed format".to_string()))?
            .try_into()
            .map_err(|_| ProtocolError::InvalidParams("Seed must be 32 bytes".to_string()))?;

        // Calculate best quality in compression range
        let quality = match pocx_hashlib::calculate_best_quality_in_range(
            &address_payload,
            &seed,
            params.nonce,
            mining_info.minimum_compression_level,
            mining_info.target_compression_level,
            mining_info.height,
            &mining_info.generation_signature_bytes,
        ) {
            Ok(q) => q,
            Err(_) => {
                return Err(ProtocolError::InternalError(
                    "Failed to calculate quality".to_string(),
                ));
            }
        };

        let quality_adjusted = quality / mining_info.base_target;
        let poc_time = crate::db::quality_adj_to_time(
            quality_adjusted,
            self.config.network.block_time_seconds,
        );

        // Log the submission (showing only what the server calculated)
        println!(
            "nonce: height={}, gensig=...{}, account={}, seed=...{}, nonce={}, \
             quality={}, poc_time={}",
            mining_info.height,
            mining_info
                .generation_signature
                .chars()
                .skip(56)
                .take(8)
                .collect::<String>(),
            &params.account_id,
            &params.seed.chars().skip(56).take(8).collect::<String>(),
            &params.nonce,
            quality_adjusted, // Only show server's calculated adjusted quality
            poc_time
        );

        // Validate quality against target
        if quality_adjusted > mining_info.target_quality {
            return Err(ProtocolError::InvalidSubmission(format!(
                "quality {} exceeds target quality: {}",
                quality_adjusted, mining_info.target_quality
            )));
        }

        // Handle best quality tracking and forging simulation
        let mut best_dl = self
            .best_quality
            .lock()
            .map_err(|_| ProtocolError::InternalError("Mutex lock failed".to_string()))?;

        if quality < *best_dl {
            *best_dl = quality;

            // Get latest block to calculate remaining time
            let latest_block = self.db.get_latest_block().ok_or_else(|| {
                ProtocolError::InternalError("No blocks found in database".to_string())
            })?;

            let last_creation = latest_block.creation_time;
            let elapsed = Utc::now().naive_utc().signed_duration_since(last_creation);
            let remaining = match elapsed.to_std() {
                Ok(elapsed_duration) => {
                    let poc_duration = Duration::from_millis(poc_time * 1000);
                    if elapsed_duration > poc_duration {
                        Duration::from_millis(0)
                    } else {
                        poc_duration - elapsed_duration
                    }
                }
                Err(_) => Duration::from_millis(0), // Handle negative duration
            };

            // Create new tripwire and trigger existing one if any
            let (interrupter, interrupt_handler) = oneshot::channel::<()>();
            let mut tripwire = self.tripwire.lock().map_err(|_| {
                ProtocolError::InternalError("Tripwire mutex lock failed".to_string())
            })?;

            if let Some(inner) = tripwire.take() {
                let _ = inner.send(());
            }
            *tripwire = Some(interrupter);

            // Spawn forging task
            let db = self.db.clone();
            let best_quality = self.best_quality.clone();
            let account_id = account_id_for_storage.clone();
            let seed = params.seed.clone();
            let nonce = params.nonce;
            let height = mining_info.height;

            tokio::spawn(async move {
                tokio::select! {
                    _ = sleep(remaining) => {
                        if let Ok(mut best_dl) = best_quality.lock() {
                            db.forge_block(height, account_id, seed, nonce, poc_time);
                            *best_dl = u64::MAX;
                        } else {
                            eprintln!("Failed to acquire best_quality mutex in forging task");
                        }
                    }
                    _ = interrupt_handler => {
                        // Interrupted by better quality
                    }
                }
            });
        }

        Ok(SubmitNonceResult::new(quality_adjusted, poc_time))
    }
}
