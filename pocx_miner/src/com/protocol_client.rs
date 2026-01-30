// Copyright (c) 2025 Proof of Capacity Consortium

use crate::com::api::*;
use pocx_protocol::{
    JsonRpcClient, MiningInfo as JsonRpcMiningInfo, ProtocolError,
    SubmitNonceParams as JsonRpcSubmitParams, SubmitNonceResult,
};
use std::time::Duration;
use url::Url;

/// A client for communicating with Pool/Proxy/Wallet using JSON-RPC protocol.
#[derive(Clone, Debug)]
pub struct ProtocolClient {
    jsonrpc_client: JsonRpcClient,
}

impl ProtocolClient {
    /// Create a new JSON-RPC protocol client with HTTP/HTTPS URL.
    pub fn new(
        url: Url,
        timeout: u64,
        auth_token: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let timeout_duration = Duration::from_millis(timeout);

        let mut client = JsonRpcClient::new(url.as_str())?.with_timeout(timeout_duration);

        if let Some(token) = auth_token {
            client = client.with_auth_token(token);
        }

        Ok(Self {
            jsonrpc_client: client,
        })
    }

    /// Get current mining info using JSON-RPC.
    pub async fn get_mining_info(&self) -> Result<MiningInfo, FetchError> {
        match self.jsonrpc_client.get_mining_info().await {
            Ok(jsonrpc_mining_info) => Ok(convert_jsonrpc_to_mining_info(jsonrpc_mining_info)),
            Err(ProtocolError::NetworkError(e)) => Err(FetchError::Http(e)),
            Err(e) => Err(FetchError::Pool(PoolError {
                code: -1,
                message: e.to_string(),
            })),
        }
    }

    /// Submit nonce using JSON-RPC.
    pub async fn submit_nonce(
        &self,
        query: &NonceSubmission,
    ) -> Result<SubmitNonceResponse, FetchError> {
        let params = convert_to_jsonrpc_submit_params(query);
        match self.jsonrpc_client.submit_nonce(params).await {
            Ok(result) => Ok(convert_jsonrpc_to_submit_response(result)),
            Err(ProtocolError::NetworkError(e)) => Err(FetchError::Http(e)),
            Err(e) => Err(FetchError::Pool(PoolError {
                code: -1,
                message: e.to_string(),
            })),
        }
    }
}

// Conversion functions between internal API types and JSON-RPC types

fn convert_jsonrpc_to_mining_info(jsonrpc: JsonRpcMiningInfo) -> MiningInfo {
    MiningInfo {
        generation_signature: jsonrpc.generation_signature,
        base_target: jsonrpc.base_target,
        height: jsonrpc.height,
        block_hash: jsonrpc.block_hash,
        target_quality: jsonrpc.target_quality,
        minimum_compression_level: jsonrpc.minimum_compression_level.unwrap_or(1) as u32,
        target_compression_level: jsonrpc.target_compression_level.unwrap_or(1) as u32,
    }
}

fn convert_to_jsonrpc_submit_params(submission: &NonceSubmission) -> JsonRpcSubmitParams {
    JsonRpcSubmitParams::new(
        submission.block_height,
        submission.generation_signature.clone(),
        submission.account_id.clone(),
        submission.seed.clone(),
        submission.nonce,
        submission.compression,
    )
    .with_quality(submission.quality)
}

fn convert_jsonrpc_to_submit_response(jsonrpc: SubmitNonceResult) -> SubmitNonceResponse {
    SubmitNonceResponse {
        quality_adjusted: jsonrpc.quality,
        poc_time: jsonrpc.poc_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversion_functions() {
        // Test JSON-RPC to mining info conversion
        let jsonrpc_mining_info = JsonRpcMiningInfo::new(
            "abc123".to_string(),
            12345,
            98765,
            "blockhash456".to_string(),
        )
        .with_compression(2, 8)
        .with_target_quality(4294967295);

        let mining_info = convert_jsonrpc_to_mining_info(jsonrpc_mining_info);

        assert_eq!(mining_info.generation_signature, "abc123");
        assert_eq!(mining_info.base_target, 12345);
        assert_eq!(mining_info.height, 98765);
        assert_eq!(mining_info.block_hash, "blockhash456");
        assert_eq!(mining_info.target_quality, Some(4294967295));
        assert_eq!(mining_info.minimum_compression_level, 2);
        assert_eq!(mining_info.target_compression_level, 8);

        // Test nonce submission conversion
        let nonce_submission = NonceSubmission {
            block_height: 100,
            generation_signature: "test_sig".to_string(),
            account_id: "1234567890abcdef1234567890abcdef12345678".to_string(),
            seed: "test_seed".to_string(),
            nonce: 123456,
            quality: 789,
            compression: 4,
        };

        let jsonrpc_params = convert_to_jsonrpc_submit_params(&nonce_submission);

        assert_eq!(jsonrpc_params.height, 100);
        assert_eq!(jsonrpc_params.generation_signature, "test_sig");
        assert_eq!(
            jsonrpc_params.account_id,
            "1234567890abcdef1234567890abcdef12345678"
        );
        assert_eq!(jsonrpc_params.seed, "test_seed");
        assert_eq!(jsonrpc_params.nonce, 123456);
        assert_eq!(jsonrpc_params.compression, 4);
        assert_eq!(jsonrpc_params.quality, Some(789));
    }
}
