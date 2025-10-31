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

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest<T> {
    pub jsonrpc: String,
    pub method: String,
    pub params: T,
    pub id: JsonRpcId,
}

impl<T> JsonRpcRequest<T> {
    pub fn new(method: impl Into<String>, params: T) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
            id: JsonRpcId::new(),
        }
    }

    pub fn with_id(method: impl Into<String>, params: T, id: JsonRpcId) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
            id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcResponse<T> {
    Success {
        jsonrpc: String,
        result: T,
        id: JsonRpcId,
    },
    Error {
        jsonrpc: String,
        error: JsonRpcError,
        id: JsonRpcId,
    },
}

impl<T> JsonRpcResponse<T> {
    pub fn success(result: T, id: JsonRpcId) -> Self {
        Self::Success {
            jsonrpc: "2.0".to_string(),
            result,
            id,
        }
    }

    pub fn error(error: JsonRpcError, id: JsonRpcId) -> Self {
        Self::Error {
            jsonrpc: "2.0".to_string(),
            error,
            id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    String(String),
    Number(u64),
    Null,
}

impl JsonRpcId {
    pub fn new() -> Self {
        Self::String(Uuid::new_v4().to_string())
    }

    pub fn from_string(s: impl Into<String>) -> Self {
        Self::String(s.into())
    }

    pub fn from_number(n: u64) -> Self {
        Self::Number(n)
    }
}

impl Default for JsonRpcId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GetMiningInfoParams {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningInfo {
    pub generation_signature: String,
    pub base_target: u64,
    pub height: u64,
    pub block_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_quality: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_compression_level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_compression_level: Option<u8>,
}

impl MiningInfo {
    pub fn new(
        generation_signature: String,
        base_target: u64,
        height: u64,
        block_hash: String,
    ) -> Self {
        Self {
            generation_signature,
            base_target,
            height,
            block_hash,
            target_quality: None,
            minimum_compression_level: None,
            target_compression_level: None,
        }
    }

    pub fn with_compression(
        mut self,
        minimum_compression_level: u8,
        target_compression_level: u8,
    ) -> Self {
        self.minimum_compression_level = Some(minimum_compression_level);
        self.target_compression_level = Some(target_compression_level);
        self
    }

    pub fn with_target_quality(mut self, target_quality: u64) -> Self {
        self.target_quality = Some(target_quality);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitNonceParams {
    pub height: u64,
    pub generation_signature: String,
    pub account_id: String,
    pub seed: String,
    pub nonce: u64,
    pub compression: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality: Option<u64>,
}

impl SubmitNonceParams {
    pub fn new(
        height: u64,
        generation_signature: String,
        account_id: String,
        seed: String,
        nonce: u64,
        compression: u8,
    ) -> Self {
        Self {
            height,
            generation_signature,
            account_id,
            seed,
            nonce,
            compression,
            quality: None,
        }
    }

    pub fn with_quality(mut self, quality: u64) -> Self {
        self.quality = Some(quality);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitNonceResult {
    pub quality: u64, // This is adjusted quality (raw_quality / base_target)
    pub poc_time: u64,
}

impl SubmitNonceResult {
    pub fn new(quality: u64, poc_time: u64) -> Self {
        Self { quality, poc_time }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorData {
    pub reason: String,
    #[serde(flatten)]
    pub details: serde_json::Value,
}

pub const METHOD_GET_MINING_INFO: &str = "get_mining_info";
pub const METHOD_SUBMIT_NONCE: &str = "submit_nonce";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_rpc_request_serialization() {
        let request = JsonRpcRequest::new(METHOD_GET_MINING_INFO, GetMiningInfoParams::default());
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"get_mining_info\""));
    }

    #[test]
    fn test_mining_info_serialization() {
        let info = MiningInfo::new(
            "abc123".to_string(),
            12345,
            98765,
            "blockhash123".to_string(),
        )
        .with_compression(1, 9);

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"generation_signature\":\"abc123\""));
        assert!(json.contains("\"base_target\":12345"));
        assert!(json.contains("\"height\":98765"));
        assert!(json.contains("\"block_hash\":\"blockhash123\""));
        assert!(json.contains("\"minimum_compression_level\":1"));
        assert!(json.contains("\"target_compression_level\":9"));
    }

    #[test]
    fn test_submit_nonce_params_serialization() {
        let params = SubmitNonceParams::new(
            98765,
            "abc123".to_string(),
            "1234567890abcdef1234567890abcdef12345678".to_string(),
            "seed123".to_string(),
            123456789,
            5,
        )
        .with_quality(987654321);

        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains("\"height\":98765"));
        assert!(json.contains("\"nonce\":123456789"));
        assert!(json.contains("\"compression\":5"));
        assert!(json.contains("\"quality\":987654321"));
    }

    #[test]
    fn test_response_success() {
        let result = SubmitNonceResult::new(12345, 240);
        let response = JsonRpcResponse::success(result, JsonRpcId::from_string("test-id"));

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"quality\":12345"));
        assert!(json.contains("\"poc_time\":240"));
    }
}
