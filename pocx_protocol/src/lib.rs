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

//! JSON-RPC protocol implementation for PoCX mining
//!
//! This crate provides:
//! - JSON-RPC 2.0 protocol implementation (client and server)
//! - Protocol types (MiningInfo, SubmitNonceParams, etc.)
//! - Error handling

pub mod protocol;

// Re-export main protocol types for convenience
pub use protocol::{
    extract_auth_token, GetMiningInfoParams, JsonRpcClient, JsonRpcDispatcher, JsonRpcError,
    JsonRpcHandler, JsonRpcId, JsonRpcRequest, JsonRpcResponse, MiningInfo, ProtocolError, Result,
    SubmitNonceParams, SubmitNonceResult, METHOD_GET_MINING_INFO, METHOD_SUBMIT_NONCE,
};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use async_trait::async_trait;

    struct TestHandler;

    #[async_trait]
    impl JsonRpcHandler for TestHandler {
        async fn get_mining_info(&self, _auth_token: Option<&str>) -> Result<MiningInfo> {
            Ok(MiningInfo::new(
                "abcdef123456".to_string(),
                1000,
                500,
                "test_block_hash".to_string(),
            )
            .with_compression(1, 9)
            .with_target_quality(u64::MAX))
        }

        async fn submit_nonce(
            &self,
            params: SubmitNonceParams,
            _auth_token: Option<&str>,
        ) -> Result<SubmitNonceResult> {
            if params.height != 500 {
                return Err(ProtocolError::WrongHeight {
                    expected: 500,
                    submitted: params.height,
                });
            }
            Ok(SubmitNonceResult::new(params.nonce, 120))
        }
    }

    #[tokio::test]
    async fn test_full_protocol_flow() {
        let handler = TestHandler;
        let dispatcher = JsonRpcDispatcher::new(handler);

        // Test get_mining_info
        let request = r#"{
            "jsonrpc": "2.0",
            "method": "get_mining_info",
            "params": {},
            "id": "test-1"
        }"#;

        let response = dispatcher.handle_request(request, None).await;
        let response_value: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response_value["jsonrpc"], "2.0");
        assert_eq!(
            response_value["result"]["generation_signature"],
            "abcdef123456"
        );
        assert_eq!(response_value["result"]["base_target"], 1000);
        assert_eq!(response_value["result"]["height"], 500);

        // Test submit_nonce success
        let request = r#"{
            "jsonrpc": "2.0",
            "method": "submit_nonce",
            "params": {
                "height": 500,
                "generation_signature": "abcdef123456",
                "account_id": "1234567890abcdef1234567890abcdef12345678",
                "seed": "test_seed",
                "nonce": 999888777,
                "compression": 5
            },
            "id": "test-2"
        }"#;

        let response = dispatcher.handle_request(request, None).await;
        let response_value: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response_value["jsonrpc"], "2.0");
        assert_eq!(response_value["result"]["quality"], 999888777);
        assert_eq!(response_value["result"]["poc_time"], 120);

        // Test submit_nonce error
        let request = r#"{
            "jsonrpc": "2.0",
            "method": "submit_nonce",
            "params": {
                "height": 999,
                "generation_signature": "abcdef123456",
                "account_id": "1234567890abcdef1234567890abcdef12345678",
                "seed": "test_seed",
                "nonce": 123456,
                "compression": 5
            },
            "id": "test-3"
        }"#;

        let response = dispatcher.handle_request(request, None).await;
        let response_value: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response_value["jsonrpc"], "2.0");
        assert_eq!(response_value["error"]["code"], -32002);
        assert_eq!(response_value["error"]["data"]["expected"], 500);
        assert_eq!(response_value["error"]["data"]["submitted"], 999);
    }
}
