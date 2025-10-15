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

use async_trait::async_trait;
use serde_json::Value;
use tracing::{debug, error, warn};

use crate::{
    errors::{self, ProtocolError, Result},
    types::{
        GetMiningInfoParams, JsonRpcId, JsonRpcResponse, MiningInfo, SubmitNonceParams,
        SubmitNonceResult, METHOD_GET_MINING_INFO, METHOD_SUBMIT_NONCE,
    },
};

#[async_trait]
pub trait JsonRpcHandler: Send + Sync {
    async fn get_mining_info(&self, auth_token: Option<&str>) -> Result<MiningInfo>;

    async fn submit_nonce(
        &self,
        params: SubmitNonceParams,
        auth_token: Option<&str>,
    ) -> Result<SubmitNonceResult>;
}

pub struct JsonRpcDispatcher<H> {
    handler: H,
}

impl<H> JsonRpcDispatcher<H>
where
    H: JsonRpcHandler,
{
    pub fn new(handler: H) -> Self {
        Self { handler }
    }

    pub async fn handle_request(&self, request_body: &str, auth_token: Option<&str>) -> String {
        match self.process_request(request_body, auth_token).await {
            Ok(response) => response,
            Err(err) => {
                error!("Failed to process JSON-RPC request: {}", err);
                let error_response: JsonRpcResponse<()> =
                    JsonRpcResponse::error(err.to_json_rpc_error(), JsonRpcId::Null);
                serde_json::to_string(&error_response).unwrap_or_else(|_| {
                    r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"},"id":null}"#.to_string()
                })
            }
        }
    }

    async fn process_request(
        &self,
        request_body: &str,
        auth_token: Option<&str>,
    ) -> Result<String> {
        let raw_request: Value = serde_json::from_str(request_body)
            .map_err(|e| ProtocolError::ParseError(e.to_string()))?;

        if raw_request.is_array() {
            return self.handle_batch_request(raw_request, auth_token).await;
        }

        self.handle_single_request(raw_request, auth_token).await
    }

    async fn handle_single_request(
        &self,
        raw_request: Value,
        auth_token: Option<&str>,
    ) -> Result<String> {
        let jsonrpc = raw_request
            .get("jsonrpc")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if jsonrpc != "2.0" {
            return Err(ProtocolError::InvalidRequest(
                "Invalid JSON-RPC version".to_string(),
            ));
        }

        let method = raw_request
            .get("method")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ProtocolError::InvalidRequest("Missing method".to_string()))?;

        let id = raw_request
            .get("id")
            .map(|v| {
                if let Some(s) = v.as_str() {
                    JsonRpcId::String(s.to_string())
                } else if let Some(n) = v.as_u64() {
                    JsonRpcId::Number(n)
                } else {
                    JsonRpcId::Null
                }
            })
            .unwrap_or(JsonRpcId::Null);

        let params = raw_request.get("params").unwrap_or(&Value::Null);

        debug!(
            "Processing JSON-RPC request: method={}, id={:?}",
            method, id
        );

        let response_str = match method {
            METHOD_GET_MINING_INFO => {
                let _: GetMiningInfoParams = serde_json::from_value(params.clone())
                    .map_err(|e| ProtocolError::InvalidParams(e.to_string()))?;

                match self.handler.get_mining_info(auth_token).await {
                    Ok(mining_info) => {
                        let response = JsonRpcResponse::success(mining_info, id);
                        serde_json::to_string(&response).map_err(ProtocolError::JsonError)?
                    }
                    Err(err) => {
                        let response: JsonRpcResponse<()> =
                            JsonRpcResponse::error(err.to_json_rpc_error(), id);
                        serde_json::to_string(&response).map_err(ProtocolError::JsonError)?
                    }
                }
            }
            METHOD_SUBMIT_NONCE => {
                let submit_params: SubmitNonceParams = serde_json::from_value(params.clone())
                    .map_err(|e| ProtocolError::InvalidParams(e.to_string()))?;

                self.validate_submit_nonce_params(&submit_params)?;

                match self.handler.submit_nonce(submit_params, auth_token).await {
                    Ok(submit_result) => {
                        let response = JsonRpcResponse::success(submit_result, id);
                        serde_json::to_string(&response).map_err(ProtocolError::JsonError)?
                    }
                    Err(err) => {
                        let response: JsonRpcResponse<()> =
                            JsonRpcResponse::error(err.to_json_rpc_error(), id);
                        serde_json::to_string(&response).map_err(ProtocolError::JsonError)?
                    }
                }
            }
            _ => {
                let response: JsonRpcResponse<()> =
                    JsonRpcResponse::error(errors::method_not_found(method), id);
                serde_json::to_string(&response).map_err(ProtocolError::JsonError)?
            }
        };

        Ok(response_str)
    }

    async fn handle_batch_request(&self, batch: Value, auth_token: Option<&str>) -> Result<String> {
        let requests = batch
            .as_array()
            .ok_or_else(|| ProtocolError::InvalidRequest("Invalid batch format".to_string()))?;

        if requests.is_empty() {
            return Err(ProtocolError::InvalidRequest(
                "Empty batch request".to_string(),
            ));
        }

        let mut responses = Vec::new();

        for request in requests {
            match self
                .handle_single_request(request.clone(), auth_token)
                .await
            {
                Ok(response_str) => {
                    if let Ok(response_value) = serde_json::from_str::<Value>(&response_str) {
                        responses.push(response_value);
                    } else {
                        error!("Failed to parse response as JSON");
                    }
                }
                Err(err) => {
                    warn!("Batch request item failed: {}", err);
                    let error_response: JsonRpcResponse<()> =
                        JsonRpcResponse::error(err.to_json_rpc_error(), JsonRpcId::Null);
                    if let Ok(error_value) = serde_json::to_value(error_response) {
                        responses.push(error_value);
                    }
                }
            }
        }

        serde_json::to_string(&responses).map_err(ProtocolError::JsonError)
    }

    fn validate_submit_nonce_params(&self, params: &SubmitNonceParams) -> Result<()> {
        if params.account_id.len() != 40 {
            return Err(ProtocolError::InvalidParams(
                "account_id must be exactly 40 hex characters".to_string(),
            ));
        }

        if !params.account_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ProtocolError::InvalidParams(
                "account_id must contain only hex characters".to_string(),
            ));
        }

        if params.generation_signature.is_empty() {
            return Err(ProtocolError::InvalidParams(
                "generation_signature cannot be empty".to_string(),
            ));
        }

        if !params
            .generation_signature
            .chars()
            .all(|c| c.is_ascii_hexdigit())
        {
            return Err(ProtocolError::InvalidParams(
                "generation_signature must contain only hex characters".to_string(),
            ));
        }

        if params.seed.is_empty() {
            return Err(ProtocolError::InvalidParams(
                "seed cannot be empty".to_string(),
            ));
        }

        // Compression validation removed - handled by validator automatically

        Ok(())
    }
}

pub fn extract_auth_token(auth_header: Option<&str>) -> Option<String> {
    auth_header
        .and_then(|header| header.strip_prefix("Bearer "))
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockHandler;

    #[async_trait]
    impl JsonRpcHandler for MockHandler {
        async fn get_mining_info(&self, _auth_token: Option<&str>) -> Result<MiningInfo> {
            Ok(MiningInfo::new(
                "abc123".to_string(),
                12345,
                98765,
                "test_hash".to_string(),
            ))
        }

        async fn submit_nonce(
            &self,
            params: SubmitNonceParams,
            _auth_token: Option<&str>,
        ) -> Result<SubmitNonceResult> {
            if params.height != 98765 {
                return Err(ProtocolError::WrongHeight {
                    expected: 98765,
                    submitted: params.height,
                });
            }
            Ok(SubmitNonceResult::new(987654321, 240))
        }
    }

    #[tokio::test]
    async fn test_get_mining_info_request() {
        let handler = MockHandler;
        let dispatcher = JsonRpcDispatcher::new(handler);

        let request = r#"
        {
            "jsonrpc": "2.0",
            "method": "get_mining_info",
            "params": {},
            "id": "test-id"
        }
        "#;

        let response = dispatcher.handle_request(request, None).await;
        let response_value: Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response_value["jsonrpc"], "2.0");
        assert_eq!(response_value["id"], "test-id");
        assert_eq!(response_value["result"]["generation_signature"], "abc123");
        assert_eq!(response_value["result"]["base_target"], 12345);
        assert_eq!(response_value["result"]["height"], 98765);
    }

    #[tokio::test]
    async fn test_submit_nonce_request() {
        let handler = MockHandler;
        let dispatcher = JsonRpcDispatcher::new(handler);

        let request = r#"
        {
            "jsonrpc": "2.0",
            "method": "submit_nonce",
            "params": {
                "height": 98765,
                "generation_signature": "abc123",
                "account_id": "1234567890abcdef1234567890abcdef12345678",
                "seed": "seed123",
                "nonce": 123456789,
                "compression_level": 4
            },
            "id": "test-id"
        }
        "#;

        let response = dispatcher.handle_request(request, None).await;
        let response_value: Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response_value["jsonrpc"], "2.0");
        assert_eq!(response_value["id"], "test-id");
        assert_eq!(response_value["result"]["quality"], 987654321);
        assert_eq!(response_value["result"]["poc_time"], 240);
    }

    #[tokio::test]
    async fn test_wrong_height_error() {
        let handler = MockHandler;
        let dispatcher = JsonRpcDispatcher::new(handler);

        let request = r#"
        {
            "jsonrpc": "2.0",
            "method": "submit_nonce",
            "params": {
                "height": 99999,
                "generation_signature": "abc123",
                "account_id": "1234567890abcdef1234567890abcdef12345678",
                "seed": "seed123",
                "nonce": 123456789,
                "compression_level": 4
            },
            "id": "test-id"
        }
        "#;

        let response = dispatcher.handle_request(request, None).await;
        let response_value: Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response_value["jsonrpc"], "2.0");
        assert_eq!(response_value["id"], "test-id");
        assert_eq!(response_value["error"]["code"], -32002);
        assert_eq!(response_value["error"]["data"]["expected"], 98765);
        assert_eq!(response_value["error"]["data"]["submitted"], 99999);
    }

    #[tokio::test]
    async fn test_invalid_method() {
        let handler = MockHandler;
        let dispatcher = JsonRpcDispatcher::new(handler);

        let request = r#"
        {
            "jsonrpc": "2.0",
            "method": "unknown_method",
            "params": {},
            "id": "test-id"
        }
        "#;

        let response = dispatcher.handle_request(request, None).await;
        let response_value: Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response_value["jsonrpc"], "2.0");
        assert_eq!(response_value["id"], "test-id");
        assert_eq!(response_value["error"]["code"], -32601);
        assert_eq!(response_value["error"]["message"], "Method not found");
    }

    #[test]
    fn test_extract_auth_token() {
        assert_eq!(
            extract_auth_token(Some("Bearer abc123")),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_auth_token(Some("Bearer   xyz789   ")),
            Some("xyz789".to_string())
        );
        assert_eq!(extract_auth_token(Some("Basic abc123")), None);
        assert_eq!(extract_auth_token(Some("Bearer")), None);
        assert_eq!(extract_auth_token(Some("")), None);
        assert_eq!(extract_auth_token(None), None);
    }

    #[tokio::test]
    async fn test_validation_errors() {
        let handler = MockHandler;
        let dispatcher = JsonRpcDispatcher::new(handler);

        // Test invalid account_id length
        let request = r#"
        {
            "jsonrpc": "2.0",
            "method": "submit_nonce",
            "params": {
                "height": 98765,
                "generation_signature": "abc123",
                "account_id": "invalid",
                "seed": "seed123",
                "nonce": 123456789,
                "compression_level": 4
            },
            "id": "test-id"
        }
        "#;

        let response = dispatcher.handle_request(request, None).await;
        let response_value: Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response_value["error"]["code"], -32602);
        assert!(response_value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Invalid params"));
    }
}
