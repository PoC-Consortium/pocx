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

use reqwest::{header, Client, ClientBuilder};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;
use tracing::{debug, error, trace};

use crate::protocol::{
    errors::{ProtocolError, Result},
    types::{
        GetMiningInfoParams, JsonRpcId, JsonRpcRequest, JsonRpcResponse, MiningInfo,
        SubmitNonceParams, SubmitNonceResult, METHOD_GET_MINING_INFO, METHOD_SUBMIT_NONCE,
    },
};

#[derive(Debug, Clone)]
pub struct JsonRpcClient {
    client: Client,
    base_url: String,
    auth_token: Option<String>,
    timeout: Duration,
}

impl JsonRpcClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static("PoCX-Miner/1.0.0"),
        );

        let client = ClientBuilder::new()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(ProtocolError::NetworkError)?;

        Ok(Self {
            client,
            base_url: base_url.into(),
            auth_token: None,
            timeout: Duration::from_secs(30),
        })
    }

    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn set_auth_token(&mut self, token: Option<String>) {
        self.auth_token = token;
    }

    pub async fn get_mining_info(&self) -> Result<MiningInfo> {
        let params = GetMiningInfoParams::default();
        self.request(METHOD_GET_MINING_INFO, params).await
    }

    pub async fn submit_nonce(&self, params: SubmitNonceParams) -> Result<SubmitNonceResult> {
        self.request(METHOD_SUBMIT_NONCE, params).await
    }

    pub async fn request<P, R>(&self, method: &str, params: P) -> Result<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let id = JsonRpcId::new();
        let request = JsonRpcRequest::with_id(method, params, id.clone());

        trace!("Sending JSON-RPC request: method={}, id={:?}", method, id);

        let mut req_builder = self
            .client
            .post(&self.base_url)
            .timeout(self.timeout)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request);

        if let Some(ref token) = self.auth_token {
            req_builder = req_builder.header(header::AUTHORIZATION, format!("Bearer {}", token));
        }

        let response = req_builder
            .send()
            .await
            .map_err(ProtocolError::NetworkError)?;

        if !response.status().is_success() {
            error!("HTTP error: {} {}", response.status(), response.url());
            return Err(ProtocolError::Other(format!(
                "HTTP error: {} {}",
                response.status(),
                response.url()
            )));
        }

        let response_text = response.text().await.map_err(ProtocolError::NetworkError)?;

        trace!("Received JSON-RPC response: {}", response_text);

        let json_response: JsonRpcResponse<R> =
            serde_json::from_str(&response_text).map_err(ProtocolError::JsonError)?;

        match json_response {
            JsonRpcResponse::Success { result, .. } => {
                debug!("JSON-RPC request successful: method={}", method);
                Ok(result)
            }
            JsonRpcResponse::Error { error, .. } => {
                error!(
                    "JSON-RPC error: method={}, code={}, message={}",
                    method, error.code, error.message
                );

                match error.code {
                    crate::protocol::errors::WRONG_HEIGHT => {
                        if let Some(data) = error.data {
                            if let (Some(expected), Some(submitted)) =
                                (data.get("expected"), data.get("submitted"))
                            {
                                return Err(ProtocolError::WrongHeight {
                                    expected: expected.as_u64().unwrap_or(0),
                                    submitted: submitted.as_u64().unwrap_or(0),
                                });
                            }
                        }
                        Err(ProtocolError::InvalidSubmission(error.message))
                    }
                    crate::protocol::errors::STALE_SUBMISSION => {
                        Err(ProtocolError::StaleSubmission)
                    }
                    crate::protocol::errors::AUTH_REQUIRED => Err(ProtocolError::AuthRequired),
                    crate::protocol::errors::AUTH_INVALID => Err(ProtocolError::AuthInvalid),
                    crate::protocol::errors::RATE_LIMITED => Err(ProtocolError::RateLimited),
                    crate::protocol::errors::PARSE_ERROR => {
                        Err(ProtocolError::ParseError(error.message))
                    }
                    crate::protocol::errors::INVALID_REQUEST => {
                        Err(ProtocolError::InvalidRequest(error.message))
                    }
                    crate::protocol::errors::METHOD_NOT_FOUND => {
                        Err(ProtocolError::MethodNotFound(error.message))
                    }
                    crate::protocol::errors::INVALID_PARAMS => {
                        Err(ProtocolError::InvalidParams(error.message))
                    }
                    crate::protocol::errors::INTERNAL_ERROR => {
                        Err(ProtocolError::InternalError(error.message))
                    }
                    crate::protocol::errors::INVALID_SUBMISSION => {
                        Err(ProtocolError::InvalidSubmission(error.message))
                    }
                    _ => Err(ProtocolError::Other(format!(
                        "Unknown error code {}: {}",
                        error.code, error.message
                    ))),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use serde_json::json;

    #[tokio::test]
    async fn test_client_creation() {
        let client = JsonRpcClient::new("http://localhost:8080/jsonrpc").unwrap();
        assert_eq!(client.base_url, "http://localhost:8080/jsonrpc");
        assert!(client.auth_token.is_none());
    }

    #[tokio::test]
    async fn test_client_with_auth() {
        let client = JsonRpcClient::new("http://localhost:8080/jsonrpc")
            .unwrap()
            .with_auth_token("test-token");
        assert_eq!(client.auth_token, Some("test-token".to_string()));
    }

    #[tokio::test]
    async fn test_get_mining_info_success() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/jsonrpc")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "result": {
                        "generation_signature": "abc123",
                        "base_target": 12345,
                        "height": 98765,
                        "block_hash": "test_hash",
                        "minimum_compression_level": 1,
                        "target_compression_level": 9
                    },
                    "id": "test-id"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let client = JsonRpcClient::new(server.url() + "/jsonrpc").unwrap();
        let result = client.get_mining_info().await.unwrap();

        assert_eq!(result.generation_signature, "abc123");
        assert_eq!(result.base_target, 12345);
        assert_eq!(result.height, 98765);
        assert_eq!(result.minimum_compression_level, Some(1));
        assert_eq!(result.target_compression_level, Some(9));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_submit_nonce_success() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/jsonrpc")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "result": {
                        "quality": 987654321,
                        "poc_time": 240
                    },
                    "id": "test-id"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let client = JsonRpcClient::new(server.url() + "/jsonrpc").unwrap();
        let params = SubmitNonceParams::new(
            98765,
            "abc123".to_string(),
            "1234567890abcdef1234567890abcdef12345678".to_string(),
            "seed123".to_string(),
            123456789,
        );

        let result = client.submit_nonce(params).await.unwrap();

        assert_eq!(result.quality, 987654321);
        assert_eq!(result.poc_time, 240);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_error_response() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/jsonrpc")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32002,
                        "message": "Wrong height",
                        "data": {
                            "reason": "wrong_height",
                            "expected": 100,
                            "submitted": 99
                        }
                    },
                    "id": "test-id"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let client = JsonRpcClient::new(server.url() + "/jsonrpc").unwrap();
        let params = SubmitNonceParams::new(
            99,
            "abc123".to_string(),
            "1234567890abcdef1234567890abcdef12345678".to_string(),
            "seed123".to_string(),
            123456789,
        );

        let result = client.submit_nonce(params).await;

        match result {
            Err(ProtocolError::WrongHeight {
                expected,
                submitted,
            }) => {
                assert_eq!(expected, 100);
                assert_eq!(submitted, 99);
            }
            _ => panic!("Expected WrongHeight error"),
        }

        mock.assert_async().await;
    }
}
