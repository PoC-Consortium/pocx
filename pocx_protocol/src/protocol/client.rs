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

use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::{debug, error, info, trace, warn};
use reqwest::{header, Client, ClientBuilder};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::config::{RpcAuth, RpcClientConfig};
use crate::protocol::{
    errors::{ProtocolError, Result},
    types::{
        GetMiningInfoParams, JsonRpcId, JsonRpcRequest, JsonRpcResponse, MiningInfo,
        SubmitNonceParams, SubmitNonceResult, METHOD_GET_MINING_INFO, METHOD_SUBMIT_NONCE,
    },
};

/// Internal transport implementation
#[derive(Clone)]
struct Transport {
    client: Client,
    base_url: String,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport")
            .field("base_url", &self.base_url)
            .finish()
    }
}

#[derive(Clone)]
pub struct JsonRpcClient {
    transport: Transport,
    /// Current Basic-auth token (`username:password`), shared across clones so a
    /// runtime cookie re-read propagates to every handler of this connection.
    auth_token: Arc<RwLock<Option<String>>>,
    /// Authentication source, retained for runtime re-resolution (e.g. a cookie
    /// file rotated by a node restart). Only `Cookie` is re-read on auth failure.
    auth_source: Option<RpcAuth>,
    timeout: Duration,
    /// Optional `X-Miner` header value sent on every request, identifying this
    /// miner instance to a pool/aggregator. `None` = header omitted.
    miner_tag: Option<header::HeaderValue>,
}

impl std::fmt::Debug for JsonRpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let has_auth = self.auth_token.read().map(|t| t.is_some()).unwrap_or(false);
        f.debug_struct("JsonRpcClient")
            .field("transport", &self.transport)
            .field("timeout", &self.timeout)
            .field("authenticated", &has_auth)
            .finish()
    }
}

impl JsonRpcClient {
    /// Create a new HTTP-based JSON-RPC client.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into();
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
            transport: Transport { client, base_url },
            auth_token: Arc::new(RwLock::new(None)),
            auth_source: None,
            timeout: Duration::from_secs(30),
            miner_tag: None,
        })
    }

    /// Create a JSON-RPC client from configuration.
    pub fn from_config(config: &RpcClientConfig) -> Result<Self> {
        let url = config
            .build_url()
            .ok_or_else(|| ProtocolError::Other("Failed to build URL".to_string()))?;
        let client = Self::new(url)?;
        Ok(client.with_timeout(Duration::from_millis(config.timeout_ms)))
    }

    pub fn with_auth_token(self, token: impl Into<String>) -> Self {
        *self.auth_token.write().unwrap() = Some(token.into());
        self
    }

    /// Register the authentication source for runtime re-resolution.
    ///
    /// Enables re-reading a rotated cookie file and retrying once when the node
    /// rejects the cached credentials with HTTP 401 (e.g. after a node restart
    /// regenerates its `.cookie`). Non-cookie sources are never re-read.
    pub fn with_auth_source(mut self, source: RpcAuth) -> Self {
        self.auth_source = Some(source);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Attach an `X-Miner` header to every request, identifying this miner
    /// instance to a pool/aggregator (e.g. a hostname or operator-defined rig
    /// tag). An invalid value (non-printable-ASCII) is ignored with a warning,
    /// leaving the header unset.
    pub fn with_miner_tag(mut self, tag: impl AsRef<str>) -> Self {
        let tag = tag.as_ref();
        match header::HeaderValue::from_str(tag) {
            Ok(value) => self.miner_tag = Some(value),
            Err(_) => warn!(
                "Ignoring invalid X-Miner tag {:?}: must be printable ASCII",
                tag
            ),
        }
        self
    }

    pub fn set_auth_token(&self, token: Option<String>) {
        *self.auth_token.write().unwrap() = token;
    }

    /// Get the endpoint description for logging.
    pub fn endpoint(&self) -> &str {
        &self.transport.base_url
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
        self.request_http(
            &self.transport.client,
            &self.transport.base_url,
            method,
            params,
        )
        .await
    }

    /// Send request over HTTP transport.
    ///
    /// On an authentication failure (HTTP 401) the cookie file is re-read and the
    /// request retried once, transparently recovering from a node restart that
    /// rotated the `.cookie`. See [`Self::refresh_cookie_token`].
    async fn request_http<P, R>(
        &self,
        client: &Client,
        base_url: &str,
        method: &str,
        params: P,
    ) -> Result<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let id = JsonRpcId::new();
        let request = JsonRpcRequest::with_id(method, params, id.clone());

        trace!("Sending JSON-RPC request: method={}, id={:?}", method, id);

        let token = self.auth_token.read().unwrap().clone();
        match self
            .send_once(client, base_url, method, &request, &token)
            .await
        {
            Err(ProtocolError::AuthInvalid) => match self.refresh_cookie_token(&token) {
                Some(fresh) => {
                    self.send_once(client, base_url, method, &request, &Some(fresh))
                        .await
                }
                None => Err(ProtocolError::AuthInvalid),
            },
            other => other,
        }
    }

    /// Perform a single HTTP attempt with the provided auth token.
    async fn send_once<B, R>(
        &self,
        client: &Client,
        base_url: &str,
        method: &str,
        body: &B,
        token: &Option<String>,
    ) -> Result<R>
    where
        B: Serialize,
        R: DeserializeOwned,
    {
        let mut req_builder = client
            .post(base_url)
            .timeout(self.timeout)
            .header(header::CONTENT_TYPE, "application/json")
            .json(body);

        if let Some(tag) = &self.miner_tag {
            req_builder = req_builder.header("X-Miner", tag.clone());
        }

        // Use Basic auth with base64 encoding (required for Bitcoin Core RPC)
        // Token format: "username:password" (e.g., cookie content "__cookie__:randomhex")
        if let Some(token) = token {
            let encoded = STANDARD.encode(token);
            req_builder = req_builder.header(header::AUTHORIZATION, format!("Basic {}", encoded));
        }

        let response = req_builder
            .send()
            .await
            .map_err(ProtocolError::NetworkError)?;

        if !response.status().is_success() {
            let status = response.status();
            let url = response.url().clone();

            if status == reqwest::StatusCode::UNAUTHORIZED {
                error!(
                    "AUTH ERROR: 401 Unauthorized - Invalid or missing credentials for {}",
                    url
                );
                return Err(ProtocolError::AuthInvalid);
            } else if status == reqwest::StatusCode::FORBIDDEN {
                error!("AUTH ERROR: 403 Forbidden - Access denied to {}", url);
                return Err(ProtocolError::AuthRequired);
            } else {
                error!("HTTP error: {} {}", status, url);
                return Err(ProtocolError::Other(format!(
                    "HTTP error: {} {}",
                    status, url
                )));
            }
        }

        let response_text = response.text().await.map_err(ProtocolError::NetworkError)?;

        self.parse_response(&response_text, method)
    }

    /// Re-read a rotated cookie file after an authentication failure.
    ///
    /// Returns the refreshed token only when the source is cookie-based and the
    /// file content actually changed (e.g. the node restarted and regenerated its
    /// `.cookie`). On success the shared token is updated so sibling handlers of
    /// the same connection reuse it. Returns `None` for non-cookie auth, an
    /// unreadable file, or an unchanged cookie — in those cases retrying the same
    /// request would not help.
    fn refresh_cookie_token(&self, current: &Option<String>) -> Option<String> {
        match &self.auth_source {
            Some(source @ RpcAuth::Cookie { .. }) => match source.get_token() {
                Some(fresh) if Some(&fresh) != current.as_ref() => {
                    info!("Auth failed (401); cookie file rotated, retrying with refreshed token");
                    *self.auth_token.write().unwrap() = Some(fresh.clone());
                    Some(fresh)
                }
                Some(_) => {
                    warn!("Auth failed (401) but cookie file is unchanged; not retrying");
                    None
                }
                None => {
                    warn!("Auth failed (401) and cookie file could not be re-read; not retrying");
                    None
                }
            },
            _ => None,
        }
    }

    /// Parse JSON-RPC response and handle errors.
    fn parse_response<R>(&self, response_text: &str, method: &str) -> Result<R>
    where
        R: DeserializeOwned,
    {
        trace!("Received JSON-RPC response: {}", response_text);

        let json_response: JsonRpcResponse<R> =
            serde_json::from_str(response_text).map_err(ProtocolError::JsonError)?;

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
                    crate::protocol::errors::NOT_ASSIGNED => {
                        Err(ProtocolError::NotAssigned(error.message))
                    }
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
    async fn test_client_from_config() {
        let config = RpcClientConfig {
            rpc_transport: crate::config::RpcTransport::Http,
            rpc_host: "localhost".to_string(),
            rpc_port: 8080,
            rpc_auth: crate::config::RpcAuth::None,
            timeout_ms: 5000,
        };

        let client = JsonRpcClient::from_config(&config).unwrap();
        assert_eq!(client.endpoint(), "http://localhost:8080");
        assert_eq!(client.timeout, Duration::from_millis(5000));
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
                        "raw_quality": 987654321,
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
            "blockhash456".to_string(),
            98765,
            "abc123".to_string(),
            12345,
            "1234567890abcdef1234567890abcdef12345678".to_string(),
            "seed123".to_string(),
            123456789,
            5,
            987654321,
        );

        let result = client.submit_nonce(params).await.unwrap();

        assert_eq!(result.raw_quality, 987654321);
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
            "blockhash456".to_string(),
            99,
            "abc123".to_string(),
            12345,
            "1234567890abcdef1234567890abcdef12345678".to_string(),
            "seed123".to_string(),
            123456789,
            5,
            100,
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

    fn mining_info_body() -> String {
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
        .to_string()
    }

    // A stale cookie (HTTP 401) is recovered by re-reading the rotated cookie
    // file and retrying the request once with the refreshed token.
    #[tokio::test]
    async fn test_cookie_reauth_retries_with_refreshed_token() {
        let mut server = Server::new_async().await;

        let stale = "__cookie__:stale";
        let fresh = "__cookie__:fresh";
        let stale_hdr = format!("Basic {}", STANDARD.encode(stale));
        let fresh_hdr = format!("Basic {}", STANDARD.encode(fresh));

        // Cookie file on disk holds the FRESH token, as if the node rotated it.
        let path = std::env::temp_dir().join(format!("pocx_reauth_ok_{}", std::process::id()));
        std::fs::write(&path, fresh).unwrap();

        let mock_stale = server
            .mock("POST", "/jsonrpc")
            .match_header("authorization", stale_hdr.as_str())
            .with_status(401)
            .expect(1)
            .create_async()
            .await;

        let mock_fresh = server
            .mock("POST", "/jsonrpc")
            .match_header("authorization", fresh_hdr.as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mining_info_body())
            .expect(1)
            .create_async()
            .await;

        let client = JsonRpcClient::new(server.url() + "/jsonrpc")
            .unwrap()
            .with_auth_token(stale)
            .with_auth_source(RpcAuth::Cookie {
                cookie_path: Some(path.to_string_lossy().to_string()),
            });

        let result = client.get_mining_info().await.unwrap();
        assert_eq!(result.base_target, 12345);

        mock_stale.assert_async().await;
        mock_fresh.assert_async().await;
        let _ = std::fs::remove_file(&path);
    }

    // When the cookie file is unchanged, the client must not retry in a loop:
    // a single 401 is surfaced as AuthInvalid.
    #[tokio::test]
    async fn test_cookie_reauth_no_retry_when_unchanged() {
        let mut server = Server::new_async().await;

        let token = "__cookie__:same";
        let hdr = format!("Basic {}", STANDARD.encode(token));

        let path = std::env::temp_dir().join(format!("pocx_reauth_same_{}", std::process::id()));
        std::fs::write(&path, token).unwrap();

        let mock = server
            .mock("POST", "/jsonrpc")
            .match_header("authorization", hdr.as_str())
            .with_status(401)
            .expect(1)
            .create_async()
            .await;

        let client = JsonRpcClient::new(server.url() + "/jsonrpc")
            .unwrap()
            .with_auth_token(token)
            .with_auth_source(RpcAuth::Cookie {
                cookie_path: Some(path.to_string_lossy().to_string()),
            });

        let result = client.get_mining_info().await;
        assert!(matches!(result, Err(ProtocolError::AuthInvalid)));

        mock.assert_async().await;
        let _ = std::fs::remove_file(&path);
    }

    // With a miner tag configured, every request carries the `X-Miner` header.
    #[tokio::test]
    async fn test_miner_tag_sets_x_miner_header() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/jsonrpc")
            .match_header("x-miner", "rig-01")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mining_info_body())
            .expect(1)
            .create_async()
            .await;

        let client = JsonRpcClient::new(server.url() + "/jsonrpc")
            .unwrap()
            .with_miner_tag("rig-01");

        client.get_mining_info().await.unwrap();
        mock.assert_async().await;
    }

    // Without a miner tag, no `X-Miner` header is sent.
    #[tokio::test]
    async fn test_no_miner_tag_omits_x_miner_header() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/jsonrpc")
            .match_header("x-miner", mockito::Matcher::Missing)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mining_info_body())
            .expect(1)
            .create_async()
            .await;

        let client = JsonRpcClient::new(server.url() + "/jsonrpc").unwrap();

        client.get_mining_info().await.unwrap();
        mock.assert_async().await;
    }
}
