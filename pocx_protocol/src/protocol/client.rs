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
use log::{debug, error, trace};
use reqwest::{header, Client, ClientBuilder};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::time::Duration;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::config::{RpcClientConfig, RpcTransport};
use crate::protocol::{
    errors::{ProtocolError, Result},
    types::{
        GetMiningInfoParams, JsonRpcId, JsonRpcRequest, JsonRpcResponse, MiningInfo,
        SubmitNonceParams, SubmitNonceResult, METHOD_GET_MINING_INFO, METHOD_SUBMIT_NONCE,
    },
};

/// Internal transport implementation
#[derive(Clone)]
enum Transport {
    /// HTTP/HTTPS transport using reqwest
    Http { client: Client, base_url: String },
    /// IPC transport using Unix socket or Windows named pipe
    Ipc {
        path: String,
        #[cfg(unix)]
        connection: Arc<Mutex<Option<tokio::net::UnixStream>>>,
        #[cfg(windows)]
        connection: Arc<Mutex<Option<IpcConnection>>>,
    },
}

/// Windows named pipe connection wrapper
#[cfg(windows)]
struct IpcConnection {
    // Windows named pipe implementation placeholder
    // Will be implemented when needed
    _path: String,
}

#[cfg(windows)]
impl Clone for IpcConnection {
    fn clone(&self) -> Self {
        Self {
            _path: self._path.clone(),
        }
    }
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Http { base_url, .. } => {
                f.debug_struct("Http").field("base_url", base_url).finish()
            }
            Transport::Ipc { path, .. } => f.debug_struct("Ipc").field("path", path).finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct JsonRpcClient {
    transport: Transport,
    auth_token: Option<String>,
    timeout: Duration,
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
            transport: Transport::Http { client, base_url },
            auth_token: None,
            timeout: Duration::from_secs(30),
        })
    }

    /// Create a new IPC-based JSON-RPC client.
    pub fn new_ipc(path: impl Into<String>) -> Result<Self> {
        let path = path.into();

        #[cfg(unix)]
        let transport = Transport::Ipc {
            path: path.clone(),
            connection: Arc::new(Mutex::new(None)),
        };

        #[cfg(windows)]
        let transport = Transport::Ipc {
            path: path.clone(),
            connection: Arc::new(Mutex::new(None)),
        };

        #[cfg(not(any(unix, windows)))]
        return Err(ProtocolError::Other(
            "IPC transport not supported on this platform".to_string(),
        ));

        #[cfg(any(unix, windows))]
        Ok(Self {
            transport,
            auth_token: None,
            timeout: Duration::from_secs(30),
        })
    }

    /// Create a JSON-RPC client from configuration.
    pub fn from_config(config: &RpcClientConfig) -> Result<Self> {
        let client = match config.rpc_transport {
            RpcTransport::Http | RpcTransport::Https => {
                let url = config
                    .build_url()
                    .ok_or_else(|| ProtocolError::Other("Failed to build URL".to_string()))?;
                Self::new(url)?
            }
            RpcTransport::Ipc => {
                let path = config.ipc_path.as_ref().ok_or_else(|| {
                    ProtocolError::Other("IPC transport requires ipc_path".to_string())
                })?;
                Self::new_ipc(path)?
            }
        };

        Ok(client.with_timeout(Duration::from_millis(config.timeout_ms)))
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

    /// Check if this client uses IPC transport.
    pub fn is_ipc(&self) -> bool {
        matches!(self.transport, Transport::Ipc { .. })
    }

    /// Get the endpoint description for logging.
    pub fn endpoint(&self) -> &str {
        match &self.transport {
            Transport::Http { base_url, .. } => base_url,
            Transport::Ipc { path, .. } => path,
        }
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
        match &self.transport {
            Transport::Http { client, base_url } => {
                self.request_http(client, base_url, method, params).await
            }
            Transport::Ipc { path, connection } => {
                self.request_ipc(path, connection, method, params).await
            }
        }
    }

    /// Send request over HTTP transport.
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

        let mut req_builder = client
            .post(base_url)
            .timeout(self.timeout)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request);

        // Use Basic auth with base64 encoding (required for Bitcoin Core RPC)
        // Token format: "username:password" (e.g., cookie content "__cookie__:randomhex")
        if let Some(ref token) = self.auth_token {
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

    /// Send request over IPC transport (Unix socket or Windows named pipe).
    #[cfg(unix)]
    async fn request_ipc<P, R>(
        &self,
        path: &str,
        connection: &Arc<Mutex<Option<tokio::net::UnixStream>>>,
        method: &str,
        params: P,
    ) -> Result<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let id = JsonRpcId::new();
        let request = JsonRpcRequest::with_id(method, params, id.clone());

        trace!(
            "Sending JSON-RPC request over IPC: method={}, id={:?}",
            method,
            id
        );

        // Serialize request to JSON with newline delimiter
        let mut request_bytes = serde_json::to_vec(&request).map_err(ProtocolError::JsonError)?;
        request_bytes.push(b'\n');

        // Connect or reconnect if needed
        let mut conn_guard = connection.lock().await;
        let stream = if conn_guard.is_none() {
            debug!("Connecting to IPC socket: {}", path);
            let stream = tokio::time::timeout(self.timeout, tokio::net::UnixStream::connect(path))
                .await
                .map_err(|_| ProtocolError::Other(format!("IPC connection timeout: {}", path)))?
                .map_err(|e| ProtocolError::Other(format!("IPC connection failed: {}", e)))?;
            *conn_guard = Some(stream);
            conn_guard.as_mut().unwrap()
        } else {
            conn_guard.as_mut().unwrap()
        };

        // Write request
        if let Err(e) = stream.write_all(&request_bytes).await {
            // Connection may be stale, drop it and retry
            *conn_guard = None;
            return Err(ProtocolError::Other(format!("IPC write failed: {}", e)));
        }

        // Read response (line-delimited JSON)
        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();

        let read_result = tokio::time::timeout(self.timeout, reader.read_line(&mut response_line))
            .await
            .map_err(|_| ProtocolError::Other("IPC read timeout".to_string()))?;

        if let Err(e) = read_result {
            *conn_guard = None;
            return Err(ProtocolError::Other(format!("IPC read failed: {}", e)));
        }

        if response_line.is_empty() {
            *conn_guard = None;
            return Err(ProtocolError::Other(
                "IPC connection closed unexpectedly".to_string(),
            ));
        }

        self.parse_response(&response_line, method)
    }

    /// Windows IPC implementation (placeholder - to be implemented when needed)
    #[cfg(windows)]
    async fn request_ipc<P, R>(
        &self,
        path: &str,
        _connection: &Arc<Mutex<Option<IpcConnection>>>,
        method: &str,
        params: P,
    ) -> Result<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        // Windows named pipe implementation
        // For now, fall back to HTTP-style behavior or return an error
        // TODO: Implement Windows named pipe support using tokio's named_pipe module

        let _ = (path, method, params);
        Err(ProtocolError::Other(
            "Windows IPC support not yet implemented".to_string(),
        ))
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
        assert_eq!(client.endpoint(), "http://localhost:8080/jsonrpc");
        assert!(client.auth_token.is_none());
        assert!(!client.is_ipc());
    }

    #[tokio::test]
    async fn test_client_with_auth() {
        let client = JsonRpcClient::new("http://localhost:8080/jsonrpc")
            .unwrap()
            .with_auth_token("test-token");
        assert_eq!(client.auth_token, Some("test-token".to_string()));
    }

    #[tokio::test]
    async fn test_client_from_config() {
        let config = RpcClientConfig {
            rpc_transport: RpcTransport::Http,
            rpc_host: "localhost".to_string(),
            rpc_port: 8080,
            ipc_path: None,
            rpc_auth: crate::config::RpcAuth::None,
            timeout_ms: 5000,
        };

        let client = JsonRpcClient::from_config(&config).unwrap();
        assert_eq!(client.endpoint(), "http://localhost:8080");
        assert!(!client.is_ipc());
        assert_eq!(client.timeout, Duration::from_millis(5000));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_ipc_client_creation() {
        let client = JsonRpcClient::new_ipc("/tmp/test.sock").unwrap();
        assert_eq!(client.endpoint(), "/tmp/test.sock");
        assert!(client.is_ipc());
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
            5,
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
            5,
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
