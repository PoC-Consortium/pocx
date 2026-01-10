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

use crate::config::{Config, RpcServerAuth};
use crate::db::Database;
use crate::error::{Error, Result};
use crate::pool::PoolManager;
use crate::stats::Stats;
use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::{debug, error, info, warn};
use pocx_protocol::{
    JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse, MiningInfo, SubmitNonceParams,
    SubmitNonceResult, METHOD_GET_MINING_INFO, METHOD_SUBMIT_NONCE,
};
use serde_json::Value;
use std::net::SocketAddr;

/// Main aggregator server
pub struct AggregatorServer {
    config: Config,
    pool_manager: PoolManager,
    stats: Stats,
    database: Database,
}

impl AggregatorServer {
    pub fn stats(&self) -> &Stats {
        &self.stats
    }
}

#[derive(Clone)]
struct AppState {
    pool_manager: PoolManager,
    stats: Stats,
    current_base_target: Arc<RwLock<u64>>, // Track current base target from mining info
    current_block_hash: Arc<RwLock<String>>, // Track current block hash for submissions
    database: Database,
    current_height: Arc<RwLock<u64>>, // Track current height for submissions
    retention_blocks: u64,            // Database retention period in blocks (0 = keep forever)
    server_auth: RpcServerAuth,       // Authentication config for downstream connections
}

use std::sync::Arc;
use tokio::sync::RwLock;

impl AggregatorServer {
    /// Create a new aggregator server
    pub async fn new(config: Config) -> Result<Self> {
        let pool_manager = PoolManager::new(
            &config.upstream,
            config.cache.mining_info_ttl_secs,
            config.cache.pool_timeout_secs,
        )?;

        // Create stats with block time from config
        let stats = Stats::new(config.block_time_secs);

        // Initialize database
        let database = Database::new(&config.database.path)?;

        // Load historical submissions to restore stats
        info!("Loading historical submissions from database...");
        match database.get_all_recent_submissions(1000) {
            Ok(submissions) => {
                info!("Loaded {} historical submissions", submissions.len());
                for sub in submissions {
                    stats
                        .record_submission(
                            &sub.account_id,
                            Some(sub.machine_id),
                            sub.quality as u64,
                            sub.base_target as u64,
                            sub.height as u64,
                        )
                        .await;
                }
                info!("Historical data loaded successfully");
            }
            Err(e) => {
                error!("Failed to load historical submissions: {}", e);
            }
        }

        Ok(Self {
            config,
            pool_manager,
            stats,
            database,
        })
    }

    /// Run the server
    pub async fn run(self) -> Result<()> {
        let retention_blocks = self.config.retention_blocks();
        let listen_address = self.config.server.listen_address.clone();
        let server_auth = self.config.server.auth.clone();

        if server_auth.is_required() {
            info!("Server authentication: ENABLED (BasicAuth)");
        } else {
            info!("Server authentication: DISABLED");
        }

        let state = AppState {
            pool_manager: self.pool_manager,
            stats: self.stats,
            current_base_target: Arc::new(RwLock::new(1)), // Will be updated from mining_info
            current_block_hash: Arc::new(RwLock::new(String::new())), /* Will be updated from
                                                            * mining_info */
            database: self.database,
            current_height: Arc::new(RwLock::new(0)), // Will be updated from mining_info
            retention_blocks,
            server_auth,
        };

        // Build the main JSON-RPC router
        let app = Router::new()
            .route("/", post(handle_jsonrpc))
            .route("/health", get(health_check))
            .route("/stats", get(get_stats))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(&listen_address)
            .await
            .map_err(|e| Error::Server(format!("Failed to bind to {}: {}", listen_address, e)))?;

        info!("Aggregator listening on {}", listen_address);

        // Set up graceful shutdown
        let server = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal());

        server
            .await
            .map_err(|e| Error::Server(format!("Server error: {}", e)))?;

        info!("Server shutdown complete");
        Ok(())
    }
}

/// Handle JSON-RPC requests
async fn handle_jsonrpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    let client_ip = addr.ip().to_string();
    debug!("Received JSON-RPC request: {}", request);

    // Validate authentication if required
    if state.server_auth.is_required() {
        if let Err(response) = validate_basic_auth(&headers, &state.server_auth, &client_ip) {
            return response;
        }
    }

    // Parse the method from the request
    let method = match request.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => {
            return json_rpc_error(
                JsonRpcError {
                    code: -32600,
                    message: "Invalid Request: missing method".to_string(),
                    data: None,
                },
                JsonRpcId::Null,
            );
        }
    };

    // Extract the id
    let id = request
        .get("id")
        .and_then(|id| {
            if id.is_string() {
                id.as_str().map(|s| JsonRpcId::from_string(s.to_string()))
            } else if id.is_number() {
                id.as_u64().map(JsonRpcId::from_number)
            } else {
                Some(JsonRpcId::Null)
            }
        })
        .unwrap_or(JsonRpcId::Null);

    // Route to appropriate handler
    match method {
        METHOD_GET_MINING_INFO => handle_get_mining_info(state, request, id, client_ip).await,
        METHOD_SUBMIT_NONCE => handle_submit_nonce(state, request, id, client_ip).await,
        _ => json_rpc_error(
            JsonRpcError {
                code: -32601,
                message: format!("Method not found: {}", method),
                data: None,
            },
            id,
        ),
    }
}

/// Handle get_mining_info request
async fn handle_get_mining_info(
    state: AppState,
    _request: Value,
    id: JsonRpcId,
    _client_ip: String,
) -> Response {
    match state.pool_manager.get_mining_info().await {
        Ok(info) => {
            // Update stats with current height and base target
            state.stats.update_height(info.height).await;
            state.stats.update_base_target(info.base_target).await;

            // Store current base_target for capacity estimation
            *state.current_base_target.write().await = info.base_target;

            // Store current block_hash for submission filtering
            *state.current_block_hash.write().await = info.block_hash.clone();

            // Store current height for submissions
            let old_height = *state.current_height.read().await;
            *state.current_height.write().await = info.height;

            // Cleanup old database entries when height changes
            if info.height != old_height && state.retention_blocks > 0 {
                if let Err(e) = state
                    .database
                    .cleanup_old_submissions(info.height, state.retention_blocks)
                {
                    error!("Failed to cleanup old submissions: {}", e);
                }
            }

            let response: JsonRpcResponse<MiningInfo> = JsonRpcResponse::success(info, id);
            Json(response).into_response()
        }
        Err(e) => {
            error!("Failed to get mining info: {}", e);
            json_rpc_error(
                JsonRpcError {
                    code: -32000,
                    message: "Failed to get mining info".to_string(),
                    data: Some(serde_json::json!({ "error": e.to_string() })),
                },
                id,
            )
        }
    }
}

/// Handle submit_nonce request
async fn handle_submit_nonce(
    state: AppState,
    request: Value,
    id: JsonRpcId,
    client_ip: String,
) -> Response {
    // Parse the request
    let req: JsonRpcRequest<SubmitNonceParams> = match serde_json::from_value(request) {
        Ok(r) => r,
        Err(e) => {
            return json_rpc_error(
                JsonRpcError {
                    code: -32600,
                    message: "Invalid Request".to_string(),
                    data: Some(serde_json::json!({ "error": e.to_string() })),
                },
                id,
            );
        }
    };

    // Get current block_hash for submission filtering
    let block_hash = state.current_block_hash.read().await.clone();

    // Submit to pool with block_hash for filtering
    match state
        .pool_manager
        .submit_nonce(req.params.clone(), block_hash)
        .await
    {
        Ok(mut result) => {
            // Get current base_target and height
            let base_target = *state.current_base_target.read().await;
            let height = *state.current_height.read().await;

            // Use client IP as machine identifier
            let machine_id = Some(client_ip);

            // Calculate poc_time using time-bending formula
            // Note: result.quality is adjusted quality (raw_quality / base_target)
            // The time-bending formula expects raw quality, so multiply back
            let raw_quality = result.quality * base_target;
            let poc_time = state.stats.calculate_poc_time(raw_quality, base_target);
            result.poc_time = poc_time;

            // Update stats (without poc_time, it's calculated on display)
            state
                .stats
                .record_submission(
                    &req.params.account_id,
                    machine_id.clone(),
                    result.quality,
                    base_target,
                    height,
                )
                .await;

            // Save to database (queued in dedicated writer task)
            if let Err(e) = state.database.save_submission(
                &req.params.account_id,
                machine_id,
                result.quality,
                base_target,
                height,
            ) {
                error!("Failed to queue submission save: {}", e);
            }

            let response: JsonRpcResponse<SubmitNonceResult> = JsonRpcResponse::success(result, id);
            Json(response).into_response()
        }
        Err(e) => {
            error!("Failed to submit nonce: {}", e);
            json_rpc_error(
                JsonRpcError {
                    code: -32000,
                    message: "Failed to submit nonce".to_string(),
                    data: Some(serde_json::json!({ "error": e.to_string() })),
                },
                id,
            )
        }
    }
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Stats endpoint
async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    let snapshot = state.stats.snapshot().await;
    Json(snapshot)
}

/// Helper to create JSON-RPC error response
fn json_rpc_error(error: JsonRpcError, id: JsonRpcId) -> Response {
    let response: JsonRpcResponse<()> = JsonRpcResponse::error(error, id);
    (StatusCode::OK, Json(response)).into_response()
}

/// Validate Basic Auth credentials from request headers
#[allow(clippy::result_large_err)]
fn validate_basic_auth(
    headers: &HeaderMap,
    auth_config: &RpcServerAuth,
    client_ip: &str,
) -> std::result::Result<(), Response> {
    let auth_header = headers.get(header::AUTHORIZATION);

    let auth_value = match auth_header {
        Some(value) => value.to_str().unwrap_or(""),
        None => {
            warn!(
                "Auth required but no Authorization header from {}",
                client_ip
            );
            return Err(json_rpc_error(
                JsonRpcError {
                    code: -32004,
                    message: "Authentication required".to_string(),
                    data: None,
                },
                JsonRpcId::Null,
            ));
        }
    };

    // Parse "Basic <base64(user:pass)>" format
    if !auth_value.starts_with("Basic ") {
        warn!("Invalid auth scheme from {}", client_ip);
        return Err(json_rpc_error(
            JsonRpcError {
                code: -32005,
                message: "Invalid authentication scheme".to_string(),
                data: None,
            },
            JsonRpcId::Null,
        ));
    }

    let encoded = &auth_value[6..];
    let decoded = match STANDARD.decode(encoded) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => {
            warn!("Invalid base64 in auth header from {}", client_ip);
            return Err(json_rpc_error(
                JsonRpcError {
                    code: -32005,
                    message: "Invalid authentication credentials".to_string(),
                    data: None,
                },
                JsonRpcId::Null,
            ));
        }
    };

    // Split username:password
    let parts: Vec<&str> = decoded.splitn(2, ':').collect();
    if parts.len() != 2 {
        warn!("Malformed credentials from {}", client_ip);
        return Err(json_rpc_error(
            JsonRpcError {
                code: -32005,
                message: "Invalid authentication credentials".to_string(),
                data: None,
            },
            JsonRpcId::Null,
        ));
    }

    let (username, password) = (parts[0], parts[1]);

    if auth_config.validate_credentials(username, password) {
        debug!("Auth successful for user '{}' from {}", username, client_ip);
        Ok(())
    } else {
        warn!("Auth failed for user '{}' from {}", username, client_ip);
        Err(json_rpc_error(
            JsonRpcError {
                code: -32005,
                message: "Invalid authentication credentials".to_string(),
                data: None,
            },
            JsonRpcId::Null,
        ))
    }
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, shutting down gracefully...");
        },
        _ = terminate => {
            info!("Received SIGTERM, shutting down gracefully...");
        },
    }
}
