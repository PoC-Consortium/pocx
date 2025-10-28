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

mod cache;
mod config;
mod db;
mod json_rpc_handler;
mod mining_info;
mod models;
mod schema;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::post,
    Router,
};
use config::PoCXConfig;
use db::DB;
use dotenvy::dotenv;
use futures::channel::oneshot::Sender;
use json_rpc_handler::MockchainJsonRpcHandler;
use pocx_protocol::{extract_auth_token, JsonRpcDispatcher};
use serde::Serialize;
use std::env;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct AppState {
    db: Arc<DB>,
    config: Arc<PoCXConfig>,
    tripwire: Arc<Mutex<Option<Sender<()>>>>,
    best_quality: Arc<Mutex<u64>>,
}

#[derive(Debug, Serialize, Clone)]
struct ErrorResponse {
    pub message: String,
}

async fn handle_jsonrpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let body_str = std::str::from_utf8(&body).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                message: "Invalid UTF-8 in request body".to_string(),
            }),
        )
    })?;

    // Extract auth token from Authorization header
    let auth_token = headers
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header_str| extract_auth_token(Some(header_str)));

    // Create JSON-RPC handler and dispatcher
    let handler = MockchainJsonRpcHandler::new(
        state.db.clone(),
        state.config.clone(),
        state.tripwire.clone(),
        state.best_quality.clone(),
    );
    let dispatcher = JsonRpcDispatcher::new(handler);

    // Handle the JSON-RPC request
    let response = dispatcher
        .handle_request(body_str, auth_token.as_deref())
        .await;

    Ok(response)
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Load PoCX Mockchain configuration
    let config = Arc::new(match PoCXConfig::load() {
        Ok(config) => {
            println!("🚀 PoCX Mockchain - {} Network", config.network.name);
            println!("   Network ID: {}", config.network.network_id);
            println!(
                "   Compression Range: {} to {} (2^{} to 2^{} density)",
                config.network.minimum_compression_level,
                config.network.target_compression_level,
                config.network.minimum_compression_level,
                config.network.target_compression_level
            );
            println!("   Server: {}:{}", config.server.host, config.server.port);
            config
        }
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            eprintln!("Creating sample configuration files...");
            if let Err(sample_err) = PoCXConfig::create_sample_config() {
                eprintln!("Failed to create sample config: {}", sample_err);
            }
            eprintln!("Please configure mockchain_config.toml or set environment variables.");
            std::process::exit(1);
        }
    });

    // Use configuration for server address
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let addr: std::net::SocketAddr = addr
        .parse()
        .expect("Invalid server host/port configuration");

    // Use configuration for database URL (with fallback to env var for
    // compatibility)
    let dsn = env::var("DATABASE_URL").unwrap_or_else(|_| config.database.url.clone());

    let state = AppState {
        db: Arc::new(DB::new(&dsn, config.clone())),
        config: config.clone(),
        tripwire: Arc::new(Mutex::new(None)),
        best_quality: Arc::new(Mutex::new(u64::MAX)),
    };

    let app = Router::new()
        .route("/pocx", post(handle_jsonrpc))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("❌ Failed to bind to address {}: {}", addr, e);
            eprintln!("   Please check that the port is not already in use");
            std::process::exit(1);
        });
    println!(
        "🌐 Mockchain listening on {} (Network: {})",
        addr, config.network.name
    );

    axum::serve(listener, app).await.unwrap_or_else(|e| {
        eprintln!("❌ Server error: {}", e);
        std::process::exit(1);
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_address_payload_validation() {
        // Test the new payload-only validation approach

        let test_payload = [42u8; 20];
        let payload_hex = hex::encode(test_payload);

        // Test valid 40-character hex payload
        assert_eq!(payload_hex.len(), 40, "Payload should be 40 hex characters");

        // Test that hex decoding works
        let decoded = hex::decode(&payload_hex).unwrap();
        assert_eq!(decoded.len(), 20, "Decoded payload should be 20 bytes");
        assert_eq!(decoded, test_payload, "Round-trip should preserve payload");

        // Test invalid hex lengths
        let short_payload = "1234567890abcdef"; // 16 chars = 8 bytes
        let long_payload = "1234567890abcdef1234567890abcdef1234567890abcdef"; // 48 chars = 24 bytes

        assert_ne!(
            short_payload.len(),
            40,
            "Short payload should fail length check"
        );
        assert_ne!(
            long_payload.len(),
            40,
            "Long payload should fail length check"
        );
    }
}
