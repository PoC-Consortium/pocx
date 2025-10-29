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

use crate::stats::Stats;
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use log::info;

#[derive(Clone)]
pub struct DashboardState {
    pub stats: Stats,
}

pub fn create_dashboard_router(stats: Stats) -> Router {
    let state = DashboardState { stats };

    Router::new()
        .route("/", get(serve_dashboard))
        .route("/stats", get(get_stats))
        .with_state(state)
}

async fn serve_dashboard(State(_state): State<DashboardState>) -> impl IntoResponse {
    Html(include_str!("dashboard.html"))
}

async fn get_stats(State(state): State<DashboardState>) -> impl IntoResponse {
    let snapshot = state.stats.snapshot().await;
    Json(snapshot)
}

pub async fn run_dashboard(listen_addr: &str, stats: Stats) {
    let app = create_dashboard_router(stats);

    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("Failed to bind dashboard to {}: {}", listen_addr, e);
            return;
        }
    };

    info!("Dashboard listening on {}", listen_addr);

    if let Err(e) = axum::serve(listener, app).await {
        log::error!("Dashboard server error: {}", e);
    }
}
