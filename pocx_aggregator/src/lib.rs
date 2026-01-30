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

//! PoCX Aggregator - High-performance mining aggregator
//!
//! The aggregator acts as a proxy between miners and mining pools,
//! providing load balancing, failover, and efficient caching of mining
//! information.

pub mod callback;
pub mod config;
pub mod control;
pub mod dashboard;
pub mod db;
pub mod error;
pub mod logging;
pub mod pool;
pub mod queue;
pub mod schema;
pub mod server;
pub mod stats;
pub mod time_bending;

// Re-export core types
pub use config::Config;
pub use error::{Error, Result};
pub use server::AggregatorServer;
pub use stats::{Stats, StatsSnapshot};

// Re-export callback system
pub use callback::{
    get_aggregator_callback, set_aggregator_callback, with_callback, AcceptedInfo,
    AggregatorCallback, AggregatorStartedInfo, BlockUpdate, ForwardedInfo, NoOpCallback,
    RejectedInfo, SubmissionInfo,
};

// Re-export control system
pub use control::{clear_stop_request, is_stop_requested, request_stop};

/// Run the aggregator with panic safety and callback error reporting.
///
/// Clears any previous stop request, runs the server, and fires
/// `on_stopped()` / `on_error()` callbacks on completion.
pub async fn run_aggregator_safe(config: Config) -> Result<()> {
    clear_stop_request();

    let result = std::panic::AssertUnwindSafe(async {
        let server = AggregatorServer::new(config).await?;
        server.run().await
    });

    match futures::FutureExt::catch_unwind(result).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            callback::with_callback(|cb| cb.on_error(&e.to_string()));
            Err(e)
        }
        Err(panic) => {
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            callback::with_callback(|cb| cb.on_error(&format!("Aggregator panicked: {}", msg)));
            Err(Error::Server(format!("Aggregator panicked: {}", msg)))
        }
    }
}
