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

use clap::Parser;
use log::{error, info};
use pocx_aggregator::{config::Config, dashboard, server::AggregatorServer};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "pocx_aggregator")]
#[command(about = "High-performance mining aggregator for PoCX protocol", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "aggregator_config.yaml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging
    if let Err(e) = pocx_aggregator::logging::init() {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    info!("Starting PoCX Aggregator v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = match Config::from_file(&args.config) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration from {:?}: {}", args.config, e);
            std::process::exit(1);
        }
    };

    info!("Loaded configuration from {:?}", args.config);
    info!("Listening on {}", config.server.listen_address);
    info!(
        "Upstream: {} ({})",
        config.upstream.name,
        config.upstream.endpoint()
    );

    // Create the aggregator server
    let server = match AggregatorServer::new(config.clone()).await {
        Ok(server) => server,
        Err(e) => {
            error!("Failed to create aggregator server: {}", e);
            std::process::exit(1);
        }
    };

    // Start dashboard if enabled (shares stats with main server)
    let dashboard_handle = if let Some(ref dashboard_config) = config.dashboard {
        if dashboard_config.enabled {
            info!("Starting dashboard on {}", dashboard_config.listen_address);
            let stats_clone = server.stats().clone();
            let listen_addr = dashboard_config.listen_address.clone();
            Some(tokio::spawn(async move {
                dashboard::run_dashboard(&listen_addr, stats_clone).await;
            }))
        } else {
            None
        }
    } else {
        None
    };

    // Run the server
    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }

    // Wait for dashboard to finish if it's running
    if let Some(handle) = dashboard_handle {
        let _ = handle.await;
    }
}
