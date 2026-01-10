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

//! PoCX Miner Library
//!
//! This crate provides the core mining functionality for PoCX cryptocurrency.
//! It can be used as a library for integration into applications like Phoenix wallet,
//! or as a standalone binary via the pocx_miner executable.
//!
//! # Library Usage
//!
//! ```ignore
//! use pocx_miner::{CfgBuilder, Chain, Miner, MinerCallback};
//! use std::sync::Arc;
//!
//! // Create a custom callback
//! struct MyCallback;
//! impl MinerCallback for MyCallback {
//!     fn on_started(&self, info: &MinerStartedInfo) {
//!         println!("Miner started!");
//!     }
//! }
//!
//! // Build configuration programmatically
//! let cfg = CfgBuilder::new()
//!     .add_chain(chain)
//!     .add_plot_dir("/path/to/plots")
//!     .cpu_threads(4)
//!     .build();
//!
//! // Set callback before creating miner
//! set_miner_callback(Arc::new(MyCallback));
//!
//! // Create and run miner
//! let miner = Miner::new(cfg);
//! miner.run().await;
//! ```

#[macro_use]
extern crate log;
#[macro_use]
extern crate cfg_if;

mod buffer;
pub mod callback;
mod com;
mod compression;
pub mod config;
pub mod control;
mod future;
mod hasher;
pub mod logger;
pub mod miner;
mod plots;
mod request;
mod utils;

// Re-export main types for library usage
pub use config::{Benchmark, Cfg, CfgBuilder};
pub use miner::{genesis_base_target, Chain, Miner, RpcAuth, RpcTransport, SubmissionMode};

// Re-export callback system
pub use callback::{
    get_miner_callback, set_miner_callback, with_callback, AcceptedDeadline, BlockInfo,
    CapacityInfo, MinerCallback, MinerStartedInfo, NoOpCallback, QueueItem, ScanStartedInfo,
    ScanStatus,
};

// Re-export control system
pub use control::{clear_stop_request, is_stop_requested, request_stop};
