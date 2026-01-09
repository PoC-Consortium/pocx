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

use clap::{Arg, Command};

const CRATE_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

macro_rules! crate_description {
    () => {
        CRATE_DESCRIPTION
    };
}
use log::info;

#[macro_use]
extern crate log;
#[macro_use]
extern crate cfg_if;

mod buffer;
mod callback;
mod com;
mod compression;
mod config;
mod control;
mod future;
mod hasher;
mod logger;
mod miner;
mod plots;
mod request;
mod utils;

use crate::config::load_cfg;
use crate::miner::Miner;

#[tokio::main]
async fn main() {
    let arg = Command::new("PoCX Miner")
        .version(env!("CARGO_PKG_VERSION"))
        .about(crate_description!())
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Location of the config file")
                .default_value("miner_config.yaml"),
        )
        .arg(
            Arg::new("line-progress")
                .long("line-progress")
                .action(clap::ArgAction::SetTrue)
                .help("Enable machine-parsable progress protocol for GUI")
                .hide(true),
        );

    let matches = arg.get_matches();
    let config = matches.get_one::<String>("config").unwrap();
    let line_progress = matches.get_flag("line-progress");
    let mut cfg_loaded = load_cfg(config);

    // CLI flag overrides config file
    if line_progress {
        cfg_loaded.line_progress = true;
        // Mutual exclusivity: line_progress disables show_progress
        cfg_loaded.show_progress = false;
    }
    logger::init_logger(&cfg_loaded);

    info!("PoCX Miner {}", env!("CARGO_PKG_VERSION"));
    info!("{}", crate_description!());

    let m = Miner::new(cfg_loaded);
    m.run().await;
}
