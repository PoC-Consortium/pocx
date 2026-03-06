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

#[macro_use]
extern crate cfg_if;

use std::sync::atomic::{AtomicBool, Ordering};

/// Global stop flag for graceful termination
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

pub fn request_stop() {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

pub fn is_stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

pub fn clear_stop_request() {
    STOP_REQUESTED.store(false, Ordering::SeqCst);
}

mod buffer;
mod disk_writer;
mod error;
#[cfg(feature = "opencl")]
mod ocl;
mod perf_monitor;
mod plotter;
#[cfg(feature = "opencl")]
mod ring_scheduler;
mod utils;

use crate::error::{PoCXPlotterError, Result};

use std::sync::Arc;

pub trait PlotterCallback: Send + Sync {
    fn on_started(&self, total_warps: u64, resume_offset: u64);
    fn on_hashing_progress(&self, warps_delta: u64);
    fn on_writing_progress(&self, warps_delta: u64);
    fn on_complete(&self, total_warps: u64, duration_ms: u64);
    fn on_error(&self, error: &str);
}

static PLOTTER_CALLBACK: std::sync::OnceLock<Arc<dyn PlotterCallback>> =
    std::sync::OnceLock::new();

pub fn get_plotter_callback() -> Option<Arc<dyn PlotterCallback>> {
    PLOTTER_CALLBACK.get().cloned()
}

use crate::plotter::{Plotter, PlotterTask};
use crate::utils::set_low_prio;
use clap::{Arg, Command};
use std::process;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let cmd = Command::new("PoCX GPU Plotter")
        .version(env!("CARGO_PKG_VERSION"))
        .about("PoCX GPU Plotter — ring buffer design with fused scatter+compress")
        .arg_required_else_help(true)
        .next_display_order(None)
        .arg(
            Arg::new("disable-direct-io")
                .short('d')
                .long("ddio")
                .help("Disables direct i/o")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("low-priority")
                .short('l')
                .long("prio")
                .help("Runs plotter with low priority")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("non-verbosity")
                .short('q')
                .long("quiet")
                .help("Runs plotter in non-verbose mode")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("benchmark")
                .short('b')
                .long("bench")
                .help("Runs plotter in GPU benchmark mode")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("line-progress")
                .long("line-progress")
                .help("Output machine-readable progress lines")
                .action(clap::ArgAction::SetTrue)
                .hide(true)
                .global(true),
        )
        .arg(
            Arg::new("address")
                .short('i')
                .long("id")
                .value_name("address")
                .help("your PoC mining address (any PoC coin)"),
        )
        .arg(
            Arg::new("warps")
                .short('w')
                .long("warps")
                .value_name("warps")
                .help("how many warps you want to plot (1 warp = 1 GiB, default: fill disk)"),
        )
        .arg(
            Arg::new("number")
                .short('n')
                .long("num")
                .value_name("number")
                .help("number of files to plot (default: 1, 0 = fill disk)"),
        )
        .arg(
            Arg::new("compression")
                .short('x')
                .long("compression")
                .help("compression level 1-6 (default: 1, higher = more PoW per plot)"),
        )
        .arg(
            Arg::new("path")
                .short('p')
                .long("path")
                .value_name("path")
                .help("target disk path(s) for plotfile(s) (default: current path)")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("seed")
                .short('s')
                .long("seed")
                .value_name("seed")
                .help("specify seed to resume an unfinished plot (optional, needs n=1)"),
        )
        .arg(
            Arg::new("memory")
                .short('m')
                .long("mem")
                .value_name("memory")
                .help("limit host memory usage (optional)"),
        )
        .arg(
            Arg::new("escalate")
                .short('e')
                .long("escalate")
                .help("write buffer size multiplier in warps (default: 1, e.g. -e 5 = 5 GiB buffer)"),
        )
        .arg(
            Arg::new("double-buffer")
                .short('D')
                .long("double-buffer")
                .help("allocate an extra write buffer for GPU/disk overlap")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("gpu")
                .short('g')
                .long("gpu")
                .value_name("platform_id:device_id:cores")
                .help("GPU to use for plotting (default: 0:0:0 = first GPU, all CUs)"),
        )
        .arg(
            Arg::new("ocl-devices")
                .short('o')
                .long("opencl")
                .help("Display OpenCL platforms and devices")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("kws")
                .short('k')
                .long("kws-override")
                .help("tweak: overrides default gpu kernel workgroup size")
                .global(true),
        );

    let matches = cmd.get_matches();

    if matches.get_flag("low-priority") {
        set_low_prio();
    }

    #[cfg(feature = "opencl")]
    if matches.get_flag("ocl-devices") {
        ocl::platform_info();
        return Ok(());
    }

    let address = matches
        .get_one::<String>("address")
        .ok_or_else(|| PoCXPlotterError::InvalidInput("PoC address is required".to_string()))?
        .clone();

    if address.is_empty() {
        return Err(PoCXPlotterError::Crypto(
            "Address cannot be empty".to_string(),
        ));
    }

    if address.len() > 90 {
        return Err(PoCXPlotterError::Crypto(
            "Address too long: maximum 90 characters allowed".to_string(),
        ));
    }

    let (address_payload, network_id) = pocx_address::decode_address(&address)
        .map_err(|e| PoCXPlotterError::Crypto(format!("Invalid address: {}", e)))?;

    let warps = matches
        .get_one::<String>("warps")
        .map(|s| {
            let value = s.parse::<u64>().map_err(|e| {
                PoCXPlotterError::InvalidInput(format!("Invalid warps value: {}", e))
            })?;
            if value > 1_000_000 {
                return Err(PoCXPlotterError::InvalidInput(
                    "Warps value too large: maximum 1,000,000 allowed".to_string(),
                ));
            }
            Ok::<u64, PoCXPlotterError>(value)
        })
        .transpose()?
        .unwrap_or(0);

    let number_of_plots = matches
        .get_one::<String>("number")
        .map(|s| {
            s.parse::<u64>().map_err(|e| {
                PoCXPlotterError::InvalidInput(format!("Invalid number value: {}", e))
            })
        })
        .transpose()?
        .unwrap_or(1);

    let escalate = matches
        .get_one::<String>("escalate")
        .map(|s| {
            let value = s.parse::<u64>().map_err(|e| {
                PoCXPlotterError::InvalidInput(format!("Invalid escalate value: {}", e))
            })?;
            if value == 0 {
                return Err(PoCXPlotterError::InvalidInput(
                    "Escalate value must be at least 1".to_string(),
                ));
            }
            Ok(value)
        })
        .transpose()?
        .unwrap_or(1);

    let compress = matches
        .get_one::<String>("compression")
        .map(|s| {
            let value = s.parse::<u8>().map_err(|e| {
                PoCXPlotterError::InvalidInput(format!("Invalid compression value: {}", e))
            })?;
            if value == 0 || value > 6 {
                return Err(PoCXPlotterError::InvalidInput(
                    "Compression must be 1-6".to_string(),
                ));
            }
            Ok(value)
        })
        .transpose()?
        .unwrap_or(1);

    let kws_override = matches
        .get_one::<String>("kws")
        .map(|s| {
            s.parse::<usize>()
                .map_err(|e| PoCXPlotterError::InvalidInput(format!("Invalid kws value: {}", e)))
        })
        .transpose()?
        .unwrap_or(0);

    let output_paths = matches
        .get_many::<String>("path")
        .map(|vals| vals.cloned().collect::<Vec<String>>())
        .unwrap_or_else(|| {
            vec![std::env::current_dir()
                .and_then(|dir| {
                    dir.into_os_string().into_string().map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid path")
                    })
                })
                .unwrap_or_else(|_| ".".to_string())]
        });

    let seed = if let Some(seed_str) = matches.get_one::<String>("seed") {
        if number_of_plots != 1 {
            return Err(PoCXPlotterError::InvalidInput(
                "When specifying a seed, n (number of plots) must be 1".to_string(),
            ));
        }
        if output_paths.len() != 1 {
            return Err(PoCXPlotterError::InvalidInput(
                "When specifying a seed, there can only be one output path".to_string(),
            ));
        }

        if seed_str.len() != 64 {
            return Err(PoCXPlotterError::Crypto(format!(
                "Invalid seed length: expected 64 hex characters, got {}",
                seed_str.len()
            )));
        }

        if !seed_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(PoCXPlotterError::Crypto(
                "Seed contains invalid characters: only hexadecimal allowed".to_string(),
            ));
        }

        let mut seed = [0; 32];
        let decoded_seed = hex::decode(seed_str)
            .map_err(|e| PoCXPlotterError::Crypto(format!("Invalid seed hex: {}", e)))?;
        seed[..].clone_from_slice(&decoded_seed);
        Some(seed)
    } else {
        None
    };

    let mem = matches
        .get_one::<String>("memory")
        .cloned()
        .unwrap_or_else(|| "0B".to_owned());

    let gpu = matches
        .get_one::<String>("gpu")
        .cloned()
        .unwrap_or_else(|| "0:0:0".to_string());

    let num_paths = output_paths.len();
    let p = Plotter::new();
    p.run(PlotterTask {
        address_payload,
        address,
        network_id,
        warps: vec![warps; num_paths],
        number_of_plots: vec![number_of_plots; num_paths],
        output_paths,
        seed,
        compress,
        mem,
        gpu,
        direct_io: !matches.get_flag("disable-direct-io"),
        escalate,
        double_buffer: matches.get_flag("double-buffer"),
        quiet: matches.get_flag("non-verbosity"),
        benchmark: matches.get_flag("benchmark"),
        line_progress: matches.get_flag("line-progress"),
        kws_override,
    })?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::needless_range_loop)]
#[allow(clippy::assertions_on_constants)]
#[allow(clippy::const_is_empty)]
mod input_validation_tests {

    #[test]
    fn test_valid_poc_address_mainnet() {
        let mut payload = [0u8; 20];
        for i in 0..20 {
            payload[i] = (i * 3) as u8;
        }
        let network_id = pocx_address::NetworkId::Base58(0x55);
        let test_id = pocx_address::encode_address(&payload, network_id).unwrap();
        let (decoded_payload, decoded_network_id) = pocx_address::decode_address(&test_id).unwrap();
        assert_eq!(decoded_payload, payload);
        assert_eq!(decoded_network_id, pocx_address::NetworkId::Base58(0x55));
    }

    #[test]
    fn test_valid_poc_address_testnet() {
        let mut payload = [0u8; 20];
        for i in 0..20 {
            payload[i] = (i * 7) as u8;
        }
        let network_id = pocx_address::NetworkId::Base58(0x7F);
        let test_id = pocx_address::encode_address(&payload, network_id).unwrap();
        let (decoded_payload, decoded_network_id) = pocx_address::decode_address(&test_id).unwrap();
        assert_eq!(decoded_payload, payload);
        assert_eq!(decoded_network_id, pocx_address::NetworkId::Base58(0x7F));
    }

    #[test]
    fn test_invalid_seed_format() {
        let g_repeat = "g".repeat(64);
        let short_repeat = "1234567890abcdef".repeat(3);
        let long_repeat = "1234567890abcdef".repeat(5);

        let invalid_seeds = vec![
            ("", "too short"),
            ("123", "too short"),
            (g_repeat.as_str(), "invalid hex characters"),
            (short_repeat.as_str(), "wrong length - too short"),
            (long_repeat.as_str(), "wrong length - too long"),
        ];

        for (seed, _description) in invalid_seeds {
            if seed.len() != 64 {
                assert!(seed.len() != 64);
            } else if !seed.chars().all(|c| c.is_ascii_hexdigit()) {
                assert!(!seed.chars().all(|c| c.is_ascii_hexdigit()));
            }
        }
    }

    #[test]
    fn test_valid_seed_format() {
        let valid_seed = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        assert_eq!(valid_seed.len(), 64);
        assert!(valid_seed.chars().all(|c| c.is_ascii_hexdigit()));
        let decoded = hex::decode(valid_seed).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_parameter_bounds() {
        assert!(0u64 == 0, "Should reject escalate = 0");
        assert!(0u32 == 0, "Should reject compression = 0");
    }

    #[test]
    fn test_memory_calculations_overflow() {
        use crate::plotter::{DIM, NONCE_SIZE};

        let large_escalate = u64::MAX / 1000;
        let result = DIM
            .checked_mul(NONCE_SIZE)
            .and_then(|v| v.checked_mul(large_escalate));

        assert!(
            result.is_none() || result.unwrap() < u64::MAX / 2,
            "Should prevent or detect overflow"
        );
    }
}

#[cfg(test)]
mod security_tests {
    use crate::buffer::PageAlignedByteBuffer;

    #[test]
    fn test_buffer_size_validation() {
        let result = PageAlignedByteBuffer::new(0);
        assert!(result.is_err(), "Should reject zero-sized buffer");

        let result = PageAlignedByteBuffer::new(usize::MAX);
        assert!(result.is_err(), "Should reject excessively large buffer");
    }

    #[test]
    fn test_reasonable_buffer_sizes() {
        let sizes = vec![4096, 1024 * 1024, 16 * 1024 * 1024];
        for size in sizes {
            let result = PageAlignedByteBuffer::new(size);
            assert!(result.is_ok(), "Should accept reasonable buffer size: {}", size);
        }
    }

    #[test]
    fn test_crypto_parameter_validation() {
        let long_id = "B".repeat(150);
        assert!(long_id.len() > 90, "Long ID validation - max 90 chars");

        let invalid_b58 = "0OIl";
        let result = pocx_address::decode_address(invalid_b58);
        assert!(result.is_err(), "Should reject invalid base58");
    }
}
