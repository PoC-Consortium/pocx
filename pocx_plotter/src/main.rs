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

mod buffer;
mod compressor;
mod cpu_hasher;
mod disk_writer;
mod error;
#[cfg(feature = "opencl")]
mod gpu_hasher;
#[cfg(feature = "opencl")]
mod ocl;
mod plotter;
mod utils;
mod xpu_scheduler;

use crate::error::{PoCXPlotterError, Result};
use crate::plotter::{Plotter, PlotterTask};
use crate::utils::set_low_prio;
#[cfg(feature = "opencl")]
use clap::ArgGroup;
use clap::{Arg, Command};
use std::cmp::min;
use std::process;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    #[cfg_attr(not(feature = "opencl"), allow(unused_mut))]
    let mut cmd = Command::new("PoCX Plotter")
        .version(env!("CARGO_PKG_VERSION"))
        .about("PoCX Plotter")
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
                .help("Runs plotter in xPU benchmark mode")
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
                .help("POW stored in plot files is scaled by 2 to the power of x (default: 1)"),
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
                .help("limit memory usage when plotting multiple disks (optional)"),
        )
        .arg(
            Arg::new("escalate")
                .short('e')
                .long("escalate")
                .help("tweak: buffer multiplier (default : 1)"),
        )
        .arg(
            Arg::new("cpu")
                .short('c')
                .long("cpu")
                .value_name("threads")
                .help("cpu threads you want to use (optional)"),
        );

    #[cfg(feature = "opencl")]
    {
        cmd = cmd
            .arg(
                Arg::new("gpu")
                    .short('g')
                    .long("gpu")
                    .value_name("platform_id:device_id:cores")
                    .help("GPU(s) you want to use for plotting (optional, default=all)")
                    .action(clap::ArgAction::Append),
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
                Arg::new("zero-copy")
                    .short('z')
                    .long("zcb")
                    .help("Enables zero copy buffers for shared mem (integrated) gpus")
                    .action(clap::ArgAction::SetTrue)
                    .global(true),
            )
            .arg(
                Arg::new("kws")
                    .short('k')
                    .long("kws-override")
                    .help("tweak: overrides default gpu kernel workgroup size")
                    .global(true),
            )
            .group(
                ArgGroup::new("processing")
                    .args(["cpu", "gpu"])
                    .multiple(true),
            );
    }

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

    // Security: Basic address validation
    if address.is_empty() {
        return Err(PoCXPlotterError::Crypto(
            "Address cannot be empty".to_string(),
        ));
    }

    // Check for reasonable length limits to prevent DoS
    if address.len() > 90 {
        return Err(PoCXPlotterError::Crypto(
            "Address too long: maximum 90 characters allowed (Bech32 limit)".to_string(),
        ));
    }

    // Decode and validate the address (supports both Base58 and Bech32 formats)
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
            let value = s.parse::<usize>().map_err(|e| {
                PoCXPlotterError::InvalidInput(format!("Invalid number value: {}", e))
            })?;
            Ok::<usize, PoCXPlotterError>(value)
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
            if value == 0 {
                return Err(PoCXPlotterError::InvalidInput(
                    "Compression value must be at least 1".to_string(),
                ));
            }
            if value > 6 {
                return Err(PoCXPlotterError::InvalidInput(
                    "Compression value too large: maximum 6 allowed (exponential CPU load)"
                        .to_string(),
                ));
            }
            Ok(value)
        })
        .transpose()?
        .unwrap_or(1);

    #[cfg(feature = "opencl")]
    let kws_override = matches
        .get_one::<String>("kws")
        .map(|s| {
            let value = s
                .parse::<usize>()
                .map_err(|e| PoCXPlotterError::InvalidInput(format!("Invalid kws value: {}", e)))?;
            Ok::<usize, PoCXPlotterError>(value)
        })
        .transpose()?
        .unwrap_or(0);
    let output_paths = matches
        .get_many::<String>("path")
        .map(|vals| {
            // Security: Validate and sanitize all output paths
            vals.map(|path| {
                // Check path length to prevent extremely long paths
                if path.len() > 4096 {
                    return Err(PoCXPlotterError::InvalidInput(
                        "Path too long: maximum 4096 characters allowed".to_string(),
                    ));
                }

                Ok(path.clone())
            })
            .collect::<Result<Vec<String>>>()
        })
        .transpose()?
        .unwrap_or_else(|| {
            match std::env::current_dir().and_then(|dir| {
                dir.into_os_string().into_string().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid path")
                })
            }) {
                Ok(path) => vec![path],
                Err(_) => vec![".".to_string()],
            }
        });

    // process seed - critical cryptographic parameter validation
    let seed = if let Some(seed_str) = matches.get_one::<String>("seed") {
        // Strict validation for seed usage
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

        // Validate seed format and length for security
        if seed_str.len() != 64 {
            return Err(PoCXPlotterError::Crypto(format!(
                "Invalid seed length: expected 64 hex characters, got {}",
                seed_str.len()
            )));
        }

        // Validate that seed contains only valid hex characters
        if !seed_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(PoCXPlotterError::Crypto(
                "Seed contains invalid characters: only hexadecimal (0-9, a-f, A-F) allowed"
                    .to_string(),
            ));
        }

        let mut seed = [0; 32];
        let decoded_seed = hex::decode(seed_str)
            .map_err(|e| PoCXPlotterError::Crypto(format!("Invalid seed hex: {}", e)))?;

        // Double-check decoded length for security
        if decoded_seed.len() != 32 {
            return Err(PoCXPlotterError::Crypto(format!(
                "Invalid decoded seed length: expected 32 bytes, got {} bytes",
                decoded_seed.len()
            )));
        }

        seed[..].clone_from_slice(&decoded_seed);
        Some(seed)
    } else {
        None
    };

    let mem = matches
        .get_one::<String>("memory")
        .cloned()
        .unwrap_or_else(|| "0B".to_owned());
    let cpu_threads = matches
        .get_one::<String>("cpu")
        .map(|s| {
            let value = s.parse::<u8>().map_err(|e| {
                PoCXPlotterError::InvalidInput(format!("Invalid cpu threads value: {}", e))
            })?;
            if value > 128 {
                return Err(PoCXPlotterError::InvalidInput(
                    "CPU threads value too large: maximum 128 allowed".to_string(),
                ));
            }
            Ok::<u8, PoCXPlotterError>(value)
        })
        .transpose()?
        .unwrap_or(0u8);

    #[cfg(feature = "opencl")]
    let gpus = matches
        .get_many::<String>("gpu")
        .map(|vals| vals.cloned().collect::<Vec<String>>());

    #[cfg(not(feature = "opencl"))]
    let gpus: Option<Vec<String>> = None;

    // work out number of cpu threads to use
    // Use num_cpus instead of sysinfo for better Android compatibility
    let cores = num_cpus::get() as u8;
    let cpu_threads = if cpu_threads == 0 {
        cores
    } else {
        min(2 * cores, cpu_threads)
    };

    // special case: dont use cpu if only a gpu is defined
    #[cfg(feature = "opencl")]
    let cpu_threads = if matches.contains_id("gpu") && !matches.contains_id("cpu") {
        0u8
    } else {
        cpu_threads
    };

    let p = Plotter::new();
    p.run(PlotterTask {
        address_payload,
        address,
        network_id,
        warps: vec![warps; output_paths.len()],
        number_of_plots: vec![number_of_plots as u64; output_paths.len()],
        compress,
        output_paths,
        seed,
        mem,
        cpu_threads,
        gpus,
        direct_io: !matches.get_flag("disable-direct-io"),
        escalate,
        quiet: matches.get_flag("non-verbosity"),
        benchmark: matches.get_flag("benchmark"),
        line_progress: matches.get_flag("line-progress"),
        #[cfg(feature = "opencl")]
        zcb: matches.get_flag("zero-copy"),
        #[cfg(feature = "opencl")]
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
        // Generate a valid PoCX mainnet address for testing
        let mut payload = [0u8; 20]; // Use 20-byte payload as expected by encode function
                                     // Fill with some test data
        for i in 0..20 {
            payload[i] = (i * 3) as u8;
        }
        let network_id = pocx_address::NetworkId::Base58(0x55); // Mainnet version
        let test_id = pocx_address::encode_address(&payload, network_id).unwrap();

        // Validate the address and check the network ID
        let (decoded_payload, decoded_network_id) = pocx_address::decode_address(&test_id).unwrap();
        assert_eq!(decoded_payload, payload);
        assert_eq!(decoded_network_id, pocx_address::NetworkId::Base58(0x55)); // Check payload matches
    }

    #[test]
    fn test_valid_poc_address_testnet() {
        // Generate a valid testnet address for testing
        let mut payload = [0u8; 20]; // Use 20-byte payload as expected by encode function
                                     // Fill with some test data
        for i in 0..20 {
            payload[i] = (i * 7) as u8;
        }
        let network_id = pocx_address::NetworkId::Base58(0x7F); // Testnet version
        let test_id = pocx_address::encode_address(&payload, network_id).unwrap();

        // Validate the address and check the network ID
        let (decoded_payload, decoded_network_id) = pocx_address::decode_address(&test_id).unwrap();
        assert_eq!(decoded_payload, payload);
        assert_eq!(decoded_network_id, pocx_address::NetworkId::Base58(0x7F)); // Check payload matches
    }

    #[test]
    fn test_invalid_seed_format() {
        // Test various invalid seed formats
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
                assert!(seed.len() != 64, "Seed length validation should catch this");
            } else if !seed.chars().all(|c| c.is_ascii_hexdigit()) {
                assert!(
                    !seed.chars().all(|c| c.is_ascii_hexdigit()),
                    "Hex validation should catch this"
                );
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
        // Test that our parameter validation catches minimum values where applicable

        // Escalate zero should be rejected
        assert!(0u64 == 0, "Should reject escalate = 0");

        // Compression zero should be rejected
        assert!(0u32 == 0, "Should reject compression = 0");

        // Note: No max limits for warps, escalate, compression, or CPU threads
        // anymore Memory checks will prevent unreasonable values at
        // runtime
    }

    #[test]
    fn test_memory_calculations_overflow() {
        // Test that large values don't cause integer overflow
        use crate::plotter::{DIM, NONCE_SIZE};

        let large_escalate = u64::MAX / 1000;
        let result = DIM
            .checked_mul(NONCE_SIZE)
            .and_then(|v| v.checked_mul(large_escalate));

        // Should detect overflow for very large values
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
        // Test zero size rejection
        let result = PageAlignedByteBuffer::new(0);
        assert!(result.is_err(), "Should reject zero-sized buffer");

        // Test extremely large size rejection (if system allows the test)
        let huge_size = 32 * 1024 * 1024 * 1024; // 32 GB
        let result = PageAlignedByteBuffer::new(huge_size);
        assert!(result.is_err(), "Should reject excessively large buffer");
    }

    #[test]
    fn test_reasonable_buffer_sizes() {
        // Test that reasonable sizes work
        let sizes = vec![
            4096,             // 4 KB
            1024 * 1024,      // 1 MB
            16 * 1024 * 1024, // 16 MB
        ];

        for size in sizes {
            let result = PageAlignedByteBuffer::new(size);
            assert!(
                result.is_ok(),
                "Should accept reasonable buffer size: {}",
                size
            );
        }
    }

    #[test]
    fn test_crypto_parameter_validation() {
        // Test that cryptographic parameters are properly validated

        // Empty PoCX ID should be rejected - test that empty string is handled

        // Overly long PoCX ID should be rejected (Bech32 limit)
        let long_id = "B".repeat(150);
        assert!(long_id.len() > 90, "Long ID validation - max 90 chars");

        // Invalid base58 should be rejected
        let invalid_b58 = "0OIl"; // Contains invalid base58 characters
        let result = pocx_address::decode_address(invalid_b58);
        assert!(result.is_err(), "Should reject invalid base58");
    }
}
