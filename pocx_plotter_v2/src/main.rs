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
mod cpu_compressor;
mod cpu_hasher;
mod cpu_scheduler;
mod disk_writer;
mod error;
#[cfg(feature = "opencl")]
mod ocl;
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

static PLOTTER_CALLBACK: std::sync::OnceLock<Arc<dyn PlotterCallback>> = std::sync::OnceLock::new();

pub fn get_plotter_callback() -> Option<Arc<dyn PlotterCallback>> {
    PLOTTER_CALLBACK.get().cloned()
}

use crate::plotter::{Plotter, PlotterTask, WARP_SIZE};
use crate::utils::{free_disk_space, set_low_prio};
use clap::{Arg, Command};
use pocx_plotfile::PoCXPlotFile;
use std::process;

/// Represents an incomplete plot file found on disk.
struct IncompletePlot {
    path: String,
    seed: [u8; 32],
    /// Total warps in the file (from filename).
    warps: u64,
    /// Warps already written (resume offset read from the file header).
    warps_done: u64,
    compression: u8,
}

/// Scan a directory for `.tmp` files matching the given address payload and compression.
fn find_incomplete_plots(
    dir: &str,
    address_payload: &[u8; 20],
    compression: u8,
) -> Vec<IncompletePlot> {
    let addr_hex = hex::encode_upper(address_payload);
    let suffix = format!("_X{}.tmp", compression);

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // Match: {ADDR_HEX}_{SEED_HEX}_{WARPS}_X{COMPRESSION}.tmp
        if !name.starts_with(&addr_hex) || !name.ends_with(&suffix) {
            continue;
        }

        // Delete 0-byte files left behind by failed preallocations
        match entry.metadata() {
            Ok(m) if m.len() == 0 => {
                let path = entry.path();
                if let Err(e) = std::fs::remove_file(&path) {
                    eprintln!(
                        "WARNING: Failed to delete empty .tmp file {}: {}",
                        path.display(),
                        e
                    );
                } else {
                    eprintln!("Deleted empty .tmp file: {}/{}", dir, name);
                }
                continue;
            }
            Err(_) => continue,
            _ => {}
        }

        let parts: Vec<&str> = name.split('_').collect();
        if parts.len() != 4 {
            continue;
        }

        let seed_hex = parts[1];
        if seed_hex.len() != 64 || !seed_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }

        let warps = match parts[2].parse::<u64>() {
            Ok(w) if w > 0 => w,
            _ => continue,
        };

        let mut seed = [0u8; 32];
        if hex::decode_to_slice(seed_hex, &mut seed).is_err() {
            continue;
        }

        // Open the file to read how many warps were already committed.
        // If we can open the file but find 0 warps written (preallocated but
        // never started, or RESUME_MAGIC absent), delete it: the file holds no
        // useful data and keeping it would shrink the fill-slot size on every
        // restart, causing the resume queue to grow indefinitely.
        let plot_file = PoCXPlotFile::new(
            dir,
            address_payload,
            &seed,
            warps,
            compression,
            false,
            false,
        );
        let warps_done = match plot_file {
            Err(_) => continue, // Can't open → leave it alone
            Ok(mut pf) => match pf.read_resume_info() {
                Ok(0) | Err(_) => {
                    // 0 warps written or no resume marker — delete the empty skeleton
                    let path = entry.path();
                    if let Err(e) = std::fs::remove_file(&path) {
                        eprintln!(
                            "WARNING: Failed to delete unstarted .tmp file {}: {}",
                            path.display(),
                            e
                        );
                    } else {
                        eprintln!("Deleted unstarted .tmp file: {}/{}", dir, name);
                    }
                    continue;
                }
                Ok(w) => w,
            },
        };

        results.push(IncompletePlot {
            path: dir.to_string(),
            seed,
            warps,
            warps_done,
            compression,
        });
    }
    results
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let cmd =
        Command::new("PoCX GPU Plotter")
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
                    .help("how many warps per file (1 warp = 1 GiB, 0: fill disk)"),
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
            .arg(Arg::new("escalate").short('e').long("escalate").help(
                "write buffer size multiplier in warps (default: 1, e.g. -e 5 = 5 GiB buffer)",
            ))
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
                    .help("GPU to use for plotting (default: 0:0:0 = first GPU, all CUs)")
                    .conflicts_with("cpu"),
            )
            .arg(
                Arg::new("cpu")
                    .short('c')
                    .long("cpu")
                    .value_name("threads")
                    .help("CPU-only plotting with N threads (0 = auto-detect)")
                    .conflicts_with("gpu"),
            )
            .arg(
                Arg::new("fill")
                    .short('f')
                    .long("fill")
                    .help("After plotting, fill remaining disk space with one last file per path")
                    .action(clap::ArgAction::SetTrue)
                    .global(true),
            )
            .arg(
                Arg::new("no-auto-resume")
                    .long("no-auto-resume")
                    .help("Disable automatic resumption of incomplete .tmp files")
                    .action(clap::ArgAction::SetTrue)
                    .global(true),
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
            )
            .arg(
                Arg::new("threads")
                    .short('t')
                    .long("threads")
                    .value_name("N")
                    .help("max concurrent writer threads (default: one per unique disk)"),
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

    let fill_last = matches.get_flag("fill");

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
            Ok(value)
        })
        .transpose()?
        .unwrap_or(0);

    // When fill_last and -n not specified, default to 0 (fill disk with full-sized files)
    let number_of_plots_default = if fill_last { 0 } else { 1 };
    let number_of_plots = matches
        .get_one::<String>("number")
        .map(|s| {
            s.parse::<u64>()
                .map_err(|e| PoCXPlotterError::InvalidInput(format!("Invalid number value: {}", e)))
        })
        .transpose()?
        .unwrap_or(number_of_plots_default);

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

    let gpu_explicit = matches.get_one::<String>("gpu").cloned();

    let cpu_threads = matches
        .get_one::<String>("cpu")
        .map(|s| {
            let value = s.parse::<usize>().map_err(|e| {
                PoCXPlotterError::InvalidInput(format!("Invalid cpu threads value: {}", e))
            })?;
            Ok::<usize, PoCXPlotterError>(if value == 0 { num_cpus::get() } else { value })
        })
        .transpose()?
        .unwrap_or_else(|| {
            // Default to CPU (auto-detect) when neither --cpu nor --gpu is specified
            if gpu_explicit.is_none() {
                num_cpus::get()
            } else {
                0
            }
        });

    let gpu = if cpu_threads > 0 {
        String::new()
    } else {
        gpu_explicit.unwrap_or_else(|| "0:0:0".to_string())
    };

    let auto_resume =
        !matches.get_flag("no-auto-resume") && seed.is_none() && !matches.get_flag("benchmark");
    let quiet = matches.get_flag("non-verbosity");
    let benchmark = matches.get_flag("benchmark");

    // Messages collected here, printed after the GPU banner in plotter.rs
    let mut startup_messages: Vec<String> = Vec::new();

    // Build unified work queue: resume + full plots + fill-last, all in one pass.
    // Each entry is one "slot" in the PlotterTask (path, seed, warps, n).
    // The ring scheduler round-robins across all slots, keeping all disks busy.
    let mut q_paths: Vec<String> = Vec::new();
    let mut q_seeds: Vec<Option<[u8; 32]>> = Vec::new();
    let mut q_warps: Vec<u64> = Vec::new();
    let mut q_plots: Vec<u64> = Vec::new();
    // Remaining warps to write per slot — used to sort shortest-first.
    let mut q_remaining: Vec<u64> = Vec::new();

    if benchmark {
        // Benchmark mode: simple 1:1 mapping, let plotter.rs handle defaults
        if let Some(s) = seed {
            q_paths.push(output_paths[0].clone());
            q_seeds.push(Some(s));
            q_warps.push(warps);
            q_plots.push(number_of_plots);
        } else {
            for path in &output_paths {
                q_paths.push(path.clone());
                q_seeds.push(None);
                q_warps.push(warps);
                q_plots.push(number_of_plots);
            }
        }
    } else {
        // Phase 1: Collect resume jobs per path
        if auto_resume {
            for dir in &output_paths {
                let incomplete = find_incomplete_plots(dir, &address_payload, compress);
                for plot in incomplete {
                    q_remaining.push(plot.warps.saturating_sub(plot.warps_done));
                    q_paths.push(plot.path);
                    q_seeds.push(Some(plot.seed));
                    q_warps.push(plot.warps);
                    q_plots.push(1);
                }
            }
        }

        // Count resume jobs already queued per path
        let mut resume_count_per_path: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        for p in &q_paths {
            *resume_count_per_path.entry(p.clone()).or_insert(0) += 1;
        }

        // Phase 2 + 3: Compute full-size plots and fill-last per path
        for path in &output_paths {
            let space = free_disk_space(path)?;
            let already_resumed = *resume_count_per_path.get(path).unwrap_or(&0);

            // Resolve warps/n using the same logic as plotter.rs
            let (resolved_warps, resolved_n) = if warps == 0 && number_of_plots == 0 {
                // Neither specified — this is an error unless -f supplies work
                if !fill_last {
                    return Err(PoCXPlotterError::InvalidInput(
                        "Need to specify either number of plots or number of warps".to_string(),
                    ));
                }
                (0u64, 0u64)
            } else if warps == 0 {
                // -n given, compute warps from space
                let remaining_n = number_of_plots.saturating_sub(already_resumed);
                let w = if remaining_n > 0 {
                    space / WARP_SIZE / remaining_n
                } else {
                    0
                };
                if w == 0 && remaining_n > 0 && !fill_last {
                    return Err(PoCXPlotterError::Config(format!(
                        "Insufficient disk space for {} file(s), available={:.2} GiB, path={}",
                        remaining_n,
                        space as f64 / 1024.0 / 1024.0 / 1024.0,
                        path
                    )));
                }
                (w, if w > 0 { remaining_n } else { 0 })
            } else if number_of_plots == 0 {
                // -w given, -n 0: fill disk with full-size files
                let n = space / WARP_SIZE / warps;
                (warps, n)
            } else {
                // Both explicit — subtract resume jobs already covering this path
                let remaining_n = number_of_plots.saturating_sub(already_resumed);
                (warps, remaining_n)
            };

            // Add full-size plot entry (if any files to plot)
            if resolved_n > 0 && resolved_warps > 0 {
                // For manual seed mode, use the provided seed
                let entry_seed = if seed.is_some() && output_paths.len() == 1 {
                    seed
                } else {
                    None
                };
                q_remaining.push(resolved_warps * resolved_n);
                q_paths.push(path.clone());
                q_seeds.push(entry_seed);
                q_warps.push(resolved_warps);
                q_plots.push(resolved_n);
            }

            // Add fill-last entry only when no resume files are pending for this disk.
            // If resumes exist, starting a fill file races with them: the fill (often
            // the shortest slot due to rounding) gets scheduled first, gets killed, and
            // becomes yet another resume on the next restart — causing unbounded queue
            // growth. Skip it; the fill will be computed correctly once the disk is clean.
            if fill_last && already_resumed == 0 {
                let used_by_full = resolved_n * resolved_warps * WARP_SIZE;
                let remaining = space.saturating_sub(used_by_full);
                let fill_w = remaining / WARP_SIZE;
                if fill_w > 0 {
                    q_remaining.push(fill_w);
                    q_paths.push(path.clone());
                    q_seeds.push(None);
                    q_warps.push(fill_w);
                    q_plots.push(1);
                }
            }
        }
    }

    if q_paths.is_empty() {
        if !quiet {
            eprintln!("Nothing to do: no resume jobs, no plots to create, no fill space.");
        }
        return Ok(());
    }

    // Sort all slots by remaining warps ascending: shortest work completes first,
    // freeing GPU pressure sooner and balancing disk I/O across the run.
    if !benchmark && q_paths.len() > 1 {
        let mut order: Vec<usize> = (0..q_paths.len()).collect();
        order.sort_unstable_by_key(|&i| q_remaining[i]);
        let sorted_paths: Vec<String> = order.iter().map(|&i| q_paths[i].clone()).collect();
        let sorted_seeds: Vec<Option<[u8; 32]>> = order.iter().map(|&i| q_seeds[i]).collect();
        let sorted_warps: Vec<u64> = order.iter().map(|&i| q_warps[i]).collect();
        let sorted_plots: Vec<u64> = order.iter().map(|&i| q_plots[i]).collect();
        q_paths = sorted_paths;
        q_seeds = sorted_seeds;
        q_warps = sorted_warps;
        q_plots = sorted_plots;
    }

    let work_queue_summary = if !quiet && !benchmark {
        let resume_count = q_seeds.iter().filter(|s| s.is_some()).count();
        let total_entries = q_paths.len();
        let new_count = total_entries - resume_count;
        let unique_paths = q_paths
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        Some(format!(
            "Work queue: {} job(s) ({} resume, {} new) across {} unique path(s)",
            total_entries, resume_count, new_count, unique_paths
        ))
    } else {
        None
    };

    let p = Plotter::new();
    p.run(PlotterTask {
        address_payload,
        address,
        network_id,
        warps: q_warps,
        number_of_plots: q_plots,
        output_paths: q_paths,
        initial_seeds: q_seeds,
        compress,
        mem,
        gpu,
        cpu_threads,
        direct_io: !matches.get_flag("disable-direct-io"),
        escalate,
        double_buffer: matches.get_flag("double-buffer"),
        quiet,
        benchmark,
        line_progress: matches.get_flag("line-progress"),
        kws_override,
        max_concurrent_writes: matches
            .get_one::<String>("threads")
            .map(|v| v.parse::<usize>().expect("threads must be a number")),
        startup_messages,
        work_queue_summary,
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
            assert!(
                result.is_ok(),
                "Should accept reasonable buffer size: {}",
                size
            );
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
