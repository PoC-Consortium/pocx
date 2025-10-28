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

use bytesize::ByteSize;
use crossbeam_channel::bounded;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use pocx_plotfile::PoCXPlotFile;
use std::cmp::min;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::System;

use crate::error::{PoCXPlotterError, Result};

use crate::buffer::PageAlignedByteBuffer;
use crate::compressor::create_chunk_compressor_thread;
use crate::cpu_hasher::{init_simd, SimdExtension};
use crate::disk_writer::create_writer_thread;
#[cfg(feature = "opencl")]
use crate::ocl::gpu_get_info;
use crate::utils::free_disk_space;
use crate::utils::get_sector_size;
use crate::xpu_scheduler::create_scheduler_thread;

#[cfg(windows)]
use crate::utils::is_elevated;
#[cfg(windows)]
use crate::utils::set_thread_ideal_processor;

pub const DOUBLE_HASH_SIZE: u64 = 64;
pub const DIM: u64 = 4096;
pub const NONCE_SIZE: u64 = DIM * DOUBLE_HASH_SIZE;
pub const WARP_SIZE: u64 = DIM * NONCE_SIZE;

pub struct Plotter {}

pub struct PlotterTask {
    pub address_payload: [u8; 20], // Network-independent address payload
    pub address: String,
    pub network_id: pocx_address::NetworkId, // Network ID from address
    pub seed: Option<[u8; 32]>,
    pub warps: Vec<u64>,
    pub number_of_plots: Vec<u64>,
    pub compress: u32,
    pub output_paths: Vec<String>,
    pub mem: String,
    pub cpu_threads: u8,
    pub gpus: Option<Vec<String>>,
    pub direct_io: bool,
    pub escalate: u64,
    pub quiet: bool,
    pub benchmark: bool,
    pub line_progress: bool,
    #[cfg(feature = "opencl")]
    pub zcb: bool,
    #[cfg(feature = "opencl")]
    pub kws_override: usize,
}

impl Default for Plotter {
    fn default() -> Self {
        Self::new()
    }
}

impl Plotter {
    pub fn new() -> Plotter {
        Plotter {}
    }

    pub fn run(self, mut task: PlotterTask) -> Result<()> {
        let mut sys = System::new_all();
        sys.refresh_cpu_all();
        sys.refresh_memory();

        let cpu_name = sys
            .cpus()
            .first()
            .map(|cpu| cpu.brand().trim().to_string())
            .unwrap_or_else(|| "Unknown CPU".to_string());

        let cores = sys.cpus().len() as u32;

        let simd_ext = init_simd();

        if !task.quiet {
            println!("PoCX Plotter {}", env!("CARGO_PKG_VERSION"));
            println!("written by Proof of Capacity Consortium in Rust\n");
        }

        if !task.quiet && task.benchmark {
            println!("*BENCHMARK MODE*\n");
        }

        if !task.quiet {
            println!(
                "CPU: {} [using {} of {} cores{}{:?}]",
                cpu_name,
                task.cpu_threads,
                cores,
                if let SimdExtension::None = simd_ext {
                    ""
                } else {
                    " + "
                },
                simd_ext
            );
        }

        #[cfg(not(feature = "opencl"))]
        let mem_gpu = 0u64;
        #[cfg(feature = "opencl")]
        let mem_gpu = match &task.gpus {
            Some(x) => gpu_get_info(x, task.quiet, task.kws_override),
            None => 0,
        };

        #[cfg(feature = "opencl")]
        let mem_gpu = if task.zcb { mem_gpu / 2 } else { mem_gpu };

        // check direct i/o capabilities
        // NB: warp = 1 GiB, 1 scoop = 1 GiB  / 4096 = 256 KiB = 2^18
        // as long as sector size is power 2 and smaller than 256 KiB direct IO will be
        // fine
        for path in &task.output_paths {
            let sector_size = get_sector_size(path)?;

            let is_power_of_2 = (sector_size & (sector_size - 1)) == 0;
            if task.direct_io && (!is_power_of_2 || sector_size > (1 << 18)) {
                return Err(PoCXPlotterError::Config(format!(
                    "Direct I/O: sector_size is not a power of 2 or bigger than 256KiB, sector_size={}, disk={}",
                    sector_size, path
                )));
            }
        }

        // work out number of warps and files to plot if not fully specified and check
        // target disk
        for (i, w) in task.warps.iter_mut().enumerate() {
            let space = free_disk_space(&task.output_paths[i])?;
            let path = Path::new(&task.output_paths[i]);
            if !task.benchmark && !path.exists() {
                return Err(PoCXPlotterError::InvalidInput(format!(
                    "Specified target path does not exist: {:?}",
                    path
                )));
            }
            if *w == 0 {
                if task.number_of_plots[i] == 0 {
                    return Err(PoCXPlotterError::InvalidInput(
                        "Need to specify either number of plot or number of warps".to_string(),
                    ));
                }
                // Security: Prevent division by zero and validate calculation
                if task.number_of_plots[i] == 0 {
                    return Err(PoCXPlotterError::InvalidInput(
                        "Number of plots cannot be zero when calculating warps".to_string(),
                    ));
                }
                *w = space / WARP_SIZE / task.number_of_plots[i];
                if !task.benchmark && *w == 0 {
                    return Err(PoCXPlotterError::Config(format!(
                        "Insufficient disk space, MiB_required={:.2}, MiB_available={:.2}, path={}",
                        (task.number_of_plots[i] * WARP_SIZE) as f64 / 1024.0 / 1024.0,
                        space as f64 / 1024.0 / 1024.0,
                        &task.output_paths[i]
                    )));
                }
            } else if task.number_of_plots[i] == 0 {
                // Security: Prevent division by zero and validate calculation
                if *w == 0 {
                    return Err(PoCXPlotterError::InvalidInput(
                        "Warps cannot be zero when calculating number of plots".to_string(),
                    ));
                }
                task.number_of_plots[i] = space / WARP_SIZE / *w;
                if !task.benchmark && *w == 0 {
                    return Err(PoCXPlotterError::Config(format!(
                        "Insufficient disk space, MiB_required={:.2}, MiB_available={:.2}, path={}",
                        (*w * WARP_SIZE) as f64 / 1024.0 / 1024.0,
                        space as f64 / 1024.0 / 1024.0,
                        &task.output_paths[i]
                    )));
                }
            } else {
                // Security: Check for multiplication overflow before space comparison
                let required_space = w
                    .checked_mul(task.number_of_plots[i])
                    .and_then(|v| v.checked_mul(WARP_SIZE))
                    .ok_or_else(|| {
                        PoCXPlotterError::Config(
                            "Disk space calculation overflow: warps and plots values too large"
                                .to_string(),
                        )
                    })?;

                if !task.benchmark && required_space >= space {
                    return Err(PoCXPlotterError::Config(format!(
                        "Insufficient disk space, MiB_required={:.2}, MiB_available={:.2}, path={}",
                        (*w * WARP_SIZE * task.number_of_plots[i]) as f64 / 1024.0 / 1024.0,
                        space as f64 / 1024.0 / 1024.0,
                        &task.output_paths[i]
                    )));
                }
            }
        }

        // feature: check if path belong to same drive and throw error
        let gpu = task.gpus.is_some();

        // Security: Validate memory calculations to prevent integer overflow
        let mem_write = DIM
            .checked_mul(NONCE_SIZE)
            .and_then(|v| v.checked_mul(task.escalate))
            .ok_or_else(|| {
                PoCXPlotterError::Config(
                    "Memory write calculation overflow: escalate value too large".to_string(),
                )
            })?;

        let compression_multiplier = u64::pow(2, task.compress);
        let mem_plot = compression_multiplier.checked_mul(mem_write)
            .ok_or_else(|| PoCXPlotterError::Config(format!(
                "Memory plot calculation overflow: compression value {} results in 2^{} = {} which causes overflow when multiplied by memory requirements",
                task.compress, task.compress, compression_multiplier
            )))?;

        // determine maximum memory usage
        let mem_limit = task.mem.parse::<ByteSize>()
            .map_err(|_| PoCXPlotterError::InvalidInput(format!(
                "Can't parse memory limit parameter: {}. Please specify a number followed by a unit (B, KiB, MiB, GiB, TiB, PiB, EiB, KB, MB, GB, TB, PB, EB). Example: --mem 10GiB",
                task.mem
            )))?
            .as_u64();

        // Security: Validate memory limits and prevent excessive memory usage
        let available_mem = sys.available_memory();

        let max_mem_usage = if mem_limit > 0 {
            // Validate that user-specified memory limit is reasonable
            if mem_limit > available_mem * 2 {
                return Err(PoCXPlotterError::Config(format!(
                    "Requested memory limit ({:.2} GiB) exceeds twice the available system memory ({:.2} GiB). This may indicate an error.",
                    mem_limit as f64 / 1024.0 / 1024.0 / 1024.0,
                    available_mem as f64 / 1024.0 / 1024.0 / 1024.0
                )));
            }
            min(mem_limit, available_mem)
        } else {
            available_mem
        };

        // Security: Check for underflow in memory calculations
        let gpu_mem = if gpu { mem_gpu } else { 0 };
        let reserved_mem = mem_plot.checked_add(gpu_mem).ok_or_else(|| {
            PoCXPlotterError::Config(
                "Memory calculation overflow: combined plot and GPU memory too large".to_string(),
            )
        })?;

        let maximum_mem_for_writing = max_mem_usage.saturating_sub(reserved_mem);

        let minimum_mem_for_writing = mem_write;

        if maximum_mem_for_writing < minimum_mem_for_writing {
            return Err(PoCXPlotterError::Memory(format!(
                "Insufficient host memory for plotting!\n\nRAM: Total={:.2} GiB, Available={:.2} GiB\nPlotter requirement: {:.2} GiB x{} (escalation)\nWriter requirement: {:.2} GiB x{} (escalation)\nGPU requirement: {:.2} GiB\nTOTAL requirement: {:.2} GiB",
                sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0,
                sys.available_memory() as f64 / 1024.0 / 1024.0 / 1024.0,
                (u64::pow(2, task.compress) * DIM * NONCE_SIZE) as f64 / 1024.0 / 1024.0 / 1024.0,
                task.escalate,
                WARP_SIZE as f64 / 1024.0 / 1024.0 / 1024.0,
                task.escalate,
                if gpu { mem_gpu } else { 0 } as f64 / 1024.0 / 1024.0 / 1024.0,
                (mem_plot + minimum_mem_for_writing + mem_gpu) as f64 / 1024.0 / 1024.0 / 1024.0
            )));
        }

        let num_write_buffers = min(
            maximum_mem_for_writing / mem_write,
            task.output_paths.len() as u64,
        );

        // check if file exists needs resume
        let mut resume = 0;
        if let Some(seed) = task.seed {
            let optimized_plot_file = PoCXPlotFile::new(
                &task.output_paths[0],
                &task.address_payload,
                &seed,
                task.warps[0],
                task.compress,
                false,
                false,
            );
            if let Ok(mut i) = optimized_plot_file {
                let progress = i.read_resume_info();
                if let Ok(j) = progress {
                    resume = j;
                }
            }
        }

        let total_planned_warps = task
            .warps
            .iter()
            .zip(task.number_of_plots.iter())
            .map(|(x, y)| x * y)
            .sum::<u64>();

        let total_warps = total_planned_warps - resume;

        if task.line_progress {
            println!("#TOTAL:{}", total_warps);
        }

        if !task.quiet {
            println!(
                "RAM: Total={:.2} GiB, Available={:.2} GiB, Usage={:.2} GiB",
                sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0,
                sys.available_memory() as f64 / 1024.0 / 1024.0 / 1024.0,
                (mem_plot + (mem_write * num_write_buffers) + mem_gpu) as f64
                    / 1024.0
                    / 1024.0
                    / 1024.0
            );

            println!(
                "     Cache(Plotter)={:.2} GiB x{} (escalation), Cache(HDD)={:.2} GiB x{} (escalation) x{} (disks), Cache(GPU)={:.2} GiB,\n",
                (u64::pow(2, task.compress) * DIM * NONCE_SIZE) as f64 / 1024.0 / 1024.0 / 1024.0,
                task.escalate,
                (DIM * NONCE_SIZE) as f64 / 1024.0 / 1024.0 / 1024.0,
                task.escalate,
                num_write_buffers,
                mem_gpu as f64 / 1024.0 / 1024.0 / 1024.0
            );

            // Display address info based on format
            match &task.network_id {
                pocx_address::NetworkId::Base58(version) => {
                    println!(
                        "Address       : {} (network: 0x{:02X})",
                        task.address, version
                    );
                }
                pocx_address::NetworkId::Bech32(_hrp) => {
                    println!("Address       : {}", task.address);
                }
            }
            println!(
                "Address Hex   : {} (network-independent payload)",
                hex::encode_upper(task.address_payload)
            );
            println!(
                "Compression    : {:?}(X{:?})",
                u64::pow(2, task.compress),
                task.compress
            );
            println!("Output path(s) : {:?}", task.output_paths);
            println!("Files to plot  : {:?}", task.number_of_plots);
            println!("Warps per file : {:?}", task.warps);
            println!("Total warps    : {:?}\n", total_warps);

            #[cfg(windows)]
            if !is_elevated() {
                println!(
                    "WARNING: administrative rights missing, file pre-allocations will be slow!\n"
                );
            }

            if resume == 0 {
                println!("Starting plotting...\n");
            } else {
                println!("Resuming plotting from warp offset {}...\n", resume);
            }
        }

        let (tx_empty_plot_buffers, rx_empty_plot_buffers) = bounded(1);
        let (tx_full_plot_buffers, rx_full_plot_buffers) = bounded(1);
        let (tx_empty_write_buffers, rx_empty_write_buffers) = bounded(num_write_buffers as usize);

        let buffer = PageAlignedByteBuffer::new(mem_plot as usize)?;
        tx_empty_plot_buffers.send(buffer).map_err(|e| {
            PoCXPlotterError::Channel(format!("Failed to send empty plot buffer: {}", e))
        })?;

        for _ in 0..num_write_buffers {
            let buffer = PageAlignedByteBuffer::new((mem_write) as usize)?;
            tx_empty_write_buffers.send(buffer).map_err(|e| {
                PoCXPlotterError::Channel(format!("Failed to send empty write buffer: {}", e))
            })?;
        }

        let multi_progress = if !task.quiet && !task.line_progress {
            let mp = MultiProgress::new();
            // Ensure progress bars are visible by enabling steady tick
            mp.set_move_cursor(true);
            Some(Arc::new(mp))
        } else {
            None
        };

        let hash_pb = if let Some(mp) = &multi_progress {
            let pb = mp.add(ProgressBar::new(total_warps * WARP_SIZE));
            pb.set_style(
                ProgressStyle::with_template(
                    "Hashing: [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta}) {msg}"
                ).unwrap()
                .progress_chars("█░░")
            );
            pb.enable_steady_tick(Duration::from_millis(100));
            Some(pb)
        } else {
            None
        };

        let write_pb = if let Some(mp) = &multi_progress {
            let pb = mp.add(ProgressBar::new(total_warps * WARP_SIZE));
            pb.set_style(
                ProgressStyle::with_template(
                    "Writing: [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta}) {msg}"
                ).unwrap()
                .progress_chars("█░░")
            );
            pb.enable_steady_tick(Duration::from_millis(100));
            Some(Arc::new(pb))
        } else {
            None
        };

        let start_time = Instant::now();
        let task = Arc::new(task);

        // hi bold! might make this optional in future releases.
        let thread_pinning = true;
        let core_ids = if thread_pinning {
            core_affinity::get_core_ids()
                .ok_or_else(|| PoCXPlotterError::Hardware("Failed to get core IDs".to_string()))?
        } else {
            Vec::new()
        };

        // create writers and writer channels
        let mut writers = Vec::new();
        let mut tx_full = Vec::new();
        for (i, _) in task.output_paths.iter().enumerate() {
            let (tx_full_write_buffers, rx_full_write_buffers) =
                bounded(num_write_buffers as usize);
            let write_progress = write_pb.as_ref().cloned();
            writers.push(thread::spawn({
                create_writer_thread(
                    task.clone(),
                    write_progress,
                    rx_full_write_buffers.clone(),
                    tx_empty_write_buffers.clone(),
                    i,
                )
            }));
            tx_full.push(tx_full_write_buffers);
        }

        let compressor = thread::spawn({
            create_chunk_compressor_thread(
                task.clone(),
                rx_full_plot_buffers.clone(),
                tx_empty_plot_buffers.clone(),
                rx_empty_write_buffers.clone(),
                tx_full,
                resume,
            )
        });

        let hasher = thread::spawn({
            create_scheduler_thread(
                task.clone(),
                rayon::ThreadPoolBuilder::new()
                    .num_threads(task.cpu_threads as usize)
                    .start_handler(move |id| {
                        if thread_pinning {
                            #[cfg(not(windows))]
                            let core_id = core_ids[id % core_ids.len()];
                            #[cfg(not(windows))]
                            core_affinity::set_for_current(core_id);
                            #[cfg(windows)]
                            set_thread_ideal_processor(id % core_ids.len());
                        }
                    })
                    .build()
                    .map_err(|e| {
                        PoCXPlotterError::Hardware(format!("Failed to build thread pool: {}", e))
                    })?,
                hash_pb,
                rx_empty_plot_buffers.clone(),
                tx_full_plot_buffers.clone(),
                resume,
            )
        });

        // MultiProgress handles rendering automatically, no need to join

        for writer in writers {
            writer
                .join()
                .map_err(|_| PoCXPlotterError::Channel("Writer thread panicked".to_string()))?;
        }

        compressor
            .join()
            .map_err(|_| PoCXPlotterError::Channel("Compressor thread panicked".to_string()))?;
        hasher
            .join()
            .map_err(|_| PoCXPlotterError::Channel("Hasher thread panicked".to_string()))?;

        // Progress bars finish automatically when threads complete

        let elapsed = start_time.elapsed().as_millis() as u64;
        let hours = elapsed / 1000 / 60 / 60;
        let minutes = elapsed / 1000 / 60 - hours * 60;
        let seconds = elapsed / 1000 - hours * 60 * 60 - minutes * 60;

        if !task.quiet {
            let session_nonces = 2 * total_warps * DIM;
            let total_planned_nonces = 2 * total_planned_warps * DIM;
            let resumed_nonces = 2 * resume * DIM;

            if resume > 0 {
                println!(
                    "\nSession completed: Generated {} nonces in {}h{:02}m{:02}s, {:.2} MiB/s, {:.2} warps/h.",
                    session_nonces,
                    hours,
                    minutes,
                    seconds,
                    session_nonces as f64 * 1000.0 / (elapsed as f64 + 1.0) / 4.0 / 2.0,
                    session_nonces as f64 * 1000.0 / (elapsed as f64 + 1.0) * 60.0 * 60.0 / 8192.0
                );
                println!(
                    "Total progress: {}/{} nonces (100% complete, {} resumed from previous session).",
                    total_planned_nonces,
                    total_planned_nonces,
                    resumed_nonces
                );
            } else {
                println!(
                    "\nGenerated {} nonces in {}h{:02}m{:02}s, {:.2} MiB/s, {:.2} warps/h.",
                    session_nonces,
                    hours,
                    minutes,
                    seconds,
                    session_nonces as f64 * 1000.0 / (elapsed as f64 + 1.0) / 4.0 / 2.0,
                    session_nonces as f64 * 1000.0 / (elapsed as f64 + 1.0) * 60.0 * 60.0 / 8192.0
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_parsing() {
        // Test various memory formats
        let test_cases = vec![
            ("1GiB", 1_073_741_824u64),
            ("10GiB", 10_737_418_240u64),
            ("512MiB", 536_870_912u64),
            ("1GB", 1_000_000_000u64),
            ("2TB", 2_000_000_000_000u64),
        ];

        for (input, expected) in test_cases {
            let parsed = input.parse::<ByteSize>().unwrap();
            assert_eq!(parsed.as_u64(), expected, "Failed to parse {}", input);
        }
    }
}
