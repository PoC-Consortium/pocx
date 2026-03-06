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
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::System;

use crate::buffer::PageAlignedByteBuffer;
use crate::disk_writer::create_writer_thread;
use crate::error::{PoCXPlotterError, Result};
use crate::get_plotter_callback;
use crate::ocl::{gpu_get_info, gpu_ring_init};
use crate::ring_scheduler::create_ring_scheduler_thread;
use crate::utils::free_disk_space;
use crate::utils::get_sector_size;

#[cfg(windows)]
use crate::utils::is_elevated;

pub const DOUBLE_HASH_SIZE: u64 = 64;
pub const DIM: u64 = 4096;
pub const NONCE_SIZE: u64 = DIM * DOUBLE_HASH_SIZE;
pub const WARP_SIZE: u64 = DIM * NONCE_SIZE;

pub struct Plotter {}

pub struct PlotterTask {
    pub address_payload: [u8; 20],
    pub address: String,
    pub network_id: pocx_address::NetworkId,
    pub seed: Option<[u8; 32]>,
    pub warps: Vec<u64>,
    pub number_of_plots: Vec<u64>,
    pub output_paths: Vec<String>,
    pub mem: String,
    pub gpu: String,
    pub compress: u8,
    pub direct_io: bool,
    pub escalate: u64,
    pub quiet: bool,
    pub benchmark: bool,
    pub line_progress: bool,
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

        if !task.quiet {
            println!("PoCX GPU Plotter {}", env!("CARGO_PKG_VERSION"));
            println!("written by Proof of Capacity Consortium in Rust\n");
        }

        if !task.quiet && task.benchmark {
            println!("*BENCHMARK MODE*\n");
        }

        // Get GPU info and validate memory
        let (worksize, _ring_size, mem_gpu) =
            gpu_get_info(&task.gpu, task.quiet, task.kws_override);

        if worksize == 0 {
            return Err(PoCXPlotterError::Hardware(
                "No GPU available or GPU initialization failed".to_string(),
            ));
        }

        // Check direct I/O capabilities
        for path in &task.output_paths {
            let sector_size = get_sector_size(path)?;
            let is_power_of_2 = (sector_size & (sector_size - 1)) == 0;
            if task.direct_io && (!is_power_of_2 || sector_size > (1 << 18)) {
                eprintln!(
                    "Warning: Direct I/O not supported for {} (sector_size={}), falling back to buffered I/O",
                    path, sector_size
                );
                task.direct_io = false;
            }
        }

        // Check resume
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
            if let Ok(mut plot_file) = optimized_plot_file {
                if let Ok(progress) = plot_file.read_resume_info() {
                    resume = progress;
                }
            }
        }

        // Validate warps and disk space
        if task.benchmark {
            // Benchmark mode: default to 1 warp if not specified, skip disk checks
            if task.warps[0] == 0 {
                task.warps[0] = 1;
            }
            if task.number_of_plots[0] == 0 {
                task.number_of_plots[0] = 1;
            }
        } else {
            let path = Path::new(&task.output_paths[0]);
            if !path.exists() {
                return Err(PoCXPlotterError::InvalidInput(format!(
                    "Specified target path does not exist: {:?}",
                    path
                )));
            }

            let space = free_disk_space(&task.output_paths[0])?;

            if task.warps[0] == 0 {
                if task.number_of_plots[0] == 0 {
                    return Err(PoCXPlotterError::InvalidInput(
                        "Need to specify either number of plots or number of warps".to_string(),
                    ));
                }
                task.warps[0] = space / WARP_SIZE / task.number_of_plots[0];
                if task.warps[0] == 0 {
                    return Err(PoCXPlotterError::Config(format!(
                        "Insufficient disk space, MiB_required={:.2}, MiB_available={:.2}, path={}",
                        (task.number_of_plots[0] * WARP_SIZE) as f64 / 1024.0 / 1024.0,
                        space as f64 / 1024.0 / 1024.0,
                        &task.output_paths[0]
                    )));
                }
            } else if task.number_of_plots[0] == 0 {
                task.number_of_plots[0] = space / WARP_SIZE / task.warps[0];
            } else {
                let required_space = task.warps[0]
                    .checked_mul(task.number_of_plots[0])
                    .and_then(|v| v.checked_mul(WARP_SIZE))
                    .ok_or_else(|| {
                        PoCXPlotterError::Config(
                            "Disk space calculation overflow".to_string(),
                        )
                    })?;

                if resume == 0 && required_space >= space {
                    return Err(PoCXPlotterError::Config(format!(
                        "Insufficient disk space, MiB_required={:.2}, MiB_available={:.2}, path={}",
                        required_space as f64 / 1024.0 / 1024.0,
                        space as f64 / 1024.0 / 1024.0,
                        &task.output_paths[0]
                    )));
                }
            }
        }

        // Host memory: only need write buffers (1 GiB each * escalate)
        let mem_write = WARP_SIZE * task.escalate;

        let mem_limit = task.mem.parse::<ByteSize>()
            .map_err(|_| PoCXPlotterError::InvalidInput(format!(
                "Can't parse memory limit parameter: {}. Example: --mem 10GiB",
                task.mem
            )))?
            .as_u64();

        let available_mem = sys.available_memory();
        let max_mem_usage = if mem_limit > 0 {
            std::cmp::min(mem_limit, available_mem)
        } else {
            available_mem
        };

        let num_write_buffers = std::cmp::min(
            std::cmp::max(max_mem_usage / mem_write, 1),
            task.escalate,
        );

        if max_mem_usage < mem_write {
            return Err(PoCXPlotterError::Memory(format!(
                "Insufficient host memory!\nRAM: Available={:.2} GiB, Need={:.2} GiB (1 write buffer)\nGPU-RAM: {:.2} GiB",
                available_mem as f64 / 1024.0 / 1024.0 / 1024.0,
                mem_write as f64 / 1024.0 / 1024.0 / 1024.0,
                mem_gpu as f64 / 1024.0 / 1024.0 / 1024.0,
            )));
        }

        let total_planned_warps = task.warps[0] * task.number_of_plots[0];
        let total_warps = total_planned_warps - resume;

        if task.line_progress {
            println!("#TOTAL:{}", total_warps);
        }

        if let Some(cb) = get_plotter_callback() {
            cb.on_started(total_warps, resume);
        }

        if !task.quiet {
            println!(
                "RAM: Total={:.2} GiB, Available={:.2} GiB, Host usage={:.2} GiB ({} write buffers)",
                sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0,
                available_mem as f64 / 1024.0 / 1024.0 / 1024.0,
                (mem_write * num_write_buffers) as f64 / 1024.0 / 1024.0 / 1024.0,
                num_write_buffers,
            );

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
            println!("Compression    : {}(X{})", 1u64 << task.compress, task.compress);
            println!("Output path    : {}", task.output_paths[0]);
            println!("Files to plot  : {}", task.number_of_plots[0]);
            println!("Warps per file : {}", task.warps[0]);
            println!("Total warps    : {}\n", total_warps);

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

        // Create channels
        let (tx_empty_write_buffers, rx_empty_write_buffers) =
            bounded(num_write_buffers as usize);
        let (tx_full_write_buffers, rx_full_write_buffers) =
            bounded(num_write_buffers as usize);

        // Allocate write buffers
        for _ in 0..num_write_buffers {
            let buffer = PageAlignedByteBuffer::new(WARP_SIZE as usize)?;
            tx_empty_write_buffers.send(buffer).map_err(|e| {
                PoCXPlotterError::Channel(format!("Failed to send empty write buffer: {}", e))
            })?;
        }

        // Progress bars (matching old plotter style)
        let multi_progress = if !task.quiet && !task.line_progress {
            let mp = MultiProgress::new();
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

        // Initialize GPU
        let gpu_ctx = gpu_ring_init(&task.gpu, task.kws_override)
            .map_err(|e| PoCXPlotterError::Hardware(format!("GPU init failed: {}", e)))?;

        // Create writer thread
        let write_progress = write_pb.clone();
        let writer = thread::spawn({
            create_writer_thread(
                task.clone(),
                write_progress,
                rx_full_write_buffers,
                tx_empty_write_buffers.clone(),
                0,
            )
        });

        // Create ring scheduler thread
        let hasher = thread::spawn({
            create_ring_scheduler_thread(
                task.clone(),
                gpu_ctx,
                hash_pb,
                rx_empty_write_buffers,
                tx_full_write_buffers,
                resume,
            )
        });

        hasher
            .join()
            .map_err(|_| PoCXPlotterError::Channel("Hasher thread panicked".to_string()))?;
        writer
            .join()
            .map_err(|_| PoCXPlotterError::Channel("Writer thread panicked".to_string()))?;

        let elapsed = start_time.elapsed().as_millis() as u64;
        let hours = elapsed / 1000 / 60 / 60;
        let minutes = elapsed / 1000 / 60 - hours * 60;
        let seconds = elapsed / 1000 - hours * 60 * 60 - minutes * 60;

        if !task.quiet {
            let passes_per_warp = 1u64 << (task.compress - 1);
            let session_nonces = passes_per_warp * 2 * total_warps * DIM;
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

        if let Some(cb) = get_plotter_callback() {
            cb.on_complete(total_warps, elapsed);
        }

        Ok(())
    }
}
