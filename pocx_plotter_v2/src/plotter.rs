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
use crossbeam_channel::{bounded, Receiver, Sender};
use hex;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use pocx_plotfile::PoCXPlotFile;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use sysinfo::System;

use crate::buffer::PageAlignedByteBuffer;
use crate::cpu_scheduler::create_cpu_scheduler_thread;
use crate::disk_writer::create_writer_thread;
use crate::error::{PoCXPlotterError, Result};
use crate::get_plotter_callback;
#[cfg(feature = "opencl")]
use crate::ocl::{gpu_get_info, gpu_ring_init};
#[cfg(feature = "opencl")]
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
    /// Per-path initial seeds. `Some` = resume with this seed, `None` = generate random.
    pub initial_seeds: Vec<Option<[u8; 32]>>,
    pub warps: Vec<u64>,
    pub number_of_plots: Vec<u64>,
    pub output_paths: Vec<String>,
    pub mem: String,
    pub gpu: String,
    pub cpu_threads: usize,
    pub compress: u8,
    pub direct_io: bool,
    pub escalate: u64,
    pub double_buffer: bool,
    pub quiet: bool,
    pub benchmark: bool,
    pub line_progress: bool,
    pub kws_override: usize,
    /// Max concurrent disk writes. `None` = no limit (one per disk).
    pub max_concurrent_writes: Option<usize>,
    /// Messages collected during work queue building, printed after the banner.
    pub startup_messages: Vec<String>,
    /// Work queue summary line, printed after the slot table.
    pub work_queue_summary: Option<String>,
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

        let cpu_mode = task.cpu_threads > 0;

        let cpu_name = sys
            .cpus()
            .first()
            .map(|cpu| cpu.brand().trim().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| {
                #[cfg(target_arch = "aarch64")]
                {
                    "ARM/Other CPU".to_string()
                }
                #[cfg(not(target_arch = "aarch64"))]
                {
                    "Unknown CPU".to_string()
                }
            });
        let cores = num_cpus::get() as u32;
        let simd_ext = crate::cpu_hasher::init_simd();

        if !task.quiet {
            println!("PoCX Plotter {}", env!("CARGO_PKG_VERSION"));
            println!("written by Proof of Capacity Consortium in Rust\n");
            for msg in &task.startup_messages {
                eprintln!("{}", msg);
            }
        }

        if !task.quiet && task.benchmark {
            println!("*BENCHMARK MODE*\n");
        }

        if !task.quiet {
            let simd_str = match simd_ext {
                crate::cpu_hasher::SimdExtension::None => String::new(),
                _ => format!(" + {:?}", simd_ext),
            };
            println!(
                "CPU: {} [using {} of {} cores{}]",
                cpu_name, task.cpu_threads, cores, simd_str
            );
        }

        // Get GPU info (only in GPU mode)
        #[cfg(feature = "opencl")]
        let (_worksize, _ring_size, mem_gpu) = if !cpu_mode {
            let info = gpu_get_info(&task.gpu, task.quiet, task.kws_override);
            if info.0 == 0 {
                return Err(PoCXPlotterError::Hardware(
                    "No GPU available or GPU initialization failed".to_string(),
                ));
            }
            info
        } else {
            (0, 0, 0)
        };
        #[cfg(not(feature = "opencl"))]
        let mem_gpu: u64 = 0;

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

        // Check resume per path
        let mut resumes: Vec<u64> = vec![0; task.output_paths.len()];
        for i in 0..task.output_paths.len() {
            if let Some(seed) = task.initial_seeds.get(i).copied().flatten() {
                let optimized_plot_file = PoCXPlotFile::new(
                    &task.output_paths[i],
                    &task.address_payload,
                    &seed,
                    task.warps[i],
                    task.compress,
                    false,
                    false,
                );
                if let Ok(mut plot_file) = optimized_plot_file {
                    if let Ok(progress) = plot_file.read_resume_info() {
                        resumes[i] = progress;
                    }
                }
            }
        }
        let total_resume: u64 = resumes.iter().sum();

        // Validate warps and disk space per path
        if task.benchmark {
            for i in 0..task.output_paths.len() {
                if task.warps[i] == 0 {
                    task.warps[i] = 1;
                }
                if task.number_of_plots[i] == 0 {
                    task.number_of_plots[i] = 1;
                }
            }
        } else {
            for i in 0..task.output_paths.len() {
                let path = Path::new(&task.output_paths[i]);
                if !path.exists() {
                    return Err(PoCXPlotterError::InvalidInput(format!(
                        "Specified target path does not exist: {:?}",
                        path
                    )));
                }

                let space = free_disk_space(&task.output_paths[i])?;

                if task.warps[i] == 0 {
                    if task.number_of_plots[i] == 0 {
                        return Err(PoCXPlotterError::InvalidInput(
                            "Need to specify either number of plots or number of warps".to_string(),
                        ));
                    }
                    task.warps[i] = space / WARP_SIZE / task.number_of_plots[i];
                    if task.warps[i] == 0 {
                        return Err(PoCXPlotterError::Config(format!(
                            "Insufficient disk space, MiB_required={:.2}, MiB_available={:.2}, path={}",
                            (task.number_of_plots[i] * WARP_SIZE) as f64 / 1024.0 / 1024.0,
                            space as f64 / 1024.0 / 1024.0,
                            &task.output_paths[i]
                        )));
                    }
                } else if task.number_of_plots[i] == 0 {
                    task.number_of_plots[i] = space / WARP_SIZE / task.warps[i];
                } else {
                    let required_space = task.warps[i]
                        .checked_mul(task.number_of_plots[i])
                        .and_then(|v| v.checked_mul(WARP_SIZE))
                        .ok_or_else(|| {
                            PoCXPlotterError::Config("Disk space calculation overflow".to_string())
                        })?;

                    // Skip disk space check for resume jobs (files already preallocated)
                    if task.initial_seeds.get(i).and_then(|s| s.as_ref()).is_none()
                        && required_space >= space
                    {
                        return Err(PoCXPlotterError::Config(format!(
                            "Insufficient disk space, MiB_required={:.2}, MiB_available={:.2}, path={}",
                            required_space as f64 / 1024.0 / 1024.0,
                            space as f64 / 1024.0 / 1024.0,
                            &task.output_paths[i]
                        )));
                    }
                }
            }
        }

        // Host memory: write buffers + scatter buffer (CPU only)
        let mem_write = WARP_SIZE * task.escalate;
        let mem_scatter: u64 = if cpu_mode {
            8192 * pocx_hashlib::noncegen_common::NONCE_SIZE as u64
        } else {
            0
        };

        let mem_limit = task
            .mem
            .parse::<ByteSize>()
            .map_err(|_| {
                PoCXPlotterError::InvalidInput(format!(
                    "Can't parse memory limit parameter: {}. Example: --mem 10GiB",
                    task.mem
                ))
            })?
            .as_u64();

        let available_mem = sys.available_memory();
        let max_mem_usage = if mem_limit > 0 {
            std::cmp::min(mem_limit, available_mem)
        } else {
            available_mem
        };

        // 1 buffer per unique physical disk path + 1 if double buffering enabled.
        // Multiple job slots on the same disk share buffers.
        // When -t limits writer threads, cap buffer count so only that many
        // writes can be in-flight at once — the GPU pipeline blocks naturally.
        let unique_disk_count = {
            let mut unique = task.output_paths.clone();
            unique.sort();
            unique.dedup();
            unique.len() as u64
        };
        let effective_writers = if let Some(c) = task.max_concurrent_writes {
            (c as u64).min(unique_disk_count).max(1)
        } else {
            unique_disk_count
        };
        let num_write_buffers = effective_writers + if task.double_buffer { 1 } else { 0 };

        let total_host_mem = mem_write * num_write_buffers + mem_scatter;
        if max_mem_usage < total_host_mem {
            return Err(PoCXPlotterError::Memory(format!(
                "Insufficient host memory!\nRAM: Available={:.2} GiB, Need={:.2} GiB ({} x {:.2} GiB write buffers{})\nGPU-RAM: {:.2} GiB",
                available_mem as f64 / 1024.0 / 1024.0 / 1024.0,
                total_host_mem as f64 / 1024.0 / 1024.0 / 1024.0,
                num_write_buffers,
                mem_write as f64 / 1024.0 / 1024.0 / 1024.0,
                if cpu_mode { " + 2 GiB scatter" } else { "" },
                mem_gpu as f64 / 1024.0 / 1024.0 / 1024.0,
            )));
        }

        let total_planned_warps: u64 = task
            .warps
            .iter()
            .zip(task.number_of_plots.iter())
            .map(|(w, n)| w * n)
            .sum();
        let total_warps = total_planned_warps - total_resume;

        if task.line_progress {
            println!("#TOTAL:{}", total_warps);
        }

        if let Some(cb) = get_plotter_callback() {
            cb.on_started(total_warps, total_resume);
        }

        if !task.quiet {
            println!(
                "RAM: Total={:.2} GiB, Available={:.2} GiB, Usage={:.2} GiB",
                sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0,
                available_mem as f64 / 1024.0 / 1024.0 / 1024.0,
                total_host_mem as f64 / 1024.0 / 1024.0 / 1024.0,
            );
            if cpu_mode {
                println!(
                    "     Cache(HDD)={:.2} GiB x{} (escalation) x{} (buffers{}), Scatter={:.2} GiB",
                    WARP_SIZE as f64 / 1024.0 / 1024.0 / 1024.0,
                    task.escalate,
                    num_write_buffers,
                    if task.double_buffer {
                        ", double-buffered"
                    } else {
                        ""
                    },
                    mem_scatter as f64 / 1024.0 / 1024.0 / 1024.0,
                );
            } else {
                println!(
                    "     Cache(HDD)={:.2} GiB x{} (escalation) x{} (buffers{}), Cache(GPU)={:.2} GiB",
                    WARP_SIZE as f64 / 1024.0 / 1024.0 / 1024.0,
                    task.escalate,
                    num_write_buffers,
                    if task.double_buffer { ", double-buffered" } else { "" },
                    mem_gpu as f64 / 1024.0 / 1024.0 / 1024.0,
                );
            }

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
                "Compression   : {}(X{})",
                1u64 << task.compress,
                task.compress
            );
            println!("Total warps   : {}\n", total_warps);

            // Build the per-slot table: Path | Files | Warps | Resume | Seed
            let n = task.output_paths.len();
            let resume_strs: Vec<String> = resumes
                .iter()
                .map(|&r| {
                    if r > 0 {
                        r.to_string()
                    } else {
                        "-".to_string()
                    }
                })
                .collect();
            let seed_strs: Vec<String> = task
                .initial_seeds
                .iter()
                .map(|s| match s {
                    Some(seed) => {
                        let full = hex::encode_upper(seed);
                        format!("{}...", &full[..20])
                    }
                    None => "-".to_string(),
                })
                .collect();

            let col_path = task
                .output_paths
                .iter()
                .map(|s| s.len())
                .max()
                .unwrap_or(4)
                .max(4);
            let col_files = task
                .number_of_plots
                .iter()
                .map(|v| v.to_string().len())
                .max()
                .unwrap_or(5)
                .max(5);
            let col_warps = task
                .warps
                .iter()
                .map(|v| v.to_string().len())
                .max()
                .unwrap_or(5)
                .max(5);
            let col_res = resume_strs
                .iter()
                .map(|s| s.len())
                .max()
                .unwrap_or(6)
                .max(6);
            let col_seed = seed_strs.iter().map(|s| s.len()).max().unwrap_or(4).max(4);

            println!(
                "{:<col_path$}  {:>col_files$}  {:>col_warps$}  {:>col_res$}  {:<col_seed$}",
                "Path",
                "Files",
                "Warps",
                "Resume",
                "Seed",
                col_path = col_path,
                col_files = col_files,
                col_warps = col_warps,
                col_res = col_res,
                col_seed = col_seed
            );
            println!(
                "{:-<col_path$}  {:->col_files$}  {:->col_warps$}  {:->col_res$}  {:-<col_seed$}",
                "",
                "",
                "",
                "",
                "",
                col_path = col_path,
                col_files = col_files,
                col_warps = col_warps,
                col_res = col_res,
                col_seed = col_seed
            );
            for i in 0..n {
                println!(
                    "{:<col_path$}  {:>col_files$}  {:>col_warps$}  {:>col_res$}  {:<col_seed$}",
                    task.output_paths[i],
                    task.number_of_plots[i],
                    task.warps[i],
                    resume_strs[i],
                    seed_strs[i],
                    col_path = col_path,
                    col_files = col_files,
                    col_warps = col_warps,
                    col_res = col_res,
                    col_seed = col_seed
                );
            }
            println!();
            if let Some(ref summary) = task.work_queue_summary {
                println!("{}", summary);
            }

            #[cfg(windows)]
            if !is_elevated() {
                println!(
                    "WARNING: administrative rights missing, file pre-allocations will be slow!\n"
                );
            }

            println!("Start plotting...\n");
        }

        // Create shared empty-buffer pool
        let (tx_empty_write_buffers, rx_empty_write_buffers) = bounded(num_write_buffers as usize);

        // Allocate write buffers (each holds `escalate` warps)
        for _ in 0..num_write_buffers {
            let buffer = PageAlignedByteBuffer::new(mem_write as usize)?;
            tx_empty_write_buffers.send(buffer).map_err(|e| {
                PoCXPlotterError::Channel(format!("Failed to send empty write buffer: {}", e))
            })?;
        }

        // Progress bars (matching old plotter style)
        let multi_progress = if !task.quiet && !task.line_progress {
            let mp = MultiProgress::new();
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
            Some(Arc::new(pb))
        } else {
            None
        };

        let start_time = Instant::now();
        let task = Arc::new(task);

        // Build slot → unique-disk mapping so we create one writer per physical disk.
        // Multiple job slots targeting the same disk share a single writer thread.
        let mut disk_first_slot: Vec<usize> = Vec::new();
        let mut slot_to_disk: Vec<usize> = Vec::new();
        {
            let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
            for (slot, path) in task.output_paths.iter().enumerate() {
                let disk_idx = *seen.entry(path.as_str()).or_insert_with(|| {
                    let idx = disk_first_slot.len();
                    disk_first_slot.push(slot);
                    idx
                });
                slot_to_disk.push(disk_idx);
            }
        }

        // Create one writer thread per unique disk.
        // An I/O semaphore limits concurrent writer threads to avoid overwhelming SMB/NAS.
        let num_disks = disk_first_slot.len();
        let io_permit: Option<(Sender<()>, Receiver<()>)> =
            if let Some(limit) = task.max_concurrent_writes {
                let limit = limit.min(num_disks).max(1);
                let (tx, rx) = bounded(limit);
                for _ in 0..limit {
                    tx.send(()).unwrap();
                }
                Some((tx, rx))
            } else {
                None
            };

        // Initialize GPU ring scheduler (only when not in CPU mode)
        #[cfg(feature = "opencl")]
        let gpu_ctx = if !cpu_mode {
            Some(
                gpu_ring_init(&task.gpu, task.kws_override)
                    .map_err(|e| PoCXPlotterError::Hardware(format!("GPU init failed: {}", e)))?,
            )
        } else {
            None
        };
        let mut writers = Vec::new();
        let mut disk_senders = Vec::new();
        for &first_slot in &disk_first_slot {
            let (tx_full, rx_full) = bounded(num_write_buffers as usize);
            let write_progress = write_pb.as_ref().cloned();
            let permit: Option<(Receiver<()>, Sender<()>)> =
                io_permit.as_ref().map(|(tx, rx)| (rx.clone(), tx.clone()));
            writers.push(thread::spawn({
                create_writer_thread(
                    task.clone(),
                    write_progress,
                    rx_full,
                    tx_empty_write_buffers.clone(),
                    first_slot,
                    permit,
                )
            }));
            disk_senders.push(tx_full);
        }

        // Per-slot sender: each slot's sender is a clone of its disk's sender.
        // The ring scheduler indexes by slot — this routes to the shared writer.
        let tx_full_per_path: Vec<_> = slot_to_disk
            .iter()
            .map(|&disk_idx| disk_senders[disk_idx].clone())
            .collect();
        drop(disk_senders);

        if cpu_mode {
            // CPU mode: use CPU scheduler with rayon thread pool
            let hasher = thread::spawn({
                create_cpu_scheduler_thread(
                    task.clone(),
                    task.cpu_threads,
                    hash_pb,
                    rx_empty_write_buffers,
                    tx_full_per_path,
                    total_resume,
                )
            });
            hasher
                .join()
                .map_err(|_| PoCXPlotterError::Channel("CPU hasher thread panicked".to_string()))?;
        } else {
            // GPU mode: ring buffer scheduler with per-slot resume and disk routing
            #[cfg(feature = "opencl")]
            {
                let hasher = thread::spawn({
                    create_ring_scheduler_thread(
                        task.clone(),
                        gpu_ctx.unwrap(),
                        hash_pb,
                        rx_empty_write_buffers,
                        tx_full_per_path,
                        resumes,
                        slot_to_disk,
                    )
                });
                hasher.join().map_err(|_| {
                    PoCXPlotterError::Channel("GPU hasher thread panicked".to_string())
                })?;
            }
            #[cfg(not(feature = "opencl"))]
            {
                return Err(PoCXPlotterError::Hardware(
                    "GPU mode requires the 'opencl' feature".to_string(),
                ));
            }
        }

        for writer in writers {
            writer
                .join()
                .map_err(|_| PoCXPlotterError::Channel("Writer thread panicked".to_string()))?;
        }

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

            let dropped =
                crate::disk_writer::WARPS_DROPPED.load(std::sync::atomic::Ordering::Relaxed);
            if dropped > 0 {
                eprintln!(
                    "\nWARNING: {} warp(s) ({:.2} GiB) lost to write errors and need re-computation. \
                     Re-run with the same parameters to resume.",
                    dropped,
                    dropped as f64 * WARP_SIZE as f64 / 1024.0 / 1024.0 / 1024.0
                );
            }
        }

        if let Some(cb) = get_plotter_callback() {
            cb.on_complete(total_warps, elapsed);
        }

        Ok(())
    }
}
