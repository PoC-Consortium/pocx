#![allow(clippy::needless_range_loop)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::const_is_empty)]
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

//! PoCX GPU Plotter Library
//!
//! GPU-fused Proof-of-Capacity plotter with ring buffer design.
//! Minimal host memory (1 GiB) with on-GPU scatter, shuffle, and helix compression.

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

pub mod buffer;
pub mod cpu_compressor;
pub mod cpu_hasher;
pub mod cpu_scheduler;
pub mod disk_writer;
pub mod error;
#[cfg(feature = "opencl")]
pub mod ocl;
pub mod plotter;
#[cfg(feature = "opencl")]
pub mod ring_scheduler;
pub mod utils;

pub use buffer::PageAlignedByteBuffer;
pub use error::{PoCXPlotterError, Result};
#[cfg(feature = "opencl")]
pub use ocl::{get_gpu_device_info, GpuDeviceInfo};
pub use plotter::{Plotter, PlotterTask};

use std::sync::Arc;

/// Callback trait for plotter progress updates
pub trait PlotterCallback: Send + Sync {
    fn on_started(&self, total_warps: u64, resume_offset: u64);
    fn on_hashing_progress(&self, warps_delta: u64);
    fn on_writing_progress(&self, warps_delta: u64);
    fn on_complete(&self, total_warps: u64, duration_ms: u64);
    fn on_error(&self, error: &str);
}

pub struct NoOpPlotterCallback;

impl PlotterCallback for NoOpPlotterCallback {
    fn on_started(&self, _total_warps: u64, _resume_offset: u64) {}
    fn on_hashing_progress(&self, _warps_delta: u64) {}
    fn on_writing_progress(&self, _warps_delta: u64) {}
    fn on_complete(&self, _total_warps: u64, _duration_ms: u64) {}
    fn on_error(&self, _error: &str) {}
}

static PLOTTER_CALLBACK: std::sync::OnceLock<Arc<dyn PlotterCallback>> = std::sync::OnceLock::new();

pub fn set_plotter_callback(callback: Arc<dyn PlotterCallback>) {
    let _ = PLOTTER_CALLBACK.set(callback);
}

pub fn get_plotter_callback() -> Option<Arc<dyn PlotterCallback>> {
    PLOTTER_CALLBACK.get().cloned()
}

#[allow(dead_code)]
pub fn clear_plotter_callback() {
    // OnceLock cannot be cleared. First callback persists for app lifetime.
}

/// Run the plotter with panic safety
pub fn run_plotter_safe(task: PlotterTask) -> Result<()> {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    clear_stop_request();

    let result = catch_unwind(AssertUnwindSafe(|| {
        let plotter = Plotter::new();
        plotter.run(task)
    }));

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            if let Some(cb) = get_plotter_callback() {
                cb.on_error(&e.to_string());
            }
            Err(e)
        }
        Err(panic) => {
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "Unknown panic".to_string());

            let error_msg = format!("Plotter panic: {}", msg);
            if let Some(cb) = get_plotter_callback() {
                cb.on_error(&error_msg);
            }
            Err(PoCXPlotterError::Internal(error_msg))
        }
    }
}

/// Builder for creating PlotterTask configurations programmatically
#[derive(Default)]
pub struct PlotterTaskBuilder {
    address: String,
    address_payload: [u8; 20],
    network_id: Option<pocx_address::NetworkId>,
    initial_seeds: Vec<Option<[u8; 32]>>,
    warps: Vec<u64>,
    number_of_plots: Vec<u64>,
    output_paths: Vec<String>,
    mem: String,
    gpu: String,
    cpu_threads: u8,
    compress: u8,
    direct_io: bool,
    escalate: u64,
    double_buffer: bool,
    quiet: bool,
    benchmark: bool,
    line_progress: bool,
    #[cfg(feature = "opencl")]
    kws_override: usize,
}

impl PlotterTaskBuilder {
    pub fn new() -> Self {
        Self {
            mem: "0B".to_string(),
            compress: 1,
            direct_io: true,
            escalate: 1,
            quiet: true,
            line_progress: true,
            #[cfg(feature = "opencl")]
            kws_override: 0,
            ..Default::default()
        }
    }

    pub fn address(mut self, addr: &str) -> Result<Self> {
        let (payload, network_id) = pocx_address::decode_address(addr)
            .map_err(|e| PoCXPlotterError::InvalidInput(format!("Invalid address: {:?}", e)))?;

        self.address = addr.to_string();
        self.address_payload = payload;
        self.network_id = Some(network_id);
        Ok(self)
    }

    pub fn seed(mut self, seed: [u8; 32]) -> Self {
        if self.initial_seeds.is_empty() {
            self.initial_seeds.push(Some(seed));
        } else {
            self.initial_seeds[0] = Some(seed);
        }
        self
    }

    pub fn add_output(mut self, path: String, warps: u64, plots: u64) -> Self {
        self.output_paths.push(path);
        self.warps.push(warps);
        self.number_of_plots.push(plots);
        self.initial_seeds.push(None);
        self
    }

    pub fn memory(mut self, mem: String) -> Self {
        self.mem = mem;
        self
    }

    pub fn gpu(mut self, gpu: String) -> Self {
        self.gpu = gpu;
        self
    }

    pub fn cpu_threads(mut self, threads: u8) -> Self {
        self.cpu_threads = threads;
        self
    }

    pub fn compression(mut self, level: u8) -> Self {
        self.compress = level;
        self
    }

    pub fn direct_io(mut self, enabled: bool) -> Self {
        self.direct_io = enabled;
        self
    }

    pub fn escalate(mut self, level: u64) -> Self {
        self.escalate = level;
        self
    }

    pub fn double_buffer(mut self, enabled: bool) -> Self {
        self.double_buffer = enabled;
        self
    }

    pub fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    pub fn line_progress(mut self, enabled: bool) -> Self {
        self.line_progress = enabled;
        self
    }

    pub fn benchmark(mut self, enabled: bool) -> Self {
        self.benchmark = enabled;
        self
    }

    #[cfg(feature = "opencl")]
    pub fn kws_override(mut self, size: usize) -> Self {
        self.kws_override = size;
        self
    }

    pub fn build(self) -> Result<PlotterTask> {
        if self.address.is_empty() {
            return Err(PoCXPlotterError::InvalidInput(
                "Address is required".to_string(),
            ));
        }

        if self.output_paths.is_empty() {
            return Err(PoCXPlotterError::InvalidInput(
                "At least one output path is required".to_string(),
            ));
        }

        if self.gpu.is_empty() && self.cpu_threads == 0 {
            return Err(PoCXPlotterError::InvalidInput(
                "Either GPU (e.g. '0:0:0') or CPU threads must be specified".to_string(),
            ));
        }

        let network_id = self
            .network_id
            .ok_or_else(|| PoCXPlotterError::InvalidInput("Network ID not set".to_string()))?;

        Ok(PlotterTask {
            address_payload: self.address_payload,
            address: self.address,
            network_id,
            initial_seeds: self.initial_seeds,
            compress: self.compress,
            warps: self.warps,
            number_of_plots: self.number_of_plots,
            output_paths: self.output_paths,
            mem: self.mem,
            gpu: self.gpu,
            cpu_threads: self.cpu_threads as usize,
            direct_io: self.direct_io,
            escalate: self.escalate,
            double_buffer: self.double_buffer,
            quiet: self.quiet,
            benchmark: self.benchmark,
            line_progress: self.line_progress,
            kws_override: self.kws_override,
            max_concurrent_writes: None,
            startup_messages: Vec::new(),
            work_queue_summary: None,
        })
    }
}
