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

//! PoCX Plotter Library
//!
//! Professional cryptocurrency plotting library for PoCX blockchain
//! Provides high-performance CPU and GPU plotting capabilities

#[macro_use]
extern crate cfg_if;

use std::sync::atomic::{AtomicBool, Ordering};

/// Global stop flag for graceful termination
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Request the plotter to stop as soon as possible
pub fn request_stop() {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

/// Check if stop has been requested
pub fn is_stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

/// Clear the stop request (call before starting a new plot)
pub fn clear_stop_request() {
    STOP_REQUESTED.store(false, Ordering::SeqCst);
}

pub mod buffer;
pub mod compressor;
pub mod cpu_hasher;
pub mod disk_writer;
pub mod error;
#[cfg(feature = "opencl")]
pub mod gpu_hasher;
#[cfg(feature = "opencl")]
pub mod ocl;
pub mod perf_monitor;
pub mod plotter;
pub mod utils;
pub mod xpu_scheduler;

// Re-export main types for convenience
pub use buffer::PageAlignedByteBuffer;
pub use error::{PoCXPlotterError, Result};
pub use plotter::{Plotter, PlotterTask};
#[cfg(feature = "opencl")]
pub use ocl::{get_gpu_device_info, GpuDeviceInfo};

use std::sync::Arc;

/// Callback trait for plotter progress updates
///
/// Progress is reported in warps (1 warp = 4096 nonces = 1 GiB uncompressed).
/// The caller can calculate bytes/percentages from warp counts.
pub trait PlotterCallback: Send + Sync {
    /// Called when plotting starts
    fn on_started(&self, total_warps: u64, resume_offset: u64);

    /// Called after each buffer is hashed (reports warp delta)
    fn on_hashing_progress(&self, warps_delta: u64);

    /// Called after each buffer is written (reports warp delta)
    fn on_writing_progress(&self, warps_delta: u64);

    /// Called when all plotting is complete
    fn on_complete(&self, total_warps: u64, duration_ms: u64);

    /// Called on error (including caught panics)
    fn on_error(&self, error: &str);
}

/// No-op callback implementation for standalone usage
pub struct NoOpPlotterCallback;

impl PlotterCallback for NoOpPlotterCallback {
    fn on_started(&self, _total_warps: u64, _resume_offset: u64) {}
    fn on_hashing_progress(&self, _warps_delta: u64) {}
    fn on_writing_progress(&self, _warps_delta: u64) {}
    fn on_complete(&self, _total_warps: u64, _duration_ms: u64) {}
    fn on_error(&self, _error: &str) {}
}

/// Global callback holder for the plotter
/// This is used to pass callback references to worker threads
static PLOTTER_CALLBACK: std::sync::OnceLock<Arc<dyn PlotterCallback>> = std::sync::OnceLock::new();

/// Set the global plotter callback
pub fn set_plotter_callback(callback: Arc<dyn PlotterCallback>) {
    let _ = PLOTTER_CALLBACK.set(callback);
}

/// Get the global plotter callback
pub fn get_plotter_callback() -> Option<Arc<dyn PlotterCallback>> {
    PLOTTER_CALLBACK.get().cloned()
}

/// Clear the global plotter callback (useful for resetting between runs)
pub fn clear_plotter_callback() {
    // OnceLock doesn't have a clear method, so we use a different approach
    // The callback will be replaced on next set_plotter_callback call
}

/// Run the plotter with panic safety
///
/// This wrapper catches panics and converts them to errors, preventing
/// plotter crashes from taking down the host application.
pub fn run_plotter_safe(task: PlotterTask) -> Result<()> {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    // Clear any previous stop request before starting
    clear_stop_request();

    let result = catch_unwind(AssertUnwindSafe(|| {
        let plotter = Plotter::new();
        plotter.run(task)
    }));

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            // Normal error - report via callback
            if let Some(cb) = get_plotter_callback() {
                cb.on_error(&e.to_string());
            }
            Err(e)
        }
        Err(panic) => {
            // Panic caught - convert to error
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
    seed: Option<[u8; 32]>,
    warps: Vec<u64>,
    number_of_plots: Vec<u64>,
    compress: u8,
    output_paths: Vec<String>,
    mem: String,
    cpu_threads: u8,
    gpus: Option<Vec<String>>,
    direct_io: bool,
    escalate: u64,
    quiet: bool,
    benchmark: bool,
    line_progress: bool,
    #[cfg(feature = "opencl")]
    zcb: bool,
    #[cfg(feature = "opencl")]
    kws_override: usize,
}

impl PlotterTaskBuilder {
    pub fn new() -> Self {
        Self {
            mem: "0B".to_string(), // Match CLI default format
            cpu_threads: num_cpus::get() as u8,
            direct_io: true,
            escalate: 1,
            quiet: true,
            line_progress: true,
            #[cfg(feature = "opencl")]
            zcb: false,
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
        self.seed = Some(seed);
        self
    }

    pub fn add_output(mut self, path: String, warps: u64, plots: u64) -> Self {
        self.output_paths.push(path);
        self.warps.push(warps);
        self.number_of_plots.push(plots);
        self
    }

    pub fn compression(mut self, level: u8) -> Self {
        self.compress = level;
        self
    }

    pub fn memory(mut self, mem: String) -> Self {
        self.mem = mem;
        self
    }

    pub fn cpu_threads(mut self, threads: u8) -> Self {
        self.cpu_threads = threads;
        self
    }

    #[cfg(feature = "opencl")]
    pub fn gpus(mut self, gpus: Vec<String>) -> Self {
        self.gpus = Some(gpus);
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

    /// Enable zero-copy buffers for integrated GPUs (APUs)
    #[cfg(feature = "opencl")]
    pub fn zcb(mut self, enabled: bool) -> Self {
        self.zcb = enabled;
        self
    }

    /// Override kernel workgroup size (0 = auto-detect)
    #[cfg(feature = "opencl")]
    pub fn kws_override(mut self, size: usize) -> Self {
        self.kws_override = size;
        self
    }

    pub fn build(self) -> Result<PlotterTask> {
        if self.address.is_empty() {
            return Err(PoCXPlotterError::InvalidInput("Address is required".to_string()));
        }

        if self.output_paths.is_empty() {
            return Err(PoCXPlotterError::InvalidInput("At least one output path is required".to_string()));
        }

        let network_id = self.network_id
            .ok_or_else(|| PoCXPlotterError::InvalidInput("Network ID not set".to_string()))?;

        Ok(PlotterTask {
            address_payload: self.address_payload,
            address: self.address,
            network_id,
            seed: self.seed,
            warps: self.warps,
            number_of_plots: self.number_of_plots,
            compress: self.compress,
            output_paths: self.output_paths,
            mem: self.mem,
            cpu_threads: self.cpu_threads,
            gpus: self.gpus,
            direct_io: self.direct_io,
            escalate: self.escalate,
            quiet: self.quiet,
            benchmark: self.benchmark,
            line_progress: self.line_progress,
            #[cfg(feature = "opencl")]
            zcb: self.zcb,
            #[cfg(feature = "opencl")]
            kws_override: self.kws_override,
        })
    }
}
