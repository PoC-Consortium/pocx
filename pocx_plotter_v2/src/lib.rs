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

//! PoCX Plotter v2
//!
//! High-performance Proof-of-Capacity plotter with GPU-fused ring buffer architecture.

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
    seeds: Vec<Option<[u8; 32]>>,
    warps: Vec<u64>,
    number_of_plots: Vec<u64>,
    output_paths: Vec<String>,
    gpu: String,
    cpu_threads: usize,
    cpu_threads_set: bool,
    compress: u8,
    direct_io: bool,
    escalate: u64,
    async_write: bool,
    quiet: bool,
    benchmark: bool,
    #[cfg(feature = "opencl")]
    kws_override: usize,
}

impl PlotterTaskBuilder {
    pub fn new() -> Self {
        Self {
            compress: 1,
            direct_io: true,
            escalate: 1,
            quiet: true,
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

    pub fn seed(mut self, index: usize, seed: [u8; 32]) -> Self {
        if self.seeds.len() <= index {
            self.seeds.resize(index + 1, None);
        }
        self.seeds[index] = Some(seed);
        self
    }

    pub fn add_output(mut self, path: String, warps: u64, plots: u64) -> Self {
        self.output_paths.push(path);
        self.warps.push(warps);
        self.number_of_plots.push(plots);
        self
    }

    pub fn gpu(mut self, gpu: String) -> Self {
        self.gpu = gpu;
        self
    }

    pub fn cpu_threads(mut self, threads: usize) -> Self {
        self.cpu_threads = threads;
        self.cpu_threads_set = true;
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

    pub fn async_write(mut self, enabled: bool) -> Self {
        self.async_write = enabled;
        self
    }

    pub fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
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

        if self.cpu_threads_set && self.cpu_threads == 0 {
            return Err(PoCXPlotterError::InvalidInput(
                "cpu_threads must be greater than 0 when CPU participation is requested"
                    .to_string(),
            ));
        }

        if self.warps.contains(&0) {
            return Err(PoCXPlotterError::InvalidInput(
                "Warps must be greater than 0 for all output paths".to_string(),
            ));
        }

        let network_id = self
            .network_id
            .ok_or_else(|| PoCXPlotterError::InvalidInput("Network ID not set".to_string()))?;

        Ok(PlotterTask {
            address_payload: self.address_payload,
            address: self.address,
            network_id,
            seeds: {
                let mut s = self.seeds;
                s.resize(self.output_paths.len(), None);
                s
            },
            compress: self.compress,
            warps: self.warps,
            number_of_plots: self.number_of_plots,
            output_paths: self.output_paths,
            gpu: self.gpu,
            cpu_threads: self.cpu_threads,
            direct_io: self.direct_io,
            escalate: self.escalate,
            async_write: self.async_write,
            quiet: self.quiet,
            benchmark: self.benchmark,
            kws_override: self.kws_override,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ADDRESS: &str = "POCX-2345-4567-89AB-CDEF1";

    fn make_builder() -> PlotterTaskBuilder {
        let mut payload = [0u8; 20];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i * 7) as u8;
        }
        let addr =
            pocx_address::encode_address(&payload, pocx_address::NetworkId::Base58(0x55)).unwrap();
        PlotterTaskBuilder::new()
            .address(&addr)
            .unwrap()
            .add_output("/tmp/plot_test".to_string(), 1, 1)
    }

    #[test]
    fn test_cpu_threads_256_does_not_overflow() {
        let _ = TEST_ADDRESS;
        let task = make_builder().cpu_threads(256).build().unwrap();
        assert_eq!(
            task.cpu_threads, 256,
            "cpu_threads=256 must be preserved (u8 overflow would yield 0)"
        );
    }

    #[test]
    fn test_cpu_threads_1024_preserved() {
        let task = make_builder().cpu_threads(1024).build().unwrap();
        assert_eq!(task.cpu_threads, 1024);
    }

    #[test]
    fn test_rayon_pool_honors_large_thread_count() {
        let requested = 256usize;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(requested)
            .build()
            .expect("pool build");
        assert_eq!(
            pool.current_num_threads(),
            requested,
            "rayon should create exactly the requested number of threads"
        );
    }

    #[test]
    fn test_explicit_zero_cpu_threads_rejected() {
        let result = make_builder()
            .gpu("0:0:0".to_string())
            .cpu_threads(0)
            .build();
        assert!(
            result.is_err(),
            "explicit cpu_threads(0) with GPU set must be rejected"
        );
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("cpu_threads"),
            "error should mention cpu_threads, got: {msg}"
        );
    }

    #[test]
    fn test_gpu_only_build_succeeds() {
        let task = make_builder()
            .gpu("0:0:0".to_string())
            .build()
            .ok()
            .expect("GPU-only config should build");
        assert_eq!(task.cpu_threads, 0);
        assert_eq!(task.gpu, "0:0:0");
    }
}
