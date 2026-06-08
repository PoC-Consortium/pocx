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

//! OpenCL GPU acceleration for PoCX mining.

use crate::com::api::NonceSubmission;
use crate::com::api::SubmissionParameters;
use crate::hasher::HashingTask;
use pocx_plotfile::NUM_SCOOPS;

#[cfg(feature = "opencl")]
use opencl3::command_queue::CommandQueue;
#[cfg(feature = "opencl")]
use opencl3::context::Context;
#[cfg(feature = "opencl")]
use opencl3::device::{Device, CL_DEVICE_TYPE_GPU};
#[cfg(feature = "opencl")]
use opencl3::kernel::{ExecuteKernel, Kernel};
#[cfg(feature = "opencl")]
use opencl3::memory::{Buffer, CL_MEM_READ_ONLY, CL_MEM_READ_WRITE};
#[cfg(feature = "opencl")]
use opencl3::platform::get_platforms;
#[cfg(feature = "opencl")]
use opencl3::program::Program;
#[cfg(feature = "opencl")]
use opencl3::types::CL_BLOCKING;

#[cfg(feature = "opencl")]
use std::sync::Mutex;

#[cfg(feature = "opencl")]
static KERNEL_SRC: &str = include_str!("../../pocx_plotter/src/ocl/kernel.cl");

#[cfg(feature = "opencl")]
pub struct GpuContext {
    pub device_name: String,
    _context: Context,
    queue: CommandQueue,
    kernel: Kernel,
    // Reuse buffers to avoid re-allocation overhead
    scoop_buffer: Mutex<Buffer<u32>>,
    gensig_buffer: Mutex<Buffer<u32>>,
    results_buffer: Mutex<Buffer<u64>>,
    max_nonces: usize,
}

// Safety: GpuContext is safe to send between threads as OpenCL handles are thread-safe.
// Internal buffers are protected by Mutex.
unsafe impl Sync for GpuContext {}
unsafe impl Send for GpuContext {}

#[cfg(feature = "opencl")]
impl GpuContext {
    pub fn new(platform_idx: usize, device_idx: usize, max_nonces: usize) -> Result<Self, String> {
        let platforms = get_platforms().map_err(|e| format!("OCL error: {:?}", e))?;
        if platform_idx >= platforms.len() {
            return Err(format!("Invalid platform index: {}", platform_idx));
        }
        let platform = platforms[platform_idx];

        let devices = platform
            .get_devices(CL_DEVICE_TYPE_GPU)
            .map_err(|e| format!("OCL error: {:?}", e))?;
        if device_idx >= devices.len() {
            return Err(format!("Invalid device index: {}", device_idx));
        }
        let device = Device::new(devices[device_idx]);
        let name = device.name().unwrap_or_else(|_| "Unknown".to_string());

        let context = Context::from_device(&device).map_err(|e| format!("OCL error: {:?}", e))?;
        let queue =
            CommandQueue::create_default(&context, 0).map_err(|e| format!("OCL error: {:?}", e))?;

        let program = Program::create_and_build_from_source(&context, KERNEL_SRC, "")
            .map_err(|e| format!("OCL error: {:?}", e))?;
        let kernel = Kernel::create(&program, "find_best_quality")
            .map_err(|e| format!("OCL error: {:?}", e))?;

        // Pre-allocate buffers for the maximum expected work size
        let scoop_buffer = unsafe {
            Buffer::<u32>::create(
                &context,
                CL_MEM_READ_ONLY,
                max_nonces * 16,
                std::ptr::null_mut(),
            )
            .map_err(|e| format!("Buffer error: {:?}", e))?
        };
        let gensig_buffer = unsafe {
            Buffer::<u32>::create(&context, CL_MEM_READ_ONLY, 8, std::ptr::null_mut())
                .map_err(|e| format!("Buffer error: {:?}", e))?
        };
        let results_buffer = unsafe {
            Buffer::<u64>::create(
                &context,
                CL_MEM_READ_WRITE,
                max_nonces,
                std::ptr::null_mut(),
            )
            .map_err(|e| format!("Buffer error: {:?}", e))?
        };

        Ok(Self {
            device_name: name,
            _context: context,
            queue,
            kernel,
            scoop_buffer: Mutex::new(scoop_buffer),
            gensig_buffer: Mutex::new(gensig_buffer),
            results_buffer: Mutex::new(results_buffer),
            max_nonces,
        })
    }

    pub fn process_task(&self, task: HashingTask) {
        let num_nonces = (task.number_of_warps * NUM_SCOOPS) as usize;
        if num_nonces > self.max_nonces {
            // Fallback to CPU if task is too large for GPU buffers
            log::warn!(
                "Task size {} exceeds GPU buffer capacity {}, falling back to CPU",
                num_nonces,
                self.max_nonces
            );
            (crate::hasher::calc_qualities(task))();
            return;
        }

        let scoop_data = task.buffer.get_buffer_ref();
        let gensig =
            unsafe { std::mem::transmute::<[u8; 32], [u32; 8]>(task.generation_signature_bytes) };

        let mut s_buf = self.scoop_buffer.lock().unwrap();
        let mut g_buf = self.gensig_buffer.lock().unwrap();
        let r_buf = self.results_buffer.lock().unwrap();

        // 1. Upload data
        let scoop_data_u32 = unsafe {
            std::slice::from_raw_parts(scoop_data.as_ptr() as *const u32, num_nonces * 16)
        };
        unsafe {
            self.queue
                .enqueue_write_buffer(&mut s_buf, CL_BLOCKING, 0, scoop_data_u32, &[])
                .expect("OCL write error");
            self.queue
                .enqueue_write_buffer(&mut g_buf, CL_BLOCKING, 0, &gensig, &[])
                .expect("OCL write error");
        }

        // 2. Set args and run
        let kernel = self.kernel.clone();
        unsafe {
            kernel.set_arg(0, &*s_buf).expect("OCL arg error");
            kernel.set_arg(1, &*g_buf).expect("OCL arg error");
            kernel.set_arg(2, &*r_buf).expect("OCL arg error");
            kernel
                .set_arg(3, &(num_nonces as u32))
                .expect("OCL arg error");

            ExecuteKernel::new(&kernel)
                .set_global_work_size(num_nonces)
                .enqueue_nd_range(&self.queue)
                .expect("OCL exec error");
        }

        // 3. Download results
        let mut results = vec![0u64; num_nonces];
        unsafe {
            self.queue
                .enqueue_read_buffer(&r_buf, CL_BLOCKING, 0, &mut results, &[])
                .expect("OCL read error");
        }

        // 4. Find best quality
        let mut best_quality = u64::MAX;
        let mut best_offset = 0;
        for (i, &q) in results.iter().enumerate() {
            if q < best_quality {
                best_quality = q;
                best_offset = i as u64;
            }
        }

        // 5. Submit result
        if task
            .tx_nonce_data
            .clone()
            .unbounded_send((
                task.chain_id,
                SubmissionParameters {
                    chain: task.chain_name,
                    block_count: task.block_count,
                    nonce_submission: NonceSubmission {
                        block_hash: task.block_hash,
                        account_id: task.account_id,
                        seed: task.seed,
                        nonce: task.start_warp * NUM_SCOOPS + best_offset,
                        block_height: task.block_height,
                        generation_signature: hex::encode(task.generation_signature_bytes),
                        base_target: task.base_target,
                        raw_quality: best_quality,
                        compression: task.compression_level,
                    },
                },
            ))
            .is_err()
        {
            log::debug!("GPU Hasher: nonce channel closed");
        }

        // Return buffer to pool
        let _ = task.tx_buffer.send(task.buffer);
    }
}

pub fn list_gpu_devices() {
    #[cfg(feature = "opencl")]
    {
        if let Ok(platforms) = get_platforms() {
            for (p_idx, p) in platforms.iter().enumerate() {
                if let Ok(devices) = p.get_devices(CL_DEVICE_TYPE_GPU) {
                    for (d_idx, d) in devices.iter().enumerate() {
                        let device = Device::new(*d);
                        if let Ok(name) = device.name() {
                            println!(
                                "GPU Device [Platform {}, Device {}]: {}",
                                p_idx, d_idx, name
                            );
                        }
                    }
                }
            }
        }
    }
}
