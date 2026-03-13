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

//! OpenCL GPU acceleration module for ring buffer GPU plotter.
//!
//! Uses a single ring buffer on the GPU for hashing, with a fused
//! scatter+compress kernel that produces scoop-major compressed output
//! directly on the GPU. Only 1 GiB of host memory is needed for the
//! write buffer.

use crate::plotter::NONCE_SIZE;
use opencl3::command_queue::CommandQueue;
use opencl3::context::Context;
use opencl3::device::{Device, CL_DEVICE_TYPE_GPU};
use opencl3::kernel::{ExecuteKernel, Kernel};
use opencl3::memory::{Buffer, CL_MEM_READ_ONLY, CL_MEM_READ_WRITE};
use opencl3::platform::get_platforms;
use opencl3::program::Program;
use opencl3::types::{CL_BLOCKING, CL_NON_BLOCKING};
use std::cmp::min;
use std::ptr;

static SRC: &str = include_str!("ocl/kernel.cl");

const GPU_HASHES_PER_RUN: usize = 32;
const COMPRESS_BATCH: u64 = 8192;
const DIM: u64 = 4096;
const DOUBLE_HASH_SIZE: u64 = 64;
const NONCES_VECTOR: u64 = 16;
const MAX_RING_SPLITS: usize = 4;

/// Compute ring buffer size in nonces: R = W + C - gcd(W, C)
pub fn compute_ring_size(worksize: u64) -> u64 {
    let w = worksize;
    let c = COMPRESS_BATCH;
    w + c - gcd(w, c)
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

pub struct GpuRingContext {
    #[allow(dead_code)]
    context: Context,
    queue_hash: CommandQueue,
    queue_transfer: CommandQueue,
    hash_kernel: Kernel,
    compress_kernel: Kernel,
    hash_kernel_split: Option<Kernel>,
    compress_kernel_split: Option<Kernel>,
    ldim1: [usize; 3],
    gdim1: [usize; 3],
    base58: Buffer<u8>,
    seed: Buffer<u8>,
    ring_buffer: Buffer<u8>,
    ring_sub_buffers: Vec<Buffer<u8>>,
    nonces_per_sub: u64,
    compressed_buffer: Buffer<u8>,
    pub worksize: u64,
    pub ring_size: u64,
}

// Safety: GpuRingContext is safe to send between threads as OpenCL handles are thread-safe
unsafe impl Sync for GpuRingContext {}
unsafe impl Send for GpuRingContext {}

impl GpuRingContext {
    pub fn new(
        gpu_platform: usize,
        gpu_id: usize,
        cores: usize,
        kws_override: usize,
    ) -> Result<GpuRingContext, String> {
        let platforms =
            get_platforms().map_err(|e| format!("Failed to get OpenCL platforms: {:?}", e))?;
        let platform = platforms[gpu_platform];

        let devices = platform
            .get_devices(CL_DEVICE_TYPE_GPU)
            .map_err(|e| format!("Failed to get GPU devices: {:?}", e))?;
        let device = Device::new(devices[gpu_id]);

        let context = Context::from_device(&device)
            .map_err(|e| format!("Failed to create context: {:?}", e))?;

        let program = Program::create_and_build_from_source(&context, SRC, "")
            .map_err(|e| format!("Failed to build OpenCL program: {:?}", e))?;

        let queue_hash = CommandQueue::create_default(&context, 0)
            .map_err(|e| format!("Failed to create hash queue: {:?}", e))?;
        let queue_transfer = CommandQueue::create_default(&context, 0)
            .map_err(|e| format!("Failed to create transfer queue: {:?}", e))?;

        let hash_kernel = Kernel::create(&program, "calculate_nonces")
            .map_err(|e| format!("Failed to create hash kernel: {:?}", e))?;
        let compress_kernel = Kernel::create(&program, "fused_scatter_compress")
            .map_err(|e| format!("Failed to create compress kernel: {:?}", e))?;

        let device_kws = get_kernel_work_group_size(&hash_kernel, &device, kws_override);
        let max_alloc = device.max_mem_alloc_size().unwrap_or(u64::MAX);
        let (kernel_workgroup_size, effective_cores, _) =
            fit_kws_to_max_alloc(device_kws, cores, max_alloc, kws_override);
        let worksize = (kernel_workgroup_size * effective_cores) as u64;
        let ring_size = compute_ring_size(worksize);

        let gdim1 = [worksize as usize, 1, 1];
        let ldim1 = [kernel_workgroup_size, 1, 1];

        let ring_buffer_bytes = ring_size * NONCE_SIZE;
        let compressed_buffer_bytes = (DIM * DIM * DOUBLE_HASH_SIZE) as usize; // 1 GiB

        let num_splits = compute_ring_splits(ring_buffer_bytes, max_alloc);

        let base58 = unsafe {
            Buffer::<u8>::create(&context, CL_MEM_READ_ONLY, 20, ptr::null_mut())
                .map_err(|e| format!("Failed to create base58 buffer: {:?}", e))?
        };
        let seed = unsafe {
            Buffer::<u8>::create(&context, CL_MEM_READ_ONLY, 32, ptr::null_mut())
                .map_err(|e| format!("Failed to create seed buffer: {:?}", e))?
        };

        // Allocate ring buffer(s)
        let (ring_buffer, ring_sub_buffers, nonces_per_sub, hash_kernel_split, compress_kernel_split) =
            if num_splits > 1 {
                let nps = nonces_per_sub_aligned(ring_size, num_splits);
                let sub_bytes = (nps * NONCE_SIZE) as usize;

                let mut subs = Vec::with_capacity(MAX_RING_SPLITS);
                for i in 0..MAX_RING_SPLITS {
                    let size = if i < num_splits { sub_bytes } else { 4 };
                    let buf = unsafe {
                        Buffer::<u8>::create(
                            &context,
                            CL_MEM_READ_WRITE,
                            size,
                            ptr::null_mut(),
                        )
                        .map_err(|e| {
                            format!("Failed to create ring sub-buffer {}: {:?}", i, e)
                        })?
                    };
                    subs.push(buf);
                }

                // Dummy single ring_buffer (not used in split mode)
                let dummy = unsafe {
                    Buffer::<u8>::create(&context, CL_MEM_READ_WRITE, 4, ptr::null_mut())
                        .map_err(|e| format!("Failed to create dummy ring buffer: {:?}", e))?
                };

                let hk = Kernel::create(&program, "calculate_nonces_split")
                    .map_err(|e| format!("Failed to create split hash kernel: {:?}", e))?;
                let ck = Kernel::create(&program, "fused_scatter_compress_split")
                    .map_err(|e| format!("Failed to create split compress kernel: {:?}", e))?;

                (dummy, subs, nps, Some(hk), Some(ck))
            } else {
                let ring_buffer = unsafe {
                    Buffer::<u8>::create(
                        &context,
                        CL_MEM_READ_WRITE,
                        ring_buffer_bytes as usize,
                        ptr::null_mut(),
                    )
                    .map_err(|e| format!("Failed to create ring buffer: {:?}", e))?
                };
                (ring_buffer, Vec::new(), 0, None, None)
            };

        let compressed_buffer = unsafe {
            Buffer::<u8>::create(
                &context,
                CL_MEM_READ_WRITE,
                compressed_buffer_bytes,
                ptr::null_mut(),
            )
            .map_err(|e| format!("Failed to create compressed buffer: {:?}", e))?
        };

        Ok(GpuRingContext {
            context,
            queue_hash,
            queue_transfer,
            hash_kernel,
            compress_kernel,
            hash_kernel_split,
            compress_kernel_split,
            ldim1,
            gdim1,
            base58,
            seed,
            ring_buffer,
            ring_sub_buffers,
            nonces_per_sub,
            compressed_buffer,
            worksize,
            ring_size,
        })
    }

    /// Returns true if this context uses split ring buffers.
    pub fn is_split(&self) -> bool {
        !self.ring_sub_buffers.is_empty()
    }

    /// Number of ring sub-buffers (1 = single mode).
    #[allow(dead_code)]
    pub fn num_splits(&self) -> usize {
        if self.ring_sub_buffers.is_empty() {
            1
        } else {
            self.ring_sub_buffers
                .iter()
                .take_while(|_| true)
                .count()
                .min(MAX_RING_SPLITS)
        }
    }
}

/// Upload address payload to GPU
pub fn gpu_upload_base58(ctx: &mut GpuRingContext, address_payload: &[u8; 20]) {
    unsafe {
        ctx.queue_hash
            .enqueue_write_buffer(&mut ctx.base58, CL_BLOCKING, 0, address_payload, &[])
            .expect("Failed to write base58 buffer");
    }
}

/// Upload seed to GPU
pub fn gpu_upload_seed(ctx: &mut GpuRingContext, seed: &[u8; 32]) {
    unsafe {
        ctx.queue_hash
            .enqueue_write_buffer(&mut ctx.seed, CL_BLOCKING, 0, seed, &[])
            .expect("Failed to write seed buffer");
    }
}

/// Hash nonces into the ring buffer at the given ring_offset.
///
/// `startnonce` is the global nonce number for nonce 0 of this dispatch.
/// `ring_offset` is the slot in the ring buffer where gid=0 maps to.
/// `nonces` is the number of nonces to hash (== worksize).
pub fn gpu_ring_hash(ctx: &GpuRingContext, startnonce: u64, nonces: u64, ring_offset: u64) {
    if ctx.is_split() {
        gpu_ring_hash_split(ctx, startnonce, nonces, ring_offset);
    } else {
        gpu_ring_hash_single(ctx, startnonce, nonces, ring_offset);
    }
}

fn gpu_ring_hash_single(
    ctx: &GpuRingContext,
    startnonce: u64,
    nonces: u64,
    ring_offset: u64,
) {
    for i in (0..8192usize).step_by(GPU_HASHES_PER_RUN) {
        let (start, end) = if i + GPU_HASHES_PER_RUN < 8192 {
            (i as i32, (i + GPU_HASHES_PER_RUN - 1) as i32)
        } else {
            (i as i32, (i + GPU_HASHES_PER_RUN) as i32)
        };

        unsafe {
            ExecuteKernel::new(&ctx.hash_kernel)
                .set_arg(&ctx.ring_buffer)
                .set_arg(&startnonce)
                .set_arg(&ctx.base58)
                .set_arg(&ctx.seed)
                .set_arg(&start)
                .set_arg(&end)
                .set_arg(&nonces)
                .set_arg(&ring_offset)
                .set_arg(&ctx.ring_size)
                .set_global_work_size(ctx.gdim1[0])
                .set_local_work_size(ctx.ldim1[0])
                .enqueue_nd_range(&ctx.queue_hash)
                .expect("Failed to enqueue hash kernel");
        }
    }
    ctx.queue_hash
        .finish()
        .expect("Failed to finish hash queue");
}

fn gpu_ring_hash_split(
    ctx: &GpuRingContext,
    startnonce: u64,
    nonces: u64,
    ring_offset: u64,
) {
    let kernel = ctx.hash_kernel_split.as_ref().expect("Split hash kernel not initialized");

    for i in (0..8192usize).step_by(GPU_HASHES_PER_RUN) {
        let (start, end) = if i + GPU_HASHES_PER_RUN < 8192 {
            (i as i32, (i + GPU_HASHES_PER_RUN - 1) as i32)
        } else {
            (i as i32, (i + GPU_HASHES_PER_RUN) as i32)
        };

        unsafe {
            ExecuteKernel::new(kernel)
                .set_arg(&ctx.ring_sub_buffers[0])
                .set_arg(&ctx.ring_sub_buffers[1])
                .set_arg(&ctx.ring_sub_buffers[2])
                .set_arg(&ctx.ring_sub_buffers[3])
                .set_arg(&ctx.nonces_per_sub)
                .set_arg(&startnonce)
                .set_arg(&ctx.base58)
                .set_arg(&ctx.seed)
                .set_arg(&start)
                .set_arg(&end)
                .set_arg(&nonces)
                .set_arg(&ring_offset)
                .set_arg(&ctx.ring_size)
                .set_global_work_size(ctx.gdim1[0])
                .set_local_work_size(ctx.ldim1[0])
                .enqueue_nd_range(&ctx.queue_hash)
                .expect("Failed to enqueue split hash kernel");
        }
    }
    ctx.queue_hash
        .finish()
        .expect("Failed to finish hash queue");
}

/// Run the fused scatter+compress kernel on 8192 nonces starting at compress_start.
/// `accumulate`: false = overwrite (first pass), true = XOR-accumulate (subsequent passes).
pub fn gpu_ring_compress(ctx: &GpuRingContext, compress_start: u64, accumulate: bool) {
    if ctx.is_split() {
        gpu_ring_compress_split(ctx, compress_start, accumulate);
    } else {
        gpu_ring_compress_single(ctx, compress_start, accumulate);
    }
}

fn gpu_ring_compress_single(ctx: &GpuRingContext, compress_start: u64, accumulate: bool) {
    let gws = DIM as usize;
    let lws = min(256, gws);
    let acc_flag: i32 = if accumulate { 1 } else { 0 };

    unsafe {
        ExecuteKernel::new(&ctx.compress_kernel)
            .set_arg(&ctx.ring_buffer)
            .set_arg(&ctx.compressed_buffer)
            .set_arg(&ctx.ring_size)
            .set_arg(&compress_start)
            .set_arg(&acc_flag)
            .set_global_work_size(gws)
            .set_local_work_size(lws)
            .enqueue_nd_range(&ctx.queue_hash)
            .expect("Failed to enqueue compress kernel");
    }
    ctx.queue_hash
        .finish()
        .expect("Failed to finish compress queue");
}

fn gpu_ring_compress_split(ctx: &GpuRingContext, compress_start: u64, accumulate: bool) {
    let kernel = ctx
        .compress_kernel_split
        .as_ref()
        .expect("Split compress kernel not initialized");
    let gws = DIM as usize;
    let lws = min(256, gws);
    let acc_flag: i32 = if accumulate { 1 } else { 0 };

    unsafe {
        ExecuteKernel::new(kernel)
            .set_arg(&ctx.ring_sub_buffers[0])
            .set_arg(&ctx.ring_sub_buffers[1])
            .set_arg(&ctx.ring_sub_buffers[2])
            .set_arg(&ctx.ring_sub_buffers[3])
            .set_arg(&ctx.nonces_per_sub)
            .set_arg(&ctx.compressed_buffer)
            .set_arg(&ctx.ring_size)
            .set_arg(&compress_start)
            .set_arg(&acc_flag)
            .set_global_work_size(gws)
            .set_local_work_size(lws)
            .enqueue_nd_range(&ctx.queue_hash)
            .expect("Failed to enqueue split compress kernel");
    }
    ctx.queue_hash
        .finish()
        .expect("Failed to finish compress queue");
}

/// Transfer compressed buffer (1 warp) from GPU into interleaved host buffer.
///
/// GPU layout: 4096 scoops × SCOOP_SIZE contiguous.
/// Host layout: scoops spaced by `total_warps_in_buffer × SCOOP_SIZE`,
/// with this warp's data at `warp_index × SCOOP_SIZE` within each row.
///
/// For escalate=1, this is equivalent to a linear copy.
pub fn gpu_ring_transfer(
    ctx: &GpuRingContext,
    host_buffer: &mut [u8],
    warp_index: u64,
    total_warps_in_buffer: u64,
    blocking: bool,
) {
    let scoop_size = DIM as usize * DOUBLE_HASH_SIZE as usize; // 256 KiB
    let num_scoops = DIM as usize; // 4096

    // Fast path: no interleaving needed
    if total_warps_in_buffer == 1 {
        let cl_blocking = if blocking {
            CL_BLOCKING
        } else {
            CL_NON_BLOCKING
        };
        unsafe {
            ctx.queue_transfer
                .enqueue_read_buffer(
                    &ctx.compressed_buffer,
                    cl_blocking,
                    0,
                    &mut host_buffer[..scoop_size * num_scoops],
                    &[],
                )
                .expect("Failed to read compressed buffer");
        }
    } else {
        // Rect transfer: GPU scoops (contiguous) → host scoops (interleaved)
        let buffer_origin: [usize; 3] = [0, 0, 0];
        let host_origin: [usize; 3] = [warp_index as usize * scoop_size, 0, 0];
        let region: [usize; 3] = [scoop_size, num_scoops, 1];
        let buffer_row_pitch = scoop_size;
        let host_row_pitch = total_warps_in_buffer as usize * scoop_size;
        let cl_blocking = if blocking {
            CL_BLOCKING
        } else {
            CL_NON_BLOCKING
        };

        unsafe {
            ctx.queue_transfer
                .enqueue_read_buffer_rect(
                    &ctx.compressed_buffer,
                    cl_blocking,
                    buffer_origin.as_ptr(),
                    host_origin.as_ptr(),
                    region.as_ptr(),
                    buffer_row_pitch,
                    0, // slice pitch (unused for 2D)
                    host_row_pitch,
                    0, // slice pitch (unused for 2D)
                    host_buffer.as_mut_ptr() as *mut std::ffi::c_void,
                    &[],
                )
                .expect("Failed to read compressed buffer rect");
        }
    }

    if !blocking {
        ctx.queue_transfer
            .finish()
            .expect("Failed to finish transfer queue");
    }
}

/// Transfer raw ring buffer data from GPU to host (for testing).
/// In split mode, reads from each sub-buffer and concatenates.
#[cfg(test)]
pub fn gpu_ring_transfer_raw(ctx: &GpuRingContext, host_buffer: &mut [u8]) {
    if ctx.is_split() {
        let sub_bytes = (ctx.nonces_per_sub * NONCE_SIZE) as usize;
        let num_real = compute_ring_splits(ctx.ring_size * NONCE_SIZE,
            // Reconstruct max_alloc from split geometry
            ctx.nonces_per_sub * NONCE_SIZE);
        for i in 0..num_real {
            let remaining_nonces = if (i as u64 + 1) * ctx.nonces_per_sub > ctx.ring_size {
                ctx.ring_size - i as u64 * ctx.nonces_per_sub
            } else {
                ctx.nonces_per_sub
            };
            let bytes_to_read = (remaining_nonces * NONCE_SIZE) as usize;
            let offset = i * sub_bytes;
            unsafe {
                ctx.queue_transfer
                    .enqueue_read_buffer(
                        &ctx.ring_sub_buffers[i],
                        CL_BLOCKING,
                        0,
                        &mut host_buffer[offset..offset + bytes_to_read],
                        &[],
                    )
                    .expect("Failed to read ring sub-buffer");
            }
        }
    } else {
        unsafe {
            ctx.queue_transfer
                .enqueue_read_buffer(&ctx.ring_buffer, CL_BLOCKING, 0, host_buffer, &[])
                .expect("Failed to read ring buffer");
        }
    }
}

/// GPU memory needed for ring buffer plotter (ring + compressed + constants)
pub fn gpu_mem_needed(_worksize: u64, ring_size: u64) -> u64 {
    let ring_bytes = ring_size * NONCE_SIZE;
    let compressed_bytes = DIM * DIM * DOUBLE_HASH_SIZE;
    ring_bytes + compressed_bytes + 64 // +64 for base58+seed
}

pub fn platform_info() {
    println!("PoCX Plotter v2 {}", env!("CARGO_PKG_VERSION"));
    println!("written by Proof of Capacity Consortium in Rust\n");
    println!("*OpenCL Information*\n");

    let platforms = match get_platforms() {
        Ok(p) if !p.is_empty() => p,
        Ok(_) => {
            println!("No OpenCL platforms found.");
            println!("OpenCL runtime is not installed or no compatible GPU detected.");
            println!("GPU acceleration requires compatible hardware (Intel/AMD/NVIDIA GPU).\n");
            return;
        }
        Err(e) => {
            println!("Failed to query OpenCL platforms: {:?}", e);
            println!("OpenCL runtime may not be installed.\n");
            return;
        }
    };

    for (i, platform) in platforms.iter().enumerate() {
        let platform_name = platform.name().unwrap_or_else(|_| "Unknown".to_string());
        let platform_version = platform.version().unwrap_or_else(|_| "Unknown".to_string());

        println!("platform {}, {} - {}", i, platform_name, platform_version);

        let devices = match platform.get_devices(CL_DEVICE_TYPE_GPU) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for (j, device_id) in devices.iter().enumerate() {
            let device = Device::new(*device_id);
            let context = match Context::from_device(&device) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let program = match Program::create_and_build_from_source(&context, SRC, "") {
                Ok(p) => p,
                Err(_) => continue,
            };

            let kernel = match Kernel::create(&program, "calculate_nonces") {
                Ok(k) => k,
                Err(_) => continue,
            };

            let cores = device.max_compute_units().unwrap_or(0) as usize;
            let device_kws = get_kernel_work_group_size(&kernel, &device, 0);
            let vendor = device.vendor().unwrap_or_else(|_| "Unknown".to_string());
            let name = device.name().unwrap_or_else(|_| "Unknown".to_string());
            let mem = device.global_mem_size().unwrap_or(0);
            let max_alloc = device.max_mem_alloc_size().unwrap_or(0);

            let (effective_kws, effective_cores, was_reduced) =
                fit_kws_to_max_alloc(device_kws, cores, max_alloc, 0);
            let worksize = (effective_cores as u64) * (effective_kws as u64);
            let ring_size = compute_ring_size(worksize);
            let ring_bytes = ring_size * NONCE_SIZE;
            let num_splits = compute_ring_splits(ring_bytes, max_alloc);
            let mem_needed = gpu_mem_needed(worksize, ring_size);

            let cores_info = if effective_cores < cores {
                format!("{} (auto-reduced from {})", effective_cores, cores)
            } else {
                format!("{}", cores)
            };
            let kws_info = if was_reduced && effective_kws < device_kws {
                format!("{} (auto-reduced from {})", effective_kws, device_kws)
            } else {
                format!("{}", effective_kws)
            };

            let split_info = if num_splits > 1 {
                let nps = nonces_per_sub_aligned(ring_size, num_splits);
                format!(
                    ", ring-split={}x{:.2} GiB",
                    num_splits,
                    (nps * NONCE_SIZE) as f64 / 1024.0 / 1024.0 / 1024.0
                )
            } else {
                String::new()
            };

            println!(
                "- device {}, {} - {}, cores={}, kws={}, ring={} nonces, GPU-RAM={:.2}/{:.2} GiB, max-alloc={:.2} GiB{}",
                j,
                vendor,
                name,
                cores_info,
                kws_info,
                ring_size,
                mem_needed as f64 / 1024.0 / 1024.0 / 1024.0,
                mem as f64 / 1024.0 / 1024.0 / 1024.0,
                max_alloc as f64 / 1024.0 / 1024.0 / 1024.0,
                split_info,
            );
        }
    }
}

fn get_kernel_work_group_size(kernel: &Kernel, device: &Device, kws_override: usize) -> usize {
    if kws_override != 0 {
        return kws_override;
    }
    kernel.get_work_group_size(device.id()).unwrap_or(256)
}

/// Auto-reduce cores and kws until ring buffer fits in max_alloc or
/// reaches the irreducible minimum (8192 nonces = 2 GiB).
///
/// Strategy:
/// 1. Reduce cores to prev_power_of_two — maximizes gcd(worksize, 8192),
///    ensuring ring_size = exactly 8192 when worksize ≤ 8192.
/// 2. Halve kws while ring_bytes > max_alloc AND ring_size > 8192.
///    Stops at the 8192 floor since further halving cannot shrink the ring.
/// 3. If ring still exceeds max_alloc (i.e. max_alloc < 2 GiB), splitting
///    handles the rest (see `compute_ring_splits`).
///
/// Returns (effective_kws, effective_cores, was_reduced).
/// Skips all reduction if kws_override is set.
fn fit_kws_to_max_alloc(
    device_kws: usize,
    cores: usize,
    max_alloc: u64,
    kws_override: usize,
) -> (usize, usize, bool) {
    if kws_override != 0 {
        return (kws_override, cores, false);
    }
    let min_ring_bytes = COMPRESS_BATCH * NONCE_SIZE; // 2 GiB floor
    // Step 1: reduce cores to next lower power of 2
    let effective_cores = prev_power_of_two(cores);
    // Step 2: halve kws while ring exceeds max_alloc and hasn't hit the floor
    let mut kws = device_kws;
    loop {
        let worksize = (kws * effective_cores) as u64;
        let ring_size = compute_ring_size(worksize);
        let ring_bytes = ring_size * NONCE_SIZE;
        if ring_bytes <= max_alloc || ring_bytes <= min_ring_bytes || kws <= 1 {
            break;
        }
        kws /= 2;
    }
    let was_reduced = effective_cores < cores || kws < device_kws;
    (kws, effective_cores, was_reduced)
}

/// Largest power of 2 less than or equal to n. Returns 1 for n <= 1.
fn prev_power_of_two(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    1 << (usize::BITS - 1 - n.leading_zeros())
}

/// Determine how many sub-buffers are needed to fit ring_bytes into max_alloc.
/// Returns 1 (no split) when ring_bytes <= max_alloc.
fn compute_ring_splits(ring_bytes: u64, max_alloc: u64) -> usize {
    if ring_bytes <= max_alloc {
        return 1;
    }
    let n = ((ring_bytes + max_alloc - 1) / max_alloc) as usize;
    assert!(
        n <= MAX_RING_SPLITS,
        "Ring buffer requires {} splits but max is {} (max_alloc={:.2} GiB too small)",
        n,
        MAX_RING_SPLITS,
        max_alloc as f64 / 1024.0 / 1024.0 / 1024.0
    );
    n
}

/// Compute nonces per sub-buffer, aligned to NONCES_VECTOR (16).
fn nonces_per_sub_aligned(ring_size: u64, num_splits: usize) -> u64 {
    let raw = (ring_size + num_splits as u64 - 1) / num_splits as u64;
    (raw + NONCES_VECTOR - 1) & !(NONCES_VECTOR - 1)
}

/// GPU device information with kernel workgroup size
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GpuDeviceInfo {
    pub platform_index: usize,
    pub device_index: usize,
    pub platform_name: String,
    pub vendor: String,
    pub name: String,
    pub compute_units: usize,
    pub kernel_workgroup_size: usize,
    pub memory_bytes: u64,
    pub opencl_version: String,
    pub is_apu: bool,
}

/// Get detailed GPU info including kernel workgroup sizes
#[allow(dead_code)]
pub fn get_gpu_device_info() -> Vec<GpuDeviceInfo> {
    let mut devices = Vec::new();

    let platforms = match get_platforms() {
        Ok(p) if !p.is_empty() => p,
        _ => return devices,
    };

    for (i, platform) in platforms.iter().enumerate() {
        let platform_name = platform.name().unwrap_or_else(|_| "Unknown".to_string());

        let gpu_devices = match platform.get_devices(CL_DEVICE_TYPE_GPU) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for (j, device_id) in gpu_devices.iter().enumerate() {
            let device = Device::new(*device_id);
            let context = match Context::from_device(&device) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let program = match Program::create_and_build_from_source(&context, SRC, "") {
                Ok(p) => p,
                Err(_) => continue,
            };

            let kernel = match Kernel::create(&program, "calculate_nonces") {
                Ok(k) => k,
                Err(_) => continue,
            };

            let compute_units = device.max_compute_units().unwrap_or(0) as usize;
            let kernel_workgroup_size = get_kernel_work_group_size(&kernel, &device, 0);
            let vendor = device.vendor().unwrap_or_else(|_| "Unknown".to_string());
            let name = device.name().unwrap_or_else(|_| "Unknown".to_string());
            let memory_bytes = device.global_mem_size().unwrap_or(0);
            let opencl_version = device.version().unwrap_or_else(|_| "Unknown".to_string());
            let host_unified = device.host_unified_memory().unwrap_or(false);

            let is_apu = host_unified
                || (vendor.to_uppercase().contains("INTEL")
                    && !name.to_uppercase().contains("ARC"))
                || (name.to_uppercase().contains("RADEON GRAPHICS"));

            devices.push(GpuDeviceInfo {
                platform_index: i,
                device_index: j,
                platform_name: platform_name.clone(),
                vendor: vendor.trim().to_string(),
                name: name.trim().to_string(),
                compute_units,
                kernel_workgroup_size,
                memory_bytes,
                opencl_version,
                is_apu,
            });
        }
    }

    devices
}

pub fn gpu_get_info(gpu: &str, quiet: bool, kws_override: usize) -> Result<(u64, u64, u64), String> {
    let platforms = match get_platforms() {
        Ok(p) => p,
        Err(_) => return Ok((0, 0, 0)),
    };

    let parts: Vec<&str> = gpu.split(':').collect();
    if parts.len() < 2 {
        return Err(format!(
            "Invalid GPU format '{}'. Expected platform:device or platform:device:cores (e.g. 0:0 or 0:0:0)",
            gpu
        ));
    }
    let platform_id = parts[0].parse::<usize>().unwrap();
    let gpu_id = parts[1].parse::<usize>().unwrap();
    let gpu_cores = if parts.len() > 2 {
        parts[2].parse::<usize>().unwrap()
    } else {
        0
    };

    if platform_id >= platforms.len() {
        return Err("Selected OpenCL platform doesn't exist".to_string());
    }

    let platform = &platforms[platform_id];
    let devices = match platform.get_devices(CL_DEVICE_TYPE_GPU) {
        Ok(d) => d,
        Err(_) => {
            return Err("Failed to get GPU devices".to_string());
        }
    };

    if gpu_id >= devices.len() {
        return Err("Selected OpenCL device doesn't exist".to_string());
    }

    let device = Device::new(devices[gpu_id]);
    let max_compute_units = device.max_compute_units().unwrap_or(0) as usize;
    let mem = device.global_mem_size().unwrap_or(0);

    let context = Context::from_device(&device).expect("Failed to create context");
    let program =
        Program::create_and_build_from_source(&context, SRC, "").expect("Failed to build program");
    let kernel = Kernel::create(&program, "calculate_nonces").expect("Failed to create kernel");
    let device_kws = get_kernel_work_group_size(&kernel, &device, kws_override);
    let max_alloc = device.max_mem_alloc_size().unwrap_or(u64::MAX);

    let gpu_cores = if gpu_cores == 0 {
        max_compute_units
    } else {
        min(gpu_cores, max_compute_units)
    };

    let (kernel_workgroup_size, effective_cores, was_reduced) =
        fit_kws_to_max_alloc(device_kws, gpu_cores, max_alloc, kws_override);
    let worksize = (effective_cores * kernel_workgroup_size) as u64;
    let ring_size = compute_ring_size(worksize);
    let ring_bytes = ring_size * NONCE_SIZE;
    let num_splits = compute_ring_splits(ring_bytes, max_alloc);
    let mem_needed = gpu_mem_needed(worksize, ring_size);

    if mem_needed > mem {
        return Err(format!(
            "Not enough GPU-memory ({:.2} GiB needed, {:.2} GiB available). Plotter v2 requires at least 3 GiB GPU memory. Use CPU mode or plotter v1.",
            mem_needed as f64 / 1024.0 / 1024.0 / 1024.0,
            mem as f64 / 1024.0 / 1024.0 / 1024.0
        ));
    }

    if !quiet {
        let vendor = device.vendor().unwrap_or_else(|_| "Unknown".to_string());
        let name = device.name().unwrap_or_else(|_| "Unknown".to_string());
        let cu_info = if effective_cores < max_compute_units {
            format!("{} of {}", effective_cores, max_compute_units)
        } else {
            format!("{}", effective_cores)
        };
        let kws_info = if was_reduced && kernel_workgroup_size < device_kws {
            format!("{} of {}", kernel_workgroup_size, device_kws)
        } else {
            format!("{}", kernel_workgroup_size)
        };
        println!(
            "GPU: {} - {} [{} CUs, {} kws]",
            vendor, name, cu_info, kws_info
        );
        let split_info = if num_splits > 1 {
            let nps = nonces_per_sub_aligned(ring_size, num_splits);
            format!(
                ", split={}x{:.2} GiB",
                num_splits,
                (nps * NONCE_SIZE) as f64 / 1024.0 / 1024.0 / 1024.0
            )
        } else {
            String::new()
        };
        println!(
            "     worksize={}, ring={} nonces{}, GPU-RAM: {:.2}/{:.2} GiB",
            worksize,
            ring_size,
            split_info,
            mem_needed as f64 / 1024.0 / 1024.0 / 1024.0,
            mem as f64 / 1024.0 / 1024.0 / 1024.0,
        );
    }

    Ok((worksize, ring_size, mem_needed))
}

pub fn gpu_ring_init(gpu: &str, kws_override: usize) -> Result<GpuRingContext, String> {
    let platforms = match get_platforms() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to get OpenCL platforms: {:?}", e)),
    };

    let parts: Vec<&str> = gpu.split(':').collect();
    if parts.len() < 2 {
        return Err(format!(
            "Invalid GPU format: '{}'. Expected platform:device or platform:device:cores (e.g. 0:0 or 0:0:0)",
            gpu
        ));
    }
    let platform_id = parts[0]
        .parse::<usize>()
        .map_err(|_| format!("Invalid platform ID in GPU: {}", gpu))?;
    let gpu_id = parts[1]
        .parse::<usize>()
        .map_err(|_| format!("Invalid device ID in GPU: {}", gpu))?;
    let gpu_cores = if parts.len() > 2 {
        parts[2]
            .parse::<usize>()
            .map_err(|_| format!("Invalid cores in GPU: {}", gpu))?
    } else {
        0
    };

    if platform_id >= platforms.len() {
        return Err(format!(
            "OpenCL platform {} doesn't exist (only {} platforms found)",
            platform_id,
            platforms.len()
        ));
    }

    let platform = &platforms[platform_id];
    let devices = platform
        .get_devices(CL_DEVICE_TYPE_GPU)
        .map_err(|e| format!("Failed to get GPU devices: {:?}", e))?;

    if gpu_id >= devices.len() {
        return Err(format!(
            "OpenCL device {} doesn't exist on platform {} (only {} devices found)",
            gpu_id,
            platform_id,
            devices.len()
        ));
    }

    let device = Device::new(devices[gpu_id]);
    let max_compute_units = device.max_compute_units().unwrap_or(0) as usize;

    let gpu_cores = if gpu_cores == 0 {
        max_compute_units
    } else {
        min(gpu_cores, max_compute_units)
    };

    GpuRingContext::new(platform_id, gpu_id, gpu_cores, kws_override)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_ring_size() {
        assert_eq!(compute_ring_size(7168), 14336);
        assert_eq!(compute_ring_size(8192), 8192);
        assert_eq!(compute_ring_size(16384), 16384);
        assert_eq!(compute_ring_size(256), 8192);
    }

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(7168, 8192), 1024);
        assert_eq!(gcd(8192, 8192), 8192);
        assert_eq!(gcd(256, 8192), 256);
        assert_eq!(gcd(100, 75), 25);
    }

    #[test]
    fn test_prev_power_of_two() {
        assert_eq!(prev_power_of_two(1), 1);
        assert_eq!(prev_power_of_two(2), 2);
        assert_eq!(prev_power_of_two(3), 2);
        assert_eq!(prev_power_of_two(4), 4);
        assert_eq!(prev_power_of_two(7), 4);
        assert_eq!(prev_power_of_two(8), 8);
        assert_eq!(prev_power_of_two(10), 8);
        assert_eq!(prev_power_of_two(16), 16);
        assert_eq!(prev_power_of_two(31), 16);
        assert_eq!(prev_power_of_two(32), 32);
    }

    #[test]
    fn test_fit_kws_cores_reduction() {
        let max_alloc_2gib = 2 * 1024 * 1024 * 1024u64;
        // 10 cores, kws=256: should reduce cores to 8 (power of 2)
        // worksize=8*256=2048, ring=8192, ring_bytes=2GiB
        let (kws, cores, reduced) = fit_kws_to_max_alloc(256, 10, max_alloc_2gib, 0);
        assert_eq!(cores, 8, "cores should be reduced to 8");
        assert!(reduced, "should be marked as reduced");
        let ring = compute_ring_size((kws * cores) as u64);
        assert_eq!(ring, 8192);
    }

    #[test]
    fn test_fit_kws_power_of_two_cores_unchanged() {
        let max_alloc_4gib = 4 * 1024 * 1024 * 1024u64;
        // 8 cores already power of 2, plenty of max_alloc
        let (kws, cores, reduced) = fit_kws_to_max_alloc(256, 8, max_alloc_4gib, 0);
        assert_eq!(cores, 8);
        assert_eq!(kws, 256);
        assert!(!reduced);
    }

    #[test]
    fn test_fit_kws_override_bypasses_reduction() {
        let max_alloc_1gib = 1024 * 1024 * 1024u64;
        let (kws, cores, reduced) = fit_kws_to_max_alloc(256, 10, max_alloc_1gib, 64);
        assert_eq!(kws, 64, "override should be used as-is");
        assert_eq!(cores, 10, "cores should not be reduced with override");
        assert!(!reduced);
    }

    #[test]
    fn test_fit_kws_stops_at_floor_when_max_alloc_below_2gib() {
        // max_alloc = 1.5 GiB (below 2 GiB floor)
        let max_alloc_1_5g = 3 * 1024 * 1024 * 1024 / 2;
        // 8 cores, kws=256: worksize=2048, ring=8192 (2 GiB floor) — can't go lower
        let (kws, cores, _reduced) = fit_kws_to_max_alloc(256, 8, max_alloc_1_5g, 0);
        assert_eq!(cores, 8);
        assert_eq!(kws, 256, "kws should not be reduced past the ring floor");
        let ring_bytes = compute_ring_size((kws * cores) as u64) * NONCE_SIZE;
        assert_eq!(ring_bytes, COMPRESS_BATCH * NONCE_SIZE);
    }

    #[test]
    fn test_fit_kws_halves_above_2gib() {
        // max_alloc = 3 GiB (above 2 GiB, halving can help)
        let max_alloc_3g = 3 * 1024 * 1024 * 1024u64;
        // 48 cores → 32 (power of 2), kws=512: worksize=16384, ring=16384 (4 GiB)
        // halve to kws=256: worksize=8192, ring=8192 (2 GiB) → fits
        let (kws, cores, reduced) = fit_kws_to_max_alloc(512, 48, max_alloc_3g, 0);
        assert_eq!(cores, 32);
        let ring_bytes = compute_ring_size((kws * cores) as u64) * NONCE_SIZE;
        assert!(ring_bytes <= max_alloc_3g);
        assert!(reduced);
    }

    #[test]
    fn test_fit_kws_32core_512kws_2gib() {
        // Real case: 32 CU iGPU, kws=512, max_alloc=2 GiB
        let max_alloc_2gib = 2 * 1024 * 1024 * 1024u64;
        let (kws, cores, reduced) = fit_kws_to_max_alloc(512, 32, max_alloc_2gib, 0);
        assert_eq!(cores, 32);
        // worksize=32*512=16384, ring=16384 (4 GiB) → halve
        // kws=256: worksize=8192, ring=8192 (2 GiB) → fits
        assert_eq!(kws, 256);
        assert!(reduced);
        let ring = compute_ring_size((kws * cores) as u64);
        assert_eq!(ring, 8192);
    }

    #[test]
    fn test_compute_ring_splits() {
        let two_gib = COMPRESS_BATCH * NONCE_SIZE;
        assert_eq!(compute_ring_splits(two_gib, two_gib), 1);
        assert_eq!(compute_ring_splits(two_gib, two_gib + 1), 1);
        let max_alloc_1_5g = 3 * 1024 * 1024 * 1024 / 2;
        assert_eq!(compute_ring_splits(two_gib, max_alloc_1_5g), 2);
        let max_alloc_1g = 1024 * 1024 * 1024u64;
        assert_eq!(compute_ring_splits(two_gib, max_alloc_1g), 2);
        let max_alloc_768m = 768 * 1024 * 1024u64;
        assert_eq!(compute_ring_splits(two_gib, max_alloc_768m), 3);
        let max_alloc_512m = 512 * 1024 * 1024u64;
        assert_eq!(compute_ring_splits(two_gib, max_alloc_512m), 4);
    }

    #[test]
    fn test_nonces_per_sub_aligned() {
        assert_eq!(nonces_per_sub_aligned(8192, 2), 4096);
        assert_eq!(nonces_per_sub_aligned(8192, 4), 2048);
        assert_eq!(nonces_per_sub_aligned(8192, 3), 2736);
        for n in 2..=4 {
            let nps = nonces_per_sub_aligned(8192, n);
            assert!(nps * n as u64 >= 8192, "n={}: nps*n={} < 8192", n, nps * n as u64);
            assert_eq!(nps % NONCES_VECTOR, 0, "n={}: nps={} not aligned", n, nps);
        }
    }

    fn try_create_gpu_context() -> Option<GpuRingContext> {
        GpuRingContext::new(0, 0, 1, 0).ok()
    }

    const TEST_SEED_HEX: &str = "AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE";
    const TEST_ADDR_HEX: &str = "99BC78BA577A95A11F1A344D4D2AE55F2F857B98";
    const TEST_START_NONCE: u64 = 1337;

    // Pre-computed reference SHA256 digests (addr=TEST_ADDR, seed=TEST_SEED, start=1337)
    const HASH_REF_SHA256: &str =
        "7806d17671576c9053794799817baeb294034e76013e94550fcd25f1d092d4a2";
    const COMPRESS_REF_SHA256: &str =
        "ae9e739c88cc55f38db4c71e44f69975a493802c3009cbed7493ea5d80dd58b9";

    fn test_params() -> ([u8; 20], [u8; 32]) {
        let addr: [u8; 20] = hex::decode(TEST_ADDR_HEX).unwrap().try_into().unwrap();
        let seed: [u8; 32] = hex::decode(TEST_SEED_HEX).unwrap().try_into().unwrap();
        (addr, seed)
    }

    /// Extract a u32 word from the GPU ring buffer using the Address macro formula.
    fn gpu_ring_read_word(buf: &[u8], nonce: usize, hash: usize, word: usize) -> u32 {
        const NV: usize = 16; // NONCES_VECTOR
        const NSW: usize = 8 * 8192; // NONCE_SIZE_WORDS = HASH_SIZE_WORDS * NUM_HASHES
        const HSW: usize = 8; // HASH_SIZE_WORDS
        let addr = (nonce >> 4) * NV * NSW + hash * NV * HSW + word * NV + (nonce & 15);
        let byte_addr = addr * 4;
        u32::from_ne_bytes(buf[byte_addr..byte_addr + 4].try_into().unwrap())
    }

    /// Extract a 64-byte scoop from GPU ring buffer for a given nonce index.
    fn gpu_ring_extract_scoop(buf: &[u8], nonce: usize, scoop: usize) -> [u8; 64] {
        let h_first = 2 * scoop;
        let h_second = (4095 - scoop) * 2 + 1;
        let mut out = [0u8; 64];
        for w in 0..8 {
            let v = gpu_ring_read_word(buf, nonce, h_first, w);
            out[w * 4..w * 4 + 4].copy_from_slice(&v.to_ne_bytes());
        }
        for w in 0..8 {
            let v = gpu_ring_read_word(buf, nonce, h_second, w);
            out[32 + w * 4..32 + w * 4 + 4].copy_from_slice(&v.to_ne_bytes());
        }
        out
    }

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(data))
    }

    const HASH_TEST_NONCES: u64 = 256;

    /// Verify GPU nonce hashing matches CPU reference via full-buffer SHA256.
    #[test]
    fn test_gpu_nonce_hash_correctness() {
        let mut ctx = match try_create_gpu_context() {
            Some(c) => c,
            None => {
                println!("No GPU available, skipping test_gpu_nonce_hash_correctness");
                return;
            }
        };

        let (addr, seed) = test_params();
        gpu_upload_base58(&mut ctx, &addr);
        gpu_upload_seed(&mut ctx, &seed);

        // Hash fixed number of nonces, dispatched in worksize chunks
        let ws = ctx.worksize;
        let mut ring_head: u64 = 0;
        let mut hashed: u64 = 0;
        let mut current_nonce = TEST_START_NONCE;
        while hashed < HASH_TEST_NONCES {
            let batch = std::cmp::min(ws, HASH_TEST_NONCES - hashed);
            gpu_ring_hash(&ctx, current_nonce, batch, ring_head);
            ring_head = (ring_head + ws) % ctx.ring_size;
            hashed += batch;
            current_nonce += batch;
        }

        // Read back raw ring buffer and re-linearize into scoop-major layout
        let ring_bytes = ctx.ring_size as usize * NONCE_SIZE as usize;
        let mut gpu_raw = vec![0u8; ring_bytes];
        gpu_ring_transfer_raw(&ctx, &mut gpu_raw);

        let n = HASH_TEST_NONCES as usize;
        let nonce_size = NONCE_SIZE as usize;
        let mut gpu_linear = vec![0u8; n * nonce_size];
        for ni in 0..n {
            for sc in 0..DIM as usize {
                let scoop = gpu_ring_extract_scoop(&gpu_raw, ni, sc);
                let off = sc * 64 * n + ni * 64;
                gpu_linear[off..off + 64].copy_from_slice(&scoop);
            }
        }

        let gpu_hash = sha256_hex(&gpu_linear);
        assert_eq!(
            HASH_REF_SHA256, gpu_hash,
            "GPU hash doesn't match reference"
        );

        println!(
            "GPU hash test: SHA256={} ({} nonces)",
            gpu_hash, HASH_TEST_NONCES
        );
    }

    /// Verify fused scatter+compress kernel produces correct helix-compressed output.
    #[test]
    fn test_gpu_fused_compress_correctness() {
        let mut ctx = match try_create_gpu_context() {
            Some(c) => c,
            None => {
                println!("No GPU available, skipping test_gpu_fused_compress_correctness");
                return;
            }
        };

        let (addr, seed) = test_params();
        gpu_upload_base58(&mut ctx, &addr);
        gpu_upload_seed(&mut ctx, &seed);

        // Fill ring with at least 8192 nonces via multiple hash dispatches
        let ws = ctx.worksize;
        let mut ring_head: u64 = 0;
        let mut nonces_hashed: u64 = 0;
        let mut current_nonce = TEST_START_NONCE;

        while nonces_hashed < COMPRESS_BATCH {
            gpu_ring_hash(&ctx, current_nonce, ws, ring_head);
            ring_head = (ring_head + ws) % ctx.ring_size;
            nonces_hashed += ws;
            current_nonce += ws;
        }

        // Run compress starting at ring offset 0
        gpu_ring_compress(&ctx, 0, false);

        // Read compressed output (1 warp = 1 GiB)
        let compressed_size = (DIM * DIM * DOUBLE_HASH_SIZE) as usize;
        let mut gpu_compressed = vec![0u8; compressed_size];
        gpu_ring_transfer(&ctx, &mut gpu_compressed, 0, 1, true);

        let gpu_hash = sha256_hex(&gpu_compressed);
        assert_eq!(
            COMPRESS_REF_SHA256, gpu_hash,
            "GPU compress doesn't match reference"
        );

        println!("GPU compress test: SHA256={} (1 warp)", gpu_hash);
    }
}
