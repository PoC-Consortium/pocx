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
use std::process;
use std::ptr;

static SRC: &str = include_str!("ocl/kernel.cl");

const GPU_HASHES_PER_RUN: usize = 32;
const COMPRESS_BATCH: u64 = 8192;
const DIM: u64 = 4096;
const DOUBLE_HASH_SIZE: u64 = 64;

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
    ldim1: [usize; 3],
    gdim1: [usize; 3],
    base58: Buffer<u8>,
    seed: Buffer<u8>,
    ring_buffer: Buffer<u8>,
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
        let (kernel_workgroup_size, _) =
            fit_kws_to_max_alloc(device_kws, cores, max_alloc, kws_override);
        let worksize = (kernel_workgroup_size * cores) as u64;
        let ring_size = compute_ring_size(worksize);

        let gdim1 = [worksize as usize, 1, 1];
        let ldim1 = [kernel_workgroup_size, 1, 1];

        let ring_buffer_bytes = (NONCE_SIZE as usize) * (ring_size as usize);
        let compressed_buffer_bytes = (DIM * DIM * DOUBLE_HASH_SIZE) as usize; // 1 GiB

        let base58 = unsafe {
            Buffer::<u8>::create(&context, CL_MEM_READ_ONLY, 20, ptr::null_mut())
                .map_err(|e| format!("Failed to create base58 buffer: {:?}", e))?
        };
        let seed = unsafe {
            Buffer::<u8>::create(&context, CL_MEM_READ_ONLY, 32, ptr::null_mut())
                .map_err(|e| format!("Failed to create seed buffer: {:?}", e))?
        };
        let ring_buffer = unsafe {
            Buffer::<u8>::create(
                &context,
                CL_MEM_READ_WRITE,
                ring_buffer_bytes,
                ptr::null_mut(),
            )
            .map_err(|e| format!("Failed to create ring buffer: {:?}", e))?
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
            ldim1,
            gdim1,
            base58,
            seed,
            ring_buffer,
            compressed_buffer,
            worksize,
            ring_size,
        })
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

/// Run the fused scatter+compress kernel on 8192 nonces starting at compress_start.
/// `accumulate`: false = overwrite (first pass), true = XOR-accumulate (subsequent passes).
pub fn gpu_ring_compress(ctx: &GpuRingContext, compress_start: u64, accumulate: bool) {
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
#[cfg(test)]
pub fn gpu_ring_transfer_raw(ctx: &GpuRingContext, host_buffer: &mut [u8]) {
    unsafe {
        ctx.queue_transfer
            .enqueue_read_buffer(&ctx.ring_buffer, CL_BLOCKING, 0, host_buffer, &[])
            .expect("Failed to read ring buffer");
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

            let (effective_kws, kws_reduced) =
                fit_kws_to_max_alloc(device_kws, cores, max_alloc, 0);
            let worksize = (cores as u64) * (effective_kws as u64);
            let ring_size = compute_ring_size(worksize);
            let mem_needed = gpu_mem_needed(worksize, ring_size);

            let kws_info = if kws_reduced {
                format!("{} (auto-reduced from {})", effective_kws, device_kws)
            } else {
                format!("{}", effective_kws)
            };

            println!(
                "- device {}, {} - {}, cores={}, kws={}, ring={} nonces, GPU-RAM={:.2}/{:.2} GiB, max-alloc={:.2} GiB",
                j,
                vendor,
                name,
                cores,
                kws_info,
                ring_size,
                mem_needed as f64 / 1024.0 / 1024.0 / 1024.0,
                mem as f64 / 1024.0 / 1024.0 / 1024.0,
                max_alloc as f64 / 1024.0 / 1024.0 / 1024.0,
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

/// Auto-reduce kws by halving until ring buffer fits in max_mem_alloc_size.
/// Returns (effective_kws, was_reduced). Skips reduction if kws_override is set.
fn fit_kws_to_max_alloc(
    device_kws: usize,
    cores: usize,
    max_alloc: u64,
    kws_override: usize,
) -> (usize, bool) {
    if kws_override != 0 {
        return (kws_override, false);
    }
    let mut kws = device_kws;
    loop {
        let worksize = (kws * cores) as u64;
        let ring_size = compute_ring_size(worksize);
        let ring_bytes = ring_size * NONCE_SIZE;
        if ring_bytes <= max_alloc || kws <= 1 {
            break;
        }
        kws /= 2;
    }
    (kws, kws < device_kws)
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

pub fn gpu_get_info(gpu: &str, quiet: bool, kws_override: usize) -> (u64, u64, u64) {
    let platforms = match get_platforms() {
        Ok(p) => p,
        Err(_) => return (0, 0, 0),
    };

    let parts: Vec<&str> = gpu.split(':').collect();
    if parts.len() < 2 {
        eprintln!("Error: Invalid GPU format '{}'. Expected platform:device or platform:device:cores (e.g. 0:0 or 0:0:0)", gpu);
        process::exit(1);
    }
    let platform_id = parts[0].parse::<usize>().unwrap();
    let gpu_id = parts[1].parse::<usize>().unwrap();
    let gpu_cores = if parts.len() > 2 {
        parts[2].parse::<usize>().unwrap()
    } else {
        0
    };

    if platform_id >= platforms.len() {
        println!("Error: Selected OpenCL platform doesn't exist.");
        process::exit(1);
    }

    let platform = &platforms[platform_id];
    let devices = match platform.get_devices(CL_DEVICE_TYPE_GPU) {
        Ok(d) => d,
        Err(_) => {
            println!("Error: Failed to get GPU devices");
            process::exit(1);
        }
    };

    if gpu_id >= devices.len() {
        println!("Error: Selected OpenCL device doesn't exist");
        process::exit(1);
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

    let (kernel_workgroup_size, kws_reduced) =
        fit_kws_to_max_alloc(device_kws, gpu_cores, max_alloc, kws_override);
    let worksize = (gpu_cores * kernel_workgroup_size) as u64;
    let ring_size = compute_ring_size(worksize);
    let mem_needed = gpu_mem_needed(worksize, ring_size);

    if mem_needed > mem {
        println!(
            "Error: Not enough GPU-memory ({:.2} GiB needed, {:.2} GiB available).",
            mem_needed as f64 / 1024.0 / 1024.0 / 1024.0,
            mem as f64 / 1024.0 / 1024.0 / 1024.0
        );
        println!("Please reduce number of cores.");
        process::exit(1);
    }

    if !quiet {
        let vendor = device.vendor().unwrap_or_else(|_| "Unknown".to_string());
        let name = device.name().unwrap_or_else(|_| "Unknown".to_string());
        let cu_info = if gpu_cores < max_compute_units {
            format!("{} of {}", gpu_cores, max_compute_units)
        } else {
            format!("{}", gpu_cores)
        };
        let kws_info = if kws_reduced {
            format!("{} of {}", kernel_workgroup_size, device_kws)
        } else {
            format!("{}", kernel_workgroup_size)
        };
        println!(
            "GPU: {} - {} [{} CUs, {} kws]",
            vendor, name, cu_info, kws_info
        );
        println!(
            "     worksize={}, ring={} nonces, GPU-RAM: {:.2}/{:.2} GiB",
            worksize,
            ring_size,
            mem_needed as f64 / 1024.0 / 1024.0 / 1024.0,
            mem as f64 / 1024.0 / 1024.0 / 1024.0,
        );
    }

    (worksize, ring_size, mem_needed)
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
