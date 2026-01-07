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

//! OpenCL GPU acceleration module using opencl3 with dynamic loading.
//!
//! This module provides GPU acceleration for PoCX plotting operations.
//! It uses the `opencl3` crate with the `dynamic` feature, which loads
//! the OpenCL library at runtime rather than link-time. This allows the
//! binary to run on systems without OpenCL installed, gracefully falling
//! back to CPU-only operation.

use crate::gpu_hasher::GpuTask;
use crate::plotter::{DIM, DOUBLE_HASH_SIZE, NONCE_SIZE};
use opencl3::command_queue::{CommandQueue, CL_QUEUE_PROFILING_ENABLE};
use opencl3::context::Context;
use opencl3::device::{Device, CL_DEVICE_TYPE_GPU};
use opencl3::kernel::{ExecuteKernel, Kernel};
use opencl3::memory::{
    Buffer, ClMem, CL_MAP_READ, CL_MEM_ALLOC_HOST_PTR, CL_MEM_READ_ONLY, CL_MEM_READ_WRITE,
};
use opencl3::platform::get_platforms;
use opencl3::program::Program;
use opencl3::types::{CL_BLOCKING, CL_NON_BLOCKING};
use rayon::prelude::*;
use std::cell::RefCell;
use std::cmp::min;
use std::process;
use std::ptr;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::sync::{Arc, Mutex};

static SRC: &str = include_str!("ocl/kernel.cl");

const GPU_HASHES_PER_RUN: usize = 32;
const MSHABAL512_VECTOR_SIZE: u64 = 16;

pub struct GpuContext {
    #[allow(dead_code)]
    context: Context,
    queue_a: CommandQueue,
    queue_b: CommandQueue,
    kernel: Kernel,
    ldim1: [usize; 3],
    gdim1: [usize; 3],
    mapping: bool,
    // Use RefCell for interior mutability to avoid borrow conflicts
    pub base58: RefCell<Buffer<u8>>,
    pub seed: RefCell<Buffer<u8>>,
    // Persistent host-mapped pointer for non-mapping mode (pinned memory for fast DMA)
    buffer_ptr_host: Option<*mut u8>,
    #[allow(dead_code)]
    buffer_host: Option<Buffer<u8>>,
    buffer_gpu_a: Buffer<u8>,
    buffer_gpu_b: Buffer<u8>,
    pub worksize: usize,
}

// Safety: GpuContext is safe to send between threads as OpenCL handles are thread-safe
// The buffer_ptr_host is only accessed while holding the Mutex lock
unsafe impl Sync for GpuContext {}
unsafe impl Send for GpuContext {}

impl GpuContext {
    pub fn new(
        gpu_platform: usize,
        gpu_id: usize,
        cores: usize,
        nvidia: bool,
        mapping: bool,
        kws_override: usize,
    ) -> Result<GpuContext, String> {
        let platforms = get_platforms().map_err(|e| format!("Failed to get OpenCL platforms: {:?}", e))?;
        let platform = platforms[gpu_platform];

        let devices = platform
            .get_devices(CL_DEVICE_TYPE_GPU)
            .map_err(|e| format!("Failed to get GPU devices: {:?}", e))?;
        let device = Device::new(devices[gpu_id]);

        let context = Context::from_device(&device).map_err(|e| format!("Failed to create context: {:?}", e))?;

        let program = Program::create_and_build_from_source(&context, SRC, "")
            .map_err(|e| format!("Failed to build OpenCL program: {:?}", e))?;

        let queue_a =
            CommandQueue::create_default_with_properties(&context, CL_QUEUE_PROFILING_ENABLE, 0)
                .map_err(|e| format!("Failed to create command queue A: {:?}", e))?;
        let queue_b =
            CommandQueue::create_default_with_properties(&context, CL_QUEUE_PROFILING_ENABLE, 0)
                .map_err(|e| format!("Failed to create command queue B: {:?}", e))?;

        let kernel = Kernel::create(&program, "calculate_nonces").map_err(|e| format!("Failed to create kernel: {:?}", e))?;

        let kernel_workgroup_size = get_kernel_work_group_size(&kernel, &device, kws_override);
        let workgroup_count = cores;
        let worksize = kernel_workgroup_size * workgroup_count;
        let gdim1 = [worksize, 1, 1];
        let ldim1 = [kernel_workgroup_size, 1, 1];

        let buffer_size = (NONCE_SIZE as usize) * worksize;

        // Create buffers
        let base58 = unsafe {
            Buffer::<u8>::create(&context, CL_MEM_READ_ONLY, 20, ptr::null_mut())
                .map_err(|e| format!("Failed to create base58 buffer: {:?}", e))?
        };
        let seed = unsafe {
            Buffer::<u8>::create(&context, CL_MEM_READ_ONLY, 32, ptr::null_mut())
                .map_err(|e| format!("Failed to create seed buffer: {:?}", e))?
        };

        // mapping = zero copy buffers, no mapping = pinned memory for fast DMA
        if mapping {
            // Zero-copy mode: GPU buffers with host-accessible memory
            let buffer_gpu_a = unsafe {
                Buffer::<u8>::create(
                    &context,
                    CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
                    buffer_size,
                    ptr::null_mut(),
                )
                .map_err(|e| format!("Failed to create GPU buffer A: {:?}", e))?
            };
            let buffer_gpu_b = unsafe {
                Buffer::<u8>::create(
                    &context,
                    CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
                    buffer_size,
                    ptr::null_mut(),
                )
                .map_err(|e| format!("Failed to create GPU buffer B: {:?}", e))?
            };

            Ok(GpuContext {
                context,
                queue_a,
                queue_b,
                kernel,
                ldim1,
                gdim1,
                mapping,
                base58: RefCell::new(base58),
                seed: RefCell::new(seed),
                buffer_ptr_host: None,
                buffer_host: None,
                buffer_gpu_a,
                buffer_gpu_b,
                worksize,
            })
        } else {
            // Pinned memory mode: create host buffer and map it persistently
            let buffer_host = unsafe {
                Buffer::<u8>::create(
                    &context,
                    CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
                    buffer_size,
                    ptr::null_mut(),
                )
                .map_err(|e| format!("Failed to create host buffer: {:?}. Try reducing GPU cores.", e))?
            };

            // Map the host buffer persistently for fast DMA access
            let buffer_ptr_host: *mut u8 = unsafe {
                let mut mapped_ptr: *mut std::ffi::c_void = ptr::null_mut();
                queue_b
                    .enqueue_map_buffer::<u8>(
                        &buffer_host,
                        CL_BLOCKING,
                        CL_MAP_READ,
                        0,
                        buffer_size,
                        &mut mapped_ptr,
                        &[],
                    )
                    .map_err(|e| format!("Failed to map host buffer: {:?}", e))?;
                mapped_ptr as *mut u8
            };

            // For NVIDIA: share buffer_host as buffer_gpu_a for zero-copy
            // For other vendors: create separate GPU buffer
            let buffer_gpu_a = if nvidia {
                // NVIDIA optimization: share the same buffer (zero-copy)
                unsafe {
                    Buffer::<u8>::create(
                        &context,
                        CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
                        buffer_size,
                        ptr::null_mut(),
                    )
                    .map_err(|e| format!("Failed to create GPU buffer A: {:?}. Try reducing GPU cores.", e))?
                }
            } else {
                unsafe {
                    Buffer::<u8>::create(&context, CL_MEM_READ_WRITE, buffer_size, ptr::null_mut())
                        .map_err(|e| format!("Failed to create GPU buffer A: {:?}. Try reducing GPU cores.", e))?
                }
            };

            let buffer_gpu_b = unsafe {
                Buffer::<u8>::create(&context, CL_MEM_READ_WRITE, buffer_size, ptr::null_mut())
                    .map_err(|e| format!("Failed to create GPU buffer B: {:?}. Try reducing GPU cores.", e))?
            };

            let buffer_host = if nvidia { None } else { Some(buffer_host) };

            Ok(GpuContext {
                context,
                queue_a,
                queue_b,
                kernel,
                ldim1,
                gdim1,
                mapping,
                base58: RefCell::new(base58),
                seed: RefCell::new(seed),
                buffer_ptr_host: Some(buffer_ptr_host),
                buffer_host,
                buffer_gpu_a,
                buffer_gpu_b,
                worksize,
            })
        }
    }
}

pub fn platform_info() {
    println!("PoCX Plotter {}", env!("CARGO_PKG_VERSION"));
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

            let cores = device.max_compute_units().unwrap_or(0);
            let kernel_workgroup_size = get_kernel_work_group_size(&kernel, &device, 0);
            let vendor = device.vendor().unwrap_or_else(|_| "Unknown".to_string());
            let name = device.name().unwrap_or_else(|_| "Unknown".to_string());

            println!(
                "- device {}, {} - {}, cores={}, kernel_workgroupsize={}",
                j, vendor, name, cores, kernel_workgroup_size
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

/// GPU device information with kernel workgroup size
#[derive(Debug, Clone)]
#[allow(dead_code)] // Used by library consumers (Tauri), not binary
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
#[allow(dead_code)] // Used by library consumers (Tauri), not binary
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

            // Check if APU (integrated graphics)
            let is_apu = host_unified
                || (vendor.to_uppercase().contains("INTEL") && !name.to_uppercase().contains("ARC"))
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

pub fn gpu_get_info(gpus: &[String], quiet: bool, kws_override: usize) -> u64 {
    let mut total_mem_needed = 0u64;

    let platforms = match get_platforms() {
        Ok(p) => p,
        Err(_) => return 0,
    };

    for gpu in gpus.iter() {
        let parts: Vec<&str> = gpu.split(':').collect();
        let platform_id = parts[0].parse::<usize>().unwrap();
        let gpu_id = parts[1].parse::<usize>().unwrap();
        let gpu_cores = parts[2].parse::<usize>().unwrap();

        if platform_id >= platforms.len() {
            println!("Error: Selected OpenCL platform doesn't exist.");
            println!("Shutting down...");
            process::exit(0);
        }

        let platform = &platforms[platform_id];
        let devices = match platform.get_devices(CL_DEVICE_TYPE_GPU) {
            Ok(d) => d,
            Err(_) => {
                println!("Error: Failed to get GPU devices");
                println!("Shutting down...");
                process::exit(0);
            }
        };

        if gpu_id >= devices.len() {
            println!("Error: Selected OpenCL device doesn't exist");
            println!("Shutting down...");
            process::exit(0);
        }

        let device = Device::new(devices[gpu_id]);
        let max_compute_units = device.max_compute_units().unwrap_or(0) as usize;
        let mem = device.global_mem_size().unwrap_or(0);

        // Get work_group_size for kernel
        let context = Context::from_device(&device).expect("Failed to create context");
        let program = Program::create_and_build_from_source(&context, SRC, "")
            .expect("Failed to build program");
        let kernel = Kernel::create(&program, "calculate_nonces").expect("Failed to create kernel");
        let kernel_workgroup_size = get_kernel_work_group_size(&kernel, &device, kws_override);

        let gpu_cores = if gpu_cores == 0 {
            max_compute_units
        } else {
            min(gpu_cores, 2 * max_compute_units)
        };
        let mem_needed = 2 * gpu_cores * kernel_workgroup_size * 256 * 1024;

        if mem_needed as u64 > mem {
            println!("Error: Not enough GPU-memory. Please reduce number of cores.");
            println!("Shutting down...");
            process::exit(0);
        }

        if !quiet {
            let vendor = device.vendor().unwrap_or_else(|_| "Unknown".to_string());
            let name = device.name().unwrap_or_else(|_| "Unknown".to_string());
            println!(
                "GPU: {} - {} [using {} of {} cores]",
                vendor, name, gpu_cores, max_compute_units
            );
            println!(
                "     GPU-RAM: Total={:.2} MiB, Usage={:.2} MiB",
                mem / 1024 / 1024,
                mem_needed / 1024 / 1024,
            );
        }
        total_mem_needed += mem_needed as u64;
    }
    total_mem_needed
}

pub fn gpu_init(gpus: &[String], zcb: bool, kws_override: usize) -> Result<Vec<Arc<Mutex<GpuContext>>>, String> {
    let mut result = Vec::new();

    let platforms = match get_platforms() {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to get OpenCL platforms: {:?}", e)),
    };

    for gpu in gpus.iter() {
        let parts: Vec<&str> = gpu.split(':').collect();
        if parts.len() < 3 {
            return Err(format!("Invalid GPU ID format: {}. Expected platform:device:cores", gpu));
        }
        let platform_id = parts[0].parse::<usize>()
            .map_err(|_| format!("Invalid platform ID in GPU: {}", gpu))?;
        let gpu_id = parts[1].parse::<usize>()
            .map_err(|_| format!("Invalid device ID in GPU: {}", gpu))?;
        let gpu_cores = parts[2].parse::<usize>()
            .map_err(|_| format!("Invalid cores in GPU: {}", gpu))?;

        if platform_id >= platforms.len() {
            return Err(format!("OpenCL platform {} doesn't exist (only {} platforms found)", platform_id, platforms.len()));
        }

        let platform = &platforms[platform_id];
        let devices = platform.get_devices(CL_DEVICE_TYPE_GPU)
            .map_err(|e| format!("Failed to get GPU devices: {:?}", e))?;

        if gpu_id >= devices.len() {
            return Err(format!("OpenCL device {} doesn't exist on platform {} (only {} devices found)", gpu_id, platform_id, devices.len()));
        }

        let device = Device::new(devices[gpu_id]);
        let max_compute_units = device.max_compute_units().unwrap_or(0) as usize;
        let vendor = device
            .vendor()
            .unwrap_or_else(|_| "Unknown".to_string())
            .to_uppercase();
        let nvidia = vendor.contains("NVIDIA");

        let gpu_cores = if gpu_cores == 0 {
            max_compute_units
        } else {
            min(gpu_cores, max_compute_units)
        };

        let context = GpuContext::new(
            platform_id,
            gpu_id,
            gpu_cores,
            nvidia,
            zcb,
            kws_override,
        )?;
        result.push(Arc::new(Mutex::new(context)));
    }
    Ok(result)
}

pub fn gpu_hash(gpu_context: &Arc<Mutex<GpuContext>>, task: &GpuTask) {
    // Upload base58 and seed
    upload_base58(gpu_context, &task.address_payload, true);
    upload_seed(gpu_context, task.seed, true);

    let gpu_context = gpu_context.lock().unwrap();

    for i in (0..8192).step_by(GPU_HASHES_PER_RUN) {
        let (start, end) = if i + GPU_HASHES_PER_RUN < 8192 {
            (i as i32, (i + GPU_HASHES_PER_RUN - 1) as i32)
        } else {
            (i as i32, (i + GPU_HASHES_PER_RUN) as i32)
        };

        unsafe {
            ExecuteKernel::new(&gpu_context.kernel)
                .set_arg(&gpu_context.buffer_gpu_a)
                .set_arg(&task.local_startnonce)
                .set_arg(&*gpu_context.base58.borrow())
                .set_arg(&*gpu_context.seed.borrow())
                .set_arg(&start)
                .set_arg(&end)
                .set_arg(&task.local_nonces)
                .set_global_work_size(gpu_context.gdim1[0])
                .set_local_work_size(gpu_context.ldim1[0])
                .enqueue_nd_range(&gpu_context.queue_a)
                .expect("Failed to enqueue kernel");
        }
    }
    gpu_context
        .queue_a
        .finish()
        .expect("Failed to finish queue");
}

pub fn gpu_transfer_to_host(
    gpu_context: &Arc<Mutex<GpuContext>>,
    buffer_id: u8,
    transfer_task: &GpuTask,
) {
    let gpu_context = gpu_context.lock().unwrap();
    let buffer_size = gpu_context.worksize * NONCE_SIZE as usize;

    // Select source buffer
    let src_buffer = if buffer_id == 1 {
        &gpu_context.buffer_gpu_a
    } else {
        &gpu_context.buffer_gpu_b
    };

    let buffer_ptr = if gpu_context.mapping {
        // Zero-copy mode: map GPU buffer to host temporarily
        let mut mapped_ptr: *mut std::ffi::c_void = ptr::null_mut();
        unsafe {
            gpu_context
                .queue_b
                .enqueue_map_buffer::<u8>(
                    src_buffer,
                    CL_BLOCKING,
                    CL_MAP_READ,
                    0,
                    buffer_size,
                    &mut mapped_ptr,
                    &[],
                )
                .expect("Failed to map buffer");
        }
        let ptr = mapped_ptr as *const u8;

        // Process the data while mapped
        unpack_shuffle_scatter(ptr, &gpu_context, transfer_task);

        // Unmap the buffer
        unsafe {
            gpu_context
                .queue_a
                .enqueue_unmap_mem_object(src_buffer.get(), mapped_ptr, &[])
                .expect("Failed to unmap buffer");
        }
        gpu_context
            .queue_a
            .finish()
            .expect("Failed to finish queue");
        return;
    } else {
        // Pinned memory mode: use persistent mapped buffer
        let ptr = gpu_context
            .buffer_ptr_host
            .expect("buffer_ptr_host not set");

        // Copy from GPU to pinned host buffer
        let slice = unsafe { from_raw_parts_mut(ptr, buffer_size) };
        unsafe {
            gpu_context
                .queue_b
                .enqueue_read_buffer(src_buffer, CL_BLOCKING, 0, slice, &[])
                .expect("Failed to read buffer");
        }
        ptr
    };

    unpack_shuffle_scatter(buffer_ptr, &gpu_context, transfer_task);
}

pub fn gpu_hash_and_transfer_to_host(
    gpu_context: &Arc<Mutex<GpuContext>>,
    buffer_id: u8,
    hasher_task: &GpuTask,
    transfer_task: &GpuTask,
) {
    let gpu_context = gpu_context.lock().unwrap();
    let buffer_size = gpu_context.worksize * NONCE_SIZE as usize;

    // Determine which buffer to compute into and which to transfer from
    let (compute_buffer, transfer_buffer) = if buffer_id == 0 {
        (&gpu_context.buffer_gpu_a, &gpu_context.buffer_gpu_b)
    } else {
        (&gpu_context.buffer_gpu_b, &gpu_context.buffer_gpu_a)
    };

    // Store mapped pointer for later unmap (if in mapping mode)
    let mut mapped_ptr: *mut std::ffi::c_void = ptr::null_mut();

    let buffer_ptr = if gpu_context.mapping {
        // Zero-copy mode: map transfer buffer while computing
        unsafe {
            gpu_context
                .queue_b
                .enqueue_map_buffer::<u8>(
                    transfer_buffer,
                    CL_BLOCKING,
                    CL_MAP_READ,
                    0,
                    buffer_size,
                    &mut mapped_ptr,
                    &[],
                )
                .expect("Failed to map buffer");
        }
        mapped_ptr as *const u8
    } else {
        // Pinned memory mode: start async copy to persistent mapped buffer
        let ptr = gpu_context
            .buffer_ptr_host
            .expect("buffer_ptr_host not set");
        let slice = unsafe { from_raw_parts_mut(ptr, buffer_size) };
        unsafe {
            gpu_context
                .queue_b
                .enqueue_read_buffer(transfer_buffer, CL_NON_BLOCKING, 0, slice, &[])
                .expect("Failed to enqueue read buffer");
        }
        ptr
    };

    // Enqueue compute kernels on queue_a (overlaps with transfer on queue_b)
    for i in (0..8192).step_by(GPU_HASHES_PER_RUN) {
        let (start, end) = if i + GPU_HASHES_PER_RUN < 8192 {
            (i as i32, (i + GPU_HASHES_PER_RUN - 1) as i32)
        } else {
            (i as i32, (i + GPU_HASHES_PER_RUN) as i32)
        };

        unsafe {
            ExecuteKernel::new(&gpu_context.kernel)
                .set_arg(compute_buffer)
                .set_arg(&hasher_task.local_startnonce)
                .set_arg(&*gpu_context.base58.borrow())
                .set_arg(&*gpu_context.seed.borrow())
                .set_arg(&start)
                .set_arg(&end)
                .set_arg(&hasher_task.local_nonces)
                .set_global_work_size(gpu_context.gdim1[0])
                .set_local_work_size(gpu_context.ldim1[0])
                .enqueue_nd_range(&gpu_context.queue_a)
                .expect("Failed to enqueue kernel");
        }
    }

    // Wait for transfer to complete
    gpu_context
        .queue_b
        .finish()
        .expect("Failed to finish transfer queue");

    // Process transferred data
    unpack_shuffle_scatter(buffer_ptr, &gpu_context, transfer_task);

    // Unmap if in mapping mode
    if gpu_context.mapping && !mapped_ptr.is_null() {
        unsafe {
            gpu_context
                .queue_a
                .enqueue_unmap_mem_object(transfer_buffer.get(), mapped_ptr, &[])
                .expect("Failed to unmap buffer");
        }
    }

    // Wait for compute to finish
    gpu_context
        .queue_a
        .finish()
        .expect("Failed to finish compute queue");
}

fn upload_base58(gpu_context: &Arc<Mutex<GpuContext>>, address_payload: &[u8; 20], blocking: bool) {
    let gpu_context = gpu_context.lock().unwrap();
    let mut base58 = gpu_context.base58.borrow_mut();
    unsafe {
        gpu_context
            .queue_a
            .enqueue_write_buffer(
                &mut *base58,
                if blocking {
                    CL_BLOCKING
                } else {
                    CL_NON_BLOCKING
                },
                0,
                address_payload,
                &[],
            )
            .expect("Failed to write base58 buffer");
    }
}

fn upload_seed(gpu_context: &Arc<Mutex<GpuContext>>, seed: [u8; 32], blocking: bool) {
    let gpu_context = gpu_context.lock().unwrap();
    let mut seed_buf = gpu_context.seed.borrow_mut();
    unsafe {
        gpu_context
            .queue_a
            .enqueue_write_buffer(
                &mut *seed_buf,
                if blocking {
                    CL_BLOCKING
                } else {
                    CL_NON_BLOCKING
                },
                0,
                &seed,
                &[],
            )
            .expect("Failed to write seed buffer");
    }
}

// SIMD shabal words unpack + POC Shuffle + scatter nonces into optimised cache
fn unpack_shuffle_scatter(buffer: *const u8, gpu_context: &GpuContext, transfer_task: &GpuTask) {
    unsafe {
        let buffer = from_raw_parts(buffer, gpu_context.worksize * NONCE_SIZE as usize);
        let iter: Vec<u64> = (0..transfer_task.local_nonces).step_by(16).collect();
        iter.par_iter().for_each(|n| {
            // Get global buffer
            let data = from_raw_parts_mut(
                transfer_task.cache.as_ptr(),
                NONCE_SIZE as usize * transfer_task.cache_size as usize,
            );
            for i in 0..(DIM * 2) {
                for j in (0..32).step_by(4) {
                    for k in 0..u64::min(MSHABAL512_VECTOR_SIZE, transfer_task.local_nonces - n) {
                        let data_offset = (((i & 1) * (4095 - (i >> 1)) + ((i + 1) & 1) * (i >> 1))
                            * DOUBLE_HASH_SIZE
                            * transfer_task.cache_size
                            + (*n + k + transfer_task.chunk_offset) * DOUBLE_HASH_SIZE
                            + (i & 1) * 32
                            + j) as usize;
                        let buffer_offset = (*n * NONCE_SIZE
                            + (i * 32 + j) * MSHABAL512_VECTOR_SIZE
                            + k * 4) as usize;
                        data[data_offset..(data_offset + 4)]
                            .clone_from_slice(&buffer[buffer_offset..(buffer_offset + 4)]);
                    }
                }
            }
        })
    }
}
