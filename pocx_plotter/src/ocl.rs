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

use self::core::{
    ArgVal, ContextProperties, DeviceInfo, Event, KernelWorkGroupInfo, PlatformInfo, Status,
};
use crate::gpu_hasher::GpuTask;
use crate::plotter::{DIM, DOUBLE_HASH_SIZE, NONCE_SIZE};
use ocl_core as core;
use rayon::prelude::*;
use std::cmp::min;
use std::ffi::CString;
use std::process;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::sync::{Arc, Mutex};

static SRC: &str = include_str!("ocl/kernel.cl");

const GPU_HASHES_PER_RUN: usize = 32;
const MSHABAL512_VECTOR_SIZE: u64 = 16;

// convert the info or error to a string for printing:
macro_rules! to_string {
    ($expr:expr) => {
        match $expr {
            Ok(info) => info.to_string(),
            Err(err) => match err.api_status() {
                Some(Status::CL_KERNEL_ARG_INFO_NOT_AVAILABLE) => "Not available".into(),
                _ => err.to_string(),
            },
        }
    };
}

pub struct GpuContext {
    queue_a: core::CommandQueue,
    queue_b: core::CommandQueue,
    kernel: core::Kernel,
    ldim1: [usize; 3],
    gdim1: [usize; 3],
    mapping: bool,
    pub base58: core::Mem,
    pub seed: core::Mem,
    buffer_ptr_host: Option<core::MemMap<u8>>,
    #[allow(dead_code)]
    buffer_host: Option<core::Mem>,
    buffer_gpu_a: core::Mem,
    buffer_gpu_b: core::Mem,
    pub worksize: usize,
}

// Ohne Gummi im Bahnhofsviertel... das wird noch Konsequenzen haben
unsafe impl Sync for GpuContext {}

impl GpuContext {
    pub fn new(
        gpu_platform: usize,
        gpu_id: usize,
        cores: usize,
        nvidia: bool,
        mapping: bool,
        kws_override: usize,
    ) -> GpuContext {
        let platform_ids = core::get_platform_ids().unwrap();
        let platform_id = platform_ids[gpu_platform];
        let device_ids = core::get_device_ids(platform_id, None, None).unwrap();
        let device_id = device_ids[gpu_id];
        let context_properties = ContextProperties::new().platform(platform_id);
        let context =
            core::create_context(Some(&context_properties), &[device_id], None, None).unwrap();
        let src_cstring = CString::new(SRC).unwrap();
        let program = core::create_program_with_source(&context, &[src_cstring]).unwrap();
        core::build_program(
            &program,
            None::<&[()]>,
            &CString::new("").unwrap(),
            None,
            None,
        )
        .unwrap();
        let queue_a = core::create_command_queue(&context, device_id, None).unwrap();
        let queue_b = core::create_command_queue(&context, device_id, None).unwrap();
        let kernel = core::create_kernel(&program, "calculate_nonces").unwrap();
        let kernel_workgroup_size = get_kernel_work_group_size(&kernel, device_id, kws_override);
        let workgroup_count = cores;
        let worksize = kernel_workgroup_size * workgroup_count;
        let gdim1 = [worksize, 1, 1];
        let ldim1 = [kernel_workgroup_size, 1, 1];

        // create buffers
        let base58 = unsafe {
            core::create_buffer::<_, u8>(&context, core::MEM_READ_ONLY, 20, None).unwrap()
        };
        let seed = unsafe {
            core::create_buffer::<_, u8>(&context, core::MEM_READ_ONLY, 32, None).unwrap()
        };
        // mapping = zero copy buffers, no mapping = pinned memory for fast DMA.
        if mapping {
            let buffer_gpu_a = unsafe {
                core::create_buffer::<_, u8>(
                    &context,
                    core::MEM_READ_WRITE | core::MEM_ALLOC_HOST_PTR,
                    (NONCE_SIZE as usize) * worksize,
                    None,
                )
                .unwrap()
            };
            let buffer_gpu_b = unsafe {
                core::create_buffer::<_, u8>(
                    &context,
                    core::MEM_READ_WRITE | core::MEM_ALLOC_HOST_PTR,
                    (NONCE_SIZE as usize) * worksize,
                    None,
                )
                .unwrap()
            };
            GpuContext {
                queue_a,
                queue_b,
                kernel,
                ldim1,
                gdim1,
                mapping,
                base58,
                seed,
                buffer_gpu_a,
                buffer_gpu_b,
                buffer_ptr_host: None,
                buffer_host: None,
                worksize,
            }
        } else {
            let buffer_host = unsafe {
                core::create_buffer::<_, u8>(
                    &context,
                    core::MEM_READ_WRITE | core::MEM_ALLOC_HOST_PTR,
                    (NONCE_SIZE as usize) * worksize,
                    None,
                )
                .unwrap()
            };
            let buffer_ptr_host = unsafe {
                Some(
                    core::enqueue_map_buffer::<u8, _, _, _>(
                        &queue_b,
                        &buffer_host,
                        true,
                        core::MAP_READ,
                        0,
                        worksize * NONCE_SIZE as usize,
                        None::<Event>,
                        None::<&mut Event>,
                    )
                    .unwrap(),
                )
            };
            let buffer_gpu_a = if nvidia {
                buffer_host.clone()
            } else {
                unsafe {
                    core::create_buffer::<_, u8>(
                        &context,
                        core::MEM_READ_WRITE,
                        (NONCE_SIZE as usize) * worksize,
                        None,
                    )
                    .unwrap()
                }
            };
            let buffer_gpu_b = unsafe {
                core::create_buffer::<_, u8>(
                    &context,
                    core::MEM_READ_WRITE,
                    (NONCE_SIZE as usize) * worksize,
                    None,
                )
                .unwrap()
            };

            let buffer_host = if nvidia { None } else { Some(buffer_host) };
            GpuContext {
                queue_a,
                queue_b,
                kernel,
                ldim1,
                gdim1,
                mapping,
                base58,
                seed,
                buffer_ptr_host,
                buffer_host,
                buffer_gpu_a,
                buffer_gpu_b,
                worksize,
            }
        }
    }
}

pub fn platform_info() {
    println!("PoCX Plotter {}", env!("CARGO_PKG_VERSION"));
    println!("written by Proof of Capacity Consortium in Rust\n");
    println!("*OpenCL Information*\n");
    let platform_ids = match core::get_platform_ids() {
        Ok(ids) => ids,
        Err(_) => {
            println!("No OpenCL platforms found.");
            println!("OpenCL runtime is installed but no compatible GPU detected.");
            println!("GPU acceleration requires compatible hardware (Intel/AMD/NVIDIA GPU).\n");
            return;
        }
    };

    if platform_ids.is_empty() {
        println!("No OpenCL platforms found.");
        return;
    }

    for (i, platform_id) in platform_ids.iter().enumerate() {
        println!(
            "platform {}, {} - {}",
            i,
            to_string!(core::get_platform_info(platform_id, PlatformInfo::Name)),
            to_string!(core::get_platform_info(platform_id, PlatformInfo::Version))
        );
        let device_ids = core::get_device_ids(*platform_id, None, None).unwrap();
        let context_properties = ContextProperties::new().platform(*platform_id);
        for (j, device_id) in device_ids.iter().enumerate() {
            let context =
                core::create_context(Some(&context_properties), &[*device_id], None, None).unwrap();
            let src_cstring = CString::new(SRC).unwrap();
            let program = core::create_program_with_source(&context, &[src_cstring]).unwrap();
            core::build_program(
                &program,
                None::<&[()]>,
                &CString::new("").unwrap(),
                None,
                None,
            )
            .unwrap();
            let kernel = core::create_kernel(&program, "calculate_nonces").unwrap();
            let cores = get_cores(*device_id) as usize;
            let kernel_workgroup_size = get_kernel_work_group_size(&kernel, *device_id, 0);
            println!(
                "- device {}, {} - {}, cores={}, kernel_workgroupsize={}",
                j,
                to_string!(core::get_device_info(*device_id, DeviceInfo::Vendor)),
                to_string!(core::get_device_info(*device_id, DeviceInfo::Name)),
                cores,
                kernel_workgroup_size
            );
        }
    }
}

fn get_cores(device: core::DeviceId) -> u32 {
    match core::get_device_info(device, DeviceInfo::MaxComputeUnits).unwrap() {
        core::DeviceInfoResult::MaxComputeUnits(mcu) => mcu,
        _ => panic!("Unexpected error"),
    }
}

pub fn gpu_get_info(gpus: &[String], quiet: bool, kws_override: usize) -> u64 {
    let mut total_mem_needed = 0u64;
    for gpu in gpus.iter() {
        let gpu = gpu.split(':').collect::<Vec<&str>>();
        let platform_id = gpu[0].parse::<usize>().unwrap();
        let gpu_id = gpu[1].parse::<usize>().unwrap();
        let gpu_cores = gpu[2].parse::<usize>().unwrap();

        let platform_ids = core::get_platform_ids().unwrap();
        if platform_id >= platform_ids.len() {
            println!("Error: Selected OpenCL platform doesn't exist.");
            println!("Shutting down...");
            process::exit(0);
        }
        let platform = platform_ids[platform_id];
        let device_ids = core::get_device_ids(platform, None, None).unwrap();
        if gpu_id >= device_ids.len() {
            println!("Error: Selected OpenCL device doesn't exist");
            println!("Shutting down...");
            process::exit(0);
        }
        let device = device_ids[gpu_id];
        let max_compute_units =
            match core::get_device_info(device, DeviceInfo::MaxComputeUnits).unwrap() {
                core::DeviceInfoResult::MaxComputeUnits(mcu) => mcu,
                _ => panic!("Unexpected error. Can't obtain number of GPU cores."),
            };
        let mem = match core::get_device_info(device, DeviceInfo::GlobalMemSize).unwrap() {
            core::DeviceInfoResult::GlobalMemSize(gms) => gms,
            _ => panic!("Unexpected error. Can't obtain GPU memory size."),
        };

        // get work_group_size for kernel
        let context_properties = ContextProperties::new().platform(platform);
        let context =
            core::create_context(Some(&context_properties), &[device], None, None).unwrap();
        let src_cstring = CString::new(SRC).unwrap();
        let program = core::create_program_with_source(&context, &[src_cstring]).unwrap();
        core::build_program(
            &program,
            None::<&[()]>,
            &CString::new("").unwrap(),
            None,
            None,
        )
        .unwrap();
        let kernel = core::create_kernel(&program, "calculate_nonces").unwrap();
        let kernel_workgroup_size = get_kernel_work_group_size(&kernel, device, kws_override);

        let gpu_cores = if gpu_cores == 0 {
            max_compute_units as usize
        } else {
            min(gpu_cores, 2 * max_compute_units as usize)
        };
        let mem_needed = 2 * gpu_cores * kernel_workgroup_size * 256 * 1024;

        if mem_needed > mem as usize {
            println!("Error: Not enough GPU-memory. Please reduce number of cores.");
            println!("Shutting down...");
            process::exit(0);
        }

        if !quiet {
            println!(
                "GPU: {} - {} [using {} of {} cores]",
                to_string!(core::get_device_info(device, DeviceInfo::Vendor)),
                to_string!(core::get_device_info(device, DeviceInfo::Name)),
                gpu_cores,
                max_compute_units
            );
        }
        if !quiet {
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

pub fn gpu_init(gpus: &[String], zcb: bool, kws_override: usize) -> Vec<Arc<Mutex<GpuContext>>> {
    let mut result = Vec::new();
    for gpu in gpus.iter() {
        let gpu = gpu.split(':').collect::<Vec<&str>>();
        let platform_id = gpu[0].parse::<usize>().unwrap();
        let gpu_id = gpu[1].parse::<usize>().unwrap();
        let gpu_cores = gpu[2].parse::<usize>().unwrap();
        let platform_ids = core::get_platform_ids().unwrap();
        if platform_id >= platform_ids.len() {
            println!("Error: Selected OpenCL platform doesn't exist.");
            println!("Shutting down...");
            process::exit(0);
        }
        let platform = platform_ids[platform_id];
        let device_ids = core::get_device_ids(platform, None, None).unwrap();
        if gpu_id >= device_ids.len() {
            println!("Error: Selected OpenCL device doesn't exist");
            println!("Shutting down...");
            process::exit(0);
        }
        let device = device_ids[gpu_id];
        let max_compute_units =
            match core::get_device_info(device, DeviceInfo::MaxComputeUnits).unwrap() {
                core::DeviceInfoResult::MaxComputeUnits(mcu) => mcu,
                _ => panic!("Unexpected error. Can't obtain number of GPU cores."),
            };
        let vendor = to_string!(core::get_device_info(device, DeviceInfo::Vendor)).to_uppercase();
        let nvidia = vendor.contains("NVIDIA");
        let gpu_cores = if gpu_cores == 0 {
            max_compute_units as usize
        } else {
            min(gpu_cores, max_compute_units as usize)
        };
        result.push(Arc::new(Mutex::new(GpuContext::new(
            platform_id,
            gpu_id,
            gpu_cores,
            nvidia,
            zcb,
            kws_override,
        ))));
    }
    result
}

fn get_kernel_work_group_size(x: &core::Kernel, y: core::DeviceId, kws_override: usize) -> usize {
    if kws_override != 0 {
        return kws_override;
    }
    match core::get_kernel_work_group_info(x, y, KernelWorkGroupInfo::WorkGroupSize).unwrap() {
        core::KernelWorkGroupInfoResult::WorkGroupSize(kws) => kws,
        _ => panic!("Unexpected error"),
    }
}

pub fn gpu_hash(gpu_context: &Arc<Mutex<GpuContext>>, task: &GpuTask) {
    let mut start;
    let mut end;

    // upload base58 and seed
    upload_base58(gpu_context, &task.address_payload, true);
    upload_seed(gpu_context, task.seed, true);

    let gpu_context = gpu_context.lock().unwrap();

    core::set_kernel_arg(
        &gpu_context.kernel,
        0,
        ArgVal::mem(&gpu_context.buffer_gpu_a),
    )
    .unwrap();
    core::set_kernel_arg(
        &gpu_context.kernel,
        1,
        ArgVal::primitive(&task.local_startnonce),
    )
    .unwrap();
    core::set_kernel_arg(&gpu_context.kernel, 2, ArgVal::mem(&gpu_context.base58)).unwrap();
    core::set_kernel_arg(&gpu_context.kernel, 3, ArgVal::mem(&gpu_context.seed)).unwrap();
    core::set_kernel_arg(
        &gpu_context.kernel,
        6,
        ArgVal::primitive(&task.local_nonces),
    )
    .unwrap();

    for i in (0..8192).step_by(GPU_HASHES_PER_RUN) {
        if i + GPU_HASHES_PER_RUN < 8192 {
            start = i;
            end = i + GPU_HASHES_PER_RUN - 1;
        } else {
            start = i;
            end = i + GPU_HASHES_PER_RUN;
        }

        core::set_kernel_arg(&gpu_context.kernel, 4, ArgVal::primitive(&(start as i32))).unwrap();
        core::set_kernel_arg(&gpu_context.kernel, 5, ArgVal::primitive(&(end as i32))).unwrap();

        unsafe {
            core::enqueue_kernel(
                &gpu_context.queue_a,
                &gpu_context.kernel,
                1,
                None,
                &gpu_context.gdim1,
                Some(gpu_context.ldim1),
                None::<Event>,
                None::<&mut Event>,
            )
            .unwrap();
        }
    }
    core::finish(&gpu_context.queue_a).unwrap();
}

pub fn gpu_transfer_to_host(
    gpu_context: &Arc<Mutex<GpuContext>>,
    buffer_id: u8,
    transfer_task: &GpuTask,
) {
    let mut gpu_context = gpu_context.lock().unwrap();

    // get mem mapping
    let map = if gpu_context.mapping {
        Some(mem_map_gpu_to_host(buffer_id, &gpu_context))
    } else {
        None
    };

    let buffer = if gpu_context.mapping {
        // map to host (zero copy buffer)
        map.as_ref().unwrap().as_ptr()
    } else {
        // get pointer
        let ptr = gpu_context.buffer_ptr_host.as_mut().unwrap().as_mut_ptr();
        // copy to host
        let slice = unsafe { from_raw_parts_mut(ptr, gpu_context.worksize * NONCE_SIZE as usize) };
        mem_transfer_gpu_to_host(buffer_id, &gpu_context, slice);
        core::finish(&gpu_context.queue_b).unwrap();
        ptr
    };
    unpack_shuffle_scatter(buffer, &gpu_context, transfer_task);
    if gpu_context.mapping {
        mem_unmap_gpu_to_host(buffer_id, &gpu_context, map);
        core::finish(&gpu_context.queue_a).unwrap();
    }
}

pub fn gpu_hash_and_transfer_to_host(
    gpu_context: &Arc<Mutex<GpuContext>>,
    buffer_id: u8,
    hasher_task: &GpuTask,
    transfer_task: &GpuTask,
) {
    let mut start;
    let mut end;

    let mut gpu_context = gpu_context.lock().unwrap();

    let map = if gpu_context.mapping {
        Some(mem_map_gpu_to_host(buffer_id, &gpu_context))
    } else {
        None
    };

    let buffer = if gpu_context.mapping {
        // map to host (zero copy buffer)
        map.as_ref().unwrap().as_ptr()
    } else {
        // get pointer
        let ptr = gpu_context.buffer_ptr_host.as_mut().unwrap().as_mut_ptr();
        // copy to host
        let slice = unsafe { from_raw_parts_mut(ptr, gpu_context.worksize * NONCE_SIZE as usize) };
        mem_transfer_gpu_to_host(buffer_id, &gpu_context, slice);
        ptr
    };

    core::set_kernel_arg(
        &gpu_context.kernel,
        0,
        ArgVal::mem(if buffer_id == 0 {
            &gpu_context.buffer_gpu_a
        } else {
            &gpu_context.buffer_gpu_b
        }),
    )
    .unwrap();
    core::set_kernel_arg(
        &gpu_context.kernel,
        1,
        ArgVal::primitive(&hasher_task.local_startnonce),
    )
    .unwrap();
    core::set_kernel_arg(&gpu_context.kernel, 2, ArgVal::mem(&gpu_context.base58)).unwrap();
    core::set_kernel_arg(&gpu_context.kernel, 3, ArgVal::mem(&gpu_context.seed)).unwrap();
    core::set_kernel_arg(
        &gpu_context.kernel,
        6,
        ArgVal::primitive(&hasher_task.local_nonces),
    )
    .unwrap();

    for i in (0..8192).step_by(GPU_HASHES_PER_RUN) {
        if i + GPU_HASHES_PER_RUN < 8192 {
            start = i;
            end = i + GPU_HASHES_PER_RUN - 1;
        } else {
            start = i;
            end = i + GPU_HASHES_PER_RUN;
        }
        core::set_kernel_arg(&gpu_context.kernel, 4, ArgVal::primitive(&(start as i32))).unwrap();
        core::set_kernel_arg(&gpu_context.kernel, 5, ArgVal::primitive(&(end as i32))).unwrap();
        unsafe {
            core::enqueue_kernel(
                &gpu_context.queue_a,
                &gpu_context.kernel,
                1,
                None,
                &gpu_context.gdim1,
                Some(gpu_context.ldim1),
                None::<Event>,
                None::<&mut Event>,
            )
            .unwrap();
        }
    }
    core::finish(&gpu_context.queue_b).unwrap();
    unpack_shuffle_scatter(buffer, &gpu_context, transfer_task);
    if gpu_context.mapping {
        mem_unmap_gpu_to_host(buffer_id, &gpu_context, map);
    }
    core::finish(&gpu_context.queue_a).unwrap();
}

fn mem_map_gpu_to_host(buffer_id: u8, gpu_context: &GpuContext) -> core::MemMap<u8> {
    unsafe {
        if buffer_id == 1 {
            core::enqueue_map_buffer::<u8, _, _, _>(
                &gpu_context.queue_b,
                &gpu_context.buffer_gpu_a,
                true,
                core::MAP_READ,
                0,
                gpu_context.gdim1[0] * NONCE_SIZE as usize,
                None::<Event>,
                None::<&mut Event>,
            )
            .unwrap()
        } else {
            core::enqueue_map_buffer::<u8, _, _, _>(
                &gpu_context.queue_b,
                &gpu_context.buffer_gpu_b,
                true,
                core::MAP_READ,
                0,
                gpu_context.gdim1[0] * NONCE_SIZE as usize,
                None::<Event>,
                None::<&mut Event>,
            )
            .unwrap()
        }
    }
}

fn mem_unmap_gpu_to_host(buffer_id: u8, gpu_context: &GpuContext, map: Option<core::MemMap<u8>>) {
    // map to host (zero copy buffer)
    if buffer_id == 1 {
        core::enqueue_unmap_mem_object(
            &gpu_context.queue_a,
            &gpu_context.buffer_gpu_a,
            &map.unwrap(),
            None::<Event>,
            None::<&mut Event>,
        )
        .unwrap()
    } else {
        core::enqueue_unmap_mem_object(
            &gpu_context.queue_a,
            &gpu_context.buffer_gpu_b,
            &map.unwrap(),
            None::<Event>,
            None::<&mut Event>,
        )
        .unwrap()
    };
}

fn mem_transfer_gpu_to_host(buffer_id: u8, gpu_context: &GpuContext, slice: &mut [u8]) {
    unsafe {
        if buffer_id == 1 {
            core::enqueue_read_buffer(
                &gpu_context.queue_b,
                &gpu_context.buffer_gpu_a,
                false,
                0,
                slice,
                None::<Event>,
                None::<&mut Event>,
            )
            .unwrap();
        } else {
            core::enqueue_read_buffer(
                &gpu_context.queue_b,
                &gpu_context.buffer_gpu_b,
                false,
                0,
                slice,
                None::<Event>,
                None::<&mut Event>,
            )
            .unwrap();
        }
    }
}

fn upload_base58(gpu_context: &Arc<Mutex<GpuContext>>, address_payload: &[u8; 20], blocking: bool) {
    let gpu_context = gpu_context.lock().unwrap();
    unsafe {
        core::enqueue_write_buffer(
            &gpu_context.queue_a,
            &gpu_context.base58,
            blocking,
            0,
            address_payload,
            None::<Event>,
            None::<&mut Event>,
        )
        .unwrap();
    }
}

fn upload_seed(gpu_context: &Arc<Mutex<GpuContext>>, seed: [u8; 32], blocking: bool) {
    let gpu_context = gpu_context.lock().unwrap();
    unsafe {
        core::enqueue_write_buffer(
            &gpu_context.queue_a,
            &gpu_context.seed,
            blocking,
            0,
            &seed,
            None::<Event>,
            None::<&mut Event>,
        )
        .unwrap();
    }
}

// simd shabal words unpack + POC Shuffle + scatter nonces into optimised cache
fn unpack_shuffle_scatter(buffer: *const u8, gpu_context: &GpuContext, transfer_task: &GpuTask) {
    unsafe {
        let buffer = from_raw_parts(buffer, gpu_context.worksize * NONCE_SIZE as usize);
        let iter: Vec<u64> = (0..transfer_task.local_nonces).step_by(16).collect();
        iter.par_iter().for_each(|n| {
            // get global buffer
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
