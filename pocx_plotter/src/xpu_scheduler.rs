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

use crate::buffer::PageAlignedByteBuffer;
use crate::compressor::CompressorTask;
use crate::cpu_hasher::{hash_cpu, CpuTask, SafePointer};
use crate::get_plotter_callback;
#[cfg(feature = "opencl")]
use crate::gpu_hasher::{create_gpu_hasher_thread, GpuTask};
use crate::is_stop_requested;
#[cfg(feature = "opencl")]
use crate::ocl::gpu_init;
use crate::plotter::{PlotterTask, DIM, NONCE_SIZE, WARP_SIZE};
use crossbeam_channel::{unbounded, Receiver, Sender};
use rand::Rng;
use std::cmp::min;
use std::sync::Arc;
#[cfg(feature = "opencl")]
use std::thread;

const CPU_TASK_SIZE: u64 = 64;

#[derive(Debug, Clone)]
pub enum HasherMessage {
    CpuRequestForWork,
    #[cfg(feature = "opencl")]
    GpuRequestForWork(usize),
    NoncesHashed(u64),
}

pub fn create_scheduler_thread(
    task: Arc<PlotterTask>,
    thread_pool: rayon::ThreadPool,
    pb: Option<indicatif::ProgressBar>,
    rx_empty_buffers: Receiver<PageAlignedByteBuffer>,
    tx_buffers_to_compressor: Sender<CompressorTask>,
    resume: u64,
) -> impl FnOnce() {
    move || {
        // synchronisation chanel for all hashing devices (CPU+GPU)
        // message protocol:    (hash_device_id: u8, message: u8, nonces processed: u64)
        // hash_device_id:      0=CPU, 1=GPU0, 2=GPU1...
        // message:             0 = data ready to write
        //                      1 = device ready to compute next hashing batch
        // nonces_processed:    nonces hashed / nonces writen to host buffer
        let (tx, rx) = unbounded();

        // create gpu threads and channels
        #[cfg(feature = "opencl")]
        let gpu_contexts = task
            .gpus
            .as_ref()
            .map(|x| gpu_init(x, task.zcb, task.kws_override));

        #[cfg(feature = "opencl")]
        let gpus = match gpu_contexts {
            Some(Ok(contexts)) => contexts,
            Some(Err(e)) => {
                // GPU initialization failed - report error and stop
                if let Some(cb) = get_plotter_callback() {
                    cb.on_error(&e);
                }
                return;
            }
            None => Vec::new(),
        };
        #[cfg(feature = "opencl")]
        let mut gpu_threads = Vec::new();
        #[cfg(feature = "opencl")]
        let mut gpu_channels = Vec::new();

        #[cfg(feature = "opencl")]
        for (i, gpu) in gpus.iter().enumerate() {
            gpu_channels.push(unbounded());
            gpu_threads.push(thread::spawn({
                create_gpu_hasher_thread(
                    i,
                    gpu.clone(),
                    tx.clone(),
                    gpu_channels.last().unwrap().1.clone(),
                )
            }));
        }

        let mut hash_progress = vec![0; task.output_paths.len()];
        hash_progress[0] = resume;
        let mut plotfile_progress = vec![0u64; task.output_paths.len()];

        // create initial set of random seeds
        let mut seeds = Vec::new();

        // add manual seed if specified
        if let Some(seed) = task.seed {
            seeds.push(seed);
        }

        while seeds.len() < task.output_paths.len() {
            let mut seed = [0u8; 32];
            rand::rng().fill(&mut seed);
            seeds.push(seed);
        }

        let mut pointer = 0_usize;

        for buffer in rx_empty_buffers {
            // Check for stop request at the start of each buffer iteration
            if is_stop_requested() {
                println!("\nPlotting stopped by user.");
                // Shutdown GPU threads
                #[cfg(feature = "opencl")]
                for gpu in &gpu_channels {
                    let _ = gpu.0.send(None);
                }
                break;
            }

            let mut_bs = &buffer.get_buffer();
            let mut bs = mut_bs.lock().unwrap();
            let buffer_size = (*bs).len() as u64;

            let warps_to_hash = min(
                buffer_size / WARP_SIZE / u64::pow(2, task.compress as u32),
                task.warps[pointer] - hash_progress[pointer],
            );

            let nonces_to_hash = u64::pow(2, task.compress as u32) * warps_to_hash * DIM;
            let nonces_hashed = u64::pow(2, task.compress as u32) * hash_progress[pointer] * DIM;

            let mut requested = 0u64;
            let mut processed = 0u64;

            // kickoff first gpu and cpu runs
            #[cfg(feature = "opencl")]
            for (i, gpu) in gpus.iter().enumerate() {
                // schedule next gpu task
                let gpu = gpu.lock().unwrap();
                let task_size = min(gpu.worksize as u64, nonces_to_hash - requested);
                if task_size > 0 {
                    gpu_channels[i]
                        .0
                        .send(Some(GpuTask {
                            cache: SafePointer::new(bs.as_mut_ptr()),
                            cache_size: buffer_size / NONCE_SIZE,
                            chunk_offset: requested,
                            address_payload: task.address_payload,
                            seed: seeds[pointer],
                            local_startnonce: nonces_hashed + requested,
                            local_nonces: task_size,
                        }))
                        .unwrap();
                }
                requested += task_size;
                // println!("Debug: Device: {} started. {} nonces assigned.
                // Total requested: {}\n\n\n",i+1,task_size,requested);
            }

            for _ in 0..task.cpu_threads {
                let task_size = min(CPU_TASK_SIZE, nonces_to_hash - requested);
                if task_size > 0 {
                    let cpu_task = hash_cpu(
                        tx.clone(),
                        CpuTask {
                            cache: SafePointer::new(bs.as_mut_ptr()),
                            cache_size: (buffer_size / NONCE_SIZE) as usize,
                            chunk_offset: requested as usize,
                            address_payload: task.address_payload,
                            seed: seeds[pointer],
                            local_startnonce: nonces_hashed + requested,
                            local_nonces: task_size,
                        },
                    );
                    thread_pool.spawn(cpu_task);
                }
                requested += task_size;
            }

            // control loop
            let rx = &rx;
            for msg in rx {
                match msg {
                    // schedule next cpu task
                    HasherMessage::CpuRequestForWork => {
                        let task_size = min(CPU_TASK_SIZE, nonces_to_hash - requested);
                        if task_size > 0 {
                            let task = hash_cpu(
                                tx.clone(),
                                CpuTask {
                                    cache: SafePointer::new(bs.as_mut_ptr()),
                                    cache_size: (buffer_size / NONCE_SIZE) as usize,
                                    chunk_offset: requested as usize,
                                    address_payload: task.address_payload,
                                    seed: seeds[pointer],
                                    local_startnonce: nonces_hashed + requested,
                                    local_nonces: task_size,
                                },
                            );
                            thread_pool.spawn(task);
                        }
                        requested += task_size
                    }
                    // schedule next gpu task
                    #[cfg(feature = "opencl")]
                    HasherMessage::GpuRequestForWork(id) => {
                        let gpu = gpus[id].lock().unwrap();
                        let task_size = min(gpu.worksize as u64, nonces_to_hash - requested);

                        // optimisation: leave some work for cpu in dual mode
                        let task_size = if task_size < gpu.worksize as u64
                            && task.cpu_threads > 0
                            && task_size > CPU_TASK_SIZE
                        {
                            task_size / 2
                        } else {
                            task_size
                        };

                        gpu_channels[id]
                            .0
                            .send(Some(GpuTask {
                                cache: SafePointer::new(bs.as_mut_ptr()),
                                cache_size: buffer_size / NONCE_SIZE,
                                chunk_offset: requested,
                                address_payload: task.address_payload,
                                seed: seeds[pointer],
                                local_startnonce: nonces_hashed + requested,
                                local_nonces: task_size,
                            }))
                            .unwrap();
                        requested += task_size;
                    }
                    // process work completed message
                    HasherMessage::NoncesHashed(nonces) => {
                        processed += nonces;
                        let delta = nonces * NONCE_SIZE / u64::pow(2, task.compress as u32);

                        if let Some(i) = &pb {
                            i.inc(delta);
                        }
                    }
                }
                if processed == nonces_to_hash {
                    break;
                }
            }

            // queue buffer for compressing
            tx_buffers_to_compressor
                .send(CompressorTask {
                    buffer,
                    seed: seeds[pointer],
                    warps_to_compress: warps_to_hash,
                    warp_offset: hash_progress[pointer],
                    number_of_warps: task.warps[pointer],
                    path_pointer: pointer,
                })
                .unwrap();

            // update status
            hash_progress[pointer] += warps_to_hash;

            if task.line_progress {
                println!("#HASH_DELTA:{}", warps_to_hash);
            }

            // Notify callback of hashing progress
            if let Some(cb) = get_plotter_callback() {
                cb.on_hashing_progress(warps_to_hash);
            }

            if hash_progress[pointer] == task.warps[pointer] {
                plotfile_progress[pointer] += 1;
                if plotfile_progress[pointer] < task.number_of_plots[pointer] {
                    // reset for new file
                    hash_progress[pointer] = 0;
                    rand::rng().fill(&mut seeds[pointer]);
                }
            }

            pointer += 1;
            pointer %= task.output_paths.len();

            // thread end
            if is_stop_requested()
                || (task.number_of_plots.iter().sum::<u64>()
                    == plotfile_progress.iter().sum::<u64>())
            {
                if let Some(pb) = &pb {
                    pb.finish_with_message("Hasher done.");
                }
                // shutdown gpu threads
                #[cfg(feature = "opencl")]
                for gpu in &gpu_channels {
                    gpu.0.send(None).unwrap();
                }
                break;
            };
        }
    }
}
