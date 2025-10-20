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
#[cfg(feature = "opencl")]
use crate::gpu_hasher::{create_gpu_hasher_thread, GpuTask};
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
        let gpus = gpu_contexts.unwrap_or_default();
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
            let mut_bs = &buffer.get_buffer();
            let mut bs = mut_bs.lock().unwrap();
            let buffer_size = (*bs).len() as u64;

            let warps_to_hash = min(
                buffer_size / WARP_SIZE / u64::pow(2, task.compress),
                task.warps[pointer] - hash_progress[pointer],
            );

            let nonces_to_hash = u64::pow(2, task.compress) * warps_to_hash * DIM;
            let nonces_hashed = u64::pow(2, task.compress) * hash_progress[pointer] * DIM;

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
                        let delta = nonces * NONCE_SIZE / u64::pow(2, task.compress);

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
            if task.number_of_plots.iter().sum::<u64>() == plotfile_progress.iter().sum::<u64>() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;

    #[test]
    fn test_cpu_task_size() {
        // Test that CPU_TASK_SIZE has a reasonable value
        assert_eq!(CPU_TASK_SIZE, 64);
        // Removed constant assertions that will be optimized out
    }

    #[test]
    fn test_hasher_message_variants() {
        // Test CpuRequestForWork variant
        let cpu_msg = HasherMessage::CpuRequestForWork;
        match cpu_msg {
            HasherMessage::CpuRequestForWork => {}
            _ => panic!("CpuRequestForWork variant not matching"),
        }

        // Test NoncesHashed variant
        let nonces_msg = HasherMessage::NoncesHashed(1000);
        match nonces_msg {
            HasherMessage::NoncesHashed(count) => {
                assert_eq!(count, 1000);
            }
            _ => panic!("NoncesHashed variant not matching"),
        }

        // Test GPU variant if OpenCL is enabled
        #[cfg(feature = "opencl")]
        {
            let gpu_msg = HasherMessage::GpuRequestForWork(2);
            match gpu_msg {
                HasherMessage::GpuRequestForWork(id) => {
                    assert_eq!(id, 2);
                }
                _ => panic!("GpuRequestForWork variant not matching"),
            }
        }
    }

    #[test]
    fn test_hasher_message_channel_communication() {
        let (tx, rx) = unbounded::<HasherMessage>();

        // Test sending and receiving CPU work request
        tx.send(HasherMessage::CpuRequestForWork).unwrap();
        let received = rx.recv().unwrap();
        match received {
            HasherMessage::CpuRequestForWork => {}
            _ => panic!("CpuRequestForWork not transmitted correctly"),
        }

        // Test sending and receiving nonces hashed
        tx.send(HasherMessage::NoncesHashed(500)).unwrap();
        let received = rx.recv().unwrap();
        match received {
            HasherMessage::NoncesHashed(count) => {
                assert_eq!(count, 500);
            }
            _ => panic!("NoncesHashed not transmitted correctly"),
        }

        // Test GPU message if available
        #[cfg(feature = "opencl")]
        {
            tx.send(HasherMessage::GpuRequestForWork(1)).unwrap();
            let received = rx.recv().unwrap();
            match received {
                HasherMessage::GpuRequestForWork(id) => {
                    assert_eq!(id, 1);
                }
                _ => panic!("GpuRequestForWork not transmitted correctly"),
            }
        }
    }

    #[test]
    fn test_hasher_message_sizes() {
        // Test message size is reasonable
        let size = std::mem::size_of::<HasherMessage>();
        assert!(size > 0);
        assert!(size <= 64); // Should be small for efficient message passing
    }

    #[test]
    fn test_nonces_hashed_values() {
        // Test various nonce count values
        let test_values = [0, 1, 100, 1000, 10000, u64::MAX];

        for &value in &test_values {
            let msg = HasherMessage::NoncesHashed(value);
            match msg {
                HasherMessage::NoncesHashed(count) => {
                    assert_eq!(count, value);
                }
                _ => panic!("NoncesHashed value not preserved for {}", value),
            }
        }
    }

    #[cfg(feature = "opencl")]
    #[test]
    fn test_gpu_work_request_ids() {
        // Test various GPU ID values
        let test_ids = [0, 1, 2, 5, 10, usize::MAX];

        for &id in &test_ids {
            let msg = HasherMessage::GpuRequestForWork(id);
            match msg {
                HasherMessage::GpuRequestForWork(received_id) => {
                    assert_eq!(received_id, id);
                }
                _ => panic!("GPU ID not preserved for {}", id),
            }
        }
    }

    #[test]
    fn test_message_debug_format() {
        let cpu_msg = HasherMessage::CpuRequestForWork;
        let debug_str = format!("{:?}", cpu_msg);
        assert!(!debug_str.is_empty());
        assert!(debug_str.contains("CpuRequestForWork"));

        let nonces_msg = HasherMessage::NoncesHashed(42);
        let debug_str = format!("{:?}", nonces_msg);
        assert!(!debug_str.is_empty());
        assert!(debug_str.contains("NoncesHashed"));
        assert!(debug_str.contains("42"));

        #[cfg(feature = "opencl")]
        {
            let gpu_msg = HasherMessage::GpuRequestForWork(3);
            let debug_str = format!("{:?}", gpu_msg);
            assert!(!debug_str.is_empty());
            assert!(debug_str.contains("GpuRequestForWork"));
            assert!(debug_str.contains("3"));
        }
    }

    #[test]
    fn test_multiple_messages_in_channel() {
        let (tx, rx) = unbounded::<HasherMessage>();

        // Send multiple different messages
        tx.send(HasherMessage::CpuRequestForWork).unwrap();
        tx.send(HasherMessage::NoncesHashed(100)).unwrap();
        tx.send(HasherMessage::CpuRequestForWork).unwrap();
        tx.send(HasherMessage::NoncesHashed(200)).unwrap();

        // Receive and verify order
        match rx.recv().unwrap() {
            HasherMessage::CpuRequestForWork => {}
            _ => panic!("First message incorrect"),
        }

        match rx.recv().unwrap() {
            HasherMessage::NoncesHashed(100) => {}
            _ => panic!("Second message incorrect"),
        }

        match rx.recv().unwrap() {
            HasherMessage::CpuRequestForWork => {}
            _ => panic!("Third message incorrect"),
        }

        match rx.recv().unwrap() {
            HasherMessage::NoncesHashed(200) => {}
            _ => panic!("Fourth message incorrect"),
        }
    }

    #[test]
    fn test_channel_error_handling() {
        let (tx, rx) = unbounded::<HasherMessage>();

        // Drop receiver to cause send errors
        drop(rx);

        // Send should fail gracefully
        let result = tx.send(HasherMessage::CpuRequestForWork);
        assert!(result.is_err());

        let result = tx.send(HasherMessage::NoncesHashed(42));
        assert!(result.is_err());

        #[cfg(feature = "opencl")]
        {
            let result = tx.send(HasherMessage::GpuRequestForWork(0));
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_constants_consistency() {
        // Test that CPU_TASK_SIZE is consistent with other constants
        #[allow(unused_imports)]
        use crate::plotter::{NONCE_SIZE, WARP_SIZE};

        // CPU task size should be reasonable relative to other sizes
        // Removed constant assertions that will be optimized out

        // Should be a reasonable multiple
        assert!(CPU_TASK_SIZE.is_multiple_of(8) || CPU_TASK_SIZE.is_multiple_of(4));
    }

    #[test]
    fn test_message_cloning() {
        // Test that messages can be cloned
        let original = HasherMessage::NoncesHashed(500);
        let cloned = original.clone();

        match (original, cloned) {
            (HasherMessage::NoncesHashed(orig_val), HasherMessage::NoncesHashed(clone_val)) => {
                assert_eq!(orig_val, clone_val);
            }
            _ => panic!("Message cloning failed"),
        }

        let cpu_msg = HasherMessage::CpuRequestForWork;
        let cpu_cloned = cpu_msg.clone();

        match (cpu_msg, cpu_cloned) {
            (HasherMessage::CpuRequestForWork, HasherMessage::CpuRequestForWork) => {}
            _ => panic!("CPU message cloning failed"),
        }

        #[cfg(feature = "opencl")]
        {
            let gpu_msg = HasherMessage::GpuRequestForWork(7);
            let gpu_cloned = gpu_msg.clone();

            match (gpu_msg, gpu_cloned) {
                (
                    HasherMessage::GpuRequestForWork(orig_id),
                    HasherMessage::GpuRequestForWork(clone_id),
                ) => {
                    assert_eq!(orig_id, clone_id);
                }
                _ => panic!("GPU message cloning failed"),
            }
        }
    }
}
