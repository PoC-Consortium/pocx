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

use crate::cpu_hasher::SafePointer;
use crate::ocl::{gpu_hash, gpu_hash_and_transfer_to_host, gpu_transfer_to_host, GpuContext};
use crate::xpu_scheduler::HasherMessage;
use crossbeam_channel::{Receiver, Sender};
use std::sync::{Arc, Mutex};

pub struct GpuTask {
    pub cache: SafePointer,
    pub cache_size: u64,
    pub chunk_offset: u64,
    pub address_payload: [u8; 20], // Network-independent address payload
    pub seed: [u8; 32],
    pub local_startnonce: u64,
    pub local_nonces: u64,
}

pub fn create_gpu_hasher_thread(
    gpu_id: usize,
    gpu_context: Arc<Mutex<GpuContext>>,
    tx: Sender<HasherMessage>,
    rx_hasher_task: Receiver<Option<GpuTask>>,
) -> impl FnOnce() {
    move || {
        let mut first_run = true;
        let mut buffer_id = 0u8;
        let mut last_task = GpuTask {
            cache: SafePointer::new(&mut 0u8),
            cache_size: 0,
            chunk_offset: 0,
            address_payload: [0u8; 20],
            seed: [0u8; 32],
            local_startnonce: 0,
            local_nonces: 0,
        };
        for task in rx_hasher_task {
            // check if new task or termination
            match task {
                // new task
                Some(task) => {
                    // first run - just hash
                    if first_run {
                        if task.local_nonces != 0 {
                            first_run = false;
                            gpu_hash(&gpu_context, &task);
                            buffer_id = 1 - buffer_id;
                            last_task = task;
                            tx.send(HasherMessage::GpuRequestForWork(gpu_id))
                                .expect("GPU task can't communicate with scheduler thread.");
                        }
                    // last run - just transfer
                    } else if task.local_nonces == 0 {
                        gpu_transfer_to_host(&gpu_context, buffer_id, &last_task);
                        first_run = true;
                        buffer_id = 0;
                        tx.send(HasherMessage::NoncesHashed(last_task.local_nonces))
                            .expect("GPU task can't communicate with scheduler thread.");
                    // normal run - hash and transfer async
                    } else {
                        gpu_hash_and_transfer_to_host(&gpu_context, buffer_id, &task, &last_task);
                        buffer_id = 1 - buffer_id;
                        tx.send(HasherMessage::NoncesHashed(last_task.local_nonces))
                            .expect("GPU task can't communicate with scheduler thread.");
                        last_task = task;
                        tx.send(HasherMessage::GpuRequestForWork(gpu_id))
                            .expect("GPU task can't communicate with scheduler thread.");
                    }
                }
                // termination
                None => {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu_hasher::SafePointer;
    use crate::ocl::{gpu_hash, gpu_init};
    use crate::plotter;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_noncegen_gpu() {
        let mut seed = [0u8; 32];
        seed[..].clone_from_slice(
            &hex::decode("AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE")
                .unwrap(),
        );
        let mut address_payload = [0u8; 20];
        address_payload
            .clone_from_slice(&hex::decode("99BC78BA577A95A11F1A344D4D2AE55F2F857B98").unwrap());
        let start_nonce = 1337;
        let exp_result_hash = "acc0b40a22cf8ce8aabe361bd4b67bdb61b7367755ae9cb9963a68acaa6d322c";

        let check_result = |buf: &Vec<u8>| {
            let mut hasher = Sha256::new();
            hasher.update(buf);
            assert_eq!(format!("{:x}", hasher.finalize()), exp_result_hash);
        };

        let mut buf = vec![0; 32 * plotter::NONCE_SIZE as usize];

        // create context for first gpu - skip test if no OpenCL platforms available
        let context = match std::panic::catch_unwind(|| gpu_init(&["0:0:0".to_owned()], false, 0)) {
            Ok(ctx) => ctx,
            Err(_) => {
                println!("Skipping GPU test: gpu_init panicked (no OpenCL runtime)");
                return;
            }
        };

        // Skip if no GPUs were found
        if context.is_empty() {
            println!("Skipping GPU test: No OpenCL devices available");
            return;
        }

        // create task
        let gpu_task = GpuTask {
            cache: SafePointer::new(buf.as_mut_ptr()),
            cache_size: 32,
            chunk_offset: 0,
            address_payload,
            seed,
            local_startnonce: start_nonce,
            local_nonces: 32,
        };

        gpu_hash(&context[0], &gpu_task);
        gpu_transfer_to_host(&context[0], 1, &gpu_task);

        check_result(&buf);
    }
}
