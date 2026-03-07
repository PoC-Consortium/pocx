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

//! CPU scheduling thread.
//!
//! Drives the hash → helix compress → write buffer pipeline using CPU threads.
//! Mirrors `ring_scheduler.rs` flow but uses a 2 GiB scatter buffer instead of
//! a GPU ring buffer. Supports multi-path interleaving, escalation, and
//! variable compression (X1–X6).

use crate::buffer::PageAlignedByteBuffer;
use crate::cpu_compressor::{helix_compress, helix_compress_xor};
use crate::cpu_hasher::hash_nonces_cpu;
use crate::disk_writer::WriterTask;
use crate::error::lock_mutex;
use crate::get_plotter_callback;
use crate::is_stop_requested;
use crate::plotter::{PlotterTask, WARP_SIZE};
use crossbeam_channel::{Receiver, Sender};
use rand::Rng;
use std::sync::Arc;

const COMPRESS_BATCH: u64 = 8192; // DIM * 2 nonces per helix compress cycle
const SCATTER_SIZE: usize = COMPRESS_BATCH as usize * pocx_hashlib::noncegen_common::NONCE_SIZE;

pub fn create_cpu_scheduler_thread(
    task: Arc<PlotterTask>,
    cpu_threads: usize,
    pb: Option<indicatif::ProgressBar>,
    rx_empty_write_buffers: Receiver<PageAlignedByteBuffer>,
    tx_full_per_path: Vec<Sender<WriterTask>>,
    resume: u64,
) -> impl FnOnce() {
    move || {
        let escalate = task.escalate;
        let num_paths = task.output_paths.len();
        let passes_per_warp = 1u64 << (task.compress - 1);

        // Build rayon thread pool
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(cpu_threads)
            .build()
            .expect("Failed to build rayon thread pool");

        // Allocate 2 GiB scatter buffer
        let mut scatter_buf = vec![0u8; SCATTER_SIZE];

        // Per-path state
        let mut seeds: Vec<[u8; 32]> = Vec::with_capacity(num_paths);
        let mut warp_offsets: Vec<u64> = vec![0; num_paths];
        let mut files_done: Vec<u64> = vec![0; num_paths];

        // First path: manual seed or random, with resume support
        if let Some(s) = task.seed {
            seeds.push(s);
            warp_offsets[0] = resume;
        } else {
            let mut s = [0u8; 32];
            rand::rng().fill(&mut s);
            seeds.push(s);
        }

        // Remaining paths: random seeds
        for _ in 1..num_paths {
            let mut s = [0u8; 32];
            rand::rng().fill(&mut s);
            seeds.push(s);
        }

        let mut global_nonces: Vec<u64> = vec![0; num_paths];
        let mut pass_in_warp: u64 = 0;
        let mut path_pointer: usize = 0;

        if resume > 0 {
            global_nonces[0] = resume * passes_per_warp * COMPRESS_BATCH;
        }

        let mut write_buffer: Option<PageAlignedByteBuffer> = None;
        let mut warps_in_buffer: u64 = 0;
        let mut buffer_start_warp: u64 = warp_offsets[path_pointer];
        let mut buffer_path: usize = path_pointer;

        let flush_buffer =
            |write_buffer: &mut Option<PageAlignedByteBuffer>,
             warps_in_buffer: &mut u64,
             buffer_start_warp: &mut u64,
             buffer_path: usize,
             seed: [u8; 32],
             next_warp_offset: u64,
             current_warps: u64,
             tx_per_path: &[Sender<WriterTask>]| {
                if let Some(buf) = write_buffer.take() {
                    tx_per_path[buffer_path]
                        .send(WriterTask::ProcessTask {
                            buffer: buf,
                            seed,
                            warp_offset: *buffer_start_warp,
                            warps_to_write: *warps_in_buffer,
                            number_of_warps: current_warps,
                        })
                        .expect("Failed to send to writer");
                    *warps_in_buffer = 0;
                    *buffer_start_warp = next_warp_offset;
                }
            };

        loop {
            // Check if all paths are complete
            if files_done
                .iter()
                .zip(task.number_of_plots.iter())
                .all(|(d, n)| d >= n)
            {
                break;
            }
            if is_stop_requested() {
                break;
            }

            // Hash COMPRESS_BATCH nonces into scatter buffer
            let start_nonce = global_nonces[path_pointer];
            hash_nonces_cpu(
                &mut scatter_buf,
                &task.address_payload,
                &seeds[path_pointer],
                start_nonce,
                COMPRESS_BATCH,
                &pool,
            );
            global_nonces[path_pointer] += COMPRESS_BATCH;

            // Helix compress scatter → write buffer
            // Acquire write buffer if needed
            if write_buffer.is_none() {
                write_buffer = match rx_empty_write_buffers.recv() {
                    Ok(buf) => Some(buf),
                    Err(_) => break,
                };
                buffer_start_warp = warp_offsets[path_pointer];
                buffer_path = path_pointer;
            }

            {
                let buf_ref = write_buffer.as_ref().unwrap();
                let mutex_buf = buf_ref.get_buffer();
                let mut buf = lock_mutex(&mutex_buf).expect("Write buffer mutex poisoned");

                if pass_in_warp == 0 {
                    helix_compress(&scatter_buf, &mut buf, warps_in_buffer, 1);
                } else {
                    helix_compress_xor(&scatter_buf, &mut buf, warps_in_buffer, 1);
                }
            }

            pass_in_warp += 1;

            if pass_in_warp == passes_per_warp {
                pass_in_warp = 0;
                warps_in_buffer += 1;
                warp_offsets[path_pointer] += 1;

                if let Some(pb) = &pb {
                    pb.inc(WARP_SIZE);
                }
                if task.line_progress {
                    println!("#HASH_DELTA:1");
                }
                if let Some(cb) = get_plotter_callback() {
                    cb.on_hashing_progress(1);
                }

                let current_warps = task.warps[path_pointer];
                let at_file_boundary = warp_offsets[path_pointer] == current_warps;

                if warps_in_buffer == escalate || at_file_boundary {
                    flush_buffer(
                        &mut write_buffer,
                        &mut warps_in_buffer,
                        &mut buffer_start_warp,
                        buffer_path,
                        seeds[path_pointer],
                        warp_offsets[path_pointer],
                        current_warps,
                        &tx_full_per_path,
                    );

                    if at_file_boundary {
                        files_done[path_pointer] += 1;
                        if files_done[path_pointer] < task.number_of_plots[path_pointer] {
                            rand::rng().fill(&mut seeds[path_pointer]);
                        }
                    }

                    // Round-robin: find next active path
                    let old_path = path_pointer;
                    if num_paths > 1 {
                        let mut found = false;
                        for i in 1..=num_paths {
                            let candidate = (old_path + i) % num_paths;
                            if files_done[candidate] < task.number_of_plots[candidate] {
                                path_pointer = candidate;
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            break;
                        }
                    }

                    // No ring discard needed for CPU mode — scatter is per-warp
                    if path_pointer != old_path || at_file_boundary {
                        if at_file_boundary {
                            warp_offsets[old_path] = 0;
                            global_nonces[old_path] = 0;
                        }
                        buffer_start_warp = warp_offsets[path_pointer];
                    }
                }
            }
        }

        // Flush any remaining warps
        if warps_in_buffer > 0 {
            let current_warps = task.warps[buffer_path];
            flush_buffer(
                &mut write_buffer,
                &mut warps_in_buffer,
                &mut buffer_start_warp,
                buffer_path,
                seeds[buffer_path],
                warp_offsets[buffer_path],
                current_warps,
                &tx_full_per_path,
            );
        }

        // Signal all writers to stop
        for tx in &tx_full_per_path {
            let _ = tx.send(WriterTask::EndTask);
        }

        if let Some(pb) = &pb {
            pb.finish_with_message("Hashing done.");
        }
    }
}
