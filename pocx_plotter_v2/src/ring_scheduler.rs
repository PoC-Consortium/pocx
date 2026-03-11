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

//! Ring buffer GPU scheduler.
//!
//! Drives the hash → compress → transfer pipeline using a ring buffer on GPU.
//! The ring holds R = W + C - gcd(W, C) nonces. Each iteration:
//!   1. Hash W nonces into ring at current write_head
//!   2. When ≥ 8192 (C) nonces are available, run fused compress
//!   3. Transfer 1 GiB compressed result to host write buffer
//!   4. Send write buffer to disk writer
//!
//! Supports multiple output paths (round-robin) and escalated write buffers.

use crate::buffer::PageAlignedByteBuffer;
use crate::disk_writer::WriterTask;
use crate::error::lock_mutex;
use crate::get_plotter_callback;
use crate::is_stop_requested;
use crate::ocl::{
    gpu_ring_compress, gpu_ring_hash, gpu_ring_transfer, gpu_upload_base58, gpu_upload_seed,
    GpuRingContext,
};
use crate::plotter::{PlotterTask, WARP_SIZE};
use crossbeam_channel::{Receiver, Sender};
use rand::Rng;
use std::sync::Arc;

const COMPRESS_BATCH: u64 = 8192; // DIM * 2 nonces per helix compress cycle

pub fn create_ring_scheduler_thread(
    task: Arc<PlotterTask>,
    mut gpu_ctx: GpuRingContext,
    pb: Option<indicatif::ProgressBar>,
    rx_empty_write_buffers: Receiver<PageAlignedByteBuffer>,
    tx_full_per_path: Vec<Sender<WriterTask>>,
    resumes: Vec<u64>,
) -> impl FnOnce() {
    move || {
        let worksize = gpu_ctx.worksize;
        let ring_size = gpu_ctx.ring_size;
        let escalate = task.escalate;
        let num_paths = task.output_paths.len();

        // Per-path state
        let mut seeds: Vec<[u8; 32]> = Vec::with_capacity(num_paths);
        let mut warp_offsets: Vec<u64> = vec![0; num_paths];
        let mut files_done: Vec<u64> = vec![0; num_paths];

        // Per-path seed and resume init
        for i in 0..num_paths {
            if let Some(s) = task.seeds.get(i).and_then(|s| *s) {
                seeds.push(s);
                warp_offsets[i] = resumes[i];
            } else {
                let mut s = [0u8; 32];
                rand::rng().fill(&mut s);
                seeds.push(s);
            }
        }

        // Upload constants (start with first path's seed)
        gpu_upload_base58(&mut gpu_ctx, &task.address_payload);
        gpu_upload_seed(&mut gpu_ctx, &seeds[0]);

        // Xn compression: 2^(x-1) helix passes per warp, each consuming 8192 nonces
        let passes_per_warp = 1u64 << (task.compress - 1);

        let mut global_nonces: Vec<u64> = vec![0; num_paths];
        let mut ring_head: u64 = 0;
        let mut ring_available: u64 = 0;
        let mut pass_in_warp: u64 = 0;
        let mut path_pointer: usize = 0;

        // Init nonce counters for resumed paths
        for i in 0..num_paths {
            if resumes[i] > 0 {
                global_nonces[i] = resumes[i] * passes_per_warp * COMPRESS_BATCH;
            }
        }

        // Escalation: accumulate multiple warps into one write buffer
        let mut write_buffer: Option<PageAlignedByteBuffer> = None;
        let mut warps_in_buffer: u64 = 0;
        let mut buffer_start_warp: u64 = warp_offsets[path_pointer];
        let mut buffer_path: usize = path_pointer;

        // Helper: flush current write buffer to the correct writer
        let flush_buffer = |write_buffer: &mut Option<PageAlignedByteBuffer>,
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

            let nonces_for_file = task.warps[path_pointer] * passes_per_warp * COMPRESS_BATCH;

            // Phase 1: Fill ring with hash dispatches
            while ring_available + worksize <= ring_size
                && global_nonces[path_pointer] < nonces_for_file
            {
                if is_stop_requested() {
                    break;
                }

                let nonces_this_batch =
                    std::cmp::min(worksize, nonces_for_file - global_nonces[path_pointer]);

                gpu_ring_hash(
                    &gpu_ctx,
                    global_nonces[path_pointer],
                    nonces_this_batch,
                    ring_head,
                );

                ring_head = (ring_head + worksize) % ring_size;
                ring_available += worksize;
                global_nonces[path_pointer] += nonces_this_batch;
            }

            // Phase 2: Compress available batches (XOR-accumulate into compressed buffer)
            while ring_available >= COMPRESS_BATCH {
                if is_stop_requested() {
                    break;
                }

                let compress_start = (ring_head + ring_size - ring_available) % ring_size;

                gpu_ring_compress(&gpu_ctx, compress_start, pass_in_warp > 0);
                ring_available -= COMPRESS_BATCH;
                pass_in_warp += 1;

                // All passes for this warp done — transfer into write buffer
                if pass_in_warp == passes_per_warp {
                    pass_in_warp = 0;

                    // Acquire a write buffer if we don't have one
                    if write_buffer.is_none() {
                        write_buffer = match rx_empty_write_buffers.recv() {
                            Ok(buf) => Some(buf),
                            Err(_) => break,
                        };
                        buffer_start_warp = warp_offsets[path_pointer];
                        buffer_path = path_pointer;
                    }

                    // Transfer this warp into the interleaved buffer position
                    {
                        let buf_ref = write_buffer.as_ref().unwrap();
                        let mutex_buf = buf_ref.get_buffer();
                        let mut buf = lock_mutex(&mutex_buf).expect("Write buffer mutex poisoned");
                        gpu_ring_transfer(&gpu_ctx, &mut buf, warps_in_buffer, escalate, true);
                    }

                    warps_in_buffer += 1;
                    warp_offsets[path_pointer] += 1;

                    if let Some(pb) = &pb {
                        pb.inc(WARP_SIZE);
                    }
                    if let Some(cb) = get_plotter_callback() {
                        cb.on_hashing_progress(1);
                    }

                    let current_warps = task.warps[path_pointer];
                    let at_file_boundary = warp_offsets[path_pointer] == current_warps;

                    // Flush buffer when full or at file boundary
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

                        // Handle file completion
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
                                break; // All paths complete
                            }
                        }

                        let path_changed = path_pointer != old_path;

                        // Discard ring when seed changes (path switch or new file)
                        if path_changed || at_file_boundary {
                            // Undo nonce counter for uncompressed ring leftovers
                            if !at_file_boundary {
                                global_nonces[old_path] -= ring_available;
                            }
                            ring_available = 0;
                            ring_head = 0;

                            if at_file_boundary {
                                warp_offsets[old_path] = 0;
                                global_nonces[old_path] = 0;
                            }

                            gpu_upload_seed(&mut gpu_ctx, &seeds[path_pointer]);
                            buffer_start_warp = warp_offsets[path_pointer];
                            break; // Exit Phase 2, refill ring for new seed
                        }
                    }
                }
            }
        }

        // Flush any remaining warps in the buffer
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
