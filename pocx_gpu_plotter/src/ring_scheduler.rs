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

use crate::buffer::PageAlignedByteBuffer;
use crate::disk_writer::WriterTask;
use crate::error::lock_mutex;
use crate::get_plotter_callback;
use crate::is_stop_requested;
use crate::ocl::{
    gpu_ring_compress, gpu_ring_hash, gpu_ring_transfer, gpu_upload_base58, gpu_upload_seed,
    gpu_zero_compressed_buffer, GpuRingContext,
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
    tx_full_write_buffers: Sender<WriterTask>,
    resume: u64,
) -> impl FnOnce() {
    move || {
        let worksize = gpu_ctx.worksize;
        let ring_size = gpu_ctx.ring_size;

        // Generate seed
        let seed = if let Some(s) = task.seed {
            s
        } else {
            let mut s = [0u8; 32];
            rand::rng().fill(&mut s);
            s
        };

        // Upload constants
        gpu_upload_base58(&mut gpu_ctx, &task.address_payload);
        gpu_upload_seed(&mut gpu_ctx, &seed);

        let total_warps = task.warps[0] * task.number_of_plots[0];
        let warps_to_plot = total_warps - resume;

        // Xn compression: 2^(x-1) helix passes per warp, each consuming 8192 nonces
        let passes_per_warp = 1u64 << (task.compress - 1);
        let total_raw_nonces = warps_to_plot * passes_per_warp * COMPRESS_BATCH;

        let mut global_nonce = resume * passes_per_warp * COMPRESS_BATCH;
        let mut ring_head: u64 = 0;
        let mut ring_available: u64 = 0;
        let mut nonces_hashed: u64 = 0;
        let mut warp_offset = resume;
        let mut files_done: u64 = 0;
        let mut pass_in_warp: u64 = 0;

        while nonces_hashed < total_raw_nonces {
            if is_stop_requested() {
                break;
            }

            // Zero compressed buffer before first pass of each warp
            if pass_in_warp == 0 {
                gpu_zero_compressed_buffer(&gpu_ctx);
            }

            // Phase 1: Fill ring with hash dispatches
            while ring_available + worksize <= ring_size
                && nonces_hashed < total_raw_nonces
            {
                if is_stop_requested() {
                    break;
                }

                let nonces_this_batch =
                    std::cmp::min(worksize, total_raw_nonces - nonces_hashed);

                gpu_ring_hash(
                    &gpu_ctx,
                    global_nonce,
                    nonces_this_batch,
                    ring_head,
                );

                ring_head = (ring_head + worksize) % ring_size;
                ring_available += worksize;
                nonces_hashed += nonces_this_batch;
                global_nonce += nonces_this_batch;
            }

            // Phase 2: Compress available batches (XOR-accumulate into compressed buffer)
            while ring_available >= COMPRESS_BATCH {
                if is_stop_requested() {
                    break;
                }

                let compress_start =
                    (ring_head + ring_size - ring_available) % ring_size;

                gpu_ring_compress(&gpu_ctx, compress_start);
                ring_available -= COMPRESS_BATCH;
                pass_in_warp += 1;

                // All passes for this warp done — transfer and send to writer
                if pass_in_warp == passes_per_warp {
                    pass_in_warp = 0;

                    let write_buffer = match rx_empty_write_buffers.recv() {
                        Ok(buf) => buf,
                        Err(_) => break,
                    };

                    {
                        let mutex_buf = write_buffer.get_buffer();
                        let mut buf =
                            lock_mutex(&mutex_buf).expect("Write buffer mutex poisoned");
                        gpu_ring_transfer(&gpu_ctx, &mut buf, true);
                    }

                    let current_warps = task.warps[0];
                    tx_full_write_buffers
                        .send(WriterTask::ProcessTask {
                            buffer: write_buffer,
                            seed,
                            warp_offset,
                            warps_to_write: 1,
                            number_of_warps: current_warps,
                        })
                        .expect("Failed to send to writer");

                    warp_offset += 1;

                    if let Some(pb) = &pb {
                        pb.inc(WARP_SIZE);
                    }
                    if task.line_progress {
                        println!("#HASH_DELTA:1");
                    }
                    if let Some(cb) = get_plotter_callback() {
                        cb.on_hashing_progress(1);
                    }

                    // Check if current file is complete
                    if warp_offset == current_warps {
                        files_done += 1;
                        warp_offset = 0;

                        if files_done < task.number_of_plots[0] {
                            let mut new_seed = [0u8; 32];
                            rand::rng().fill(&mut new_seed);
                            gpu_upload_seed(&mut gpu_ctx, &new_seed);
                        }
                    }
                }
            }
        }

        // Signal writer to stop
        let _ = tx_full_write_buffers.send(WriterTask::EndTask);

        if let Some(pb) = &pb {
            pb.finish_with_message("Hashing done.");
        }
    }
}
