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

use crossbeam_channel::{Receiver, Sender};
use rayon::prelude::*;
use std::slice::from_raw_parts_mut;
use std::sync::Arc;

use crate::error::lock_mutex;

use crate::buffer::PageAlignedByteBuffer;
use crate::disk_writer::WriterTask;
use crate::is_stop_requested;
use crate::plotter::{PlotterTask, DOUBLE_HASH_SIZE};

#[cfg(not(test))]
use crate::plotter::{DIM, WARP_SIZE};
#[cfg(test)]
pub const DIM: u64 = 8;
#[cfg(test)]
pub const WARP_SIZE: u64 = DIM * DIM * DOUBLE_HASH_SIZE;

#[derive(Clone, Copy)]
struct ThreadSafeMutDataPtr(*mut u8);
// SAFETY: ThreadSafeMutDataPtr is used to share raw pointers across threads in
// parallel processing. The safety is ensured by:
// 1. Each thread accesses non-overlapping memory regions (different y values in
//    par_iter)
// 2. The pointer lifetime is managed by the parent function ensuring it remains
//    valid
// 3. Memory access patterns are coordinated to prevent data races
unsafe impl Send for ThreadSafeMutDataPtr {}
unsafe impl Sync for ThreadSafeMutDataPtr {}

impl ThreadSafeMutDataPtr {
    fn new(ptr: *mut u8) -> Self {
        ThreadSafeMutDataPtr(ptr)
    }

    fn as_ptr(&self) -> *mut u8 {
        self.0
    }
}

pub struct CompressorTask {
    pub buffer: PageAlignedByteBuffer,
    pub seed: [u8; 32],
    pub warp_offset: u64,
    pub warps_to_compress: u64,
    pub number_of_warps: u64,
    pub path_pointer: usize,
}

pub fn create_chunk_compressor_thread(
    task: Arc<PlotterTask>,
    rx_full_plot_buffers: Receiver<CompressorTask>,
    tx_empty_plot_buffers: Sender<PageAlignedByteBuffer>,
    rx_empty_write_buffers: Receiver<PageAlignedByteBuffer>,
    tx_full_write_buffers: Vec<Sender<WriterTask>>,
    resume: u64,
) -> impl FnOnce() {
    move || {
        // progress tracker taking resume into account
        let mut compressor_progress = vec![0; task.output_paths.len()];
        let total_warps = task
            .warps
            .iter()
            .zip(task.number_of_plots.iter())
            .map(|(x, y)| x * y)
            .sum::<u64>()
            - resume;

        for read_buffer in rx_full_plot_buffers {
            let mutex_read_buffer = &(read_buffer.buffer).get_buffer();
            let mut mutex_read_buffer =
                lock_mutex(mutex_read_buffer).expect("Read buffer mutex poisoned");

             // get write buffer           
             let write_buffer = rx_empty_write_buffers
                .recv()
                .expect("Can't receive empty write buffer - channel closed");

            let mutex_write_buffer = write_buffer.get_buffer();
            let mut mutex_write_buffer =
                lock_mutex(&mutex_write_buffer).expect("Write buffer mutex poisoned");

            // compress into write buffer
            if task.compress == 1 {
                helix_compress(
                    &mutex_read_buffer,
                    &mut mutex_write_buffer,
                    0,
                    read_buffer.warps_to_compress,
                );
            } else {
                helix_compress_inline(
                    &mut mutex_read_buffer,
                    0,
                    u64::pow(2, (task.compress - 1) as u32) * read_buffer.warps_to_compress,
                );
                xor_compress(
                    &mutex_read_buffer,
                    &mut mutex_write_buffer,
                    0,
                    read_buffer.warps_to_compress,
                    (task.compress - 1) as u32,
                )
            }

            // send to writer
            tx_full_write_buffers[read_buffer.path_pointer]
                .send(WriterTask::ProcessTask {
                    buffer: write_buffer,
                    seed: read_buffer.seed,
                    number_of_warps: read_buffer.number_of_warps,
                    warps_to_write: read_buffer.warps_to_compress,
                    warp_offset: read_buffer.warp_offset,
                })
                .expect("Failed to send to writer");

            // update status
            compressor_progress[read_buffer.path_pointer] += read_buffer.warps_to_compress;

            // thread end
            if is_stop_requested() || total_warps == compressor_progress.iter().sum::<u64>() {
                // shutdown signals for all writers
                for writer in tx_full_write_buffers {
                    if writer.send(WriterTask::EndTask).is_err() {
                        // Writer thread has likely exited, continue with other writers
                        continue;
                    }
                }
                if tx_empty_plot_buffers.send(read_buffer.buffer).is_err() {
                    // Plot buffer channel closed, but we're shutting down
                    // anyway
                }
                break;
            }

            if tx_empty_plot_buffers.send(read_buffer.buffer).is_err() {
                // Plot buffer channel closed, exit compressor thread gracefully
                break;
            }
        }
    }
}

// multi-threaded xor compression of (2GiB * n) ^ iterations of nonce data into
// an optimized buffer
pub fn xor_compress(
    source_buffer: &[u8],
    target_buffer: &mut [u8],
    warp_offset: u64,
    output_len: u64,
    iterations: u32,
) {
    let target_buffer_len = target_buffer.len() as u64 / WARP_SIZE;
    let source_buffer_len = source_buffer.len() as u64 / WARP_SIZE;
    let ptr = ThreadSafeMutDataPtr::new(target_buffer.as_mut_ptr());
    let size = target_buffer.len();
    let src_len = u64::pow(2, iterations);
    (0..DIM).into_par_iter().for_each(|y| {
        for x in 0..DIM {
            for w in 0..output_len {
                // SAFETY: ptr contains a valid pointer to allocated memory and size
                // matches the actual buffer size. Each thread works on different y values
                // ensuring no memory overlap between threads.
                let target_buffer = unsafe { from_raw_parts_mut(ptr.as_ptr(), size) };
                let target_offset = y * target_buffer_len * DIM * DOUBLE_HASH_SIZE
                    + ((warp_offset + w) * DIM + x) * DOUBLE_HASH_SIZE;

                for z in 0..DOUBLE_HASH_SIZE {
                    let mut buffer = 0u8;
                    for i in 0..src_len {
                        let source_offset = y * source_buffer_len * DIM * DOUBLE_HASH_SIZE
                            + ((src_len * w + i) * DIM + x) * DOUBLE_HASH_SIZE;
                        let source_index = (source_offset + z) as usize;

                        // Security: Bounds check before array access
                        if source_index >= source_buffer.len() {
                            // This should never happen with correct parameters, but defend against
                            // it
                            continue;
                        }
                        buffer ^= source_buffer[source_index];
                    }

                    let target_index = (target_offset + z) as usize;
                    // Security: Bounds check before array access
                    if target_index < target_buffer.len() {
                        target_buffer[target_index] = buffer;
                    }
                }
            }
        }
    });
}

// multi-threaded compression of 2GiB x n of nonce data into an optimized buffer
pub fn helix_compress(
    source_buffer: &[u8],
    target_buffer: &mut [u8],
    warp_offset: u64,
    output_len: u64,
) {
    let target_buffer_len = target_buffer.len() as u64 / WARP_SIZE;
    let source_buffer_len = source_buffer.len() as u64 / WARP_SIZE;
    let ptr = ThreadSafeMutDataPtr::new(target_buffer.as_mut_ptr());
    let size = target_buffer.len();
    (0..DIM).into_par_iter().for_each(|y| {
        for x in 0..DIM {
            for w in 0..output_len {
                // SAFETY: ptr contains a valid pointer to allocated memory and size
                // matches the actual buffer size. Each thread works on different y values.
                let target_buffer = unsafe { from_raw_parts_mut(ptr.as_ptr(), size) };
                let offset = y * source_buffer_len * DIM * DOUBLE_HASH_SIZE
                    + (x + w * DIM * 2) * DOUBLE_HASH_SIZE;
                let mirror_offset = x * source_buffer_len * DIM * DOUBLE_HASH_SIZE
                    + (w * DIM * 2 + DIM + y) * DOUBLE_HASH_SIZE;
                let target_offset = y * target_buffer_len * DIM * DOUBLE_HASH_SIZE
                    + ((warp_offset + w) * DIM + x) * DOUBLE_HASH_SIZE;
                for z in 0..DOUBLE_HASH_SIZE {
                    let source_index = (offset + z) as usize;
                    let mirror_index = (mirror_offset + z) as usize;
                    let target_index = (target_offset + z) as usize;

                    // Security: Bounds check before array access
                    if source_index < source_buffer.len()
                        && mirror_index < source_buffer.len()
                        && target_index < target_buffer.len()
                    {
                        target_buffer[target_index] =
                            source_buffer[source_index] ^ source_buffer[mirror_index];
                    }
                }
            }
        }
    });
}

// multi-threaded compression of 2GiB x n of nonce data within an optimized
// buffer
pub fn helix_compress_inline(buffer: &mut [u8], warp_offset: u64, output_len: u64) {
    let buffer_len = buffer.len() as u64 / WARP_SIZE;
    let ptr = ThreadSafeMutDataPtr::new(buffer.as_mut_ptr());
    let size = buffer.len();
    for w in 0..output_len {
        (0..DIM).into_par_iter().for_each(|y| {
            for x in 0..DIM {
                // SAFETY: ptr contains a valid pointer to allocated memory and size
                // matches the actual buffer size. Parallel access is safe as each thread
                // processes different y values with no overlap.
                let target_buffer = unsafe { from_raw_parts_mut(ptr.as_ptr(), size) };
                let offset =
                    y * buffer_len * DIM * DOUBLE_HASH_SIZE + (x + w * DIM * 2) * DOUBLE_HASH_SIZE;
                let mirror_offset = x * buffer_len * DIM * DOUBLE_HASH_SIZE
                    + (w * DIM * 2 + DIM + y) * DOUBLE_HASH_SIZE;
                let target_offset = y * buffer_len * DIM * DOUBLE_HASH_SIZE
                    + ((warp_offset + w) * DIM + x) * DOUBLE_HASH_SIZE;
                for z in 0..DOUBLE_HASH_SIZE {
                    let source_index = (offset + z) as usize;
                    let mirror_index = (mirror_offset + z) as usize;
                    let target_index = (target_offset + z) as usize;

                    // Security: Bounds check before array access
                    if source_index < buffer.len()
                        && mirror_index < buffer.len()
                        && target_index < buffer.len()
                    {
                        target_buffer[target_index] = buffer[source_index] ^ buffer[mirror_index];
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod helix_tests {
    use super::{helix_compress, DIM, DOUBLE_HASH_SIZE};

    trait MemSetExt<T> {
        fn memset(&mut self, v: T);
    }

    impl MemSetExt<u8> for [u8] {
        fn memset(&mut self, v: u8) {
            for i in self {
                *i = v
            }
        }
    }

    #[test]
    fn helix_scatter_compression_test() {
        // check completeness (scatter case)
        let mut source_buffer = vec![1u8; (2 * DIM * DIM * DOUBLE_HASH_SIZE) as usize];
        for scoop in 0..DIM {
            let scoop_offset = scoop * 2 * DIM * DOUBLE_HASH_SIZE;
            source_buffer[scoop_offset as usize..(scoop_offset + DIM * DOUBLE_HASH_SIZE) as usize]
                .memset(0);
        }
        let mut target_buffer = vec![2u8; (4 * DIM * DIM * DOUBLE_HASH_SIZE) as usize];
        let result = vec![1u8; (4 * DIM * DIM * DOUBLE_HASH_SIZE) as usize];
        helix_compress(&source_buffer, &mut target_buffer, 0, 1);
        helix_compress(&source_buffer, &mut target_buffer, 1, 1);
        helix_compress(&source_buffer, &mut target_buffer, 2, 1);
        helix_compress(&source_buffer, &mut target_buffer, 3, 1);
        assert_eq!(target_buffer, result);
    }
}
