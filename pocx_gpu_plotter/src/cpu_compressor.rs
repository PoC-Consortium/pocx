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

//! Helix compression for CPU mode.
//!
//! Mirrors the GPU ring compress operation: XOR mirror nonce pairs from a
//! 2 GiB scatter buffer into a write buffer warp slot. Two variants:
//! - `helix_compress`: write mode (first pass)
//! - `helix_compress_xor`: XOR-accumulate mode (subsequent passes for X2+)

use crate::plotter::{DIM, DOUBLE_HASH_SIZE, WARP_SIZE};
use rayon::prelude::*;
use std::slice::{from_raw_parts, from_raw_parts_mut};

/// Helix compress: XOR mirror nonce pairs from source into target (write mode).
///
/// Source holds COMPRESS_BATCH (8192 = 2*DIM) nonces in scoop-major layout.
/// Output is DIM nonces per warp in the target buffer at `warp_offset`.
pub fn helix_compress(
    source_buffer: &[u8],
    target_buffer: &mut [u8],
    warp_offset: u64,
    output_len: u64,
) {
    let target_buffer_len = target_buffer.len() as u64 / WARP_SIZE;
    let source_buffer_len = source_buffer.len() as u64 / WARP_SIZE;
    let src_addr = source_buffer.as_ptr() as usize;
    let src_len = source_buffer.len();
    let dst_addr = target_buffer.as_mut_ptr() as usize;
    let dst_len = target_buffer.len();
    (0..DIM).into_par_iter().for_each(move |y| {
        // SAFETY: Each thread processes a unique y value (scoop index),
        // writing to non-overlapping target memory regions. Source is read-only.
        let source = unsafe { from_raw_parts(src_addr as *const u8, src_len) };
        let target = unsafe { from_raw_parts_mut(dst_addr as *mut u8, dst_len) };
        for x in 0..DIM {
            for w in 0..output_len {
                let offset = y * source_buffer_len * DIM * DOUBLE_HASH_SIZE
                    + (x + w * DIM * 2) * DOUBLE_HASH_SIZE;
                let mirror_offset = x * source_buffer_len * DIM * DOUBLE_HASH_SIZE
                    + (w * DIM * 2 + DIM + y) * DOUBLE_HASH_SIZE;
                let target_offset = y * target_buffer_len * DIM * DOUBLE_HASH_SIZE
                    + ((warp_offset + w) * DIM + x) * DOUBLE_HASH_SIZE;
                for z in 0..DOUBLE_HASH_SIZE {
                    let si = (offset + z) as usize;
                    let mi = (mirror_offset + z) as usize;
                    let ti = (target_offset + z) as usize;
                    if si < src_len && mi < src_len && ti < dst_len {
                        target[ti] = source[si] ^ source[mi];
                    }
                }
            }
        }
    });
}

/// Helix compress with XOR-accumulate: same as `helix_compress` but XORs into
/// the target instead of overwriting. Used for passes > 0 in X2+ compression.
pub fn helix_compress_xor(
    source_buffer: &[u8],
    target_buffer: &mut [u8],
    warp_offset: u64,
    output_len: u64,
) {
    let target_buffer_len = target_buffer.len() as u64 / WARP_SIZE;
    let source_buffer_len = source_buffer.len() as u64 / WARP_SIZE;
    let src_addr = source_buffer.as_ptr() as usize;
    let src_len = source_buffer.len();
    let dst_addr = target_buffer.as_mut_ptr() as usize;
    let dst_len = target_buffer.len();
    (0..DIM).into_par_iter().for_each(move |y| {
        // SAFETY: Each thread processes a unique y value (scoop index),
        // writing to non-overlapping target memory regions. Source is read-only.
        let source = unsafe { from_raw_parts(src_addr as *const u8, src_len) };
        let target = unsafe { from_raw_parts_mut(dst_addr as *mut u8, dst_len) };
        for x in 0..DIM {
            for w in 0..output_len {
                let offset = y * source_buffer_len * DIM * DOUBLE_HASH_SIZE
                    + (x + w * DIM * 2) * DOUBLE_HASH_SIZE;
                let mirror_offset = x * source_buffer_len * DIM * DOUBLE_HASH_SIZE
                    + (w * DIM * 2 + DIM + y) * DOUBLE_HASH_SIZE;
                let target_offset = y * target_buffer_len * DIM * DOUBLE_HASH_SIZE
                    + ((warp_offset + w) * DIM + x) * DOUBLE_HASH_SIZE;
                for z in 0..DOUBLE_HASH_SIZE {
                    let si = (offset + z) as usize;
                    let mi = (mirror_offset + z) as usize;
                    let ti = (target_offset + z) as usize;
                    if si < src_len && mi < src_len && ti < dst_len {
                        target[ti] ^= source[si] ^ source[mi];
                    }
                }
            }
        }
    });
}
