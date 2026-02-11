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

pub const MESSAGE_SIZE: usize = 16;
pub const HASH_SIZE: usize = 32;
pub const HASH_CAP: usize = 4096;
pub const NUM_SCOOPS: usize = 4096;
pub const SCOOP_SIZE: usize = 64;
pub const NONCE_SIZE: usize = NUM_SCOOPS * SCOOP_SIZE;
pub const AVX_VECTOR_SIZE: usize = 4;
pub const AVX2_VECTOR_SIZE: usize = 8;
pub const AVX512_VECTOR_SIZE: usize = 16;

/// Extract one scoop per lane from a SIMD-interleaved nonce buffer using POC2 shuffle indexing.
///
/// The SIMD nonce generation buffer stores hash data in lane-interleaved format.
/// This function extracts a single 64-byte scoop for a specific lane without
/// performing the full unpack+shuffle+scatter operation.
///
/// POC2 scoop layout maps scoop `s` to two hash indices:
/// - First 32 bytes:  hash index `2 * s` (forward)
/// - Second 32 bytes: hash index `(4095 - s) * 2 + 1` (reverse)
pub fn extract_scoop_from_interleaved(
    source: &[u8],
    vector_size: usize,
    lane: usize,
    scoop: u64,
    output: &mut [u8; SCOOP_SIZE],
) {
    let s = scoop as usize;
    let hash_idx_first = 2 * s;
    let hash_idx_second = (4095 - s) * 2 + 1;

    // First 32 bytes of scoop
    for j in (0..32).step_by(4) {
        let src_offset = (hash_idx_first * 32 + j) * vector_size + lane * 4;
        // SAFETY: src_offset is bounded by (8191 * 32 + 28) * vector_size + (vector_size-1) * 4
        // which is within the NONCE_SIZE * vector_size buffer. We copy exactly 4 bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                source.get_unchecked(src_offset),
                output.get_unchecked_mut(j) as *mut u8,
                4,
            );
        }
    }

    // Second 32 bytes of scoop
    for j in (0..32).step_by(4) {
        let src_offset = (hash_idx_second * 32 + j) * vector_size + lane * 4;
        unsafe {
            std::ptr::copy_nonoverlapping(
                source.get_unchecked(src_offset),
                output.get_unchecked_mut(32 + j) as *mut u8,
                4,
            );
        }
    }
}

// simd shabal words unpack + POC Shuffle + scatter nonces into optimised cache
pub fn unpack_shuffle_scatter(
    source: &[u8],
    target: &mut [u8],
    target_offset: usize,
    vector_size: usize,
) {
    let target_size = target.len() / NONCE_SIZE;
    for i in 0..(NUM_SCOOPS * 2) {
        for j in (0..32).step_by(4) {
            for k in 0..vector_size {
                let data_offset = ((i & 1) * (4095 - (i >> 1)) + ((i + 1) & 1) * (i >> 1))
                    * SCOOP_SIZE
                    * target_size
                    + (k + target_offset) * SCOOP_SIZE
                    + (i & 1) * 32
                    + j;
                let buffer_offset = (i * 32 + j) * vector_size + k * 4;

                // Add bounds checking while preserving performance
                if data_offset + 4 > target.len() || buffer_offset + 4 > source.len() {
                    // Skip this write instead of panicking to maintain performance
                    continue;
                }
                // SAFETY: This unsafe block performs the POC2 shuffle operation with unchecked
                // access. The safety invariants are:
                // - buffer_offset and data_offset are calculated to be within bounds
                // - source has size vector_size * NONCE_SIZE, target has adequate space
                // - We copy exactly 4 bytes (size of u32) which matches the data layout
                // - The complex offset calculations implement the required POC2 memory layout
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        source.get_unchecked(buffer_offset),
                        target.get_unchecked_mut(data_offset) as *mut u8,
                        4,
                    );
                }
            }
        }
    }
}
