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

use pocx_plotfile::{NUM_SCOOPS, SCOOP_SIZE};

#[derive(Debug, Clone)]
pub enum CompressionAction {
    Skip(&'static str),
    MineNormal,
    CompressOnFly { steps: u32 },
}

pub fn determine_compression_action(
    plot_compression: u8,
    min_required: u32,
    target_level: u32,
    max_steps_possible: u32,
) -> CompressionAction {
    let plot_compression = plot_compression as u32;
    if plot_compression > target_level {
        return CompressionAction::Skip("compression higher than chain target");
    }

    if plot_compression >= min_required {
        return CompressionAction::MineNormal;
    }

    // Need to compress
    let steps_needed = min_required - plot_compression;

    if steps_needed > max_steps_possible {
        return CompressionAction::Skip("insufficient buffer size for required compression");
    }

    CompressionAction::CompressOnFly {
        steps: steps_needed,
    }
}

pub fn compress_warps_inline(buffer: &mut [u8], warp_count: u64, compression_steps: u32) -> u64 {
    let mut current_warps = warp_count;
    let warp_size_bytes = (NUM_SCOOPS * SCOOP_SIZE) as usize;

    for _step in 0..compression_steps {
        let pairs_to_process = current_warps / 2;

        // Use highest available SIMD for XOR operations
        #[cfg(all(target_arch = "x86_64", feature = "simd"))]
        if is_x86_feature_detected!("avx512f") {
            unsafe {
                compress_pairs_avx512f(buffer, pairs_to_process, warp_size_bytes);
            }
        } else if is_x86_feature_detected!("avx2") {
            unsafe {
                compress_pairs_avx2(buffer, pairs_to_process, warp_size_bytes);
            }
        } else if is_x86_feature_detected!("avx") {
            unsafe {
                compress_pairs_avx(buffer, pairs_to_process, warp_size_bytes);
            }
        } else if is_x86_feature_detected!("sse2") {
            unsafe {
                compress_pairs_sse2(buffer, pairs_to_process, warp_size_bytes);
            }
        } else {
            compress_pairs_fallback(buffer, pairs_to_process, warp_size_bytes);
        }

        #[cfg(not(all(target_arch = "x86_64", feature = "simd")))]
        compress_pairs_fallback(buffer, pairs_to_process, warp_size_bytes);

        current_warps = pairs_to_process;
    }

    current_warps
}

// AVX512F: Process 64 bytes per instruction (perfect for SCOOP_SIZE=64)
#[cfg(all(target_arch = "x86_64", feature = "simd"))]
unsafe fn compress_pairs_avx512f(buffer: &mut [u8], pairs: u64, warp_size: usize) {
    use std::arch::x86_64::*;

    for pair in 0..pairs {
        let warp_a_start = (pair * 2) as usize * warp_size;
        let warp_b_start = (pair * 2 + 1) as usize * warp_size;
        let dest_start = pair as usize * warp_size; // Compact destination

        // Process warp in 64-byte chunks (aligned access trusted)
        for chunk_offset in (0..warp_size).step_by(64) {
            let a_ptr = buffer.as_ptr().add(warp_a_start + chunk_offset) as *const __m512i;
            let b_ptr = buffer.as_ptr().add(warp_b_start + chunk_offset) as *const __m512i;

            let a = _mm512_load_si512(a_ptr);
            let b = _mm512_load_si512(b_ptr);
            let result = _mm512_xor_si512(a, b);

            // Store at compacted position
            let dest_ptr = buffer.as_mut_ptr().add(dest_start + chunk_offset) as *mut __m512i;
            _mm512_store_si512(dest_ptr, result);
        }
    }
}

// AVX2: Process 32 bytes per instruction
#[cfg(all(target_arch = "x86_64", feature = "simd"))]
unsafe fn compress_pairs_avx2(buffer: &mut [u8], pairs: u64, warp_size: usize) {
    use std::arch::x86_64::*;

    for pair in 0..pairs {
        let warp_a_start = (pair * 2) as usize * warp_size;
        let warp_b_start = (pair * 2 + 1) as usize * warp_size;
        let dest_start = pair as usize * warp_size; // Compact destination

        for chunk_offset in (0..warp_size).step_by(32) {
            let a_ptr = buffer.as_ptr().add(warp_a_start + chunk_offset) as *const __m256i;
            let b_ptr = buffer.as_ptr().add(warp_b_start + chunk_offset) as *const __m256i;

            let a = _mm256_load_si256(a_ptr);
            let b = _mm256_load_si256(b_ptr);
            let result = _mm256_xor_si256(a, b);

            // Store at compacted position
            let dest_ptr = buffer.as_mut_ptr().add(dest_start + chunk_offset) as *mut __m256i;
            _mm256_store_si256(dest_ptr, result);
        }
    }
}

// AVX: Process 32 bytes per instruction (same as AVX2 for XOR)
#[cfg(all(target_arch = "x86_64", feature = "simd"))]
unsafe fn compress_pairs_avx(buffer: &mut [u8], pairs: u64, warp_size: usize) {
    // Same implementation as AVX2 for XOR operations
    compress_pairs_avx2(buffer, pairs, warp_size);
}

// SSE2: Process 16 bytes per instruction
#[cfg(all(target_arch = "x86_64", feature = "simd"))]
unsafe fn compress_pairs_sse2(buffer: &mut [u8], pairs: u64, warp_size: usize) {
    use std::arch::x86_64::*;

    for pair in 0..pairs {
        let warp_a_start = (pair * 2) as usize * warp_size;
        let warp_b_start = (pair * 2 + 1) as usize * warp_size;
        let dest_start = pair as usize * warp_size; // Compact destination

        for chunk_offset in (0..warp_size).step_by(16) {
            let a_ptr = buffer.as_ptr().add(warp_a_start + chunk_offset) as *const __m128i;
            let b_ptr = buffer.as_ptr().add(warp_b_start + chunk_offset) as *const __m128i;

            let a = _mm_load_si128(a_ptr);
            let b = _mm_load_si128(b_ptr);
            let result = _mm_xor_si128(a, b);

            // Store at compacted position
            let dest_ptr = buffer.as_mut_ptr().add(dest_start + chunk_offset) as *mut __m128i;
            _mm_store_si128(dest_ptr, result);
        }
    }
}

// Fallback for systems without SIMD
fn compress_pairs_fallback(buffer: &mut [u8], pairs: u64, warp_size: usize) {
    for pair in 0..pairs {
        let warp_a_start = (pair * 2) as usize * warp_size;
        let warp_b_start = (pair * 2 + 1) as usize * warp_size;
        let dest_start = pair as usize * warp_size; // Compact destination

        // XOR and compact in one pass
        for i in 0..warp_size {
            buffer[dest_start + i] = buffer[warp_a_start + i] ^ buffer[warp_b_start + i];
        }
    }
}
