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

//! SIMD quality calculation using AVX512 (16 scoops in parallel)

use crate::noncegen_common::SCOOP_SIZE;

const SIMD_BATCH_SIZE: usize = 16;

/// Finds the best quality using AVX512 SIMD (16 scoops in parallel)
///
/// # Arguments
/// * `data` - Scoop data (multiple scoops concatenated)
/// * `number_of_nonces` - Number of nonces (scoops) in data
/// * `generation_signature_bytes` - Generation signature (32 bytes)
///
/// # Returns
/// Tuple of (best_quality, best_offset)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn find_best_quality_512(
    data: &[u8],
    number_of_nonces: u64,
    generation_signature_bytes: &[u8; 32],
) -> (u64, u64) {
    let mut best_quality = u64::MAX;
    let mut best_offset = 0u64;

    let nonces = number_of_nonces as usize;
    let simd_batches = nonces / SIMD_BATCH_SIZE;
    let remainder = nonces % SIMD_BATCH_SIZE;

    // Process in SIMD batches of 16
    for batch in 0..simd_batches {
        let start_offset = batch * SIMD_BATCH_SIZE;
        let start_idx = start_offset * SCOOP_SIZE;
        let batch_size = SIMD_BATCH_SIZE * SCOOP_SIZE;

        if start_idx + batch_size <= data.len() {
            let batch_data = &data[start_idx..start_idx + batch_size];

            let qualities = unsafe {
                crate::shabal256_lite_avx512::shabal256_lite_512(
                    batch_data,
                    generation_signature_bytes,
                )
            };

            // Find best in this batch
            for (i, &quality) in qualities.iter().enumerate() {
                if quality < best_quality {
                    best_quality = quality;
                    best_offset = (start_offset + i) as u64;
                }
            }
        }
    }

    // Process remaining scoops that don't fit in a full SIMD batch
    if remainder > 0 {
        let remaining_start = simd_batches * SIMD_BATCH_SIZE;
        for i in 0..remainder {
            let scoop_idx = remaining_start + i;
            let start_idx = scoop_idx * SCOOP_SIZE;
            let end_idx = start_idx + SCOOP_SIZE;

            if end_idx <= data.len() {
                let scoop_data = &data[start_idx..end_idx];
                let quality =
                    crate::shabal256::shabal256_lite(scoop_data, generation_signature_bytes);

                if quality < best_quality {
                    best_quality = quality;
                    best_offset = scoop_idx as u64;
                }
            }
        }
    }

    (best_quality, best_offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_512_quality_hashing() {
        // Skip test if AVX512 is not supported
        if !is_x86_feature_detected!("avx512f") {
            return;
        }

        let gensig =
            hex::decode("4a6f686e6e7946464d206861742064656e206772f6df74656e2050656e697321")
                .unwrap();
        let mut gensig_array = [0u8; 32];
        gensig_array.copy_from_slice(&gensig[..]);

        let winner: [u8; 64] = [0; 64];
        let loser: [u8; 64] = [5; 64];
        let mut data: [u8; 64 * 32] = [5; 64 * 32];

        for i in 0..32 {
            data[i * 64..i * 64 + 64].clone_from_slice(&winner);
            let (quality, _offset) = find_best_quality_512(&data, (i + 1) as u64, &gensig_array);
            assert_eq!(
                3084580316385335914u64, quality,
                "512-bit SIMD failed at iteration {}",
                i
            );
            data[i * 64..i * 64 + 64].clone_from_slice(&loser);
        }
    }
}
