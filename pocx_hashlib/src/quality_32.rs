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

//! Scalar quality calculation implementation (no SIMD)

use crate::noncegen_common::SCOOP_SIZE;
use crate::shabal256::shabal256_lite;

/// Finds the best quality in a series of nonces using scalar computation
///
/// # Arguments
/// * `data` - Scoop data (multiple scoops concatenated)
/// * `number_of_nonces` - Number of nonces (scoops) in data
/// * `generation_signature_bytes` - Generation signature (32 bytes)
///
/// # Returns
/// Tuple of (best_quality, best_offset)
pub fn find_best_quality_32(
    data: &[u8],
    number_of_nonces: u64,
    generation_signature_bytes: &[u8; 32],
) -> (u64, u64) {
    let mut best_quality = u64::MAX;
    let mut best_offset = 0;

    for i in 0..number_of_nonces as usize {
        let start_idx = i * SCOOP_SIZE;
        let end_idx = start_idx + SCOOP_SIZE;

        if end_idx <= data.len() {
            let scoop_data = &data[start_idx..end_idx];
            let quality = shabal256_lite(scoop_data, generation_signature_bytes);

            if quality < best_quality {
                best_quality = quality;
                best_offset = i as u64;
            }
        }
    }

    (best_quality, best_offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_quality_hashing() {
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
            let (quality, _offset) = find_best_quality_32(&data, (i + 1) as u64, &gensig_array);
            assert_eq!(
                3084580316385335914u64, quality,
                "Scalar failed at iteration {}",
                i
            );
            data[i * 64..i * 64 + 64].clone_from_slice(&loser);
        }
    }
}
