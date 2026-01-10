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

use crate::buffer::PageAlignedByteBuffer;
use crate::com::api::NonceSubmission;
use crate::com::api::SubmissionParameters;
use crossbeam_channel::Sender;
use futures::channel::mpsc;
use mpsc::UnboundedSender;
use pocx_hashlib::find_best_quality;
use pocx_plotfile::NUM_SCOOPS;

pub struct HashingTask {
    pub buffer: PageAlignedByteBuffer,
    pub chain_id: usize,
    pub chain_name: String,
    pub block_count: u64,
    pub generation_signature_bytes: [u8; 32],
    pub account_id: String,
    pub seed: String,
    pub block_height: u64,
    pub base_target: u64,
    pub start_warp: u64,
    pub number_of_warps: u64,
    pub compression_level: u8,
    pub tx_buffer: Sender<PageAlignedByteBuffer>,
    pub tx_nonce_data: UnboundedSender<(usize, SubmissionParameters)>,
}

pub fn calc_qualities(task: HashingTask) -> impl FnOnce() {
    move || {
        let buffer = task.buffer.get_buffer_ref();

        let result = find_best_quality(
            buffer,
            task.number_of_warps * NUM_SCOOPS,
            &task.generation_signature_bytes,
        );
        let quality = result.0;
        let offset = result.1;

        // Try to send nonce data - channel may be closed during shutdown
        if let Err(_) = task.tx_nonce_data.clone().unbounded_send((
            task.chain_id,
            SubmissionParameters {
                chain: task.chain_name,
                quality_raw: quality, // raw_quality (Shabal-256 hash result)
                block_count: task.block_count,
                nonce_submission: NonceSubmission {
                    account_id: task.account_id,
                    seed: task.seed,
                    nonce: task.start_warp * NUM_SCOOPS + offset,
                    block_height: task.block_height,
                    generation_signature: hex::encode(task.generation_signature_bytes),
                    quality: quality / task.base_target, /* raw_quality -> quality_adjusted
                                                          * (dimensionless quality score) */
                    compression: task.compression_level,
                },
            },
        )) {
            // Channel disconnected - miner is shutting down, this is expected
            log::debug!("Hasher: nonce channel closed (shutdown in progress)");
        }

        // Try to return buffer - channel may be closed during shutdown
        if let Err(_) = task.tx_buffer.clone().send(task.buffer) {
            // Channel disconnected - miner is shutting down
            // Buffer will be dropped, which is fine during shutdown
            log::debug!("Hasher: buffer channel closed (shutdown in progress)");
        }
    }
}

#[cfg(test)]
mod tests {
    use pocx_hashlib::find_best_quality;

    #[test]
    fn test_quality_hashing() {
        let mut quality: u64;
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

            let result = find_best_quality(&data, (i + 1) as u64, &gensig_array);
            quality = result.0;

            assert_eq!(3084580316385335914u64, quality);
            data[i * 64..i * 64 + 64].clone_from_slice(&loser);
        }
    }

    #[test]
    fn test_simd_quality_hashing() {
        let gensig =
            hex::decode("4a6f686e6e7946464d206861742064656e206772f6df74656e2050656e697321")
                .unwrap();
        let winner: [u8; 64] = [0; 64];
        let loser: [u8; 64] = [5; 64];
        let mut data: [u8; 64 * 32] = [5; 64 * 32];
        let mut gensig_array = [0; 32];
        gensig_array.copy_from_slice(&gensig[..gensig.len()]);

        for i in 0..32 {
            data[i * 64..i * 64 + 64].clone_from_slice(&winner);
            let result = find_best_quality(&data, (i + 1) as u64, &gensig_array);
            let quality = result.0;
            assert_eq!(3084580316385335914u64, quality);
            data[i * 64..i * 64 + 64].clone_from_slice(&loser);
        }
    }
    #[test]
    fn test_neon_quality_hashing() {
        let gensig =
            hex::decode("4a6f686e6e7946464d206861742064656e206772f6df74656e2050656e697321")
                .unwrap();
        let winner: [u8; 64] = [0; 64];
        let loser: [u8; 64] = [5; 64];
        let mut data: [u8; 64 * 32] = [5; 64 * 32];
        let mut gensig_array = [0; 32];
        gensig_array.copy_from_slice(&gensig[..gensig.len()]);

        for i in 0..32 {
            data[i * 64..i * 64 + 64].clone_from_slice(&winner);
            let result = find_best_quality(&data, (i + 1) as u64, &gensig_array);
            let quality = result.0;
            assert_eq!(3084580316385335914u64, quality);
            data[i * 64..i * 64 + 64].clone_from_slice(&loser);
        }
    }

    #[test]
    fn test_generation_signature_processing() {
        // Test hex decoding of generation signatures
        let valid_hex_sigs = [
            "4a6f686e6e7946464d206861742064656e206772f6df74656e2050656e697321",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ];

        for hex_sig in &valid_hex_sigs {
            let decoded = hex::decode(hex_sig);
            assert!(decoded.is_ok(), "Should decode valid hex: {}", hex_sig);

            if let Ok(bytes) = decoded {
                assert_eq!(bytes.len(), 32, "Generation signature should be 32 bytes");

                // Test that we can create an array from the bytes
                let mut sig_array = [0u8; 32];
                sig_array.copy_from_slice(&bytes);

                // Verify the conversion worked correctly
                assert_eq!(sig_array.to_vec(), bytes);
            }
        }
    }

    #[test]
    fn test_quality_calculation_edge_cases() {
        let gensig =
            hex::decode("4a6f686e6e7946464d206861742064656e206772f6df74656e2050656e697321")
                .unwrap();
        let mut gensig_array = [0u8; 32];
        gensig_array.copy_from_slice(&gensig[..]);

        // Test with single scoop
        let single_scoop_data: [u8; 64] = [0; 64];
        let result = find_best_quality(&single_scoop_data, 1, &gensig_array);
        assert!(result.0 > 0, "Quality should be positive");
        assert_eq!(result.1, 0, "Offset should be 0 for single scoop");

        // Test with all zero data
        let zero_data: [u8; 64 * 4] = [0; 64 * 4];
        let zero_result = find_best_quality(&zero_data, 4, &gensig_array);
        assert!(
            zero_result.0 > 0,
            "Quality should be positive even for zero data"
        );
        assert!(zero_result.1 < 4, "Offset should be within bounds");

        // Test with maximum values
        let max_data: [u8; 64 * 4] = [255; 64 * 4];
        let max_result = find_best_quality(&max_data, 4, &gensig_array);
        assert!(max_result.0 > 0, "Quality should be positive for max data");
        assert!(max_result.1 < 4, "Offset should be within bounds");
    }

    #[test]
    fn test_nonce_count_variations() {
        let gensig =
            hex::decode("4a6f686e6e7946464d206861742064656e206772f6df74656e2050656e697321")
                .unwrap();
        let mut gensig_array = [0u8; 32];
        gensig_array.copy_from_slice(&gensig[..]);

        let test_data: [u8; 64 * 16] = [42; 64 * 16]; // Arbitrary test pattern

        let nonce_counts = [1u64, 2u64, 4u64, 8u64, 16u64];

        for &count in &nonce_counts {
            let result = find_best_quality(&test_data, count, &gensig_array);

            assert!(
                result.0 > 0,
                "Quality should be positive for count {}",
                count
            );
            assert!(
                result.1 < count,
                "Offset should be less than nonce count {}",
                count
            );
        }
    }

    #[test]
    fn test_hex_encoding_roundtrip() {
        let original_bytes = [
            0x4a, 0x6f, 0x68, 0x6e, 0x6e, 0x79, 0x46, 0x46, 0x4d, 0x20, 0x68, 0x61, 0x74, 0x20,
            0x64, 0x65, 0x6e, 0x20, 0x67, 0x72, 0xf6, 0xdf, 0x74, 0x65, 0x6e, 0x20, 0x50, 0x65,
            0x6e, 0x69, 0x73, 0x21,
        ];

        // Encode to hex
        let hex_string = hex::encode(original_bytes);
        assert_eq!(hex_string.len(), 64); // 32 bytes * 2 hex chars per byte

        // Decode back from hex
        let decoded_bytes = hex::decode(&hex_string).unwrap();
        assert_eq!(decoded_bytes, original_bytes);

        // Test that it works with our generation signature
        let mut gensig_array = [0u8; 32];
        gensig_array.copy_from_slice(&decoded_bytes);

        let test_data: [u8; 64] = [0; 64];
        let result = find_best_quality(&test_data, 1, &gensig_array);
        assert!(result.0 > 0);
    }

    #[test]
    fn test_quality_comparison() {
        let gensig =
            hex::decode("4a6f686e6e7946464d206861742064656e206772f6df74656e2050656e697321")
                .unwrap();
        let mut gensig_array = [0u8; 32];
        gensig_array.copy_from_slice(&gensig[..]);

        // Create different data patterns and compare their qualities
        let patterns = [
            [0u8; 64],   // All zeros
            [1u8; 64],   // All ones
            [128u8; 64], // All mid-values
            [255u8; 64], // All max values
        ];

        let mut qualities = Vec::new();

        for pattern in &patterns {
            let result = find_best_quality(pattern, 1, &gensig_array);
            qualities.push(result.0);
        }

        // All qualities should be positive and different (likely)
        for &quality in &qualities {
            assert!(quality > 0, "Quality should be positive");
            assert!(quality < u64::MAX, "Quality should not be maximum u64");
        }

        // Qualities should vary based on input (this is probabilistic but very likely)
        let unique_qualities: std::collections::HashSet<_> = qualities.iter().collect();
        assert!(
            unique_qualities.len() >= 2,
            "Should have some variation in qualities"
        );
    }

    #[test]
    fn test_memory_safety_boundaries() {
        let gensig =
            hex::decode("4a6f686e6e7946464d206861742064656e206772f6df74656e2050656e697321")
                .unwrap();
        let mut gensig_array = [0u8; 32];
        gensig_array.copy_from_slice(&gensig[..]);

        // Test with minimum valid data size (64 bytes = 1 scoop)
        let min_data: [u8; 64] = [42; 64];
        let min_result = find_best_quality(&min_data, 1, &gensig_array);
        assert!(min_result.0 > 0);
        assert_eq!(min_result.1, 0);

        // Test with larger data sizes
        let large_data: [u8; 64 * 32] = [123; 64 * 32];
        let large_result = find_best_quality(&large_data, 32, &gensig_array);
        assert!(large_result.0 > 0);
        assert!(large_result.1 < 32);
    }
}
