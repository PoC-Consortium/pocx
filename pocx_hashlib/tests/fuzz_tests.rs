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

//! Fuzzing tests for pocx_hashlib
//!
//! These tests use arbitrary data to find edge cases and potential panics
//! in the hash library.

use arbitrary::{Arbitrary, Unstructured};
use pocx_hashlib::{
    calculate_scoop, decode_generation_signature, generate_nonces,
    noncegen_common::{NONCE_SIZE, NUM_SCOOPS},
    PoCXHashError,
};

/// Arbitrary implementation for hash operation parameters
#[derive(Debug, Clone, Arbitrary)]
struct FuzzHashParams {
    account: [u8; 20],
    seed: [u8; 32],
    num_nonces: u64,
    start_nonce: u64,
    cache_offset: usize,
}

impl FuzzHashParams {
    fn sanitized(self) -> Self {
        // Sanitize parameters to prevent resource exhaustion while fuzzing
        FuzzHashParams {
            account: self.account,
            seed: self.seed,
            // Limit nonces to prevent huge allocations during fuzzing
            num_nonces: std::cmp::min(self.num_nonces % 20 + 1, 10),
            start_nonce: self.start_nonce,
            // Limit cache offset to reasonable values
            cache_offset: self.cache_offset % 1024,
        }
    }
}

/// Fuzz test for nonce generation operations
fn fuzz_nonce_generation(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut unstructured = Unstructured::new(data);

    // Generate fuzzed parameters - return early if insufficient data
    let fuzz_params: FuzzHashParams = match FuzzHashParams::arbitrary(&mut unstructured) {
        Ok(params) => params.sanitized(),
        Err(_) => return Ok(()), // Skip if insufficient data for parameter generation
    };

    // Calculate required buffer size
    let required_size = fuzz_params.cache_offset + (fuzz_params.num_nonces as usize * NONCE_SIZE);

    // Limit total allocation to prevent OOM during fuzzing (reduced for speed)
    if required_size > 1024 * 1024 {
        // Reduced from 10MB to 1MB
        return Ok(()); // Skip excessively large allocations
    }

    // Skip if required size would be too small or zero
    if required_size == 0 || fuzz_params.num_nonces == 0 {
        return Ok(());
    }

    let mut cache = vec![0u8; required_size];

    // Test nonce generation - should not panic regardless of parameters
    let result = generate_nonces(
        &mut cache,
        fuzz_params.cache_offset,
        &fuzz_params.account,
        &fuzz_params.seed,
        fuzz_params.start_nonce,
        fuzz_params.num_nonces,
    );

    // Either succeeds or fails gracefully, but no panics
    match result {
        Ok(()) => {
            // Verify the operation was valid
            assert_eq!(cache.len(), required_size);
        }
        Err(PoCXHashError::BufferSizeError(_)) => {
            // Expected error for invalid buffer sizes
        }
        Err(e) => {
            // Other errors are acceptable, just no panics
            println!("Fuzz test encountered error: {}", e);
        }
    }

    Ok(())
}

fn fuzz_hash_operations(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut unstructured = Unstructured::new(data);

    // Test generation signature decoding with various string lengths
    while unstructured.len() >= 10 {
        let str_len_byte = match unstructured.arbitrary::<u8>() {
            Ok(b) => b,
            Err(_) => break,
        };
        let str_len = std::cmp::min(
            str_len_byte as usize,
            std::cmp::min(unstructured.len(), 128),
        );

        if str_len == 0 {
            break;
        }

        let string_bytes = match unstructured.bytes(str_len) {
            Ok(b) => b,
            Err(_) => break,
        };

        let fuzz_string = String::from_utf8_lossy(string_bytes);

        // Test decoding - should not panic regardless of input
        let _result = decode_generation_signature(&fuzz_string);
    }

    Ok(())
}

fn fuzz_scoop_calculation(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut unstructured = Unstructured::new(data);

    while unstructured.len() >= 40 {
        // 8 bytes for block_height + 32 bytes for generation_signature
        let block_height = match unstructured.arbitrary::<u64>() {
            Ok(h) => h,
            Err(_) => break, // Insufficient data
        };
        let mut generation_signature = [0u8; 32];

        for item in &mut generation_signature {
            *item = match unstructured.arbitrary() {
                Ok(b) => b,
                Err(_) => break, // Insufficient data
            };
        }

        // Calculate scoop - should not panic and should be in bounds
        let scoop = calculate_scoop(block_height, &generation_signature);
        assert!(scoop < NUM_SCOOPS as u64);

        // Consistency check - same inputs should produce same output
        let scoop2 = calculate_scoop(block_height, &generation_signature);
        assert_eq!(scoop, scoop2);
    }

    Ok(())
}

fn fuzz_generation_signature_decoding(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut unstructured = Unstructured::new(data);

    while !unstructured.is_empty() {
        // Generate string length
        let str_len_byte = match unstructured.arbitrary::<u8>() {
            Ok(b) => b,
            Err(_) => break, // Insufficient data
        };
        let str_len = std::cmp::min(str_len_byte as usize, unstructured.len());

        if str_len == 0 {
            break;
        }

        // Generate fuzzed string data
        let string_bytes = match unstructured.bytes(str_len) {
            Ok(b) => b,
            Err(_) => break, // Insufficient data
        };

        // Convert to string (replace invalid UTF-8 with replacement chars)
        let fuzz_string = String::from_utf8_lossy(string_bytes);

        // Test decoding - should not panic
        let result = decode_generation_signature(&fuzz_string);

        match result {
            Ok(bytes) => {
                // If successful, should always be 32 bytes
                assert_eq!(bytes.len(), 32);
            }
            Err(PoCXHashError::HexDecodeError(_)) => {
                // Expected for invalid hex strings
            }
            Err(e) => {
                // Other errors are acceptable
                println!("Fuzz generation signature error: {}", e);
            }
        }
    }

    Ok(())
}

// Test harnesses for different fuzzing scenarios
#[cfg(test)]
mod fuzz_tests {
    use super::*;

    #[test]
    fn fuzz_comprehensive_hash_operations() {
        // Test with various byte patterns (reduced sizes for speed)
        let test_cases = vec![
            vec![0u8; 50],                             // All zeros (reduced from 100)
            vec![0xFFu8; 50],                          // All ones (reduced from 100)
            (0u8..=255u8).cycle().take(100).collect(), // Repeating pattern (reduced from 500)
            vec![0x55u8; 64],                          /* Alternating bits pattern (reduced from
                                                        * 200) */
            vec![0xAAu8; 64], // Opposite alternating bits (reduced from 200)
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF].repeat(8), /* Hex pattern (reduced
                               * from 20) */
        ];

        for test_data in test_cases {
            // Re-enabled after fixing buffer bounds checking
            let _ = fuzz_nonce_generation(&test_data);
            let _ = fuzz_hash_operations(&test_data);
            let _ = fuzz_scoop_calculation(&test_data);
            let _ = fuzz_generation_signature_decoding(&test_data);
        }
    }

    #[test]
    fn fuzz_edge_case_sizes() {
        // Test with edge case byte sequences (reduced for speed)
        let edge_cases = vec![
            vec![0u8; 1],                          // Minimal data
            vec![0xFFu8; 100],                     // Reduced from 1000 to 100
            (0u8..50u8).collect(),                 // Reduced from 100 to 50
            (0u8..50u8).rev().collect::<Vec<_>>(), // Reduced from 100 to 50
        ];

        for test_data in edge_cases {
            // Extend data to minimum required length for some operations
            let mut extended_data = test_data;
            while extended_data.len() < 60 {
                // Reduced from 100 to 60
                extended_data.extend_from_slice(&[0x42u8; 10]);
            }

            // Test operations that should not panic
            let _ = fuzz_nonce_generation(&extended_data); // Re-enabled after fixing buffer bounds
            let _ = fuzz_hash_operations(&extended_data);
            let _ = fuzz_scoop_calculation(&extended_data);
        }
    }

    #[test]
    fn fuzz_boundary_values() {
        // Test with values that might trigger boundary conditions
        let boundary_test = |base_value: u8| {
            let mut test_data = vec![base_value; 64]; // Reduced from 200 to 64

            // Insert some boundary values at specific positions
            if test_data.len() > 10 {
                test_data[10] = 0xFF; // Maximum value
                test_data[11] = 0x00; // Minimum value
                test_data[12] = 0x7F; // Mid-range value
                if test_data.len() > 13 {
                    test_data[13] = 0x80; // High bit set
                }
            }

            let _ = fuzz_nonce_generation(&test_data); // Re-enabled after fixing buffer bounds
            let _ = fuzz_hash_operations(&test_data);
        };

        // Test with different base values
        for base in [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF] {
            boundary_test(base);
        }
    }

    #[test]
    fn fuzz_concurrent_operations() {
        use std::sync::Arc;
        use std::thread;

        let test_data = (0u8..=255u8).cycle().take(1000).collect::<Vec<_>>();
        let shared_data = Arc::new(test_data);

        let mut handles = vec![];

        // Test concurrent fuzzing (operations are thread-safe)
        for thread_id in 0..3 {
            let data_clone = Arc::clone(&shared_data);

            let handle = thread::spawn(move || {
                let thread_data = data_clone[thread_id * 100..(thread_id + 1) * 100 + 50].to_vec();

                // Each thread runs fuzz tests with different data slices
                let _ = fuzz_nonce_generation(&thread_data); // Re-enabled after fixing buffer bounds
                let _ = fuzz_hash_operations(&thread_data);
                let _ = fuzz_scoop_calculation(&thread_data);

                thread_id
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().unwrap());
        }

        // Verify all threads completed
        results.sort();
        assert_eq!(results, vec![0, 1, 2]);
    }

    #[test]
    fn fuzz_error_resilience() {
        // Test that the library handles malformed data gracefully
        let malformed_cases = vec![
            vec![],             // Empty data
            vec![0u8; 1],       // Insufficient data
            vec![0xFFu8; 10],   // Small but with max values
            vec![0u8; 2000],    // Large with zeros
            vec![0xFFu8; 2000], // Large with max values
        ];

        for test_data in malformed_cases {
            // These should handle errors gracefully, not panic
            let _ = fuzz_nonce_generation(&test_data); // Re-enabled after fixing buffer bounds
            let _ = fuzz_hash_operations(&test_data);
            let _ = fuzz_scoop_calculation(&test_data);
            let _ = fuzz_generation_signature_decoding(&test_data);
        }
    }

    #[test]
    fn fuzz_specific_operation_sequences() {
        // Test specific sequences that might cause issues
        let operation_sequences = vec![
            // Sequence 1: Nonce generation parameters
            vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05], // Small incremental
            vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA], // Large decremental
            vec![0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF], // Alternating extremes
            vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC], // Random hex values
        ];

        for sequence in operation_sequences {
            // Extend sequence to provide enough data for all operations
            let mut extended_sequence = sequence.clone();
            while extended_sequence.len() < 100 {
                extended_sequence.extend_from_slice(&sequence);
            }

            // Should not panic regardless of sequence
            let _ = fuzz_nonce_generation(&extended_sequence); // Re-enabled after fixing buffer bounds
            let _ = fuzz_hash_operations(&extended_sequence);
            let _ = fuzz_scoop_calculation(&extended_sequence);
            let _ = fuzz_generation_signature_decoding(&extended_sequence);
        }
    }

    #[test]
    fn fuzz_memory_safety() {
        // Test patterns that might expose memory safety issues
        let memory_test_patterns = vec![
            // Pattern 1: Gradual size increase
            (1..100).map(|i| (i % 256) as u8).collect::<Vec<_>>(),
            // Pattern 2: Powers of 2
            vec![
                1, 2, 4, 8, 16, 32, 64, 128, 255, 128, 64, 32, 16, 8, 4, 2, 1,
            ],
            // Pattern 3: Fibonacci-like
            {
                let mut fib = vec![1u8, 1u8];
                for _ in 2..50 {
                    let len = fib.len();
                    let next = fib[len - 1].wrapping_add(fib[len - 2]);
                    fib.push(next);
                }
                fib
            },
        ];

        for pattern in memory_test_patterns {
            // Ensure sufficient size for operations
            let mut test_pattern = pattern;
            while test_pattern.len() < 200 {
                test_pattern.extend_from_slice(&[0x42; 20]);
            }

            // Test memory safety - no crashes or memory corruption
            let _ = fuzz_nonce_generation(&test_pattern); // Re-enabled after fixing buffer bounds
            let _ = fuzz_hash_operations(&test_pattern);
        }
    }

    #[test]
    fn fuzz_utf8_edge_cases() {
        // Test generation signature decoding with various UTF-8 edge cases
        let utf8_edge_cases = vec![
            // Valid ASCII hex (extend to 64 chars)
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_vec(),
            // Invalid UTF-8 sequences
            vec![0xFF, 0xFE, 0xFD, 0xFC],
            // Mixed valid/invalid
            vec![b'a', b'b', 0xFF, b'c', b'd'],
            // Control characters
            vec![0x00, 0x01, 0x02, 0x03, 0x1F],
            // High Unicode values
            vec![0xE2, 0x82, 0xAC], // Euro symbol in UTF-8
        ];

        for case in utf8_edge_cases {
            let _ = fuzz_generation_signature_decoding(&case);
        }
    }
}
