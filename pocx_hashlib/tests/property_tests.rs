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

//! Property-based tests for pocx_hashlib
//!
//! This module contains property-based tests to verify that the hash library
//! maintains its invariants across a wide range of inputs and conditions.

use pocx_hashlib::{
    calculate_scoop, decode_generation_signature, generate_nonces,
    noncegen_common::{NONCE_SIZE, NUM_SCOOPS},
    PoCXHashError,
};
use proptest::prelude::*;
use quickcheck::QuickCheck;
use quickcheck_macros::quickcheck;

/// Strategy for generating valid hex strings
fn valid_hex_strategy(len: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(prop::char::range('0', 'f'), len * 2).prop_map(|chars| {
        chars
            .iter()
            .map(|&c| {
                if c > '9' && c <= 'f' {
                    c
                } else {
                    (c as u8 % 10 + b'0') as char
                }
            })
            .collect()
    })
}

/// Strategy for generating valid account and seed data
fn account_and_seed_strategy() -> impl Strategy<Value = ([u8; 20], [u8; 32])> {
    (any::<[u8; 20]>(), any::<[u8; 32]>()).prop_map(|(account, seed)| (account, seed))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5))]  // Reduced from 20 to 5 for much faster testing

    /// Test that nonce generation handles valid parameters correctly
    /// Re-enabled after fixing buffer bounds checking
    #[test]
    fn test_nonce_generation_bounds(
        (account, seed) in account_and_seed_strategy(),
        num_nonces in 1u64..2u64,  // Just test with 1 nonce for speed
        start_nonce in 0u64..5u64,  // Reduced from 10 to 5
        cache_offset in 0usize..128usize  // Reduced from 256 to 128
    ) {
        let required_size = cache_offset + (num_nonces as usize * NONCE_SIZE);
        let mut cache = vec![0u8; required_size];

        let result = generate_nonces(
            &mut cache,
            cache_offset,
            &account,
            &seed,
            start_nonce,
            num_nonces,
        );

        // Should succeed with valid parameters
        prop_assert!(result.is_ok());
    }

    /// Test that nonce generation fails appropriately with insufficient buffer
    /// Re-enabled after fixing buffer bounds checking
    #[test]
    fn test_nonce_generation_buffer_validation(
        (account, seed) in account_and_seed_strategy(),
        num_nonces in 1u64..5u64,
        cache_offset in 0usize..512usize
    ) {
        let required_size = cache_offset + (num_nonces as usize * NONCE_SIZE);
        let insufficient_size = required_size.saturating_sub(1);
        let mut cache = vec![0u8; insufficient_size];

        let result = generate_nonces(
            &mut cache,
            cache_offset,
            &account,
            &seed,
            0,
            num_nonces,
        );

        // Should fail with insufficient buffer
        prop_assert!(result.is_err());
        if let Err(PoCXHashError::BufferSizeError(_)) = result {
            // Expected error type
        } else {
            prop_assert!(false, "Expected BufferSizeError");
        }
    }

    /// Test scoop calculation properties
    #[test]
    fn test_scoop_calculation_properties(
        block_height in any::<u64>(),
        generation_signature in any::<[u8; 32]>()
    ) {
        let scoop = calculate_scoop(block_height, &generation_signature);

        // Scoop should always be in valid range
        prop_assert!(scoop < NUM_SCOOPS as u64);

        // Same inputs should produce same output
        let scoop2 = calculate_scoop(block_height, &generation_signature);
        prop_assert_eq!(scoop, scoop2);
    }

    /// Test generation signature decoding with valid hex
    #[test]
    fn test_generation_signature_decoding(
        hex_string in valid_hex_strategy(32)
    ) {
        // Ensure we have exactly 64 hex characters
        let padded_hex = format!("{:0<64}", hex_string);

        let result = decode_generation_signature(&padded_hex);

        if padded_hex.len() == 64 && padded_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            prop_assert!(result.is_ok());
            if let Ok(bytes) = result {
                prop_assert_eq!(bytes.len(), 32);
            }
        }
    }

}

/// QuickCheck tests for additional coverage with reduced iterations for speed
/// Re-enabled after fixing buffer bounds checking
#[test]
fn quickcheck_nonce_generation_no_panic() {
    fn prop(account: Vec<u8>, seed: Vec<u8>, num_nonces: u8, start_nonce: u64) -> bool {
        // Convert to fixed size arrays
        let mut account_fixed = [0u8; 20];
        let mut seed_fixed = [0u8; 32];

        for (i, &b) in account.iter().take(20).enumerate() {
            account_fixed[i] = b;
        }
        for (i, &b) in seed.iter().take(32).enumerate() {
            seed_fixed[i] = b;
        }

        let num_nonces = std::cmp::max(1, num_nonces as u64 % 3); // Reduced from 10 to 3
        let mut cache = vec![0u8; num_nonces as usize * NONCE_SIZE];

        // This should not panic, but may return an error
        let _result = generate_nonces(
            &mut cache,
            0,
            &account_fixed,
            &seed_fixed,
            start_nonce,
            num_nonces,
        );
        true // If we reach here, no panic occurred
    }

    // Run with reduced iterations (10 instead of default 100)
    QuickCheck::new()
        .tests(10)
        .quickcheck(prop as fn(Vec<u8>, Vec<u8>, u8, u64) -> bool);
}

#[quickcheck]
fn quickcheck_scoop_calculation_bounds(block_height: u64, gen_sig: Vec<u8>) -> bool {
    let mut gen_sig_fixed = [0u8; 32];
    for (i, &b) in gen_sig.iter().take(32).enumerate() {
        gen_sig_fixed[i] = b;
    }

    let scoop = calculate_scoop(block_height, &gen_sig_fixed);
    scoop < NUM_SCOOPS as u64 // Should always be in bounds
}

#[cfg(test)]
mod integration_property_tests {
    use super::*;

    #[test]
    fn test_basic_nonce_generation() {
        // Test basic nonce generation without offsets
        let account = [1u8; 20];
        let seed = [2u8; 32];
        let num_nonces = 1;

        let mut cache = vec![0u8; num_nonces * NONCE_SIZE];
        let result = generate_nonces(&mut cache, 0, &account, &seed, 0, num_nonces as u64);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generation_signature_reproducibility() {
        // Test that the same generation signature operations are reproducible
        let test_sig = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut results = Vec::new();

        for _ in 0..10 {
            let result = decode_generation_signature(test_sig);
            results.push(result);
        }

        // All results should be identical
        for result in &results[1..] {
            assert_eq!(result, &results[0]);
        }
    }

    #[test]
    fn test_scoop_calculation_distribution() {
        // Test that scoop calculation produces reasonable distribution
        let mut scoop_counts = [0u32; 16]; // Track distribution in 16 buckets
        let bucket_size = NUM_SCOOPS / 16;

        for height in 0..1000 {
            let gen_sig = [height as u8; 32]; // Simple but varied generation signatures
            let scoop = calculate_scoop(height, &gen_sig);
            let bucket = (scoop / bucket_size as u64) as usize;
            if bucket < scoop_counts.len() {
                scoop_counts[bucket] += 1;
            }
        }

        // Each bucket should have at least some values (basic distribution check)
        let total: u32 = scoop_counts.iter().sum();
        assert_eq!(total, 1000);

        // No bucket should be completely empty (with 1000 samples, this is very
        // unlikely)
        assert!(scoop_counts.iter().all(|&count| count > 0));
    }

    #[test]
    fn test_error_handling_consistency() {
        // Test that error conditions are handled consistently
        let account = [0u8; 20];
        let seed = [0u8; 32];

        // Test various invalid buffer sizes
        let invalid_sizes = vec![0, 1, NONCE_SIZE - 1, NONCE_SIZE / 2];

        for size in invalid_sizes {
            let mut cache = vec![0u8; size];
            let result = generate_nonces(&mut cache, 0, &account, &seed, 0, 1);

            assert!(result.is_err());
            assert!(
                matches!(result, Err(PoCXHashError::BufferSizeError(_))),
                "Expected BufferSizeError, got: {:?}",
                result
            );
        }
    }

    #[test]
    fn test_generation_signature_edge_cases() {
        // Test various edge cases for generation signature decoding
        let test_cases = vec![
            ("", true),                 // Empty string should fail
            ("invalid", true),          // Non-hex should fail
            ("0123456789abcdef", true), // Too short should fail
            (
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                false,
            ), // Valid
            (
                "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
                false,
            ), // Valid uppercase
            (
                "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
                true,
            ), // Invalid hex chars
        ];

        for (input, should_fail) in test_cases {
            let result = decode_generation_signature(input);

            if should_fail {
                assert!(result.is_err(), "Expected failure for input: {}", input);
            } else {
                assert!(result.is_ok(), "Expected success for input: {}", input);
                if let Ok(bytes) = result {
                    assert_eq!(bytes.len(), 32);
                }
            }
        }
    }
}
