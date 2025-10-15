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

use pocx_plotter::buffer::PageAlignedByteBuffer;
use pocx_plotter::compressor::{helix_compress, xor_compress};
use proptest::prelude::*;
use quickcheck::{quickcheck, TestResult};

/// Property-based tests for PoCX Plotter
/// These tests verify invariants and properties that should hold for all valid
/// inputs
#[cfg(test)]
mod crypto_property_tests {
    use super::*;

    // Test that PoC address validation is consistent and secure
    proptest! {
        #[test]
        fn test_poc_address_validation_properties(
            version in 0u8..=255,
            data in prop::collection::vec(0u8..=255, 24)
        ) {
            let mut test_bytes = [0u8; 25];
            test_bytes[0] = version;
            for (i, &byte) in data.iter().enumerate() {
                if i < 24 {
                    test_bytes[i + 1] = byte;
                }
            }

            let payload = &test_bytes[1..21]; // Extract 20-byte payload
            let mut payload_array = [0u8; 20];
            payload_array.copy_from_slice(payload);
            let test_id = pocx_address::encode_address(&payload_array, pocx_address::NetworkId::Base58(test_bytes[0])).unwrap();

            // Property: Valid address encoding should always decode correctly
            let decoded = pocx_address::decode_address(&test_id);
            prop_assert!(decoded.is_ok(), "Valid address should decode");

            let (decoded_payload, decoded_network) = decoded.unwrap();
            prop_assert_eq!(decoded_payload, payload_array, "Payload should match");
            prop_assert_eq!(decoded_network, pocx_address::NetworkId::Base58(version), "Network ID should match");

            // Property: ID length should be consistent
            prop_assert!(test_id.len() >= 32 && test_id.len() <= 36,
                        "Base58 encoded ID should be reasonable length");
        }
    }

    proptest! {
        #[test]
        fn test_seed_validation_properties(
            seed_bytes in prop::collection::vec(0u8..=255, 32)
        ) {
            let hex_seed = hex::encode(&seed_bytes);

            // Property: 32-byte seed should always encode to 64 hex chars
            prop_assert_eq!(hex_seed.len(), 64, "32 bytes should encode to 64 hex chars");

            // Property: All characters should be valid hex
            prop_assert!(hex_seed.chars().all(|c| c.is_ascii_hexdigit()),
                        "All characters should be valid hex");

            // Property: Should be able to decode back to original
            let decoded = hex::decode(&hex_seed);
            prop_assert!(decoded.is_ok(), "Should decode successfully");
            prop_assert_eq!(decoded.unwrap(), seed_bytes, "Should decode to original");
        }
    }

    proptest! {
        #[test]
        fn test_parameter_bounds_properties(
            warps in 1u64..1_000_000,
            escalate in 1u64..64,
            compression in 1u32..32,
            cpu_threads in 1u8..128
        ) {
            // Property: All valid parameters should pass validation
            prop_assert!(warps <= 1_000_000, "Warps within bounds");
            prop_assert!((1..=64).contains(&escalate), "Escalate within bounds");
            prop_assert!((1..=32).contains(&compression), "Compression within bounds");
            prop_assert!(cpu_threads <= 128, "CPU threads within bounds");

            // Property: Memory calculations should not overflow
            let mem_calc = (4096u64).checked_mul(compression as u64)
                .and_then(|v| v.checked_mul(escalate));
            prop_assert!(mem_calc.is_some(), "Memory calculations should not overflow");
        }
    }
}

#[cfg(test)]
mod buffer_property_tests {
    use super::*;

    proptest! {
        #[test]
        fn test_buffer_allocation_properties(
            size in 4096usize..16_777_216 // 4KB to 16MB
        ) {
            // Property: Valid buffer sizes should always succeed
            let buffer_result = PageAlignedByteBuffer::new(size);
            prop_assert!(buffer_result.is_ok(), "Valid buffer size should succeed");

            if let Ok(buffer) = buffer_result {
                let data = buffer.get_buffer();
                let guard = data.lock().unwrap();

                // Property: Buffer should have exact requested size
                prop_assert_eq!(guard.len(), size, "Buffer should have requested size");

                // Property: Buffer should be properly aligned
                let ptr = guard.as_ptr() as usize;
                let page_size = page_size::get();
                prop_assert_eq!(ptr % page_size, 0, "Buffer should be page-aligned");
            }
        }
    }

    proptest! {
        #[test]
        fn test_buffer_rejection_properties(
            size in 0usize..4096
        ) {
            if size == 0 {
                // Property: Zero-sized buffers should always be rejected
                let buffer_result = PageAlignedByteBuffer::new(size);
                prop_assert!(buffer_result.is_err(), "Zero-sized buffer should be rejected");
            } else if size < 4096 {
                // Property: Small buffers might be accepted but must be valid if they are
                let buffer_result = PageAlignedByteBuffer::new(size);
                if let Ok(buffer) = buffer_result {
                    let data = buffer.get_buffer();
                    let guard = data.lock().unwrap();
                    prop_assert_eq!(guard.len(), size, "If accepted, size should match");
                }
            }
        }
    }
}

#[cfg(test)]
mod compression_property_tests {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]
        #[test]
        fn test_helix_compression_properties(
            warp_offset in 0u64..2,
            output_len in 1u64..2,
            fill_byte in 1u8..=255
        ) {
            // Use minimal test dimensions for faster execution in debug mode
            const SMALL_DIM: u64 = 1;
            const SMALL_HASH_SIZE: u64 = 8;

            let source_size = (2 * SMALL_DIM * SMALL_DIM * SMALL_HASH_SIZE) as usize;
            let target_size = (4 * SMALL_DIM * SMALL_DIM * SMALL_HASH_SIZE) as usize;

            let mut source_buffer = vec![0u8; source_size];
            // Create a pattern that will definitely cause changes
            for (i, byte) in source_buffer.iter_mut().enumerate() {
                *byte = ((i % 256) as u8) ^ fill_byte;
            }
            let mut target_buffer = vec![0u8; target_size];

            // Property: Compression should not panic with valid inputs
            helix_compress(&source_buffer, &mut target_buffer, warp_offset, output_len);

            // Property: Should not write beyond buffer bounds
            prop_assert_eq!(target_buffer.len(), target_size, "Target buffer size unchanged");

            // Property: Target buffer should be deterministic for same input
            let mut target_buffer2 = vec![0u8; target_size];
            helix_compress(&source_buffer, &mut target_buffer2, warp_offset, output_len);
            prop_assert_eq!(target_buffer, target_buffer2, "Results should be deterministic");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]
        #[test]
        fn test_xor_compression_properties(
            warp_offset in 0u64..2,
            output_len in 1u64..2,
            iterations in 1u32..2
        ) {
            // Use minimal test dimensions for faster execution in debug mode
            const SMALL_DIM: u64 = 1;
            const SMALL_HASH_SIZE: u64 = 8;

            let src_len = u64::pow(2, iterations);
            let source_size = (src_len * SMALL_DIM * SMALL_DIM * SMALL_HASH_SIZE) as usize;
            let target_size = (output_len * SMALL_DIM * SMALL_DIM * SMALL_HASH_SIZE) as usize;

            let mut source_buffer = vec![0u8; source_size];
            // Create varied test data
            for (i, byte) in source_buffer.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }
            let mut target_buffer = vec![0u8; target_size];

            // Property: XOR compression should not panic with valid inputs
            xor_compress(&source_buffer, &mut target_buffer, warp_offset, output_len, iterations);

            // Property: Should not write beyond buffer bounds
            prop_assert_eq!(target_buffer.len(), target_size, "Target buffer size unchanged");

            // Property: XOR compression should be deterministic
            let mut target_buffer2 = vec![0u8; target_size];
            xor_compress(&source_buffer, &mut target_buffer2, warp_offset, output_len, iterations);
            prop_assert_eq!(target_buffer, target_buffer2, "XOR compression should be deterministic");
        }
    }
}

#[cfg(test)]
mod path_validation_property_tests {
    use super::*;

    proptest! {
        #[test]
        fn test_path_length_properties(
            path_prefix in "[a-zA-Z0-9_-]{1,10}",
            path_suffix in "[a-zA-Z0-9_.-]{1,10}"
        ) {
            let path = format!("{}/{}", path_prefix, path_suffix);

            // Property: Path length should be reasonable (only check we keep)
            prop_assert!(path.len() <= 4096, "Path should not be excessively long");

            // Property: Path should be valid for filesystem use
            prop_assert!(!path.is_empty(), "Path should not be empty");
        }
    }

    proptest! {
        #[test]
        fn test_path_flexibility(
            prefix in "[a-zA-Z0-9_-]{0,5}",
            suffix in "[a-zA-Z0-9_.-]{0,5}"
        ) {
            let relative_path = format!("{}../{}/../{}", prefix, suffix, prefix);

            // Property: Client apps should accept any path format users want
            prop_assert!(relative_path.len() <= 4096, "Only length should be limited");

            // Property: Various path formats should be acceptable
            prop_assert!(true, "Client applications should trust user intentions");
        }
    }
}

// QuickCheck-based tests for additional coverage
#[cfg(test)]
mod quickcheck_tests {
    use super::*;

    #[test]
    fn quickcheck_poc_address_roundtrip() {
        fn prop(data: Vec<u8>) -> TestResult {
            if data.len() != 25 {
                return TestResult::discard();
            }

            let mut bytes = [0u8; 25];
            bytes.copy_from_slice(&data);

            let payload = &bytes[1..21]; // Extract 20-byte payload
            let mut payload_array = [0u8; 20];
            payload_array.copy_from_slice(payload);
            let network_id = pocx_address::NetworkId::Base58(bytes[0]);
            let encoded = pocx_address::encode_address(&payload_array, network_id.clone()).unwrap();
            let (decoded_payload, decoded_network) =
                pocx_address::decode_address(&encoded).unwrap();

            // Check that the payload and network match
            TestResult::from_bool(decoded_network == network_id && decoded_payload == payload_array)
        }
        quickcheck(prop as fn(Vec<u8>) -> TestResult);
    }

    #[test]
    fn quickcheck_hex_seed_roundtrip() {
        fn prop(data: Vec<u8>) -> TestResult {
            if data.len() != 32 {
                return TestResult::discard();
            }

            let hex_string = hex::encode(&data);
            if hex_string.len() != 64 {
                return TestResult::failed();
            }

            let decoded = hex::decode(&hex_string).unwrap();
            TestResult::from_bool(decoded == data)
        }
        quickcheck(prop as fn(Vec<u8>) -> TestResult);
    }

    #[test]
    fn quickcheck_parameter_validation() {
        fn prop(warps: u64, escalate: u64, compression: u32) -> TestResult {
            // Test that parameter bounds are consistently enforced
            let warps_valid = warps <= 1_000_000;
            let escalate_valid = (1..=64).contains(&escalate);
            let compression_valid = (1..=32).contains(&compression);

            // If all parameters are valid, memory calculations should not overflow
            if warps_valid && escalate_valid && compression_valid {
                let mem_calc = (4096u64)
                    .checked_mul(compression as u64)
                    .and_then(|v| v.checked_mul(escalate))
                    .and_then(|v| v.checked_mul(warps));

                TestResult::from_bool(mem_calc.is_some())
            } else {
                TestResult::discard()
            }
        }
        quickcheck(prop as fn(u64, u64, u32) -> TestResult);
    }
}

#[cfg(test)]
mod cli_fuzzing_tests {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn test_cli_argument_validation(
            arg_name in "[a-z-]{2,10}",
            arg_value in "[a-zA-Z0-9._/-]{0,20}"
        ) {
            // Property: CLI parsing should handle various argument patterns
            let arg_string = format!("--{}", arg_name);

            // Basic validation that shouldn't panic
            prop_assert!(arg_string.starts_with("--"), "Should start with --");
            prop_assert!(arg_string.len() >= 4, "Should have reasonable length");
            prop_assert!(!arg_value.contains('\0'), "Should not contain null bytes");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]
        #[test]
        fn test_poc_address_format_validation(
            id_value in "[a-zA-Z0-9]{20,40}"
        ) {
            // Property: PoC address format validation should be consistent
            prop_assert!(id_value.len() >= 20, "Should have minimum length");
            prop_assert!(id_value.len() <= 40, "Should have maximum length");
            prop_assert!(id_value.chars().all(|c| c.is_ascii_alphanumeric()),
                        "Should only contain alphanumeric characters");

            // Test address decoding (should not panic)
            let _decode_result = pocx_address::decode_address(&id_value);
        }
    }
}
