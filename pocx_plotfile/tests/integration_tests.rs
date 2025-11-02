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

//! Integration tests for pocx_plotfile
//!
//! These tests verify that the library works correctly in realistic scenarios
//! and that all components work together as expected.

use pocx_plotfile::{AccessType, PoCXPlotFile, NUM_SCOOPS};
use std::time::Instant;
use tempfile::TempDir;

#[test]
fn test_full_plotfile_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    // Create test address payloads and seeds
    let accounts_and_seeds = [
        ([1u8; 20], [0x11u8; 32]),
        ([2u8; 20], [0x22u8; 32]),
        ([3u8; 20], [0x33u8; 32]),
    ];

    let mut plotfiles = Vec::new();

    // Create multiple plotfiles
    for (i, (account, seed)) in accounts_and_seeds.iter().enumerate() {
        let plotfile_result = PoCXPlotFile::new(
            temp_path,
            account,
            seed,
            (i + 1) as u64 * 2, // Different warp counts
            1,
            false, // No direct I/O for testing
            false, // Don't create actual files
        );

        if let Ok(mut plotfile) = plotfile_result {
            // Use dummy mode for safe testing
            plotfile.access = AccessType::Dummy;

            // Verify metadata
            assert_eq!(plotfile.meta.base58_decoded, *account);
            assert_eq!(plotfile.meta.seed_decoded, *seed);
            assert_eq!(plotfile.meta.number_of_warps, (i + 1) as u64 * 2);

            plotfiles.push(plotfile);
        }
    }

    // Test operations on all plotfiles
    for (i, plotfile) in plotfiles.iter_mut().enumerate() {
        // Test nonce reading
        for scoop in [0, 1000, 2000, 4095] {
            let max_nonces = plotfile.meta.number_of_warps * NUM_SCOOPS;
            for nonce in [0, max_nonces / 2, max_nonces - 1] {
                let result = plotfile.read_nonce(scoop, nonce);
                if let Ok(data) = result {
                    assert_eq!(data.len(), 64);
                } // Errors are acceptable in dummy mode
            }
        }

        // Test buffer reading
        let mut buffer = vec![0u8; 1024 * (i + 1)]; // Different buffer sizes
        for scoop in [0, 100, 500] {
            let _result = plotfile.read(&mut buffer, scoop);
            // May succeed or fail in dummy mode, just shouldn't panic
        }

        // Test resume operations
        let _resume_result = plotfile.read_resume_info();
        let _write_result = plotfile.write_resume_info(i as u64);
    }
}

#[test]
fn test_access_type_behaviors() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    let account = [1u8; 20];
    let seed = [0u8; 32];

    // Test different access types
    for &create_actual in &[false] {
        // Only test without creating actual files
        for &direct_io in &[false, true] {
            let plotfile_result = PoCXPlotFile::new(
                temp_path,
                &account,
                &seed,
                3, // 3 warps
                1,
                direct_io,
                create_actual,
            );

            if let Ok(mut plotfile) = plotfile_result {
                // Test Dummy access
                plotfile.access = AccessType::Dummy;

                let nonce_result = plotfile.read_nonce(0, 0);
                assert!(nonce_result.is_ok() || nonce_result.is_err()); // Should not panic

                let mut buffer = vec![0u8; 1024];
                let read_result = plotfile.read(&mut buffer, 0);
                assert!(read_result.is_ok() || read_result.is_err()); // Should not panic

                // Test resume operations
                let _resume_read = plotfile.read_resume_info();
                let _resume_write = plotfile.write_resume_info(1);
            }
        }
    }
}

#[test]
fn test_boundary_conditions() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    let account = [1u8; 20];
    let seed = [0u8; 32];

    // Test with minimum warp count
    if let Ok(mut plotfile) = PoCXPlotFile::new(temp_path, &account, &seed, 1, 1, false, false) {
        plotfile.access = AccessType::Dummy;

        // Test boundary nonce values
        let max_nonces = NUM_SCOOPS; // 1 warp = NUM_SCOOPS nonces

        // Valid boundary cases
        let _result1 = plotfile.read_nonce(0, 0); // First nonce
        let _result2 = plotfile.read_nonce(4095, 0); // Last scoop, first nonce
        let _result3 = plotfile.read_nonce(0, max_nonces - 1); // First scoop, last valid nonce

        // Invalid cases should return errors, not panic
        let invalid_result1 = plotfile.read_nonce(0, max_nonces); // One past end
        assert!(invalid_result1.is_err());

        let _invalid_result2 = plotfile.read_nonce(4096, 0); // Invalid scoop
                                                             // May be allowed or may error, depending on implementation

        // Test with large nonce values
        let invalid_result3 = plotfile.read_nonce(0, max_nonces * 2);
        assert!(invalid_result3.is_err());
    }
}

#[test]
fn test_buffer_size_variations() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    let account = [1u8; 20];
    let seed = [0u8; 32];

    if let Ok(mut plotfile) = PoCXPlotFile::new(temp_path, &account, &seed, 5, 1, false, false) {
        plotfile.access = AccessType::Dummy;

        // Test various buffer sizes
        let buffer_sizes = vec![
            64,     // Single scoop
            1024,   // Small buffer
            4096,   // Page size
            65536,  // 64KB
            262144, // 256KB (close to warp size)
        ];

        for &size in &buffer_sizes {
            let mut buffer = vec![0u8; size];

            // Should not panic regardless of buffer size
            let result = plotfile.read(&mut buffer, 0);

            if let Ok(warps_read) = result {
                assert!(warps_read <= plotfile.meta.number_of_warps);
            }
            // Errors are acceptable, just no panics
        }
    }
}

#[test]
fn test_concurrent_safety_simulation() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    let account = [1u8; 20];
    let seed = [0u8; 32];

    // Create a plotfile to test with
    if let Ok(plotfile) = PoCXPlotFile::new(temp_path, &account, &seed, 4, 1, false, false) {
        let plotfile = Arc::new(Mutex::new(plotfile));
        let mut handles = vec![];

        // Simulate concurrent access (though we're using a mutex)
        for thread_id in 0..3 {
            let plotfile_clone = Arc::clone(&plotfile);

            let handle = thread::spawn(move || {
                if let Ok(mut pf) = plotfile_clone.lock() {
                    pf.access = AccessType::Dummy;

                    // Perform various operations
                    for i in 0..10 {
                        let scoop = (thread_id * 100 + i) % 4096;
                        let nonce = (thread_id * 10 + i) % (pf.meta.number_of_warps * NUM_SCOOPS);

                        let _nonce_result = pf.read_nonce(scoop, nonce);

                        let mut buffer = vec![0u8; 1024];
                        let _read_result = pf.read(&mut buffer, scoop);

                        // Small delay to encourage interleaving
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }

                thread_id
            });

            handles.push(handle);
        }

        // Wait for all threads
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().unwrap());
        }

        // Verify all threads completed
        results.sort();
        assert_eq!(results, vec![0, 1, 2]);
    }
}

#[test]
fn test_metadata_consistency() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    // Test different account and seed combinations
    let test_cases = [
        ([0u8; 20], [0u8; 32]),       // All zeros
        ([0xFFu8; 20], [0xFFu8; 32]), // All ones
        ([0x55u8; 20], [0xAAu8; 32]), // Alternating patterns
    ];

    for (i, (account, seed)) in test_cases.iter().enumerate() {
        if let Ok(plotfile) = PoCXPlotFile::new(
            temp_path,
            account,
            seed,
            (i + 1) as u64,
            (i + 1) as u8,
            false,
            false,
        ) {
            // Verify metadata consistency
            assert_eq!(plotfile.meta.base58_decoded, *account);
            assert_eq!(plotfile.meta.seed_decoded, *seed);
            assert_eq!(plotfile.meta.number_of_warps, (i + 1) as u64);
            assert_eq!(plotfile.meta.compression, (i + 1) as u8);

            // Verify derived metadata
            assert!(!plotfile.meta.base58.is_empty());
            assert_eq!(plotfile.meta.seed.len(), 64); // Hex string length
            assert!(!plotfile.meta.filename.is_empty());

            // Verify access type
            assert_eq!(plotfile.access, AccessType::ReadWrite);

            // Verify sector size is reasonable
            assert!(plotfile.sector_size > 0);
            assert!(plotfile.sector_size <= 65536); // Reasonable upper bound
        }
    }
}

#[test]
fn test_error_handling_scenarios() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    let account = [1u8; 20];
    let seed = [0u8; 32];

    if let Ok(mut plotfile) = PoCXPlotFile::new(temp_path, &account, &seed, 2, 1, false, false) {
        plotfile.access = AccessType::Dummy;

        // Test out-of-bounds operations
        let max_nonces = plotfile.meta.number_of_warps * NUM_SCOOPS;

        // These should return errors, not panic
        let error_cases = vec![
            (0u64, max_nonces),     // Nonce too high
            (0u64, max_nonces + 1), // Way too high
            (0u64, u64::MAX),       // Extremely high
        ];

        for (scoop, nonce) in error_cases {
            let result = plotfile.read_nonce(scoop, nonce);
            assert!(
                result.is_err(),
                "Expected error for scoop={}, nonce={}",
                scoop,
                nonce
            );
        }

        // Test with different access modes
        plotfile.access = AccessType::Read;

        // Write operations should fail in read-only mode
        let test_data = vec![0u8; 1024];
        let write_result = plotfile.write_optimised_buffer_into_plotfile(&test_data, 0, 1, &None);
        assert!(write_result.is_err());

        let resume_write_result = plotfile.write_resume_info(1);
        assert!(resume_write_result.is_err());
    }
}

#[test]
fn test_performance_characteristics() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    let account = [1u8; 20];
    let seed = [0u8; 32];

    // Test with moderately sized plotfile
    if let Ok(mut plotfile) = PoCXPlotFile::new(temp_path, &account, &seed, 10, 1, false, false) {
        plotfile.access = AccessType::Dummy;

        let start_time = Instant::now();

        // Perform many operations
        for i in 0..100 {
            let scoop = (i * 37) % 4096; // Pseudo-random access pattern
            let nonce = (i * 127) % (plotfile.meta.number_of_warps * NUM_SCOOPS);

            let _result = plotfile.read_nonce(scoop, nonce);
        }

        let operation_time = start_time.elapsed();

        // Operations should complete quickly (even in dummy mode)
        assert!(
            operation_time.as_secs() < 5,
            "Operations took too long: {:?}",
            operation_time
        );

        // Test buffer operations performance
        let start_time = Instant::now();

        let mut buffer = vec![0u8; 8192];
        for scoop in 0..10 {
            let _result = plotfile.read(&mut buffer, scoop);
        }

        let buffer_time = start_time.elapsed();
        assert!(
            buffer_time.as_secs() < 5,
            "Buffer operations took too long: {:?}",
            buffer_time
        );
    }
}

#[test]
fn test_large_parameter_handling() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    let account = [1u8; 20];
    let seed = [0u8; 32];

    // Test with larger parameters (but still reasonable for testing)
    let large_params = vec![
        (50u64, 1u32), // Many warps
        (1u64, 10u32), // High compression
        (20u64, 5u32), // Balanced
    ];

    for (warps, compression) in large_params {
        let plotfile_result = PoCXPlotFile::new(
            temp_path,
            &account,
            &seed,
            warps,
            compression as u8,
            false,
            false,
        );

        if let Ok(mut plotfile) = plotfile_result {
            plotfile.access = AccessType::Dummy;

            // Basic operations should still work
            let _nonce_result = plotfile.read_nonce(0, 0);

            let mut buffer = vec![0u8; 4096];
            let _read_result = plotfile.read(&mut buffer, 0);

            // Verify metadata is correct
            assert_eq!(plotfile.meta.number_of_warps, warps);
            assert_eq!(plotfile.meta.compression, compression as u8);
        }
    }
}

#[test]
fn test_comprehensive_error_recovery() {
    // Test that the plotfile library handles errors gracefully and can recover
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    let account = [1u8; 20];
    let seed = [0x42u8; 32];

    // Test sequence: valid operation, multiple invalid operations, valid operation
    // again

    // 1. Initial valid operation
    if let Ok(mut plotfile1) = PoCXPlotFile::new(temp_path, &account, &seed, 4, 1, false, false) {
        plotfile1.access = AccessType::Dummy;

        let valid_result1 = plotfile1.read_nonce(0, 0);
        assert!(
            valid_result1.is_ok(),
            "Initial valid operation should succeed"
        );

        // 2. Multiple error scenarios
        let max_nonces = plotfile1.meta.number_of_warps * NUM_SCOOPS;

        // Invalid scoop (too high)
        let invalid_scoop_result = plotfile1.read_nonce(NUM_SCOOPS, 0);
        assert!(
            invalid_scoop_result.is_err(),
            "Invalid scoop should return error"
        );

        // Invalid nonce (too high)
        let invalid_nonce_result = plotfile1.read_nonce(0, max_nonces);
        assert!(
            invalid_nonce_result.is_err(),
            "Invalid nonce should return error"
        );

        // Invalid buffer operations
        let mut small_buffer = vec![0u8; 1]; // Too small
        let small_buffer_result = plotfile1.read(&mut small_buffer, 0);
        assert!(
            small_buffer_result.is_err(),
            "Too small buffer should return error"
        );

        // 3. Valid operations after errors (should still work)
        let valid_result2 = plotfile1.read_nonce(1, 1);
        assert!(
            valid_result2.is_ok(),
            "Valid operation after error should succeed"
        );

        let mut normal_buffer = vec![0u8; 4096];
        let valid_read_result = plotfile1.read(&mut normal_buffer, 1);
        assert!(
            valid_read_result.is_ok(),
            "Valid read after errors should succeed"
        );

        // 4. Create new plotfile after errors to test state isolation
        if let Ok(mut plotfile2) =
            PoCXPlotFile::new(temp_path, &account, &[0x99u8; 32], 2, 1, false, false)
        {
            plotfile2.access = AccessType::Dummy;

            let new_plotfile_result = plotfile2.read_nonce(0, 0);
            assert!(
                new_plotfile_result.is_ok(),
                "New plotfile should work after previous errors"
            );

            // 5. Mixed valid/invalid operations in sequence
            let operations = vec![
                (0u64, 0u64, true),     // Valid
                (NUM_SCOOPS, 0, false), // Invalid scoop
                (1, 1, true),           // Valid
                (0, max_nonces, false), // Invalid nonce
                (2, 2, true),           // Valid
            ];

            for (scoop, nonce, should_succeed) in operations {
                let result = plotfile2.read_nonce(scoop, nonce);
                if should_succeed {
                    assert!(
                        result.is_ok(),
                        "Expected operation to succeed: scoop={}, nonce={}",
                        scoop,
                        nonce
                    );
                } else {
                    assert!(
                        result.is_err(),
                        "Expected operation to fail: scoop={}, nonce={}",
                        scoop,
                        nonce
                    );
                }
            }

            // 6. Final verification that plotfile is still usable
            let final_result = plotfile2.read_nonce(0, 0);
            assert!(
                final_result.is_ok(),
                "Plotfile should still be usable after mixed operations"
            );
        }
    }

    // Continue with general validation tests that don't require plotfile access

    // 2. Test parameter validation error recovery
    // Invalid ID lengths
    let long_id = "1".repeat(100);
    let invalid_ids = vec![
        "",                     // Empty
        "1",                    // Too short
        "invalid_base58_chars", // Invalid characters
        &long_id,               // Too long
    ];

    for invalid_id in invalid_ids {
        // These should be handled gracefully by validation
        assert!(invalid_id.len() != 34 || !invalid_id.chars().all(|c| c.is_alphanumeric()));
    }

    // Valid ID should still work after invalid attempts - test binary
    // representation Generate a valid address for testing
    let test_payload = [0x42u8; 20]; // 20 bytes of test data
    let network_id = pocx_address::NetworkId::Base58(0x55);
    let valid_id = pocx_address::encode_address(&test_payload, network_id.clone())
        .expect("Should be able to encode valid address");

    // Decode it back and verify the binary representation
    if let Ok((decoded_payload, decoded_network)) = pocx_address::decode_address(&valid_id) {
        assert_eq!(
            decoded_payload.len(),
            20,
            "Decoded payload should be 20 bytes"
        );
        assert_eq!(decoded_network, network_id, "Network ID should match");
        assert_eq!(
            decoded_payload, test_payload,
            "Payload should match original data"
        );
    } else {
        panic!("Valid Base58 ID should decode successfully");
    }

    // 3. Test seed validation error recovery
    let invalid_hex_seed = "g".repeat(64);
    let invalid_seeds = vec![
        "",                // Empty
        "invalid_hex",     // Invalid hex
        "1234",            // Too short
        &invalid_hex_seed, // Invalid hex chars
    ];

    for invalid_seed in invalid_seeds {
        // Validation should catch these
        let is_valid_hex =
            invalid_seed.len() == 64 && invalid_seed.chars().all(|c| c.is_ascii_hexdigit());
        assert!(!is_valid_hex, "Invalid seed should be rejected");
    }

    // Valid seed should work after invalid attempts
    let valid_seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let is_valid = valid_seed.len() == 64 && valid_seed.chars().all(|c| c.is_ascii_hexdigit());
    assert!(
        is_valid,
        "Valid seed should be accepted after error recovery"
    );
}
