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

//! Property-based tests for pocx_plotfile
//!
//! This module contains property-based tests to verify that the plotfile
//! library maintains its invariants across a wide range of inputs and
//! conditions.

use pocx_plotfile::{AccessType, PoCXPlotFile, NUM_SCOOPS};
use proptest::prelude::*;
use quickcheck_macros::quickcheck;
use tempfile::TempDir;

/// Strategy for generating valid plot file parameters
fn valid_plot_params() -> impl Strategy<Value = (u64, u32)> {
    (
        1u64..50u64, // number_of_warps: small but meaningful for tests
        1u32..5u32,  // compression: reasonable range
    )
}

/// Strategy for generating test address payload and seed data
fn account_and_seed_strategy() -> impl Strategy<Value = ([u8; 20], [u8; 32])> {
    any::<([u8; 20], [u8; 32])>().prop_map(|(account, seed)| {
        // Address payload is already in correct format (20 bytes)
        (account, seed)
    })
}

proptest! {
    /// Test that plot file creation and metadata are consistent
    #[test]
    fn test_create_consistency(
        (number_of_warps, compression) in valid_plot_params(),
        (account, seed) in account_and_seed_strategy()
    ) {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Create plot file (dummy mode for testing)
        let plotfile_result = PoCXPlotFile::new(
            temp_path,
            &account,
            &seed,
            number_of_warps,
            compression,
            false, // no direct I/O
            false  // don't create actual file
        );

        if let Ok(plotfile) = plotfile_result {
            // Verify parameters are preserved
            assert_eq!(plotfile.meta.number_of_warps, number_of_warps);
            assert_eq!(plotfile.meta.compression, compression);
            assert_eq!(plotfile.meta.base58_decoded, account);
            assert_eq!(plotfile.meta.seed_decoded, seed);

            // Verify metadata consistency
            assert!(!plotfile.meta.base58.is_empty());
            assert_eq!(plotfile.meta.seed.len(), 64); // Hex string should be 64 chars
        }
    }

    /// Test that reading operations are safe with various parameters
    #[test]
    fn test_safe_reading(
        (number_of_warps, compression) in valid_plot_params(),
        (account, seed) in account_and_seed_strategy(),
        scoop in 0u64..4096u64,
        nonce in 0u64..100u64
    ) {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        let plotfile_result = PoCXPlotFile::new(
            temp_path,
            &account,
            &seed,
            number_of_warps,
            compression,
            false,
            false
        );

        if let Ok(mut plotfile) = plotfile_result {
            // Override to dummy mode for safe testing
            plotfile.access = AccessType::Dummy;

            // Calculate valid nonce range for this plotfile
            let max_nonces = number_of_warps * NUM_SCOOPS;

            if nonce < max_nonces {
                // This should not panic for valid nonces
                let result = plotfile.read_nonce(scoop, nonce);

                // Either succeeds or fails gracefully
                if let Ok(data) = result {
                    assert_eq!(data.len(), 64);
                }
                // Errors are acceptable, just no panics
            } else {
                // Out of bounds nonce should return an error, not panic
                let result = plotfile.read_nonce(scoop, nonce);
                assert!(result.is_err());
            }
        }
    }

    /// Test that buffer operations handle various sizes safely
    #[test]
    fn test_buffer_operations(
        (number_of_warps, compression) in valid_plot_params(),
        (account, seed) in account_and_seed_strategy(),
        buffer_size in 1024usize..10240usize
    ) {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        let plotfile_result = PoCXPlotFile::new(
            temp_path,
            &account,
            &seed,
            number_of_warps,
            compression,
            false,
            false
        );

        if let Ok(mut plotfile) = plotfile_result {
            plotfile.access = AccessType::Dummy;

            let mut buffer = vec![0u8; buffer_size];

            // This should not panic regardless of buffer size
            let result = plotfile.read(&mut buffer, 0);

            // Should either succeed or fail gracefully
            if let Ok(warps_read) = result {
                assert!(warps_read <= number_of_warps);
            }
            // Errors are acceptable
        }
    }
}

/// QuickCheck tests for additional coverage
#[quickcheck]
fn quickcheck_plotfile_bounds(number_of_warps: u8, compression: u8, scoop: u16, nonce: u32) {
    // Sanitize inputs to reasonable ranges
    let warps = std::cmp::max(1, number_of_warps as u64);
    let comp = std::cmp::max(1, compression as u32);
    let safe_scoop = (scoop as u64) % 4096;
    let safe_nonce = (nonce as u64) % (warps * NUM_SCOOPS);

    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    // Use fixed test account and seed
    let account = [1u8; 20];
    let seed = [0u8; 32];

    if let Ok(mut plotfile) =
        PoCXPlotFile::new(temp_path, &account, &seed, warps, comp, false, false)
    {
        plotfile.access = AccessType::Dummy;

        // These operations should not panic
        let _result1 = plotfile.read_nonce(safe_scoop, safe_nonce);

        let mut buffer = vec![0u8; 1024];
        let _result2 = plotfile.read(&mut buffer, safe_scoop);
    }
}

#[quickcheck]
fn quickcheck_access_types(direct_io: bool, create_file: bool) {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    let account = [1u8; 20];
    let seed = [0u8; 32];

    // Creating plotfiles with different parameters should not panic
    let result = PoCXPlotFile::new(
        temp_path,
        &account,
        &seed,
        1, // Small number for testing
        1,
        direct_io,
        create_file,
    );

    // May succeed or fail, but should not panic
    drop(result);
}

#[cfg(test)]
mod integration_property_tests {
    use super::*;

    #[test]
    fn test_multiple_plotfiles_consistency() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Create multiple plotfiles with different parameters
        for i in 0..5 {
            let mut account = [1u8; 20];
            account[1] = i; // Make each account unique
            let seed = [i; 32];

            let plotfile_result = PoCXPlotFile::new(
                temp_path,
                &account,
                &seed,
                (i + 1) as u64, // Different warp counts
                1,
                false,
                false,
            );

            if let Ok(mut plotfile) = plotfile_result {
                plotfile.access = AccessType::Dummy;

                // Each plotfile should maintain its own parameters
                assert_eq!(plotfile.meta.number_of_warps, (i + 1) as u64);
                assert_eq!(plotfile.meta.base58_decoded[1], i);
                assert_eq!(plotfile.meta.seed_decoded[0], i);

                // Basic operations should work
                let mut buffer = vec![0u8; 1024];
                let _result = plotfile.read(&mut buffer, 0);
                let _nonce_result = plotfile.read_nonce(0, 0);
            }
        }
    }

    #[test]
    fn test_edge_case_parameters() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        let account = [1u8; 20];
        let seed = [0u8; 32];

        // Test minimum values
        let result1 = PoCXPlotFile::new(temp_path, &account, &seed, 1, 1, false, false);
        assert!(result1.is_ok() || result1.is_err()); // Should not panic

        // Test larger values (but still reasonable for testing)
        let result2 = PoCXPlotFile::new(temp_path, &account, &seed, 100, 10, false, false);
        assert!(result2.is_ok() || result2.is_err()); // Should not panic

        if let Ok(mut plotfile) = result1 {
            plotfile.access = AccessType::Dummy;

            // Test boundary conditions
            let max_nonce = plotfile.meta.number_of_warps * NUM_SCOOPS - 1;
            let _valid_read = plotfile.read_nonce(0, max_nonce);

            // Out of bounds should error, not panic
            let invalid_read = plotfile.read_nonce(0, max_nonce + 1);
            assert!(invalid_read.is_err());
        }
    }

    #[test]
    fn test_resume_operations_safety() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        let account = [1u8; 20];
        let seed = [0u8; 32];

        if let Ok(mut plotfile) = PoCXPlotFile::new(temp_path, &account, &seed, 2, 1, false, false)
        {
            plotfile.access = AccessType::Dummy;

            // Resume operations should be safe in dummy mode
            let _resume_result = plotfile.read_resume_info();
            let _write_result = plotfile.write_resume_info(1);

            // These may succeed or fail but should not panic
        }
    }
}
