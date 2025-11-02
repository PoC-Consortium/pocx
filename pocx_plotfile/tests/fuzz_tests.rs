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

//! Fuzzing tests for pocx_plotfile
//!
//! These tests use arbitrary data to find edge cases and potential panics
//! in the plotfile library.

use arbitrary::{Arbitrary, Unstructured};
use pocx_plotfile::{AccessType, PoCXPlotFile, NUM_SCOOPS};
use tempfile::TempDir;

/// Arbitrary implementation for plot file parameters to enable fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzPlotFileParams {
    number_of_warps: u64,
    compression: u32,
    direct_io: bool,
    create_file: bool,
}

impl FuzzPlotFileParams {
    fn sanitized(self) -> Self {
        // Sanitize parameters to prevent resource exhaustion while fuzzing
        FuzzPlotFileParams {
            // Limit warps to prevent huge files during fuzzing
            number_of_warps: std::cmp::min(self.number_of_warps % 20 + 1, 10),
            // Limit compression to reasonable values
            compression: std::cmp::min(self.compression % 10 + 1, 5),
            direct_io: self.direct_io,
            // Always false to avoid creating actual files during fuzzing
            create_file: false,
        }
    }
}

/// Fuzz test for plot file creation and basic operations
fn fuzz_plot_file_creation(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut unstructured = Unstructured::new(data);

    // Generate fuzzed parameters
    let fuzz_params: FuzzPlotFileParams =
        FuzzPlotFileParams::arbitrary(&mut unstructured)?.sanitized();

    // Generate account and seed from fuzz data
    let mut account = [0u8; 20];
    let mut seed = [0u8; 32];

    // Fill account and seed with fuzz data
    for item in &mut account {
        *item = unstructured.arbitrary().unwrap_or(0);
    }
    for item in &mut seed {
        *item = unstructured.arbitrary().unwrap_or(0);
    }

    // Ensure valid account format
    account[0] = 0x01; // Version byte

    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path().to_str().unwrap();

    // Test plot file creation
    let plotfile_result = PoCXPlotFile::new(
        temp_path,
        &account,
        &seed,
        fuzz_params.number_of_warps,
        fuzz_params.compression as u8,
        fuzz_params.direct_io,
        fuzz_params.create_file,
    );

    if let Ok(mut plotfile) = plotfile_result {
        // Override to dummy mode for safe fuzzing
        plotfile.access = AccessType::Dummy;

        // Test file operations with remaining fuzz data
        if !unstructured.is_empty() {
            fuzz_file_operations(&mut plotfile, &mut unstructured)?;
        }
    }

    Ok(())
}

fn fuzz_file_operations(
    plotfile: &mut PoCXPlotFile,
    unstructured: &mut Unstructured,
) -> Result<(), Box<dyn std::error::Error>> {
    // Fuzz read operations
    for _ in 0..10 {
        // Limit iterations to prevent infinite loops
        if unstructured.len() < 4 {
            break;
        }

        // Generate fuzzed read parameters
        let scoop = (unstructured.arbitrary::<u8>().unwrap_or(0) as u64) % 4096;
        let nonce_byte1 = unstructured.arbitrary::<u8>().unwrap_or(0) as u64;
        let nonce_byte2 = unstructured.arbitrary::<u8>().unwrap_or(0) as u64;
        let nonce = (nonce_byte1 << 8) | nonce_byte2;

        // Limit nonce to reasonable range for fuzzing
        let max_nonces = plotfile.meta.number_of_warps * NUM_SCOOPS;
        let safe_nonce = nonce % max_nonces;

        // This should not panic regardless of parameters
        let _result = plotfile.read_nonce(scoop, safe_nonce);

        // Test buffer operations
        let buffer_size_byte = unstructured.arbitrary::<u8>().unwrap_or(1);
        let buffer_size = std::cmp::min((buffer_size_byte as usize) * 64 + 64, 4096);
        let mut buffer = vec![0u8; buffer_size];

        let _read_result = plotfile.read(&mut buffer, scoop);
    }

    Ok(())
}

fn fuzz_metadata_operations(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut unstructured = Unstructured::new(data);

    while unstructured.len() >= 57 {
        // 25 + 32 bytes for account and seed
        let mut account = [0u8; 20];
        let mut seed = [0u8; 32];

        // Extract account and seed from fuzz data
        for item in &mut account {
            *item = unstructured.arbitrary()?;
        }
        for item in &mut seed {
            *item = unstructured.arbitrary()?;
        }

        // Ensure valid account format
        account[0] = 0x01;

        let warps: u8 = unstructured.arbitrary()?;
        let compression: u8 = unstructured.arbitrary()?;

        // Sanitize parameters
        let safe_warps = std::cmp::max(1, warps as u64 % 10);
        let safe_compression = std::cmp::max(1, compression as u32 % 5);

        let temp_dir = TempDir::new()?;
        let temp_path = temp_dir.path().to_str().unwrap();

        // Test plotfile creation with fuzzed metadata
        let plotfile_result = PoCXPlotFile::new(
            temp_path,
            &account,
            &seed,
            safe_warps,
            safe_compression as u8,
            false,
            false,
        );

        if let Ok(plotfile) = plotfile_result {
            // Verify metadata consistency (should not panic)
            assert_eq!(plotfile.meta.base58_decoded, account);
            assert_eq!(plotfile.meta.seed_decoded, seed);
            assert_eq!(plotfile.meta.number_of_warps, safe_warps);
            assert_eq!(plotfile.meta.compression, safe_compression as u8);
        }
    }

    Ok(())
}

fn fuzz_access_patterns(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut unstructured = Unstructured::new(data);

    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path().to_str().unwrap();

    let account = [1u8; 20];
    let seed = [0u8; 32];

    if let Ok(mut plotfile) = PoCXPlotFile::new(temp_path, &account, &seed, 3, 1, false, false) {
        plotfile.access = AccessType::Dummy;

        // Fuzz different access patterns
        while unstructured.len() >= 4 {
            let access_type_byte: u8 = unstructured.arbitrary()?;

            // Map to access types
            let new_access = match access_type_byte % 3 {
                0 => AccessType::Read,
                1 => AccessType::ReadWrite,
                _ => AccessType::Dummy,
            };

            plotfile.access = new_access;

            // Test operations with different access types
            let scoop: u8 = unstructured.arbitrary()?;
            let nonce_low: u8 = unstructured.arbitrary()?;
            let nonce_high: u8 = unstructured.arbitrary()?;

            let safe_scoop = (scoop as u64) % 4096;
            let nonce = ((nonce_high as u64) << 8) | (nonce_low as u64);
            let max_nonces = plotfile.meta.number_of_warps * NUM_SCOOPS;
            let safe_nonce = nonce % max_nonces;

            // These should not panic regardless of access type
            let _read_result = plotfile.read_nonce(safe_scoop, safe_nonce);

            let mut buffer = vec![0u8; 1024];
            let _buffer_result = plotfile.read(&mut buffer, safe_scoop);

            // Test resume operations
            let _resume_read = plotfile.read_resume_info();

            // Write operations (may fail for Read access, but shouldn't panic)
            let _resume_write = plotfile.write_resume_info(1);
        }
    }

    Ok(())
}

// Test harnesses for different fuzzing scenarios
#[cfg(test)]
mod fuzz_tests {
    use super::*;

    #[test]
    fn fuzz_comprehensive_plotfile_operations() {
        // Test with various byte patterns
        let test_cases = vec![
            vec![0u8; 100],                            // All zeros
            vec![0xFFu8; 100],                         // All ones
            (0u8..=255u8).cycle().take(500).collect(), // Repeating pattern
            vec![0x55u8; 200],                         /* Alternating bits
                                                        * pattern */
            vec![0xAAu8; 200], // Opposite alternating bits
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF].repeat(20), // Hex pattern
        ];

        for test_data in test_cases {
            let _ = fuzz_plot_file_creation(&test_data);
            let _ = fuzz_metadata_operations(&test_data);
            let _ = fuzz_access_patterns(&test_data);
        }
    }

    #[test]
    fn fuzz_edge_case_parameters() {
        // Test with edge case byte sequences
        let edge_cases = vec![
            vec![0u8, 0u8, 0u8],                    // Minimal data
            vec![0xFFu8; 200],                      // Maximum values
            (0u8..100u8).collect(),                 // Sequential values
            (0u8..100u8).rev().collect::<Vec<_>>(), // Reverse sequential
        ];

        for test_data in edge_cases {
            // Extend data to minimum required length
            let mut extended_data = test_data;
            while extended_data.len() < 100 {
                extended_data.extend_from_slice(&[0x42u8; 10]);
            }

            // Test operations that should not panic
            let _ = fuzz_plot_file_creation(&extended_data);
            let _ = fuzz_metadata_operations(&extended_data);
        }
    }

    #[test]
    fn fuzz_boundary_values() {
        // Test with values that might trigger boundary conditions
        let boundary_test = |base_value: u8| {
            let mut test_data = vec![base_value; 200];

            // Insert some boundary values at specific positions
            if test_data.len() > 100 {
                test_data[50] = 0xFF; // Maximum value
                test_data[51] = 0x00; // Minimum value
                test_data[52] = 0x7F; // Mid-range value
                test_data[53] = 0x80; // High bit set
            }

            let _ = fuzz_plot_file_creation(&test_data);
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

        // Test concurrent fuzzing (though operations are still serialized by mutex on
        // test data)
        for thread_id in 0..3 {
            let data_clone = Arc::clone(&shared_data);

            let handle = thread::spawn(move || {
                let thread_data = data_clone[thread_id * 100..(thread_id + 1) * 100].to_vec();

                // Each thread runs fuzz tests with different data slices
                let _ = fuzz_plot_file_creation(&thread_data);
                let _ = fuzz_access_patterns(&thread_data);

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
            vec![0u8; 1000],    // Large with zeros
            vec![0xFFu8; 1000], // Large with max values
        ];

        for test_data in malformed_cases {
            // These should handle errors gracefully, not panic
            let _ = fuzz_plot_file_creation(&test_data);
            let _ = fuzz_metadata_operations(&test_data);
            let _ = fuzz_access_patterns(&test_data);
        }
    }

    #[test]
    fn fuzz_specific_operation_sequences() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        let account = [1u8; 20];
        let seed = [0u8; 32];

        if let Ok(mut plotfile) = PoCXPlotFile::new(temp_path, &account, &seed, 2, 1, false, false)
        {
            plotfile.access = AccessType::Dummy;

            // Test specific sequences that might cause issues
            let operation_sequences = vec![
                // Sequence 1: Read operations
                vec![0x00, 0x00, 0x00, 0x00], // All zeros
                vec![0xFF, 0xFF, 0xFF, 0xFF], // All max
                vec![0x00, 0xFF, 0x00, 0xFF], // Alternating
                vec![0x12, 0x34, 0x56, 0x78], // Random values
            ];

            for sequence in operation_sequences {
                for i in 0..sequence.len() / 2 {
                    let scoop = (sequence[i * 2] as u64) % 4096;
                    let nonce =
                        (sequence[i * 2 + 1] as u64) % (plotfile.meta.number_of_warps * NUM_SCOOPS);

                    // Should not panic
                    let _result = plotfile.read_nonce(scoop, nonce);
                }
            }

            // Test resume operations with fuzzed values
            for &warp_value in &[0u64, 1u64, 2u64, u64::MAX] {
                let safe_warp = warp_value % (plotfile.meta.number_of_warps + 1);
                let _result = plotfile.write_resume_info(safe_warp);
            }
        }
    }
}
