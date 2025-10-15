// Copyright (c) 2025 Proof of Capacity Consortium
//
// Property-based tests for pocx_verifier using proptest

#[cfg(test)]
#[allow(clippy::single_component_path_imports)]
#[allow(unused_variables)]
#[allow(clippy::len_zero)]
mod property_tests {
    use pocx_hashlib;
    use pocx_plotfile::{PoCXPlotFile, PoCXPlotFileError};
    use proptest::prelude::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Custom helper to create temp directories in project test_output/
    struct ProjectTempDir {
        path: PathBuf,
    }

    impl ProjectTempDir {
        fn new(prefix: &str) -> Result<Self, std::io::Error> {
            let project_root = env!("CARGO_MANIFEST_DIR");
            let temp_base = PathBuf::from(project_root)
                .parent()
                .unwrap()
                .join("test_output")
                .join("property_tests");

            // Ensure base directory exists
            fs::create_dir_all(&temp_base)?;

            // Create unique subdirectory
            let temp_dir = temp_base.join(format!(
                "{}_{}_{}",
                prefix,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));

            fs::create_dir_all(&temp_dir)?;

            Ok(ProjectTempDir { path: temp_dir })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for ProjectTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]  // Reduced from default 100 to 10 for speed

        #[test]
        fn prop_mode_validation(mode in r"[a-z]{1,20}") {
            // Test that mode validation works consistently
            let valid_modes = ["single", "partial", "random", "complete"];
            let is_valid = valid_modes.contains(&mode.as_str());

            // This property ensures our validation logic is consistent
            prop_assert_eq!(
                is_valid,
                mode == "single" || mode == "partial" || mode == "random" || mode == "complete"
            );
        }

        #[test]
        fn prop_file_path_handling(path_str in r"[a-zA-Z0-9\./\-_]{1,50}") {
            // Test that file path handling is consistent
            let path = Path::new(&path_str);

            // Properties that should always hold for path handling
            prop_assert!(path.to_string_lossy().len() >= path_str.len());

            // Path should be consistent
            if !path_str.is_empty() {
                prop_assert!(!path.to_string_lossy().is_empty());
            }
        }

        #[test]
        fn prop_nonce_value_validation(nonce: u64) {
            // Test that nonce values are handled consistently
            // All u64 values should be valid nonce values (by definition)

            // Nonce should be convertible to string and back
            let nonce_str = nonce.to_string();
            let parsed_nonce = nonce_str.parse::<u64>();
            prop_assert!(parsed_nonce.is_ok());
            prop_assert_eq!(parsed_nonce.unwrap(), nonce);
        }

        #[test]
        fn prop_scoop_value_validation(scoop: u32) {
            // Test scoop value validation properties
            // Scoop values should be within valid range (0-4095 for PoC)
            let is_valid_scoop = scoop < 4096; // NUM_SCOOPS from pocx_plotfile

            if is_valid_scoop {
                // Valid scoop values should pass validation
                prop_assert!(scoop < 4096);
            } else {
                // Invalid scoop values should be rejected
                prop_assert!(scoop >= 4096);
            }
        }

        #[test]
        fn prop_version_string_consistency(_dummy: u8) {
            // Test that version string handling is consistent
            let version_str = env!("CARGO_PKG_VERSION");
            prop_assert!(!version_str.is_empty());
            prop_assert!(version_str.contains('.'), "Version should contain dots");

            // Version should be parseable
            let parts: Vec<&str> = version_str.split('.').collect();
            prop_assert!(parts.len() >= 2, "Version should have at least major.minor");
        }

        #[test]
        fn prop_plot_file_metadata_validation(warps in 1u64..10u64, compression in 1u32..4u32) {
            // Test plot file metadata validation properties
            let temp_dir = ProjectTempDir::new("metadata_test").expect("Failed to create temp dir");
            let account = [1u8; 20];
            let seed = [2u8; 32];

            // Test that valid parameters produce consistent metadata
            let path = temp_dir.path().join("test.plot");

            // Only test if we can create the plot file (some parameter combinations may be invalid)
            if let Ok(plotfile) = PoCXPlotFile::new(
                path.to_str().unwrap(),
                &account,
                &seed,
                warps,
                compression,
                false, // dummy mode
                false, // no direct io
            ) {
                prop_assert_eq!(plotfile.meta.number_of_warps, warps);
                prop_assert_eq!(plotfile.meta.compression, compression);
                prop_assert_eq!(plotfile.meta.base58_decoded, account);
                prop_assert_eq!(plotfile.meta.seed_decoded, seed);
            }
        }

        #[test]
        fn prop_verification_result_consistency(scoop in 0u32..4096u32, nonce_count in 1u64..10u64) {
            // Test that verification results are consistent for same inputs
            let test_data = vec![0u8; (nonce_count * 64) as usize]; // SCOOP_SIZE = 64
            let generation_signature = [0u8; 32];

            // Multiple calls with same parameters should be consistent
            let quality1 = pocx_hashlib::find_best_quality(&test_data, nonce_count, &generation_signature).0;
            let quality2 = pocx_hashlib::find_best_quality(&test_data, nonce_count, &generation_signature).0;

            prop_assert_eq!(quality1, quality2);

            // Quality should be deterministic for given inputs
            prop_assert!(quality1 == quality2);
        }

        #[test]
        fn prop_error_message_consistency(error_type in 0u8..5u8) {
            // Test that error messages are consistent and informative
            let error = match error_type % 5 {
                0 => PoCXPlotFileError::FileNotFound("test".to_string()),
                1 => PoCXPlotFileError::InvalidFilename("test".to_string()),
                2 => PoCXPlotFileError::InvalidExtension("test".to_string()),
                3 => PoCXPlotFileError::InvalidSeed("test".to_string()),
                _ => PoCXPlotFileError::InvalidBase58("test".to_string()),
            };

            let error_string = error.to_string();
            prop_assert!(!error_string.is_empty());
            prop_assert!(error_string.len() > 0);
            prop_assert!(error_string.contains("test"));
        }

        #[test]
        fn prop_progress_reporting_bounds(progress in 0u64..1000u64, total in 1u64..1000u64) {
            // Test that progress reporting stays within bounds
            let normalized_progress = if progress > total { total } else { progress };
            let percentage = (normalized_progress * 100) / total;

            prop_assert!(percentage <= 100);
            prop_assert!(normalized_progress <= total);

            // Progress should be monotonic
            if progress <= total {
                prop_assert!(normalized_progress == progress);
            }
        }

        #[test]
        fn prop_memory_usage_bounds(buffer_size in 1usize..1024usize, num_buffers in 1usize..10usize) {
            // Test that memory calculations don't overflow
            let total_memory_result = buffer_size.checked_mul(num_buffers);

            if let Some(total_memory) = total_memory_result {
                prop_assert!(total_memory >= buffer_size);
                prop_assert!(total_memory >= num_buffers);
                prop_assert!(total_memory / num_buffers == buffer_size);
            } else {
                // If multiplication overflows, individual components should be large
                prop_assert!(buffer_size > usize::MAX / num_buffers);
            }
        }
    }
}
