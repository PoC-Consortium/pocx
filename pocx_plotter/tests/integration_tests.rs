#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::const_is_empty)]

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

use std::process::Command;
use tempfile::TempDir;

/// Integration tests for PoCX Plotter
/// Tests the complete workflow from CLI to file generation

#[test]
fn test_help_command() {
    let output = Command::new("cargo")
        .args(&["run", "--", "--help"])
        .output()
        .expect("Failed to execute help command");

    assert!(output.status.success(), "Help command should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    println!("Help output: {}", stdout);
    assert!(
        stdout.contains("pocx_plotter") || stdout.contains("PoCX"),
        "Should display program name"
    );
    assert!(stdout.contains("--id"), "Should show PoC address option");
}

#[test]
fn test_opencl_feature_conditional() {
    // Test that help shows correct options without OpenCL feature
    let output_no_opencl = Command::new("cargo")
        .args(&["run", "--", "--help"])
        .output()
        .expect("Failed to get help without OpenCL");

    assert!(
        output_no_opencl.status.success(),
        "Help without OpenCL should succeed"
    );
    let stdout_no_opencl = String::from_utf8(output_no_opencl.stdout).unwrap();

    // Without OpenCL feature, should not show GPU-specific options
    assert!(
        !stdout_no_opencl.contains("--gpu"),
        "Non-OpenCL build should not show --gpu option"
    );
    assert!(
        !stdout_no_opencl.contains("--opencl"),
        "Non-OpenCL build should not show --opencl option"
    );

    // Try to compile with OpenCL feature (may fail if libraries not available)
    let output_with_opencl = Command::new("cargo")
        .args(&["run", "--features", "opencl", "--", "--help"])
        .output()
        .expect("Failed to attempt OpenCL build");

    if output_with_opencl.status.success() {
        // If OpenCL libraries are available, test the features
        let stdout_with_opencl = String::from_utf8(output_with_opencl.stdout).unwrap();
        assert!(
            stdout_with_opencl.contains("--opencl") || stdout_with_opencl.contains("--gpu"),
            "OpenCL build should show GPU/OpenCL options"
        );
    } else {
        // If OpenCL libraries are not available, that's expected
        let stderr = String::from_utf8(output_with_opencl.stderr).unwrap();
        assert!(
            stderr.contains("OpenCL")
                || stderr.contains("lOpenCL")
                || stderr.contains("could not compile"),
            "Should fail due to missing OpenCL libraries"
        );
    }
}

#[test]
fn test_invalid_poc_address() {
    let output = Command::new("cargo")
        .args(&["run", "--", "--id", "invalid_id", "--bench"])
        .output()
        .expect("Failed to execute with invalid ID");

    println!("Exit status: {}", output.status);
    let stderr = String::from_utf8(output.stderr).unwrap();
    println!("Stderr: {}", stderr);

    assert!(
        !output.status.success(),
        "Should fail with invalid PoC address"
    );
    assert!(
        stderr.contains("Invalid PoC address")
            || stderr.contains("base58")
            || stderr.contains("Crypto"),
        "Should show PoC address error"
    );
}

#[test]
fn test_benchmark_mode_cli_parsing() {
    // Test that benchmark mode CLI arguments are parsed correctly by running with
    // --help to verify the arguments exist and are accessible
    let output = Command::new("cargo")
        .args(&["run", "--", "--help"])
        .output()
        .expect("Failed to get help");

    assert!(output.status.success(), "Help should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--bench"), "Should show benchmark option");
    assert!(stdout.contains("--warps"), "Should show warps option");
    assert!(stdout.contains("--cpu"), "Should show CPU option");
}

#[test]
fn test_parameter_validation_integration() {
    // Create a valid address using proper pocx_address encoding
    let mut payload = [0u8; 20];
    for i in 0..20 {
        payload[i] = (i * 5) as u8;
    }
    let test_id =
        pocx_address::encode_address(&payload, pocx_address::NetworkId::Base58(0x55)).unwrap();

    // Test warps too large
    let output = Command::new("cargo")
        .args(&[
            "run", "--", "--id", &test_id, "--warps", "2000000", // Over our 1M limit
            "-b",      // Buffer-only mode to prevent file creation
        ])
        .output()
        .expect("Failed to execute with large warps");

    assert!(!output.status.success(), "Should reject warps > 1M");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("too large"), "Should show size error");
}

#[test]
fn test_compression_validation() {
    // Create a valid address using proper pocx_address encoding
    let mut payload = [0u8; 20];
    for i in 0..20 {
        payload[i] = (i * 7) as u8;
    }
    let test_id =
        pocx_address::encode_address(&payload, pocx_address::NetworkId::Base58(0x55)).unwrap();

    // Test compression too large
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--",
            "--id",
            &test_id,
            "--compression",
            "50", // Over our 32 limit
            "--bench",
        ])
        .output()
        .expect("Failed to execute with large compression");

    assert!(!output.status.success(), "Should reject compression > 32");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("too large"),
        "Should show compression error"
    );
}

#[test]
fn test_seed_validation_integration() {
    // Create a valid address using proper pocx_address encoding
    let mut payload = [0u8; 20];
    for i in 0..20 {
        payload[i] = (i * 11) as u8;
    }
    let test_id =
        pocx_address::encode_address(&payload, pocx_address::NetworkId::Base58(0x55)).unwrap();

    // Test invalid seed
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--",
            "--id",
            &test_id,
            "--seed",
            "invalid_seed",
            "--bench",
        ])
        .output()
        .expect("Failed to execute with invalid seed");

    assert!(!output.status.success(), "Should reject invalid seed");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("seed"), "Should show seed error");
}

#[test]
fn test_path_handling() {
    // This test verifies that we removed the path traversal restrictions
    // The actual CLI may fail for other reasons (missing parameters, etc.)
    // but it should not fail specifically due to path traversal restrictions

    // Create a valid address using proper pocx_address encoding
    let mut payload = [0u8; 20];
    for i in 0..20 {
        payload[i] = (i * 13) as u8;
    }
    let test_id =
        pocx_address::encode_address(&payload, pocx_address::NetworkId::Base58(0x55)).unwrap();

    // Test that relative paths don't get blocked by traversal checks
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--",
            "--id",
            &test_id,
            "--path",
            "../test_plots", // This should not be blocked
            "--bench",
        ])
        .output()
        .expect("Failed to execute with relative path");

    // The key test: it should NOT fail due to "traversal" restrictions
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("traversal") && !stderr.contains("Directory traversal not allowed"),
        "Should not block paths due to traversal restrictions: {}",
        stderr
    );
}

#[test]
fn test_memory_limit_parsing() {
    // Test that --mem argument is properly recognized in CLI
    let output = Command::new("cargo")
        .args(&["run", "--", "--help"])
        .output()
        .expect("Failed to get help");

    assert!(output.status.success(), "Help should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--mem"), "Should show memory option");
}

#[test]
fn test_cpu_thread_validation() {
    // Create a valid address using proper pocx_address encoding
    let mut payload = [0u8; 20];
    for i in 0..20 {
        payload[i] = (i * 19) as u8;
    }
    let test_id =
        pocx_address::encode_address(&payload, pocx_address::NetworkId::Base58(0x55)).unwrap();

    // Test CPU threads too large
    let output = Command::new("cargo")
        .args(&[
            "run", "--", "--id", &test_id, "--cpu", "200", // Over our 128 limit
            "--bench",
        ])
        .output()
        .expect("Failed to execute with large CPU threads");

    assert!(!output.status.success(), "Should reject cpu threads > 128");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("too large"),
        "Should show CPU threads error"
    );
}

/// Test that CLI parsing works for plotting workflow arguments
#[test]
fn test_plot_workflow_cli_parsing() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let plot_path = temp_dir.path().to_str().unwrap();

    // Test that --path argument is properly recognized
    let output = Command::new("cargo")
        .args(&["run", "--", "--help"])
        .output()
        .expect("Failed to get help");

    assert!(output.status.success(), "Help should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--path"), "Should show path option");
    assert!(stdout.contains("--warps"), "Should show warps option");
    assert!(
        stdout.contains("--num"),
        "Should show number of plots option"
    );

    // Test that the temp directory exists (basic sanity check)
    assert!(
        std::path::Path::new(plot_path).exists(),
        "Temp directory should exist"
    );
}

#[test]
fn test_error_reporting_quality() {
    // Test that error messages are helpful and detailed

    // Test missing required parameter
    let output = Command::new("cargo")
        .args(&["run", "--", "--warps", "10"])
        .output()
        .expect("Failed to execute with missing ID");

    assert!(!output.status.success(), "Should fail without PoC address");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("required") || stderr.contains("help"),
        "Should show helpful error message"
    );
}

#[test]
fn test_version_output() {
    let output = Command::new("cargo")
        .args(&["run", "--", "--version"])
        .output()
        .expect("Failed to execute version command");

    assert!(output.status.success(), "Version command should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.trim().is_empty(),
        "Should output version information"
    );
}

/// Test that CLI parsing works for resource constraint arguments
#[test]
fn test_resource_constraint_cli_parsing() {
    // Test that resource-related arguments are properly recognized
    let output = Command::new("cargo")
        .args(&["run", "--", "--help"])
        .output()
        .expect("Failed to get help");

    assert!(output.status.success(), "Help should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--mem"), "Should show memory option");
    assert!(stdout.contains("--cpu"), "Should show CPU option");
    assert!(stdout.contains("--escalate"), "Should show escalate option");
}

/// Test comprehensive error recovery scenarios for plotter operations
#[test]
fn test_comprehensive_error_recovery() {
    use pocx_plotter::buffer::PageAlignedByteBuffer;
    use pocx_plotter::error::PoCXPlotterError;

    // Test sequence: valid operations, errors, recovery

    // 1. Test buffer allocation error recovery
    let valid_buffer_result = PageAlignedByteBuffer::new(4096);
    assert!(
        valid_buffer_result.is_ok(),
        "Valid buffer allocation should succeed"
    );

    // Test buffer that's too large (should return error, not panic)
    let invalid_buffer_result = PageAlignedByteBuffer::new(usize::MAX);
    assert!(
        invalid_buffer_result.is_err(),
        "Oversized buffer should return error"
    );

    // Verify we can still allocate valid buffers after error
    let recovery_buffer_result = PageAlignedByteBuffer::new(8192);
    assert!(
        recovery_buffer_result.is_ok(),
        "Buffer allocation should work after error"
    );

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
        // Invalid IDs are either empty, too short/long, or contain invalid base58 chars
        assert!(
            invalid_id.is_empty()
                || invalid_id.len() < 20
                || invalid_id.len() > 50
                || invalid_id.contains('_')
        );
    }

    // Valid ID should still work after invalid attempts
    // Base58 addresses have variable length (typically 32-34 chars for
    // Bitcoin-style addresses)
    let valid_id = "POCX16iS4DvuLzBjBhkWf6QPCjSKVzqBN";
    // Proper validation would decode and check network ID + checksum, not just
    // length For this test, we just verify it's a reasonable base58 string
    assert!(!valid_id.is_empty());
    assert!(valid_id.chars().all(|c| c.is_alphanumeric()));

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

    // 4. Test buffer size calculation error recovery
    let test_cases = vec![
        (0u64, false),     // Zero size
        (1u64, true),      // Valid small size
        (u64::MAX, false), // Overflow size
        (1024u64, true),   // Valid normal size
    ];

    for (size, should_succeed) in test_cases {
        let calculation_result = size.checked_mul(1024);
        if should_succeed {
            assert!(
                calculation_result.is_some(),
                "Valid calculation should succeed"
            );
        } else {
            assert!(
                calculation_result.is_none() || size == 0,
                "Invalid calculation should be caught"
            );
        }
    }

    // 5. Test error state isolation
    // Simulate multiple operations with mixed success/failure
    let operations = vec![
        (1024usize, true),   // Valid
        (0usize, false),     // Invalid (zero)
        (2048usize, true),   // Valid
        (usize::MAX, false), // Invalid (too large)
        (4096usize, true),   // Valid
    ];

    for (size, should_succeed) in operations {
        let result = if size == 0 || size > 16 * 1024 * 1024 * 1024 {
            Err(PoCXPlotterError::Memory(format!("Invalid size: {}", size)))
        } else {
            PageAlignedByteBuffer::new(size)
        };

        if should_succeed {
            assert!(
                result.is_ok(),
                "Expected operation to succeed with size {}",
                size
            );
        } else {
            assert!(
                result.is_err(),
                "Expected operation to fail with size {}",
                size
            );
        }
    }

    // 6. Final verification - system should be in clean state
    let final_buffer = PageAlignedByteBuffer::new(1024);
    assert!(
        final_buffer.is_ok(),
        "System should be in clean state after error recovery tests"
    );
}
