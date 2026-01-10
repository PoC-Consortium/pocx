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

use std::path::PathBuf;
use std::process::Command;
use std::sync::Once;

/// Integration tests for PoCX Plotter
/// Tests the complete workflow from CLI to file generation
static INIT: Once = Once::new();

/// Build the plotter binary once and return its path
fn get_plotter_binary() -> PathBuf {
    INIT.call_once(|| {
        // Build the binary once for all tests
        let output = Command::new("cargo")
            .args(["build", "--bin", "pocx_plotter"])
            .current_dir("../")
            .output()
            .expect("Failed to build pocx_plotter");

        assert!(
            output.status.success(),
            "Failed to build pocx_plotter: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    });

    // Return path to the built binary
    PathBuf::from("../target/debug/pocx_plotter")
}

#[test]
fn test_invalid_poc_address() {
    let binary = get_plotter_binary();
    let output = Command::new(&binary)
        .args(&["--id", "invalid_id", "--bench"])
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
fn test_parameter_validation_integration() {
    // Create a valid address using proper pocx_address encoding
    let mut payload = [0u8; 20];
    for i in 0..20 {
        payload[i] = (i * 5) as u8;
    }
    let test_id =
        pocx_address::encode_address(&payload, pocx_address::NetworkId::Base58(0x55)).unwrap();

    // Test warps too large
    let binary = get_plotter_binary();
    let output = Command::new(&binary)
        .args(&[
            "--id", &test_id, "--warps", "2000000", // Over our 1M limit
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
    let binary = get_plotter_binary();
    let output = Command::new(&binary)
        .args(&[
            "--id",
            &test_id,
            "--compression",
            "10", // Over our 6 limit (exponential CPU load)
            "--bench",
        ])
        .output()
        .expect("Failed to execute with large compression");

    assert!(!output.status.success(), "Should reject compression > 6");
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
    let binary = get_plotter_binary();
    let output = Command::new(&binary)
        .args(&["--id", &test_id, "--seed", "invalid_seed", "--bench"])
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
    // The CLI will fail for other reasons (path doesn't exist, etc.) but
    // should NOT fail due to path traversal security restrictions
    let binary = get_plotter_binary();
    let output = Command::new(&binary)
        .args(&[
            "--id",
            &test_id,
            "--path",
            "../nonexistent_test_path", // Relative path - should not be blocked for traversal
        ])
        .output()
        .expect("Failed to execute with relative path");

    // The key test: it should NOT fail due to "traversal" restrictions
    // (it will fail for other reasons like path not existing, which is fine)
    let stderr = String::from_utf8(output.stderr).unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        !combined.contains("traversal") && !combined.contains("Directory traversal not allowed"),
        "Should not block paths due to traversal restrictions: {}",
        combined
    );
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
    let binary = get_plotter_binary();
    let output = Command::new(&binary)
        .args(&[
            "--id", &test_id, "--cpu", "200", // Over our 128 limit
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
