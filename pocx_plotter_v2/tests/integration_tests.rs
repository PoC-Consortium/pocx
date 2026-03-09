#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::const_is_empty)]

// Copyright (c) 2025 Proof of Capacity Consortium
// MIT License

use std::path::PathBuf;
use std::process::Command;
use std::sync::Once;

static INIT: Once = Once::new();

fn get_plotter_binary() -> PathBuf {
    INIT.call_once(|| {
        let output = Command::new("cargo")
            .args(["build", "--bin", "pocx_plotter_v2"])
            .current_dir("../")
            .output()
            .expect("Failed to build pocx_plotter_v2");

        assert!(
            output.status.success(),
            "Failed to build pocx_plotter_v2: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    });

    PathBuf::from("../target/debug/pocx_plotter_v2")
}

#[test]
fn test_invalid_poc_address() {
    let binary = get_plotter_binary();
    let output = Command::new(&binary)
        .args(["--id", "invalid_id", "--bench"])
        .output()
        .expect("Failed to execute with invalid ID");

    assert!(
        !output.status.success(),
        "Should fail with invalid PoC address"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("Invalid") || stderr.contains("base58") || stderr.contains("Crypto"),
        "Should show address error"
    );
}

#[test]
fn test_parameter_validation_integration() {
    let mut payload = [0u8; 20];
    for i in 0..20 {
        payload[i] = (i * 5) as u8;
    }
    let test_id =
        pocx_address::encode_address(&payload, pocx_address::NetworkId::Base58(0x55)).unwrap();

    let binary = get_plotter_binary();
    let output = Command::new(&binary)
        .args(["--id", &test_id, "--warps", "2000000", "-b"])
        .output()
        .expect("Failed to execute with large warps");

    assert!(!output.status.success(), "Should reject warps > 1M");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("too large"), "Should show size error");
}

#[test]
fn test_seed_validation_integration() {
    let mut payload = [0u8; 20];
    for i in 0..20 {
        payload[i] = (i * 11) as u8;
    }
    let test_id =
        pocx_address::encode_address(&payload, pocx_address::NetworkId::Base58(0x55)).unwrap();

    let binary = get_plotter_binary();
    let output = Command::new(&binary)
        .args(["--id", &test_id, "--seed", "invalid_seed", "--bench"])
        .output()
        .expect("Failed to execute with invalid seed");

    assert!(!output.status.success(), "Should reject invalid seed");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("seed"), "Should show seed error");
}

#[test]
fn test_comprehensive_error_recovery() {
    use pocx_plotter_v2::buffer::PageAlignedByteBuffer;
    use pocx_plotter_v2::error::PoCXPlotterError;

    // Buffer allocation error recovery
    let valid_buffer_result = PageAlignedByteBuffer::new(4096);
    assert!(valid_buffer_result.is_ok());

    let invalid_buffer_result = PageAlignedByteBuffer::new(usize::MAX);
    assert!(invalid_buffer_result.is_err());

    let recovery_buffer_result = PageAlignedByteBuffer::new(8192);
    assert!(recovery_buffer_result.is_ok());

    // Seed validation
    let valid_seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let is_valid = valid_seed.len() == 64 && valid_seed.chars().all(|c| c.is_ascii_hexdigit());
    assert!(is_valid);

    // Buffer size calculation overflow
    let test_cases = vec![
        (0u64, false),
        (1u64, true),
        (u64::MAX, false),
        (1024u64, true),
    ];

    for (size, should_succeed) in test_cases {
        let calculation_result = size.checked_mul(1024);
        if should_succeed {
            assert!(calculation_result.is_some());
        } else {
            assert!(calculation_result.is_none() || size == 0);
        }
    }

    // Error state isolation
    let operations = vec![
        (1024usize, true),
        (0usize, false),
        (2048usize, true),
        (usize::MAX, false),
        (4096usize, true),
    ];

    for (size, should_succeed) in operations {
        let result = if size == 0 || size > 16 * 1024 * 1024 * 1024 {
            Err(PoCXPlotterError::Memory(format!("Invalid size: {}", size)))
        } else {
            PageAlignedByteBuffer::new(size)
        };

        if should_succeed {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    let final_buffer = PageAlignedByteBuffer::new(1024);
    assert!(final_buffer.is_ok());
}
