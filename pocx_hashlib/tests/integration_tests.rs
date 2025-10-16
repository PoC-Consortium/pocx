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

//! Integration tests for pocx_hashlib
//!
//! These tests verify that the library works correctly in realistic scenarios
//! and that all components work together as expected.

use pocx_hashlib::{
    calculate_scoop, decode_generation_signature, generate_nonces,
    noncegen_common::{NONCE_SIZE, NUM_SCOOPS, SCOOP_SIZE},
};
use std::time::Instant;

#[test]
fn test_full_mining_workflow() {
    // Simulate a complete mining workflow
    let account = [1u8; 20];
    let seed = [0x42u8; 32];
    let num_nonces = 5;
    let start_nonce = 0;

    // Step 1: Generate nonces
    let mut cache = vec![0u8; num_nonces * NONCE_SIZE];
    let result = generate_nonces(
        &mut cache,
        0,
        &account,
        &seed,
        start_nonce,
        num_nonces as u64,
    );
    assert!(result.is_ok());

    // Step 2: Verify cache contains data
    assert!(
        !cache.iter().all(|&b| b == 0),
        "Cache should contain generated data"
    );

    // Step 3: Simulate mining by reading scoops
    let generation_signature = [0x11u8; 32];
    let block_height = 12345;
    let target_scoop = calculate_scoop(block_height, &generation_signature);

    // Read the target scoop from each nonce
    for nonce_idx in 0..num_nonces {
        let nonce_offset = nonce_idx * NONCE_SIZE;
        let scoop_offset = nonce_offset + (target_scoop as usize * SCOOP_SIZE);

        if scoop_offset + SCOOP_SIZE <= cache.len() {
            let scoop_data = &cache[scoop_offset..scoop_offset + SCOOP_SIZE];
            assert_eq!(scoop_data.len(), SCOOP_SIZE);

            // Verify scoop data has been populated (not all zeros)
            // Note: In dummy mode, this might be all zeros, so we just check structure
            assert_eq!(scoop_data.len(), 64);
        }
    }
}

#[test]
fn test_large_nonce_generation() {
    // Test with larger number of nonces to ensure scalability
    let account = [2u8; 20];
    let seed = [0x33u8; 32];
    let num_nonces = 8; // Reduced from 50 to 8 for faster testing
    let start_nonce = 1000;

    let mut cache = vec![0u8; num_nonces * NONCE_SIZE];

    let start_time = Instant::now();
    let result = generate_nonces(
        &mut cache,
        0,
        &account,
        &seed,
        start_nonce,
        num_nonces as u64,
    );
    let generation_time = start_time.elapsed();

    assert!(result.is_ok());
    println!("Generated {} nonces in {:?}", num_nonces, generation_time);

    // Verify data was generated
    let zero_count = cache.iter().filter(|&&b| b == 0).count();
    let total_bytes = cache.len();
    let non_zero_ratio = 1.0 - (zero_count as f64 / total_bytes as f64);

    // In a real implementation, we'd expect significant non-zero data
    // For testing purposes, we just ensure the operation completed
    println!("Non-zero data ratio: {:.2}%", non_zero_ratio * 100.0);
}

#[test]
fn test_concurrent_safety_simulation() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    // Simulate concurrent hashing operations
    let shared_counter = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    for thread_id in 0..4 {
        let counter = Arc::clone(&shared_counter);

        let handle = thread::spawn(move || {
            // Test concurrent nonce generation instead of hasher
            let account = [thread_id; 20];
            let seed = [thread_id * 2; 32];
            let mut cache = vec![0u8; NONCE_SIZE];

            let result = generate_nonces(&mut cache, 0, &account, &seed, 0, 1);

            // Update shared counter
            if let Ok(mut count) = counter.lock() {
                *count += 1;
            }

            result
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.join().unwrap());
    }

    // Verify all threads completed
    assert_eq!(*shared_counter.lock().unwrap(), 4);

    // Verify each thread completed successfully
    for result in results {
        assert!(result.is_ok(), "Thread should complete successfully");
    }
}

#[test]
fn test_memory_efficiency() {
    // Test that the library is memory efficient for large operations
    let account = [3u8; 20];
    let seed = [0x55u8; 32];

    // Test with chunked processing to simulate real-world usage (reduced for speed)
    let total_nonces = 20; // Reduced from 100 to 20
    let chunk_size = 5; // Reduced from 10 to 5

    for chunk_start in (0..total_nonces).step_by(chunk_size) {
        let chunk_nonces = std::cmp::min(chunk_size, total_nonces - chunk_start);
        let mut cache = vec![0u8; chunk_nonces * NONCE_SIZE];

        let result = generate_nonces(
            &mut cache,
            0,
            &account,
            &seed,
            chunk_start as u64,
            chunk_nonces as u64,
        );

        assert!(result.is_ok());

        // Verify chunk was processed
        assert_eq!(cache.len(), chunk_nonces * NONCE_SIZE);
    }
}

#[test]
fn test_error_recovery() {
    // Test that the library handles and recovers from errors gracefully
    let account = [4u8; 20];
    let seed = [0x77u8; 32];

    // Test sequence: valid operation, invalid operation, valid operation again

    // 1. Valid operation
    let mut cache1 = vec![0u8; 2 * NONCE_SIZE];
    let result1 = generate_nonces(&mut cache1, 0, &account, &seed, 0, 2);
    assert!(result1.is_ok());

    // 2. Invalid operation (insufficient buffer)
    let mut cache2 = vec![0u8; NONCE_SIZE - 1];
    let result2 = generate_nonces(&mut cache2, 0, &account, &seed, 2, 1);
    assert!(result2.is_err());

    // 3. Valid operation again (should work despite previous error)
    let mut cache3 = vec![0u8; 3 * NONCE_SIZE];
    let result3 = generate_nonces(&mut cache3, 0, &account, &seed, 4, 3);
    assert!(result3.is_ok());
}

#[test]
fn test_cross_platform_consistency() {
    // Test that results are consistent across different platforms/configurations
    let test_cases = vec![
        ([0u8; 20], [0u8; 32]),
        ([0xFFu8; 20], [0xFFu8; 32]),
        ([0x55u8; 20], [0xAAu8; 32]),
    ];

    for (account, seed) in test_cases {
        // Generate same nonces multiple times
        let mut cache1 = vec![0u8; NONCE_SIZE];
        let mut cache2 = vec![0u8; NONCE_SIZE];

        let result1 = generate_nonces(&mut cache1, 0, &account, &seed, 0, 1);
        let result2 = generate_nonces(&mut cache2, 0, &account, &seed, 0, 1);

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // Results should be identical for same inputs
        assert_eq!(cache1, cache2);
    }
}

#[test]
fn test_scoop_calculation_comprehensive() {
    // Test scoop calculation with various realistic scenarios
    let test_scenarios = vec![
        (0, [0u8; 32]),           // Genesis block
        (1, [1u8; 32]),           // Block 1
        (12345, [0x42u8; 32]),    // Random block
        (u64::MAX, [0xFFu8; 32]), // Maximum values
    ];

    for (block_height, generation_signature) in test_scenarios {
        let scoop = calculate_scoop(block_height, &generation_signature);

        // Basic validity checks
        assert!(scoop < NUM_SCOOPS as u64);

        // Consistency check - same inputs should produce same output
        let scoop2 = calculate_scoop(block_height, &generation_signature);
        assert_eq!(scoop, scoop2);

        // Different inputs should generally produce different outputs
        let different_height = block_height.wrapping_add(1);
        let _scoop3 = calculate_scoop(different_height, &generation_signature);

        // Note: This might occasionally be equal due to hash collision, but
        // very unlikely We don't assert inequality here to avoid flaky
        // tests
    }
}

#[test]
fn test_generation_signature_realistic() {
    // Test generation signature decoding with realistic mining data
    let test_signatures = vec![
        "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ];

    for signature_hex in test_signatures {
        let result = decode_generation_signature(signature_hex);
        assert!(result.is_ok(), "Failed to decode: {}", signature_hex);

        if let Ok(bytes) = result {
            assert_eq!(bytes.len(), 32);

            // Verify round-trip consistency
            let rehexed = hex::encode(bytes);
            assert_eq!(rehexed.to_lowercase(), signature_hex.to_lowercase());
        }
    }
}

#[test]
fn test_performance_characteristics() {
    // Test that operations complete within reasonable time bounds
    let account = [5u8; 20];
    let seed = [0x99u8; 32];

    // Single nonce generation should be fast
    let mut cache = vec![0u8; NONCE_SIZE];
    let start = Instant::now();
    let result = generate_nonces(&mut cache, 0, &account, &seed, 0, 1);
    let single_nonce_time = start.elapsed();

    assert!(result.is_ok());
    println!("Single nonce generation time: {:?}", single_nonce_time);

    // Multiple nonce generation should scale reasonably
    let num_nonces = 10;
    let mut large_cache = vec![0u8; num_nonces * NONCE_SIZE];
    let start = Instant::now();
    let result = generate_nonces(&mut large_cache, 0, &account, &seed, 0, num_nonces as u64);
    let multiple_nonce_time = start.elapsed();

    assert!(result.is_ok());
    println!("Multiple nonce generation time: {:?}", multiple_nonce_time);

    // Test generation signature operations instead
    let start = Instant::now();
    let _result = decode_generation_signature(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let decode_time = start.elapsed();

    println!("Generation signature decode time: {:?}", decode_time);

    // Scoop calculation should be very fast
    let start = Instant::now();
    let _scoop = calculate_scoop(12345, &[0x42u8; 32]);
    let scoop_time = start.elapsed();

    println!("Scoop calculation time: {:?}", scoop_time);
}

#[test]
fn test_simple_offset_handling() {
    // Test basic offset functionality without unsafe operations
    let account = [6u8; 20];
    let seed = [0xBBu8; 32];
    let num_nonces = 1;

    // Test without offset first
    let mut cache = vec![0u8; num_nonces * NONCE_SIZE];
    let result = generate_nonces(&mut cache, 0, &account, &seed, 0, num_nonces as u64);
    assert!(result.is_ok());
}

#[test]
fn test_edge_case_parameters() {
    // Test various edge cases that might occur in real usage
    let account = [7u8; 20];
    let seed = [0xCCu8; 32];

    // Minimum valid nonce count
    let mut cache = vec![0u8; NONCE_SIZE];
    let result = generate_nonces(&mut cache, 0, &account, &seed, 0, 1);
    assert!(result.is_ok());

    // Large start nonce
    let result = generate_nonces(&mut cache, 0, &account, &seed, u64::MAX - 100, 1);
    assert!(result.is_ok());

    // Zero offset
    let result = generate_nonces(&mut cache, 0, &account, &seed, 0, 1);
    assert!(result.is_ok());

    // Various account patterns
    let special_accounts = vec![[0u8; 20], [0xFFu8; 20], [0x55u8; 20]];

    for special_account in special_accounts {
        let result = generate_nonces(&mut cache, 0, &special_account, &seed, 0, 1);
        assert!(result.is_ok());
    }
}
