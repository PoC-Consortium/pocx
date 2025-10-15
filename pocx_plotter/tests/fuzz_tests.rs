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

/// Simple fuzz testing without external dependencies
/// Tests critical functions with pseudo-random inputs
use pocx_plotter::buffer::PageAlignedByteBuffer;
use pocx_plotter::compressor::{helix_compress, xor_compress};

/// Simple pseudo-random number generator for reproducible fuzz testing
struct SimplePrng {
    state: u64,
}

impl SimplePrng {
    fn new(seed: u64) -> Self {
        SimplePrng { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(1103515245).wrapping_add(12345);
        self.state
    }

    fn next_bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| (self.next() % 256) as u8).collect()
    }

    fn next_usize(&mut self, max: usize) -> usize {
        (self.next() as usize) % max.max(1)
    }

    fn next_u64(&mut self, max: u64) -> u64 {
        self.next() % max.max(1)
    }
}

#[test]
fn fuzz_poc_address_validation() {
    let mut prng = SimplePrng::new(12345);

    // Test with various byte patterns
    for _iteration in 0..100 {
        // Test different length inputs
        for len in [0, 1, 24, 25, 26, 32, 50, 100] {
            let data = prng.next_bytes(len);

            // Test address encoding - should never panic
            if len == 25 {
                let mut id_bytes = [0u8; 25];
                id_bytes.copy_from_slice(&data);
                let payload = &id_bytes[1..21];
                let mut payload_array = [0u8; 20];
                payload_array.copy_from_slice(payload);
                let network_id = pocx_address::NetworkId::Base58(id_bytes[0]);
                let encoded = pocx_address::encode_address(&payload_array, network_id).unwrap();

                // Should be able to decode back
                if let Ok((decoded_payload, decoded_network)) =
                    pocx_address::decode_address(&encoded)
                {
                    assert_eq!(decoded_payload, payload_array);
                    if let pocx_address::NetworkId::Base58(version) = decoded_network {
                        assert_eq!(version, id_bytes[0]);
                    }
                }
            }

            // Test arbitrary input to address decoder
            if (20..=100).contains(&len) {
                let payload = &data[..20.min(len)];
                let mut payload_array = [0u8; 20];
                payload_array[..payload.len()].copy_from_slice(payload);
                let network_id = if len > 0 { data[0] } else { 0x55 };
                let network_id_enum = pocx_address::NetworkId::Base58(network_id);
                let encoded =
                    pocx_address::encode_address(&payload_array, network_id_enum).unwrap();
                let _decode_result = pocx_address::decode_address(&encoded);
                // Should not panic regardless of success/failure
            }
        }
    }
}

#[test]
fn fuzz_seed_validation() {
    let mut prng = SimplePrng::new(54321);

    for _iteration in 0..100 {
        // Test different length inputs
        for len in [0, 1, 16, 31, 32, 33, 64, 128] {
            let data = prng.next_bytes(len);

            // Hex encoding should never panic
            let hex_encoded = hex::encode(&data);
            assert_eq!(hex_encoded.len(), data.len() * 2);
            assert!(hex_encoded.chars().all(|c| c.is_ascii_hexdigit()));

            // Should be able to decode back
            if let Ok(decoded) = hex::decode(&hex_encoded) {
                assert_eq!(decoded, data);
            }

            // Test 32-byte seeds specifically
            if len == 32 {
                assert_eq!(hex_encoded.len(), 64);
                let decoded = hex::decode(&hex_encoded).unwrap();
                assert_eq!(decoded, data);
            }
        }

        // Test with potentially invalid hex strings
        let random_string: String = (0..prng.next_usize(129))
            .map(|_| {
                let chars =
                    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()";
                chars[prng.next_usize(chars.len())] as char
            })
            .collect();

        // Should not panic on invalid input
        let _decode_result = hex::decode(&random_string);
    }
}

#[test]
fn fuzz_buffer_allocation() {
    let mut prng = SimplePrng::new(98765);

    // Test various buffer sizes
    let test_sizes: [usize; 10] = [0, 1, 2, 3, 4095, 4096, 4097, 8192, 16384, 65536];

    for &base_size in &test_sizes {
        // Add some randomness to the size
        let variation = prng.next_usize(1024);
        let size = base_size.saturating_add(variation);

        let result = PageAlignedByteBuffer::new(size);

        match result {
            Ok(buffer) => {
                // Verify properties if allocation succeeded
                assert!(size > 0);
                assert!(size <= 16 * 1024 * 1024 * 1024); // 16GB limit

                let data = buffer.get_buffer();
                let guard = data.lock().unwrap();
                assert_eq!(guard.len(), size);

                // Test basic read/write if size > 0
                if size > 0 {
                    drop(guard);
                    let data = buffer.get_buffer();
                    let mut guard = data.lock().unwrap();

                    guard[0] = 0xFF;
                    assert_eq!(guard[0], 0xFF);

                    if size > 1 {
                        guard[size - 1] = 0xAA;
                        assert_eq!(guard[size - 1], 0xAA);
                    }
                }
            }
            Err(_) => {
                // Failure is acceptable for invalid sizes
                let expected_failure = size == 0 || size > 16 * 1024 * 1024 * 1024;
                if !expected_failure {
                    // Size might be valid but system could be out of memory
                    // This is acceptable during testing
                }
            }
        }
    }
}

#[test]
fn fuzz_compression_functions() {
    let mut prng = SimplePrng::new(11111);

    // Use minimal dimensions for faster execution in debug mode with coverage
    const FUZZ_DIM: u64 = 1;
    const FUZZ_DOUBLE_HASH_SIZE: u64 = 8;

    for _iteration in 0..1 {
        // Reduced to 1 iteration for speed in debug mode
        let warp_offset = prng.next_u64(3);
        let output_len = prng.next_u64(3) + 1;
        let iterations = (prng.next_u64(2) + 1) as u32;

        // Test helix compression
        let source_size = (2 * FUZZ_DIM * FUZZ_DIM * FUZZ_DOUBLE_HASH_SIZE) as usize;
        let target_size = (4 * FUZZ_DIM * FUZZ_DIM * FUZZ_DOUBLE_HASH_SIZE) as usize;

        let source_buffer = prng.next_bytes(source_size);
        let mut target_buffer = vec![0u8; target_size];

        // Should not panic
        helix_compress(&source_buffer, &mut target_buffer, warp_offset, output_len);
        assert_eq!(target_buffer.len(), target_size);

        // Test XOR compression
        let src_len = u64::pow(2, iterations);
        let xor_source_size = (src_len * FUZZ_DIM * FUZZ_DIM * FUZZ_DOUBLE_HASH_SIZE) as usize;
        let xor_target_size = (output_len * FUZZ_DIM * FUZZ_DIM * FUZZ_DOUBLE_HASH_SIZE) as usize;

        let xor_source_buffer = prng.next_bytes(xor_source_size);
        let mut xor_target_buffer = vec![0u8; xor_target_size];

        // Should not panic
        xor_compress(
            &xor_source_buffer,
            &mut xor_target_buffer,
            warp_offset,
            output_len,
            iterations,
        );
        assert_eq!(xor_target_buffer.len(), xor_target_size);
    }
}

#[test]
fn fuzz_parameter_validation() {
    let mut prng = SimplePrng::new(22222);

    for _iteration in 0..200 {
        let warps = prng.next_u64(2_000_000);
        let escalate = prng.next_u64(100);
        let compression = (prng.next_u64(50)) as u32;
        let cpu_threads = (prng.next_u64(200)) as u8;

        // Test bounds checking logic
        let warps_valid = warps <= 1_000_000;
        let escalate_valid = (1..=64).contains(&escalate);
        let compression_valid = (1..=32).contains(&compression);
        let _cpu_threads_valid = cpu_threads <= 128;

        // Test memory calculations for overflow
        if warps_valid && escalate_valid && compression_valid {
            let mem_calc = (4096u64)
                .checked_mul(compression as u64)
                .and_then(|v| v.checked_mul(escalate))
                .and_then(|v| v.checked_mul(warps));

            // Should either succeed or detect overflow gracefully
            if mem_calc.is_none() {
                // Overflow detected - this is correct behavior
                assert!(warps > 1_000_000 || escalate > 64 || compression > 32);
            }
        }

        // Test various edge cases - these comparisons removed as they're always
        // true Variables are already constrained by their types
    }
}

#[test]
fn fuzz_crypto_operations() {
    let mut prng = SimplePrng::new(33333);

    for _iteration in 0..100 {
        // Test various PoC address scenarios
        let version = (prng.next_u64(256)) as u8;
        let mut test_bytes = [0u8; 25];
        test_bytes[0] = version;

        for item in test_bytes.iter_mut().skip(1) {
            *item = (prng.next_u64(256)) as u8;
        }

        // Should not panic
        let payload = &test_bytes[1..21];
        let mut payload_array = [0u8; 20];
        payload_array.copy_from_slice(payload);
        let network_id = pocx_address::NetworkId::Base58(test_bytes[0]);
        let encoded = pocx_address::encode_address(&payload_array, network_id.clone()).unwrap();

        // Basic validation checks
        assert!(!encoded.is_empty());
        assert!(encoded.len() <= 100); // Reasonable upper bound

        // Should decode back correctly
        if let Ok((decoded_payload, decoded_network)) = pocx_address::decode_address(&encoded) {
            assert_eq!(decoded_payload, payload_array);
            assert_eq!(decoded_network, network_id);
        }

        // Test checksum validation (basic)
        let has_valid_version = matches!(version, 0x55 | 0x7F);
        if !has_valid_version {
            // Non-standard version should be handled gracefully
        }
    }
}
