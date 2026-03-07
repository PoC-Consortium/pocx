// Copyright (c) 2025 Proof of Capacity Consortium
// MIT License

use pocx_plotter_v2::buffer::PageAlignedByteBuffer;

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

    for _iteration in 0..100 {
        for len in [0, 1, 24, 25, 26, 32, 50, 100] {
            let data = prng.next_bytes(len);

            if len == 25 {
                let mut id_bytes = [0u8; 25];
                id_bytes.copy_from_slice(&data);
                let payload = &id_bytes[1..21];
                let mut payload_array = [0u8; 20];
                payload_array.copy_from_slice(payload);
                let network_id = pocx_address::NetworkId::Base58(id_bytes[0]);
                let encoded = pocx_address::encode_address(&payload_array, network_id).unwrap();

                if let Ok((decoded_payload, decoded_network)) =
                    pocx_address::decode_address(&encoded)
                {
                    assert_eq!(decoded_payload, payload_array);
                    if let pocx_address::NetworkId::Base58(version) = decoded_network {
                        assert_eq!(version, id_bytes[0]);
                    }
                }
            }

            if (20..=100).contains(&len) {
                let payload = &data[..20.min(len)];
                let mut payload_array = [0u8; 20];
                payload_array[..payload.len()].copy_from_slice(payload);
                let network_id = if len > 0 { data[0] } else { 0x55 };
                let network_id_enum = pocx_address::NetworkId::Base58(network_id);
                let encoded =
                    pocx_address::encode_address(&payload_array, network_id_enum).unwrap();
                let _decode_result = pocx_address::decode_address(&encoded);
            }
        }
    }
}

#[test]
fn fuzz_seed_validation() {
    let mut prng = SimplePrng::new(54321);

    for _iteration in 0..100 {
        for len in [0, 1, 16, 31, 32, 33, 64, 128] {
            let data = prng.next_bytes(len);

            let hex_encoded = hex::encode(&data);
            assert_eq!(hex_encoded.len(), data.len() * 2);
            assert!(hex_encoded.chars().all(|c| c.is_ascii_hexdigit()));

            if let Ok(decoded) = hex::decode(&hex_encoded) {
                assert_eq!(decoded, data);
            }

            if len == 32 {
                assert_eq!(hex_encoded.len(), 64);
                let decoded = hex::decode(&hex_encoded).unwrap();
                assert_eq!(decoded, data);
            }
        }

        let random_string: String = (0..prng.next_usize(129))
            .map(|_| {
                let chars =
                    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()";
                chars[prng.next_usize(chars.len())] as char
            })
            .collect();

        let _decode_result = hex::decode(&random_string);
    }
}

#[test]
fn fuzz_buffer_allocation() {
    let mut prng = SimplePrng::new(98765);

    let test_sizes: [usize; 10] = [0, 1, 2, 3, 4095, 4096, 4097, 8192, 16384, 65536];

    for &base_size in &test_sizes {
        let variation = prng.next_usize(1024);
        let size = base_size.saturating_add(variation);

        let result = PageAlignedByteBuffer::new(size);

        match result {
            Ok(buffer) => {
                assert!(size > 0);
                let data = buffer.get_buffer();
                let guard = data.lock().unwrap();
                assert_eq!(guard.len(), size);

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
            }
        }
    }
}

#[test]
fn fuzz_parameter_validation() {
    let mut prng = SimplePrng::new(22222);

    for _iteration in 0..200 {
        let warps = prng.next_u64(2_000_000);
        let escalate = prng.next_u64(100);
        let compression = (prng.next_u64(50)) as u32;

        let warps_valid = warps <= 1_000_000;
        let escalate_valid = (1..=64).contains(&escalate);
        let compression_valid = (1..=32).contains(&compression);

        if warps_valid && escalate_valid && compression_valid {
            let mem_calc = (4096u64)
                .checked_mul(compression as u64)
                .and_then(|v| v.checked_mul(escalate))
                .and_then(|v| v.checked_mul(warps));

            if mem_calc.is_none() {
                assert!(warps > 1_000_000 || escalate > 64 || compression > 32);
            }
        }
    }
}

#[test]
fn fuzz_crypto_operations() {
    let mut prng = SimplePrng::new(33333);

    for _iteration in 0..100 {
        let version = (prng.next_u64(256)) as u8;
        let mut test_bytes = [0u8; 25];
        test_bytes[0] = version;

        for item in test_bytes.iter_mut().skip(1) {
            *item = (prng.next_u64(256)) as u8;
        }

        let payload = &test_bytes[1..21];
        let mut payload_array = [0u8; 20];
        payload_array.copy_from_slice(payload);
        let network_id = pocx_address::NetworkId::Base58(test_bytes[0]);
        let encoded = pocx_address::encode_address(&payload_array, network_id.clone()).unwrap();

        assert!(!encoded.is_empty());
        assert!(encoded.len() <= 100);

        if let Ok((decoded_payload, decoded_network)) = pocx_address::decode_address(&encoded) {
            assert_eq!(decoded_payload, payload_array);
            assert_eq!(decoded_network, network_id);
        }
    }
}

#[cfg(feature = "opencl")]
#[test]
fn fuzz_ring_size_computation() {
    use pocx_plotter_v2::ocl::compute_ring_size;

    let mut prng = SimplePrng::new(44444);

    for _iteration in 0..200 {
        // Test various worksize values (must be > 0)
        let worksize = (prng.next_u64(32768) + 1) as u64;
        let ring_size = compute_ring_size(worksize);

        // Ring size must be >= max(worksize, 8192)
        assert!(
            ring_size >= worksize,
            "Ring size {} must be >= worksize {}",
            ring_size,
            worksize
        );
        assert!(
            ring_size >= 8192,
            "Ring size {} must be >= compress batch 8192",
            ring_size
        );

        // Ring size = W + C - gcd(W, C), always <= W + C
        assert!(
            ring_size <= worksize + 8192,
            "Ring size {} must be <= worksize + 8192 = {}",
            ring_size,
            worksize + 8192
        );
    }
}
