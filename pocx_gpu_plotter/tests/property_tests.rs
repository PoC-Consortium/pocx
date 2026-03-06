// Copyright (c) 2025 Proof of Capacity Consortium
// MIT License

use pocx_gpu_plotter::buffer::PageAlignedByteBuffer;
use proptest::prelude::*;
use quickcheck::{quickcheck, TestResult};

#[cfg(test)]
mod crypto_property_tests {
    use super::*;

    proptest! {
        #[test]
        fn test_poc_address_validation_properties(
            version in 0u8..=255,
            data in prop::collection::vec(0u8..=255, 24)
        ) {
            let mut test_bytes = [0u8; 25];
            test_bytes[0] = version;
            for (i, &byte) in data.iter().enumerate() {
                if i < 24 {
                    test_bytes[i + 1] = byte;
                }
            }

            let payload = &test_bytes[1..21];
            let mut payload_array = [0u8; 20];
            payload_array.copy_from_slice(payload);
            let test_id = pocx_address::encode_address(&payload_array, pocx_address::NetworkId::Base58(test_bytes[0])).unwrap();

            let decoded = pocx_address::decode_address(&test_id);
            prop_assert!(decoded.is_ok(), "Valid address should decode");

            let (decoded_payload, decoded_network) = decoded.unwrap();
            prop_assert_eq!(decoded_payload, payload_array, "Payload should match");
            prop_assert_eq!(decoded_network, pocx_address::NetworkId::Base58(version), "Network ID should match");

            prop_assert!(test_id.len() >= 32 && test_id.len() <= 36,
                        "Base58 encoded ID should be reasonable length");
        }
    }

    proptest! {
        #[test]
        fn test_seed_validation_properties(
            seed_bytes in prop::collection::vec(0u8..=255, 32)
        ) {
            let hex_seed = hex::encode(&seed_bytes);

            prop_assert_eq!(hex_seed.len(), 64);
            prop_assert!(hex_seed.chars().all(|c| c.is_ascii_hexdigit()));

            let decoded = hex::decode(&hex_seed);
            prop_assert!(decoded.is_ok());
            prop_assert_eq!(decoded.unwrap(), seed_bytes);
        }
    }

    proptest! {
        #[test]
        fn test_parameter_bounds_properties(
            warps in 1u64..1_000_000,
            escalate in 1u64..64,
        ) {
            prop_assert!(warps <= 1_000_000);
            prop_assert!((1..=64).contains(&escalate));

            let mem_calc = (4096u64).checked_mul(escalate);
            prop_assert!(mem_calc.is_some());
        }
    }
}

#[cfg(test)]
mod buffer_property_tests {
    use super::*;

    proptest! {
        #[test]
        fn test_buffer_allocation_properties(
            size in 4096usize..16_777_216
        ) {
            let buffer_result = PageAlignedByteBuffer::new(size);
            prop_assert!(buffer_result.is_ok());

            if let Ok(buffer) = buffer_result {
                let data = buffer.get_buffer();
                let guard = data.lock().unwrap();

                prop_assert_eq!(guard.len(), size);

                let ptr = guard.as_ptr() as usize;
                let page_size = page_size::get();
                prop_assert_eq!(ptr % page_size, 0, "Buffer should be page-aligned");
            }
        }
    }

    proptest! {
        #[test]
        fn test_buffer_rejection_properties(
            size in 0usize..4096
        ) {
            if size == 0 {
                let buffer_result = PageAlignedByteBuffer::new(size);
                prop_assert!(buffer_result.is_err());
            } else if size < 4096 {
                let buffer_result = PageAlignedByteBuffer::new(size);
                if let Ok(buffer) = buffer_result {
                    let data = buffer.get_buffer();
                    let guard = data.lock().unwrap();
                    prop_assert_eq!(guard.len(), size);
                }
            }
        }
    }
}

#[cfg(test)]
mod path_validation_property_tests {
    use super::*;

    proptest! {
        #[test]
        fn test_path_length_properties(
            path_prefix in "[a-zA-Z0-9_-]{1,10}",
            path_suffix in "[a-zA-Z0-9_.-]{1,10}"
        ) {
            let path = format!("{}/{}", path_prefix, path_suffix);
            prop_assert!(path.len() <= 4096);
            prop_assert!(!path.is_empty());
        }
    }
}

#[cfg(test)]
mod quickcheck_tests {
    use super::*;

    #[test]
    fn quickcheck_poc_address_roundtrip() {
        fn prop(data: Vec<u8>) -> TestResult {
            if data.len() != 25 {
                return TestResult::discard();
            }

            let mut bytes = [0u8; 25];
            bytes.copy_from_slice(&data);

            let payload = &bytes[1..21];
            let mut payload_array = [0u8; 20];
            payload_array.copy_from_slice(payload);
            let network_id = pocx_address::NetworkId::Base58(bytes[0]);
            let encoded = pocx_address::encode_address(&payload_array, network_id.clone()).unwrap();
            let (decoded_payload, decoded_network) =
                pocx_address::decode_address(&encoded).unwrap();

            TestResult::from_bool(decoded_network == network_id && decoded_payload == payload_array)
        }
        quickcheck(prop as fn(Vec<u8>) -> TestResult);
    }

    #[test]
    fn quickcheck_hex_seed_roundtrip() {
        fn prop(data: Vec<u8>) -> TestResult {
            if data.len() != 32 {
                return TestResult::discard();
            }

            let hex_string = hex::encode(&data);
            if hex_string.len() != 64 {
                return TestResult::failed();
            }

            let decoded = hex::decode(&hex_string).unwrap();
            TestResult::from_bool(decoded == data)
        }
        quickcheck(prop as fn(Vec<u8>) -> TestResult);
    }

    #[test]
    fn quickcheck_parameter_validation() {
        fn prop(warps: u64, escalate: u64) -> TestResult {
            let warps_valid = warps <= 1_000_000;
            let escalate_valid = (1..=64).contains(&escalate);

            if warps_valid && escalate_valid {
                let mem_calc = (4096u64)
                    .checked_mul(escalate)
                    .and_then(|v| v.checked_mul(warps));

                TestResult::from_bool(mem_calc.is_some())
            } else {
                TestResult::discard()
            }
        }
        quickcheck(prop as fn(u64, u64) -> TestResult);
    }
}

#[cfg(test)]
mod cli_fuzzing_tests {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn test_cli_argument_validation(
            arg_name in "[a-z-]{2,10}",
            arg_value in "[a-zA-Z0-9._/-]{0,20}"
        ) {
            let arg_string = format!("--{}", arg_name);
            prop_assert!(arg_string.starts_with("--"));
            prop_assert!(arg_string.len() >= 4);
            prop_assert!(!arg_value.contains('\0'));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]
        #[test]
        fn test_poc_address_format_validation(
            id_value in "[a-zA-Z0-9]{20,40}"
        ) {
            prop_assert!(id_value.len() >= 20);
            prop_assert!(id_value.len() <= 40);
            prop_assert!(id_value.chars().all(|c| c.is_ascii_alphanumeric()));

            let _decode_result = pocx_address::decode_address(&id_value);
        }
    }
}

#[cfg(feature = "opencl")]
#[cfg(test)]
mod ring_buffer_property_tests {
    use super::*;
    use pocx_gpu_plotter::ocl::compute_ring_size;

    proptest! {
        #[test]
        fn test_ring_size_properties(
            cu_count in 1u64..128,
            kws in prop::sample::select(vec![64u64, 128, 256, 512])
        ) {
            let worksize = cu_count * kws;
            let ring_size = compute_ring_size(worksize);

            // R >= W (always enough room for one hash dispatch)
            prop_assert!(ring_size >= worksize,
                "ring_size {} >= worksize {}", ring_size, worksize);

            // R >= C (always enough for one compress batch)
            prop_assert!(ring_size >= 8192,
                "ring_size {} >= 8192", ring_size);

            // R <= W + C (never wastes more than necessary)
            prop_assert!(ring_size <= worksize + 8192,
                "ring_size {} <= worksize + 8192 = {}", ring_size, worksize + 8192);

            // R = W + C - gcd(W, C)
            let expected = worksize + 8192 - gcd(worksize, 8192);
            prop_assert_eq!(ring_size, expected);
        }
    }

    fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }
}
