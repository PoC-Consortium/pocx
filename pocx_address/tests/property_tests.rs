// Copyright (c) 2025 Proof of Capacity Consortium
//
// Property-based tests for pocx_address library functions

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;

    // Note: Tests for parse_network_version() CLI function have been removed
    // as they belong in main.rs unit tests, not library property tests.
    // This file now focuses on testing the actual address library API.

    proptest! {
        /// Test that address generation is consistent
        #[test]
        fn prop_address_generation_consistency(payload in any::<[u8; 20]>(), network_id in any::<u8>()) {
            // Generate address and decode it back
            let network_id_obj = pocx_address::NetworkId::Base58(network_id);
            let address = pocx_address::encode_address(&payload, network_id_obj.clone()).unwrap();
            let result = pocx_address::decode_address(&address);

            prop_assert!(result.is_ok());
            let (decoded_payload, detected_network) = result.unwrap();
            prop_assert_eq!(detected_network, network_id_obj);
            prop_assert_eq!(decoded_payload, payload);
        }

        /// Test Base58 encoding/decoding properties
        #[test]
        fn prop_base58_encoding_properties(data in prop::collection::vec(any::<u8>(), 1..100)) {
            // Base58 encode and decode should be reversible
            let encoded = bs58::encode(&data).into_string();
            let decoded_result = bs58::decode(&encoded).into_vec();

            prop_assert!(decoded_result.is_ok());
            prop_assert_eq!(decoded_result.unwrap(), data);

            // Base58 strings should only contain valid characters
            prop_assert!(encoded.chars().all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)));
        }

        /// Test network version validation properties
        #[test]
        fn prop_network_version_validation(version in any::<u8>()) {
            let payload = [0x42u8; 20];
            let network_id = pocx_address::NetworkId::Base58(version);
            let address = pocx_address::encode_address(&payload, network_id.clone()).unwrap();

            // Address should decode correctly
            let decode_result = pocx_address::decode_address(&address);
            prop_assert!(decode_result.is_ok());
            prop_assert_eq!(decode_result.as_ref().unwrap().1.clone(), network_id.clone());

            // Decoded network should match original
            let (_, detected_network) = pocx_address::decode_address(&address).unwrap();
            prop_assert_eq!(detected_network, network_id.clone());
        }
    }
}
