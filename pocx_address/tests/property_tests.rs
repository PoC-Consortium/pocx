// Copyright (c) 2025 Proof of Capacity Consortium
//
// Property-based tests for pocx_address library functions

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;

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
    }
}
