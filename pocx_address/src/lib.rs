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

//! Address encoding/decoding for PoCX (supports Base58 and Bech32)

pub mod base58;
pub mod bech32;
pub mod common;
pub mod crypto;

// Re-export common types and constants
pub use common::{
    detect_address_format, AddressError, AddressFormat, NetworkId, BASE58_DECODED_LENGTH,
    PAYLOAD_LENGTH,
};

/// Encode 20-byte payload using NetworkId format
pub fn encode_address(payload: &[u8], network_id: NetworkId) -> Result<String, AddressError> {
    // Ensure payload is correct length
    if payload.len() != PAYLOAD_LENGTH {
        return Err(AddressError::InvalidLength {
            expected: PAYLOAD_LENGTH,
            actual: payload.len(),
        });
    }

    let mut payload_array = [0u8; PAYLOAD_LENGTH];
    payload_array.copy_from_slice(payload);

    match network_id {
        NetworkId::Base58(version) => base58::encode(&payload_array, version),
        NetworkId::Bech32(hrp) => bech32::encode(&payload_array, &hrp),
    }
}

/// Decode address and return payload with NetworkId
pub fn decode_address(address: &str) -> Result<([u8; PAYLOAD_LENGTH], NetworkId), AddressError> {
    let address_format = detect_address_format(address);

    match address_format {
        Some(AddressFormat::Base58) => {
            let (decoded, version) = base58::decode(address)?;
            let mut payload = [0u8; PAYLOAD_LENGTH];
            payload.copy_from_slice(&decoded[1..21]);
            Ok((payload, NetworkId::Base58(version)))
        }
        Some(AddressFormat::Bech32) => {
            let (payload, hrp) = bech32::decode(address)?;
            Ok((payload, NetworkId::Bech32(hrp)))
        }
        None => Err(AddressError::UnknownFormat),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test encode/decode roundtrip for Base58 addresses
    #[test]
    fn roundtrip_base58() {
        let payload = [0x42u8; 20];
        let network = NetworkId::Base58(0x55);

        let address = encode_address(&payload, network.clone()).unwrap();
        let (decoded_payload, decoded_network) = decode_address(&address).unwrap();

        assert_eq!(decoded_payload, payload);
        assert_eq!(decoded_network, network);
    }

    /// Test encode/decode roundtrip for Bech32 addresses
    #[test]
    fn roundtrip_bech32() {
        let payload = [0x42u8; 20];
        let network = NetworkId::Bech32("pocx".to_string());

        let address = encode_address(&payload, network.clone()).unwrap();
        assert!(address.starts_with("pocx1"));

        let (decoded_payload, decoded_network) = decode_address(&address).unwrap();
        assert_eq!(decoded_payload, payload);
        assert_eq!(decoded_network, network);
    }

    /// Test various network versions and HRPs
    #[test]
    fn various_networks() {
        let payload = [0x55u8; 20];

        // Test different Base58 versions
        for version in [0x00, 0x55, 0x7F, 0xFF] {
            let network = NetworkId::Base58(version);
            let address = encode_address(&payload, network.clone()).unwrap();
            let (decoded_payload, decoded_network) = decode_address(&address).unwrap();
            assert_eq!(decoded_payload, payload);
            assert_eq!(decoded_network, network);
        }

        // Test different Bech32 HRPs
        for hrp in ["pocx", "tpocx", "test"] {
            let network = NetworkId::Bech32(hrp.to_string());
            let address = encode_address(&payload, network.clone()).unwrap();
            let (decoded_payload, decoded_network) = decode_address(&address).unwrap();
            assert_eq!(decoded_payload, payload);
            assert_eq!(decoded_network, network);
        }
    }

    /// Test address format detection
    #[test]
    fn format_detection() {
        let payload = [0x42u8; 20];

        // Base58 detection
        let base58_addr = base58::encode(&payload, 0x55).unwrap();
        assert_eq!(
            detect_address_format(&base58_addr),
            Some(AddressFormat::Base58)
        );

        // Bech32 detection
        let bech32_addr = bech32::encode(&payload, "pocx").unwrap();
        assert_eq!(
            detect_address_format(&bech32_addr),
            Some(AddressFormat::Bech32)
        );

        // Invalid addresses
        assert_eq!(detect_address_format("invalid"), None);
        assert_eq!(detect_address_format(""), None);
    }

    /// Test cryptographic integration
    #[test]
    fn crypto_integration() {
        let private_key = crypto::PrivateKey::generate_random();
        let payload = private_key.to_public_key().to_address_payload();

        // Should work with both formats
        let base58_addr = encode_address(&payload, NetworkId::Base58(0x55)).unwrap();
        let bech32_addr = encode_address(&payload, NetworkId::Bech32("pocx".to_string())).unwrap();

        let (payload1, _) = decode_address(&base58_addr).unwrap();
        let (payload2, _) = decode_address(&bech32_addr).unwrap();

        assert_eq!(payload1, payload);
        assert_eq!(payload2, payload);
    }

    /// Test bech32 address with witness version 2 and roundtrip
    #[test]
    fn test_specific_bech32_address() {
        let address = "pocx1qfycvpqwhpf5jct5tmd090u4cxy9gleppquaasl";

        let format = detect_address_format(address);
        assert_eq!(format, Some(AddressFormat::Bech32));

        let (payload, network_id) = decode_address(address).unwrap();
        assert_eq!(network_id, NetworkId::Bech32("pocx".to_string()));

        let re_encoded = encode_address(&payload, network_id).unwrap();
        assert_eq!(re_encoded, address);
    }
}
