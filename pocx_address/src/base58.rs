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

//! Base58Check address encoding/decoding implementation

use crate::common::{AddressError, BASE58_DECODED_LENGTH, PAYLOAD_LENGTH};

/// Encodes bytes with a version byte into a Base58 address with checksum
///
/// # Arguments
/// * `payload` - Raw bytes to encode (must be 20 bytes for addresses)
/// * `version` - Version byte (network identifier)
///
/// # Returns
/// Base58-encoded address string with checksum
pub fn encode(payload: &[u8; PAYLOAD_LENGTH], version: u8) -> Result<String, AddressError> {
    let encoded = bs58::encode(payload)
        .with_check_version(version)
        .into_string();
    Ok(encoded)
}

/// Decodes a Base58 address
///
/// # Arguments
/// * `address` - Base58-encoded address string
///
/// # Returns
/// Tuple of (decoded_bytes, version)
///
/// # Errors
/// Returns error if address is invalid or checksum fails
pub fn decode(address: &str) -> Result<([u8; BASE58_DECODED_LENGTH], u8), AddressError> {
    // Decode with checksum validation but no specific version check
    let mut decoded = [0u8; BASE58_DECODED_LENGTH];
    bs58::decode(address)
        .with_check(None) // Validate checksum but accept any version
        .onto(&mut decoded)
        .map_err(|_| AddressError::ChecksumError)?;

    // Extract version from the decoded result
    let version = decoded[0];

    Ok((decoded, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let payload = [0x42u8; 20];
        let version = 0x55;

        let address = encode(&payload, version).unwrap();
        let (decoded, detected_version) = decode(&address).unwrap();

        assert_eq!(decoded[0], version);
        assert_eq!(&decoded[1..21], &payload);
        assert_eq!(detected_version, version);

        // Test with different version to ensure it works for any version
        let testnet_version = 0x7F;
        let testnet_address = encode(&payload, testnet_version).unwrap();
        let (testnet_decoded, testnet_detected) = decode(&testnet_address).unwrap();

        assert_eq!(testnet_decoded[0], testnet_version);
        assert_eq!(&testnet_decoded[1..21], &payload);
        assert_eq!(testnet_detected, testnet_version);
    }
}
