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

//! Bech32 address encoding/decoding implementation

use crate::common::{AddressError, PAYLOAD_LENGTH};
use bech32::{segwit, Hrp};

/// Encodes a 20-byte payload into a Bech32 address using segwit encoding
///
/// # Arguments
/// * `payload` - 20-byte payload to encode
/// * `hrp` - Human Readable Part (e.g., "pocx", "tpocx", "bc")
///
/// # Returns
/// Bech32-encoded address string
pub fn encode(payload: &[u8; PAYLOAD_LENGTH], hrp: &str) -> Result<String, AddressError> {
    let hrp_parsed = Hrp::parse(hrp).map_err(|e| AddressError::InvalidHrp(e.to_string()))?;

    // Use segwit encoding with witness version 0 for P2WPKH (20-byte payload)
    let encoded = segwit::encode(hrp_parsed, segwit::VERSION_0, payload)
        .map_err(|e| AddressError::InvalidBech32(e.to_string()))?;

    Ok(encoded)
}

/// Decodes a Bech32 address using segwit decoding
///
/// # Arguments
/// * `address` - Bech32-encoded address string
///
/// # Returns
/// Tuple of (payload, hrp)
///
/// # Errors
/// Returns error if address is invalid
pub fn decode(address: &str) -> Result<([u8; PAYLOAD_LENGTH], String), AddressError> {
    let (hrp, witness_version, witness_program) =
        segwit::decode(address).map_err(|e| AddressError::InvalidBech32(e.to_string()))?;

    // Check payload length for supported witness versions
    match witness_version.to_u8() {
        0 => {
            // P2WPKH requires 20-byte payload
            if witness_program.len() != PAYLOAD_LENGTH {
                return Err(AddressError::InvalidLength {
                    expected: PAYLOAD_LENGTH,
                    actual: witness_program.len(),
                });
            }
        }
        1..=16 => {
            // For other witness versions, accept various payload lengths
            // but still require our standard PAYLOAD_LENGTH for consistency
            if witness_program.len() != PAYLOAD_LENGTH {
                return Err(AddressError::InvalidLength {
                    expected: PAYLOAD_LENGTH,
                    actual: witness_program.len(),
                });
            }
        }
        _ => {
            return Err(AddressError::InvalidWitnessVersion(witness_version.to_u8()));
        }
    }

    let mut payload = [0u8; PAYLOAD_LENGTH];
    payload.copy_from_slice(&witness_program);

    Ok((payload, hrp.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let payload = [0x42u8; 20];

        // Test mainnet HRP
        let mainnet_hrp = "pocx";
        let mainnet_address = encode(&payload, mainnet_hrp).unwrap();
        assert!(mainnet_address.starts_with("pocx1"));

        let (decoded_payload, decoded_hrp) = decode(&mainnet_address).unwrap();
        assert_eq!(decoded_payload, payload);
        assert_eq!(decoded_hrp, mainnet_hrp);

        // Test testnet HRP
        let testnet_hrp = "tpocx";
        let testnet_address = encode(&payload, testnet_hrp).unwrap();
        assert!(testnet_address.starts_with("tpocx1"));

        let (decoded_payload, decoded_hrp) = decode(&testnet_address).unwrap();
        assert_eq!(decoded_payload, payload);
        assert_eq!(decoded_hrp, testnet_hrp);

        // Test custom HRP
        let custom_hrp = "test";
        let custom_address = encode(&payload, custom_hrp).unwrap();
        assert!(custom_address.starts_with("test1"));

        let (decoded_payload, decoded_hrp) = decode(&custom_address).unwrap();
        assert_eq!(decoded_payload, payload);
        assert_eq!(decoded_hrp, custom_hrp);
    }
}
