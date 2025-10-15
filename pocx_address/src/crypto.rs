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

//! Bitcoin-compatible cryptographic key derivation

use rand::RngCore;
use ripemd::Ripemd160;
use secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// Private key (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey([u8; 32]);

/// Public key (33 bytes, compressed)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey([u8; 33]);

impl PrivateKey {
    /// Generate random private key
    pub fn generate_random() -> Self {
        let mut bytes = [0u8; 32];

        loop {
            rand::rng().fill_bytes(&mut bytes);
            if !bytes.iter().all(|&b| b == 0) && !is_key_overflow(&bytes) {
                break;
            }
        }

        PrivateKey(bytes)
    }

    /// Derive public key
    pub fn to_public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array(self.0).expect("Private key should be valid");
        let public_key = Secp256k1PublicKey::from_secret_key(&secp, &secret_key);
        PublicKey(public_key.serialize())
    }

    /// Convert to WIF format
    pub fn to_wif(&self, network_version: u8) -> String {
        let wif_version = match network_version {
            0x7F | 0x7E => 0xEF, // Testnet
            _ => 0x80,           // Mainnet
        };

        let mut wif_data = Vec::with_capacity(34);
        wif_data.push(wif_version);
        wif_data.extend_from_slice(&self.0);
        wif_data.push(0x01); // Compression flag

        let hash1 = Sha256::digest(&wif_data);
        let hash2 = Sha256::digest(hash1);
        wif_data.extend_from_slice(&hash2[..4]);

        bs58::encode(wif_data).into_string()
    }

    /// Get raw bytes (testing only)
    #[cfg(test)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PublicKey {
    /// Derive Hash160 (20 bytes)
    pub fn to_hash160(&self) -> [u8; 20] {
        let sha256_hash = Sha256::digest(self.0);
        let ripemd_hash = Ripemd160::digest(sha256_hash);
        let mut result = [0u8; 20];
        result.copy_from_slice(&ripemd_hash);
        result
    }

    /// Convert to address payload
    pub fn to_address_payload(&self) -> [u8; 20] {
        self.to_hash160()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get raw bytes (testing only)
    #[cfg(test)]
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}

/// Check if private key overflows secp256k1 curve order
fn is_key_overflow(key: &[u8; 32]) -> bool {
    // secp256k1 curve order

    const CURVE_ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    for i in 0..32 {
        match key[i].cmp(&CURVE_ORDER[i]) {
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Equal => continue,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_key_generation() {
        let key1 = PrivateKey::generate_random();
        let key2 = PrivateKey::generate_random();

        // Keys should be different
        assert_ne!(key1, key2);

        // Keys should not be zero
        assert_ne!(key1.as_bytes(), &[0u8; 32]);
        assert_ne!(key2.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_public_key_derivation() {
        let privkey = PrivateKey::generate_random();
        let pubkey1 = privkey.to_public_key();
        let pubkey2 = privkey.to_public_key();

        // Same private key produces same public key
        assert_eq!(pubkey1, pubkey2);

        // Public key is 33 bytes
        assert_eq!(pubkey1.as_bytes().len(), 33);

        // First byte is 0x02 or 0x03
        let prefix = pubkey1.as_bytes()[0];
        assert!(prefix == 0x02 || prefix == 0x03);
    }

    #[test]
    fn test_hash160_derivation() {
        let privkey = PrivateKey::generate_random();
        let pubkey = privkey.to_public_key();
        let hash160_1 = pubkey.to_hash160();
        let hash160_2 = pubkey.to_address_payload();

        // Same public key produces same hash160
        assert_eq!(hash160_1, hash160_2);

        // Hash160 is 20 bytes
        assert_eq!(hash160_1.len(), 20);
    }

    #[test]
    fn test_deterministic_derivation() {
        let privkey_bytes = [0x01; 32];
        let privkey1 = PrivateKey(privkey_bytes);
        let privkey2 = PrivateKey(privkey_bytes);

        let pubkey1 = privkey1.to_public_key();
        let pubkey2 = privkey2.to_public_key();

        let payload1 = pubkey1.to_address_payload();
        let payload2 = pubkey2.to_address_payload();

        // Results should be identical
        assert_eq!(pubkey1, pubkey2);
        assert_eq!(payload1, payload2);
    }

    #[test]
    fn test_curve_order_validation() {
        assert!(!is_key_overflow(&[0x00; 32]));
        let mut max_valid = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x40,
        ];
        assert!(!is_key_overflow(&max_valid));

        max_valid[31] = 0x41;
        assert!(is_key_overflow(&max_valid));
    }

    #[test]
    fn test_wif_encoding() {
        let privkey = PrivateKey::generate_random();
        let mainnet_wif = privkey.to_wif(0x55);
        assert!(mainnet_wif.starts_with('K') || mainnet_wif.starts_with('L'));
        assert_eq!(mainnet_wif.len(), 52);
        let testnet_wif = privkey.to_wif(0x7F);
        assert!(testnet_wif.starts_with('c') || testnet_wif.starts_with('9'));
        assert_eq!(testnet_wif.len(), 52);
        assert_ne!(mainnet_wif, testnet_wif);
    }

    #[test]
    fn test_public_key_hex() {
        let privkey = PrivateKey::generate_random();
        let pubkey = privkey.to_public_key();
        let hex = pubkey.to_hex();
        assert_eq!(hex.len(), 66);
        assert!(hex.starts_with("02") || hex.starts_with("03"));
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
