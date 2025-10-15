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

use crate::models::Block;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MiningInfo {
    pub generation_signature: String,
    pub base_target: u64,
    pub height: u64,
    pub block_hash: String,
    pub target_quality: u64,
    pub minimum_compression_level: u8,
    pub target_compression_level: u8,
    #[serde(skip_serializing)]
    pub generation_signature_bytes: [u8; 32],
}

fn generate_random_generation_signature() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::rng().fill(&mut seed);
    seed
}

fn generate_random_block_hash() -> String {
    let mut hash = [0u8; 32];
    rand::rng().fill(&mut hash);
    hex::encode(hash)
}

impl MiningInfo {
    pub fn new(
        height: u64,
        base_target: u64,
        generation_signature: Option<String>,
        minimum_compression_level: u8,
        target_compression_level: u8,
    ) -> Self {
        let generation_signature_bytes = if let Some(generation_signature) = generation_signature {
            hex::decode(generation_signature)
                .unwrap_or_default()
                .try_into()
                .unwrap_or_else(|_| generate_random_generation_signature())
        } else {
            generate_random_generation_signature()
        };

        Self {
            generation_signature: hex::encode(generation_signature_bytes),
            generation_signature_bytes,
            base_target,
            height,
            block_hash: generate_random_block_hash(),
            target_quality: u64::MAX,
            minimum_compression_level,
            target_compression_level,
        }
    }
}

impl MiningInfo {
    pub fn from_block(
        block: Block,
        minimum_compression_level: u8,
        target_compression_level: u8,
    ) -> Result<Self, String> {
        let decoded = hex::decode(&block.generation_signature)
            .map_err(|e| format!("Failed to decode generation signature: {}", e))?;
        let generation_signature_bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| "Generation signature must be exactly 32 bytes".to_string())?;
        Ok(Self {
            generation_signature_bytes,
            height: block.height as u64,
            base_target: block.base_target as u64,
            generation_signature: block.generation_signature,
            block_hash: generate_random_block_hash(),
            target_quality: u64::MAX,
            minimum_compression_level,
            target_compression_level,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mining_info_new() {
        let info = MiningInfo::new(100, 5000, None, 1, 4);
        assert_eq!(info.height, 100);
        assert_eq!(info.base_target, 5000);
        assert_eq!(info.target_quality, u64::MAX);
        assert_eq!(info.generation_signature_bytes.len(), 32);
        assert_eq!(info.minimum_compression_level, 1);
        assert_eq!(info.target_compression_level, 4);
    }

    #[test]
    fn test_mining_info_with_signature() {
        let sig = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let info = MiningInfo::new(200, 10000, Some(sig.to_string()), 2, 8);
        assert_eq!(info.generation_signature, sig);
        assert_eq!(info.height, 200);
        assert_eq!(info.base_target, 10000);
        assert_eq!(info.minimum_compression_level, 2);
        assert_eq!(info.target_compression_level, 8);
    }

    #[test]
    fn test_mining_info_invalid_signature() {
        // Invalid hex should generate random signature
        let info = MiningInfo::new(300, 15000, Some("invalid_hex".to_string()), 1, 1);
        assert_eq!(info.generation_signature_bytes.len(), 32);
        assert_ne!(info.generation_signature, "invalid_hex");
        assert_eq!(info.minimum_compression_level, 1);
        assert_eq!(info.target_compression_level, 1);
    }

    #[test]
    fn test_random_generation_signature() {
        let sig1 = generate_random_generation_signature();
        let sig2 = generate_random_generation_signature();
        assert_eq!(sig1.len(), 32);
        assert_eq!(sig2.len(), 32);
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_mining_info_from_block() {
        use chrono::DateTime;

        let block = Block {
            height: 1000,
            base_target: 20000,
            generation_signature:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            cumulative_difficulty: 50000,
            generator: "test_generator".to_string(),
            creation_time: DateTime::from_timestamp(1234567890, 0).unwrap().naive_utc(),
            nonce: 12345,
            seed: "test_seed".to_string(),
            poc_time: 100,
        };

        let info = MiningInfo::from_block(block, 1, 4)
            .expect("Test block should create valid mining info");
        assert_eq!(info.height, 1000);
        assert_eq!(info.base_target, 20000);
        assert_eq!(
            info.generation_signature,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(info.target_quality, u64::MAX);
        assert_eq!(info.minimum_compression_level, 1);
        assert_eq!(info.target_compression_level, 4);
    }
}
