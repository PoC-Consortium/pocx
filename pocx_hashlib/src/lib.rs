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

#![crate_name = "pocx_hashlib"]

//! # PoCX Hashlib - Universal Cryptographic Library for Proof of Capacity
//!
//! This library provides highly optimized implementations of the Shabal256
//! cryptographic hash function and nonce generation algorithms required for
//! Proof of Capacity consensus mechanisms (supporting multiple PoC
//! cryptocurrencies).
//!
//! ## Features
//!
//! - **SIMD Acceleration**: Automatic detection and use of SSE2, AVX, AVX2, and
//!   AVX512 instruction sets
//! - **Memory Optimized**: Efficient memory layouts and direct pointer access
//!   for maximum performance
//! - **Safe API**: Input validation and proper error handling for production
//!   use
//! - **Cross Platform**: Works on x86 and x86_64 architectures with graceful
//!   fallbacks
//!
//! ## Main Functions
//!
//! - [`generate_nonces`] - Generate multiple nonces using optimized SIMD
//!   algorithms
//! - [`calculate_quality_raw`] - Calculate proof of capacity quality for mining
//! - [`calculate_scoop`] - Determine scoop number from block height and
//!   generation signature
//! - [`decode_generation_signature`] - Convert hex string to generation
//!   signature bytes
//!
//! ## Example Usage
//!
//! ```rust
//! use pocx_hashlib::*;
//!
//! // Generate nonces for proof of capacity
//! let mut cache = vec![0u8; 1024 * 1024]; // 1MB cache
//! let account = [0u8; 20]; // Account ID (20 bytes)
//! let seed = [0u8; 32]; // Random seed
//!
//! generate_nonces(&mut cache, 0, &account, &seed, 0, 4)
//!     .expect("Should be able to generate nonces");
//!
//! // Calculate quality for mining
//! let generation_signature = [0u8; 32];
//! let quality = calculate_quality_raw(&account, &seed, 1337, 0, 42, &generation_signature)
//!     .expect("Should be able to calculate quality");
//! ```
// x86/x86_64 SIMD imports
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::noncegen_128::generate_nonces_128;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::noncegen_256::generate_nonces_256;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::noncegen_512::generate_nonces_512;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::quality_128::find_best_quality_128;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::quality_256::find_best_quality_256;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::quality_512::find_best_quality_512;

// ARM NEON SIMD imports
#[cfg(target_arch = "aarch64")]
use crate::noncegen_neon::generate_nonces_neon;
#[cfg(target_arch = "aarch64")]
use crate::quality_neon::find_best_quality_neon;

// Always available (scalar) imports
use crate::noncegen_32::generate_nonces_32;
use crate::noncegen_common::*;
// Used for x86 no-SIMD fallback, unused on aarch64 (has NEON)
#[cfg_attr(target_arch = "aarch64", allow(unused_imports))]
use crate::quality_32::find_best_quality_32;
use crate::shabal256::shabal256;

pub mod batch_validation;
mod buffer;
pub mod error;
pub mod noncegen_32;
pub mod noncegen_batch_32;
pub mod noncegen_common;
pub mod quality_32;
mod shabal256;

// x86/x86_64 SIMD modules
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod noncegen_128;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod noncegen_256;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod noncegen_512;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod noncegen_batch_128;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod noncegen_batch_256;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod noncegen_batch_512;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod quality_128;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod quality_256;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod quality_512;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod shabal256_avx;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod shabal256_avx2;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod shabal256_avx512;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod shabal256_lite_avx;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod shabal256_lite_avx2;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod shabal256_lite_avx512;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod shabal256_lite_sse2;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod shabal256_sse2;

// ARM NEON SIMD modules
#[cfg(target_arch = "aarch64")]
pub mod noncegen_batch_neon;
#[cfg(target_arch = "aarch64")]
pub mod noncegen_neon;
#[cfg(target_arch = "aarch64")]
pub mod quality_neon;
#[cfg(target_arch = "aarch64")]
mod shabal256_lite_neon;
#[cfg(target_arch = "aarch64")]
mod shabal256_neon;

// Re-export batch validation types
pub use batch_validation::{
    validate_proof, validate_proofs, BatchValidationResult, ProofInput, ValidationResult,
};
// Re-export main error types for convenience
pub use error::{PoCXHashError, Result};

/// Calculate the next generation signature for proof of capacity consensus.
///
/// This function combines the previous generation signature with a generator's
/// public key to produce the next generation signature used in the proof of
/// capacity algorithm.
///
/// # Parameters
///
/// * `old_generation_signature` - The previous generation signature (32 bytes)
/// * `generator_public_key` - The generator's public key (64 bytes)
///
/// # Returns
///
/// Returns a 32-byte array containing the new generation signature.
///
/// # Example
///
/// ```rust
/// use pocx_hashlib::calculate_next_generation_signature;
///
/// let old_sig = [0u8; 32];
/// let pub_key = [0u8; 64];
/// let next_sig = calculate_next_generation_signature(&old_sig, &pub_key);
/// ```
pub fn calculate_next_generation_signature(
    old_generation_signature: &[u8],
    generator_pub_key: &[u8],
) -> [u8; 32] {
    assert_eq!(old_generation_signature.len(), 32);
    assert_eq!(generator_pub_key.len(), 64);

    let mut data = [0u8; 64];
    data[0..32].clone_from_slice(old_generation_signature);
    data[32..64].clone_from_slice(&generator_pub_key[0..32]);

    let mut term = [0u8; 64];
    term[0..32].clone_from_slice(&generator_pub_key[32..64]);
    // SAFETY: Transmuting [u8; 64] to [u32; 16] is safe because:
    // - Both types have the same size (64 bytes)
    // - u32 alignment (4) is compatible with u8 alignment (1)
    // - We're reinterpreting bytes as little-endian u32 values for Shabal256 input
    let mut term = unsafe { std::mem::transmute::<[u8; 64], [u32; 16]>(term) };
    term[8] = 0x80;

    shabal256(&data, None, &term)
}

/// generate a specific nonce and calculate quality for a given scoop
/// * `payload` - 20-byte address payload
/// * `seed` - user specified seed
/// * `nonce` - number of nonce to generate
/// * `compression` - compression factor
/// * `scoop` - scoop number (must be < 4096)
/// * `generation_signature_bytes` - generation signature
///
/// # Returns
///
/// Returns the calculated quality value on success
///
/// # Errors
///
/// Returns `PoCXHashError::InvalidInput` if `scoop >= NUM_SCOOPS` (4096)
pub fn calculate_quality_raw(
    address_payload: &[u8; 20],
    seed: &[u8; 32],
    nonce: u64,
    compression: u8,
    scoop: u64,
    generation_signature_bytes: &[u8; 32],
) -> Result<u64> {
    if scoop >= NUM_SCOOPS as u64 {
        return Err(PoCXHashError::InvalidInput(format!(
            "Scoop number {} must be less than {}",
            scoop, NUM_SCOOPS
        )));
    }
    let nonce = generate_scoop(address_payload, seed, scoop, nonce, compression)?;
    Ok(find_best_quality(&nonce, 1, generation_signature_bytes).0)
}

/// Calculate best quality in compression range
pub fn calculate_best_quality_in_range(
    address_payload: &[u8; 20],
    seed: &[u8; 32],
    nonce: u64,
    min_compression: u8,
    max_compression: u8,
    block_height: u64,
    generation_signature_bytes: &[u8; 32],
) -> Result<u64> {
    if min_compression > max_compression {
        return Err(PoCXHashError::InvalidInput(
            "Minimum compression cannot be greater than maximum compression".to_string(),
        ));
    }

    let scoop = calculate_scoop(block_height, generation_signature_bytes);
    let mut best_quality = u64::MAX;

    for current_compression in min_compression..=max_compression {
        let result = generate_scoop(address_payload, seed, scoop, nonce, current_compression)?;
        let quality = find_best_quality(&result, 1, generation_signature_bytes).0;
        best_quality = best_quality.min(quality);
    }

    Ok(best_quality)
}

/// Calculate raw quality directly from block height and generation signature
pub fn calculate_quality_from_height(
    address_payload: &[u8; 20],
    seed: &[u8; 32],
    nonce: u64,
    compression: u8,
    block_height: u64,
    generation_signature_bytes: &[u8; 32],
) -> Result<u64> {
    let scoop = calculate_scoop(block_height, generation_signature_bytes);
    calculate_quality_raw(
        address_payload,
        seed,
        nonce,
        compression,
        scoop,
        generation_signature_bytes,
    )
}

/// converts a hex string representation a generation signature into a byte
/// array
pub fn decode_generation_signature(generation_signature: &str) -> Result<[u8; 32]> {
    let mut generation_signature_bytes = [0; 32];
    hex::decode_to_slice(generation_signature, &mut generation_signature_bytes).map_err(|e| {
        PoCXHashError::HexDecodeError(format!(
            "Failed to decode generation signature '{}': {}",
            generation_signature, e
        ))
    })?;
    Ok(generation_signature_bytes)
}

/// calculates the scoop number for a specific height and generation signature
pub fn calculate_scoop(block_height: u64, generation_signature_bytes: &[u8; 32]) -> u64 {
    let mut data: [u8; 64] = [0; 64];
    let height_bytes: [u8; 8] = block_height.to_be_bytes();

    data[..32].clone_from_slice(generation_signature_bytes);
    data[32..40].clone_from_slice(&height_bytes);
    data[40] = 0x80;
    // SAFETY: Transmuting [u8; 64] to [u32; 16] is safe because:
    // - Both types have the same size (64 bytes)
    // - u32 alignment (4) is compatible with u8 alignment (1)
    // - We're reinterpreting bytes as little-endian u32 values for Shabal256 input
    let data = unsafe { std::mem::transmute::<[u8; 64], [u32; 16]>(data) };

    let new_generation_signature = shabal256(&[], None, &data);
    (u64::from(new_generation_signature[30] & 0x0F) << 8) | u64::from(new_generation_signature[31])
}

/// searches the best quality in a series of nonces and outputs quality and
/// offset
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn find_best_quality(
    data: &[u8],
    number_of_nonces: u64,
    generation_signature_bytes: &[u8; 32],
) -> (u64, u64) {
    // Use the best available SIMD implementation with runtime detection
    if is_x86_feature_detected!("avx512f") {
        find_best_quality_512(data, number_of_nonces, generation_signature_bytes)
    } else if is_x86_feature_detected!("avx2") {
        find_best_quality_256(data, number_of_nonces, generation_signature_bytes)
    } else if is_x86_feature_detected!("avx") || is_x86_feature_detected!("sse2") {
        find_best_quality_128(data, number_of_nonces, generation_signature_bytes)
    } else {
        find_best_quality_32(data, number_of_nonces, generation_signature_bytes)
    }
}

#[cfg(target_arch = "aarch64")]
pub fn find_best_quality(
    data: &[u8],
    number_of_nonces: u64,
    generation_signature_bytes: &[u8; 32],
) -> (u64, u64) {
    // NEON is always available on AArch64
    find_best_quality_neon(data, number_of_nonces, generation_signature_bytes)
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
pub fn find_best_quality(
    data: &[u8],
    number_of_nonces: u64,
    generation_signature_bytes: &[u8; 32],
) -> (u64, u64) {
    find_best_quality_32(data, number_of_nonces, generation_signature_bytes)
}

/// generates a single nonce with compression and extracts the specified scoop
pub fn generate_scoop(
    address_payload: &[u8; 20],
    seed: &[u8; 32],
    scoop: u64,
    nonce: u64,
    compression: u8,
) -> Result<[u8; 64]> {
    let warp = nonce / NUM_SCOOPS as u64;
    let nonce_in_warp = nonce % NUM_SCOOPS as u64;
    let num_uncompressed_nonces = u64::pow(2, compression as u32);

    let mut result = [0u8; SCOOP_SIZE];
    let mut nonce_buffer = [0u8; NONCE_SIZE];

    for i in 0..num_uncompressed_nonces {
        let (scoop_x, nonce_in_warp_x) = if (i % 2) == 0 {
            (scoop, nonce_in_warp)
        } else {
            (nonce_in_warp, scoop)
        };
        let warp_x = num_uncompressed_nonces * warp + i;
        let nonce_x = warp_x * NUM_SCOOPS as u64 + nonce_in_warp_x;

        generate_nonces(&mut nonce_buffer, 0, address_payload, seed, nonce_x, 1)?;

        let start = scoop_x as usize * SCOOP_SIZE;
        let end = start + SCOOP_SIZE;

        // SAFETY: We're casting a slice pointer to a fixed-size array pointer.
        // This is safe because:
        // - start and end are calculated to ensure exactly SCOOP_SIZE (64) bytes
        // - scoop_x is validated to be < NUM_SCOOPS, so start will be within bounds
        // - nonce_buffer has size NONCE_SIZE = NUM_SCOOPS * SCOOP_SIZE
        // - The slice [start..end] is guaranteed to be exactly 64 bytes
        let scoop = unsafe { *(nonce_buffer[start..end].as_ptr() as *const [u8; SCOOP_SIZE]) };

        for (b1, b2) in result.iter_mut().zip(scoop.iter()) {
            *b1 ^= *b2;
        }
    }

    Ok(result)
}

/// generates a series of uncompressed nonces and stores them into an optimized
/// buffer
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn generate_nonces(
    cache: &mut [u8],
    cache_offset: usize,
    address_payload: &[u8; 20],
    seed: &[u8; 32],
    start_nonce: u64,
    num_nonces: u64,
) -> Result<()> {
    let required_size = cache_offset + (num_nonces as usize * NONCE_SIZE);
    if cache.len() < required_size {
        return Err(PoCXHashError::BufferSizeError(format!(
            "Cache buffer too small: need {} bytes, have {} bytes",
            required_size,
            cache.len()
        )));
    }

    // vectorize using SIMD if possible
    if is_x86_feature_detected!("avx512f") {
        let simd_nonces = num_nonces / AVX512_VECTOR_SIZE as u64 * AVX512_VECTOR_SIZE as u64;
        let reminder = num_nonces % AVX512_VECTOR_SIZE as u64;
        generate_nonces_512(
            cache,
            cache_offset,
            address_payload,
            seed,
            start_nonce,
            simd_nonces,
        );
        if reminder > 0 {
            generate_nonces_32(
                cache,
                cache_offset.saturating_add(simd_nonces as usize),
                address_payload,
                seed,
                start_nonce.saturating_add(simd_nonces),
                reminder,
            );
        }
    } else if is_x86_feature_detected!("avx2") {
        let simd_nonces = num_nonces / AVX2_VECTOR_SIZE as u64 * AVX2_VECTOR_SIZE as u64;
        let reminder = num_nonces % AVX2_VECTOR_SIZE as u64;
        generate_nonces_256(
            cache,
            cache_offset,
            address_payload,
            seed,
            start_nonce,
            simd_nonces,
        );
        if reminder > 0 {
            generate_nonces_32(
                cache,
                cache_offset.saturating_add(simd_nonces as usize),
                address_payload,
                seed,
                start_nonce.saturating_add(simd_nonces),
                reminder,
            );
        }
    } else if is_x86_feature_detected!("avx") || is_x86_feature_detected!("sse2") {
        let simd_nonces = num_nonces / AVX_VECTOR_SIZE as u64 * AVX_VECTOR_SIZE as u64;
        let reminder = num_nonces % AVX_VECTOR_SIZE as u64;
        generate_nonces_128(
            cache,
            cache_offset,
            address_payload,
            seed,
            start_nonce,
            simd_nonces,
        );
        if reminder > 0 {
            generate_nonces_32(
                cache,
                cache_offset.saturating_add(simd_nonces as usize),
                address_payload,
                seed,
                start_nonce.saturating_add(simd_nonces),
                reminder,
            );
        }
    } else {
        generate_nonces_32(
            cache,
            cache_offset,
            address_payload,
            seed,
            start_nonce,
            num_nonces,
        );
    }

    Ok(())
}

#[cfg(target_arch = "aarch64")]
pub fn generate_nonces(
    cache: &mut [u8],
    cache_offset: usize,
    address_payload: &[u8; 20],
    seed: &[u8; 32],
    start_nonce: u64,
    num_nonces: u64,
) -> Result<()> {
    let required_size = cache_offset + (num_nonces as usize * NONCE_SIZE);
    if cache.len() < required_size {
        return Err(PoCXHashError::BufferSizeError(format!(
            "Cache buffer too small: need {} bytes, have {} bytes",
            required_size,
            cache.len()
        )));
    }

    // NEON is always available on AArch64
    const NEON_VECTOR_SIZE: u64 = 4;
    let simd_nonces = num_nonces / NEON_VECTOR_SIZE * NEON_VECTOR_SIZE;
    let remainder = num_nonces % NEON_VECTOR_SIZE;

    if simd_nonces > 0 {
        generate_nonces_neon(
            cache,
            cache_offset,
            address_payload,
            seed,
            start_nonce,
            simd_nonces,
        );
    }

    if remainder > 0 {
        generate_nonces_32(
            cache,
            cache_offset + (simd_nonces as usize * NONCE_SIZE),
            address_payload,
            seed,
            start_nonce + simd_nonces,
            remainder,
        );
    }

    Ok(())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
pub fn generate_nonces(
    cache: &mut [u8],
    cache_offset: usize,
    address_payload: &[u8; 20],
    seed: &[u8; 32],
    start_nonce: u64,
    num_nonces: u64,
) -> Result<()> {
    let required_size = cache_offset + (num_nonces as usize * NONCE_SIZE);
    if cache.len() < required_size {
        return Err(PoCXHashError::BufferSizeError(format!(
            "Cache buffer too small: need {} bytes, have {} bytes",
            required_size,
            cache.len()
        )));
    }

    generate_nonces_32(
        cache,
        cache_offset,
        address_payload,
        seed,
        start_nonce,
        num_nonces,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_calculate_scoop() {
        let block_height = 0;
        let mut generation_signature_bytes = [0u8; 32];
        hex::decode_to_slice(
            "9821beb3b34d9a3b30127c05f8d1e9006f8a02f565a3572145134bbe34d37a76",
            &mut generation_signature_bytes,
        )
        .unwrap();

        let scoop = calculate_scoop(block_height, &generation_signature_bytes);
        assert_eq!(scoop, 667);
    }

    #[test]
    fn test_decode_generation_signature_valid() {
        let hex_string = "9821beb3b34d9a3b30127c05f8d1e9006f8a02f565a3572145134bbe34d37a76";
        let result = decode_generation_signature(hex_string);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_decode_generation_signature_invalid_length() {
        let hex_string = "9821beb3b34d9a3b30127c05f8d1e900"; // Too short
        let result = decode_generation_signature(hex_string);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_generation_signature_invalid_hex() {
        let hex_string = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"; // Invalid hex
        let result = decode_generation_signature(hex_string);
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_quality_raw_invalid_scoop() {
        let address_payload = [0u8; 20];
        let seed = [0u8; 32];
        let generation_signature = [0u8; 32];
        let result =
            calculate_quality_raw(&address_payload, &seed, 0, 0, 5000, &generation_signature); // scoop > 4096
        assert!(result.is_err());
        assert!(
            matches!(result, Err(PoCXHashError::InvalidInput(_))),
            "Expected InvalidInput error for scoop > 4096, got: {:?}",
            result
        );
    }

    #[test]
    fn test_calculate_quality_from_height() {
        let address_payload = [1u8; 20];
        let seed = [2u8; 32];
        let mut generation_signature_bytes = [0u8; 32];
        hex::decode_to_slice(
            "9821beb3b34d9a3b30127c05f8d1e9006f8a02f565a3572145134bbe34d37a76",
            &mut generation_signature_bytes,
        )
        .unwrap();

        let result = calculate_quality_from_height(
            &address_payload,
            &seed,
            1337,
            1, // min compression level
            0, // block height
            &generation_signature_bytes,
        );

        assert!(result.is_ok());
        let quality = result.unwrap();
        assert!(quality > 0);
    }

    #[test]
    fn test_calculate_quality_from_height_consistency() {
        let address_payload = [3u8; 20];
        let seed = [4u8; 32];
        let mut generation_signature_bytes = [0u8; 32];
        hex::decode_to_slice(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            &mut generation_signature_bytes,
        )
        .unwrap();
        let block_height = 100;
        let nonce = 42;
        let compression = 1;

        // Use new function
        let quality_from_height = calculate_quality_from_height(
            &address_payload,
            &seed,
            nonce,
            compression,
            block_height,
            &generation_signature_bytes,
        )
        .unwrap();

        // Use individual functions
        let scoop = calculate_scoop(block_height, &generation_signature_bytes);
        let quality_from_scoop = calculate_quality_raw(
            &address_payload,
            &seed,
            nonce,
            compression,
            scoop,
            &generation_signature_bytes,
        )
        .unwrap();

        // Should be identical
        assert_eq!(quality_from_height, quality_from_scoop);
    }

    #[test]
    fn test_calculate_best_quality_in_range() {
        let address_payload = [1u8; 20];
        let seed = [2u8; 32];
        let mut generation_signature_bytes = [0u8; 32];
        hex::decode_to_slice(
            "9821beb3b34d9a3b30127c05f8d1e9006f8a02f565a3572145134bbe34d37a76",
            &mut generation_signature_bytes,
        )
        .unwrap();

        let single_result = calculate_best_quality_in_range(
            &address_payload,
            &seed,
            1337,
            1,
            1,
            0,
            &generation_signature_bytes,
        );

        assert!(single_result.is_ok());
        let single_quality = single_result.unwrap();
        assert!(single_quality > 0);

        let range_result = calculate_best_quality_in_range(
            &address_payload,
            &seed,
            1337,
            1,
            3,
            0,
            &generation_signature_bytes,
        );

        assert!(range_result.is_ok());
        let range_quality = range_result.unwrap();
        assert!(range_quality > 0);
        assert!(range_quality <= single_quality);
    }

    #[test]
    fn test_calculate_best_quality_in_range_invalid_params() {
        let address_payload = [1u8; 20];
        let seed = [2u8; 32];
        let generation_signature_bytes = [0u8; 32];

        let result = calculate_best_quality_in_range(
            &address_payload,
            &seed,
            1337,
            2,
            1,
            0,
            &generation_signature_bytes,
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(PoCXHashError::InvalidInput(_))));
    }
}
