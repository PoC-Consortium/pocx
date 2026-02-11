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

//! Batch proof validation for server-side PoC verification.
//!
//! Pools and wallets receive proofs from many miners — each with different
//! `(account, seed, nonce, compression)` parameters. This module provides
//! heterogeneous SIMD nonce generation where each lane processes a completely
//! independent triple, avoiding the 100% scalar fallback that occurs when
//! calling `generate_nonces(..., num_nonces=1)` for individual work units.

use crate::error::{PoCXHashError, Result};
use crate::noncegen_batch_32::generate_and_extract_scoop_32;
use crate::noncegen_common::*;
use crate::shabal256::shabal256_lite;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

// SIMD batch imports
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::noncegen_batch_128::generate_and_extract_scoops_128;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::noncegen_batch_256::generate_and_extract_scoops_256;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::noncegen_batch_512::generate_and_extract_scoops_512;

#[cfg(target_arch = "aarch64")]
use crate::noncegen_batch_neon::generate_and_extract_scoops_neon;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Input for validating a single PoC proof.
#[derive(Clone, Debug)]
pub struct ProofInput {
    pub address_payload: [u8; 20],
    pub seed: [u8; 32],
    pub nonce: u64,
    pub compression: u8,
    pub block_height: u64,
    pub generation_signature: [u8; 32],
    pub base_target: u64,
    /// If set, enables early surrender when computed quality mismatches.
    pub claimed_quality: Option<u64>,
}

/// Result of validating a single PoC proof.
#[derive(Clone, Debug)]
pub struct ValidationResult {
    pub quality: u64,
    pub deadline: u64,
    pub is_valid: bool,
    pub error: Option<PoCXHashError>,
}

/// Batch result with early surrender tracking.
#[derive(Clone, Debug)]
pub struct BatchValidationResult {
    pub results: Vec<ValidationResult>,
    pub early_surrender: bool,
    pub surrender_index: Option<usize>,
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct WorkUnit {
    proof_index: usize,
    address_payload: [u8; 20],
    seed: [u8; 32],
    base_nonce: u64,
    scoop: u64,
}

struct ProofAccumulator {
    xor_result: Mutex<[u8; SCOOP_SIZE]>,
    #[allow(dead_code)]
    units_completed: AtomicUsize,
    #[allow(dead_code)]
    units_expected: usize,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Validate a batch of PoC proofs using SIMD-accelerated nonce generation.
///
/// Each proof is expanded into work units based on its compression level,
/// processed in SIMD-width batches, and finalized with quality computation.
/// Supports early surrender when `claimed_quality` is set and mismatches.
pub fn validate_proofs(inputs: &[ProofInput]) -> Result<BatchValidationResult> {
    if inputs.is_empty() {
        return Ok(BatchValidationResult {
            results: vec![],
            early_surrender: false,
            surrender_index: None,
        });
    }

    // Step 1: Work expansion
    let mut work_units = Vec::new();
    let mut accumulators = Vec::new();

    for (idx, input) in inputs.iter().enumerate() {
        let scoop = crate::calculate_scoop(input.block_height, &input.generation_signature);
        let units = expand_work_units(idx, input, scoop);
        let expected = units.len();
        work_units.extend(units);
        accumulators.push(ProofAccumulator {
            xor_result: Mutex::new([0u8; SCOOP_SIZE]),
            units_completed: AtomicUsize::new(0),
            units_expected: expected,
        });
    }

    let surrender = AtomicBool::new(false);

    // Step 2+3: SIMD batch processing + XOR accumulation
    let total_work = work_units.len();
    let simd_width = detect_simd_width();
    let hw_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let max_threads = hw_threads.saturating_sub(1).max(1);
    let min_work_per_thread = simd_width;
    let num_threads = max_threads.min(total_work.div_ceil(min_work_per_thread));

    if num_threads <= 1 {
        // Single-threaded fast path
        process_work_range(&work_units, &accumulators, &surrender);
    } else {
        // Multi-threaded via std::thread::scope
        let chunk_size = total_work.div_ceil(num_threads);
        std::thread::scope(|s| {
            for chunk_start in (0..total_work).step_by(chunk_size) {
                let chunk_end = std::cmp::min(chunk_start + chunk_size, total_work);
                let chunk = &work_units[chunk_start..chunk_end];
                let accs = &accumulators;
                let surr = &surrender;
                s.spawn(move || {
                    process_work_range(chunk, accs, surr);
                });
            }
        });
    }

    // Step 4: Quality finalization
    let mut results = Vec::with_capacity(inputs.len());
    let mut early_surrender_flag = false;
    let mut surrender_index = None;

    for (idx, input) in inputs.iter().enumerate() {
        let xor_result = accumulators[idx].xor_result.lock().unwrap();
        let quality = shabal256_lite(&xor_result[..], &input.generation_signature);
        let deadline = if input.base_target > 0 {
            quality / input.base_target
        } else {
            u64::MAX
        };

        let (is_valid, error) = if let Some(claimed) = input.claimed_quality {
            if quality == claimed {
                (true, None)
            } else {
                early_surrender_flag = true;
                if surrender_index.is_none() {
                    surrender_index = Some(idx);
                }
                (
                    false,
                    Some(PoCXHashError::QualityMismatch {
                        expected: claimed,
                        actual: quality,
                        proof_index: idx,
                    }),
                )
            }
        } else {
            (true, None)
        };

        results.push(ValidationResult {
            quality,
            deadline,
            is_valid,
            error,
        });
    }

    Ok(BatchValidationResult {
        results,
        early_surrender: early_surrender_flag,
        surrender_index,
    })
}

/// Validate a single PoC proof (convenience wrapper).
pub fn validate_proof(input: &ProofInput) -> Result<ValidationResult> {
    let batch = validate_proofs(std::slice::from_ref(input))?;
    Ok(batch.results.into_iter().next().unwrap())
}

// ---------------------------------------------------------------------------
// Work expansion
// ---------------------------------------------------------------------------

fn expand_work_units(proof_index: usize, input: &ProofInput, scoop: u64) -> Vec<WorkUnit> {
    let warp = input.nonce / NUM_SCOOPS as u64;
    let nonce_in_warp = input.nonce % NUM_SCOOPS as u64;
    let num_uncompressed = 1u64 << input.compression as u64;

    let mut units = Vec::with_capacity(num_uncompressed as usize);
    for i in 0..num_uncompressed {
        let (scoop_x, nonce_in_warp_x) = if i % 2 == 0 {
            (scoop, nonce_in_warp)
        } else {
            (nonce_in_warp, scoop)
        };
        let warp_x = num_uncompressed * warp + i;
        let nonce_x = warp_x * NUM_SCOOPS as u64 + nonce_in_warp_x;

        units.push(WorkUnit {
            proof_index,
            address_payload: input.address_payload,
            seed: input.seed,
            base_nonce: nonce_x,
            scoop: scoop_x,
        });
    }
    units
}

// ---------------------------------------------------------------------------
// SIMD dispatch + processing
// ---------------------------------------------------------------------------

fn detect_simd_width() -> usize {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("avx512f") {
            return 16;
        }
        if is_x86_feature_detected!("avx2") {
            return 8;
        }
        if is_x86_feature_detected!("avx") || is_x86_feature_detected!("sse2") {
            return 4;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        return 4; // NEON always available
    }
    #[allow(unreachable_code)]
    1
}

fn process_work_range(
    work_units: &[WorkUnit],
    accumulators: &[ProofAccumulator],
    surrender: &AtomicBool,
) {
    let mut i = 0;
    while i < work_units.len() {
        if surrender.load(Ordering::Relaxed) {
            break;
        }
        let remaining = work_units.len() - i;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if is_x86_feature_detected!("avx512f") && remaining >= 16 {
                process_batch_simd::<16>(&work_units[i..i + 16], accumulators);
                i += 16;
                continue;
            }
            if is_x86_feature_detected!("avx2") && remaining >= 8 {
                process_batch_simd::<8>(&work_units[i..i + 8], accumulators);
                i += 8;
                continue;
            }
            if (is_x86_feature_detected!("avx") || is_x86_feature_detected!("sse2"))
                && remaining >= 4
            {
                process_batch_simd::<4>(&work_units[i..i + 4], accumulators);
                i += 4;
                continue;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if remaining >= 4 {
                process_batch_simd::<4>(&work_units[i..i + 4], accumulators);
                i += 4;
                continue;
            }
        }

        // Scalar fallback
        process_single_scalar(&work_units[i], accumulators);
        i += 1;
    }
}

fn process_single_scalar(wu: &WorkUnit, accumulators: &[ProofAccumulator]) {
    let scoop_data =
        generate_and_extract_scoop_32(&wu.address_payload, &wu.seed, wu.base_nonce, wu.scoop);
    accumulate_scoop(wu.proof_index, &scoop_data, accumulators);
}

fn process_batch_simd<const N: usize>(work_units: &[WorkUnit], accumulators: &[ProofAccumulator]) {
    debug_assert_eq!(work_units.len(), N);

    match N {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        16 => {
            let mut payloads = [[0u8; 20]; 16];
            let mut seeds = [[0u8; 32]; 16];
            let mut nonces = [0u64; 16];
            let mut scoops = [0u64; 16];
            for (j, wu) in work_units.iter().enumerate() {
                payloads[j] = wu.address_payload;
                seeds[j] = wu.seed;
                nonces[j] = wu.base_nonce;
                scoops[j] = wu.scoop;
            }
            let results = generate_and_extract_scoops_512(&payloads, &seeds, &nonces, &scoops);
            for (j, wu) in work_units.iter().enumerate() {
                accumulate_scoop(wu.proof_index, &results[j], accumulators);
            }
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        8 => {
            let mut payloads = [[0u8; 20]; 8];
            let mut seeds = [[0u8; 32]; 8];
            let mut nonces = [0u64; 8];
            let mut scoops = [0u64; 8];
            for (j, wu) in work_units.iter().enumerate() {
                payloads[j] = wu.address_payload;
                seeds[j] = wu.seed;
                nonces[j] = wu.base_nonce;
                scoops[j] = wu.scoop;
            }
            let results = generate_and_extract_scoops_256(&payloads, &seeds, &nonces, &scoops);
            for (j, wu) in work_units.iter().enumerate() {
                accumulate_scoop(wu.proof_index, &results[j], accumulators);
            }
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        4 => {
            process_batch_4lane_x86(work_units, accumulators);
        }
        #[cfg(target_arch = "aarch64")]
        4 => {
            let mut payloads = [[0u8; 20]; 4];
            let mut seeds = [[0u8; 32]; 4];
            let mut nonces = [0u64; 4];
            let mut scoops = [0u64; 4];
            for (j, wu) in work_units.iter().enumerate() {
                payloads[j] = wu.address_payload;
                seeds[j] = wu.seed;
                nonces[j] = wu.base_nonce;
                scoops[j] = wu.scoop;
            }
            let results = generate_and_extract_scoops_neon(&payloads, &seeds, &nonces, &scoops);
            for (j, wu) in work_units.iter().enumerate() {
                accumulate_scoop(wu.proof_index, &results[j], accumulators);
            }
        }
        _ => {
            // Scalar fallback for unsupported widths
            for wu in work_units {
                process_single_scalar(wu, accumulators);
            }
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn process_batch_4lane_x86(work_units: &[WorkUnit], accumulators: &[ProofAccumulator]) {
    let mut payloads = [[0u8; 20]; 4];
    let mut seeds = [[0u8; 32]; 4];
    let mut nonces = [0u64; 4];
    let mut scoops = [0u64; 4];
    for (j, wu) in work_units.iter().enumerate() {
        payloads[j] = wu.address_payload;
        seeds[j] = wu.seed;
        nonces[j] = wu.base_nonce;
        scoops[j] = wu.scoop;
    }
    let results = generate_and_extract_scoops_128(&payloads, &seeds, &nonces, &scoops);
    for (j, wu) in work_units.iter().enumerate() {
        accumulate_scoop(wu.proof_index, &results[j], accumulators);
    }
}

fn accumulate_scoop(
    proof_index: usize,
    scoop_data: &[u8; SCOOP_SIZE],
    accumulators: &[ProofAccumulator],
) {
    let acc = &accumulators[proof_index];
    let mut xor_guard = acc.xor_result.lock().unwrap();
    for (b1, b2) in xor_guard.iter_mut().zip(scoop_data.iter()) {
        *b1 ^= *b2;
    }
    drop(xor_guard);
    acc.units_completed.fetch_add(1, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> [u8; 32] {
        hex::decode("AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE")
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn test_payload() -> [u8; 20] {
        hex::decode("99BC78BA577A95A11F1A344D4D2AE55F2F857B98")
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn test_gensig() -> [u8; 32] {
        let mut gensig = [0u8; 32];
        hex::decode_to_slice(
            "9821beb3b34d9a3b30127c05f8d1e9006f8a02f565a3572145134bbe34d37a76",
            &mut gensig,
        )
        .unwrap();
        gensig
    }

    #[test]
    fn test_validate_proof_matches_calculate_quality_raw() {
        let seed = test_seed();
        let payload = test_payload();
        let gensig = test_gensig();
        let block_height = 0u64;
        let base_target = 1u64;

        for compression in 0..=3u8 {
            for nonce in [0, 1, 42, 1337] {
                let expected_quality = crate::calculate_quality_from_height(
                    &payload,
                    &seed,
                    nonce,
                    compression,
                    block_height,
                    &gensig,
                )
                .unwrap();

                let input = ProofInput {
                    address_payload: payload,
                    seed,
                    nonce,
                    compression,
                    block_height,
                    generation_signature: gensig,
                    base_target,
                    claimed_quality: None,
                };

                let result = validate_proof(&input).unwrap();
                assert_eq!(
                    result.quality, expected_quality,
                    "Quality mismatch: compression={}, nonce={}",
                    compression, nonce
                );
                assert!(result.is_valid);
                assert!(result.error.is_none());
            }
        }
    }

    #[test]
    fn test_validate_proofs_batch() {
        let gensig = test_gensig();
        let base_target = 1000u64;

        let inputs: Vec<ProofInput> = (0..8)
            .map(|i| ProofInput {
                address_payload: [i as u8 + 1; 20],
                seed: [(i as u8 + 1).wrapping_mul(0xAB); 32],
                nonce: 100 + i,
                compression: 0,
                block_height: 0,
                generation_signature: gensig,
                base_target,
                claimed_quality: None,
            })
            .collect();

        let batch_result = validate_proofs(&inputs).unwrap();
        assert_eq!(batch_result.results.len(), 8);
        assert!(!batch_result.early_surrender);

        // Cross-validate each result
        for (idx, input) in inputs.iter().enumerate() {
            let expected = crate::calculate_quality_from_height(
                &input.address_payload,
                &input.seed,
                input.nonce,
                input.compression,
                input.block_height,
                &input.generation_signature,
            )
            .unwrap();
            assert_eq!(
                batch_result.results[idx].quality, expected,
                "Batch result {} mismatch",
                idx
            );
            assert!(batch_result.results[idx].is_valid);
        }
    }

    #[test]
    fn test_validate_proof_claimed_quality_match() {
        let seed = test_seed();
        let payload = test_payload();
        let gensig = test_gensig();

        // First compute the real quality
        let real_quality =
            crate::calculate_quality_from_height(&payload, &seed, 1337, 0, 0, &gensig).unwrap();

        let input = ProofInput {
            address_payload: payload,
            seed,
            nonce: 1337,
            compression: 0,
            block_height: 0,
            generation_signature: gensig,
            base_target: 1,
            claimed_quality: Some(real_quality),
        };

        let result = validate_proof(&input).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.quality, real_quality);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_validate_proof_claimed_quality_mismatch() {
        let seed = test_seed();
        let payload = test_payload();
        let gensig = test_gensig();

        let input = ProofInput {
            address_payload: payload,
            seed,
            nonce: 1337,
            compression: 0,
            block_height: 0,
            generation_signature: gensig,
            base_target: 1,
            claimed_quality: Some(12345), // wrong
        };

        let result = validate_proof(&input).unwrap();
        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(matches!(
            result.error,
            Some(PoCXHashError::QualityMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_proofs_early_surrender() {
        let gensig = test_gensig();

        let inputs = vec![
            ProofInput {
                address_payload: [0x01; 20],
                seed: [0xAA; 32],
                nonce: 100,
                compression: 0,
                block_height: 0,
                generation_signature: gensig,
                base_target: 1,
                claimed_quality: Some(999), // likely wrong
            },
            ProofInput {
                address_payload: [0x02; 20],
                seed: [0xBB; 32],
                nonce: 200,
                compression: 0,
                block_height: 0,
                generation_signature: gensig,
                base_target: 1,
                claimed_quality: None, // no claim, always valid
            },
        ];

        let result = validate_proofs(&inputs).unwrap();
        assert_eq!(result.results.len(), 2);
        // First proof should fail (wrong claimed quality)
        assert!(!result.results[0].is_valid);
        // Second proof should still be computed and valid
        assert!(result.results[1].is_valid);
        assert!(result.early_surrender);
        assert_eq!(result.surrender_index, Some(0));
    }

    #[test]
    fn test_validate_proofs_empty() {
        let result = validate_proofs(&[]).unwrap();
        assert!(result.results.is_empty());
        assert!(!result.early_surrender);
    }

    #[test]
    fn test_validate_proof_deadline_calculation() {
        let seed = test_seed();
        let payload = test_payload();
        let gensig = test_gensig();
        let base_target = 1000u64;

        let input = ProofInput {
            address_payload: payload,
            seed,
            nonce: 1337,
            compression: 0,
            block_height: 0,
            generation_signature: gensig,
            base_target,
            claimed_quality: None,
        };

        let result = validate_proof(&input).unwrap();
        assert_eq!(result.deadline, result.quality / base_target);
    }

    #[test]
    fn test_validate_proof_zero_base_target() {
        let input = ProofInput {
            address_payload: [0x01; 20],
            seed: [0xAA; 32],
            nonce: 100,
            compression: 0,
            block_height: 0,
            generation_signature: [0u8; 32],
            base_target: 0,
            claimed_quality: None,
        };

        let result = validate_proof(&input).unwrap();
        assert_eq!(result.deadline, u64::MAX);
    }

    #[test]
    fn test_validate_proof_compression_levels() {
        let seed = test_seed();
        let payload = test_payload();
        let gensig = test_gensig();

        for compression in 0..=4u8 {
            let expected = crate::calculate_quality_from_height(
                &payload,
                &seed,
                1337,
                compression,
                0,
                &gensig,
            )
            .unwrap();

            let input = ProofInput {
                address_payload: payload,
                seed,
                nonce: 1337,
                compression,
                block_height: 0,
                generation_signature: gensig,
                base_target: 1,
                claimed_quality: None,
            };

            let result = validate_proof(&input).unwrap();
            assert_eq!(
                result.quality, expected,
                "Compression {} quality mismatch",
                compression
            );
        }
    }

    #[test]
    fn test_work_expansion_compression_0() {
        let input = ProofInput {
            address_payload: [0; 20],
            seed: [0; 32],
            nonce: 1337,
            compression: 0,
            block_height: 0,
            generation_signature: [0; 32],
            base_target: 1,
            claimed_quality: None,
        };
        let units = expand_work_units(0, &input, 667);
        assert_eq!(units.len(), 1); // 2^0 = 1
    }

    #[test]
    fn test_work_expansion_compression_3() {
        let input = ProofInput {
            address_payload: [0; 20],
            seed: [0; 32],
            nonce: 1337,
            compression: 3,
            block_height: 0,
            generation_signature: [0; 32],
            base_target: 1,
            claimed_quality: None,
        };
        let units = expand_work_units(0, &input, 667);
        assert_eq!(units.len(), 8); // 2^3 = 8
    }

    #[test]
    fn test_validate_proofs_large_batch() {
        let gensig = test_gensig();

        // 32 proofs with compression 0 — enough to exercise SIMD batching
        let inputs: Vec<ProofInput> = (0..32)
            .map(|i| ProofInput {
                address_payload: {
                    let mut p = [0u8; 20];
                    p[0] = (i & 0xFF) as u8;
                    p[1] = ((i >> 8) & 0xFF) as u8;
                    p
                },
                seed: {
                    let mut s = [0u8; 32];
                    s[0] = (i & 0xFF) as u8;
                    s[1] = ((i >> 8) & 0xFF) as u8;
                    s
                },
                nonce: 1000 + i,
                compression: 0,
                block_height: 0,
                generation_signature: gensig,
                base_target: 1,
                claimed_quality: None,
            })
            .collect();

        let batch = validate_proofs(&inputs).unwrap();
        assert_eq!(batch.results.len(), 32);

        for (idx, input) in inputs.iter().enumerate() {
            let expected = crate::calculate_quality_from_height(
                &input.address_payload,
                &input.seed,
                input.nonce,
                input.compression,
                input.block_height,
                &input.generation_signature,
            )
            .unwrap();
            assert_eq!(
                batch.results[idx].quality, expected,
                "Large batch result {} mismatch",
                idx
            );
        }
    }
}
