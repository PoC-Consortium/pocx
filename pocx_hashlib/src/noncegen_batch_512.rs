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

//! AVX512 heterogeneous 16-lane batch nonce generation with scoop extraction.
//!
//! Each SIMD lane processes a completely independent (account, seed, nonce) triple.
//! Unlike the plotting path which splatters identical params across lanes, this
//! module sets up per-lane termination strings for server-side proof validation.

use crate::buffer::PageAlignedByteBuffer;
use crate::noncegen_common::*;
use crate::shabal256_avx512::shabal256_512;
use std::slice::from_raw_parts_mut;

const V: usize = AVX512_VECTOR_SIZE;

/// Generate 16 nonces with independent params and extract one scoop per lane (AVX512).
pub fn generate_and_extract_scoops_512(
    account_payloads: &[[u8; 20]; V],
    seeds: &[[u8; 32]; V],
    nonces: &[u64; V],
    scoops: &[u64; V],
) -> [[u8; SCOOP_SIZE]; V] {
    // Convert inputs to u32 arrays
    let mut payloads_u32 = [[0u32; 5]; V];
    let mut seeds_u32 = [[0u32; 8]; V];
    for lane in 0..V {
        unsafe {
            std::ptr::copy_nonoverlapping(
                account_payloads[lane].as_ptr(),
                payloads_u32[lane].as_mut_ptr() as *mut u8,
                20,
            );
            std::ptr::copy_nonoverlapping(
                seeds[lane].as_ptr(),
                seeds_u32[lane].as_mut_ptr() as *mut u8,
                32,
            );
        }
    }

    // Allocate SIMD-aligned buffers
    let mut aligned_buffer = PageAlignedByteBuffer::new(NONCE_SIZE * V)
        .expect("Should be able to allocate SIMD nonce buffer");
    let buffer = aligned_buffer.get_buffer_mut_unchecked();

    let mut aligned_final_buffer = PageAlignedByteBuffer::new(HASH_SIZE * V)
        .expect("Should be able to allocate SIMD hash buffer");
    let final_buffer = aligned_final_buffer.get_buffer_mut_unchecked();

    // Set up termination strings with per-lane values (heterogeneous — no splatter)
    let mut t1 = [0u32; MESSAGE_SIZE * V];
    let mut t2 = [0u32; MESSAGE_SIZE * V];
    let mut pt2 = [0u32; MESSAGE_SIZE * V];
    let mut t3 = [0u32; MESSAGE_SIZE * V];

    for lane in 0..V {
        let nonce_parts: [u32; 2] = unsafe { std::mem::transmute(nonces[lane].to_be()) };

        // t1: seed[0..8] + payload[8..13] + nonce[13..15] + 0x80[15]
        for j in 0..8 {
            t1[j * V + lane] = seeds_u32[lane][j];
        }
        for k in 0..5 {
            t1[(8 + k) * V + lane] = payloads_u32[lane][k];
        }
        t1[13 * V + lane] = nonce_parts[0];
        t1[14 * V + lane] = nonce_parts[1];
        t1[15 * V + lane] = 0x80;

        // t2: payload[0..5] + nonce[5..7] + 0x80[7]
        for k in 0..5 {
            t2[k * V + lane] = payloads_u32[lane][k];
        }
        t2[5 * V + lane] = nonce_parts[0];
        t2[6 * V + lane] = nonce_parts[1];
        t2[7 * V + lane] = 0x80;

        // pt2: [first_hash (set after round 1)][0..8] + seed[8..16]
        for j in 0..8 {
            pt2[(8 + j) * V + lane] = seeds_u32[lane][j];
        }

        // t3: 0x80[0]
        t3[lane] = 0x80;
    }

    // Shabal rounds — identical to noncegen_512.rs

    // Round 1
    unsafe {
        shabal256_512(
            &[],
            None,
            &t1,
            &mut buffer[V * (NONCE_SIZE - HASH_SIZE)..V * NONCE_SIZE],
        )
    };

    // Copy first hash into pt2[0..8] per lane
    unsafe {
        std::ptr::copy_nonoverlapping(
            buffer.get_unchecked(V * (NONCE_SIZE - HASH_SIZE)),
            pt2.get_unchecked_mut(0) as *mut u32 as *mut u8,
            32 * V,
        );
    }

    // Rounds 2-128
    for i in (NONCE_SIZE - HASH_CAP + HASH_SIZE..=NONCE_SIZE - HASH_SIZE)
        .rev()
        .step_by(HASH_SIZE)
    {
        let pointer: &mut [u8] = unsafe {
            from_raw_parts_mut(
                buffer[i * V - HASH_SIZE * V..i * V].as_mut_ptr(),
                HASH_SIZE * V,
            )
        };
        if i % 64 == 0 {
            unsafe { shabal256_512(&buffer[i * V..NONCE_SIZE * V], None, &t1, pointer) };
        } else {
            unsafe { shabal256_512(&buffer[i * V..NONCE_SIZE * V], Some(&pt2), &t2, pointer) };
        }
    }

    // Rounds 128-8192
    for i in (HASH_SIZE..=NONCE_SIZE - HASH_CAP).rev().step_by(HASH_SIZE) {
        let pointer: &mut [u8] = unsafe {
            from_raw_parts_mut(
                buffer[i * V - HASH_SIZE * V..i * V].as_mut_ptr(),
                HASH_SIZE * V,
            )
        };
        unsafe { shabal256_512(&buffer[i * V..i * V + HASH_CAP * V], None, &t3, pointer) };
    }

    // Final hash
    unsafe { shabal256_512(&buffer[0..NONCE_SIZE * V], None, &t1, final_buffer) };

    // XOR with final
    let final_size = HASH_SIZE * V;
    let total_size = NONCE_SIZE * V;
    for chunk_start in (0..total_size).step_by(final_size) {
        let chunk_end = std::cmp::min(chunk_start + final_size, total_size);
        let chunk_size = chunk_end - chunk_start;
        for i in 0..chunk_size {
            unsafe {
                *buffer.get_unchecked_mut(chunk_start + i) ^= *final_buffer.get_unchecked(i);
            }
        }
    }

    // Extract scoops per lane (no full shuffle)
    let mut outputs = [[0u8; SCOOP_SIZE]; V];
    for lane in 0..V {
        extract_scoop_from_interleaved(buffer, V, lane, scoops[lane], &mut outputs[lane]);
    }
    outputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noncegen_batch_32::generate_and_extract_scoop_32;

    #[test]
    fn test_batch_512_matches_scalar() {
        if !is_x86_feature_detected!("avx512f") {
            return;
        }

        let seeds: [[u8; 32]; V] = [
            [0xAA; 32], [0xBB; 32], [0xCC; 32], [0xDD; 32],
            [0xEE; 32], [0xFF; 32], [0x11; 32], [0x22; 32],
            [0x33; 32], [0x44; 32], [0x55; 32], [0x66; 32],
            [0x77; 32], [0x88; 32], [0x99; 32], [0xAB; 32],
        ];
        let payloads: [[u8; 20]; V] = [
            [0x01; 20], [0x02; 20], [0x03; 20], [0x04; 20],
            [0x05; 20], [0x06; 20], [0x07; 20], [0x08; 20],
            [0x09; 20], [0x0A; 20], [0x0B; 20], [0x0C; 20],
            [0x0D; 20], [0x0E; 20], [0x0F; 20], [0x10; 20],
        ];
        let nonces: [u64; V] = [100, 200, 300, 400, 500, 600, 700, 800,
                                 900, 1000, 1100, 1200, 1300, 1400, 1500, 1600];
        let scoops: [u64; V] = [0, 42, 667, 2048, 4095, 1, 100, 3000,
                                 512, 1024, 2000, 3500, 777, 1999, 10, 4000];

        let simd_results = generate_and_extract_scoops_512(&payloads, &seeds, &nonces, &scoops);

        for lane in 0..V {
            let scalar_result = generate_and_extract_scoop_32(
                &payloads[lane],
                &seeds[lane],
                nonces[lane],
                scoops[lane],
            );
            assert_eq!(
                simd_results[lane], scalar_result,
                "Lane {} mismatch: nonce={}, scoop={}",
                lane, nonces[lane], scoops[lane]
            );
        }
    }

    #[test]
    fn test_batch_512_same_params_different_nonces() {
        if !is_x86_feature_detected!("avx512f") {
            return;
        }

        let seed = [0xAB; 32];
        let payload = [0x42; 20];
        let scoop = 667u64;

        let seeds = [seed; V];
        let payloads = [payload; V];
        let nonces: [u64; V] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let scoops = [scoop; V];

        let simd_results = generate_and_extract_scoops_512(&payloads, &seeds, &nonces, &scoops);

        for lane in 0..V {
            let scalar_result =
                generate_and_extract_scoop_32(&payload, &seed, nonces[lane], scoop);
            assert_eq!(
                simd_results[lane], scalar_result,
                "Lane {} mismatch for nonce {}",
                lane, nonces[lane]
            );
        }
    }
}
