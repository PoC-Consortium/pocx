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

//! Scalar batch nonce generation with scoop extraction.
//!
//! Generates a single nonce and extracts one scoop, bypassing the full
//! unpack+shuffle+scatter pipeline. Used as fallback when SIMD lanes
//! cannot be filled.

use crate::noncegen_common::*;
use crate::shabal256::shabal256;

/// Generate a single nonce and extract one scoop (scalar).
pub fn generate_and_extract_scoop_32(
    address_payload: &[u8; 20],
    seed: &[u8; 32],
    nonce: u64,
    scoop: u64,
) -> [u8; SCOOP_SIZE] {
    let mut payload_bytes = [0u32; 5];
    unsafe {
        std::ptr::copy_nonoverlapping(
            address_payload.as_ptr(),
            payload_bytes.as_mut_ptr() as *mut u8,
            20,
        );
    }

    let mut seed_u32 = [0u32; 8];
    unsafe {
        std::ptr::copy_nonoverlapping(seed.as_ptr(), seed_u32.as_mut_ptr() as *mut u8, 32);
    }
    let seed = seed_u32;

    let mut buffer = [0u8; NONCE_SIZE];
    let mut final_buffer = [0u8; HASH_SIZE];

    // Prepare termination strings
    let mut t1 = [0u32; MESSAGE_SIZE];
    t1[0..8].clone_from_slice(&seed);
    t1[8..13].clone_from_slice(&payload_bytes);
    t1[15] = 0x80;

    let mut t2 = [0u32; MESSAGE_SIZE];
    t2[0..5].clone_from_slice(&payload_bytes);
    t2[7] = 0x80;

    let mut pt2 = [0u32; MESSAGE_SIZE];
    pt2[8..16].clone_from_slice(&seed);

    let mut t3 = [0u32; MESSAGE_SIZE];
    t3[0] = 0x80;

    // Set nonce in termination strings
    let nonce_parts: [u32; 2] = unsafe { std::mem::transmute(nonce.to_be()) };
    t1[13..15].clone_from_slice(&nonce_parts);
    t2[5..7].clone_from_slice(&nonce_parts);

    // Round 1
    let hash = shabal256(&[], None, &t1);
    buffer[NONCE_SIZE - HASH_SIZE..NONCE_SIZE].clone_from_slice(&hash);
    let hash = unsafe { std::mem::transmute::<[u8; 32], [u32; 8]>(hash) };
    pt2[0..8].clone_from_slice(&hash);

    // Rounds 2-128
    for i in (NONCE_SIZE - HASH_CAP + HASH_SIZE..=NONCE_SIZE - HASH_SIZE)
        .rev()
        .step_by(HASH_SIZE)
    {
        if i % 64 == 0 {
            let hash = &shabal256(&buffer[i..NONCE_SIZE], None, &t1);
            buffer[i - HASH_SIZE..i].clone_from_slice(hash);
        } else {
            let hash = &shabal256(&buffer[i..NONCE_SIZE], Some(&pt2), &t2);
            buffer[i - HASH_SIZE..i].clone_from_slice(hash);
        }
    }

    // Rounds 128-8192
    for i in (HASH_SIZE..=NONCE_SIZE - HASH_CAP).rev().step_by(HASH_SIZE) {
        let hash = &shabal256(&buffer[i..i + HASH_CAP], None, &t3);
        buffer[i - HASH_SIZE..i].clone_from_slice(hash);
    }

    // Final hash
    final_buffer.clone_from_slice(&shabal256(&buffer[0..NONCE_SIZE], None, &t1));

    // XOR with final
    for i in 0..NONCE_SIZE {
        buffer[i] ^= final_buffer[i % HASH_SIZE];
    }

    // Extract scoop using POC2 indexing (vector_size=1, lane=0)
    let mut output = [0u8; SCOOP_SIZE];
    extract_scoop_from_interleaved(&buffer, 1, 0, scoop, &mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noncegen_32::generate_nonces_32;

    #[test]
    fn test_batch_32_matches_generate_nonces() {
        let seed: [u8; 32] =
            hex::decode("AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE")
                .unwrap()
                .try_into()
                .unwrap();
        let address_payload: [u8; 20] = hex::decode("99BC78BA577A95A11F1A344D4D2AE55F2F857B98")
            .unwrap()
            .try_into()
            .unwrap();

        // Generate a full nonce using the standard path
        let mut cache = vec![0u8; NONCE_SIZE];
        generate_nonces_32(&mut cache, 0, &address_payload, &seed, 1337, 1);

        // Extract each scoop via batch and compare
        for scoop in [0, 1, 42, 667, 2048, 4095] {
            let batch_scoop = generate_and_extract_scoop_32(&address_payload, &seed, 1337, scoop);
            let start = scoop as usize * SCOOP_SIZE;
            let expected = &cache[start..start + SCOOP_SIZE];
            assert_eq!(
                &batch_scoop[..],
                expected,
                "Scoop {} mismatch for nonce 1337",
                scoop
            );
        }
    }

    #[test]
    fn test_batch_32_multiple_nonces() {
        let seed = [0xABu8; 32];
        let address_payload = [0x42u8; 20];

        for nonce in [0, 1, 100, 12345] {
            let mut cache = vec![0u8; NONCE_SIZE];
            generate_nonces_32(&mut cache, 0, &address_payload, &seed, nonce, 1);

            let scoop = 667u64;
            let batch_scoop = generate_and_extract_scoop_32(&address_payload, &seed, nonce, scoop);
            let start = scoop as usize * SCOOP_SIZE;
            assert_eq!(
                &batch_scoop[..],
                &cache[start..start + SCOOP_SIZE],
                "Mismatch for nonce {}",
                nonce
            );
        }
    }
}
