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

use crate::noncegen_common::*;
use crate::shabal256::shabal256;

/// generates a series of uncompressed nonces and stores them into an optimized
/// buffer no SIMD extensions are used
/// * `cache` - buffer to store the nonces into
/// * `cache_offset` - nonce offset in buffer
/// * `payload` - 20-byte address payload
/// * `seed` - 32 byte seed
/// * `compression` - compression factor
/// * `start_nonce` - nonce to start generation at
/// * `num_nonces` - number of nonces to generate
pub fn generate_nonces_32(
    cache: &mut [u8],
    cache_offset: usize,
    address_payload: &[u8; 20],
    seed: &[u8; 32],
    start_nonce: u64,
    num_nonces: u64,
) {
    let mut payload_bytes = [0u32; 5];
    // SAFETY: Copying 20 bytes from address_payload (guaranteed 20-byte array)
    // to payload_bytes (20 bytes capacity as 5 * 4 bytes). This is safe as:
    // - Source is guaranteed to be 20 bytes by type system
    // - Destination has exact capacity (20 bytes)
    // - No overlapping memory regions
    unsafe {
        std::ptr::copy_nonoverlapping(
            address_payload.as_ptr(),
            payload_bytes.as_mut_ptr() as *mut u8,
            20,
        );
    }

    let mut seed_u32 = [0u32; 8];
    // SAFETY: Copying 32 bytes from seed (guaranteed 32-byte array)
    // to seed_u32 (32 bytes capacity as 8 * 4 bytes). This is safe as:
    // - Source is guaranteed to be 32 bytes by type system
    // - Destination has exact capacity (32 bytes)
    // - No overlapping memory regions
    unsafe {
        std::ptr::copy_nonoverlapping(seed.as_ptr(), seed_u32.as_mut_ptr() as *mut u8, 32);
    }
    let seed = seed_u32;

    let mut buffer = [0u8; NONCE_SIZE];
    let mut final_buffer = [0u8; HASH_SIZE];

    // prepare termination strings
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

    for n in 0..num_nonces {
        // generate nonce numbers & change endianness
        // SAFETY: Transmuting u64 to [u32; 2] is safe as both types are 8 bytes.
        // This converts the nonce to big-endian u64, then reinterprets as two u32s.
        let nonce: [u32; 2] = unsafe { std::mem::transmute(start_nonce.saturating_add(n).to_be()) };

        // store nonce numbers in relevant termination strings
        t1[13..15].clone_from_slice(&nonce);
        t2[5..7].clone_from_slice(&nonce);

        // start shabal rounds
        // case 1: first 128 rounds, hashes are even: use termination string 1
        // case 2: first 128 rounds, hashes are odd: use termination string 2 with
        // pretermination case 3: round > 128: use termination string 4
        // round 1
        let hash = shabal256(&[], None, &t1);

        buffer[NONCE_SIZE - HASH_SIZE..NONCE_SIZE].clone_from_slice(&hash);
        // SAFETY: Transmuting [u8; 32] to [u32; 8] is safe as both types are 32 bytes.
        // This reinterprets the hash bytes as u32 array for further processing.
        let hash = unsafe { std::mem::transmute::<[u8; 32], [u32; 8]>(hash) };

        // store first hash into pretermination string 2
        pt2[0..8].clone_from_slice(&hash);
        // round 2 - 128
        for i in (NONCE_SIZE - HASH_CAP + HASH_SIZE..=NONCE_SIZE - HASH_SIZE)
            .rev()
            .step_by(HASH_SIZE)
        {
            // check if msg can be divided into 512bit packages without a
            // remainder
            if i % 64 == 0 {
                // last msg = seed + termination
                let hash = &shabal256(&buffer[i..NONCE_SIZE], None, &t1);
                buffer[i - HASH_SIZE..i].clone_from_slice(hash);
            } else {
                // last msg = 256 bit data + seed + termination
                let hash = &shabal256(&buffer[i..NONCE_SIZE], Some(&pt2), &t2);
                buffer[i - HASH_SIZE..i].clone_from_slice(hash);
            }
        }

        // round 128-8192
        for i in (HASH_SIZE..=NONCE_SIZE - HASH_CAP).rev().step_by(HASH_SIZE) {
            let hash = &shabal256(&buffer[i..i + HASH_CAP], None, &t3);
            buffer[i - HASH_SIZE..i].clone_from_slice(hash);
        }

        // generate final hash
        final_buffer.clone_from_slice(&shabal256(&buffer[0..NONCE_SIZE], None, &t1));

        // XOR with final
        for i in 0..NONCE_SIZE {
            buffer[i] ^= final_buffer[i % HASH_SIZE];
        }

        // PoC2 shuffle
        unpack_shuffle_scatter(&buffer, cache, cache_offset + n as usize, 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_nonce_generation_scalar() {
        let mut seed = [0u8; 32];
        seed[..].clone_from_slice(
            &hex::decode("AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE")
                .unwrap(),
        );
        // Create address payload from hex (20 bytes without version/checksum)
        let address_payload: [u8; 20] = hex::decode("99BC78BA577A95A11F1A344D4D2AE55F2F857B98")
            .unwrap()
            .try_into()
            .unwrap();
        let start_nonce = 1337;
        let exp_result_hash = "acc0b40a22cf8ce8aabe361bd4b67bdb61b7367755ae9cb9963a68acaa6d322c";

        let mut buf = vec![0; 32 * NONCE_SIZE];
        generate_nonces_32(&mut buf, 0, &address_payload, &seed, start_nonce, 32);

        let mut hasher = Sha256::new();
        hasher.update(&buf);
        assert_eq!(format!("{:x}", hasher.finalize()), exp_result_hash);
    }
}
