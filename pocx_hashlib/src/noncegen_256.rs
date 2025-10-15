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

use crate::buffer::PageAlignedByteBuffer;
use crate::noncegen_common::*;
use crate::shabal256_avx2::shabal256_256;
use std::slice::from_raw_parts_mut;

/// generates a series of uncompressed nonces and stores them into an optimized
/// buffer AVX2 SIMD extensions are used
/// * `cache` - buffer to store the nonces into
/// * `cache_offset` - nonce offset in buffer
/// * `payload` - 20-byte address payload
/// * `seed` - 32 byte seed
/// * `compression` - compression factor
/// * `start_nonce` - nonce to start generation at
/// * `num_nonces` - number of nonces to generate
pub fn generate_nonces_256(
    cache: &mut [u8],
    cache_offset: usize,
    address_payload: &[u8; 20],
    seed: &[u8; 32],
    start_nonce: u64,
    num_nonces: u64,
) {
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

    let mut aligned_buffer = PageAlignedByteBuffer::new(NONCE_SIZE * AVX2_VECTOR_SIZE)
        .expect("Should be able to allocate SIMD nonce buffer");
    let buffer = aligned_buffer.get_buffer_mut_unchecked();

    let mut aligned_final_buffer = PageAlignedByteBuffer::new(HASH_SIZE * AVX2_VECTOR_SIZE)
        .expect("Should be able to allocate SIMD hash buffer");
    let final_buffer = aligned_final_buffer.get_buffer_mut_unchecked();

    // prepare termination strings
    let mut t1 = [0u32; MESSAGE_SIZE];
    t1[0..8].clone_from_slice(&seed);
    t1[8..13].clone_from_slice(&payload_bytes);
    t1[15] = 0x80;
    let mut t1 = splatter_256(&t1);

    let mut t2 = [0u32; MESSAGE_SIZE];
    t2[0..5].clone_from_slice(&payload_bytes);
    t2[7] = 0x80;
    let mut t2 = splatter_256(&t2);

    let mut pt2 = [0u32; MESSAGE_SIZE];
    pt2[8..16].clone_from_slice(&seed);
    let mut pt2 = splatter_256(&pt2);

    let mut t3 = [0u32; MESSAGE_SIZE];
    t3[0] = 0x80;
    let t3 = splatter_256(&t3);

    for n in (0..num_nonces).step_by(AVX2_VECTOR_SIZE) {
        // store nonce numbers in relevant termination strings
        unsafe {
            for i in 0..AVX2_VECTOR_SIZE {
                let nonce: [u32; 2] = std::mem::transmute(
                    start_nonce
                        .saturating_add(n)
                        .saturating_add(i as u64)
                        .to_be(),
                );

                *t1.get_unchecked_mut(13 * AVX2_VECTOR_SIZE + i) = nonce[0];
                *t1.get_unchecked_mut(14 * AVX2_VECTOR_SIZE + i) = nonce[1];
                *t2.get_unchecked_mut(5 * AVX2_VECTOR_SIZE + i) = nonce[0];
                *t2.get_unchecked_mut(6 * AVX2_VECTOR_SIZE + i) = nonce[1];
            }
        }

        // start shabal rounds
        // case 1: first 128 rounds, hashes are even: use termination string 1
        // case 2: first 128 rounds, hashes are odd: use termination string 2 with
        // pretermination case 3: round > 128: use termination string 4
        // round 1
        unsafe {
            shabal256_256(
                &[],
                None,
                &t1,
                &mut buffer
                    [AVX2_VECTOR_SIZE * (NONCE_SIZE - HASH_SIZE)..AVX2_VECTOR_SIZE * NONCE_SIZE],
            )
        };

        unsafe {
            std::ptr::copy_nonoverlapping(
                buffer.get_unchecked(AVX2_VECTOR_SIZE * (NONCE_SIZE - HASH_SIZE)),
                pt2.get_unchecked_mut(0) as *mut u32 as *mut u8,
                32 * AVX2_VECTOR_SIZE,
            );
        }
        // round 2 - 128
        for i in (NONCE_SIZE - HASH_CAP + HASH_SIZE..=NONCE_SIZE - HASH_SIZE)
            .rev()
            .step_by(HASH_SIZE)
        {
            // check if msg can be divided into 512bit packages without a
            // remainder
            let pointer: &mut [u8] = unsafe {
                from_raw_parts_mut(
                    buffer
                        [i * AVX2_VECTOR_SIZE - HASH_SIZE * AVX2_VECTOR_SIZE..i * AVX2_VECTOR_SIZE]
                        .as_mut_ptr(),
                    HASH_SIZE * AVX2_VECTOR_SIZE,
                )
            };
            if i % 64 == 0 {
                // last msg = seed + termination
                unsafe {
                    shabal256_256(
                        &buffer[i * AVX2_VECTOR_SIZE..NONCE_SIZE * AVX2_VECTOR_SIZE],
                        None,
                        &t1,
                        pointer,
                    )
                };
            } else {
                // last msg = 256 bit data + seed + termination
                unsafe {
                    shabal256_256(
                        &buffer[i * AVX2_VECTOR_SIZE..NONCE_SIZE * AVX2_VECTOR_SIZE],
                        Some(&pt2),
                        &t2,
                        pointer,
                    )
                };
            }
        }

        // round 128-8192
        for i in (HASH_SIZE..=NONCE_SIZE - HASH_CAP).rev().step_by(HASH_SIZE) {
            let pointer: &mut [u8] = unsafe {
                from_raw_parts_mut(
                    buffer
                        [i * AVX2_VECTOR_SIZE - HASH_SIZE * AVX2_VECTOR_SIZE..i * AVX2_VECTOR_SIZE]
                        .as_mut_ptr(),
                    HASH_SIZE * AVX2_VECTOR_SIZE,
                )
            };
            unsafe {
                shabal256_256(
                    &buffer
                        [i * AVX2_VECTOR_SIZE..i * AVX2_VECTOR_SIZE + HASH_CAP * AVX2_VECTOR_SIZE],
                    None,
                    &t3,
                    pointer,
                )
            };
        }

        // generate final hash
        unsafe {
            shabal256_256(
                &buffer[0..NONCE_SIZE * AVX2_VECTOR_SIZE],
                None,
                &t1,
                final_buffer,
            )
        };

        // Optimized XOR with final - use chunks and avoid modulo in tight loop
        let final_size = HASH_SIZE * AVX2_VECTOR_SIZE;
        let total_size = NONCE_SIZE * AVX2_VECTOR_SIZE;

        for chunk_start in (0..total_size).step_by(final_size) {
            let chunk_end = std::cmp::min(chunk_start + final_size, total_size);
            let chunk_size = chunk_end - chunk_start;

            for i in 0..chunk_size {
                unsafe {
                    *buffer.get_unchecked_mut(chunk_start + i) ^= *final_buffer.get_unchecked(i);
                }
            }
        }

        // PoC2 shuffle
        unpack_shuffle_scatter(buffer, cache, cache_offset + n as usize, AVX2_VECTOR_SIZE);
    }
}

#[inline(always)]
fn splatter_256(input: &[u32; MESSAGE_SIZE]) -> [u32; MESSAGE_SIZE * AVX2_VECTOR_SIZE] {
    let mut result = [0u32; MESSAGE_SIZE * AVX2_VECTOR_SIZE];
    for j in 0..MESSAGE_SIZE {
        for i in 0..AVX2_VECTOR_SIZE {
            unsafe {
                *result.get_unchecked_mut(j * AVX2_VECTOR_SIZE + i) = *input.get_unchecked(j)
            };
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_nonce_generation_avx2() {
        if is_x86_feature_detected!("avx2") {
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
            let exp_result_hash =
                "acc0b40a22cf8ce8aabe361bd4b67bdb61b7367755ae9cb9963a68acaa6d322c";

            let check_result = |buf: &Vec<u8>| {
                let mut hasher = Sha256::new();
                hasher.update(buf);
                assert_eq!(format!("{:x}", hasher.finalize()), exp_result_hash);
            };

            let mut aligned_buffer = PageAlignedByteBuffer::new(32 * NONCE_SIZE)
                .expect("Should be able to allocate test buffer");
            let buf = aligned_buffer.get_buffer_mut_unchecked();
            generate_nonces_256(buf, 0, &address_payload, &seed, start_nonce, 32);
            check_result(buf);
        }
    }
}
