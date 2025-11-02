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

//! ARM NEON-optimized Shabal256 implementation
//!
//! This module provides a 4-way parallel Shabal256 implementation using ARM
//! NEON intrinsics. It processes 4 independent hash calculations simultaneously
//! using 128-bit NEON vectors.

#![allow(clippy::too_many_arguments)]

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

#[allow(overflowing_literals)]
const A_INIT: [i32; 12] = [
    0x52F84552, 0xE54B7999, 0x2D8EE3EC, 0xB9645191, 0xE0078B86, 0xBB7C44C9, 0xD2B5C1CA, 0xB0D2EB8C,
    0x14CE5A45, 0x22AF50DC, 0xEFFDBC6B, 0xEB21B74A,
];

#[allow(overflowing_literals)]
const B_INIT: [i32; 16] = [
    0xB555C6EE, 0x3E710596, 0xA72A652F, 0x9301515F, 0xDA28C1FA, 0x696FD868, 0x9CB6BF72, 0x0AFE4002,
    0xA6E03615, 0x5138C1D4, 0xBE216306, 0xB38B8890, 0x3EA8B96B, 0x3299ACE4, 0x30924DD4, 0x55CB34A5,
];

#[allow(overflowing_literals)]
const C_INIT: [i32; 16] = [
    0xB405F031, 0xC4233EBA, 0xB3733979, 0xC0DD9D55, 0xC51C28AE, 0xA327B8E1, 0x56C56167, 0xED614433,
    0x88B59D60, 0x60E2CEBA, 0x758B4B8B, 0x83E82A7F, 0xBC968828, 0xE6E00BF7, 0xBA839E55, 0x9B491C60,
];

#[allow(overflowing_literals)]
const ONE: i32 = 0xFFFFFFFF;

const SIMD_VECTOR_SIZE: usize = 4;
const MESSAGE_SIZE: usize = 16;

/// Helper macro to perform left rotation on NEON vectors
/// NEON doesn't have native rotate, so we synthesize it with shift + or
macro_rules! vrotlq_n_u32 {
    ($a:expr, $n:expr) => {
        vorrq_u32(vshlq_n_u32::<$n>($a), vshrq_n_u32::<{ 32 - $n }>($a))
    };
}

/// 4-way parallel Shabal256 using ARM NEON intrinsics
///
/// Processes 4 independent Shabal256 hashes simultaneously using 128-bit NEON
/// vectors. Equivalent to the SSE2 implementation but using ARM NEON
/// instructions.
///
/// # Safety
///
/// This function uses NEON intrinsics and requires the `neon` target feature.
/// NEON is mandatory on all AArch64 processors, so this is always available on
/// ARM64.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn shabal256_neon(
    data: &[u8],
    pre_term: Option<&[u32; 16 * SIMD_VECTOR_SIZE]>,
    term: &[u32; 16 * SIMD_VECTOR_SIZE],
    target: &mut [u8],
) {
    let mut a: [uint32x4_t; 12] = [
        vdupq_n_u32(A_INIT[0] as u32),
        vdupq_n_u32(A_INIT[1] as u32),
        vdupq_n_u32(A_INIT[2] as u32),
        vdupq_n_u32(A_INIT[3] as u32),
        vdupq_n_u32(A_INIT[4] as u32),
        vdupq_n_u32(A_INIT[5] as u32),
        vdupq_n_u32(A_INIT[6] as u32),
        vdupq_n_u32(A_INIT[7] as u32),
        vdupq_n_u32(A_INIT[8] as u32),
        vdupq_n_u32(A_INIT[9] as u32),
        vdupq_n_u32(A_INIT[10] as u32),
        vdupq_n_u32(A_INIT[11] as u32),
    ];

    let mut b: [uint32x4_t; 16] = [
        vdupq_n_u32(B_INIT[0] as u32),
        vdupq_n_u32(B_INIT[1] as u32),
        vdupq_n_u32(B_INIT[2] as u32),
        vdupq_n_u32(B_INIT[3] as u32),
        vdupq_n_u32(B_INIT[4] as u32),
        vdupq_n_u32(B_INIT[5] as u32),
        vdupq_n_u32(B_INIT[6] as u32),
        vdupq_n_u32(B_INIT[7] as u32),
        vdupq_n_u32(B_INIT[8] as u32),
        vdupq_n_u32(B_INIT[9] as u32),
        vdupq_n_u32(B_INIT[10] as u32),
        vdupq_n_u32(B_INIT[11] as u32),
        vdupq_n_u32(B_INIT[12] as u32),
        vdupq_n_u32(B_INIT[13] as u32),
        vdupq_n_u32(B_INIT[14] as u32),
        vdupq_n_u32(B_INIT[15] as u32),
    ];

    let mut c: [uint32x4_t; 16] = [
        vdupq_n_u32(C_INIT[0] as u32),
        vdupq_n_u32(C_INIT[1] as u32),
        vdupq_n_u32(C_INIT[2] as u32),
        vdupq_n_u32(C_INIT[3] as u32),
        vdupq_n_u32(C_INIT[4] as u32),
        vdupq_n_u32(C_INIT[5] as u32),
        vdupq_n_u32(C_INIT[6] as u32),
        vdupq_n_u32(C_INIT[7] as u32),
        vdupq_n_u32(C_INIT[8] as u32),
        vdupq_n_u32(C_INIT[9] as u32),
        vdupq_n_u32(C_INIT[10] as u32),
        vdupq_n_u32(C_INIT[11] as u32),
        vdupq_n_u32(C_INIT[12] as u32),
        vdupq_n_u32(C_INIT[13] as u32),
        vdupq_n_u32(C_INIT[14] as u32),
        vdupq_n_u32(C_INIT[15] as u32),
    ];

    let mut w_high = 0u32;
    let mut w_low = 1u32;
    let mut num = (data.len() / SIMD_VECTOR_SIZE) >> 6;
    let mut ptr = 0;

    let data_ptr = data.as_ptr() as *const uint32x4_t;
    let term_ptr = term.as_ptr() as *const uint32x4_t;

    // Process main data blocks
    while num > 0 {
        for i in 0..16 {
            *b.get_unchecked_mut(i) = vaddq_u32(
                *b.get_unchecked(i),
                vld1q_u32(data_ptr.add(ptr + i) as *const u32),
            );
        }
        a[0] = veorq_u32(a[0], vdupq_n_u32(w_low));
        a[1] = veorq_u32(a[1], vdupq_n_u32(w_high));
        apply_p(&mut a, &mut b, &c, data_ptr.add(ptr));
        for i in 0..16 {
            *c.get_unchecked_mut(i) = vsubq_u32(
                *c.get_unchecked(i),
                vld1q_u32(data_ptr.add(ptr + i) as *const u32),
            );
        }
        std::mem::swap(&mut b, &mut c);
        w_low = w_low.wrapping_add(1);
        if w_low == 0 {
            w_high = w_high.wrapping_add(1);
        }
        ptr = ptr.wrapping_add(MESSAGE_SIZE);
        num = num.wrapping_sub(1);
    }

    // Process pre-termination block if present
    if let Some(pre_term) = pre_term {
        let pre_term_ptr = pre_term.as_ptr() as *const uint32x4_t;
        for i in 0..16 {
            *b.get_unchecked_mut(i) = vaddq_u32(
                *b.get_unchecked(i),
                vld1q_u32(pre_term_ptr.add(i) as *const u32),
            );
        }
        a[0] = veorq_u32(a[0], vdupq_n_u32(w_low));
        a[1] = veorq_u32(a[1], vdupq_n_u32(w_high));
        apply_p(&mut a, &mut b, &c, pre_term_ptr);
        for i in 0..16 {
            *c.get_unchecked_mut(i) = vsubq_u32(
                *c.get_unchecked(i),
                vld1q_u32(pre_term_ptr.add(i) as *const u32),
            );
        }
        std::mem::swap(&mut b, &mut c);
        w_low = w_low.wrapping_add(1);
        if w_low == 0 {
            w_high = w_high.wrapping_add(1);
        }
    }

    // Process termination block
    for i in 0..16 {
        *b.get_unchecked_mut(i) = vaddq_u32(
            *b.get_unchecked(i),
            vld1q_u32(term_ptr.add(i) as *const u32),
        );
    }
    a[0] = veorq_u32(a[0], vdupq_n_u32(w_low));
    a[1] = veorq_u32(a[1], vdupq_n_u32(w_high));
    apply_p(&mut a, &mut b, &c, term_ptr);

    // Final 3 rounds
    for _ in 0..3 {
        std::mem::swap(&mut b, &mut c);
        a[0] = veorq_u32(a[0], vdupq_n_u32(w_low));
        a[1] = veorq_u32(a[1], vdupq_n_u32(w_high));
        apply_p(&mut a, &mut b, &c, term_ptr);
    }

    // Write output
    let target_ptr = target.as_mut_ptr() as *mut uint32x4_t;
    for i in 0..8 {
        vst1q_u32(target_ptr.add(i) as *mut u32, *b.get_unchecked(i + 8));
    }
}

#[inline(always)]
#[cfg(target_arch = "aarch64")]
unsafe fn apply_p(
    a: &mut [uint32x4_t; 12],
    b: &mut [uint32x4_t; 16],
    c: &[uint32x4_t; 16],
    data_ptr: *const uint32x4_t,
) {
    // Rotate b elements
    for i in 0..16 {
        *b.get_unchecked_mut(i) = vrotlq_n_u32!(*b.get_unchecked(i), 17);
    }

    // Apply permutation elements (48 rounds)
    perm_elt(a, b, 0, 11, 0, 13, 9, 6, c[8], data_ptr.add(0));
    perm_elt(a, b, 1, 0, 1, 14, 10, 7, c[7], data_ptr.add(1));
    perm_elt(a, b, 2, 1, 2, 15, 11, 8, c[6], data_ptr.add(2));
    perm_elt(a, b, 3, 2, 3, 0, 12, 9, c[5], data_ptr.add(3));
    perm_elt(a, b, 4, 3, 4, 1, 13, 10, c[4], data_ptr.add(4));
    perm_elt(a, b, 5, 4, 5, 2, 14, 11, c[3], data_ptr.add(5));
    perm_elt(a, b, 6, 5, 6, 3, 15, 12, c[2], data_ptr.add(6));
    perm_elt(a, b, 7, 6, 7, 4, 0, 13, c[1], data_ptr.add(7));
    perm_elt(a, b, 8, 7, 8, 5, 1, 14, c[0], data_ptr.add(8));
    perm_elt(a, b, 9, 8, 9, 6, 2, 15, c[15], data_ptr.add(9));
    perm_elt(a, b, 10, 9, 10, 7, 3, 0, c[14], data_ptr.add(10));
    perm_elt(a, b, 11, 10, 11, 8, 4, 1, c[13], data_ptr.add(11));
    perm_elt(a, b, 0, 11, 12, 9, 5, 2, c[12], data_ptr.add(12));
    perm_elt(a, b, 1, 0, 13, 10, 6, 3, c[11], data_ptr.add(13));
    perm_elt(a, b, 2, 1, 14, 11, 7, 4, c[10], data_ptr.add(14));
    perm_elt(a, b, 3, 2, 15, 12, 8, 5, c[9], data_ptr.add(15));
    perm_elt(a, b, 4, 3, 0, 13, 9, 6, c[8], data_ptr.add(0));
    perm_elt(a, b, 5, 4, 1, 14, 10, 7, c[7], data_ptr.add(1));
    perm_elt(a, b, 6, 5, 2, 15, 11, 8, c[6], data_ptr.add(2));
    perm_elt(a, b, 7, 6, 3, 0, 12, 9, c[5], data_ptr.add(3));
    perm_elt(a, b, 8, 7, 4, 1, 13, 10, c[4], data_ptr.add(4));
    perm_elt(a, b, 9, 8, 5, 2, 14, 11, c[3], data_ptr.add(5));
    perm_elt(a, b, 10, 9, 6, 3, 15, 12, c[2], data_ptr.add(6));
    perm_elt(a, b, 11, 10, 7, 4, 0, 13, c[1], data_ptr.add(7));
    perm_elt(a, b, 0, 11, 8, 5, 1, 14, c[0], data_ptr.add(8));
    perm_elt(a, b, 1, 0, 9, 6, 2, 15, c[15], data_ptr.add(9));
    perm_elt(a, b, 2, 1, 10, 7, 3, 0, c[14], data_ptr.add(10));
    perm_elt(a, b, 3, 2, 11, 8, 4, 1, c[13], data_ptr.add(11));
    perm_elt(a, b, 4, 3, 12, 9, 5, 2, c[12], data_ptr.add(12));
    perm_elt(a, b, 5, 4, 13, 10, 6, 3, c[11], data_ptr.add(13));
    perm_elt(a, b, 6, 5, 14, 11, 7, 4, c[10], data_ptr.add(14));
    perm_elt(a, b, 7, 6, 15, 12, 8, 5, c[9], data_ptr.add(15));
    perm_elt(a, b, 8, 7, 0, 13, 9, 6, c[8], data_ptr.add(0));
    perm_elt(a, b, 9, 8, 1, 14, 10, 7, c[7], data_ptr.add(1));
    perm_elt(a, b, 10, 9, 2, 15, 11, 8, c[6], data_ptr.add(2));
    perm_elt(a, b, 11, 10, 3, 0, 12, 9, c[5], data_ptr.add(3));
    perm_elt(a, b, 0, 11, 4, 1, 13, 10, c[4], data_ptr.add(4));
    perm_elt(a, b, 1, 0, 5, 2, 14, 11, c[3], data_ptr.add(5));
    perm_elt(a, b, 2, 1, 6, 3, 15, 12, c[2], data_ptr.add(6));
    perm_elt(a, b, 3, 2, 7, 4, 0, 13, c[1], data_ptr.add(7));
    perm_elt(a, b, 4, 3, 8, 5, 1, 14, c[0], data_ptr.add(8));
    perm_elt(a, b, 5, 4, 9, 6, 2, 15, c[15], data_ptr.add(9));
    perm_elt(a, b, 6, 5, 10, 7, 3, 0, c[14], data_ptr.add(10));
    perm_elt(a, b, 7, 6, 11, 8, 4, 1, c[13], data_ptr.add(11));
    perm_elt(a, b, 8, 7, 12, 9, 5, 2, c[12], data_ptr.add(12));
    perm_elt(a, b, 9, 8, 13, 10, 6, 3, c[11], data_ptr.add(13));
    perm_elt(a, b, 10, 9, 14, 11, 7, 4, c[10], data_ptr.add(14));
    perm_elt(a, b, 11, 10, 15, 12, 8, 5, c[9], data_ptr.add(15));

    // Add c values to a
    a[0] = vaddq_u32(vaddq_u32(vaddq_u32(a[0], c[11]), c[15]), c[3]);
    a[1] = vaddq_u32(vaddq_u32(vaddq_u32(a[1], c[12]), c[0]), c[4]);
    a[2] = vaddq_u32(vaddq_u32(vaddq_u32(a[2], c[13]), c[1]), c[5]);
    a[3] = vaddq_u32(vaddq_u32(vaddq_u32(a[3], c[14]), c[2]), c[6]);
    a[4] = vaddq_u32(vaddq_u32(vaddq_u32(a[4], c[15]), c[3]), c[7]);
    a[5] = vaddq_u32(vaddq_u32(vaddq_u32(a[5], c[0]), c[4]), c[8]);
    a[6] = vaddq_u32(vaddq_u32(vaddq_u32(a[6], c[1]), c[5]), c[9]);
    a[7] = vaddq_u32(vaddq_u32(vaddq_u32(a[7], c[2]), c[6]), c[10]);
    a[8] = vaddq_u32(vaddq_u32(vaddq_u32(a[8], c[3]), c[7]), c[11]);
    a[9] = vaddq_u32(vaddq_u32(vaddq_u32(a[9], c[4]), c[8]), c[12]);
    a[10] = vaddq_u32(vaddq_u32(vaddq_u32(a[10], c[5]), c[9]), c[13]);
    a[11] = vaddq_u32(vaddq_u32(vaddq_u32(a[11], c[6]), c[10]), c[14]);
}

#[inline(always)]
#[cfg(target_arch = "aarch64")]
unsafe fn perm_elt(
    a: &mut [uint32x4_t; 12],
    b: &mut [uint32x4_t; 16],
    xa0: usize,
    xa1: usize,
    xb0: usize,
    xb1: usize,
    xb2: usize,
    xb3: usize,
    xc: uint32x4_t,
    xm: *const uint32x4_t,
) {
    // tt = (a[xa1] <<< 15) * 5
    let mut tt = vrotlq_n_u32!(*a.get_unchecked(xa1), 15);
    tt = vaddq_u32(vshlq_n_u32::<2>(tt), tt); // tt * 5 = (tt << 2) + tt

    // tt = a[xa0] ^ tt ^ xc
    tt = veorq_u32(veorq_u32(*a.get_unchecked(xa0), tt), xc);

    // tt = tt * 3
    tt = vaddq_u32(vshlq_n_u32::<1>(tt), tt); // tt * 3 = (tt << 1) + tt

    // tt = tt ^ b[xb1] ^ (~b[xb3] & b[xb2]) ^ m
    tt = veorq_u32(
        veorq_u32(tt, *b.get_unchecked(xb1)),
        veorq_u32(
            vbicq_u32(*b.get_unchecked(xb2), *b.get_unchecked(xb3)), // NEON: bic = a & ~b
            vld1q_u32(xm as *const u32),
        ),
    );

    *a.get_unchecked_mut(xa0) = tt;

    // tt = (b[xb0] <<< 1)
    tt = vrotlq_n_u32!(*b.get_unchecked(xb0), 1);

    // b[xb0] = tt ^ ~a[xa0]
    *b.get_unchecked_mut(xb0) = veorq_u32(
        tt,
        veorq_u32(*a.get_unchecked(xa0), vdupq_n_u32(ONE as u32)),
    );
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_A_RESULT: [u8; 32] = [
        0xDA, 0x8F, 0x08, 0xC0, 0x2A, 0x67, 0xBA, 0x9A, 0x56, 0xBD, 0xD0, 0x79, 0x8E, 0x48, 0xAE,
        0x07, 0x14, 0x21, 0x5E, 0x09, 0x3B, 0x5B, 0x85, 0x06, 0x49, 0xA3, 0x77, 0x18, 0x99, 0x3F,
        0x54, 0xA2,
    ];

    const TEST_B_RESULT: [u8; 32] = [
        0xB4, 0x9F, 0x34, 0xBF, 0x51, 0x86, 0x4C, 0x30, 0x53, 0x3C, 0xC4, 0x6C, 0xC2, 0x54, 0x2B,
        0xDE, 0xC2, 0xF9, 0x6F, 0xD0, 0x6F, 0x5C, 0x53, 0x9A, 0xFF, 0x6E, 0xAD, 0x58, 0x83, 0xF7,
        0x32, 0x7A,
    ];

    const TEST_B_M1: [u32; 16] = [
        0x64636261, 0x68676665, 0x6C6B6A69, 0x706F6E6D, 0x74737271, 0x78777675, 0x302D7A79,
        0x34333231, 0x38373635, 0x42412D39, 0x46454443, 0x4A494847, 0x4E4D4C4B, 0x5251504F,
        0x56555453, 0x5A595857,
    ];

    const TEST_B_M2: [u32; 16] = [
        0x3231302D, 0x36353433, 0x2D393837, 0x64636261, 0x68676665, 0x6C6B6A69, 0x706F6E6D,
        0x74737271, 0x78777675, 0x00807A79, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000,
    ];

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_shabal256_neon() {
        // Test message A x SIMD_VECTOR_SIZE
        let test_data_a = [0u8; 64 * SIMD_VECTOR_SIZE];
        let mut test_term_a = [0u32; 16 * SIMD_VECTOR_SIZE];
        #[allow(clippy::needless_range_loop)]
        for i in 0..SIMD_VECTOR_SIZE {
            test_term_a[i] = 0x80;
        }

        let mut hash_a = [0u8; 32 * SIMD_VECTOR_SIZE];
        unsafe { shabal256_neon(&test_data_a, None, &test_term_a, &mut hash_a) };

        for word in 0..8 {
            for hash in 0..SIMD_VECTOR_SIZE {
                for byte in 0..4 {
                    assert_eq!(
                        hash_a[word * 4 * SIMD_VECTOR_SIZE + hash * 4 + byte],
                        TEST_A_RESULT[word * 4 + byte]
                    );
                }
            }
        }

        // Test message B x SIMD_VECTOR_SIZE
        let mut b1 = [0u32; 16 * SIMD_VECTOR_SIZE];
        for j in 0..16 {
            for i in 0..SIMD_VECTOR_SIZE {
                b1[j * SIMD_VECTOR_SIZE + i] = TEST_B_M1[j];
            }
        }
        let b1 = unsafe {
            std::mem::transmute::<[u32; 16 * SIMD_VECTOR_SIZE], [u8; 64 * SIMD_VECTOR_SIZE]>(b1)
        };

        let mut b2 = [0u32; 16 * SIMD_VECTOR_SIZE];
        for j in 0..16 {
            for i in 0..SIMD_VECTOR_SIZE {
                b2[j * SIMD_VECTOR_SIZE + i] = TEST_B_M2[j];
            }
        }

        let mut hash_b = [0u8; 32 * SIMD_VECTOR_SIZE];
        unsafe { shabal256_neon(&b1, None, &b2, &mut hash_b) };

        for word in 0..8 {
            for hash in 0..SIMD_VECTOR_SIZE {
                for byte in 0..4 {
                    assert_eq!(
                        hash_b[word * 4 * SIMD_VECTOR_SIZE + hash * 4 + byte],
                        TEST_B_RESULT[word * 4 + byte]
                    );
                }
            }
        }
    }
}
