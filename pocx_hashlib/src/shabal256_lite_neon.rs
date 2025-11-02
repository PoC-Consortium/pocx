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

//! ARM NEON-optimized Shabal256 lite implementation for quality calculations

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

use crate::noncegen_common::SCOOP_SIZE;

const MSHABAL_NEON_VECTOR_SIZE: usize = 4;

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

/// Helper macro to perform left rotation on NEON vectors
macro_rules! vrotlq_n_u32 {
    ($a:expr, $n:expr) => {
        vorrq_u32(vshlq_n_u32::<$n>($a), vshrq_n_u32::<{32 - $n}>($a))
    };
}

/// 4-way parallel Shabal256 lite using ARM NEON intrinsics
///
/// Optimized version for quality calculations in mining. Processes 4 scoops
/// in parallel to calculate mining quality values.
///
/// # Safety
///
/// This function uses NEON intrinsics and requires the `neon` target feature.
/// NEON is mandatory on all AArch64 processors.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn shabal256_lite_neon(
    scoops: &[u8],
    gensig: &[u8; 32],
) -> [u64; MSHABAL_NEON_VECTOR_SIZE] {
    assert_eq!(scoops.len(), SCOOP_SIZE * MSHABAL_NEON_VECTOR_SIZE);

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

    let one = vdupq_n_u32(0xFFFFFFFFu32);
    let mut w_low = 1u32;
    let mut w_high = 0u32;

    let mut message_data = [0u32; 16 * MSHABAL_NEON_VECTOR_SIZE];
    prepare_message_round1(&mut message_data, gensig, scoops);
    let message = message_data.as_ptr() as *const uint32x4_t;

    mshabal_quality_round(
        &mut a,
        &mut b,
        &mut c,
        message,
        &one,
        &mut w_low,
        &mut w_high,
        false,
    );

    prepare_message_termination(&mut message_data, scoops);
    let termination = message_data.as_ptr() as *const uint32x4_t;

    for _ in 0..4 {
        mshabal_quality_round(
            &mut a,
            &mut b,
            &mut c,
            termination,
            &one,
            &mut w_low,
            &mut w_high,
            true,
        );
    }

    let mut simd_dst = [0u32; 8];
    vst1q_u32(simd_dst.as_mut_ptr(), c[8]);
    vst1q_u32(simd_dst.as_mut_ptr().add(4), c[9]);

    let mut results = [0u64; MSHABAL_NEON_VECTOR_SIZE];
    for lane in 0..MSHABAL_NEON_VECTOR_SIZE {
        let low = simd_dst[lane] as u64;
        let high = simd_dst[lane + 4] as u64;
        results[lane] = low | (high << 32);
    }

    results
}

#[inline(always)]
#[cfg(target_arch = "aarch64")]
unsafe fn prepare_message_round1(
    message_data: &mut [u32; 16 * MSHABAL_NEON_VECTOR_SIZE],
    gensig: &[u8; 32],
    scoops: &[u8],
) {
    let gensig_u32 = gensig.as_ptr() as *const u32;
    let scoops_u32 = scoops.as_ptr() as *const u32;

    for i in 0..16 {
        for lane in 0..4 {
            let value = if i < 8 {
                *gensig_u32.add(i)
            } else {
                *scoops_u32.add(lane * 16 + (i - 8))
            };
            message_data[i * 4 + lane] = value;
        }
    }
}

#[inline(always)]
#[cfg(target_arch = "aarch64")]
unsafe fn prepare_message_termination(
    message_data: &mut [u32; 16 * MSHABAL_NEON_VECTOR_SIZE],
    scoops: &[u8],
) {
    let scoops_u32 = scoops.as_ptr() as *const u32;

    for i in 0..16 {
        for lane in 0..4 {
            let value = if i < 8 {
                *scoops_u32.add(lane * 16 + 8 + i)
            } else if i == 8 {
                0x80u32
            } else {
                0u32
            };
            message_data[i * 4 + lane] = value;
        }
    }
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
#[cfg(target_arch = "aarch64")]
unsafe fn mshabal_quality_round(
    a: &mut [uint32x4_t; 12],
    b: &mut [uint32x4_t; 16],
    c: &mut [uint32x4_t; 16],
    message: *const uint32x4_t,
    one: &uint32x4_t,
    w_low: &mut u32,
    w_high: &mut u32,
    is_termination: bool,
) {
    #[allow(clippy::needless_range_loop)]
    for j in 0..16 {
        b[j] = vaddq_u32(b[j], vld1q_u32(message.add(j) as *const u32));
    }

    a[0] = veorq_u32(a[0], vdupq_n_u32(*w_low));
    a[1] = veorq_u32(a[1], vdupq_n_u32(*w_high));

    #[allow(clippy::needless_range_loop)]
    for j in 0..16 {
        b[j] = vrotlq_n_u32!(b[j], 17);
    }

    pp_neon(a, 0x0, 0xB, b, 0x0, 0xD, 0x9, 0x6, c, 0x8, vld1q_u32(message.add(0x0) as *const u32), one);
    pp_neon(a, 0x1, 0x0, b, 0x1, 0xE, 0xA, 0x7, c, 0x7, vld1q_u32(message.add(0x1) as *const u32), one);
    pp_neon(a, 0x2, 0x1, b, 0x2, 0xF, 0xB, 0x8, c, 0x6, vld1q_u32(message.add(0x2) as *const u32), one);
    pp_neon(a, 0x3, 0x2, b, 0x3, 0x0, 0xC, 0x9, c, 0x5, vld1q_u32(message.add(0x3) as *const u32), one);
    pp_neon(a, 0x4, 0x3, b, 0x4, 0x1, 0xD, 0xA, c, 0x4, vld1q_u32(message.add(0x4) as *const u32), one);
    pp_neon(a, 0x5, 0x4, b, 0x5, 0x2, 0xE, 0xB, c, 0x3, vld1q_u32(message.add(0x5) as *const u32), one);
    pp_neon(a, 0x6, 0x5, b, 0x6, 0x3, 0xF, 0xC, c, 0x2, vld1q_u32(message.add(0x6) as *const u32), one);
    pp_neon(a, 0x7, 0x6, b, 0x7, 0x4, 0x0, 0xD, c, 0x1, vld1q_u32(message.add(0x7) as *const u32), one);
    pp_neon(a, 0x8, 0x7, b, 0x8, 0x5, 0x1, 0xE, c, 0x0, vld1q_u32(message.add(0x8) as *const u32), one);
    pp_neon(a, 0x9, 0x8, b, 0x9, 0x6, 0x2, 0xF, c, 0xF, vld1q_u32(message.add(0x9) as *const u32), one);
    pp_neon(a, 0xA, 0x9, b, 0xA, 0x7, 0x3, 0x0, c, 0xE, vld1q_u32(message.add(0xA) as *const u32), one);
    pp_neon(a, 0xB, 0xA, b, 0xB, 0x8, 0x4, 0x1, c, 0xD, vld1q_u32(message.add(0xB) as *const u32), one);
    pp_neon(a, 0x0, 0xB, b, 0xC, 0x9, 0x5, 0x2, c, 0xC, vld1q_u32(message.add(0xC) as *const u32), one);
    pp_neon(a, 0x1, 0x0, b, 0xD, 0xA, 0x6, 0x3, c, 0xB, vld1q_u32(message.add(0xD) as *const u32), one);
    pp_neon(a, 0x2, 0x1, b, 0xE, 0xB, 0x7, 0x4, c, 0xA, vld1q_u32(message.add(0xE) as *const u32), one);
    pp_neon(a, 0x3, 0x2, b, 0xF, 0xC, 0x8, 0x5, c, 0x9, vld1q_u32(message.add(0xF) as *const u32), one);

    pp_neon(a, 0x4, 0x3, b, 0x0, 0xD, 0x9, 0x6, c, 0x8, vld1q_u32(message.add(0x0) as *const u32), one);
    pp_neon(a, 0x5, 0x4, b, 0x1, 0xE, 0xA, 0x7, c, 0x7, vld1q_u32(message.add(0x1) as *const u32), one);
    pp_neon(a, 0x6, 0x5, b, 0x2, 0xF, 0xB, 0x8, c, 0x6, vld1q_u32(message.add(0x2) as *const u32), one);
    pp_neon(a, 0x7, 0x6, b, 0x3, 0x0, 0xC, 0x9, c, 0x5, vld1q_u32(message.add(0x3) as *const u32), one);
    pp_neon(a, 0x8, 0x7, b, 0x4, 0x1, 0xD, 0xA, c, 0x4, vld1q_u32(message.add(0x4) as *const u32), one);
    pp_neon(a, 0x9, 0x8, b, 0x5, 0x2, 0xE, 0xB, c, 0x3, vld1q_u32(message.add(0x5) as *const u32), one);
    pp_neon(a, 0xA, 0x9, b, 0x6, 0x3, 0xF, 0xC, c, 0x2, vld1q_u32(message.add(0x6) as *const u32), one);
    pp_neon(a, 0xB, 0xA, b, 0x7, 0x4, 0x0, 0xD, c, 0x1, vld1q_u32(message.add(0x7) as *const u32), one);
    pp_neon(a, 0x0, 0xB, b, 0x8, 0x5, 0x1, 0xE, c, 0x0, vld1q_u32(message.add(0x8) as *const u32), one);
    pp_neon(a, 0x1, 0x0, b, 0x9, 0x6, 0x2, 0xF, c, 0xF, vld1q_u32(message.add(0x9) as *const u32), one);
    pp_neon(a, 0x2, 0x1, b, 0xA, 0x7, 0x3, 0x0, c, 0xE, vld1q_u32(message.add(0xA) as *const u32), one);
    pp_neon(a, 0x3, 0x2, b, 0xB, 0x8, 0x4, 0x1, c, 0xD, vld1q_u32(message.add(0xB) as *const u32), one);
    pp_neon(a, 0x4, 0x3, b, 0xC, 0x9, 0x5, 0x2, c, 0xC, vld1q_u32(message.add(0xC) as *const u32), one);
    pp_neon(a, 0x5, 0x4, b, 0xD, 0xA, 0x6, 0x3, c, 0xB, vld1q_u32(message.add(0xD) as *const u32), one);
    pp_neon(a, 0x6, 0x5, b, 0xE, 0xB, 0x7, 0x4, c, 0xA, vld1q_u32(message.add(0xE) as *const u32), one);
    pp_neon(a, 0x7, 0x6, b, 0xF, 0xC, 0x8, 0x5, c, 0x9, vld1q_u32(message.add(0xF) as *const u32), one);

    pp_neon(a, 0x8, 0x7, b, 0x0, 0xD, 0x9, 0x6, c, 0x8, vld1q_u32(message.add(0x0) as *const u32), one);
    pp_neon(a, 0x9, 0x8, b, 0x1, 0xE, 0xA, 0x7, c, 0x7, vld1q_u32(message.add(0x1) as *const u32), one);
    pp_neon(a, 0xA, 0x9, b, 0x2, 0xF, 0xB, 0x8, c, 0x6, vld1q_u32(message.add(0x2) as *const u32), one);
    pp_neon(a, 0xB, 0xA, b, 0x3, 0x0, 0xC, 0x9, c, 0x5, vld1q_u32(message.add(0x3) as *const u32), one);
    pp_neon(a, 0x0, 0xB, b, 0x4, 0x1, 0xD, 0xA, c, 0x4, vld1q_u32(message.add(0x4) as *const u32), one);
    pp_neon(a, 0x1, 0x0, b, 0x5, 0x2, 0xE, 0xB, c, 0x3, vld1q_u32(message.add(0x5) as *const u32), one);
    pp_neon(a, 0x2, 0x1, b, 0x6, 0x3, 0xF, 0xC, c, 0x2, vld1q_u32(message.add(0x6) as *const u32), one);
    pp_neon(a, 0x3, 0x2, b, 0x7, 0x4, 0x0, 0xD, c, 0x1, vld1q_u32(message.add(0x7) as *const u32), one);
    pp_neon(a, 0x4, 0x3, b, 0x8, 0x5, 0x1, 0xE, c, 0x0, vld1q_u32(message.add(0x8) as *const u32), one);
    pp_neon(a, 0x5, 0x4, b, 0x9, 0x6, 0x2, 0xF, c, 0xF, vld1q_u32(message.add(0x9) as *const u32), one);
    pp_neon(a, 0x6, 0x5, b, 0xA, 0x7, 0x3, 0x0, c, 0xE, vld1q_u32(message.add(0xA) as *const u32), one);
    pp_neon(a, 0x7, 0x6, b, 0xB, 0x8, 0x4, 0x1, c, 0xD, vld1q_u32(message.add(0xB) as *const u32), one);
    pp_neon(a, 0x8, 0x7, b, 0xC, 0x9, 0x5, 0x2, c, 0xC, vld1q_u32(message.add(0xC) as *const u32), one);
    pp_neon(a, 0x9, 0x8, b, 0xD, 0xA, 0x6, 0x3, c, 0xB, vld1q_u32(message.add(0xD) as *const u32), one);
    pp_neon(a, 0xA, 0x9, b, 0xE, 0xB, 0x7, 0x4, c, 0xA, vld1q_u32(message.add(0xE) as *const u32), one);
    pp_neon(a, 0xB, 0xA, b, 0xF, 0xC, 0x8, 0x5, c, 0x9, vld1q_u32(message.add(0xF) as *const u32), one);

    a[0xB] = vaddq_u32(a[0xB], c[0x6]);
    a[0xA] = vaddq_u32(a[0xA], c[0x5]);
    a[0x9] = vaddq_u32(a[0x9], c[0x4]);
    a[0x8] = vaddq_u32(a[0x8], c[0x3]);
    a[0x7] = vaddq_u32(a[0x7], c[0x2]);
    a[0x6] = vaddq_u32(a[0x6], c[0x1]);
    a[0x5] = vaddq_u32(a[0x5], c[0x0]);
    a[0x4] = vaddq_u32(a[0x4], c[0xF]);
    a[0x3] = vaddq_u32(a[0x3], c[0xE]);
    a[0x2] = vaddq_u32(a[0x2], c[0xD]);
    a[0x1] = vaddq_u32(a[0x1], c[0xC]);
    a[0x0] = vaddq_u32(a[0x0], c[0xB]);
    a[0xB] = vaddq_u32(a[0xB], c[0xA]);
    a[0xA] = vaddq_u32(a[0xA], c[0x9]);
    a[0x9] = vaddq_u32(a[0x9], c[0x8]);
    a[0x8] = vaddq_u32(a[0x8], c[0x7]);
    a[0x7] = vaddq_u32(a[0x7], c[0x6]);
    a[0x6] = vaddq_u32(a[0x6], c[0x5]);
    a[0x5] = vaddq_u32(a[0x5], c[0x4]);
    a[0x4] = vaddq_u32(a[0x4], c[0x3]);
    a[0x3] = vaddq_u32(a[0x3], c[0x2]);
    a[0x2] = vaddq_u32(a[0x2], c[0x1]);
    a[0x1] = vaddq_u32(a[0x1], c[0x0]);
    a[0x0] = vaddq_u32(a[0x0], c[0xF]);
    a[0xB] = vaddq_u32(a[0xB], c[0xE]);
    a[0xA] = vaddq_u32(a[0xA], c[0xD]);
    a[0x9] = vaddq_u32(a[0x9], c[0xC]);
    a[0x8] = vaddq_u32(a[0x8], c[0xB]);
    a[0x7] = vaddq_u32(a[0x7], c[0xA]);
    a[0x6] = vaddq_u32(a[0x6], c[0x9]);
    a[0x5] = vaddq_u32(a[0x5], c[0x8]);
    a[0x4] = vaddq_u32(a[0x4], c[0x7]);
    a[0x3] = vaddq_u32(a[0x3], c[0x6]);
    a[0x2] = vaddq_u32(a[0x2], c[0x5]);
    a[0x1] = vaddq_u32(a[0x1], c[0x4]);
    a[0x0] = vaddq_u32(a[0x0], c[0x3]);

    for j in 0..16 {
        let message_j = vld1q_u32(message.add(j) as *const u32);
        let temp = b[j];
        b[j] = vsubq_u32(c[j], message_j);
        c[j] = temp;
    }

    *w_low = w_low.wrapping_add(1);
    if *w_low == 0 {
        *w_high = w_high.wrapping_add(1);
    }

    if is_termination {
        let old_low = *w_low;
        *w_low = w_low.wrapping_sub(1);
        if old_low == 0 {
            *w_high = w_high.wrapping_sub(1);
        }
    }
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
#[cfg(target_arch = "aarch64")]
unsafe fn pp_neon(
    a: &mut [uint32x4_t; 12],
    xa0_idx: usize,
    xa1_idx: usize,
    b: &mut [uint32x4_t; 16],
    xb0_idx: usize,
    xb1_idx: usize,
    xb2_idx: usize,
    xb3_idx: usize,
    c: &[uint32x4_t; 16],
    xc_idx: usize,
    xm: uint32x4_t,
    one: &uint32x4_t,
) {
    let xa1 = a[xa1_idx];
    let xb1 = b[xb1_idx];
    let xb2 = b[xb2_idx];
    let xb3 = b[xb3_idx];
    let xc = c[xc_idx];

    let mut tt = vrotlq_n_u32!(xa1, 15);
    tt = vaddq_u32(vshlq_n_u32::<2>(tt), tt);
    tt = veorq_u32(veorq_u32(a[xa0_idx], tt), xc);
    tt = vaddq_u32(vshlq_n_u32::<1>(tt), tt);
    tt = veorq_u32(
        veorq_u32(tt, xb1),
        veorq_u32(vbicq_u32(xb2, xb3), xm),
    );
    a[xa0_idx] = tt;

    tt = b[xb0_idx];
    tt = vrotlq_n_u32!(tt, 1);
    b[xb0_idx] = veorq_u32(tt, veorq_u32(a[xa0_idx], *one));
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_C_RESULT: u64 = 0x9824d76d62cd4f2f;
    const TEST_D_RESULT: u64 = 0x2ACEA174774F5A6A;

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_shabal256_lite_neon() {
        // Test message C: zero-filled test data and gensig
        let test_data = [0u8; 64];
        let gensig_c = [0u8; 32];
        let simd_data_c = [test_data; 4].concat();
        let neon_qualities_c = unsafe { shabal256_lite_neon(&simd_data_c, &gensig_c) };

        // Verify all lanes produce the expected result for test C
        for (i, &quality) in neon_qualities_c.iter().enumerate() {
            assert_eq!(
                quality, TEST_C_RESULT,
                "NEON test C: quality[{}] {} doesn't match expected {}",
                i, quality, TEST_C_RESULT
            );
        }

        // Test message D: zero-filled test data with specific gensig
        let gensig_hex = "4a6f686e6e7946464d206861742064656e206772f6df74656e2050656e697321";
        let gensig_d: [u8; 32] = hex::decode(gensig_hex)
            .expect("invalid hex")
            .try_into()
            .expect("hex must be 32 bytes");
        let simd_data_d = [test_data; 4].concat();
        let neon_qualities_d = unsafe { shabal256_lite_neon(&simd_data_d, &gensig_d) };

        // Verify all lanes produce the expected result for test D
        for (i, &quality) in neon_qualities_d.iter().enumerate() {
            assert_eq!(
                quality, TEST_D_RESULT,
                "NEON test D: quality[{}] {} doesn't match expected {}",
                i, quality, TEST_D_RESULT
            );
        }
    }
}
