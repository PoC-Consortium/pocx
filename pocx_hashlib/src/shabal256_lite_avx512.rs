#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::noncegen_common::SCOOP_SIZE;

const MSHABAL512_VECTOR_SIZE: usize = 16;

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

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx512f")]
pub unsafe fn shabal256_lite_512(
    scoops: &[u8],
    gensig: &[u8; 32],
) -> [u64; MSHABAL512_VECTOR_SIZE] {
    assert_eq!(scoops.len(), SCOOP_SIZE * MSHABAL512_VECTOR_SIZE);

    let mut a: [__m512i; 12] = [
        _mm512_set1_epi32(A_INIT[0]),
        _mm512_set1_epi32(A_INIT[1]),
        _mm512_set1_epi32(A_INIT[2]),
        _mm512_set1_epi32(A_INIT[3]),
        _mm512_set1_epi32(A_INIT[4]),
        _mm512_set1_epi32(A_INIT[5]),
        _mm512_set1_epi32(A_INIT[6]),
        _mm512_set1_epi32(A_INIT[7]),
        _mm512_set1_epi32(A_INIT[8]),
        _mm512_set1_epi32(A_INIT[9]),
        _mm512_set1_epi32(A_INIT[10]),
        _mm512_set1_epi32(A_INIT[11]),
    ];

    let mut b: [__m512i; 16] = [
        _mm512_set1_epi32(B_INIT[0]),
        _mm512_set1_epi32(B_INIT[1]),
        _mm512_set1_epi32(B_INIT[2]),
        _mm512_set1_epi32(B_INIT[3]),
        _mm512_set1_epi32(B_INIT[4]),
        _mm512_set1_epi32(B_INIT[5]),
        _mm512_set1_epi32(B_INIT[6]),
        _mm512_set1_epi32(B_INIT[7]),
        _mm512_set1_epi32(B_INIT[8]),
        _mm512_set1_epi32(B_INIT[9]),
        _mm512_set1_epi32(B_INIT[10]),
        _mm512_set1_epi32(B_INIT[11]),
        _mm512_set1_epi32(B_INIT[12]),
        _mm512_set1_epi32(B_INIT[13]),
        _mm512_set1_epi32(B_INIT[14]),
        _mm512_set1_epi32(B_INIT[15]),
    ];

    let mut c: [__m512i; 16] = [
        _mm512_set1_epi32(C_INIT[0]),
        _mm512_set1_epi32(C_INIT[1]),
        _mm512_set1_epi32(C_INIT[2]),
        _mm512_set1_epi32(C_INIT[3]),
        _mm512_set1_epi32(C_INIT[4]),
        _mm512_set1_epi32(C_INIT[5]),
        _mm512_set1_epi32(C_INIT[6]),
        _mm512_set1_epi32(C_INIT[7]),
        _mm512_set1_epi32(C_INIT[8]),
        _mm512_set1_epi32(C_INIT[9]),
        _mm512_set1_epi32(C_INIT[10]),
        _mm512_set1_epi32(C_INIT[11]),
        _mm512_set1_epi32(C_INIT[12]),
        _mm512_set1_epi32(C_INIT[13]),
        _mm512_set1_epi32(C_INIT[14]),
        _mm512_set1_epi32(C_INIT[15]),
    ];

    let one = _mm512_set1_epi32(0xFFFFFFFFu32 as i32);
    let mut w_low = 1u32;
    let mut w_high = 0u32;

    let mut message_data = [0u32; 16 * MSHABAL512_VECTOR_SIZE];
    prepare_message_round1(&mut message_data, gensig, scoops);
    let message = message_data.as_ptr() as *const __m512i;

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
    let termination = message_data.as_ptr() as *const __m512i;

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

    let mut simd_dst = [0u32; 32];
    _mm512_storeu_si512(simd_dst.as_mut_ptr() as *mut __m512i, c[8]);
    _mm512_storeu_si512(simd_dst.as_mut_ptr().add(16) as *mut __m512i, c[9]);

    let mut results = [0u64; MSHABAL512_VECTOR_SIZE];
    for lane in 0..MSHABAL512_VECTOR_SIZE {
        let low = simd_dst[lane] as u64;
        let high = simd_dst[lane + 16] as u64;
        results[lane] = low | (high << 32);
    }

    results
}

#[inline(always)]
unsafe fn prepare_message_round1(
    message_data: &mut [u32; 16 * MSHABAL512_VECTOR_SIZE],
    gensig: &[u8; 32],
    scoops: &[u8],
) {
    let gensig_u32 = gensig.as_ptr() as *const u32;
    let scoops_u32 = scoops.as_ptr() as *const u32;

    for i in 0..16 {
        for lane in 0..16 {
            let value = if i < 8 {
                *gensig_u32.add(i)
            } else {
                *scoops_u32.add(lane * 16 + (i - 8))
            };
            message_data[i * 16 + lane] = value;
        }
    }
}

#[inline(always)]
unsafe fn prepare_message_termination(
    message_data: &mut [u32; 16 * MSHABAL512_VECTOR_SIZE],
    scoops: &[u8],
) {
    let scoops_u32 = scoops.as_ptr() as *const u32;

    for i in 0..16 {
        for lane in 0..16 {
            let value = if i < 8 {
                *scoops_u32.add(lane * 16 + 8 + i)
            } else if i == 8 {
                0x80u32
            } else {
                0u32
            };
            message_data[i * 16 + lane] = value;
        }
    }
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
unsafe fn mshabal_quality_round(
    a: &mut [__m512i; 12],
    b: &mut [__m512i; 16],
    c: &mut [__m512i; 16],
    message: *const __m512i,
    one: &__m512i,
    w_low: &mut u32,
    w_high: &mut u32,
    is_termination: bool,
) {
    #[allow(clippy::needless_range_loop)]
    for j in 0..16 {
        b[j] = _mm512_add_epi32(b[j], _mm512_loadu_si512(message.add(j)));
    }

    a[0] = _mm512_xor_si512(a[0], _mm512_set1_epi32(*w_low as i32));
    a[1] = _mm512_xor_si512(a[1], _mm512_set1_epi32(*w_high as i32));

    #[allow(clippy::needless_range_loop)]
    for j in 0..16 {
        b[j] = _mm512_or_si512(_mm512_slli_epi32(b[j], 17), _mm512_srli_epi32(b[j], 15));
    }

    pp512_avx512(
        a,
        0x0,
        0xB,
        b,
        0x0,
        0xD,
        0x9,
        0x6,
        c,
        0x8,
        _mm512_loadu_si512(message.add(0x0)),
        one,
    );
    pp512_avx512(
        a,
        0x1,
        0x0,
        b,
        0x1,
        0xE,
        0xA,
        0x7,
        c,
        0x7,
        _mm512_loadu_si512(message.add(0x1)),
        one,
    );
    pp512_avx512(
        a,
        0x2,
        0x1,
        b,
        0x2,
        0xF,
        0xB,
        0x8,
        c,
        0x6,
        _mm512_loadu_si512(message.add(0x2)),
        one,
    );
    pp512_avx512(
        a,
        0x3,
        0x2,
        b,
        0x3,
        0x0,
        0xC,
        0x9,
        c,
        0x5,
        _mm512_loadu_si512(message.add(0x3)),
        one,
    );
    pp512_avx512(
        a,
        0x4,
        0x3,
        b,
        0x4,
        0x1,
        0xD,
        0xA,
        c,
        0x4,
        _mm512_loadu_si512(message.add(0x4)),
        one,
    );
    pp512_avx512(
        a,
        0x5,
        0x4,
        b,
        0x5,
        0x2,
        0xE,
        0xB,
        c,
        0x3,
        _mm512_loadu_si512(message.add(0x5)),
        one,
    );
    pp512_avx512(
        a,
        0x6,
        0x5,
        b,
        0x6,
        0x3,
        0xF,
        0xC,
        c,
        0x2,
        _mm512_loadu_si512(message.add(0x6)),
        one,
    );
    pp512_avx512(
        a,
        0x7,
        0x6,
        b,
        0x7,
        0x4,
        0x0,
        0xD,
        c,
        0x1,
        _mm512_loadu_si512(message.add(0x7)),
        one,
    );
    pp512_avx512(
        a,
        0x8,
        0x7,
        b,
        0x8,
        0x5,
        0x1,
        0xE,
        c,
        0x0,
        _mm512_loadu_si512(message.add(0x8)),
        one,
    );
    pp512_avx512(
        a,
        0x9,
        0x8,
        b,
        0x9,
        0x6,
        0x2,
        0xF,
        c,
        0xF,
        _mm512_loadu_si512(message.add(0x9)),
        one,
    );
    pp512_avx512(
        a,
        0xA,
        0x9,
        b,
        0xA,
        0x7,
        0x3,
        0x0,
        c,
        0xE,
        _mm512_loadu_si512(message.add(0xA)),
        one,
    );
    pp512_avx512(
        a,
        0xB,
        0xA,
        b,
        0xB,
        0x8,
        0x4,
        0x1,
        c,
        0xD,
        _mm512_loadu_si512(message.add(0xB)),
        one,
    );
    pp512_avx512(
        a,
        0x0,
        0xB,
        b,
        0xC,
        0x9,
        0x5,
        0x2,
        c,
        0xC,
        _mm512_loadu_si512(message.add(0xC)),
        one,
    );
    pp512_avx512(
        a,
        0x1,
        0x0,
        b,
        0xD,
        0xA,
        0x6,
        0x3,
        c,
        0xB,
        _mm512_loadu_si512(message.add(0xD)),
        one,
    );
    pp512_avx512(
        a,
        0x2,
        0x1,
        b,
        0xE,
        0xB,
        0x7,
        0x4,
        c,
        0xA,
        _mm512_loadu_si512(message.add(0xE)),
        one,
    );
    pp512_avx512(
        a,
        0x3,
        0x2,
        b,
        0xF,
        0xC,
        0x8,
        0x5,
        c,
        0x9,
        _mm512_loadu_si512(message.add(0xF)),
        one,
    );

    pp512_avx512(
        a,
        0x4,
        0x3,
        b,
        0x0,
        0xD,
        0x9,
        0x6,
        c,
        0x8,
        _mm512_loadu_si512(message.add(0x0)),
        one,
    );
    pp512_avx512(
        a,
        0x5,
        0x4,
        b,
        0x1,
        0xE,
        0xA,
        0x7,
        c,
        0x7,
        _mm512_loadu_si512(message.add(0x1)),
        one,
    );
    pp512_avx512(
        a,
        0x6,
        0x5,
        b,
        0x2,
        0xF,
        0xB,
        0x8,
        c,
        0x6,
        _mm512_loadu_si512(message.add(0x2)),
        one,
    );
    pp512_avx512(
        a,
        0x7,
        0x6,
        b,
        0x3,
        0x0,
        0xC,
        0x9,
        c,
        0x5,
        _mm512_loadu_si512(message.add(0x3)),
        one,
    );
    pp512_avx512(
        a,
        0x8,
        0x7,
        b,
        0x4,
        0x1,
        0xD,
        0xA,
        c,
        0x4,
        _mm512_loadu_si512(message.add(0x4)),
        one,
    );
    pp512_avx512(
        a,
        0x9,
        0x8,
        b,
        0x5,
        0x2,
        0xE,
        0xB,
        c,
        0x3,
        _mm512_loadu_si512(message.add(0x5)),
        one,
    );
    pp512_avx512(
        a,
        0xA,
        0x9,
        b,
        0x6,
        0x3,
        0xF,
        0xC,
        c,
        0x2,
        _mm512_loadu_si512(message.add(0x6)),
        one,
    );
    pp512_avx512(
        a,
        0xB,
        0xA,
        b,
        0x7,
        0x4,
        0x0,
        0xD,
        c,
        0x1,
        _mm512_loadu_si512(message.add(0x7)),
        one,
    );
    pp512_avx512(
        a,
        0x0,
        0xB,
        b,
        0x8,
        0x5,
        0x1,
        0xE,
        c,
        0x0,
        _mm512_loadu_si512(message.add(0x8)),
        one,
    );
    pp512_avx512(
        a,
        0x1,
        0x0,
        b,
        0x9,
        0x6,
        0x2,
        0xF,
        c,
        0xF,
        _mm512_loadu_si512(message.add(0x9)),
        one,
    );
    pp512_avx512(
        a,
        0x2,
        0x1,
        b,
        0xA,
        0x7,
        0x3,
        0x0,
        c,
        0xE,
        _mm512_loadu_si512(message.add(0xA)),
        one,
    );
    pp512_avx512(
        a,
        0x3,
        0x2,
        b,
        0xB,
        0x8,
        0x4,
        0x1,
        c,
        0xD,
        _mm512_loadu_si512(message.add(0xB)),
        one,
    );
    pp512_avx512(
        a,
        0x4,
        0x3,
        b,
        0xC,
        0x9,
        0x5,
        0x2,
        c,
        0xC,
        _mm512_loadu_si512(message.add(0xC)),
        one,
    );
    pp512_avx512(
        a,
        0x5,
        0x4,
        b,
        0xD,
        0xA,
        0x6,
        0x3,
        c,
        0xB,
        _mm512_loadu_si512(message.add(0xD)),
        one,
    );
    pp512_avx512(
        a,
        0x6,
        0x5,
        b,
        0xE,
        0xB,
        0x7,
        0x4,
        c,
        0xA,
        _mm512_loadu_si512(message.add(0xE)),
        one,
    );
    pp512_avx512(
        a,
        0x7,
        0x6,
        b,
        0xF,
        0xC,
        0x8,
        0x5,
        c,
        0x9,
        _mm512_loadu_si512(message.add(0xF)),
        one,
    );

    pp512_avx512(
        a,
        0x8,
        0x7,
        b,
        0x0,
        0xD,
        0x9,
        0x6,
        c,
        0x8,
        _mm512_loadu_si512(message.add(0x0)),
        one,
    );
    pp512_avx512(
        a,
        0x9,
        0x8,
        b,
        0x1,
        0xE,
        0xA,
        0x7,
        c,
        0x7,
        _mm512_loadu_si512(message.add(0x1)),
        one,
    );
    pp512_avx512(
        a,
        0xA,
        0x9,
        b,
        0x2,
        0xF,
        0xB,
        0x8,
        c,
        0x6,
        _mm512_loadu_si512(message.add(0x2)),
        one,
    );
    pp512_avx512(
        a,
        0xB,
        0xA,
        b,
        0x3,
        0x0,
        0xC,
        0x9,
        c,
        0x5,
        _mm512_loadu_si512(message.add(0x3)),
        one,
    );
    pp512_avx512(
        a,
        0x0,
        0xB,
        b,
        0x4,
        0x1,
        0xD,
        0xA,
        c,
        0x4,
        _mm512_loadu_si512(message.add(0x4)),
        one,
    );
    pp512_avx512(
        a,
        0x1,
        0x0,
        b,
        0x5,
        0x2,
        0xE,
        0xB,
        c,
        0x3,
        _mm512_loadu_si512(message.add(0x5)),
        one,
    );
    pp512_avx512(
        a,
        0x2,
        0x1,
        b,
        0x6,
        0x3,
        0xF,
        0xC,
        c,
        0x2,
        _mm512_loadu_si512(message.add(0x6)),
        one,
    );
    pp512_avx512(
        a,
        0x3,
        0x2,
        b,
        0x7,
        0x4,
        0x0,
        0xD,
        c,
        0x1,
        _mm512_loadu_si512(message.add(0x7)),
        one,
    );
    pp512_avx512(
        a,
        0x4,
        0x3,
        b,
        0x8,
        0x5,
        0x1,
        0xE,
        c,
        0x0,
        _mm512_loadu_si512(message.add(0x8)),
        one,
    );
    pp512_avx512(
        a,
        0x5,
        0x4,
        b,
        0x9,
        0x6,
        0x2,
        0xF,
        c,
        0xF,
        _mm512_loadu_si512(message.add(0x9)),
        one,
    );
    pp512_avx512(
        a,
        0x6,
        0x5,
        b,
        0xA,
        0x7,
        0x3,
        0x0,
        c,
        0xE,
        _mm512_loadu_si512(message.add(0xA)),
        one,
    );
    pp512_avx512(
        a,
        0x7,
        0x6,
        b,
        0xB,
        0x8,
        0x4,
        0x1,
        c,
        0xD,
        _mm512_loadu_si512(message.add(0xB)),
        one,
    );
    pp512_avx512(
        a,
        0x8,
        0x7,
        b,
        0xC,
        0x9,
        0x5,
        0x2,
        c,
        0xC,
        _mm512_loadu_si512(message.add(0xC)),
        one,
    );
    pp512_avx512(
        a,
        0x9,
        0x8,
        b,
        0xD,
        0xA,
        0x6,
        0x3,
        c,
        0xB,
        _mm512_loadu_si512(message.add(0xD)),
        one,
    );
    pp512_avx512(
        a,
        0xA,
        0x9,
        b,
        0xE,
        0xB,
        0x7,
        0x4,
        c,
        0xA,
        _mm512_loadu_si512(message.add(0xE)),
        one,
    );
    pp512_avx512(
        a,
        0xB,
        0xA,
        b,
        0xF,
        0xC,
        0x8,
        0x5,
        c,
        0x9,
        _mm512_loadu_si512(message.add(0xF)),
        one,
    );

    a[0xB] = _mm512_add_epi32(a[0xB], c[0x6]);
    a[0xA] = _mm512_add_epi32(a[0xA], c[0x5]);
    a[0x9] = _mm512_add_epi32(a[0x9], c[0x4]);
    a[0x8] = _mm512_add_epi32(a[0x8], c[0x3]);
    a[0x7] = _mm512_add_epi32(a[0x7], c[0x2]);
    a[0x6] = _mm512_add_epi32(a[0x6], c[0x1]);
    a[0x5] = _mm512_add_epi32(a[0x5], c[0x0]);
    a[0x4] = _mm512_add_epi32(a[0x4], c[0xF]);
    a[0x3] = _mm512_add_epi32(a[0x3], c[0xE]);
    a[0x2] = _mm512_add_epi32(a[0x2], c[0xD]);
    a[0x1] = _mm512_add_epi32(a[0x1], c[0xC]);
    a[0x0] = _mm512_add_epi32(a[0x0], c[0xB]);
    a[0xB] = _mm512_add_epi32(a[0xB], c[0xA]);
    a[0xA] = _mm512_add_epi32(a[0xA], c[0x9]);
    a[0x9] = _mm512_add_epi32(a[0x9], c[0x8]);
    a[0x8] = _mm512_add_epi32(a[0x8], c[0x7]);
    a[0x7] = _mm512_add_epi32(a[0x7], c[0x6]);
    a[0x6] = _mm512_add_epi32(a[0x6], c[0x5]);
    a[0x5] = _mm512_add_epi32(a[0x5], c[0x4]);
    a[0x4] = _mm512_add_epi32(a[0x4], c[0x3]);
    a[0x3] = _mm512_add_epi32(a[0x3], c[0x2]);
    a[0x2] = _mm512_add_epi32(a[0x2], c[0x1]);
    a[0x1] = _mm512_add_epi32(a[0x1], c[0x0]);
    a[0x0] = _mm512_add_epi32(a[0x0], c[0xF]);
    a[0xB] = _mm512_add_epi32(a[0xB], c[0xE]);
    a[0xA] = _mm512_add_epi32(a[0xA], c[0xD]);
    a[0x9] = _mm512_add_epi32(a[0x9], c[0xC]);
    a[0x8] = _mm512_add_epi32(a[0x8], c[0xB]);
    a[0x7] = _mm512_add_epi32(a[0x7], c[0xA]);
    a[0x6] = _mm512_add_epi32(a[0x6], c[0x9]);
    a[0x5] = _mm512_add_epi32(a[0x5], c[0x8]);
    a[0x4] = _mm512_add_epi32(a[0x4], c[0x7]);
    a[0x3] = _mm512_add_epi32(a[0x3], c[0x6]);
    a[0x2] = _mm512_add_epi32(a[0x2], c[0x5]);
    a[0x1] = _mm512_add_epi32(a[0x1], c[0x4]);
    a[0x0] = _mm512_add_epi32(a[0x0], c[0x3]);

    for j in 0..16 {
        let message_j = _mm512_loadu_si512(message.add(j));
        let temp = b[j];
        b[j] = _mm512_sub_epi32(c[j], message_j);
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
unsafe fn pp512_avx512(
    a: &mut [__m512i; 12],
    xa0_idx: usize,
    xa1_idx: usize,
    b: &mut [__m512i; 16],
    xb0_idx: usize,
    xb1_idx: usize,
    xb2_idx: usize,
    xb3_idx: usize,
    c: &[__m512i; 16],
    xc_idx: usize,
    xm: __m512i,
    one: &__m512i,
) {
    let xa1 = a[xa1_idx];
    let xb1 = b[xb1_idx];
    let xb2 = b[xb2_idx];
    let xb3 = b[xb3_idx];
    let xc = c[xc_idx];

    let mut tt = _mm512_or_si512(_mm512_slli_epi32(xa1, 15), _mm512_srli_epi32(xa1, 17));
    tt = _mm512_add_epi32(_mm512_slli_epi32(tt, 2), tt);
    tt = _mm512_xor_si512(_mm512_xor_si512(a[xa0_idx], tt), xc);
    tt = _mm512_add_epi32(_mm512_slli_epi32(tt, 1), tt);
    tt = _mm512_xor_si512(
        _mm512_xor_si512(tt, xb1),
        _mm512_xor_si512(_mm512_andnot_si512(xb3, xb2), xm),
    );
    a[xa0_idx] = tt;

    tt = b[xb0_idx];
    tt = _mm512_or_si512(_mm512_slli_epi32(tt, 1), _mm512_srli_epi32(tt, 31));
    b[xb0_idx] = _mm512_xor_si512(tt, _mm512_xor_si512(a[xa0_idx], *one));
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_C_RESULT: u64 = 0x9824d76d62cd4f2f;
    const TEST_D_RESULT: u64 = 0x2ACEA174774F5A6A;

    #[test]
    fn test_shabal256_lite_avx512() {
        if !is_x86_feature_detected!("avx512f") {
            println!("SKIPPED: test_shabal256_lite_avx512 - AVX512 not supported by CPU");
            return;
        }

        // Test message C: zero-filled test data and gensig
        let test_data = [0u8; 64];
        let gensig_c = [0u8; 32];
        let simd_data_c = [test_data; 16].concat();
        let avx512_qualities_c = unsafe { shabal256_lite_512(&simd_data_c, &gensig_c) };

        // Verify all lanes produce the expected result for test C
        for (i, &quality) in avx512_qualities_c.iter().enumerate() {
            assert_eq!(
                quality, TEST_C_RESULT,
                "AVX512 test C: quality[{}] {} doesn't match expected {}",
                i, quality, TEST_C_RESULT
            );
        }

        // Test message D: zero-filled test data with specific gensig
        let gensig_hex = "4a6f686e6e7946464d206861742064656e206772f6df74656e2050656e697321";
        let gensig_d: [u8; 32] = hex::decode(gensig_hex)
            .expect("invalid hex")
            .try_into()
            .expect("hex must be 32 bytes");
        let simd_data_d = [test_data; 16].concat();
        let avx512_qualities_d = unsafe { shabal256_lite_512(&simd_data_d, &gensig_d) };

        // Verify all lanes produce the expected result for test D
        for (i, &quality) in avx512_qualities_d.iter().enumerate() {
            assert_eq!(
                quality, TEST_D_RESULT,
                "AVX512 test D: quality[{}] {} doesn't match expected {}",
                i, quality, TEST_D_RESULT
            );
        }
    }
}
