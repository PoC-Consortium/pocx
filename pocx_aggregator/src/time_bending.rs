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

use num_bigint::BigUint;
use num_traits::One;
#[cfg(test)]
use num_traits::Zero;

/// Integer cube root using binary search (256-bit precision)
fn int_cuberoot_u256(x: &BigUint) -> BigUint {
    let mut hi = BigUint::one();

    while (&hi * &hi * &hi) < *x {
        hi <<= 1;
    }
    let mut lo = &hi >> 1;

    while lo < hi {
        let mid = (&lo + &hi + BigUint::one()) >> 1;
        let mid3 = &mid * &mid * &mid;
        if &mid3 <= x {
            lo = mid;
        } else {
            hi = mid - BigUint::one();
        }
    }
    lo
}

/// Calculate dynamic scale factor SCALE_Q based on block_time
fn calculate_qscale_uint(block_time: u64) -> BigUint {
    const Q: u32 = 42;

    // Precomputed Gamma(4/3) in Q42 fixed point
    // Gamma(4/3) ≈ 0.892979511
    // 0.892979511 * 2^42 ≈ 3927365422841
    const GAMMA_FP: u64 = 3927365422841;

    let t = BigUint::from(block_time);

    // Compute cube root of block_time in Q42 fixed point
    // t_cbrt = floor(block_time^(1/3) * 2^Q)
    let block_scaled = &t << (3 * Q);
    let t_cbrt = int_cuberoot_u256(&block_scaled);

    // Formula: SCALE_Q = (block_time * 2^Q) / (cbrt * gamma / 2^Q)
    // numerator = block_time * 2^(2*Q)
    let numerator = &t << (2 * Q);

    // denominator = t_cbrt * GAMMA_FP >> Q
    let denominator = (&t_cbrt * BigUint::from(GAMMA_FP)) >> Q;

    // SCALE_Q = round-half-up
    (&numerator + (&denominator >> 1)) / &denominator
}

/// Calculate time-bended deadline using exact integer math
/// Port of C++ CalculateTimeBendedDeadline with identical arithmetic
pub fn calculate_time_bended_deadline(quality: u64, base_target: u64, block_time: u64) -> u64 {
    const P: u32 = 21;
    const Q: u32 = 42;

    if quality == 0 {
        return 0;
    }

    // Calculate dynamic scale factor based on block_time
    let scale_q = calculate_qscale_uint(block_time);

    let shift_3p = BigUint::one() << (3 * P);
    let v = (BigUint::from(quality) * &shift_3p) / BigUint::from(base_target);

    let r = int_cuberoot_u256(&v);

    let numer = &scale_q * &r;
    let denom = BigUint::one() << (P + Q);
    let rounded: BigUint = (&numer + (&denom >> 1)) / &denom;

    // Extract low 64 bits
    let digits = rounded.to_u64_digits();
    if digits.is_empty() {
        0
    } else {
        digits[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cuberoot_basic() {
        assert_eq!(int_cuberoot_u256(&BigUint::from(0u64)), BigUint::zero());
        assert_eq!(int_cuberoot_u256(&BigUint::from(1u64)), BigUint::one());
        assert_eq!(int_cuberoot_u256(&BigUint::from(8u64)), BigUint::from(2u64));
        assert_eq!(
            int_cuberoot_u256(&BigUint::from(27u64)),
            BigUint::from(3u64)
        );
    }

    #[test]
    fn test_time_bending_zero() {
        assert_eq!(calculate_time_bended_deadline(0, 100, 120), 0);
    }

    #[test]
    fn test_time_bending_basic() {
        // Test with raw quality (not adjusted)
        let adjusted_quality = 1000u64;
        let base_target = 265949979u64;
        let raw_quality = adjusted_quality * base_target;

        let poc_time = calculate_time_bended_deadline(raw_quality, base_target, 120);
        println!(
            "poc_time for adjusted_quality={}, base_target={}, block_time=120: {}",
            adjusted_quality, base_target, poc_time
        );
        assert!(poc_time > 0, "poc_time should be > 0, got {}", poc_time);
        assert!(
            poc_time < 86400,
            "poc_time should be < 86400, got {}",
            poc_time
        );
    }

    #[test]
    fn test_time_bending_reference_values() {
        // Test with realistic base_target value
        let bt = 314467198u64;

        // Wallet log shows: quality=103, poc_time=128
        // But that quality is ADJUSTED quality (raw/base_target)
        // So raw_quality = adjusted_quality * base_target
        let adjusted_quality = 103u64;
        let raw_quality = adjusted_quality * bt;

        println!(
            "Testing: adjusted_quality={}, base_target={}",
            adjusted_quality, bt
        );
        println!(
            "raw_quality = {} * {} = {}",
            adjusted_quality, bt, raw_quality
        );

        let result = calculate_time_bended_deadline(raw_quality, bt, 120);
        println!(
            "calculate_time_bended_deadline({}, {}, 120) = {}",
            raw_quality, bt, result
        );
        println!("Expected: ~128 seconds");

        // The result should be close to 128 (allow small rounding differences)
        assert!(
            result > 100 && result < 150,
            "Expected ~128, got {}",
            result
        );
    }
}
