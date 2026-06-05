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

//! Emits a single `pocx_neon` cfg that unifies the NEON code paths across
//! AArch64 (NEON is mandatory, stable toolchain) and 32-bit ARM (NEON is
//! opt-in via the `armv7_neon` feature and requires a nightly toolchain).

fn main() {
    println!("cargo::rustc-check-cfg=cfg(pocx_neon)");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let armv7_neon = std::env::var("CARGO_FEATURE_ARMV7_NEON").is_ok();

    // AArch64: NEON is always available (stable intrinsics).
    // ARM (armv7/armhf): NEON intrinsics are nightly-only, gated behind the
    // `armv7_neon` feature.
    if arch == "aarch64" || (arch == "arm" && armv7_neon) {
        println!("cargo::rustc-cfg=pocx_neon");
    }
}
