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

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use pocx_hashlib::noncegen_common::{NUM_SCOOPS, SCOOP_SIZE};
use pocx_hashlib::quality_128::find_best_quality_128;
use pocx_hashlib::quality_256::find_best_quality_256;
use pocx_hashlib::quality_32::find_best_quality_32;
use pocx_hashlib::quality_512::find_best_quality_512;

// 16 warps * 4096 nonces * 64 bytes = 4MiB per benchmark run
const WARPS_PER_RUN: u64 = 16;
const NONCES_PER_WARP: u64 = NUM_SCOOPS as u64;
const TOTAL_NONCES: u64 = WARPS_PER_RUN * NONCES_PER_WARP;
const DATA_SIZE: usize = (TOTAL_NONCES * SCOOP_SIZE as u64) as usize;

fn bench_quality_calculation_none(c: &mut Criterion) {
    let mut group = c.benchmark_group("quality_calc");
    group.sample_size(100);
    group.throughput(Throughput::Elements(WARPS_PER_RUN));
    group.measurement_time(std::time::Duration::new(60, 0));

    let gensig = [0x55u8; 32];
    let data = vec![0x42u8; DATA_SIZE];

    group.bench_function("quality_32", |b| {
        b.iter(|| {
            find_best_quality_32(&data, TOTAL_NONCES, &gensig);
        })
    });
}

fn bench_quality_calculation_sse2avx(c: &mut Criterion) {
    if !is_x86_feature_detected!("avx") && !is_x86_feature_detected!("sse2") {
        return;
    };
    let mut group = c.benchmark_group("quality_calc");
    group.sample_size(100);
    group.throughput(Throughput::Elements(WARPS_PER_RUN));
    group.measurement_time(std::time::Duration::new(60, 0));

    let gensig = [0x55u8; 32];
    let data = vec![0x42u8; DATA_SIZE];

    group.bench_function("quality_128", |b| {
        b.iter(|| {
            find_best_quality_128(&data, TOTAL_NONCES, &gensig);
        })
    });
}

fn bench_quality_calculation_avx2(c: &mut Criterion) {
    if !is_x86_feature_detected!("avx2") {
        return;
    };
    let mut group = c.benchmark_group("quality_calc");
    group.sample_size(100);
    group.throughput(Throughput::Elements(WARPS_PER_RUN));
    group.measurement_time(std::time::Duration::new(60, 0));

    let gensig = [0x55u8; 32];
    let data = vec![0x42u8; DATA_SIZE];

    group.bench_function("quality_256", |b| {
        b.iter(|| {
            find_best_quality_256(&data, TOTAL_NONCES, &gensig);
        })
    });
}

fn bench_quality_calculation_avx512(c: &mut Criterion) {
    if !is_x86_feature_detected!("avx512f") {
        return;
    };
    let mut group = c.benchmark_group("quality_calc");
    group.sample_size(100);
    group.throughput(Throughput::Elements(WARPS_PER_RUN));
    group.measurement_time(std::time::Duration::new(60, 0));

    let gensig = [0x55u8; 32];
    let data = vec![0x42u8; DATA_SIZE];

    group.bench_function("quality_512", |b| {
        b.iter(|| {
            find_best_quality_512(&data, TOTAL_NONCES, &gensig);
        })
    });
}

criterion_group!(
    benches,
    bench_quality_calculation_none,
    bench_quality_calculation_sse2avx,
    bench_quality_calculation_avx2,
    bench_quality_calculation_avx512
);
criterion_main!(benches);
