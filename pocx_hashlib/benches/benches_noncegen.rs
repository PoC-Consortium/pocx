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

use pocx_hashlib::noncegen_128::generate_nonces_128;
use pocx_hashlib::noncegen_256::generate_nonces_256;
use pocx_hashlib::noncegen_32::generate_nonces_32;
use pocx_hashlib::noncegen_512::generate_nonces_512;
use pocx_hashlib::noncegen_common::NONCE_SIZE;

fn bench_nonce_generation_none(c: &mut Criterion) {
    let mut group = c.benchmark_group("nonce_gen");
    group.sample_size(100);
    group.throughput(Throughput::Elements(1));
    group.measurement_time(std::time::Duration::new(60, 0));
    let mut seed = [0u8; 32];
    seed[..].clone_from_slice(
        &hex::decode("AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE").unwrap(),
    );
    let mut address_payload = [0u8; 20];
    address_payload
        .clone_from_slice(&hex::decode("5599BC78BA577A95A11F1A344D4D2AE55F2F857B").unwrap());
    let start_nonce = 1337;

    let mut buf = vec![0; NONCE_SIZE];

    group.bench_function("generate_nonces_32", |b| {
        b.iter(|| {
            generate_nonces_32(&mut buf, 0, &address_payload, &seed, start_nonce, 1);
        })
    });
}

fn bench_nonce_generation_sse2avx(c: &mut Criterion) {
    if !is_x86_feature_detected!("avx") && !is_x86_feature_detected!("sse2") {
        return;
    };
    let mut group = c.benchmark_group("nonce_gen");
    group.sample_size(100);
    group.throughput(Throughput::Elements(4));
    group.measurement_time(std::time::Duration::new(60, 0));
    let mut seed = [0u8; 32];
    seed[..].clone_from_slice(
        &hex::decode("AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE").unwrap(),
    );
    let mut address_payload = [0u8; 20];
    address_payload
        .clone_from_slice(&hex::decode("5599BC78BA577A95A11F1A344D4D2AE55F2F857B").unwrap());
    let start_nonce = 1337;

    let mut buf = vec![0; 4 * NONCE_SIZE];

    group.bench_function("generate_nonces_128", |b| {
        b.iter(|| {
            generate_nonces_128(&mut buf, 0, &address_payload, &seed, start_nonce, 4);
        })
    });
}

fn bench_nonce_generation_avx2(c: &mut Criterion) {
    if !is_x86_feature_detected!("avx2") {
        return;
    };
    let mut group = c.benchmark_group("nonce_gen");
    group.sample_size(100);
    group.throughput(Throughput::Elements(8));
    group.measurement_time(std::time::Duration::new(60, 0));

    let mut seed = [0u8; 32];
    seed[..].clone_from_slice(
        &hex::decode("AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE").unwrap(),
    );
    let mut address_payload = [0u8; 20];
    address_payload
        .clone_from_slice(&hex::decode("5599BC78BA577A95A11F1A344D4D2AE55F2F857B").unwrap());
    let start_nonce = 1337;

    let mut buf = vec![0; 8 * NONCE_SIZE];

    group.bench_function("generate_nonces_256", |b| {
        b.iter(|| {
            generate_nonces_256(&mut buf, 0, &address_payload, &seed, start_nonce, 8);
        })
    });
}

fn bench_nonce_generation_avx512(c: &mut Criterion) {
    if !is_x86_feature_detected!("avx512f") {
        return;
    };
    let mut group = c.benchmark_group("nonce_gen");
    group.sample_size(100);
    group.throughput(Throughput::Elements(16));
    group.measurement_time(std::time::Duration::new(60, 0));
    let mut seed = [0u8; 32];
    seed[..].clone_from_slice(
        &hex::decode("AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE").unwrap(),
    );
    let mut address_payload = [0u8; 20];
    address_payload
        .clone_from_slice(&hex::decode("5599BC78BA577A95A11F1A344D4D2AE55F2F857B").unwrap());
    let start_nonce = 1337;

    let mut buf = vec![0; 16 * NONCE_SIZE];

    group.bench_function("generate_nonces_512", |b| {
        b.iter(|| {
            generate_nonces_512(&mut buf, 0, &address_payload, &seed, start_nonce, 16);
        })
    });
}

criterion_group!(
    benches,
    bench_nonce_generation_none,
    bench_nonce_generation_sse2avx,
    bench_nonce_generation_avx2,
    bench_nonce_generation_avx512
);
criterion_main!(benches);
