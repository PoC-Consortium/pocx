// Copyright (c) 2025 Proof of Capacity Consortium

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pocx_hashlib::{validate_proof, validate_proofs, ProofInput};

fn bench_gensig() -> [u8; 32] {
    let mut gensig = [0u8; 32];
    hex::decode_to_slice(
        "9821beb3b34d9a3b30127c05f8d1e9006f8a02f565a3572145134bbe34d37a76",
        &mut gensig,
    )
    .unwrap();
    gensig
}

fn bench_validate_single(c: &mut Criterion) {
    let gensig = bench_gensig();
    let mut group = c.benchmark_group("validate_single");

    for compression in [0u8, 1, 2, 3] {
        group.bench_with_input(
            BenchmarkId::new("compression", compression),
            &compression,
            |b, &comp| {
                let input = ProofInput {
                    address_payload: [0x42; 20],
                    seed: [0xAB; 32],
                    nonce: 1337,
                    compression: comp,
                    block_height: 0,
                    generation_signature: gensig,
                    base_target: 1,
                    claimed_quality: None,
                };
                b.iter(|| validate_proof(&input).unwrap());
            },
        );
    }
    group.finish();
}

fn bench_validate_batch(c: &mut Criterion) {
    let gensig = bench_gensig();
    let mut group = c.benchmark_group("validate_batch");

    for batch_size in [1, 4, 8, 16, 32, 64] {
        group.bench_with_input(
            BenchmarkId::new("proofs", batch_size),
            &batch_size,
            |b, &size| {
                let inputs: Vec<ProofInput> = (0..size)
                    .map(|i| ProofInput {
                        address_payload: {
                            let mut p = [0u8; 20];
                            p[0] = (i & 0xFF) as u8;
                            p[1] = ((i >> 8) & 0xFF) as u8;
                            p
                        },
                        seed: {
                            let mut s = [0u8; 32];
                            s[0] = (i & 0xFF) as u8;
                            s
                        },
                        nonce: 1000 + i as u64,
                        compression: 0,
                        block_height: 0,
                        generation_signature: gensig,
                        base_target: 1,
                        claimed_quality: None,
                    })
                    .collect();
                b.iter(|| validate_proofs(&inputs).unwrap());
            },
        );
    }
    group.finish();
}

fn bench_validate_batch_compressed(c: &mut Criterion) {
    let gensig = bench_gensig();
    let mut group = c.benchmark_group("validate_batch_compressed");

    for compression in [1u8, 2, 3] {
        group.bench_with_input(
            BenchmarkId::new("compression", compression),
            &compression,
            |b, &comp| {
                let inputs: Vec<ProofInput> = (0..8)
                    .map(|i| ProofInput {
                        address_payload: [(i + 1) as u8; 20],
                        seed: [((i + 1) as u8).wrapping_mul(0xAB); 32],
                        nonce: 100 + i as u64,
                        compression: comp,
                        block_height: 0,
                        generation_signature: gensig,
                        base_target: 1,
                        claimed_quality: None,
                    })
                    .collect();
                b.iter(|| validate_proofs(&inputs).unwrap());
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_validate_single,
    bench_validate_batch,
    bench_validate_batch_compressed,
);
criterion_main!(benches);
