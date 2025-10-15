use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use pocx_plotfile::{NUM_SCOOPS, SCOOP_SIZE};

// Include all SIMD implementations directly to avoid module dependencies

// Fallback implementation (no explicit SIMD)
fn compress_fallback(buffer: &mut [u8], pairs: u64, warp_size: usize) {
    for pair in 0..pairs {
        let warp_a_start = (pair * 2) as usize * warp_size;
        let warp_b_start = (pair * 2 + 1) as usize * warp_size;
        let dest_start = pair as usize * warp_size;

        for i in 0..warp_size {
            buffer[dest_start + i] = buffer[warp_a_start + i] ^ buffer[warp_b_start + i];
        }
    }
}

// SSE2 implementation
#[cfg(target_arch = "x86_64")]
unsafe fn compress_sse2(buffer: &mut [u8], pairs: u64, warp_size: usize) {
    use std::arch::x86_64::*;

    for pair in 0..pairs {
        let warp_a_start = (pair * 2) as usize * warp_size;
        let warp_b_start = (pair * 2 + 1) as usize * warp_size;
        let dest_start = pair as usize * warp_size;

        for chunk_offset in (0..warp_size).step_by(16) {
            let a_ptr = buffer.as_ptr().add(warp_a_start + chunk_offset) as *const __m128i;
            let b_ptr = buffer.as_ptr().add(warp_b_start + chunk_offset) as *const __m128i;

            let a = _mm_loadu_si128(a_ptr);
            let b = _mm_loadu_si128(b_ptr);
            let result = _mm_xor_si128(a, b);

            let dest_ptr = buffer.as_mut_ptr().add(dest_start + chunk_offset) as *mut __m128i;
            _mm_storeu_si128(dest_ptr, result);
        }
    }
}

// AVX implementation (32-byte operations, same as AVX2 for XOR)
#[cfg(target_arch = "x86_64")]
unsafe fn compress_avx(buffer: &mut [u8], pairs: u64, warp_size: usize) {
    use std::arch::x86_64::*;

    for pair in 0..pairs {
        let warp_a_start = (pair * 2) as usize * warp_size;
        let warp_b_start = (pair * 2 + 1) as usize * warp_size;
        let dest_start = pair as usize * warp_size;

        for chunk_offset in (0..warp_size).step_by(32) {
            let a_ptr = buffer.as_ptr().add(warp_a_start + chunk_offset) as *const __m256i;
            let b_ptr = buffer.as_ptr().add(warp_b_start + chunk_offset) as *const __m256i;

            let a = _mm256_loadu_si256(a_ptr);
            let b = _mm256_loadu_si256(b_ptr);
            let result = _mm256_xor_si256(a, b);

            let dest_ptr = buffer.as_mut_ptr().add(dest_start + chunk_offset) as *mut __m256i;
            _mm256_storeu_si256(dest_ptr, result);
        }
    }
}

// AVX2 implementation (32-byte operations with additional instructions)
#[cfg(target_arch = "x86_64")]
unsafe fn compress_avx2(buffer: &mut [u8], pairs: u64, warp_size: usize) {
    use std::arch::x86_64::*;

    for pair in 0..pairs {
        let warp_a_start = (pair * 2) as usize * warp_size;
        let warp_b_start = (pair * 2 + 1) as usize * warp_size;
        let dest_start = pair as usize * warp_size;

        for chunk_offset in (0..warp_size).step_by(32) {
            let a_ptr = buffer.as_ptr().add(warp_a_start + chunk_offset) as *const __m256i;
            let b_ptr = buffer.as_ptr().add(warp_b_start + chunk_offset) as *const __m256i;

            let a = _mm256_loadu_si256(a_ptr);
            let b = _mm256_loadu_si256(b_ptr);
            let result = _mm256_xor_si256(a, b);

            let dest_ptr = buffer.as_mut_ptr().add(dest_start + chunk_offset) as *mut __m256i;
            _mm256_storeu_si256(dest_ptr, result);
        }
    }
}

// AVX512F implementation
#[cfg(target_arch = "x86_64")]
unsafe fn compress_avx512f(buffer: &mut [u8], pairs: u64, warp_size: usize) {
    use std::arch::x86_64::*;

    for pair in 0..pairs {
        let warp_a_start = (pair * 2) as usize * warp_size;
        let warp_b_start = (pair * 2 + 1) as usize * warp_size;
        let dest_start = pair as usize * warp_size;

        for chunk_offset in (0..warp_size).step_by(64) {
            let a_ptr = buffer.as_ptr().add(warp_a_start + chunk_offset) as *const __m512i;
            let b_ptr = buffer.as_ptr().add(warp_b_start + chunk_offset) as *const __m512i;

            let a = _mm512_loadu_si512(a_ptr);
            let b = _mm512_loadu_si512(b_ptr);
            let result = _mm512_xor_si512(a, b);

            let dest_ptr = buffer.as_mut_ptr().add(dest_start + chunk_offset) as *mut __m512i;
            _mm512_storeu_si512(dest_ptr, result);
        }
    }
}

fn create_test_buffer(warps: usize) -> Vec<u8> {
    let warp_size = (NUM_SCOOPS * SCOOP_SIZE) as usize;
    let total_size = warps * warp_size;
    let mut buffer = vec![0u8; total_size];

    // Fill with pseudo-random data for realistic compression
    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte = ((i * 7919 + 1327) % 256) as u8;
    }

    buffer
}

fn bench_compression_none(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression");
    group.sample_size(100);
    group.throughput(Throughput::Elements(16)); // 16 warps -> 8 pairs
    group.measurement_time(std::time::Duration::new(10, 0)); // Reduced to 10 seconds

    let warps = 16;
    let warp_size_bytes = (NUM_SCOOPS * SCOOP_SIZE) as usize;
    let pairs = (warps / 2) as u64;

    group.bench_function("compress_fallback", |b| {
        b.iter(|| {
            let mut buffer = create_test_buffer(warps);
            compress_fallback(&mut buffer, pairs, warp_size_bytes);
        })
    });
}

fn bench_compression_sse2(c: &mut Criterion) {
    #[cfg(not(target_arch = "x86_64"))]
    return;

    #[cfg(target_arch = "x86_64")]
    {
        if !is_x86_feature_detected!("sse2") {
            return;
        }

        let mut group = c.benchmark_group("compression");
        group.sample_size(100);
        group.throughput(Throughput::Elements(16)); // 16 warps -> 8 pairs
        group.measurement_time(std::time::Duration::new(60, 0));

        let warps = 16;
        let warp_size_bytes = (NUM_SCOOPS * SCOOP_SIZE) as usize;
        let pairs = (warps / 2) as u64;

        group.bench_function("compress_sse2", |b| {
            b.iter(|| {
                let mut buffer = create_test_buffer(warps);
                unsafe {
                    compress_sse2(&mut buffer, pairs, warp_size_bytes);
                }
            })
        });
    }
}

fn bench_compression_avx(c: &mut Criterion) {
    #[cfg(not(target_arch = "x86_64"))]
    return;

    #[cfg(target_arch = "x86_64")]
    {
        if !is_x86_feature_detected!("avx") {
            return;
        }

        let mut group = c.benchmark_group("compression");
        group.sample_size(100);
        group.throughput(Throughput::Elements(16)); // 16 warps -> 8 pairs
        group.measurement_time(std::time::Duration::new(60, 0));

        let warps = 16;
        let warp_size_bytes = (NUM_SCOOPS * SCOOP_SIZE) as usize;
        let pairs = (warps / 2) as u64;

        group.bench_function("compress_avx", |b| {
            b.iter(|| {
                let mut buffer = create_test_buffer(warps);
                unsafe {
                    compress_avx(&mut buffer, pairs, warp_size_bytes);
                }
            })
        });
    }
}

fn bench_compression_avx2(c: &mut Criterion) {
    #[cfg(not(target_arch = "x86_64"))]
    return;

    #[cfg(target_arch = "x86_64")]
    {
        if !is_x86_feature_detected!("avx2") {
            return;
        }

        let mut group = c.benchmark_group("compression");
        group.sample_size(100);
        group.throughput(Throughput::Elements(16)); // 16 warps -> 8 pairs
        group.measurement_time(std::time::Duration::new(60, 0));

        let warps = 16;
        let warp_size_bytes = (NUM_SCOOPS * SCOOP_SIZE) as usize;
        let pairs = (warps / 2) as u64;

        group.bench_function("compress_avx2", |b| {
            b.iter(|| {
                let mut buffer = create_test_buffer(warps);
                unsafe {
                    compress_avx2(&mut buffer, pairs, warp_size_bytes);
                }
            })
        });
    }
}

fn bench_compression_avx512(c: &mut Criterion) {
    #[cfg(not(target_arch = "x86_64"))]
    return;

    #[cfg(target_arch = "x86_64")]
    {
        if !is_x86_feature_detected!("avx512f") {
            return;
        }

        let mut group = c.benchmark_group("compression");
        group.sample_size(100);
        group.throughput(Throughput::Elements(16)); // 16 warps -> 8 pairs
        group.measurement_time(std::time::Duration::new(60, 0));

        let warps = 16;
        let warp_size_bytes = (NUM_SCOOPS * SCOOP_SIZE) as usize;
        let pairs = (warps / 2) as u64;

        group.bench_function("compress_avx512f", |b| {
            b.iter(|| {
                let mut buffer = create_test_buffer(warps);
                unsafe {
                    compress_avx512f(&mut buffer, pairs, warp_size_bytes);
                }
            })
        });
    }
}

criterion_group!(
    benches,
    bench_compression_none,
    bench_compression_sse2,
    bench_compression_avx,
    bench_compression_avx2,
    bench_compression_avx512
);
criterion_main!(benches);
