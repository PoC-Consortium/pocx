# pocx_hashlib

Core cryptographic library for PoCX with SIMD-optimized Shabal256 implementations.

## Features

- **Nonce Hashing**: SIMD-optimized nonce generation for plot files
- **Quality Hashing**: High-performance quality calculations for mining
- **Generation Signature Hashing**: Next signature calculation and hex decoding
- **Scoop Hashing**: Block height to scoop number calculations
- **SIMD Support**: Runtime detection and optimization for SSE2, AVX, AVX2, AVX512f

## Quick Start

```rust
use pocx_hashlib::{
    find_best_quality, calculate_scoop, 
    generate_nonces, calculate_next_generation_signature
};

// Calculate next generation signature
let next_gen_sig = calculate_next_generation_signature(&old_gen_sig, &public_key);

// Calculate scoop number for current block  
let scoop = calculate_scoop(block_height, &next_gen_sig);

// Find best quality in plot data
let (quality, index) = find_best_quality(plot_data, nonce_count, &next_gen_sig);

// Generate nonces for plotting
generate_nonces(
    &mut cache, cache_offset, 
    &address_payload, &seed, 
    start_nonce, nonce_count
)?;
```

## Build

```bash
# Standard build
cargo build --release -p pocx_hashlib

# Run tests
cargo test -p pocx_hashlib

# Benchmarks
cargo bench -p pocx_hashlib
```

## API Functions

- `calculate_scoop(height, gen_sig)` - Get scoop number for mining
- `find_best_quality(data, count, gen_sig)` - Find best quality in plot data
- `generate_nonces(...)` - Generate plot file nonces
- `calculate_quality_raw(...)` - Calculate individual nonce quality
- `calculate_next_generation_signature(old_sig, pub_key)` - Calculate next generation signature
- `decode_generation_signature(hex)` - Parse hex generation signature

## License

MIT License - See [LICENSE](../LICENSE) for details.