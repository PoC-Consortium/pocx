# pocx_miner

High-performance Proof-of-Capacity mining client.

## Features

- Multi-chain mining with priority scheduling and pause/resume
- Cross-platform (Windows, Linux, macOS)
- SIMD-optimized hash computation (AVX512/AVX2/SSE2)
- On-the-fly plot scaling
- Direct I/O support

## Quick Start

Configure via `config.yaml` file, then:

```bash
pocx_miner
```

## Build

```bash
cargo build --release -p pocx_miner
```

## License

MIT