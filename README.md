# PoCX - A neXt Generation Proof of Capacity Framework

[![Release](https://img.shields.io/github/v/release/PoC-Consortium/pocx)](https://github.com/PoC-Consortium/pocx/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%3E%3D1.91.0--nightly-brightgreen.svg)](https://www.rust-lang.org)

PoCX is a high-performance Proof-of-Capacity (PoC) cryptocurrency mining framework written in Rust. It provides tools for plot generation, mining, verification, and testing for PoC-based blockchains.

## What is Proof of Capacity?

Proof of Capacity is an eco-friendly consensus algorithm that uses pre-computed plot files stored on hard drives to participate in blockchain consensus. Unlike energy-intensive Proof-of-Work mining, PoC mining consumes minimal electricity after the initial plotting phase.

## Key Features

- **🚀 High Performance**: SIMD-optimized cryptographic operations (SSE2/AVX/AVX2/AVX512)
- **🎮 GPU Acceleration**: OpenCL support for faster plotting
- **⛓️ Multi-Chain Ready**: Support for multiple PoC blockchains
- **🔒 Enhanced Security**: Helix-resistant format prevents storage reduction attacks
- **⚡ Scalable PoW**: Adjustable proof-of-work difficulty (X1, X2, X4, ...)
- **📊 Built-in Testing**: Mock blockchain for development and testing
- **💻 Cross-Platform**: Windows, Linux, macOS support

## Quick Start

### Prerequisites

```bash
# Install Rust nightly toolchain
rustup toolchain install nightly --component rustfmt clippy
rustup override set nightly
```

### Build & Run

```bash
# Clone the repository
git clone https://github.com/PoC-Consortium/pocx.git
cd pocx

# Build all components
cargo build --release

# Create a plot file (example: 10 warps = ~10GB)
./target/release/pocx_plotter -i <your_address> -p /path/to/plots -w 10

# Start mining (requires config.yaml)
./target/release/pocx_miner -c config.yaml
```

## Project Components

| Component | Description |
|-----------|-------------|
| **pocx_hashlib** | Core cryptographic library with SIMD optimizations |
| **pocx_address** | Address encoding/decoding utilities |
| **pocx_plotfile** | Plot file I/O with memory-mapped operations |
| **pocx_plotter** | High-performance plot file generator |
| **pocx_miner** | Mining client supporting multiple chains |
| **pocx_aggregator** | Mining proxy aggregating submissions from multiple miners |
| **pocx_verifier** | Plot file integrity verification tool |
| **pocx_protocol** | JSON-RPC 2.0 protocol implementation |
| **pocx_mockchain** | Mock blockchain for testing |

## Example Configuration

### Mining Configuration (config.yaml)

```yaml
# Mining pools
chains:
  - name: "primary_pool"
    base_url: "http://pool.example.com:8080"
    api_path: "/pocx"
    accounts:
      - account: "your_account_id"

# Plot file directories  
plot_dirs:
  - "/path/to/plots1"
  - "/path/to/plots2"

# Performance settings
cpu_threads: 8
hdd_use_direct_io: true
show_progress: true
```

## Documentation

For comprehensive documentation, see the [Wiki](https://github.com/PoC-Consortium/pocx/wiki):
- **[Plotter Guide](https://github.com/PoC-Consortium/pocx/wiki/Plotter-Guide)** - Complete guide to plot file generation
- **[Miner Guide](https://github.com/PoC-Consortium/pocx/wiki/Miner-Guide)** - Mining configuration and operation
- **[Aggregator Guide](https://github.com/PoC-Consortium/pocx/wiki/Aggregator-Guide)** - Mining proxy configuration and setup
- **[Plot Format Specification](https://github.com/PoC-Consortium/pocx/wiki/Plot-Format)** - Technical format details
- **[Technical Details](https://github.com/PoC-Consortium/pocx/wiki/Technical-Details)** - Nonce construction and security analysis

## Development

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run CI pipeline
./ci/run-ci.sh
```

### Benchmarks

```bash
# Run performance benchmarks
cargo bench --workspace
```

## Attribution

### Plot Format
The plot format is based on POC2, originally specified by Burstcoin, with enhancements:
- Fixed security vulnerabilities (on-the-fly compression prevention)
- Scalable PoW for plot generation
- SIMD-aligned layout optimizations
- Enhanced compression capabilities

### Source Projects
- **Miner**: Based on [PoC-Consortium/scavenger](https://github.com/PoC-Consortium/scavenger)
- **Plotter**: Based on [PoC-Consortium/engraver](https://github.com/PoC-Consortium/engraver)

## Contributing

We welcome contributions! Please ensure your code:
- Passes all tests (`cargo test --workspace`)
- Follows Rust formatting (`cargo fmt`)
- Passes clippy lints (`cargo clippy`)

## License

PoCX is released under the MIT License. See [LICENSE](LICENSE) for details.

## Contact

**Organization**: Proof of Capacity Consortium  
**Project**: PoCX - Proof of Capacity neXt Generation

---