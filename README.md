# PoCX - A neXt Generation Proof of Capacity Framework

[![Release](https://img.shields.io/github/v/release/PoC-Consortium/pocx)](https://github.com/PoC-Consortium/pocx/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%3E%3D1.75.0-brightgreen.svg)](https://www.rust-lang.org)
![Website](https://img.shields.io/website?url=https%3A%2F%2Fbitcoin-pocx.org&up_message=Website%20here&up_color=%23ED7D31&down_message=Maintainance&down_color=lightgrey&logo=bitcoin&logoColor=%23ED7D31)


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
# Install Rust stable toolchain (1.75.0 or later)
rustup toolchain install stable --component rustfmt clippy
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
| **pocx_plotter** | Plot file generator (v1, low-VRAM fallback) |
| **pocx_plotter_v2** | Plot file generator (v2, GPU-fused pipeline, recommended; requires ≥ 3 GiB GPU memory) |
| **pocx_miner** | Mining client supporting multiple chains |
| **pocx_aggregator** | Mining proxy aggregating submissions from multiple miners |
| **pocx_verifier** | Plot file integrity verification tool |
| **pocx_protocol** | JSON-RPC 2.0 protocol implementation |
| **pocx_mockchain** | Mock blockchain for testing |

## Example Configuration

### Mining Configuration (miner_config.yaml)

```yaml
# Mining chains (pools or local nodes)
chains:
  - name: 'primary_pool'
    rpc_transport: http           # http | https
    rpc_host: 'pool.example.com'
    rpc_port: 8080
    rpc_auth:
      type: none                  # none | user_pass | cookie
      # username: 'miner'
      # password: 'secret'
    block_time_seconds: 120
    submission_mode: pool         # pool | wallet
    # Optional per-account quality overrides
    # accounts:
    #   - account: '0123456789abcdef...'
    #     target_quality: 500000

# Plot file directories - all drives containing .pocx plot files
plot_dirs:
  - 'D:\'
  # - '/mnt/plots'                # Linux example

# Performance settings
cpu_threads: 0                    # 0 = auto-detect
hdd_use_direct_io: true
show_progress: true
```

See `pocx_miner/miner_config.yaml` for the complete reference (cookie auth, HTTPS pools, multi-chain setups).

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
