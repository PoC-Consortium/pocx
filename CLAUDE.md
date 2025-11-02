# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a high-performance Proof-of-Capacity (PoC) cryptocurrency mining framework written in Rust. PoC mining uses pre-computed plot files stored on hard drives to participate in blockchain consensus, offering an energy-efficient alternative to Proof-of-Work. The PoCX ecosystem provides a complete toolkit for plot generation, mining, verification, and testing - supporting multiple PoC-based blockchains simultaneously. The codebase features SIMD-optimized cryptographic operations (SSE2/AVX/AVX2/AVX512), memory-mapped I/O for efficient large file handling, and a modern async architecture with JSON-RPC 2.0 protocol support.

## Branding and Project Identity

- **Organization**: Proof of Capacity Consortium
- **Project Name**: PoCX
- **Full Name**: PoCX - A neXt generation Proof of Capacity Framework

## Attribution

### Plot Format
The plot format is based on POC2, a format used and specified by Burstcoin. Further development has been made on the format:
- Fixed security flaw (possibility to compress on-the-fly by a factor of 2, as exploited by Helix)
- PoW to generate the format can now be scaled
- Layout changed for SIMD alignment
- Added seed functionality

### Source Projects
- **Miner**: Based on https://github.com/PoC-Consortium/scavenger
- **Plotter**: Based on https://github.com/PoC-Consortium/engraver

## Project Structure

The repository contains 8 Rust crates:

- **pocx_hashlib/**: Core cryptographic library with SIMD optimizations (Shabal256, nonce generation)
- **pocx_address/**: Address encoding/decoding library (Base58, network IDs)
- **pocx_plotfile/**: Plot file I/O library with memory-mapped operations
- **pocx_plotter/**: Plot file generation with CPU/GPU acceleration
- **pocx_miner/**: Mining client for multiple PoC blockchains
- **pocx_mockchain/**: Mock blockchain simulator for testing
- **pocx_verifier/**: Plot file integrity verification tools
- **pocx_protocol/**: JSON-RPC 2.0 protocol implementation

## Development Requirements

### Rust Toolchain
- **Required Version**: Rust 1.91.0-nightly or later
- **Why Nightly**: Required for AVX512 intrinsics (will switch to stable once stabilized)
- **Components**: rustfmt, clippy
- **CI Tools**: cargo-audit, cargo-deny (auto-installed by CI scripts if missing)

### Installation
```bash
# Install nightly toolchain with required components
rustup toolchain install nightly --component rustfmt clippy

# Set as project default
rustup override set nightly

# Optional: Install CI tools manually (CI scripts auto-install if missing)
cargo install cargo-audit cargo-deny
```

### Optional Dependencies
- **OpenCL**: For GPU acceleration in pocx_plotter (requires OpenCL SDK)
- **SQLite**: Automatically handled by diesel for pocx_mockchain

## Common Development Commands

### Building
```bash
# Build entire workspace
cargo build --release

# Build with all features (includes OpenCL)
cargo build --release --all-features

# Build specific crate
cargo build --release -p pocx_miner
```

### Testing
```bash
# Run all tests
cargo test --workspace

# Run tests with release optimizations (faster for heavy tests)
cargo test --release --workspace

# Run specific crate tests
cargo test -p pocx_hashlib

# Run benchmarks
cargo bench --workspace
```

## CI Pipeline

Use the local CI scripts for development:
```bash
# Full CI pipeline (7 steps)
./ci/run-ci.sh

# Individual steps (workspace-level operations)
./ci/01-format.sh    # Code formatting
./ci/02-lint.sh      # Clippy linting (workspace-level)
./ci/03-security.sh  # Security audit
./ci/04-build.sh     # Build verification (workspace-level)
./ci/05-test.sh      # Test suite (workspace-level)
./ci/06-coverage.sh  # Coverage analysis (comprehensive, no timeouts)
./ci/07-docs.sh      # Documentation generation
```

# Instructions for Claude
- Role: Senior Software Engineer & Researcher in cryptography and distributed systems.  
- Priority: Quality over speed, with clean architecture, robustness, and security.  
- Output: production-grade, well-documented, testable code with clear reasoning and alternatives.  
- Internal reasoning: create and coordinate tasks/agents when useful; split complex problems into subtasks, explore solutions in parallel, and consolidate the best results.

## Code Style Guidelines
- **Documentation**: Professional and concise. Avoid excessive examples, emoji-heavy explanations, or tutorial-style comments.
- **Comments**: Essential explanations only. Remove verbose inline comments and step-by-step walkthroughs.
- **Function docs**: One-line summary preferred. Avoid multi-paragraph explanations unless absolutely necessary.
- **Demo code**: Always include clear production warnings when displaying sensitive data (private keys, etc.).
- **Test functions**: Keep functional tests, remove purely educational/tutorial test functions.
- **Implementation**: Clean, minimal code. Remove redundant intermediate variables and verbose logging.

## Git Commit Guidelines
- **CRITICAL**: NEVER use Co-Authored-By for Claude. ALL commits must have ONLY the user as the author.
- **Author**: Use only the user's name and email, never include Claude as co-author
- **Commit message format**: Clear subject line, detailed body if needed, NO co-author attribution
- **When committing**: ALWAYS use `git commit` without Co-Authored-By trailer  
