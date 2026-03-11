# pocx_plotter_v2

High-performance plot file generator with GPU-fused ring buffer architecture.

## Features

- **GPU-Fused Pipeline**: On-GPU scatter, shuffle, and helix compression
- **CPU Fallback**: Multi-threaded CPU plotting when no GPU is available
- **SIMD Optimizations**: Leverages pocx_hashlib SIMD implementations
- **Minimal Host Memory**: Ring buffer design uses ~1 GiB host memory per write buffer
- **Compression Support**: POW scaling via compression parameter (levels 1-6)
- **Async Write**: Optional double-buffered GPU/disk overlap
- **Multi-Path Resume**: Per-path seed and resume support for interrupted plots
- **Progress Monitoring**: Real-time plotting progress with indicatif

## Quick Start

```bash
# CPU plotting (10 warps = ~10 GiB, default)
pocx_plotter_v2 -i <your_address> -p /path/to/plots -w 10

# GPU plotting with OpenCL
pocx_plotter_v2 -i <your_address> -p /path/to/plots -w 10 -g 0:0

# With compression (2^4 scaling)
pocx_plotter_v2 -i <your_address> -p /path/to/plots -w 10 -x 4

# Resume plotting with seed
pocx_plotter_v2 -i <your_address> -p /path/to/plots -w 10 -s <seed_hex>

# Multi-path resume (one seed per path)
pocx_plotter_v2 -i <your_address> -p /disk1 -p /disk2 -w 10 -s <seed1> -s <seed2>
```

## Build

```bash
# With OpenCL support (default)
cargo build --release -p pocx_plotter_v2

# CPU-only build
cargo build --release -p pocx_plotter_v2 --no-default-features

# List OpenCL devices
./target/release/pocx_plotter_v2 -o
```

## Command Line Options

- `-i, --id <address>` - Your PoC mining address (required)
- `-p, --path <path>` - Target disk path(s) for plot files
- `-w, --warps <warps>` - Number of warps to plot (1 warp = 1 GiB, required)
- `-n, --num <number>` - Number of files to plot (default: 1)
- `-x, --compression <level>` - POW scaling factor 1-6 (default: 1)
- `-s, --seed <seed>` - Seed(s) to resume unfinished plot(s), one per -p path
- `-c, --cpu <threads>` - CPU-only plotting with N threads (0 = auto-detect)
- `-g, --gpu <platform:device:cores>` - GPU configuration for plotting
- `-e, --escalate <warps>` - Write buffer size multiplier (default: 1)
- `-a, --async-write` - Allocate extra write buffer for GPU/disk overlap
- `-b, --bench` - Run in benchmark mode
- `-o, --opencl` - Display OpenCL platforms and devices

## OpenCL GPU Plotting

```bash
# List available OpenCL devices
pocx_plotter_v2 -o

# Use specific GPU (platform 0, device 0)
pocx_plotter_v2 -i <address> -p /plots -w 100 -g 0:0

# GPU with async write for overlapping I/O
pocx_plotter_v2 -i <address> -p /plots -w 100 -g 0:0 -a
```

## License

MIT License - See [LICENSE](../LICENSE) for details.
