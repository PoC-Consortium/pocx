# pocx_plotter

High-performance plot file generator with CPU and GPU acceleration support.

## Features

- **Multi-Threaded CPU**: Efficient CPU plotting with thread scheduling
- **GPU Acceleration**: Optional OpenCL support for faster plotting  
- **SIMD Optimizations**: Leverages pocx_hashlib SIMD implementations
- **Memory Management**: Page-aligned buffers and efficient memory usage
- **Compression Support**: POW scaling via compression parameter
- **Progress Monitoring**: Real-time plotting progress with indicatif
- **Resume Support**: Continue interrupted plotting with seed parameter

## Quick Start

```bash
# CPU plotting (10 warps = ~10GB)
pocx_plotter -i <your_address> -p /path/to/plots -w 10

# GPU plotting with OpenCL  
pocx_plotter -i <your_address> -p /path/to/plots -w 10 -g 0:0

# With compression (2^4 scaling)
pocx_plotter -i <your_address> -p /path/to/plots -w 10 -x 4

# Resume plotting with seed
pocx_plotter -i <your_address> -p /path/to/plots -w 10 -s <seed_value> -n 1
```

## Build

```bash
# CPU-only build
cargo build --release -p pocx_plotter

# With OpenCL support
cargo build --release -p pocx_plotter --features opencl

# List OpenCL devices
./target/release/pocx_plotter -o
```

## Command Line Options

- `-i, --id <address>` - Your PoC mining address (required)
- `-p, --path <path>` - Target disk path(s) for plot files
- `-w, --warps <warps>` - Number of warps to plot (1 warp = 1 GiB)
- `-n, --num <number>` - Number of files to plot (default: 1)
- `-x, --compression <level>` - POW scaling factor (default: 1)
- `-s, --seed <seed>` - Seed to resume unfinished plot
- `-c, --cpu <threads>` - CPU threads to use
- `-g, --gpu <platform:device:cores>` - GPU configuration for plotting
- `-m, --mem <memory>` - Memory limit when plotting multiple disks
- `-b, --bench` - Run in benchmark mode
- `-o, --opencl` - Display OpenCL platforms and devices

## OpenCL GPU Plotting

```bash
# List available OpenCL devices
pocx_plotter -o

# Use specific GPU (platform 0, device 0)
pocx_plotter -i <address> -p /plots -w 100 -g 0:0

# Multiple GPUs with custom core count
pocx_plotter -i <address> -p /plots -w 100 -g 0:0:1024 -g 0:1:1024
```

## License

MIT License - See [LICENSE](../LICENSE) for details.