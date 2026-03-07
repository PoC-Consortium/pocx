# GPU Plotter Enhancement Plan

## Remaining Features

(none)

---

## Completed (archived)

### CPU Mode (`--cpu` as alternative to `--gpu`)

**Goal:** CPU-only plotting for machines without a GPU. Mutually exclusive with `--gpu`.

#### Architecture

```
CPU MODE:
  Scatter Buffer (2 GiB for X1)     Write Buffer (1 GiB * escalate)
  ┌───────────────────────┐         ┌───────────────────────┐
  │ generate_nonces()     │ helix   │ scoop-major layout    │ WriterTask
  │ hash + scatter via    │────────>│ interleaved warps     │──────────> disk_writer
  │ SIMD (AVX2/512/NEON)  │ compress│ (same as GPU output)  │
  └───────────────────────┘         └───────────────────────┘
```

Key difference from GPU mode: no ring buffer, no GPU transfer step. The CPU
hashes directly into a scatter buffer, then compresses into the write buffer.
Same disk writer, same multi-path interleaving, same escalation.

#### Buffer Sizes

- **Scatter buffer**: `DIM * 2 * NONCE_SIZE = 2 GiB` (constant, independent of compression)
  - Same approach as GPU: first pass writes (`=`), subsequent passes XOR-accumulate (`^=`)
  - Compression level only changes the number of passes, not the buffer size
- **Write buffer**: `WARP_SIZE * escalate` (1 GiB × escalate), same as GPU mode
- **Total host RAM**: 2 GiB scatter + (num_write_buffers × write_buffer_size)

#### File Changes

| File | Action | Description |
|------|--------|-------------|
| `Cargo.toml` | Modify | Add `pocx_hashlib`, `rayon`, `core_affinity` deps |
| `main.rs` | Modify | Add `--cpu [threads]` flag, mutual exclusion with `--gpu` |
| `plotter.rs` | Modify | Add `cpu_threads` to `PlotterTask`, branch `run()` on CPU vs GPU |
| `lib.rs` | Modify | Add module declarations, update `PlotterTaskBuilder` |
| `cpu_scheduler.rs` | Create | CPU scheduling thread (mirrors `ring_scheduler.rs` flow) |
| `cpu_compressor.rs` | Create | Port `helix_compress`, `xor_compress` from old plotter |
| `cpu_hasher.rs` | Create | `SafePointer`, `CpuTask`, `hash_cpu`, SIMD detection |

#### CPU Scheduler Flow

```rust
loop {
    // Check all paths complete / stop requested

    // Phase 1: Hash passes_per_warp × 8192 nonces into scatter buffer
    //   - Dispatch CPU_TASK_SIZE chunks to rayon thread pool
    //   - generate_nonces() scatters into scoop-major layout
    //   - First pass: write into scatter buffer
    //   - Subsequent passes (X2+): XOR-accumulate into same 2 GiB buffer
    //   - Same constant-memory approach as GPU ring compress

    // Phase 2: Transfer scatter → write buffer
    //   - Copy/interleave compressed result into correct warp slot

    // Phase 3: Flush and rotate (identical to ring_scheduler)
    //   - Flush when warps_in_buffer == escalate or at file boundary
    //   - Round-robin to next active path
    //   - No ring discard needed (scatter buffer is per-warp, not a ring)
}
```

#### Porting from Old Plotter

Source files to port from `pocx_plotter/src/`:
- `compressor.rs` → `cpu_compressor.rs` (helix XOR logic, scoop-level parallelism)
- `cpu_hasher.rs` → `cpu_hasher.rs` (SafePointer, CpuTask, hash_cpu, SIMD init)
- `xpu_scheduler.rs` → reference for CPU task dispatch pattern (crossbeam work stealing)

The `pocx_hashlib::generate_nonces()` function does the actual hashing + scatter.
It uses SIMD (AVX2/AVX512/NEON) and calls `unpack_shuffle_scatter()` internally.

#### Test Suite Additions

Add to `tests/` directory:

| Test | Description |
|------|-------------|
| `11_cpu_x1.sh` | CPU mode, X1, 9 warps — compare against old plotter |
| `12_cpu_x2.sh` | CPU mode, X2, 4 warps — compare against old plotter |
| `13_cpu_e3.sh` | CPU mode, X1, escalation=3 — compare against old plotter |
| `14_cpu_multipath.sh` | CPU mode, 2 paths — extract seeds, verify against old plotter |
| `15_cpu_vs_gpu.sh` | Same seed: CPU and GPU must produce byte-identical output |

Test 15 is the critical correctness gate: given the same seed, address, warps,
and compression, CPU and GPU modes must produce identical plotfiles.

---

## Completed

- **Variable Compression (X1–X6):** Multi-pass XOR-accumulate with constant GPU memory.
- **Escalation (`-e`):** Write buffer size = `escalate × WARP_SIZE`. Uses `clEnqueueReadBufferRect` for zero-copy interleaved GPU→host transfer.
- **Double-buffer (`-D`):** Extra write buffer for GPU/disk overlap. Count = `num_paths + 1`.
- **Multiple Disks (`--path` repeated):** Buffer-level round-robin interleaving across N output paths. Per-path nonce counters, seed management, completion tracking.
- **Integration Test Suite:** 10 tests covering X1/X2, escalation, double-buffer, multi-path, multi-file, and combinations.
- **CPU Mode (`--cpu`):** CPU-only plotting with `--cpu [threads]` flag. 2 GiB constant scatter buffer, helix compress with XOR-accumulate for X2+, same multi-path interleaving and escalation as GPU. Tests 11-15 verify X1, X2, escalation, multi-path, and CPU vs GPU byte-identical output.
