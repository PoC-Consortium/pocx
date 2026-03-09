#!/usr/bin/env bash
# 15_cpu_vs_gpu.sh — Same seed: CPU and GPU must produce byte-identical output.
# This is the critical correctness gate.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "=== Test 15: CPU vs GPU (same seed, must be byte-identical) ==="

WARPS=2
COMPRESS=1
ESCALATE=1
THREADS="${CPU_THREADS:-0}"

DIR_CPU=$(make_temp_dir)
DIR_GPU=$(make_temp_dir)
trap 'rm -rf "$DIR_CPU" "$DIR_GPU"' EXIT

run_new_plotter_cpu_seeded "$DIR_CPU" "$WARPS" "$COMPRESS" "$ESCALATE" "$THREADS"
run_new_plotter_seeded "$DIR_GPU" "$WARPS" "$COMPRESS" "$ESCALATE"

FILE_CPU=$(find_plotfile "$DIR_CPU")
FILE_GPU=$(find_plotfile "$DIR_GPU")

if compare_files "$FILE_CPU" "$FILE_GPU"; then
    pass "CPU vs GPU — byte-identical output"
else
    fail "CPU vs GPU — files differ"
    exit 1
fi
