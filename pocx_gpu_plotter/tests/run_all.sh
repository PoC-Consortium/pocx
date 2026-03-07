#!/usr/bin/env bash
# run_all.sh — Run the full GPU+CPU plotter integration test suite.
#
# Usage: ./run_all.sh [gpu_id] [cpu_threads]
#   gpu_id: OpenCL device spec (default: 0:0:0)
#   cpu_threads: Number of CPU threads for CPU tests (default: 0 = auto)
#
# Individual tests can also be run standalone:
#   GPU=0:0:0 CPU_THREADS=0 ./tests/07_multipath.sh
set -euo pipefail

export GPU="${1:-0:0:0}"
export CPU_THREADS="${2:-0}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

echo "============================================"
echo "  PoCX Plotter — Integration Test Suite"
echo "============================================"
echo "GPU: $GPU"
echo "CPU threads: $CPU_THREADS (0=auto)"
echo ""

build_plotters

TESTS=(
    "$SCRIPT_DIR/01_x1_baseline.sh"
    "$SCRIPT_DIR/02_x2.sh"
    "$SCRIPT_DIR/03_x1_e3.sh"
    "$SCRIPT_DIR/04_x2_e2.sh"
    "$SCRIPT_DIR/05_x1_e5.sh"
    "$SCRIPT_DIR/06_double_buffer.sh"
    "$SCRIPT_DIR/07_multipath.sh"
    "$SCRIPT_DIR/08_multipath_x2_e2.sh"
    "$SCRIPT_DIR/09_multifile.sh"
    "$SCRIPT_DIR/10_multipath_multifile.sh"
    "$SCRIPT_DIR/11_cpu_x1.sh"
    "$SCRIPT_DIR/12_cpu_x2.sh"
    "$SCRIPT_DIR/13_cpu_e3.sh"
    "$SCRIPT_DIR/14_cpu_multipath.sh"
    "$SCRIPT_DIR/15_cpu_vs_gpu.sh"
)

TOTAL_PASS=0
TOTAL_FAIL=0

for test_script in "${TESTS[@]}"; do
    echo ""
    echo "--------------------------------------------"
    if bash "$test_script"; then
        ((TOTAL_PASS++)) || true
    else
        ((TOTAL_FAIL++)) || true
    fi
done

echo ""
echo "============================================"
echo "  Test Suite Summary"
echo "============================================"
echo "  Passed : $TOTAL_PASS / ${#TESTS[@]}"
echo "  Failed : $TOTAL_FAIL / ${#TESTS[@]}"
echo "============================================"
if [ "$TOTAL_FAIL" -gt 0 ]; then
    echo "  SOME TESTS FAILED"
    exit 1
else
    echo "  ALL TESTS PASSED"
fi
