#!/usr/bin/env bash
# test_plotter_compare_x2.sh — Compare old vs new plotter at compression X2.
#
# Usage: ./test_plotter_compare_x2.sh [gpu_id] [warps]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/test_plotter_compare.sh" "${1:-0:0:0}" 2 "${2:-4}"
