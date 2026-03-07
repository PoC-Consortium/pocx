#!/usr/bin/env bash
# test_plotter_compare_e3.sh — Compare old vs new plotter with escalation=3.
#
# Usage: ./test_plotter_compare_e3.sh [gpu_id] [warps]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/test_plotter_compare.sh" "${1:-0:0:0}" 1 "${2:-9}" 3
