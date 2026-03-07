#!/usr/bin/env bash
# 12_cpu_x2.sh — CPU mode, X2, 1 warp — compare against old plotter (GPU).
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "=== Test 12: CPU X2 (1 warp, e=1) ==="

WARPS=1
COMPRESS=2
ESCALATE=1
THREADS="${CPU_THREADS:-0}"

DIR_NEW=$(make_temp_dir)
DIR_OLD=$(make_temp_dir)
trap 'rm -rf "$DIR_NEW" "$DIR_OLD"' EXIT

run_new_plotter_cpu_seeded "$DIR_NEW" "$WARPS" "$COMPRESS" "$ESCALATE" "$THREADS"
run_old_plotter "$DIR_OLD" "$WARPS" "$COMPRESS" "$ESCALATE"

FILE_NEW=$(find_plotfile "$DIR_NEW")
FILE_OLD=$(find_plotfile "$DIR_OLD")

if compare_files "$FILE_NEW" "$FILE_OLD"; then
    pass "CPU X2 — byte-identical to old plotter"
else
    fail "CPU X2 — files differ"
    exit 1
fi
