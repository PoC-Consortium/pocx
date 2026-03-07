#!/usr/bin/env bash
# 06_double_buffer.sh — X1, 9 warps, e=3 with double-buffer flag.
# Double-buffer only affects performance, output must be identical.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "=== Test 06: Double-buffer (X1, 9 warps, e=3, -D) ==="

DIR_OLD=$(make_temp_dir)
DIR_NEW=$(make_temp_dir)
trap 'rm -rf "$DIR_OLD" "$DIR_NEW"' EXIT

run_old_plotter "$DIR_OLD" 9 1 3
run_new_plotter_seeded "$DIR_NEW" 9 1 3 --double-buffer

OLD_FILE=$(find_plotfile "$DIR_OLD")
NEW_FILE=$(find_plotfile "$DIR_NEW")

if compare_files "$OLD_FILE" "$NEW_FILE"; then
    pass "Double-buffer — files are byte-identical"
else
    fail "Double-buffer — files differ"
    exit 1
fi
