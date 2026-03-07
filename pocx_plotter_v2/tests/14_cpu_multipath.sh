#!/usr/bin/env bash
# 14_cpu_multipath.sh — CPU mode, 2 paths, X1, 2 warps each.
# Extract seeds from filenames, verify each against old plotter.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "=== Test 14: CPU multi-path (2 paths, X1, 2 warps) ==="

WARPS=2
COMPRESS=1
ESCALATE=1
THREADS="${CPU_THREADS:-0}"

DIR_A=$(make_temp_dir)
DIR_B=$(make_temp_dir)
DIR_VERIFY=$(make_temp_dir)
trap 'rm -rf "$DIR_A" "$DIR_B" "$DIR_VERIFY"' EXIT

run_new_plotter_cpu "$WARPS" 1 "$COMPRESS" "$ESCALATE" "$THREADS" -- "$DIR_A" "$DIR_B"

ALL_PASS=true

for DIR in "$DIR_A" "$DIR_B"; do
    FILE=$(find_plotfile "$DIR")
    if [ -z "$FILE" ]; then
        fail "CPU multi-path — no plotfile in $DIR"
        ALL_PASS=false
        continue
    fi

    SEED=$(extract_seed "$FILE")
    FILE_WARPS=$(extract_warps "$FILE")

    echo "  Verifying: $(basename "$FILE") (seed=$SEED, warps=$FILE_WARPS)"

    VERIFY_DIR=$(mktemp -d -p "$DIR_VERIFY")
    "$OLD_BIN" \
        --id "$ADDR" --seed "$SEED" \
        --warps "$FILE_WARPS" --num 1 \
        --path "$VERIFY_DIR" \
        --compression "$COMPRESS" --escalate "$ESCALATE" \
        --gpu "$GPU" --ddio

    VERIFY_FILE=$(find_plotfile "$VERIFY_DIR")
    if compare_files "$FILE" "$VERIFY_FILE"; then
        echo "    OK"
    else
        fail "CPU multi-path — $(basename "$FILE") differs from reference"
        ALL_PASS=false
    fi
done

if $ALL_PASS; then
    pass "CPU multi-path — all files verified"
else
    exit 1
fi
