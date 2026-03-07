#!/usr/bin/env bash
# 07_multipath.sh — 2 output paths, X1, 4 warps each, e=1.
#
# Strategy: plot with new GPU plotter to 2 paths (random seeds).
# Then extract each file's seed from its filename and replot
# individually with the old plotter. Binary compare.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "=== Test 07: Multi-path (2 paths, X1, 4 warps, e=1) ==="

WARPS=4
COMPRESS=1
ESCALATE=1

DIR_A=$(make_temp_dir)
DIR_B=$(make_temp_dir)
DIR_VERIFY=$(make_temp_dir)
trap 'rm -rf "$DIR_A" "$DIR_B" "$DIR_VERIFY"' EXIT

# Plot to 2 paths with new GPU plotter (no seed — random per path)
run_new_plotter "$WARPS" 1 "$COMPRESS" "$ESCALATE" -- "$DIR_A" "$DIR_B"

ALL_PASS=true

for DIR in "$DIR_A" "$DIR_B"; do
    FILE=$(find_plotfile "$DIR")
    if [ -z "$FILE" ]; then
        fail "Multi-path — no plotfile in $DIR"
        ALL_PASS=false
        continue
    fi

    SEED=$(extract_seed "$FILE")
    FILE_WARPS=$(extract_warps "$FILE")

    echo "  Verifying: $(basename "$FILE") (seed=$SEED, warps=$FILE_WARPS)"

    # Replot with old plotter using extracted seed
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
        fail "Multi-path — $(basename "$FILE") differs from reference"
        ALL_PASS=false
    fi
done

if $ALL_PASS; then
    pass "Multi-path — all files verified against old plotter"
else
    exit 1
fi
