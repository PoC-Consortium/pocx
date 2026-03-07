#!/usr/bin/env bash
# 08_multipath_x2_e2.sh — 2 output paths, X2, 4 warps, escalation=2.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "=== Test 08: Multi-path + X2 + e=2 (2 paths, 4 warps) ==="

WARPS=4
COMPRESS=2
ESCALATE=2

DIR_A=$(make_temp_dir)
DIR_B=$(make_temp_dir)
DIR_VERIFY=$(make_temp_dir)
trap 'rm -rf "$DIR_A" "$DIR_B" "$DIR_VERIFY"' EXIT

run_new_plotter "$WARPS" 1 "$COMPRESS" "$ESCALATE" -- "$DIR_A" "$DIR_B"

ALL_PASS=true

for DIR in "$DIR_A" "$DIR_B"; do
    FILE=$(find_plotfile "$DIR")
    if [ -z "$FILE" ]; then
        fail "Multi-path X2 e=2 — no plotfile in $DIR"
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
        fail "Multi-path X2 e=2 — $(basename "$FILE") differs from reference"
        ALL_PASS=false
    fi
done

if $ALL_PASS; then
    pass "Multi-path X2 e=2 — all files verified against old plotter"
else
    exit 1
fi
