#!/usr/bin/env bash
# 09_multifile.sh — Single path, 2 files (num=2), X1, 2 warps each.
#
# Verifies that multiple files per path are generated correctly.
# Each file gets a random seed; we extract and verify individually.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "=== Test 09: Multi-file (num=2, X1, 2 warps, e=1) ==="

WARPS=2
NUM=2
COMPRESS=1
ESCALATE=1

DIR_NEW=$(make_temp_dir)
DIR_VERIFY=$(make_temp_dir)
trap 'rm -rf "$DIR_NEW" "$DIR_VERIFY"' EXIT

run_new_plotter "$WARPS" "$NUM" "$COMPRESS" "$ESCALATE" -- "$DIR_NEW"

FILES=()
while IFS= read -r f; do
    FILES+=("$f")
done < <(find_all_plotfiles "$DIR_NEW")

if [ "${#FILES[@]}" -ne "$NUM" ]; then
    fail "Multi-file — expected $NUM files, found ${#FILES[@]}"
    ls -la "$DIR_NEW"/
    exit 1
fi

ALL_PASS=true

for FILE in "${FILES[@]}"; do
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
        fail "Multi-file — $(basename "$FILE") differs from reference"
        ALL_PASS=false
    fi
done

if $ALL_PASS; then
    pass "Multi-file — all $NUM files verified against old plotter"
else
    exit 1
fi
