#!/usr/bin/env bash
# 10_multipath_multifile.sh — 2 paths, 2 files each (num=2), X1, 2 warps, e=1.
#
# The full combination: buffer-level interleaving across paths,
# multiple files per path with seed rotation.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "=== Test 10: Multi-path + multi-file (2 paths, num=2, X1, 2 warps) ==="

WARPS=2
NUM=2
COMPRESS=1
ESCALATE=1

DIR_A=$(make_temp_dir)
DIR_B=$(make_temp_dir)
DIR_VERIFY=$(make_temp_dir)
trap 'rm -rf "$DIR_A" "$DIR_B" "$DIR_VERIFY"' EXIT

run_new_plotter "$WARPS" "$NUM" "$COMPRESS" "$ESCALATE" -- "$DIR_A" "$DIR_B"

ALL_PASS=true

for DIR in "$DIR_A" "$DIR_B"; do
    FILES=()
    while IFS= read -r f; do
        FILES+=("$f")
    done < <(find_all_plotfiles "$DIR")

    if [ "${#FILES[@]}" -ne "$NUM" ]; then
        fail "Multi-path+file — expected $NUM files in $DIR, found ${#FILES[@]}"
        ls -la "$DIR"/
        ALL_PASS=false
        continue
    fi

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
            fail "Multi-path+file — $(basename "$FILE") differs from reference"
            ALL_PASS=false
        fi
    done
done

if $ALL_PASS; then
    pass "Multi-path + multi-file — all files verified"
else
    exit 1
fi
