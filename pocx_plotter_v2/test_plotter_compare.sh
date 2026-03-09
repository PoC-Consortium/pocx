#!/usr/bin/env bash
# test_plotter_compare.sh — Plot with both plotters, then binary-compare output files.
#
# Usage: ./test_plotter_compare.sh [gpu_id] [compression] [warps] [escalate]
#   gpu_id:      OpenCL device spec (default: 0:0:0)
#   compression: compression level 1-6 (default: 1)
#   warps:       number of warps to plot (default: 9)
#   escalate:    write buffer size multiplier (default: 1)
set -euo pipefail

GPU="${1:-0:0:0}"
COMPRESS="${2:-1}"
WARPS="${3:-9}"
ESCALATE="${4:-1}"
SEED="AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE"
ADDR="tpocx1qj0hnnyffma7tru28dlj92efhujs6y24l847ccp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "============================================"
echo "  PoCX Plotter Comparison Test"
echo "============================================"
echo "Address     : $ADDR"
echo "Seed        : $SEED"
echo "Compression : X$COMPRESS"
echo "Warps       : $WARPS"
echo "Escalation  : $ESCALATE"
echo "GPU         : $GPU"
echo ""

# Create temp directories for output
DIR_OLD=$(mktemp -d)
DIR_NEW=$(mktemp -d)
trap 'rm -rf "$DIR_OLD" "$DIR_NEW"' EXIT

echo "Old plotter dir: $DIR_OLD"
echo "New plotter dir: $DIR_NEW"
echo ""

# Build both plotters
echo "--- Building both plotters (release) ---"
cargo build --release -p pocx_plotter -p pocx_plotter_v2 2>&1 | tail -3
echo ""

OLD_BIN="target/release/pocx_plotter"
NEW_BIN="target/release/pocx_plotter_v2"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) OLD_BIN="${OLD_BIN}.exe"; NEW_BIN="${NEW_BIN}.exe" ;;
esac

for bin in "$OLD_BIN" "$NEW_BIN"; do
    if [ ! -f "$bin" ]; then
        echo "ERROR: Binary not found: $bin"
        exit 1
    fi
done

# --- Run old plotter ---
echo "--- Running OLD plotter (GPU, X$COMPRESS, $WARPS warps) ---"
OLD_START=$SECONDS
"$OLD_BIN" \
    --id "$ADDR" \
    --seed "$SEED" \
    --warps "$WARPS" \
    --num 1 \
    --path "$DIR_OLD" \
    --compression "$COMPRESS" \
    --escalate "$ESCALATE" \
    --gpu "$GPU" \
    --ddio
OLD_ELAPSED=$((SECONDS - OLD_START))
echo "Old plotter finished in ${OLD_ELAPSED}s"
echo ""

# --- Run new GPU plotter ---
echo "--- Running NEW GPU plotter (ring buffer, X$COMPRESS, $WARPS warps, -e $ESCALATE) ---"
NEW_START=$SECONDS
"$NEW_BIN" \
    --id "$ADDR" \
    --seed "$SEED" \
    --warps "$WARPS" \
    --num 1 \
    --path "$DIR_NEW" \
    --compression "$COMPRESS" \
    --escalate "$ESCALATE" \
    --gpu "$GPU" \
    --ddio
NEW_ELAPSED=$((SECONDS - NEW_START))
echo "New GPU plotter finished in ${NEW_ELAPSED}s"
echo ""

# --- Compare ---
echo "============================================"
echo "  Comparing output files"
echo "============================================"

OLD_FILE=$(find "$DIR_OLD" -maxdepth 1 \( -name '*.pocx' -o -name '*.tmp' \) | head -1)
NEW_FILE=$(find "$DIR_NEW" -maxdepth 1 \( -name '*.pocx' -o -name '*.tmp' \) | head -1)

if [ -z "$OLD_FILE" ]; then
    echo "ERROR: No plotfile found in old plotter output dir"
    ls -la "$DIR_OLD"/
    exit 1
fi

if [ -z "$NEW_FILE" ]; then
    echo "ERROR: No plotfile found in new plotter output dir"
    ls -la "$DIR_NEW"/
    exit 1
fi

OLD_SIZE=$(wc -c < "$OLD_FILE" | tr -d ' ')
NEW_SIZE=$(wc -c < "$NEW_FILE" | tr -d ' ')

echo "Old file: $(basename "$OLD_FILE") ($OLD_SIZE bytes)"
echo "New file: $(basename "$NEW_FILE") ($NEW_SIZE bytes)"

if [ "$OLD_SIZE" != "$NEW_SIZE" ]; then
    echo ""
    echo "FAIL: File sizes differ! Old=$OLD_SIZE New=$NEW_SIZE"
    exit 1
fi

if cmp -s "$OLD_FILE" "$NEW_FILE"; then
    echo ""
    echo "============================================"
    echo "  PASS: Files are byte-identical!"
    echo "  X$COMPRESS, $WARPS warps, $OLD_SIZE bytes verified."
    echo "  Old plotter: ${OLD_ELAPSED}s"
    echo "  New plotter: ${NEW_ELAPSED}s"
    echo "============================================"
    exit 0
else
    echo ""
    echo "FAIL: Files differ!"
    DIFF_INFO=$(cmp "$OLD_FILE" "$NEW_FILE" 2>&1 | head -1)
    echo "First difference: $DIFF_INFO"

    DIFF_BYTE=$(echo "$DIFF_INFO" | grep -oP 'byte \K[0-9]+' || echo "")
    if [ -n "$DIFF_BYTE" ]; then
        OFFSET=$((DIFF_BYTE - 16))
        [ "$OFFSET" -lt 0 ] && OFFSET=0
        echo ""
        echo "Old file hex at offset $OFFSET:"
        od -A x -t x1 -j "$OFFSET" -N 64 "$OLD_FILE" | head -5
        echo "New file hex at offset $OFFSET:"
        od -A x -t x1 -j "$OFFSET" -N 64 "$NEW_FILE" | head -5
    fi
    exit 1
fi
