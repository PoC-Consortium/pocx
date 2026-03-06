#!/usr/bin/env bash
# lib.sh — Shared helpers for GPU plotter integration tests.
set -euo pipefail

ADDR="tpocx1qj0hnnyffma7tru28dlj92efhujs6y24l847ccp"
FIXED_SEED="AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE"
GPU="${GPU:-0:0:0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR/../.."

OLD_BIN="$REPO_ROOT/target/release/pocx_plotter"
NEW_BIN="$REPO_ROOT/target/release/pocx_gpu_plotter"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) OLD_BIN="${OLD_BIN}.exe"; NEW_BIN="${NEW_BIN}.exe" ;;
esac

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Build both plotters (called once by run_all.sh)
build_plotters() {
    echo "--- Building plotters (release) ---"
    cargo build --release -p pocx_plotter -p pocx_gpu_plotter \
        --manifest-path "$REPO_ROOT/Cargo.toml" 2>&1 | tail -3
    for bin in "$OLD_BIN" "$NEW_BIN"; do
        if [ ! -f "$bin" ]; then
            echo "ERROR: Binary not found: $bin"
            exit 1
        fi
    done
    echo ""
}

# Create a temp directory that is cleaned up on exit.
# Usage: DIR=$(make_temp_dir)
make_temp_dir() {
    mktemp -d
}

# Run old plotter with given args (single path, deterministic seed).
# run_old_plotter <output_dir> <warps> <compress> <escalate> [extra_args...]
run_old_plotter() {
    local dir="$1" warps="$2" compress="$3" escalate="$4"
    shift 4
    "$OLD_BIN" \
        --id "$ADDR" --seed "$FIXED_SEED" \
        --warps "$warps" --num 1 \
        --path "$dir" \
        --compression "$compress" --escalate "$escalate" \
        --gpu "$GPU" --ddio "$@"
}

# Run new GPU plotter with given args.
# run_new_plotter <warps> <num> <compress> <escalate> [extra_args...] -- <paths...>
# Paths come after "--".
run_new_plotter() {
    local warps="$1" num="$2" compress="$3" escalate="$4"
    shift 4

    local extra_args=()
    local paths=()
    local past_separator=false
    for arg in "$@"; do
        if [ "$arg" = "--" ]; then
            past_separator=true
            continue
        fi
        if $past_separator; then
            paths+=("$arg")
        else
            extra_args+=("$arg")
        fi
    done

    local path_args=()
    for p in "${paths[@]}"; do
        path_args+=(--path "$p")
    done

    "$NEW_BIN" \
        --id "$ADDR" \
        --warps "$warps" --num "$num" \
        --compression "$compress" --escalate "$escalate" \
        --gpu "$GPU" --ddio \
        "${extra_args[@]}" \
        "${path_args[@]}"
}

# Run new GPU plotter with a fixed seed (single path only).
# run_new_plotter_seeded <output_dir> <warps> <compress> <escalate> [extra_args...]
run_new_plotter_seeded() {
    local dir="$1" warps="$2" compress="$3" escalate="$4"
    shift 4
    run_new_plotter "$warps" 1 "$compress" "$escalate" \
        --seed "$FIXED_SEED" "$@" -- "$dir"
}

# Find the first plotfile (.pocx or .tmp) in a directory.
find_plotfile() {
    find "$1" -maxdepth 1 \( -name '*.pocx' -o -name '*.tmp' \) | head -1
}

# Find all plotfiles in a directory.
find_all_plotfiles() {
    find "$1" -maxdepth 1 \( -name '*.pocx' -o -name '*.tmp' \) | sort
}

# Extract seed hex from a plotfile name (2nd underscore-delimited field).
# Filename format: {addr_hex}_{seed_hex}_{warps}_X{compress}.pocx
extract_seed() {
    local fname
    fname=$(basename "$1")
    echo "$fname" | cut -d'_' -f2
}

# Extract warps from a plotfile name (3rd field).
extract_warps() {
    local fname
    fname=$(basename "$1")
    echo "$fname" | cut -d'_' -f3
}

# Compare two files byte-for-byte. Returns 0 on match, 1 on mismatch.
# On mismatch, prints diagnostic info.
compare_files() {
    local file_a="$1" file_b="$2"
    local size_a size_b

    size_a=$(wc -c < "$file_a" | tr -d ' ')
    size_b=$(wc -c < "$file_b" | tr -d ' ')

    if [ "$size_a" != "$size_b" ]; then
        echo "  Size mismatch: $size_a vs $size_b"
        return 1
    fi

    if cmp -s "$file_a" "$file_b"; then
        return 0
    else
        local diff_info
        diff_info=$(cmp "$file_a" "$file_b" 2>&1 | head -1)
        echo "  First difference: $diff_info"
        local diff_byte
        diff_byte=$(echo "$diff_info" | grep -oP 'byte \K[0-9]+' || echo "")
        if [ -n "$diff_byte" ]; then
            local offset=$((diff_byte - 16))
            [ "$offset" -lt 0 ] && offset=0
            echo "  File A hex at offset $offset:"
            od -A x -t x1 -j "$offset" -N 64 "$file_a" | head -3
            echo "  File B hex at offset $offset:"
            od -A x -t x1 -j "$offset" -N 64 "$file_b" | head -3
        fi
        return 1
    fi
}

# Report a test result.
pass() {
    echo "  PASS: $1"
    ((PASS_COUNT++)) || true
}

fail() {
    echo "  FAIL: $1"
    ((FAIL_COUNT++)) || true
}

skip() {
    echo "  SKIP: $1"
    ((SKIP_COUNT++)) || true
}

print_summary() {
    echo ""
    echo "============================================"
    echo "  Test Summary"
    echo "============================================"
    echo "  Passed : $PASS_COUNT"
    echo "  Failed : $FAIL_COUNT"
    echo "  Skipped: $SKIP_COUNT"
    echo "============================================"
    if [ "$FAIL_COUNT" -gt 0 ]; then
        echo "  SOME TESTS FAILED"
        return 1
    else
        echo "  ALL TESTS PASSED"
        return 0
    fi
}
