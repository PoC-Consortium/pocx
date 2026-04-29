#!/usr/bin/env bash
# repro.sh — Issue #48 regression test.
#
# Reproduces the "resume marker reports file 100% complete" panic/hang
# (https://github.com/PoC-Consortium/pocx/issues/48) and verifies the fix.
#
# Test matrix:
#   3 scenarios × 2 compute modes (cpu, gpu) × 2 binaries (old, new) = 12 runs.
#
# Scenarios:
#   1. v1-single   : pocx_plotter, single -p path, marker-full .tmp
#   2. v2-single   : pocx_plotter_v2, single -p path, marker-full .tmp
#   3. v2-partial  : pocx_plotter_v2, two -p paths — path A is marker-full,
#                    path B is fresh (no file). Exercises the partial-completion
#                    case where total_warps != 0 but one path is already done.
#
# Per run, "OLD" binary should FAIL (panic on CPU, hang on GPU — capped at 60s
# via `timeout`). "NEW" binary should PASS (exit 0 with .pocx artefacts present).
#
# Required: pocx_plotter_old.exe and pocx_plotter_v2_old.exe (master snapshots)
# alongside pocx_plotter.exe and pocx_plotter_v2.exe (post-fix) in target/release/.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

ADDR="tpocx1qj0hnnyffma7tru28dlj92efhujs6y24l847ccp"
SEED_A="AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE"
SEED_B="BEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEF"
WARPS=1
COMPRESS=1
GPU="0:0:0"  # v1 requires 3-part platform:device:cores; v2 accepts both forms
CPU_THREADS=32
HANG_TIMEOUT=120

V1_OLD="target/release/pocx_plotter_old.exe"
V1_NEW="target/release/pocx_plotter.exe"
V2_OLD="target/release/pocx_plotter_v2_old.exe"
V2_NEW="target/release/pocx_plotter_v2.exe"

# Verify all four binaries are present.
for bin in "$V1_OLD" "$V1_NEW" "$V2_OLD" "$V2_NEW"; do
    if [ ! -x "$bin" ]; then
        echo "ERROR: missing binary $bin"
        echo "  build the OLD pair on master, save as *_old.exe, then build the NEW pair after the fix."
        exit 2
    fi
done

# Plot a fresh 1-warp .pocx file using the binary, then rename it back to .tmp
# to simulate the kill-window state.
prepare_marker_full() {
    local plotter="$1"
    local dir="$2"
    local seed="$3"
    "$plotter" \
        --id "$ADDR" \
        --warps "$WARPS" \
        --num 1 \
        --compression "$COMPRESS" \
        --seed "$seed" \
        --path "$dir" \
        --cpu "$CPU_THREADS" \
        > "$dir/setup.log" 2>&1
    local pocx
    pocx=$(ls "$dir"/*.pocx 2>/dev/null | head -1)
    if [ -z "$pocx" ]; then
        echo "    setup failed: no .pocx produced (see $dir/setup.log)"
        return 1
    fi
    mv "$pocx" "${pocx%.pocx}.tmp"
}

# Build mode flag.
mode_flag() {
    case "$1" in
        cpu) echo "--cpu $CPU_THREADS" ;;
        gpu) echo "--gpu $GPU" ;;
    esac
}

# Run a binary under test with a hang-timeout. Returns the exit code.
run_under_test() {
    local timeout_secs="$1"
    shift
    timeout --preserve-status "${timeout_secs}s" "$@"
}

# Scenario 1 / 2: single-path resume of marker-full .tmp.
test_single_path() {
    local label="$1"
    local plotter="$2"
    local mode="$3"
    local setup_plotter="$4"
    local dir
    dir=$(mktemp -d)
    trap "rm -rf '$dir'" RETURN

    if ! prepare_marker_full "$setup_plotter" "$dir" "$SEED_A" 2>&1 ; then
        echo "[$label/$mode] SETUP-FAIL"
        return 2
    fi

    local flag
    flag=$(mode_flag "$mode")
    # shellcheck disable=SC2086
    run_under_test "$HANG_TIMEOUT" "$plotter" \
        --id "$ADDR" \
        --warps "$WARPS" \
        --num 1 \
        --compression "$COMPRESS" \
        --seed "$SEED_A" \
        --path "$dir" \
        $flag \
        > "$dir/run.log" 2>&1
    local rc=$?

    local pocx
    pocx=$(ls "$dir"/*.pocx 2>/dev/null | head -1)

    echo "$rc|$([ -n "$pocx" ] && echo pocx || echo no-pocx)"
}

# Scenario 3: two paths — path A marker-full, path B fresh (no file).
test_v2_partial() {
    local label="$1"
    local plotter="$2"
    local mode="$3"
    local dir_a dir_b
    dir_a=$(mktemp -d)
    dir_b=$(mktemp -d)
    trap "rm -rf '$dir_a' '$dir_b'" RETURN

    if ! prepare_marker_full "$V2_NEW" "$dir_a" "$SEED_A" 2>&1 ; then
        echo "[$label/$mode] SETUP-FAIL"
        return 2
    fi
    # dir_b stays empty — the plotter must preallocate from scratch.

    local flag
    flag=$(mode_flag "$mode")
    # shellcheck disable=SC2086
    run_under_test "$HANG_TIMEOUT" "$plotter" \
        --id "$ADDR" \
        --warps "$WARPS" \
        --num 1 \
        --compression "$COMPRESS" \
        --seed "$SEED_A" \
        --seed "$SEED_B" \
        --path "$dir_a" \
        --path "$dir_b" \
        $flag \
        > "$dir_a/run.log" 2>&1
    local rc=$?

    local pocx_a pocx_b
    pocx_a=$(ls "$dir_a"/*.pocx 2>/dev/null | head -1)
    pocx_b=$(ls "$dir_b"/*.pocx 2>/dev/null | head -1)

    local artefacts="A=$([ -n "$pocx_a" ] && echo pocx || echo no),B=$([ -n "$pocx_b" ] && echo pocx || echo no)"
    echo "$rc|$artefacts"
}

# Driver: run the matrix and emit a summary table.
declare -A RESULTS

run_cell() {
    local key="$1"
    local result="$2"
    local rc="${result%%|*}"
    local artefacts="${result##*|}"

    local should_pass="$3"
    local pass_marker="✓"
    local fail_marker="✗"

    local outcome
    if [ "$should_pass" = "yes" ]; then
        if [ "$rc" -eq 0 ] && [[ "$artefacts" != *"no-pocx"* ]] && [[ "$artefacts" != *"B=no"* ]]; then
            outcome="PASS$pass_marker (rc=$rc, $artefacts)"
        else
            outcome="UNEXPECTED-FAIL$fail_marker (rc=$rc, $artefacts)"
        fi
    else
        if [ "$rc" -ne 0 ]; then
            outcome="FAIL$pass_marker [as expected] (rc=$rc, $artefacts)"
        else
            outcome="UNEXPECTED-PASS$fail_marker (rc=$rc, $artefacts)"
        fi
    fi
    RESULTS[$key]="$outcome"
}

echo "=================================================="
echo " Issue #48 regression: 12 runs (3 × 2 × 2)"
echo "=================================================="

for scenario in v1-single v2-single v2-partial; do
    for binkind in old new; do
        for mode in cpu gpu; do
            case "$scenario:$binkind" in
                v1-single:old)   bin=$V1_OLD; setup=$V1_OLD ;;
                v1-single:new)   bin=$V1_NEW; setup=$V1_NEW ;;
                v2-single:old)   bin=$V2_OLD; setup=$V2_NEW ;; # setup with NEW so artefact is reliable
                v2-single:new)   bin=$V2_NEW; setup=$V2_NEW ;;
                v2-partial:old)  bin=$V2_OLD ;;
                v2-partial:new)  bin=$V2_NEW ;;
            esac
            label="$scenario/$binkind/$mode"
            echo "[run] $label"
            case "$scenario" in
                v1-single|v2-single)
                    res=$(test_single_path "$label" "$bin" "$mode" "$setup")
                    ;;
                v2-partial)
                    res=$(test_v2_partial "$label" "$bin" "$mode")
                    ;;
            esac
            should_pass="yes"
            [ "$binkind" = "old" ] && should_pass="no"
            run_cell "$label" "$res" "$should_pass"
            echo "        $res"
        done
    done
done

echo ""
echo "=================================================="
echo " Summary"
echo "=================================================="
printf "%-22s %-5s %-32s %-32s\n" "Scenario" "Mode" "OLD (expected: FAIL)" "NEW (expected: PASS)"
for scenario in v1-single v2-single v2-partial; do
    for mode in cpu gpu; do
        old="${RESULTS[$scenario/old/$mode]:-skipped}"
        new="${RESULTS[$scenario/new/$mode]:-skipped}"
        printf "%-22s %-5s %-32s %-32s\n" "$scenario" "$mode" "$old" "$new"
    done
done

# Exit non-zero if any cell mismatched expectation.
fail=0
for k in "${!RESULTS[@]}"; do
    case "${RESULTS[$k]}" in
        UNEXPECTED-*) fail=1 ;;
    esac
done
exit $fail
