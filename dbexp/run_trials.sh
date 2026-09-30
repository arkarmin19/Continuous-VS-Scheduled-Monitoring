#!/usr/bin/env bash
set -euo pipefail

if [ ! -f /opt/dbexp/lab.env ]; then
    echo "ERROR: /opt/dbexp/lab.env not found. Fix that first (see setup_vm.sh output)." >&2
    exit 1
fi
source /opt/dbexp/lab.env
cd /opt/dbexp
PY=/opt/dbexp/venv/bin/python

# Sanity check: verify site reachability before starting 2-hour execution
if ! curl -sf -o /dev/null --max-time 5 "$WP_URL"; then
    echo "ERROR: $WP_URL is not reachable. Check Apache/networking before running trials." >&2
    exit 1
fi

SEEDS=(101 102 103 104 105)
ALL_RUNS=()
DET=""

cleanup() {
    if [ -n "$DET" ] && kill -0 "$DET" 2>/dev/null; then
        echo "Cleaning up: stopping leftover detector (pid $DET)..."
        kill -INT "$DET" 2>/dev/null || true
        wait "$DET" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

stop_detector() {
    local pid=$1 label=$2
    kill -INT "$pid" 2>/dev/null || true
    local status=0
    wait "$pid" 2>/dev/null || status=$?
    if [ "$status" -ne 0 ]; then
        echo "WARNING: detector for $label exited with status $status (expected 0) - check its output/logs." >&2
    fi
}

for i in "${!SEEDS[@]}"; do
    idx=$((i + 1))
    seed=${SEEDS[$i]}

    CONT_ID="cont-$seed"
    SCHED_ID="sched-$seed"

    echo "=========================================="
    echo "Starting Trial $idx of ${#SEEDS[@]} (Seed: $seed)"
    echo "=========================================="

    # 1. Continuous Run
    echo "[Trial $idx] Running Continuous ($CONT_ID)..."
    $PY detector.py run --mode continuous --run-id "$CONT_ID" &
    DET=$!
    sleep 2
    $PY workload.py --run-id "$CONT_ID" --duration 600 --attacks 30 --seed "$seed"
    sleep 5
    stop_detector "$DET" "$CONT_ID"
    DET=""

    echo "Cooling down for 60s..."
    sleep 60

    # 2. Scheduled Run
    echo "[Trial $idx] Running Scheduled (60s) ($SCHED_ID)..."
    $PY detector.py run --mode scheduled --interval 60 --run-id "$SCHED_ID" &
    DET=$!
    sleep 2
    $PY workload.py --run-id "$SCHED_ID" --duration 600 --attacks 30 --seed "$seed"
    sleep 65
    stop_detector "$DET" "$SCHED_ID"
    DET=""

    ALL_RUNS+=("$CONT_ID" "$SCHED_ID")

    echo "Cooling down for 60s..."
    sleep 60
done

echo "=========================================="
echo "All trials complete. Compiling final results..."
echo "=========================================="
$PY evaluate.py "${ALL_RUNS[@]}" --csv final_results.csv
