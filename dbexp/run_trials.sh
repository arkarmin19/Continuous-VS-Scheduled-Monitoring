#!/usr/bin/env bash
# Run the full experiment: continuous vs scheduled (several intervals) + two controls,
# repeated TRIALS times, with the condition order RANDOMISED inside every trial.
#
# Every condition in one trial uses the same workload seed (paired design), so they all
# see the same request mix. The order is shuffled with that seed, so it is reproducible.
#
# Settings (environment variables, all optional):
#   TRIALS=5                 number of repetitions of every condition
#   INTERVALS="10 60 300"    scheduled-mode intervals in seconds
#   DURATION=600             workload length per run (s). Keep >= 2x the largest interval.
#   ATTACKS=30               attack episodes per run (split evenly: classic / evasive / phish)
#   COOLDOWN=60              pause between runs (s)
#   CONTROLS=1               1 = include logonly + none control runs, 0 = skip them
#   TRAIN=1                  1 = retrain the baseline first (needed after the REST fix), 0 = reuse it
#   TAG=<yyyymmdd-hhmm>      prefix for run ids, so new runs never clash with old ones
#
# Example:  TRIALS=10 INTERVALS="10 60 300" bash run_trials.sh
set -euo pipefail

TRIALS=${TRIALS:-5}
INTERVALS=${INTERVALS:-"10 60 300"}
DURATION=${DURATION:-600}
ATTACKS=${ATTACKS:-30}
COOLDOWN=${COOLDOWN:-60}
CONTROLS=${CONTROLS:-1}
TRAIN=${TRAIN:-1}
TAG=${TAG:-$(date +%Y%m%d-%H%M)}
FIRST_SEED=101

if [ ! -f /opt/dbexp/lab.env ]; then
    echo "ERROR: /opt/dbexp/lab.env not found. Fix that first (see setup_vm.sh output)." >&2
    exit 1
fi
source /opt/dbexp/lab.env
cd /opt/dbexp
PY=/opt/dbexp/venv/bin/python
OUT_DIR=/opt/dbexp/results/$TAG
mkdir -p "$OUT_DIR"
ORDER_LOG=$OUT_DIR/run_order.csv
echo "trial,position,seed,condition,run_id,started_utc" > "$ORDER_LOG"

# ---------------------------------------------------------------- sanity checks
for iv in $INTERVALS; do
    if [ $((iv * 2)) -gt "$DURATION" ]; then
        echo "ERROR: interval ${iv}s is more than half of DURATION=${DURATION}s - too few batches per run." >&2
        echo "       Raise DURATION or drop that interval." >&2
        exit 1
    fi
done
if ! curl -sf -o /dev/null --max-time 5 "$WP_URL"; then
    echo "ERROR: $WP_URL is not reachable. Check Apache/networking before running trials." >&2
    exit 1
fi
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
       -u "$WP_ADMIN_USER:$WP_ADMIN_APP_PW" "$WP_URL/?rest_route=/wp/v2/users/me")
if [ "$code" != "200" ]; then
    echo "ERROR: authenticated REST API check returned HTTP $code (expected 200)." >&2
    echo "       401 = wrong WP_ADMIN_APP_PW in lab.env; 404 = REST API not reachable." >&2
    exit 1
fi
rm -f /var/lib/dbexp/LOGGER_OFF       # never start with logging disabled by an aborted run

# ---------------------------------------------------------------- helpers
DET=""
cleanup() {
    if [ -n "$DET" ] && kill -0 "$DET" 2>/dev/null; then
        echo "Cleaning up: stopping leftover detector (pid $DET)..."
        kill -INT "$DET" 2>/dev/null || true
        wait "$DET" 2>/dev/null || true
    fi
    rm -f /var/lib/dbexp/LOGGER_OFF
}
trap cleanup EXIT INT TERM

stop_detector() {
    local pid=$1 label=$2 status=0
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || status=$?
    if [ "$status" -ne 0 ]; then
        echo "WARNING: detector for $label exited with status $status (expected 0) - check $OUT_DIR/$label.det.log" >&2
    fi
}

workload() {   # workload <run_id> <seed>
    $PY workload.py --run-id "$1" --duration "$DURATION" --attacks "$ATTACKS" --seed "$2" \
        2>&1 | tee "$OUT_DIR/$1.workload.log"
}

run_condition() {   # run_condition <condition> <run_id> <seed>
    local cond=$1 rid=$2 seed=$3
    case "$cond" in
        cont)
            $PY detector.py run --mode continuous --run-id "$rid" > "$OUT_DIR/$rid.det.log" 2>&1 &
            DET=$!; sleep 2
            workload "$rid" "$seed"
            sleep 5
            stop_detector "$DET" "$rid"; DET="" ;;
        sched-*)
            local iv=${cond#sched-}
            $PY detector.py run --mode scheduled --interval "$iv" --run-id "$rid" > "$OUT_DIR/$rid.det.log" 2>&1 &
            DET=$!; sleep 2
            workload "$rid" "$seed"
            sleep $((iv + 5))                      # let the last scheduled batch run
            stop_detector "$DET" "$rid"; DET="" ;;
        logonly)                                   # logger on, no detector
            workload "$rid" "$seed" ;;
        none)                                      # no logger, no detector
            touch /var/lib/dbexp/LOGGER_OFF
            workload "$rid" "$seed"
            rm -f /var/lib/dbexp/LOGGER_OFF ;;
    esac
}

# ---------------------------------------------------------------- baseline
if [ "$TRAIN" = "1" ]; then
    echo "=========================================="
    echo "Retraining baseline on benign-only traffic (${DURATION}s)"
    echo "=========================================="
    sudo truncate -s0 /var/log/dbexp/events.jsonl
    $PY workload.py --run-id "$TAG-train" --duration "$DURATION" --attacks 0 --seed 1
    $PY detector.py train | tee "$OUT_DIR/baseline.log"
    sleep "$COOLDOWN"
fi

# ---------------------------------------------------------------- trials
CONDITIONS=(cont)
for iv in $INTERVALS; do CONDITIONS+=("sched-$iv"); done
if [ "$CONTROLS" = "1" ]; then CONDITIONS+=(logonly none); fi

N_RUNS=$(( TRIALS * ${#CONDITIONS[@]} ))
echo "Plan: $TRIALS trials x ${#CONDITIONS[@]} conditions (${CONDITIONS[*]}) = $N_RUNS runs,"
echo "      about $(( N_RUNS * (DURATION + COOLDOWN + 20) / 3600 + 1 )) hours. Results -> $OUT_DIR"

ALL_RUNS=()
run_no=0
for ((t = 1; t <= TRIALS; t++)); do
    seed=$(( FIRST_SEED + t - 1 ))
    # reproducible shuffle: the same seed always gives the same order
    mapfile -t ORDER < <(printf '%s\n' "${CONDITIONS[@]}" | \
        shuf --random-source=<(openssl enc -aes-256-ctr -pass pass:"$seed" -nosalt </dev/zero 2>/dev/null))

    echo "=========================================="
    echo "Trial $t/$TRIALS (seed $seed) order: ${ORDER[*]}"
    echo "=========================================="
    pos=0
    for cond in "${ORDER[@]}"; do
        pos=$((pos + 1)); run_no=$((run_no + 1))
        rid="$TAG-$cond-s$seed"
        echo "[run $run_no/$N_RUNS] $rid"
        echo "$t,$pos,$seed,$cond,$rid,$(date -u +%FT%TZ)" >> "$ORDER_LOG"
        run_condition "$cond" "$rid" "$seed"
        ALL_RUNS+=("$rid")
        if [ "$run_no" -lt "$N_RUNS" ]; then
            echo "Cooling down for ${COOLDOWN}s..."; sleep "$COOLDOWN"
        fi
    done
done

echo "=========================================="
echo "All trials complete. Compiling results..."
echo "=========================================="
$PY evaluate.py "${ALL_RUNS[@]}" --csv "$OUT_DIR/final_results.csv" | tee "$OUT_DIR/evaluate.log"
cp "$OUT_DIR/final_results.csv" /opt/dbexp/final_results.csv
echo
echo "Results : $OUT_DIR/final_results.csv  (also copied to /opt/dbexp/final_results.csv)"
echo "Order   : $ORDER_LOG"
if grep -q ",no," "$OUT_DIR/final_results.csv"; then
    echo "WARNING : some runs are marked valid=no - see the 'warnings' column / evaluate.log." >&2
fi
