#!/usr/bin/env python3
"""Compute security + performance metrics for one or more runs.

  python evaluate.py c1 s1 --csv results.csv

Security (request level): a request is a positive if its X-Exp-Label starts with "attack",
a negative if it is "benign"/empty, and ignored if "ignore". A request counts as detected
if the detector raised at least one alert on any of its queries.

Detection delay = ts_alert - ts_event of the first alerting query of the request.
Performance: HTTP latency/throughput/errors from workload.py (benign requests only for
latency), detector CPU time, and system CPU/memory samples.
"""
import argparse
import csv
import math
import statistics
from collections import defaultdict

from common import DB_PATH, Store


def pct(xs, p):
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100
    f, c = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def klass(label):
    label = label or ""
    if label.startswith("attack"):
        return "attack"
    return "ignore" if label == "ignore" else "benign"


def safe_div(a, b):
    return a / b if b else float("nan")


def evaluate(db, run_id):
    run = db.execute("SELECT mode, interval_s, threshold, started, ended, events_scored, detector_cpu_s "
                     "FROM runs WHERE run_id=?", (run_id,)).fetchone()
    if not run:                                   # control run (no detector): HTTP metrics only
        ts = db.execute("SELECT MIN(ts), MAX(ts) FROM http_requests WHERE run_id=?", (run_id,)).fetchone()
        if ts[0] is None:
            raise SystemExit(f"unknown run {run_id}")
        run = ("control", 0.0, float("nan"), ts[0], ts[1], None, None)
    mode, interval, thr, started, ended, n_ev, cpu_s = run
    wall = (ended or started) - started

    # ---- request-level detection ----
    reqs = {}
    for eid, req, label in db.execute("SELECT id, req_id, label FROM events WHERE run_id=?", (run_id,)):
        reqs.setdefault(req or f"e{eid}", {"label": label, "delays": []})
    for req, ts_e, ts_a in db.execute("SELECT req_id, ts_event, ts_alert FROM alerts WHERE run_id=?", (run_id,)):
        if req in reqs:
            reqs[req]["delays"].append(ts_a - ts_e)

    tp = fp = fn = tn = 0
    delays = []
    per_label = defaultdict(lambda: [0, 0])          # label -> [detected, total]
    for r in reqs.values():
        k, hit = klass(r["label"]), bool(r["delays"])
        if k == "ignore":
            continue
        if k == "attack":
            per_label[r["label"]][1] += 1
            if hit:
                tp += 1
                per_label[r["label"]][0] += 1
                delays.append(min(r["delays"]))
            else:
                fn += 1
        else:
            fp += hit
            tn += not hit
    precision, recall = safe_div(tp, tp + fp), safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall) if tp else 0.0

    # ---- HTTP performance ----
    rows = db.execute("SELECT ts, label, status, latency_ms FROM http_requests WHERE run_id=?", (run_id,)).fetchall()
    lat = [r[3] for r in rows if klass(r[1]) == "benign" and r[2] != 0]
    span = (max(r[0] for r in rows) - min(r[0] for r in rows)) if len(rows) > 1 else float("nan")
    errors = sum(1 for r in rows if r[2] == 0 or r[2] >= 500)

    perf = db.execute("SELECT AVG(sys_cpu_pct), MAX(sys_cpu_pct), AVG(sys_mem_pct), AVG(det_cpu_pct), "
                      "MAX(det_rss_mb) FROM perf WHERE run_id=?", (run_id,)).fetchone()
    batch = db.execute("SELECT AVG(score_seconds), MAX(score_seconds) FROM batches WHERE run_id=?",
                       (run_id,)).fetchone()

    m = {
        "run_id": run_id, "mode": mode, "interval_s": interval, "threshold": thr,
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "fpr": safe_div(fp, fp + tn),
        "delay_mean_s": statistics.fmean(delays) if delays else float("nan"),
        "delay_p50_s": pct(delays, 50), "delay_p95_s": pct(delays, 95),
        "http_requests": len(rows), "throughput_rps": safe_div(len(rows), span),
        "lat_mean_ms": statistics.fmean(lat) if lat else float("nan"),
        "lat_p50_ms": pct(lat, 50), "lat_p95_ms": pct(lat, 95), "lat_p99_ms": pct(lat, 99),
        "error_rate": safe_div(errors, len(rows)),
        "det_cpu_s": cpu_s or float("nan"), "det_cpu_pct_avg": safe_div((cpu_s or 0) * 100, wall),
        "det_rss_mb_max": perf[4] or float("nan"),
        "sys_cpu_avg": perf[0] or float("nan"), "sys_cpu_max": perf[1] or float("nan"),
        "sys_mem_avg": perf[2] or float("nan"),
        "batch_score_s_avg": batch[0] if batch[0] is not None else float("nan"),
        "events_scored": n_ev,
    }
    return m, dict(per_label)


def show(m, per_label):
    f = lambda v: "n/a" if isinstance(v, float) and math.isnan(v) else (f"{v:.3f}" if isinstance(v, float) else str(v))
    print(f"\n=== {m['run_id']}  mode={m['mode']}  interval={m['interval_s']}s  threshold={m['threshold']} ===")
    print(f"  detection : TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']}  "
          f"precision={f(m['precision'])} recall={f(m['recall'])} F1={f(m['f1'])} FPR={f(m['fpr'])}")
    for lbl, (d, t) in sorted(per_label.items()):
        print(f"      {lbl:<22} {d}/{t} detected")
    print(f"  delay (s) : mean={f(m['delay_mean_s'])} p50={f(m['delay_p50_s'])} p95={f(m['delay_p95_s'])}")
    print(f"  HTTP      : {m['http_requests']} req, {f(m['throughput_rps'])} req/s, error rate={f(m['error_rate'])}")
    print(f"  latency ms: mean={f(m['lat_mean_ms'])} p50={f(m['lat_p50_ms'])} p95={f(m['lat_p95_ms'])} p99={f(m['lat_p99_ms'])}")
    print(f"  detector  : cpu={f(m['det_cpu_s'])}s ({f(m['det_cpu_pct_avg'])}% avg)  rss max={f(m['det_rss_mb_max'])} MB  "
          f"batch avg={f(m['batch_score_s_avg'])}s")
    print(f"  system    : cpu avg={f(m['sys_cpu_avg'])}% max={f(m['sys_cpu_max'])}%  mem avg={f(m['sys_mem_avg'])}%")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_ids", nargs="+")
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--csv", help="write one summary row per run to this file")
    a = ap.parse_args()

    db = Store(a.db).db
    summaries = []
    for rid in a.run_ids:
        m, per_label = evaluate(db, rid)
        show(m, per_label)
        summaries.append(m)
    if a.csv:
        with open(a.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(summaries[0].keys()))
            w.writeheader()
            w.writerows(summaries)
        print(f"\nwrote {a.csv}")


if __name__ == "__main__":
    main()
