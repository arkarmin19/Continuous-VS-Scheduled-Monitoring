#!/usr/bin/env python3
"""Detector service.

  train : learn the baseline (query templates + length stats) from a benign-only log
  run   : score events from the logger's JSONL file
            --mode continuous : score every event the moment it appears (tail -f style)
            --mode scheduled  : score everything accumulated, every --interval seconds

Examples
  python detector.py train --log /var/log/dbexp/events.jsonl
  python detector.py run --mode continuous --run-id c1
  python detector.py run --mode scheduled  --run-id s1 --interval 60
"""
import argparse
import json
import os
import signal
import sys
import threading
import time

import psutil

from common import (BASELINE_PATH, DB_PATH, DEFAULT_THRESHOLD, LOG_PATH, Baseline, Store, analyze)


# --------------------------------------------------------------------------
# Log reader (the "ingest" half of the logger/interceptor role)
# --------------------------------------------------------------------------
class LogTail:
    def __init__(self, path, from_start=False):
        while not os.path.exists(path):          # logger creates the file on first web request
            time.sleep(0.5)
        self.f = open(path, "r", encoding="utf-8", errors="replace")
        if not from_start:
            self.f.seek(0, os.SEEK_END)
        self.partial = ""

    def read_lines(self):
        out = []
        while True:
            line = self.f.readline()
            if not line:
                break
            if not line.endswith("\n"):          # writer is mid-line; finish it next time
                self.partial += line
                break
            out.append(self.partial + line)
            self.partial = ""
        return out


# --------------------------------------------------------------------------
# Scoring engine (same code path for both modes)
# --------------------------------------------------------------------------
class Engine:
    def __init__(self, store, run_id, baseline, threshold):
        self.store, self.run_id, self.baseline, self.threshold = store, run_id, baseline, threshold
        self.n_events = 0
        self.n_alerts = 0

    def handle(self, line, commit):
        try:
            ev = json.loads(line)
        except ValueError:
            return
        risk, reasons = analyze(ev.get("sql", ""), int(ev.get("user_id", 0) or 0), self.baseline)
        now = time.time()
        eid = self.store.add_event(self.run_id, ev, risk, reasons, now)
        self.n_events += 1
        if risk >= self.threshold:
            self.store.add_alert(self.run_id, eid, ev, risk, reasons, now)
            self.n_alerts += 1
            print(f"[ALERT {risk:.2f}] req={ev.get('req_id')} uid={ev.get('user_id')} "
                  f"delay={now - ev.get('ts', now):.3f}s {','.join(reasons)} :: "
                  f"{(ev.get('sql') or '')[:100]!r}", flush=True)
        if commit:
            self.store.commit()


def run_continuous(engine, tail, stop, poll):
    while not stop.is_set():
        lines = tail.read_lines()
        if not lines:
            stop.wait(poll)
            continue
        for line in lines:
            engine.handle(line, commit=True)     # persist every event immediately


def run_scheduled(engine, tail, stop, interval):
    def batch():
        lines = tail.read_lines()
        t0 = time.time()
        for line in lines:
            engine.handle(line, commit=False)
        engine.store.commit()                    # one transaction per batch
        engine.store.add_batch(engine.run_id, t0, len(lines), time.time() - t0)
        print(f"[batch] {len(lines)} events scored in {time.time() - t0:.2f}s", flush=True)

    next_t = time.monotonic() + interval
    while not stop.wait(max(0.0, next_t - time.monotonic())):
        batch()
        next_t += interval
    batch()                                      # final flush on shutdown


def perf_sampler(db_path, run_id, stop, every=5.0):
    store, proc = Store(db_path), psutil.Process()
    psutil.cpu_percent(None)
    proc.cpu_percent(None)
    while not stop.wait(every):
        store.add_perf(run_id, time.time(), psutil.cpu_percent(None),
                       psutil.virtual_memory().percent, proc.cpu_percent(None),
                       proc.memory_info().rss / 1e6)


# --------------------------------------------------------------------------
def cmd_train(a):
    sqls = []
    with open(a.log, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if (ev.get("label") or "").startswith(("attack", "ignore")):
                continue                          # never train on labelled attack traffic
            sqls.append(ev.get("sql", ""))
    if not sqls:
        sys.exit("no events found in log")
    bl = Baseline.fit(sqls)
    bl.save(a.out)
    print(f"baseline: {bl.n} events, {len(bl.templates)} distinct templates -> {a.out}")


def cmd_run(a):
    baseline = Baseline.load(a.baseline)
    store = Store(a.db)
    store.start_run(a.run_id, a.mode, a.interval if a.mode == "scheduled" else 0.0,
                    a.threshold, a.notes)
    tail = LogTail(a.log)                         # start at end-of-file: only score new traffic
    engine = Engine(store, a.run_id, baseline, a.threshold)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    threading.Thread(target=perf_sampler, args=(a.db, a.run_id, stop), daemon=True).start()

    print(f"run={a.run_id} mode={a.mode} threshold={a.threshold} - Ctrl-C to stop", flush=True)
    if a.mode == "continuous":
        run_continuous(engine, tail, stop, a.poll)
        for line in tail.read_lines():            # drain anything written just before stop
            engine.handle(line, commit=False)
        store.commit()
    else:
        run_scheduled(engine, tail, stop, a.interval)

    cpu = psutil.Process().cpu_times()
    store.end_run(a.run_id, engine.n_events, cpu.user + cpu.system)
    print(f"done: {engine.n_events} events, {engine.n_alerts} alerts, cpu={cpu.user + cpu.system:.1f}s")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train")
    t.add_argument("--log", default=LOG_PATH)
    t.add_argument("--out", default=BASELINE_PATH)
    t.set_defaults(fn=cmd_train)

    r = sub.add_parser("run")
    r.add_argument("--mode", choices=["continuous", "scheduled"], required=True)
    r.add_argument("--run-id", required=True)
    r.add_argument("--interval", type=float, default=60.0, help="scheduled mode: seconds between batches")
    r.add_argument("--poll", type=float, default=0.05, help="continuous mode: idle poll seconds")
    r.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    r.add_argument("--log", default=LOG_PATH)
    r.add_argument("--db", default=DB_PATH)
    r.add_argument("--baseline", default=BASELINE_PATH)
    r.add_argument("--notes", default="")
    r.set_defaults(fn=cmd_run)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
