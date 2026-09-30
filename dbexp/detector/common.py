"""Shared pieces: config, SQLite storage, SQL feature extraction, risk scoring.

The scoring function is IDENTICAL for continuous and scheduled mode. The only
thing that differs between the two experimental conditions is *when* it runs.
"""
import json
import math
import os
import re
import sqlite3
import statistics
import time
from collections import Counter

DB_PATH = os.environ.get("DBEXP_DB", "/var/lib/dbexp/experiment.db")
LOG_PATH = os.environ.get("DBEXP_LOG", "/var/log/dbexp/events.jsonl")
BASELINE_PATH = os.environ.get("DBEXP_BASELINE", "/var/lib/dbexp/baseline.json")
DEFAULT_THRESHOLD = 0.80

# --------------------------------------------------------------------------
# Storage (SQLite, WAL mode so detector / workload / evaluator can share it)
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
  run_id TEXT PRIMARY KEY, mode TEXT, interval_s REAL, threshold REAL,
  started REAL, ended REAL, events_scored INTEGER, detector_cpu_s REAL, notes TEXT);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, req_id TEXT, seq INTEGER,
  ts REAL, scored_ts REAL, user_id INTEGER, ip TEXT, method TEXT, uri TEXT,
  label TEXT, sql TEXT, score REAL, reasons TEXT);
CREATE INDEX IF NOT EXISTS ix_events_run ON events(run_id, req_id);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, event_id INTEGER, req_id TEXT,
  ts_event REAL, ts_alert REAL, score REAL, reasons TEXT, label TEXT, sql TEXT);
CREATE INDEX IF NOT EXISTS ix_alerts_run ON alerts(run_id);
CREATE TABLE IF NOT EXISTS batches(
  run_id TEXT, started REAL, n_events INTEGER, score_seconds REAL);
CREATE TABLE IF NOT EXISTS perf(
  run_id TEXT, ts REAL, sys_cpu_pct REAL, sys_mem_pct REAL,
  det_cpu_pct REAL, det_rss_mb REAL);
CREATE TABLE IF NOT EXISTS http_requests(
  run_id TEXT, ts REAL, label TEXT, method TEXT, path TEXT,
  status INTEGER, latency_ms REAL, error TEXT);
"""


class Store:
    def __init__(self, path=DB_PATH):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, timeout=30)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)

    def commit(self):
        self.db.commit()

    def start_run(self, run_id, mode, interval_s, threshold, notes=""):
        if self.db.execute("SELECT 1 FROM runs WHERE run_id=?", (run_id,)).fetchone():
            raise SystemExit(f"run_id '{run_id}' already exists - pick a new one")
        self.db.execute(
            "INSERT INTO runs(run_id,mode,interval_s,threshold,started,notes) VALUES (?,?,?,?,?,?)",
            (run_id, mode, interval_s, threshold, time.time(), notes))
        self.db.commit()

    def end_run(self, run_id, events_scored, cpu_s):
        self.db.execute(
            "UPDATE runs SET ended=?, events_scored=?, detector_cpu_s=? WHERE run_id=?",
            (time.time(), events_scored, cpu_s, run_id))
        self.db.commit()

    def add_event(self, run_id, ev, score, reasons, scored_ts):
        cur = self.db.execute(
            "INSERT INTO events(run_id,req_id,seq,ts,scored_ts,user_id,ip,method,uri,label,sql,score,reasons)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, ev.get("req_id", ""), ev.get("seq", 0), ev.get("ts", 0.0), scored_ts,
             ev.get("user_id", 0), ev.get("ip", ""), ev.get("method", ""), ev.get("uri", ""),
             ev.get("label", ""), (ev.get("sql") or "")[:2000], score, ",".join(reasons)))
        return cur.lastrowid

    def add_alert(self, run_id, event_id, ev, score, reasons, ts_alert):
        self.db.execute(
            "INSERT INTO alerts(run_id,event_id,req_id,ts_event,ts_alert,score,reasons,label,sql)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (run_id, event_id, ev.get("req_id", ""), ev.get("ts", 0.0), ts_alert, score,
             ",".join(reasons), ev.get("label", ""), (ev.get("sql") or "")[:500]))

    def add_batch(self, run_id, started, n, seconds):
        self.db.execute("INSERT INTO batches VALUES (?,?,?,?)", (run_id, started, n, seconds))
        self.db.commit()

    def add_perf(self, run_id, ts, sys_cpu, sys_mem, det_cpu, det_rss):
        self.db.execute("INSERT INTO perf VALUES (?,?,?,?,?,?)",
                        (run_id, ts, sys_cpu, sys_mem, det_cpu, det_rss))
        self.db.commit()

    def add_http_rows(self, rows):
        self.db.executemany("INSERT INTO http_requests VALUES (?,?,?,?,?,?,?,?)", rows)
        self.db.commit()


# --------------------------------------------------------------------------
# SQL normalisation -> "query template" (structure without data)
# --------------------------------------------------------------------------
_STR = re.compile(r"'(?:[^'\\]|\\.|'')*'")
_DQ = re.compile(r'"(?:[^"\\]|\\.|"")*"')
_VER_COMMENT = re.compile(r"/\*!\d*(.*?)\*/", re.S)      # /*!50000UNION*/ is executed by MySQL
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"(?:--(?:\s|$)|#).*$", re.M)
_COMMENT_TOKEN = re.compile(r"--(?:\s|$)|#|/\*")
_HEX = re.compile(r"\b0x[0-9a-f]+\b", re.I)
_NUM = re.compile(r"\b\d+(?:\.\d+)?\b")
_LIST = re.compile(r"\?(?:\s*,\s*\?)+")
_PAREN1 = re.compile(r"\(\s*\?\s*\)")
_ROWS = re.compile(r"\(\?\.\.\)(?:\s*,\s*\(\?\.\.\))+")
_WS = re.compile(r"\s+")


def normalize(sql: str) -> str:
    s = _DQ.sub("?", _STR.sub("?", sql))          # 1. literals -> ?
    s = _VER_COMMENT.sub(r" \1 ", s)              # 2. unwrap executable comments
    s = _BLOCK_COMMENT.sub(" ", s)                #    drop ordinary comments
    s = _LINE_COMMENT.sub(" ", s)
    s = s.replace("`", "").lower()
    s = _HEX.sub("?", s)                          # 3. hex / numbers -> ?
    s = _NUM.sub("?", s)
    s = _LIST.sub("?..", s)                       # 4. collapse value lists
    s = _PAREN1.sub("(?..)", s)
    s = _ROWS.sub("(?..)", s)
    return _WS.sub(" ", s).strip().rstrip("; ")


# --------------------------------------------------------------------------
# Baseline (learned from a benign-only run)
# --------------------------------------------------------------------------
class Baseline:
    def __init__(self, d=None):
        d = d or {}
        self.templates = d.get("templates", {})
        self.mu = d.get("len_mu", 5.0)
        self.sd = d.get("len_sd", 1.0)
        self.n = d.get("n_events", 0)

    @classmethod
    def fit(cls, sqls):
        counts, lens = Counter(), []
        for sql in sqls:
            counts[normalize(sql)] += 1
            lens.append(math.log(len(sql) + 1))
        mu = statistics.fmean(lens) if lens else 5.0
        sd = max(statistics.pstdev(lens), 0.25) if len(lens) > 1 else 1.0
        return cls({"templates": dict(counts), "len_mu": mu, "len_sd": sd, "n_events": len(lens)})

    @classmethod
    def load(cls, path=BASELINE_PATH):
        if not os.path.exists(path):
            raise SystemExit(f"No baseline at {path}. Run:  detector.py train --log <benign log>")
        with open(path) as f:
            return cls(json.load(f))

    def save(self, path=BASELINE_PATH):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump({"templates": self.templates, "len_mu": self.mu, "len_sd": self.sd,
                       "n_events": self.n}, f)

    def is_known(self, tmpl):
        return tmpl in self.templates

    def len_z(self, sql):
        return (math.log(len(sql) + 1) - self.mu) / self.sd


# --------------------------------------------------------------------------
# Features + risk score
# --------------------------------------------------------------------------
WRITE_STMTS = {"insert", "update", "delete", "replace"}

# Structural red flags. Only evaluated on *unseen* templates (an injection changes structure).
RULES = {
    "union_select": re.compile(r"\bunion\b(\s+all)?\s+select\b"),
    "time_fn":      re.compile(r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\b"),
    "info_schema":  re.compile(r"\binformation_schema\b"),
    "file_io":      re.compile(r"\b(load_file|into\s+(outfile|dumpfile))\b"),
    "tautology":    re.compile(r"\b(or|and)\s+\?\s*(=|<>|!=|<|>|like)\s*\?"),
    "subselect":    re.compile(r"\(\s*select\b"),
    "error_fn":     re.compile(r"\b(extractvalue|updatexml)\s*\("),
    "sys_var":      re.compile(r"@@\w+"),
    "cred_cols":    re.compile(r"\b(user_pass|user_activation_key)\b"),
}

# Content red flags, evaluated on writes (what is being *stored* - the phishing-kit footprint).
_FORM = re.compile(r"<form\b", re.I)
_PWD_FIELD = re.compile(r"type\s*=\s*\\?[\"']?password", re.I)
_MARKUP = re.compile(r"<iframe\b|<script\b|eval\s*\(|base64_decode|atob\s*\(|document\.write", re.I)
_SENS_OPT = re.compile(
    r"option_name\s*=\s*'(siteurl|home|admin_email|active_plugins|users_can_register|default_role)'", re.I)
_USERS_WRITE = re.compile(r"^(insert\s+(ignore\s+)?into|replace\s+into|update|delete\s+from)\s+\w*users\b")

W = dict(unseen=1.0, rule=1.2, comment=0.8, hexlit=0.8, long=0.5, unauth_write=0.8,
         sens_write=1.7, phish_form=2.0, phish_markup=1.2, entropy=1.7, priv_esc=2.0)
ENTROPY_MIN_LEN, ENTROPY_THRESHOLD = 80, 5.2


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def analyze(sql: str, user_id: int, baseline: Baseline):
    """Return (risk in [0,1], [reasons]). Uses only the query text and HTTP-side user id."""
    tmpl = normalize(sql)
    stmt = tmpl.split(" ", 1)[0] if tmpl else ""
    is_write = stmt in WRITE_STMTS
    x, reasons = 0.0, []

    def add(w, why):
        nonlocal x
        x += w
        reasons.append(why)

    # ---- structural anomaly -------------------------------------------------
    if not baseline.is_known(tmpl):
        add(W["unseen"], "unseen_template")
        for name in [n for n, rx in RULES.items() if rx.search(tmpl)][:3]:
            add(W["rule"], f"rule:{name}")
        no_lit = _STR.sub("''", sql)
        if _COMMENT_TOKEN.search(no_lit):
            add(W["comment"], "sql_comment")
        if _HEX.search(no_lit):
            add(W["hexlit"], "hex_literal")
        z = baseline.len_z(sql)
        if z > 3:
            add(W["long"], f"long_query(z={z:.1f})")
        if user_id == 0 and is_write:
            add(W["unauth_write"], "unauth_write")

    # ---- content anomaly (phishing-kit / persistence footprints) ------------
    if is_write:
        lits = [m[1:-1] for m in _STR.findall(sql)]
        text = "\n".join(lits)
        if _FORM.search(text) and _PWD_FIELD.search(text):
            add(W["phish_form"], "credential_form_in_write")
        elif _FORM.search(text) or _MARKUP.search(text):
            add(W["phish_markup"], "active_markup_in_write")
        if max((shannon(l) for l in lits if len(l) >= ENTROPY_MIN_LEN), default=0) >= ENTROPY_THRESHOLD:
            add(W["entropy"], "high_entropy_blob")
        if _SENS_OPT.search(sql.replace("`", "")) or _USERS_WRITE.search(tmpl):
            add(W["sens_write"], "sensitive_write")
        if "usermeta" in tmpl and "administrator" in text.lower():
            add(W["priv_esc"], "admin_privilege_grant")

    return 1.0 - math.exp(-x), reasons
