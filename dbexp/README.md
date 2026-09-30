# Continuous vs. scheduled database anomaly detection on WordPress

A small lab kit for your study. One WordPress + MariaDB site, one Python detector, and the
only thing that changes between conditions is **when the detector scores queries**.

```
 visitors / admin ──HTTP──▶ Apache + WordPress ──▶ MariaDB
 (workload.py, labelled)          │
                                  │ mu-plugin hooks $wpdb "query" filter
                                  ▼
                       /var/log/dbexp/events.jsonl   (1 JSON line per query:
                                  │                   ts, req_id, user_id, ip, uri, sql, label)
                                  ▼
                        detector.py  ── continuous: score each line as it appears
                                     └─ scheduled : score everything every N seconds
                                  │
                                  ▼
                 SQLite experiment.db: runs · events · alerts · batches · perf · http_requests
                                  │
                                  ▼
                       evaluate.py → precision / recall / delay / latency / CPU  (+CSV)
```

## Files

| Path | Role |
|---|---|
| `setup_vm.sh` | Installs Apache, PHP, MariaDB, WordPress, Contact Form 7, Yoast SEO, 4 user roles, logger, Python env |
| `wordpress/mu-plugins/dbexp-logger.php` | **Logger/interceptor.** Logs every query with HTTP context |
| `wordpress/plugins/dbexp-lab-vulnerable/` | Deliberately SQL-injectable endpoint (`/?dbexp_id=`) — lab only |
| `detector/common.py` | SQLite schema, SQL normalisation, features, risk score |
| `detector/detector.py` | `train` a baseline; `run --mode continuous|scheduled` |
| `detector/workload.py` | Benign traffic + labelled SQLi and phishing-footprint episodes |
| `detector/evaluate.py` | Metrics per run, CSV export |

## 1. Provision

1. Create a free-tier VM (Oracle Always Free ARM/AMD, GCP e2-micro, AWS t2/t3.micro), Ubuntu 22.04/24.04.
2. In the cloud firewall allow ports 22 and 80 **only from your own IP** (the lab plugin is injectable on purpose).
3. Copy this folder to the VM and run:

```bash
SITE_URL=http://<vm-public-ip> bash setup_vm.sh
```

It prints the admin password and writes `/opt/dbexp/lab.env` (site URL + a REST application password for the workload generator).

## 2. Experiment protocol

```bash
source /opt/dbexp/lab.env && cd /opt/dbexp && PY=/opt/dbexp/venv/bin/python

# --- Step 0: learn what "normal" looks like (benign only, no detector running) ---
sudo truncate -s0 /var/log/dbexp/events.jsonl
$PY workload.py --run-id train0 --duration 600 --attacks 0 --seed 1
$PY detector.py train                      # -> /var/lib/dbexp/baseline.json

# --- Step 1: one measured run per condition, repeated (>=5 each) ---
# Continuous
$PY detector.py run --mode continuous --run-id cont-1 &  DET=$!
sleep 2
$PY workload.py --run-id cont-1 --duration 600 --attacks 30 --seed 100
sleep 5; kill -INT $DET; wait $DET

# Scheduled (60 s; also try 300 s and 900 s)
$PY detector.py run --mode scheduled --interval 60 --run-id sched60-1 &  DET=$!
sleep 2
$PY workload.py --run-id sched60-1 --duration 600 --attacks 30 --seed 100
sleep 65; kill -INT $DET; wait $DET       # wait > interval so the last batch runs

# Control A: logger only, no detector       (workload only)
$PY workload.py --run-id logonly-1 --duration 600 --attacks 30 --seed 100
# Control B: no monitoring at all           (touch /var/lib/dbexp/LOGGER_OFF first, rm afterwards)
touch /var/lib/dbexp/LOGGER_OFF
$PY workload.py --run-id none-1 --duration 600 --attacks 30 --seed 100
rm /var/lib/dbexp/LOGGER_OFF

# --- Step 2: results ---
$PY evaluate.py cont-1 sched60-1 logonly-1 none-1 --csv results.csv
```

Use the **same `--seed`** for paired runs so both conditions see the same request mix. Rest a minute between runs. Randomise the run order (don't do all continuous first) to avoid VM noisy-neighbour bias.

## 3. What is measured

| Objective | Metric | Source |
|---|---|---|
| Performance | HTTP latency mean / p50 / p95 / p99 (benign requests), throughput, error rate | `http_requests` |
| Performance | Detector CPU seconds, avg CPU %, peak RSS, system CPU/mem, batch scoring time | `runs`, `perf`, `batches` |
| Accuracy | TP/FP/FN/TN, precision, recall, F1, FPR — request level, per attack type | `events`, `alerts` |
| Response time | Alert delay = alert time − time of the offending query (mean / p50 / p95) | `alerts` |

The two controls let you separate **logging overhead** (`logonly` vs `none`) from **detection overhead** (`cont`/`sched` vs `logonly`).

Ground truth comes from an `X-Exp-Label` header the workload attaches (`benign`, `attack:sqli-classic`, `attack:sqli-evasive`, `attack:phish-kit`, `ignore`). The logger copies it into the log; the detector never reads it when scoring, and `train` skips attack-labelled events.

## 4. How the detector scores (identical in both modes)

Each query is normalised to a **template** (literals → `?`, comments stripped, `/*!50000UNION*/` unwrapped, value lists collapsed), then a risk `1 − exp(−Σ weights)` is computed. Alert threshold defaults to 0.80.

- **Structural anomaly:** template never seen in the baseline (+1.0), plus corroborating signals only for unseen templates: `UNION SELECT`, `SLEEP/BENCHMARK`, `information_schema`, tautologies (`OR ?=?`), sub-selects, `EXTRACTVALUE`, `@@vars`, credential columns, SQL comments, hex literals, abnormal length, unauthenticated writes. A novelty flag alone never alerts.
- **Content anomaly (writes):** credential form (`<form>` + password field) in stored content, active markup (`<script>`, `<iframe>`, `eval(`, `atob(`), high-entropy blobs (Shannon ≥ 5.2 on ≥ 80 chars), writes to `*_users` or to `siteurl/home/admin_email/active_plugins/default_role`, and admin-capability grants in `usermeta`.

Because the logger sits **after** PHP has URL-decoded the input, HTTP-level evasion (case tricks, `%55NION`, comment splitting) is undone before the detector sees the SQL — one argument for database-side detection worth discussing in your paper.

## 5. Design decisions to state in your methodology

- **Continuous** = the detector tails the log and scores each event as it lands (≈50 ms poll) and commits each event immediately. It is out-of-band, so it competes for CPU with WordPress but doesn't block requests. If you want a stricter "inline" variant, add a blocking `curl` (50 ms timeout) from the mu-plugin to a local scoring endpoint; that is the natural third condition.
- **Scheduled** = the same code run in one batch every N seconds, one SQLite transaction per batch. Expect lower average overhead, CPU spikes at each batch, and detection delay ≈ N/2 on average.
- Both conditions share one VM and one WordPress install (a free VM can't run two identical stacks at once), so run them **sequentially** with the same seeds rather than in parallel.
- `ignore`-labelled clean-up requests are excluded from metrics; WP-CLI activity isn't logged.

## 6. Limitations / threats to validity

- The phishing "kit" is a **harmless stand-in** reproducing DB footprints (fake login markup posting to `example.invalid`, hidden random blob, rogue admin, admin_email change). It shows detection of the *persistence footprint* in the DB, not of a real kit's file-system or network behaviour. If you need real kit samples, replay them only in an isolated sandbox and add the resulting queries to the workload.
- The SQLi payload list is small and textbook; extend `SQLI_CLASSIC` / `SQLI_EVASIVE` (or drive the endpoint with sqlmap) for a stronger evaluation. The scoring weights are hand-set — tune them on a validation run, not on the runs you report.
- Requests are the unit of evaluation; per-request features (e.g. burst of queries in one request) are not used, but are an interesting place where the two modes could differ (batch mode sees the whole request, continuous mode only what's arrived).
- Free-tier VMs have noisy CPU; report repeats, medians and confidence intervals.
- `WP_ENVIRONMENT_TYPE=local` and the vulnerable plugin are lab conveniences. Tear the VM down when finished.

## 7. Testing status

The Python components were exercised end to end on synthetic logs (train → continuous and scheduled runs → evaluation) and the workload generator against a stub HTTP server. The PHP files and `setup_vm.sh` couldn't be run in that environment, so expect to fix a small typo or package name on your first VM run. Perfect scores on synthetic data mean nothing; real numbers come from your VM runs.
