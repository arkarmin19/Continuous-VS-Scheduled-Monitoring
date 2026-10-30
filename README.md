# Continuous vs. scheduled database anomaly detection on WordPress

Lab kit for the University BSc Computer Science thesis
*Making Databases Safe: Preliminary Study of Comparing Continuous & Scheduled Anomaly Detection in Web CMS Environments*.

One WordPress + MariaDB site and one Python detector are used. Every condition uses the same
baseline, scoring function, threshold, workload and attacks. The only difference between
conditions is **when the detector scores queries**.

**Research question:** How does continuous database anomaly detection compare with scheduled
database anomaly detection for identifying SQL injection and unauthorized phishing-kit activity
in a Web CMS, when both security effectiveness and system-performance overhead are considered?

```
 visitors / admin ──HTTP──▶ Apache + WordPress ──▶ MariaDB
 (workload.py, labelled)          │
                                  │ mu-plugin hooks $wpdb "query" filter
                                  ▼
                       /var/log/dbexp/events.jsonl   (1 JSON line per query:
                                  │                   ts, req_id, seq, user_id, ip,
                                  │                   method, uri, label, sql)
                                  ▼
                        detector.py  ── continuous: score each line as it appears (≈50 ms poll)
                                     └─ scheduled : score everything every T = 10 / 60 / 300 s
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
| `setup_vm.sh` | Installs Apache (with URL rewriting), PHP, MariaDB, WordPress, Contact Form 7, Yoast SEO, four user roles, the logger and the Python environment; writes `/opt/dbexp/lab.env` |
| `run_trials.sh` | Runs the whole experiment: baseline training, then all conditions × all trials in a randomised order, then evaluation |
| `wordpress/mu-plugins/dbexp-logger.php` | **Query logger.** Logs every `$wpdb` query with its HTTP context |
| `wordpress/plugins/dbexp-lab-vulnerable/` | Deliberately SQL-injectable endpoint `/?dbexp_id=` (lab only; returns a row count, never data) |
| `detector/common.py` | SQLite schema, SQL normalisation, indicators, risk score |
| `detector/detector.py` | `train` a baseline; `run --mode continuous` or `run --mode scheduled --interval T` |
| `detector/workload.py` | Legitimate traffic plus labelled SQL injection and phishing-kit episodes |
| `detector/evaluate.py` | Metrics per run; CSV export |

## 1. Set up the environment

The thesis experiment ran on an **Ubuntu virtual machine on one laptop** (VirtualBox). A cloud VM also works.

**Local VM**

```bash
scp -r dbexp vboxuser@<vm-ip>:
ssh vboxuser@<vm-ip>
cd dbexp && bash setup_vm.sh
```

**Cloud VM** (allow ports 22 and 80 **only from your own IP**, because the lab plugin is injectable on purpose)

```bash
SITE_URL=http://<vm-public-ip> bash setup_vm.sh
```

The script prints the admin password and writes `/opt/dbexp/lab.env` (site URL, admin user and a REST application password for the workload generator). It also enables post-name permalinks and writes the WordPress `.htaccess` rules, so `/wp-json/` REST addresses reach WordPress.

## 2. Run the experiment

The whole thesis experiment is one command:

```bash
cd /opt/dbexp
bash run_trials.sh
```

Defaults (all can be overridden with environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `TRIALS` | 5 | repetitions of every condition (seeds 101, 102, …) |
| `INTERVALS` | `"10 60 300"` | scheduled-mode intervals in seconds |
| `DURATION` | 600 | workload length per run (s); must be ≥ 2 × the largest interval |
| `ATTACKS` | 30 | attack episodes per run (10 classic SQLi, 10 evasive SQLi, 10 phishing-kit) |
| `COOLDOWN` | 60 | pause between runs (s) |
| `CONTROLS` | 1 | include the `logonly` and `none` control conditions |
| `TRAIN` | 1 | retrain the baseline on a benign-only run first |
| `TAG` | current date-time | prefix for run IDs |

Example: `TRIALS=10 INTERVALS="10 60" bash run_trials.sh`

What the script does:

1. **Checks** that the site responds and that an authenticated REST API call returns HTTP 200. It stops if either check fails, so a misconfigured experiment is not recorded.
2. **Trains the baseline** on a separate 600 s run of legitimate traffic only (seed 1, no detector).
3. **Runs every trial.** Each trial runs the six conditions with the same seed, in an order shuffled reproducibly from that seed:

   | Condition | What runs |
   |---|---|
   | `cont` | logger + detector in continuous mode |
   | `sched-10`, `sched-60`, `sched-300` | logger + detector in scheduled mode with T = 10, 60 or 300 s |
   | `logonly` | logger only, no detector (cost of logging) |
   | `none` | logger switched off via `/var/lib/dbexp/LOGGER_OFF` (no monitoring) |

   After the workload, the detector is stopped after 5 s (continuous) or T + 5 s (scheduled), so the final batch is processed. There is a 60 s cool-down between runs.
4. **Evaluates** all runs into `/opt/dbexp/results/<TAG>/final_results.csv`. The run order is in `run_order.csv` in the same folder.

### Running conditions by hand

```bash
source /opt/dbexp/lab.env && cd /opt/dbexp && PY=/opt/dbexp/venv/bin/python

# Baseline (benign only, no detector)
sudo truncate -s0 /var/log/dbexp/events.jsonl
$PY workload.py --run-id train0 --duration 600 --attacks 0 --seed 1
$PY detector.py train                                   # -> /var/lib/dbexp/baseline.json

# Continuous
$PY detector.py run --mode continuous --run-id cont-s101 &  DET=$!
sleep 2; $PY workload.py --run-id cont-s101 --duration 600 --attacks 30 --seed 101
sleep 5; kill -INT $DET; wait $DET

# Scheduled, T = 60 s (wait T + 5 s so the last batch runs)
$PY detector.py run --mode scheduled --interval 60 --run-id sched-60-s101 &  DET=$!
sleep 2; $PY workload.py --run-id sched-60-s101 --duration 600 --attacks 30 --seed 101
sleep 65; kill -INT $DET; wait $DET

# Control: logger only
$PY workload.py --run-id logonly-s101 --duration 600 --attacks 30 --seed 101

# Control: no monitoring
touch /var/lib/dbexp/LOGGER_OFF
$PY workload.py --run-id none-s101 --duration 600 --attacks 30 --seed 101
rm /var/lib/dbexp/LOGGER_OFF

# Results
$PY evaluate.py cont-s101 sched-60-s101 logonly-s101 none-s101 --csv results.csv
```

## 3. Workload and attacks

- **Legitimate traffic:** three simulated users, mean think time 1 s (about 3–4 requests/s). About 15% of actions are administrator actions (create/edit/view/delete a post through the REST API; list posts; view profile). The rest are visitor actions: home 30%, post 20%, search 12%, page 8%, REST post list 8%, category 6%, lab endpoint with a valid ID 6%, comment 6%, feed 4%.
- **SQL injection:** sent to `/?dbexp_id=`. There are five classic payloads (tautology, UNION credential extraction, `SLEEP`, `information_schema`, `EXTRACTVALUE`) and five evasive payloads (mixed case, `/**/` splitting, `/*!50000UNION*/`, hex tautology, `IF(…,SLEEP(1),0)`). Each payload is sent twice per run.
- **Phishing kit (harmless stand-in):** an attacker with an admin account (1) publishes an "Account Verification" page with a password form posting to `example.invalid`, (2) publishes a post with a hidden base64 blob, (3) creates the administrator `svc_helpdesk_<k>`, and (4) changes `admin_email`. Each episode is reverted afterwards with `ignore`-labelled requests, which are excluded from the metrics.
- **Ground truth:** every request carries an `X-Exp-Label` header (`benign`, `attack:sqli-classic`, `attack:sqli-evasive`, `attack:phish-kit`, `ignore`). The logger copies the label into the log. The detector never reads it when scoring, and `train` skips attack and ignore events.

## 4. How the detector scores (identical in both modes)

Each query is normalised to a **template**: string literals → `?`, `/*!50000…*/` unwrapped, comments removed, hex and numbers → `?`, value lists collapsed, lower-cased. The risk is `1 − exp(−Σ weights)`, and an alert is raised at risk ≥ **0.80**.

| Group | Indicator | Weight |
|---|---|---|
| Structural | Template not in the baseline | 1.0 |
| Structural (unseen only) | Up to three of: `UNION SELECT`, `SLEEP/BENCHMARK`, `information_schema`, `LOAD_FILE/INTO OUTFILE`, tautology, sub-select, `EXTRACTVALUE/UPDATEXML`, `@@var`, credential columns | 1.2 each |
| Structural (unseen only) | SQL comment token; hex literal | 0.8 each |
| Structural (unseen only) | Length z-score > 3; write by an unauthenticated user | 0.5; 0.8 |
| Content (writes) | HTML form with a password field | 2.0 |
| Content (writes) | Other form or active markup (`<script>`, `<iframe>`, `eval(`, `atob(`, `base64_decode`, `document.write`) | 1.2 |
| Content (writes) | High-entropy string (Shannon ≥ 5.2 on ≥ 80 chars) | 1.7 |
| Content (writes) | Write to the users table or to `siteurl`, `home`, `admin_email`, `active_plugins`, `users_can_register`, `default_role` | 1.7 |
| Content (writes) | Administrator role granted in `usermeta` | 2.0 |

An unseen template on its own (risk 0.63) never alerts. SQL injection is caught by **structure** and phishing-kit activity by **content**.

## 5. What is measured

| Aspect | Metric | Source table |
|---|---|---|
| Accuracy | TP/FP/FN/TN, precision, recall, F1, FPR (request level, per attack type) | `events`, `alerts` |
| Detection delay | Alert time − time of the offending query (mean / p50 / p95) | `alerts` |
| Application | Latency mean / p50 / p95 / p99 (legitimate requests only); throughput and error rate (all requests; error = HTTP ≥ 500 or no response) | `http_requests` |
| Resources | Detector CPU time and average CPU %, peak detector memory (RSS), system CPU and memory (sampled every 5 s), batch processing time | `runs`, `perf`, `batches` |

Logging overhead = `logonly` vs `none`. Detection overhead = `cont` / `sched-*` vs `logonly`.

## 6. Results (thesis experiment: 5 trials × 6 conditions = 30 runs)

| Condition | Recall | Precision | Mean delay | Latency vs logger only | Detector CPU / run | Peak detector memory |
|---|---|---|---|---|---|---|
| Continuous | 1.000 | 0.997 | 0.027 s | +7.1 ms | 9.64 s | 18.3 MB |
| Scheduled 10 s | 1.000 | 0.997 | 5.2 s | +2.9 ms | 2.84 s | 20.1 MB |
| Scheduled 60 s | 1.000 | 0.997 | 32.6 s | +4.2 ms | 2.94 s | 24.0 MB |
| Scheduled 300 s | 1.000 | 0.990 | 148.8 s | +1.7 ms | 3.13 s | 37.7 MB |

- All 60 attack requests were detected in every run. All six false positives (out of about 59,100 legitimate requests) were the same WordPress theme-pattern cache write.
- Scheduled delay ≈ T/2. Throughput (≈3.7 req/s) and server-error rate (0%) did not change between conditions.
- **Conclusion:** use continuous detection when fast response matters. A 10 s schedule is the best scheduled compromise. Long intervals are only suited to periodic auditing.

### Result files

| File | Contents |
|---|---|
| `results/20261009-0614/final_results.csv` | the 30 measured runs reported in the thesis (run IDs `20261009-0614-<condition>-s<seed>`) |
| `results/20261009-0614/run_order.csv` | condition order of every trial |
| `pilot_results.csv` | earlier 10-run pilot (continuous and 60 s only). Its phishing-kit and admin REST requests got HTTP 404 because URL rewriting was not yet enabled, so they are **not** used in the thesis |
| `smoke_test.csv` | first test runs, used only to check that the scripts and site work |

## 7. Limitations

- One CMS (WordPress), one database (MariaDB), one rule- and baseline-based detector; a light workload (three users, about 3–4 req/s); five runs per condition on one laptop.
- The SQLi payload list is short and textbook-based, and the indicator weights are set by hand.
- The phishing kit reproduces the database footprint only, not a real kit's file-system or network behaviour.
- The detector is out-of-band: it raises alerts but does not block requests.
- About 1.6% of requests (comment submissions) were rejected by WordPress as duplicates (HTTP 409) in every condition, including both controls.
- Detector resource samples include the T + 5 s wait after the workload, which lowers the average CPU figures for the 300 s schedule.

## 8. Safety

Everything runs on an isolated VM. All accounts and e-mail addresses are synthetic (`example.invalid`), the vulnerable endpoint never returns data, and no working phishing page is published. **Never install `dbexp-lab-vulnerable` on a real site**, and tear the VM down when finished.
