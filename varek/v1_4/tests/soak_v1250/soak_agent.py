#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_agent.py — the agent of the v1.25 soak test (soak.sh runs it under
the Warden). Every <interval> seconds it fetches one URL, taking the names in
turn, and prints one JSON line per fetch:

  {"t": <unix time>, "name": "de.wikipedia.org", "url": ..., "ok": true|false,
   "status": 200, "peer": "203.0.113.7", "ms": 41, "error": "..."}

  soak_agent.py --interval 60 --seconds 86400 --template URL NAME...

URL contains {name}. Standard library only. The agent resolves each name
through glibc (hosts: files dns), so through the Warden's stub resolver: the
names are matched by a wildcard rule, and none is in the hosts view.
"""
import argparse
import http.client
import json
import ssl
import time
import urllib.parse

UA = "varek-soak/1.25 (https://github.com/kwdoug63/varek; VAREK Warden soak test, one request a minute)"


def fetch(name, url, ctx):
    u = urllib.parse.urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    rec = {"t": round(time.time(), 3), "name": name, "url": url}
    t0 = time.time()
    conn = None
    try:
        if u.scheme == "https":
            conn = http.client.HTTPSConnection(u.hostname, port, timeout=20, context=ctx)
        else:
            conn = http.client.HTTPConnection(u.hostname, port, timeout=20)
        conn.connect()
        rec["peer"] = conn.sock.getpeername()[0]
        conn.request("GET", path, headers={"User-Agent": UA, "Accept": "application/json"})
        r = conn.getresponse()
        r.read(262144)
        rec.update(ok=200 <= r.status < 400, status=r.status)
    except Exception as e:                      # noqa: BLE001 - every failure is recorded
        rec.update(ok=False, error=f"{type(e).__name__}: {e}"[:200])
    finally:
        if conn is not None:
            conn.close()
    rec["ms"] = int((time.time() - t0) * 1000)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--seconds", type=float, default=86400)
    ap.add_argument("--template", required=True)
    ap.add_argument("names", nargs="+")
    a = ap.parse_args()
    ctx = ssl.create_default_context()
    end = time.time() + a.seconds
    nxt = time.time()
    i = 0
    while time.time() < end:
        name = a.names[i % len(a.names)]
        print(json.dumps(fetch(name, a.template.replace("{name}", name), ctx)), flush=True)
        i += 1
        nxt += a.interval
        time.sleep(max(0.0, min(nxt, end) - time.time()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
