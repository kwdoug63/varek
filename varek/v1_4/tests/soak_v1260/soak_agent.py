#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_agent.py — the agent of the v1.26 soak test (soak.sh runs it under
the Warden, with the egress proxy on). Every <interval> seconds it fetches
one URL, taking them in turn, and prints one JSON line per fetch:

  {"t": <unix time>, "url": ..., "name": "pypi.org", "port": 443,
   "ok": true|false, "status": 200, "peer": "198.18.0.1", "ms": 41,
   "error": "..."}

The third fetch, and every <probe-every>-th after it, is instead a probe the policy must refuse: a TLS
connection to an allowed name's address whose SNI names a host no rule
allows (domain fronting). Its line has "probe": true and "sni".

  soak_agent.py --interval 60 --seconds 86400 [--probe-every 10]
                [--probe-via pypi.org --probe-sni example.org] URL...

Standard library only. Names resolve through glibc: the hosts view and the
Warden's stub, so to synthetic addresses, and every connection goes through
the proxy.
"""
import argparse
import http.client
import json
import socket
import ssl
import time
import urllib.parse

UA = "varek-soak/1.26 (https://github.com/kwdoug63/varek; VAREK Warden soak test, one request a minute)"


def fetch(url, ctx):
    u = urllib.parse.urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    rec = {"t": round(time.time(), 3), "url": url, "name": u.hostname, "port": port}
    t0 = time.time()
    conn = None
    try:
        cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        kw = {"context": ctx} if u.scheme == "https" else {}
        conn = cls(u.hostname, port, timeout=20, **kw)
        conn.connect()
        rec["peer"] = conn.sock.getpeername()[0]
        # a small range: the soak tests reaching the API, not its bandwidth
        conn.request("GET", path, headers={"User-Agent": UA, "Accept": "application/json, */*",
                                           "Range": "bytes=0-65535"})
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


def probe(via, sni, ctx):
    rec = {"t": round(time.time(), 3), "probe": True, "name": via, "sni": sni, "port": 443}
    t0 = time.time()
    try:
        s = ctx.wrap_socket(socket.create_connection((via, 443), 20), server_hostname=sni)
        s.close()
        rec.update(ok=True)                     # reached: the policy did not hold
    except Exception as e:                      # noqa: BLE001
        rec.update(ok=False, error=f"{type(e).__name__}: {e}"[:200])
    rec["ms"] = int((time.time() - t0) * 1000)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--seconds", type=float, default=86400)
    ap.add_argument("--probe-every", type=int, default=10)
    ap.add_argument("--probe-via", default="pypi.org")
    ap.add_argument("--probe-sni", default="example.org")
    ap.add_argument("--insecure", action="store_true", help="local trials: do not verify certificates")
    ap.add_argument("urls", nargs="+")
    a = ap.parse_args()
    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    pctx = ssl.create_default_context()
    pctx.check_hostname = False
    pctx.verify_mode = ssl.CERT_NONE
    end = time.time() + a.seconds
    nxt = time.time()
    i = j = 0
    while time.time() < end:
        i += 1
        # the third fetch is a probe, then every probe_every-th: even a
        # 3-minute trial at one a minute runs one
        if a.probe_every and i >= 3 and (i - 3) % a.probe_every == 0:
            rec = probe(a.probe_via, a.probe_sni, pctx)
        else:
            rec = fetch(a.urls[j % len(a.urls)], ctx)
            j += 1
        print(json.dumps(rec), flush=True)
        nxt += a.interval
        time.sleep(max(0.0, min(nxt, end) - time.time()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
