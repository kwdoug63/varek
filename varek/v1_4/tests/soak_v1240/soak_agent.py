#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_agent.py — the agent of the v1.24 soak test (soak.sh runs it under
the Warden). Every <interval> seconds it fetches each URL once, by name, and
prints one JSON line per fetch:

  {"t": <unix time>, "url": ..., "ok": true|false, "status": 200,
   "peer": "203.0.113.7", "cdn": "fastly|cloudflare|cloudfront|unknown",
   "ms": 41, "error": "PermissionError: ..."}

  soak_agent.py --interval 60 --seconds 86400 URL...

Standard library only. The agent never sends a DNS query: it resolves through
the Warden's /etc/hosts view (glibc getaddrinfo).
"""
import argparse
import http.client
import json
import socket
import ssl
import sys
import time
import urllib.parse


def cdn_of(headers):
    h = {k.lower(): v for k, v in headers}
    via = h.get("via", "").lower()
    if "x-amz-cf-id" in h or "cloudfront" in via or "cloudfront" in h.get("x-cache", "").lower():
        return "cloudfront"
    if "cf-ray" in h or h.get("server", "").lower() == "cloudflare":
        return "cloudflare"
    if "x-served-by" in h and "cache-" in h.get("x-served-by", "") or "varnish" in via or "x-fastly-request-id" in h:
        return "fastly"
    return "unknown"


def fetch(url, ctx):
    u = urllib.parse.urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    rec = {"t": round(time.time(), 3), "url": url}
    t0 = time.time()
    conn = None
    try:
        if u.scheme == "https":
            conn = http.client.HTTPSConnection(u.hostname, port, timeout=20, context=ctx)
        else:
            conn = http.client.HTTPConnection(u.hostname, port, timeout=20)
        conn.connect()
        rec["peer"] = conn.sock.getpeername()[0]
        conn.request("GET", path, headers={"User-Agent": "varek-soak/1.24", "Accept": "*/*"})
        r = conn.getresponse()
        r.read(65536)
        rec.update(ok=200 <= r.status < 400, status=r.status, cdn=cdn_of(r.getheaders()))
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
    ap.add_argument("urls", nargs="+")
    a = ap.parse_args()
    ctx = ssl.create_default_context()
    end = time.time() + a.seconds
    nxt = time.time()
    while time.time() < end:
        for url in a.urls:
            print(json.dumps(fetch(url, ctx)), flush=True)
        nxt += a.interval
        time.sleep(max(0.0, min(nxt, end) - time.time()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
