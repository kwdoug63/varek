#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_agent.py — the agent of the v1.26.1 soak test (soak.sh runs it under
the Warden, with the egress proxy in inspecting mode). Every <interval>
seconds it fetches one URL, taking them in turn, and prints one JSON line per
fetch:

  {"t": <unix time>, "url": ..., "name": "pypi.org", "port": 443, "path": "/...",
   "ok": true|false, "status": 200, "peer": "198.18.0.1", "ms": 41,
   "error": "..."}

It verifies every server with the default trust store: under the Warden in
inspecting mode that is the host's bundle with the run's CA after it.

The third fetch, and every <probe-every>-th after it, is instead a probe the
policy must refuse, the kinds in turn, to an allowed name (<probe-via>):

  sni       TLS to its address with an SNI no rule allows (domain fronting
            by SNI): the connection is refused
  host      TLS to it, then a request whose Host names another host (domain
            fronting by Host): the proxy's parser refuses it, 403
  path      a request for an allowed path written another way
            (<path> with a "/./" segment): the parser refuses it, 403
  denied    a request a deny rule refuses: 403
  unlisted  a request for a path no request rule allows: 403

Its line has "probe": <kind>, and "ok": true if the probe got through (the
policy did not hold).

  soak_agent.py --interval 60 --seconds 86400 [--probe-every 10]
                [--probe-via pypi.org] [--probe-path /pypi/sampleproject/json]
                [--denied-path /simple/pip/] [--unlisted-path /pypi/pip/json]
                [--probe-sni example.org] URL...

Standard library only.
"""
import argparse
import http.client
import json
import socket
import ssl
import time
import urllib.parse

UA = "varek-soak/1.26.1 (https://github.com/kwdoug63/varek; VAREK Warden soak test, one request a minute)"
PROBES = ("sni", "host", "path", "denied", "unlisted")


def request(scheme, name, port, path, ctx, host=None):
    """One GET; (status, peer). host: send this Host instead of the name."""
    cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    kw = {"context": ctx} if scheme == "https" else {}
    conn = cls(name, port, timeout=20, **kw)
    try:
        conn.connect()
        peer = conn.sock.getpeername()[0]
        conn.putrequest("GET", path, skip_host=host is not None, skip_accept_encoding=True)
        if host is not None:
            conn.putheader("Host", host)
        # a small range: the soak tests reaching the API, not its bandwidth
        for k, v in (("User-Agent", UA), ("Accept", "application/json, */*"), ("Range", "bytes=0-65535")):
            conn.putheader(k, v)
        conn.endheaders()
        r = conn.getresponse()
        r.read(262144)
        return r.status, peer
    finally:
        conn.close()


def fetch(url, ctx):
    u = urllib.parse.urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    rec = {"t": round(time.time(), 3), "url": url, "name": u.hostname, "port": port,
           "scheme": u.scheme, "path": path}
    t0 = time.time()
    try:
        st, peer = request(u.scheme, u.hostname, port, path, ctx)
        rec.update(ok=200 <= st < 400, status=st, peer=peer)
    except Exception as e:                      # noqa: BLE001 - every failure is recorded
        rec.update(ok=False, error=f"{type(e).__name__}: {e}"[:200])
    rec["ms"] = int((time.time() - t0) * 1000)
    return rec


def probe(kind, a, ctx, pctx):
    rec = {"t": round(time.time(), 3), "probe": kind, "name": a.probe_via, "port": 443}
    t0 = time.time()
    try:
        if kind == "sni":
            rec["sni"] = a.probe_sni
            s = pctx.wrap_socket(socket.create_connection((a.probe_via, 443), 20), server_hostname=a.probe_sni)
            s.close()
            rec.update(ok=True)                 # reached: the policy did not hold
        else:
            # "path": the allowed path with a "/./" segment after its first
            # one (/pypi/./sampleproject/json), which a server reads as it
            path = {"host": a.probe_path,
                    "path": "/" + a.probe_path.strip("/").replace("/", "/./", 1),
                    "denied": a.denied_path, "unlisted": a.unlisted_path}[kind]
            rec["path"] = path
            if kind == "host":
                rec["host"] = a.probe_sni
            st, _ = request("https", a.probe_via, 443, path, ctx, host=a.probe_sni if kind == "host" else None)
            rec.update(ok=st != 403, status=st)
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
    ap.add_argument("--probe-path", default="/pypi/sampleproject/json")
    ap.add_argument("--denied-path", default="/simple/pip/")
    ap.add_argument("--unlisted-path", default="/pypi/pip/json")
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
    i = j = p = 0
    while time.time() < end:
        i += 1
        # the third fetch is a probe, then every probe_every-th: even a
        # short trial runs one
        if a.probe_every and i >= 3 and (i - 3) % a.probe_every == 0:
            rec = probe(PROBES[p % len(PROBES)], a, ctx, pctx)
            p += 1
        else:
            rec = fetch(a.urls[j % len(a.urls)], ctx)
            j += 1
        print(json.dumps(rec), flush=True)
        nxt += a.interval
        time.sleep(max(0.0, min(nxt, end) - time.time()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
