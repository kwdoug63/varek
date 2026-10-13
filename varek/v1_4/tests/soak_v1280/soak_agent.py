#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""soak_agent.py — the agent of the v1.28 soak test (soak.sh runs it under
the Warden, the egress proxy in inspecting mode, with four credentials).
It holds only placeholders (VAREK_CRED_<NAME>). Every <interval> seconds it
makes one request to the soak's API, the four credentials in turn:

  api   GET  /v1/a  Authorization: Bearer <placeholder>   (a file store)
  db    GET  /v1/b  X-Api-Key: <placeholder>              (a Vault lease, renewed)
  st    POST /v1/c  X-Token: <placeholder>, with a body   (AWS Secrets Manager)
  gh    GET  /v1/d  Authorization: token <placeholder>    (Vault KV version 2)

and prints one JSON line: {"t", "task", "status", "ms", "error"}. The API
answers 200 only when the header held the value.

The third turn, and every <probe-every>-th after it, is instead a probe, the
kinds in turn ("probe": <kind>; "held": true when it came out as it must):

  missing    /v1/a without its header: the proxy refuses it (403)
  other      /v1/a with the db credential's placeholder: refused (403)
  elsewhere  /v1/plain?q=<placeholder>, where no rule names a credential:
             sent as it is (200; the API sees the placeholder, no value)
  read       an open of the file store: refused (EACCES)

  soak_agent.py --interval 60 --seconds 86400 --name api.example.com --port P --store PATH

Standard library only.
"""
import argparse
import http.client
import json
import os
import ssl
import time

TASKS = (("api", "GET", "/v1/a", "Authorization", "Bearer "), ("db", "GET", "/v1/b", "X-Api-Key", ""),
         ("st", "POST", "/v1/c", "X-Token", ""), ("gh", "GET", "/v1/d", "Authorization", "token "))
PROBES = ("missing", "other", "elsewhere", "read")
BODY = b"soak body " + b"x" * 64


def ph(name):
    return os.environ.get("VAREK_CRED_" + name.upper(), "")


def call(a, ctx, method, path, headers, body=None):
    """(status, parsed body)"""
    conn = http.client.HTTPSConnection(a.name, a.port, timeout=20, context=ctx)
    try:
        conn.putrequest(method, path, skip_accept_encoding=True)
        for k, v in headers:
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        r = conn.getresponse()
        b = r.read(65536)
        try:
            return r.status, json.loads(b or b"{}")
        except ValueError:
            return r.status, {}
    finally:
        conn.close()


def task(a, ctx, i):
    name, method, path, hdr, scheme = TASKS[i % len(TASKS)]
    rec = {"t": round(time.time(), 3), "task": name}
    t0 = time.time()
    try:
        st, _ = call(a, ctx, method, path, [(hdr, scheme + ph(name))], BODY if method == "POST" else None)
        rec.update(status=st, ok=st == 200)
    except Exception as e:                      # noqa: BLE001 - every failure is recorded
        rec.update(ok=False, error=f"{type(e).__name__}: {e}"[:200])
    rec["ms"] = int((time.time() - t0) * 1000)
    return rec


def probe(a, ctx, kind):
    rec = {"t": round(time.time(), 3), "probe": kind}
    t0 = time.time()
    try:
        if kind == "read":
            try:
                open(a.store, "rb").close()
                rec.update(held=False, result="opened")
            except PermissionError:
                rec.update(held=True, result="EACCES")
        elif kind == "elsewhere":
            st, b = call(a, ctx, "GET", "/v1/plain?q=" + ph("api"), [("X-Other", ph("db"))])
            rec.update(status=st, held=st == 200 and b.get("placeholder_seen") is True and b.get("value_seen") is False)
        else:
            h = [] if kind == "missing" else [("Authorization", "Bearer " + ph("db"))]
            st, _ = call(a, ctx, "GET", "/v1/a", h)
            rec.update(status=st, held=st == 403)
    except Exception as e:                      # noqa: BLE001
        rec.update(held=False, error=f"{type(e).__name__}: {e}"[:200])
    rec["ms"] = int((time.time() - t0) * 1000)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--seconds", type=float, default=86400)
    ap.add_argument("--probe-every", type=int, default=10)
    ap.add_argument("--name", default="api.example.com")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--store", required=True)
    a = ap.parse_args()
    ctx = ssl.create_default_context()          # the host's bundle and the run's CA
    print(json.dumps({"t": round(time.time(), 3), "start": True,
                      "placeholders": all(ph(n).startswith(f"varek_ph_{n}_") for n, *_ in TASKS)}), flush=True)
    end = time.time() + a.seconds
    nxt = time.time()
    i = j = p = 0
    while time.time() < end:
        i += 1
        if a.probe_every and i >= 3 and (i - 3) % a.probe_every == 0:
            rec = probe(a, ctx, PROBES[p % len(PROBES)])
            p += 1
        else:
            rec = task(a, ctx, j)
            j += 1
        print(json.dumps(rec), flush=True)
        nxt += a.interval
        time.sleep(max(0.0, min(nxt, end) - time.time()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
