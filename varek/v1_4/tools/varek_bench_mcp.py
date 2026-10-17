# SPDX-License-Identifier: MIT
"""
varek_bench_mcp: what deciding an MCP call over HTTP costs, on this host
(v1.31; `varek bench --mcp`).

An MCP call is decided on its body (the method and the tool's name, read
from the JSON-RPC message), so the proxy holds the body until it has read
and parsed all of it: none of it is sent before the call is decided. A
client (tools/bench_mcp_client.py) makes tools/call requests whose bodies
are 1 KiB, 16 KiB, 256 KiB and 1 MiB (the default max_body), each on one
kept-alive HTTPS connection, to a stand-in MCP server on this host's own
address, in three modes, rounds alternating:

  native   the client to the server directly;
  request  as the agent under the Warden, the proxy inspecting, the
           endpoint allowed by a request rule (`allow request POST URL`):
           the request is decided on its head and its body streamed;
  mcp      the same with an MCP rule (`allow mcp URL tools/call echo`): the
           body held, read and parsed, the call decided, then sent.

The report gives, for each size, the time a call took in each mode (the
client's own timing), the time the proxy adds (each mode's p50 minus the
native p50), what holding and parsing the body adds (mcp minus request),
and the Warden's own time per decision, from its records.

Every call's outcome is checked: answered 200 with its own id, in request
mode each request decided and certified, in mcp mode each call decided as
an MCP call and certified with the body's length and SHA-256 as the client
sent it, and the audit (tools/varek_audit.py) accepts every stream.
"""

import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

import bench_mcp_client as client_mod
import varek_bench as vb
import varek_bench_proxy as vbp

FORMAT = 1
NAME = vbp.NAME
RUN_TIMEOUT = 900
SIZES = (1024, 16384, 262144, 1048576)
MODES = ("native", "request", "mcp")


def kind(size):
    return f"s{size}"


def label(size):
    return f"{size // 1048576} MiB" if size >= 1048576 else f"{size // 1024} KiB"


# ------------------------------------------------------------------ policy --

def compose_policy(mode, port, bench_dir):
    """The policy of a run under the Warden: the proxy inspecting, the
    bench's name, the endpoint allowed by a request rule (request) or as
    MCP calls of echo (mcp), and read-only paths for Python."""
    url = f"https://{NAME}:{port}/mcp"
    lines = [f"# varek bench --mcp ({mode}): the bench's own rules only",
             "require warden 1.31",
             "proxy inspect",
             f"proxy ports {port}",
             f"allow host {NAME}:{port}",
             f"allow request POST {url}" if mode == "request" else f"allow mcp {url} tools/call echo"]
    lines += [f"allow path {d} readonly" for d in ("/usr/", "/lib/", "/lib64/", "/etc/ld.so.cache",
                                                    "/etc/ssl/", "/proc/self/", f"{bench_dir}/")]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ server --

class _Server:
    """The stand-in MCP server, HTTPS on the host's address, keep-alive: a
    POST /mcp with a Content-Length body is read to its end and answered
    with a JSON-RPC result carrying the call's id. Counts the bodies of each
    length it read whole."""

    ID = re.compile(rb'^\{"jsonrpc":"2\.0","id":(\d+),')

    def __init__(self, addr, cert, key):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.l = socket.socket()
        self.l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l.bind((addr, 0))
        self.l.listen(64)
        self.port = self.l.getsockname()[1]
        self.lock = threading.Lock()
        self.seen = {}
        threading.Thread(target=self._accept, daemon=True).start()

    def count(self, n):
        with self.lock:
            return self.seen.get(n, 0)

    def _accept(self):
        while True:
            try:
                c, _ = self.l.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            c.settimeout(60)
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            c = self.ctx.wrap_socket(c, server_side=True)
            buf = b""
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                head, _, buf = buf.partition(b"\r\n\r\n")
                cl = 0
                for ln in head.split(b"\r\n")[1:]:
                    if ln.lower().startswith(b"content-length:"):
                        cl = int(ln.split(b":", 1)[1])
                chunks, have = [buf], len(buf)
                while have < cl:
                    d = c.recv(262144)
                    if not d:
                        return
                    chunks.append(d)
                    have += len(d)
                body = b"".join(chunks)
                body, buf = body[:cl], body[cl:]
                m = self.ID.match(body)
                with self.lock:
                    self.seen[len(body)] = self.seen.get(len(body), 0) + 1
                out = b'{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}' % (
                    m.group(1) if m else b"null")
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                          % len(out) + out)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            c.close()

    def close(self):
        self.l.close()


# ------------------------------------------------------------------ checks --

def check_mode(mode, out, recs, sizes, calls):
    """The checks of one run (`calls` = warm-up + timed, per size)."""
    res = []
    bad = [s for s in sizes if out["classes"][kind(s)]["ok"] != calls]
    res.append((f"{mode}: every call answered 200 with its own id", not bad,
                "" if not bad else ", ".join(f"{label(s)}: {out['classes'][kind(s)]['status']}" for s in bad)))
    if mode == "native":
        return res
    px = [r for r in recs if r.get("action") == "net.proxy"]
    pbad = [r for r in px if r.get("decision_final") != "ALLOW" or r.get("check") != "ok"
            or r.get("inspected") is not True]
    res.append((f"{mode}: each connection decided by name, dialed, certified and inspected",
                bool(px) and not pbad, "" if px and not pbad else f"{len(px)} connections, {len(pbad)} not so"))
    want = calls * len(sizes)
    if mode == "request":
        rq = [r for r in recs if r.get("action") == "net.request"]
        ok = [r for r in rq if r.get("rule") == "request_allowed" and r.get("decision_final") == "ALLOW"
              and r.get("check") == "ok" and r.get("target", "").endswith("/mcp")]
        mc = [r for r in recs if r.get("action") == "net.mcp"]
        res.append(("request: each call decided by the request rule and certified, none as an MCP call",
                    len(ok) == want == len(rq) and not mc,
                    "" if len(ok) == want == len(rq) and not mc else
                    f"{len(ok)} of {len(rq)} requests allowed and certified for {want} calls, {len(mc)} net.mcp"))
        return res
    mc = [r for r in recs if r.get("action") == "net.mcp"]
    ok = [r for r in mc if r.get("rule") == "mcp_allowed" and r.get("decision_final") == "ALLOW"
          and r.get("check") == "ok" and r.get("mcp_method") == "tools/call" and r.get("mcp_name") == "echo"]
    res.append(("mcp: each call decided as an MCP call (tools/call echo) and certified", len(ok) == want == len(mc),
                "" if len(ok) == want == len(mc) else f"{len(ok)} of {len(mc)} calls for {want}"))
    wrong = 0
    for r in mc:
        try:
            i = int(r.get("rpc_id"))
        except (TypeError, ValueError):
            wrong += 1
            continue
        size = r.get("body_len")
        if size not in sizes or r.get("body_sha256") != hashlib.sha256(client_mod.body(i, size)).hexdigest():
            wrong += 1
    res.append(("mcp: each call's record has the body's length and SHA-256 as the client sent it", not wrong,
                "" if not wrong else f"{wrong} records do not"))
    return res


def by_size(recs, action, sizes, calls, warmup):
    """The Warden's own time (latency_us) of each size's timed decisions:
    the records in order, `calls` per size, the first `warmup` of each
    dropped."""
    rs = sorted((r for r in recs if r.get("action") == action and "latency_us" in r), key=lambda r: r.get("seq", 0))
    out = {}
    for j, s in enumerate(sizes):
        out[s] = [r["latency_us"] for r in rs[j * calls + warmup:(j + 1) * calls]]
    return out


# --------------------------------------------------------------------- run --

def run(warden, checker, *, n=100, warmup=10, rounds=3, run_as="nobody", sign_key=None,
        progress=None, keep=False, sizes=SIZES):
    """Run the MCP bench. Returns the result dictionary."""
    for path, what, fix in ((warden, "Warden", "build the runtime: `make`"),
                            (os.path.join(os.path.dirname(warden), "warden-proxy"), "warden-proxy",
                             "build it: `make warden-proxy`"),
                            (checker, "certificate checker", "build it: `make tools/vdp_cert_check`")):
        if not os.access(path, os.X_OK):
            raise vb.BenchError(f"no {what} at {path}", fix=fix)
    python = shutil.which("python3") or sys.executable
    here = os.path.dirname(os.path.abspath(__file__))
    uid, gid = vb.resolve_user(run_as)
    progress = progress or (lambda msg: None)
    addr = vbp.host_address()
    d = priv = dns = server = None
    try:
        d = tempfile.mkdtemp(prefix="varek-benchmcp-", dir="/tmp")
        os.chmod(d, 0o755)
        client = os.path.join(d, "bench_mcp_client.py")
        shutil.copyfile(os.path.join(here, "bench_mcp_client.py"), client)
        os.chmod(client, 0o644)
        priv = vb._private_dir()
        cert, key = vbp._make_cert(priv)
        shutil.copyfile(cert, os.path.join(d, "server.pem"))
        os.chmod(os.path.join(d, "server.pem"), 0o644)
        dns = vbp._Dns(addr)
        server = _Server(addr, cert, key)
        policies = {}
        for mode in ("request", "mcp"):
            policies[mode] = os.path.join(priv, f"{mode}.policy.txt")
            with open(policies[mode], "w") as fh:
                fh.write(compose_policy(mode, server.port, d))
            os.chmod(policies[mode], 0o644)
        calls = n + warmup
        kinds = [kind(s) for s in sizes]
        samples = {m: {s: [] for s in sizes} for m in MODES}
        round_p50 = {m: {s: [] for s in sizes} for m in MODES}
        warden_us = {m: {s: [] for s in sizes} for m in ("request", "mcp")}
        checks, run_start = [], None
        audit = os.path.join(here, "varek_audit.py")
        for rnd in range(rounds):
            order = MODES if rnd % 2 == 0 else MODES[::-1]
            for mode in order:
                progress(f"round {rnd + 1}/{rounds}: {mode}")
                cargs = [python, client, NAME if mode != "native" else f"{NAME}={addr}", str(server.port),
                         "default" if mode != "native" else os.path.join(d, "server.pem"),
                         str(n), str(warmup)] + [str(s) for s in sizes]
                if mode == "native":
                    r = subprocess.run(cargs, capture_output=True, text=True, timeout=RUN_TIMEOUT,
                                       user=uid, group=gid, extra_groups=[])
                    if r.returncode != 0:
                        raise vb.BenchError("the client failed natively: " + r.stderr.strip()[-300:])
                    out = vbp.parse_client(r.stdout, kinds, n)
                    checks += [(f"round {rnd + 1} {c}", ok, det) for c, ok, det in
                               check_mode(mode, out, [], sizes, calls)]
                else:
                    log = os.path.join(priv, f"verdicts-{mode}-{rnd + 1}.log")
                    argv = [warden, policies[mode], "--dns-server", f"127.0.0.1:{dns.port}",
                            "--trust-bundle", os.path.join(d, "server.pem")]
                    if sign_key:
                        argv += ["--sign-key", sign_key]
                    argv += ["--run-as", run_as, "--"] + cargs
                    with open(log, "w") as err:
                        r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=err, text=True,
                                           timeout=RUN_TIMEOUT, env={"PATH": "/usr/bin:/bin"})
                    with open(log, encoding="utf-8", errors="replace") as fh:
                        log_text = fh.read()
                    if r.returncode != 0 or "END" not in r.stdout:
                        lines = [ln for ln in log_text.splitlines() if not ln.startswith("{")]
                        why = [ln for ln in lines if "Refusing" in ln or "ERROR" in ln] or lines[-3:]
                        raise vb.BenchError(f"the run in {mode} mode failed (exit {r.returncode}): "
                                            + " | ".join(why))
                    out = vbp.parse_client(r.stdout, kinds, n)
                    recs = vb.read_records(log_text)
                    for rec in recs:
                        if rec.get("event") == "run_start" and run_start is None:
                            run_start = rec
                    checks += [(f"round {rnd + 1} {c}", ok, det) for c, ok, det in
                               check_mode(mode, out, recs, sizes, calls)]
                    a = subprocess.run([python, audit, "--policy", policies[mode], "--checker", checker, log],
                                       capture_output=True, text=True, timeout=RUN_TIMEOUT)
                    checks.append((f"round {rnd + 1} {mode}: the audit accepts the stream", a.returncode == 0,
                                   "" if a.returncode == 0 else
                                   " | ".join(ln for ln in a.stdout.splitlines() if "PROBLEM" in ln)[:300]))
                    for s, xs in by_size(recs, "net.mcp" if mode == "mcp" else "net.request",
                                         sizes, calls, warmup).items():
                        warden_us[mode][s] += xs
                for s in sizes:
                    samples[mode][s] += out["samples"][kind(s)]
                    round_p50[mode][s].append(vb.stats(out["samples"][kind(s)])["p50"])
        rows = {}
        for s in sizes:
            st = {m: vb.stats(samples[m][s]) for m in MODES}
            nat = st["native"]["p50"]
            rows[kind(s)] = {
                "label": label(s), "bytes": s, **st,
                "added_p50_us": {m: round(st[m]["p50"] - nat, 1) for m in ("request", "mcp")},
                "held_p50_us": round(st["mcp"]["p50"] - st["request"]["p50"], 1),
                "round_p50_us": {m: round_p50[m][s] for m in MODES},
                "warden_us": {m: vb.stats(warden_us[m][s]) for m in ("request", "mcp")},
            }
        result = {
            "varek_bench_mcp": FORMAT,
            "date": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host": vb.host_info(),
            "warden": {"version": (run_start or {}).get("warden"), "path": warden,
                       "sha256": vb.sha256_file(warden),
                       "proxy_sha256": (run_start or {}).get("proxy_binary_sha256")},
            "server": {"address": addr, "port": server.port, "certificate": "RSA 2048, self-signed"},
            "settings": {"calls_per_size_per_run": n, "warmup": warmup, "rounds": rounds,
                         "run_as": run_as, "signing": bool(sign_key), "sizes": list(sizes)},
            "policy_sha256": {m: hashlib.sha256(open(policies[m], "rb").read()).hexdigest()
                              for m in policies},
            "sizes": rows,
            "checks": [{"check": c, "ok": ok, "detail": det} for c, ok, det in checks],
            "ok": all(ok for _, ok, _ in checks),
            "kept": [d, priv] if keep else None,
        }
    except subprocess.TimeoutExpired as e:
        raise vb.BenchError(f"a run took longer than {RUN_TIMEOUT} s and was stopped: {e.cmd[0]}")
    except (OSError, ValueError, IndexError) as e:
        raise vb.BenchError(f"the MCP bench could not run: {e}")
    finally:
        for x in (server, dns):
            if x:
                x.close()
        if not keep:
            for x in (d, priv):
                if x:
                    shutil.rmtree(x, ignore_errors=True)
    return result


# ------------------------------------------------------------------ report --

def format_report(res, cli_version=""):
    f, h, s = vb._f, res["host"], res["settings"]
    L = ["VAREK bench --mcp: what deciding an MCP call over HTTP costs on this host", ""]
    L.append(f"  Warden    {res['warden']['version'] or '?'}  (sha256 {res['warden']['sha256'][:12]}; "
             f"warden-proxy {str(res['warden']['proxy_sha256'] or '?')[:12]})"
             + (f"   varek command {cli_version}" if cli_version else ""))
    L.append(f"  Host      Linux {h['kernel']} {h['machine']}, {h['cpus']} CPU"
             + (f", {h['cpu_model']}" if h['cpu_model'] else "")
             + (f", {h['memory']}" if h['memory'] else ""))
    L.append(f"  Date      {res['date']}")
    L.append(f"  Server    a stand-in MCP server, HTTPS on this host's own address {res['server']['address']}")
    L.append(f"  Runs      {s['rounds']} each natively, under a request rule and as MCP calls, alternating; "
             f"{s['calls_per_size_per_run']} timed calls of each size per run, after {s['warmup']} warm-up,")
    L.append("            each size on one kept-alive connection")
    L.append("")
    L.append("  Microseconds per tools/call, as the client measured it (p50 / p99), the p50 the proxy adds,")
    L.append("  and what holding and parsing the body adds (MCP rule minus request rule):")
    L.append("")
    L.append(f"  {'body':8} {'native':>13}   {'request rule':>13} {'added':>8}   {'MCP rule':>13} "
             f"{'added':>8}   {'held':>8}")
    for k, r in res["sizes"].items():
        def cell(m):
            return f"{f(r[m]['p50']):>6} {f(r[m]['p99']):>6}"
        a = r["added_p50_us"]
        L.append(f"  {r['label']:8} {cell('native')}   {cell('request')} {vb._signed(a['request']):>8}   "
                 f"{cell('mcp')} {vb._signed(a['mcp']):>8}   {vb._signed(r['held_p50_us']):>8}")
    L.append("")
    L.append("  The Warden's own time per decision, from its records (p50 / p99 us):")
    L.append(f"    {'body':8} {'a request decided':>20} {'an MCP call decided':>22}")
    for k, r in res["sizes"].items():
        w = r["warden_us"]
        L.append(f"    {r['label']:8} {f(w['request'].get('p50')):>10} {f(w['request'].get('p99')):>9} "
                 f"{f(w['mcp'].get('p50')):>12} {f(w['mcp'].get('p99')):>9}")
    L.append("")
    failed = [c for c in res["checks"] if not c["ok"]]
    if failed:
        L.append(f"  CHECKS FAILED ({len(failed)} of {len(res['checks'])}):")
        for c in failed[:12]:
            L.append(f"    FAIL  {c['check']}: {c['detail']}")
    else:
        L.append(f"  Verdicts  all {len(res['checks'])} checks passed: every call was answered with its own id,")
        L.append("            each decided and certified (as an MCP call with its body's length and SHA-256")
        L.append("            under the MCP rule), and the audit accepted every stream.")
    L.append("")
    L.append("  Notes")
    L.append("  - Under a request rule the proxy decides the request on its head and streams the body;")
    L.append("    under an MCP rule it holds the body until it has read and parsed all of it, then")
    L.append("    decides the call and sends it, so the held column grows with the body.")
    L.append("  - 1 MiB is the default max_body of an MCP rule; a larger call needs max_body= on its rule.")
    L.append("  - The server is on this host: a real server's network time is not in these numbers.")
    return "\n".join(L) + "\n"
