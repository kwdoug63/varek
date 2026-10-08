# SPDX-License-Identifier: MIT
"""
varek_bench_proxy: what the egress proxy costs per request, on this host
(v1.26.1; `varek bench --proxy`).

The proxied kinds deferred from v1.26.0. A client (tools/bench_proxy_client.py)
makes HTTPS requests by name to a server on this host's own address, natively
and as the agent under the Warden with the proxy in SNI mode and in
inspecting mode, rounds alternating, and the report gives for each kind:

  - the time the request took natively, in SNI mode and in inspecting mode
    (percentiles of the client's own timing),
  - the time added in each mode (p50 minus the native p50),
  - the Warden's own time, from its records: a connection decided and
    dialed (net.proxy), a request decided (net.request).

Kinds: an HTTPS request on a new connection (connect, handshake, GET, the
reply), a request on a kept-alive connection (the per-request cost once a
connection is open), and a request a deny rule refuses (inspecting mode
only; natively the server answers it).

Every request's outcome is checked: allowed ones answered 200, each
connection decided and certified, in inspecting mode each request decided and
certified, the denied ones answered 403 by the proxy and never seen by the
server, and the audit (tools/varek_audit.py) accepts every stream.

Names are answered by a DNS responder inside the bench (the Warden's
--dns-server), and the server listens on this host's own address: the Warden
connects a name to no loopback address.
"""

import datetime as _dt
import hashlib
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading

import varek_bench as vb

FORMAT = 1
NAME = "bench.example.com"
RUN_TIMEOUT = 900

# (key, label, the modes it runs in)
KINDS = [
    ("https", "HTTPS request, new connection", ("native", "sni", "inspect")),
    ("request", "request on a kept-alive connection", ("native", "sni", "inspect")),
    ("denied", "request a deny rule refuses", ("native", "inspect")),
]
LABEL = {k: lab for k, lab, _ in KINDS}
MODES = ("native", "sni", "inspect")


def kinds_for(mode):
    return [k for k, _, ms in KINDS if mode in ms]


# ----------------------------------------------------------------- parsing --

def parse_client(text, kinds, n):
    """Parse bench_proxy_client's output. Raises ValueError if incomplete."""
    out = {"classes": {}, "samples": {}}
    done = False
    for line in text.splitlines():
        p = line.split()
        if not p:
            continue
        if p[0] == "CLASS" and len(p) >= 5:
            kv = dict(x.split("=", 1) for x in p[2:] if "=" in x)
            st = {}
            for item in filter(None, kv.get("status", "").split(",")):
                c, k = item.split(":")
                st[int(c)] = int(k)
            out["classes"][p[1]] = {"ok": int(kv["ok"]), "fail": int(kv["fail"]), "status": st}
        elif p[0] == "SAMPLES" and len(p) >= 2:
            out["samples"][p[1]] = [float(x) for x in p[2:]]
        elif p[0] == "END":
            done = True
    if not done:
        raise ValueError("the client's output is incomplete (no END line)")
    for k in kinds:
        if k not in out["classes"] or len(out["samples"].get(k, [])) != n:
            raise ValueError(f"the client's output has no complete '{k}' samples")
    return out


# ------------------------------------------------------------------ policy --

def compose_policy(mode, port, bench_dir):
    """The policy of a run under the Warden: the proxy on (SNI mode) or
    inspecting, the bench's name, in inspecting mode a request rule for
    /ok and a deny rule for /denied, and read-only paths for Python."""
    lines = ["# varek bench --proxy: the bench's own rules only",
             "require warden 1.26",
             "proxy inspect" if mode == "inspect" else "proxy on",
             f"proxy ports {port}",
             f"allow host {NAME}:{port}"]
    if mode == "inspect":
        lines += [f"deny request GET https://{NAME}:{port}/denied",
                  f"allow request GET https://{NAME}:{port}/ok"]
    lines += [f"allow path {d} readonly" for d in ("/usr/", "/lib/", "/lib64/", "/etc/ld.so.cache",
                                                    "/etc/ssl/", "/proc/self/", f"{bench_dir}/")]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ checks --

def check_native(run, calls):
    bad = [k for k in kinds_for("native") if run["classes"][k]["ok"] != calls]
    return [("every request is answered 200 natively", not bad,
             "" if not bad else ", ".join(f"{k}: {run['classes'][k]['status']}" for k in bad))]


def check_mode(mode, run, recs, calls, denied_seen):
    """The checks of one run under the Warden (`calls` = warm-up + timed, per
    kind), over the client's outcomes and the Warden's records."""
    out = []
    for k in kinds_for(mode):
        c = run["classes"][k]
        if k == "denied":
            ok = c["status"] == {403: calls}
            out.append((f"{mode}: every denied request answered 403 by the proxy", ok,
                        "" if ok else f"the client saw {c['status']}"))
        else:
            ok = c["ok"] == calls
            out.append((f"{mode}: every {k} request answered 200", ok,
                        "" if ok else f"the client saw {c['status']}"))
    px = [r for r in recs if r.get("action") == "net.proxy"]
    bad = [r for r in px if r.get("rule") != "proxy_dialed" or r.get("decision_final") != "ALLOW"
           or r.get("check") != "ok" or (r.get("inspected") is True) != (mode == "inspect")]
    want = calls * (2 if mode == "inspect" else 1)          # https (+ denied), each a connection
    ok = not bad and want + 1 <= len(px) <= want + 1 + calls   # + the kept-alive one(s)
    out.append((f"{mode}: each connection decided by name, dialed and certified"
                + (", and inspected" if mode == "inspect" else ""), ok,
                "" if ok else f"{len(px)} connection decisions for {want + 1} connections, "
                              f"{len(bad)} not allowed, certified and "
                              f"{'inspected' if mode == 'inspect' else 'in SNI mode'}"))
    rq = [r for r in recs if r.get("action") == "net.request"]
    if mode == "inspect":
        allowed = [r for r in rq if r.get("rule") == "request_allowed" and r.get("decision_final") == "ALLOW"
                   and r.get("check") == "ok" and r.get("target", "").endswith("/ok")]
        refused = [r for r in rq if r.get("rule") == "policy_match" and r.get("decision_final") == "DENY"
                   and r.get("target", "").endswith("/denied")]
        ok = len(allowed) == 2 * calls and len(refused) == calls and len(rq) == 3 * calls
        out.append(("inspect: each request decided: the allowed ones certified, the denied ones by "
                    "the deny rule", ok,
                    "" if ok else f"{len(allowed)} allowed and certified, {len(refused)} denied, "
                                  f"of {len(rq)} for {3 * calls} requests"))
        out.append(("inspect: the server never saw a denied request", denied_seen == 0,
                    "" if denied_seen == 0 else f"it saw {denied_seen}"))
    else:
        out.append(("sni: no request decided (SNI mode decides connections only)", not rq,
                    "" if not rq else f"{len(rq)} request records"))
    return out


# ------------------------------------------------------------------ host --

def host_address():
    """This host's own IPv4 address (the one a default route leaves by)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        a = s.getsockname()[0]
        s.close()
    except OSError:
        a = ""
    if not a or a.startswith("127.") or a == "0.0.0.0":
        raise vb.BenchError("this host has no address of its own to serve the bench on",
                            fix="the proxied bench needs an IPv4 address other than loopback")
    return a


class _Dns:
    """A DNS responder on 127.0.0.1: NAME A -> the host's address, any other
    question NXDOMAIN (AAAA of NAME: no answer)."""

    def __init__(self, addr):
        self.a = socket.inet_aton(addr)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", 0))
        self.port = self.s.getsockname()[1]
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self):
        while True:
            try:
                q, peer = self.s.recvfrom(4096)
            except OSError:
                return
            try:
                self.s.sendto(self.answer(q), peer)
            except (OSError, ValueError, IndexError, struct.error):
                pass

    def answer(self, q):
        qid, flags, qd = struct.unpack("!HHH", q[:6])
        off, labels = 12, []
        while q[off]:
            labels.append(q[off + 1:off + 1 + q[off]].decode("ascii", "replace").lower())
            off += 1 + q[off]
        qtype = struct.unpack("!H", q[off + 1:off + 3])[0]
        question = q[12:off + 5]
        name = ".".join(labels)
        rd = flags & 0x0100
        if name != NAME:
            return struct.pack("!HHHHHH", qid, 0x8180 | rd | 3, 1, 0, 0, 0) + question
        if qtype != 1:
            return struct.pack("!HHHHHH", qid, 0x8580 | rd, 1, 0, 0, 0) + question
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 3600, 4) + self.a
        return struct.pack("!HHHHHH", qid, 0x8580 | rd, 1, 1, 0, 0) + question + rr

    def close(self):
        self.s.close()


class _Server:
    """The bench's HTTPS server on the host's address: keep-alive, answers
    GET /ok and GET /denied with 200 and a few bytes, counts the paths."""

    REPLY = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n%s\r\nok"

    def __init__(self, addr, cert, key):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.l = socket.socket()
        self.l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l.bind((addr, 0))
        self.l.listen(1024)
        self.port = self.l.getsockname()[1]
        self.lock = threading.Lock()
        self.seen = {}
        threading.Thread(target=self._accept, daemon=True).start()

    def count(self, path):
        with self.lock:
            return self.seen.get(path, 0)

    def _accept(self):
        while True:
            try:
                c, _ = self.l.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            c.settimeout(30)
            c = self.ctx.wrap_socket(c, server_side=True)
            buf = b""
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                head, _, buf = buf.partition(b"\r\n\r\n")
                lines = head.split(b"\r\n")
                parts = lines[0].split()
                path = parts[1].decode(errors="replace") if len(parts) > 1 else ""
                with self.lock:
                    self.seen[path] = self.seen.get(path, 0) + 1
                close = any(ln.lower() == b"connection: close" for ln in lines[1:])
                c.sendall(self.REPLY % (b"Connection: close\r\n" if close else b""))
                if close:
                    return
        except (OSError, ssl.SSLError):
            pass
        finally:
            c.close()

    def close(self):
        self.l.close()


def _make_cert(d):
    cert, key = os.path.join(d, "server.pem"), os.path.join(d, "server.key")
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                        "-out", cert, "-days", "1", "-subj", f"/CN={NAME}",
                        "-addext", f"subjectAltName=DNS:{NAME}"], capture_output=True)
    if r.returncode != 0:
        raise vb.BenchError("could not make the bench server's certificate",
                            fix="the proxied bench needs the openssl command")
    os.chmod(cert, 0o644)
    return cert, key


# --------------------------------------------------------------------- run --

def run(warden, checker, *, n=200, warmup=20, rounds=3, run_as="nobody", sign_key=None,
        progress=None, keep=False):
    """Run the proxied bench. Returns the result dictionary."""
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
    addr = host_address()
    d = priv = dns = server = None
    try:
        d = tempfile.mkdtemp(prefix="varek-benchpx-", dir="/tmp")
        os.chmod(d, 0o755)
        client = os.path.join(d, "bench_proxy_client.py")
        shutil.copyfile(os.path.join(here, "bench_proxy_client.py"), client)
        os.chmod(client, 0o644)
        priv = vb._private_dir()
        cert, key = _make_cert(priv)
        shutil.copyfile(cert, os.path.join(d, "server.pem"))
        os.chmod(os.path.join(d, "server.pem"), 0o644)
        dns = _Dns(addr)
        server = _Server(addr, cert, key)
        policies = {}
        for mode in ("sni", "inspect"):
            policies[mode] = os.path.join(priv, f"{mode}.policy.txt")
            with open(policies[mode], "w") as fh:
                fh.write(compose_policy(mode, server.port, d))
            os.chmod(policies[mode], 0o644)
        calls = n + warmup
        samples = {m: {k: [] for k, _, _ in KINDS} for m in MODES}
        round_p50 = {m: {k: [] for k, _, _ in KINDS} for m in MODES}
        conn_us = {m: [] for m in ("sni", "inspect")}
        req_us = {"request": [], "denied": []}
        checks, run_start = [], None
        audit = os.path.join(here, "varek_audit.py")
        for rnd in range(rounds):
            order = MODES if rnd % 2 == 0 else MODES[::-1]
            for mode in order:
                progress(f"round {rnd + 1}/{rounds}: {mode}")
                kinds = kinds_for(mode)
                cargs = [python, client, NAME if mode != "native" else f"{NAME}={addr}", str(server.port),
                         "default" if mode == "inspect" else os.path.join(d, "server.pem"),
                         str(n), str(warmup)] + kinds
                if mode == "native":
                    r = subprocess.run(cargs, capture_output=True, text=True, timeout=RUN_TIMEOUT,
                                       user=uid, group=gid, extra_groups=[])
                    if r.returncode != 0:
                        raise vb.BenchError("the client failed natively: " + r.stderr.strip()[-300:])
                    out = parse_client(r.stdout, kinds, n)
                    checks += [(f"round {rnd + 1} {c}", ok, det) for c, ok, det in check_native(out, calls)]
                else:
                    log = os.path.join(priv, f"verdicts-{mode}-{rnd + 1}.log")
                    argv = [warden, policies[mode], "--dns-server", f"127.0.0.1:{dns.port}"]
                    if mode == "inspect":
                        argv += ["--trust-bundle", os.path.join(d, "server.pem")]   # the proxy user reads it
                    if sign_key:
                        argv += ["--sign-key", sign_key]
                    argv += ["--run-as", run_as, "--"] + cargs
                    seen0 = server.count("/denied")
                    with open(log, "w") as err:
                        r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=err, text=True,
                                           timeout=RUN_TIMEOUT, env={"PATH": "/usr/bin:/bin"})
                    denied_seen = server.count("/denied") - seen0
                    with open(log, encoding="utf-8", errors="replace") as fh:
                        log_text = fh.read()
                    if r.returncode != 0 or "END" not in r.stdout:
                        lines = [ln for ln in log_text.splitlines() if not ln.startswith("{")]
                        why = [ln for ln in lines if "Refusing" in ln or "ERROR" in ln] or lines[-3:]
                        raise vb.BenchError(f"the run in {mode} mode failed (exit {r.returncode}): "
                                            + " | ".join(why))
                    out = parse_client(r.stdout, kinds, n)
                    recs = vb.read_records(log_text)
                    for rec in recs:
                        if rec.get("event") == "run_start" and run_start is None:
                            run_start = rec
                    checks += [(f"round {rnd + 1} {c}", ok, det)
                               for c, ok, det in check_mode(mode, out, recs, calls, denied_seen)]
                    a = subprocess.run([python, audit, "--policy", policies[mode], "--checker", checker, log],
                                       capture_output=True, text=True, timeout=RUN_TIMEOUT)
                    checks.append((f"round {rnd + 1} {mode}: the audit accepts the stream", a.returncode == 0,
                                   "" if a.returncode == 0 else
                                   " | ".join(ln for ln in a.stdout.splitlines() if "PROBLEM" in ln)[:300]))
                    # the Warden's own time, after the warm-up
                    px = [x for x in recs if x.get("action") == "net.proxy" and "latency_us" in x]
                    conn_us[mode] += [x["latency_us"] for x in px[warmup:]]
                    if mode == "inspect":
                        rq = [x for x in recs if x.get("action") == "net.request" and "latency_us" in x]
                        ka = [x for x in rq if x.get("request_seq", 0) > 1]
                        dn = [x for x in rq if x.get("rule") == "policy_match"]
                        req_us["request"] += [x["latency_us"] for x in ka[warmup:]]
                        req_us["denied"] += [x["latency_us"] for x in dn[warmup:]]
                for k in kinds:
                    samples[mode][k] += out["samples"][k]
                    round_p50[mode][k].append(vb.stats(out["samples"][k])["p50"])
        kinds = {}
        for k, label, ms in KINDS:
            st = {m: vb.stats(samples[m][k]) if m in ms else None for m in MODES}
            nat = st["native"]["p50"]
            kinds[k] = {
                "label": label,
                **st,
                "added_p50_us": {m: round(st[m]["p50"] - nat, 1) for m in ("sni", "inspect") if st[m]},
                "round_p50_us": {m: round_p50[m][k] for m in ms},
            }
        result = {
            "varek_bench_proxy": FORMAT,
            "date": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host": vb.host_info(),
            "warden": {"version": (run_start or {}).get("warden"), "path": warden,
                       "sha256": vb.sha256_file(warden),
                       "proxy_sha256": (run_start or {}).get("proxy_binary_sha256")},
            "server": {"address": addr, "port": server.port, "certificate": "RSA 2048, self-signed"},
            "settings": {"requests_per_kind_per_run": n, "warmup": warmup, "rounds": rounds,
                         "run_as": run_as, "signing": bool(sign_key)},
            "policy_sha256": {m: hashlib.sha256(open(policies[m], "rb").read()).hexdigest()
                              for m in policies},
            "kinds": kinds,
            "warden_us": {"connection_sni": vb.stats(conn_us["sni"]),
                          "connection_inspect": vb.stats(conn_us["inspect"]),
                          "request_allowed": vb.stats(req_us["request"]),
                          "request_denied": vb.stats(req_us["denied"])},
            "checks": [{"check": c, "ok": ok, "detail": det} for c, ok, det in checks],
            "ok": all(ok for _, ok, _ in checks),
            "kept": [d, priv] if keep else None,
        }
    except subprocess.TimeoutExpired as e:
        raise vb.BenchError(f"a run took longer than {RUN_TIMEOUT} s and was stopped: {e.cmd[0]}")
    except (OSError, ValueError, IndexError) as e:
        raise vb.BenchError(f"the proxied bench could not run: {e}")
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
    L = ["VAREK bench --proxy: what the egress proxy costs per request on this host", ""]
    L.append(f"  Warden    {res['warden']['version'] or '?'}  (sha256 {res['warden']['sha256'][:12]}; "
             f"warden-proxy {str(res['warden']['proxy_sha256'] or '?')[:12]})"
             + (f"   varek command {cli_version}" if cli_version else ""))
    L.append(f"  Host      Linux {h['kernel']} {h['machine']}, {h['cpus']} CPU"
             + (f", {h['cpu_model']}" if h['cpu_model'] else "")
             + (f", {h['memory']}" if h['memory'] else ""))
    L.append(f"  Date      {res['date']}")
    L.append(f"  Server    HTTPS on this host's own address {res['server']['address']} "
             f"({res['server']['certificate']}); the client verifies it, or the run's CA")
    L.append(f"  Runs      {s['rounds']} each natively, in SNI mode and in inspecting mode, alternating; "
             f"{s['requests_per_kind_per_run']} timed requests of each kind per run, after {s['warmup']} warm-up")
    L.append("")
    L.append("  Microseconds per request, as the client measured it (p50 / p99), and the p50 added:")
    L.append("")
    L.append(f"  {'':36} {'native':>11}   {'SNI mode':>11} {'added':>7}   {'inspecting':>11} {'added':>7}")
    for k, label, ms in KINDS:
        r = res["kinds"][k]

        def cell(m):
            return f"{f(r[m]['p50']):>5} {f(r[m]['p99']):>5}" if r.get(m) else f"{'-':>11}"
        add = r["added_p50_us"]
        L.append(f"  {label:36} {cell('native')}   {cell('sni')} "
                 f"{(vb._signed(add['sni']) if 'sni' in add else '-'):>7}   {cell('inspect')} "
                 f"{(vb._signed(add['inspect']) if 'inspect' in add else '-'):>7}")
    L.append("")
    w = res["warden_us"]
    L.append("  The Warden's own time, from its records (p50 / p99 us):")
    for key, label in (("connection_sni", "a connection decided and dialed, SNI mode"),
                       ("connection_inspect", "a connection decided and dialed, inspecting"),
                       ("request_allowed", "a request decided and certified"),
                       ("request_denied", "a request refused by a deny rule")):
        L.append(f"    {label:46} {f(w[key].get('p50')):>6} {f(w[key].get('p99')):>6}")
    L.append("")
    failed = [c for c in res["checks"] if not c["ok"]]
    if failed:
        L.append(f"  CHECKS FAILED ({len(failed)} of {len(res['checks'])}):")
        for c in failed[:12]:
            L.append(f"    FAIL  {c['check']}: {c['detail']}")
    else:
        L.append(f"  Verdicts  all {len(res['checks'])} checks passed: every allowed request was answered and")
        L.append("            certified, every denied one refused by the proxy and never sent, and the audit")
        L.append("            accepted every stream.")
    L.append("")
    L.append("  Notes")
    L.append("  - A new connection in inspecting mode adds a second TLS handshake (the client's, with")
    L.append("    the run's CA) after the proxy verifies the server; on a kept-alive connection only")
    L.append("    the request's own decision is added.")
    L.append("  - Natively the denied request is answered by the server; under the Warden it is")
    L.append("    refused before a byte of it is sent, so its row is not a like-for-like cost.")
    L.append("  - The server is on this host: a real server's network time is not in these numbers,")
    L.append("    so the share the proxy adds to a real request is smaller.")
    return "\n".join(L) + "\n"
