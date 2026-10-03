# SPDX-License-Identifier: MIT
"""
varek_bench: what the Warden's mediation costs per call, on this host (v1.22).

`varek bench` runs a fixed workload (tools/bench_workload) natively and as the
agent under the Warden, alternating, and reports for each kind of call:

  - the time the call took natively and under the Warden (percentiles of the
    agent's own CLOCK_MONOTONIC timing around the system call),
  - the time added (Warden p50 minus native p50),
  - the Warden's own time for the decision, from its verdict records
    (latency_us; for a connect it includes the dial, dial_us),

and checks that every call got the verdict the policy promises: allowed calls
succeed and are certified, denied and unmatched calls are refused, and the
listener behind the denied destination is never reached.

Every number in the report is a measurement taken during the run. Nothing is
estimated, extrapolated or carried over from another host.

This module holds the logic; the `varek` command calls run() and formats the
result. The pure functions (parsing, percentiles, checks, the report) are
tested without root in tests/test_varek_bench.py.
"""

import datetime as _dt
import hashlib
import json
import math
import os
import platform
import pwd
import shutil
import subprocess
import tempfile

FORMAT = 1

# (key, label in the report)
KINDS = [
    ("open_allowed", "open, allowed (read)"),
    ("open_denied", "open, denied by a rule"),
    ("open_unknown", "open, no rule (UNKNOWN)"),
    ("connect_allowed", "connect, allowed (dialed)"),
    ("connect_denied", "connect, denied by a rule"),
    ("request", "request (connect + 1 KiB reply)"),
]
LABEL = dict(KINDS)

# What the Warden must decide for each kind: (decision_raw, decision_final).
EXPECT = {
    "open_allowed": ("ALLOW", "ALLOW"),
    "open_denied": ("DENY", "DENY"),
    "open_unknown": ("UNKNOWN", "DENY"),
    "connect_allowed": ("ALLOW", "ALLOW"),
    "connect_denied": ("DENY", "DENY"),
    "request": ("ALLOW", "ALLOW"),
}
REFUSED = {"open_denied", "open_unknown", "connect_denied"}
DIALED = {"connect_allowed", "request"}   # the Warden dials these; dial_us is reported
EACCES = 13
RUN_TIMEOUT = 900                         # seconds, per run; a stuck run fails the bench

# Read-only loader paths, added only when the workload is dynamically linked
# and no base policy is used (a static workload makes no loader opens).
LOADER_RULES = [
    "allow path /etc/ld.so.cache readonly",
    "allow path /lib/ readonly",
    "allow path /lib64/ readonly",
    "allow path /usr/lib/ readonly",
    "allow path /usr/lib64/ readonly",
]


class BenchError(Exception):
    def __init__(self, msg, fix=None):
        super().__init__(msg)
        self.fix = fix


# ------------------------------------------------------------- statistics --

def pct(sorted_vals, p):
    """Nearest-rank percentile of an already sorted list (p in 0..1)."""
    if not sorted_vals:
        return None
    k = max(1, math.ceil(p * len(sorted_vals)))
    return sorted_vals[min(k, len(sorted_vals)) - 1]


def stats(vals):
    v = sorted(vals)
    if not v:
        return {"n": 0}
    return {
        "n": len(v),
        "p50": round(pct(v, 0.50), 1),
        "p90": round(pct(v, 0.90), 1),
        "p99": round(pct(v, 0.99), 1),
        "max": round(v[-1], 1),
        "mean": round(sum(v) / len(v), 1),
    }


# ----------------------------------------------------------------- parsing --

def parse_workload(text):
    """Parse bench_workload's output. Raises ValueError if it is incomplete."""
    out = {"n": None, "warmup": None, "classes": {}, "samples": {}}
    done = False
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "BENCHW":
            kv = dict(p.split("=", 1) for p in parts[2:] if "=" in p)
            out["n"], out["warmup"] = int(kv["n"]), int(kv["warmup"])
        elif parts[0] == "CLASS" and len(parts) >= 5:
            kv = dict(p.split("=", 1) for p in parts[2:] if "=" in p)
            errnos = {}
            for item in filter(None, kv.get("errnos", "").split(",")):
                e, c = item.split(":")
                errnos[int(e)] = int(c)
            out["classes"][parts[1]] = {"ok": int(kv["ok"]), "fail": int(kv["fail"]),
                                        "errnos": errnos}
        elif parts[0] == "SAMPLES" and len(parts) >= 2:
            out["samples"][parts[1]] = [float(x) for x in parts[2:]]
        elif parts[0] == "END":
            done = True
    if not done or out["n"] is None:
        raise ValueError("the workload's output is incomplete (no END line)")
    for k, _ in KINDS:
        if k not in out["classes"] or len(out["samples"].get(k, [])) != out["n"]:
            raise ValueError(f"the workload's output has no complete '{k}' samples")
    return out


def read_records(text):
    recs = []
    for line in text.splitlines():
        if line.startswith("{"):
            try:
                recs.append(json.loads(line))
            except ValueError:
                pass
    return recs


def classify(rec, bench_dir, ports):
    """The bench kind a verdict record belongs to, or None (loader opens, the
    workload's own start-up, anything else)."""
    action, res = rec.get("action"), rec.get("resolved") or ""
    if action == "file.open":
        for k, sub in (("open_allowed", "allowed"), ("open_denied", "denied"),
                       ("open_unknown", "unknown")):
            if res == f"{bench_dir}/{sub}/f":
                return k
    elif action == "net.connect":
        for k, port in (("connect_allowed", ports["allowed"]), ("connect_denied", ports["denied"]),
                        ("request", ports["request"])):
            if res == f"127.0.0.1:{port}":
                return k
    return None


def records_by_kind(recs, bench_dir, ports, warmup):
    """Verdict records per kind, in call order: (all of them, the timed ones).
    The timed ones drop the first `warmup` of each kind (the workload's untimed
    warm-up calls); every record, warm-up included, is checked."""
    by = {k: [] for k, _ in KINDS}
    for r in sorted((r for r in recs if "decision_final" in r), key=lambda r: r.get("seq", 0)):
        k = classify(r, bench_dir, ports)
        if k:
            by[k].append(r)
    return by, {k: v[warmup:] for k, v in by.items()}


# ------------------------------------------------------------------ policy --

def bench_rules(bench_dir, ports):
    return [
        f"allow path {bench_dir}/allowed/ readonly",
        f"deny  path {bench_dir}/denied/",
        f"allow host 127.0.0.1:{ports['allowed']}",
        f"allow host 127.0.0.1:{ports['request']}",
        f"deny  host 127.0.0.1:{ports['denied']}",
    ]


def compose_policy(bench_dir, ports, base_text=None, dynamic=False):
    """The policy a bench run uses. With a base policy, its rules come first and
    the bench's rules last: rules are matched first to last, so each bench call
    is decided only after every rule of the base policy has been considered (the
    cost a real policy adds is in the numbers), and if a base rule matches a
    bench call first, the checks report the different verdict. A dynamically
    linked workload also gets read-only loader rules, after the base policy's."""
    lines = []
    if base_text is not None:
        lines.append(base_text.rstrip("\n"))
        lines.append("")
        lines.append("# ---- varek bench: rules for the bench's own files and listeners ----")
    else:
        lines.append("# varek bench: the bench's own rules only")
    if dynamic:
        lines += LOADER_RULES
    lines += bench_rules(bench_dir, ports)
    return "\n".join(lines) + "\n"


def count_rules(text):
    n = 0
    for raw in text.splitlines():
        s = raw.split("#", 1)[0].split()
        if s and s[0] in ("allow", "deny"):
            n += 1
    return n


# ------------------------------------------------------------------ checks --

def check_native(run):
    """Natively every call must succeed: same files, same listeners, no decision."""
    bad = [k for k, _ in KINDS if run["classes"][k]["fail"]]
    if bad:
        return [("every call succeeds natively", False,
                 "failed natively: " + ", ".join(
                     f"{k} ({run['classes'][k]['fail']}x, errno {run['classes'][k]['errnos']})"
                     for k in bad))]
    return [("every call succeeds natively", True, "")]


def check_warden(run, all_by_kind, calls):
    """The verdict checks for one run under the Warden, over every call of each
    kind (`calls` = warm-up + timed) and every one of their verdict records."""
    out = []
    for k, _ in KINDS:
        c = run["classes"][k]
        recs = all_by_kind[k]
        if len(recs) != calls:
            out.append((f"{k}: one verdict record per call", False,
                        f"{len(recs)} records for {calls} calls"))
            continue
        want_raw, want_final = EXPECT[k]
        wrong = [r for r in recs if (r.get("decision_raw"), r.get("decision_final")) != (want_raw, want_final)]
        if wrong:
            r = wrong[0]
            line = r.get("policy_line", -1)
            where = f" (policy line {line})" if isinstance(line, int) and line >= 0 else ""
            out.append((f"{k}: decided {want_raw}", False,
                        f"{len(wrong)} decided {r.get('decision_raw')}/{r.get('decision_final')}{where}: "
                        "a rule of the base policy matches the bench's call first; "
                        "run with --bare to measure without it"))
            continue
        if k in REFUSED:
            ok = c["ok"] == 0 and c["errnos"] == {EACCES: calls}
            out.append((f"{k}: refused with EACCES", ok,
                        "" if ok else f"agent saw ok={c['ok']} errnos={c['errnos']}"))
        else:
            uncert = [r for r in recs if r.get("check") != "ok"]
            ok = c["fail"] == 0 and not uncert
            out.append((f"{k}: allowed, certified, and the call succeeded", ok,
                        "" if ok else f"agent failures {c['fail']} {c['errnos']}; "
                                      f"{len(uncert)} records without check=ok"))
    return out


# ------------------------------------------------------------------ host --

def host_info():
    model, mem = "", ""
    try:
        with open("/proc/cpuinfo") as fh:
            for line in fh:
                if line.startswith("model name"):
                    model = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    mem = f"{int(line.split()[1]) // 1024} MiB"
                    break
    except OSError:
        pass
    return {
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpus": os.cpu_count(),
        "cpu_model": model,
        "memory": mem,
    }


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def is_dynamic(path):
    """True if the ELF file has a program interpreter (is dynamically linked)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    if data[:4] != b"\x7fELF" or data[4] != 2:  # 64-bit only (the Warden is x86_64)
        return False
    import struct
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        if struct.unpack_from("<I", data, phoff + i * phentsize)[0] == 3:  # PT_INTERP
            return True
    return False


# --------------------------------------------------------------------- run --

def resolve_user(spec):
    """A user name, a uid, or uid:gid, as the Warden's --run-as takes it."""
    try:
        if ":" in spec:
            u, g = spec.split(":", 1)
            return int(u), int(g)
        if spec.isdigit():
            uid = int(spec)
            try:
                return uid, pwd.getpwuid(uid).pw_gid
            except KeyError:
                return uid, uid
        pw = pwd.getpwnam(spec)
        return pw.pw_uid, pw.pw_gid
    except (KeyError, ValueError):
        raise BenchError(f"no user '{spec}' to run the agent as",
                         fix="pass --run-as <user>, <uid> or <uid>:<gid>")


def _private_dir():
    """Root-only directory for the bench policy and verdict streams, outside
    /tmp: the Warden refuses to start if the policy would let the agent open
    its verdict stream, and a policy may well allow /tmp/."""
    for base in ("/run", "/var/tmp", None):
        if base is None or os.path.isdir(base):
            try:
                return tempfile.mkdtemp(prefix="varek-bench-", dir=base)
            except OSError:
                continue
    raise BenchError("could not create a private directory for the bench")


def _setup_dir():
    d = tempfile.mkdtemp(prefix="varek-bench-", dir="/tmp")
    os.chmod(d, 0o755)
    for sub in ("allowed", "denied", "unknown"):
        os.mkdir(os.path.join(d, sub), 0o755)
        p = os.path.join(d, sub, "f")
        with open(p, "w") as fh:
            fh.write("varek bench\n")
        os.chmod(p, 0o644)
    return d


class _Server:
    """The bench's listeners (bench_workload serve), run natively as the
    unprivileged agent user."""

    def __init__(self, workload, uid, gid):
        self.p = subprocess.Popen([workload, "serve"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True,
                                  user=uid, group=gid, extra_groups=[])
        line = self.p.stdout.readline().split()
        if len(line) != 4 or line[0] != "PORTS":
            self.close()
            raise BenchError("the bench's listeners did not start")
        self.ports = {"allowed": int(line[1]), "denied": int(line[2]), "request": int(line[3])}

    def accepts(self):
        self.p.stdin.write("count\n")
        self.p.stdin.flush()
        parts = self.p.stdout.readline().split()
        if len(parts) != 4 or parts[0] != "ACCEPTS":
            raise BenchError("the bench's listeners stopped answering")
        return {"allowed": int(parts[1]), "denied": int(parts[2]), "request": int(parts[3])}

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()


def run(warden, workload, *, base_policy=None, base_label=None, n=2000, warmup=200, rounds=5,
        run_as="nobody", sign_key=None, progress=None, keep=False):
    """Run the bench. Returns the result dictionary (see the module docstring)."""
    if not os.access(warden, os.X_OK):
        raise BenchError(f"no Warden at {warden}", fix="build the runtime: `make`")
    if not os.access(workload, os.X_OK):
        raise BenchError(f"no bench workload at {workload}",
                         fix="build it: `make tools/bench_workload`")
    uid, gid = resolve_user(run_as)
    progress = progress or (lambda msg: None)
    dynamic = is_dynamic(workload)
    base_text = None
    if base_policy:
        with open(base_policy, encoding="utf-8", errors="replace") as fh:
            base_text = fh.read()

    d = priv = server = None
    try:
        d = _setup_dir()
        priv = _private_dir()
        server = _Server(workload, uid, gid)
        ports = server.ports
        policy_text = compose_policy(d, ports, base_text, dynamic)
        policy = os.path.join(priv, "bench.policy.txt")
        with open(policy, "w") as fh:
            fh.write(policy_text)
        os.chmod(policy, 0o644)

        wl_args = [workload, "run", d, str(ports["allowed"]), str(ports["denied"]),
                   str(ports["request"]), str(n), str(warmup)]
        native_s = {k: [] for k, _ in KINDS}
        warden_s = {k: [] for k, _ in KINDS}
        decide = {k: [] for k, _ in KINDS}
        dial = {k: [] for k, _ in KINDS}
        round_p50 = {"native": {k: [] for k, _ in KINDS}, "warden": {k: [] for k, _ in KINDS}}
        checks, run_start = [], None

        for rnd in range(rounds):
            order = ("native", "warden") if rnd % 2 == 0 else ("warden", "native")
            for mode in order:
                progress(f"round {rnd + 1}/{rounds}: {mode}")
                if mode == "native":
                    r = subprocess.run(wl_args, capture_output=True, text=True, timeout=RUN_TIMEOUT,
                                       user=uid, group=gid, extra_groups=[])
                    if r.returncode != 0:
                        raise BenchError("the workload failed natively: " + r.stderr.strip()[-300:])
                    wl = parse_workload(r.stdout)
                    checks += [(f"round {rnd + 1} native: {c}", ok, det)
                               for c, ok, det in check_native(wl)]
                    for k, _ in KINDS:
                        native_s[k] += wl["samples"][k]
                        round_p50["native"][k].append(stats(wl["samples"][k])["p50"])
                    continue
                before = server.accepts()
                log = os.path.join(priv, f"verdicts-{rnd + 1}.log")
                argv = [warden, policy]
                if sign_key:
                    argv += ["--sign-key", sign_key]
                argv += ["--run-as", run_as, "--"] + wl_args
                with open(log, "w") as err:
                    r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=err, text=True,
                                       timeout=RUN_TIMEOUT)
                after = server.accepts()
                with open(log, encoding="utf-8", errors="replace") as fh:
                    log_text = fh.read()
                if r.returncode != 0 or "END" not in r.stdout:
                    lines = [ln for ln in log_text.splitlines()
                             if not ln.startswith("{") and "WARNING" not in ln]
                    why = [ln for ln in lines if "Refusing" in ln or "ERROR" in ln] or lines[-3:]
                    raise BenchError("the run under the Warden failed (exit "
                                     f"{r.returncode}): " + " | ".join(why),
                                     fix="--bare measures without the policy's rules")
                wl = parse_workload(r.stdout)
                recs = read_records(log_text)
                for rec in recs:
                    if rec.get("event") == "run_start" and run_start is None:
                        run_start = rec
                all_by_kind, by_kind = records_by_kind(recs, d, ports, warmup)
                checks += [(f"round {rnd + 1} Warden: {c}", ok, det)
                           for c, ok, det in check_warden(wl, all_by_kind, n + warmup)]
                reached = after["denied"] - before["denied"]
                checks.append((f"round {rnd + 1} Warden: the denied listener was never reached",
                               reached == 0, "" if reached == 0 else f"{reached} connection(s) reached it"))
                for k, _ in KINDS:
                    warden_s[k] += wl["samples"][k]
                    round_p50["warden"][k].append(stats(wl["samples"][k])["p50"])
                    decide[k] += [r["latency_us"] for r in by_kind[k] if "latency_us" in r]
                    if k in DIALED:
                        dial[k] += [r["dial_us"] for r in by_kind[k] if "dial_us" in r]

        kinds = {}
        for k, label in KINDS:
            ns, ws = stats(native_s[k]), stats(warden_s[k])
            kinds[k] = {
                "label": label,
                "native": ns,
                "warden": ws,
                "added_p50_us": round(ws["p50"] - ns["p50"], 1),
                "round_p50_us": {"native": round_p50["native"][k],
                                 "warden": round_p50["warden"][k]},
                "warden_decision_us": stats(decide[k]),
                "dial_us": stats(dial[k]) if dial[k] else None,
            }
        result = {
            "varek_bench": FORMAT,
            "date": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host": host_info(),
            "warden": {
                "version": (run_start or {}).get("warden"),
                "path": warden,
                "sha256": sha256_file(warden),
            },
            "workload": {"path": workload, "sha256": sha256_file(workload), "static": not dynamic},
            "policy": {
                "base": base_label,
                "base_path": base_policy,
                "rules": count_rules(policy_text),
                "bench_rules": len(bench_rules(d, ports)),
                "sha256": hashlib.sha256(policy_text.encode()).hexdigest(),
            },
            "settings": {"calls_per_kind_per_run": n, "warmup": warmup, "rounds": rounds,
                         "run_as": run_as, "signing": bool(sign_key)},
            "kinds": kinds,
            "checks": [{"check": c, "ok": ok, "detail": det} for c, ok, det in checks],
            "ok": all(ok for _, ok, _ in checks),
            "kept": [d, priv] if keep else None,
        }
    except subprocess.TimeoutExpired as e:
        raise BenchError(f"a run took longer than {RUN_TIMEOUT} s and was stopped: {e.cmd[0]}")
    except PermissionError as e:
        raise BenchError(f"the bench could not run: {e}",
                         fix=f"the workload and its directory must be readable and executable "
                             f"by {run_as}")
    except (OSError, ValueError, IndexError) as e:
        raise BenchError(f"the bench could not run: {e}")
    finally:
        if server:
            server.close()
        if not keep:
            for x in (d, priv):
                if x:
                    shutil.rmtree(x, ignore_errors=True)
    return result


# ------------------------------------------------------------------ report --

def _f(v):
    return "-" if v is None else (f"{v:.0f}" if v >= 10 else f"{v:.1f}")


def _signed(v):
    return ("+" if v >= 0 else "-") + _f(abs(v))


def format_report(res, cli_version=""):
    h, s, pol = res["host"], res["settings"], res["policy"]
    L = []
    L.append("VAREK bench: what mediation costs per call on this host")
    L.append("")
    L.append(f"  Warden    {res['warden']['version'] or '?'}  (sha256 {res['warden']['sha256'][:12]})"
             + (f"   varek command {cli_version}" if cli_version else ""))
    L.append(f"  Host      Linux {h['kernel']} {h['machine']}, {h['cpus']} CPU"
             + (f", {h['cpu_model']}" if h['cpu_model'] else "")
             + (f", {h['memory']}" if h['memory'] else ""))
    L.append(f"  Date      {res['date']}")
    base = (f"{pol['base']} + {pol['bench_rules']} bench rules ({pol['rules']} rules)"
            if pol["base"] else f"bench rules only ({pol['rules']} rules)")
    L.append(f"  Policy    {base}, sha256 {pol['sha256'][:12]}")
    L.append(f"  Agent     runs as {s['run_as']}; verdict stream "
             f"{'signed' if s['signing'] else 'chained, unsigned'}; workload "
             f"{'static' if res['workload']['static'] else 'dynamically linked'}")
    L.append(f"  Runs      {s['rounds']} native and {s['rounds']} under the Warden, alternating; "
             f"{s['calls_per_kind_per_run']} timed calls of each kind per run, "
             f"after {s['warmup']} warm-up")
    L.append("")
    L.append("  Microseconds per call, as the agent measured it (p50 / p90 / p99):")
    L.append("")
    hdr = (f"  {'':33} {'native':>17}   {'under the Warden':>17}   {'added':>6}   "
           f"{'Warden decision':>15}")
    L.append(hdr)
    L.append(f"  {'':33} {'p50   p90   p99':>17}   {'p50   p90   p99':>17}   {'p50':>6}   "
             f"{'p50    p99':>15}")
    for k, label in KINDS:
        r = res["kinds"][k]
        n, w, dd = r["native"], r["warden"], r["warden_decision_us"]
        L.append(f"  {label:33} {_f(n['p50']):>5} {_f(n['p90']):>5} {_f(n['p99']):>5}   "
                 f"{_f(w['p50']):>5} {_f(w['p90']):>5} {_f(w['p99']):>5}   "
                 f"{_signed(r['added_p50_us']):>6}   {_f(dd.get('p50')):>6} {_f(dd.get('p99')):>6}")
    L.append("")
    spread = []
    for k, label in KINDS:
        rp = res["kinds"][k]["round_p50_us"]
        if rp["warden"]:
            spread.append(f"{k} {_f(min(rp['warden']))}-{_f(max(rp['warden']))}")
    if spread:
        L.append("  Warden p50 across runs: " + ", ".join(spread))
    con = res["kinds"]["connect_allowed"]["dial_us"]
    if con and con.get("n"):
        L.append(f"  Of the allowed connect's decision, dialing the destination took p50 {_f(con['p50'])} us.")
    L.append("")
    failed = [c for c in res["checks"] if not c["ok"]]
    if failed:
        L.append(f"  CHECKS FAILED ({len(failed)} of {len(res['checks'])}):")
        for c in failed[:12]:
            L.append(f"    FAIL  {c['check']}: {c['detail']}")
    else:
        L.append(f"  Verdicts  all {len(res['checks'])} checks passed: every allowed call was certified "
                 "and succeeded, every denied")
        L.append("            or unmatched call was refused with EACCES, and the denied listener "
                 "was never reached.")
    L.append("")
    L.append("  Notes")
    L.append("  - 'added' is the cost of a mediated call: the decision, the notification round trip")
    L.append("    to the Warden, and (for an allowed open or connect) the Warden opening the file or")
    L.append("    dialing the destination for the agent. 'Warden decision' is the Warden's own time")
    L.append("    from its verdict records, without the round trip.")
    L.append("  - Natively the denied and unmatched calls do their full work (the file opens, the")
    L.append("    connection is made); under the Warden they are refused before any of it.")
    L.append("  - An agent slows down by (mediated calls) x (added), so how much depends on how")
    L.append("    often it opens files and connects compared with the work it does in between.")
    L.append("    The request row shows one call next to a small whole request on loopback; a")
    L.append("    real network request takes far longer, so the share there is smaller.")
    L.append("  - These numbers are for this host. Compare hosts by running varek bench on each.")
    return "\n".join(L) + "\n"
