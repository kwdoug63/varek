# SPDX-License-Identifier: MIT
"""
varek_bench_launch: what deciding program launches costs, on this host (v1.27).

`varek bench --launches` runs tools/bench_workload's launch mode three ways,
rounds alternating: natively, under the Warden with a policy that does not
decide launches (`require warden 1.26`), and under the Warden with one that
does (`require warden 1.27`). Kinds, each timed by the workload around the
whole call:

  - launch_allowed: vfork, launch a program the policy allows, wait for it
    (under 1.27: decided on its name, certified, held to the launch set by
    Landlock, its identity checked; under 1.26 it is refused)
  - launch_denied: the same for a program a deny rule refuses
  - open_allowed: an allowed open, made between the launches (with launches
    on it follows a real launch, whose effect on the host's caches is in its
    time; `varek bench --policy` with a `require warden 1.27` base measures
    the identity check alone, about 2 to 3 us a call on the host it was
    built on)

It reports each kind's time per mode, the time added over native, and the
Warden's own time per decision (from the verdict records), and checks every
outcome: under 1.27 each allowed launch ran, was certified and has its
exec_result, each denied one was refused with EACCES, and the audit accepts
each stream; under 1.26 each launch was refused as before.

Every number is a measurement taken during the run.
"""

import datetime as _dt
import hashlib
import os
import shutil
import subprocess
import sys

import varek_bench as vb

FORMAT = 1
KINDS = [
    ("launch_allowed", "a launch the policy allows (spawn, launch, wait)"),
    ("launch_denied", "a launch a deny rule refuses"),
    ("open_allowed", "an allowed open, between launches"),
]
MODES = ("native", "off", "on")
MODE_LABEL = {"native": "native", "off": "Warden, launches off (1.26)", "on": "Warden, launches on (1.27)"}
EACCES = 13


def parse(text, kinds):
    """bench_workload's output (BENCHW, CLASS, SAMPLES, END) for these kinds."""
    out = {"n": None, "classes": {}, "samples": {}}
    done = False
    for line in text.splitlines():
        p = line.split()
        if not p:
            continue
        if p[0] == "BENCHW":
            kv = dict(x.split("=", 1) for x in p[2:] if "=" in x)
            out["n"] = int(kv["n"])
        elif p[0] == "CLASS" and len(p) >= 5:
            kv = dict(x.split("=", 1) for x in p[2:] if "=" in x)
            errnos = {}
            for item in filter(None, kv.get("errnos", "").split(",")):
                e, c = item.split(":")
                errnos[int(e)] = int(c)
            out["classes"][p[1]] = {"ok": int(kv["ok"]), "fail": int(kv["fail"]), "errnos": errnos}
        elif p[0] == "SAMPLES" and len(p) >= 2:
            out["samples"][p[1]] = [float(x) for x in p[2:]]
        elif p[0] == "END":
            done = True
    if not done or out["n"] is None:
        raise ValueError("the workload's output is incomplete (no END line)")
    for k in kinds:
        if k not in out["classes"] or len(out["samples"].get(k, [])) != out["n"]:
            raise ValueError(f"the workload's output has no complete '{k}' samples")
    return out


def compose_policy(d, launches, dynamic=False):
    lines = [f"require warden {'1.27' if launches else '1.26'}",
             f"# varek bench --launches ({'launches decided' if launches else 'launches refused as before 1.27'})",
             f"deny exec {d}/bin/denied",
             f"allow exec {d}/bin/ok",
             f"allow path {d}/allowed/ readonly"]
    if dynamic:
        lines += vb.LOADER_RULES
    return "\n".join(lines) + "\n"


def check_native(wl, calls):
    bad = [k for k, _ in KINDS if wl["classes"][k]["ok"] != calls]
    return [("every call succeeds natively", not bad,
             "" if not bad else "failed natively: " + ", ".join(f"{k} {wl['classes'][k]}" for k in bad))]


def check_on(wl, recs, d, calls):
    """Launches decided: each allowed launch ran, was decided exec_allowed and
    certified, and has its exec_result; each denied one was refused (EACCES,
    policy_match); each open succeeded."""
    out = []
    c = wl["classes"]
    ok_recs = [r for r in recs if r.get("action") == "process.exec" and r.get("resolved") == f"{d}/bin/ok"]
    den_recs = [r for r in recs if r.get("action") == "process.exec" and r.get("resolved") == f"{d}/bin/denied"]
    results = [r for r in recs if r.get("event") == "exec_result"]
    good = c["launch_allowed"]["ok"] == calls and len(ok_recs) == calls and all(
        r.get("rule") == "exec_allowed" and r.get("check") == "ok" for r in ok_recs) and len(results) == calls
    out.append(("launches on: each allowed launch ran, decided, certified, with its exec_result", good,
                "" if good else f"ran {c['launch_allowed']['ok']}/{calls}, {len(ok_recs)} records, "
                                f"{len(results)} exec_result"))
    good = c["launch_denied"]["ok"] == 0 and c["launch_denied"]["errnos"] == {EACCES: calls} and \
        len(den_recs) == calls and all(r.get("rule") == "policy_match" for r in den_recs)
    out.append(("launches on: each denied launch refused (EACCES, the deny rule)", good,
                "" if good else f"{c['launch_denied']}, {len(den_recs)} records"))
    out.append(("launches on: each open succeeded", c["open_allowed"]["ok"] == calls,
                "" if c["open_allowed"]["ok"] == calls else str(c["open_allowed"])))
    out.append(("launches on: no process killed by the identity check",
                not any(r.get("rule") == "exec_identity_mismatch" for r in recs), ""))
    return out


def check_off(wl, recs, calls):
    """Launches not decided (1.26): every launch refused as before, opens fine."""
    c = wl["classes"]
    refused = [r for r in recs if r.get("action") == "process.exec" and r.get("rule") == "deny_only_nonfile_v191"]
    good = c["launch_allowed"]["ok"] == 0 and c["launch_allowed"]["errnos"] == {EACCES: calls} and \
        len(refused) == calls
    return [("launches off: each launch refused as before 1.27", good,
             "" if good else f"{c['launch_allowed']}, {len(refused)} deny_only records"),
            ("launches off: each open succeeded", c["open_allowed"]["ok"] == calls, "")]


def run(warden, workload, checker, audit, *, n=200, warmup=20, rounds=3, run_as="nobody", sign_key=None,
        progress=None, keep=False):
    if not os.access(warden, os.X_OK):
        raise vb.BenchError(f"no Warden at {warden}", fix="build the runtime: `make`")
    if not os.access(workload, os.X_OK):
        raise vb.BenchError(f"no bench workload at {workload}", fix="build it: `make tools/bench_workload`")
    uid, gid = vb.resolve_user(run_as)
    progress = progress or (lambda m: None)
    dynamic = vb.is_dynamic(workload)
    d = priv = None
    try:
        d = vb._setup_dir()
        os.mkdir(os.path.join(d, "bin"), 0o755)
        for name in ("ok", "denied"):
            p = os.path.join(d, "bin", name)
            shutil.copyfile(workload, p)
            os.chmod(p, 0o755)
        priv = vb._private_dir()
        pol = {}
        for mode in ("off", "on"):
            pol[mode] = os.path.join(priv, f"bench-{mode}.policy.txt")
            with open(pol[mode], "w") as fh:
                fh.write(compose_policy(d, mode == "on", dynamic))
            os.chmod(pol[mode], 0o644)
        calls = n + warmup
        wl_args = [workload, "launch", d, str(n), str(warmup)]
        samples = {m: {k: [] for k, _ in KINDS} for m in MODES}
        decide = {m: {k: [] for k, _ in KINDS} for m in ("off", "on")}
        checks, run_start = [], None
        for rnd in range(rounds):
            order = MODES[rnd % 3:] + MODES[:rnd % 3]
            for mode in order:
                progress(f"round {rnd + 1}/{rounds}: {MODE_LABEL[mode]}")
                if mode == "native":
                    r = subprocess.run(wl_args, capture_output=True, text=True, timeout=vb.RUN_TIMEOUT,
                                       user=uid, group=gid, extra_groups=[])
                    if r.returncode != 0:
                        raise vb.BenchError("the workload failed natively: " + r.stderr.strip()[-300:])
                    wl = parse(r.stdout, [k for k, _ in KINDS])
                    checks += [(f"round {rnd + 1} native: {c}", ok, det) for c, ok, det in check_native(wl, calls)]
                else:
                    log = os.path.join(priv, f"verdicts-{mode}-{rnd + 1}.log")
                    argv = [warden, pol[mode]] + (["--sign-key", sign_key] if sign_key else []) + \
                        ["--run-as", run_as, "--"] + wl_args
                    with open(log, "w") as err:
                        r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=err, text=True,
                                           timeout=vb.RUN_TIMEOUT)
                    with open(log, encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                    if r.returncode != 0 or "END" not in r.stdout:
                        why = [ln for ln in text.splitlines() if not ln.startswith("{")][-3:]
                        raise vb.BenchError(f"the run under the Warden ({mode}) failed (exit {r.returncode}): "
                                            + " | ".join(why))
                    wl = parse(r.stdout, [k for k, _ in KINDS])
                    recs = vb.read_records(text)
                    if mode == "on" and run_start is None:
                        run_start = next((x for x in recs if x.get("event") == "run_start"), None)
                    checks += [(f"round {rnd + 1} {c}", ok, det) for c, ok, det in
                               (check_on(wl, recs, d, calls) if mode == "on" else check_off(wl, recs, calls))]
                    a = subprocess.run([sys.executable, audit, "--policy", pol[mode], "--checker", checker]
                                       + (["--pubkey", sign_key + ".pub"] if sign_key else []) + [log],
                                       capture_output=True, text=True)
                    checks.append((f"round {rnd + 1} {mode}: the audit accepts the stream", a.returncode == 0,
                                   "" if a.returncode == 0 else
                                   (a.stdout.strip().splitlines() or ["?"])[-1]))
                    # the Warden's own time per decision, timed calls only
                    exec_ok = [x for x in recs if x.get("action") == "process.exec" and x.get("resolved") == f"{d}/bin/ok"]
                    exec_den = [x for x in recs if x.get("action") == "process.exec" and x.get("resolved") == f"{d}/bin/denied"]
                    opens = [x for x in recs if x.get("action") == "file.open" and x.get("resolved") == f"{d}/allowed/f"]
                    for k, lst in (("launch_allowed", exec_ok), ("launch_denied", exec_den), ("open_allowed", opens)):
                        decide[mode][k] += [x["latency_us"] for x in lst[warmup:] if "latency_us" in x]
                for k, _ in KINDS:
                    samples[mode][k] += wl["samples"][k]
        kinds = {}
        for k, label in KINDS:
            st = {m: vb.stats(samples[m][k]) for m in MODES}
            kinds[k] = {"label": label, **st,
                        "added_p50_us": {m: round(st[m]["p50"] - st["native"]["p50"], 1) for m in ("off", "on")},
                        "warden_decision_us": {m: vb.stats(decide[m][k]) if decide[m][k] else None
                                               for m in ("off", "on")}}
        rs = run_start or {}
        return {
            "varek_bench_launch": FORMAT,
            "date": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host": vb.host_info(),
            "warden": {"version": rs.get("warden"), "sha256": vb.sha256_file(warden),
                       "landlock": rs.get("landlock")},
            "workload": {"sha256": vb.sha256_file(workload), "static": not dynamic},
            "settings": {"calls_per_kind_per_run": n, "warmup": warmup, "rounds": rounds, "run_as": run_as,
                         "signing": bool(sign_key)},
            "kinds": kinds,
            "checks": [{"check": c, "ok": ok, "detail": det} for c, ok, det in checks],
            "ok": all(ok for _, ok, _ in checks),
            "kept": [d, priv] if keep else None,
        }
    except subprocess.TimeoutExpired as e:
        raise vb.BenchError(f"a run took longer than {vb.RUN_TIMEOUT} s and was stopped: {e.cmd[0]}")
    except (OSError, ValueError, IndexError) as e:
        raise vb.BenchError(f"the bench could not run: {e}")
    finally:
        if not keep:
            for x in (d, priv):
                if x:
                    shutil.rmtree(x, ignore_errors=True)


def format_report(res, cli_version=""):
    h = res["host"]
    s = res["settings"]
    ll = (res["warden"].get("landlock") or {}).get("abi")
    out = [f"VAREK bench --launches{(' (varek ' + cli_version + ')') if cli_version else ''}, {res['date']}",
           f"Host: {h.get('cpu_model') or '?'}, {h.get('cpus')} CPUs, kernel {h.get('kernel')}; "
           f"Landlock ABI {ll if ll else 'none'}",
           f"Warden {res['warden']['version']} ({res['warden']['sha256'][:16]}...); "
           f"{s['calls_per_kind_per_run']} calls of each kind per run, {s['warmup']} warm-up, {s['rounds']} rounds, "
           f"as {s['run_as']}",
           "",
           f"{'microseconds, p50 / p99':52} {'native':>15} {'launches off':>15} {'launches on':>15}"]
    for k, _ in KINDS:
        r = res["kinds"][k]
        cells = [f"{r[m]['p50']:.0f} / {r[m]['p99']:.0f}" for m in MODES]
        out.append(f"{r['label']:52} {cells[0]:>15} {cells[1]:>15} {cells[2]:>15}")
    out.append("")
    for k, _ in KINDS:
        r = res["kinds"][k]
        dec = r["warden_decision_us"]["on"]
        out.append(f"{r['label']}: launches on add {vb._signed(r['added_p50_us']['on'])} us at p50 over native"
                   + (f"; the Warden decides it in {dec['p50']:.0f} us (p99 {dec['p99']:.0f})" if dec else ""))
    oa = res["kinds"]["open_allowed"]
    out.append(f"An allowed open between launches takes {vb._signed(round(oa['on']['p50'] - oa['off']['p50'], 1))} "
               f"us at p50 with launches on than off; that includes what a real launch does to the host's caches. "
               f"`varek bench --policy` with a `require warden 1.27` base measures the identity check alone.")
    out.append("(With launches off, every launch is refused; its row is the time to be refused.)")
    out.append("")
    bad = [c for c in res["checks"] if not c["ok"]]
    if bad:
        out += [f"  FAIL  {c['check']}: {c['detail']}" for c in bad]
    else:
        out.append(f"All {len(res['checks'])} checks passed.")
    return "\n".join(out) + "\n"
