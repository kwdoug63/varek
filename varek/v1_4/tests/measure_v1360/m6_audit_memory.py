# SPDX-License-Identifier: MIT
"""v1.36 step 1, M6 (docs/security/v1.36-kubernetes-parity.md, D9): where
the audit's memory goes, check by check.

  sudo python3 m6_audit_memory.py --records 1000000 --out /var/tmp/m6out

Makes a stream with the Warden (an agent held to its plan: allowed opens,
refusals by the policy and outside the plan, launches), then audits it in
this process with each of the audit's functions wrapped. For each function
main calls it records the resident memory before and after, and the peak
while it ran (the kernel's high-water mark, reset before each call through
/proc/self/clear_refs). It also sizes the parsed records themselves. The
checker runs in its own process and is not counted."""
import argparse
import functools
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
V14 = os.path.dirname(os.path.dirname(HERE))

AGENT = '''import os, subprocess, sys
n = int(sys.argv[1])
def touch(p):
    try:
        os.close(os.open(p, os.O_RDONLY))
    except OSError:
        pass
for i in range(n):
    touch("/etc/hostname")
    if i % 10 == 0:
        touch("/etc/shadow")    # the policy refuses it
        touch("/etc/hosts")     # the policy allows it, the plan does not
    if i % 500 == 0:
        subprocess.run(["/usr/bin/true"])
'''


def status(field):
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith(field + ":"):
                return int(line.split()[1])      # kB
    return 0


def reset_peak():
    try:
        with open("/proc/self/clear_refs", "w") as f:
            f.write("5")
    except OSError:
        pass


def make_stream(work, out, records):
    os.makedirs(work, exist_ok=True)
    py = os.path.realpath(sys.executable if os.path.basename(sys.executable).startswith("python3")
                          else "/usr/bin/python3")
    with open(os.path.join(work, "agent.py"), "w") as f:
        f.write(AGENT)
    with open(os.path.join(work, "m6.policy"), "w") as f:
        f.write(f"require warden 1.35\nallow exec {py}\nallow exec /usr/bin/true\n"
                "allow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n"
                "allow path /etc/hostname readonly\nallow path /etc/hosts readonly\n"
                f"allow path {work}/ readonly\nallow path /proc/ readonly\nallow path /dev/null\n")
    with open(os.path.join(work, "m6.plan"), "w") as f:
        f.write(f"plan 1.35\naction x1 process_exec {py}\naction x2 process_exec /usr/bin/true\n"
                "action f1 file_open /usr/ open=read\naction f2 file_open /lib/ open=read\n"
                "action f3 file_open /etc/ld.so.cache open=read\naction f4 file_open /etc/hostname open=read\n"
                f"action f5 file_open {work}/ open=read\naction f6 file_open /proc/ open=read\n"
                "action f7 file_open /dev/null\n")
    for n in ("agent.py", "m6.policy", "m6.plan"):
        os.chmod(os.path.join(work, n), 0o644)
    # about 1.2 records a turn (measured): turns for the records asked
    turns = max(1, int(records / 1.2))
    stream = os.path.join(out, "m6.log")
    t = time.time()
    with open(stream, "wb") as err:
        rc = subprocess.run([os.path.join(V14, "warden"), os.path.join(work, "m6.policy"),
                             "--plan", os.path.join(work, "m6.plan"), "--hold-to-plan", "--",
                             py, os.path.join(work, "agent.py"), str(turns)],
                            stdout=subprocess.DEVNULL, stderr=err).returncode
    return stream, os.path.join(work, "m6.policy"), os.path.join(work, "m6.plan"), rc, time.time() - t


def deep_size(o, seen=None):
    seen = seen if seen is not None else set()
    if id(o) in seen:
        return 0
    seen.add(id(o))
    n = sys.getsizeof(o)
    if isinstance(o, dict):
        n += sum(deep_size(k, seen) + deep_size(v, seen) for k, v in o.items())
    elif isinstance(o, (list, tuple, set)):
        n += sum(deep_size(v, seen) for v in o)
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=int, default=1000000)
    ap.add_argument("--out", default="/var/tmp/m6out")
    ap.add_argument("--work", default="/var/tmp/m6")
    ap.add_argument("--stream", help="audit this stream (with --policy and --plan) instead of making one")
    ap.add_argument("--policy")
    ap.add_argument("--plan")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    if a.stream:
        stream, policy, plan, rc, secs = a.stream, a.policy, a.plan, 0, 0.0
    else:
        stream, policy, plan, rc, secs = make_stream(a.work, a.out, a.records)
    nrec = 0
    kinds = {}
    with open(stream, "rb") as f:
        for line in f:
            if line.startswith(b"{"):
                nrec += 1
                try:
                    r = json.loads(line)
                    k = r.get("event") or (r.get("action", "?") + " " + str(r.get("rule", "")))
                    kinds[k] = kinds.get(k, 0) + 1
                except ValueError:
                    pass
    print(f"MEASURE stream: {nrec} records, {os.path.getsize(stream)} bytes, the Warden exit {rc}, {secs:.0f} s")

    sys.path.insert(0, os.path.join(V14, "tools"))
    import varek_audit as va                                                # noqa: E402
    rows = []
    depth = [0]

    def wrap(name, fn):
        @functools.wraps(fn)
        def w(*args, **kw):
            if depth[0]:
                return fn(*args, **kw)
            depth[0] += 1
            before = status("VmRSS")
            reset_peak()
            t = time.time()
            try:
                return fn(*args, **kw)
            finally:
                depth[0] -= 1
                rows.append((name, before, status("VmRSS"), status("VmHWM"), time.time() - t))
        return w

    for name in dir(va):
        fn = getattr(va, name)
        if callable(fn) and getattr(fn, "__module__", None) == va.__name__ and name != "main" and \
                (name.startswith(("check_", "policy_", "log_", "read_", "stub_", "_parse_log"))):
            setattr(va, name, wrap(name, fn))

    sized = {}
    orig_parse = va._parse_log

    def parse_and_size(*args, **kw):
        res = orig_parse(*args, **kw)
        recs = res[1]
        sample = recs[:: max(1, len(recs) // 2000)]
        sized["n"] = len(recs)
        sized["per_record"] = sum(deep_size(r) for r in sample) / max(1, len(sample))
        return res
    va._parse_log = wrap("_parse_log", parse_and_size)

    start_rss = status("VmRSS")
    reset_peak()
    t = time.time()
    try:
        code = va.main(["--policy", policy, "--checker", os.path.join(V14, "tools", "vdp_cert_check"),
                        "--plan", plan, stream])
    except SystemExit as e:
        code = e.code
    total = time.time() - t
    peak = status("VmHWM")
    peak = max([peak] + [r[3] for r in rows])
    print(f"MEASURE audit: exit {code}, {total:.0f} s, resident at start {start_rss} kB, peak {peak} kB "
          f"(the checker, a process of its own, not counted)")
    if sized:
        print(f"MEASURE parsed records: {sized['n']}, about {sized['per_record']:.0f} bytes each in Python "
              f"objects ({sized['n'] * sized['per_record'] / 1048576:.0f} MiB)")
    summary = {}
    for name, before, after, hwm, secs in rows:
        s = summary.setdefault(name, [0, 0, 0, 0.0, 0])
        s[0] += 1
        s[1] = max(s[1], after - before)
        s[2] = max(s[2], hwm - before)
        s[3] += secs
        s[4] = max(s[4], hwm)
    print(f"{'function':32} {'calls':>5} {'kept kB':>10} {'peak +kB':>10} {'peak kB':>10} {'s':>7}")
    for name, (calls, kept, peak_add, secs, hwm) in sorted(summary.items(), key=lambda x: -x[1][2]):
        print(f"{name:32} {calls:5} {kept:10} {peak_add:10} {hwm:10} {secs:7.1f}")
    with open(os.path.join(a.out, "m6.json"), "w") as f:
        json.dump({"records": nrec, "kinds": kinds, "rows": rows, "sized": sized, "peak_kb": peak,
                   "seconds": total, "exit": code}, f, indent=1)


if __name__ == "__main__":
    main()
