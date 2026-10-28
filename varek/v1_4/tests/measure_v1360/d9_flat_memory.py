# SPDX-License-Identifier: MIT
"""v1.36 step 8 (docs/security/v1.36-kubernetes-parity.md, D9): the audit's
memory, from the stream's first record to its last.

  sudo python3 d9_flat_memory.py --records 1000000 --out /var/tmp/d9 [--reference OLD_TOOLS]

Makes a stream with the Warden as M6 does (m6_audit_memory.py: an agent held
to its plan, with allowed opens, refusals by the policy and outside the
plan, launches), or takes one (--stream, --policy, --plan), then audits it
with tools/varek_audit.py in a process of its own. Every SAMPLE_S it reads
that process's resident memory (VmRSS) and how far it has read the stream
(the stream's offset, /proc/PID/fdinfo). It passes when, while the stream
is read, the memory at the last tenth is within SLACK_KB of the memory at
the first tenth, and the audit's verdict is the reference audit's (with
--reference, the tools directory of the audit to compare with: the same
exit status, and the same report but for the time it took). The
certificate checker runs in its own processes and is not counted."""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
V14 = os.path.dirname(os.path.dirname(HERE))
SAMPLE_S = 0.2
SLACK_KB = 16 * 1024


def status(pid, field):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith(field + ":"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def offset(pid, path):
    """how far the audit has read the stream: the offset of its descriptor on it"""
    real = os.path.realpath(path)
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                if os.readlink(f"/proc/{pid}/fd/{fd}") == real:
                    with open(f"/proc/{pid}/fdinfo/{fd}") as f:
                        for line in f:
                            if line.startswith("pos:"):
                                return int(line.split()[1])
            except OSError:
                continue
    except OSError:
        pass
    return None


def audit(tools, stream, policy, plan, samples=None):
    cmd = [sys.executable, os.path.join(tools, "varek_audit.py"), "--policy", policy,
           "--checker", os.path.join(V14, "tools", "vdp_cert_check"), "--plan", plan, stream]
    t = time.time()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    peak = 0
    while p.poll() is None:
        rss, hwm, pos = status(p.pid, "VmRSS"), status(p.pid, "VmHWM"), offset(p.pid, stream)
        if hwm:
            peak = max(peak, hwm)
        if samples is not None and rss is not None and pos is not None:
            samples.append((round(time.time() - t, 2), pos, rss))
        time.sleep(SAMPLE_S)
    out = p.stdout.read()
    return p.returncode, out, peak, time.time() - t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=int, default=1000000)
    ap.add_argument("--out", default="/var/tmp/d9")
    ap.add_argument("--work", default="/var/tmp/d9work")
    ap.add_argument("--stream", help="audit this stream (with --policy and --plan) instead of making one")
    ap.add_argument("--policy")
    ap.add_argument("--plan")
    ap.add_argument("--reference", help="the tools directory of the audit to compare the verdict with")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    if a.stream:
        stream, policy, plan = a.stream, a.policy, a.plan
    else:
        sys.path.insert(0, HERE)
        import m6_audit_memory as m6
        stream, policy, plan, rc, secs = m6.make_stream(a.work, a.out, a.records)
        print(f"MEASURE stream made: the Warden exit {rc}, {secs:.0f} s")
    size = os.path.getsize(stream)
    with open(stream, "rb") as f:
        nrec = sum(1 for line in f if line.startswith(b"{"))
    print(f"MEASURE stream: {nrec} records, {size} bytes")
    samples = []
    rc, out, peak, secs = audit(os.path.join(V14, "tools"), stream, policy, plan, samples)
    print(f"MEASURE audit: exit {rc}, {secs:.0f} s, peak {peak} kB")
    print("\n".join("  " + l for l in out.strip().splitlines()[:3] + out.strip().splitlines()[-1:]))
    # the memory while the stream is read, by how far: the first and the last tenth
    read = [(pos, rss) for _, pos, rss in samples if pos < size]
    first = [rss for pos, rss in read if pos <= size * 0.1]
    last = [rss for pos, rss in read if pos >= size * 0.9]
    ok = bool(first) and bool(last)
    for k in range(1, 11):
        at = [rss for pos, rss in read if size * (k - 1) / 10 <= pos < size * k / 10]
        if at:
            print(f"MEASURE read {k * 10:3d}%: resident {max(at)} kB (at most)")
    if ok:
        grow = max(last) - min(first)
        ok = grow <= SLACK_KB
        print(f"MEASURE flat: {'yes' if ok else 'NO'}: {max(last)} kB at the last tenth, {min(first)} kB at the "
              f"first ({grow:+d} kB, at most {SLACK_KB} kB allowed)")
    else:
        print("MEASURE flat: NO: too few samples while the stream was read")
    same = None
    if a.reference:
        rrc, rout, rpeak, rsecs = audit(a.reference, stream, policy, plan)
        same = rrc == rc and rout == out
        print(f"MEASURE reference audit: exit {rrc}, {rsecs:.0f} s, peak {rpeak} kB; "
              f"the same verdict and report: {'yes' if same else 'NO'}")
        if not same:
            ok = False
    with open(os.path.join(a.out, "d9.json"), "w") as f:
        json.dump({"records": nrec, "bytes": size, "exit": rc, "seconds": secs, "peak_kb": peak,
                   "samples": samples, "same_as_reference": same}, f)
    print(f"MEASURE {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
