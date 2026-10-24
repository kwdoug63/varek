# SPDX-License-Identifier: MIT
"""v1340_bpf_check.py — v1.34 step 3 (tests/test_v1340.sh): the node agent's
BPF interpreter (tests/v1340_bpf_run.c) and step 1's (v1340_bpf_compare.py)
run the Warden's filter on the same calls: every system call number, with
x32's bit and as i386, each with the values the rules compare against.

  v1340_bpf_check.py BPF_RUN FLAGS DIR     exit 0 when every call agrees"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import v1340_bpf_compare as c  # noqa: E402

run_bin, flags, d = sys.argv[1:4]
calls = []
vals = [0, 1, 2, 3, 0x40, 0x80000, 0xffffffff, 0x100000000, 0xffffffffffffffff, 0x7fffffff, 0x80000000]
for nr in range(0, 600):
    for v in vals:
        for i in range(6):
            a = [0] * 6
            a[i] = v
            for arch, n in ((c.AUDIT_ARCH_X86_64 if os.uname().machine == "x86_64" else c.AUDIT_ARCH_AARCH64, nr),
                            (c.AUDIT_ARCH_X86_64, nr | c.X32_BIT), (c.AUDIT_ARCH_I386, nr)):
                calls.append(c.data(n, arch, a))
out = subprocess.run([run_bin, flags, f"{d}/w.bpf"], input=b"".join(calls), capture_output=True, check=True).stdout.split()
prog = c.load(f"{d}/w.bpf")
bad = sum(1 for dd, got in zip(calls, out) if c.run(prog, dd) != int(got))
print(f"{len(calls)} calls, {bad} answered differently")
sys.exit(0 if bad == 0 and len(out) == len(calls) else 1)
