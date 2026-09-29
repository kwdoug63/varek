#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""compare_plan_verify.py — run two plan_verify builds on the same random
plans and report any difference in exit status or output (v1.16.3).

    python3 tests/compare_plan_verify.py OLD_BINARY NEW_BINARY [N] [SEED]

The "version" field is ignored, so an earlier build (which reported 1.9.2)
can be compared with this one. The plans use only characters that need no
JSON escaping, so the two must agree exactly; with escaping-relevant
characters the outputs are expected to differ (see test_plan_verify.sh).
"""
import os
import random
import re
import subprocess
import sys
import tempfile

KINDS = ["file_open", "net_connect", "process_exec", "teleport", "FILE_OPEN"]
TARGETS = ["/work/a", "/tmp/varek_conf/x", "/etc/passwd", "api.allowed.internal:443",
           "evil:1", "/usr/bin/x", "demo:SAT:q", "demo:UNSAT:q", "demo:unk:q",
           "DEMO:Sat:z", "/work/café"]
VERSION = re.compile(rb'"version":"[^"]*"')


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    old, new = sys.argv[1], sys.argv[2]
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 3000
    rng = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 7)
    same = diff = 0
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "plan")
        for _ in range(n):
            k = rng.randint(1, 8)
            labels = [f"n{j}" for j in range(k)]
            lines = [f"action {l} {rng.choice(KINDS)} {rng.choice(TARGETS)}" for l in labels]
            for _ in range(rng.randint(0, 10)):
                a, b = rng.sample(labels, 2) if k > 1 else (labels[0], labels[0])
                lines.append(f"edge {a} {b}")
            if rng.random() < 0.05:
                lines.append("junk line")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            o = subprocess.run([old, path], capture_output=True)
            m = subprocess.run([new, path], capture_output=True)
            if (o.returncode, VERSION.sub(b"", o.stdout)) == (m.returncode, VERSION.sub(b"", m.stdout)):
                same += 1
            else:
                diff += 1
                if diff <= 3:
                    print("DIFF:", lines, o.returncode, o.stdout, m.returncode, m.stdout)
    print(f"compare_plan_verify: {same} identical, {diff} different ({n} plans)")
    sys.exit(1 if diff else 0)


if __name__ == "__main__":
    main()
