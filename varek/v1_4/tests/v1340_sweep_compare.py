#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1340_sweep_compare.py OUT KNOWN SUITE... — v1.34 step 7: each suite's
checks in the host run and in the node run of tests/v1340_sweep.sh,
compared. A check is a suite's line "PASS ...", "FAIL ..." or "SKIP ..." (as
the suites print them); the same text twice in a suite is matched in order, its figures masked;
in a pytest suite, each "FAILED path::test" line (a test the host passed,
when the host run passed, is a difference).

Each check is:
  held       passed on both;
  differs    passed on the host, not in the node run: listed in KNOWN with
             its reason (a tab-separated line: SUITE, a regular expression on
             the check's text, the reason), or a failure;
  both fail  failed on the host too (the host run's own failure);
  node only  passed in the node run alone (said, not a failure).
The calls each suite made of the Warden (OUT/calls.jsonl) are counted:
carried to the node agent, or passed through to the Warden and why. A KNOWN
line that matches no difference is said, so the list stays true.
Exit status 1 for an unlisted difference or a suite failed on the host."""
import collections
import json
import os
import re
import sys

CHECK = re.compile(r"^\s*(?:note\s+)?(PASS|FAIL|SKIP)\b[\s:]*(.*?)\s*$")
PYTEST_FAILED = re.compile(r"^FAILED (\S+)")      # a pytest suite's failures (test-cli)


def checks(path):
    out, seen = [], collections.Counter()
    if not os.path.exists(path):
        return out
    for line in open(path, errors="replace"):
        f = PYTEST_FAILED.match(line)
        if f:
            out.append((("pytest " + f.group(1), 1), "FAIL"))
            continue
        m = CHECK.match(line)
        if not m or not m.group(2):
            continue
        # a check's figures (times, counts) are not its identity
        text = re.sub(r"\d+", "#", re.sub(r"\s+", " ", m.group(2)))
        seen[text] += 1
        out.append(((text, seen[text]), m.group(1)))
    return out


def rc(path):
    try:
        return int(open(path).read().strip())
    except (OSError, ValueError):
        return None


def main():
    out, known_file, suites = sys.argv[1], sys.argv[2], sys.argv[3:]
    known = []
    if os.path.exists(known_file):
        for line in open(known_file):
            if line.strip() and not line.startswith("#"):
                s, rx, why = (line.rstrip("\n").split("\t") + ["", ""])[:3]
                known.append([s, re.compile(rx), why, 0])
    calls = collections.defaultdict(lambda: collections.Counter())
    if os.path.exists(os.path.join(out, "calls.jsonl")):
        for line in open(os.path.join(out, "calls.jsonl")):
            try:
                c = json.loads(line)
            except ValueError:
                continue
            calls[c["suite"]][(c["kind"], c["why"])] += 1
    bad = 0
    rows, notes = [], []
    tot = collections.Counter()
    for s in suites:
        h = dict(checks(os.path.join(out, "host", s + ".log")))
        n = dict(checks(os.path.join(out, "node", s + ".log")))
        hrc, nrc = rc(os.path.join(out, "host", s + ".rc")), rc(os.path.join(out, "node", s + ".rc"))
        c = collections.Counter()
        for k, hv in h.items():
            nv = n.get(k, "MISSING")
            if hv == "PASS" and nv == "PASS":
                c["held"] += 1
            elif hv == "PASS":
                why = next((kn for kn in known if kn[0] == s and kn[1].search(k[0])), None)
                if why:
                    why[3] += 1
                    c["known"] += 1
                    notes.append("  %-16s differs (%s): %s\n%-20s why: %s" % (s, nv, k[0][:110], "", why[2]))
                else:
                    c["unlisted"] += 1
                    bad += 1
                    notes.append("  %-16s DIFFERS, no reason listed (%s): %s" % (s, nv, k[0][:110]))
            elif hv == "FAIL":
                c["both fail" if nv != "PASS" else "node only"] += 1
            elif hv == "SKIP":
                c["skipped"] += 1
        for k, nv in n.items():
            if k not in h and nv == "PASS":
                c["node only"] += 1
            elif k not in h and k[0].startswith("pytest ") and hrc == 0:
                # a pytest test failed in the node run alone (the host's passed)
                why = next((kn for kn in known if kn[0] == s and kn[1].search(k[0])), None)
                if why:
                    why[3] += 1
                    c["known"] += 1
                    notes.append("  %-16s differs (FAIL): %s\n%-20s why: %s" % (s, k[0][:110], "", why[2]))
                else:
                    c["unlisted"] += 1
                    bad += 1
                    notes.append("  %-16s DIFFERS, no reason listed (FAIL): %s" % (s, k[0][:110]))
        carried = sum(v for (kind, _), v in calls[s].items() if kind == "carried")
        passed = sum(v for (kind, _), v in calls[s].items() if kind == "passed")
        if hrc not in (0, None):
            bad += 1
            notes.append("  %-16s FAILED ON THE HOST (rc=%s): the host run's own failure, see host/%s.log" % (s, hrc, s))
        rows.append((s, hrc, nrc, c, carried, passed))
        tot.update(c)
        tot["carried"] += carried
        tot["passed"] += passed
    print("%-18s %4s %4s %6s %6s %6s %6s %6s %6s %8s %7s" % ("SUITE", "HOST", "NODE", "HELD", "KNOWN", "UNLIST", "BOTHF", "NODE+", "SKIP",
                                                             "CARRIED", "PASSED"))
    for s, hrc, nrc, c, carried, passed in rows:
        print("%-18s %4s %4s %6d %6d %6d %6d %6d %6d %8d %7d" % (s, hrc, nrc, c["held"], c["known"], c["unlisted"], c["both fail"],
                                                                 c["node only"], c["skipped"], carried, passed))
    print("%-18s %4s %4s %6d %6d %6d %6d %6d %6d %8d %7d" % ("total", "", "", tot["held"], tot["known"], tot["unlisted"], tot["both fail"],
                                                             tot["node only"], tot["skipped"], tot["carried"], tot["passed"]))
    print()
    print("Calls passed through to the Warden, by why:")
    why = collections.Counter()
    for s in suites:
        for (kind, w), v in calls[s].items():
            if kind == "passed":
                why[re.sub(r"\(.*\)", "(...)", w)] += v
    for w, v in why.most_common():
        print("  %5d  %s" % (v, w))
    if notes:
        print()
        print("Checks that differ:")
        print("\n".join(notes))
    unused = [k for k in known if k[3] == 0 and k[0] in suites]
    if unused:
        print()
        print("Listed differences no check showed (the list to be corrected):")
        for k in unused:
            print("  %-16s %s" % (k[0], k[1].pattern))
    print()
    print("v1340_sweep: %s" % ("PASS" if bad == 0 else "FAIL (%d)" % bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
