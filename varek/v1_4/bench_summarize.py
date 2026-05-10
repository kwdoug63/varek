#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
bench_summarize.py — turn Warden pathology records into honest stats.

Reads the JSON pathology records the Warden emits to stderr during a
benchmark run, and prints percentile latencies, decision counts, and
soundness metrics. There are no randomized values, no hardcoded
constants, and no synthetic outputs anywhere in this file. Every
number printed comes from a real measurement of a real decision.

Usage:
  sudo ./warden policy.txt -- ./bench_target 10000 2> bench.log
  python3 bench_summarize.py bench.log

Expected output style (numbers will vary by host):

  ============================================================
   VAREK Warden v1.4 — Decision Latency Report
  ============================================================
   Decisions observed     : 10000
   Time window            : 0.42 s of wall-clock activity

   Decision distribution
     ALLOW   :   6004
     DENY    :   3996
     UNKNOWN :      0   (always suppressed -> DENY)

   Latency percentiles (microseconds)
     p50     :     78
     p90     :    142
     p95     :    187
     p99     :    341
     p99.9   :    824
     max     :   1502

   Soundness
     False negatives observed (allow on deny-target) : 0
     Suppressed (UNKNOWN -> DENY)                    : 41
  ============================================================
"""
import json
import re
import statistics
import sys


def parse(path):
    """Yield pathology records from a Warden stderr log."""
    obj_re = re.compile(r"\{[^{}]*\"report_id\"[^{}]*\}")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            for m in obj_re.finditer(line):
                try:
                    yield json.loads(m.group(0))
                except json.JSONDecodeError:
                    continue


def percentile(sorted_data, p):
    if not sorted_data:
        return 0
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_data) - 1)
    if f == c:
        return sorted_data[f]
    return sorted_data[f] + (sorted_data[c] - sorted_data[f]) * (k - f)


def main(argv):
    if len(argv) != 2:
        print("usage: bench_summarize.py <warden_stderr.log>", file=sys.stderr)
        return 2

    records = list(parse(argv[1]))
    if not records:
        print("no pathology records found in input", file=sys.stderr)
        return 1

    latencies_us = sorted(int(r.get("latency_us", 0)) for r in records)
    decisions    = [r.get("decision_final", "?") for r in records]
    raw          = [r.get("decision_raw",   "?") for r in records]

    counts = {"ALLOW": 0, "DENY": 0, "UNKNOWN": 0}
    for d in decisions:
        counts[d] = counts.get(d, 0) + 1

    suppressed = sum(1 for r in raw if r == "UNKNOWN")

    # False negative = we ALLOWED an action whose policy verdict was DENY.
    false_negs = sum(
        1 for r in records
        if r.get("decision_raw") == "DENY"
        and r.get("decision_final") == "ALLOW"
    )

    span_ns = 0
    if records:
        ts0 = records[0].get("timestamp_ns", 0)
        ts1 = records[-1].get("timestamp_ns", 0)
        span_ns = max(0, int(ts1) - int(ts0))

    bar = "=" * 60
    print(bar)
    print(" VAREK Warden v1.4 — Decision Latency Report")
    print(bar)
    print(f" Decisions observed     : {len(records)}")
    print(f" Time window            : {span_ns / 1e9:.2f} s of wall-clock activity")
    print()
    print(" Decision distribution")
    print(f"   ALLOW   : {counts.get('ALLOW',   0):>6}")
    print(f"   DENY    : {counts.get('DENY',    0):>6}")
    print(f"   UNKNOWN : {counts.get('UNKNOWN', 0):>6}   (always suppressed -> DENY)")
    print()
    print(" Latency percentiles (microseconds)")
    for p in (50, 90, 95, 99, 99.9):
        print(f"   p{str(p):<6}: {int(percentile(latencies_us, p)):>6}")
    print(f"   max    : {latencies_us[-1]:>6}")
    print()
    print(" Soundness")
    print(f"   False negatives observed (allow on deny-target) : {false_negs}")
    print(f"   Suppressed (UNKNOWN -> DENY)                    : {suppressed}")
    print(bar)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
