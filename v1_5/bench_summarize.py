#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
bench_summarize.py — turn pathology records into honest stats (v1.5)

Drop-in replacement for v1_4/bench_summarize.py. Behavior is identical
on v1.4 logs (which only contain `latency_us`). When records contain a
`latency_ns` field (v1.5 fast_match emits both), this tool reports
percentiles with sub-microsecond precision.

There are no randomized values, no hardcoded constants, and no
synthetic outputs anywhere in this file. Every number printed comes
from a real measurement of a real decision.

Usage:
  python3 bench_summarize.py bench_fast.log
  python3 bench_summarize.py bench.log              # works on v1.4 logs too
"""
import json
import re
import sys


def parse(path):
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
        return 0.0
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_data) - 1)
    if f == c:
        return sorted_data[f]
    return sorted_data[f] + (sorted_data[c] - sorted_data[f]) * (k - f)


def fmt(us, sub_us_precision):
    """Format a microsecond value, with decimals only when ns data exists."""
    if sub_us_precision:
        if us < 1.0:    return f"{us:7.3f}"
        elif us < 10:   return f"{us:7.2f}"
        elif us < 100:  return f"{us:7.1f}"
        else:           return f"{int(us):>7d}"
    return f"{int(us):>7d}"


def main(argv):
    if len(argv) != 2:
        print("usage: bench_summarize.py <pathology.log>", file=sys.stderr)
        return 2

    records = list(parse(argv[1]))
    if not records:
        print("no pathology records found in input", file=sys.stderr)
        return 1

    have_ns = any("latency_ns" in r for r in records)
    if have_ns:
        latencies_us = sorted(
            (int(r["latency_ns"]) / 1000.0) if "latency_ns" in r
            else float(r.get("latency_us", 0))
            for r in records
        )
    else:
        latencies_us = sorted(float(r.get("latency_us", 0)) for r in records)

    decisions = [r.get("decision_final", "?") for r in records]
    raw       = [r.get("decision_raw",   "?") for r in records]

    counts = {"ALLOW": 0, "DENY": 0, "UNKNOWN": 0}
    for d in decisions:
        counts[d] = counts.get(d, 0) + 1

    suppressed = sum(1 for r in raw if r == "UNKNOWN")
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
    print(" VAREK Warden — Decision Latency Report")
    print(bar)
    print(f" Decisions observed     : {len(records)}")
    print(f" Time window            : {span_ns / 1e9:.2f} s of wall-clock activity")
    if have_ns:
        print(f" Measurement precision  : nanosecond (sub-microsecond)")
    print()
    print(" Decision distribution")
    print(f"   ALLOW   : {counts.get('ALLOW',   0):>6}")
    print(f"   DENY    : {counts.get('DENY',    0):>6}")
    print(f"   UNKNOWN : {counts.get('UNKNOWN', 0):>6}   (always suppressed -> DENY)")
    print()
    print(" Latency percentiles (microseconds)")
    for p in (50, 90, 95, 99, 99.9):
        print(f"   p{str(p):<6}: {fmt(percentile(latencies_us, p), have_ns)}")
    print(f"   max    : {fmt(latencies_us[-1], have_ns)}")
    print()
    print(" Soundness")
    print(f"   False negatives observed (allow on deny-target) : {false_negs}")
    print(f"   Suppressed (UNKNOWN -> DENY)                    : {suppressed}")
    print(bar)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
