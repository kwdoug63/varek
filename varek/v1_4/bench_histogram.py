#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
bench_histogram.py — extract histogram bin counts from a Warden bench log.

Outputs a CSV-style table of (bin_lower_us, bin_upper_us, count) suitable
for pasting directly into a chart designer. Also prints percentile markers
and a tail summary.

Usage:
  python3 bench_histogram.py bench.log
  python3 bench_histogram.py bench.log --bin-us 2 --max-us 100
"""
import argparse
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
        return 0
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_data) - 1)
    if f == c:
        return sorted_data[f]
    return sorted_data[f] + (sorted_data[c] - sorted_data[f]) * (k - f)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("--bin-us", type=int, default=2,
                    help="Bin width in microseconds (default: 2)")
    ap.add_argument("--max-us", type=int, default=100,
                    help="Right edge of main histogram (default: 100). "
                         "Tail values aggregate into final 'overflow' bin.")
    args = ap.parse_args(argv[1:])

    records = list(parse(args.logfile))
    if not records:
        print("no pathology records found", file=sys.stderr)
        return 1

    latencies = sorted(int(r.get("latency_us", 0)) for r in records)
    n = len(latencies)

    # Build bins
    bin_w = args.bin_us
    max_v = args.max_us
    n_bins = max_v // bin_w
    bins = [0] * n_bins
    overflow = 0
    for v in latencies:
        if v >= max_v:
            overflow += 1
        else:
            bins[v // bin_w] += 1

    # Output histogram table
    print(f"# Histogram of decision latency (n={n})")
    print(f"# Bin width: {bin_w} µs   |   Main range: 0–{max_v} µs")
    print(f"# bin_lower_us, bin_upper_us, count, pct_of_total")
    for i, c in enumerate(bins):
        lo = i * bin_w
        hi = (i + 1) * bin_w
        pct = 100.0 * c / n
        print(f"{lo:>4}, {hi:>4}, {c:>5}, {pct:6.2f}%")
    if overflow:
        max_observed = latencies[-1]
        pct = 100.0 * overflow / n
        print(f"{max_v:>4}+, {max_observed:>4}, {overflow:>5}, {pct:6.2f}%   (overflow / tail)")

    # Percentile markers for chart annotations
    print()
    print("# Percentile markers (chart annotations):")
    for p in (50, 90, 95, 99, 99.9):
        v = percentile(latencies, p)
        print(f"#   P{p}  = {v:.1f} µs")
    print(f"#   max  = {latencies[-1]} µs")
    print()
    print("# Reference points for context:")
    print(f"#   50 ms budget   = 50000 µs ({50000/percentile(latencies,99):.0f}x our P99)")
    print(f"#   1 ms threshold = 1000 µs   ({1000/percentile(latencies,99):.0f}x our P99)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
