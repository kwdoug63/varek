# SPDX-License-Identifier: MIT
"""soak_v1340/soak_check.py's memory judgement: the size a process's growth
is judged from (mem_baseline)."""
import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("soak_check", os.path.join(HERE, "soak_v1340", "soak_check.py"))
soak_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(soak_check)
MB = 1024


def test_a_day_long_run_is_judged_from_its_first_hour():
    t0 = 1000
    xs = [(t0 + 30, 3 * MB), (t0 + 1800, 12 * MB), (t0 + 3600, 13 * MB), (t0 + 7200, 13 * MB)]
    assert soak_check.mem_baseline(xs, t0, 24) == 13 * MB


def test_the_six_minute_trial_skips_the_supervisor_before_its_run():
    # PR #117's arm64 trial: the first sample before the agents ran (2.8 MB),
    # then 12.7 MB to the end, which was read as growth
    t0 = 1000
    xs = [(t0 + 48, 2.8 * MB)] + [(t0 + 48 + 30 * i, 12.7 * MB) for i in range(1, 12)]
    base = soak_check.mem_baseline(xs, t0, 0.1)
    assert base == 12.7 * MB
    assert not xs[-1][1] > 1.5 * base + 4096
    # growth after the first third is still found
    grown = xs[:-1] + [(xs[-1][0], 30 * MB)]
    assert grown[-1][1] > 1.5 * soak_check.mem_baseline(grown, t0, 0.1) + 4096


def test_a_run_with_no_sample_after_its_warm_up_uses_its_first():
    t0 = 1000
    xs = [(t0 + 10, 5 * MB), (t0 + 20, 6 * MB)]
    assert soak_check.mem_baseline(xs, t0, 24) == 5 * MB
