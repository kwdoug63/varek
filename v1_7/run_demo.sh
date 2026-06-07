#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# run_demo.sh — build and run the VAREK v1.9 human-out-of-the-loop demo.
# target: any POSIX build host (Droplet / Codespaces / local). Run from v1_7/.
set -euo pipefail

V16="../v1_6"
CC="${CC:-cc}"
CFLAGS="-std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Wmissing-prototypes"
INC="-I. -I${V16}"
SRC="plan_dataflow.c plan_dataflow_adapter.c plan_dataflow_pathology.c \
plan_warden_binding.c plan_policy_config.c plan_breaker.c plan_progress.c"
V16SRC="${V16}/execution_plan.c ${V16}/plan_evaluator.c"

echo "building demo_hootl..."
# shellcheck disable=SC2086
"$CC" $CFLAGS $INC demo_hootl.c $SRC $V16SRC -o demo_hootl

echo "running..."
echo
./demo_hootl "${1:-hotl_policy.cfg}" "${2:-uncertified_policy.cfg}"
