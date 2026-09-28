# SPDX-License-Identifier: MIT
#
# VAREK Warden v1.4 reference build.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wno-unused-parameter \
           -D_GNU_SOURCE -std=gnu11
LDFLAGS ?=
LDLIBS  ?= -lseccomp

# v1.6 plan-graph integration. The Warden references these symbols
# directly; -I../../v1_6 lets warden.c #include the v1.6 headers.
V1_6_DIR  := ../../v1_6
V1_6_SRC  := $(V1_6_DIR)/execution_plan.c \
             $(V1_6_DIR)/plan_evaluator.c \
             $(V1_6_DIR)/warden_adapter.c \
             $(V1_6_DIR)/pathology.c \
             $(V1_6_DIR)/plan_parser.c
CFLAGS    += -I$(V1_6_DIR)

# v1.9.3 lifecycle coupling (supervisor/target lifetime).
V1_7_DIR  := ../../v1_7
LIFECYCLE := $(V1_7_DIR)/warden_lifecycle.c
CFLAGS    += -I$(V1_7_DIR)

BINS := warden target_demo bench_target tools/vdp_check

.PHONY: all clean run-demo run-bench run-plan-demo run-conformance check-kernel test-lifecycle test-v112 test-v1121 test-v1122 test-v1123 test-v1124 test-v1130 test-v1140 crosscheck harness video-v112

all: $(BINS)

warden: warden.c warden_baseline_filter.c smt_decide.c smt_decide.h $(LIFECYCLE) $(V1_6_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ warden.c warden_baseline_filter.c smt_decide.c $(LIFECYCLE) $(V1_6_SRC) $(LDLIBS)

# v1.13: command-line front end to the SMT decision procedure (lint, analyze,
# batch queries); the same smt_decide.c the Warden runs.
tools/vdp_check: tools/vdp_check.c smt_decide.c smt_decide.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tools/vdp_check.c smt_decide.c

target_demo: target_demo.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

bench_target: bench_target.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

check-kernel:
	@uname -r | awk -F. '{ \
	  if ($$1 < 5 || ($$1 == 5 && $$2 < 14)) { \
	    print "WARN: kernel " $$0 " < 5.14 — SECCOMP_ADDFD_FLAG_SEND missing"; \
	    exit 1; \
	  } else { \
	    print "OK:   kernel " $$0 " supports required seccomp features"; \
	  } \
	}'

run-demo: warden target_demo
	@sudo ./warden policy.txt -- ./target_demo

run-plan-demo: warden target_demo
	@sudo ./warden policy.txt --plan $(V1_6_DIR)/sample_plan.txt -- ./target_demo

run-bench: warden bench_target
	@sudo ./warden policy.txt -- ./bench_target 10000 2> bench.log
	@python3 bench_summarize.py bench.log

# v1.9.3 lifecycle coupling, end to end: kills the Warden (SIGKILL and
# SIGTERM) and asserts the agent and its descendants die with it.
tests/lifecycle_target: tests/lifecycle_target.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

tests/test_v193_lifecycle: tests/test_v193_lifecycle.c $(LIFECYCLE)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

test-lifecycle: warden tests/lifecycle_target tests/test_v193_lifecycle
	@sudo ./tests/test_v193_lifecycle ./warden ./policy.txt $(abspath tests/lifecycle_target)

# v1.12 mediation regression: resolve-then-decide (traversal, symlink,
# /proc/self), audit-log soundness, and datagram-egress mediation. The probe is
# built static so its own loader opens stay out of policy.
tests/v112_probe: tests/v112_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<

test-v112: warden tests/v112_probe
	@sudo ./tests/test_v112.sh ./warden tests/v112_policy.txt $(abspath tests/v112_probe)

# v1.12.1 regression: denied opens have no side effect, the verdict stream is
# authenticated (relayed agent stderr, run id, seq, framing; the exporter
# refuses forged or foreign records), and inbound networking is refused.
tests/v1121_probe: tests/v1121_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<

test-v1121: warden tests/v1121_probe
	@sudo ./tests/test_v1121.sh ./warden tests/v1121_policy.txt $(abspath tests/v1121_probe) tools/varek_cyclonedx.py

# v1.12.2 regression: threads (clone3 answers ENOSYS so libc falls back to the
# inspectable clone), wait4/waitid, the narrow ioctl allowlist, and the kill
# report. Runs the filter unit test first, then the probe under the Warden.
tests/v1122_probe: tests/v1122_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -static -pthread -o $@ $<

tests/test_v14_filter: tests/test_v14_filter.c warden_baseline_filter.c
	$(CC) $(CFLAGS) -I. $(LDFLAGS) -pthread -o $@ $^ $(LDLIBS)

test-v1122: warden tests/v1122_probe tests/test_v14_filter
	@sudo ./tests/test_v14_filter
	@sudo ./tests/test_v1122.sh ./warden tests/v1122_policy.txt $(abspath tests/v1122_probe) tools/varek_cyclonedx.py

# v1.12.3 regression: symlinks are followed and decided on the canonical path,
# so dynamically linked agents start; /proc/self maps to the agent; escapes and
# foreign /proc stay refused. The probe is built DYNAMICALLY on purpose (its own
# loader opens must succeed).
tests/v1123_probe: tests/v1123_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

test-v1123: warden tests/v1123_probe
	@sudo ./tests/test_v1123.sh ./warden tests/v1123_policy.txt $(abspath tests/v1123_probe) tools/varek_cyclonedx.py

# v1.12.4 regression: the --plan gate authorizes plans that open policy-allowed
# files again (a file_open node was always UNKNOWN from v1.12.0 because the plan
# decider never filled the resolved path the file-open decision reads). No probe:
# it drives the Warden's pre-fork --plan path directly.
test-v1124: warden
	@sudo ./tests/test_v1124.sh ./warden

# v1.13: the SMT decision procedure in the enforcement path. Flag-fragment
# enforcement under a live Warden, load-time dead-rule analysis, parser
# refusals, lint of the shipped policies, the --plan gate's symbolic flags, the
# solver cross-check and the harness gate. Needs python3 and z3-solver.
tests/v1130_probe: tests/v1130_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<

test-v1130: warden tools/vdp_check tests/v1130_probe
	@sudo ./tests/test_v1130.sh ./warden ./tools/vdp_check $(abspath tests/v1130_probe)

# v1.14: the bounded string fragment (exact / prefix / suffix / contains / glob
# matchers). Enforcement under a live Warden (on resolved paths, through a
# symlink), load-time analysis by the automaton search, parser refusals and
# v1.13 compatibility, the --plan gate, the cross-check and the harness gate.
tests/v1140_probe: tests/v1140_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<

test-v1140: warden tools/vdp_check tests/v1140_probe
	@sudo ./tests/test_v1140.sh ./warden ./tools/vdp_check $(abspath tests/v1140_probe)

# Differential check of the decision procedure against an SMT solver (Z3) and,
# for suffix / contains / glob reachability, a derivative-based oracle. These
# are exactly the runs RELEASE-v1.14.0.md quotes: every policy in the
# repository, then 300 fuzzed policies for each of seeds 1, 2 and 3.
crosscheck: tools/vdp_check
	@python3 tools/smt_crosscheck.py --vdp tools/vdp_check --queries 60 \
	    policy.txt conformance_policy.txt policies/*.txt tests/*policy*.txt
	@for seed in 1 2 3; do \
	    python3 tools/smt_crosscheck.py --vdp tools/vdp_check --fuzz 300 --seed $$seed --queries 60 || exit 1; \
	done

# Verdict-distribution harness over the (synthetic) seed corpus.
harness: tools/vdp_check
	@python3 tools/verdict_harness.py --vdp tools/vdp_check harness/corpus/

# v1.12 before/after demo, video-capture friendly (see v112_video.sh header).
# Builds the pre-fix Warden from the v1.9.3 tag and runs the same adversarial
# agent under both; every verdict on screen is read from the live Warden.
video-v112: warden tests/v112_probe
	@sudo ./v112_video.sh

# Conformance target (Test Target 1). Built static so the loader's own
# library opens stay out of policy. Creates the work directory first: the
# target cannot create it under enforcement.
CONF_DIR := /tmp/varek_conf

target_conformance: target_conformance.c
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<

run-conformance: warden target_conformance
	@install -d -m 0755 $(CONF_DIR)
	@sudo ./warden conformance_policy.txt -- $(abspath target_conformance)

clean:
	rm -f $(BINS) target_conformance bench.log tests/lifecycle_target tests/test_v193_lifecycle tests/v112_probe tests/v1121_probe tests/v1122_probe tests/v1123_probe tests/v1130_probe tests/v1140_probe tests/test_v14_filter
