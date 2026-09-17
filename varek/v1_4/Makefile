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

BINS := warden target_demo bench_target

.PHONY: all clean run-demo run-bench run-plan-demo run-conformance check-kernel test-lifecycle test-v112

all: $(BINS)

warden: warden.c warden_baseline_filter.c $(LIFECYCLE) $(V1_6_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ warden.c warden_baseline_filter.c $(LIFECYCLE) $(V1_6_SRC) $(LDLIBS)

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
	rm -f $(BINS) target_conformance bench.log tests/lifecycle_target tests/test_v193_lifecycle tests/v112_probe
