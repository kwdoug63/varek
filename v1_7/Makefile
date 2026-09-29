# SPDX-License-Identifier: MIT
# VAREK v1.7 / v1.8 — cross-action data-flow verification

CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow \
           -Wstrict-prototypes -Wmissing-prototypes
SANFLAGS ?= -fsanitize=address,undefined -g

# v1.6 kernel that this layer joins with on the node axis.
V16      := ../v1_6
V16_SRC  := $(V16)/execution_plan.c $(V16)/plan_evaluator.c
V16_HDR  := $(V16)/execution_plan.h $(V16)/execution_plan_internal.h

# v1.7.0 — flat-set data-flow kernel
# v1.7.1 — sticky posture, adapter, JSON pathology + lineage (v1.7.4)
# v1.7.2 — Warden binding
# v1.7.3 — config file format
# v1.7.4 — argument matching, lineage tracing
# v1.8.0 — declassification
# v1.8.2 — bounded-refusal breaker (v1.18.0: persistent state)
# v1.9.0 — progress-safety verifier
KERNEL_SRC  := plan_dataflow.c
ADAPTER_SRC := plan_dataflow_adapter.c plan_dataflow_pathology.c
WARDEN_SRC  := plan_warden_binding.c
CONFIG_SRC  := plan_policy_config.c
HOTL_SRC    := plan_breaker.c plan_progress.c

ALL_SRC := $(KERNEL_SRC) $(ADAPTER_SRC) $(WARDEN_SRC) $(CONFIG_SRC) $(HOTL_SRC)
ALL_HDR := plan_label.h plan_label_policy.h plan_dataflow.h \
           plan_dataflow_adapter.h plan_dataflow_pathology.h \
           plan_warden_binding.h plan_policy_config.h varek_dataflow.h \
           plan_breaker.h plan_progress.h

DEMO         := varek_demo
EXAMPLE      := warden_example

# v1.18.0: the v1.8.2 breaker and v1.9 progress tests were built by hand only;
# `make check` now runs them, and test_v118 (URL host matching, breaker state).
# v1.19.0: test_v119 (the session's refusal limit).
TESTS := tests/test_dataflow \
         tests/test_v17_1 \
         tests/test_v17_2 \
         tests/test_v17_3 \
         tests/test_v17_4 \
         tests/test_v18_0 \
         tests/test_v18_2_breaker \
         tests/test_v19_progress \
         tests/test_v118 \
         tests/test_v119

# The v1.9.2 kernel checks need libseccomp and a Linux x86_64 kernel.
SECCOMP_TESTS := tests/test_v192_abi_lockdown tests/test_v192_baseline_deny

.PHONY: all check check-seccomp demo example clean

all: $(DEMO) $(EXAMPLE) $(TESTS)

# Demo and example link the real v1.6 kernel from ../v1_6, NOT a shim.
$(DEMO): varek_demo.c $(ALL_SRC) $(V16_SRC) $(ALL_HDR) $(V16_HDR)
	$(CC) $(CFLAGS) -I. -I$(V16) -o $@ varek_demo.c $(ALL_SRC) $(V16_SRC)

$(EXAMPLE): warden_integration_example.c $(ALL_SRC) $(V16_SRC) $(ALL_HDR) $(V16_HDR)
	$(CC) $(CFLAGS) -I. -I$(V16) -o $@ warden_integration_example.c $(ALL_SRC) $(V16_SRC)

# Tests build under sanitizers, matching the v1_6/ convention.
tests/%: tests/%.c $(ALL_SRC) $(V16_SRC) $(ALL_HDR) $(V16_HDR)
	$(CC) $(CFLAGS) $(SANFLAGS) -I. -I$(V16) -o $@ $< $(ALL_SRC) $(V16_SRC)

demo: $(DEMO)
	./$(DEMO)

example: $(EXAMPLE)
	./$(EXAMPLE)

check: $(TESTS)
	@set -e; for t in $(TESTS); do echo "-- $$t"; ./$$t; done
	@echo "all tests passed"

$(SECCOMP_TESTS): tests/%: tests/%.c warden_seccomp_baseline.c warden_seccomp_baseline.h
	$(CC) -O2 -Wall -Wextra -I. -o $@ $< warden_seccomp_baseline.c -lseccomp

# v1.18.0: the v1.9.2 ABI-lockdown and baseline-deny checks on the running
# kernel (test_v191_io_uring needs the filter installed around it; the live
# Warden filter's io_uring denial is checked by varek/v1_4 test_v14_filter).
check-seccomp: $(SECCOMP_TESTS)
	@set -e; for t in $(SECCOMP_TESTS); do echo "-- $$t"; ./$$t; done
	@echo "all seccomp tests passed"

clean:
	rm -f $(DEMO) $(EXAMPLE) $(TESTS) $(SECCOMP_TESTS) *.o tests/*.o
