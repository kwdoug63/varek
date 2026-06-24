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

BINS := warden target_demo bench_target

.PHONY: all clean run-demo run-bench run-plan-demo check-kernel

all: $(BINS)

warden: warden.c warden_baseline_filter.c $(V1_6_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ warden.c warden_baseline_filter.c $(V1_6_SRC) $(LDLIBS)

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

clean:
	rm -f $(BINS) bench.log
