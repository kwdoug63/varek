# SPDX-License-Identifier: MIT
# VAREK v1.6 — ExecutionPlan verification + adapter

CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow \
           -Wstrict-prototypes -Wmissing-prototypes

# v1.6.0 core
CORE_SRC := execution_plan.c plan_evaluator.c
CORE_HDR := execution_plan.h execution_plan_internal.h

# v1.6.1 adapter + pathology
ADAPTER_SRC := pathology.c warden_adapter.c plan_parser.c
ADAPTER_HDR := pathology.h plan_spec.h warden_adapter.h plan_parser.h

ALL_SRC := $(CORE_SRC) $(ADAPTER_SRC)
ALL_HDR := $(CORE_HDR) $(ADAPTER_HDR)

DEMO         := plan_demo
ADAPTER_DEMO := adapter_demo

TESTS := tests/test_evaluator \
         tests/test_symmetric_suppression \
         tests/test_order_invariance \
         tests/test_fanout \
         tests/test_cycle_detection \
         tests/test_adapter \
         tests/test_pathology \
         tests/test_plan_parser

.PHONY: all check demo adapter-demo clean

all: $(DEMO) $(ADAPTER_DEMO) $(TESTS)

$(DEMO): plan_demo.c $(CORE_SRC) $(CORE_HDR)
	$(CC) $(CFLAGS) -o $@ plan_demo.c $(CORE_SRC)

$(ADAPTER_DEMO): adapter_demo.c $(ALL_SRC) $(ALL_HDR)
	$(CC) $(CFLAGS) -o $@ adapter_demo.c $(ALL_SRC)

tests/%: tests/%.c $(ALL_SRC) $(ALL_HDR)
	$(CC) $(CFLAGS) -I. -o $@ $< $(ALL_SRC)

demo: $(DEMO)
	./$(DEMO)

adapter-demo: $(ADAPTER_DEMO)
	./$(ADAPTER_DEMO)

check: $(TESTS)
	@set -e; for t in $(TESTS); do echo "-- $$t"; ./$$t; done
	@echo "all tests passed"

clean:
	rm -f $(DEMO) $(ADAPTER_DEMO) $(TESTS)
