# SPDX-License-Identifier: MIT
# VAREK v1.6.0 — ExecutionPlan verification kernel

CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow \
           -Wstrict-prototypes -Wmissing-prototypes

CORE_SRC := execution_plan.c plan_evaluator.c
CORE_HDR := execution_plan.h execution_plan_internal.h

DEMO  := plan_demo

TESTS := tests/test_evaluator \
         tests/test_symmetric_suppression \
         tests/test_order_invariance \
         tests/test_fanout \
         tests/test_cycle_detection

.PHONY: all check demo clean

all: $(DEMO) $(TESTS)

$(DEMO): plan_demo.c $(CORE_SRC) $(CORE_HDR)
	$(CC) $(CFLAGS) -o $@ plan_demo.c $(CORE_SRC)

tests/%: tests/%.c $(CORE_SRC) $(CORE_HDR)
	$(CC) $(CFLAGS) -I. -o $@ $< $(CORE_SRC)

demo: $(DEMO)
	./$(DEMO)

check: $(TESTS)
	@set -e; for t in $(TESTS); do echo "-- $$t"; ./$$t; done
	@echo "all tests passed"

clean:
	rm -f $(DEMO) $(TESTS)
