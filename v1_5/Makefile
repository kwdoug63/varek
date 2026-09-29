# SPDX-License-Identifier: MIT
#
# VAREK v1.5 — SMT probe build
#
# The two SMT probes link the reference off-the-shelf SMT solver's C library;
# `make deps` installs it (fast_match needs nothing).

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wno-unused-parameter \
           -D_GNU_SOURCE -std=gnu11
LDFLAGS ?=
LDLIBS  ?= -lz3

BIN  := smt_probe
BIN2 := smt_probe2
BIN3 := fast_match

.PHONY: all clean run deps check-solver

all: $(BIN) $(BIN2) $(BIN3)

$(BIN): smt_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

$(BIN2): smt_probe2.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

$(BIN3): fast_match.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

deps:
	@if command -v apt-get >/dev/null 2>&1; then sudo apt-get install -y libz3-dev; \
	elif command -v dnf >/dev/null 2>&1; then sudo dnf install -y z3-devel; \
	else echo "install the solver's C development package with your package manager"; exit 1; fi

check-solver:
	@if ! ldconfig -p | grep -q libz3; then \
		echo "ERROR: the solver's C library is not installed; run: make deps"; \
		exit 1; \
	fi
	@echo "OK: solver library present"

run: $(BIN)
	./$(BIN) 10000 2> bench.log
	@echo
	@echo "Run summarizer: python3 ../v1_4/bench_summarize.py bench.log"

clean:
	rm -f $(BIN) $(BIN2) $(BIN3) bench.log bench2.log bench_fast.log
