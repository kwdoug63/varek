# SPDX-License-Identifier: MIT
#
# VAREK v1.5 \xe2\x80\x94 SMT probe build
#
# Requires: libz3-dev installed
#   sudo apt install -y libz3-dev

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wno-unused-parameter \
           -D_GNU_SOURCE -std=gnu11
LDFLAGS ?=
LDLIBS  ?= -lz3

BIN  := smt_probe
BIN2 := smt_probe2
BIN3 := fast_match

.PHONY: all clean run check-z3

all: $(BIN) $(BIN2) $(BIN3)

$(BIN): smt_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

$(BIN2): smt_probe2.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

$(BIN3): fast_match.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

check-z3:
	@if ! ldconfig -p | grep -q libz3; then \
		echo "ERROR: libz3 not found. Install with: sudo apt install -y libz3-dev"; \
		exit 1; \
	fi
	@echo "OK: libz3 present"

run: $(BIN)
	./$(BIN) 10000 2> bench.log
	@echo
	@echo "Run summarizer: python3 ../v1_4/bench_summarize.py bench.log"

clean:
	rm -f $(BIN) $(BIN2) $(BIN3) bench.log bench2.log bench_fast.log
