# SPDX-License-Identifier: MIT
#
# VAREK Warden v1.4 reference build.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wno-unused-parameter \
           -D_GNU_SOURCE -std=gnu11
LDFLAGS ?=

BINS := warden target_demo bench_target

.PHONY: all clean run-demo run-bench check-kernel

all: $(BINS)

warden: warden.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

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

run-bench: warden bench_target
	@sudo ./warden policy.txt -- ./bench_target 10000 2> bench.log
	@python3 bench_summarize.py bench.log

clean:
	rm -f $(BINS) bench.log
