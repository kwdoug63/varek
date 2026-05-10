# SPDX-License-Identifier: MIT
#
# Build the seccomp-unotify TOCTOU reproducer harness.
#
# Requires:  Linux kernel >= 5.14  (SECCOMP_ADDFD_FLAG_SEND)
#            glibc with pthread
#            x86_64 (BPF arch check; trivial to extend)

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wno-unused-parameter \
           -D_GNU_SOURCE -std=gnu11
LDFLAGS ?=
LDLIBS  ?= -lpthread

BIN := seccomp_toctou_harness
SRC := $(BIN).c

.PHONY: all clean run-naive run-mitigated check-kernel

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

check-kernel:
	@uname -r | awk -F. '{ \
	  if ($$1 < 5 || ($$1 == 5 && $$2 < 14)) { \
	    print "WARN: kernel " $$0 " < 5.14 — SECCOMP_ADDFD_FLAG_SEND missing"; \
	    exit 1; \
	  } else { \
	    print "OK:   kernel " $$0 " supports required seccomp features"; \
	  } \
	}'

run-naive: $(BIN)
	@sudo ./$(BIN) --naive 50000

run-mitigated: $(BIN)
	@sudo ./$(BIN) --mitigated 50000

clean:
	rm -f $(BIN)
