# SPDX-License-Identifier: MIT
#
# VAREK Warden v1.4 reference build.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wno-unused-parameter \
           -D_GNU_SOURCE -std=gnu11
LDFLAGS ?=
LDLIBS  ?= -lseccomp -lsodium

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

# v1.18.0: the --plan gate's data-flow check (v1.7), refusal breaker (v1.8.2)
# and progress-safety check (v1.9), for --flow-policy.
FLOW_SRC  := $(V1_7_DIR)/plan_dataflow.c $(V1_7_DIR)/plan_dataflow_adapter.c \
             $(V1_7_DIR)/plan_dataflow_pathology.c $(V1_7_DIR)/plan_warden_binding.c \
             $(V1_7_DIR)/plan_policy_config.c $(V1_7_DIR)/plan_breaker.c \
             $(V1_7_DIR)/plan_progress.c

BINS := warden warden-proxy target_demo bench_target tools/vdp_check tools/vdp_cert_check tools/varek_keygen tools/bench_workload

.PHONY: all deps deps-check deps-check-ssl preflight install uninstall test-cli clean run-demo run-bench run-bench-v14 run-plan-demo run-conformance check-kernel test-lifecycle test-v112 test-v1121 test-v1122 test-v1123 test-v1124 test-v1130 test-v1140 test-v1150 test-v1160 test-v1161 test-v1162 test-v1170 test-v1180 test-v1190 test-v1200 test-v1210 test-v1211 test-v1240 test-v1250 test-v1260 test-v1261 latency-v1260 fuzz-proxy-parse fuzz-proxy-parse-libfuzzer crosscheck harness video-v112

all: $(BINS)

# v1.16.1: the Warden needs the libseccomp and (from v1.16) libsodium headers;
# v1.26.1: warden-proxy needs OpenSSL's. Checked when (and only when) one of
# them is about to be built, naming the command that installs them; `make
# deps` runs that command.
deps-check:
	@printf '#include <seccomp.h>\n#include <sodium.h>\n' | $(CC) -E -x c - >/dev/null 2>&1 || { \
	    echo "ERROR: the Warden needs the libseccomp and libsodium development headers."; \
	    echo "  Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y build-essential libseccomp-dev libsodium-dev libssl-dev"; \
	    echo "  Fedora/RHEL:   sudo dnf install -y gcc make libseccomp-devel libsodium-devel openssl-devel"; \
	    echo "  or run: make deps"; exit 1; }

deps-check-ssl:
	@printf '#include <openssl/ssl.h>\n#include <openssl/pkcs12.h>\n' | $(CC) -E -x c - >/dev/null 2>&1 || { \
	    echo "ERROR: warden-proxy (the egress proxy) needs the OpenSSL development headers."; \
	    echo "  Debian/Ubuntu: sudo apt-get install -y libssl-dev"; \
	    echo "  Fedora/RHEL:   sudo dnf install -y openssl-devel"; \
	    echo "  or run: make deps"; exit 1; }

deps:
	@if command -v apt-get >/dev/null 2>&1; then \
	    sudo apt-get update && sudo apt-get install -y build-essential libseccomp-dev libsodium-dev libssl-dev; \
	elif command -v dnf >/dev/null 2>&1; then \
	    sudo dnf install -y gcc make libseccomp-devel libsodium-devel openssl-devel; \
	else echo "install libseccomp, libsodium and OpenSSL (development packages) with your package manager"; exit 1; fi

# v1.16.1: check a deployment before running it (dependencies, build, policy,
# the verdict stream / key / anchor locations the Warden refuses, and with
# --run a real trial run). Example:
#   make preflight POLICY=policies/finance.policy.txt LOG=/var/log/varek/verdicts.log
preflight:
	@./tools/varek_preflight.sh "$(POLICY)" $(if $(LOG),--log "$(LOG)") $(if $(KEY),--sign-key "$(KEY)") $(if $(ANCHOR),--anchor "$(ANCHOR)") $(if $(FLOW),--flow-policy "$(FLOW)") $(if $(STATE),--breaker-state "$(STATE)") $(if $(RUN),--run)

CHECKER := checker/vdp_checker.c checker/vdp_checker.h

# v1.24: the resolution table (warden_resolve.c) runs a resolver thread and
# uses the host's resolver library.
RESOLVE := warden_resolve.c warden_resolve.h warden_names.inc.c warden_stub.inc.c warden_synth.inc.c warden_pxdecide.inc.c warden_trust.inc.c shared_domains.c shared_domains.h warden_proxy.c warden_proxy.h proxy_parse.h

warden: warden.c warden_net.inc.c warden_baseline_filter.c smt_decide.c smt_decide.h $(CHECKER) $(RESOLVE) $(LIFECYCLE) $(FLOW_SRC) $(V1_6_SRC)
	@$(MAKE) -s --no-print-directory deps-check
	$(CC) $(CFLAGS) -pthread $(LDFLAGS) -o $@ warden.c warden_baseline_filter.c smt_decide.c checker/vdp_checker.c warden_resolve.c shared_domains.c warden_proxy.c $(LIFECYCLE) $(FLOW_SRC) $(V1_6_SRC) $(LDLIBS) -lresolv

# v1.26.1: the egress proxy, its own program (the Warden starts it from a
# sealed copy whose SHA-256 it records). It links neither libseccomp nor
# libsodium, and never holds the signing key; v1.26.1 inspecting mode links
# OpenSSL here, and only here.
warden-proxy: warden_proxy_helper.c warden_proxy.h proxy_parse.c proxy_parse.h proxy_ca.c proxy_ca.h
	@$(MAKE) -s --no-print-directory deps-check-ssl
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ warden_proxy_helper.c proxy_parse.c proxy_ca.c -lssl -lcrypto

# v1.15, TEST ONLY: a Warden whose decision procedure has a planted bug (a path
# ending in /.inject is decided SATISFIED). test_v1150.sh uses it to show that
# the certificate checker refuses the wrong verdict. Never deploy it.
warden_faultinject: warden.c warden_net.inc.c warden_baseline_filter.c smt_decide.c smt_decide.h $(CHECKER) $(RESOLVE) $(LIFECYCLE) $(FLOW_SRC) $(V1_6_SRC)
	@$(MAKE) -s --no-print-directory deps-check
	$(CC) $(CFLAGS) -DVDP_FAULT_INJECT -pthread $(LDFLAGS) -o $@ warden.c warden_baseline_filter.c smt_decide.c checker/vdp_checker.c warden_resolve.c shared_domains.c warden_proxy.c $(LIFECYCLE) $(FLOW_SRC) $(V1_6_SRC) $(LDLIBS) -lresolv

# v1.15: command-line front end to the certificate checker (policy digest,
# batch certificate checks). Links the checker only, never smt_decide.c.
tools/vdp_cert_check: tools/vdp_cert_check.c $(CHECKER)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tools/vdp_cert_check.c checker/vdp_checker.c

# v1.16: Ed25519 key pair for signing the verdict stream (--sign-key).
tools/varek_keygen: tools/varek_keygen.c
	@$(MAKE) -s --no-print-directory deps-check
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tools/varek_keygen.c -lsodium

# v1.13: command-line front end to the SMT decision procedure (lint, analyze,
# batch queries); the same smt_decide.c the Warden runs.
tools/vdp_check: shared_domains.c shared_domains.h tools/vdp_check.c smt_decide.c smt_decide.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tools/vdp_check.c smt_decide.c shared_domains.c

target_demo: target_demo.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

bench_target: bench_target.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# v1.22: the workload behind `varek bench`. Static where the host has a static
# libc (Debian/Ubuntu: libc6-dev; Fedora/RHEL/Amazon Linux: glibc-static), so a
# run under the Warden makes no loader opens; otherwise dynamic, and the bench
# adds read-only loader rules to the policy it runs with.
tools/bench_workload: tools/bench_workload.c
	@if printf 'int main(void){return 0;}\n' | $(CC) -static -x c -o $@.probe - 2>/dev/null; then \
	    rm -f $@.probe; \
	    echo "$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<"; \
	    $(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<; \
	else \
	    rm -f $@.probe; \
	    echo "note: no static libc; building $@ dynamically (install glibc-static or libc6-dev for a static build)"; \
	    $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<; \
	fi

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

# v1.22: `varek bench` (native vs Warden, per kind of call, every verdict
# checked). The v1.4 bench (Warden-side decision latency only) stays as
# run-bench-v14.
run-bench: warden tools/vdp_check tools/vdp_cert_check tools/bench_workload
	@sudo ./tools/varek bench --bare

run-bench-v14: warden bench_target
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
# solver cross-check and the harness gate. Needs python3 and
# tools/requirements-crosscheck.txt.
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

# v1.15: certificates. Every authorization carries a certificate the
# independent checker accepted in-line; the audit tool re-checks a saved
# stream; a planted procedure bug (warden_faultinject) is refused by the
# checker; the --plan gate; forged certificates; the cross-check with --cert.
tests/v1150_probe: tests/v1150_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<

test-v1150: warden warden_faultinject tools/vdp_check tools/vdp_cert_check tests/v1150_probe
	@sudo ./tests/test_v1150.sh ./warden ./warden_faultinject ./tools/vdp_check ./tools/vdp_cert_check $(abspath tests/v1150_probe)

# v1.16: the verdict stream against its holder (hash chain, Ed25519-signed
# checkpoints, the external anchor, tampering by a holder with and without the
# key, anchor failures, startup refusals) and the 4,096-token glob cap.
tests/v1160_probe: tests/v1160_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<

test-v1160: warden tools/vdp_check tools/vdp_cert_check tools/varek_keygen tests/v1160_probe
	@sudo ./tests/test_v1160.sh ./warden ./tools/vdp_check ./tools/vdp_cert_check ./tools/varek_keygen $(abspath tests/v1160_probe)

# v1.16.1: deployment preflight. vdp_cert_check's openable check agrees with
# the Warden's startup refusal; varek_preflight.sh passes a good deployment and
# fails the ones the Warden would refuse; the dependency check names packages.
test-v1161: warden tools/vdp_cert_check tools/varek_keygen
	@sudo ./tests/test_v1161.sh ./warden ./tools/vdp_cert_check

# v1.17.0: the signing key, stream and anchor refused by identity (through a
# bind mount into the allowed tree); raw devices refused; stat/access/readlink
# mediated, recorded and audited; the agent unprivileged (--run-as).
tests/v1170_probe: tests/v1170_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<

tests/v1180_probe: tests/v1180_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<

test-v1170: warden tools/vdp_cert_check tools/varek_keygen tests/v1170_probe
	@sudo ./tests/test_v1170.sh ./warden ./tools/vdp_cert_check ./tools/varek_keygen $(abspath tests/v1170_probe)

# v1.18.0: where the published claims and the code disagreed. The --plan gate
# refuses connect/launch steps; --flow-policy runs the data-flow check, the
# refusal breaker (state kept across runs, protected from the agent) and the
# progress-safety check; refusals record EACCES; the CycloneDX export is derived
# from the stream, checks the policy, is signed (JSF Ed25519) and schema-valid;
# the Python suites collect. Also runs the v1.7 layer's checks (URL host
# matching, breaker state) and the live filter's io_uring probe. The schema
# check needs tools/requirements-test.txt.
test-v1180: warden tools/vdp_cert_check tools/varek_keygen tests/v1180_probe tests/test_v14_filter
	@$(MAKE) -s --no-print-directory -C $(V1_7_DIR) tests/test_v118
	@out="$$($(V1_7_DIR)/tests/test_v118)"; rc=$$?; printf '%s\n' "$$out" | tail -1; exit $$rc
	@sudo ./tests/test_v14_filter
	@sudo ./tests/test_v1180.sh ./warden ./tools/vdp_cert_check ./tools/varek_keygen $(abspath tests/v1180_probe)

# v1.19.0: a refusal limit per session. The breaker counted refusals per
# (session, plan), so a planner that changed one step each time was never
# stopped; session_refusal_budget bounds the session, whatever the plans.
test-v1190: warden tools/vdp_cert_check tests/v1180_probe
	@$(MAKE) -s --no-print-directory -C $(V1_7_DIR) tests/test_v119
	@out="$$($(V1_7_DIR)/tests/test_v119)"; rc=$$?; printf '%s\n' "$$out" | tail -1; exit $$rc
	@sudo ./tests/test_v1190.sh ./warden ./tools/vdp_cert_check $(abspath tests/v1180_probe)

# v1.20.0: fields on plan steps (key=value after the target), handed to the
# --flow-policy's rules as named arguments. Also runs the v1.6 parser's field
# tests.
test-v1200: warden tools/vdp_cert_check tests/v1180_probe
	@$(MAKE) -s --no-print-directory -C $(V1_6_DIR) tests/test_plan_fields
	@out="$$($(V1_6_DIR)/tests/test_plan_fields)"; rc=$$?; printf '%s\n' "$$out" | tail -1; exit $$rc
	@sudo ./tests/test_v1200.sh ./warden ./tools/vdp_cert_check $(abspath tests/v1180_probe)

# v1.21.0: decided connections. The Warden decides each connect on the
# destination it will dial, dials it outside the agent's network namespace and
# hands the connected socket over (SECCOMP_IOCTL_NOTIF_ADDFD). The probe
# (static) covers TCP, UDP, Unix, the destination-swap race, options carried
# over, relayed sends and every refusal; the script adds the plan gate, the
# records and their audit, then real clients (curl, Python requests, Node)
# and the per-connection latency (section 6 of tests/test_v1210.sh).
tests/v1210_probe: tests/v1210_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -static -pthread -o $@ $<

tests/v1210_bench: tests/v1210_bench.c
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $<

# v1.21.1: a plan step may declare how it opens its file (open=read,
# open=O_WRONLY|O_CREAT|...); the gate decides the step with those flags.
test-v1211: warden tools/vdp_cert_check tests/v1180_probe
	@sudo ./tests/test_v1211.sh ./warden ./tools/vdp_cert_check $(abspath tests/v1180_probe)

test-v1210: warden tools/vdp_check tools/vdp_cert_check tests/v1210_probe tests/v1210_bench tests/test_v14_filter
	@sudo ./tests/test_v14_filter
	@sudo ./tests/test_v1210.sh ./warden ./tools/vdp_cert_check $(abspath tests/v1210_probe) $(abspath tests/v1210_bench)

# v1.16.2: the off-host anchor. A receiver behind a private sshd on
# 127.0.0.1:2222 and the forwarder: a run anchored off-host audits "signed,
# anchored"; the receiver only appends; an outage loses nothing; preflight
# checks the FIFO's reader. Skipped without OpenSSH.
test-v1162: warden tools/vdp_cert_check tools/varek_keygen tests/v1160_probe
	@sudo ./tests/test_v1162.sh ./warden ./tools/varek_keygen $(abspath tests/v1160_probe)

# v1.24.0 (in progress): host names. The policy grammar in both parsers, the
# resolution table against a local test DNS server, and (as root) the Warden
# resolving a policy's names before and while the agent runs. Sections 1 and 2
# need no root (CI runs them); section 3 is skipped without it.
tests/test_v1240_resolve: tests/test_v1240_resolve.c $(RESOLVE)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tests/test_v1240_resolve.c warden_resolve.c -lresolv

# v1.24.0: connect latency on host names (numeric, 1 name, 15 names); root
latency-v1240: warden tests/v1210_bench
	@sudo ./tests/latency_v1240.sh ./warden tests/v1210_bench 3000

# v1.25.0: lookups through the stub, and connects decided over 1 and 40
# names on one address; root
latency-v1250: warden
	@sudo ./tests/latency_v1250.sh ./warden 1000

# v1.26.0: whole requests through the egress proxy (SNI mode), against
# direct dials and no Warden, and through Squid where installed; root
latency-v1260: warden warden-proxy
	@sudo ./tests/latency_v1260.sh ./warden 1000

test-v1240: warden tools/vdp_check tools/vdp_cert_check tests/test_v1240_resolve
	@./tests/test_v1240.sh ./tools/vdp_check ./tools/vdp_cert_check ./tests/test_v1240_resolve \
	    $(if $(filter 0,$(shell id -u)),./warden)

# v1.25.0 (in progress): wildcard host names. The grammar in both parsers and
# the shared-domain refusals (shared_domains.c against an independent Python
# statement over the whole Public Suffix List). Needs no root; with root it
# also checks run_start.
tests/test_v1250_shared: tests/test_v1250_shared.c shared_domains.c shared_domains.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tests/test_v1250_shared.c shared_domains.c

test-v1250: warden tools/vdp_check tools/vdp_cert_check tests/test_v1250_shared
	@./tests/test_v1250.sh ./tools/vdp_check ./tools/vdp_cert_check ./tests/test_v1250_shared ./warden

# v1.26.0 (in progress): the egress proxy in SNI mode; the grammar so far
test-v1260: warden warden-proxy tools/vdp_check tools/vdp_cert_check tests/proxy_parse_test
	@./tests/test_v1260.sh ./tools/vdp_check ./tools/vdp_cert_check ./warden

# v1.26.1: the egress proxy's inspecting mode (step 1: the grammar)
test-v1261: warden warden-proxy tools/vdp_check tools/vdp_cert_check
	@./tests/test_v1261.sh ./tools/vdp_check ./tools/vdp_cert_check ./warden

# v1.26 step 5: the proxy's parsers, under ASan and UBSan: the vectors, then
# FUZZ_N mutated inputs (make fuzz-proxy-parse FUZZ_N=50000000 for longer).
FUZZ_N ?= 2000000
tests/proxy_parse_test: tests/proxy_parse_test.c proxy_parse.c proxy_parse.h
	$(CC) -O1 -g -std=gnu11 -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=all -o $@ tests/proxy_parse_test.c proxy_parse.c

fuzz-proxy-parse: tests/proxy_parse_test
	./tests/proxy_parse_test unit
	./tests/proxy_parse_test fuzz $(FUZZ_N) 1

# With a clang that has libFuzzer's runtime: coverage-guided, for FUZZ_S seconds.
FUZZ_S ?= 60
fuzz-proxy-parse-libfuzzer: tests/proxy_parse_test.c proxy_parse.c proxy_parse.h
	clang -O1 -g -DPP_LIBFUZZER -fsanitize=fuzzer,address,undefined -o tests/proxy_parse_fuzzer tests/proxy_parse_test.c proxy_parse.c
	./tests/proxy_parse_fuzzer -max_total_time=$(FUZZ_S) -max_len=40000

# Differential check of the decision procedure against an off-the-shelf SMT
# solver (tools/requirements-crosscheck.txt) and,
# for suffix / contains / glob reachability, a derivative-based oracle. These
# are exactly the runs RELEASE-v1.15.0.md quotes: every policy in the
# repository, then 300 fuzzed policies for each of seeds 1, 2 and 3.
crosscheck: tools/vdp_check tools/vdp_cert_check
	@python3 tools/smt_crosscheck.py --vdp tools/vdp_check --cert tools/vdp_cert_check --queries 60 \
	    policy.txt conformance_policy.txt policies/*.txt tests/*policy*.txt
	@for seed in 1 2 3; do \
	    python3 tools/smt_crosscheck.py --vdp tools/vdp_check --cert tools/vdp_cert_check --fuzz 300 --seed $$seed --queries 60 || exit 1; \
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
	rm -f $(BINS) target_conformance bench.log tests/lifecycle_target tests/test_v193_lifecycle tests/v112_probe tests/v1121_probe tests/v1122_probe tests/v1123_probe tests/v1130_probe tests/v1140_probe tests/v1150_probe tests/v1160_probe tests/v1170_probe tests/v1180_probe tests/v1210_probe tests/v1210_bench warden_faultinject tests/test_v14_filter tests/test_v1240_resolve tests/test_v1250_shared tests/proxy_parse_test tests/proxy_parse_fuzzer

# v1.22: install the runtime and the `varek` command.
#   sudo make install                  -> /opt/varek, plus /usr/local/bin/varek
#   sudo make install PREFIX=/srv/varek BINDIR=/usr/bin
PREFIX ?= /opt/varek
BINDIR ?= /usr/local/bin
INSTALL_TOOLS := tools/varek tools/vdp_check tools/vdp_cert_check tools/varek_keygen \
	tools/varek_audit.py tools/varek_cyclonedx.py tools/varek_ed25519.py \
	tools/varek_preflight.sh tools/varek_anchor_forward.py tools/varek_anchor_receiver.sh \
	tools/varek_license.py tools/varek_bench.py tools/bench_workload

install: warden warden-proxy tools/vdp_check tools/vdp_cert_check tools/varek_keygen tools/bench_workload
	install -d -m 0755 $(DESTDIR)$(PREFIX)/tools $(DESTDIR)$(PREFIX)/policies $(DESTDIR)$(PREFIX)/data $(DESTDIR)$(BINDIR)
	install -m 0644 data/public_suffix_list.dat data/varek_shared_domains.txt $(DESTDIR)$(PREFIX)/data/
	install -m 0755 warden warden-proxy $(DESTDIR)$(PREFIX)/
	install -m 0755 $(INSTALL_TOOLS) $(DESTDIR)$(PREFIX)/tools/
	install -m 0644 policies/*.policy.txt $(DESTDIR)$(PREFIX)/policies/
	if [ -d tools/systemd ]; then install -d -m 0755 $(DESTDIR)$(PREFIX)/tools/systemd && \
	    install -m 0644 tools/systemd/* $(DESTDIR)$(PREFIX)/tools/systemd/; fi
	ln -sf $(PREFIX)/tools/varek $(DESTDIR)$(BINDIR)/varek
	@echo "installed in $(PREFIX); next: sudo varek doctor"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/varek
	rm -rf $(DESTDIR)$(PREFIX)
	@echo "removed $(PREFIX); settings in /etc/varek and logs in /var/log/varek were kept"

test-cli: warden warden-proxy tools/vdp_check tools/vdp_cert_check tools/varek_keygen tools/bench_workload
	python3 -m pytest -q tests/test_varek_cli.py tests/test_varek_license.py tests/test_varek_bench.py
