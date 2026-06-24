#!/usr/bin/env python3
# apply_bootstrap_exec_fix.py
#
# Run from varek/v1_4/ (the dir with warden.c).
#
# Why this exists: the v1.9.1 deny-only exec mediation (the "deny_only_nonfile_v191"
# block in supervise()) denies EVERY execve whose policy decision is ALLOW. But the
# Warden launches the target by having the child install the filter and then
# execvp() the target program — so the target's OWN bootstrap execve is mediated and
# denied, and the target never starts (execvp returns EACCES -> _exit(127)). This
# blocks not just the conformance target but ANY target under the post-v1.9.1 Warden.
#
# Confirm first (10s): `make run-demo` — if target_demo fails to launch with a
# permission error on exec, this fix is needed.
#
# The fix authorizes exactly the operator-specified target's first execve, once per
# pid, before the target runs any code. There is no TOCTOU on the path: the target
# is single-threaded and blocked in execve, so nothing can swap the pathname between
# check and use. Every LATER exec (agent-initiated) still falls through to deny-only.

import sys

src = open("warden.c").read()
orig = src

# 1) per-pid launched flag
a = "    char    cwd[PATH_LIMIT];\n};"
b = "    char    cwd[PATH_LIMIT];\n    bool    launched;\n};"
assert a in src, "exec_ctx struct not found as expected"
src = src.replace(a, b, 1)

# 2) supervise() takes the bootstrap path
a = "static void supervise(int notify_fd, const struct policy *p) {"
b = "static void supervise(int notify_fd, const struct policy *p,\n                      const char *bootstrap_path) {"
assert a in src, "supervise() signature not found"
src = src.replace(a, b, 1)

# 3) bootstrap-allow block, inserted just before the first policy decision
anchor = "        decision_t d_raw   = policy_decide(p, &act);"
assert anchor in src, "policy_decide call site not found"
block = (
"        /* Bootstrap launch: the target's own first execve of the operator-\n"
"         * specified binary is authorized by the act of launching it. Allowed\n"
"         * exactly once per pid, before the target runs any code (no TOCTOU on\n"
"         * the path: single-threaded, blocked in execve). Later execs fall\n"
"         * through to the deny-only block below. */\n"
"        if (act.kind == ACT_PROCESS_EXEC && ctx && !ctx->launched &&\n"
"            bootstrap_path && strcmp(act.target, bootstrap_path) == 0) {\n"
"            ctx->launched = true;\n"
"            clock_gettime(CLOCK_MONOTONIC, &t1);\n"
"            uint64_t lat_b = (t1.tv_sec - t0.tv_sec) * 1000000000ULL\n"
"                           + (t1.tv_nsec - t0.tv_nsec);\n"
"            emit_pathology(seq++, req.pid, &act, DEC_ALLOW, DEC_ALLOW,\n"
"                           \"bootstrap_exec_allow\", lat_b, 0);\n"
"            send_simple(notify_fd, req.id, DEC_ALLOW);\n"
"            continue;\n"
"        }\n\n"
)
src = src.replace(anchor, block + anchor, 1)

# 4) pass the target path at the call site
a = "    supervise(notify_fd, &p);"
b = "    supervise(notify_fd, &p, target_argv[0]);"
assert a in src, "supervise() call site not found"
src = src.replace(a, b, 1)

if src == orig:
    print("no change made"); sys.exit(1)
open("warden.c", "w").write(src)
print("bootstrap-exec fix applied to warden.c")
