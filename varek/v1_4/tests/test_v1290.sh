#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# test_v1290.sh — VAREK v1.29.0: `varek run` with nothing set up first, a dry
# run, and `varek policy suggest` (docs/security/v1.29-varek-run.md). The
# parts built so far:
#   1. opening files as the agent: `require warden 1.29`, read the same way by
#      the decision procedure (vdp_check) and the certificate checker
#      (vdp_cert_check); the Warden reports 1.29.0 and compares the two
#      readings at load; under it, the Warden resolves and opens each file it
#      hands the agent with the agent's user, group and its user's
#      supplementary groups (tests/v1290_open makes the opens): a created
#      file is the agent's, a file the agent's user could not open is not
#      opened whatever the policy allows (the kernel's error, recorded with
#      the decision), and a v1.28 policy opens as root, as before.
#   2. the baseline policy (tools/varek_baseline.py) and the agents' profiles
#      (policies/agents/): the profile chosen by each spelling of a command;
#      the working directories refused; every profile's baseline lints, loads
#      in both parsers and in the Warden, and the cross-check agrees; `varek
#      run` with no configuration: first-use setup, the policy stored by its
#      SHA-256, run_start's baseline, credential stores refused, the profile's
#      directory and API host reached, launches by every name; the audit,
#      refusals and runs with no configuration; a Node.js agent.
#   2b. changes by name (D12): unlink, rmdir, mkdir, rename (both names; a
#      directory refused with EXDEV), chmod, utimensat, truncate, ftruncate,
#      fchmod and chdir decided as writes (chdir a read) with the flags their
#      kind is decided as, carried out as the agent, recorded and audited
#      (four forged streams); links refused; a v1.28 policy as before; git,
#      mv, rm -r and Python's tempfile under the baseline.
#   3. the dry run: each kind of call the policy refuses let through and
#      recorded enforced:false (an open, a write, a lookup, a change, a call
#      outside the allowlist, a connect, a launch, a name), the agent's own
#      rights still applying, and what still refuses (a protected object, a
#      Unix socket, a hard-denied call, revocation); the labels and counts;
#      the same agent enforcing; what a dry run is refused with.
#   4. varek policy suggest: from a dry run, a draft with an exact rule per
#      object refused (a read, a write, a launch, a connect), a directory
#      alternative commented out, each never-active case commented out with
#      its reason, system calls as notes; deterministic; it lints; a second
#      dry run under it refuses none of what it suggested; an enforcing
#      run's stream; a sub-agent named.
#   6. the agent's user (the user who ran sudo, else nobody; never root) and
#      environment (a clean one; --env by name; recorded by name only), and
#      the agent's /tmp/varek-<uid>.
#
#   test_v1290.sh VDP_CHECK VDP_CERT_CHECK [WARDEN]
set -u

VDP="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
CERT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
WARDEN="${3:-}"
[ -n "$WARDEN" ] && WARDEN="$(cd "$(dirname "$WARDEN")" && pwd)/$(basename "$WARDEN")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d)"
fail=0 skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
TUSER=varek1290u TGROUP=varek1290g MADE_USER= MADE_BU=
cleanup() {
    if [ -n "$MADE_USER" ]; then userdel "$TUSER" >/dev/null 2>&1; groupdel "$TGROUP" >/dev/null 2>&1; fi
    if [ -n "$MADE_BU" ]; then rm -rf "/tmp/varek-$(id -u varek1290r 2>/dev/null)"; userdel varek1290r >/dev/null 2>&1; fi
    [ -n "${KEEP:-}" ] && echo "kept $OUT" || rm -rf "$OUT"
}
trap cleanup EXIT

echo "== 1. opening files as the agent =="
# both parsers load the policy and say the same about opening as the agent
openas() {
    printf '%b' "$2" > "$OUT/p.txt"
    local a b
    a="$("$VDP" "$OUT/p.txt" openas 2>&1)"; b="$("$CERT" "$OUT/p.txt" openas 2>&1)"
    if [ "$a" = "$3" ] && [ "$b" = "$3" ]; then pass "$1"; else flunk "$1 (procedure: $a; checker: $b)"; fi
}
openas "require warden 1.29: files opened as the agent, in both parsers" 'require warden 1.29\nallow path /tmp/\n' on
openas "require warden 1.28: as root, as before"                         'require warden 1.28\nallow path /tmp/\n' off
openas "require warden 1.27: as root"                                    'require warden 1.27\nallow path /tmp/\n' off
openas "no require: as root"                                             'allow path /tmp/\n'                      off
openas "1.29 after 1.28: the highest counts"                             'require warden 1.28\nrequire warden 1.29\n' on
printf 'require warden 1.99\n' > "$OUT/p.txt"
check "require warden 1.99: refused by the procedure" sh -c "'$VDP' '$OUT/p.txt' analyze 2>&1 | grep -Eq 'requires Warden 1.99; this is 1\.(29|[3-9][0-9])'"
check "require warden 1.99: refused by the checker" sh -c "! '$CERT' '$OUT/p.txt' digest"
printf 'require warden 1.29\nallow path /usr/ readonly\n' > "$OUT/p.txt"

if [ -z "$WARDEN" ]; then
    skip "the Warden's checks (no warden binary given)"
elif [ "$(id -u)" != 0 ]; then
    skip "the Warden's checks (they run as root: the agent runs as another user)"
else
    check "the Warden reports 1.29.0 or later" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | python3 -c 'import re,sys; m=re.search(r\"VAREK Warden  (\\d+)\\.(\\d+)\\.(\\d+)\", sys.stdin.read()); sys.exit(0 if m and tuple(map(int, m.groups())) >= (1, 29, 0) else 1)'"
    check "the Warden starts a 1.29 policy, read as version 1.29 or later" sh -c "'$WARDEN' '$OUT/p.txt' --check-startup 2>&1 | grep -Eq 'loaded policy .* v1\.(29|[3-9][0-9]) '"

    # the agent's files: W writable by anyone; a root-owned 0644 file and a
    # 0600 file in it; a directory the agent cannot search, with a file
    # anyone could read; a file only the test group may read
    chmod 755 "$OUT"
    mkdir -p "$OUT/bin" "$OUT/w" "$OUT/w/closed" "$OUT/w/tmpd"
    cp "$HERE/tests/v1290_open" "$OUT/bin/"
    chmod 1777 "$OUT/w" "$OUT/w/tmpd"
    echo root > "$OUT/w/rootfile";  chmod 644 "$OUT/w/rootfile"
    echo secret > "$OUT/w/private"; chmod 600 "$OUT/w/private"
    echo inside > "$OUT/w/closed/f"; chmod 644 "$OUT/w/closed/f"; chmod 700 "$OUT/w/closed"
    echo group > "$OUT/w/grp"
    pol() {   # pol FILE VERSION: the policy for these runs
        printf 'require warden %s\nallow path /usr/ readonly\nallow path /etc/ld.so.cache readonly\nallow path /dev/ readonly\nallow path %s/w/\n' \
            "$2" "$OUT" > "$1"
    }
    pol "$OUT/p129.txt" 1.29
    pol "$OUT/p128.txt" 1.28
    # run LOG POLICY RUNAS ARGS...: the program's output in LOG.out, the stream
    # in LOG; the agent inherits umask 027 (the filter refuses umask itself)
    run() {
        local log="$1" p="$2" ra="$3"; shift 3
        (umask 027; "$WARDEN" "$p" --run-as "$ra" -- "$OUT/bin/v1290_open" "$@" > "$log.out" 2> "$log")
    }
    # a raw device present here (refused by identity, whatever the policy)
    RAW=/dev/mem
    [ -e "$RAW" ] || RAW="$(find /dev -maxdepth 1 -type b 2>/dev/null | head -1)"
    # rec LOG PYEXPR: some record r of the stream satisfies PYEXPR
    rec() {
        python3 - "$1" "$2" <<'PY'
import json, sys
for line in open(sys.argv[1], errors="replace"):
    if not line.startswith("{"): continue
    try: r = json.loads(line)
    except ValueError: continue
    try:
        if eval(sys.argv[2]): sys.exit(0)
    except Exception: pass
sys.exit(1)
PY
    }
    NB=65534
    run "$OUT/a1.log" "$OUT/p129.txt" nobody create "$OUT/w/new" write "$OUT/w/rootfile" \
        read "$OUT/w/private" read "$OUT/w/closed/f" create "$OUT/w/closed/g" tmpfile "$OUT/w/tmpd" read "$RAW"
    check "the run ended" rec "$OUT/a1.log" "r.get('event') == 'run_end'"
    check "run_start records opening as the agent: nobody's uid, gid and groups" \
        rec "$OUT/a1.log" "r.get('event') == 'run_start' and r.get('open_as') == {'agent': True, 'uid': $NB, 'gid': $NB, 'groups': [$NB]}"
    check "a file the agent creates is the agent's (the agent sees it so)" grep -qx "create ok $NB $NB 640" "$OUT/a1.log.out"
    check "... and on disk: nobody's, with the agent's mode and umask" sh -c "[ \"\$(stat -c '%u %g %a' '$OUT/w/new')\" = '$NB $NB 640' ]"
    check "a root-owned 0644 file under a writable tree is not writable (the kernel's EACCES)" grep -qx "write Permission denied" "$OUT/a1.log.out"
    check "... and is unchanged" sh -c "[ \"\$(cat '$OUT/w/rootfile')\" = root ]"
    check "... recorded as the decision it was (ALLOW), the open failing with errno 13" \
        rec "$OUT/a1.log" "r.get('resolved') == '$OUT/w/rootfile' and r['decision_final'] == 'ALLOW' and r['rule'] == 'allowed_open_failed' and r['errno'] == 13"
    check "a root-only 0600 file under an allowed tree is not readable" sh -c "sed -n 3p '$OUT/a1.log.out' | grep -qx 'read Permission denied'"
    check "a file in a directory the agent cannot search is not opened" sh -c "sed -n 4p '$OUT/a1.log.out' | grep -qx 'read Permission denied'"
    check "... though its own mode lets anyone read it; recorded ALLOW, errno 13" \
        rec "$OUT/a1.log" "r.get('resolved') == '$OUT/w/closed/f' and r['decision_final'] == 'ALLOW' and r['errno'] == 13"
    check "nothing is created in a directory the agent cannot search" sh -c "sed -n 5p '$OUT/a1.log.out' | grep -qx 'create Permission denied' && [ ! -e '$OUT/w/closed/g' ]"
    check "... recorded ALLOW on the name it would have had, errno 13" \
        rec "$OUT/a1.log" "r.get('resolved') == '$OUT/w/closed/g' and r['decision_final'] == 'ALLOW' and r['errno'] == 13"
    check "an unnamed file (O_TMPFILE) the agent makes is the agent's" grep -qx "tmpfile ok $NB $NB" "$OUT/a1.log.out"
    check "a raw device ($RAW) is still refused by identity, though the policy allows /dev/" \
        rec "$OUT/a1.log" "r.get('resolved') == '$RAW' and r['decision_final'] == 'DENY' and r['rule'] == 'raw_device'"
    check "the stream stays root's, written to the end after the agent's opens" \
        sh -c "[ \"\$(stat -c %u '$OUT/a1.log')\" = 0 ] && tail -n 3 '$OUT/a1.log' | grep -q '\"event\":\"run_end\"'"

    # the same opens under a v1.28 policy: as root, as before
    rm -f "$OUT/w/new"
    run "$OUT/a2.log" "$OUT/p128.txt" nobody create "$OUT/w/new" write "$OUT/w/rootfile" read "$OUT/w/closed/f"
    check "require warden 1.28: no open_as in run_start" rec "$OUT/a2.log" "r.get('event') == 'run_start' and 'open_as' not in r"
    check "require warden 1.28: a created file is root's, as before" sh -c "[ \"\$(stat -c '%u %g' '$OUT/w/new')\" = '0 0' ]"
    check "require warden 1.28: the root-owned file is written, as before" sh -c "grep -qx 'write ok' '$OUT/a2.log.out' && [ \"\$(tail -n 1 '$OUT/w/rootfile')\" = x ]"
    check "require warden 1.28: the closed directory is reached, as before" grep -qx "read ok" "$OUT/a2.log.out"
    echo root > "$OUT/w/rootfile"

    # --run-as root: files opened as root, and run_start says why
    rm -f "$OUT/w/new"
    run "$OUT/a3.log" "$OUT/p129.txt" root create "$OUT/w/new"
    check "--run-as root under 1.29: run_start says the agent is root" \
        rec "$OUT/a3.log" "r.get('event') == 'run_start' and r.get('open_as') == {'agent': False, 'why': 'run_as_root'}"
    check "... and the file is root's" sh -c "[ \"\$(stat -c %u '$OUT/w/new')\" = 0 ]"

    # a user's supplementary groups: by name, the group's file is readable; as
    # uid:gid (no groups beyond the gid), it is not
    if groupadd "$TGROUP" >/dev/null 2>&1 && useradd -M -N -g nogroup -G "$TGROUP" -s /usr/sbin/nologin "$TUSER" >/dev/null 2>&1; then
        MADE_USER=1
        TU="$(id -u "$TUSER")" TG="$(getent group "$TGROUP" | cut -d: -f3)" PG="$(id -g "$TUSER")"
        chgrp "$TGROUP" "$OUT/w/grp"; chmod 640 "$OUT/w/grp"
        run "$OUT/a4.log" "$OUT/p129.txt" "$TUSER" read "$OUT/w/grp"
        check "a user named by --run-as: run_start lists its supplementary groups" \
            rec "$OUT/a4.log" "r.get('event') == 'run_start' and r['open_as']['uid'] == $TU and $TG in r['open_as']['groups']"
        check "... and a file its group may read is read" grep -qx "read ok" "$OUT/a4.log.out"
        run "$OUT/a5.log" "$OUT/p129.txt" "$TU:$PG" read "$OUT/w/grp"
        check "--run-as uid:gid: no supplementary groups, so the group's file is not read" \
            sh -c "grep -qx 'read Permission denied' '$OUT/a5.log.out'"
        check "the agent itself still has no supplementary groups (v1.17)" \
            sh -c "'$WARDEN' '$OUT/p129.txt' --run-as '$TUSER' -- /usr/bin/id -G 2>/dev/null | grep -qx '$PG'"
    else
        skip "supplementary groups (cannot add a test user and group here)"
    fi
fi

echo "== 2. the baseline policy and the agents' profiles; 6. the agent's user and environment =="
VB="$HERE/tools/varek_baseline.py"
# py EXPR...: a Python check against varek_baseline (exit 0 when it holds)
py() { PYTHONPATH="$HERE/tools" python3 -c "import sys, varek_baseline as b; $1"; }
check "a profile by the command's name: claude"            py "p=b.all_profiles('$HERE'); sys.exit(b.choose_profile(['claude','-p','hi'],p)[0]['name']!='claude')"
check "... through npx and a scoped package with a version" py "p=b.all_profiles('$HERE'); sys.exit(b.choose_profile(['npx','-y','@anthropic-ai/claude-code@1.2'],p)[0]['name']!='claude')"
check "... after env and its assignments"                   py "p=b.all_profiles('$HERE'); sys.exit(b.choose_profile(['env','A=1','codex'],p)[0]['name']!='codex')"
check "... a module run by an interpreter (python3 -m aider)" py "p=b.all_profiles('$HERE'); sys.exit(b.choose_profile(['/usr/bin/python3.11','-m','aider'],p)[0]['name']!='aider')"
check "... an unknown Python script: the python profile"    py "p=b.all_profiles('$HERE'); sys.exit(b.choose_profile(['python3','agent.py'],p)[0]['name']!='python')"
check "... an unknown Node script: the node profile"        py "p=b.all_profiles('$HERE'); sys.exit(b.choose_profile(['node','x/run.mjs'],p)[0]['name']!='node')"
check "... an unknown program: the baseline alone"          py "p=b.all_profiles('$HERE'); sys.exit(b.choose_profile(['./myagent'],p)[0] is not None)"
check "... --profile none: the baseline alone"              py "p=b.all_profiles('$HERE'); sys.exit(b.choose_profile(['claude'],p,'none')[0] is not None)"
check "... --profile with an unknown name is refused"       py "p=b.all_profiles('$HERE')
try: b.choose_profile(['x'],p,'nosuch')
except b.BaselineError: sys.exit(0)
sys.exit(1)"
for d in / /etc /usr /tmp /home /root; do
    check "the working directory $d is refused" py "
try: b.check_cwd('$d','/home/x')
except b.BaselineError: sys.exit(0)
sys.exit(1)"
done
mkdir -p "$OUT/sp ace"
check "a working directory with a space is refused (a policy line cannot hold it)" py "
try: b.check_cwd('$OUT/sp ace','/home/x')
except b.BaselineError: sys.exit(0)
sys.exit(1)"
check "the home directory itself is refused as the working directory" py "
try: b.check_cwd('$OUT','$OUT')
except b.BaselineError: sys.exit(0)
sys.exit(1)"

# every shipped profile: its baseline lints, both parsers load it, the cross-check agrees
mkdir -p "$OUT/gen" "$OUT/gproj"
for prof in $(ls "$HERE/policies/agents/" | sed 's/\.profile\.txt$//') none; do
    PYTHONPATH="$HERE/tools" python3 -c "
import pwd, varek_baseline as b
pw = pwd.getpwnam('nobody')
p = None if '$prof' == 'none' else b.all_profiles('$HERE')['$prof']
open('$OUT/gen/$prof.txt', 'w').write(b.generate('$OUT/gproj', pw, '/tmp/varek-65534', p))"
    check "the baseline with profile $prof lints with no dead rule" sh -c "'$VDP' '$OUT/gen/$prof.txt' lint | grep -q ' 0 can never fire'"
    check "... the certificate checker loads it, and both open as the agent" sh -c "[ \"\$('$VDP' '$OUT/gen/$prof.txt' openas)\" = on ] && [ \"\$('$CERT' '$OUT/gen/$prof.txt' openas)\" = on ]"
done
# the cross-check on the largest one (the profiles add a few rules each; its
# reachability queries over the baseline's globs take minutes, so 2 queries)
if python3 "$HERE/tools/smt_crosscheck.py" --vdp "$VDP" --cert "$CERT" --queries 2 "$OUT/gen/claude.txt" > "$OUT/cc.out" 2>&1; then
    pass "the cross-check: the three parsers agree on the claude baseline"
else flunk "the cross-check: the three parsers agree on the claude baseline ($(tail -1 "$OUT/cc.out"))"; fi
# v1.29 step 6: but for the certificate authorities' bundles (read-only), which a key pattern (*.pem) would refuse
check "the credential stores come before any allow rule but the CA bundles'" python3 -c "
import sys
L = [l.split('#')[0].strip() for l in open('$OUT/gen/none.txt')]
last_deny = max(k for k, l in enumerate(L) if l.startswith('deny '))
early = [l for l in L[:last_deny] if l.startswith('allow ')]
ok = all(l.endswith(' readonly') and any(s in l for s in ('/etc/ssl/', '/etc/pki/', '/usr/local/ssl/', '/certifi/')) for l in early)
sys.exit(0 if early and ok and any('contains /.ssh/' in l for l in L[:last_deny + 1]) else 1)"
check "the header says what the baseline was made for" sh -c "head -6 '$OUT/gen/claude.txt' | grep -q '^#@ profile claude [0-9a-f]\{64\}$' && grep -qx '#@ cwd $OUT/gproj' '$OUT/gen/claude.txt' && grep -qx '#@ user nobody' '$OUT/gen/claude.txt'"
check "the claude profile's \${HOME} becomes the user's home" grep -q "^allow path /nonexistent/.claude/ " "$OUT/gen/claude.txt"
check "programs are named by every path they are called by (/bin/sh and its file)" sh -c "grep -qx 'allow exec /bin/sh' '$OUT/gen/none.txt' && grep -qx \"allow exec \$(readlink -f /bin/sh)\" '$OUT/gen/none.txt'"

if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "varek run with the baseline (it runs as root)"
else
    for prof in $(ls "$OUT/gen/" | sed 's/\.txt$//'); do
        check "the Warden starts the baseline with profile $prof" "$WARDEN" "$OUT/gen/$prof.txt" --check-startup
    done
    BU=varek1290r BH="$OUT/home"
    if useradd -m -d "$BH" -s /bin/sh "$BU" >/dev/null 2>&1; then
        MADE_BU=1
        chmod 755 "$BH"
        BUID="$(id -u "$BU")" BGID="$(id -g "$BU")"
        su "$BU" -s /bin/sh -c "mkdir -p '$BH/proj' '$BH/.ssh' '$BH/.aws' '$BH/.claude' '$BH/.testagent' && echo key > '$BH/.ssh/id_rsa' && echo k > '$BH/.aws/credentials' && echo c > '$BH/.claude/settings.json' && echo t > '$BH/.testagent/conf' && echo TOKEN=1 > '$BH/proj/.env' && echo ok > '$BH/proj/README'"
        cat > "$BH/proj/agent.py" <<'PYA'
import os, subprocess, sys, urllib.request
def t(what, f):
    try:
        f(); print(what, "ok")
    except Exception as e:
        print(what, type(e).__name__, getattr(e, "errno", ""))
t("write-cwd", lambda: open("out.txt", "w").write("hi"))
t("read-readme", lambda: open("README").read())
t("read-ssh", lambda: open(os.path.expanduser("~/.ssh/id_rsa")).read())
t("read-aws", lambda: open(os.path.expanduser("~/.aws/credentials")).read())
t("read-env", lambda: open(".env").read())
t("read-claude", lambda: open(os.path.expanduser("~/.claude/settings.json")).read())
t("read-testagent", lambda: open(os.path.expanduser("~/.testagent/conf")).read())
t("write-tmpdir", lambda: open(os.path.join(os.environ["TMPDIR"], "t"), "w").write("x"))
t("git", lambda: subprocess.run(["git", "--version"], check=True, capture_output=True))
t("sh", lambda: subprocess.run(["sh", "-c", "true"], check=True))
t("binsh", lambda: subprocess.run(["/bin/sh", "-c", "true"], check=True))
t("system", lambda: (os.system("true") == 0) or 1/0)
if len(sys.argv) > 1:
    t("api", lambda: urllib.request.urlopen(sys.argv[1], timeout=5).read())
for k in ("HOME", "USER", "LOGNAME", "TMPDIR", "SECRET1290", "OTHER1290"):
    print("env", k, os.environ.get(k, "-"))
print("path", os.environ.get("PATH"))
print("uid", os.getuid(), os.getgid())
PYA
        chown "$BU" "$BH/proj/agent.py"
        # a stand-in for a model API on the loopback, and a test profile naming it
        python3 -m http.server 0 --bind 127.0.0.1 --directory "$BH/proj" > "$OUT/http.out" 2>&1 &
        HPID=$!
        for _ in $(seq 1 50); do PORT="$(sed -n 's/.*port \([0-9]*\).*/\1/p' "$OUT/http.out" | head -1)"; [ -n "$PORT" ] && break; sleep 0.1; done
        printf '#@ profile testapi\n#@ about a test agent\n#@ commands testagent\n#@ programs python3\nallow path ${HOME}/.testagent/\nallow host 127.0.0.1:%s\n' "$PORT" > "$OUT/testapi.profile.txt"
        VENV="VAREK_CONFIG=$OUT/etc/varek.conf VAREK_LIB_DIR=$OUT/lib VAREK_LOG_DIR=$OUT/log"
        vrun() {   # vrun OUTFILE [env assignments] -- varek args...: in the project, as root with sudo's variables
            local o="$1"; shift
            (cd "$BH/proj" && env SUDO_UID="$BUID" SUDO_GID="$BGID" SUDO_USER="$BU" $VENV "$@" > "$o" 2> "$o.err")
        }
        vrun "$OUT/r1.out" SECRET1290=s3cr3t-1290 OTHER1290=x python3 "$HERE/tools/varek" run --env SECRET1290 \
            --profile "$OUT/testapi.profile.txt" -- python3 agent.py "http://127.0.0.1:$PORT/README"
        L1="$(ls "$OUT"/log/verdicts-*.log 2>/dev/null | head -1)"
        o() { grep -qx "$1" "$OUT/r1.out"; }
        check "varek run with no configuration ran the agent" o "write-cwd ok"
        check "first use: the log directory and a signing key made; no varek.conf" sh -c "[ -d '$OUT/log' ] && [ -f '$OUT/etc/log.key' ] && [ -f '$OUT/etc/log.key.pub' ] && [ ! -e '$OUT/etc/varek.conf' ]"
        check "... and it says so" grep -q "signing key .* made on first use" "$OUT/r1.out.err"
        check "the agent runs as the user who ran sudo" o "uid $BUID $BGID"
        check "... and says why" grep -q "the agent runs as $BU (the user who ran sudo)" "$OUT/r1.out.err"
        check "a file it writes in the working directory is its user's" sh -c "[ \"\$(stat -c '%u %g' '$BH/proj/out.txt')\" = '$BUID $BGID' ]"
        check "it reads the working directory" o "read-readme ok"
        check "~/.ssh is refused" o "read-ssh PermissionError 13"
        check "~/.aws is refused" o "read-aws PermissionError 13"
        check "a .env in the working directory is refused" o "read-env PermissionError 13"
        check "a home directory no profile names is refused (~/.claude, no claude profile)" o "read-claude PermissionError 13"
        check "the profile's own directory is read (\${HOME}/.testagent)" o "read-testagent ok"
        check "TMPDIR is the user's /tmp/varek-<uid>, 0700, and writable" sh -c "grep -qx 'write-tmpdir ok' '$OUT/r1.out' && grep -qx 'env TMPDIR /tmp/varek-$BUID' '$OUT/r1.out' && [ \"\$(stat -c '%U %a' /tmp/varek-$BUID)\" = '$BU 700' ]"
        check "git launches" o "git ok"
        check "sh (by PATH) launches" o "sh ok"
        check "/bin/sh launches" o "binsh ok"
        check "system() (/bin/sh -c) works" o "system ok"
        check "the profile's API host is reached" o "api ok"
        check "HOME, USER and LOGNAME are the agent user's" sh -c "grep -qx 'env HOME $BH' '$OUT/r1.out' && grep -qx 'env USER $BU' '$OUT/r1.out' && grep -qx 'env LOGNAME $BU' '$OUT/r1.out'"
        check "--env passes the named variable" o "env SECRET1290 s3cr3t-1290"
        check "a variable not named is not passed" o "env OTHER1290 -"
        check "PATH is the system's (root's own PATH not passed)" sh -c "grep '^path ' '$OUT/r1.out' | grep -qv '/root/'"
        check "the policy is stored by its SHA-256, root's, 0644" sh -c "f=\$(ls '$OUT'/lib/policies/*.policy.txt | head -1); [ \"\$(basename \"\$f\" .policy.txt)\" = \"\$(sha256sum < \"\$f\" | cut -c1-64)\" ] && [ \"\$(stat -c '%u %a' \"\$f\")\" = '0 644' ]"
        check "run_start records the baseline: profile, its SHA-256, cwd, home, user, tmp" \
            rec "$L1" "r.get('event') == 'run_start' and r['baseline']['profile'] == 'testapi' and len(r['baseline']['profile_sha256']) == 64 and r['baseline']['cwd'] == '$BH/proj' and r['baseline']['home'] == '$BH' and r['baseline']['user'] == '$BU' and r['baseline']['tmp'] == '/tmp/varek-$BUID'"
        check "run_start lists the agent environment's names: SECRET1290, not OTHER1290" \
            rec "$L1" "r.get('event') == 'run_start' and 'SECRET1290' in r['agent_env'] and 'OTHER1290' not in r['agent_env'] and 'TMPDIR' in r['agent_env']"
        check "the variable's value is nowhere in the stream" sh -c "! grep -q 's3cr3t-1290' '$L1'"
        check "run_start says files are opened as the agent" rec "$L1" "r.get('event') == 'run_start' and r['open_as']['uid'] == $BUID"
        vrun "$OUT/a.out" python3 "$HERE/tools/varek" audit
        check "varek audit passes the run, with no configuration" grep -q "PASS" "$OUT/a.out"
        vrun "$OUT/rf.out" python3 "$HERE/tools/varek" refusals
        check "varek refusals reads it, with no configuration" grep -q "id_rsa" "$OUT/rf.out"
        vrun "$OUT/rs.out" python3 "$HERE/tools/varek" runs
        check "varek runs lists it" grep -qF "$L1" "$OUT/rs.out"
        N1="$(ls "$OUT"/lib/policies | wc -l)"
        vrun "$OUT/r2.out" python3 "$HERE/tools/varek" run --profile "$OUT/testapi.profile.txt" -- python3 agent.py
        check "a second run in the same place reuses the same policy file" sh -c "[ \"\$(ls '$OUT'/lib/policies | wc -l)\" = '$N1' ]"
        f="$(ls "$OUT"/lib/policies/*.policy.txt | head -1)"; cp "$f" "$OUT/saved"; echo "# changed" >> "$f"
        vrun "$OUT/r3.out" python3 "$HERE/tools/varek" run --profile "$OUT/testapi.profile.txt" -- python3 agent.py
        check "a stored policy that was changed is not reused or rewritten" sh -c "grep -q 'exists with other contents' '$OUT/r3.out.err' && tail -1 '$f' | grep -q changed"
        cp "$OUT/saved" "$f"
        vrun "$OUT/sp.out" python3 "$HERE/tools/varek" run --show-policy -- claude
        check "--show-policy prints the baseline (the claude profile) and runs nothing" sh -c "grep -q '^#@ profile claude ' '$OUT/sp.out' && grep -q '^allow path $BH/.claude/ ' '$OUT/sp.out'"
        vrun "$OUT/e1.out" python3 "$HERE/tools/varek" run --env NOT_SET_1290 -- python3 agent.py
        check "--env with a variable that is not set is refused" grep -q "not set in varek's environment" "$OUT/e1.out.err"
        vrun "$OUT/e2.out" python3 "$HERE/tools/varek" run --env 'A-B' -- python3 agent.py
        check "--env with a bad name is refused" grep -q "not a variable name" "$OUT/e2.out.err"
        (cd "$BH/proj" && env $VENV python3 "$HERE/tools/varek" run --show-policy -- python3 agent.py > "$OUT/n.out" 2> "$OUT/n.err")
        check "with no sudo user, the agent is nobody" grep -q "the agent runs as nobody (no sudo user)" "$OUT/n.err"
        (cd "$BH/proj" && env SUDO_UID=0 SUDO_USER=root $VENV python3 "$HERE/tools/varek" run --show-policy -- python3 agent.py > "$OUT/n0.out" 2> "$OUT/n0.err")
        check "sudo from root: the agent is nobody, not root" grep -q "the agent runs as nobody" "$OUT/n0.err"
        vrun "$OUT/rr.out" python3 "$HERE/tools/varek" run --run-as root -- python3 agent.py
        check "--run-as root is refused with the baseline" grep -q "the agent would run as root" "$OUT/rr.out.err"
        mv "/tmp/varek-$BUID" "$OUT/tmpkeep"; ln -s /etc "/tmp/varek-$BUID"
        vrun "$OUT/tl.out" python3 "$HERE/tools/varek" run -- python3 agent.py
        check "a /tmp/varek-<uid> that is a link is refused" grep -q "not a directory of $BU's with mode 0700" "$OUT/tl.out.err"
        rm -f "/tmp/varek-$BUID"; mkdir -m 777 "/tmp/varek-$BUID"
        vrun "$OUT/tm.out" python3 "$HERE/tools/varek" run -- python3 agent.py
        check "a /tmp/varek-<uid> of another mode (or owner) is refused" grep -q "not a directory of $BU's with mode 0700" "$OUT/tm.out.err"
        rmdir "/tmp/varek-$BUID"
        (cd "$BH" && env SUDO_UID="$BUID" SUDO_GID="$BGID" SUDO_USER="$BU" $VENV python3 "$HERE/tools/varek" run -- python3 proj/agent.py > "$OUT/hd.out" 2> "$OUT/hd.err")
        check "varek run from the home directory itself is refused" grep -q "not /, a system directory or a home directory itself" "$OUT/hd.err"
        # a Node.js agent with the node profile
        cat > "$BH/proj/agent.js" <<'JSA'
const fs = require("fs"), cp = require("child_process");
fs.writeFileSync("node-out.txt", "hi");
console.log("node-write ok");
try { cp.execSync("sh -c true"); console.log("node-sh ok"); } catch (e) { console.log("node-sh " + e.message); }
try { fs.readFileSync(process.env.HOME + "/.ssh/id_rsa"); console.log("node-ssh read"); } catch (e) { console.log("node-ssh " + e.code); }
JSA
        chown "$BU" "$BH/proj/agent.js"
        if command -v node >/dev/null 2>&1; then
            vrun "$OUT/nd.out" python3 "$HERE/tools/varek" run -- node agent.js
            check "a Node.js agent gets the node profile" grep -q "profile node (the interpreter \`node\`)" "$OUT/nd.out.err"
            check "... writes in the working directory" grep -qx "node-write ok" "$OUT/nd.out"
            check "... launches sh" grep -qx "node-sh ok" "$OUT/nd.out"
            check "... and is refused ~/.ssh" grep -qx "node-ssh EACCES" "$OUT/nd.out"
        else
            skip "a Node.js agent (node is not installed)"
        fi
        kill "$HPID" 2>/dev/null
        rm -rf "/tmp/varek-$BUID"
    else
        skip "varek run with the baseline (cannot add a test user here)"
    fi
fi

echo "== 2b. changing files by name (D12) =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "changes by name (they run as root: the agent runs as another user)"
else
    C="$OUT/c"
    mkdir -p "$C/w/ro" "$C/w/ao" "$C/w/keep" "$C/w/dir1/sub" "$C/w/d2" "$C/out" "$C/bin"
    cp "$HERE/tests/v1290_open" "$C/bin/"
    chmod 755 "$C" "$C/bin"; chmod 1777 "$C/w" "$C/w/ro" "$C/w/ao" "$C/w/keep" "$C/w/dir1" "$C/w/d2"; chmod 777 "$C/w/dir1/sub"
    echo r > "$C/w/ro/f"; echo a > "$C/w/ao/f"; echo s > "$C/w/keep/.env"; chmod 666 "$C/w/ro/f" "$C/w/ao/f" "$C/w/keep/.env"
    mkdir -m 700 "$C/out/secret"
    cpol() {   # cpol FILE VERSION
        # first match wins, and a rule whose flag clause fails does not match:
        # a read-only (or append-only) tree is a read rule, then a deny
        printf 'require warden %s\nallow path /usr/ readonly\nallow path /etc/ld.so.cache readonly\ndeny path glob /**/.[eE][nN][vV]\nallow path %s/w/ro/ readonly\ndeny path %s/w/ro/\nallow path %s/w/ao/ access=wo -O_TRUNC\ndeny path %s/w/ao/\nallow path exact %s/w readonly\nallow path %s/w/\nallow path /proc/self/ readonly\n' \
            "$2" "$C" "$C" "$C" "$C" "$C" "$C" > "$1"
    }
    cpol "$C/p129.txt" 1.29
    cpol "$C/p128.txt" 1.28
    W="$C/w"
    (cd "$W" && umask 027 && "$WARDEN" "$C/p129.txt" --run-as nobody -- "$C/bin/v1290_open" \
        create "$W/f" chmod "$W/f" utime "$W/f" fchmod "$W/f" truncate "$W/f" ftruncate "$W/f" \
        create "$W/x" rename "$W/x:$W/y" create "$W/z" exchange "$W/y:$W/z" \
        rename "$W/y:$W/ro/y" rename "$W/keep/.env:$W/e2" rename "$W/dir1:$W/dir9" \
        unlink "$W/ro/f" unlink "$W/ao/f" mkdir "$W/m" rmdir "$W/m" mkdir "$W/m2" \
        create "$W/d2/g" unlinkat "$W/d2:g" unlink "$W/f" \
        chdir "$W/d2" chdir "$C/out" symlink "$W/sl" link "$W/z" \
        truncate /proc/self/oom_score_adj unlink "$W/nosuch" > "$C/a.out" 2> "$C/a.log")
    co() { grep -qx "$1" "$C/a.out"; }
    # recc ACTION RESOLVED FINAL RULE [FLAGS]: a record of the run says so
    recc() { rec "$C/a.log" "r.get('action') == '$1' and r.get('resolved') == '$2' and r['decision_final'] == '$3' and r['rule'] == '$4'${5:+ and r.get('open_flags') == '$5'}"; }
    check "chmod by name, as the agent, on its own file"                  co "chmod ok"
    check "... recorded file.chmod, decided as a write (0x1), done"       recc file.chmod "$W/f" ALLOW change_done 0x1
    check "utimensat sets the times"                                      sh -c "co() { grep -qx \"\$1\" '$C/a.out'; }; co 'utime ok'"
    check "fchmod on a descriptor, decided on its file"                   sh -c "grep -qx 'fchmod ok' '$C/a.out' && grep -q '\"action\":\"file.chmod\",\"target\":\"fd:3\",\"resolved\":\"$W/f\"' '$C/a.log'"
    check "truncate and ftruncate, decided as O_WRONLY|O_TRUNC (0x201)"   sh -c "grep -qx 'truncate ok' '$C/a.out' && grep -qx 'ftruncate ok' '$C/a.out'"
    check "... recorded so"                                               recc file.truncate "$W/f" ALLOW change_done 0x201
    check "a rename: both names decided and recorded"                     sh -c "grep -qx 'rename ok' '$C/a.out' && [ -e '$W/y' ] && [ ! -e '$W/x' ]"
    check "... file.rename_from (0x201)"                                  recc file.rename_from "$W/x" ALLOW change_done 0x201
    check "... file.rename_to (0x241)"                                    recc file.rename_to "$W/y" ALLOW change_done 0x241
    check "RENAME_EXCHANGE: both names decided as replaced (0x241)"      sh -c "grep -qx 'exchange ok' '$C/a.out'" 
    check "... recorded so"                                               recc file.rename_from "$W/y" ALLOW change_done 0x241
    check "a rename into a read-only tree is refused, the file stays"     sh -c "[ \"\$(sed -n '/^rename/p' '$C/a.out' | sed -n 2p)\" = 'rename Permission denied' ] && [ -e '$W/y' ] && [ ! -e '$W/ro/y' ]"
    check "... recorded: the new name refused"                            recc file.rename_to "$W/ro/y" DENY policy_match
    check "a rename of a file a deny rule names (.env) is refused"        sh -c "[ -e '$W/keep/.env' ] && [ ! -e '$W/e2' ]"
    check "... recorded on its old name"                                  recc file.rename_from "$W/keep/.env" DENY policy_match
    check "a directory is never renamed: EXDEV"                           sh -c "grep -qx 'rename Invalid cross-device link' '$C/a.out' && [ -d '$W/dir1/sub' ] && [ ! -e '$W/dir9' ]"
    check "... recorded rename_directory_refused, errno 18"              rec "$C/a.log" "r.get('action') == 'file.rename_from' and r.get('resolved') == '$W/dir1' and r['rule'] == 'rename_directory_refused' and r['errno'] == 18"
    check "unlink under a read-only rule is refused, the file stays"      sh -c "[ -e '$W/ro/f' ]"
    check "... decided as 0x201 and refused"                              recc file.unlink "$W/ro/f" DENY policy_match 0x201
    check "unlink under a rule that refuses O_TRUNC (append-only) is refused" sh -c "[ -e '$W/ao/f' ]"
    check "mkdir, as the agent, under its umask (0777 & ~027)"            sh -c "[ \"\$(stat -c '%U %a' '$W/m2')\" = 'nobody 750' ]"
    check "... recorded file.mkdir (0xc1)"                                recc file.mkdir "$W/m2" ALLOW change_done 0xc1
    check "rmdir"                                                         sh -c "[ ! -e '$W/m' ] && grep -qx 'rmdir ok' '$C/a.out'"
    check "unlinkat relative to a directory descriptor"                   sh -c "grep -qx 'unlinkat ok' '$C/a.out' && [ ! -e '$W/d2/g' ]"
    check "unlink"                                                        sh -c "[ ! -e '$W/f' ]"
    check "chdir into an allowed directory (the kernel does it, as the agent)" sh -c "grep -qx 'cwd $W/d2' '$C/a.out'"
    check "... recorded chdir_continued (0x10000)"                        recc file.chdir "$W/d2" ALLOW chdir_continued 0x10000
    check "chdir outside the policy is refused"                           recc file.chdir "$C/out" DENY default_deny_unknown
    check "a symbolic link stays refused (EPERM, the filter)"            sh -c "grep -qx 'symlink Operation not permitted' '$C/a.out' && [ ! -e '$W/sl' ]"
    check "a hard link stays refused (EPERM, the filter)"                sh -c "grep -qx 'link Operation not permitted' '$C/a.out' && [ ! -e '$W/z.l' ]"
    check "a change on procfs is refused whatever the policy says"        rec "$C/a.log" "r.get('action') == 'file.truncate' and r['rule'] == 'change_on_kernel_fs'"
    check "a name that does not exist: the kernel's ENOENT, recorded"     recc file.unlink "$W/nosuch" ALLOW change_failed
    check "the agent's changes are its own (the renamed file is nobody's)" sh -c "[ \"\$(stat -c %U '$W/y')\" = nobody ]"
    check "the audit passes the run" python3 "$HERE/tools/varek_audit.py" --policy "$C/p129.txt" --checker "$CERT" "$C/a.log"
    F="$HERE/tests/v1270_forge.py"
    forged() {   # forged LABEL PYTHON WORDS: the audit refuses the forged stream, naming WORDS
        python3 "$F" "$C/a.log" "$C/f.log" "$2" >/dev/null 2>&1
        if python3 "$HERE/tools/varek_audit.py" --policy "$C/p129.txt" --checker "$CERT" "$C/f.log" > "$C/f.out" 2>&1; then
            flunk "forged: $1 (the audit passed it)"
        elif grep -qF -- "$3" "$C/f.out"; then pass "forged: $1"
        else flunk "forged: $1 (not for its own reason: $(grep -v '^varek_audit: \(integrity\|run started\)' "$C/f.out" | head -2 | tr '\n' ' '))"; fi
    }
    forged "a chmod recorded with flags other than its kind's" \
        "[r.__setitem__('open_flags', '0x0') for r in recs if isinstance(r, dict) and r.get('action') == 'file.chmod' and r.get('rule') == 'change_done']" \
        "not as its kind is decided"
    forged "a rename with its new name dropped" \
        "i = [k for k, r in enumerate(recs) if isinstance(r, dict) and r.get('action') == 'file.rename_to' and r.get('rule') == 'change_done'][0]; recs.pop(i); [r.__setitem__('seq', r['seq'] - 1) for r in recs[i:] if isinstance(r, dict) and 'seq' in r]; [r.__setitem__('records', r['records'] - 1) for r in recs if isinstance(r, dict) and r.get('event') == 'run_end']" \
        "without its new name decided and recorded next"
    forged "a rename's new name with its old name dropped" \
        "i = [k for k, r in enumerate(recs) if isinstance(r, dict) and r.get('action') == 'file.rename_from' and r.get('rule') == 'change_done'][0]; recs.pop(i); [r.__setitem__('seq', r['seq'] - 1) for r in recs[i:] if isinstance(r, dict) and 'seq' in r]; [r.__setitem__('records', r['records'] - 1) for r in recs if isinstance(r, dict) and r.get('event') == 'run_end']" \
        "without its old name before it"
    forged "a chdir allowed with a rule other than chdir_continued" \
        "[r.__setitem__('rule', 'change_done') for r in recs if isinstance(r, dict) and r.get('action') == 'file.chdir' and r.get('decision_final') == 'ALLOW']" \
        "allowed with rule"
    # under a v1.28 policy the changes are not sent to the Warden: EPERM, as before
    rm -f "$W/q"; echo q > "$W/q"; chmod 666 "$W/q"
    (cd "$W" && "$WARDEN" "$C/p128.txt" --run-as nobody -- "$C/bin/v1290_open" unlink "$W/q" mkdir "$W/m3" chdir "$W/d2" > "$C/b.out" 2> "$C/b.log")
    check "require warden 1.28: unlink, mkdir and chdir are refused by the filter (EPERM), as before" \
        sh -c "grep -qx 'unlink Operation not permitted' '$C/b.out' && grep -qx 'mkdir Operation not permitted' '$C/b.out' && grep -qx 'chdir Operation not permitted' '$C/b.out' && [ -e '$W/q' ]"
    check "... and nothing is recorded for them" sh -c "! grep -q '\"action\":\"file\.\(unlink\|mkdir\|chdir\)\"' '$C/b.log'"
    # tools an agent uses, through varek run with the baseline (the section-2 user)
    if [ -n "${MADE_BU:-}" ] && id varek1290r >/dev/null 2>&1; then
        cat > "$BH/proj/tools.sh" <<'SHT'
export GIT_AUTHOR_NAME=a GIT_AUTHOR_EMAIL=a@b GIT_COMMITTER_NAME=a GIT_COMMITTER_EMAIL=a@b
git init -q repo && cd repo && echo hi > f && git add f && git commit -qm one && echo "git-commit ok"
[ "$(git log --oneline | wc -l)" = 1 ] && echo "git-log ok"
cd .. && mkdir -p d/e && echo x > d/e/g && mv d d2 2>/dev/null; [ -f d2/e/g ] && [ ! -e d ] && echo "mv-dir ok"
rm -r d2 && [ ! -e d2 ] && echo "rm-r ok"
python3 -c "import tempfile; tempfile.NamedTemporaryFile().write(b'x'); tempfile.TemporaryDirectory().cleanup(); print('tempfile ok')"
SHT
        chown varek1290r "$BH/proj/tools.sh"
        vrun "$OUT/tools.out" python3 "$HERE/tools/varek" run --profile python -- sh tools.sh
        for w in git-commit git-log mv-dir rm-r tempfile; do
            check "with the baseline: $w" grep -qx "$w ok" "$OUT/tools.out"
        done
        vrun "$OUT/tools.audit" python3 "$HERE/tools/varek" audit
        check "... and the audit passes that run" grep -q PASS "$OUT/tools.audit"
    else
        skip "git, mv, rm -r and tempfile with the baseline (no section-2 user)"
    fi
fi

echo "== 3. the dry run =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "the dry run (it runs as root: the agent runs as another user)"
else
    Y="$OUT/y"
    mkdir -p "$Y/w" "$Y/o" "$Y/u"
    chmod 755 "$Y"; chmod 1777 "$Y/w" "$Y/o"
    echo hi > "$Y/o/f"; chmod 644 "$Y/o/f"
    echo s > "$Y/o/secret"; chmod 600 "$Y/o/secret"
    printf 'require warden 1.29\nallow path /usr/ readonly\nallow path /etc/ld.so.cache readonly\nallow path %s/w/\nallow exec /usr/bin/python3\n' "$Y" > "$Y/p.txt"
    python3 -m http.server 0 --bind 127.0.0.1 --directory "$Y/w" > "$Y/http.out" 2>&1 &
    YH=$!
    for _ in $(seq 1 50); do YP="$(sed -n 's/.*port \([0-9]*\).*/\1/p' "$Y/http.out" | head -1)"; [ -n "$YP" ] && break; sleep 0.1; done
    python3 -c "
import socket, os, time
s = socket.socket(socket.AF_UNIX); s.bind('$Y/u/sock'); os.chmod('$Y/u/sock', 0o777); s.listen(4)
time.sleep(60)" & YU=$!
    YN="$(hostname)"           # a name the host resolves (its /etc/hosts), not in the agent's hosts view
    cat > "$Y/w/agent.py" <<PYD
import ctypes, os, socket, subprocess, sys
def t(what, f):
    try:
        r = f(); print(what, "ok" if r is None else r)
    except Exception as e:
        print(what, type(e).__name__, getattr(e, "errno", ""))
t("read-outside", lambda: open("$Y/o/f").read().strip())
t("write-outside", lambda: open("$Y/o/new", "w").write("x") and None)
t("read-root-only", lambda: open("$Y/o/secret").read())
t("stat-outside", lambda: os.stat("$Y/o/f").st_size)
t("own", lambda: open("$Y/o/mine", "w").write("m") and None)
t("link", lambda: os.link("$Y/o/mine", "$Y/w/hl"))
t("unlink-outside", lambda: os.unlink("$Y/o/mine"))
def conn():
    s = socket.create_connection(("127.0.0.1", $YP), timeout=5); s.sendall(b"GET / HTTP/1.0\r\n\r\n"); return s.recv(12).decode()
t("connect", conn)
t("launch", lambda: subprocess.run(["/usr/bin/id", "-u"], capture_output=True, text=True).stdout.strip())
t("stream", lambda: open(sys.argv[1]).read(1))
def unix():
    s = socket.socket(socket.AF_UNIX); s.connect("$Y/u/sock")
t("unix", unix)
t("name", lambda: socket.getaddrinfo("$YN", $YP, socket.AF_INET)[0][4][0])
PYD
    chmod 644 "$Y/w/agent.py"
    "$WARDEN" "$Y/p.txt" --dry-run --run-as nobody -- /usr/bin/python3 "$Y/w/agent.py" "$Y/d.log" > "$Y/d.out" 2> "$Y/d.log"
    yo() { grep -qx "$1" "$Y/d.out"; }
    # recd ACTION-or-EVENT SUBSTRING RULE: a record not enforced, DENY, with that rule
    recd() { rec "$Y/d.log" "r.get('enforced') is False and r.get('decision_final', 'DENY') == 'DENY' and (r.get('action') == '$1' or r.get('event') == '$1') and '$2' in str(r.get('target', r.get('name', ''))) and r.get('rule') == '$3'"; }
    check "the Warden says DRY RUN: NOT ENFORCING at the start"          grep -q '^\[warden\] DRY RUN: NOT ENFORCING\. ' "$Y/d.log"
    check "... and at the end, with the count"                            grep -q '^\[warden\] DRY RUN: NOT ENFORCING: [0-9]* call(s)' "$Y/d.log"
    check "run_start says mode dry_run"                                   rec "$Y/d.log" "r.get('event') == 'run_start' and r.get('mode') == 'dry_run'"
    check "run_end says mode dry_run and counts the records not enforced" python3 -c "
import json, sys
recs = [json.loads(l) for l in open('$Y/d.log') if l.startswith('{')]
end = [r for r in recs if r.get('event') == 'run_end'][0]
n = sum(1 for r in recs if r.get('enforced') is False)
sys.exit(0 if end.get('mode') == 'dry_run' and end.get('not_enforced') == n and n > 0 else 1)"
    check "no record not enforced says ALLOW"                             python3 -c "
import json, sys
sys.exit(any(json.loads(l).get('enforced') is False and json.loads(l).get('decision_final') == 'ALLOW' for l in open('$Y/d.log') if l.startswith('{')))"
    check "a read the policy refuses is let through"                      yo "read-outside hi"
    check "... recorded DENY, enforced:false"                             recd file.open "$Y/o/f" default_deny_unknown
    check "a write the policy refuses is let through, as the agent's user" sh -c "grep -qx 'write-outside ok' '$Y/d.out' && [ \"\$(stat -c %U '$Y/o/new')\" = nobody ]"
    check "a root-only file stays unreadable: the kernel decides as the agent, never as root" yo "read-root-only PermissionError 13"
    check "a lookup the policy refuses is let through"                    yo "stat-outside 3"
    check "a call outside the allowlist (link) goes to the kernel"        sh -c "grep -qx 'link ok' '$Y/d.out' && [ -e '$Y/w/hl' ]"
    check "... recorded syscall_not_admitted, enforced:false"             recd other syscall:86 syscall_not_admitted
    check "a change by name the policy refuses is let through"            sh -c "grep -qx 'unlink-outside ok' '$Y/d.out' && [ ! -e '$Y/o/mine' ]"
    check "a connect the policy refuses is dialed by the Warden"          yo "connect HTTP/1.0 200"
    check "... recorded DENY, enforced:false (dialed: at once or in progress)" \
        rec "$Y/d.log" "r.get('enforced') is False and r.get('decision_final') == 'DENY' and r.get('action') == 'net.connect' and r.get('target') == '127.0.0.1:$YP' and r.get('rule') in ('dialed_fd_injection', 'dialed_in_progress')"
    check "a launch outside the launch set runs (no Landlock in a dry run)" yo "launch 65534"
    check "... recorded, enforced:false"                                  recd process.exec /usr/bin/id default_deny_unknown
    # the stub looks the name up through the host's resolver: whether it is
    # found depends on the host; that it was asked and looked up does not
    check "a name no rule reaches is asked of the stub and looked up, not refused" \
        rec "$Y/d.log" "r.get('event') == 'dns_question' and r.get('name') == '$YN' and r.get('rule') == 'no_rule' and r.get('enforced') is False and r.get('answer') == 'lookup'"
    check "the verdict stream (a protected object) is still refused"      yo "stream PermissionError 13"
    check "... recorded protected_object, enforced"                       rec "$Y/d.log" "r.get('rule') == 'protected_object' and 'enforced' not in r"
    check "a Unix socket connect stays refused (the Warden would reach it as root)" yo "unix PermissionError 13"
    check "... recorded, enforced"                                        rec "$Y/d.log" "r.get('action') == 'net.connect' and str(r.get('target')).startswith('unix:') and 'enforced' not in r"
    # the same agent enforcing: each of those refused
    rm -f "$Y/o/new" "$Y/w/hl"; echo m > "$Y/o/mine"; chmod 666 "$Y/o/mine"
    "$WARDEN" "$Y/p.txt" --run-as nobody -- /usr/bin/python3 "$Y/w/agent.py" "$Y/e.log" > "$Y/e.out" 2> "$Y/e.log"
    check "enforcing, the same agent is refused each of them" sh -c "grep -qx 'read-outside PermissionError 13' '$Y/e.out' && grep -qx 'write-outside PermissionError 13' '$Y/e.out' && grep -qx 'link PermissionError 1' '$Y/e.out' && grep -q '^connect PermissionError' '$Y/e.out' && grep -q '^launch PermissionError' '$Y/e.out' && [ ! -e '$Y/o/new' ]"
    check "... and no record of it says enforced:false, nor run_start dry_run" sh -c "! grep -q '\"enforced\":false\|\"mode\":\"dry_run\"' '$Y/e.log'"
    # a hard-denied call still refuses in a dry run (the strict build kills)
    "$WARDEN" "$Y/p.txt" --dry-run --run-as nobody -- /usr/bin/python3 -c "
import ctypes; libc = ctypes.CDLL(None, use_errno=True)
r = libc.syscall(101, 0, 0, 0, 0)          # ptrace(PTRACE_TRACEME)
print('ptrace', r, ctypes.get_errno())" > "$Y/h.out" 2> "$Y/h.log"
    check "a hard-denied call (ptrace) is still refused in a dry run" sh -c "! grep -qx 'ptrace 0 0' '$Y/h.out' && ! grep -q 'syscall:101' '$Y/h.log'"
    # revocation still refuses in a dry run
    "$WARDEN" "$Y/p.txt" --dry-run --run-as nobody -- /usr/bin/python3 -c "
import time
ok = no = 0
for i in range(24):
    try: open('$Y/o/f').read(); ok += 1
    except OSError: no += 1
    time.sleep(0.25)
print('opened', ok, 'refused', no)" > "$Y/r.out" 2> "$Y/r.log" &
    YW=$!
    for _ in $(seq 1 50); do RID="$(sed -n 's/.*"event":"run_start","run":"\([0-9a-f]*\)".*/\1/p' "$Y/r.log" | head -1)"; [ -n "$RID" ] && break; sleep 0.1; done
    sleep 2; python3 "$HERE/tools/varek" revoke "$RID" > /dev/null 2>&1
    wait "$YW"
    check "after varek revoke a dry run refuses: opens let through before, refused after" sh -c "grep -q 'opened [1-9][0-9]* refused [1-9]' '$Y/r.out'"
    check "... the refusals after it recorded revoked, enforced" rec "$Y/r.log" "r.get('rule') == 'revoked' and 'enforced' not in r and r.get('decision_final') == 'DENY'"
    # what a dry run is refused with
    printf 'require warden 1.29\nallow path /usr/ readonly\nallow exec /usr/bin/python3 subagent=helper\n' > "$Y/ps.txt"
    check "--dry-run with sub-agents is refused" sh -c "'$WARDEN' '$Y/ps.txt' --dry-run --run-as nobody -- /bin/true 2>&1 | grep -q 'dry-run with a policy that names sub-agents'"
    printf 'require warden 1.29\nproxy inspect\ncredential k from file:/etc/varek/k\nallow path /usr/ readonly\n' > "$Y/pc.txt"
    check "--dry-run with credentials is refused" sh -c "'$WARDEN' '$Y/pc.txt' --dry-run --run-as nobody -- /bin/true 2>&1 | grep -q 'dry-run with a policy that names credentials'"
    printf 'step 1 file_open /usr/lib/os-release\n' > "$Y/plan.txt"
    check "--dry-run with --plan is refused" sh -c "'$WARDEN' '$Y/p.txt' --plan '$Y/plan.txt' --dry-run --run-as nobody -- /bin/true 2>&1 | grep -q 'dry-run with --plan is refused'"
    check "a policy cannot ask for a dry run (no such directive)" sh -c "printf 'require warden 1.29\ndry run\n' > '$Y/pd.txt'; ! '$VDP' '$Y/pd.txt' analyze >/dev/null 2>&1"
    # varek run --dry-run
    (cd "$Y" && VAREK_CONFIG="$Y/none/varek.conf" VAREK_LOG_DIR="$Y/log" python3 "$HERE/tools/varek" run --dry-run --policy "$Y/p.txt" \
        --run-as nobody -- /usr/bin/python3 -c "print(open('$Y/o/f').read().strip())" > "$Y/v.out" 2> "$Y/v.err")
    check "varek run --dry-run says DRY RUN: NOT ENFORCING before and after" sh -c "[ \"\$(grep -c 'DRY RUN: NOT ENFORCING' '$Y/v.err')\" -ge 2 ] && grep -q 'call(s) the policy refuses were let through' '$Y/v.err' && grep -qx hi '$Y/v.out'"
    kill "$YH" "$YU" 2>/dev/null
fi

echo "== 4. varek policy suggest =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "varek policy suggest on real runs (they run as root)"
else
    Z="$OUT/z"
    mkdir -p "$Z/w" "$Z/o/many" "$Z/o/.ssh"
    chmod 755 "$Z"; chmod 1777 "$Z/w" "$Z/o"
    echo hi > "$Z/o/f"; echo d > "$Z/o/denied"; echo k > "$Z/o/.ssh/id_rsa"
    for i in 1 2 3 4 5 6; do echo "$i" > "$Z/o/many/f$i"; done
    chmod -R a+rX "$Z/o"; chmod 644 "$Z/o/.ssh/id_rsa"
    printf 'require warden 1.29\nallow path /usr/ readonly\nallow path /etc/ld.so.cache readonly\ndeny path %s/o/denied\nallow path %s/w/\nallow exec /usr/bin/python3\n' "$Z" "$Z" > "$Z/p.txt"
    python3 -m http.server 0 --bind 127.0.0.1 --directory "$Z/w" > "$Z/http.out" 2>&1 &
    ZH=$!
    for _ in $(seq 1 50); do ZP="$(sed -n 's/.*port \([0-9]*\).*/\1/p' "$Z/http.out" | head -1)"; [ -n "$ZP" ] && break; sleep 0.1; done
    SUDO="$(command -v sudo 2>/dev/null)"
    cat > "$Z/w/a.py" <<PYZ
import os, shutil, socket, subprocess
for p in ["$Z/o/f", "$Z/o/denied", "$Z/o/.ssh/id_rsa", "/root/.profile"] + ["$Z/o/many/f%d" % i for i in range(1, 7)]:
    try: open(p).read()
    except OSError: pass
open("$Z/o/new", "w").write("x")
os.unlink("$Z/o/new")
try: open("/etc/varek-suggest-test", "w")
except OSError: pass
subprocess.run(["/usr/bin/id"], capture_output=True)
shutil.copy("/bin/sh", "$Z/w/mysh"); os.chmod("$Z/w/mysh", 0o755)
subprocess.run(["$Z/w/mysh", "-c", "true"])
if "$SUDO":
    subprocess.run(["$SUDO", "-n", "true"], capture_output=True)
try:
    s = socket.create_connection(("127.0.0.1", $ZP)); s.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n"); s.recv(10)
except OSError: pass
PYZ
    chmod 644 "$Z/w/a.py"
    "$WARDEN" "$Z/p.txt" --dry-run --run-as nobody -- /usr/bin/python3 "$Z/w/a.py" > /dev/null 2> "$Z/d.log"
    rm -f "$Z/w/mysh"
    VS() { VAREK_CONFIG="$Z/none/varek.conf" VAREK_LOG_DIR="$Z/log" python3 "$HERE/tools/varek" policy suggest "$@"; }
    VS "$Z/d.log" -o "$Z/d1.txt" > /dev/null 2> "$Z/s.err"
    VS "$Z/d.log" > "$Z/d2.txt" 2> /dev/null
    dl() { grep -qF -- "$1" "$Z/d1.txt"; }
    check "varek policy suggest writes a draft (-o), and says how many rules"     sh -c "[ -s '$Z/d1.txt' ] && grep -q 'rule(s) suggested' '$Z/s.err'"
    check "the draft says it is a draft from one run, with its run and mode"      sh -c "head -1 '$Z/d1.txt' | grep -q '^# DRAFT POLICY' && grep -q '^# run [0-9a-f]*, dry run (not enforcing)' '$Z/d1.txt'"
    check "the same stream gives the same draft, byte for byte"                   cmp -s "$Z/d1.txt" "$Z/d2.txt"
    check "the policy is kept as it was, its deny rule included"                  sh -c "grep -qx 'deny path $Z/o/denied' '$Z/d1.txt' && grep -qx 'allow path $Z/w/' '$Z/d1.txt'"
    check "a read: an exact readonly rule"                                        dl "
allow path exact $Z/o/f readonly    # "
    check "a write and a removal: an exact rule, its flags noted"                 sh -c "grep -q '^allow path exact $Z/o/new    # 2 times; .*flags 0x201,' '$Z/d1.txt'"
    check "a launch: by the name used"                                            dl "
allow exec /usr/bin/id    # "
    check "a connect: the host and port"                                          dl "
allow host 127.0.0.1:$ZP    # "
    check "five or more under one directory: a directory rule, commented out"     dl "# allow path $Z/o/many/ readonly    # ALTERNATIVE (not active)"
    check "never active: an object a deny rule refuses"                           dl "# allow path exact $Z/o/denied readonly    # NOT SUGGESTED: a deny rule of the policy (line 4)"
    check "never active: a key"                                                   dl "# allow path exact $Z/o/.ssh/id_rsa readonly    # NOT SUGGESTED: a credential store or key"
    check "never active: another user's home"                                     dl "# allow path exact /root/.profile readonly    # NOT SUGGESTED: in another user's home"
    check "never active: a write under /etc/"                                     dl "# allow path exact /etc/varek-suggest-test    # NOT SUGGESTED: a write under a system directory"
    check "never active: a program the agent wrote (a shell copied as mysh)"      dl "# allow exec $Z/w/mysh    # NOT SUGGESTED: a program the agent wrote in this run"
    if [ -n "$SUDO" ]; then
        check "never active: sudo"                                                dl "# allow exec $SUDO    # NOT SUGGESTED: sudo runs programs as another user"
    else skip "never active: sudo (not installed)"; fi
    check "a system call outside the allowlist is a note, not a rule"             sh -c "grep -q '^# system call [0-9]* (.*) is outside the Warden' '$Z/d1.txt' && ! grep -q '^allow .*syscall' '$Z/d1.txt'"
    check "the draft lints"                                                       "$VDP" "$Z/d1.txt" lint
    check "the draft loads in the certificate checker"                           "$CERT" "$Z/d1.txt" digest
    "$WARDEN" "$Z/d1.txt" --dry-run --run-as nobody -- /usr/bin/python3 "$Z/w/a.py" > /dev/null 2> "$Z/d3.log"
    rm -f "$Z/w/mysh"
    check "a second dry run under the draft: what it suggested is no longer refused" python3 -c "
import json, sys
recs = [json.loads(l) for l in open('$Z/d3.log') if l.startswith('{')]
bad = [r for r in recs if r.get('enforced') is False and (r.get('resolved') in ('$Z/o/f', '$Z/o/new', '/usr/bin/id') or
       str(r.get('resolved', '')).startswith('$Z/o/many/') or r.get('target') == '127.0.0.1:$ZP')]
sys.exit(1 if bad or not recs else 0)"
    check "... while what it did not suggest still is (the denied file, the key)" python3 -c "
import json, sys
recs = [json.loads(l) for l in open('$Z/d3.log') if l.startswith('{')]
got = {r.get('resolved') for r in recs if r.get('enforced') is False}
sys.exit(0 if '$Z/o/denied' in got and '$Z/o/.ssh/id_rsa' in got else 1)"
    # an enforcing run's refusals
    "$WARDEN" "$Z/p.txt" --run-as nobody -- /usr/bin/python3 "$Z/w/a.py" > /dev/null 2> "$Z/e.log"
    rm -f "$Z/w/mysh"
    VS "$Z/e.log" > "$Z/e1.txt" 2> /dev/null
    check "from an enforcing run: a draft, and the read it was refused"           sh -c "grep -q '^# run [0-9a-f]*, enforcing' '$Z/e1.txt' && grep -q '^allow path exact $Z/o/f readonly' '$Z/e1.txt'"
    check "-o does not overwrite a file without --force" sh -c "! VAREK_CONFIG='$Z/none/varek.conf' python3 '$HERE/tools/varek' policy suggest '$Z/d.log' -o '$Z/d1.txt' 2>/dev/null"
    # a stream with sub-agents: the sub-agent named on the rule's comment
    python3 - "$Z/d.log" "$Z/sub.log" <<'PYS'
import json, sys
out = open(sys.argv[2], "w")
for line in open(sys.argv[1]):
    if line.startswith("{"):
        r = json.loads(line)
        if r.get("resolved", "").endswith("/o/f"):
            r["obo"] = ["agent", "subagent:helper#1"]
        line = json.dumps(r) + "\n"
    out.write(line)
PYS
    PYTHONPATH="$HERE/tools" python3 -c "
import json, varek_suggest as v
recs = [json.loads(l) for l in open('$Z/sub.log') if l.startswith('{')]
t, a, c = v.suggest(recs, open('$Z/p.txt').read(), '$Z/p.txt', 'x', '$VDP')
open('$Z/sub.txt', 'w').write(t)"
    check "a sub-agent's refusal: the rule's comment names it" grep -q "^allow path exact $Z/o/f readonly    # .*sub-agent helper#1" "$Z/sub.txt"
    kill "$ZH" 2>/dev/null
fi

echo "== 5. audit, export and tools for the dry run and the baseline =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "the audit, export and tools (they read runs that run as root)"
else
    Q="$OUT/q"
    mkdir -p "$Q/w" "$Q/o" "$Q/log"
    chmod 755 "$Q" "$Q/o"; chmod 1777 "$Q/w"
    echo hi > "$Q/o/f"; chmod 644 "$Q/o/f"
    # a policy with a baseline's header (the Warden copies it into run_start)
    printf '#@ varek baseline 1\n#@ profile none -\n#@ cwd %s/w\n#@ home /nonexistent\n#@ user nobody\n#@ tmp /tmp\nrequire warden 1.29\nallow path /usr/ readonly\nallow path /etc/ld.so.cache readonly\nallow path %s/w/\nallow exec /usr/bin/python3\n' "$Q" "$Q" > "$Q/b.txt"
    QA='import sys
for p in ("'"$Q"'/o/f", sys.argv[1]):
    try: open(p).read(1); print("read ok")
    except OSError as e: print("read", e.errno)'
    "$WARDEN" "$Q/b.txt" --run-as nobody -- /usr/bin/python3 -c "$QA" "$Q/e.log" > "$Q/e.out" 2> "$Q/e.log"
    "$WARDEN" "$Q/b.txt" --dry-run --run-as nobody -- /usr/bin/python3 -c "$QA" "$Q/d.log" > "$Q/d.out" 2> "$Q/d.log"
    QN="$(python3 -c "import json; print([json.loads(l) for l in open('$Q/d.log') if l.startswith('{\"event\":\"run_end\"')][0]['not_enforced'])")"
    AUD() { python3 "$HERE/tools/varek_audit.py" --policy "$Q/b.txt" --checker "$CERT" "$@"; }
    AUD "$Q/e.log" > "$Q/ae.out" 2>&1; QE=$?
    AUD "$Q/d.log" > "$Q/ad.out" 2>&1; QD=$?
    check "the audit passes an enforcing run under a baseline (exit 0)"   sh -c "[ $QE = 0 ] && grep -q 'PASS' '$Q/ae.out'"
    check "the audit verifies a dry run, exit 3: VERIFIED: DRY RUN, NOT ENFORCED" \
        sh -c "[ $QD = 3 ] && grep -q '^varek_audit: VERIFIED: DRY RUN, NOT ENFORCED ($QN call(s)' '$Q/ad.out' && ! grep -q 'PASS' '$Q/ad.out'"
    if [ -s "$Y/r.log" ]; then
        python3 "$HERE/tools/varek_audit.py" --policy "$Y/p.txt" --checker "$CERT" "$Y/r.log" > "$Q/ar.out" 2>&1; QR=$?
        check "... and a dry run that was revoked (exit 3)" sh -c "[ $QR = 3 ]"
        python3 "$HERE/tools/varek_audit.py" --policy "$Y/p.txt" --checker "$CERT" "$Y/d.log" > "$Q/ay.out" 2>&1; QR=$?
        check "... and section 3's dry run: stub questions, connects, launches, changes (exit 3)" sh -c "[ $QR = 3 ]"
    else skip "a dry run that was revoked (section 3 did not run it)"; fi
    F="$HERE/tests/v1270_forge.py"
    qforged() {   # qforged LABEL STREAM PYTHON WORDS: the audit fails the forged stream (exit 1), naming WORDS
        python3 "$F" "$2" "$Q/f.log" "$3" >/dev/null 2>&1
        AUD "$Q/f.log" > "$Q/f.out" 2>&1
        local rc=$?
        if [ "$rc" != 1 ]; then flunk "forged: $1 (the audit exited $rc)"
        elif grep -qF -- "$4" "$Q/f.out"; then pass "forged: $1"
        else flunk "forged: $1 (not for its own reason: $(grep '^  PROBLEM' "$Q/f.out" | head -2 | tr '\n' ' '))"; fi
    }
    NE="[r for r in recs if isinstance(r, dict) and r.get('enforced') is False]"
    RS="[r for r in recs if isinstance(r, dict) and r.get('event') == 'run_start'][0]"
    RE="[r for r in recs if isinstance(r, dict) and r.get('event') == 'run_end'][0]"
    qforged "a record let through that says ALLOW" "$Q/d.log" \
        "$NE[0]['decision_final'] = 'ALLOW'" "a dry run lets through only what the policy refused"
    qforged "the protected object let through" "$Q/d.log" \
        "r = [r for r in recs if isinstance(r, dict) and r.get('rule') == 'protected_object'][0]; r['enforced'] = False; $RE['not_enforced'] += 1" \
        "protected_object let through"
    qforged "\"enforced\":true (the Warden writes only false)" "$Q/d.log" \
        "$NE[0]['enforced'] = True; $RE['not_enforced'] -= 1" "the Warden writes only false"
    qforged "run_start's mode dropped (a dry run passed off as enforcing)" "$Q/d.log" \
        "$RS.pop('mode'); $RE.pop('mode')" "a record not enforced, in a run that is not a dry run"
    qforged "run_end's mode dropped" "$Q/d.log" "$RE.pop('mode')" "run_end's mode None is not run_start's 'dry_run'"
    qforged "run_end's count of calls not enforced, one short" "$Q/d.log" "$RE['not_enforced'] -= 1" "calls not enforced; the stream holds $QN"
    qforged "a call let through after a revocation" "$Q/d.log" \
        "i = recs.index($NE[-1]); recs.insert(i, {'event': 'revoked', 'run': $RS['run'], 'by_uid': 0, 'by_pid': 1, 'timestamp_ns': recs[i].get('timestamp_ns', 0)})" \
        "a call let through after the run was revoked"
    qforged "enforced:false in an enforcing run" "$Q/e.log" \
        "[r for r in recs if isinstance(r, dict) and r.get('decision_final') == 'DENY' and r.get('rule') == 'default_deny_unknown'][0]['enforced'] = False" \
        "a record not enforced, in a run that is not a dry run"
    qforged "run_end counting calls not enforced in an enforcing run" "$Q/e.log" "$RE['not_enforced'] = 0" \
        "run_end counts calls not enforced in a run that is not a dry run"
    qforged "open_as dropped from run_start" "$Q/e.log" "$RS.pop('open_as')" "does not say whom files were opened as"
    qforged "open_as naming root" "$Q/e.log" "$RS['open_as']['uid'] = 0" "malformed (or names root)"
    qforged "the baseline's user changed in run_start" "$Q/e.log" "$RS['baseline']['user'] = 'root'" "is not the policy file's header"
    qforged "the baseline dropped from run_start" "$Q/e.log" "$RS.pop('baseline')" "the policy is a baseline, but run_start does not say so"
    # the export
    python3 "$HERE/tools/varek_cyclonedx.py" --log "$Q/d.log" --policy "$Q/b.txt" --agent t --output "$Q/d.cdx.json" > /dev/null 2>&1
    python3 "$HERE/tools/varek_cyclonedx.py" --log "$Q/e.log" --policy "$Q/b.txt" --agent t --output "$Q/e.cdx.json" > /dev/null 2>&1
    check "the export marks a dry run: mode, would_refuse, on each component, and the attestation" python3 -c "
import json, sys
b = json.load(open('$Q/d.cdx.json'))
p = {x['name']: x['value'] for x in b['metadata']['properties']}
c = {x['name']: x['value'] for x in b['metadata']['component']['properties']}
comps = [x for x in b.get('components', []) if any(y['name'] == 'varek:action' for y in x.get('properties', []))]
ok = (p.get('varek:mode') == 'dry_run' and c.get('varek:mode') == 'dry_run' and c.get('varek:decisions.would_refuse') == '$QN'
      and comps and all(any(y == {'name': 'varek:mode', 'value': 'dry_run'} for y in x['properties']) for x in comps)
      and any(a.get('text', '').startswith('DRY RUN, NOT ENFORCING') for a in b.get('annotations', [])))
sys.exit(0 if ok else 1)"
    check "... and an enforcing run as enforcing, with no would_refuse" python3 -c "
import json, sys
b = json.load(open('$Q/e.cdx.json'))
p = {x['name']: x['value'] for x in b['metadata']['properties']}
c = {x['name']: x['value'] for x in b['metadata']['component']['properties']}
sys.exit(0 if p.get('varek:mode') == 'enforcing' and c.get('varek:mode') == 'enforcing' and 'varek:decisions.would_refuse' not in c
         and not any(a.get('text', '').startswith('DRY RUN') for a in b.get('annotations', [])) else 1)"
    if [ -s "$Y/d.log" ]; then
        python3 "$HERE/tools/varek_cyclonedx.py" --log "$Y/d.log" --policy "$Y/p.txt" --agent t --output "$Q/y.cdx.json" > /dev/null 2>&1
        check "... would_refuse counts what run_end counts, the stub's questions included" python3 -c "
import json, sys
b = json.load(open('$Q/y.cdx.json'))
c = {x['name']: x['value'] for x in b['metadata']['component']['properties']}
end = [json.loads(l) for l in open('$Y/d.log') if l.startswith('{\"event\":\"run_end\"')][0]
q = sum(1 for l in open('$Y/d.log') if l.startswith('{\"event\":\"dns_question\"') and '\"enforced\":false' in l)
sys.exit(0 if q > 0 and c.get('varek:decisions.would_refuse') == str(end['not_enforced']) else 1)"
    else skip "would_refuse with the stub's questions (section 3 did not run)"; fi
    # the tools
    cp "$Q/e.log" "$Q/log/verdicts-1.log"; touch -d '2 minutes ago' "$Q/log/verdicts-1.log"
    cp "$Q/d.log" "$Q/log/verdicts-2.log"
    VQ() { VAREK_CONFIG="$Q/none/varek.conf" VAREK_LOG_DIR="$Q/log" python3 "$HERE/tools/varek" "$@"; }
    VQ refusals > "$Q/rf.out" 2>&1
    check "varek refusals: a dry run says DRY RUN, NOT ENFORCING, with the count" grep -q "DRY RUN, NOT ENFORCING: $QN call(s) the policy refuses were let through" "$Q/rf.out"
    check "... lists a call let through as WOULD_REFUSE, and why"  sh -c "grep -q '^  WOULD_REFUSE  file.open  *$Q/o/f\$' '$Q/rf.out' && grep -q 'let through (dry run: not enforced)' '$Q/rf.out'"
    check "... and a call refused all the same as refused (the stream)" sh -c "grep '  file.open  *$Q/d.log\$' '$Q/rf.out' | grep -qv WOULD_REFUSE"
    VQ refusals --not-enforced > "$Q/rn.out" 2>&1
    VQ refusals --enforced > "$Q/rx.out" 2>&1
    check "varek refusals --not-enforced: only the calls let through" sh -c "grep -q 'WOULD_REFUSE' '$Q/rn.out' && ! grep -q '$Q/d.log' '$Q/rn.out'"
    check "varek refusals --enforced: only the calls refused"         sh -c "! grep -q '^  WOULD_REFUSE' '$Q/rx.out' && grep -q '$Q/d.log\$' '$Q/rx.out'"
    VQ refusals "$Q/log/verdicts-1.log" > "$Q/re.out" 2>&1
    check "... an enforcing run: no dry-run header, no WOULD_REFUSE" sh -c "! grep -q 'DRY RUN\|WOULD_REFUSE' '$Q/re.out' && grep -q '$Q/o/f' '$Q/re.out'"
    VQ runs > "$Q/runs.out" 2>&1
    check "varek runs: a MODE column, dry run and enforce" sh -c "grep -q '^STARTED  *MODE ' '$Q/runs.out' && grep -q ' dry run .*verdicts-2.log\$' '$Q/runs.out' && grep -q ' enforce .*verdicts-1.log\$' '$Q/runs.out'"
    VQ status > "$Q/st.out" 2>&1
    check "varek status: the last run was a dry run, not enforced" grep -q "a DRY RUN, NOT ENFORCED: $QN call(s)" "$Q/st.out"
    VQ audit > "$Q/au.out" 2>&1; QU=$?
    check "varek audit: exit 3 for a dry run" sh -c "[ $QU = 3 ] && grep -q 'VERIFIED: DRY RUN, NOT ENFORCED' '$Q/au.out'"
    VQ policy show "$Q/b.txt" > "$Q/ps.out" 2>&1
    check "varek policy show: a baseline's header" grep -q "^Baseline written by \`varek run\` (format 1) for user nobody, working directory $Q/w, home /nonexistent, temporary directory /tmp; profile none" "$Q/ps.out"
    printf 'require warden 1.29\nallow path /usr/ readonly\n' > "$Q/plain.txt"
    VQ policy show "$Q/plain.txt" > "$Q/pp.out" 2>&1
    check "... and none for a policy that is not a baseline" sh -c "grep -q '^Policy ' '$Q/pp.out' && ! grep -q '^Baseline' '$Q/pp.out'"
    env -u SUDO_UID -u SUDO_USER VAREK_CONFIG="$Q/none/varek.conf" python3 "$HERE/tools/varek" doctor > "$Q/doc.out" 2>&1
    check "varek doctor: the dry run is available"                 grep -q "dry runs available" "$Q/doc.out"
    check "varek doctor: with no sudo user, the agent runs as nobody" grep -q "the baseline runs the agent as nobody (no sudo user)" "$Q/doc.out"
fi

echo "== 7. what the agents' dry runs found (step 6) =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "what the agents' dry runs found (it runs as root: the agent runs as another user)"
else
    G="$OUT/g7"
    mkdir -p "$G/bin" "$G/w" "$G/o/sub/d2" "$G/closed"
    chmod 755 "$G" "$G/bin" "$G/o" "$G/o/sub" "$G/o/sub/d2"; chmod 1777 "$G/w"; chmod 700 "$G/closed"
    cp "$HERE/tests/v1290_open" "$G/bin/"; chmod 755 "$G/bin/v1290_open"
    echo r > "$G/o/r"; echo s > "$G/o/secret"; chmod 644 "$G/o/r" "$G/o/secret"
    ln -s /etc/hostname "$G/o/link"
    gpol() {   # gpol FILE VERSION
        printf 'require warden %s\nallow path /usr/ readonly\nallow path /etc/ld.so.cache readonly\nallow path %s/w/\nallow path exact %s/o/r readonly\nallow path exact %s/o/link readonly\nallow path %s/o/sub/ readonly\nallow path %s/mi/x/ readonly\n' \
            "$2" "$G" "$G" "$G" "$G" "$G" > "$1"
    }
    gpol "$G/p129.txt" 1.29
    gpol "$G/p128.txt" 1.28
    G7=(rstat "$G/o/r" rstat "$G/o/secret" rstat "$G/w/nosuch" rlstat "$G/o/link"
        rstat "$G/mi/x/y" rstat "$G/mi/z/y" rstat "$G/mi/../mi/x/y" read "$G/mi/x/y"
        mkdir "$G/o/sub/d2" mkdir "$G/o" mkdir "$G/closed" mkdir "$G/w/new" admits "$G/o/r")
    (cd "$G/w" && "$WARDEN" "$G/p129.txt" --run-as nobody -- "$G/bin/v1290_open" "${G7[@]}" > "$G/a.out" 2> "$G/a.log")
    (cd "$G/w" && "$WARDEN" "$G/p128.txt" --run-as nobody -- "$G/bin/v1290_open" "${G7[@]}" > "$G/b.out" 2> "$G/b.log")
    go() { grep -qx "$1" "$G/a.out"; }
    bo() { grep -qx "$1" "$G/b.out"; }
    check "stat(2), as musl calls it: an allowed file is answered"                 go "rstat ok"
    check "... recorded as a lookup (file.stat), metadata_answered"                 rec "$G/a.log" "r.get('action') == 'file.stat' and r.get('resolved') == '$G/o/r' and r['rule'] == 'metadata_answered'"
    check "... a file the policy does not name: EACCES"                             go "rstat Permission denied"
    check "... a missing file where the policy allows it: ENOENT"                    go "rstat No such file or directory"
    check "lstat(2) answers the link itself"                                        rec "$G/a.log" "r.get('action') == 'file.stat' and r.get('resolved') == '$G/o/link' and r['rule'] == 'metadata_answered'"
    check "under require warden 1.28, stat(2) is refused by the filter (EPERM), as before" bo "rstat Operation not permitted"
    check "a lookup under a missing directory, of a name the policy allows: ENOENT" sh -c "grep -q 'rstat No such file or directory' '$G/a.out' && [ \"\$(grep -c '^rstat No such file or directory' '$G/a.out')\" = 2 ]"
    check "... decided on the whole name asked for"                                 rec "$G/a.log" "r.get('action') == 'file.stat' and r.get('resolved') == '$G/mi/x/y' and r['rule'] == 'metadata_not_found'"
    check "... a name it does not allow: EACCES, on the first missing directory"    rec "$G/a.log" "r.get('action') == 'file.stat' and r.get('target') == '$G/mi/z/y' and r.get('resolved') == '$G/mi/z/y' and r['decision_final'] == 'DENY'"
    check "... a name with .. after the missing directory: decided there (EACCES)"  rec "$G/a.log" "r.get('action') == 'file.stat' and r.get('target') == '$G/mi/../mi/x/y' and r.get('resolved') == '$G/mi' and r['decision_final'] == 'DENY'"
    check "... an open of it too: ENOENT"                                           go "read No such file or directory"
    check "mkdir of a directory the policy allows reading: EEXIST, nothing changed" sh -c "grep -qx 'mkdir File exists' '$G/a.out' && [ \"\$(grep -c '^mkdir File exists' '$G/a.out')\" = 2 ]"
    check "... recorded mkdir_exists, decided as a lookup (0x0)"                     rec "$G/a.log" "r.get('action') == 'file.mkdir' and r.get('resolved') == '$G/o/sub/d2' and r['rule'] == 'mkdir_exists' and r.get('open_flags') == '0x0' and r.get('errno') == 17"
    check "... of a directory the policy leads to: mkdir_exists_ancestor"           rec "$G/a.log" "r.get('action') == 'file.mkdir' and r.get('resolved') == '$G/o' and r['rule'] == 'mkdir_exists_ancestor' and r.get('errno') == 17"
    check "... of a directory it may not look up: EACCES, as before"                go "mkdir Permission denied"
    check "... and a new one is made"                                               sh -c "grep -qx 'mkdir ok' '$G/a.out' && [ -d '$G/w/new' ]"
    for c in getrusage getpgrp setpgid getsid capget fadvise64 flock fstatfs getitimer alarm umask prctl_set_name prctl_get_name pidfd_open setsid; do
        check "admitted under 1.29: $c"                                             go "$c ok"
    done
    check "prctl with any other option stays refused (PR_SET_DUMPABLE)"              go "prctl_set_dumpable Operation not permitted"
    check "under 1.28 they are refused, as before (getrusage, pidfd_open, setsid)"  sh -c "grep -qx 'getrusage Operation not permitted' '$G/b.out' && grep -qx 'pidfd_open Operation not permitted' '$G/b.out' && grep -qx 'setsid refused' '$G/b.out'"
    check "the audit passes the run" python3 "$HERE/tools/varek_audit.py" --policy "$G/p129.txt" --checker "$CERT" "$G/a.log"
    # a dry run of an earlier policy: what enforcing refuses in the filter is
    # recorded as a call outside the allowlist, not decided
    (cd "$G/w" && "$WARDEN" "$G/p128.txt" --dry-run --run-as nobody -- "$G/bin/v1290_open" rstat "$G/o/secret" mkdir "$G/w/n2" > /dev/null 2> "$G/d.log")
    check "a dry run under 1.28: stat(2) and mkdir are syscall_not_admitted, not decided" sh -c "
        python3 -c \"import json,sys; R=[json.loads(l) for l in open('$G/d.log') if l.startswith('{')]; t={r.get('target') for r in R if r.get('rule') == 'syscall_not_admitted'}; sys.exit(0 if 'syscall:4' in t and t & {'syscall:83','syscall:258'} and not any(r.get('action') == 'file.mkdir' for r in R) else 1)\""
    # noexec: a place inside a writable directory that keeps exec
    H7="$G/h"
    mkdir -p "$H7/inst/bin"; chmod 1777 "$H7"; chmod 755 "$H7/inst" "$H7/inst/bin"
    cp "$G/bin/v1290_open" "$H7/inst/bin/"; chmod 755 "$H7/inst/bin/v1290_open"
    printf 'require warden 1.29\nallow path /usr/ readonly\nallow path /etc/ld.so.cache readonly\nallow path glob %s/.cfg*\nallow path %s/inst/ readonly\n' "$H7" "$H7" > "$G/n129.txt"
    printf 'require warden 1.29\nallow path /usr/ readonly\nallow path /etc/ld.so.cache readonly\nallow path glob %s/in*\nallow path %s/inst/ readonly\n' "$H7" "$H7" > "$G/nreach.txt"
    sed 's/^require warden 1.29/require warden 1.28/' "$G/n129.txt" > "$G/n128.txt"
    (cd "$H7" && "$WARDEN" "$G/n129.txt" --run-as nobody -- "$H7/inst/bin/v1290_open" create "$H7/.cfgA" > "$G/n.out" 2> "$G/n.log")
    check "the agent's own program inside a directory it may write runs, its place kept executable" sh -c "grep -q '^create ok' '$G/n.out'"
    check "... run_start lists the directory noexec and the place kept executable" rec "$G/n.log" "r.get('event') == 'run_start' and [e['path'] for e in r['noexec']] == ['$H7'] and r['noexec_exec'] == [{'path': '$H7/inst', 'in': '$H7'}]"
    check "... the audit passes it" python3 "$HERE/tools/varek_audit.py" --policy "$G/n129.txt" --checker "$CERT" "$G/n.log"
    (cd "$H7" && "$WARDEN" "$G/nreach.txt" --run-as nobody -- "$H7/inst/bin/v1290_open" create "$H7/.cfgB" > /dev/null 2> "$G/r.log")
    check "a rule that could write there (glob in*): refused to start, as before" grep -q "noexec: the agent's own program $H7/inst/bin/v1290_open is under $H7" "$G/r.log"
    (cd "$H7" && "$WARDEN" "$G/n128.txt" --run-as nobody -- "$H7/inst/bin/v1290_open" create "$H7/.cfgC" > /dev/null 2> "$G/o.log")
    check "under 1.28: refused to start, as before"                                 grep -q "noexec: the agent's own program $H7/inst/bin/v1290_open is under $H7" "$G/o.log"
    qforge() {   # qforge LABEL STREAM POLICY PYTHON WORDS: the audit fails the forged stream for its reason
        python3 "$HERE/tests/v1270_forge.py" "$2" "$G/f.log" "$4" >/dev/null 2>&1
        if python3 "$HERE/tools/varek_audit.py" --policy "$3" --checker "$CERT" "$G/f.log" > "$G/f.out" 2>&1; then
            flunk "forged: $1 (the audit passed it)"
        elif grep -qF -- "$5" "$G/f.out"; then pass "forged: $1"
        else flunk "forged: $1 (not for its own reason: $(grep '^  PROBLEM' "$G/f.out" | head -2 | tr '\n' ' '))"; fi
    }
    NRS="[r for r in recs if isinstance(r, dict) and r.get('event') == 'run_start'][0]"
    qforge "a place kept executable that a writable rule reaches" "$G/n.log" "$G/n129.txt" "$NRS['noexec_exec'].append({'path': '$H7/.cfgdir', 'in': '$H7'})" "lets the agent write there"
    qforge "a place kept executable outside the noexec directories" "$G/n.log" "$G/n129.txt" "$NRS['noexec_exec'][0]['in'] = '/usr'" "which is not a directory run_start's noexec mounts"
    qforge "the places kept executable dropped" "$G/n.log" "$G/n129.txt" "$NRS.pop('noexec_exec')" "noexec_exec is missing or malformed"
    qforge "a mkdir answered EEXIST recorded with the flags of a create" "$G/a.log" "$G/p129.txt" "[r.__setitem__('open_flags', '0xc1') for r in recs if isinstance(r, dict) and r.get('rule') == 'mkdir_exists']" "which the Warden writes only for a mkdir decided as a lookup"
    qforge "a mkdir answered EEXIST as an ancestor that is not one" "$G/a.log" "$G/p129.txt" "[r.__setitem__('resolved', '$G/closed') for r in recs if isinstance(r, dict) and r.get('rule') == 'mkdir_exists_ancestor']" "is not one"
    # step 9: the launch set is hashed by libcrypto, which reads no
    # configuration (a file naming a provider that is not there would stop it)
    printf 'openssl_conf = oc\n[oc]\nproviders = pv\n[pv]\nbad = bp\n[bp]\nmodule = /nonexistent/varek-test-provider.so\nactivate = 1\n' > "$G/bad.cnf"
    (cd "$H7" && OPENSSL_CONF="$G/bad.cnf" "$WARDEN" "$G/n129.txt" --run-as nobody -- "$H7/inst/bin/v1290_open" read "$H7/inst/bin/v1290_open" > "$G/ssl.out" 2> "$G/ssl.log")
    check "the launch set's SHA-256 (libcrypto) reads no OpenSSL configuration" grep -qx 'read ok' "$G/ssl.out"
    check "... and each file's is the file's" rec "$G/ssl.log" "r.get('event') == 'run_start' and r['exec_ruleset'] and all(__import__('hashlib').sha256(open(e['path'], 'rb').read()).hexdigest() == e['sha256'] for e in r['exec_ruleset'])"
    # the baseline (6b)
    py7() { PYTHONPATH="$HERE/tools" python3 -c "import pwd, varek_baseline as b; $1"; }
    py7 "open('$G/base.txt','w').write(b.generate('$G/w', pwd.getpwnam('nobody'), '/tmp/varek-65534', None, path=b.SYSTEM_PATH + ':$G/bin'))"
    check "the baseline lets the agent read the CA bundles, before the key patterns" sh -c "a=\$(grep -n '^allow path /etc/ssl/certs/ readonly' '$G/base.txt' | cut -d: -f1); d=\$(grep -n '^deny  path glob /\*\*/\*.\[pP\]' '$G/base.txt' | head -1 | cut -d: -f1); [ -n \"\$a\" ] && [ -n \"\$d\" ] && [ \"\$a\" -lt \"\$d\" ] && grep -q '^allow path glob /\*\*/certifi/cacert.pem readonly' '$G/base.txt' && grep -q '^allow path exact /etc/pki/tls/cert.pem readonly' '$G/base.txt'"
    check "... what language runtimes read at startup (/proc/version, cgroup limits)" sh -c "grep -q '^allow path exact /proc/version readonly' '$G/base.txt' && grep -q '^allow path /sys/fs/cgroup/ readonly' '$G/base.txt'"
    check "... the directory its PATH gains for the agent's command, read-only" grep -qx "allow path $G/bin/ readonly" "$G/base.txt"
    check "... but not a directory that is not a bin (a command at /home/x)" py7 "
import sys
t = b.generate('$G/w', pwd.getpwnam('nobody'), '/tmp/varek-65534', None, path=b.SYSTEM_PATH + ':/home:$G')
sys.exit(1 if [l for l in t.splitlines() if l in ('allow path /home/ readonly', 'allow path $G/ readonly')] else 0)"
    if [ -d /usr/lib/git-core ] && command -v git >/dev/null; then
        check "... git's helpers (/usr/lib/git-core/)" grep -qx "allow exec prefix /usr/lib/git-core/" "$G/base.txt"
    else skip "git's helpers (no /usr/lib/git-core here)"; fi
    check "the baseline lints" "$VDP" "$G/base.txt" lint
    # the profiles (6c): none lets the agent write a name in the home itself
    # by a bare prefix (the whole home noexec, and agents installed there
    # could not start); exact names and globs are bounded, directories end in /
    check "no shipped profile has a writable prefix rule without a trailing slash" sh -c "! grep -h '^allow path \${HOME}/' '$HERE'/policies/agents/*.profile.txt | grep -v ' readonly' | grep -v '^allow path \(exact\|glob\) ' | awk '{print \$3}' | grep -v '/\$'"
    for prof in claude codex gemini aider python node; do
        py7 "p=b.load_profile('$HERE/policies/agents/$prof.profile.txt'); open('$G/prof-$prof.txt','w').write(b.generate('$G/w', pwd.getpwnam('nobody'), '/tmp/varek-65534', p))"
        check "the $prof profile's baseline lints and loads in the checker" sh -c "'$VDP' '$G/prof-$prof.txt' lint > /dev/null && '$CERT' '$G/prof-$prof.txt' digest > /dev/null"
    done
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1290: all checks passed ($skips skipped)"; else echo "test_v1290: FAILURES"; fi
exit "$fail"
