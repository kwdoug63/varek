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
check "require warden 1.99: refused by the procedure" sh -c "'$VDP' '$OUT/p.txt' analyze 2>&1 | grep -q 'requires Warden 1.99; this is 1.29'"
check "require warden 1.99: refused by the checker" sh -c "! '$CERT' '$OUT/p.txt' digest"
printf 'require warden 1.29\nallow path /usr/ readonly\n' > "$OUT/p.txt"

if [ -z "$WARDEN" ]; then
    skip "the Warden's checks (no warden binary given)"
elif [ "$(id -u)" != 0 ]; then
    skip "the Warden's checks (they run as root: the agent runs as another user)"
else
    check "the Warden reports 1.29.0 or later" sh -c "NO_COLOR=1 VAREK_CONFIG=/nonexistent python3 '$HERE/tools/varek' version | python3 -c 'import re,sys; m=re.search(r\"VAREK Warden  (\\d+)\\.(\\d+)\\.(\\d+)\", sys.stdin.read()); sys.exit(0 if m and tuple(map(int, m.groups())) >= (1, 29, 0) else 1)'"
    check "the Warden starts a 1.29 policy, read as version 1.29" sh -c "'$WARDEN' '$OUT/p.txt' --check-startup 2>&1 | grep -q 'loaded policy .* v1.29 '"

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
check "the credential stores come before any allow rule" sh -c "awk '/^allow /{a=NR} /contains \\/\\.ssh\\//{d=NR} END{exit !(d && (!a || d < a))}' '$OUT/gen/none.txt' && [ \"\$(grep -n '^allow ' '$OUT/gen/none.txt' | head -1 | cut -d: -f1)\" -gt \"\$(grep -n '^deny ' '$OUT/gen/none.txt' | tail -1 | cut -d: -f1)\" ]"
check "the header says what the baseline was made for" sh -c "head -6 '$OUT/gen/claude.txt' | grep -q '^#@ profile claude [0-9a-f]\{64\}$' && grep -qx '#@ cwd $OUT/gproj' '$OUT/gen/claude.txt' && grep -qx '#@ user nobody' '$OUT/gen/claude.txt'"
check "the claude profile's \${HOME} becomes the user's home" grep -q "^allow path /nonexistent/.claude " "$OUT/gen/claude.txt"
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
        check "--show-policy prints the baseline (the claude profile) and runs nothing" sh -c "grep -q '^#@ profile claude ' '$OUT/sp.out' && grep -q '^allow path $BH/.claude ' '$OUT/sp.out'"
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

echo
if [ "$fail" = 0 ]; then echo "test_v1290: all checks passed ($skips skipped)"; else echo "test_v1290: FAILURES"; fi
exit "$fail"
