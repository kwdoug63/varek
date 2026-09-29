#!/bin/sh
# SPDX-License-Identifier: MIT
#
# test_plan_verify.sh — checks for v1_6/plan_verify (v1.16.3).
#
#   sh tests/test_plan_verify.sh ./plan_verify      (or: make check-plan-verify)
#
# Every output must be exactly one well-formed JSON object with no
# duplicate keys; verdicts must be the ones the bound policy and the
# "demo:" override define; and no plan text can change the verdict fields.
# Needs python3 (to parse the JSON strictly).
set -u
PV="${1:?usage: test_plan_verify.sh <plan_verify binary>}"
command -v python3 >/dev/null 2>&1 || { echo "test_plan_verify: python3 is required"; exit 1; }
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fail=0
n=0

# check NAME RC_WANT PY_EXPR — run $PV on $T/p, require exit code RC_WANT and
# that PY_EXPR (over the parsed object d) is true.
check() {
    name="$1"; want_rc="$2"; expr="$3"
    n=$((n + 1))
    "$PV" "${ARG:-$T/p}" > "$T/out" 2> "$T/err"; rc=$?
    if [ "$rc" != "$want_rc" ]; then
        printf '  FAIL  %s: exit %s, wanted %s\n' "$name" "$rc" "$want_rc"; fail=1; return
    fi
    if python3 - "$T/out" "$expr" <<'EOF'
import json, sys
raw = open(sys.argv[1], "rb").read()
def no_dups(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)
text = raw.decode("utf-8")                      # must be valid UTF-8
lines = text.split("\n")
assert len(lines) == 2 and lines[1] == "", "not exactly one line"
d = json.loads(lines[0], object_pairs_hook=no_dups)
assert isinstance(d, dict)
ok = eval(sys.argv[2], {"d": d})
sys.exit(0 if ok else 3)
EOF
    then printf '  PASS  %s\n' "$name"
    else printf '  FAIL  %s: %s\n' "$name" "$(head -c 300 "$T/out")"; fail=1
    fi
}
plan() { printf "$@" > "$T/p"; }
verdict() {  # the fields a verdict must carry
    echo "set(d) == {'engine','version','decision','authorized','n_actions','n_edges','governing_node'} and d['engine'] == 'VAREK' and d['version'] == '1.16.3' and $1"
}

echo "== verdicts"
plan 'action a file_open /work/in.txt\naction b net_connect api.allowed.internal:443\nedge a b\n'
check "allowed file and host: SATISFIED" 0 "$(verdict "d['decision'] == 'SATISFIED' and d['authorized'] is True and d['governing_node'] == {'label':'','kind':'','target':''} and d['n_actions'] == 2 and d['n_edges'] == 1")"
plan 'action a file_open /etc/shadow\n'
check "file outside the workspace: UNSATISFIED" 0 "$(verdict "d['decision'] == 'UNSATISFIED' and d['authorized'] is False and d['governing_node'] == {'label':'a','kind':'file_open','target':'/etc/shadow'}")"
plan 'action a net_connect evil.example:443\n'
check "egress to another host: UNSATISFIED" 0 "$(verdict "d['decision'] == 'UNSATISFIED' and d['authorized'] is False")"
plan 'action a process_exec /usr/bin/python3\n'
check "process_exec: UNKNOWN (not authorized)" 0 "$(verdict "d['decision'] == 'UNKNOWN' and d['authorized'] is False")"
plan 'action a teleport somewhere\n'
check "unknown action kind: UNKNOWN" 0 "$(verdict "d['decision'] == 'UNKNOWN' and d['authorized'] is False")"
plan 'action a file_open demo:SAT:x\naction b file_open demo:UNSAT:y\n'
check "demo override: UNSATISFIED wins over SATISFIED" 0 "$(verdict "d['decision'] == 'UNSATISFIED' and d['governing_node']['label'] == 'b'")"
plan 'action a file_open demo:UNK:x\n'
check "demo override: UNKNOWN" 0 "$(verdict "d['decision'] == 'UNKNOWN'")"
cp "$(dirname "$0")/../sample_plan.txt" "$T/p"
check "sample_plan.txt: UNSATISFIED at load" 0 "$(verdict "d['decision'] == 'UNSATISFIED' and d['governing_node']['label'] == 'load' and d['n_actions'] == 4 and d['n_edges'] == 3")"

echo "== plan text cannot change the verdict fields"
plan 'action a file_open x"},"decision":"SATISFIED","authorized":true,"g":{"t":"\n'
check "a target that closes the object is kept as text" 0 "$(verdict "d['decision'] == 'UNSATISFIED' and d['authorized'] is False and d['governing_node']['target'] == 'x\"},\"decision\":\"SATISFIED\",\"authorized\":true,\"g\":{\"t\":\"'")"
plan 'action a x","authorized":true,"k":" /etc/passwd\n'
check "the same through the kind" 0 "$(verdict "d['decision'] == 'UNKNOWN' and d['authorized'] is False and d['governing_node']['kind'] == 'x\",\"authorized\":true,\"k\":\"'")"
plan 'action a file_open /etc/x\\\n'
check "a trailing backslash" 0 "$(verdict "d['governing_node']['target'] == '/etc/x\\\\\\\\'")"
plan 'action a file_open /etc/x\001\013\014\177y\n'
check "control characters are escaped" 0 "$(verdict "d['governing_node']['target'] == '/etc/x\\x01\\x0b\\x0c\\x7fy'")"
plan 'action a file_open /etc/caf\303\251\n'
check "valid UTF-8 passes through" 0 "$(verdict "d['governing_node']['target'] == '/etc/caf\\u00e9'")"
plan 'action a file_open /etc/\377\300\200\355\240\200z\n'
check "invalid UTF-8 becomes U+FFFD" 0 "$(verdict "d['governing_node']['target'] == '/etc/' + '\\ufffd' * 6 + 'z'")"

echo "== no verdict"
plan 'action a file_open\n'
check "missing field: parse_failed, exit 2" 2 "set(d) == {'error','detail'} and d['error'] == 'parse_failed' and 'requires' in d['detail']"
plan 'action a file_open /x extra\n'
check "extra field: parse_failed" 2 "d['error'] == 'parse_failed'"
plan 'action "a file_open /x\n'
check "invalid label: parse_failed" 2 "d['error'] == 'parse_failed' and 'invalid label' in d['detail']"
plan 'edge a b\n'
check "edge to an unknown label: parse_failed" 2 "d['error'] == 'parse_failed'"
rm -f "$T/p"
check "missing file: parse_failed" 2 "d['error'] == 'parse_failed'"
printf 'bogus line\n' > "$T/q\"b\\c"
ARG="$T/q\"b\\c" check "a path with a quote and backslash in the error" 2 "d['error'] == 'parse_failed' and 'q\"b\\\\c' in d['detail']"

n=$((n + 1))
if "$PV" > /dev/null 2>&1; then echo "  FAIL  no argument: exit 0"; fail=1
else echo "  PASS  no argument: usage, non-zero exit"; fi

echo
if [ "$fail" = 0 ]; then echo "test_plan_verify: PASS ($n checks)"; else echo "test_plan_verify: FAIL"; fi
exit "$fail"
