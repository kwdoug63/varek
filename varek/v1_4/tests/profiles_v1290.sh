#!/bin/bash
# SPDX-License-Identifier: MIT
# profiles_v1290.sh — v1.29 step 6: each shipped agent profile against the
# real CLI (docs/security/v1.29-varek-run.md, step 6).
#
# Not part of `make test-v1290`: it needs root and network access to the npm
# registry and PyPI, and installs the CLIs for a throwaway user in that
# user's home. No account, key or sign-in is used: each agent runs until it
# asks for one. For each command it makes a dry run (what the policy would
# refuse is listed), runs it enforcing, and runs it without VAREK, then
# reports whether the enforcing run's output is the unsupervised run's.
#
#   sudo tests/profiles_v1290.sh [--keep]     (on the laptop or the droplet)
#
# The CLIs change: a difference is reported, for review, not failed on.
# --keep leaves the user and its installs for another run.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
U="${VAREK_PROFILE_USER:-varekprof1290}"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1
[ "$(id -u)" = 0 ] || { echo "profiles_v1290: run it as root (sudo)"; exit 2; }
for t in npm node git python3 timeout runuser; do
    command -v "$t" > /dev/null || { echo "profiles_v1290: $t is not installed"; exit 2; }
done
[ -x "$HERE/warden" ] || { echo "profiles_v1290: build first (make)"; exit 2; }
OUT="$(mktemp -d)"
chmod 755 "$OUT"
made=0
if ! id "$U" > /dev/null 2>&1; then
    useradd -m -s /bin/bash "$U" || exit 2
    made=1
fi
H="$(getent passwd "$U" | cut -d: -f6)"
UID_="$(id -u "$U")"; GID_="$(id -g "$U")"
as_user() { runuser -u "$U" -- env -i HOME="$H" USER="$U" PATH="/usr/local/bin:/usr/bin:/bin:$H/.local/bin:$H/.npm-global/bin" "$@"; }

echo "== installing the CLIs for $U (in $H) =="
# installed by root (with root's network settings: a proxy, its CA) into the
# user's home, then given to the user, as its own install would be
if [ ! -x "$H/.npm-global/bin/codex" ]; then
    npm install -g --prefix "$H/.npm-global" @anthropic-ai/claude-code @openai/codex @google/gemini-cli \
        > "$OUT/npm.log" 2>&1 || { echo "npm install failed: $OUT/npm.log"; exit 2; }
fi
if [ ! -x "$H/.local/bin/aider" ]; then
    if command -v uv > /dev/null; then
        UV_TOOL_DIR="$H/.local/share/uv/tools" UV_TOOL_BIN_DIR="$H/.local/bin" \
            uv tool install --python "$(command -v python3)" aider-chat > "$OUT/uv.log" 2>&1 \
            || echo "aider (uv tool) did not install: $OUT/uv.log"
    else
        echo "uv is not installed: aider is skipped"
    fi
fi
chown -R "$U:" "$H/.npm-global" "$H/.local" 2> /dev/null
mkdir -p "$H/proj"
chown "$U:" "$H/proj"
as_user sh -c "cd '$H/proj' && [ -d .git ] || { git init -q && printf 'def add(a, b):\n    return a + b\n' > calc.py && git add . && git -c user.name=t -c user.email=t@example.invalid commit -qm init; }"

CONF="$OUT/etc"; LIB="$OUT/lib"; LOGD="$OUT/log"
mkdir -p "$CONF" "$LIB" "$LOGD"
# vr NAME [--dry-run] -- COMMAND...: varek run in the project, as root with sudo's variables
vr() {
    local n="$1"; shift
    (cd "$H/proj" && env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root TERM=dumb \
        SUDO_UID="$UID_" SUDO_GID="$GID_" SUDO_USER="$U" \
        VAREK_CONFIG="$CONF/varek.conf" VAREK_LIB_DIR="$LIB" VAREK_LOG_DIR="$LOGD" \
        timeout -s INT 100 python3 "$HERE/tools/varek" run "$@" < /dev/null > "$OUT/$n.out" 2> "$OUT/$n.err")
    echo $? > "$OUT/$n.rc"
}
direct() {
    local n="$1"; shift
    (cd "$H/proj" && timeout 90 runuser -u "$U" -- env -i HOME="$H" USER="$U" LOGNAME="$U" TERM=dumb \
        PATH="/usr/local/bin:/usr/bin:/bin:$H/.local/bin:$H/.npm-global/bin" "$@" \
        < /dev/null > "$OUT/$n.out" 2> "$OUT/$n.err")
    echo $? > "$OUT/$n.rc"
}
reset_proj() { as_user git -C "$H/proj" checkout -q .; as_user git -C "$H/proj" clean -qfdx; }
# the agent's own lines, as the comparison reads them (no VAREK lines, no
# times, session ids or temporary names)
norm() {
    cat "$1.out" "$1.err" 2> /dev/null | sed 's/^\[agent\] //' | grep -v '^\[varek\]\|^\[warden\]\|^   \[warden\]\|^{' |
        sed -E 's/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z//g; s/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ID/g' |
        grep -v 'Permission denied\|could not create PATH aliases' | head -20
}

CASES=(
    "claude-version:claude:$H/.npm-global/bin/claude --version"
    "claude-prompt:claude:$H/.npm-global/bin/claude -p hi"
    "codex-version:codex:$H/.npm-global/bin/codex --version"
    "codex-prompt:codex:$H/.npm-global/bin/codex exec --sandbox danger-full-access hi"
    "gemini-version:gemini:$H/.npm-global/bin/gemini --version"
    "gemini-prompt:gemini:$H/.npm-global/bin/gemini -p hi"
    "aider-version:aider:$H/.local/bin/aider --version"
    "aider-prompt:aider:$H/.local/bin/aider --message hi --no-check-update --yes-always --no-gitignore"
)
printf '\n%-16s %-8s %10s %10s %8s  %s\n' CASE PROFILE "DIRECT RC" "VAREK RC" REFUSED "SAME OUTPUT"
for c in "${CASES[@]}"; do
    n="${c%%:*}"; rest="${c#*:}"; prof="${rest%%:*}"; cmd="${rest#*:}"
    exe="${cmd%% *}"
    if [ ! -x "$exe" ]; then printf '%-16s %-8s %s\n' "$n" "$prof" "not installed: skipped"; continue; fi
    reset_proj; vr "$n-dry" --dry-run --profile "$prof" -- $cmd
    log="$(ls -t "$LOGD"/verdicts-*.log | head -1)"
    nr="$(grep -c '"enforced":false' "$log")"
    VAREK_CONFIG="$CONF/varek.conf" VAREK_LOG_DIR="$LOGD" python3 "$HERE/tools/varek" refusals --not-enforced -n 200 "$log" \
        > "$OUT/$n-dry.refusals" 2>&1
    reset_proj; vr "$n-varek" --profile "$prof" -- $cmd
    reset_proj; direct "$n-direct" $cmd
    same=no
    [ "$(norm "$OUT/$n-varek")" = "$(norm "$OUT/$n-direct")" ] && same=yes
    printf '%-16s %-8s %10s %10s %8s  %s\n' "$n" "$prof" "$(cat "$OUT/$n-direct.rc")" "$(cat "$OUT/$n-varek.rc")" "$nr" "$same"
done
echo
echo "What each dry run would refuse: $OUT/*-dry.refusals; the outputs: $OUT/*-{varek,direct}.{out,err}"
echo "(rc 124 or 130 is the time limit: the agent waiting on a model API it cannot reach without a key.)"
if [ "$KEEP" = 0 ] && [ "$made" = 1 ]; then
    userdel -r "$U" 2> /dev/null
    echo "removed the user $U and its home"
fi
