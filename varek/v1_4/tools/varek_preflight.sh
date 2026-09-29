#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# varek_preflight.sh — check a Warden deployment before you run it (v1.16.1).
#
#   tools/varek_preflight.sh <policy> [--log PATH] [--sign-key KEY] [--anchor PATH]
#                            [--run] [--install-deps]
#
# Checks, in order, and prints PASS / WARN / FAIL for each:
#   1. Build dependencies: libseccomp and libsodium headers (v1.16 needs
#      libsodium). --install-deps installs them with apt-get or dnf (sudo).
#   2. Build: the Warden and its tools (make, incremental).
#   3. The policy parses and lints.
#   4. The places v1.16 refuses at startup, decided exactly as the Warden
#      decides them (the certificate checker's vdpc_path_openable):
#        --log PATH     the verdict stream file (2> PATH) must not be a file
#                       the policy lets the agent open;
#        --sign-key K   the key must be a private regular file with one name,
#                       64 hex characters, that the agent cannot open;
#        --anchor PATH  the agent must not be able to open the anchor;
#        with a key or an anchor, the agent must not be able to open a block
#        device, /dev/mem, /dev/kmem, /dev/port, /proc/kcore, /dev/sg*,
#        /dev/nvme* or /dev/bsg/*.
#   5. --run: a real trial run (`warden ... -- /bin/true`, as root), writing its
#      verdict stream next to --log (a temporary file in the same directory,
#      removed afterwards), then the audit of that stream (with KEY.pub if it
#      exists, and the anchor if it is a regular file). With --anchor, the
#      trial run's checkpoints are appended to the real anchor like any run's.
#
# Exit status 0 when nothing FAILed. Needs no root except for --run and
# --install-deps.
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"          # varek/v1_4
POLICY="" LOG="" KEY="" ANCHOR="" RUN=0 INSTALL=0
usage() { sed -n '4,6p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
while [ $# -gt 0 ]; do
    case "$1" in
        --log)          LOG="${2:?}"; shift 2 ;;
        --sign-key)     KEY="${2:?}"; shift 2 ;;
        --anchor)       ANCHOR="${2:?}"; shift 2 ;;
        --run)          RUN=1; shift ;;
        --install-deps) INSTALL=1; shift ;;
        -h|--help)      usage ;;
        -*)             echo "unknown option $1" >&2; usage ;;
        *)              [ -z "$POLICY" ] || usage; POLICY="$1"; shift ;;
    esac
done
[ -n "$POLICY" ] || usage

fails=0 warns=0
pass() { printf '  PASS  %s\n' "$1"; }
warn() { printf '  WARN  %s\n' "$1"; warns=$((warns + 1)); }
fail() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
abs() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"

echo "== 1. build dependencies"
have_header() { printf '#include <%s>\n' "$1" | ${CC:-cc} -E -x c - >/dev/null 2>&1; }
missing=""
command -v "${CC:-cc}" >/dev/null 2>&1 || missing="$missing compiler"
have_header seccomp.h || missing="$missing libseccomp"
have_header sodium.h || missing="$missing libsodium"
if [ -n "$missing" ] && [ "$INSTALL" = 1 ]; then
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get install -y build-essential libseccomp-dev libsodium-dev
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y gcc make libseccomp-devel libsodium-devel
    fi
    missing=""
    command -v "${CC:-cc}" >/dev/null 2>&1 || missing="$missing compiler"
    have_header seccomp.h || missing="$missing libseccomp"
    have_header sodium.h || missing="$missing libsodium"
fi
if [ -z "$missing" ]; then
    pass "compiler, libseccomp and libsodium headers found"
else
    fail "missing:$missing. Install with: sudo apt-get install -y build-essential libseccomp-dev libsodium-dev (Debian/Ubuntu) or sudo dnf install -y gcc make libseccomp-devel libsodium-devel (Fedora/RHEL), or rerun with --install-deps"
    echo "preflight: FAIL (cannot build without the dependencies)"; exit 1
fi

echo "== 2. build"
if make -s -C "$HERE" warden tools/vdp_check tools/vdp_cert_check tools/varek_keygen >/tmp/varek_preflight_build.$$ 2>&1; then
    pass "warden and tools built ($HERE)"
else
    fail "build failed: $(grep -m1 -i error /tmp/varek_preflight_build.$$)"
    rm -f /tmp/varek_preflight_build.$$
    echo "preflight: FAIL"; exit 1
fi
rm -f /tmp/varek_preflight_build.$$
VDP="$HERE/tools/vdp_check" CERT="$HERE/tools/vdp_cert_check" WARDEN="$HERE/warden"

echo "== 3. policy"
o="$("$VDP" "$POLICY" lint 2>&1)"; rc=$?
if [ "$rc" -eq 2 ] || grep -q "^policy error" <<<"$o"; then
    fail "the policy does not load: $(head -1 <<<"$o")"
    echo "preflight: FAIL"; exit 1
fi
if ! "$CERT" "$POLICY" digest >/dev/null 2>&1; then
    fail "the certificate checker refuses the policy: $("$CERT" "$POLICY" digest 2>&1 | head -1)"
else
    pass "the policy loads ($(grep -o 'glob tokens [0-9]* of [0-9]*' <<<"$o"), sha256 $("$CERT" "$POLICY" digest | cut -c1-16)…)"
fi
[ "$rc" -eq 1 ] && warn "lint: $(grep -c 'can never fire' <<<"$o") rule(s) can never fire (tools/vdp_check $POLICY lint)"

echo "== 4. what the Warden refuses at startup"
openable() { printf '%s\n' "$1" | "$CERT" "$POLICY" openable | head -1; }
if [ -n "$LOG" ]; then
    L="$(abs "$LOG")"
    r="$(openable "$L")"
    case "$r" in
        closed*)   pass "verdict stream ${r#closed }: the agent cannot open it" ;;
        openable*) fail "verdict stream ${r#openable }: the policy lets the agent open it, so the Warden will refuse to start. Put the log outside every allowed path (e.g. /var/log/varek/, and keep a 'deny path /var/log/varek/' before any broader /var/log/ allow)" ;;
        *)         fail "verdict stream $L: $r" ;;
    esac
    if [ -f "$L" ] && [ "$(stat -c %h "$L")" != 1 ]; then
        fail "verdict stream $L has $(stat -c %h "$L") names (hard links); the Warden refuses it"
    fi
    [ -d "$(dirname "$L")" ] || warn "the log directory $(dirname "$L") does not exist yet"
else
    warn "no --log given: the verdict stream location is not checked (the Warden refuses a stream file the agent could open)"
fi
if [ -n "$KEY" ]; then
    K="$(abs "$KEY")"
    if [ -L "$K" ]; then fail "signing key $K is a symlink (refused)"
    elif [ ! -f "$K" ]; then fail "signing key $K does not exist (make one with tools/varek_keygen $K)"
    else
        m="$(stat -c %a "$K")"; nl="$(stat -c %h "$K")"
        [ $((8#$m & 8#077)) -eq 0 ] && pass "signing key mode $m" || fail "signing key mode $m: readable or writable by group or others (chmod 600 $K)"
        [ "$nl" = 1 ] && pass "signing key has one name" || fail "signing key has $nl names (hard links): refused"
        if $SUDO test -r "$K"; then
            c="$($SUDO head -c 66 "$K" | tr -d '\n')"
            [[ "$c" =~ ^[0-9a-fA-F]{64}$ ]] && pass "signing key is 64 hex characters" \
                || fail "signing key is not 64 hex characters (make one with tools/varek_keygen)"
        fi
        r="$(openable "$K")"
        case "$r" in
            closed*) pass "signing key: the agent cannot open it" ;;
            *)       fail "signing key: the policy lets the agent open ${r#openable } (refused)" ;;
        esac
        [ -f "$K.pub" ] || warn "no $K.pub next to the key: give auditors the public key (tools/varek_audit.py --pubkey)"
    fi
fi
if [ -n "$ANCHOR" ]; then
    A="$(abs "$ANCHOR")"
    r="$(openable "$A")"
    case "$r" in
        closed*) pass "anchor ${r#closed }: the agent cannot open it" ;;
        *)       fail "anchor: the policy lets the agent open ${r#openable } (refused)" ;;
    esac
    if [ -p "$A" ]; then warn "anchor is a FIFO: its reader must be running before the Warden starts"; fi
fi
if [ -n "$KEY$ANCHOR" ]; then
    raw="$( { find /dev \( -type b -o -type c \) 2>/dev/null | grep -E '^/dev/(mem|kmem|port|sg[^/]*|nvme[^/]*|bsg/.*)$'
              find /dev -maxdepth 5 -type b 2>/dev/null
              [ -e /proc/kcore ] && echo /proc/kcore; } | sort -u | "$CERT" "$POLICY" openable | grep '^openable' | head -5)"
    if [ -z "$raw" ]; then pass "no raw disk or memory device is open to the agent"
    else fail "the policy lets the agent open raw storage (refused with a key or anchor): $(tr '\n' ' ' <<<"${raw//openable /}")"; fi
fi

if [ "$RUN" = 1 ]; then
    echo "== 5. trial run"
    if [ "$fails" -gt 0 ]; then
        fail "skipped: fix the failures above first"
    else
        dir="$( [ -n "$LOG" ] && dirname "$(abs "$LOG")" || echo /tmp )"
        T="$dir/.varek-preflight.$$.log"
        args=("$POLICY"); [ -n "$KEY" ] && args+=(--sign-key "$KEY"); [ -n "$ANCHOR" ] && args+=(--anchor "$ANCHOR")
        $SUDO sh -c 'exec "$0" "$@" 2> "'"$T"'"' "$WARDEN" "${args[@]}" -- /bin/true >/dev/null; rc=$?
        if $SUDO grep -q '"event":"run_end"' "$T" 2>/dev/null; then
            pass "the Warden started, supervised /bin/true and closed its stream (rc $rc)"
            aa=(--policy "$POLICY" --checker "$CERT")
            [ -n "$KEY" ] && [ -f "$(abs "$KEY").pub" ] && aa+=(--pubkey "$(abs "$KEY").pub")
            [ -n "$ANCHOR" ] && [ -f "$(abs "$ANCHOR")" ] && aa+=(--anchor "$(abs "$ANCHOR")")
            o="$($SUDO python3 "$HERE/tools/varek_audit.py" "${aa[@]}" "$T" 2>&1)"
            if grep -q "varek_audit: PASS" <<<"$o"; then pass "audit: $(grep -o 'integrity: .*' <<<"$o")"
            else fail "audit of the trial stream: $(grep -m1 -E 'PROBLEM|FAIL' <<<"$o")"; fi
        else
            fail "the Warden did not run: $($SUDO grep -m1 -v 'can never fire' "$T" 2>/dev/null)"
        fi
        $SUDO rm -f "$T"
    fi
fi

echo
if [ "$fails" -eq 0 ]; then echo "preflight: PASS ($warns warning(s))"; else echo "preflight: FAIL ($fails failure(s), $warns warning(s))"; fi
[ "$fails" -eq 0 ]
