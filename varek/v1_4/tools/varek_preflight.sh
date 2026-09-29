#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# varek_preflight.sh — check a Warden deployment before you run it (v1.16.1).
#
#   tools/varek_preflight.sh <policy> [--log PATH] [--sign-key KEY] [--anchor PATH]
#                            [--spool DIR] [--run] [--install-deps]
#
# Checks, in order, and prints PASS / WARN / FAIL for each:
#   1. The Warden and its tools are built and up to date; if not, the build
#      dependencies (compiler, libseccomp and libsodium headers; v1.16 needs
#      libsodium) are checked and the tools are built. --install-deps installs
#      missing dependencies with apt-get or dnf (sudo). A host with up-to-date
#      binaries needs neither a compiler nor the headers.
#   2. The policy loads in both parsers and lints.
#   3. The places the Warden refuses at startup, with the same check it uses
#      (the certificate checker's vdpc_path_openable, on the path an open would
#      reach; tools/vdp_cert_check <policy> openable):
#        --log PATH     the verdict stream file (2> PATH): must not be a file the
#                       policy lets the agent open, and must have one name; its
#                       directory must exist;
#        --sign-key K   a regular file (not a symlink) with one name, mode
#                       without group/other bits, exactly 64 hex characters
#                       (optionally a trailing newline), that the agent cannot
#                       open;
#        --anchor PATH  not a symlink; a regular file (one name), FIFO or
#                       character device, or a new file in an existing
#                       directory; the agent cannot open it;
#                       A FIFO anchor must have its reader (the forwarder,
#                       tools/varek_anchor_forward.py) running; a regular-file
#                       anchor on this host is a warning, since this host's root
#                       could rewrite it;
#        --spool DIR    the forwarder's spool: the agent must not open it;
#        with a key or an anchor, the agent must not be able to open a block
#        device, /dev/mem, /dev/kmem, /dev/port, /proc/kcore, /dev/sg*,
#        /dev/nvme* or /dev/bsg/*.
#      These checks cannot see everything the Warden sees (whether a FIFO has
#      a reader, for one); --run is the definitive test.
#   4. --run: a real trial run (`warden ... -- /bin/true`, as root, via sudo if
#      needed), its verdict stream written to a new temporary file (mktemp) in
#      the --log directory, which must belong to root and not be writable by
#      others (or be sticky, like /tmp); then the audit of that stream (with
#      KEY.pub if it exists, and the anchor if it is a regular file, or the
#      forwarder's spool (--spool) for a FIFO anchor). The
#      temporary file is removed. With --anchor, the trial run's checkpoints
#      are appended to the real anchor like any run's.
#
# Exit status 0 when nothing FAILed. Only --run and --install-deps use sudo; a
# key this user cannot read is reported, not read through sudo.
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"          # varek/v1_4
POLICY="" LOG="" KEY="" ANCHOR="" SPOOL="" RUN=0 INSTALL=0
usage() { sed -n '6,7p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
need() { [ $# -ge 2 ] && [ -n "$2" ] || { echo "varek_preflight: $1 needs a value" >&2; usage; }; }
while [ $# -gt 0 ]; do
    case "$1" in
        --log)          need "$@"; LOG="$2"; shift 2 ;;
        --sign-key)     need "$@"; KEY="$2"; shift 2 ;;
        --anchor)       need "$@"; ANCHOR="$2"; shift 2 ;;
        --spool)        need "$@"; SPOOL="$2"; shift 2 ;;
        --run)          RUN=1; shift ;;
        --install-deps) INSTALL=1; shift ;;
        -h|--help)      usage ;;
        -*)             echo "varek_preflight: unknown option $1" >&2; usage ;;
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
TOOLS=(warden tools/vdp_check tools/vdp_cert_check tools/varek_keygen)

echo "== 1. build"
if make -q -C "$HERE" "${TOOLS[@]}" >/dev/null 2>&1; then
    pass "the Warden and its tools are built and up to date"
else
    have_header() { printf '#include <%s>\n' "$1" | ${CC:-cc} -E -x c - >/dev/null 2>&1; }
    missing_deps() {
        missing=""
        command -v "${CC:-cc}" >/dev/null 2>&1 || missing="$missing compiler"
        have_header seccomp.h || missing="$missing libseccomp"
        have_header sodium.h || missing="$missing libsodium"
    }
    missing_deps
    if [ -n "$missing" ] && [ "$INSTALL" = 1 ]; then
        if command -v apt-get >/dev/null 2>&1; then
            $SUDO apt-get update && $SUDO apt-get install -y build-essential libseccomp-dev libsodium-dev
        elif command -v dnf >/dev/null 2>&1; then
            $SUDO dnf install -y gcc make libseccomp-devel libsodium-devel
        fi
        missing_deps
    fi
    if [ -n "$missing" ]; then
        fail "missing:$missing. Install with: sudo apt-get update && sudo apt-get install -y build-essential libseccomp-dev libsodium-dev (Debian/Ubuntu) or sudo dnf install -y gcc make libseccomp-devel libsodium-devel (Fedora/RHEL), or rerun with --install-deps"
        echo "preflight: FAIL (cannot build without the dependencies)"; exit 1
    fi
    pass "compiler, libseccomp and libsodium headers found"
    blog="$(mktemp)"
    if make -s -C "$HERE" "${TOOLS[@]}" >"$blog" 2>&1; then
        pass "the Warden and its tools built ($HERE)"
        rm -f "$blog"
    else
        fail "build failed: $(grep -m1 -iE 'error|no rule|stop' "$blog" || tail -1 "$blog")"
        rm -f "$blog"
        echo "preflight: FAIL"; exit 1
    fi
fi
VDP="$HERE/tools/vdp_check" CERT="$HERE/tools/vdp_cert_check" WARDEN="$HERE/warden"

echo "== 2. policy"
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

echo "== 3. what the Warden refuses at startup"
# The canonical path an open would reach, and whether the agent could open it.
openable() { printf '%s\n' "$1" | "$CERT" "$POLICY" openable | head -1; }
canon_of() { local r; r="$(openable "$1")"; printf '%s' "${r#* }"; }
LOGDIR=""
if [ -n "$LOG" ]; then
    L="$(abs "$LOG")"
    r="$(openable "$L")"; C="${r#* }"
    case "$r" in
        closed*)   pass "verdict stream $C: the agent cannot open it" ;;
        openable*) if [ -e "$C" ] && [ ! -f "$C" ]; then
                       warn "verdict stream $C is not a regular file (FIFO or device) the agent could open; the Warden only refuses regular files, but the agent could read or disturb it"
                   else
                       fail "verdict stream $C: the policy lets the agent open it, so the Warden will refuse to start. Put the log outside every allowed path (e.g. /var/log/varek/, with a 'deny path /var/log/varek/' before any broader /var/log/ allow)"
                   fi ;;
        *)         fail "verdict stream $L: $r" ;;
    esac
    case "$r" in
        error*) ;;
        *)  LOGDIR="$(dirname "$C")"
            if [ -f "$C" ] && [ "$(stat -c %h "$C")" != 1 ]; then
                fail "verdict stream $C has $(stat -c %h "$C") names (hard links); the Warden refuses it"
            fi
            [ -d "$LOGDIR" ] || fail "the log directory $LOGDIR does not exist (create it first; the Warden's stderr cannot be opened there)" ;;
    esac
else
    warn "no --log given: the verdict stream location is not checked (the Warden refuses a stream file the agent could open)"
fi
if [ -n "$KEY" ]; then
    K="$(abs "$KEY")"
    if [ -L "$K" ]; then fail "signing key $K is a symlink (the Warden opens it with O_NOFOLLOW and refuses)"
    elif [ ! -e "$K" ]; then fail "signing key $K not found, or not reachable as this user (make one with tools/varek_keygen $K)"
    elif [ ! -f "$K" ]; then fail "signing key $K is not a regular file"
    else
        m="$(stat -c %a "$K")"; nl="$(stat -c %h "$K")"
        [ $((8#$m & 8#077)) -eq 0 ] && pass "signing key mode $m" || fail "signing key mode $m: readable or writable by group or others (chmod 600 $K)"
        [ "$nl" = 1 ] && pass "signing key has one name" || fail "signing key has $nl names (hard links): refused"
        sz="$(stat -c %s "$K")"
        if [ -r "$K" ]; then
            body="$(head -c 64 "$K")"
            tail_ok=1
            [ "$sz" = 64 ] || { [ "$sz" = 65 ] && [ "$(tail -c 1 "$K" | od -An -c | tr -d ' ')" = '\n' ]; } || tail_ok=0
            if [ "$tail_ok" = 1 ] && [[ "$body" =~ ^[0-9a-fA-F]{64}$ ]]; then pass "signing key is 64 hex characters"
            else fail "signing key is not exactly 64 hex characters (optionally one trailing newline); make one with tools/varek_keygen"; fi
        else
            warn "cannot read the signing key as this user, so its contents were not checked (run as root, or use --run)"
        fi
        r="$(openable "$K")"
        case "$r" in
            closed*) pass "signing key: the agent cannot open it" ;;
            *)       fail "signing key: the policy lets the agent open ${r#* } (refused)" ;;
        esac
        [ -f "$K.pub" ] || warn "no $K.pub next to the key: give auditors the public key (tools/varek_audit.py --pubkey)"
    fi
fi
if [ -n "$ANCHOR" ]; then
    A="$(abs "$ANCHOR")"
    ok=1
    if [ ! -x "$(dirname "$A")" ] && [ -e "$(dirname "$A")" ]; then
        warn "cannot look inside $(dirname "$A") as this user, so the anchor was not checked (run the preflight as root)"; ok=0; unchecked=1
    elif [ -L "$A" ]; then fail "anchor $A is a symlink (the Warden opens it with O_NOFOLLOW and refuses)"; ok=0
    elif [ -e "$A" ]; then
        if [ -f "$A" ]; then
            [ "$(stat -c %h "$A")" = 1 ] || { fail "anchor $A has $(stat -c %h "$A") names (hard links): refused"; ok=0; }
        elif [ -p "$A" ]; then
            # The Warden opens the anchor non-blocking for writing, which fails
            # (ENXIO) when no process has the FIFO open for reading.
            # The forwarder holds FIFO.lock while it runs; a FIFO merely held
            # open (a running Warden holds its anchor read-write) is not a
            # forwarder. Without a lock file (another kind of reader), only
            # the reader check applies.
            live="$(python3 -c 'import errno,fcntl,os,sys
fifo = sys.argv[1]
try:
    fd = os.open(fifo + ".lock", os.O_RDONLY | os.O_NOFOLLOW)
except OSError:
    fd = None
if fd is not None:
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)   # shared: never conflicts with another probe
        print("dead")
    except OSError:
        print("alive")
    sys.exit(0)
try:
    os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
    print("reader")
except OSError:
    print("none")' "$A" 2>/dev/null)"
            case "$live" in
                alive)  pass "anchor FIFO $A: the forwarder is running (it holds $A.lock)" ;;
                reader) warn "anchor FIFO $A has a reader, but not the VAREK forwarder (no $A.lock): a running Warden's own hold would look the same" ;;
                dead)   fail "anchor FIFO $A: the forwarder is not running ($A.lock is free); the Warden refuses it. Start the forwarder first"; ok=0 ;;
                *)      fail "anchor FIFO $A has no reader: start the forwarder (tools/varek_anchor_forward.py) first; the Warden refuses it otherwise"; ok=0 ;;
            esac
        elif [ -c "$A" ]; then :
        else fail "anchor $A is not a regular file, FIFO or character device"; ok=0; fi
    else
        [ -d "$(dirname "$A")" ] || { fail "the anchor's directory $(dirname "$A") does not exist"; ok=0; }
    fi
    if [ "$ok" = 1 ]; then
        r="$(openable "$A")"
        case "$r" in
            closed*) pass "anchor ${r#* }: the agent cannot open it" ;;
            *)       fail "anchor: the policy lets the agent open ${r#* } (refused)" ;;
        esac
    fi
    if [ -z "${unchecked:-}" ] && [ ! -p "$A" ] && [ ! -c "$A" ]; then
        warn "the anchor is a file on this host: it protects the stream against people who cannot write it, not against this host's root. To anchor off this host, point --anchor at a FIFO read by tools/varek_anchor_forward.py"
    fi
fi
if [ -n "$KEY" ] && [ -z "${unchecked:-}" ] && { [ -z "$ANCHOR" ] || { [ ! -p "$(abs "$ANCHOR")" ] && [ ! -c "$(abs "$ANCHOR")" ]; }; }; then
    warn "the signing key and the verdict streams are both on this host: the signatures protect against holders of the logs who are not root here; against this host's root only an off-host anchor helps"
fi
if [ -n "$SPOOL" ]; then
    S="$(abs "$SPOOL")"
    r="$(openable "$S/anchor.spool")"
    case "$r" in
        closed*) pass "forwarder spool ${r#* }: the agent cannot open it" ;;
        *)       fail "forwarder spool: the policy lets the agent open ${r#* }; keep the spool outside every allowed path" ;;
    esac
fi
if [ -n "$KEY$ANCHOR" ]; then
    raw="$( { find /dev \( -type b -o -type c \) 2>/dev/null | grep -E '^/dev/(mem|kmem|port|sg[^/]*|nvme[^/]*|bsg/.*)$'
              find /dev -maxdepth 5 -type b 2>/dev/null
              [ -e /proc/kcore ] && echo /proc/kcore; } | sort -u | "$CERT" "$POLICY" openable | grep '^openable' | head -5)"
    if [ -z "$raw" ]; then pass "no raw disk or memory device is open to the agent"
    else fail "the policy lets the agent open raw storage (refused with a key or anchor): $(tr '\n' ' ' <<<"${raw//openable /}")"; fi
fi

if [ "$RUN" = 1 ]; then
    echo "== 4. trial run"
    dir="${LOGDIR:-/tmp}"
    downer="$(stat -c %u "$dir" 2>/dev/null)"; dmode="$(stat -c %a "$dir" 2>/dev/null)"
    if [ "$fails" -gt 0 ]; then
        fail "skipped: fix the failures above first"
    elif [ "$downer" != 0 ] || { [ $((8#$dmode & 8#022)) -ne 0 ] && [ $((8#$dmode & 8#1000)) -eq 0 ]; }; then
        fail "skipped: $dir must belong to root and not be writable by others (or be sticky, like /tmp): the Warden runs as root and writes its stream there"
    else
        T="$($SUDO mktemp "$dir/.varek-preflight.XXXXXXXX")" || T=""
        if [ -z "$T" ]; then
            fail "could not create a temporary file in $dir"
        else
            args=("$POLICY"); [ -n "$KEY" ] && args+=(--sign-key "$KEY"); [ -n "$ANCHOR" ] && args+=(--anchor "$ANCHOR")
            # The stream path is passed as an argument, never spliced into the
            # command text; mktemp created the file (O_EXCL, mode 600).
            err="$($SUDO sh -c 'out=$1; shift; exec "$@" 2>>"$out"' sh "$T" "$WARDEN" "${args[@]}" -- /bin/true 2>&1 >/dev/null)"; rc=$?
            if $SUDO grep -q '"event":"run_end"' "$T" 2>/dev/null; then
                pass "the Warden started, supervised /bin/true and closed its stream (rc $rc)"
                aa=(--policy "$POLICY" --checker "$CERT")
                [ -n "$KEY" ] && [ -f "$(abs "$KEY").pub" ] && aa+=(--pubkey "$(abs "$KEY").pub")
                [ -n "$ANCHOR" ] && [ -f "$(abs "$ANCHOR")" ] && aa+=(--anchor "$(abs "$ANCHOR")")
                # A FIFO anchor: the forwarder's spool holds what it received,
                # and its sent.offset shows whether it reached the anchor host.
                if [ -n "$ANCHOR" ] && [ -p "$(abs "$ANCHOR")" ]; then
                    if [ -n "$SPOOL" ]; then
                        # Delivered: the trial run's own run_end is in the spool,
                        # and the forwarder's sent offset is past it.
                        SPF="$(abs "$SPOOL")/anchor.spool" delivered=0
                        trid="$($SUDO grep -o '"event":"run_start","run":"[0-9a-f]*"' "$T" | head -1 | cut -d'"' -f8)"
                        for _ in $(seq 1 30); do
                            endb="$($SUDO grep -b "\"run\":\"$trid\",\"event\":\"run_end\"" "$SPF" 2>/dev/null | head -1)"
                            if [ -n "$trid" ] && [ -n "$endb" ]; then
                                pos="${endb%%:*}"; line="${endb#*:}"
                                need=$((pos + ${#line} + 1))
                                off="$($SUDO cat "$(abs "$SPOOL")/sent.offset" 2>/dev/null || echo 0)"
                                [ "$off" -ge "$need" ] 2>/dev/null && { delivered=1; break; }
                            fi
                            sleep 0.5
                        done
                        if [ "$delivered" = 1 ]; then pass "the forwarder delivered the trial run's records off-host"
                        else fail "the forwarder has not delivered the trial run's records off-host within 15 s: check the anchor host's name, the SSH key and the pinned host key (journalctl -u varek-anchor-forward)"; fi
                        aa+=(--anchor "$SPF")
                    else
                        warn "a FIFO anchor without --spool: the trial run's delivery off-host was not checked"
                    fi
                fi
                o="$($SUDO python3 "$HERE/tools/varek_audit.py" "${aa[@]}" "$T" 2>&1)"
                if grep -q "varek_audit: PASS" <<<"$o"; then pass "audit: $(grep -o 'integrity: .*' <<<"$o")"
                else fail "audit of the trial stream: $(grep -m1 -E 'PROBLEM|FAIL' <<<"$o")"; fi
            else
                why="$($SUDO grep -m1 -E '^\[warden\].*(refus|cannot|error|not )|^usage' "$T" 2>/dev/null)"
                fail "the Warden did not run: ${why:-${err:-no output (rc $rc)}}"
            fi
            $SUDO rm -f -- "$T"
        fi
    fi
fi

echo
[ -n "${unchecked:-}" ] && echo "preflight: some checks need root; run it as root for a complete check"
if [ "$fails" -eq 0 ]; then echo "preflight: PASS ($warns warning(s))"; else echo "preflight: FAIL ($fails failure(s), $warns warning(s))"; fi
[ "$fails" -eq 0 ]
