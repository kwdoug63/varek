#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# varek_anchor_receiver.sh — set up a host to receive a Warden's anchor records
# (v1.16.2). Run it as root on the ANCHOR host: a machine the Warden host's
# root cannot log in to or administer (a second small server, a different
# account or provider).
#
#   varek_anchor_receiver.sh --name NAME --pubkey 'ssh-ed25519 AAAA... comment'
#                            [--user varek-anchor] [--dir /srv/varek-anchor]
#
# It creates:
#   - a system account (default varek-anchor) whose only SSH access is the
#     given public key, restricted (`restrict`: no shell, pty, forwarding or
#     agent) to one forced command: append well-formed anchor lines read from
#     stdin to DIR/NAME.anchor.log. Each line is stored with the time THIS host
#     received it ("received_ns"), which the Warden host cannot set, so an
#     audit can see how late any record arrived.
#   - DIR/NAME.anchor.log with the append-only attribute (chattr +a), so the
#     account can add lines but not change or remove any; only root on this
#     host can lift the attribute. The script fails if the attribute cannot be
#     set (--allow-no-chattr to accept that).
#   - the forced command, /usr/local/lib/varek/varek-anchor-append (--helper).
#
# The Warden host's forwarder (tools/varek_anchor_forward.py --ssh
# USER@THIS_HOST) then sends each line within about a second. To audit, copy
# DIR/NAME.anchor.log from this host (as root or another account, not through
# the forwarder's key, which cannot read) and pass it to varek_audit.py
# --anchor; `varek_audit.py --list-runs --anchor FILE` lists every run in it.
#
# What this cannot stop: whoever holds the forwarder's SSH key (root on the
# Warden host) can APPEND lines, and can hold back records that have not been
# delivered yet (while this host is unreachable, or by stopping the
# forwarder). Lines already here cannot be changed; the receive times show
# how late each record arrived.
set -eu

NAME="" PUBKEY="" USERN="varek-anchor" DIR="/srv/varek-anchor"
HELPER="/usr/local/lib/varek/varek-anchor-append" NOCHATTR=0
usage() { sed -n '9,10p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
while [ $# -gt 0 ]; do
    case "$1" in
        --name)            NAME="${2:-}"; shift 2 ;;
        --pubkey)          PUBKEY="${2:-}"; shift 2 ;;
        --user)            USERN="${2:-}"; shift 2 ;;
        --dir)             DIR="${2:-}"; shift 2 ;;
        --helper)          HELPER="${2:-}"; shift 2 ;;
        --allow-no-chattr) NOCHATTR=1; shift ;;
        *)                 usage ;;
    esac
done
die() { echo "varek_anchor_receiver: $*" >&2; exit 2; }
[ -n "$NAME" ] && [ -n "$PUBKEY" ] || usage
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[[ "$NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "--name: letters, digits, . _ - only"
[[ "$USERN" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "--user: not a valid user name"
[[ "$DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] && [ "$DIR" != / ] || die "--dir: an absolute path of letters, digits, . _ - /"
[[ "$HELPER" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "--helper: an absolute path of letters, digits, . _ - /"
# The public key: ONE line, printable, a known key type, and a key ssh-keygen
# accepts. A newline or quote here would add a second, unrestricted key.
case "$PUBKEY" in *[[:cntrl:]]*|*\"*|*\\*) die "--pubkey: must be a single line without quotes or control characters" ;; esac
[[ "$PUBKEY" =~ ^(ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa)\ [A-Za-z0-9+/=]+(\ [[:print:]]*)?$ ]] \
    || die "--pubkey: expected one OpenSSH public key line (ssh-ed25519 AAAA... comment)"
printf '%s\n' "$PUBKEY" | ssh-keygen -l -f - >/dev/null 2>&1 || die "--pubkey: ssh-keygen does not accept this key"

# Everything is checked before anything is created.
if id "$USERN" >/dev/null 2>&1; then
    uid="$(id -u "$USERN")"; home="$(getent passwd "$USERN" | cut -d: -f6)"
    [ "$uid" -ne 0 ] || die "--user: refusing to use root"
    [ "$home" = "$DIR" ] || die "user $USERN exists with home $home, not $DIR: choose another --user"
    NEWUSER=0
else
    NEWUSER=1
fi
if [ -e "$DIR" ]; then
    [ -d "$DIR" ] && [ ! -L "$DIR" ] && [ "$(stat -c %u "$DIR")" = 0 ] \
        || die "$DIR exists and is not a root-owned directory"
    NEWDIR=0
else
    NEWDIR=1
fi
for tool in flock date ssh-keygen chattr lsattr; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
date +%s%N | grep -Eq '^[0-9]{19}$' || die "date +%s%N must print nanoseconds (GNU date)"
install -d -o root -g root -m 755 "$DIR"
probe="$DIR/.chattr-probe.$$"
: > "$probe"
if chattr +a "$probe" 2>/dev/null && lsattr "$probe" | cut -d' ' -f1 | grep -q a; then
    CHATTR=1; chattr -a "$probe"
else
    CHATTR=0
fi
rm -f "$probe"
if [ "$CHATTR" = 0 ] && [ "$NOCHATTR" = 0 ]; then
    [ "$NEWDIR" = 1 ] && rmdir "$DIR"
    die "this filesystem does not support chattr +a (append-only): use one that does (ext4, XFS), or --allow-no-chattr"
fi

# Create.
[ "$NEWUSER" = 1 ] && useradd --system --home-dir "$DIR" --no-create-home --shell /bin/sh "$USERN"
# No password, but not locked: sshd refuses key logins to a locked ("!")
# account on some configurations.
usermod -p '*' "$USERN"
install -d -o root -g root -m 755 "$DIR/.ssh"

# The forced command. It reads the whole batch first (so a stalled session
# never holds the lock), keeps only well-formed anchor lines, stamps the batch
# with this host's receive time, and appends it under an exclusive lock
# (waiting at most 30 s). A torn last line left by a failed write is closed
# before appending. Any failure exits non-zero, so the forwarder keeps the
# lines and retries (duplicates are harmless).
install -d -o root -g root -m 755 "$(dirname "$HELPER")"
cat > "$HELPER" <<'EOF'
#!/bin/sh
# varek-anchor-append NAME — forced command for the VAREK anchor account.
# Appends the well-formed anchor lines on stdin to the append-only file,
# adding "received_ns" (this host's clock). Exit 0 only if all were stored.
set -u
case "${1:-}" in *[!A-Za-z0-9._-]*|"") exit 2 ;; esac
f="${VAREK_ANCHOR_DIR:-/srv/varek-anchor}/$1.anchor.log"
tmp="$(mktemp)" || exit 3
trap 'rm -f "$tmp" "$tmp.ok"' EXIT
head -c 4194304 > "$tmp" || exit 3                     # a batch is at most 1 MiB
re='^\{"run":"[0-9a-f]{32}","event":"(run_start|checkpoint|run_end)","records":(0|[1-9][0-9]{0,19}),"chain":"[0-9a-f]{64}"(,"sig":"[0-9a-f]{128}")?,"timestamp_ns":(0|[1-9][0-9]{0,18})\}$'
LC_ALL=C grep -E "$re" "$tmp" > "$tmp.ok"; rc=$?
[ "$rc" -le 1 ] || exit 4
[ -s "$tmp.ok" ] || exit 0
now="$(date +%s%N)" || exit 5
case "$now" in *[!0-9]*|"") exit 5 ;; esac
exec 9>>"$f" || exit 6
flock -w 30 9 || exit 7
if [ -s "$f" ] && [ "$(tail -c 1 "$f" | od -An -tx1 | tr -d ' ')" != 0a ]; then
    printf '\n' >&9 || exit 8                          # close a torn line
fi
sed "s/}\$/,\"received_ns\":$now}/" "$tmp.ok" >&9 || exit 9
exit 0
EOF
chmod 755 "$HELPER"

F="$DIR/$NAME.anchor.log"
[ -e "$F" ] || install -o "$USERN" -g "$USERN" -m 640 /dev/null "$F"
if [ "$CHATTR" = 1 ] && chattr +a "$F" 2>/dev/null; then
    ATTR="append-only (chattr +a)"
else
    ATTR="NOT append-only (--allow-no-chattr): the account could rewrite it"
fi

KEYLINE="restrict,command=\"VAREK_ANCHOR_DIR=$DIR $HELPER $NAME\" $PUBKEY"
AK="$DIR/.ssh/authorized_keys"
touch "$AK"
grep -qxF "$KEYLINE" "$AK" || printf '%s\n' "$KEYLINE" >> "$AK"
chown root:root "$AK"; chmod 644 "$AK"

echo "anchor receiver ready:"
echo "  account   $USERN (SSH key only, forced append command)"
echo "  file      $F — $ATTR"
echo "  host key  $(for k in /etc/ssh/ssh_host_ed25519_key.pub; do [ -f "$k" ] && ssh-keygen -lf "$k"; done)"
echo "On the Warden host, pin this host key and start the forwarder, e.g.:"
echo "  ssh-keyscan -t ed25519 THIS_HOST > /etc/varek/anchor_known_hosts   # compare the fingerprint above"
echo "  tools/varek_anchor_forward.py --fifo /run/varek/anchor.fifo --spool /var/lib/varek/anchor-spool \\"
echo "      --ssh $USERN@THIS_HOST --ssh-key /etc/varek/anchor_ssh_key --known-hosts /etc/varek/anchor_known_hosts"
