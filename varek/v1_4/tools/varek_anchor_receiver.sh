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

# The account: create it, or accept an existing one only if it is this
# receiver's (a system account whose home is DIR). Never root.
if id "$USERN" >/dev/null 2>&1; then
    uid="$(id -u "$USERN")"; home="$(getent passwd "$USERN" | cut -d: -f6)"
    [ "$uid" -ne 0 ] || die "--user: refusing to use root"
    [ "$home" = "$DIR" ] || die "user $USERN exists with home $home, not $DIR: choose another --user"
else
    useradd --system --home-dir "$DIR" --no-create-home --shell /bin/sh "$USERN"
fi
# No password, but not locked: sshd refuses key logins to a locked ("!")
# account on some configurations.
usermod -p '*' "$USERN"
if [ -e "$DIR" ]; then
    [ -d "$DIR" ] && [ ! -L "$DIR" ] && [ "$(stat -c %u "$DIR")" = 0 ] \
        || die "$DIR exists and is not a root-owned directory"
fi
install -d -o root -g root -m 755 "$DIR" "$DIR/.ssh"

# The forced command: only well-formed anchor lines, only appended, each with
# this host's receive time; one writer at a time (flock); a failure to write
# exits non-zero, so the forwarder keeps the lines and retries.
install -d -o root -g root -m 755 "$(dirname "$HELPER")"
cat > "$HELPER" <<'EOF'
#!/bin/sh
# varek-anchor-append NAME — forced command for the VAREK anchor account.
# Appends the well-formed anchor lines on stdin to the append-only file,
# adding "received_ns" (this host's clock). Exit 0 only if all were stored.
set -u
case "${1:-}" in *[!A-Za-z0-9._-]*|"") exit 2 ;; esac
f="${VAREK_ANCHOR_DIR:-/srv/varek-anchor}/$1.anchor.log"
exec 9>>"$f" || exit 3
flock 9 || exit 4
re='^\{"run":"[0-9a-f]{32}","event":"(run_start|checkpoint|run_end)","records":(0|[1-9][0-9]*),"chain":"[0-9a-f]{64}"(,"sig":"[0-9a-f]{128}")?,"timestamp_ns":(0|[1-9][0-9]*)\}$'
while IFS= read -r l; do
    printf '%s\n' "$l" | LC_ALL=C grep -Eq "$re" || continue
    now="$(date +%s%N)" || exit 5
    printf '%s,"received_ns":%s}\n' "${l%\}}" "$now" >&9 || exit 6
done
exit 0
EOF
chmod 755 "$HELPER"

F="$DIR/$NAME.anchor.log"
[ -e "$F" ] || install -o "$USERN" -g "$USERN" -m 640 /dev/null "$F"
if chattr +a "$F" 2>/dev/null && lsattr "$F" | cut -d' ' -f1 | grep -q a; then
    ATTR="append-only (chattr +a)"
elif [ "$NOCHATTR" = 1 ]; then
    ATTR="NOT append-only (this filesystem does not support chattr +a; --allow-no-chattr): the account could rewrite it"
else
    die "cannot make $F append-only (chattr +a): use a filesystem that supports it (ext4, XFS), or --allow-no-chattr"
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
