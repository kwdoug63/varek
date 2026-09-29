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
#     given public key, restricted to one forced command: append well-formed
#     anchor lines read from stdin to DIR/NAME.anchor.log. No shell, no port
#     forwarding, no other command, no file transfer.
#   - DIR/NAME.anchor.log with the append-only attribute (chattr +a), so the
#     account can add lines but not change or remove any; only root on this
#     host can lift the attribute.
#   - /usr/local/lib/varek/varek-anchor-append, the forced command.
#
# The Warden host's forwarder (tools/varek_anchor_forward.py --ssh
# USER@THIS_HOST) then sends each line within about a second. To audit, copy
# DIR/NAME.anchor.log from this host (as root or another account, not through
# the forwarder's key, which cannot read) and pass it to varek_audit.py
# --anchor.
#
# What this cannot stop: whoever holds the forwarder's SSH key (root on the
# Warden host) can APPEND lines. Anchored lines cannot be changed, so history
# that reached this file is fixed; appended lines could only extend the
# record of a run that never finished, after its last anchored checkpoint.
set -eu

NAME="" PUBKEY="" USERN="varek-anchor" DIR="/srv/varek-anchor"
usage() { sed -n '9,10p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
while [ $# -gt 0 ]; do
    case "$1" in
        --name)   NAME="${2:-}"; shift 2 ;;
        --pubkey) PUBKEY="${2:-}"; shift 2 ;;
        --user)   USERN="${2:-}"; shift 2 ;;
        --dir)    DIR="${2:-}"; shift 2 ;;
        *)        usage ;;
    esac
done
[ -n "$NAME" ] && [ -n "$PUBKEY" ] || usage
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[[ "$NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "--name: letters, digits, . _ - only" >&2; exit 2; }
[[ "$USERN" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "--user: not a valid user name" >&2; exit 2; }
[[ "$PUBKEY" =~ ^(ssh-ed25519|ecdsa-sha2-nistp[0-9]+|ssh-rsa)\ [A-Za-z0-9+/=]+(\ [^\"]*)?$ ]] \
    || { echo "--pubkey: expected one OpenSSH public key line (ssh-ed25519 AAAA... comment)" >&2; exit 2; }
case "$DIR" in /*) ;; *) echo "--dir must be absolute" >&2; exit 2 ;; esac

id "$USERN" >/dev/null 2>&1 || useradd --system --home-dir "$DIR" --no-create-home --shell /bin/sh "$USERN"
# No password, but not locked: sshd refuses key logins to a locked ("!")
# account on some configurations.
usermod -p '*' "$USERN"
install -d -o root -g root -m 755 "$DIR" "$DIR/.ssh"

# The forced command: only well-formed anchor lines, only appended.
install -d -o root -g root -m 755 /usr/local/lib/varek
cat > /usr/local/lib/varek/varek-anchor-append <<'EOF'
#!/bin/sh
# varek-anchor-append NAME — forced command for the VAREK anchor account.
# Appends the well-formed anchor lines on stdin to the append-only file.
set -eu
case "$1" in *[!A-Za-z0-9._-]*|"") exit 2 ;; esac
f="${VAREK_ANCHOR_DIR:-/srv/varek-anchor}/$1.anchor.log"
LC_ALL=C grep -E '^\{"run":"[0-9a-f]{32}","event":"(run_start|checkpoint|run_end)","records":[0-9]+,"chain":"[0-9a-f]{64}"(,"sig":"[0-9a-f]{128}")?,"timestamp_ns":[0-9]+\}$' >> "$f" || [ $? -eq 1 ]
EOF
chmod 755 /usr/local/lib/varek/varek-anchor-append

F="$DIR/$NAME.anchor.log"
[ -e "$F" ] || install -o "$USERN" -g "$USERN" -m 640 /dev/null "$F"
if chattr +a "$F" 2>/dev/null && lsattr "$F" | cut -d' ' -f1 | grep -q a; then
    ATTR="append-only (chattr +a)"
else
    ATTR="NOT append-only: this filesystem does not support chattr +a; the account could rewrite it"
fi

KEYLINE="restrict,command=\"VAREK_ANCHOR_DIR=$DIR /usr/local/lib/varek/varek-anchor-append $NAME\" $PUBKEY"
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
