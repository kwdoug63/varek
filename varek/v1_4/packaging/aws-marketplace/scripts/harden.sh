#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Last step of the Packer build, as root: make the image meet the AWS
# Marketplace AMI policy, then remove everything tied to this build instance.
#   - SSH: key-only, no password or keyboard-interactive login, no root login
#   - no passwords set for any account; no authorized_keys anywhere
#   - no SSH host keys, machine ID, cloud-init state, logs or shell history
#     carried into buyers' instances
#   - no private keys anywhere in the image
set -euo pipefail

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'harden.sh: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"

say "SSH: keys only, no root login"
# sshd uses the first value it reads, and drop-ins load before sshd_config's
# own settings, so 00- makes these win.
install -d -m 0755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-varek-hardening.conf <<'EOF'
# VAREK Enterprise AMI (AWS Marketplace policy): key-based login only.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
EOF
chmod 0644 /etc/ssh/sshd_config.d/00-varek-hardening.conf
sshd -t || die "sshd rejects the hardened configuration"
eff=$(sshd -T 2>/dev/null)
grep -qx 'passwordauthentication no' <<<"$eff" || die "password login is still on"
grep -qx 'permitrootlogin no' <<<"$eff" || die "root login is still allowed"

say "Accounts: no passwords"
passwd -l root >/dev/null
while IFS=: read -r user hash _; do
    case "$hash" in
        '!'*|'*'*) ;;
        '') die "account $user has an empty password (passwordless login)" ;;
        *) die "account $user has a password set" ;;
    esac
done < /etc/shadow
# The buyer keeps full administration through ec2-user's sudo (cloud-init).
id ec2-user >/dev/null 2>&1 || die "ec2-user is missing"

say "Removing build identity"
rm -f /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys
rm -f /etc/ssh/ssh_host_*            # regenerated at each new instance's first boot
cloud-init clean --logs --seed       # so a new instance gets its own key and hostname
truncate -s 0 /etc/machine-id
rm -f /var/lib/systemd/random-seed

say "Removing logs, caches and history"
dnf clean all
rm -rf /var/cache/dnf/* /tmp/* /var/tmp/*
journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
find /var/log -type f \( -name '*.log' -o -name '*.gz' -o -name '*-[0-9]*' \) -delete
for f in /var/log/wtmp /var/log/btmp /var/log/lastlog; do [ -f "$f" ] && : > "$f"; done
rm -f /root/.bash_history /home/*/.bash_history /root/.python_history /home/*/.python_history
rm -rf /root/.cache /home/*/.cache /root/.aws /home/*/.aws

say "Checking for secrets"
[ ! -e /etc/varek ] || die "/etc/varek must not ship (each buyer makes their own key)"
found=$(grep -rlsI --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev \
        -e 'BEGIN [A-Z ]*PRIVATE KEY' -e 'BEGIN OPENSSH PRIVATE KEY' \
        /etc /root /home /opt /usr/local 2>/dev/null || true)
[ -z "$found" ] || die "private key material found: $found"
ls /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null && die "authorized_keys left behind" || true

history -c 2>/dev/null || true
echo "hardened"
