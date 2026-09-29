# VAREK v1.16.2 — Off-Host Anchor

Released 2026-09-28 · MIT · github.com/kwdoug63/varek

## Summary

The first real deployment check, on a single droplet, passed with
`integrity: signed, anchored`. It also made a gap visible: the signing key, the
verdict streams and the anchor file were all on the same machine, so that
machine's root could rewrite a log and re-sign it.

- **The anchor.** It is the only defense against that host's root. It works
  only if it lives somewhere that root cannot rewrite.
- **The key.** The signatures still protect against everyone else who handles
  the logs, but they cannot protect against the machine that holds the key.

v1.16.2 ships the missing piece: a way to put the anchor on a second machine
as it is written. It also corrects the command order in the v1.16.1 notes.
There is no change to decisions, records or the policy grammar.

- **`tools/varek_anchor_forward.py`** reads the Warden's anchor FIFO and sends
  each record off the host, normally within a second.
  - **Always a reader.** It creates the FIFO and holds it open, so the Warden
    always finds a reader.
  - **Spool first.** Every record goes to a local spool before it is sent, and
    sending is retried with backoff. An outage of the anchor host delays
    anchoring but loses nothing, and after a restart the forwarder resumes
    where it stopped.
  - **Filtered.** Only well-formed anchor lines are forwarded.
  - **Destinations.** `--ssh USER@HOST` sends to an append-only receiver.
    `--exec COMMAND` sends to any sink that stores lines from stdin, such as a
    remote syslog or an object store with a retention lock.
- **`tools/varek_anchor_receiver.sh`** sets up the anchor host (as root). It
  creates an account whose SSH key has one forced command: append well-formed
  anchor lines to a file marked append-only (`chattr +a`). The account gets:
  - no shell;
  - no forwarding;
  - no other command;
  - no way to change or remove a line.

  Only the anchor host's own root can lift the attribute.
- **`tools/systemd/varek-anchor-forward.service`** runs the forwarder as a
  service. Point the Warden's `--anchor` at `/run/varek/anchor.fifo`.
- **The preflight checks the new pieces.**
  - A FIFO anchor must have its reader running. The Warden refuses one without
    a reader, so this is now a FAIL before you start, not a refusal at start.
  - A trial run with a FIFO anchor is audited against the forwarder's spool.
  - `--spool` checks that the agent cannot open the spool.
  - Two warnings name the gap this release closes:
    - an anchor that is a plain file on the Warden's host;
    - a signing key on the same host as the logs with no off-host anchor.

## Who can do what, with the anchor off-host

| Who | Holds | Can they alter a finished run's log undetected? |
|---|---|---|
| Someone holding the logs, without the key | the logs | No: signatures |
| The Warden host's root | the logs and the key | No: every signed record reached the anchor host, which it cannot rewrite |
| The Warden host's root, for an unfinished run | the logs and the key | Only the records after the last anchored checkpoint (at most 64 records, about one second) |
| The anchor host's root | the anchor | Could lift the append-only attribute, so keep that machine under separate control |

**Appending to the anchor.** Whoever holds the forwarder's SSH key (the Warden
host's root) can append to the anchor but cannot change it. What they append
could only extend the record of a run that never finished.

## Setting it up (two machines)

**1. On the Warden host** (as root): make the forwarder's own SSH key and
print its public half.

```sh
ssh-keygen -t ed25519 -N '' -f /etc/varek/anchor_ssh_key -C varek-forwarder
cat /etc/varek/anchor_ssh_key.pub
```

**2. On the anchor host** (any small Linux server you control separately, as
root): paste that public key.

```sh
git clone https://github.com/kwdoug63/varek.git /opt/varek
/opt/varek/varek/v1_4/tools/varek_anchor_receiver.sh --name droplet1 \
    --pubkey 'ssh-ed25519 AAAA... varek-forwarder'
```

It prints the anchor host's key fingerprint.

**3. Back on the Warden host** (in `/opt/varek/varek/v1_4`): pin the anchor
host's key, start the forwarder, and check with a trial run.

```sh
ssh-keyscan -t ed25519 ANCHOR_HOST > /etc/varek/anchor_known_hosts
ssh-keygen -lf /etc/varek/anchor_known_hosts        # must match the fingerprint from step 2
cp tools/systemd/varek-anchor-forward.service /etc/systemd/system/
sed -i 's/ANCHOR_HOST/<anchor host name or IP>/' /etc/systemd/system/varek-anchor-forward.service
systemctl daemon-reload && systemctl enable --now varek-anchor-forward
tools/varek_preflight.sh policies/finance.policy.txt \
    --log /var/log/varek/verdicts.log --sign-key /etc/varek/log.key \
    --anchor /run/varek/anchor.fifo --spool /var/lib/varek/anchor-spool --run
```

Then run the Warden with `--anchor /run/varek/anchor.fifo`. To audit, copy
`/srv/varek-anchor/droplet1.anchor.log` from the anchor host and pass it to
`varek_audit.py --anchor`. Copy it as root or another account: the forwarder's
key can only append.

## Changes

- **Added:**
  - `tools/varek_anchor_forward.py` (Python 3 standard library only);
  - `tools/varek_anchor_receiver.sh`;
  - `tools/systemd/varek-anchor-forward.service`;
  - the `--spool` option and the FIFO reader check in `varek_preflight.sh`;
  - `make test-v1162`.
- **Fixed:** the command order in `RELEASE-v1.16.1.md` ("Using it") and in
  `varek/v1_4/README.md`. `varek_keygen` must be built before it is run.
- **Changed:**
  - `run_start` reads `"warden":"1.16.2"`;
  - `varek/v1_4/README.md` gains an "Off-host anchor" section.

## Testing

`make test-v1162` (14 checks). It runs a receiver behind a private sshd on
127.0.0.1:2222, with the forwarder in front of the Warden, and checks:

- **Off-host anchoring.** Every signed record of a run reaches the receiver,
  and the run audits `signed, anchored` against the receiver's copy.
- **The receiver only appends.**
  - Its account ignores a requested command (`rm` of the anchor).
  - It drops malformed lines.
  - It cannot truncate the file.
  - It refuses port forwarding.
- **Outages.** With the receiver down, a run's records wait in the spool.
  After it returns and the forwarder restarts, all are delivered, and that run
  audits `signed, anchored`.
- **The preflight.**
  - With the forwarder running, it passes with no warnings, and the trial run
    is audited against the spool.
  - A FIFO with no reader fails.
  - A local-file anchor and an on-host key are warnings.
  - A spool the agent could open fails.
- **`--exec`.** It delivers to a command, and the run audits `anchored`.

The test is skipped without OpenSSH. Earlier suites pass.

## Requirements

- **Warden:** unchanged.
- **Forwarder:** Python 3, plus the OpenSSH client for `--ssh`.
- **Receiver:** OpenSSH server, `useradd`, and a filesystem that supports
  `chattr +a` (ext4, XFS). The receiver script says so when the filesystem
  does not.
