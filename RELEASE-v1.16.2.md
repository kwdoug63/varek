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
    anchoring but loses nothing the forwarder has read, and after a restart
    it resumes where it stopped.
  - **When records can still be lost.** Two cases: while the forwarder itself
    is stopped for longer than the pipe can hold (64 KiB, a few hundred
    records), or for more than 10 s at the end of a run. The Warden records
    either case (`anchor_error`, or a status line), and the audit reports the
    records as never anchored.
  - **A full spool disk.** Records are held in memory until there is room.
  - **Files it trusts.** It refuses a FIFO, spool directory or spool file that
    belongs to another user or is a symlink.
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
- **The Warden holds a FIFO anchor read-write.** It first checks that a reader
  is there, then keeps the FIFO open read-write.
  - **A forwarder restart mid-run.** Records written while the forwarder is
    restarting wait in the pipe instead of failing.
  - **At exit.** The Warden gives the forwarder up to 10 s to read what is
    left, and says so if it does not.
- **The receiver stores each line with its own receive time**
  (`"received_ns"`).
  - One writer at a time (`flock`).
  - A write failure makes the forwarder retry.
- **The audit** has three new options:
  - `--list-runs` lists every run in an anchor;
  - `--max-anchor-delay` fails late records;
  - `--run` names the run to audit.

  It also ignores unsigned, conflicting and malformed anchor lines, and says
  so.
- **The preflight checks the new pieces.**
  - A FIFO anchor must have its reader running. The Warden refuses one without
    a reader, so this is now a FAIL before you start, not a refusal at start.
  - A trial run with a FIFO anchor is audited against the forwarder's spool.
  - `--spool` checks that the agent cannot open the spool.
  - With `--run` and `--spool`, it checks that the trial run's records were
    actually delivered off-host. A wrong anchor host name, SSH key or host key
    fails here.
  - Two warnings name the gap this release closes:
    - an anchor that is a plain file on the Warden's host;
    - a signing key on the same host as the logs with no off-host anchor.

## Who can do what, with the anchor off-host

The anchor protects what has been **delivered** to it. Normally that is every
record within about a second. The window is whatever has not been delivered
yet.

| Who | Holds | What they can do undetected |
|---|---|---|
| Someone holding the logs, without the key | the logs | Nothing before the last signature (the signatures) |
| The Warden host's root | the logs, the key, the forwarder's SSH key | Nothing that reached the anchor host. What has not been delivered yet can be changed or withheld: the last second or so, or everything since the anchor host became unreachable (an outage, or root blocking it). The receive times make this visible (next paragraph). |
| The anchor host's root | the anchor | Could lift the append-only attribute, so keep that machine under separate control |

**Receive times.** The receiver stores each line with its own receive time
(`"received_ns"`), which the Warden host cannot set.

- **The delay.** The audit prints how late the run's records arrived.
  `--max-anchor-delay SECONDS` fails the audit when any record arrived later
  than that, which is when it could have been changed before anchoring.
- **Picking the run.** Take the run id to audit from the anchor host:
  `varek_audit.py --list-runs --anchor FILE` lists every run it holds, with
  times. Then pass `--run`. Otherwise a host that withheld one run could hand
  over another.

**Appending to the anchor.** Whoever holds the forwarder's SSH key can
append, not change. The audit judges a run by the first validly signed line
for each record:

- lines without a valid signature are noted and ignored;
- later conflicting lines are noted and ignored;
- lines that are not JSON are noted and ignored.

So appended lines cannot make a genuine run fail or an altered one pass. The
Warden host's root can still make a run fail in other ways, for instance by
deleting its log.

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
  - the Warden holds a FIFO anchor read-write, and drains it at exit (up to
    10 s);
  - `run_start` reads `"warden":"1.16.2"`;
  - `varek/v1_4/README.md` gains an "Off-host anchor" section.

## Testing

`make test-v1162` (24 checks). It runs a receiver behind a private sshd on
127.0.0.1:2222, with the forwarder in front of the Warden, and checks:

- **Off-host anchoring.** Every signed record of a run reaches the receiver,
  and the run audits `signed, anchored` against the receiver's copy.
- **The receiver only appends.**
  - A public key carrying a second line is refused at setup.
  - Its account does not run a requested command (one that would succeed if
    it ran).
  - It drops malformed lines.
  - It cannot truncate the file.
  - A connection through a requested port forward gets nothing.
- **Nothing is lost.**
  - The anchor host is down: the records wait in the spool and are delivered
    when it returns.
  - The forwarder is stopped for 3 s mid-run: no anchor error, and the run
    audits `signed, anchored`.
  - The receiver cannot write: the forwarder retries until it can.
  - The spool disk is full: lines are held in memory and sent once there is
    room.
- **Receive times.** Each line carries one. `--max-anchor-delay` flags records
  that arrived late.
- **Extra anchor lines.** Unsigned, conflicting (validly signed) and
  malformed lines are noted and ignored, and the run passes. `--list-runs`
  lists every run.
- **The preflight.**
  - With the forwarder running, the trial run is delivered off-host and
    audited, with no warnings.
  - With the anchor host down, delivery fails.
  - A FIFO with no reader fails.
  - A local-file anchor and an on-host key are warnings.
  - A spool the agent could open fails.
- **`--exec`.** It delivers to a command, and the run audits `anchored`.

The test is skipped without OpenSSH. Earlier suites pass.

**One changed expectation.** A FIFO whose reader goes away mid-run no longer
produces EPIPE `anchor_error` records. The Warden holds the FIFO, so the
records wait in the pipe, and at exit it reports what no reader took.
`test_v1160.sh` checks that report instead.

**Independent review.** It found problems in the first version of this
release, all fixed and covered above:

- a public key with an embedded newline gave an unrestricted shell on the
  anchor host;
- the notes overstated what the anchor protects: records not yet delivered,
  including whole runs during an outage, were open to rewriting, with no trace
  (hence receive times, `--max-anchor-delay` and `--list-runs`);
- appended or malformed lines could make honest runs fail;
- a forwarder restart mid-run lost checkpoints;
- a failed append could look successful where `/bin/sh` is bash, and
  concurrent appends could tear lines;
- a full spool disk crashed the forwarder;
- a rotation crash could skip lines;
- the forwarder trusted files owned by other users;
- the receiver would take over existing accounts;
- the preflight passed without checking delivery;
- two test checks passed without the protection they tested.

## Requirements

- **Warden:** unchanged.
- **Forwarder:** Python 3, plus the OpenSSH client for `--ssh`.
- **Receiver:** OpenSSH server, `useradd`, and a filesystem that supports
  `chattr +a` (ext4, XFS). The receiver script says so when the filesystem
  does not.
