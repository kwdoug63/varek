# VAREK v1.16.2 — Off-Host Anchor

Released 2026-09-28 · MIT · github.com/kwdoug63/varek

## Summary

The first real deployment check, on a single droplet, passed with
`integrity: signed, anchored`. It also made a gap visible: the signing key, the
verdict streams and the anchor file were all on the same machine, so that
machine's root could rewrite a log and sign it again.

- **The anchor.** It is the only defense against that host's root. It works
  only if it lives somewhere that root cannot rewrite.
- **The key.** The signatures still protect against everyone else who handles
  the logs, but they cannot protect against the machine that holds the key.

v1.16.2 ships a way to put the anchor on a second machine as records are
written. It also corrects the command order in the v1.16.1 notes. Decisions,
records and the policy grammar are unchanged.

- **`tools/varek_anchor_forward.py`** reads the Warden's anchor FIFO and sends
  each record off the host, normally within a second.
  - **Liveness.** It holds the FIFO open and holds a lock on `FIFO.lock` while
    it runs, so the Warden and the preflight can tell a live forwarder from a
    FIFO that is merely held open.
  - **Spool first.** Every record goes to a local spool before it is sent, and
    sending is retried with backoff. An outage of the anchor host delays
    anchoring. Records the forwarder has spooled are not lost, and after a
    restart it resumes where it stopped.
  - **A full spool disk.** It stops reading the FIFO, leaving the rest in the
    pipe, and cuts any partial write back.
  - **Files it trusts.** It refuses a FIFO, spool directory or spool file that
    belongs to another user or is a symlink.
  - **Destinations.** `--ssh USER@HOST` sends to an append-only receiver.
    `--exec COMMAND` sends to any sink that stores lines from stdin.
- **`tools/varek_anchor_receiver.sh`** sets up the anchor host (as root).
  - **Checks first.** It creates nothing until every check has passed:
    - a single-line public key that `ssh-keygen` accepts;
    - no existing account other than its own, and never root;
    - a root-owned directory;
    - a filesystem that supports `chattr +a`.
  - **The account.** Its SSH key is `restrict`ed to one forced command: append
    well-formed anchor lines to a file marked append-only. So it has no shell,
    no port forwarding and no other command, and it cannot change or remove a
    line.
  - **What the forced command does:**
    - reads the whole batch before taking the file's lock (so a stalled
      session blocks nobody);
    - stamps the batch with this host's receive time (`"received_ns"`);
    - closes any torn last line;
    - exits non-zero on any failure, so the forwarder retries.
- **`tools/systemd/varek-anchor-forward.service`** runs the forwarder as a
  service. Point the Warden's `--anchor` at `/run/varek/anchor.fifo`.
- **The Warden** handles a FIFO anchor differently.
  - **At start.** It refuses the anchor when the forwarder's lock is free,
    even if another Warden holds the FIFO open. Once it starts, it keeps the
    FIFO open read-write, so records written while the forwarder restarts wait
    in the pipe.
  - **At exit.** If no forwarder is running, it gives one up to 10 s to
    appear. After that it reports what was left.
- **The audit** gets two new options and a new rule for anchor lines:
  - **`--list-runs`** lists every run an anchor holds.
  - **`--max-anchor-delay SECONDS`** fails records that reached the anchor
    host too late after they were written. It measures from the stream's
    signed times, not from the anchor line's own.
  - **Which lines count.** A record is anchored if any validly signed line
    matches it.
    - Lines without a valid signature, lines that conflict with a record and
      lines that are not JSON are noted and ignored.
    - A signed line for a record the stream does not hold is evidence of
      rewriting. The exception is a line received after the run's `run_end`
      was anchored, which is only noted.
- **The preflight** checks the new pieces:
  - the forwarder is alive (its lock);
  - `--spool` is a place the agent cannot open;
  - with `--run --spool`, the trial run's own records were delivered off-host;
  - it warns about a local-file anchor and an on-host key.

## Who can do what, with the anchor off-host

The anchor protects what has been **delivered** to it. Normally that is every
record within about a second. The window is whatever has not been delivered
yet.

| Who | Holds | What they can do undetected |
|---|---|---|
| Someone holding the logs, without the key | the logs | Nothing before the last signature (the signatures). |
| The Warden host's root | the logs, the key, the forwarder's SSH key | Nothing that reached the anchor host. Records not yet delivered (the last second or so, or everything since the anchor host became unreachable or the forwarder was stopped) can be changed or withheld. |
| The anchor host's root | the anchor | Could lift the append-only attribute, so keep that machine under separate control. |

**Receive times.** The anchor host stamps each batch with its own clock, and
the Warden host cannot set that time.

- **How the audit uses it.** The audit reports each record's delay: its
  receive time against the time in the stream's own signed record.
  `--max-anchor-delay` turns a long delay into a failure.
- **What it cannot prove.** Someone who holds the key and withholds records
  can rewrite them with new times before releasing them. The receive time
  bounds when a record was anchored, not when it was created.
- **Picking the run.** Take the run to audit from the anchor host with
  `--list-runs`, and pass `--run`. Otherwise a host that withheld one run
  could hand over another.

**Appending.**

- Whoever holds the forwarder's SSH key can append to the anchor but cannot
  change or remove what is there.
- Appended lines cannot make a record that was anchored look different.
- Someone holding the Warden's key can still make a run's audit fail: for
  instance, by appending a signed line for a record the log does not hold
  before the run's `run_end` arrives, or simply by deleting the log. They can
  always do that. It does not make an altered run pass.

**When records can still be lost.** Each of these is reported, and the audit
then reports those records as never anchored:

- **The forwarder stops for a long time mid-run.** Once the pipe (64 KiB, a
  few hundred records) fills, the Warden records an `anchor_error`.
- **A run ends while no forwarder runs, and none starts within 10 s.** The
  Warden prints a status line.
- **The forwarder stops while holding records it could not spool.** It logs
  them as lost.

**A hint for the anchor host.** Set `ClientAliveInterval` in its sshd
configuration so that dead sessions are closed. The forced command never
holds the lock while waiting for input, but a dead session keeps a process
alive until sshd notices.

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

Then run the Warden with `--anchor /run/varek/anchor.fifo`.

**To audit:**

1. Copy `/srv/varek-anchor/droplet1.anchor.log` from the anchor host, as root
   or another account (the forwarder's key can only append).
2. Pick the run with `varek_audit.py --list-runs --anchor droplet1.anchor.log`.
3. Audit it with `--anchor droplet1.anchor.log --run <id>`, plus
   `--max-anchor-delay` if you want late records to fail.

## Changes

- **Added:**
  - `tools/varek_anchor_forward.py` (Python 3 standard library only);
  - `tools/varek_anchor_receiver.sh`;
  - `tools/systemd/varek-anchor-forward.service`;
  - `varek_audit.py --list-runs` and `--max-anchor-delay`;
  - in the preflight, the forwarder liveness check, `--spool`, the delivery
    check, and the warnings for a local-file anchor and an on-host key;
  - `make test-v1162`.
- **Changed (Warden):**
  - a FIFO anchor needs a live forwarder when its `FIFO.lock` exists;
  - it is held read-write, and drained for up to 10 s at exit when no
    forwarder runs;
  - `run_start` reads `"warden":"1.16.2"`.
- **Changed (audit):** which anchor lines count (above).
- **Fixed:** the command order in `RELEASE-v1.16.1.md` ("Using it") and in
  `varek/v1_4/README.md`. `varek_keygen` must be built before it is run, and
  `/etc/varek` must exist.

## Testing

`make test-v1162` (30 checks) runs a receiver behind a private sshd on
127.0.0.1:2222, with the forwarder in front of the Warden.

- **Setup.** A public key carrying a second line is refused before anything is
  created. The receiver is set up with one restricted key.
- **Off-host anchoring.** Every signed record of a run reaches the receiver
  with a receive time, and the run audits `signed, anchored`.
- **The receiver only appends.**
  - A requested command is not run (one that would succeed if it ran).
  - Malformed lines are dropped.
  - The file cannot be truncated.
  - A connection through a requested port forward gets nothing.
- **Nothing is lost.**
  - The anchor host is down: the records wait in the spool and are delivered.
  - `--max-anchor-delay 1.5` passes the prompt run and fails the one held
    during the outage.
  - The anchor lines' times are edited to look prompt: the run still fails
    (the delay is measured from the stream).
  - The forwarder is stopped for 3 s mid-run: no anchor error, and the run
    audits `signed, anchored`.
  - The receiver cannot write: the forwarder retries until it can.
  - The spool disk is full: the forwarder keeps running and sends once there
    is room.
- **Extra anchor lines.** None of these makes the run fail; each is noted:
  - unsigned lines;
  - a conflicting, validly signed line placed first;
  - lines that are not JSON;
  - a 5,000-digit number;
  - a signed line appended after the run ended.

  `--list-runs` lists every run.
- **The preflight.**
  - With the forwarder running, the trial run is delivered off-host and
    audited, with no warnings.
  - With the anchor host down, delivery fails.
  - A FIFO held open by another Warden, with the forwarder gone, fails, and
    the Warden refuses it too.
  - A FIFO with no reader at all fails.
  - A local-file anchor and an on-host key are warnings.
  - A spool the agent could open fails.
- **Liveness.**
  - With a busy forwarder, the Warden exits at once and the records still
    arrive.
  - A stalled session does not block another.
- **`--exec`.** It delivers to a command, and the run audits `anchored`.

The test is skipped without OpenSSH. Earlier suites pass.

**One changed expectation.** A FIFO whose reader goes away mid-run no longer
produces EPIPE `anchor_error` records. The Warden holds the FIFO, so the
records wait in the pipe, and at exit it reports what no reader took.
`test_v1160.sh` checks that report instead.

**Independent review.** Two rounds. The first found:

- a public key with an embedded newline gave an unrestricted shell on the
  anchor host;
- the notes overstated what the anchor protects;
- appended or malformed lines could make honest runs fail;
- a forwarder restart mid-run lost checkpoints;
- a failed append could look successful where `/bin/sh` is bash, and
  concurrent appends could tear lines;
- a full spool disk crashed the forwarder;
- a rotation crash could skip lines;
- the forwarder trusted files owned by other users;
- the receiver would take over existing accounts;
- the preflight passed without checking delivery.

The second found:

- the anchor delay could be faked by editing the spool;
- a FIFO held open by another Warden looked like a live forwarder;
- a line placed first, or a huge number, could still make an honest run fail;
- a stalled session blocked all appends;
- torn lines on a full disk;
- the receiver left partial state behind on refusal.

All are fixed and covered above.

## Requirements

- **Warden:** unchanged dependencies.
- **Forwarder:** Python 3, plus the OpenSSH client for `--ssh`.
- **Receiver:**
  - OpenSSH server;
  - `useradd`, `flock`, GNU `date` (nanoseconds) and `ssh-keygen`;
  - a filesystem that supports `chattr +a` (ext4, XFS). Setup fails otherwise,
    unless `--allow-no-chattr` is given.
