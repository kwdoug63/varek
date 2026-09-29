# VAREK v1.16.0 — A Verdict Stream Its Holder Cannot Rewrite, and a Bound on Every Decision

Released 2026-09-28 · MIT · github.com/kwdoug63/varek

## Summary

v1.15.0 disclosed two limits. v1.16.0 addresses both.

1. **The log could be rewritten by whoever held it.** Since v1.12.1 the
   supervised agent cannot forge, drop or reorder a record. Nothing stopped a
   person who held the log file afterwards from editing it. From v1.16:
   - every record is **hash-chained**;
   - run_start, a **checkpoint** every 64 records (and at least once a second),
     and run_end are **signed with Ed25519** (`--sign-key`);
   - each checkpoint can also be **appended to an external anchor**
     (`--anchor`), on storage the log's holder cannot rewrite.

   `tools/varek_audit.py --pubkey --anchor` verifies all three. Without the
   private key, nobody can alter, add, remove or reorder a record before the
   last signature, or cut the stream short, without the audit failing. With an
   anchor, not even the key holder can rewrite history that reached it. The
   Warden also refuses to start if the policy would let the agent open the key,
   the anchor, the verdict stream itself or a raw disk.

2. **A pathological policy could make one decision take about 0.4 s.** A
   policy's globs may now total at most **4,096 tokens** (was 65,536). All three
   parsers enforce this: the decision procedure's, the certificate checker's,
   and the cross-check's Python parser. `contains` rules are matched in linear
   time, and the checker's glob matcher no longer clears and copies its rows
   for every byte. On adversarial policies built to hit the worst case, one
   decision in the live Warden now takes **about 26 ms** (median; up to 61 ms
   observed), where v1.15's checker alone took 415 ms. Real policies are
   unchanged at 0.1–2 µs; the five example policies use 14–92 glob tokens
   each.

Both limits now leave a smaller one behind. Those are listed under
[What remains](#what-remains).

## Log integrity

### The hash chain (always on)

Every record of a run ends with a chain value:

```
..."timestamp_ns":1790639914760238631,"chain":"4fb53436…"}
chain_i = SHA-256(chain_{i-1} || body_i)        chain_{-1} = SHA-256("VAREK-LOG-CHAIN-1")
```

`body_i` is the record's exact bytes from its `{` up to, not including,
`,"chain":`. The chained records are run_start and every record carrying the
run id: decision records, `checkpoint`, `anchor_error` and run_end. Editing,
inserting, removing or reordering any of them changes every chain value after
it.

The chain carries no secret, so on its own it only catches accidental damage.
Anyone editing the log can recompute it. What it provides is one value per
record that a signature or an anchor can seal.

### Signatures (`--sign-key`)

```
tools/varek_keygen /etc/varek/log.key         # writes log.key (0600) and log.key.pub
sudo ./warden policy.txt --sign-key /etc/varek/log.key -- ./agent 2> verdicts.log
```

- **What is signed.** run_start, every checkpoint and run_end carry
  `"sig"`, an Ed25519 signature over `"VAREK-LOG-SIG-1" || chain_i`.
  run_start also names the public key (`"log_pubkey"`).
- **When a checkpoint is written.** After every 64 decision records
  (`--checkpoint-every N`), and once a second while records are pending.
  Checkpoints are written between notifications, never while an agent thread
  waits for an answer.
- **The key file.** It holds 64 hex characters (the 32-byte seed). It must be
  a regular file with a single name (no hard links), not a symlink, and not
  readable or writable by group or others. The Warden reads it once before
  starting the agent and wipes the seed. The private key lives in libsodium's
  guarded memory (locked, excluded from core dumps) and is wiped at exit.
- **Keeping the key from the agent.** The Warden refuses to start if the policy
  would let the agent open the key file with any flags, deciding it with the
  certificate checker (which every authorization needs) on the path the kernel
  reports for the open file. With a key or an anchor it also refuses a policy
  that would let the agent open any block device under `/dev`, `/dev/mem`,
  `/dev/kmem`, `/dev/port`, `/proc/kcore` or a disk's command device
  (`/dev/sg*`, `/dev/nvme*`, `/dev/bsg/`): raw access to a disk reads every file
  on it. Within the agent's allowlist there is no other way to the key: `link`,
  `rename`, `mknod`, `ptrace` and `process_vm_readv` are refused, and
  `/proc/<pid>/fd` and `/proc/self/root` fail the Warden's magic-link checks.
- **Signing library.** libsodium, and nothing else in the Warden, handles key
  material.

### The anchor (`--anchor PATH`)

Each checkpoint-type record is also appended to `PATH` as one line, in a
single `write()`. With a key, that means run_start, checkpoints and run_end;
without one, the Warden still writes checkpoints to the anchor.

```
{"run":"93d6…","event":"checkpoint","records":5,"chain":"4fb5…","sig":"b6c5…","timestamp_ns":…}
```

**Where the anchor should live.** `PATH` may be a regular file, a FIFO or a
character device. It is meant to be somewhere the log's holder cannot
rewrite, for example:

- a FIFO read by a forwarder that sends each line off the host (remote syslog,
  object storage with a retention lock, a transparency log);
- a file the log's holder cannot write to at all. Append-only (`chattr +a`) is
  not enough on its own: it stops existing lines from changing, but a holder
  who can append could add forged checkpoints after the last genuine one of an
  unfinished run.

**Failure handling.**

- The descriptor is non-blocking, so a FIFO whose reader is slow or gone never
  stalls supervision (`O_NONBLOCK` does not help a regular file on a hung
  network filesystem). A failed write is recorded in the stream as an
  `anchor_error` record, which is chained and signed by the next checkpoint. A
  failed write of run_end, after which nothing may follow, is reported on a
  status line instead.
- The Warden refuses to start if the policy would let the agent open the anchor
  (or it has a second name), or if a FIFO has no reader yet.

### The verdict stream itself

When the Warden's stderr is a regular file, the Warden refuses to start if the
policy would let the agent open that file: an agent that could open its own
verdict stream could truncate it, removing its denied attempts, or read the
run id. (This applies to every run, signed or not.) If a record cannot be
written to the stream, the Warden stops supervising and the agent is killed.

### What the audit checks

```
varek_audit.py --policy policy.txt --checker tools/vdp_cert_check \
               --pubkey /etc/varek/log.key.pub --anchor anchor.log verdicts.log
```

**On every stream it reads, the audit:**

- checks the hash chain (as the CycloneDX exporter does), and refuses a stream
  whose run_start names Warden 1.16 or later but carries no chain (a stripped
  chain);
- verifies every signature under the stream's key;
- requires a complete stream to end in a signed run_end, and at most
  `checkpoint_every` decision records between signatures (fewer means
  checkpoints were removed);
- prints the run id and the run's start time, and with `--run ID` requires that
  run.

**An incomplete stream** (no run_end: the Warden was killed, or the stream was
cut) fails unless `--allow-incomplete` is given. With it, the audit covers
only the records up to the last signature (or, with an anchor and no key, the
last anchored checkpoint). It says how many records follow, and it neither
counts nor checks them, because anyone could have written them.

**With `--pubkey`:** the stream's key must be the pinned one.

**With `--anchor`:**

- every signed record in the stream must appear in the anchor, with the same
  chain value, signature and count;
- every anchor line of this run must appear in the stream;
- any `anchor_error` fails the audit.

**The report's `integrity:` line** states how far the stream is protected
against its holder:

| Integrity | Meaning |
|---|---|
| `none` | A pre-1.16 stream: no chain. |
| `chain` | Catches edits whose author did not recompute the chain. |
| `signed, key not pinned` | Consistent, but anyone can sign with a key of their own. Pass `--pubkey` to rely on it. |
| `signed` | Nothing before the last signature can change without the private key. An incomplete stream adds "covers the first N decision records only". |
| `signed, anchored` | Anchored history cannot change even with the key. |

**Signature checking is independent of the signer.** The audit verifies
signatures with `tools/varek_ed25519.py`, a pure-Python RFC 8032 verifier. It
does not use the library that made them. The verifier:

- requires canonical point encodings, S < L and a public key that is not of
  small order;
- passes the RFC 8032 test vectors;
- agrees with OpenSSL on every case the test suite tries.

### Tampering, tested

`make test-v1160` runs a signed, anchored run of `/bin/cat` over 13 files: 12
allowed, one denied. It then edits the log as three kinds of holder:

| Holder | Edit | Caught by |
|---|---|---|
| without the key | a read of `f3` rewritten as a read of the secret | the hash chain |
| without the key | the same, chain recomputed | the signatures |
| without the key | a record removed, later counts and chain fixed up | the signatures |
| without the key | the stream cut after its last decision | no run_end; `--allow-incomplete` audits only up to the last signature |
| without the key | an incomplete stream with every checkpoint removed and the rest rewritten | more than `checkpoint_every` records without a signature |
| without the key | the chain and format fields stripped (a downgrade) | "the chain was stripped" |
| without the key | the cut stream with an unsigned run_end appended | "run_end record is not signed" |
| without the key | signatures stripped, key removed from run_start | `--pubkey`: "the stream is not signed" |
| with another key | rewritten and re-signed with that key | `--pubkey`: "not by the pinned key" |
| **with the Warden's key** | rewritten and re-signed | **passes the signature check, as documented**; fails against the anchor |
| anyone | a checkpoint line deleted from the anchor | "was never anchored" |

It also covers:

- **Anchor without a key.** It passes as `chain, anchored`, and an edit with
  the chain recomputed fails against the anchor.
- **Anchor failures.**
  - A FIFO reader that exits after one line: the run completes, the EPIPE
    writes are recorded as `anchor_error`, and the anchored audit fails and
    names them. run_end stays the last record.
  - A FIFO that fills because its reader never reads: EAGAIN is recorded and
    the run is not slowed.
  - A FIFO with no reader is refused at startup.
- **Checkpoints and a broken stream.**
  - A checkpoint written after one second while the agent sleeps.
  - A stream on `/dev/full` stops the run within milliseconds.
- **Startup refusals.**
  - Key file: open permissions, malformed contents, a symlink, a second hard
    link.
  - Policy: one that lets the agent open the key (including write-only
    through a flag clause), the anchor, the verdict stream file or a block
    device.
  - `--checkpoint-every` values out of range.

## A bound on every decision

v1.15's certificate checker re-decides the earlier rules of every
authorization with its own simple matchers. Its glob matcher costs one step
per token, plus one per glob, for every byte of the path, so the policy's glob
size bounds one decision. Through v1.15 that meant up to 65,536 tokens × 4,095
bytes, which measured 415 ms.

- **The cap is now 4,096 glob tokens per policy.** The lowest cap that still
  admits a glob as long as the 4,095-byte length bound, which the
  bound-reachability test fixtures need. `vdp_check lint` reports each
  policy's glob size (`glob tokens 77 of 4096` for the finance policy).
- **`contains` is matched with `memmem`** (linear time) in the checker too. A
  byte-by-byte search is quadratic in the worst case, and 255 such rules would
  have cost more than the globs.
- **The glob matcher computes each row in one pass.** It used to clear two
  arrays and copy two more for every byte, a fixed cost per glob that made 255
  short globs cost more than one long one. The rewritten matcher agrees with
  v1.15's on 36,000 random glob/string pairs. The cross-check compares it with
  the oracle, and 7 of 8 hand-made mutants of it are caught; the eighth only
  changes how early a dead match stops.

**What is guaranteed** is a count, not a time: no policy the Warden accepts
makes the checker take more than (4,096 tokens + 256 globs) × 4,095 steps for
its globs in one decision.

**What that costs** was measured on this 2-vCPU host, per decision, with a
path of 3,600–4,095 bytes chosen to pass every pre-filter:

| Adversarial policy | Checker | Procedure |
|---|---|---|
| One glob of 4,090 tokens | 18.6 ms | 0.4 ms |
| 255 globs of 16 tokens (the review's case) | 24.9 ms | 0.1 ms |
| 255 globs `/**c*c*c*c*c*c*b` (the review's case) | 26.4 ms | 8.5 ms |
| 255 `contains` rules of 2,048 bytes | 4.6 ms | 4.1 ms |
| (v1.15: 16 globs of about 4,000 tokens) | (415 ms) | (4 ms) |
| Live Warden, the `/**c*c*…*b` policy, a 3,667-byte path (3 × 100 opens) | 26 ms median, 61 ms max (decision, certificate and check together) | |

The procedure figures include loading the policy once per 20 to 200
decisions.

## What remains

These are the limits v1.16 leaves, stated so they are known rather than
discovered.

- **The key holder, without an anchor.** Someone who holds both the log and the
  signing key can rewrite and re-sign the whole run. Keep the key where the
  log's holder cannot read it, or use an anchor.
- **The unanchored tail.** With an anchor, a key holder can still rewrite
  records after the last anchored checkpoint: at most 64 records or about one
  second, and only in a run that did not finish (a finished run's run_end is
  anchored).
- **Root on the Warden host, during the run.** It can forge records before they
  are signed or anchored. This was already outside the threat model: the
  Warden trusts its host.
- **The anchor's own storage.** VAREK cannot check that the anchor is
  somewhere the log's holder cannot rewrite. That is a deployment property.
- **What is not chained:**
  - human status lines (`[warden] …`);
  - the agent's relayed stderr (`[agent] …`);
  - the `--plan` gate's records, which come from the v1.6 plan verifier.

  None of these is an authorization record, but an editor can change them
  undetected.
- **A killed Warden.** It leaves no run_end. The audit then fails by default;
  `--allow-incomplete` audits up to the last signature and leaves out what
  follows it.
- **Another genuine run.** The audit checks the stream it is given. A holder
  could hand over a different signed run, or none. `--run`, the printed start
  time, and the anchor, which lists every run, are how to tell.
- **Raw storage the Warden does not recognize.** The startup check knows block
  devices, memory devices and disk command devices. A driver that exposes
  storage some other way, allowed by the policy, would give the agent the key.
  The agent runs with the privileges it was started with, so running it as an
  unprivileged user remains the stronger protection.
- **Worst-case decision time is tens of milliseconds, not microseconds**
  (26 ms median, 61 ms at most in the measurements above). Only a policy near
  the cap and a long path that passes every pre-filter reach it. The agent can
  only slow its own run.

## Latency

| Measure (`bench_target 10000`, 15 interleaved runs, median) | v1.15.0 | v1.16.0 chain | v1.16.0 signed + anchored |
|---|---|---|---|
| Whole run, per action | 58.1 µs | 61.2 µs | 61.5 µs |
| Warden decision latency (`latency_us`), P50, all / authorized opens | 8 / 51 µs | 8 / 48 µs | 8 / 50 µs |

**What each step costs:**

- Chaining costs about 3 µs per record: SHA-256 of about 560 bytes, measured
  at 2.6 µs here.
- Signing costs 22 µs per checkpoint, about 0.3 µs per record at one
  checkpoint every 64 records.

**What `latency_us` does and does not include.** It measures the decision, not
the writing of its record; that was already true in v1.15. So the chain cost
shows in the whole-run figure, not the decision figure. For a denial, the
record is written before the answer, so a denied call waits about 3 µs longer.

## Compatibility

- **Policies over 4,096 glob tokens are refused**, where v1.15 accepted up to
  65,536. The five example policies use 14–92. The v1.14 fixture
  `tests/v1140_bound2_policy.txt` held two 4,095-byte globs, so it was split
  into `v1140_bound2` and `v1140_bound4`.
- **`require warden 1.16` is accepted**, and `1.17` is refused. The grammar is
  otherwise unchanged.
- **Records end in `"chain"`**, plus `"sig"` on signed records. There are two
  new record types, `checkpoint` and `anchor_error`, and run_start gains
  `"log"`, `"log_pubkey"`, `"checkpoint_every"` and `"anchored"`.
  - Consumers that ignore unknown fields and events are unaffected. v1.15's
    exporter and audit read v1.16 streams; they just don't check the chain.
  - v1.16's exporter and audit read older streams and report their integrity
    as `none`.
- **Edited streams are refused.** The exporter and audit now reject a v1.16
  stream whose chain does not verify, or whose chain was stripped. Earlier
  regression tests that edit a stream to test the certificate audit now
  recompute the chain first, with `tests/log_rechain.py`. That only shows the
  chain is not a signature: only `--pubkey` and `--anchor` protect against the
  log's holder.
- **New startup refusals.**
  - For every run: a verdict stream file the policy lets the agent open.
  - With `--sign-key` or `--anchor`: a policy that lets the agent open a raw
    disk or memory device.
  - Check an existing deployment with a trial run.
- **A stream that cannot be written stops supervision.** With `--anchor`, the
  Warden ignores SIGPIPE, so a dead FIFO reader cannot kill it. The agent gets
  the default disposition back before it runs. When a record cannot be written
  to the verdict stream, the Warden now stops supervising and kills the agent,
  rather than letting it run unrecorded.
- **A rejected `--plan` now ends the stream with run_end** (signed if a key is
  given), so the stream is complete.
- **Fixed: the report of an agent killed by a signal was lost about one run in
  four.** The Warden's SIGCHLD handler could end the loop before the agent's
  exit was noticed. The Warden now records that the child exited.
- **Building.** The Warden and `tools/varek_keygen` link **libsodium**
  (`apt install libsodium-dev`). The CycloneDX BOM gains `varek:log.chain`
  (the stream's final chain value) and `varek:log.pubkey`.

## Not in this release

- A shipped anchor forwarder. `--anchor` takes a path, and forwarding it
  off-host is left to the deployment.
- Key rotation, hardware-backed keys (TPM, HSM) and multiple signers.
- Signing or chaining the agent's relayed output.
- From the v1.10 program: a formally verified checker, a customer-derived
  corpus and measured baseline, and the bounded sequence fragment (v1.11
  candidate).

## Testing

- `make test-v1160`: 54 checks, covering the tampering table and the
  other cases above, the glob cap including mixed token kinds, and the
  Ed25519 verifier's edge encodings.
- `make crosscheck`: 57,135 procedure checks; 5,000 certificates accepted;
  94,199 forged and 5,287 shadowed claims refused; 396 mutated witnesses;
  535,589 rule/string match comparisons against the oracle; fuzzed policies
  accepted or refused alike by all three parsers; 0 disagreements.
- **Earlier suites pass:** `make test-v1150` (its audit tamper cases now
  recompute the chain first), `test-v1140`, `test-v1130`, `test-v1124`,
  `test-v1123`, `test-v1122`, `test-v1121`, `test-v112`, `test-lifecycle`,
  `run-conformance`, `make harness` and `v1_6/integration_test.sh`.
- **Independent review.** It found no way for someone without the key to make
  the audit pass an altered complete stream. The same held for someone with
  the key when an anchor is given. The verifier agreed with RFC 8032 on every
  edge case tried. Its findings are addressed in this release:
  - `--allow-incomplete` passed records no signature covered;
  - the agent could read the key through a hard link or a raw block device;
  - the agent could truncate its own verdict stream when the policy allowed
    it;
  - the worst case was about twice the figure first given;
  - a stripped chain passed as a pre-1.16 stream;
  - the key was not excluded from core dumps;
  - several inaccurate statements in these notes.

## Requirements

- **Runtime:** unchanged (Linux ≥ 5.14, `pidfd_getfd`, `CAP_SYS_ADMIN`,
  x86_64), plus **libsodium** (1.0.18 or later).
- **Audit:** `python3` only.
- **Tests:** the cross-check needs the reference solver's package
  (`tools/requirements-crosscheck.txt` since v1.18.0). `make test-v1160`'s re-signing
  cases use the Python `cryptography` package and are skipped without it.
