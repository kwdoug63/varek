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
   anchor, not even the key holder can rewrite history that reached it.

2. **A pathological policy could make one decision take about 0.4 s.** A
   policy's globs may now total at most **4,096 tokens** (was 65,536). All three
   parsers enforce this: the decision procedure's, the certificate checker's,
   and the cross-check's Python parser. `contains` rules are matched in linear
   time. The worst case of one decision, measured on adversarial policies
   built to hit it, is now **about 20 ms** (was 415 ms). Real policies are
   unchanged at 0.1–2 µs; the five example policies use 14–92 glob tokens each.

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
  a regular file, not a symlink, and not readable or writable by group or
  others. The Warden reads it once before starting the agent and wipes the seed
  from memory. The private key is locked in memory where the system allows it,
  and wiped at exit.
- **The agent cannot read the key.** The Warden refuses to start if the policy
  would let the agent open the key file with any flags. The certificate checker
  decides this, since every authorization needs it. The agent cannot reach the
  key another way: `link`, `rename`, `ptrace` and `process_vm_readv` are not in
  its allowlist.
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
- a file with the append-only attribute (`chattr +a`, which protects it from
  everyone but root).

**Failure handling.**

- The descriptor is non-blocking, so a slow or absent reader never stalls
  supervision. A failed write is recorded in the stream as an `anchor_error`
  record, which is chained and signed by the next checkpoint.
- The Warden refuses to start if the policy would let the agent open the anchor
  path, or if a FIFO has no reader yet.

### What the audit checks

```
varek_audit.py --policy policy.txt --checker tools/vdp_cert_check \
               --pubkey /etc/varek/log.key.pub --anchor anchor.log verdicts.log
```

**On every stream it reads, the audit:**

- checks the hash chain (as the CycloneDX exporter does);
- verifies every signature under the stream's key;
- requires a complete stream to end in a signed run_end.

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
| `signed` | Nothing before the last signature can change without the private key. |
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
| without the key | the stream cut after its last decision | no run_end; `--allow-incomplete` reports the unsigned tail |
| without the key | the cut stream with an unsigned run_end appended | "run_end record is not signed" |
| without the key | signatures stripped, key removed from run_start | `--pubkey`: "the stream is not signed" |
| with another key | rewritten and re-signed with that key | `--pubkey`: "not by the pinned key" |
| **with the Warden's key** | rewritten and re-signed | **passes the signature check, as documented**; fails against the anchor |
| anyone | a checkpoint line deleted from the anchor | "was never anchored" |

It also covers anchor failures:

- A FIFO reader that exits after one line: the run completes, EPIPE writes
  are recorded as `anchor_error`, and the anchored audit fails and names them.
- A FIFO with no reader is refused at startup.

## A bound on every decision

v1.15's certificate checker re-decides the earlier rules of every
authorization with its own simple matchers. Its glob matcher costs one step
per token per byte, so the policy's glob size times the path length bounds one
decision. Through v1.15 that meant up to 65,536 tokens × 4,095 bytes, which
measured 415 ms.

- **The cap is now 4,096 glob tokens per policy.** The lowest cap that still
  admits a glob as long as the 4,095-byte length bound, which the
  bound-reachability test fixtures need. `vdp_check lint` reports each
  policy's glob size (`glob tokens 77 of 4096` for the finance policy).
- **`contains` is matched with `memmem`** (linear time) in the checker too. A
  byte-by-byte search is quadratic in the worst case, and 255 such rules would
  have cost more than the globs.

Measured on this 2-vCPU host, per decision, with a 4,095-byte path chosen to
pass every pre-filter:

| Adversarial policy | Checker | Procedure |
|---|---|---|
| One glob of 4,090 tokens | 20.1 ms | 0.39 ms |
| 32 globs of 124 tokens | 19.3 ms | 0.41 ms |
| 255 `contains` rules of 2,048 bytes | 4.4 ms | 4.1 ms |
| (v1.15: 16 globs of about 4,000 tokens) | (415 ms) | (4 ms) |

The procedure figures include loading the policy once per 20 decisions. The
bound is a guarantee, not a measurement: no policy the Warden accepts can
exceed 4,096 × 4,095 matcher steps for its globs in one decision.

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
  - the pre-launch `--plan` records, which are written before run_start.

  None of these is an authorization record, but an editor can change them
  undetected.
- **A killed Warden.** It leaves no run_end. The audit then fails by default;
  `--allow-incomplete` verifies up to the last signature and reports what
  follows it.
- **Worst-case decision time is about 20 ms, not microseconds.** Only a policy
  near the 4,096-token cap and a path near 4,095 bytes that passes every
  pre-filter reach it. The agent can only slow its own run.

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
  stream whose chain does not verify. Earlier regression tests that edit a
  stream to test the certificate audit now recompute the chain first, with
  `tests/log_rechain.py`.
- **A stream that cannot be written stops supervision.** With `--anchor`, the
  Warden ignores SIGPIPE, so a dead FIFO reader cannot kill it. The agent gets
  the default disposition back before it runs. When a record cannot be written
  to the verdict stream, the Warden now stops supervising and kills the agent,
  rather than letting it run unrecorded.
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

- `make test-v1160`: 40 checks, covering sections 1–7 of the test, the
  tampering table above, startup refusals and the glob cap.
- `make crosscheck`: CROSSCHECK_SUMMARY
- **Earlier suites pass:** `make test-v1150` (its audit tamper cases now
  recompute the chain first), `test-v1140`, `test-v1130`, `test-v1124`,
  `test-v1123`, `test-v1122`, `test-v1121`, `test-v112`, `test-lifecycle`,
  `run-conformance`, `make harness` and `v1_6/integration_test.sh`.

## Requirements

- **Runtime:** unchanged (Linux ≥ 5.14, `pidfd_getfd`, `CAP_SYS_ADMIN`,
  x86_64), plus **libsodium** (1.0.18 or later).
- **Audit:** `python3` only.
- **Tests:** the cross-check needs `z3-solver`. `make test-v1160`'s re-signing
  cases use the Python `cryptography` package and are skipped without it.
