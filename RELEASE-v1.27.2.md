# VAREK v1.27.2 — Checkpoints Within Their Bound

> **Draft.** Not yet released: the release date, the 24-hour soak's figures
> and the CHANGELOG entry come with the release commit, after the soak.

MIT · github.com/kwdoug63/varek

## Summary

A patch release of v1.27.1 with one fix, to the signed verdict stream.
Nothing else changes: no policy, decision, record or option.

With `--sign-key`, the Warden signs a checkpoint at least every
`checkpoint_every` decision records (64 by default; `run_start` names it),
and `varek_audit.py` refuses a stream with a longer stretch between two
signatures, since only removing checkpoints could make one. The Warden
wrote checkpoints only between notifications. But one pass over the egress
proxy's reports (a burst of requests at once) can write several records,
so a signed stream could hold more than `checkpoint_every` records between
two signatures, and fail its own audit ("checkpoints were removed").

From v1.27.2, a checkpoint is written before any decision record that
would pass the bound, wherever the record is written.

**What it affected.** Signed runs (`--sign-key`) with the egress proxy in
inspecting mode (`proxy inspect`) whose agent made requests in bursts: by
the code, from v1.26.1 (which added the inspecting proxy) to v1.27.1.
Decisions and their enforcement were never affected. The stream was intact
and hash-chained, and every checkpoint that was written was signed. The
fault made the audit fail on a stream that had not been changed, and left
a few records more than `checkpoint_every` past the last signature.

**How it was found.** The shared soak harness written for v1.28.1, v1.29.0
and v1.31.0 (`tests/soak_shared`) failed its 6-minute trial on v1.31's
branch: a gap of 65 to 73 records. The same fault was then reproduced on
v1.28.0 and, by `tests/test_v1272.sh`, on v1.27.1 itself: a signed run of
640 requests in bursts of 32 had up to 67 decision records between two
signatures, and the audit failed three times. The fix is in v1.28.0,
v1.28.1, v1.29.0 and v1.31.0 before their release; this release brings it
to v1.27.

## Tested

- `make test-v1272` (new): the Warden reports 1.27.2; an agent under the
  inspecting proxy makes 20 bursts of 32 requests at once in a signed run;
  no two signatures are more than `checkpoint_every` decision records
  apart (at most 64 here; up to 67 on v1.27.1); the audit passes the
  stream, signed. On v1.27.1 the same test fails.
- Every suite of v1.27.1 on this build, in a 4-vCPU container: 1,484
  checks passed across the 30 `make test-*` suites, and `make test-cli`
  71 tests (1 skipped). The 3 checks that did not pass are the container's:
  its Python `requests` is installed under `/root/.local`, which the
  agent cannot read (test-v1210's `requests` clients); and test-v1162
  skipped (no OpenSSH server there). The release commit's build is run
  again on the droplet.
- Test changes, none in what they check: `test_v1271.sh` accepts the
  Warden's version as 1.27.1 or later (in `varek version` and
  `run_start`); `test_v1210.sh`'s lint check looks at the sample policy's
  host rules, as written in v1.21 (since v1.27.0 the exec rules draw notes
  of their own, so it had failed on every host since then).

## 24 hours on a small host

v1.27.1's soak harness (`tests/soak_v1270`), signed (`--sign-key`), on the
1 vCPU, 1 GB droplet once v1.28.0's soak had freed it. A 3-minute trial
passed on 2026-10-15: Warden 1.27.2, the work directory mounted `noexec`,
the tasks ok, the probe refused, the signed stream's audit passed. The
24-hour run started the same day; the release commit adds its figures.

## Compatibility

- Every v1.27.1 policy, option and record is unchanged. The grammar stays
  1.27; `run_start` and `varek version` name the Warden 1.27.2.
- A signed stream gains a checkpoint where it would have passed the bound,
  so it may hold a few more checkpoints than before.
- Streams from v1.26.1 to v1.27.1 that failed the audit for this reason
  ("N decision records since the previous signature, more than
  checkpoint_every"), with every other check passing, were not changed;
  their records past `checkpoint_every` were simply signed later, by the
  next checkpoint.

## Known limits

Those of v1.27.1 (`RELEASE-v1.27.1.md`).

## Upgrading

1. Rebuild (`make`) and reinstall (`make install`). `varek version` reports
   the Warden 1.27.2.
2. Nothing else: no policy or option changes.
