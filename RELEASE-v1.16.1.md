# VAREK v1.16.1 — Deployment Preflight

Released 2026-09-28 · MIT · github.com/kwdoug63/varek

## Summary

v1.16.0 added two things an existing deployment has to account for before it
upgrades:

- **The verdict stream check.** The Warden refuses to start when its policy
  would let the agent open the verdict stream file, the file its stderr goes
  to.
- **libsodium.** Building the Warden now needs the libsodium headers.

v1.16.1 makes both checkable before anything runs. There is no change to
decisions, records or the policy grammar.

- **`tools/varek_preflight.sh`** checks a deployment end to end, printing PASS,
  WARN or FAIL for each step:
  1. the build dependencies (`--install-deps` installs them);
  2. the build;
  3. the policy;
  4. every location the Warden refuses at startup: the verdict stream
     (`--log`), the signing key (`--sign-key`), the anchor (`--anchor`), and
     raw disks when a key or anchor is used;
  5. with `--run`, a real trial run whose stream is audited.
- **`tools/vdp_cert_check <policy> openable`** answers the question behind
  every one of those refusals: could the agent open this path? It uses the
  same certificate-checker function the Warden uses, so the answers agree. The
  new test checks that on every shipped policy.
- **`make` names the missing packages.**
  - If the libseccomp or libsodium headers are missing, the build stops with
    the command that installs them.
  - `make deps` runs that command.
  - `make preflight POLICY=… LOG=…` runs the preflight.
- **A CI job** (`.github/workflows/warden-build.yml`) installs exactly
  `libseccomp-dev` and `libsodium-dev` on Ubuntu, builds the Warden and its
  tools, lints the shipped policies and runs the preflight on each.

## Trial run of the shipped setups

Every shipped policy was run through the preflight and a live trial run.
Each trial run used a signing key and an anchor, and wrote its verdict stream
to `/var/log/varek/verdicts.log`. All seven pass, and the audit of each trial
stream reports `integrity: signed, anchored`.

Where the verdict stream can go, per policy ("refused" = the Warden will not
start):

| Stream location | policy.txt | conformance | cybersecurity | finance | healthcare | national-defense | utility |
|---|---|---|---|---|---|---|---|
| `/var/log/varek/verdicts.log` | ok | ok | ok | ok | ok | ok | ok |
| `/var/lib/varek/verdicts.log` | ok | ok | ok | ok | ok | ok | ok |
| `/tmp/verdicts.log`, `/root/…`, `/home/…` | ok | ok | ok | ok | ok | ok | ok |
| `/var/log/verdicts.log` | ok | ok | **refused** | ok | ok | ok | ok |
| `/tmp/varek/verdicts.log` | ok | ok | **refused** | **refused** | **refused** | **refused** | **refused** |
| `/tmp/varek_allowed_x/verdicts.log` | **refused** | ok | ok | ok | ok | ok | ok |

**Why these are refused:**

- **`/tmp/varek/`** is the sector policies' scratch space, which the agent may
  write.
- **The cybersecurity policy** lets the agent read `/var/log/` for detection.
  It already denies `/var/log/varek/` first, so that location stays usable.

**Recommended location:** `/var/log/varek/`. Each sector policy's header now
says so and gives the preflight command.

## Using it

```sh
cd varek/v1_4
make deps                                    # once, if headers are missing (sudo)
tools/varek_keygen /etc/varek/log.key        # once, if you sign
tools/varek_preflight.sh policies/finance.policy.txt \
    --log /var/log/varek/verdicts.log --sign-key /etc/varek/log.key \
    --anchor /var/log/varek/anchor.log --run
```

**Scope.** The preflight decides each location exactly as the Warden does. It
does not replace the Warden's own startup check, which still runs on every
start.

**Side effects of `--run`.**

- It needs root.
- It writes its trial stream to a temporary file next to `--log` and removes it
  afterwards.
- With `--anchor`, the trial run's checkpoints are appended to the anchor like
  any run's.

## Changes

- **Added:**
  - `tools/varek_preflight.sh` and the `openable` mode of `tools/vdp_cert_check`;
  - the `make deps`, `make deps-check` and `make preflight` targets;
  - `make test-v1161`;
  - the CI job.
- **Changed:**
  - `warden`, `warden_faultinject` and `tools/varek_keygen` depend on
    `deps-check` (an order-only prerequisite, so it causes no rebuilds);
  - `run_start` reads `"warden":"1.16.1"`;
  - the sector policies gain a header note on where to put the verdict stream
    (comments only: their rules are unchanged, but their SHA-256 differs);
  - `docs/development.md` and `varek/v1_4/README.md` list the build
    dependencies.

## Testing

`make test-v1161` (12 checks):

- For every shipped policy and three stream locations, the `openable` check and
  the live Warden agree on all 21 pairs.
- The preflight passes a signed, anchored deployment with an audited trial run.
- It fails each case the Warden would refuse:
  - a stream in scratch space;
  - a group-readable key;
  - a hard-linked key;
  - a key or an anchor the agent could open;
  - a missing key.
- `make` names the packages when the headers are missing. This was also
  checked on a host with libsodium removed: the Warden build and the preflight
  both stop with the install command, and `--install-deps` installs it and
  continues to a passing trial run.

Earlier suites pass: `test-v1160`, `test-v1150`, `test-v1140`, `test-v1130`,
`test-v1124`, `test-v1123`, `test-v1122`, `test-v1121`, `test-v112`,
`test-lifecycle`, `run-conformance`, `make harness` and
`v1_6/integration_test.sh`.

## Requirements

- **Unchanged from v1.16.0:** Linux ≥ 5.14, x86_64, `CAP_SYS_ADMIN`,
  libseccomp and libsodium.
- **The preflight:** bash, and python3 for `--run`'s audit.
