# VAREK v1.22.0 — The `varek` Command and `varek bench`

Released 2026-10-03 · MIT · github.com/kwdoug63/varek

## Summary

Through v1.21.1, running the Warden meant assembling its flags and those of
its tools by hand: the policy, the verdict stream, the signing key, the
anchor, the agent's user, then `vdp_check`, `varek_audit.py` and
`varek_cyclonedx.py` afterwards. v1.22.0 adds one command, `varek`, that
reads those settings from `/etc/varek/varek.conf` and wraps the tools:

```sh
make deps && make && sudo make install     # /opt/varek, plus /usr/local/bin/varek
sudo varek doctor                          # is this host ready?
sudo varek init --pack healthcare          # settings, signing key, log directory
sudo varek run -- python3 agent.py         # supervise an agent
varek refusals                             # what the last run refused, and why
sudo varek audit                           # re-check certificates, chain, signatures
sudo varek export                          # signed CycloneDX 1.6 evidence
sudo varek bench                           # what mediation costs per call on this host
```

`varek bench` is new in this release. It measures what the Warden adds to
each mediated call on the host it runs on, and checks every verdict while it
does. Its first results correct a figure VAREK has published since v1.14
(see "The 8 µs figure" below).

The Warden's decisions are unchanged from v1.21.1, and so is the
symmetric-suppression invariant (**no extension may move a genuinely unsafe
action to SATISFIED**).

## The `varek` command

`doctor`, `init`, `policy list|show|check|use|add`, `preflight`, `run`,
`status`, `runs`, `refusals`, `audit`, `export` (signed CycloneDX 1.6;
`--verify` checks a file), `bench`, `license` and `version`.
`--show-commands` prints each underlying call, so nothing is hidden. `audit`,
`export` and `refusals` find the policy a run used by the SHA-256 in its
`run_start`, so switching policies later does not break the audit of an older
run. `make install` / `make uninstall` take `PREFIX` (default `/opt/varek`)
and `BINDIR` (default `/usr/local/bin`). The command changes no verdict
semantics.

## `varek bench`

A fixed workload (`tools/bench_workload`, linked static where the host has a
static libc) runs natively and as the agent under the Warden, alternating:
five runs of each by default, 2,000 timed calls of each kind per run after
200 warm-up calls. The six kinds are an allowed, a denied and an unmatched
file open; an allowed and a denied connect; and a small whole request on
loopback (connect, send, read a 1 KiB reply), for scale.

For each kind it reports:

- p50 / p90 / p99 natively and under the Warden, as the agent timed the call;
- the time added (Warden p50 minus native p50);
- the Warden's own decision time, from `latency_us` in its records (for a
  connect, including dialing the destination, `dial_us`).

It stamps the host, the Warden's version and SHA-256, and the policy's
SHA-256. It checks every call, warm-up included: each allowed call was
certified and succeeded, each denied or unmatched call was refused with
`EACCES`, and the listener behind the denied destination was never reached.
A failed check makes it exit 1.

It decides with the active policy's rules followed by five of its own
(`--policy <pack or file>` for another policy, `--bare` for its own only), so
the cost of a real policy is in the numbers. If a rule of that policy decides
one of the bench's calls differently, the check names the line. It signs its
verdict streams when `varek init` set up signing, keeps them out of
`/var/log/varek`, and removes everything it made unless `--keep`.
`-o results.json` / `--json` give every number and check;
`--max-added-p50 <µs>` fails the run past a budget, for CI.

## Latency

`bench_results_v1_22_0.txt`: a 2-vCPU cloud VM, `sudo varek bench --bare`
(the bench's 5 rules, unsigned) / `sudo varek bench --policy healthcare`
(33 rules first, signed), microseconds:

| Call | Native p50 | Under the Warden p50 | p99 | Warden decision p50 |
|---|---|---|---|---|
| Open, allowed (read) | 2.4 | 70 / 80 | 156 / 168 | 56 / 66 |
| Open, denied by a rule | 0.9 | 53 / 57 | 131 / 135 | 13 / 17 |
| Open, no rule (UNKNOWN) | 0.8 | 58 / 61 | 133 / 136 | 13 / 17 |
| Connect, allowed (dialed) | 23 | 148 / 143 | 295 / 275 | 118 / 114 |
| Connect, denied by a rule | 23 | 56 / 54 | 130 / 122 | 12 / 11 |
| Request (connect + 1 KiB reply) | 92 | 212 / 208 | 412 / 370 | 105 / 100 |

All 40 checks passed in both runs. The gap between the agent's time and the
Warden's decision is mostly the notification round trip (the call trapping,
the Warden waking, the answer reaching the agent): 15 to 45 µs at the median
on this host, depending on the kind of call. An agent slows down by roughly (mediated calls) x (time added), so
how much depends on how often it opens files and connects compared with the
work it does in between; a real network request takes far longer than the
loopback request above, so the Warden's share of it is smaller.

### The 8 µs figure

The v1.14, v1.15 and v1.16 release notes, and the v1.21.1 spec paper, give
the Warden's median decision across all decisions as 8 µs; the paper added
"including the notification round trip". That figure is the Warden's own
time (its clock starts once it has received the notification, so the round
trip is not in it), measured with the v1.4 `bench_target`, over a mix in
which every connect was refused after its decision with nothing dialed
(v1.9.1's deny-only posture, in force until v1.21.0). It was never what an
agent waits, and since v1.21.0 an allowed connect is dialed. Use the per-kind
figures above. The spec paper is corrected (Appendix B, item 8);
`bench_results_v1_21_1.txt` has the same measurement for the v1.21.1 Warden.

## Fixed

- The five VAREK Core packs allow `/usr/lib64/` read-only. On RHEL, Fedora
  and Amazon Linux, `/lib64` is a link to `/usr/lib64` and the Warden decides
  on the resolved path, so every dynamically linked agent was refused its
  shared libraries (UNKNOWN) there. Writes stay refused.
- The Warden builds against glibc 2.34 headers (Amazon Linux 2023, RHEL 9),
  which lack `CLONE_NEWTIME`.
- `tools/varek_preflight.sh` accepts an installed runtime (no Makefile beside
  it) whose binaries are present, instead of trying to build it.

## Tests

`make test-cli` runs `tests/test_varek_cli.py`, `tests/test_varek_license.py`
and `tests/test_varek_bench.py` (root, Linux; 47 passed, 1 skipped, the
skipped one being the non-root message). The bench's tests cover parsing,
percentiles, matching records to calls, the policy it composes, every check
(including a wrong verdict during warm-up) and end-to-end runs, among them a
dynamically linked workload under a policy without loader rules. CI runs the
parts that need no root. Before release an independent review of the bench
found ten issues (warm-up verdicts unchecked, no loader rules for a dynamic
workload under a base policy, a listener-count race, the listeners running as
root, tracebacks on error paths, missing timeouts, a weak reply-length check,
the static-link probe, the AMI smoke output, and wording); all were fixed.

## Compatibility

- **Records:** `run_start` says `"warden":"1.22.0"`. No other record changes.
- No change to the policy grammar, which stays at 1.21: `require warden 1.21`
  is the highest a policy can require, and `require warden 1.22` is refused
  ("policy requires Warden 1.22; this is 1.21"). No change to the runtime, the
  breaker state file or the audit.
- `make run-bench` now runs `varek bench --bare`; the v1.4 bench is
  `make run-bench-v14`. `make` also builds `tools/bench_workload`.
- The source also contains the VAREK Enterprise AMI packaging
  (`packaging/aws-marketplace/`) and its AWS License Manager check
  (`varek license`, `tools/varek_license.py`). They take effect only on that
  image, whose first release will be v1.23.0; off it nothing is checked and
  the Warden and the Core packs never depend on a license.

## Version plan

- **v1.23.0:** the first VAREK Enterprise AMI on AWS Marketplace, built from
  this code.
- **v1.24.0:** host names without agent DNS (v1.21 stage 2, previously
  targeted at v1.21.2), with `require warden 1.24`
  ([design](./docs/security/v1.21-stage2-host-names.md)).

## Upgrading

```sh
git pull && make -C varek/v1_4 && sudo make -C varek/v1_4 install
sudo varek doctor
sudo varek bench          # optional: this host's numbers
```

Existing policies, plans and verdict streams work unchanged.
