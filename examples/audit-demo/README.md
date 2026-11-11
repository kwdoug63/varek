# Audit reconstructibility demo

One script that lets you check, on your own machine, the claim that VAREK's
evidence can be audited later without trusting VAREK, the operator, or
whoever kept the logs:

> A decision log can tell you which policy said yes. VAREK can prove, later,
> why yes was correct for the action that actually ran.

`varek_audit_demo.sh` builds VAREK from a release tag, runs an agent under the
Warden, and then audits the run from a separate folder that holds only four
files: the verdict log, the policy file, the Warden's public key and the
anchor file. It then tampers with that evidence in 18 ways and shows which
check catches each one.

## What it shows

**Part 1: file opens.** Allowed, denied and UNKNOWN file opens.

**Part 2: network actions.** A direct TCP connect allowed by one rule and
refused by another; MCP tool calls through the inspecting egress proxy
(`tools/list` and `tools/call get_issue` allowed, `tools/call delete_repo`
denied); and plain HTTPS requests through the proxy (`GET /status` allowed,
`POST /admin` refused).

For each run the audit checks that:

- the policy file is byte-for-byte the one the Warden ran with (its SHA-256 is
  in the signed `run_start` record);
- the log is complete, in order, signed by the pinned key and matches the
  anchor;
- every ALLOW carries a certificate (the deciding rule and a witness), and
  each certificate is re-checked by `vdp_cert_check`, a small checker that
  shares no code with the SMT decision procedure.

The last rows of each table remove the cryptography from the picture: the
attacker's own key is trusted and there is no anchor. A forged authorization
still fails there, because the certificate does not hold against the policy.
Two control rows (an unedited log, and a harmless field edited) pass, to show
the audit catches forgeries, not edits in general.

## Where and how to run it

Run it as root on a disposable Linux x86_64 VM or cloud instance (Ubuntu 24.04
or Fedora tested) with internet access to GitHub, from that machine's
terminal. The Warden uses seccomp-BPF and seccomp user-notify, network
namespaces and Landlock, so it needs root and a recent kernel. It does not run
on macOS or in an unprivileged container.

```bash
curl -fsSLO https://raw.githubusercontent.com/kwdoug63/varek/main/examples/audit-demo/varek_audit_demo.sh
sudo bash varek_audit_demo.sh --install-deps    # first run: installs build dependencies
sudo bash varek_audit_demo.sh                   # later runs
```

It takes a few minutes, most of it building. Options, as environment
variables:

| Variable | Default | Meaning |
|---|---|---|
| `VAREK_REF` | `v1.36.3` | release tag or branch to build and test |
| `VAREK_SRC` | (clone) | use an existing checkout instead, e.g. `VAREK_SRC=$(git rev-parse --show-toplevel)` |
| `WORK` | `./varek-audit-demo` | working folder; the evidence is kept in `WORK/evidence` |

The exit status is 0 only if every row came out as expected.

## Expected result

```
  #   Change made to the saved evidence                              Audit
  1   Clean run: pinned public key + anchor                          PASS
  2   Policy file loosened after the run                             FAIL
  3   ALLOW record retargeted to secret/payroll.db                   FAIL
  4   Same edit, hash chain recomputed                               FAIL
  5   DENY record deleted, chain recomputed                          FAIL
  6   Log cut short (run_end removed)                                FAIL
  7   Audited against a different public key                         FAIL
  8   Edited + re-signed with attacker key; real key pinned          FAIL
  9   Edited + re-signed; attacker key trusted, anchor kept          FAIL
  --- crypto bypassed below: attacker's key trusted, no anchor ---
  10  Control: unedited log, attacker key trusted, no anchor         PASS
  11  Certificate forged to name another rule                        FAIL
  12  ALLOW retargeted to secret/payroll.db                          FAIL
  13  Clean run: pinned public key + anchor                          PASS
  14  Policy file changed after the run (delete_* now allowed)       FAIL
  15  MCP call retargeted + re-signed; real key pinned               FAIL
  --- crypto bypassed below: attacker's key trusted, no anchor ---
  16  Control: unedited log                                          PASS
  17  Control: harmless field edited (latency)                       PASS
  18  Direct connect retargeted to the denied port                   FAIL
  19  MCP get_issue ALLOW retargeted to delete_repo                  FAIL
  20  MCP delete_repo DENY flipped to ALLOW (get_* certificate)      FAIL
  21  HTTPS GET /status ALLOW retargeted to POST /admin              FAIL
  22  HTTPS POST /admin DENY flipped to ALLOW (GET certificate)      FAIL
  23  Proxy dial retargeted to evil.example.net                      FAIL

  23 of 23 rows came out as expected.
  DEMO RESULT: PASS
```

The script also prints the reason the audit gives for each failure, and keeps
every audit's full output in `WORK/evidence/audit_NN.txt`.

## What it does not show

- **That the policy is right.** A certificate proves the action matched the
  policy as written. For example, `allow host api.example.com` with no port
  allows every port on that name, and a later `deny` on one of those ports
  never fires, because the first rule that holds decides. The record names
  that rule, so the audit shows exactly why the action was allowed.
- **Fields outside the decision, without the key and the anchor.** With the
  attacker's key trusted and no anchor, a timestamp or latency field can still
  be changed, and a DENY record can be dropped and the log renumbered. *When*
  an action was allowed, and that nothing was hidden, rest on pinning the
  public key and keeping the anchor where the log's holder cannot rewrite it.
  *Why* it was allowed rests on the certificate alone.
- **The full system state.** Each record carries what the action resolved to
  (the canonical path and open flags, the destination and the names it was
  decided over, the MCP method and tool name, the request line), not the
  machine's wider state.
- **The proxy hand-off on its own.** The connect that hands a connection to
  the egress proxy carries no certificate; the proxy's decision right after it
  does, and the audit checks that the two agree.
- **Policy retention.** The log holds the policy's SHA-256, not its text. To
  re-check a run later you need the policy file itself, so archive every
  policy you deploy.
