#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
varek_audit.py — re-check a saved Warden verdict stream against its policy
(v1.15).

Every file open the Warden authorized carries a certificate (the deciding rule
and a witness), which the Warden's in-line checker accepted before the open
took effect. This tool repeats that check later, from the saved stream and the
policy file alone:

  1. The stream is authenticated as varek_cyclonedx.py does (run id, gap-free
     seq, run_end count), so the supervised AGENT cannot have added, dropped or
     forged a record. (This does not protect the log from whoever holds it:
     keep it on append-only storage, or sign it, if that matters.)
  2. The policy file given here must hash to the policy_sha256 in run_start:
     the certificates are checked against exactly the text the Warden used.
  3. The only authorizations are certified file opens and the agent's one
     launch exec: any other record that reads ALLOW fails the audit.
  4. Every authorized file open must carry a certificate the checker accepted
     in-line ("check":"ok"), and every such certificate is re-checked now by
     the certificate checker (tools/vdp_cert_check, the same small program the
     Warden runs; it shares no code with the decision procedure).
  5. A stream from the test-only fault-injected Warden is refused.

Exit 0 only if all of these hold. The verdict stream is the Warden's stderr
(`warden policy -- agent 2> verdicts.log`).

Usage:
  varek_audit.py --policy POLICY --checker tools/vdp_cert_check VERDICTS.LOG
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from varek_cyclonedx import StreamError, _parse_log  # noqa: E402

# Record rules for an authorized file open (the policy decided ALLOW).
AUTHORIZED_OPEN_RULES = ("resolved_fd_injection", "allowed_open_failed", "injection_failed")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Re-check a VAREK verdict stream's certificates.")
    ap.add_argument("--policy", required=True, help="the policy file the Warden ran with")
    ap.add_argument("--checker", required=True, help="tools/vdp_cert_check")
    ap.add_argument("--allow-incomplete", action="store_true",
                    help="audit a stream with no run_end record")
    ap.add_argument("--allow-test-build", action="store_true",
                    help="audit a stream from the test-only fault-injected Warden (testing)")
    ap.add_argument("log")
    a = ap.parse_args(argv)

    with open(a.log, encoding="utf-8", errors="surrogateescape", newline="\n") as fh:
        meta = {}
        try:
            run, records, complete, warden = _parse_log(fh, a.allow_incomplete, meta)
        except StreamError as e:
            print(f"varek_audit: FAIL: {e}")
            return 1
    problems = []
    if meta.get("run_start", {}).get("build") and not a.allow_test_build:
        problems.append(f"the stream comes from a test build ({meta['run_start']['build']}), "
                        f"not a Warden that may supervise a real agent")
    with open(a.policy, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    recorded = meta.get("run_start", {}).get("policy_sha256")
    if not recorded:
        problems.append("run_start has no policy_sha256 (a pre-v1.15 Warden): nothing to check against")
    elif recorded != digest:
        problems.append(f"the policy file hashes to {digest}, the Warden ran with {recorded}")

    lines, which = [], []
    authorized = refused = 0
    launches = 0
    for rec in records:
        allowed = rec.get("decision_final") == "ALLOW" or rec.get("kernel_verdict") == "ALLOW"
        if not allowed:
            if rec.get("rule") == "certificate_refused":
                refused += 1                 # the in-line checker stopped it
            continue
        if rec.get("action") == "process.exec" and rec.get("rule") == "bootstrap_exec_allow":
            launches += 1                    # the agent's own launch, once per run
            if launches > 1:
                problems.append(f"seq {rec.get('seq')}: a second launch exec")
            continue
        if rec.get("action") != "file.open" or rec.get("rule") not in AUTHORIZED_OPEN_RULES:
            problems.append(f"seq {rec.get('seq')}: an authorization that is not a certified "
                            f"file open ({rec.get('action')}, rule {rec.get('rule')})")
            continue
        authorized += 1
        cr, cw = rec.get("cert_rule"), rec.get("cert_witness")
        if not isinstance(cr, int) or not isinstance(cw, str) or rec.get("check") != "ok":
            problems.append(f"seq {rec.get('seq')}: authorized open of {rec.get('resolved')!r} "
                            f"without an accepted certificate")
            continue
        s = rec.get("resolved", "")
        fl = rec.get("open_flags")
        if not isinstance(fl, str) or not fl.startswith("0x"):
            problems.append(f"seq {rec.get('seq')}: authorized open without its open flags")
            continue
        try:
            hx = s.encode("utf-8", errors="surrogateescape").hex() or "="
        except UnicodeEncodeError:
            problems.append(f"seq {rec.get('seq')}: path cannot be encoded")
            continue
        if " " in cw or not cw:
            problems.append(f"seq {rec.get('seq')}: malformed certificate witness")
            continue
        lines.append(f"path {fl} {hx} {cr} {cw}")
        which.append(rec)

    checked = 0
    if lines and not problems:
        p = subprocess.run([a.checker, a.policy, "batch"], input="\n".join(lines) + "\n",
                           capture_output=True, text=True)
        if p.returncode != 0:
            problems.append(f"checker failed: {p.stderr.strip()}")
        else:
            out = [json.loads(l) for l in p.stdout.splitlines() if l.strip()]
            if len(out) != len(lines):
                problems.append("checker answered a different number of certificates")
            for rec, o in zip(which, out):
                checked += 1
                if o.get("check") != "ok":
                    problems.append(f"seq {rec.get('seq')}: certificate for {rec.get('resolved')!r} "
                                    f"refused: {o.get('why')}")

    print(f"varek_audit: run {run} (Warden {warden}, {'complete' if complete else 'INCOMPLETE'}), "
          f"{len(records)} records, {authorized} authorized file opens, {checked} certificates "
          f"re-checked, {refused} refused in-line")
    for pr in problems[:50]:
        print(f"  PROBLEM {pr}")
    print(f"varek_audit: {'PASS' if not problems else 'FAIL'}")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
