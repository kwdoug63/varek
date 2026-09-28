#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
varek_cyclonedx.py — export a VAREK Warden pathology log as authorization
evidence in the CycloneDX 1.6 format.

The Warden emits one JSON pathology record per mediated action (see
`emit_pathology()` in warden.c): the action, the raw pathname the agent
supplied, the RESOLVED canonical object (v1.12+), the policy decision, the rule
that fired, and the per-decision latency. That stream IS the authorization
evidence for a run. This tool renders it as a Bill of Materials in the
CycloneDX 1.6 format so the evidence travels in a standard, tool-consumable form
alongside an SBOM.

Trademark: CycloneDX is a trademark of the OWASP Foundation. VAREK and Sober
Agentic Infrastructure, Inc. are not affiliated with, endorsed by, or certified
by the OWASP Foundation or the CycloneDX project. The CycloneDX name is used here
only to describe interoperability with the openly published CycloneDX format
(ECMA-424), whose schemas are Apache-2.0 licensed. See the NOTICE file.

What it produces (all within stable CycloneDX 1.6 — no dependency on any
unmerged specification proposal):

  * metadata.tools.components[0] — the VAREK Warden, with its license and the
    three provisional-patent references as properties.
  * metadata.component — the supervised agent run (application), carrying the
    policy identity and the run window as properties.
  * annotations[] — one machine- and human-readable authorization attestation:
    the verdict distribution, the authorized/refused counts, and the
    Authorization-Before-Execution invariant that held for the run.
  * components[] — one component per DISTINCT resolved object the agent was
    authorized to reach, each with the deciding rule as a property. Refused
    actions are summarized in the annotation, not minted as components (a
    refused object was never a dependency of the run).

Forward compatibility: when the CycloneDX "pre-defined perspectives" proposal
(specification PR #1067) lands in 2.0, the authorization annotation is the
natural carrier for a `cdx:perspectives:*` reference. This tool deliberately
emits stable 1.6 today and leaves that binding for a 2.0 target.

Usage:
    varek_cyclonedx.py --log bench.log --agent ./target_demo --policy policy.txt \
        [--output bom.json] [--serial urn:uuid:...]

Reads the log from --log or stdin. Writes the BOM to --output or stdout.
Exit status is non-zero when the stream cannot be authenticated (see
_parse_log), never on the presence of refusals (a run full of denials is a
valid, well-formed authorization record).
"""

import argparse
import datetime as _dt
import json
import sys
import uuid

VAREK_VERSION = "1.12.3"
SPEC_VERSION = "1.6"

# The provisional patents, as recorded in the runtime's own documentation.
PATENTS = [
    ("varek:patent:smt-layer", "USPTO Provisional 64/006,104 (SMT decision layer)"),
    ("varek:patent:warden-architecture", "USPTO Provisional 64/059,592 (Warden kernel architecture)"),
    ("varek:patent:action-graph", "USPTO Provisional 64/062,549 (compositional action-graph verification)"),
]


class StreamError(SystemExit):
    pass


def _parse_log(stream, allow_incomplete=False):
    """Read a Warden verdict stream and return (run, records, complete).

    v1.12.1 streams are authenticated, and this refuses any stream it cannot
    authenticate (a refusal is a non-zero exit with the reason):

      * Only lines that START with '{' are records. Everything else is a human
        status line ("[warden] ...") or the agent's relayed stderr
        ("[agent] ..."), which the Warden prefixes so no agent byte can begin a
        line. Lines are split on '\n' only (never on '\r').
      * The first record is run_start, carrying a per-run id the agent never
        sees. Every decision record must carry that id and a seq that counts
        up from 0 with no gap or repeat. A record with any other id is foreign
        (for example the agent's stdout merged in with 2>&1) and the stream is
        refused.
      * run_end closes the stream and states the record count. A stream with
        no run_end is incomplete (the Warden was killed, or the log was cut)
        and is refused unless allow_incomplete is set.

    v1.12.0 and older logs have no run id and are refused: their records
    could be forged by the supervised agent."""
    name = getattr(stream, "name", "<stdin>")

    def fail(lineno, why):
        raise StreamError(f"varek_cyclonedx: {name}:{lineno}: {why} "
                          f"Refusing to emit a BOM.")

    run = None
    records = []
    ended = None
    warden_version = VAREK_VERSION
    for lineno, raw in enumerate(stream, 1):
        if not raw.startswith("{"):
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError as e:
            fail(lineno, f"record is not valid JSON ({e}).")
        if not isinstance(rec, dict):
            fail(lineno, "record is not a JSON object.")
        event = rec.get("event")
        if event == "run_start":
            if run is not None:
                fail(lineno, "second run_start in one stream.")
            run = rec.get("run")
            if not isinstance(run, str) or len(run) != 32:
                fail(lineno, "run_start has no valid run id.")
            w = rec.get("warden")
            if isinstance(w, str) and w:
                warden_version = w
            continue
        if "decision_final" not in rec and event != "run_end":
            continue   # e.g. a pre-launch plan record; carries no authorization
        if run is None:
            fail(lineno, "record before run_start (a pre-v1.12.1 log, or not a "
                         "Warden stream); its records cannot be authenticated.")
        if ended is not None:
            fail(lineno, "record after run_end.")
        if rec.get("run") != run:
            fail(lineno, "foreign record: its run id does not match this run's "
                         "run_start (it was not written by this Warden run).")
        if event == "run_end":
            if rec.get("records") != len(records):
                fail(lineno, f"run_end counts {rec.get('records')} records, the "
                             f"stream holds {len(records)}.")
            ended = rec
            continue
        if rec.get("seq") != len(records):
            fail(lineno, f"seq {rec.get('seq')} where {len(records)} was expected "
                         f"(a record is missing, repeated or foreign).")
        records.append(rec)

    if run is None:
        fail(0, "no run_start record: not a v1.12.1+ Warden stream.")
    if ended is None and not allow_incomplete:
        fail(0, "no run_end record: the stream is incomplete (the Warden did "
                "not finish, or the log was cut). Use --allow-incomplete to "
                "attest the part that is present.")
    return run, records, ended is not None, warden_version


def _ts(records):
    """Best-effort run window from timestamp_ns fields, else 'now' (UTC)."""
    ns = [r["timestamp_ns"] for r in records if isinstance(r.get("timestamp_ns"), int)]
    if ns:
        start = _dt.datetime.fromtimestamp(min(ns) / 1e9, _dt.timezone.utc)
        end = _dt.datetime.fromtimestamp(max(ns) / 1e9, _dt.timezone.utc)
    else:
        start = end = _dt.datetime.now(_dt.timezone.utc)
    fmt = lambda d: d.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return fmt(start), fmt(end)


def build_bom(records, agent, policy, serial, run_id="", complete=True,
              warden_version=VAREK_VERSION):
    # v1.12.2: the Warden component carries the version named in the stream's
    # run_start (the Warden that made the decisions), not this exporter's.
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    run_start, run_end = _ts(records)

    authorized = [r for r in records if r.get("decision_final") == "ALLOW"]
    refused = [r for r in records if r.get("decision_final") != "ALLOW"]

    # Distinct resolved objects the agent was authorized to reach. Prefer the
    # canonical 'resolved' path (v1.12+); fall back to 'target' for older logs
    # and for non-file actions (exec bootstrap).
    seen = {}
    for r in authorized:
        key = r.get("resolved") or r.get("target") or "<unknown>"
        if key and key not in seen:
            seen[key] = r

    def bomref(prefix, s):
        return f"{prefix}:{uuid.uuid5(uuid.NAMESPACE_URL, s)}"

    warden_tool = {
        "type": "application",
        "bom-ref": "tool:varek-warden",
        "publisher": "Sober Agentic Infrastructure, Inc.",
        "name": "VAREK Warden",
        "version": warden_version,
        "description": "Pre-execution authorization runtime for autonomous AI agents "
                       "(Authorization-Before-Execution; kernel-enforced via seccomp-BPF "
                       "and seccomp user-notify).",
        "licenses": [{"license": {"id": "MIT"}}],
        "properties": [{"name": n, "value": v} for n, v in PATENTS] + [
            {"name": "varek:status", "value": "patent-pending"},
        ],
    }

    agent_component = {
        "type": "application",
        "bom-ref": "agent-run",
        "name": agent,
        "version": run_start,
        "description": "Autonomous agent run supervised under VAREK Authorization-Before-Execution.",
        "properties": [
            {"name": "varek:policy", "value": policy},
            {"name": "varek:run.id", "value": run_id},
            {"name": "varek:run.complete", "value": "true" if complete else "false"},
            {"name": "varek:run.start", "value": run_start},
            {"name": "varek:run.end", "value": run_end},
            {"name": "varek:decisions.total", "value": str(len(records))},
            {"name": "varek:decisions.authorized", "value": str(len(authorized))},
            {"name": "varek:decisions.refused", "value": str(len(refused))},
        ],
    }

    # Verdict distribution over the RAW verdict (before suppression), so an
    # UNKNOWN that was suppressed to DENY is still visible.
    dist = {}
    for r in records:
        d = r.get("decision_raw", r.get("decision_final", "UNKNOWN"))
        dist[d] = dist.get(d, 0) + 1

    components = []
    for path, r in sorted(seen.items()):
        comp = {
            "type": "data",
            "bom-ref": bomref("authorized-object", path),
            "name": path,
            "description": f"Object the agent was authorized to reach via {r.get('action','?')}.",
            "properties": [
                {"name": "varek:action", "value": str(r.get("action", ""))},
                {"name": "varek:rule", "value": str(r.get("rule", ""))},
                {"name": "varek:requested", "value": str(r.get("target", ""))},
                {"name": "varek:kernel_verdict", "value": str(r.get("kernel_verdict", ""))},
            ],
        }
        components.append(comp)

    attest_text = (
        f"VAREK Authorization-Before-Execution attestation. Policy '{policy}'. "
        f"{len(records)} action(s) mediated between {run_start} and {run_end}: "
        f"{len(authorized)} authorized, {len(refused)} refused. "
        f"Raw verdict distribution: "
        + ", ".join(f"{k}={v}" for k, v in sorted(dist.items()))
        + ". Every action was decided BEFORE it executed; no action reached the "
        "kernel without a verdict. UNKNOWN verdicts were suppressed to DENY "
        "(symmetric-suppression invariant). File decisions were made on the "
        "resolved canonical object, not the requested pathname (v1.12 "
        "resolve-then-decide)."
    )

    annotation = {
        "bom-ref": "authorization-attestation",
        "subjects": ["agent-run"],
        "annotator": {"component": {
            "type": "application", "bom-ref": "annotator:varek-warden",
            "name": "VAREK Warden", "version": warden_version,
        }},
        "timestamp": now,
        "text": attest_text,
    }

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "lifecycles": [{"phase": "operations"}],
            "tools": {"components": [warden_tool]},
            "component": agent_component,
            "properties": [
                {"name": f"varek:verdict.{k.lower()}", "value": str(v)}
                for k, v in sorted(dist.items())
            ],
        },
        "components": components,
        "annotations": [annotation],
    }
    return bom


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render a VAREK Warden pathology log as a CycloneDX 1.6 BOM.")
    ap.add_argument("--log", help="Warden pathology log (default: stdin)")
    ap.add_argument("--agent", default="agent", help="name/path of the supervised agent")
    ap.add_argument("--policy", default="policy.txt", help="policy identity for the run")
    ap.add_argument("--output", help="output BOM path (default: stdout)")
    ap.add_argument("--serial", help="BOM serialNumber (default: a fresh urn:uuid)")
    ap.add_argument("--allow-incomplete", action="store_true",
                    help="attest a stream with no run_end record (marked run.complete=false)")
    args = ap.parse_args(argv)

    # Split on '\n' only, so a '\r' the agent wrote cannot start a new line.
    if args.log:
        stream = open(args.log, encoding="utf-8", errors="surrogateescape", newline="\n")
    else:
        stream = open(sys.stdin.fileno(), encoding="utf-8", errors="surrogateescape",
                      newline="\n", closefd=False)
    run_id, records, complete, warden_version = _parse_log(stream, args.allow_incomplete)
    stream.close()

    serial = args.serial or f"urn:uuid:{uuid.uuid4()}"
    bom = build_bom(records, args.agent, args.policy, serial, run_id, complete,
                    warden_version)

    out = json.dumps(bom, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out + "\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
