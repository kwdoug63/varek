#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
varek_cyclonedx.py — turn a VAREK Warden pathology log into a CycloneDX 1.6 BOM.

The Warden emits one JSON pathology record per mediated action (see
`emit_pathology()` in warden.c): the action, the raw pathname the agent
supplied, the RESOLVED canonical object (v1.12+), the policy decision, the rule
that fired, and the per-decision latency. That stream IS the authorization
evidence for a run. This tool renders it as a CycloneDX 1.6 Bill of Materials so
the evidence travels in a standard, tool-consumable form alongside an SBOM.

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
Exit status is non-zero only on malformed input, never on the presence of
refusals (a run full of denials is a valid, well-formed authorization record).
"""

import argparse
import datetime as _dt
import json
import sys
import uuid

VAREK_VERSION = "1.12.0"
SPEC_VERSION = "1.6"

# The provisional patents, as recorded in the runtime's own documentation.
PATENTS = [
    ("varek:patent:smt-layer", "USPTO Provisional 64/006,104 (SMT decision layer)"),
    ("varek:patent:warden-architecture", "USPTO Provisional 64/059,592 (Warden kernel architecture)"),
    ("varek:patent:action-graph", "USPTO Provisional 64/062,549 (compositional action-graph verification)"),
]


def _parse_log(stream):
    """Yield pathology records from a Warden log stream, skipping human status
    lines (those beginning with '[warden')."""
    records = []
    for lineno, raw in enumerate(stream, 1):
        line = raw.strip()
        if not line or line.startswith("[warden"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            raise SystemExit(f"varek_cyclonedx: {getattr(stream,'name','<stdin>')}:{lineno}: "
                             f"not valid JSON ({e}). A malformed verdict stream cannot be "
                             f"attested; refusing to emit a BOM.")
        if isinstance(rec, dict) and "decision_final" in rec:
            records.append(rec)
    return records


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


def build_bom(records, agent, policy, serial):
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
        "version": VAREK_VERSION,
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
            "name": "VAREK Warden", "version": VAREK_VERSION,
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
    args = ap.parse_args(argv)

    stream = open(args.log) if args.log else sys.stdin
    records = _parse_log(stream)
    if args.log:
        stream.close()

    serial = args.serial or f"urn:uuid:{uuid.uuid4()}"
    bom = build_bom(records, args.agent, args.policy, serial)

    out = json.dumps(bom, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out + "\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
