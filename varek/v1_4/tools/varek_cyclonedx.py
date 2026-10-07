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
  * annotations[] — one machine- and human-readable authorization attestation.
    v1.18.0: every sentence in it is derived from the stream (the counts, the
    UNKNOWN verdicts and what became of them, which authorizations name a
    resolved object and carry an accepted certificate, the plan gate's
    decision, whether the stream is chained), and it says which system calls
    the record covers. Through v1.17.0 most of it was fixed wording, including
    "no action reached the kernel without a verdict", which is not true of the
    calls the filter admits without asking the Warden. If the records break an
    invariant the text would state (an UNKNOWN that was authorized), the
    exporter refuses to attest.
  * signature — v1.18.0, with --sign-key: an Ed25519 signature over the whole
    BOM in the JSON Signature Format (JSF) that CycloneDX 1.6 defines, made
    with the Warden's log key (tools/varek_keygen). --verify checks one
    against the public key the caller trusts (--pubkey, required); the key
    inside the BOM is not trusted. With --pubkey when exporting, the stream's
    own signatures must verify under that key, or no BOM is written.
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
        [--output bom.json] [--serial urn:uuid:...] [--pubkey log.key.pub]
        [--sign-key log.key]
    varek_cyclonedx.py --verify bom.json --pubkey log.key.pub

--policy names the policy for the record. When it is a readable file, its
SHA-256 must equal the policy_sha256 the Warden recorded in run_start (v1.15+),
or the exporter refuses: the BOM would otherwise name a policy the Warden did
not decide with.

Reads the log from --log or stdin. Writes the BOM to --output or stdout.
Exit status is non-zero when the stream cannot be authenticated (see
_parse_log), never on the presence of refusals (a run full of denials is a
valid, well-formed authorization record).
"""

import argparse
import base64
import ctypes
import ctypes.util
import datetime as _dt
import hashlib
import json
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import varek_ed25519  # noqa: E402  (pure-Python RFC 8032 verification)

VAREK_VERSION = "1.20.0"
SPEC_VERSION = "1.6"

# The provisional patents, as recorded in the runtime's own documentation.
PATENTS = [
    ("varek:patent:smt-layer", "USPTO Provisional 64/006,104 (SMT decision layer)"),
    ("varek:patent:warden-architecture", "USPTO Provisional 64/059,592 (Warden kernel architecture)"),
    ("varek:patent:action-graph", "USPTO Provisional 64/062,549 (compositional action-graph verification)"),
]


class StreamError(SystemExit):
    pass


LOG_CHAIN_FORMAT = "chain-1"
LOG_CHAIN_IV = hashlib.sha256(b"VAREK-LOG-CHAIN-1").digest()
LOG_SIG_DOMAIN = b"VAREK-LOG-SIG-1"
CHECKPOINT_EVENTS = ("run_start", "checkpoint", "run_end")
_CHAIN_TAIL = re.compile(rb',"chain":"([0-9a-f]{64})"(?:,"sig":"([0-9a-f]{128})")?\}\n?\Z')


def _version_at_least(v, want):
    """True if v (e.g. "1.16.0") is at least want (e.g. (1, 16))."""
    if not isinstance(v, str):
        return False
    parts = v.split(".")
    try:
        return tuple(int(x) for x in parts[:2]) >= want
    except ValueError:
        return False


def _chain_step(st, raw, rec, lineno, ndecisions, fail):
    """v1.16: check one record's chain value against the exact bytes of the
    line, and advance the chain."""
    b = raw.encode("utf-8", errors="surrogateescape")
    m = _CHAIN_TAIL.search(b)
    if not m:
        fail(lineno, "record of a chained stream without a well-formed chain value "
                     "(it was edited, or not written by the Warden).")
    body = b[:m.start()]
    h = hashlib.sha256(st["head"] + body).digest()
    if h.hex() != m.group(1).decode():
        fail(lineno, "hash chain broken: this record, or one before it, was altered, "
                     "inserted, removed or reordered.")
    st["head"] = h
    st["n"] += 1
    st["since_signed"] += 1
    event = rec.get("event")
    if event in CHECKPOINT_EVENTS:
        if event == "checkpoint" and rec.get("records") != ndecisions:
            fail(lineno, f"checkpoint counts {rec.get('records')} decision records, "
                         f"the stream holds {ndecisions} before it.")
        sig = m.group(2).decode() if m.group(2) else None
        st["signed"].append({"event": event, "chain": h, "sig": sig, "line": lineno,
                             "records": rec.get("records", 0), "ndec": ndecisions,
                             "ts": rec.get("timestamp_ns")})
        if sig:
            st["since_signed"] = 0
    elif event == "anchor_error":
        st["anchor_errors"].append({"line": lineno, "anchoring": rec.get("anchoring"),
                                    "errno": rec.get("errno")})


def _parse_log(stream, allow_incomplete=False, meta=None):
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
    could be forged by the supervised agent.

    v1.16 streams (run_start carries "log":"chain-1") are hash-chained: every
    record of the run ends with "chain":"<hex>", SHA-256 of the previous chain
    value and the record's exact bytes up to that field. A record whose chain
    value is wrong, or a record of the run without one, refuses the stream.
    The chain alone only catches accidental damage (anyone can recompute it);
    what it gives the audit is a single value per record that signatures and
    an external anchor can seal. The signed records ("sig") are returned in
    meta["log"] for tools/varek_audit.py to verify."""
    name = getattr(stream, "name", "<stdin>")

    def fail(lineno, why):
        raise StreamError(f"varek_cyclonedx: {name}:{lineno}: {why} "
                          f"Refusing to emit a BOM.")

    run = None
    records = []
    ended = None
    warden_version = VAREK_VERSION
    chained = None      # v1.16: the chain state, when run_start says the stream is chained
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
        if event == "run_start" or (run is not None and rec.get("run") == run):
            if chained is not None or (event == "run_start" and run is None
                                       and rec.get("log") == LOG_CHAIN_FORMAT):
                if chained is None:
                    chained = {"head": LOG_CHAIN_IV, "n": 0, "signed": [], "since_signed": 0,
                               "anchor_errors": []}
                if ended is not None:
                    fail(lineno, "record after run_end.")
                _chain_step(chained, raw, rec, lineno, len(records), fail)
        if event == "run_start":
            if run is not None:
                fail(lineno, "second run_start in one stream.")
            run = rec.get("run")
            if not isinstance(run, str) or len(run) != 32:
                fail(lineno, "run_start has no valid run id.")
            w = rec.get("warden")
            if isinstance(w, str) and w:
                warden_version = w
            if chained is None and _version_at_least(w, (1, 16)):
                fail(lineno, "run_start names a Warden that chains its records (1.16 or later) "
                             "but the stream is not chained: the chain was stripped.")
            if meta is not None:
                meta["run_start"] = rec      # v1.15: policy_sha256, for the audit
            continue
        if "decision_final" not in rec and event != "run_end":
            # e.g. a pre-launch plan record; carries no authorization. v1.18.0:
            # this run's plan_gate record (chained above) goes to the attestation.
            if event == "plan_gate" and run is not None and rec.get("run") == run \
                    and meta is not None:
                meta["plan_gate"] = rec
            # v1.24: this run's resolution records, each with the number of
            # decision records before it (varek_audit.py checks a connect
            # decided on a name against the resolutions it relied on).
            if event == "resolution" and run is not None and rec.get("run") == run \
                    and meta is not None:
                meta.setdefault("resolutions", []).append((len(records), rec))
            # v1.25: the stub resolver's questions and the resolutions, in
            # stream order (varek_audit.py checks the budgets and that every
            # name looked up on demand was asked for first).
            if event in ("resolution", "dns_question") and run is not None \
                    and rec.get("run") == run and meta is not None:
                meta.setdefault("dns_events", []).append(rec)
            continue
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

    if meta is not None:
        meta["log"] = chained            # v1.16: None for an unchained (pre-1.16) stream
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


FILE_ACTIONS = ("file.open", "file.stat", "file.access", "file.readlink")

# v1.24: an open of a resolver file answered with a view the Warden wrote
# (rule -> the path it answers). No file is opened and no rule decides it, so
# its raw verdict is UNKNOWN; it is not an authorization of the file, and it is
# reported apart from the decisions. varek_audit.py checks each view against
# the policy.
VIEW_RULES = {"hosts_view": "/etc/hosts", "resolv_view": "/etc/resolv.conf",
              "nsswitch_view": "/etc/nsswitch.conf", "hostconf_view": "/etc/host.conf",
              "netsvc_view": "/etc/netsvc.conf", "svc_view": "/etc/svc.conf"}   # v1.25
_O_ACCMODE, _O_CREAT, _O_TRUNC = 3, 0o100, 0o1000


def _is_view(r):
    """A view answered: a read-only open of the view's own path."""
    rule = r.get("rule")
    if r.get("action") != "file.open" or not isinstance(rule, str) or rule not in VIEW_RULES:
        return False
    try:
        fl = int(r.get("open_flags"), 16)
    except (TypeError, ValueError):
        return False
    return (r.get("resolved") == VIEW_RULES[rule] and r.get("kernel_verdict") == "ALLOW"
            and not fl & (_O_ACCMODE | _O_CREAT | _O_TRUNC))


def _scope(warden_version):
    """What the Warden records, by version: which calls it decides."""
    mediated = "file opens, connects, program launches and datagram sends"
    if _version_at_least(warden_version, (1, 17)):
        mediated = ("file opens and file lookups (stat, access, readlink), connects, "
                    "program launches and datagram sends")
    if _version_at_least(warden_version, (1, 21)):
        # v1.21: connects are dialed by the Warden; a send with no destination
        # of its own on a connected socket is not recorded (sendto is admitted
        # by the filter; sendmsg and sendmmsg are relayed without a record).
        mediated = ("file opens and file lookups (stat, access, readlink), connects "
                    "(each dialed by the Warden and handed over), program launches, and "
                    "sends that name a destination or carry control data")
    return (f"The record covers the system calls this Warden version pauses and "
            f"decides: {mediated}. Calls the kernel filter admits without asking the "
            f"Warden (reads and writes on descriptors already held, memory, time, "
            f"threads) and calls it refuses outright are not recorded.")


def attestation(records, authorized, refused, dist, policy, run_start, run_end,
                warden_version, complete, log_info, plan_gate, policy_check):
    """v1.18.0: the attestation text and its facts, each derived from the
    stream. Raises StreamError when the records break an invariant the text
    would otherwise assert."""
    unknown = [r for r in records if r.get("decision_raw") == "UNKNOWN"]
    unknown_allowed = [r for r in unknown if r.get("decision_final") == "ALLOW"]
    if unknown_allowed:
        raise StreamError(
            f"varek_cyclonedx: {len(unknown_allowed)} record(s) turn an UNKNOWN verdict "
            f"into ALLOW (first: seq {unknown_allowed[0].get('seq')}); the stream breaks "
            f"symmetric suppression. Refusing to emit a BOM.")
    auth_files = [r for r in authorized if r.get("action") in FILE_ACTIONS]
    resolved = [r for r in auth_files if r.get("resolved")]
    certified = [r for r in authorized if r.get("check") == "ok"]
    cert_refused = [r for r in records if r.get("check") == "refused"]

    parts = [f"VAREK authorization record for policy '{policy}' "
             f"(SHA-256 {policy_check}).",
             f"{len(records)} decision(s) recorded between {run_start} and {run_end}: "
             f"{len(authorized)} authorized, {len(refused)} refused."
             + ("" if complete else " The stream has no run_end: the run did not "
                "finish, or the record was cut."),
             "Raw verdicts: " + (", ".join(f"{k}={v}" for k, v in sorted(dist.items()))
                                 or "none") + "."]
    if unknown:
        parts.append(f"All {len(unknown)} UNKNOWN verdict(s) were refused "
                     f"(symmetric suppression).")
    else:
        parts.append("No UNKNOWN verdicts.")
    if auth_files:
        if len(resolved) == len(auth_files):
            parts.append(f"All {len(auth_files)} authorized file decision(s) name the "
                         f"resolved canonical object they were made on.")
        else:
            parts.append(f"{len(resolved)} of {len(auth_files)} authorized file "
                         f"decision(s) name a resolved object; the others predate "
                         f"resolve-then-decide (v1.12) or did not record it.")
    if authorized:
        parts.append(f"{len(certified)} of {len(authorized)} authorization(s) carry a "
                     f"certificate the independent checker accepted"
                     + (" (certificates start in v1.15)." if len(certified) < len(authorized)
                        and not _version_at_least(warden_version, (1, 15)) else "."))
    if cert_refused:
        parts.append(f"The checker refused {len(cert_refused)} certificate(s); those "
                     f"actions were refused.")
    if plan_gate:
        parts.append(f"Before launch, the plan gate decided {plan_gate.get('verdict')} "
                     f"(node {plan_gate.get('node_axis')}, flow {plan_gate.get('flow_axis')}; "
                     f"breaker {plan_gate.get('breaker')}).")
    chain = log_info.get("chain", "none")
    if chain != "none":
        nsig, nsigned = log_info.get("sigs", 0), log_info.get("signable", 0)
        if log_info.get("verified_key"):
            tail = log_info.get("unsigned_tail", 0)
            sig_text = (f"; all {nsig} of its signed records verify under the key "
                        f"{log_info['verified_key']}, checked by this exporter"
                        + (f"; the last {tail} record(s) come after the last signature "
                           f"(the stream has no run_end) and are covered by the chain only."
                           if tail else "."))
        elif nsig:
            sig_text = (f"; {nsig} of its {nsigned} checkpoint-type records carry a signature, "
                        f"not checked here (give --pubkey, or run tools/varek_audit.py --pubkey).")
        else:
            sig_text = "; it carries no signatures."
        parts.append("The stream is hash-chained (this exporter checked the chain)" + sig_text)
    else:
        parts.append("The stream is not hash-chained (a Warden before v1.16).")
    parts.append(_scope(warden_version))

    facts = [
        ("varek:unknown.total", str(len(unknown))),
        ("varek:unknown.authorized", "0"),
        ("varek:authorized.files", str(len(auth_files))),
        ("varek:authorized.files.resolved", str(len(resolved))),
        ("varek:authorized.certified", str(len(certified))),
        ("varek:certificates.refused", str(len(cert_refused))),
        ("varek:policy.sha256.check", policy_check),
    ]
    if plan_gate:
        facts += [("varek:plan_gate.verdict", str(plan_gate.get("verdict", ""))),
                  ("varek:plan_gate.breaker", str(plan_gate.get("breaker", "")))]
    return " ".join(parts), facts


def build_bom(records, agent, policy, serial, run_id="", complete=True,
              warden_version=VAREK_VERSION, policy_sha256="", log_info=None,
              plan_gate=None, policy_check="not checked"):
    # v1.12.2: the Warden component carries the version named in the stream's
    # run_start (the Warden that made the decisions), not this exporter's.
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    run_start, run_end = _ts(records)

    # v1.24: views answered are reported apart from the decisions
    views = [r for r in records if _is_view(r)]
    records = [r for r in records if not _is_view(r)]
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
            # v1.15: the SHA-256 of the policy bytes the Warden decided with
            {"name": "varek:policy.sha256", "value": policy_sha256},
            {"name": "varek:run.id", "value": run_id},
            # v1.16: the stream's hash chain (checked while reading it) and its
            # signing key; the signatures themselves are verified by varek_audit.py
            {"name": "varek:log.chain", "value": (log_info or {}).get("chain", "none")},
            {"name": "varek:log.pubkey", "value": (log_info or {}).get("pubkey", "")},
            {"name": "varek:run.complete", "value": "true" if complete else "false"},
            {"name": "varek:run.start", "value": run_start},
            {"name": "varek:run.end", "value": run_end},
            {"name": "varek:decisions.total", "value": str(len(records))},
            {"name": "varek:decisions.authorized", "value": str(len(authorized))},
            {"name": "varek:decisions.refused", "value": str(len(refused))},
            {"name": "varek:views.answered", "value": str(len(views))},
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
            ] + ([
                # v1.15: the verdict's certificate, as the independent checker
                # accepted it (re-checkable with tools/varek_audit.py)
                {"name": "varek:certificate.rule", "value": str(r["cert_rule"])},
                {"name": "varek:certificate.witness", "value": str(r.get("cert_witness", ""))},
                {"name": "varek:certificate.check", "value": str(r.get("check", ""))},
            ] if "cert_rule" in r else []),
        }
        components.append(comp)

    attest_text, facts = attestation(records, authorized, refused, dist, policy,
                                     run_start, run_end, warden_version, complete,
                                     log_info or {}, plan_gate, policy_check)
    if views:
        attest_text += (f" {len(views)} open(s) of the resolver files were answered with the "
                        f"Warden's views ({', '.join(sorted({r['rule'] for r in views}))}); no "
                        f"file was opened, and they are not counted as decisions.")
    agent_component["properties"] += [{"name": k, "value": v} for k, v in facts]

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


# ---------------- v1.18.0: JSF signature (Ed25519) ----------------

def jcs(obj):
    """RFC 8785 JSON canonicalization of the BOM: keys sorted, no whitespace,
    ECMAScript string escaping. The BOM holds only objects, arrays, strings,
    integers and booleans (no floats), and every key is ASCII, so sorting by
    code point equals JCS's UTF-16 order. A lone surrogate (a path byte that is
    not UTF-8, read with surrogateescape) is written as its \\u escape, as
    ECMAScript does."""
    def check(o):
        if isinstance(o, float):
            raise ValueError("a float in the BOM: JCS number form not implemented")
        if isinstance(o, dict):
            for k, v in o.items():
                if not k.isascii():
                    raise ValueError("a non-ASCII key in the BOM")
                check(v)
        elif isinstance(o, list):
            for v in o:
                check(v)
    check(obj)
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    text = re.sub("[\ud800-\udfff]", lambda m: "\\u%04x" % ord(m.group()), text)
    return text.encode("utf-8")


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(t):
    if not isinstance(t, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", t):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))


def _read_hex32(arg, what):
    txt = arg
    if os.path.exists(arg):
        with open(arg) as fh:
            txt = fh.read()
    txt = txt.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", txt):
        raise SystemExit(f"varek_cyclonedx: {what} must be 64 hex characters (or a file holding them)")
    return bytes.fromhex(txt)


def public_key_of(key_path):
    """The public key (hex) of a varek_keygen seed file, via libsodium."""
    na, seed, pk, sk = _keypair(key_path)
    ctypes.memset(sk, 0, 64)
    ctypes.memset(seed, 0, 32)
    return pk.raw.hex()


def _keypair(key_path):
    name = ctypes.util.find_library("sodium")
    if not name:
        raise SystemExit("varek_cyclonedx: --sign-key needs libsodium (the Warden's dependency)")
    na = ctypes.CDLL(name)
    if na.sodium_init() < 0:
        raise SystemExit("varek_cyclonedx: libsodium failed to initialize")
    if not os.path.isfile(key_path):
        raise SystemExit(f"varek_cyclonedx: --sign-key {key_path}: no such file")
    seed = ctypes.create_string_buffer(_read_hex32(key_path, "--sign-key"), 32)
    pk = ctypes.create_string_buffer(32)
    sk = ctypes.create_string_buffer(64)
    if na.crypto_sign_seed_keypair(pk, sk, seed) != 0:
        ctypes.memset(seed, 0, 32)
        raise SystemExit("varek_cyclonedx: cannot derive the key pair")
    return na, seed, pk, sk


def sign_bom(bom, key_path):
    """Add a JSF signature over the BOM, made with libsodium (the library the
    Warden signs its stream with) from the varek_keygen seed file."""
    # The seed and the secret key live in ctypes buffers that are zeroed on
    # every path. (Python may still hold copies of the file's text; the key
    # file itself is the secret to guard.)
    na, seed, pk, sk = _keypair(key_path)
    try:
        bom.pop("signature", None)
        bom["signature"] = {"algorithm": "Ed25519",
                            "publicKey": {"kty": "OKP", "crv": "Ed25519", "x": _b64u(pk.raw)}}
        msg = jcs(bom)
        sig = ctypes.create_string_buffer(64)
        if na.crypto_sign_detached(sig, None, msg, ctypes.c_ulonglong(len(msg)), sk) != 0:
            raise SystemExit("varek_cyclonedx: signing failed")
        bom["signature"]["value"] = _b64u(sig.raw)
        return pk.raw
    finally:
        ctypes.memset(sk, 0, 64)
        ctypes.memset(seed, 0, 32)


def _no_duplicate_keys(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def verify_bom(path, pubkey_arg):
    """Check a BOM's JSF Ed25519 signature against the key the caller trusts.
    Returns 0 if it verifies under that key, else 1, saying why. The key the BOM
    carries is not trusted: anyone can sign a BOM with a key of their own."""
    try:
        with open(path, encoding="utf-8") as fh:
            bom = json.load(fh, object_pairs_hook=_no_duplicate_keys)
    except (OSError, ValueError) as e:
        print(f"varek_cyclonedx: {path}: cannot read ({e})", file=sys.stderr)
        return 1
    sig = bom.get("signature") if isinstance(bom, dict) else None
    if not isinstance(sig, dict):
        print(f"varek_cyclonedx: {path}: not signed", file=sys.stderr)
        return 1
    pkobj = sig.get("publicKey") or {}
    try:
        if sig.get("algorithm") != "Ed25519" or pkobj.get("kty") != "OKP" \
                or pkobj.get("crv") != "Ed25519" or set(sig) - {"algorithm", "publicKey", "value"}:
            raise ValueError("expected an Ed25519 JSF signer with algorithm, publicKey and value only")
        pk = _b64u_dec(pkobj.get("x"))
        value = _b64u_dec(sig.get("value"))
    except (ValueError, TypeError) as e:
        print(f"varek_cyclonedx: {path}: malformed signature ({e})", file=sys.stderr)
        return 1
    unsigned = dict(bom)
    unsigned["signature"] = {k: v for k, v in sig.items() if k != "value"}
    if not varek_ed25519.verify(pk, jcs(unsigned), value):
        print(f"varek_cyclonedx: {path}: signature does NOT verify (the BOM was changed "
              f"after signing, or the signature is not for it)", file=sys.stderr)
        return 1
    if pk != _read_hex32(pubkey_arg, "--pubkey"):
        print(f"varek_cyclonedx: {path}: signed under key {pk.hex()}, not the one given",
              file=sys.stderr)
        return 1
    print(f"varek_cyclonedx: {path}: signature OK under the key given ({pk.hex()})")
    return 0


def check_stream_signatures(meta, pubkey_arg, complete):
    """v1.18.0: verify the stream's signed records against the key the caller
    trusts (as tools/varek_audit.py --pubkey does for the signatures). Raises
    StreamError on any failure; returns the key's hex."""
    pk = _read_hex32(pubkey_arg, "--pubkey")
    lg = meta.get("log")
    if not lg:
        raise StreamError("varek_cyclonedx: --pubkey given, but the stream is not chained "
                          "(a Warden before v1.16): nothing is signed. Refusing to emit a BOM.")
    named = str(meta.get("run_start", {}).get("log_pubkey", ""))
    if named != pk.hex():
        raise StreamError(f"varek_cyclonedx: run_start names signing key {named or '(none)'}, "
                          f"not the one given. Refusing to emit a BOM.")
    signed = lg.get("signed", [])
    for c in signed:
        if not c.get("sig"):
            raise StreamError(f"varek_cyclonedx: line {c['line']}: {c['event']} record is not "
                              f"signed. Refusing to emit a BOM.")
        if not varek_ed25519.verify(pk, LOG_SIG_DOMAIN + c["chain"], bytes.fromhex(c["sig"])):
            raise StreamError(f"varek_cyclonedx: line {c['line']}: {c['event']} signature does "
                              f"not verify under the key given. Refusing to emit a BOM.")
    if not signed or signed[0]["event"] != "run_start" or \
            (complete and signed[-1]["event"] != "run_end"):
        raise StreamError("varek_cyclonedx: the stream's signed records do not cover it from "
                          "run_start to run_end. Refusing to emit a BOM.")
    return pk.hex(), (0 if complete else int(lg.get("since_signed", 0)))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render a VAREK Warden pathology log as a CycloneDX 1.6 BOM.")
    ap.add_argument("--log", help="Warden pathology log (default: stdin)")
    ap.add_argument("--agent", default="agent", help="name/path of the supervised agent")
    ap.add_argument("--policy", default=None,
                    help="the policy file the Warden ran with (default: the policy_path "
                         "run_start records). A readable file must match the SHA-256 the "
                         "Warden recorded.")
    ap.add_argument("--output", help="output BOM path (default: stdout)")
    ap.add_argument("--serial", help="BOM serialNumber (default: a fresh urn:uuid)")
    ap.add_argument("--allow-incomplete", action="store_true",
                    help="attest a stream with no run_end record (marked run.complete=false)")
    ap.add_argument("--sign-key", help="sign the BOM (JSF, Ed25519) with this varek_keygen key file")
    ap.add_argument("--verify", metavar="BOM",
                    help="verify a signed BOM against --pubkey and exit")
    ap.add_argument("--pubkey", help="the Warden's log public key (hex, or its .pub file): with "
                    "--verify, the key the BOM must be signed with; when exporting, the key "
                    "the stream's signatures must verify under")
    args = ap.parse_args(argv)
    if args.verify:
        if not args.pubkey:
            print("varek_cyclonedx: --verify needs --pubkey: a signature under the key the BOM "
                  "carries proves only that someone holding that key signed it", file=sys.stderr)
            return 2
        return verify_bom(args.verify, args.pubkey)

    # Split on '\n' only, so a '\r' the agent wrote cannot start a new line.
    if args.log:
        stream = open(args.log, encoding="utf-8", errors="surrogateescape", newline="\n")
    else:
        stream = open(sys.stdin.fileno(), encoding="utf-8", errors="surrogateescape",
                      newline="\n", closefd=False)
    meta = {}
    run_id, records, complete, warden_version = _parse_log(stream, args.allow_incomplete, meta)
    stream.close()

    serial = args.serial or f"urn:uuid:{uuid.uuid4()}"
    lg = meta.get("log")
    log_info = {"chain": (lg["head"].hex() if lg else "none"),
                "pubkey": str(meta.get("run_start", {}).get("log_pubkey", "")),
                "signable": len(lg["signed"]) if lg else 0,
                "sigs": sum(1 for c in lg["signed"] if c.get("sig")) if lg else 0}
    if args.sign_key and not args.pubkey:
        # v1.18.0: signing vouches for the BOM, so the stream it was made from
        # must verify: under the key given, or else under the signing key.
        args.pubkey = public_key_of(args.sign_key)
    if args.pubkey:
        log_info["verified_key"], log_info["unsigned_tail"] = \
            check_stream_signatures(meta, args.pubkey, complete)
    if args.sign_key and log_info.get("unsigned_tail"):
        raise StreamError(f"varek_cyclonedx: the stream has no run_end and its last "
                          f"{log_info['unsigned_tail']} record(s) come after the last "
                          f"signature; refusing to sign a BOM that includes them.")
    recorded_sha = str(meta.get("run_start", {}).get("policy_sha256", ""))
    if args.policy is None:
        # v1.18.0: name the policy the Warden recorded, not a fixed label (the
        # default was "policy.txt", whatever the run used).
        args.policy = str(meta.get("run_start", {}).get("policy_path", "") or "unrecorded")
    if os.path.isfile(args.policy):
        with open(args.policy, "rb") as fh:
            given = hashlib.sha256(fh.read()).hexdigest()
        if recorded_sha and given != recorded_sha:
            raise StreamError(f"varek_cyclonedx: --policy {args.policy} has SHA-256 {given}, "
                              f"but the Warden decided with {recorded_sha}. Refusing to emit "
                              f"a BOM that names a policy the run did not use.")
        policy_check = (f"{given}, equal to the file named" if recorded_sha
                        else f"{given} of the file named; this Warden did not record one")
    else:
        policy_check = (f"{recorded_sha} as the Warden recorded it; the name given is not a "
                        f"file, so it was not compared" if recorded_sha else "not recorded")
    bom = build_bom(records, args.agent, args.policy, serial, run_id, complete,
                    warden_version, recorded_sha, log_info, meta.get("plan_gate"), policy_check)
    if args.sign_key:
        sign_bom(bom, args.sign_key)

    out = json.dumps(bom, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out + "\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
