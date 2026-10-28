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
    """True if v (e.g. "1.16.0") is at least want (e.g. (1, 16), or (1, 27, 1))."""
    if not isinstance(v, str):
        return False
    parts = v.split(".")
    try:
        p = [int(x) for x in parts[:len(want)]]
    except ValueError:
        return False
    return tuple(p + [0] * (len(want) - len(p))) >= want


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
        c = {"event": event, "chain": h, "sig": sig, "line": lineno,
             "records": rec.get("records", 0), "ndec": ndecisions, "ts": rec.get("timestamp_ns")}
        # v1.36 (D9): handed on as it comes (the audit keeps none), or kept
        st["on_signed"]("signed", c) if "on_signed" in st else st["signed"].append(c)
        if sig:
            st["since_signed"] = 0
    elif event == "anchor_error":
        ae = {"line": lineno, "anchoring": rec.get("anchoring"), "errno": rec.get("errno")}
        st["on_signed"]("anchor_error", ae) if "on_signed" in st else st["anchor_errors"].append(ae)


# v1.28: the events of credential release and revocation (varek_audit.py)
CRED_EVENTS = ("credential_refused", "revoked", "revocation_proxy", "revocation_leases", "lease_renewed",
               "lease_renewal_failed", "on_behalf_of_expired")      # v1.28.1: the user's token's expiry


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
    meta["log"] for tools/varek_audit.py to verify.

    v1.36 (D9): this collects what _iter_log yields, one record at a time,
    for the exporters; tools/varek_audit.py reads _iter_log itself and keeps
    no record once its checks have seen it."""
    records = []
    m = meta if meta is not None else {}
    lines = {}
    lists = (("plan_step", "plan_events"), ("plan_gate", "plan_events"), ("resolution", "resolutions"),
             ("proxy_close", "proxy_closes"), ("request_body", "request_bodies"),
             ("exec_result", "exec_results"), ("subagent_settled", "subagent_events"))
    for item in _iter_log(stream, allow_incomplete, m):
        rec, lineno = item[1], item[2]
        lines[id(rec)] = lineno           # v1.26.1 review: each record's place in the stream
        if item[0] == "dec":
            records.append(rec)
        elif item[0] == "ev":
            event, before = rec.get("event"), item[3]
            # v1.18.0: this run's plan_gate record goes to the attestation
            if event == "plan_gate":
                m["plan_gate"] = rec
            # v1.35 step 7: the plan gate's records; v1.24: the resolution
            # records; v1.26 (step 7): the proxy's closes; v1.26.1 (step 6): an
            # inspected request's body; v1.27 (step 4): each allowed launch's
            # outcome; v1.28.1 review: how each sub-agent's launch settled;
            # each with the number of decision records before it
            for ev, key in lists:
                if event == ev:
                    m.setdefault(key, []).append((before, rec))
            # v1.28: credentials and revocation
            if event in CRED_EVENTS:
                m.setdefault("cred_events", []).append((before, rec))
            # v1.25: the stub resolver's questions and the resolutions, in
            # stream order; v1.26: and the synthetic addresses
            if event in ("resolution", "dns_question", "synthetic_address"):
                m.setdefault("dns_events", []).append(rec)
    m["lineno"] = lines
    m["log"] = m.pop("chain", None)
    m.pop("ndecisions", None)
    return m.pop("_run", None), records, m.get("run_end") is not None, m.pop("_warden", VAREK_VERSION)


def _iter_log(stream, allow_incomplete=False, meta=None, on_line=None, on_signed=None):
    """v1.36 (D9): _parse_log's checks, one record at a time. Yields
    ("dec", record, line) for each decision record (its seq is its place)
    and ("ev", record, line, decisions before it) for each other record of
    the run but run_start and run_end, which go to meta["run_start"] and
    meta["run_end"] (and are yielded as ("start", record, line) and ("end",
    record, line)). The chain's state is meta["chain"]; with on_signed, each
    checkpoint-type record and each anchor_error is handed to it instead of
    being kept (("signed", entry) or ("anchor_error", entry)). on_line(rec,
    line) sees every record of the run (the token scan).

    stream may be a list: the segments of one stream, in order (the node
    agent's rotation). Each segment after the first begins with a
    checkpoint naming its number ("segment": 2, 3, ...) and the chain value
    the segment before it ended on ("prev_chain"); the chain runs on across
    them, and lines are counted across them."""
    streams = stream if isinstance(stream, list) else [stream]
    names = [getattr(s, "name", "<stdin>") for s in streams]
    bases = []          # (lines before the segment, its name)

    def fail(lineno, why):
        base, name = next(((b, n) for b, n in reversed(bases) if b < lineno), (0, bases[-1][1] if bases else
                                                                                names[0]))
        raise StreamError(f"varek_cyclonedx: {name}:{lineno - base if lineno else 0}: {why} "
                          f"Refusing to emit a BOM.")

    run = None
    ndec = 0
    ended = None
    warden_version = VAREK_VERSION
    chained = None      # v1.16: the chain state, when run_start says the stream is chained
    early = {}          # v1.35 step 9 (review): the run ids of records before run_start, by line
    lineno = 0
    segment = 2         # v1.36 (D9): the next segment's number
    for k, fh in enumerate(streams, 1):
        bases.append((lineno, names[k - 1]))
        first = True
        for raw in fh:
            lineno += 1
            if not raw.startswith("{"):
                continue
            try:
                rec = json.loads(raw)
            except ValueError as e:      # v1.25 review: also an integer past Python's digit limit
                fail(lineno, f"record is not valid JSON ({e}).")
            if not isinstance(rec, dict):
                fail(lineno, "record is not a JSON object.")
            event = rec.get("event")
            # v1.36 (D9): each segment after the first begins with a checkpoint
            # that names it and the chain value the one before ended on (in
            # its own file, or the segments put together in one)
            if (k > 1 and first) or (event == "checkpoint" and ("segment" in rec or "prev_chain" in rec)):
                if event != "checkpoint" or rec.get("segment") != segment or chained is None or run is None or \
                        rec.get("run") != run or rec.get("prev_chain") != chained["head"].hex():
                    fail(lineno, f"segment {segment} does not begin with a checkpoint of this run that names "
                                 f"it and the chain value segment {segment - 1} ended on.")
                segment += 1
            first = False
            if run is None and event != "run_start" and isinstance(rec.get("run"), str):
                early.setdefault(rec["run"], lineno)
            if event == "run_start" or (run is not None and rec.get("run") == run):
                if chained is not None or (event == "run_start" and run is None
                                           and rec.get("log") == LOG_CHAIN_FORMAT):
                    if chained is None:
                        chained = {"head": LOG_CHAIN_IV, "n": 0, "signed": [], "since_signed": 0,
                                   "anchor_errors": []}
                        if on_signed is not None:
                            chained["on_signed"] = on_signed
                        if meta is not None:
                            meta["chain"] = chained
                    if ended is not None:
                        fail(lineno, "record after run_end.")
                    _chain_step(chained, raw, rec, lineno, ndec, fail)
            if event == "run_start":
                if run is not None:
                    fail(lineno, "second run_start in one stream.")
                run = rec.get("run")
                if not isinstance(run, str) or len(run) != 32:
                    fail(lineno, "run_start has no valid run id.")
                if run in early:     # v1.35 step 9 (review): unchained, so put there by someone else
                    fail(early[run], "a record of the run before its run_start (the Warden writes run_start "
                                     "first): not one the chain covers.")
                w = rec.get("warden")
                if isinstance(w, str) and w:
                    warden_version = w
                if chained is None and _version_at_least(w, (1, 16)):
                    fail(lineno, "run_start names a Warden that chains its records (1.16 or later) "
                                 "but the stream is not chained: the chain was stripped.")
                if meta is not None:
                    meta["run_start"] = rec      # v1.15: policy_sha256, for the audit
                    meta["_run"], meta["_warden"] = run, warden_version
                if on_line is not None:
                    on_line(rec, lineno)
                yield ("start", rec, lineno)
                continue
            if on_line is not None and run is not None and rec.get("run") == run:
                on_line(rec, lineno)
            if "decision_final" in rec and event is not None:
                # v1.31 review: a decision record carries no event (the exporters
                # would read it as the event it names)
                fail(lineno, f"a decision record that also says it is a {event!r} event.")
            if "decision_final" not in rec and event != "run_end":
                # e.g. a pre-launch plan record; carries no authorization
                if run is not None and rec.get("run") == run:
                    yield ("ev", rec, lineno, ndec)
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
                if rec.get("records") != ndec:
                    fail(lineno, f"run_end counts {rec.get('records')} records, the "
                                 f"stream holds {ndec}.")
                ended = rec
                if meta is not None:
                    meta["run_end"] = ended
                yield ("end", rec, lineno)
                continue
            if rec.get("seq") != ndec:
                fail(lineno, f"seq {rec.get('seq')} where {ndec} was expected "
                             f"(a record is missing, repeated or foreign).")
            ndec += 1
            yield ("dec", rec, lineno)
        if k > 1 and first:
            fail(lineno + 1, f"{names[k - 1]} holds no record (a segment begins with its checkpoint).")

    if meta is not None:
        meta.setdefault("chain", chained)  # v1.16: None for an unchained (pre-1.16) stream
        meta["run_end"] = ended            # v1.25 review: when the run ended, for the audit
        meta["ndecisions"] = ndec
    if run is None:
        fail(0, "no run_start record: not a v1.12.1+ Warden stream.")
    if ended is None and not allow_incomplete:
        fail(0, "no run_end record: the stream is incomplete (the Warden did "
                "not finish, or the log was cut). Use --allow-incomplete to "
                "attest the part that is present.")


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
# v1.26.1: in inspecting mode, the trust views (rule -> the paths it
# answers), and a read-type lookup of one, answered from the view
TRUST_VIEW_RULES = {"trust_view": ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                                   "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem",
                                   "/etc/varek/run-bundle.pem"),
                    "run_ca_view": ("/etc/varek/run-ca.pem",),
                    "trust_store_view": ("/etc/varek/run-trust.p12",)}
_TRUST_PATHS = tuple(p for v in TRUST_VIEW_RULES.values() for p in v)
_O_ACCMODE, _O_CREAT, _O_TRUNC = 3, 0o100, 0o1000


def _is_view(r, inspecting=False):
    """A view answered: a read-only open of the view's own path (v1.26.1: or,
    in a run in inspecting mode, an open or read-type lookup of a trust
    view)."""
    rule = r.get("rule")
    if r.get("action") in ("file.stat", "file.access") and rule == "view_metadata":
        return inspecting and r.get("resolved") in _TRUST_PATHS and r.get("kernel_verdict") == "ALLOW"
    if r.get("action") == "file.open" and rule in TRUST_VIEW_RULES:
        if not inspecting:
            return False
        try:
            fl = int(r.get("open_flags"), 16)
        except (TypeError, ValueError):
            return False
        return (r.get("resolved") in TRUST_VIEW_RULES[rule] and r.get("kernel_verdict") == "ALLOW"
                and not fl & (_O_ACCMODE | _O_CREAT | _O_TRUNC))
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
                warden_version, complete, log_info, plan_gate, policy_check, meta=None):
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
    meta = meta or {}
    hold = (meta.get("run_start") or {}).get("hold")
    hold = hold if isinstance(hold, dict) else None
    nsteps = sum(1 for _, e in meta.get("plan_events", []) if e.get("event") == "plan_step")
    outside = [r for r in records if r.get("rule") == "outside_plan"]
    # step 9 (review): said from the records alone: the agent started only when the gate passed (and under
    # the flow gate its breaker); an unreadable plan by the parser's error; a hold only once the gate passed
    started = bool(plan_gate) and plan_gate.get("verdict") == "SATISFIED" and \
        (plan_gate.get("gate") != "flow" or plan_gate.get("breaker") == "PASS")
    if plan_gate:
        sha = plan_gate.get("plan_sha256")
        what = (f"The plan {plan_gate.get('plan')} ({plan_gate.get('actions')} step(s)"
                + (f", SHA-256 {sha}" if sha else "") + ")")
        flow = (f" by the flow gate (node {plan_gate.get('node_axis')}, flow {plan_gate.get('flow_axis')}; "
                f"breaker {plan_gate.get('breaker')})" if plan_gate.get("gate") == "flow" else "")
        if plan_gate.get("error"):
            why = f"could not be read ({plan_gate.get('error')})"
        else:
            why = f"was decided {plan_gate.get('verdict')}{flow} under the policy"
            if not started:
                why += (f" ({nsteps} step(s) not SATISFIED, each recorded with its reason)" if nsteps else
                        f" (the plan's {plan_gate.get('why')})" if plan_gate.get("why") else "")
        parts.append(f"{what} {why}, so the agent was {'started' if started else 'not started'}.")
    if hold and started:
        parts.append(f"The run was held to its plan: {len(outside)} call(s) the policy allowed were "
                     f"refused as outside it (outside_plan).")
    elif hold:
        parts.append("The run was to be held to its plan, which was refused: no call was made.")
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
        facts += [("varek:plan_gate.verdict", str(plan_gate.get("verdict", "")))]
        if plan_gate.get("gate") == "flow":
            facts.append(("varek:plan_gate.breaker", str(plan_gate.get("breaker", ""))))
        else:                                          # v1.35 step 7
            facts += [("varek:plan.path", str(plan_gate.get("plan", ""))),
                      ("varek:plan.steps", str(plan_gate.get("actions", ""))),
                      ("varek:plan.steps_not_satisfied", str(nsteps))]
            if plan_gate.get("plan_sha256"):
                facts.append(("varek:plan.sha256", str(plan_gate["plan_sha256"])))
    if hold:
        facts += [("varek:plan.held", "true" if started else "false (the plan was refused)"),
                  ("varek:plan.held.sha256", str(hold.get("plan_sha256", ""))),
                  ("varek:plan.outside_plan", str(len(outside)))]
    return " ".join(parts), facts


def _proxy_text(records, pm):
    """v1.26.1 (step 7): the proxy's facts and attestation sentences, from
    run_start (its mode, its binary's hash, the run's CA) and the proxy's
    records. Nothing without the proxy on."""
    rs = pm.get("run_start") or {}
    px = rs.get("proxy")
    if not isinstance(px, dict):
        return "", []
    mode = "inspect" if px.get("mode") == "inspect" else "sni"
    proxied = [r for r in records if r.get("action") == "net.proxy"]
    closes = [e for _, e in pm.get("proxy_closes", [])]
    facts = [("varek:proxy.mode", mode),
             ("varek:proxy.binary.sha256", str(rs.get("proxy_binary_sha256", ""))),
             ("varek:proxy.connections", str(len(proxied))),
             ("varek:proxy.connections.allowed",
              str(sum(1 for r in proxied if r.get("decision_final") == "ALLOW")))]
    text = (f" The egress proxy ran in {'inspecting' if mode == 'inspect' else 'SNI'} mode "
            f"(warden-proxy SHA-256 {rs.get('proxy_binary_sha256', 'not recorded')}): "
            f"{len(proxied)} connection(s) decided on their name and port.")
    if mode != "inspect":
        return text, facts
    tr = rs.get("trust") if isinstance(rs.get("trust"), dict) else {}
    reqs = [r for r in records if r.get("action") == "net.request"]
    allowed = [r for r in reqs if r.get("decision_final") == "ALLOW"]
    over = [r for r in reqs if r.get("rule") == "max_body"]
    bodies = [b for _, b in pm.get("request_bodies", [])]
    cut = [b for b in bodies if b.get("exceeded_max_body") is True]
    ends = [e for e in closes if e.get("why") in ("server_tls", "client_tls", "tls_timeout")]
    parsed = [e for e in closes if e.get("why") == "refused_request" and "request_error" in e and
              not any(r.get("proxy_conn") == e.get("proxy_conn") and r.get("decision_final") != "ALLOW"
                      for r in reqs)]
    facts += [("varek:proxy.ca.sha256", str(tr.get("ca_sha256", ""))),
              ("varek:proxy.ca.names", str(tr.get("ca_names", ""))),
              ("varek:proxy.ca.key_locked", "true" if tr.get("ca_key_locked") is True else "false"),
              ("varek:proxy.trust_store.sha256", str(tr.get("trust_store_sha256", ""))),
              ("varek:proxy.host_bundle.sha256", str(tr.get("host_bundle_sha256", ""))),
              ("varek:proxy.passthrough", ",".join(str(h) for h in tr.get("passthrough"))
               if isinstance(tr.get("passthrough"), list) else ""),
              ("varek:requests.total", str(len(reqs))),
              ("varek:requests.allowed", str(len(allowed))),
              ("varek:requests.refused", str(len(reqs) - len(allowed))),
              ("varek:requests.refused.max_body", str(len(over))),
              ("varek:requests.refused.parser", str(len(parsed))),
              ("varek:requests.bodies", str(len(bodies))),
              ("varek:requests.bodies.cut", str(len(cut))),
              ("varek:proxy.tls_failures", str(len(ends)))]
    text += (f" It terminated TLS with a CA made for this run (SHA-256 {tr.get('ca_sha256', 'not recorded')}, "
             f"name-constrained to {tr.get('ca_names', '?')} name(s)), after verifying each server; "
             f"{len(reqs)} request(s) were each decided on METHOD scheme://name:port/path?query "
             f"before any of it was sent: {len(allowed)} allowed ("
             f"{sum(1 for r in allowed if 'cert_rule' in r and r.get('check') == 'ok')} with a certificate "
             f"the independent checker accepted), and "
             f"{len(reqs) - len(allowed)} refused ({len(over)} for a body over max_body). "
             f"The proxy's parser refused {len(parsed)} more before a decision, and "
             f"{len(ends)} connection(s) ended in a failed TLS handshake. "
             f"{len(bodies)} request body(ies) were recorded by length and SHA-256, never their "
             f"contents" + (f"; {len(cut)} was cut at max_body." if cut else "."))
    return text, facts


def _launch_text(records, pm):
    """v1.27 (step 5): decided launches, from run_start (Landlock and the
    launch set) and the launch records. Nothing when the run did not decide
    launches (no launch set in run_start)."""
    rs = pm.get("run_start") or {}
    ex = rs.get("exec_ruleset")
    if not isinstance(ex, list):
        return "", []
    ll = rs.get("landlock")
    abi = str(ll.get("abi")) if isinstance(ll, dict) else "none"
    digest = hashlib.sha256(json.dumps(ex, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    launches = [r for r in records if r.get("action") == "process.exec" and r.get("rule") != "bootstrap_exec_allow"]
    allowed = [r for r in launches if r.get("rule") == "exec_allowed"]
    results = [e for _, e in pm.get("exec_results", [])]
    ran = sum(1 for e in results if e.get("result") == "launched")
    killed = [r for r in records if r.get("rule") == "exec_identity_mismatch" or
              (r.get("rule") == "subagent_env" and r.get("action") != "process.exec")]
    facts = [("varek:launches.landlock_abi", abi),
             ("varek:launches.set.files", str(len(ex))),
             ("varek:launches.set.sha256", digest),
             ("varek:launches.total", str(len(launches))),
             ("varek:launches.allowed", str(len(allowed))),
             ("varek:launches.launched", str(ran)),
             ("varek:launches.refused", str(len(launches) - len(allowed))),
             ("varek:launches.refused.not_in_set", str(sum(1 for r in launches if r.get("rule") == "exec_not_in_ruleset"))),
             ("varek:launches.killed", str(len(killed)))]
    text = (f" Launches after the agent's own were decided by the policy's exec rules"
            f"{f', the agent held by Landlock (ABI {abi})' if abi != 'none' else ' (no Landlock: all refused)'} "
            f"to a launch set of {len(ex)} file(s) fixed at startup: {len(launches)} launch(es) decided, "
            f"{len(allowed)} allowed ({ran} seen running the program decided), "
            f"{len(launches) - len(allowed)} refused" +
            (f"; {len(killed)} process(es) found running a program not decided were killed." if killed else "."))
    # v1.27.1: the directories the agent could write, mounted noexec
    if "noexec" in rs:
        nx = rs.get("noexec")
        if nx is None:
            facts.append(("varek:noexec.off", "true"))
            text += (" The writable directories were not mounted noexec (--writable-exec): files the agent "
                     "wrote could be mapped executable.")
        elif isinstance(nx, list):
            facts.append(("varek:noexec.dirs", str(len(nx))))
            facts.append(("varek:noexec.sha256", hashlib.sha256(json.dumps(nx, sort_keys=True,
                          separators=(",", ":")).encode()).hexdigest()))
            text += (f" The {len(nx)} director(ies) the agent could write were mounted noexec: no file written "
                     f"there could be launched or mapped executable.")
    return text, facts


def _cred_text(records, pm):
    """v1.28 (section 5): credential release and revocation, from run_start
    (each credential's source and version, never a value) and the stream's
    events. Nothing when the run held no credential and was not revoked."""
    rs = pm.get("run_start") or {}
    creds = [c for c in rs.get("credentials") or [] if isinstance(c, dict)] \
        if isinstance(rs.get("credentials"), list) else []
    evs = [e for _, e in pm.get("cred_events", [])]
    revoked = next((e for e in evs if e.get("event") == "revoked"), None)
    if not creds and not revoked:
        return "", []
    one = lambda n: next((e for e in evs if e.get("event") == n), {})
    carried = [r for r in records if r.get("action") == "net.request" and r.get("credential")]
    refused = [e for e in evs if e.get("event") == "credential_refused"]
    renewed = [e for e in evs if e.get("event") == "lease_renewed"]
    unrenewed = [e for e in evs if e.get("event") == "lease_renewal_failed"]
    facts = [("varek:credentials.count", str(len(creds)))]
    text = ""
    if creds:
        facts += [("varek:credentials.names", ",".join(str(c.get("name", "")) for c in creds)),
                  ("varek:credentials.secrets_binary.sha256", str(rs.get("secrets_binary_sha256", ""))),
                  ("varek:credentials.sha256", hashlib.sha256(json.dumps(creds, sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest())]
        facts += [(f"varek:credentials.{c.get('name')}", f"{c.get('store')}:{c.get('ref')} version "
                   f"{c.get('version')}") for c in creds]
        facts += [("varek:credentials.requests", str(len(carried))),
                  ("varek:credentials.refused", str(len(refused))),
                  ("varek:credentials.leases.renewed", str(len(renewed))),
                  ("varek:credentials.leases.renewal_failed", str(len(unrenewed)))]
        text += (f" {len(creds)} credential(s) were fetched at startup and held by the egress proxy; the agent "
                 f"held only placeholders. {len(carried)} request(s) carried one, each where its deciding rule "
                 f"names it; {len(refused)} were refused because the request did not hold its placeholder "
                 f"where the rule names it. No value is in this evidence or in the verdict stream.")
    facts.append(("varek:run.revoked", "true" if revoked else "false"))
    if revoked:
        rp, rl = one("revocation_proxy"), one("revocation_leases")
        facts += [("varek:revocation.by", "on_behalf_of_expiry" if revoked.get("by") == "on_behalf_of_expiry"
                   else "varek revoke"),                                       # v1.28.1
                  ("varek:revocation.by_uid", str(revoked.get("by_uid", ""))),
                  ("varek:revocation.proxy.values_held", str(rp.get("values_held", "not reported"))),
                  ("varek:revocation.leases.revoked", str(rl.get("revoked", "not reported"))),
                  ("varek:revocation.leases.failed", str(rl.get("failed", "not reported")))]
        # v1.28 review: say what the stream shows, counted here, not what it should show
        lines = pm.get("lineno", {})
        rline = lines.get(id(revoked), 0)
        late = sum(1 for r in records if lines.get(id(r), 0) > rline and r.get("decision_final") != "DENY")
        facts.append(("varek:revocation.allowed_after", str(late)))
        text += (" The run was revoked (" + ("the user's token expired" if revoked.get("by") == "on_behalf_of_expiry"
                                           else "varek revoke") + "): "
                 + ("every decision after it was UNSATISFIED" if not late else
                    f"{late} decision(s) after it were NOT refused (the audit fails such a stream)")
                 + (f", the proxy held {rp['values_held']} credential value(s) after it" if "values_held" in rp else "")
                 + (f", and {rl['revoked']} Vault lease(s) were revoked ({rl['failed']} could not be)"
                    if "revoked" in rl else "") + ".")
    return text, facts


def _obo_text(records, pm):
    """v1.28.1 (section 5): who the run acted for, from run_start's
    on_behalf_of (the user an issuer vouched for, the actors of a delegation,
    the agent's SPIFFE ID; never the token) and the records' obo: the
    decisions made for each sub-agent. Nothing for a Warden before 1.28.1."""
    rs = pm.get("run_start") or {}
    obo = rs.get("on_behalf_of")
    if not isinstance(obo, dict):
        return "", []
    user = obo.get("user") if isinstance(obo.get("user"), dict) else None
    agent = obo.get("agent") if isinstance(obo.get("agent"), dict) else {}
    actors = [a for a in obo.get("actors") or [] if isinstance(a, dict)] if isinstance(obo.get("actors"), list) else []
    facts, text = [], ""
    if user:
        facts += [("varek:on_behalf_of.user.issuer", str(user.get("issuer", ""))),
                  ("varek:on_behalf_of.user.subject", str(user.get("subject", ""))),
                  ("varek:on_behalf_of.user.audience", str(user.get("audience", ""))),
                  ("varek:on_behalf_of.user.expires", str(user.get("expires", ""))),
                  ("varek:on_behalf_of.user.token_sha256", str(user.get("token_sha256", ""))),
                  ("varek:on_behalf_of.user.on_expiry", str(user.get("on_expiry", "revoke")))]
        if actors:
            facts.append(("varek:on_behalf_of.actors", ",".join(str(a.get("subject", "")) for a in actors)))
        text += (f" The run acted on behalf of {user.get('subject')}, whose token {user.get('issuer')} issued "
                 + ("(verified against its keys at the start" if user.get("verified") is True
                    else "(recorded as NOT verified") + "; the token is not in this evidence)"
                 + (f", delegated through {len(actors)} actor(s)" if actors else "") + ".")
    else:
        text += " No user's token was given: the run acted for the agent alone."
    if "spiffe_id" in agent:
        facts.append(("varek:on_behalf_of.agent.spiffe_id", str(agent.get("spiffe_id", ""))))
        text += f" The agent's SPIFFE ID {agent.get('spiffe_id')} was verified against its trust domain's bundle."
    op = rs.get("operator")
    if isinstance(op, dict):
        facts.append(("varek:on_behalf_of.operator", f"uid {op.get('uid')}" + (f" ({op['login']})" if op.get("login") else "")
                      + " (not verified)"))
    exp = next((e for _, e in pm.get("cred_events", []) if e.get("event") == "on_behalf_of_expired"), None)
    if exp:
        facts.append(("varek:on_behalf_of.expired", str(exp.get("action", ""))))
        text += (" The user's token expired during the run, and the run was "
                 + ("revoked." if exp.get("action") == "revoke" else "let go on (--on-behalf-of-expiry record)."))
    per = {}
    for r in records:
        ob = r.get("obo")
        if isinstance(ob, list) and ob and isinstance(ob[-1], str) and ob[-1].startswith("subagent:"):
            per[ob[-1][len("subagent:"):]] = per.get(ob[-1][len("subagent:"):], 0) + 1
    for _, e in pm.get("exec_results", []):
        if isinstance(e.get("subagent"), str):
            per.setdefault(e["subagent"], 0)
    if per:
        facts.append(("varek:on_behalf_of.subagents", str(len(per))))
        facts += [(f"varek:on_behalf_of.subagent.{t}.decisions", str(n)) for t, n in sorted(per.items())]
        text += (f" {len(per)} sub-agent(s) ran, each in its own control group; each decision names whom it "
                 f"was for: " + ", ".join(f"{t} {n}" for t, n in sorted(per.items())) + ".")
    return text, facts


def build_bom(records, agent, policy, serial, run_id="", complete=True,
              warden_version=VAREK_VERSION, policy_sha256="", log_info=None,
              plan_gate=None, policy_check="not checked", proxy_meta=None):
    # v1.12.2: the Warden component carries the version named in the stream's
    # run_start (the Warden that made the decisions), not this exporter's.
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    run_start, run_end = _ts(records)

    # v1.24: views answered are reported apart from the decisions
    rs = (proxy_meta or {}).get("run_start") or {}
    insp = isinstance(rs.get("proxy"), dict) and rs["proxy"].get("mode") == "inspect"   # review
    views = [r for r in records if _is_view(r, insp)]
    records = [r for r in records if not _is_view(r, insp)]
    authorized = [r for r in records if r.get("decision_final") == "ALLOW"]
    refused = [r for r in records if r.get("decision_final") != "ALLOW"]
    # v1.29 (section 5): a dry run is said to be one everywhere: in the
    # metadata, on every authorization listed, and in the attestation; what
    # it let through is counted apart ("would refuse")
    dry = rs.get("mode") == "dry_run"
    not_enforced = [r for r in records + list((proxy_meta or {}).get("dns_events", []))
                    if isinstance(r, dict) and r.get("enforced") is False]          # the stub's too

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
        "description": "Kernel-enforced, proof-checked authorization for what an AI "
                       "agent's process actually does: each file open, lookup, connect, "
                       "program launch and datagram send is decided at the kernel "
                       "(seccomp-BPF and seccomp user-notify).",
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
        "description": "Autonomous agent run whose process's actions the VAREK Warden "
                       "decided at the kernel.",
        "properties": [
            {"name": "varek:mode", "value": "dry_run" if dry else "enforcing"},     # v1.29
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
        ] + ([{"name": "varek:decisions.would_refuse", "value": str(len(not_enforced))}] if dry else []),
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
            "properties": ([{"name": "varek:mode", "value": "dry_run"}] if dry else []) + [
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
            ] if "cert_rule" in r else []) + ([
                # v1.27: a launched program: the file of the launch set it ran,
                # by its SHA-256 at startup
                {"name": "varek:exec.sha256", "value": str(r["exec_sha256"])},
            ] if r.get("action") == "process.exec" and isinstance(r.get("exec_sha256"), str) else []),
        }
        components.append(comp)

    # v1.31 (docs/security/v1.31-standards.md, section 6): each MCP server the
    # run launched (confined, by its `mcp server` line), with its file and
    # SHA-256, and each remote MCP endpoint reached, with the methods and
    # names its calls were allowed
    ruleset = {e.get("path"): e for e in rs.get("exec_ruleset", []) if isinstance(e, dict)} \
        if isinstance(rs.get("exec_ruleset"), list) else {}
    servers = {}
    for r in authorized:
        if r.get("action") == "process.exec" and r.get("mcp_server") is True and isinstance(r.get("subagent"), str):
            name = r["subagent"].split("#", 1)[0]
            path = r.get("resolved") or r.get("target") or ""
            sv = servers.setdefault(name, {"path": path, "launches": 0,
                                           "sha": r.get("exec_sha256") or (ruleset.get(path) or {}).get("sha256")})
            sv["launches"] += 1
    for name, sv in sorted(servers.items()):
        comp = {"type": "application", "bom-ref": bomref("mcp-server", name), "name": name,
                "description": "An MCP server the agent launched, run confined: decided by its own rules only.",
                "properties": ([{"name": "varek:mode", "value": "dry_run"}] if dry else []) + [
                    {"name": "varek:mcp.server", "value": "true"},
                    {"name": "varek:file", "value": str(sv["path"])},
                    {"name": "varek:launches", "value": str(sv["launches"])}]}
        if isinstance(sv["sha"], str) and re.fullmatch(r"[0-9a-f]{64}", sv["sha"]):
            comp["hashes"] = [{"alg": "SHA-256", "content": sv["sha"]}]
        components.append(comp)
    endpoints = {}
    for r in authorized:
        if r.get("action") == "net.mcp" and isinstance(r.get("mcp_url"), str):
            ep = endpoints.setdefault(r["mcp_url"], {"methods": set(), "names": set(), "calls": 0})
            ep["calls"] += 1
            if isinstance(r.get("mcp_method"), str):
                ep["methods"].add(r["mcp_method"])
            if isinstance(r.get("mcp_name"), str):
                ep["names"].add(r["mcp_name"])
    services = []
    for url, ep in sorted(endpoints.items()):
        services.append({"bom-ref": bomref("mcp-endpoint", url), "name": url, "endpoints": [url],
                         "description": "A remote MCP endpoint the agent's calls reached, each decided on its "
                                        "method and name.",
                         "properties": [{"name": "varek:mcp.calls_allowed", "value": str(ep["calls"])}] +
                                       [{"name": "varek:mcp.method", "value": m} for m in sorted(ep["methods"])] +
                                       [{"name": "varek:mcp.name", "value": n} for n in sorted(ep["names"])]})

    attest_text, facts = attestation(records, authorized, refused, dist, policy,
                                     run_start, run_end, warden_version, complete,
                                     log_info or {}, plan_gate, policy_check, proxy_meta)
    if views:
        attest_text += (f" {len(views)} open(s) of the resolver files (and, in inspecting mode, the "
                        f"trust files) were answered with the Warden's views ({', '.join(sorted({r['rule'] for r in views}))}); no "
                        f"file was opened, and they are not counted as decisions.")
    # v1.26.1 (step 7): the egress proxy, and in inspecting mode its requests
    pt, pfacts = _proxy_text(records, proxy_meta or {})
    attest_text += pt
    facts += pfacts
    lt, lfacts = _launch_text(records, proxy_meta or {})       # v1.27
    attest_text += lt
    facts += lfacts
    ct, cfacts = _cred_text(records, proxy_meta or {})         # v1.28
    attest_text += ct
    facts += cfacts
    ot, ofacts = _obo_text(records, proxy_meta or {})          # v1.28.1
    attest_text += ot
    facts += ofacts
    agent_component["properties"] += [{"name": k, "value": v} for k, v in facts]
    if dry:                                                       # v1.29
        attest_text = (f"DRY RUN, NOT ENFORCING: every call was decided and recorded, and the "
                       f"{len(not_enforced)} call(s) the policy refused were let through (\"enforced\":false); "
                       f"this run is evidence of what the policy would decide, not of enforcement. ") + attest_text

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
            "properties": [{"name": "varek:mode", "value": "dry_run" if dry else "enforcing"}] + [
                {"name": f"varek:verdict.{k.lower()}", "value": str(v)}
                for k, v in sorted(dist.items())
            ],
        },
        "components": components,
        "annotations": [annotation],
    }
    if services:                                                  # v1.31: remote MCP endpoints
        bom["services"] = services
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
                    warden_version, recorded_sha, log_info, meta.get("plan_gate"), policy_check,
                    meta)
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
