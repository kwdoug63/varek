#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
varek_audit.py — re-check a saved Warden verdict stream against its policy
(v1.15), and verify that the stream is the one the Warden wrote (v1.16).

Every file open the Warden authorized carries a certificate (the deciding rule
and a witness), which the Warden's in-line checker accepted before the open
took effect. This tool repeats that check later, from the saved stream and the
policy file alone:

  1. The stream is authenticated as varek_cyclonedx.py does (run id, gap-free
     seq, run_end count, and from v1.16 the hash chain), so the supervised
     AGENT cannot have added, dropped or forged a record.
  1a. v1.16, against whoever HOLDS the log: with --pubkey (the Warden's
     --sign-key public half, from tools/varek_keygen), every signature in the
     stream must verify under that key, and a complete stream must end in a
     signed run_end. Nobody without the private key can then alter, add,
     remove or reorder a record before the last signature, or cut the stream
     short. With --anchor (the Warden's --anchor file, kept where the log's
     holder cannot rewrite it), every signed record in the stream must appear
     in the anchor and every anchored record of this run must appear in the
     stream: history that reached the anchor cannot be rewritten even by the
     key holder. Signatures are verified by tools/varek_ed25519.py (RFC 8032,
     pure Python), not by the library that made them.
  2. The policy file given here must hash to the policy_sha256 in run_start:
     the certificates are checked against exactly the text the Warden used.
  3. The only authorizations are certified file opens and the agent's one
     launch exec: any other record that reads ALLOW fails the audit.
  4. Every authorized file open must carry a certificate the checker accepted
     in-line ("check":"ok"), and every such certificate is re-checked now by
     the certificate checker (tools/vdp_cert_check, the same small program the
     Warden runs; it shares no code with the decision procedure).
  5. A stream from the test-only fault-injected Warden is refused.
  6. v1.24, host names: a view the Warden served for /etc/hosts,
     /etc/resolv.conf, /etc/nsswitch.conf or /etc/host.conf (no file opened, so no
     certificate) is accepted only for that path, a read-only open, in a run
     whose policy has host name rules. A connect decided with the resolution
     table must name every candidate it was decided over: each name bound to
     the address dialed by the latest resolution record before it (current, or
     in grace), every name such a record binds to that address present, and no
     host rule before the deciding one holding on any other candidate (the
     checker's own matchers).
  7. v1.25: a connect or send with rule dns_stub (to the Warden's own stub
     resolver, in the agent's network namespace) is accepted only to the stub
     address run_start names.

Exit 0 only if all of these hold. The verdict stream is the Warden's stderr
(`warden policy -- agent 2> verdicts.log`). The report's "integrity" line says
how far the stream is protected against its holder: "none" (pre-1.16),
"chain" (edits caught only if the editor did not recompute the chain),
"signed, key not pinned" (pass --pubkey to rely on it), "signed" and
"signed, anchored".

Usage:
  varek_audit.py --policy POLICY --checker tools/vdp_cert_check
                 [--pubkey KEY.pub|HEX] [--anchor ANCHOR] VERDICTS.LOG
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from varek_cyclonedx import StreamError, _parse_log, LOG_SIG_DOMAIN  # noqa: E402
import varek_ed25519  # noqa: E402

# Record rules for an authorized file open (the policy decided ALLOW).
AUTHORIZED_OPEN_RULES = ("resolved_fd_injection", "allowed_open_failed", "injection_failed")
# v1.17.0: metadata and link lookups (stat, access, readlink) are decided like a
# read-only open and certified the same way.
META_ACTIONS = ("file.stat", "file.access", "file.readlink")
META_RULES = ("metadata_answered", "metadata_not_found", "metadata_failed")
# v1.21: decided connections. Every net.connect the policy allowed carries a
# certificate for the destination the Warden dialed ("resolved": a.b.c.d:port,
# [IPv6]:port or unix:<path>), whatever became of the dial.
CONNECT_RULES = ("dialed_fd_injection", "dialed_in_progress", "dial_failed",
                 "injection_failed", "requester_gone", "already_connected",
                 "socket_option_failed", "too_many_pending", "dialed_descriptor_replaced")
# v1.24: while a policy has host name rules, a read-only open of these paths is
# answered with a view the Warden wrote (no file is opened, so there is no
# certificate): rule -> the path it answers.
VIEW_RULES = {"hosts_view": "/etc/hosts", "resolv_view": "/etc/resolv.conf",
              "nsswitch_view": "/etc/nsswitch.conf", "hostconf_view": "/etc/host.conf",
              "netsvc_view": "/etc/netsvc.conf", "svc_view": "/etc/svc.conf"}
O_CREAT, O_TRUNC = 0o100, 0o1000


def _addr_of(dest):
    """The address part of a numeric destination: a.b.c.d:port -> a.b.c.d,
    [IPv6]:port -> IPv6."""
    host = dest.rsplit(":", 1)[0]
    return host[1:-1] if host.startswith("[") else host


def check_names(rec, pos, resolutions, problems):
    """v1.24: a connect decided with the resolution table. Its candidates are
    the address dialed and name:port for each name that address belonged to;
    each name must be bound to the address by the latest resolution record
    before this record (current, or within its grace), and every name whose
    latest record lists the address must be a candidate. Returns the
    candidates other than the one decided on (for the earlier-rule check)."""
    seq = rec.get("seq")
    cands, dialed, res = rec.get("candidates"), rec.get("dialed"), rec.get("resolved")
    if not (isinstance(cands, list) and cands and all(isinstance(c, str) for c in cands)
            and isinstance(dialed, str) and cands[0] == dialed and res in cands):
        problems.append(f"seq {seq}: a connect's candidates, dialed address and decided "
                        f"destination do not agree")
        return []
    addr, port = _addr_of(dialed), dialed.rsplit(":", 1)[-1]
    ts = rec.get("timestamp_ns")
    latest = {}
    for p, r in resolutions:
        if p > pos:
            break
        if isinstance(r.get("name"), str):
            latest[r["name"]] = r
    named = set()
    for c in cands[1:]:
        name, _, cport = c.rpartition(":")
        named.add(name)
        if cport != port:
            problems.append(f"seq {seq}: candidate {c!r} has another port than {dialed!r}")
            continue
        r = latest.get(name)
        if r is None:
            problems.append(f"seq {seq}: candidate {c!r}: no resolution of {name} before it")
            continue
        ok = addr in (r.get("addresses") or [])
        for g in r.get("grace") or []:
            if isinstance(g, dict) and g.get("address") == addr and isinstance(g.get("until_s"), int) \
                    and isinstance(ts, int) and isinstance(r.get("timestamp_ns"), int) \
                    and ts <= r["timestamp_ns"] + g["until_s"] * 10**9:
                ok = True
        if not ok:
            problems.append(f"seq {seq}: candidate {c!r}: {name} did not resolve to {addr} "
                            f"(by its resolution records)")
    for name, r in latest.items():
        if addr in (r.get("addresses") or []) and name not in named:
            problems.append(f"seq {seq}: {name} resolved to {addr} but is not a candidate: the "
                            f"connect was not decided on every name of its address")
    return [c for c in cands if c != res]


def policy_ancestors(path):
    """The directories an allow rule's literal start leads to (warden.c:
    load_ancestors): lookups on these may be answered without a decision. The
    Warden answers a subset (it also skips any a deny rule covers); a record
    outside this set is a problem. Lines and tokens are split exactly as the
    policy parser does (smt_decide.c): lines on '\\n' only, tokens on ASCII
    whitespace, a token starting with '#' ends the line."""
    import re
    flag = lambda t: t == b"readonly" or t.startswith(b"access=") or t[:3] in (b"+O_", b"-O_")
    out = {"/"}
    with open(path, "rb") as fh:
        data = fh.read()
    for line in data.split(b"\n"):
        toks = []
        for t in re.split(rb"[ \t\r\v\f]+", line):
            if not t:
                continue
            if t.startswith(b"#"):
                break
            toks.append(t)
        if len(toks) < 3 or toks[0] != b"allow" or toks[1] != b"path":
            continue
        m, c = b"prefix", toks[2]
        if toks[2] in (b"exact", b"prefix", b"suffix", b"contains", b"glob") and \
                len(toks) > 3 and not flag(toks[3]):
            m, c = toks[2], toks[3]
        if m in (b"prefix", b"exact"):
            lit = c
        elif m == b"glob":
            k = 0
            while k < len(c) and c[k:k + 1] not in (b"*", b"?", b"[", b"\\"):
                k += 1
            lit = c[:k]
        else:
            continue
        if not lit.startswith(b"/"):
            continue
        for i in range(1, len(lit) + 1):
            if i == len(lit):
                if lit[i - 1:i] == b"/":
                    out.add((lit[:i - 1] or b"/").decode("utf-8", "surrogateescape"))
            elif lit[i:i + 1] == b"/":
                out.add(lit[:i].decode("utf-8", "surrogateescape"))
    return out


def _hex_key(txt):
    """Exactly 64 lowercase hex characters, or None."""
    if not isinstance(txt, str) or len(txt) != 64 or any(c not in "0123456789abcdef" for c in txt):
        return None
    return bytes.fromhex(txt)


def _cli_pubkey(arg):
    """--pubkey: 64 hex characters, or a file holding them (tools/varek_keygen's .pub)."""
    if os.path.isfile(arg):
        with open(arg) as fh:
            arg = fh.read()
    return _hex_key(arg.strip().lower())


def log_integrity(a, meta, run, complete, problems):
    """v1.16: signatures and anchor. Appends to problems; returns the
    integrity level for the report."""
    log = meta.get("log")
    rs = meta.get("run_start", {})
    if log is None:
        if a.pubkey or a.anchor:
            problems.append("the stream is not hash-chained (a pre-1.16 Warden): "
                            "--pubkey / --anchor cannot be checked")
        return "none (pre-1.16 stream: no hash chain)"
    level = "chain"
    signed = log["signed"]
    stream_key = rs.get("log_pubkey")
    if stream_key is not None:
        pk = _hex_key(stream_key)
        if pk is None:
            problems.append("run_start carries a malformed log_pubkey")
            return level
        pinned = None
        if a.pubkey:
            pinned = _cli_pubkey(a.pubkey)
            if pinned is None:
                problems.append("--pubkey is not 64 hex characters (or a file holding them)")
            elif pinned != pk:
                problems.append(f"the stream is signed by {pk.hex()}, not by the pinned key "
                                f"{pinned.hex()}")
        bad = 0
        for c in signed:
            if c["sig"] is None:
                problems.append(f"line {c['line']}: {c['event']} record is not signed")
                continue
            if not varek_ed25519.verify(pk, LOG_SIG_DOMAIN + c["chain"], bytes.fromhex(c["sig"])):
                bad += 1
                problems.append(f"line {c['line']}: {c['event']} signature does not verify")
        if complete and (not signed or signed[-1]["event"] != "run_end"):
            problems.append("the stream does not end in a signed run_end")
        # The Warden signs at least every checkpoint_every decision records. A
        # longer stretch without a signature means checkpoints were removed
        # (possible only at the unsigned end of an incomplete stream).
        every = rs.get("checkpoint_every")
        if not isinstance(every, int) or every < 1:
            problems.append("run_start of a signed stream has no valid checkpoint_every")
            every = None
        prev = 0
        sigs = [c for c in signed if c["sig"]]
        for c in sigs:
            if every is not None and c["ndec"] - prev > every:
                problems.append(f"line {c['line']}: {c['ndec'] - prev} decision records since the "
                                f"previous signature, more than checkpoint_every ({every}): "
                                f"checkpoints were removed")
            prev = c["ndec"]
        tail = meta["ndecisions"] - prev
        if every is not None and tail > every:
            problems.append(f"{tail} decision records after the last signature, more than "
                            f"checkpoint_every ({every}): checkpoints were removed")
        meta["signed_through"] = prev
        level = "signed" if (pinned is not None and pinned == pk and not bad) \
            else "signed, key not pinned (pass --pubkey to rely on the signatures)"
        if not complete:
            level += f"; covers the first {prev} decision records only"
    elif a.pubkey:
        problems.append("--pubkey given, but the stream is not signed (the Warden ran "
                        "without --sign-key)")
    if a.anchor:
        before = len(problems)
        skey = pk if stream_key is not None and _hex_key(stream_key) else None
        CLOCK_SLACK = a.clock_slack
        lines, other_runs, unparsed = read_anchor(a.anchor, problems)
        mine = [e for e in lines if e.get("run") == run]
        other_runs.discard(run)
        in_log = {c["chain"].hex(): c for c in signed}
        # Which anchor lines count. In a signed stream, only lines whose
        # signature verifies (a line appended by someone without the key is
        # ignored). A record of the stream is anchored if ANY counting line
        # carries its chain value with the same event, count and signature;
        # other lines for that chain change nothing (the chain value already
        # fixes the record) and are noted.
        valid, ignored = [], 0
        for e in mine:
            ch = str(e.get("chain"))
            if skey is not None:
                sig = e.get("sig")
                try:
                    good = isinstance(sig, str) and len(ch) == 64 and \
                        varek_ed25519.verify(skey, LOG_SIG_DOMAIN + bytes.fromhex(ch), bytes.fromhex(sig))
                except ValueError:
                    good = False
                if not good:
                    ignored += 1
                    continue
            valid.append(e)
        matched, conflicts, foreign_chain = {}, 0, []
        for e in valid:
            ch = str(e.get("chain"))
            c = in_log.get(ch)
            if c is None:
                foreign_chain.append(e)
            elif (e.get("event"), e.get("sig"), e.get("records")) == (c["event"], c["sig"], c["records"]):
                matched.setdefault(ch, e)
            else:
                conflicts += 1
        for ch, c in in_log.items():
            if ch not in matched:
                problems.append(f"line {c['line']}: {c['event']} was never anchored")
        # A validly signed anchored record the stream does not hold is evidence
        # the stream was rewritten, unless the anchor host received it after
        # this run's run_end had been anchored (then it was appended later, by
        # someone holding the key, and changes nothing that was anchored).
        end_rx = None
        for ch, e in matched.items():
            if e.get("event") == "run_end" and isinstance(e.get("received_ns"), int):
                end_rx = e["received_ns"]
        late_foreign = 0
        for e in foreign_chain:
            rx = e.get("received_ns")
            if end_rx is not None and isinstance(rx, int) and rx > end_rx:
                late_foreign += 1
                continue
            problems.append(f"anchored {e.get('event')} (records {e.get('records')}) is not in "
                            f"the stream: the stream was rewritten after it was anchored")
        for ae in log["anchor_errors"]:
            problems.append(f"line {ae['line']}: the Warden could not anchor a {ae['anchoring']} "
                            f"record (errno {ae['errno']})")
        if not valid:
            problems.append("the anchor holds nothing for this run")
        if ignored:
            print(f"varek_audit: note: {ignored} anchor line(s) for this run carry no valid signature "
                  f"and were ignored")
        if conflicts:
            print(f"varek_audit: note: {conflicts} anchor line(s) repeat a record's chain value with "
                  f"a different event or count; ignored (the chain value fixes the record)")
        if late_foreign:
            print(f"varek_audit: note: {late_foreign} signed anchor line(s) for records the stream "
                  f"does not hold arrived after its run_end was anchored; ignored")
        if unparsed:
            print(f"varek_audit: note: {unparsed} anchor line(s) are not JSON and were ignored")
        if other_runs:
            print(f"varek_audit: note: the anchor also holds {len(other_runs)} other run(s); "
                  f"list them with --list-runs")
        # How late each record reached the anchor host: its receive time (set
        # by the anchor host) against the time in the STREAM's signed record
        # (an anchor line's own timestamp is not trusted). A record received
        # well before it was written means the clocks disagree or the times
        # were changed.
        delays = []
        for ch, e in matched.items():
            c = in_log[ch]
            if isinstance(e.get("received_ns"), int) and isinstance(c.get("ts"), int):
                delays.append((e["received_ns"] - c["ts"]) / 1e9)
        if delays:
            print(f"varek_audit: anchoring delay: at most {max(delays):.1f} s, at least "
                  f"{min(delays):.1f} s ({len(delays)} record(s) with a receive time)")
            if min(delays) < -CLOCK_SLACK:
                problems.append(f"a record was received {-min(delays):.1f} s before the stream says it was "
                                f"written: the hosts' clocks disagree, or the times were changed")
            if a.max_anchor_delay is not None:
                late = [d for d in delays if d > a.max_anchor_delay]
                if late:
                    problems.append(f"{len(late)} record(s) reached the anchor more than "
                                    f"{a.max_anchor_delay:g} s after they were written (at most "
                                    f"{max(late):.1f} s): they could have been changed before anchoring")
        elif a.max_anchor_delay is not None:
            problems.append("--max-anchor-delay given, but the anchor has no receive times "
                            "(a v1.16.2 receiver adds them)")
        if len(problems) == before:
            level += ", anchored"
            if stream_key is None and not complete:
                # Anchor only: what reached the anchor is sealed, nothing after it.
                sealed = [c["ndec"] for c in signed if c["chain"].hex() in matched]
                meta["signed_through"] = max(sealed) if sealed else 0
                level += f"; covers the first {meta['signed_through']} decision records only"
    return level


def read_anchor(path, problems):
    """The anchor's lines as JSON objects, in file (arrival) order; the set of
    run ids seen; the number of lines that are not JSON objects (ignored:
    anyone who can append could add them)."""
    lines, runs, unparsed = [], set(), 0
    try:
        with open(path, encoding="utf-8", errors="surrogateescape") as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                except ValueError:           # JSONDecodeError, or a huge number
                    unparsed += 1
                    continue
                if not isinstance(e, dict):
                    unparsed += 1
                    continue
                lines.append(e)
                if isinstance(e.get("run"), str):
                    runs.add(e["run"])
    except OSError as e:
        problems.append(f"anchor {path}: {e}")
    return lines, runs, unparsed


def list_runs(path):
    """--list-runs: every run the anchor holds, with its first and last
    records and, from v1.16.2 receivers, when they arrived."""
    import datetime
    problems = []
    lines, _, unparsed = read_anchor(path, problems)
    if problems:
        print(f"varek_audit: {problems[0]}")
        return 1
    runs = {}
    for e in lines:
        r = e.get("run")
        if isinstance(r, str):
            runs.setdefault(r, []).append(e)
    fmt = lambda ns: (datetime.datetime.fromtimestamp(ns / 1e9, datetime.timezone.utc)
                      .isoformat(timespec="seconds") if isinstance(ns, int) else "?")
    print(f"varek_audit: {len(runs)} run(s) in {path}" + (f" ({unparsed} unparsed line(s))" if unparsed else ""))
    for r, es in runs.items():
        evs = [e.get("event") for e in es]
        start = next((e for e in es if e.get("event") == "run_start"), es[0])
        end = next((e for e in reversed(es) if e.get("event") == "run_end"), None)
        print(f"  {r}  started {fmt(start.get('timestamp_ns'))}  "
              f"{'ended ' + fmt(end.get('timestamp_ns')) if end else 'NO run_end'}  "
              f"{evs.count('checkpoint')} checkpoint(s)  "
              f"received {fmt(es[0].get('received_ns'))} .. {fmt(es[-1].get('received_ns'))}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Re-check a VAREK verdict stream's certificates.")
    ap.add_argument("--policy", help="the policy file the Warden ran with (required to audit)")
    ap.add_argument("--checker", help="tools/vdp_cert_check (required to audit)")
    ap.add_argument("--allow-incomplete", action="store_true",
                    help="audit a stream with no run_end record")
    ap.add_argument("--allow-test-build", action="store_true",
                    help="audit a stream from the test-only fault-injected Warden (testing)")
    ap.add_argument("--pubkey", help="the Warden's signing public key (64 hex characters, "
                    "or a .pub file from tools/varek_keygen): signatures must verify under it")
    ap.add_argument("--anchor", help="the Warden's --anchor file: the stream's signed records "
                    "must match it")
    ap.add_argument("--run", help="the run id the stream must carry (run_start's \"run\")")
    def seconds(v):
        try:
            x = float(v)
        except ValueError:
            x = float("nan")
        if not (x >= 0 and x != float("inf")):
            raise argparse.ArgumentTypeError(f"{v!r}: expected a finite number of seconds >= 0")
        return x
    ap.add_argument("--max-anchor-delay", type=seconds, metavar="SECONDS",
                    help="fail if any record reached the anchor later than this after it was "
                         "written (needs a v1.16.2 receiver's receive times)")
    ap.add_argument("--clock-slack", type=seconds, default=5.0, metavar="SECONDS",
                    help="how far the anchor host's clock may run behind the Warden host's "
                         "(default 5): a record received earlier than that before it was written fails")
    ap.add_argument("--list-runs", action="store_true",
                    help="with --anchor: list every run the anchor holds, then exit")
    ap.add_argument("log", nargs="?")
    a = ap.parse_args(argv)
    if a.list_runs:
        if not a.anchor:
            ap.error("--list-runs needs --anchor")
        return list_runs(a.anchor)
    if not (a.policy and a.checker and a.log):
        ap.error("--policy, --checker and the verdict stream are required")

    with open(a.log, encoding="utf-8", errors="surrogateescape", newline="\n") as fh:
        meta = {}
        try:
            run, records, complete, warden = _parse_log(fh, a.allow_incomplete, meta)
        except StreamError as e:
            print(f"varek_audit: FAIL: {e}")
            return 1
    problems = []
    meta["ndecisions"] = len(records)
    integrity = log_integrity(a, meta, run, complete, problems)
    if a.run and a.run != run:
        problems.append(f"the stream is run {run}, not the run asked for ({a.run})")
    # An incomplete signed stream is audited only as far as its last signature:
    # the records after it could have been written by anyone.
    if not complete and "signed_through" in meta and meta["signed_through"] < len(records):
        dropped = len(records) - meta["signed_through"]
        print(f"varek_audit: note: the last {dropped} decision record(s) follow the last "
              f"signature (the stream is incomplete); they are not audited")
        records = records[:meta["signed_through"]]
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
    authorized = refused = lookups = connects = views = stubs = 0
    resolutions = meta.get("resolutions", [])
    names_policy = meta.get("run_start", {}).get("host_name_rules") is True
    others = []                          # (rec, decided rule, other candidates)
    ancestors = None
    launches = 0
    for pos, rec in enumerate(records):
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
        if rec.get("action") in META_ACTIONS and rec.get("rule") == "metadata_ancestor":
            if ancestors is None:
                ancestors = policy_ancestors(a.policy)
            if rec.get("resolved") not in ancestors:
                problems.append(f"seq {rec.get('seq')}: a lookup answered as a directory the "
                                f"policy leads to, but {rec.get('resolved')!r} is not one")
            elif rec.get("open_flags") != "0x0" or \
                    (rec.get("action") == "file.access" and
                     int(rec.get("access_mode", "7")) & 3):
                problems.append(f"seq {rec.get('seq')}: a lookup answered as a directory the "
                                f"policy leads to, but it asked for more than a read")
            lookups += 1
            continue
        if rec.get("rule") == "dns_stub" and rec.get("action") in ("net.connect", "net.send"):
            # v1.25: a connect or send to the Warden's own stub resolver (no
            # certificate: it reaches nothing outside the agent's namespace)
            stub = meta.get("run_start", {}).get("dns_stub")
            if not stub:
                problems.append(f"seq {rec.get('seq')}: a stub connect, but run_start names no "
                                f"stub resolver")
            elif rec.get("resolved") != stub:
                problems.append(f"seq {rec.get('seq')}: a dns_stub record to {rec.get('resolved')!r}, "
                                f"not the stub at {stub}")
            stubs += 1
            continue
        if rec.get("action") == "file.open" and rec.get("rule") in VIEW_RULES:
            fl = rec.get("open_flags")
            try:
                flv = int(fl, 16)
            except (TypeError, ValueError):
                flv = -1
            if not names_policy:
                problems.append(f"seq {rec.get('seq')}: a view answered, but run_start says the "
                                f"policy has no host name rules")
            elif rec.get("resolved") != VIEW_RULES[rec["rule"]]:
                problems.append(f"seq {rec.get('seq')}: a {rec['rule']} answered an open of "
                                f"{rec.get('resolved')!r}")
            elif flv < 0 or flv & 3 or flv & (O_CREAT | O_TRUNC):
                problems.append(f"seq {rec.get('seq')}: a view answered an open that does not "
                                f"only read ({fl})")
            elif not isinstance(rec.get("view_generation"), int):
                problems.append(f"seq {rec.get('seq')}: a view without its generation")
            views += 1
            continue
        is_open = rec.get("action") == "file.open" and rec.get("rule") in AUTHORIZED_OPEN_RULES
        is_meta = rec.get("action") in META_ACTIONS and rec.get("rule") in META_RULES
        is_conn = rec.get("action") == "net.connect" and rec.get("rule") in CONNECT_RULES
        if not (is_open or is_meta or is_conn):
            problems.append(f"seq {rec.get('seq')}: an authorization that is not a certified "
                            f"file open, lookup or connect ({rec.get('action')}, rule {rec.get('rule')})")
            continue
        if is_meta:
            lookups += 1
        elif is_conn:
            connects += 1
        else:
            authorized += 1
        cr, cw = rec.get("cert_rule"), rec.get("cert_witness")
        if not isinstance(cr, int) or not isinstance(cw, str) or rec.get("check") != "ok":
            problems.append(f"seq {rec.get('seq')}: authorized open of {rec.get('resolved')!r} "
                            f"without an accepted certificate")
            continue
        s = rec.get("resolved", "")
        fl = rec.get("open_flags")
        if is_conn:
            fl = "0x0"                   # host rules carry no flag clause
            if not s:
                problems.append(f"seq {rec.get('seq')}: authorized connect without the "
                                f"destination it was decided on")
                continue
        elif not isinstance(fl, str) or not fl.startswith("0x"):
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
        lines.append(f"{'host' if is_conn else 'path'} {fl} {hx} {cr} {cw}")
        which.append(rec)
        if is_conn and "candidates" in rec:
            others.append((rec, cr, check_names(rec, pos, resolutions, problems)))

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

    # v1.24: no earlier host rule holds on any other candidate of a connect
    # decided with names (the checker's own parse and matchers).
    if others and not problems:
        k = subprocess.run([a.checker, a.policy, "kinds"], capture_output=True, text=True)
        kinds = k.stdout.strip() if k.returncode == 0 else ""
        strs = [c for _, _, oc in others for c in oc]
        if not kinds:
            problems.append(f"checker failed: {k.stderr.strip()}")
        elif strs:
            h = subprocess.run([a.checker, a.policy, "holds"],
                               input="\n".join(c.encode().hex() or "=" for c in strs) + "\n",
                               capture_output=True, text=True)
            rows = h.stdout.split()
            if h.returncode != 0 or len(rows) != len(strs):
                problems.append(f"checker failed: {h.stderr.strip()}")
            else:
                it = iter(rows)
                for rec, cr, oc in others:
                    for c in oc:
                        row = next(it)
                        early = [i for i in range(min(cr, len(row))) if kinds[i] == "h" and row[i] == "1"]
                        if early:
                            problems.append(f"seq {rec.get('seq')}: rule {early[0]} holds on candidate "
                                            f"{c!r}, before the rule that decided the connect")
    print(f"varek_audit: run {run} (Warden {warden}, {'complete' if complete else 'INCOMPLETE'}), "
          f"{len(records)} records, {authorized} authorized file opens, {lookups} lookups, "
          f"{connects} authorized connects, "
          f"{views} host-name views, {stubs} stub resolver connects, "
          f"{checked} certificates "
          f"re-checked, {refused} refused in-line")
    print(f"varek_audit: integrity: {integrity}")
    t0 = meta.get("run_start", {}).get("timestamp_ns")
    if isinstance(t0, int):
        import datetime
        when = datetime.datetime.fromtimestamp(t0 / 1e9, datetime.timezone.utc)
        print(f"varek_audit: run started {when.isoformat(timespec='seconds')} "
              f"(policy {meta['run_start'].get('policy_path')!r})")
    for pr in problems[:50]:
        print(f"  PROBLEM {pr}")
    print(f"varek_audit: {'PASS' if not problems else 'FAIL'}")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
