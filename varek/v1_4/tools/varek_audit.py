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
     address run_start names. The stub's dns_question records: run_start's
     wildcard budgets are the policy file's; each name charged to a wildcard
     rule is charged once and within its rule's names, rate (60 s) and label
     budgets; budget refusals and questions no rule allows are NXDOMAIN and
     charge nothing; every name looked up on demand was asked for first; a
     NOERROR answer carries only addresses the name's latest resolution lists.
  8. v1.26, the egress proxy: with `proxy on`, a name host rules allow only
     on proxied ports is answered with its synthetic address (A) or no data,
     never looked up or charged; every synthetic_address record gives such a
     name the next address of 198.18.0.0/15, each name and address once; and
     no connect to a synthetic address is dialed. A connect on a proxied
     port is handed to the proxy only as the policy allows; every name:port
     the proxy read is decided once, for a hand-off, and certified when
     allowed, dialing only an address of the name; every connection passed
     to the proxy has one proxy_close after it.

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
import collections
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from varek_cyclonedx import StreamError, _parse_log, _version_at_least, LOG_SIG_DOMAIN  # noqa: E402
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


DEFAULT_NAMES, DEFAULT_RATE, DEFAULT_LABEL = 256, 30, 63    # the Warden's, v1.25


STUB = "127.53.53.53:53"          # the Warden's stub resolver (warden_stub.inc.c)


def policy_rules(checker, policy):
    """The policy's rules as the certificate checker parses the file (its
    "rules" mode), one dict each: kind (p|h|e, r: a v1.26.1 request rule),
    allow, name (a host name rule), wild, line, names, rate (0: the
    default), max_body (0: none) and c (the constant).
    v1.25 review: read from the checker, not from this tool's own reading of
    the file, so a policy is read here exactly as the Warden reads it."""
    rq = subprocess.run([checker, policy, "rules"], capture_output=True)
    if rq.returncode != 0:
        raise ValueError(rq.stderr.decode(errors="replace").strip() or "the checker failed")
    out = []
    for ln in rq.stdout.decode().splitlines():
        f = ln.split()
        if len(f) != 11:
            raise ValueError(f"unexpected checker output {ln!r}")
        out.append({"kind": f[0], "allow": f[1] == "a", "name": f[2] == "n", "mask": f[3],
                     "value": f[4], "wild": f[5] == "w", "line": int(f[6]), "names": int(f[7]),
                     "rate": int(f[8]), "max_body": int(f[9]),
                     "c": "" if f[10] == "=" else bytes.fromhex(f[10]).decode("latin-1")})
    return out


def check_shared_lists(meta, a, problems):
    """v1.25 review: the shared-domain lists. A wildcard allow rule over a
    shared domain must have been refused, whatever lists the Warden was given:
    each is checked again here against the lists this release ships (lint),
    and the lists run_start names must be these unless it says they were not
    (shared_lists_pinned false, an operator's own lists, reported)."""
    rs = meta.get("run_start", {})
    here = os.path.dirname(os.path.abspath(__file__))
    data = os.path.join(here, "..", "data")
    want = {}
    for key, fn in (("psl_sha256", "public_suffix_list.dat"),
                    ("shared_domains_sha256", "varek_shared_domains.txt")):
        try:
            with open(os.path.join(data, fn), "rb") as fh:
                want[key] = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            problems.append(f"cannot read this release's {fn} to check the stream's lists")
            return
    differ = [k for k in want if rs.get(k) != want[k]]
    if differ and rs.get("shared_lists_pinned") is False:
        print(f"varek_audit: note: the Warden checked wildcards against shared-domain lists named "
              f"on its command line, not this release's ({', '.join(differ)})")
    elif differ or rs.get("shared_lists_pinned") is not True:
        problems.append(f"run_start's shared-domain lists ({', '.join(differ) or 'shared_lists_pinned'}) "
                        f"are not this release's, and it does not say so")
    lint = os.path.join(os.path.dirname(os.path.abspath(a.checker)), "vdp_check")
    r = subprocess.run([lint, a.policy, "lint"], capture_output=True, text=True)
    for ln in (r.stdout + r.stderr).splitlines():
        if " is refused: " in ln:
            problems.append(f"the policy has a wildcard the Warden must refuse: {ln.split(': ', 1)[-1]}")


def policy_wildcards(rules):
    """v1.25: each wildcard allow rule: line -> (suffix, names, rate), the
    budgets as written or the defaults. The constant is the glob the parsers
    hold, ?*.<suffix>:<port|*>."""
    out = {}
    for r in rules:
        if r["kind"] == "h" and r["allow"] and r["wild"] and r["c"].startswith("?*."):
            out[r["line"]] = (r["c"][3:].rsplit(":", 1)[0], r["names"] or DEFAULT_NAMES,
                              r["rate"] or DEFAULT_RATE)
    return out


def _host_port(c):
    """The port a host rule's constant names, or None (portless, or a glob)."""
    head, sep, port = c.rpartition(":")
    if not sep or not port.isdigit() or int(port) > 65535 or (head.startswith("[") and not head.endswith("]")):
        return None
    return int(port)


def stub_rules(checker, policy, rules, names):
    """For each name, the rule the stub answers it by, as warden_stub.inc.c's
    stub_name_rule decides: name:port for every port a host rule names and
    for one no rule names, decided by the first host rule that holds; an
    exact rule that allows any of them first, else the first wildcard rule
    that allows any. name -> rule index, or None. Asked of the checker."""
    hosts = [i for i, r in enumerate(rules) if r["kind"] == "h"]
    ports = []
    for i in hosts:
        p = _host_port(rules[i]["c"])
        if p is not None and p not in ports:
            ports.append(p)
        if len(ports) >= 63:
            break
    other = 1
    while other in ports and other < 65535:
        other += 1
    ports.append(other)
    names = sorted(names)
    strs = [f"{n}:{p}" for n in names for p in ports]
    if not strs:
        return {}
    h = subprocess.run([checker, policy, "holds"], capture_output=True, text=True,
                       input="\n".join(s.encode().hex() for s in strs) + "\n")
    rows = h.stdout.split()
    if h.returncode != 0 or len(rows) != len(strs):
        raise ValueError("the checker failed on the stub's names")
    out = {}
    for k, n in enumerate(names):
        best = None
        for j in range(len(ports)):
            row = rows[k * len(ports) + j]
            first = next((i for i in hosts if row[i] == "1"), None)
            if first is None or not rules[first]["allow"]:
                continue
            if not rules[first]["wild"]:
                best = first
                break
            if best is None or first < best:
                best = first
        out[n] = best
    return out


def policy_proxy(checker, policy):
    """v1.26: the proxied ports in force (80 and 443 when the policy names
    none), or None without `proxy on`. Asked of the checker."""
    rq = subprocess.run([checker, policy, "proxy"], capture_output=True, text=True)
    f = rq.stdout.split()
    if rq.returncode != 0 or not f or f[0] not in ("on", "off"):
        raise ValueError("the checker failed on the policy's proxy directives")
    if f[0] == "off":
        return None
    ports = f[1:f.index("upstream")] if "upstream" in f else f[1:]
    return [int(x) for x in ports]


def policy_upstream(checker, policy):
    """v1.26 section 5: the policy's `proxy upstream` as "host:port", or None."""
    rq = subprocess.run([checker, policy, "proxy"], capture_output=True, text=True)
    f = rq.stdout.split()
    return f[f.index("upstream") + 1] if rq.returncode == 0 and "upstream" in f[:-1] else None


SYN_NET = ipaddress.ip_network("198.18.0.0/15")   # the Warden's synthetic addresses (v1.26)
SYN_MAX = 131070
# v1.26 (step 4): the rules of a connect handed to the proxy
HANDOFF_RULES = ("proxy_handoff", "proxy_handoff_in_progress", "proxy_handoff_failed")
# a hand-off that ended otherwise (as a dialed connect can)
HANDOFF_OTHER_RULES = ("already_connected", "socket_option_failed", "too_many_pending", "requester_gone",
                       "injection_failed", "dialed_descriptor_replaced")
# v1.26 review: the rules of a proxied decision the Warden refused
PROXY_REFUSE_RULES = ("policy_match", "default_deny_unknown", "fragment_escape_flags",
                      "fragment_escape_length", "certificate_refused", "wildcard_budget",
                      "resolution_failed", "address_refused", "run_ended")
# v1.26 (step 6): the Warden's decision on what the proxy read, when it allowed
PROXY_ALLOW_RULES = ("proxy_dialed", "proxy_dial_failed")
PROXY_KINDS = ("tls", "http", "connect")
CLOSE_WHY = ("closed", "reset", "idle", "run_end", "unreported", "upstream_refused",
             "refused_request", "client_gone")       # v1.26 review: the last two


def check_proxy_start(meta, proxy_ports, problems, upstream=None):
    """v1.26 (step 8): with `proxy on` the Warden runs only with its proxy, so
    run_start names it: SNI mode, its listener on 127.0.0.1, an unprivileged
    user, and the policy's proxied ports; without `proxy on`, no proxy."""
    pr = meta.get("run_start", {}).get("proxy")
    if proxy_ports is None:
        if pr is not None:
            problems.append("run_start names a proxy, but the policy does not turn it on")
        return
    lst = pr.get("listen") if isinstance(pr, dict) else None
    if not isinstance(pr, dict) or pr.get("mode") != "sni" or not isinstance(lst, str) or \
            not lst.startswith("127.0.0.1:") or _host_port(lst) in (None, 0) or \
            type(pr.get("uid")) is not int or type(pr.get("gid")) is not int or \
            pr.get("uid") == 0 or pr.get("gid") == 0 or pr.get("ports") != proxy_ports or \
            pr.get("upstream") != upstream:
        problems.append(f"run_start's proxy {pr!r} is not the policy's (SNI mode, an unprivileged "
                        f"user, ports {proxy_ports})")


def check_handoff_rules(checker, policy, rules, handoffs, problems):
    """v1.26 (step 8): a connect was handed to the proxy only as the Warden
    decides: over its candidates (the address, then name:port for each name
    it belongs to), the first host rule (policy order) that holds on any of
    them must not be a deny, nor an allow that holds on the address itself (a
    numeric rule: that connect is dialed directly). A synthetic address is
    always handed over. Asked of the checker."""
    work = [(rec, cands) for rec, cands in handoffs if cands]
    strs = [c for _, cands in work for c in cands]
    if not strs:
        return
    h = subprocess.run([checker, policy, "holds"], capture_output=True, text=True,
                       input="\n".join(c.encode().hex() for c in strs) + "\n")
    rows = h.stdout.split()
    if h.returncode != 0 or len(rows) != len(strs):
        problems.append(f"checker failed on the hand-offs' candidates: {h.stderr.strip()}")
        return
    hosts = [i for i, r in enumerate(rules) if r["kind"] == "h"]
    it = iter(rows)
    for rec, cands in work:
        best = None                       # (rule index, candidate index)
        for ci, _ in enumerate(cands):
            row = next(it)
            first = next((i for i in hosts if row[i] == "1"), None)
            if first is not None and (best is None or first < best[0]):
                best = (first, ci)
        if best is None:
            continue
        r = rules[best[0]]
        if not r["allow"]:
            problems.append(f"seq {rec.get('seq')}: a connect policy line {r['line']} denies was handed "
                            f"to the proxy")
        elif best[1] == 0:
            problems.append(f"seq {rec.get('seq')}: a connect policy line {r['line']} allows by its "
                            f"address was handed to the proxy, not dialed")


def check_dialed_denies(checker, policy, rules, dialed, problems):
    """v1.26 review: the Warden dials no address a rule denies: for each
    address a proxied connection dialed (addr:port), the first host rule that
    holds on it must not be a deny. Asked of the checker."""
    if not dialed:
        return
    h = subprocess.run([checker, policy, "holds"], capture_output=True, text=True,
                       input="\n".join(d.encode().hex() for _, d in dialed) + "\n")
    rows = h.stdout.split()
    if h.returncode != 0 or len(rows) != len(dialed):
        problems.append(f"checker failed on the addresses dialed: {h.stderr.strip()}")
        return
    hosts = [i for i, r in enumerate(rules) if r["kind"] == "h"]
    for (rec, d), row in zip(dialed, rows):
        first = next((i for i in hosts if row[i] == "1"), None)
        if first is not None and not rules[first]["allow"]:
            problems.append(f"seq {rec.get('seq')}: a proxied connection dialed {d}, which policy line "
                            f"{rules[first]['line']} denies")


def check_closes(records, closes, complete, problems):
    """v1.26 (step 7): every proxy_close is of a connection the Warden passed
    to the proxy (proxy_dialed) before it, once; its byte counts and relay
    time (the proxy's report) are present and whole, or absent for
    "unreported"; and in a complete stream every connection passed on is
    closed. Returns the number of closes."""
    dialed, dialed_up = {}, {}           # proxy_conn -> its record's position; dialed to an upstream
    for pos, rec in enumerate(records):
        if rec.get("action") == "net.proxy" and rec.get("rule") == "proxy_dialed" \
                and rec.get("decision_final") == "ALLOW" and type(rec.get("proxy_conn")) is int:
            dialed.setdefault(rec["proxy_conn"], pos)
            dialed_up.setdefault(rec["proxy_conn"], "upstream" in rec)
    closed = set()
    for pos, e in closes:
        cid, why = e.get("proxy_conn"), e.get("why")
        if type(cid) is not int or cid not in dialed or dialed[cid] >= pos:
            problems.append(f"a proxy_close of connection {cid!r}, which was not passed to the proxy before it")
            continue
        if cid in closed:
            problems.append(f"connection {cid}: closed twice")
        closed.add(cid)
        counts = [e.get(k) for k in ("bytes_up", "bytes_down", "relay_ms")]
        if why not in CLOSE_WHY:
            problems.append(f"connection {cid}: a proxy_close for {why!r}")
        elif why == "unreported":
            if any(c is not None for c in counts):
                problems.append(f"connection {cid}: an unreported close with counts")
        elif not all(type(c) is int and c >= 0 for c in counts):
            problems.append(f"connection {cid}: a proxy_close without whole byte counts and relay time")
        elif (why == "upstream_refused") != ("upstream_status" in e) or \
                (why == "upstream_refused" and (type(e["upstream_status"]) is not int or
                                                not 0 <= e["upstream_status"] <= 599 or
                                                200 <= e["upstream_status"] <= 299)):
            problems.append(f"connection {cid}: an upstream refusal without the upstream's status, "
                            f"or a status without one")
        if why == "upstream_refused" and not dialed_up.get(cid):
            problems.append(f"connection {cid}: refused by an upstream, but not dialed to one")
    if complete:
        for cid in sorted(set(dialed) - closed):
            problems.append(f"connection {cid}: passed to the proxy but never closed (a proxy_close is missing)")
    return len(closes)


def check_proxied(records, resolutions, handoff_all, problems, upstream=None, dialed_out=None,
                  charged=None, exact=None, handoff_port=None):
    """v1.26 (step 6): every net.proxy record (a name:port the proxy read,
    decided by the Warden) is for a hand-off, once each, of a kind the proxy
    reads, decided on the name:port it records; one the Warden dialed names
    the address, which is neither special nor synthetic and is an address of
    the name by the latest resolution record before it (current or in
    grace). Returns their number."""
    seen, n = set(), 0
    for pos, rec in enumerate(records):
        if rec.get("action") != "net.proxy":
            continue
        n += 1
        seq, cid, tgt = rec.get("seq"), rec.get("proxy_conn"), rec.get("target")
        if type(cid) is not int or cid not in handoff_all or cid in seen:
            problems.append(f"seq {seq}: a proxied decision for connection {cid!r}, which is not "
                            f"a hand-off or was decided already")
            if type(cid) is not int:
                continue                  # v1.26 review: no crash on a malformed id
        seen.add(cid)
        if rec.get("proxy_kind") not in PROXY_KINDS or not isinstance(tgt, str) or \
                tgt != rec.get("resolved") or _host_port(tgt) in (None, 0) or ":" not in tgt or \
                tgt.startswith("["):
            problems.append(f"seq {seq}: a malformed proxied decision ({tgt!r})")
            continue
        # v1.26 review: the decision and its rule agree; a refusal dialed
        # nothing (one refused when the run ended may have been dialing)
        dfin, rule = rec.get("decision_final"), rec.get("rule")
        if not ((dfin == "ALLOW" and rule in PROXY_ALLOW_RULES) or
                (dfin == "DENY" and rule in PROXY_REFUSE_RULES and
                 ("dialed" not in rec or rule == "run_ended"))):
            problems.append(f"seq {seq}: a proxied decision {dfin!r} with rule {rule!r}, which the "
                            f"Warden does not write")
            continue
        # v1.26 review: decided on the port the agent connected to (a CONNECT
        # names its own)
        if rec.get("proxy_kind") != "connect" and handoff_port is not None and \
                handoff_port.get(cid) not in (None, _host_port(tgt)):
            problems.append(f"seq {seq}: a proxied decision on {tgt}, not on the port connection "
                            f"{cid} was handed over on ({handoff_port.get(cid)})")
            continue
        # section 5: an allowed decision went to the policy's upstream, if it
        # names one (a refusal never reaches it, and carries none)
        up = rec.get("upstream")
        if dfin != "ALLOW":
            if up is not None:
                problems.append(f"seq {seq}: a refused proxied decision that names an upstream")
            continue
        if up != upstream:
            problems.append(f"seq {seq}: a proxied connection via upstream {up!r}, not the policy's "
                            f"({upstream!r})")
            continue
        dl = rec.get("dialed")
        if rec.get("rule") == "proxy_dialed" and not isinstance(dl, str):
            problems.append(f"seq {seq}: a proxied connection passed on without the address dialed")
            continue
        if dl is None:
            continue
        cd = _canonical_dest(dl)
        if upstream is not None:
            # dialed to the upstream: its address (given, or by the latest
            # resolution of its name before this record) and its port; it is
            # the operator's, so loopback and private addresses are allowed
            uhost, uport = upstream.rsplit(":", 1)
            if cd is None or cd[1] != uport or cd[0] in SYN_NET:
                problems.append(f"seq {seq}: a proxied connection dialed {dl!r}, not the upstream {upstream}")
                continue
            # v1.26 review: a name only a wildcard allows reached the upstream
            # charged to that wildcard (a question recorded before it)
            name = tgt.rsplit(":", 1)[0]
            if charged is not None and exact is not None and name not in exact and \
                    not any(t <= rec.get("timestamp_ns", 0) for t in charged.get(name, [])):
                problems.append(f"seq {seq}: {name} reached the upstream, but was never charged to a "
                                f"wildcard's budget")
            if str(cd[0]) == uhost:
                continue
            if re.fullmatch(r"[0-9.]+", uhost):
                # v1.26 review: an upstream given as an address is dialed as it is
                problems.append(f"seq {seq}: a proxied connection dialed {cd[0]}, not the upstream's "
                                f"address {uhost}")
                continue
            last = None
            for p, r in resolutions:
                if p > pos:
                    break
                if r.get("name") == uhost:
                    last = r
            if last is None or str(cd[0]) not in set(_addrs(last, "addresses")) | set(_addrs(last, "grace")):
                problems.append(f"seq {seq}: a proxied connection dialed {cd[0]}, which the latest "
                                f"resolution of the upstream {uhost} before it does not list")
            continue
        if cd is None or int(cd[1]) != _host_port(tgt):
            problems.append(f"seq {seq}: a proxied connection dialed {dl!r}, not on {tgt}'s port")
            continue
        if _special(cd[0]) or cd[0] in SYN_NET:
            problems.append(f"seq {seq}: a proxied connection dialed {cd[0]}, a special or synthetic address")
            continue
        if dialed_out is not None:        # v1.26 review: asked of the policy below (no deny on it)
            dialed_out.append((rec, dl))
        name = tgt.rsplit(":", 1)[0]
        last = None
        for p, r in resolutions:
            if p > pos:
                break
            if r.get("name") == name:
                last = r
        if last is None or str(cd[0]) not in set(_addrs(last, "addresses")) | set(_addrs(last, "grace")):
            problems.append(f"seq {seq}: a proxied connection dialed {cd[0]}, which the latest "
                            f"resolution of {name} before it does not list")
    return n


def proxied_only(checker, policy, rules, names, pports):
    """v1.26: the names host rules allow only on proxied ports, as
    warden_synth.inc.c's syn_qualifies decides: name:port for the ports host
    rules name (as stub_rules collects them), the proxied ports, and one port
    in neither; allowed (the first host rule that holds is an allow rule) on
    some proxied port and on no other. A set of names. Asked of the checker."""
    hosts = [i for i, r in enumerate(rules) if r["kind"] == "h"]
    ports = []
    for i in hosts:
        p = _host_port(rules[i]["c"])
        if p is not None and p not in ports:
            ports.append(p)
        if len(ports) >= 63:
            break
    ports += [p for p in pports if p not in ports]
    other = 1
    while other in ports and other < 65535:
        other += 1
    ports.append(other)
    names = sorted(names)
    strs = [f"{n}:{p}" for n in names for p in ports]
    if not strs:
        return set()
    h = subprocess.run([checker, policy, "holds"], capture_output=True, text=True,
                       input="\n".join(s.encode().hex() for s in strs) + "\n")
    rows = h.stdout.split()
    if h.returncode != 0 or len(rows) != len(strs):
        raise ValueError("the checker failed on the synthetic names")
    out = set()
    for k, n in enumerate(names):
        allowed = []
        for j, port in enumerate(ports):
            row = rows[k * len(ports) + j]
            first = next((i for i in hosts if row[i] == "1"), None)
            if first is not None and rules[first]["allow"]:
                allowed.append(port)
        if allowed and all(p in pports for p in allowed):
            out.add(n)
    return out


def check_synthetic(e, given, taken, synth, by_rule, line_of, problems):
    """v1.26: a synthetic_address record (given: name -> address so far, to
    which it is added; taken: their addresses) gives a name allowed only on proxied ports, under the
    rule the stub answers it by, the next address of 198.18.0.0/15 (from
    198.18.0.1), which no other name was given, and the name no other
    address."""
    name, addr, line = e.get("name"), e.get("address"), e.get("policy_line")
    try:
        ip = ipaddress.IPv4Address(addr)
    except (ValueError, TypeError):
        problems.append(f"{name!r}: a synthetic address {addr!r} that is not an IPv4 address")
        return
    if ip not in SYN_NET or ip in (SYN_NET[0], SYN_NET[-1]):
        problems.append(f"{name}: a synthetic address {addr} outside 198.18.0.1-198.19.255.254")
    if int(ip) != int(SYN_NET[0]) + len(given) + 1:
        problems.append(f"{name}: given {addr}, not the next synthetic address")
    if name in given or addr in taken:
        problems.append(f"{name}: a synthetic address given twice ({addr})")
    if name not in synth:
        problems.append(f"{name}: given a synthetic address, but the policy allows it off the "
                        f"proxied ports (or not at all)")
    want = by_rule.get(name)
    if want is None or line != line_of(want):
        problems.append(f"{name}: given a synthetic address under policy line {line}, not the "
                        f"policy's")
    given.setdefault(name, addr)
    taken.add(addr)


def check_dns(meta, checker, policy, rules, problems):
    """v1.25: the stub resolver. run_start's budgets and stub are the
    policy's; every question was answered by the rule the policy gives its
    name (asked of the checker); every name charged to a wildcard rule
    ("new") stays within its rule's names and label budgets and is charged
    once; every lookup sent upstream ("upstream": a new name's, or one asked
    again after its TTL) counts against its rule's rate, on the Warden's own
    clock ("mono_ms"), and is answered by a resolution record; a budget
    refusal answered NXDOMAIN; a question no rule allows answered NXDOMAIN and
    charged nothing; a lookup on demand ("dynamic") was asked for and charged;
    a resolution that is not dynamic is of a name a host rule names; and a
    NOERROR answer carried only addresses the name's latest resolution listed.
    Returns (questions, budget refusals)."""
    rs = meta.get("run_start", {})
    events = meta.get("dns_events", [])
    wild = policy_wildcards(rules)
    pports = policy_proxy(checker, policy)                      # v1.26
    upstream = policy_upstream(checker, policy)                 # v1.26 section 5
    exact_names = {r["c"].rsplit(":", 1)[0] if _host_port(r["c"]) is not None else r["c"]
                   for r in rules if r["kind"] == "h" and r["name"] and not r["wild"]}
    if upstream is not None and not re.fullmatch(r"[0-9.]+", upstream.rsplit(":", 1)[0]):
        exact_names.add(upstream.rsplit(":", 1)[0])   # v1.26 section 5: its name is resolved like one
    budgets = rs.get("wildcard_budgets")
    if wild or budgets is not None:
        want = sorted([{"policy_line": ln, "names": n, "rate": r, "label": DEFAULT_LABEL}
                       for ln, (_s, n, r) in wild.items()], key=lambda b: b["policy_line"])
        ok = isinstance(budgets, list) and all(
            isinstance(b, dict) and set(b) == {"policy_line", "names", "rate", "label"}
            and all(type(v) is int for v in b.values()) for b in budgets)
        got = sorted(budgets, key=lambda b: b["policy_line"]) if ok else budgets
        if got != want:
            problems.append(f"run_start's wildcard budgets {got!r} are not the policy's {want}")
    # v1.25 review: the stub exists exactly when the policy has a wildcard
    # allow rule (v1.26: or the proxy on and a host name rule), and is always
    # at the same address
    stub = wild or (pports is not None and any(r["kind"] == "h" and r["name"] and not r["wild"]
                                               for r in rules))
    if rs.get("dns_stub") != (STUB if stub else None):
        problems.append(f"run_start's dns_stub {rs.get('dns_stub')!r} is not the policy's "
                        f"({STUB if stub else 'none'})")
    per = {ln: {"names": n, "rate": r, "label": DEFAULT_LABEL} for ln, (_s, n, r) in wild.items()}
    asked_names = {e.get("name") for e in events if e.get("event") == "dns_question"
                   and isinstance(e.get("name"), str) and e.get("name")}
    syn_names = {e.get("name") for e in events if e.get("event") == "synthetic_address"
                 and isinstance(e.get("name"), str) and e.get("name")}
    by_rule = stub_rules(checker, policy, rules, asked_names | syn_names) \
        if asked_names | syn_names else {}
    line_of = lambda i: rules[i]["line"] if i is not None else -1    # noqa: E731
    # v1.26: with the proxy on, the names allowed only on proxied ports
    synth = proxied_only(checker, policy, rules, asked_names | syn_names, pports) \
        if pports is not None else set()
    if pports is None and syn_names:
        problems.append("synthetic addresses given, but the policy does not turn the proxy on")
    syn_given, syn_taken = {}, set()
    charged, used, window, pending, latest = {}, {}, {}, {}, {}
    last_mono = None
    nq = nb = 0
    for e in events:
        name, ts = e.get("name"), e.get("timestamp_ns")
        if not isinstance(name, str) or (e.get("event") == "resolution" and not name):
            problems.append(f"a {e.get('event')} record without a name")
            continue
        if e.get("event") == "synthetic_address":
            check_synthetic(e, syn_given, syn_taken, synth, by_rule, line_of, problems)
            continue
        if e.get("event") == "resolution":
            a = e.get("a")
            if a in ("retired", "grace_end"):    # no lookup: into grace, or out of it
                latest[name] = e
                continue
            if a == "unanswered":                # the run ended before the helper answered
                if name not in pending:
                    problems.append(f"{name}: an unanswered lookup that was never sent")
                pending.pop(name, None)
                continue
            if e.get("dynamic") is True:
                if name not in pending:
                    problems.append(f"{name}: looked up on demand with no question sending it upstream")
                if name not in charged:
                    problems.append(f"{name}: looked up on demand but never charged to a rule")
                pending.pop(name, None)
            elif name not in exact_names:
                # v1.25 review: only a name a host rule names is resolved
                # without a question (dropping "dynamic" must not hide one)
                problems.append(f"{name}: resolved, but no host rule names it and no question asked")
            latest[name] = e
            continue
        nq += 1
        rule, ans, line, mono = e.get("rule"), e.get("answer"), e.get("policy_line"), e.get("mono_ms")
        if type(mono) is not int or (last_mono is not None and mono < last_mono):
            problems.append(f"{name!r}: a question whose Warden time {mono!r} is missing or earlier "
                            f"than the one before it")
            continue
        last_mono = mono
        if not isinstance(ans, str) or not isinstance(rule, str) or type(line) is not int:
            problems.append(f"{name!r}: a malformed question record")
            continue
        if rule in ("no_rule", "not_a_host_name", "malformed"):
            if ans not in ("nxdomain", "formerr") or e.get("new") or e.get("upstream"):
                problems.append(f"{name!r}: a question no rule allows was answered {ans}")
            if rule == "no_rule" and by_rule.get(name) is not None:
                problems.append(f"{name}: recorded as allowed by no rule, but policy line "
                                f"{line_of(by_rule[name])} allows it")
            continue
        # v1.25 review: the rule the question was answered by is the policy's
        want = by_rule.get(name)
        if want is None or line != line_of(want):
            problems.append(f"{name}: answered by policy line {line}, but the policy "
                            f"{'allows it by line ' + str(line_of(want)) if want is not None else 'allows it by no rule'}")
            continue
        if rule == "exact_name" and (rules[want]["wild"] or name not in exact_names):
            problems.append(f"{name}: recorded as an exact name, but no exact rule allows it")
            continue
        # v1.26: a name allowed only on proxied ports is answered with its
        # synthetic address (A) or no data, and nothing else is done for it
        # (v1.26 step 6: a lookup the Warden sent upstream to dial a proxied
        # connection, "transport":"proxy", is charged as a question and never
        # synthetic, and only of a name the proxy may reach)
        if e.get("transport") == "proxy" and (e.get("synthetic") or pports is None or
                                              (ans == "upstream") != (upstream is not None and ans != "nxdomain")):
            problems.append(f"{name}: a proxied lookup that is synthetic, or with the proxy off")
            continue
        if e.get("transport") != "proxy" and \
                (e.get("synthetic") is True) != (name in synth and rule in ("policy_match", "exact_name")):
            problems.append(f"{name}: {'answered with' if e.get('synthetic') else 'not answered with'} "
                            f"a synthetic address, but the policy allows it "
                            f"{'off' if name not in synth else 'only on'} the proxied ports")
            continue
        if e.get("synthetic") is True:
            want_a = [syn_given[name]] if e.get("type") == 1 and name in syn_given else []
            if e.get("new") or e.get("upstream") or not (
                    (ans == "noerror" and e.get("addresses") == want_a and
                     (e.get("type") != 1 or name in syn_given)) or
                    (ans == "servfail" and e.get("type") == 1 and name not in syn_given
                     and len(syn_given) >= SYN_MAX)):
                problems.append(f"{name}: a synthetic answer {ans} {e.get('addresses')!r} that is not "
                                f"its synthetic address {want_a!r}, or that charged or sent anything")
            continue
        if rule == "wildcard_budget":
            nb += 1
            if ans != "nxdomain" or e.get("budget") not in ("names", "rate", "label") or \
                    e.get("new") or e.get("upstream") or line not in wild:
                problems.append(f"{name}: a budget refusal that is not a plain NXDOMAIN of a wildcard rule")
            continue
        if rule != "policy_match" and rule != "exact_name":
            problems.append(f"{name}: a question answered by rule {rule!r}")
            continue
        b, sfx = per.get(line), wild.get(line, ("",))[0]
        if e.get("new") is True:
            if rule != "policy_match" or b is None:
                problems.append(f"{name}: charged to policy line {line}, not a wildcard allow rule")
                continue
            if name in charged:
                problems.append(f"{name}: charged twice")
            charged[name] = line
            if not name.endswith("." + sfx) or len(name) - len(sfx) - 1 > b["label"]:
                problems.append(f"{name}: over policy line {line}'s label budget, or not under *.{sfx}")
            used[line] = used.get(line, 0) + 1
            if used[line] > b["names"]:
                problems.append(f"{name}: policy line {line} charged more than its {b['names']} names")
        if e.get("upstream") is True:
            if b is None or charged.get(name) != line or ans != "lookup":
                problems.append(f"{name}: sent upstream but not charged to wildcard line {line}")
                continue
            if name in pending:
                problems.append(f"{name}: sent upstream again while its lookup was outstanding")
            pending[name] = ts if type(ts) is int else 0
            # the Warden's sliding minute: lookups at most 60 s before this one
            w = window.setdefault(line, collections.deque())
            while w and w[0] <= mono - 60000:
                w.popleft()
            if len(w) >= b["rate"]:
                problems.append(f"{name}: policy line {line} sent more than {b['rate']} lookups "
                                f"upstream in a minute")
            w.append(mono)
        elif ans == "lookup" and name not in pending:
            problems.append(f"{name}: waits on a lookup that was never sent")
        if ans == "noerror" and isinstance(e.get("addresses"), list):
            r = latest.get(name)
            have = set((r or {}).get("addresses") or [])
            extra = [x for x in e["addresses"] if not isinstance(x, str) or x not in have]
            if extra:
                problems.append(f"{name}: answered {extra}, which its latest resolution does not list")
    # v1.25 review: the Warden answers every lookup it sent upstream with a
    # resolution record, or records it unanswered when the run ends first
    if isinstance(meta.get("run_end"), dict):
        for name in pending:
            problems.append(f"{name}: a lookup sent upstream was never answered (a resolution record "
                            f"is missing)")
    return nq, nb


_PORT_RE = re.compile(r"(0|[1-9][0-9]{0,4})")


def _ip(text):
    """An address as an ipaddress object, an IPv4-mapped IPv6 address as the
    IPv4 address it names; None if text is not an address."""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _canonical_dest(dest):
    """(address, port) of a destination in the Warden's spelling
    (net_decision_string: a.b.c.d:port, or [ipv6]:port in lowercase, no
    leading zeros), or None. The v1.24 review: a port such as 07002 or +7002
    is matched by a portless rule but by no rule written with the port, so a
    forger could use it to slip past a deny."""
    if not isinstance(dest, str) or ":" not in dest:
        return None
    host, _, port = dest.rpartition(":")
    if not _PORT_RE.fullmatch(port) or int(port) > 65535:
        return None
    if host.startswith("[") and host.endswith("]"):
        h = host[1:-1]
        try:
            ip = ipaddress.IPv6Address(h)
        except ValueError:
            return None
        groups = [g for g in h.split(":") if g]
        if h != h.lower() or any(len(g) > 1 and g.startswith("0") and "." not in g for g in groups):
            return None
        return ip, port
    try:
        ip = ipaddress.IPv4Address(host)
    except ValueError:
        return None
    if str(ip) != host:
        return None
    return ip, port


def _special_v4(o):
    return (o[0] == 0 or o[0] == 127 or (o[0] == 169 and o[1] == 254) or o[0] >= 224
            or o == bytes([100, 100, 100, 200]))


def _special(ip):
    """warden_names.inc.c: special_address. A name never leads to these."""
    o = ip.packed
    if ip.version == 4:
        return _special_v4(o)
    if o[:12] == bytes(12) or ip == ipaddress.ip_address("fd00:ec2::254"):
        return True
    # v1.26 review: IPv4-mapped and IPv4-translated addresses, whatever the
    # IPv4 address (an IPv6 socket to one reaches the IPv4 address)
    if o[:12] in (bytes(10) + b"\xff\xff", bytes(8) + b"\xff\xff\x00\x00"):
        return True
    if o[:12] == bytes.fromhex("0064ff9b") + bytes(8) or o[:6] == bytes.fromhex("0064ff9b0001"):
        return _special_v4(o[12:])
    return ip.is_link_local or ip.is_multicast


def _addrs(r, key):
    v = r.get(key)
    return v if isinstance(v, list) else []


def check_names(rec, pos, resolutions, problems, exact_grace=False):
    """v1.24: a connect decided with the resolution table. Its candidates are
    the address dialed and name:port for each name that address belonged to.
    Each name must be bound to the address by the latest resolution record
    before this record (current, or within its grace). Every name whose
    latest record lists the address, or holds it in grace well before the
    grace ends, must be a candidate. The dialed address and every candidate's
    port must be spelt as the Warden spells them, and the dialed address must
    be the connect's target. resolution_generation must be the latest
    resolution record's. A special address (loopback, link-local, ...) is
    decided on the address alone. Returns the candidates other than the one
    decided on (for the earlier-rule check)."""
    seq = rec.get("seq")
    cands, dialed, res = rec.get("candidates"), rec.get("dialed"), rec.get("resolved")
    if "candidates_sha256" in rec:
        return check_names_hashed(rec, pos, resolutions, problems)  # v1.25: exact grace
    if not (isinstance(cands, list) and cands and all(isinstance(c, str) for c in cands)
            and isinstance(dialed, str) and cands[0] == dialed and res in cands):
        problems.append(f"seq {seq}: a connect's candidates, dialed address and decided "
                        f"destination do not agree")
        return []
    cd, ct = _canonical_dest(dialed), _canonical_dest(rec.get("target"))
    if cd is None:
        problems.append(f"seq {seq}: the dialed address {dialed!r} is not in the Warden's spelling")
        return []
    if ct is None or _ip(str(ct[0])) != _ip(str(cd[0])) or ct[1] != cd[1]:
        problems.append(f"seq {seq}: dialed {dialed!r}, but the connect's target was "
                        f"{rec.get('target')!r}")
        return []
    addr, port = _ip(str(cd[0])), cd[1]
    ts = rec.get("timestamp_ns")
    if not isinstance(ts, int):
        problems.append(f"seq {seq}: a connect without its time")
        return []
    latest, last = {}, None
    for p, r in resolutions:
        if p > pos:
            break
        if isinstance(r.get("name"), str):
            latest[r["name"]] = r
            last = r
    if last is not None and rec.get("resolution_generation") != last.get("generation"):
        problems.append(f"seq {seq}: decided at table generation {rec.get('resolution_generation')!r}, "
                        f"but the latest resolution record before it is generation "
                        f"{last.get('generation')!r} (a resolution record is missing)")

    def binding(r):
        """'current', 'grace' (surely inside it), 'edge' (within about a
        second of its end, either way), or None."""
        if any(_ip(x) == addr for x in _addrs(r, "addresses") if isinstance(x, str)):
            return "current"
        rt = r.get("timestamp_ns")
        for g in _addrs(r, "grace"):
            if not (isinstance(g, dict) and isinstance(g.get("address"), str)
                    and isinstance(g.get("until_s"), int) and isinstance(rt, int)):
                continue
            if _ip(g["address"]) != addr:
                continue
            # v1.25 review: a 1.25 Warden writes a resolution record when an
            # address's grace ends, before the connect decided at that time;
            # so an address listed in grace is in grace
            if exact_grace:
                return "grace"
            # until_s is rounded up to whole seconds: the Warden's grace ended
            # within the second before `end`
            end = rt + g["until_s"] * 10**9
            if ts <= end - 1200 * 10**6:
                return "grace"
            if ts <= end + 10**9:
                return "edge"
        return None

    if rec.get("special_address") is True or _special(addr):
        if not _special(addr):
            problems.append(f"seq {seq}: marked special_address, but {addr} is not special")
        if rec.get("special_address") is not True or cands != [dialed]:
            problems.append(f"seq {seq}: {addr} is a special address, decided on the address alone, "
                            f"but the record does not say so")
        return [c for c in cands if c != res]
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
        if binding(r) is None:
            problems.append(f"seq {seq}: candidate {c!r}: {name} did not resolve to {addr} "
                            f"(by its resolution records)")
    for name, r in latest.items():
        if binding(r) in ("current", "grace") and name not in named:
            problems.append(f"seq {seq}: {name} resolved to {addr} but is not a candidate: the "
                            f"connect was not decided on every name of its address")
    return [c for c in cands if c != res]


def check_names_hashed(rec, pos, resolutions, problems):
    """v1.25: a connect whose address belonged to more than 15 names records
    their number and the SHA-256 of all its candidates (the address dialed
    and name:port for each name), sorted and joined with newlines, instead of
    listing them. The candidates are rebuilt here from the resolution records
    before the connect: every name whose latest record lists the address, or
    holds it in grace. v1.25 review: the Warden writes a resolution record
    when an address's grace ends (a grace_end), before the connect decided at
    that time, so an address its latest record lists in grace is in grace:
    there is no guessing from grace rounded to whole seconds, which an agent
    could use to make an honest stream fail. Returns the candidates other than
    the one decided on."""
    seq, dialed, res = rec.get("seq"), rec.get("dialed"), rec.get("resolved")
    n, h, ts = rec.get("candidates_n"), rec.get("candidates_sha256"), rec.get("timestamp_ns")
    if not (isinstance(dialed, str) and isinstance(n, int) and isinstance(h, str)
            and isinstance(ts, int) and isinstance(res, str)):
        problems.append(f"seq {seq}: a connect's hashed candidates are malformed")
        return []
    # as for listed candidates (check_names): the Warden's spelling, the
    # target, the table generation; a special address has no names to hash
    cd, ct = _canonical_dest(dialed), _canonical_dest(rec.get("target"))
    if cd is None or ct is None or _ip(str(ct[0])) != _ip(str(cd[0])) or ct[1] != cd[1]:
        problems.append(f"seq {seq}: dialed {dialed!r} is not in the Warden's spelling, or not the "
                        f"connect's target {rec.get('target')!r}")
        return []
    addr, port = _ip(str(cd[0])), cd[1]
    if _special(addr) or rec.get("special_address"):
        problems.append(f"seq {seq}: hashed candidates for a special address, decided on the address alone")
        return []
    latest, last = {}, None
    for p, r in resolutions:
        if p > pos:
            break
        if isinstance(r.get("name"), str):
            latest[r["name"]] = r
            last = r
    if last is not None and rec.get("resolution_generation") != last.get("generation"):
        problems.append(f"seq {seq}: decided at table generation {rec.get('resolution_generation')!r}, "
                        f"but the latest resolution record before it is generation "
                        f"{last.get('generation')!r} (a resolution record is missing)")
    names = set()
    for name, r in latest.items():
        if any(_ip(x) == addr for x in _addrs(r, "addresses") if isinstance(x, str)) or \
                any(isinstance(g, dict) and isinstance(g.get("address"), str) and _ip(g["address"]) == addr
                    for g in _addrs(r, "grace")):
            names.add(name)
    cands = sorted([dialed] + [f"{x}:{port}" for x in names])
    if len(cands) == n and hashlib.sha256("\n".join(cands).encode()).hexdigest() == h:
        if res not in cands:
            problems.append(f"seq {seq}: decided on {res!r}, which is not a candidate")
            return []
        return [c for c in cands if c != res]
    problems.append(f"seq {seq}: the connect's {n} hashed candidates are not the address's names "
                    f"by the resolution records (it was not decided on every name of {addr})")
    return []


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
    # v1.24 review: whether the policy has host name rules is read from the
    # policy file (the checker's own parse), not taken from run_start.
    try:
        prules = policy_rules(a.checker, a.policy)
    except (OSError, ValueError) as e:
        problems.append(f"checker failed on the policy's rules: {e}")
        prules = []
    rules = [[r["kind"], "a" if r["allow"] else "d", "n" if r["name"] else "-", r["mask"], r["value"]]
             for r in prules]
    wild_policy = bool(policy_wildcards(prules))
    # v1.26: the proxy's ports (None: off); the stub also runs with the proxy
    # on and a host name rule
    try:
        proxy_ports = policy_proxy(a.checker, a.policy)
    except (OSError, ValueError) as e:
        problems.append(f"checker failed on the policy's proxy directives: {e}")
        proxy_ports = None
    stub_policy = wild_policy or (proxy_ports is not None and any(
        r["kind"] == "h" and r["name"] and not r["wild"] for r in prules))
    if wild_policy:
        check_shared_lists(meta, a, problems)
    # v1.25 review: from 1.25 the Warden records the end of every grace
    exact_grace = _version_at_least(meta.get("run_start", {}).get("warden"), (1, 25))
    try:
        questions, budget_hits = check_dns(meta, a.checker, a.policy, prules, problems)  # v1.25
    except Exception as e:      # v1.25 review: hostile input gives a verdict, never a traceback
        problems.append(f"the stub resolver's records cannot be checked: {type(e).__name__}: {e}")
        questions = budget_hits = 0
    names_policy = any(r[0] == "h" and r[2] == "n" for r in rules)
    if (meta.get("run_start", {}).get("host_name_rules") is True) != names_policy:
        problems.append("run_start's host_name_rules does not match the policy file")
    handoff_ids, handoffs = set(), 0     # v1.26: connects handed to the proxy
    handoff_cands = []                   # v1.26 (step 8): (record, candidates), asked of the policy below
    proxied_ok = 0                       # v1.26: proxied names allowed
    view_recs = []                       # (rec, flags): asked of the policy below
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
            # v1.25 review: only with a wildcard allow rule in the policy, and
            # only to the stub's own address, by target and by what was reached
            ct = _canonical_dest(rec.get("target"))
            if not stub_policy:
                problems.append(f"seq {rec.get('seq')}: a stub connect, but the policy has no "
                                f"wildcard allow rule and no proxy (no stub resolver)")
            elif rec.get("resolved") != STUB or ct is None or \
                    f"{_ip(str(ct[0]))}:{ct[1]}" != STUB:
                problems.append(f"seq {rec.get('seq')}: a dns_stub record to "
                                f"{rec.get('target')!r} / {rec.get('resolved')!r}, not the stub at {STUB}")
            stubs += 1
            continue
        if rec.get("proxy_handoff") is True or rec.get("rule") in HANDOFF_RULES:
            # v1.26 (step 4): a connect handed to the egress proxy reaches only
            # its listener (no certificate: the proxy's decision on the name
            # the client sends is certified, step 6). Only with the proxy on,
            # for a TCP connect on a proxied port, to the listener run_start
            # names, with a connection id of its own; never one a rule denies.
            seq = rec.get("seq")
            pr = meta.get("run_start", {}).get("proxy")
            tgt = _canonical_dest(rec.get("target"))
            cid = rec.get("proxy_conn")
            if proxy_ports is None or not isinstance(pr, dict):
                problems.append(f"seq {seq}: a connect handed to the proxy, but the proxy is not on")
            elif rec.get("proxy_handoff") is not True or rec.get("action") != "net.connect" or \
                    rec.get("sock") != "tcp" or rec.get("resolved") != pr.get("listen"):
                problems.append(f"seq {seq}: a hand-off that is not a TCP connect to the proxy's "
                                f"listener {pr.get('listen')!r}")
            elif tgt is None or int(tgt[1]) not in proxy_ports:
                problems.append(f"seq {seq}: a hand-off of {rec.get('target')!r}, not on a proxied port")
            elif rec.get("decision_raw") == "DENY" and rec.get("policy_line", -1) != -1 and \
                    tgt[0] not in SYN_NET:
                problems.append(f"seq {seq}: a connect policy line {rec.get('policy_line')} denies "
                                f"was handed to the proxy")
            elif rec.get("rule") not in HANDOFF_RULES + HANDOFF_OTHER_RULES or \
                    _canonical_dest(rec.get("dialed")) is None or \
                    _canonical_dest(rec.get("dialed"))[1] != tgt[1]:
                # v1.26 review: a hand-off's own rule, and the address it was decided on
                problems.append(f"seq {seq}: a hand-off with rule {rec.get('rule')!r} or dialed "
                                f"{rec.get('dialed')!r}, not one the Warden writes")
            elif tgt[0] not in SYN_NET and not isinstance(rec.get("candidates"), list) and \
                    not isinstance(rec.get("candidates_sha256"), str):
                # v1.26 review: every hand-off of a real address is decided over its candidates
                problems.append(f"seq {seq}: a hand-off recorded without its candidates")
            elif tgt[0] not in SYN_NET and isinstance(rec.get("candidates"), list) and \
                    (not rec["candidates"] or rec["candidates"][0] != rec.get("dialed")):
                problems.append(f"seq {seq}: a hand-off whose candidates do not begin with its target")
            elif type(cid) is not int or cid < 1 or cid in handoff_ids:
                problems.append(f"seq {seq}: a hand-off without a connection id of its own ({cid!r})")
            else:
                handoff_ids.add(cid)
                if tgt[0] not in SYN_NET and isinstance(rec.get("candidates"), list):
                    handoff_cands.append((rec, [c for c in rec["candidates"] if isinstance(c, str)]))
            handoffs += 1
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
            else:
                view_recs.append((rec, flv))
            views += 1
            continue
        is_open = rec.get("action") == "file.open" and rec.get("rule") in AUTHORIZED_OPEN_RULES
        is_meta = rec.get("action") in META_ACTIONS and rec.get("rule") in META_RULES
        is_conn = rec.get("action") == "net.connect" and rec.get("rule") in CONNECT_RULES
        # v1.26 (step 6): a name:port the proxy read, allowed: certified as a connect is
        is_proxy = rec.get("action") == "net.proxy" and rec.get("rule") in PROXY_ALLOW_RULES
        if not (is_open or is_meta or is_conn or is_proxy):
            problems.append(f"seq {rec.get('seq')}: an authorization that is not a certified "
                            f"file open, lookup or connect ({rec.get('action')}, rule {rec.get('rule')})")
            continue
        if is_meta:
            lookups += 1
        elif is_proxy:
            proxied_ok += 1
        elif is_conn:
            connects += 1
            # v1.26: with the proxy on, the synthetic range is the Warden's: no
            # connect to it is dialed (step 4 hands such a connect to the proxy)
            dd = _canonical_dest(rec.get("dialed") or rec.get("resolved"))
            if proxy_ports is not None and dd is not None and \
                    dd[0] in SYN_NET:
                problems.append(f"seq {rec.get('seq')}: a connect to the synthetic address "
                                f"{dd[0]} was dialed")
            # v1.26 (step 8): with the proxy on, a connect on a proxied port is
            # dialed directly only by a numeric rule, decided on the address
            # itself (the certificate re-check below confirms the rule holds)
            dl8 = rec.get("dialed") or rec.get("target")
            td = _canonical_dest(dl8)
            cr8 = rec.get("cert_rule")
            if proxy_ports is not None and td is not None and int(td[1]) in proxy_ports and (
                    rec.get("resolved") != dl8 or type(cr8) is not int or
                    not 0 <= cr8 < len(prules) or prules[cr8]["name"]):
                problems.append(f"seq {rec.get('seq')}: a connect to {rec.get('target')} on a proxied "
                                f"port was dialed directly, not by a numeric rule")
        else:
            authorized += 1
        cr, cw = rec.get("cert_rule"), rec.get("cert_witness")
        if not isinstance(cr, int) or not isinstance(cw, str) or rec.get("check") != "ok":
            problems.append(f"seq {rec.get('seq')}: authorized open of {rec.get('resolved')!r} "
                            f"without an accepted certificate")
            continue
        s = rec.get("resolved", "")
        fl = rec.get("open_flags")
        if not isinstance(s, str):
            problems.append(f"seq {rec.get('seq')}: a malformed decided destination or path")
            continue
        if is_proxy:
            is_conn_like = True
        else:
            is_conn_like = is_conn
        if is_conn and names_policy and not str(rec.get("target", "")).startswith("unix:") \
                and "candidates" not in rec and "candidates_sha256" not in rec:
            # v1.24 review: every connect in a run with name rules is decided
            # over its candidates and says so; one without them is not trusted.
            problems.append(f"seq {rec.get('seq')}: a connect in a run with host name rules, "
                            f"recorded without its candidates")
            continue
        if is_conn_like:
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
        lines.append(f"{'host' if is_conn_like else 'path'} {fl} {hx} {cr} {cw}")
        which.append(rec)
        if is_conn and ("candidates" in rec or "candidates_sha256" in rec):
            try:
                others.append((rec, cr, check_names(rec, pos, resolutions, problems,
                                                    exact_grace=exact_grace)))
            except (TypeError, ValueError, AttributeError, KeyError) as e:
                problems.append(f"seq {rec.get('seq')}: malformed connect or resolution records ({e})")

    # v1.24 review: a view is served unless an explicit deny in the policy
    # holds on its path (and the open's flags): ask the checker which path
    # rules hold, in order.
    if view_recs and rules:
        h = subprocess.run([a.checker, a.policy, "holds"],
                           input="\n".join(VIEW_RULES[r["rule"]].encode().hex() for r, _ in view_recs) + "\n",
                           capture_output=True, text=True)
        rows = h.stdout.split()
        if h.returncode != 0 or len(rows) != len(view_recs):
            problems.append(f"checker failed: {h.stderr.strip()}")
        else:
            for (rec, flv), row in zip(view_recs, rows):
                for i, r in enumerate(rules):
                    if i < len(row) and row[i] == "1" and r[0] == "p" and \
                            (flv & int(r[3], 16)) == int(r[4], 16):
                        if r[1] == "d":
                            problems.append(f"seq {rec.get('seq')}: a {rec['rule']} served, but policy "
                                            f"rule {i} denies {VIEW_RULES[rec['rule']]}")
                        break

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
    # v1.26 (step 8): the proxy as run_start names it, and each hand-off as the policy decides
    check_proxy_start(meta, proxy_ports, problems, policy_upstream(a.checker, a.policy))
    if prules:
        check_handoff_rules(a.checker, a.policy, prules, handoff_cands, problems)
    # v1.26 (step 6): the Warden's decisions on what the proxy read
    handoff_all = {r.get("proxy_conn") for r in records
                   if r.get("proxy_handoff") is True and type(r.get("proxy_conn")) is int}
    try:
        upstream = policy_upstream(a.checker, a.policy)               # section 5
    except (OSError, ValueError):
        upstream = None
    handoff_port = {r.get("proxy_conn"): _host_port(str(r.get("target", ""))) for r in records
                    if r.get("proxy_handoff") is True and type(r.get("proxy_conn")) is int}
    charged_at = {}                     # name -> when a question charged it as new
    for e in meta.get("dns_events", []):
        if e.get("event") == "dns_question" and e.get("new") is True and isinstance(e.get("name"), str) \
                and type(e.get("timestamp_ns")) is int:
            charged_at.setdefault(e["name"], []).append(e["timestamp_ns"])
    exact_hosts = {r["c"].rsplit(":", 1)[0] if _host_port(r["c"]) is not None else r["c"]
                   for r in prules if r["kind"] == "h" and r["name"] and not r["wild"]}
    dialed_px = []
    proxied = check_proxied(records, resolutions, handoff_all, problems, upstream, dialed_px,
                            charged_at, exact_hosts, handoff_port)
    if prules:
        check_dialed_denies(a.checker, a.policy, prules, dialed_px, problems)
    pcloses = check_closes(records, meta.get("proxy_closes", []), complete, problems)   # step 7
    if proxied and proxy_ports is None:
        problems.append("proxied decisions, but the policy does not turn the proxy on")
    # v1.26: every connection id the Warden gave a hand-off is recorded once
    if complete and handoff_ids and handoff_ids != set(range(1, len(handoff_ids) + 1)):
        problems.append(f"the hand-offs' connection ids are not 1 to {len(handoff_ids)}: one is missing")
    print(f"varek_audit: run {run} (Warden {warden}, {'complete' if complete else 'INCOMPLETE'}), "
          f"{len(records)} records, {authorized} authorized file opens, {lookups} lookups, "
          f"{connects} authorized connects, "
          f"{views} host-name views, {stubs} stub resolver connects, {handoffs} proxy hand-offs, "
          f"{proxied} proxied decisions ({proxied_ok} allowed), {pcloses} proxy closes, "
          f"{questions} stub questions ({budget_hits} over a budget), "
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
