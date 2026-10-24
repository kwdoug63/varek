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
AUTHORIZED_OPEN_RULES = ("resolved_fd_injection", "allowed_open_failed", "injection_failed",
                         "open_not_found")   # v1.27: a missing file where the policy allows the read
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
# v1.26.1: in inspecting mode, the trust views: rule -> the paths it answers
TRUST_VIEW_RULES = {"trust_view": ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                                   "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem",
                                   "/etc/varek/run-bundle.pem"),
                    "run_ca_view": ("/etc/varek/run-ca.pem",),
                    "trust_store_view": ("/etc/varek/run-trust.p12",)}
O_CREAT, O_TRUNC = 0o100, 0o1000


def _addr_of(dest):
    """The address part of a numeric destination: a.b.c.d:port -> a.b.c.d,
    [IPv6]:port -> IPv6."""
    host = dest.rsplit(":", 1)[0]
    return host[1:-1] if host.startswith("[") else host


DEFAULT_NAMES, DEFAULT_RATE, DEFAULT_LABEL = 256, 30, 63    # the Warden's, v1.25


STUB = "127.53.53.53:53"          # the Warden's stub resolver (warden_stub.inc.c)


def stub_of(rs):
    """v1.34 step 4: the stub's address in this run. Under the node agent the
    namespace is the pod's, which its containers share, so the stub takes
    the first address free from 127.53.53.53 to 127.53.53.254 (run_start
    says which); a run the Warden starts itself has its own, at STUB."""
    s = rs.get("dns_stub")
    # review (T5): written as the Warden writes it (%d: no leading zero)
    m = re.fullmatch(r"127\.53\.53\.([1-9]\d{1,2}):53", s) if isinstance(rs.get("node"), dict) and isinstance(s, str) else None
    return s if m and 53 <= int(m.group(1)) <= 254 else STUB


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
    # v1.27.1 review: each rule's matcher too (prefix, exact, glob ...), in the same order
    mq = subprocess.run([checker, policy, "matches"], capture_output=True)
    if mq.returncode != 0:
        raise ValueError(mq.stderr.decode(errors="replace").strip() or "the checker failed")
    matches = mq.stdout.decode().split()
    out = []
    for ln in rq.stdout.decode().splitlines():
        f = ln.split()
        if len(f) != 11:
            raise ValueError(f"unexpected checker output {ln!r}")
        out.append({"kind": f[0], "allow": f[1] == "a", "name": f[2] == "n", "mask": f[3],
                     "value": f[4], "wild": f[5] == "w", "line": int(f[6]), "names": int(f[7]),
                     "rate": int(f[8]), "max_body": int(f[9]),
                     "c": "" if f[10] == "=" else bytes.fromhex(f[10]).decode("latin-1")})
    if len(matches) != len(out):
        raise ValueError("the checker's matches and rules differ in number")
    for r, m in zip(out, matches):
        r["match"] = m
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
    if rq.returncode != 0 or not f or f[0] not in ("on", "off", "inspect"):
        raise ValueError("the checker failed on the policy's proxy directives")
    if f[0] == "off":
        return None
    ends = [f.index(w) for w in ("upstream", "passthrough") if w in f]
    ports = f[1:min(ends)] if ends else f[1:]
    return [int(x) for x in ports]


def policy_launches(checker, policy):
    """v1.27: whether launches after the first are decided (require warden
    1.27), as the checker reads the policy."""
    rq = subprocess.run([checker, policy, "launches"], capture_output=True, text=True)
    f = rq.stdout.split()
    if rq.returncode != 0 or f not in (["on"], ["off"]):
        raise ValueError("the checker failed on the policy's launches")
    return f == ["on"]


def policy_openas(checker, policy):
    """v1.29: whether files are opened, and changed by name, as the agent
    (require warden 1.29), as the checker reads the policy."""
    rq = subprocess.run([checker, policy, "openas"], capture_output=True, text=True)
    f = rq.stdout.split()
    if rq.returncode != 0 or f not in (["on"], ["off"]):
        raise ValueError("the checker failed on the policy's openas")
    return f == ["on"]


# v1.29 (D12): the changes by name, each decided as a path with these flags
# (warden_change.inc.c), and the rules of an allowed one
CHANGE_FLAGS = {
    "file.unlink": ("0x201",), "file.rmdir": ("0x201",), "file.mkdir": ("0xc1",),
    "file.rename_from": ("0x202", "0x242"), "file.rename_to": ("0x241", "0x242"),
    "file.chmod": ("0x1",), "file.utime": ("0x1",), "file.truncate": ("0x201",),
    "file.chdir": ("0x10000",),
}
CHANGE_RULES = ("change_done", "change_failed", "chdir_continued")
# v1.29 (step 6): a mkdir of a name that is there, answered EEXIST as the
# kernel would, decided as a lookup (flags 0x0): one the policy allows
# reading (certified), or a directory the policy leads to
MKDIR_EXISTS_RULES = ("mkdir_exists", "mkdir_exists_ancestor")


# v1.29 (section 3, D2): refusals a dry run never lets through; a record of
# one marked "enforced":false is not the Warden's
DRY_NEVER_LET = ("protected_object", "raw_device", "view_write_refused", "change_on_kernel_fs",
                 "resolution_failed", "revoked", "subagent_unattributed", "subagent_threaded",
                 "subagent_same_image", "subagent_limit", "subagent_depth", "subagent_failed",
                 "intent_derivation_failed", "rename_directory_refused", "bad_descriptor",
                 "bad_address", "family_refused", "unspec_refused", "dns_refused",
                 "subagent_env")                                        # v1.31 review


def check_dry(meta, records, problems):
    """v1.29 (section 5, D10): a dry run's stream. True if it is one.

    Every record with "enforced":false is in a stream whose run_start says
    mode dry_run, refuses (DENY: the policy's verdict, which the dry run let
    through), and is not of a kind a dry run never lets through; none comes
    after a revocation; run_end says the same mode and counts them. In a
    stream that is not a dry run, no record says enforced:false."""
    rs = meta.get("run_start", {})
    dry = rs.get("mode") == "dry_run"
    if rs.get("mode") not in (None, "dry_run"):
        problems.append(f"run_start's mode {rs.get('mode')!r} is not one the Warden writes")
    end = [meta["run_end"]] if isinstance(meta.get("run_end"), dict) else []
    if end and end[-1].get("mode") != rs.get("mode"):
        problems.append(f"run_end's mode {end[-1].get('mode')!r} is not run_start's {rs.get('mode')!r}")
    # the revocation is one of the credential events; order by stream line
    lines = meta.get("lineno", {})
    at = lambda r: lines.get(id(r), 0)
    rv = [at(e) for _, e in meta.get("cred_events", []) if e.get("event") == "revoked"]
    rline = min(rv) if rv else None
    n = 0
    by_seq = {r.get("seq"): r for r in records if isinstance(r, dict) and type(r.get("seq")) is int}
    for r in list(records) + list(meta.get("dns_events", [])):
        if not isinstance(r, dict) or "enforced" not in r:
            continue
        seq = r.get("seq", r.get("name"))
        if r.get("enforced") is not False:
            problems.append(f"seq {seq}: \"enforced\" is {r.get('enforced')!r}; the Warden writes only false")
            continue
        n += 1
        if not dry:
            problems.append(f"seq {seq}: a record not enforced, in a run that is not a dry run")
            continue
        if r.get("event") == "dns_question":
            if r.get("rule") not in ("no_rule", "wildcard_budget"):
                problems.append(f"seq {seq}: a stub question not enforced with rule {r.get('rule')!r}")
        elif r.get("decision_final") != "DENY":
            problems.append(f"seq {seq}: a record not enforced whose verdict is {r.get('decision_final')!r}: "
                            f"a dry run lets through only what the policy refused")
        if r.get("rule") in DRY_NEVER_LET:
            problems.append(f"seq {seq}: {r.get('rule')} let through: a dry run never lets it through")
        # a rename let through: both its names decided and recorded, the old
        # then the new (v1.29 review)
        act = r.get("action")
        if act in ("file.rename_from", "file.rename_to") and type(seq) is int:
            other = by_seq.get(seq + 1 if act == "file.rename_from" else seq - 1)
            want = "file.rename_to" if act == "file.rename_from" else "file.rename_from"
            if not other or other.get("action") != want or other.get("enforced") is not False or \
                    other.get("agent_pid") != r.get("agent_pid"):
                problems.append(f"seq {seq}: a rename let through without its "
                                f"{'new' if want == 'file.rename_to' else 'old'} name decided and recorded "
                                f"{'next' if want == 'file.rename_to' else 'before it'}")
        if rline is not None and at(r) > rline:
            problems.append(f"seq {seq}: a call let through after the run was revoked")
    if dry and end and end[-1].get("not_enforced") != n:
        problems.append(f"run_end counts {end[-1].get('not_enforced')!r} calls not enforced; the stream holds {n}")
    if not dry and end and "not_enforced" in end[-1]:
        problems.append("run_end counts calls not enforced in a run that is not a dry run")
    return dry


def check_open_as(meta, openas_policy, problems):
    """v1.29 (section 1): run_start's open_as against the policy and the run"""
    rs = meta.get("run_start", {})
    oa = rs.get("open_as")
    if not openas_policy:
        if oa is not None:
            problems.append("run_start says files were opened as the agent, but the policy does not say "
                            "require warden 1.29")
        return
    if not isinstance(oa, dict):
        problems.append("the policy says require warden 1.29, but run_start does not say whom files were "
                        "opened as")
    elif oa.get("agent") is True:
        if not (type(oa.get("uid")) is int and type(oa.get("gid")) is int and oa["uid"] > 0 and oa["gid"] > 0
                and isinstance(oa.get("groups"), list) and all(type(g) is int and g > 0 for g in oa["groups"])):
            problems.append(f"run_start's open_as {oa!r} is malformed (or names root)")
    elif oa != {"agent": False, "why": "run_as_root"}:
        problems.append(f"run_start's open_as {oa!r} is malformed")


def check_baseline(meta, policy, problems):
    """v1.29 (section 2): a baseline's #@ header and run_start's baseline agree"""
    rs = meta.get("run_start", {})
    b = rs.get("baseline")
    try:
        with open(policy, encoding="utf-8", errors="replace") as fh:
            head = [ln.rstrip("\n") for ln in fh.readlines()[:8]]
    except OSError:
        head = []
    hdr = {}
    if head and head[0] == "#@ varek baseline 1":
        for ln in head[1:]:
            if not ln.startswith("#@ "):
                break
            k, _, v = ln[3:].partition(" ")
            hdr[k] = v
    if not hdr and b is None:
        return
    if not hdr:
        problems.append("run_start names a baseline, but the policy file is not one")
        return
    if not isinstance(b, dict):
        problems.append("the policy is a baseline, but run_start does not say so")
        return
    prof = hdr.get("profile", "").split(" ")
    want = {"format": 1, "profile": prof[0] if prof else "", "cwd": hdr.get("cwd"), "home": hdr.get("home"),
            "user": hdr.get("user"), "tmp": hdr.get("tmp"),
            "profile_sha256": prof[1] if len(prof) > 1 and prof[1] != "-" else ""}
    if b != want:
        problems.append(f"run_start's baseline {b!r} is not the policy file's header {want!r}")


def check_changes(records, openas_policy, problems):
    """v1.29: every change by name is in a run whose policy says require
    warden 1.29; an allowed one carries the flags its kind is decided as; a
    rename's old and new names are recorded together (seq n and n+1, the same
    process and outcome), never one without the other."""
    allowed = [r for r in records if r.get("action") in CHANGE_FLAGS and r.get("decision_final") == "ALLOW"]
    if not openas_policy:
        for r in records:
            if r.get("action") in CHANGE_FLAGS:
                problems.append(f"seq {r.get('seq')}: a change by name ({r.get('action')}) in a run whose "
                                f"policy does not say require warden 1.29")
        return
    by_seq = {r.get("seq"): r for r in records if type(r.get("seq")) is int}
    for r in allowed:
        act, seq = r["action"], r.get("seq")
        if r.get("rule") in MKDIR_EXISTS_RULES:                       # step 6
            if act != "file.mkdir" or r.get("open_flags") != "0x0" or r.get("errno") != 17:
                problems.append(f"seq {seq}: {act} recorded {r.get('rule')}, which the Warden writes only for "
                                f"a mkdir decided as a lookup (0x0) and answered EEXIST")
            continue
        if r.get("open_flags") not in CHANGE_FLAGS[act]:
            problems.append(f"seq {seq}: {act} allowed as open flags {r.get('open_flags')!r}, not as its "
                            f"kind is decided ({'/'.join(CHANGE_FLAGS[act])})")
        if (act == "file.chdir") != (r.get("rule") == "chdir_continued"):
            problems.append(f"seq {seq}: {act} allowed with rule {r.get('rule')!r}")
        if act == "file.rename_from":
            nx = by_seq.get(seq + 1) if type(seq) is int else None
            if not nx or nx.get("action") != "file.rename_to" or nx.get("decision_final") != "ALLOW" or \
                    nx.get("agent_pid") != r.get("agent_pid") or nx.get("rule") != r.get("rule"):
                problems.append(f"seq {seq}: a rename allowed without its new name decided and recorded next")
        if act == "file.rename_to":
            pv = by_seq.get(seq - 1) if type(seq) is int else None
            if not pv or pv.get("action") != "file.rename_from" or pv.get("decision_final") != "ALLOW":
                problems.append(f"seq {seq}: a rename's new name allowed without its old name before it")


def _node_launcher(rs):
    """v1.34: does run_start say a node agent's container ran the launcher
    (varek-init) first?"""
    node = rs.get("node")
    return isinstance(node, dict) and node.get("launcher") is True


V127_RULES = ("exec_allowed", "exec_not_in_ruleset", "exec_no_landlock", "exec_identity_mismatch",
              "exec_identity_unreadable", "open_not_found", "subagent_env")


def check_exec_set(meta, launches, problems, records=()):
    """v1.27: with launches on, run_start records Landlock (its ABI, or null
    without it) and the launch set, and names a Warden of 1.27 or later;
    without, none of them, and no record or event only launches on writes
    (review findings 4 and 5)."""
    rs = meta.get("run_start", {})
    has = "exec_ruleset" in rs or "landlock" in rs
    w = rs.get("warden")
    if "warden" in rs and not (isinstance(w, str) and re.fullmatch(r"\d+\.\d+\.\d+", w)):
        problems.append(f"run_start names the Warden {w!r}, not a version")
    elif (launches or has) and not _version_at_least(w, (1, 27)):
        problems.append(f"run_start names the Warden {w!r}, but only 1.27 or later decides launches")
    if not launches:
        if has and _node_launcher(rs):
            # v1.34 step 7 (found by the sweep): under the node agent the
            # launcher runs first in every container and applies Landlock,
            # its launch set the container's command alone (and what starts
            # it), whatever the policy says of launches
            ll, ex = rs.get("landlock"), rs.get("exec_ruleset")
            if not _version_at_least(w, (1, 34)):
                problems.append(f"run_start names the launcher, but the Warden {w!r}: only 1.34 or later runs "
                                f"under the node agent")
            if not (isinstance(ll, dict) and type(ll.get("abi")) is int and ll["abi"] >= 1):
                problems.append(f"run_start names the launcher, but its landlock {ll!r} is not an ABI")
            # step 8 review (T4): the command alone, and what starts it: one
            # bootstrap entry, the launch the run's first record names, at
            # most one interpreter, each entry whole
            whys = [e.get("why") for e in ex] if isinstance(ex, list) else []
            boot = next((r for r in records if r.get("rule") == "bootstrap_exec_allow"), None)
            if not isinstance(ex, list) or not ex or not all(
                    isinstance(e, dict) and isinstance(e.get("name"), str) and e["name"].startswith("/") and
                    isinstance(e.get("path"), str) and type(e.get("dev")) is int and type(e.get("ino")) is int and
                    isinstance(e.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", e["sha256"]) and
                    e.get("why") in ("bootstrap", "loader", "interpreter") for e in ex) or \
                    whys.count("bootstrap") != 1 or whys.count("interpreter") > 1:
                problems.append("run_start names the launcher, and the policy does not turn launches on, but its "
                                "launch set is not the command alone (and what starts it)")
            elif boot is not None and ex[whys.index("bootstrap")].get("name") != boot.get("target"):
                problems.append(f"run_start's launch set names the bootstrap {ex[whys.index('bootstrap')].get('name')!r}, "
                                f"but the agent's own launch was {boot.get('target')!r}")
        elif has:
            problems.append("run_start records a launch set or Landlock, but the policy does not turn "
                            "launches on (require warden 1.27)")
        bad = [r for r in records if r.get("rule") in V127_RULES]
        if bad:
            problems.append(f"seq {bad[0].get('seq')}: a record with rule {bad[0].get('rule')!r}, which "
                            f"only a run with launches on (require warden 1.27) writes")
        if meta.get("exec_results"):
            problems.append("exec_result events, which only a run with launches on writes")
        re_ = meta.get("run_end")
        if isinstance(re_, dict) and "exec_identity_mismatch" in re_:
            problems.append("run_end says exec_identity_mismatch, which only a run with launches on writes")
        return
    ll, ex = rs.get("landlock", "missing"), rs.get("exec_ruleset")
    if not (ll is None or (isinstance(ll, dict) and type(ll.get("abi")) is int and ll["abi"] >= 1)):
        problems.append(f"run_start's landlock {ll!r} is neither null nor an ABI")
    if not isinstance(ex, list) or not all(
            isinstance(e, dict) and isinstance(e.get("name"), str) and isinstance(e.get("path"), str) and
            type(e.get("dev")) is int and type(e.get("ino")) is int and isinstance(e.get("sha256"), str) and
            e.get("why") in ("rule", "loader", "bootstrap", "interpreter") for e in ex):
        problems.append("run_start's exec_ruleset is missing or malformed")
        return
    names = [e["name"] for e in ex]
    if len(set(names)) != len(names):
        problems.append("run_start's launch set holds a name twice")
    if any(not re.fullmatch(r"[0-9a-f]{64}", e["sha256"]) for e in ex):
        problems.append("run_start's launch set holds a SHA-256 that is not 64 hex digits")


O_ACCMODE, O_TRUNC, O_CREAT = 3, 0o1000, 0o100


def path_rule_writable(r):
    """v1.27.1: does an allow path rule let the agent open for writing (an
    access mode of write or read-write, O_TRUNC or O_CREAT)? As the Warden
    reads it (warden_noexec.inc.c): the flags the rule requires, the rest
    free."""
    if r["kind"] != "p" or not r["allow"]:
        return False
    mask, value = int(r["mask"], 16), int(r["value"], 16)      # the checker prints them in hex
    for c in (1, 2, O_TRUNC, O_CREAT, 1 | O_TRUNC, 2 | O_TRUNC, 1 | O_CREAT, 2 | O_CREAT,
              O_CREAT | O_TRUNC, 1 | O_CREAT | O_TRUNC, 2 | O_CREAT | O_TRUNC):
        f = (c & ~mask) | value
        if (f & O_ACCMODE) in (1, 2) or f & (O_TRUNC | O_CREAT):
            return True
    return False


def _nx_under(p, d):
    """Is p inside d (or d itself)? As warden_noexec.inc.c's noexec_under."""
    return d == "/" or p == d or p.startswith(d + "/")


def _nx_parent(s):
    sl = s.rfind("/")
    return "/" if sl == 0 else s[:sl] if sl > 0 else s


def noexec_target(r):
    """v1.27.1 review: the directory (or file) a writable path rule's noexec
    mount is for, as warden_noexec.inc.c's noexec_target works it out:
    (target, exact). target None: a rule no directory bounds (the Warden
    refuses to start); "": a rule matching no absolute path (none). exact:
    the rule names one path, so the Warden mounts it, or its directory if it
    is not there (D3)."""
    c, m = r["c"], r.get("match")
    if m in ("suffix", "contains"):
        return None, False
    if m == "exact":
        return (c, True) if c.startswith("/") else ("", False)
    if m == "prefix":
        if not c.startswith("/"):
            return "", False
        return (c[:-1] if len(c) > 1 and c.endswith("/") else _nx_parent(c)), False
    if m == "glob":
        k = 0
        while k < len(c) and c[k] not in "*?[\\":
            k += 1
        if k == 0:
            return None, False
        out = c[:k]
        if not out.startswith("/"):
            return "", False
        if k < len(c):
            sl = out.rfind("/")
            return (out[:1] if sl == 0 else out[:sl]), False
        return (out[:-1] if len(out) > 1 and out.endswith("/") else out), True
    return "", False


def noexec_rule_reaches(r, s, file):
    """v1.29 (step 6): may writable rule r match s, or (a directory) a path
    inside it? As warden_noexec.inc.c's noexec_rule_reaches: every path a
    rule matches starts with its constant before the first wildcard."""
    c, m = r["c"], r.get("match")
    if m == "exact":
        return c.startswith("/") and (c == s if file else _nx_under(c, s))
    if m == "prefix":
        if not c.startswith("/"):
            return False
        stem = c
    elif m == "glob":
        k = 0
        while k < len(c) and c[k] not in "*?[\\":
            k += 1
        if k == 0:
            return True
        stem = c[:k]
        if not stem.startswith("/"):
            return False
    else:
        return True
    return s.startswith(stem) or (not file and stem.startswith(s + "/"))


def check_noexec_exec(meta, rules, openas, problems):
    """v1.29 (step 6): under `require warden 1.29`, run_start's noexec_exec:
    each place inside a directory mounted noexec that keeps exec (for the
    agent's own program or a file of the launch set). Each must be inside
    one listed directory, spelled canonically, and reached by no rule that
    lets the agent write; none of them is recorded under an earlier policy."""
    rs = meta.get("run_start", {})
    nx, ne = rs.get("noexec"), rs.get("noexec_exec")
    if not openas or not isinstance(nx, list):
        if ne is not None:
            problems.append("run_start records places kept executable inside the noexec mounts, but the "
                            "policy does not say require warden 1.29 (or nothing is mounted noexec)")
        return
    if not isinstance(ne, list) or not all(
            isinstance(e, dict) and set(e) <= {"path", "in", "file"} and isinstance(e.get("path"), str)
            and isinstance(e.get("in"), str) and e.get("file", True) is True for e in ne):
        problems.append("run_start's noexec_exec is missing or malformed")
        return
    listed = {e["path"] for e in nx if not e.get("missing")}
    writable = [r for r in rules if path_rule_writable(r)]
    for e in ne:
        p, d = e["path"], e["in"]
        if os.path.normpath(p) != p or p.startswith("//") or not p.startswith("/"):
            problems.append(f"run_start's noexec_exec names {p!r}, which is not spelled as a canonical path")
        elif d not in listed or p == d or not _nx_under(p, d):
            problems.append(f"run_start's noexec_exec keeps {p!r} executable inside {d!r}, which is not a "
                            f"directory run_start's noexec mounts, or does not hold it")
        else:
            hit = [r["line"] for r in writable if noexec_rule_reaches(r, p, bool(e.get("file")))]
            if hit:
                problems.append(f"run_start's noexec_exec keeps {p!r} executable, but policy line {hit[0]} "
                                f"lets the agent write there")


def _open_writes(flags):
    return (flags & O_ACCMODE) in (1, 2) or bool(flags & (O_TRUNC | O_CREAT))


def check_noexec(meta, rules, launches, problems, records=()):
    """v1.27.1: with launches on, a Warden of 1.27.1 or later records in
    run_start the directories it mounted noexec ("noexec"), each with the
    policy line of a rule that lets the agent write and that rule's own
    directory (target); null when the operator turned the mounts off
    (--writable-exec), which is reported, not failed. Without launches on,
    no such record.
    v1.27.1 review: each entry is checked against its rule (the directory
    the rule names, spelled canonically, none inside another, "file" only
    for a rule naming one file), every writable rule must be covered by an
    entry, and every open the stream records the agent making for writing
    under a policy rule must be under a listed directory. What the Warden's
    realpath found on the run's host cannot be repeated offline: an entry
    whose path is not its rule's directory as written is refused."""
    rs = meta.get("run_start", {})
    has = "noexec" in rs
    if not launches:
        # v1.34: under the node agent's launcher, an empty list (the pod's own
        # mounts are the node agent's D4 check, not the Warden's)
        if has and not (_node_launcher(rs) and rs["noexec"] == []):
            problems.append("run_start records noexec mounts, but the policy does not turn launches on")
        return
    if not has:
        if _version_at_least(rs.get("warden"), (1, 27, 1)):
            problems.append(f"run_start names the Warden {rs.get('warden')!r}, which records its noexec "
                            f"mounts, but has none")
        return
    if not _version_at_least(rs.get("warden"), (1, 27, 1)):
        problems.append(f"run_start records noexec mounts, but names the Warden {rs.get('warden')!r}, "
                        f"which mounts nothing noexec")
        return
    nx = rs["noexec"]
    if nx is None:
        print("varek_audit: note: the Warden ran with --writable-exec: files the agent could write "
              "were not mounted noexec, so they could be mapped executable")
        return
    keys = {"path", "target", "policy_line", "file", "missing"}
    if not isinstance(nx, list) or not all(
            isinstance(e, dict) and set(e) <= keys and isinstance(e.get("path"), str)
            and e["path"].startswith("/") and isinstance(e.get("target"), str)
            and e["target"].startswith("/") and type(e.get("policy_line")) is int
            and e.get("file", True) is True and e.get("missing", True) is True
            for e in nx):
        problems.append("run_start's noexec is malformed")
        return
    paths = [e["path"] for e in nx]
    if len(set(paths)) != len(paths):
        problems.append("run_start's noexec names a directory twice")
    for e in nx:
        p = e["path"]
        if os.path.normpath(p) != p or p.startswith("//"):
            problems.append(f"run_start's noexec names {p!r}, which is not spelled as a canonical path")
        for o in nx:
            if o is not e and o["path"] != p and _nx_under(p, o["path"]):
                problems.append(f"run_start's noexec names {p!r} inside {o['path']!r} (the Warden keeps "
                                f"only the outer)")
    writable = {r["line"]: r for r in rules if path_rule_writable(r)}
    for e in nx:
        p, line = e["path"], e["policy_line"]
        r = writable.get(line)
        if r is None:
            problems.append(f"run_start's noexec mounts {p!r} for policy line {line}, "
                            f"which does not let the agent write")
            continue
        if p == "/":
            problems.append("run_start's noexec mounts /, which the Warden refuses")
        t, exact = noexec_target(r)
        if not t:
            continue                      # reported below, once a rule
        if e["target"] not in ({t, _nx_parent(t)} if exact else {t}):
            problems.append(f"run_start's noexec gives policy line {line}'s directory as "
                            f"{e['target']!r}; the rule's is {t!r}")
        elif e.get("file") and not (exact and e["target"] == t):
            problems.append(f"run_start's noexec marks {p!r} a file, but policy line {line} names no "
                            f"single file there")
        elif e.get("file") and e.get("missing"):
            problems.append(f"run_start's noexec marks {p!r} both a file and not there")
        elif p != e["target"]:
            problems.append(f"run_start's noexec mounts {p!r} for policy line {line}, whose directory is "
                            f"{e['target']!r}: a rule that names its directory through a link (or . or "
                            f"..) matches no path the Warden resolves; name the directory itself")
    for line, r in sorted(writable.items()):
        t, _ = noexec_target(r)
        if t is None:
            problems.append(f"policy line {line} lets the agent write paths no directory bounds, "
                            f"and the Warden refuses to start with it")
        elif t and not any(_nx_under(t, e["target"]) or _nx_under(t, e["path"]) for e in nx):
            problems.append(f"policy line {line} lets the agent write under {t!r}, which run_start's "
                            f"noexec does not list")
    for rec in records:
        if rec.get("action") != "file.open" or type(rec.get("policy_line")) is not int or \
                rec["policy_line"] < 1 or \
                not (rec.get("decision_final") == "ALLOW" or rec.get("kernel_verdict") == "ALLOW"):
            continue
        try:
            flags = int(rec.get("open_flags", "0x0"), 16)
        except (TypeError, ValueError):
            continue
        res = rec.get("resolved")
        if _open_writes(flags) and isinstance(res, str) and res.startswith("/") and \
                not any(_nx_under(res, e["path"]) for e in nx):
            problems.append(f"seq {rec.get('seq')}: the agent opened {res!r} for writing, under no "
                            f"directory run_start's noexec lists")


EXEC_REFUSALS = ("policy_match", "default_deny_unknown", "certificate_refused", "exec_no_landlock",
                 "exec_not_in_ruleset", "exec_unresolved",
                 # v1.27 review: a launch by a thread another thread's launch is ending:
                 # its path cannot be read, or its image (the call is refused, nothing run)
                 "intent_derivation_failed", "exec_identity_unreadable",
                 # v1.28.1 step 3: a sub-agent's launch the Warden could not make one
                 "subagent_threaded", "subagent_limit", "subagent_depth", "subagent_failed",
                 # v1.31 review: a confined subject launched with a variable that names code
                 "subagent_env",
                 # v1.31 (the shared soak): a launch after the run was revoked (checked
                 # against the revocation with every other call refused as revoked)
                 "revoked")
SUBAGENT_REFUSALS = ("subagent_threaded", "subagent_limit", "subagent_depth", "subagent_failed", "subagent_env")
EXEC_RESULTS = ("launched", "failed", "gone", "killed")


def check_launches(checker, policy, rules, meta, records, complete, problems):
    """v1.27 (step 5), with launches on:
    - the launch set in run_start against the policy: each file admitted by a
      rule is one whose name the first exec rule that holds on it allows, at
      the line recorded; at most one bootstrap entry, the program the agent's
      own launch named, and an interpreter only with it; no file twice;
    - each refused launch asked of the policy again on its name, and each
      refusal only where it can happen (no Landlock only without it; a file
      not in the set only where the policy allows the name);
    - each allowed launch has one exec_result, after it, and no exec_result
      names anything else;
    - a process killed by the identity check: recorded in run_end, and the
      run fails the audit (a process ran what was not decided);
    - no launch is refused as before 1.27 (deny_only_nonfile_v191).
    Returns (allowed launches, refused launches). Asked of the checker."""
    rs = meta.get("run_start", {})
    ex = rs.get("exec_ruleset") if isinstance(rs.get("exec_ruleset"), list) else []
    ex = [e for e in ex if isinstance(e, dict)]
    exec_rules = [i for i, r in enumerate(rules) if r["kind"] == "e"]
    boot = next((r for r in records if r.get("action") == "process.exec"
                 and r.get("rule") == "bootstrap_exec_allow"), None)
    # review finding 1: the agent's own launch is the run's first record, and the
    # only one; any other is a launch decided like every later one
    if records and (boot is None or records[0] is not boot or boot.get("seq") != 0):
        problems.append("the agent's own launch (bootstrap_exec_allow) is not the run's first record")
    if sum(1 for r in records if r.get("rule") == "bootstrap_exec_allow") > 1:
        problems.append("more than one record of the agent's own launch")
    ids = [(e.get("dev"), e.get("ino")) for e in ex]
    if len(set(ids)) != len(ids):
        problems.append("run_start's launch set holds a file twice")
    whys = [e.get("why") for e in ex]
    # (the bootstrap's own entry may read "rule" when a rule admits it too)
    if whys.count("bootstrap") > 1 or whys.count("interpreter") > 1 or ("interpreter" in whys and boot is None):
        problems.append("run_start's launch set has more than one bootstrap or interpreter entry, or an "
                        "interpreter without the agent's own launch")
    if "bootstrap" in whys and boot is not None:
        b = ex[whys.index("bootstrap")]
        if b.get("name") != boot.get("target"):
            problems.append(f"run_start's launch set names the bootstrap {b.get('name')!r}, but the agent's "
                            f"own launch was {boot.get('target')!r}")
    if any(not str(e.get("name", "")).startswith("/") for e in ex):
        problems.append("run_start's launch set holds a name that is not absolute")
    ruled = [e for e in ex if e.get("why") == "rule"]
    launches = [r for r in records if r.get("action") == "process.exec" and r.get("rule") != "bootstrap_exec_allow"]
    refused = [r for r in launches if r.get("decision_final") != "ALLOW"]
    ASKED = ("policy_match", "default_deny_unknown", "exec_not_in_ruleset", "exec_no_landlock",
             "certificate_refused") + SUBAGENT_REFUSALS
    for r in refused:                     # review finding 1: every such refusal is asked of the policy
        if r.get("rule") in ASKED and not (isinstance(r.get("resolved"), str) and r["resolved"]):
            problems.append(f"seq {r.get('seq')}: a launch refused as {r.get('rule')!r} without the name "
                            f"it was decided on")
    asked = [(e["name"], e) for e in ruled] + \
            [(r.get("resolved"), r) for r in refused if r.get("rule") in ASKED
             and isinstance(r.get("resolved"), str) and r["resolved"]]
    if asked:
        h = subprocess.run([checker, policy, "holds"], capture_output=True, text=True,
                           input="\n".join(n.encode("utf-8", "surrogateescape").hex() or "=" for n, _ in asked) + "\n")
        rows = h.stdout.split()
        if h.returncode != 0 or len(rows) != len(asked):
            problems.append(f"checker failed on the launches: {h.stderr.strip()}")
            rows = []
        for (name, obj), row in zip(asked, rows):
            first = next((i for i in exec_rules if i < len(row) and row[i] == "1"), None)
            fr = rules[first] if first is not None else None
            if "dev" in obj:                                 # a set entry admitted by a rule
                if fr is None or not fr["allow"] or fr["line"] != obj.get("policy_line"):
                    problems.append(f"run_start's launch set holds {name!r} as admitted by line "
                                    f"{obj.get('policy_line')!r}, which does not allow it")
                continue
            seq, rule, line = obj.get("seq"), obj.get("rule"), obj.get("policy_line")
            if rule == "default_deny_unknown" and fr is not None:
                problems.append(f"seq {seq}: a launch refused as matching no rule, but line {fr['line']} matches it")
            elif rule == "policy_match" and (fr is None or fr["allow"] or fr["line"] != line):
                problems.append(f"seq {seq}: a launch refused by line {line!r}, which is not the deny rule "
                                f"that decides it")
            elif rule in ("exec_not_in_ruleset", "exec_no_landlock", "certificate_refused") + SUBAGENT_REFUSALS \
                    and (fr is None or not fr["allow"]):
                problems.append(f"seq {seq}: a launch refused as {rule!r}, but the policy does not "
                                f"allow its name")
    for r in refused:
        seq, rule = r.get("seq"), r.get("rule")
        if rule == "deny_only_nonfile_v191":
            problems.append(f"seq {seq}: a launch refused as before 1.27, but the policy decides launches")
        elif rule == "exec_no_landlock" and rs.get("landlock") is not None:
            problems.append(f"seq {seq}: a launch refused for want of Landlock, but run_start records it")
        elif rule == "exec_not_in_ruleset" and rs.get("landlock") is None:      # review finding 5
            problems.append(f"seq {seq}: a launch refused as not in the set, but without Landlock the "
                            f"Warden refuses every launch for that")
        if rule in ("exec_not_in_ruleset", "exec_no_landlock", "certificate_refused") + SUBAGENT_REFUSALS and \
                r.get("decision_raw") != "ALLOW":
            problems.append(f"seq {seq}: a launch refused as {rule!r}, which follows only a decision to "
                            f"allow it, but the decision was {r.get('decision_raw')!r}")
        elif rule == "exec_unresolved" and r.get("decision_raw") not in ("UNKNOWN", "ALLOW"):
            problems.append(f"seq {seq}: a launch refused as unresolved after a decision of "
                            f"{r.get('decision_raw')!r}")
        elif rule == "exec_identity_mismatch":
            pass
        elif rule not in EXEC_REFUSALS:
            problems.append(f"seq {seq}: a launch refused with rule {rule!r}, not one the Warden writes")
    allowed = [r for r in launches if r.get("rule") == "exec_allowed"]
    results = meta.get("exec_results", [])
    seen = {}
    for pos, e in results:
        ds = e.get("decision_seq")
        if type(ds) is not int or not 0 <= ds < len(records) or records[ds].get("rule") != "exec_allowed" \
                or pos <= ds or e.get("result") not in EXEC_RESULTS:
            problems.append(f"an exec_result for seq {ds!r} that is not after an allowed launch, or says "
                            f"{e.get('result')!r}")
            continue
        seen[ds] = seen.get(ds, 0) + 1
    for r in allowed:
        n = seen.get(r.get("seq"), 0)
        if n > 1 or (complete and n == 0):
            problems.append(f"seq {r.get('seq')}: an allowed launch with {n} exec_result records, not one")
    mism = [r for r in records if r.get("rule") == "exec_identity_mismatch"]
    # v1.31 review: a confined subject whose own environment names code is
    # killed at its first call (its launcher changed it after the decision)
    envk = [r for r in records if r.get("rule") == "subagent_env" and r.get("action") != "process.exec"]
    killed = sum(1 for _, e in results if e.get("result") == "killed")    # review finding 2
    if killed and not mism and not envk:
        problems.append(f"{killed} exec_result records say killed, but no process was killed by the "
                        f"identity check")
    re_ = meta.get("run_end")
    flag = isinstance(re_, dict) and re_.get("exec_identity_mismatch") is True
    if complete and bool(mism) != flag:
        problems.append("run_end's exec_identity_mismatch does not match the records")
    for r in envk:
        if r.get("decision_final") != "DENY":
            problems.append(f"seq {r.get('seq')}: a subagent_env record that is not a refusal")
        problems.append(f"seq {r.get('seq')}: pid {r.get('agent_pid')} was launched as a confined subject with "
                        f"{r.get('env')!r} set (it names code), after its launch was decided; it was killed")
        later = [x for x in records[r["seq"] + 1:] if x.get("agent_pid") == r.get("agent_pid")
                 and x.get("decision_final") == "ALLOW"] if type(r.get("seq")) is int else []
        if later:
            problems.append(f"seq {later[0].get('seq')}: pid {r.get('agent_pid')} was allowed a call after "
                            f"it was killed")
    for r in mism:
        problems.append(f"seq {r.get('seq')}: pid {r.get('agent_pid')} ran {r.get('exe')!r}, not a program "
                        f"the Warden decided to run; it was killed (exec_identity_mismatch)")
        later = [x for x in records[r["seq"] + 1:] if x.get("agent_pid") == r.get("agent_pid")
                 and x.get("decision_final") == "ALLOW"] if type(r.get("seq")) is int else []
        if later:
            problems.append(f"seq {later[0].get('seq')}: pid {r.get('agent_pid')} was allowed a call after "
                            f"it was killed")
    return len(allowed), len(refused)


def policy_inspect(checker, policy):
    """v1.26.1: the policy's passthrough hosts (a list) in inspecting mode,
    or None when the policy does not turn inspecting mode on."""
    rq = subprocess.run([checker, policy, "proxy"], capture_output=True, text=True)
    f = rq.stdout.split()
    if rq.returncode != 0 or not f or f[0] != "inspect":
        return None
    return f[f.index("passthrough") + 1:] if "passthrough" in f else []


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
                      "resolution_failed", "address_refused", "run_ended", "revoked")   # v1.28: revoked
# v1.26 (step 6): the Warden's decision on what the proxy read, when it allowed
PROXY_ALLOW_RULES = ("proxy_dialed", "proxy_dial_failed")
PROXY_KINDS = ("tls", "http", "connect")
CLOSE_WHY = ("closed", "reset", "idle", "run_end", "unreported", "upstream_refused",
             "refused_request", "client_gone",       # v1.26 review: the last two
             "revoked")                              # v1.28 step 4
# v1.26.1 (step 4): an inspected connection's own reasons
TLS_CLOSE_WHY = ("server_tls", "client_tls", "tls_timeout", "max_body")   # step 6: max_body


HEX64 = re.compile(r"[0-9a-f]{64}")


def trust_names(rules, proxy_ports, passthrough):
    """v1.26.1 review: the names the run's CA may sign for, as the Warden's
    trust_names takes them: each allow host name rule's name (a wildcard's
    suffix) reachable on a proxied port, once each, without the passthrough
    hosts (named exactly)."""
    out = []
    for r in rules:
        if r["kind"] != "h" or not r["allow"] or not r["name"]:
            continue
        c = r["c"]
        if r["wild"]:
            head, colon, port = c.rpartition(":")
            if not colon or not head.startswith("?*."):
                continue
            name = head[3:]
        else:
            name, colon, port = c.partition(":")
        if colon and port != "*" and not (port.isdigit() and int(port) in (proxy_ports or [])):
            continue
        if (not r["wild"] and name in (passthrough or [])) or name in out:
            continue
        out.append(name)
    return out


def check_trust(meta, passthrough, problems, rules=(), proxy_ports=None):
    """v1.26.1 (step 3): in inspecting mode run_start records the trust the
    agent was given: the host's bundle and its hash, the run's CA (the hash of
    its DER) and how many names it may sign for, the trust store's hash,
    whether the CA's key was in locked memory, and the policy's passthrough
    hosts; without inspecting mode, none of it."""
    tr = meta.get("run_start", {}).get("trust")
    if passthrough is None:
        if tr is not None:
            problems.append("run_start records a trust setup, but the policy does not turn inspecting mode on")
        return
    ok = isinstance(tr, dict) and isinstance(tr.get("host_bundle"), str) and tr["host_bundle"].startswith("/") \
        and all(isinstance(tr.get(k), str) and HEX64.fullmatch(tr[k])
                for k in ("host_bundle_sha256", "ca_sha256", "trust_store_sha256")) \
        and type(tr.get("host_roots")) is int and tr["host_roots"] > 0 \
        and type(tr.get("ca_names")) is int and tr["ca_names"] >= 0 \
        and type(tr.get("ca_key_locked")) is bool and tr.get("passthrough") == passthrough
    if not ok:
        problems.append(f"run_start's trust {tr!r} is not inspecting mode's (the host's bundle, the "
                        f"run's CA, the trust store, passthrough {passthrough})")
    elif rules and tr["ca_names"] != len(trust_names(rules, proxy_ports, passthrough)):
        problems.append(f"run_start's CA may sign for {tr['ca_names']} name(s), but the policy gives it "
                        f"{len(trust_names(rules, proxy_ports, passthrough))}")


def _inspecting(meta):
    """run_start's proxy is in inspecting mode (review: no crash on a malformed one)."""
    pr = meta.get("run_start", {}).get("proxy")
    return isinstance(pr, dict) and pr.get("mode") == "inspect"


def check_proxy_start(meta, proxy_ports, problems, upstream=None, inspect=False):
    """v1.26 (step 8): with `proxy on` the Warden runs only with its proxy, so
    run_start names it: SNI mode, its listener on 127.0.0.1, an unprivileged
    user, and the policy's proxied ports; without `proxy on`, no proxy."""
    pr = meta.get("run_start", {}).get("proxy")
    # v1.26.1: and the SHA-256 of the warden-proxy that ran, exactly with it
    sha = meta.get("run_start", {}).get("proxy_binary_sha256")
    if proxy_ports is None:
        if pr is not None:
            problems.append("run_start names a proxy, but the policy does not turn it on")
        if sha is not None:
            problems.append("run_start names a proxy binary, but the policy does not turn the proxy on")
        return
    if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
        problems.append(f"run_start's proxy_binary_sha256 {sha!r} is not a SHA-256")
    lst = pr.get("listen") if isinstance(pr, dict) else None
    if not isinstance(pr, dict) or pr.get("mode") != ("inspect" if inspect else "sni") or not isinstance(lst, str) or \
            not lst.startswith("127.0.0.1:") or _host_port(lst) in (None, 0) or \
            type(pr.get("uid")) is not int or type(pr.get("gid")) is not int or \
            pr.get("uid") == 0 or pr.get("gid") == 0 or pr.get("ports") != proxy_ports or \
            pr.get("upstream") != upstream:
        problems.append(f"run_start's proxy {pr!r} is not the policy's ({'inspecting' if inspect else 'SNI'} "
                        f"mode, an unprivileged user, ports {proxy_ports})")


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


def policy_credentials(checker, policy):
    """v1.28: the policy's credentials [(name, store, ref)] and the request
    rules that carry one {policy line: (name, header, scheme or None)}, as
    the checker reads them; v1.31: and the MCP tokens' audiences {name:
    (URL, opaque)}."""
    q = subprocess.run([checker, policy, "credentials"], capture_output=True, text=True)
    if q.returncode != 0:
        raise ValueError(q.stderr.strip() or "the checker has no credentials mode")
    creds, rules, auds = [], {}, {}
    for line in q.stdout.splitlines():
        f = line.split(" ")
        if len(f) == 4 and f[0] == "credential":
            creds.append((f[1], f[2], f[3]))
        elif len(f) == 5 and f[0] == "rule" and f[1].isdigit():
            rules[int(f[1])] = (f[2], f[3], None if f[4] == "-" else f[4])
        elif len(f) == 4 and f[0] == "audience":
            auds[f[1]] = (f[2], f[3] == "opaque")     # v1.31: an MCP access token's audience
        elif line.strip():
            raise ValueError(f"an unexpected line from the checker: {line!r}")
    return creds, rules, auds


def policy_identity(checker, policy):
    """v1.28.1: the policy's trusted issuers {iss: (aud, jwks or None)}, trust
    domains {domain: bundle}, sub-agent rules {policy line: name} and
    whether it requires a user, as the checker reads them; v1.31: and the
    MCP resources trusted for the user's token {url: (aud or None, line)}."""
    q = subprocess.run([checker, policy, "identity"], capture_output=True, text=True)
    if q.returncode != 0:
        raise ValueError(q.stderr.strip() or "the checker has no identity mode")
    iss, dom, sub, req, mres = {}, {}, {}, False, {}
    for line in q.stdout.splitlines():
        f = line.split(" ")
        if len(f) == 4 and f[0] == "issuer":
            iss[f[1]] = (f[2], None if f[3] == "-" else f[3])
        elif len(f) == 3 and f[0] == "spiffe":
            dom[f[1]] = f[2]
        elif len(f) == 3 and f[0] == "subagent" and f[1].isdigit():
            sub[int(f[1])] = f[2]
        elif line == "require on-behalf-of":
            req = True
        elif f[0] == "mcp-resource" and len(f) == 3:                  # v1.31
            mres[f[1]] = None if f[2] == "-" else f[2]
        elif f[0] in ("confined", "for") and len(f) in (3, 6):
            pass                                   # v1.31: policy_confined reads them
        elif line.strip():
            raise ValueError(f"an unexpected line from the checker: {line!r}")
    return iss, dom, sub, req, mres


def policy_confined(checker, policy):
    """v1.31: the policy's confined subjects {name: subject number}, as the
    checker reads them (`identity`: "confined K NAME mcp|subagent LINE SHA"),
    and the subject each rule is for {policy line: subject number} ("for LINE
    K"; a rule not listed is the agent's, 0)."""
    q = subprocess.run([checker, policy, "identity"], capture_output=True, text=True)
    if q.returncode != 0:
        raise ValueError(q.stderr.strip() or "the checker has no identity mode")
    out, forl = {}, {}
    for line in q.stdout.splitlines():
        f = line.split(" ")
        if len(f) == 6 and f[0] == "confined" and f[1].isdigit():
            out[f[2]] = int(f[1])
        elif len(f) == 3 and f[0] == "for" and f[1].isdigit() and f[2].isdigit():
            forl[int(f[1])] = int(f[2])
    return out, forl


def expected_subject(obo, confined):
    """v1.31: the subject a decision for this chain is made as: the
    innermost sub-agent in it that is confined, else the agent (0). (The
    Warden's attribution: a sub-agent's subject is the one its launch rule
    declares, else its launcher's.)"""
    k = 0
    for t in obo if isinstance(obo, list) else []:
        m = SUBAGENT_TAG.fullmatch(t) if isinstance(t, str) else None
        if m and m.group(1) in confined:
            k = confined[m.group(1)]
    return k


SUBAGENT_TAG = re.compile(r"subagent:([a-z][a-z0-9_]{0,31})#([1-9][0-9]{0,9})")


def check_subjects(records, confined, forl, problems):
    """v1.31 (section 6): each decision that names a policy line names a
    rule of the subject it was made for: a confined subject's decisions only
    its own `for=` rules, the agent's (and an unconfined sub-agent's) only
    rules without one. The subject is the record's chain's (the Warden's
    attribution), the rule's the policy's, as the checker reads it."""
    for rec in records:
        line = rec.get("policy_line")
        if "decision_final" not in rec:
            continue
        if type(line) is not int:
            # v1.31 review: a line given as a string or a float would pass the check below unseen
            problems.append(f"seq {rec.get('seq')}: a decision whose policy_line {line!r} is not an integer")
            continue
        if line <= 0:
            continue
        ks = expected_subject(rec.get("obo"), confined)
        kr = forl.get(line, 0)
        if ks != kr:
            problems.append(f"seq {rec.get('seq')}: a decision for subject {ks} (its chain {rec.get('obo')!r}) "
                            f"cites policy line {line}, a rule for subject {kr}: "
                            f"{'a server' if ks else 'the agent'} is decided by its own rules only")


# v1.31 (section 6): a JWT in compact form, as an MCP or user token is
# (v1.31 review: its JSON may start "{ ", "{\n", "{\r" or "{\t", and a JWE has five parts)
_B64_OBJ = r"(?:eyJ|eyA|ewo|ew0|ewk)[A-Za-z0-9_-]{6,}"
JWT_RX = re.compile(_B64_OBJ + r"\." + _B64_OBJ + r"\.[A-Za-z0-9_-]*|" +
                    _B64_OBJ + r"\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
# fields that hold what the agent sent (its paths, requests, MCP calls and
# names), where a token the agent itself chose to send is its own business
AGENT_FIELDS = ("target", "resolved", "mcp_name", "mcp_url", "rpc_id", "traceparent", "mcp_error", "name",
                "exe", "request_error", "tls_error", "why")


def check_token_values(path, run, problems):
    """v1.31 (section 6): no token value anywhere the Warden or its helpers
    write: no JWT in any record of the run outside the fields that echo what
    the agent sent. (The values the run holds are never written: a
    credential is recorded by its placeholder's SHA-256, the user's token
    by its SHA-256.)"""
    def walk(v, key, top, where):
        if isinstance(v, dict):
            for k, x in v.items():
                walk(x, k, False, where)
        elif isinstance(v, list):
            for x in v:
                walk(x, key, False, where)
        elif isinstance(v, str) and not (top and key in AGENT_FIELDS) and JWT_RX.search(v):
            problems.append(f"{where}: a token value in the stream (field {key!r})")
    try:
        fh = open(path, encoding="utf-8", errors="surrogateescape", newline="\n")
    except OSError:
        return
    with fh:
        for i, raw in enumerate(fh, 1):
            if not raw.startswith("{"):
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(rec, dict) or rec.get("run") != run:
                continue
            # v1.31 review: only a decision (or a DNS question) echoes what the
            # agent sent; the Warden's other records are its own words
            echo = "decision_final" in rec or rec.get("event") == "dns_question"
            for k, x in rec.items():
                walk(x, k, echo, f"line {i}")
JWT_ALGS = ("RS256", "PS256", "ES256", "EdDSA")


def check_chain(ident, meta, records, run, problems):
    """v1.28.1 (section 5): who each decision was for. run_start's
    on_behalf_of: a user only verified by an issuer the policy trusts, with
    its audience, not expired at the start (and one if the policy requires
    it); an agent of this run, its SPIFFE ID verified in a trust domain the
    policy trusts, its control group when the policy names a sub-agent; the
    operator, unverified. Every decision record's obo resolves: "user" only
    with a user, then "agent", then each sub-agent after the launch that
    started it (by a rule with that subagent=, from the chain before it),
    never after its launch failed; the proxy's records are their hand-off's.
    Returns {sub-agent: decisions}, or None when the Warden predates the
    chain."""
    iss, dom, subrules, req, mres = ident
    rs = meta.get("run_start", {})
    if not _version_at_least(rs.get("warden"), (1, 28, 1)):
        if "on_behalf_of" in rs or any("obo" in r for r in records):
            problems.append("run_start or a record names who a decision was for, but only a Warden of 1.28.1 "
                            "or later records it")
        if req or subrules or iss or dom:
            problems.append("the policy trusts an issuer or a trust domain, requires a user or names a "
                            "sub-agent, which only a Warden of 1.28.1 or later reads")
        return None
    obo = rs.get("on_behalf_of")
    if not isinstance(obo, dict) or not isinstance(obo.get("agent"), dict) or obo["agent"].get("run") != run:
        problems.append("run_start has no on_behalf_of naming this run's agent")
        return {}
    user, agent, actors = obo.get("user"), obo["agent"], obo.get("actors")
    if user is not None:
        if not isinstance(user, dict):
            problems.append("run_start's user is not an object")
            user = {}
        i, mr = user.get("issuer"), user.get("mcp_resource")
        if mr is not None:
            # v1.31: an issuer found through a trusted MCP resource (the
            # discovery is the helper's; what it found is checked against the
            # policy's line): the line's audience, or its URL as written
            if not isinstance(mr, str) or mr not in mres:
                problems.append(f"run_start's user was found through MCP resource {mr!r}, which the policy "
                                f"does not trust")
            elif not (isinstance(i, str) and i.startswith("https://")):
                problems.append(f"run_start's user's issuer {i!r}, found through {mr}, is not an https URL")
            elif user.get("audience") != (mres[mr] or mr):
                problems.append(f"run_start's user has the audience {user.get('audience')!r}, not the one "
                                f"trust mcp-resource {mr} names")
        elif not isinstance(i, str) or i not in iss:
            problems.append(f"run_start's user is vouched for by {i!r}, an issuer the policy does not trust")
        elif user.get("audience") != iss[i][0]:
            problems.append(f"run_start's user has the audience {user.get('audience')!r}, not the one the policy "
                            f"names for {i}")
        if user.get("verified") is not True:
            problems.append("run_start's user is not marked verified")
        if not (isinstance(user.get("subject"), str) and user["subject"]):
            problems.append("run_start's user has no subject")
        if user.get("algorithm") not in JWT_ALGS:
            problems.append(f"run_start's user was verified with {user.get('algorithm')!r}, not one of "
                            f"{', '.join(JWT_ALGS)}")
        if not (isinstance(user.get("token_sha256"), str) and HEX64.fullmatch(user["token_sha256"])):
            problems.append("run_start's user has no token SHA-256")
        t0, exp = rs.get("timestamp_ns"), user.get("expires")
        if type(exp) is not int or type(t0) is not int or exp * 1000000000 <= t0:
            problems.append("run_start's user's token had expired when the run started (or has no expiry)")
        if user.get("on_expiry", "revoke") not in ("revoke", "record"):
            problems.append(f"run_start's user says {user.get('on_expiry')!r} on expiry, not revoke or record")
        if actors is not None and not (isinstance(actors, list) and 0 < len(actors) <= 8 and
                                       all(isinstance(a_, dict) and isinstance(a_.get("subject"), str)
                                           and a_["subject"] for a_ in actors)):
            problems.append("run_start's actors are not a list of 1 to 8, each with a subject")
    elif req:
        problems.append("the policy requires on-behalf-of, but run_start names no user")
    elif actors is not None:
        problems.append("run_start lists actors, but no user")
    if "spiffe_id" in agent:
        d = agent.get("trust_domain")
        if not isinstance(d, str) or d not in dom:
            problems.append(f"the agent's SVID is in {d!r}, a trust domain the policy does not trust")
        elif not (isinstance(agent["spiffe_id"], str) and agent["spiffe_id"].startswith(f"spiffe://{d}/")):
            problems.append("the agent's SPIFFE ID is not in its trust domain")
        if agent.get("verified") is not True or not (isinstance(agent.get("svid_sha256"), str)
                                                       and HEX64.fullmatch(agent["svid_sha256"])):
            problems.append("the agent's SVID is not marked verified, or has no SHA-256")
    cg = agent.get("cgroup")
    if bool(subrules) != isinstance(cg, str):
        problems.append("run_start's agent names a control group, but the policy names no sub-agent" if cg else
                        "the policy names a sub-agent, but run_start's agent has no control group")
    op = rs.get("operator")
    if not (isinstance(op, dict) and type(op.get("uid")) is int and op.get("verified") is False):
        problems.append("run_start has no operator (its uid, marked not verified)")
    # each record's chain
    base = ["user", "agent"] if user is not None else ["agent"]
    lines = meta.get("lineno", {})
    at = lambda r: lines.get(id(r), 0)
    started = {}                     # "NAME#n" -> (line of its launch record, the launcher's chain, cgroup)
    # v1.28.1 review: how each launch settled (subagent_settled, once, after
    # its launch); a decision for a sub-agent only after it settled launched
    settled = {}                     # "NAME#n" -> (line, "launched" | "failed")
    for _, e in meta.get("subagent_events", []):
        tag = e.get("subagent")
        if not isinstance(tag, str) or e.get("result") not in ("launched", "failed") or tag in settled:
            problems.append(f"a subagent_settled event that is malformed, or a second for {tag!r}")
            continue
        settled[tag] = (at(e), e["result"])
    count, per_name, conn_obo = {}, {}, {}
    for r in sorted(records, key=at):
        ob = r.get("obo")
        seq = r.get("seq")
        if r.get("rule") == "subagent_unattributed":
            if ob != [] or r.get("decision_final") != "DENY":
                problems.append(f"seq {seq}: refused as in no group of the run, but not with an empty obo")
            continue
        # v1.28.1 review: a call refused because its thread had gone, whose
        # group could not be read either
        if ob == [] and r.get("decision_final") == "DENY" and \
                r.get("rule") in ("intent_derivation_failed", "exec_identity_unreadable", "exec_identity_mismatch"):
            continue
        if not (isinstance(ob, list) and all(isinstance(x, str) for x in ob) and ob[:len(base)] == base):
            problems.append(f"seq {seq}: obo {ob!r} does not begin with {base!r}")
            continue
        chain = ob[len(base):]
        tags = []
        for k, x in enumerate(chain):
            m = SUBAGENT_TAG.fullmatch(x)
            if not m:
                problems.append(f"seq {seq}: obo names {x!r}, not a sub-agent")
                break
            tag = f"{m.group(1)}#{m.group(2)}"
            st = started.get(tag)
            if st is None or st[0] > at(r):
                problems.append(f"seq {seq}: a decision for sub-agent {tag} before (or without) a launch that "
                                f"started it")
                break
            if st[1] != ob[:len(base) + k]:
                problems.append(f"seq {seq}: sub-agent {tag} in a chain other than the one that launched it")
                break
            se = settled.get(tag)
            if se is None or se[0] > at(r):
                problems.append(f"seq {seq}: a decision for sub-agent {tag} before its launch is known to have "
                                f"happened (subagent_settled)")
                break
            if se[1] != "launched":
                problems.append(f"seq {seq}: a decision for sub-agent {tag} after its launch failed")
                break
            tags.append(tag)
        else:
            if tags:
                count[tags[-1]] = count.get(tags[-1], 0) + 1
        if r.get("rule") in SUBAGENT_REFUSALS and not subrules.get(r.get("policy_line")):
            problems.append(f"seq {seq}: a launch refused as {r.get('rule')!r}, but policy line "
                            f"{r.get('policy_line')} names no sub-agent")
        # a sub-agent's launch: by a rule with that subagent=, numbered in order
        if "subagent" in r:
            tag, line = r.get("subagent"), r.get("policy_line")
            m = SUBAGENT_TAG.fullmatch(f"subagent:{tag}") if isinstance(tag, str) else None
            if not (r.get("action") == "process.exec" and r.get("rule") == "exec_allowed" and m):
                problems.append(f"seq {seq}: names a sub-agent {tag!r}, but is not an allowed launch")
            elif subrules.get(line) != m.group(1):
                problems.append(f"seq {seq}: starts sub-agent {tag}, but policy line {line} names "
                                f"{subrules.get(line) or 'no sub-agent'}")
            elif int(m.group(2)) != per_name.get(m.group(1), 0) + 1 or tag in started:
                problems.append(f"seq {seq}: sub-agent {tag} is not the next launch of {m.group(1)}")
            else:
                per_name[m.group(1)] = int(m.group(2))
                want = (cg or "") + "".join("/" + t.replace("#", "-") for t in tags + [tag])
                if r.get("cgroup") != want:
                    problems.append(f"seq {seq}: sub-agent {tag}'s control group is {r.get('cgroup')!r}, not {want!r}")
                started[tag] = (at(r), ob, r.get("cgroup"))
                count.setdefault(tag, 0)
        elif r.get("action") == "process.exec" and r.get("rule") == "exec_allowed" and subrules.get(r.get("policy_line")):
            problems.append(f"seq {seq}: a launch allowed by policy line {r.get('policy_line')}, which names "
                            f"sub-agent {subrules[r.get('policy_line')]}, started none")
        # the proxy's records are for whom the hand-off was
        if r.get("proxy_handoff") is True and type(r.get("proxy_conn")) is int:
            conn_obo[r["proxy_conn"]] = ob
        elif r.get("action") in ("net.proxy", "net.request", "net.mcp") and type(r.get("proxy_conn")) is int:
            want = conn_obo.get(r["proxy_conn"])
            if want is not None and ob != want:
                problems.append(f"seq {seq}: the proxy's decision on connection {r['proxy_conn']} is for {ob!r}, "
                                f"not {want!r}, whom the agent's connect was for")
    # each launch's exec_result is its own: the sub-agent its launch record
    # names (by decision_seq), and, once settled, the same outcome
    by_seq = {r.get("seq"): r for r in records}
    for _, e in meta.get("exec_results", []):
        tag = e.get("subagent")
        launch = by_seq.get(e.get("decision_seq"))
        want = launch.get("subagent") if isinstance(launch, dict) else None
        if tag != want:
            problems.append(f"an exec_result for the launch at seq {e.get('decision_seq')} names sub-agent "
                            f"{tag!r}, but that launch started {want!r}")
        elif tag is not None and tag in settled and e.get("result") in ("launched", "failed") \
                and e["result"] != settled[tag][1]:
            problems.append(f"sub-agent {tag}'s exec_result says {e['result']}, but it settled {settled[tag][1]}")
    for tag, (line, _) in settled.items():
        if tag not in started or started[tag][0] > line:
            problems.append(f"sub-agent {tag} settled, but no launch started it before")
    return count


def check_credentials(creds, cred_rules, meta, records, complete, problems, notes, auds=None):
    """v1.28 (section 5): run_start lists the policy's credentials (name,
    store, reference, in order; a version, a length, a placeholder's SHA-256;
    the helper's SHA-256), and none when the policy names none. Every
    request that carried a credential was allowed by a rule that names that
    credential and header, and every request such a rule allowed carried it;
    each refused swap follows the allowed request it refused. After
    `revoked` (by root, once) every decision is UNSATISFIED; the proxy's and
    the helper's answers follow it, the proxy holding no value; no lease is
    renewed after the helper revoked them. Returns (carried, swaps refused,
    revoked)."""
    rs = meta.get("run_start", {})
    listed = rs.get("credentials")
    names = {c[0]: c for c in creds}
    if not creds:
        # v1.28.1: the helper also runs to verify the user's token or the
        # agent's SVID, and is then recorded without credentials
        obo = rs.get("on_behalf_of") if isinstance(rs.get("on_behalf_of"), dict) else {}
        verified = "user" in obo or (isinstance(obo.get("agent"), dict) and "spiffe_id" in obo["agent"])
        if listed is not None or ("secrets_binary_sha256" in rs and not verified):
            problems.append("run_start lists credentials, but the policy names none")
    elif not isinstance(listed, list) or len(listed) != len(creds):
        problems.append(f"run_start does not list the policy's {len(creds)} credential(s)")
    else:
        if not (isinstance(rs.get("secrets_binary_sha256"), str) and HEX64.fullmatch(rs["secrets_binary_sha256"])):
            problems.append("run_start has credentials but not warden-secrets' SHA-256")
        seen_ph = set()
        for c, e in zip(creds, listed):
            if not isinstance(e, dict) or (e.get("name"), e.get("store"), e.get("ref")) != c:
                problems.append(f"run_start's credentials are not the policy's (at {c[0]})")
                break
            ph = e.get("placeholder_sha256")
            ln = e.get("length")
            if not (isinstance(e.get("version"), str) and e["version"] and isinstance(e.get("policy_line"), int)
                    and type(ln) is int and 1 <= ln <= 8192 and isinstance(ph, str) and HEX64.fullmatch(ph)
                    and ph not in seen_ph):
                problems.append(f"run_start's credential {c[0]} without a version, a length, its policy "
                                f"line or a placeholder's SHA-256 of its own")
                break
            seen_ph.add(ph)
            # v1.31: an MCP token says its server; a JWT one, its expiry
            # (in the future when the run started), an opaque one, opaque
            aud = (auds or {}).get(c[0])
            t0 = rs.get("timestamp_ns")
            if aud is None:
                if any(k in e for k in ("audience", "opaque", "expires")):
                    problems.append(f"run_start's credential {c[0]} is listed as an MCP token, which its line "
                                    f"does not say")
            elif e.get("audience") != aud[0] or (e.get("opaque") is True) != aud[1]:
                problems.append(f"run_start's credential {c[0]} is listed for another server than its line's "
                                f"{aud[0]}, or opaque where its line is not (or the reverse)")
            elif not aud[1] and not (type(e.get("expires")) is int and type(t0) is int and
                                     e["expires"] * 1000000000 > t0):
                problems.append(f"run_start's MCP token {c[0]} has no expiry, or had expired when the run started")
            elif aud[1] and "expires" in e:
                problems.append(f"run_start's opaque MCP token {c[0]} is listed with an expiry")
    # v1.28 review: ordered by each record's line in the stream, not by the
    # number of decisions before it (an event right next to the record it
    # must follow has the same count)
    lines = meta.get("lineno", {})
    at = lambda r: lines.get(id(r), 0)
    events = sorted((e for _, e in meta.get("cred_events", [])), key=at)
    rv = [e for e in events if e.get("event") == "revoked"]
    rline = at(rv[0]) if rv else None
    if len(rv) > 1:
        problems.append("the run is recorded revoked more than once")
    # v1.28.1 step 4: the user's token's expiry. Once at most, for the user
    # run_start names, at or after its expiry, doing what run_start says; a
    # revocation it makes follows it (unless the run was revoked already).
    ex = [e for e in events if e.get("event") == "on_behalf_of_expired"]
    obo = rs.get("on_behalf_of") if isinstance(rs.get("on_behalf_of"), dict) else {}
    user = obo.get("user") if isinstance(obo.get("user"), dict) else None
    if len(ex) > 1:
        problems.append("the user's token is recorded expired more than once")
    if ex:
        e = ex[0]
        if user is None:
            problems.append("on_behalf_of_expired, but run_start names no user")
        elif e.get("expires") != user.get("expires") or e.get("subject") != user.get("subject") \
                or e.get("action") != user.get("on_expiry", "revoke"):
            problems.append("on_behalf_of_expired does not match the user run_start names (subject, expiry, "
                            "what is done)")
        elif type(e.get("timestamp_ns")) is not int or type(user.get("expires")) is not int \
                or e["timestamp_ns"] < user["expires"] * 1000000000:
            problems.append("on_behalf_of_expired is recorded before the token expired")
    by_expiry = bool(rv) and rv[0].get("by") == "on_behalf_of_expiry"
    if rv and by_expiry:
        if not ex or ex[0].get("action") != "revoke" or at(ex[0]) > rline:
            problems.append("the run is recorded revoked for the user's token's expiry, but no expiry that "
                            "revokes is recorded before it")
    elif rv and not (rv[0].get("by_uid") == 0 and type(rv[0].get("by_pid")) is int and rv[0]["by_pid"] > 0):
        problems.append("the run is recorded revoked by a peer that is not root, or without who asked")
    if ex and ex[0].get("action") == "revoke" and not rv:
        problems.append("the user's token expired and the run should have been revoked, but no revocation "
                        "is recorded")
    # v1.28.1 review: the records are in time order (1 s of slack for the
    # clock); the expiry is recorded as soon as the token expired, its
    # revocation next, with nothing between; nothing is allowed after the
    # expiry unless it says the run goes on; and a stream, whole or not,
    # that runs past the expiry records it
    stamped = sorted((at(x), x["timestamp_ns"]) for x in list(records) + events +
                     [e for _, e in meta.get("exec_results", [])] + [e for _, e in meta.get("subagent_events", [])]
                     if type(x.get("timestamp_ns")) is int)
    for (l1, t1), (l2, t2) in zip(stamped, stamped[1:]):
        if t2 < t1 - 1000000000:
            problems.append(f"line {l2}: a record timestamped before the one before it (the stream is not in "
                            f"time order)")
            break
    exp_ns = user["expires"] * 1000000000 if user is not None and type(user.get("expires")) is int else None
    if ex and rv and by_expiry:
        between = [x for x in list(records) + events if at(ex[0]) < at(x) < rline]
        if between:
            problems.append("records between the token's expiry and the revocation it made (it is made at once)")
    if exp_ns is not None:
        goes_on = ex and ex[0].get("action") == "record"
        for rec in records:
            if rec.get("decision_final") == "ALLOW" and type(rec.get("timestamp_ns")) is int \
                    and rec["timestamp_ns"] > exp_ns + 2000000000 and not (goes_on and at(rec) > at(ex[0])):
                problems.append(f"seq {rec.get('seq')}: allowed after the user's token expired, with no expiry "
                                f"recorded before it that lets the run go on")
                break
        last = max((t for _, t in stamped), default=None)
        if not ex and last is not None and last > exp_ns + 2000000000:
            problems.append("the user's token expired during the run, but its expiry is not recorded "
                            "(on_behalf_of_expired)")
    carried = 0
    allowed_with = {}                # (proxy_conn, request_seq) -> (credential, line)
    after = lambda r: rline is not None and at(r) > rline
    for rec in records:
        if after(rec) and rec.get("decision_final") != "DENY":
            problems.append(f"seq {rec.get('seq')}: a decision {rec.get('decision_final')!r} after the run was "
                            f"revoked (every decision after it is UNSATISFIED)")
            continue
        # v1.28 review: a refusal for the revocation follows it
        if rec.get("rule") == "revoked" and not after(rec):
            problems.append(f"seq {rec.get('seq')}: refused as revoked, but no revocation is recorded before it")
            continue
        if rec.get("action") not in ("net.request", "net.mcp"):          # v1.31: an MCP call too
            continue
        has = "credential" in rec or "credential_header" in rec
        allowed = rec.get("decision_final") == "ALLOW" and \
            rec.get("rule") == ("mcp_allowed" if rec.get("action") == "net.mcp" else "request_allowed")
        want = cred_rules.get(rec.get("policy_line")) if allowed else None
        if has:
            if not allowed or want is None or (rec.get("credential"), rec.get("credential_header")) != want[:2]:
                problems.append(f"seq {rec.get('seq')}: a request that carried credential "
                                f"{rec.get('credential')!r} in {rec.get('credential_header')!r}, which its "
                                f"deciding rule (line {rec.get('policy_line')!r}) does not name")
                continue
            carried += 1
            # v1.31 (section 6): an MCP token only on an allowed MCP call to its server
            ad = (auds or {}).get(rec.get("credential"))
            if ad is not None and (rec.get("action") != "net.mcp" or rec.get("mcp_url") != ad[0]):
                problems.append(f"seq {rec.get('seq')}: MCP token {rec.get('credential')} (for {ad[0]}) released "
                                f"on {'a call to ' + str(rec.get('mcp_url')) if rec.get('action') == 'net.mcp' else 'a request'}")
                continue
            # v1.31: an MCP token is not released past its expiry
            ex = next((e.get("expires") for e in (rs.get("credentials") if isinstance(rs.get("credentials"), list) else []) if isinstance(e, dict)
                       and e.get("name") == rec.get("credential") and "audience" in e), None)
            if type(ex) is int and type(rec.get("timestamp_ns")) is int and rec["timestamp_ns"] >= (ex + 1) * 1000000000:
                problems.append(f"seq {rec.get('seq')}: MCP token {rec.get('credential')} released after its expiry")
            key = (rec.get("proxy_conn"), rec.get("request_seq"))
            if all(type(k) is int for k in key):
                allowed_with[key] = (rec["credential"], at(rec))
        elif want is not None:
            problems.append(f"seq {rec.get('seq')}: an allowed request whose rule (line {rec.get('policy_line')}) "
                            f"names credential {want[0]}, recorded without it")
    refused_swaps = 0
    rp = rl = None
    failed_renewal = set()
    for e in events:
        ev = e.get("event")
        if ev == "credential_refused":
            key = (e.get("proxy_conn"), e.get("request_seq"))
            got = allowed_with.get(key) if all(type(k) is int for k in key) else None
            if got is None or got[0] != e.get("credential") or got[1] >= at(e) or not isinstance(e.get("why"), str):
                problems.append(f"a credential_refused for connection {key[0]!r} request {key[1]!r} that follows "
                                f"no allowed request carrying {e.get('credential')!r}")
            refused_swaps += 1
        elif ev in ("revocation_proxy", "revocation_leases"):
            if not after(e):
                problems.append(f"{ev} without the run being revoked before it")
                continue
            if ev == "revocation_proxy":
                if rp is not None:
                    problems.append("revocation_proxy recorded more than once")
                rp = e
                if e.get("values_held") != 0:
                    problems.append(f"after the revocation the proxy still held {e.get('values_held')!r} "
                                    f"credential value(s)")
            else:
                if rl is not None:
                    problems.append("revocation_leases recorded more than once")
                rl = at(e)
                if type(e.get("revoked")) is not int or type(e.get("failed")) is not int:
                    problems.append("a malformed revocation_leases record")
                elif e["failed"]:
                    notes.append(f"{e['failed']} Vault lease(s) could not be revoked (they end at their "
                                 f"duration)")
        elif ev in ("lease_renewed", "lease_renewal_failed"):
            c = names.get(e.get("credential"))
            if c is None or c[1] != "vault":
                problems.append(f"{ev} for {e.get('credential')!r}, which is not one of the policy's Vault "
                                f"credentials")
            elif rl is not None and at(e) > rl:
                problems.append(f"{ev} for {c[0]} after the helper revoked the run's leases")
            elif c[0] in failed_renewal:
                problems.append(f"{ev} for {c[0]} after its renewal failed (a failed renewal is not retried)")
            elif ev == "lease_renewed" and type(e.get("ttl")) is not int:
                problems.append(f"lease_renewed for {c[0]} without its new duration")
            elif ev == "lease_renewal_failed":
                failed_renewal.add(c[0])
                notes.append(f"the lease of credential {c[0]} could not be renewed: {e.get('why')}")
    # v1.28 review: the proxy's and the stub's refusals for the revocation
    # follow it, and after it the stub looks nothing up
    for _, c in meta.get("proxy_closes", []):
        if c.get("why") == "revoked" and not after(c):
            problems.append(f"connection {c.get('proxy_conn')!r} closed as revoked, but no revocation is "
                            f"recorded before it")
    for q in meta.get("dns_events", []):
        if q.get("event") == "dns_question" and (q.get("rule") == "revoked") != after(q):
            problems.append(f"a stub question {'refused as revoked before' if q.get('rule') == 'revoked' else 'answered after'} "
                            f"the revocation")
    if rline is not None and complete and creds and rp is None:
        notes.append("the run was revoked, but the proxy never answered that it cleared its values")
    return carried, refused_swaps, rline is not None


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


REQUEST_REFUSE_RULES = ("policy_match", "default_deny_unknown", "certificate_refused", "max_body",
                        "fragment_escape_length", "revoked",       # v1.28: revoked
                        "mcp_query",                               # v1.31: a POST to an MCP endpoint with a query
                        "mcp_endpoint_variant")                    # review: to another spelling of one

# v1.31 (section 3): an MCP call's refusals (net.mcp): by the policy, or a
# call the proxy could not read (mcp_unreadable), whose Mcp-Method or
# Mcp-Name header disagrees with its body (mcp_header_mismatch), or whose
# body is over the limit (max_body)
MCP_REFUSE_RULES = ("policy_match", "default_deny_unknown", "certificate_refused", "max_body",
                    "fragment_escape_length", "revoked", "mcp_unreadable", "mcp_header_mismatch",
                    # step 5: the agent's own bearer token (D6), a credential past its expiry
                    "mcp_token_user", "mcp_token_audience", "mcp_token_expired", "mcp_token_malformed",
                    "credential_expired")
MCP_TOKEN_KINDS = ("placeholder", "jwt", "opaque", "malformed")
MCP_BODY_DEFAULT = 1 << 20                 # an mcp rule without max_body=


def mcp_variant(rules, url):
    """v1.31 review: url is an mcp rule's URL but for ASCII case or a
    trailing '/' (and is not that URL): the Warden refuses a POST to it
    (mcp_endpoint_variant). As warden_pxdecide.inc.c's px_mcp_variant."""
    if mcp_endpoint(rules, url) is not None:
        return False
    key = lambda u: (u[:-1] if u.endswith("/") else u).lower()          # noqa: E731
    return any(r["kind"] == "m" and key(r["c"].split("#", 1)[0]) == key(url) for r in rules)


def mcp_endpoint(rules, url):
    """v1.31: the most of a body the proxy reads for a POST to url, if an mcp
    rule (any subject's) names url, else None. An mcp rule's constant is
    <canonical URL>#<METHOD>#<NAME>."""
    ls = [r["max_body"] or MCP_BODY_DEFAULT for r in rules if r["kind"] == "m" and r["c"].startswith(url + "#")]
    return max(ls) if ls else None


UNRESERVED = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def target_problem(t):
    """v1.26.1 review: why a request's target (/path?query) is one the proxy
    must refuse (section 2: a server could read it as another path), or None.
    As proxy_parse.c's target_ok, written again here."""
    if not t.startswith("/"):
        return "a target that is not a path"
    path, q, query = t.partition("?")
    if "?" in query:
        return "more than one '?'"
    segs = path.split("/")[1:]
    for k, sg in enumerate(segs):
        if sg == "" and k < len(segs) - 1:
            return "an empty path segment ('//')"
        if sg in (".", ".."):
            return "a '.' or '..' path segment"
    for i, ch in enumerate(t):
        c = ord(ch)
        if c < 0x21 or c > 0x7e:
            return "a byte outside 0x21-0x7e"
        if ch in "\\;#":
            return "a '\\', ';' or '#'"
        if ch == "%":
            hx = t[i + 1:i + 3]
            if len(hx) != 2 or any(x not in "0123456789abcdefABCDEF" for x in hx):
                return "a bad percent escape"
            v = int(hx, 16)
            if v in (0x2f, 0x5c) or v in UNRESERVED:
                return "a percent escape of '/', '\\' or an unreserved byte"
    return None


def check_requests(records, bodies, rules, problems, closes=(), order=None):
    """v1.26.1 (step 6): every net.request is a request of a connection passed
    on to be inspected, before its close, numbered 1, 2, ... on it, with none
    after a refusal; its object is METHOD scheme://name:port/... for that
    connection's name and port (https, or http for plain HTTP), in a target
    form the proxy reads one way (review); an allowed one's max_body is its
    deciding rule's, its declared length within it, and one refused for
    max_body declared a longer body. Each allowed request with a body has
    one request_body, after it and before its connection's close: a
    declared length sent whole (or "incomplete": less, the connection
    ended), within max_body unless it says it passed it (then it stopped at
    it). Returns the number of requests.
    order: each record's line in the stream (by id), to put requests,
    bodies and closes in stream order."""
    conns = {}                       # proxy_conn -> (position, name:port, scheme)
    for pos, rec in enumerate(records):
        if rec.get("action") == "net.proxy" and rec.get("rule") == "proxy_dialed" and \
                rec.get("inspected") is True and type(rec.get("proxy_conn")) is int:
            conns.setdefault(rec["proxy_conn"], (pos, rec.get("target"),
                                                  "http" if rec.get("proxy_kind") == "http" else "https"))
    state = {}                       # proxy_conn -> {"next", "refused", "closed", "body": pending or None}
    n = 0
    # requests, bodies and closes in stream order (without the lines, a
    # body's or close's position is the number of decision records before it)
    if order is not None:
        key = lambda x: order.get(id(x), 0)
        events = [(key(r), 1, r) for r in records if r.get("action") in ("net.request", "net.mcp")] + \
                 [(key(b), 0, b) for _, b in bodies] + [(key(c), 2, c) for _, c in closes]
    else:
        events = [(pos, 1, r) for pos, r in enumerate(records) if r.get("action") in ("net.request", "net.mcp")] + \
                 [(bpos - 0.5, 0, b) for bpos, b in bodies]
    pos_of = {id(r): p for p, r in enumerate(records)}
    for _, what, rec in sorted(events, key=lambda e: (e[0], e[1])):
        cid = rec.get("proxy_conn")
        if type(cid) is not int:
            problems.append(f"a {'net.request' if what == 1 else rec.get('event')} record with a malformed "
                            f"connection id {cid!r}")
            continue
        if what == 2:                                   # a close
            st = state.get(cid)
            if st and st["body"] is not None and rec.get("why") != "unreported":
                problems.append(f"connection {cid}: closed with the body of request {st['body'][0]} never "
                                f"recorded (a request_body is missing)")
            if st:
                st["closed"] = True
            else:
                state[cid] = {"next": 1, "refused": False, "closed": True, "body": None}
            continue
        if what == 0:                                   # a body
            b = rec
            rs = b.get("request_seq")
            st = state.get(cid)
            if st and st["closed"]:
                problems.append(f"connection {cid}: a request_body after the connection's close")
                continue
            if not st or st["body"] is None or st["body"][0] != rs:
                problems.append(f"a request_body for connection {cid!r} request {rs!r}, which has no body pending")
                continue
            _, mb, kind, decl = st["body"]
            ln, exc, inc = b.get("body_len"), b.get("exceeded_max_body") is True, b.get("incomplete") is True
            if type(ln) is not int or ln < 0 or \
                    not (isinstance(b.get("body_sha256"), str) and HEX64.fullmatch(b["body_sha256"])):
                problems.append(f"connection {cid}: a request_body without a length and a SHA-256")
            elif exc and (inc or kind != "chunked" or not (mb and ln == mb)):
                problems.append(f"connection {cid}: a body said to pass max_body, at {ln}, not a chunked body "
                                f"stopped at the rule's {mb}")
            elif not exc and mb and ln > mb:
                problems.append(f"connection {cid}: a body of {ln} bytes, over its rule's max_body={mb}")
            elif kind == "length" and not exc and (ln >= decl if inc else ln != decl):
                problems.append(f"connection {cid}: a body of {ln} bytes, where its request declared {decl}"
                                + (" (said incomplete)" if inc else ""))
            st["body"] = None
            if exc:
                st["cut"] = True                         # review: the connection was cut there
            continue
        n += 1
        seq, rs = rec.get("seq"), rec.get("request_seq")
        if cid not in conns or conns[cid][0] >= pos_of.get(id(rec), -1):
            problems.append(f"seq {seq}: a request of connection {cid!r}, which was not passed on to be inspected")
            continue
        st = state.setdefault(cid, {"next": 1, "refused": False, "closed": False, "body": None})
        if st["closed"]:
            problems.append(f"seq {seq}: a request of connection {cid} after its close")
            continue
        if st["refused"]:
            problems.append(f"seq {seq}: a request of connection {cid} after one was refused")
            continue
        if st.get("cut"):
            problems.append(f"seq {seq}: a request of connection {cid} after its body passed max_body (it was cut)")
            continue
        if rs != st["next"] or st["body"] is not None:
            problems.append(f"seq {seq}: request {rs!r} of connection {cid} out of order, or before the last body")
            continue
        st["next"] += 1
        if rec.get("action") == "net.mcp":                 # v1.31
            check_mcp_call(rec, rules, st, conns[cid], problems)
            continue
        obj, (_, hp, scheme) = rec.get("target"), conns[cid]
        m = re.fullmatch(r"([A-Z]{1,20}) " + re.escape(f"{scheme}://{hp}") + r"(/[\x21-\x7e]*)", str(obj))
        if not m or obj != rec.get("resolved") or rec.get("body") not in ("none", "length", "chunked"):
            problems.append(f"seq {seq}: a request object {obj!r} that is not one of connection {cid} ({scheme}://{hp})")
            continue
        bad = target_problem(m.group(2))
        if bad:
            problems.append(f"seq {seq}: a request object {obj!r} with {bad}, which the proxy must refuse")
            continue
        # v1.31: every POST to an MCP endpoint is an MCP call (net.mcp); one
        # with a query is refused as such, and only that is mcp_query
        url, qm, _ = obj.partition(" ")[2].partition("?")
        ep = m.group(1) == "POST" and mcp_endpoint(rules, url) is not None
        if ep and not qm:
            problems.append(f"seq {seq}: a POST to the MCP endpoint {url} decided as a request, not as an MCP call")
            continue
        if rec.get("rule") == "mcp_query" and not ep:
            problems.append(f"seq {seq}: a request refused as a POST with a query to an MCP endpoint, which it is not")
            continue
        if ep and rec.get("rule") != "mcp_query":
            problems.append(f"seq {seq}: a POST with a query to the MCP endpoint {url} decided by request rules "
                            f"(it is refused, mcp_query)")
            continue
        var = m.group(1) == "POST" and mcp_variant(rules, url)
        if var != (rec.get("rule") == "mcp_endpoint_variant") or (var and rec.get("decision_final") != "DENY"):
            problems.append(f"seq {seq}: a request to {url} " + (
                "decided by request rules, but it is another spelling of an MCP endpoint (it is refused, "
                "mcp_endpoint_variant)" if var else "refused as another spelling of an MCP endpoint, which it is not"))
            continue
        decl = rec.get("body_declared")
        if (rec["body"] == "length") != (type(decl) is int and decl >= 0):
            problems.append(f"seq {seq}: a request whose body is {rec['body']!r} with a declared length {decl!r}")
            continue
        dfin, rule = rec.get("decision_final"), rec.get("rule")
        if dfin == "ALLOW" and rule == "request_allowed":
            cr = rec.get("cert_rule")
            want = rules[cr]["max_body"] if isinstance(cr, int) and 0 <= cr < len(rules) else None
            if want is None or rules[cr]["kind"] != "r" or rec.get("max_body", 0) != want:
                problems.append(f"seq {seq}: an allowed request whose max_body is not its rule's")
                continue
            if want and rec["body"] == "length" and decl > want:
                problems.append(f"seq {seq}: an allowed request declaring a body of {decl} bytes, over its "
                                f"rule's max_body={want}")
                continue
            if rec["body"] != "none":
                st["body"] = (rs, want, rec["body"], decl)
        elif dfin == "DENY" and rule in REQUEST_REFUSE_RULES:
            st["refused"] = rec.get("enforced") is not False    # v1.29: a dry run let it through
            if rule == "max_body" and rec.get("body") != "length":
                problems.append(f"seq {seq}: a request refused for max_body without a declared length")
        else:
            problems.append(f"seq {seq}: a request decision {dfin!r} with rule {rule!r}, which the Warden does not write")
    return n


def check_mcp_call(rec, rules, st, conn, problems):
    """v1.31 (section 3): a net.mcp record, in its connection's sequence. Its
    URL is an MCP endpoint of the connection (scheme://name:port/path, no
    query); its target is URL#METHOD#NAME, and the object decided (resolved)
    is the target, or "" for a call that could not be read; its body's
    length and SHA-256 are recorded. Allowed (mcp_allowed): by an mcp rule
    (the certificate re-check confirms it holds), with that rule's max_body
    (MCP_BODY_DEFAULT when it has none) and a body within it. Refused: one
    of MCP_REFUSE_RULES, and the connection takes no more requests."""
    seq, (_, hp, scheme) = rec.get("seq"), conn
    url, tg, rs = rec.get("mcp_url"), rec.get("target"), rec.get("resolved")
    if not isinstance(rec.get("rule"), str):                      # v1.31 review: no crash on a malformed rule
        problems.append(f"seq {seq}: an MCP call whose rule {rec.get('rule')!r} is not a name")
        return
    if not isinstance(url, str) or not re.fullmatch(re.escape(f"{scheme}://{hp}") + r"/[\x21-\x7e]*", url) or \
            "?" in url or target_problem(url[len(f"{scheme}://{hp}"):]) or mcp_endpoint(rules, url) is None:
        problems.append(f"seq {seq}: an MCP call to {url!r}, which is not an MCP endpoint of connection "
                        f"{rec.get('proxy_conn')} ({scheme}://{hp})")
        return
    if not isinstance(tg, str) or not tg.startswith(url + "#") or tg.count("#") < 2 or \
            not isinstance(rs, str) or (rs and rs != tg):
        problems.append(f"seq {seq}: an MCP call whose object {tg!r} (decided as {rs!r}) is not one of {url}")
        return
    # v1.31 review: only a call that could not be read, or one over the
    # endpoint's own limit before any rule, is recorded with no object decided
    if not rs and not (rec["rule"] in ("mcp_unreadable", "mcp_header_mismatch") or
                       (rec["rule"] == "max_body" and rec.get("policy_line") == -1)):
        problems.append(f"seq {seq}: an MCP call refused as {rec['rule']!r} with no object decided")
        return
    bl, bh = rec.get("body_len"), rec.get("body_sha256")
    if type(bl) is not int or bl < 0 or not (isinstance(bh, str) and HEX64.fullmatch(bh)):
        problems.append(f"seq {seq}: an MCP call without its body's length and SHA-256")
        return
    tk = rec.get("token")
    if (tk is not None and tk not in MCP_TOKEN_KINDS) or \
            (rec["rule"].startswith("mcp_token_") and tk not in ("jwt", "opaque", "malformed")) or \
            (rec.get("rule") == "mcp_token_malformed") != (tk == "malformed") or \
            (rec.get("rule") in ("mcp_token_audience", "mcp_token_expired") and tk != "jwt"):
        problems.append(f"seq {seq}: an MCP call whose bearer token ({tk!r}) is not one its rule "
                        f"{rec.get('rule')!r} is written for")
        return
    # v1.31 review: the agent's own JWT's expiry, against the decision
    te, ts = rec.get("token_expires"), rec.get("timestamp_ns")
    if tk == "jwt" and type(te) is int and type(ts) is int and (
            (rec["rule"] != "mcp_token_expired" and rec.get("decision_final") == "ALLOW" and te * 10**9 + 10**9 <= ts)
            or (rec["rule"] == "mcp_token_expired" and te * 10**9 > ts + 10**9)):
        problems.append(f"seq {seq}: an MCP call {'allowed with a bearer token that had expired' if rec['rule'] != 'mcp_token_expired' else 'refused as expired with a token that had not'}")
        return
    dfin, rule = rec.get("decision_final"), rec.get("rule")
    if dfin == "ALLOW" and rule == "mcp_allowed":
        cr = rec.get("cert_rule")
        r = rules[cr] if isinstance(cr, int) and 0 <= cr < len(rules) else None
        want = (r["max_body"] or MCP_BODY_DEFAULT) if r is not None else None
        if r is None or r["kind"] != "m" or not rs or rec.get("max_body") != want:
            problems.append(f"seq {seq}: an allowed MCP call whose rule is not an mcp rule, or whose max_body "
                            f"is not its rule's")
        elif bl > want:
            problems.append(f"seq {seq}: an allowed MCP call with a body of {bl} bytes, over its rule's "
                            f"max_body={want}")
    elif dfin == "DENY" and rule in MCP_REFUSE_RULES:
        st["refused"] = rec.get("enforced") is not False
        unread = rule in ("mcp_unreadable", "mcp_header_mismatch")
        if unread and (rs or not isinstance(rec.get("mcp_error"), str) or rec.get("enforced") is False):
            problems.append(f"seq {seq}: an MCP call refused as {rule} with an object decided, or without why, "
                            f"or let through")
    else:
        problems.append(f"seq {seq}: an MCP call decision {dfin!r} with rule {rule!r}, which the Warden does not write")


def check_refused_requests(checker, policy, rules, records, problems):
    """v1.26.1 (step 7): each refused request is asked of the policy again.
    The first request rule (policy order) that holds on its object decides:
    policy_match must be a deny rule at its policy_line; default_deny_unknown
    must have none; max_body must be an allow rule at its policy_line whose
    max_body is under the declared length. (An allowed request is re-checked
    by its certificate.) Asked of the checker."""
    # v1.31: an MCP call too (on the object decided), each by the rules of
    # the subject it was decided for
    refused = [r for r in records if r.get("action") in ("net.request", "net.mcp") and r.get("decision_final") == "DENY"
               and r.get("rule") in ("policy_match", "default_deny_unknown", "max_body")
               and isinstance(r.get("resolved" if r.get("action") == "net.mcp" else "target"), str)
               and (r.get("action") == "net.request" or r.get("resolved"))]
    if not refused:
        return
    try:
        confined, forl = policy_confined(checker, policy)
    except ValueError as e:
        problems.append(f"checker failed: {e}")
        return
    obj = lambda r: r["resolved"] if r.get("action") == "net.mcp" else r["target"]
    h = subprocess.run([checker, policy, "holds"], capture_output=True, text=True,
                       input="\n".join(obj(r).encode().hex() for r in refused) + "\n")
    rows = h.stdout.split()
    if h.returncode != 0 or len(rows) != len(refused):
        problems.append(f"checker failed on the refused requests: {h.stderr.strip()}")
        return
    for rec, row in zip(refused, rows):
        seq, rule, line = rec.get("seq"), rec["rule"], rec.get("policy_line")
        ks = expected_subject(rec.get("obo"), confined)
        kind = "m" if rec.get("action") == "net.mcp" else "r"
        reqs = [i for i, r in enumerate(rules) if r["kind"] == kind and forl.get(r["line"], 0) == ks]
        first = next((i for i in reqs if row[i] == "1"), None)
        fr = rules[first] if first is not None else None
        if rule == "default_deny_unknown":
            if fr is not None:
                problems.append(f"seq {seq}: a request refused as matching no rule, but policy line "
                                f"{fr['line']} matches it")
        elif rule == "policy_match":
            if fr is None or fr["allow"] or fr["line"] != line:
                problems.append(f"seq {seq}: a request refused by policy line {line!r}, which is not the "
                                f"deny rule that decides it")
        elif kind == "m":                                  # v1.31: the body read, over the rule's limit
            if fr is None or not fr["allow"] or fr["line"] != line or type(rec.get("body_len")) is not int or \
                    rec["body_len"] <= (fr["max_body"] or MCP_BODY_DEFAULT):
                problems.append(f"seq {seq}: an MCP call refused for max_body, but the rule that allows it "
                                f"(line {line!r}) does not limit it below its body's length")
        elif fr is None or not fr["allow"] or fr["line"] != line or not fr["max_body"] or \
                type(rec.get("body_declared")) is not int or rec["body_declared"] <= fr["max_body"]:
            problems.append(f"seq {seq}: a request refused for max_body, but the rule that allows it "
                            f"(line {line!r}) does not limit it below its declared length")


def check_closes(records, closes, complete, problems, bodies=()):
    """v1.26 (step 7): every proxy_close is of a connection the Warden passed
    to the proxy (proxy_dialed) before it, once; its byte counts and relay
    time (the proxy's report) are present and whole, or absent for
    "unreported"; and in a complete stream every connection passed on is
    closed. Returns the number of closes."""
    dialed, dialed_up = {}, {}           # proxy_conn -> its record's position; dialed to an upstream
    inspected = {}                       # v1.26.1: proxy_conn -> passed on to be inspected
    for pos, rec in enumerate(records):
        if rec.get("action") == "net.proxy" and rec.get("rule") == "proxy_dialed" \
                and rec.get("decision_final") == "ALLOW" and type(rec.get("proxy_conn")) is int:
            dialed.setdefault(rec["proxy_conn"], pos)
            dialed_up.setdefault(rec["proxy_conn"], "upstream" in rec)
            inspected.setdefault(rec["proxy_conn"], rec.get("inspected") is True)
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
        # v1.26.1 (step 4): an inspected connection's close says so, with
        # its own reasons; until requests are decided (step 6) nothing was
        # sent to its server, or to its client from the server
        insp = inspected.get(cid, False)
        if why != "unreported" and (e.get("inspected") is True) != insp:
            problems.append(f"connection {cid}: a close {'not ' if insp else ''}marked inspected, for a "
                            f"connection {'' if insp else 'not '}passed on to be inspected")
            continue
        if why in TLS_CLOSE_WHY and not insp:
            problems.append(f"connection {cid}: a close for {why!r}, which only an inspected connection has")
            continue
        # v1.26.1 (step 6): an inspected connection sends its server bytes
        # only after a request was allowed; it is cut (max_body) only after
        # a body that passed its rule's max_body
        allowed = any(r.get("action") in ("net.request", "net.mcp") and r.get("proxy_conn") == cid and
                      (r.get("decision_final") == "ALLOW" or r.get("enforced") is False) for r in records)
        if insp and why != "unreported" and not allowed and e.get("bytes_up") != 0:
            problems.append(f"connection {cid}: an inspected connection relayed bytes though no request was allowed")
            continue
        exceeded = any(b.get("proxy_conn") == cid and b.get("exceeded_max_body") is True for _, b in bodies)
        # review: the bodies recorded as sent fit in the bytes relayed to the server
        sent = sum(b["body_len"] for _, b in bodies if b.get("proxy_conn") == cid and type(b.get("body_len")) is int)
        if insp and why != "unreported" and type(e.get("bytes_up")) is int and sent > e["bytes_up"]:
            problems.append(f"connection {cid}: request bodies of {sent} bytes recorded as sent, but "
                            f"{e['bytes_up']} bytes relayed")
            continue
        if insp and (why == "max_body") != exceeded:
            problems.append(f"connection {cid}: a close for {why!r}, but a body that passed max_body "
                            f"{'was' if exceeded else 'was not'} recorded")
            continue
        # step 7: the requests it counts are those recorded on it
        nrq = sum(1 for r in records if r.get("action") in ("net.request", "net.mcp") and r.get("proxy_conn") == cid)
        if why != "unreported" and ((insp and e.get("requests") != nrq) or (not insp and "requests" in e)):
            problems.append(f"connection {cid}: a close counting {e.get('requests')!r} requests, "
                            f"but {nrq} were recorded on it")
            continue
        if insp and ("server_cert_sha256" in e and not (isinstance(e["server_cert_sha256"], str) and
                                                         HEX64.fullmatch(e["server_cert_sha256"]))):
            problems.append(f"connection {cid}: a server certificate hash that is not one")
            continue
        if why not in CLOSE_WHY + TLS_CLOSE_WHY:
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
                  charged=None, exact=None, handoff_port=None, passthrough=None):
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
                 ("dialed" not in rec or rule in ("run_ended", "revoked")))):
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
        # v1.26.1: in inspecting mode a host that is not a passthrough host is
        # passed on to be inspected (its requests are then decided one by one)
        name = tgt.rsplit(":", 1)[0]
        insp = rec.get("inspected") is True
        if "inspected" in rec and not insp:
            problems.append(f"seq {seq}: a malformed inspected mark")
            continue
        if passthrough is None and insp:
            problems.append(f"seq {seq}: a proxied decision inspected outside inspecting mode")
            continue
        if passthrough is not None:
            should = name not in passthrough
            if insp != (should and rule not in ("policy_match", "default_deny_unknown", "certificate_refused",
                                                "fragment_escape_flags", "fragment_escape_length")):
                problems.append(f"seq {seq}: in inspecting mode, {name} was {'' if insp else 'not '}inspected, "
                                f"which {'only a host that is not passthrough is' if insp else 'it must be'}")
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
                                               for r in rules)) or rs.get("mode") == "dry_run"   # v1.29
    if rs.get("dns_stub") != (stub_of(rs) if stub else None):
        problems.append(f"run_start's dns_stub {rs.get('dns_stub')!r} is not the policy's "
                        f"({stub_of(rs) if stub else 'none'})")
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
    dry = rs.get("mode") == "dry_run"                           # v1.29
    dry_sent = set()        # names a dry run looked up that the policy refuses (charged to nothing)
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
                if name not in charged and name not in dry_sent:
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
        if rule == "revoked":                    # v1.28 review: after `varek revoke`, refused, nothing looked up
            if ans != "refused" or e.get("new") or e.get("upstream") or e.get("synthetic"):
                problems.append(f"{name!r}: a question after the revocation was answered {ans}")
            continue
        if e.get("enforced") is False:
            # v1.29: a dry run answers a name the policy refuses (no rule, or
            # past a wildcard's budget) as it would an allowed one: looked up
            # (sent upstream, charged to no rule) or from what was looked up
            # (check_dry checks the run is a dry run)
            if not dry or rule not in ("no_rule", "wildcard_budget") or e.get("synthetic") or \
                    (rule == "no_rule" and (line != -1 or by_rule.get(name) is not None)) or \
                    (rule == "wildcard_budget" and line not in wild) or \
                    (e.get("upstream") is True and ans != "lookup") or \
                    (ans == "lookup" and e.get("upstream") is not True and name not in pending) or \
                    ans == "nxdomain":
                # v1.31 (found by the OCSF tests): a second question (AAAA after A)
                # waits on the lookup the first sent, so it is "lookup" without upstream
                problems.append(f"{name!r}: a question let through by a dry run that is not an answer to "
                                f"a name the policy refuses")
                continue
            if rule == "wildcard_budget":
                nb += 1
            if e.get("upstream") is True:
                if name in pending:
                    problems.append(f"{name}: sent upstream again while its lookup was outstanding")
                pending[name] = ts if type(ts) is int else 0
            dry_sent.add(name)
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
    cited = []                             # v1.31 review: reported after the certificates are re-checked
    confined, for_lines = None, {}        # v1.31: read when a certificate is first checked
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
    # v1.27: launches after the first decided (require warden 1.27)
    try:
        launches_policy = policy_launches(a.checker, a.policy)
    except (OSError, ValueError) as e:
        problems.append(f"checker failed on the policy's launches: {e}")
        launches_policy = False
    check_exec_set(meta, launches_policy, problems, records)
    try:
        openas_policy = policy_openas(a.checker, a.policy)          # v1.29
    except (OSError, ValueError) as e:
        problems.append(f"checker failed on the policy's openas: {e}")
        openas_policy = False
    check_changes(records, openas_policy, problems)
    check_open_as(meta, openas_policy, problems)                     # v1.29
    check_baseline(meta, a.policy, problems)
    dry_run = check_dry(meta, records, problems)
    try:
        check_noexec(meta, policy_rules(a.checker, a.policy), launches_policy, problems, records)   # v1.27.1
        check_noexec_exec(meta, policy_rules(a.checker, a.policy), openas_policy, problems)          # v1.29
    except (OSError, ValueError) as e:
        problems.append(f"checker failed on the policy's rules: {e}")
    exec_ok = 0
    stub_policy = wild_policy or (proxy_ports is not None and any(
        r["kind"] == "h" and r["name"] and not r["wild"] for r in prules)) or \
        meta.get("run_start", {}).get("mode") == "dry_run"          # v1.29: the stub runs in a dry run
    stub_addr = stub_of(meta.get("run_start", {}))                     # v1.34 step 4
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
        if rec.get("action") in META_ACTIONS + ("file.mkdir",) and \
                rec.get("rule") == ("mkdir_exists_ancestor" if rec.get("action") == "file.mkdir"
                                    else "metadata_ancestor"):
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
            elif rec.get("resolved") != stub_addr or ct is None or \
                    f"{_ip(str(ct[0]))}:{ct[1]}" != stub_addr:
                problems.append(f"seq {rec.get('seq')}: a dns_stub record to "
                                f"{rec.get('target')!r} / {rec.get('resolved')!r}, not the stub at {stub_addr}")
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
        if rec.get("action") == "file.open" and (rec.get("rule") in VIEW_RULES or
                                                 rec.get("rule") in TRUST_VIEW_RULES):
            fl = rec.get("open_flags")
            try:
                flv = int(fl, 16)
            except (TypeError, ValueError):
                flv = -1
            trust = rec["rule"] in TRUST_VIEW_RULES        # v1.26.1
            inspecting = _inspecting(meta)
            if trust and not inspecting:
                problems.append(f"seq {rec.get('seq')}: a trust view answered, but run_start's proxy is not "
                                f"in inspecting mode")
            elif trust and rec.get("resolved") not in TRUST_VIEW_RULES[rec["rule"]]:
                problems.append(f"seq {rec.get('seq')}: a {rec['rule']} answered an open of "
                                f"{rec.get('resolved')!r}")
            elif not trust and not names_policy and not dry_run:    # v1.29: a dry run's views
                problems.append(f"seq {rec.get('seq')}: a view answered, but run_start says the "
                                f"policy has no host name rules")
            elif not trust and rec.get("resolved") != VIEW_RULES[rec["rule"]]:
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
        # v1.26.1: a read-type lookup of a trust view, answered from the view
        if rec.get("action") in ("file.stat", "file.access") and rec.get("rule") == "view_metadata":
            inspecting = _inspecting(meta)
            if not inspecting or rec.get("resolved") not in TRUST_VIEW_RULES["trust_view"] + \
                    TRUST_VIEW_RULES["run_ca_view"] + TRUST_VIEW_RULES["trust_store_view"]:
                problems.append(f"seq {rec.get('seq')}: a view's metadata answered for {rec.get('resolved')!r}, "
                                f"which is not a trust view of a run in inspecting mode")
            # review: only a read-type lookup is answered (access without
            # W_OK or X_OK), and, as for an open, not where a deny rule holds
            elif rec.get("open_flags") != "0x0" or (rec["action"] == "file.access" and not (
                    isinstance(rec.get("access_mode"), str) and rec["access_mode"].isdigit() and
                    int(rec["access_mode"]) & 3 == 0)):
                problems.append(f"seq {rec.get('seq')}: a view's metadata answered for a lookup that is not "
                                f"read-type ({rec.get('open_flags')!r}, access {rec.get('access_mode')!r})")
            else:
                view_recs.append((rec, 0))
            views += 1
            continue
        # v1.27 (step 3): a launch the policy allows by its name, onto a file of
        # the launch set (the entry it names: same device, inode and hash), in a
        # run that Landlock holds; certified on the name like an open
        is_exec = rec.get("action") == "process.exec" and rec.get("rule") == "exec_allowed"
        if is_exec:
            seq = rec.get("seq")
            rs = meta.get("run_start", {})
            ex = rs.get("exec_ruleset") if isinstance(rs.get("exec_ruleset"), list) else []
            k = rec.get("exec_set")
            ent = ex[k] if type(k) is int and 0 <= k < len(ex) and isinstance(ex[k], dict) else None
            if not launches_policy:
                problems.append(f"seq {seq}: a launch allowed, but the policy does not turn launches on")
                continue
            if not isinstance(rs.get("landlock"), dict):
                problems.append(f"seq {seq}: a launch allowed, but run_start records no Landlock")
                continue
            if ent is None or rec.get("exec_dev") != ent.get("dev") or rec.get("exec_ino") != ent.get("ino") \
                    or rec.get("exec_sha256") != ent.get("sha256"):
                problems.append(f"seq {seq}: a launch allowed onto {k!r}, not a file of the launch set "
                                f"as run_start records it")
                continue
            if not isinstance(rec.get("resolved"), str) or not rec["resolved"].startswith("/"):
                problems.append(f"seq {seq}: a launch allowed without the absolute name it was decided on")
                continue
            exec_ok += 1
        is_open = rec.get("action") == "file.open" and rec.get("rule") in AUTHORIZED_OPEN_RULES
        if is_open and rec.get("rule") == "open_not_found":                  # review finding 3
            try:
                fl = int(str(rec.get("open_flags")), 16)
            except ValueError:
                fl = os.O_CREAT
            # v1.29: under require warden 1.29 a create whose directory is missing too
            if not launches_policy or (fl & os.O_CREAT and not openas_policy) or rec.get("errno") != 2 \
                    or rec.get("kernel_verdict") == "ALLOW":
                problems.append(f"seq {rec.get('seq')}: an open recorded as not found, which the Warden "
                                f"writes only with launches on, for an open that does not create, "
                                f"answered ENOENT")
                continue
        is_meta = (rec.get("action") in META_ACTIONS and rec.get("rule") in META_RULES) or \
                  (rec.get("action") == "file.mkdir" and rec.get("rule") == "mkdir_exists")   # v1.29
        # v1.29: a change by name, decided as a path with its flags (check_changes)
        is_change = rec.get("action") in CHANGE_FLAGS and rec.get("rule") in CHANGE_RULES
        is_meta = is_meta or is_change
        is_conn = rec.get("action") == "net.connect" and rec.get("rule") in CONNECT_RULES
        # v1.26 (step 6): a name:port the proxy read, allowed: certified as a connect is
        is_proxy = rec.get("action") == "net.proxy" and rec.get("rule") in PROXY_ALLOW_RULES
        # v1.26.1 (step 6): an inspected request, allowed: certified on its object
        is_req = rec.get("action") == "net.request" and rec.get("rule") == "request_allowed"
        is_mcp = rec.get("action") == "net.mcp" and rec.get("rule") == "mcp_allowed"       # v1.31
        is_req = is_req or is_mcp
        if not (is_open or is_meta or is_conn or is_proxy or is_req or is_exec):
            problems.append(f"seq {rec.get('seq')}: an authorization that is not a certified "
                            f"file open, lookup or connect ({rec.get('action')}, rule {rec.get('rule')})")
            continue
        if is_meta:
            lookups += 1
        elif is_exec:
            pass                               # v1.27: counted above
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
        if prules and (type(cr) is not int or not 0 <= cr < len(prules) or
                       rec.get("policy_line") != prules[cr]["line"]):
            # v1.31 review: the line a decision cites is its certificate's rule's
            cited.append(f"seq {rec.get('seq')}: a decision citing policy line {rec.get('policy_line')!r}, "
                            f"but its certificate's rule is "
                            f"{'line ' + str(prules[cr]['line']) if type(cr) is int and 0 <= cr < len(prules) else repr(cr)}")
        s = rec.get("resolved", "")
        fl = rec.get("open_flags")
        if not isinstance(s, str):
            problems.append(f"seq {rec.get('seq')}: a malformed decided destination or path")
            continue
        if is_proxy or is_req or is_exec:      # v1.26.1, v1.27: no flags either
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
        # v1.31: the certificate is checked as the subject the record's chain
        # makes it (from the policy, not the record), and the record must say so
        if confined is None:
            try:
                confined, for_lines = policy_confined(a.checker, a.policy)
            except ValueError as e:
                problems.append(f"checker failed: {e}")
                confined, for_lines = {}, {}
        ks = expected_subject(rec.get("obo"), confined)
        if rec.get("cert_subject", 0) != ks:
            problems.append(f"seq {rec.get('seq')}: certificate recorded for subject {rec.get('cert_subject', 0)!r}, "
                            f"but the decision was for subject {ks} (its chain {rec.get('obo')!r})")
            continue
        lines.append(f"{'mcp' if is_mcp else 'request' if is_req else 'exec' if is_exec else 'host' if is_conn_like else 'path'} "
                     f"{fl} {hx} {cr} {cw}" + (f" @{ks}" if ks else ""))
        which.append(rec)
        if is_conn and ("candidates" in rec or "candidates_sha256" in rec):
            try:
                others.append((rec, cr, check_names(rec, pos, resolutions, problems,
                                                    exact_grace=exact_grace)))
            except (TypeError, ValueError, AttributeError, KeyError) as e:
                problems.append(f"seq {rec.get('seq')}: malformed connect or resolution records ({e})")
        if is_conn and others and others[-1][0] is rec:
            others[-1] = others[-1] + (ks,)          # v1.31: the subject it was decided as

    # v1.24 review: a view is served unless an explicit deny in the policy
    # holds on its path (and the open's flags): ask the checker which path
    # rules hold, in order.
    if view_recs and rules:
        h = subprocess.run([a.checker, a.policy, "holds"],
                           input="\n".join(r["resolved"].encode().hex() for r, _ in view_recs) + "\n",
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
                                            f"rule {i} denies {rec['resolved']}")
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
    problems += cited
    if others and not problems:
        k = subprocess.run([a.checker, a.policy, "kinds"], capture_output=True, text=True)
        kinds = k.stdout.strip() if k.returncode == 0 else ""
        strs = [c for _, _, oc, *_ in others for c in oc]
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
                # v1.31: a rule's subject, by its policy line
                rline = [r["line"] for r in prules]
                for rec, cr, oc, *ksub in others:
                    ksub = ksub[0] if ksub else 0
                    for c in oc:
                        row = next(it)
                        early = [i for i in range(min(cr, len(row))) if kinds[i] == "h" and row[i] == "1"
                                 and (for_lines.get(rline[i], 0) if i < len(rline) else 0) == ksub]
                        if early:
                            problems.append(f"seq {rec.get('seq')}: rule {early[0]} holds on candidate "
                                            f"{c!r}, before the rule that decided the connect")
    # v1.26 (step 8): the proxy as run_start names it, and each hand-off as the policy decides
    try:
        passthrough = policy_inspect(a.checker, a.policy)                 # v1.26.1
    except (OSError, ValueError):
        passthrough = None
    check_proxy_start(meta, proxy_ports, problems, policy_upstream(a.checker, a.policy),
                      passthrough is not None)
    check_trust(meta, passthrough, problems, prules, proxy_ports)
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
                            charged_at, exact_hosts, handoff_port, passthrough)
    if prules:
        check_dialed_denies(a.checker, a.policy, prules, dialed_px, problems)
    pcloses = check_closes(records, meta.get("proxy_closes", []), complete, problems,
                           meta.get("request_bodies", []))                       # step 7
    nreq = check_requests(records, meta.get("request_bodies", []), prules, problems,       # v1.26.1
                          meta.get("proxy_closes", []), meta.get("lineno"))
    if nreq:
        check_refused_requests(a.checker, a.policy, prules, records, problems)            # step 7
    cnotes = []                                                                            # v1.28
    try:
        pcreds, pcred_rules, pcred_auds = policy_credentials(a.checker, a.policy)
    except (OSError, ValueError) as e:
        problems.append(f"checker failed on the policy's credentials: {e}")
        pcreds, pcred_rules, pcred_auds = [], {}, {}
    ncarried, nswap_refused, revoked = check_credentials(pcreds, pcred_rules, meta, records, complete,
                                                         problems, cnotes, pcred_auds)
    try:                                                                                   # v1.28.1
        ident = policy_identity(a.checker, a.policy)
    except (OSError, ValueError) as e:
        problems.append(f"checker failed on the policy's identities: {e}")
        ident = ({}, {}, {}, False, {})
    per_sub = check_chain(ident, meta, records, run, problems)
    try:                                                                                   # v1.31 (section 6)
        confined6, forl6 = policy_confined(a.checker, a.policy)
    except ValueError as e:
        problems.append(f"checker failed: {e}")
        confined6, forl6 = {}, {}
    check_subjects(records, confined6, forl6, problems)
    check_token_values(a.log, run, problems)
    nlaunch = nlaunch_refused = 0
    if launches_policy and prules:                                                         # v1.27
        nlaunch, nlaunch_refused = check_launches(a.checker, a.policy, prules, meta, records, complete,
                                                  problems)
    re_ = meta.get("run_end")
    if isinstance(re_, dict) and re_.get("proxy_failed") is True:                        # review
        problems.append("run_end says the egress proxy exited or sent a malformed report as the run "
                        "ended: its open connections were not reported")
    if proxied and proxy_ports is None:
        problems.append("proxied decisions, but the policy does not turn the proxy on")
    # v1.26: every connection id the Warden gave a hand-off is recorded once
    if complete and handoff_ids and handoff_ids != set(range(1, len(handoff_ids) + 1)):
        problems.append(f"the hand-offs' connection ids are not 1 to {len(handoff_ids)}: one is missing")
    print(f"varek_audit: run {run} (Warden {warden}, {'complete' if complete else 'INCOMPLETE'}), "
          f"{len(records)} records, {authorized} authorized file opens, {lookups} lookups, "
          f"{connects} authorized connects, "
          f"{views} host-name views, {stubs} stub resolver connects, {handoffs} proxy hand-offs, "
          f"{proxied} proxied decisions ({proxied_ok} allowed), {pcloses} proxy closes, {nreq} inspected requests, "
          f"{nlaunch} launches allowed ({nlaunch_refused} refused), "
          f"{questions} stub questions ({budget_hits} over a budget), "
          f"{checked} certificates "
          f"re-checked, {refused} refused in-line")
    if pcreds or revoked:                                                                 # v1.28
        print(f"varek_audit: credentials: {len(pcreds)} named, {ncarried} requests carried one, "
              f"{nswap_refused} swaps refused{', the run was revoked' if revoked else ''}")
    if per_sub is not None:                                                               # v1.28.1
        ob_ = meta.get("run_start", {}).get("on_behalf_of")
        u = ob_.get("user") if isinstance(ob_, dict) else None
        who = f"on behalf of {u.get('subject')} ({u.get('issuer')})" if isinstance(u, dict) else "no user"
        subs = ", ".join(f"{t} {n}" for t, n in sorted(per_sub.items())) if per_sub else "none"
        print(f"varek_audit: chain: {who}; sub-agents (decisions): {subs}")
    for n_ in cnotes:
        print(f"varek_audit: note: {n_}")
    print(f"varek_audit: integrity: {integrity}")
    t0 = meta.get("run_start", {}).get("timestamp_ns")
    if isinstance(t0, int):
        import datetime
        when = datetime.datetime.fromtimestamp(t0 / 1e9, datetime.timezone.utc)
        print(f"varek_audit: run started {when.isoformat(timespec='seconds')} "
              f"(policy {meta['run_start'].get('policy_path')!r})")
    for pr in problems[:50]:
        print(f"  PROBLEM {pr}")
    # v1.29 (D10): a dry run that passes is verified and NOT ENFORCED, with
    # an exit code of its own, so a script that reads 0 as "enforced" cannot
    # mistake it
    if dry_run and not problems:
        nd = sum(1 for r in list(records) + list(meta.get("dns_events", []))
                 if isinstance(r, dict) and r.get("enforced") is False)
        print(f"varek_audit: VERIFIED: DRY RUN, NOT ENFORCED ({nd} call(s) the policy refuses were let through)")
        return 3
    print(f"varek_audit: {'PASS' if not problems else 'FAIL'}")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
