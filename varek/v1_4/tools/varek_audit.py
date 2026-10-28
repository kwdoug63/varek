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

v1.36 (D9): the stream is read once, and no record is kept once the checks
have seen it: the audit's memory is bounded by the policy and the plan, not
by the stream. A stream the node agent rotated is given as its segments, in
order (NAME.jsonl NAME.jsonl.2 ...), or put together in one file.

Usage:
  varek_audit.py --policy POLICY --checker tools/vdp_cert_check
                 [--pubkey KEY.pub|HEX] [--anchor ANCHOR] VERDICTS.LOG [SEGMENT ...]
"""

import argparse
import bisect
import collections
import hashlib
import ipaddress
import json
import os
import pickle
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from varek_cyclonedx import StreamError, _iter_log, _version_at_least, LOG_SIG_DOMAIN, LOG_CHAIN_FORMAT, \
    CRED_EVENTS  # noqa: E402
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

# v1.36 (D9): the audit reads the stream once and keeps no record once its
# checks have seen it. What it keeps is bounded by the policy and the plan
# (names, rules, the plan's steps), by what the Warden itself bounds
# (sub-agents, SUB_MAX), and by what is open at a time (connections not yet
# closed, launches not yet settled); the rows it asks the checker about wait
# on disk; each section of the problems keeps the first PROBLEMS_SHOWN (the
# report prints no more) and counts the rest.
PROBLEMS_SHOWN = 50


class Section:
    """One check's problems, in the order the check finds them."""

    def __init__(self):
        self.items, self.n = [], 0

    def append(self, p):
        self.n += 1
        if len(self.items) < PROBLEMS_SHOWN:
            self.items.append(p)

    def clear(self):
        self.items, self.n = [], 0

    def __len__(self):
        return self.n

    def __iter__(self):
        return iter(self.items)


class Problems:
    """The audit's problems: its sections in the order the checks report."""

    def __init__(self, names):
        self.order = list(names)
        self.secs = {n: Section() for n in self.order}

    def __getitem__(self, name):
        return self.secs[name]

    def before(self, name):
        """How many problems the sections before this one hold."""
        return sum(len(self.secs[n]) for n in self.order[:self.order.index(name)])

    def __len__(self):
        return sum(len(s) for s in self.secs.values())

    def shown(self):
        out = []
        for n in self.order:
            out += self.secs[n].items
            if len(out) >= PROBLEMS_SHOWN:
                break
        return out[:PROBLEMS_SHOWN]


class IdSet:
    """A set of integers kept as intervals: small while the ids come close to
    in order (connection ids 1, 2, 3, ..., some still open)."""

    def __init__(self):
        self.lo, self.hi = [], []

    def __contains__(self, x):
        i = bisect.bisect_right(self.lo, x) - 1
        return i >= 0 and x <= self.hi[i]

    def add(self, x):
        if x in self:
            return
        i = bisect.bisect_right(self.lo, x)
        left = i > 0 and self.hi[i - 1] == x - 1
        right = i < len(self.lo) and self.lo[i] == x + 1
        if left and right:
            self.hi[i - 1] = self.hi[i]
            del self.lo[i], self.hi[i]
        elif left:
            self.hi[i - 1] = x
        elif right:
            self.lo[i] = x
        else:
            self.lo.insert(i, x)
            self.hi.insert(i, x)

    def __len__(self):
        return sum(h - l + 1 for l, h in zip(self.lo, self.hi))

    def __bool__(self):
        return bool(self.lo)

    def is_range(self, a, b):
        """exactly a..b"""
        return self.lo == [a] and self.hi == [b]


class Spool:
    """Rows to ask the checker, and what each row was asked for, on disk
    until the stream has been read."""

    def __init__(self):
        self.n = 0
        self.rows = tempfile.TemporaryFile("w+", encoding="ascii")
        self.ctx = tempfile.TemporaryFile("w+b")

    def add(self, row, ctx):
        self.rows.write(row + "\n")
        pickle.dump(ctx, self.ctx)
        self.n += 1

    def __len__(self):
        return self.n

    def contexts(self):
        self.ctx.seek(0)
        for _ in range(self.n):
            yield pickle.load(self.ctx)

    def ask(self, checker, policy, mode):
        """Run the checker's mode over the rows. Returns (ok, its answers in a
        file, how many, stderr): "holds" answers one word a row, "batch" one
        JSON object a line."""
        self.rows.flush()
        self.rows.seek(0)
        out = tempfile.TemporaryFile("w+", encoding="utf-8", errors="surrogateescape")
        err = tempfile.TemporaryFile("w+", encoding="utf-8", errors="replace")
        rc = subprocess.run([checker, policy, mode], stdin=self.rows, stdout=out, stderr=err).returncode
        out.seek(0)
        err.seek(0)
        n = 0
        for line in out:
            n += len(line.split()) if mode == "holds" else (1 if line.strip() else 0)
        out.seek(0)
        return rc == 0, out, n, err.read()


def spool_words(fh):
    for line in fh:
        yield from line.split()


class Delay:
    """v1.36 (D9): the records after the last signature of a signed stream
    (or, anchored without a key, after the last record the anchor holds),
    held until the next one seals them: an incomplete stream is audited only
    as far as that. Past HOLD in memory they wait on disk."""

    HOLD = 4096

    def __init__(self):
        self.mem, self.disk, self.ndisk = [], None, 0

    def put(self, item):
        if len(self.mem) < self.HOLD and not self.ndisk:
            self.mem.append(item)
            return
        if self.disk is None:
            self.disk = tempfile.TemporaryFile("w+b")
        pickle.dump(item, self.disk)
        self.ndisk += 1

    def take(self):
        yield from self.mem
        if self.ndisk:
            self.disk.seek(0)
            for _ in range(self.ndisk):
                yield pickle.load(self.disk)
            self.disk.close()
        self.mem, self.disk, self.ndisk = [], None, 0


class Resolutions:
    """v1.24: the resolution records so far: each name's latest, and the
    latest of all (the Warden's table generation)."""

    def __init__(self):
        self.latest, self.last = {}, None

    def add(self, r):
        if isinstance(r.get("name"), str):
            self.latest[r["name"]] = r
            self.last = r

    def of(self, name):
        return self.latest.get(name) if isinstance(name, str) else None


class Count:
    """How many decision records a check has seen, where a check of the
    whole list only asked how many (check_plan_gate)."""

    def __init__(self, n=0):
        self.n = n

    def __len__(self):
        return self.n

    def __bool__(self):
        return self.n > 0


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
                 "subagent_env",                                        # v1.31 review
                 "subagent_first_process")                              # v1.36 step 5


class HoldCheck:
    """v1.35 step 4 (D2): a run held to its plan (--hold-to-plan). run_start
    names the plan and its SHA-256; a call refused as outside it (rule
    outside_plan) is one the policy allowed (decision_raw ALLOW, refused
    after), names the same plan, and appears only in a held run."""

    def __init__(self, rs, head, problems):
        hold = rs.get("hold")
        if hold is not None and not (isinstance(hold, dict) and isinstance(hold.get("plan"), str) and
                                     isinstance(hold.get("plan_sha256"), str) and
                                     re.fullmatch(r"[0-9a-f]{64}", hold.get("plan_sha256", ""))):
            head.append(f"run_start's hold {hold!r} is not one the Warden writes")
            hold = None
        self.hold, self.problems = hold, problems
        self.nout = 0                        # the calls refused outside the plan (the report's plan line)

    def rec(self, r):
        if r.get("rule") != "outside_plan":
            return
        self.nout += 1
        hold, problems = self.hold, self.problems
        if hold is None:
            problems.append(f"seq {r.get('seq')}: an outside_plan refusal in a run not held to a plan")
        elif r.get("decision_raw") != "ALLOW" or r.get("decision_final") != "DENY":
            problems.append(f"seq {r.get('seq')}: an outside_plan record is not a refusal of a call the policy "
                            f"allowed ({r.get('decision_raw')}/{r.get('decision_final')})")
        elif r.get("plan") != hold.get("plan"):
            problems.append(f"seq {r.get('seq')}: an outside_plan record names the plan {r.get('plan')!r}, "
                            f"not the run's {hold.get('plan')!r}")


PLAN_VERDICTS = ("SATISFIED", "UNSATISFIED", "UNKNOWN")


# step 9 (review): the reasons the basic gate gives on plan_gate (why) for a plan refused with no step
# refused (pathology.c's suppression reasons)
GATE_WHYS = ("cycle", "empty", "capacity", "edge_index")


def gate_passed(r):
    """the gate's record lets the agent start: SATISFIED, and under the flow
    gate its breaker PASS"""
    return isinstance(r, dict) and r.get("verdict") == "SATISFIED" and \
        (r.get("gate") != "flow" or r.get("breaker") == "PASS")


def check_plan_gate(meta, records, problems, plan_file=None, complete=True):
    """v1.35 step 7: the plan gate's records (step 2, D9), with each other,
    with the run and with its hold. A plan_step is a step not SATISFIED
    (UNSATISFIED or UNKNOWN, with its reason), of the gate's plan, written
    before the gate's record; a plan_gate (gate plan or flow) says the
    verdict, once per gate, before any decision record. A refused plan
    starts no agent (no decision record follows), and is refused for a step
    it records (or a plan that could not be read); an authorized one records
    no step. A held run passed the plan gate, on the plan it is held to, the
    same file by its SHA-256. With plan_file, the plan's SHA-256 is that
    file's. Returns the plan gate's record (or None)."""
    rs = meta.get("run_start", {})
    events = meta.get("plan_events", [])
    gates, steps = {}, []
    for before, r in events:
        where = f"the {r.get('event')} record of plan {r.get('plan')!r}"
        if before:
            problems.append(f"{where} follows {before} decision record(s): the gate decides a plan before the "
                            f"agent starts")
        if not isinstance(r.get("plan"), str) or not r.get("plan"):
            problems.append(f"{where} names no plan")
        if r.get("event") == "plan_step":
            if r.get("decision") not in ("UNSATISFIED", "UNKNOWN"):
                problems.append(f"{where}: step {r.get('label')!r} recorded as {r.get('decision')!r} (a "
                                f"plan_step is a step not SATISFIED)")
            if not (isinstance(r.get("label"), str) and isinstance(r.get("kind"), str) and
                    isinstance(r.get("why"), str) and isinstance(r.get("policy_line"), int)):
                problems.append(f"{where}: a plan_step without its label, kind, deciding line and reason")
            if "plan" in gates:
                problems.append(f"{where}: step {r.get('label')!r} after the gate's verdict")
            steps.append(r)
            continue
        g = r.get("gate")
        if g not in ("plan", "flow"):
            problems.append(f"{where}: gate {g!r} is not one the Warden has")
            continue
        if g in gates:
            problems.append(f"{where}: a second {g} gate in one run")
        if r.get("verdict") not in PLAN_VERDICTS:
            problems.append(f"{where}: verdict {r.get('verdict')!r}")
        sha = r.get("plan_sha256")
        if sha is not None and not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
            problems.append(f"{where}: plan_sha256 {sha!r} is not a SHA-256")
        elif sha is None and "error" not in r and _version_at_least(rs.get("warden"), (1, 35)):
            problems.append(f"{where}: no plan_sha256 (the Warden records the plan's SHA-256 from 1.35)")
        if r.get("why") is not None and r.get("why") not in GATE_WHYS:
            problems.append(f"{where}: why {r.get('why')!r} is not a reason the gate gives")
        gates[g] = r
    # step 9 (review): the flow gate (--flow-policy) writes plan_step records too, and its own plan_gate
    gate = gates.get("plan") or gates.get("flow")
    # step 9 (review): a stream cut before the gate's record (--allow-incomplete), no decision after it
    cut = not complete and gate is None and not records
    if steps and gate is None and not cut:
        problems.append(f"{len(steps)} plan_step record(s) and no plan gate's verdict")
    if gate is not None:
        own = [s for s in steps if s.get("plan") == gate.get("plan")]
        if len(own) != len(steps):
            problems.append("a plan_step record names a plan other than the gate's")
        if isinstance(gate.get("actions"), int) and len(steps) > gate["actions"]:
            problems.append(f"{len(steps)} plan_step records for a plan of {gate['actions']} step(s)")
        if gate.get("verdict") == "SATISFIED" and steps:
            problems.append(f"the plan was authorized, and {len(steps)} of its steps are recorded as not "
                            f"SATISFIED")
        if gate.get("verdict") in ("UNSATISFIED", "UNKNOWN"):
            # the reason: a step, the parser's error, the plan's structure (step 9: why, a cycle), or
            # under the flow gate its flow axis (its steps all SATISFIED)
            if not steps and "error" not in gate and gate.get("why") not in GATE_WHYS and \
                    not (gate.get("gate") == "flow" and gate.get("node_axis") == "SATISFIED"):
                problems.append("the plan was refused, and no step of it is recorded as the reason")
    for g, r in gates.items():
        if not gate_passed(r) and records:
            problems.append(f"the {g} gate refused the plan ({r.get('verdict')}"
                            f"{', breaker ' + str(r.get('breaker')) if g == 'flow' else ''}), and the stream "
                            f"holds {len(records)} decision record(s): a refused plan starts no agent")
    hold = rs.get("hold") if isinstance(rs.get("hold"), dict) else None
    if hold is not None:
        if gate is None:
            if not cut:
                problems.append("the run is held to a plan, and no plan gate decided it")
        else:
            if gate.get("plan") != hold.get("plan"):
                problems.append(f"the run is held to {hold.get('plan')!r}, the gate decided {gate.get('plan')!r}")
            if gate.get("plan_sha256") and gate.get("plan_sha256") != hold.get("plan_sha256"):
                problems.append(f"the plan held to (SHA-256 {hold.get('plan_sha256')}) is not the plan the gate "
                                f"decided ({gate.get('plan_sha256')}): it changed between the two")
    if plan_file is not None:
        try:
            with open(plan_file, "rb") as fh:
                want = hashlib.sha256(fh.read()).hexdigest()
        except OSError as e:
            problems.append(f"cannot read the plan {plan_file}: {e.strerror}")
            want = None
        got = (gate or {}).get("plan_sha256") or (hold or {}).get("plan_sha256")
        if want is not None:
            if gate is None and hold is None:
                problems.append(f"--plan {plan_file}: the run decided no plan")
            elif got is None:
                problems.append(f"--plan {plan_file}: the stream records no SHA-256 of its plan to compare")
            elif got != want:
                problems.append(f"the plan {plan_file} hashes to {want}, the run's plan to {got}")
    return gate


class DryCheck:
    """v1.29 (section 5, D10): a dry run's stream.

    Every record with "enforced":false is in a stream whose run_start says
    mode dry_run, refuses (DENY: the policy's verdict, which the dry run let
    through), and is not of a kind a dry run never lets through; none comes
    after a revocation; run_end says the same mode and counts them. In a
    stream that is not a dry run, no record says enforced:false.
    v1.36 (D9): record by record; a rename's two names are the record before
    or the one after."""

    def __init__(self, rs, sec):
        self.rs, self.dry = rs, rs.get("mode") == "dry_run"
        self.recs, self.dns, self.refused = sec["dry_recs"], sec["dry_dns"], sec["dry_refused"]
        self.revoked = False                 # a revocation so far (ordered by stream line)
        self.n = 0                           # records not enforced, the report's count
        self.prev = None                     # the record before
        self.wait = None                     # a rename's old name let through: its new name is next

    def head(self, meta, problems):
        rs = self.rs
        if rs.get("mode") not in (None, "dry_run"):
            problems.append(f"run_start's mode {rs.get('mode')!r} is not one the Warden writes")
        # v1.33.0: the architecture the Warden ran on (written from v1.33.0; open
        # flags are recorded in VAREK's encoding, x86_64's, on both)
        if "arch" in rs and rs.get("arch") not in ("x86_64", "aarch64"):
            problems.append(f"run_start's arch {rs.get('arch')!r} is not one the Warden writes")
        elif "arch" not in rs and _version_at_least(rs.get("warden"), (1, 33)):
            problems.append(f"run_start names the Warden {rs.get('warden')!r}, which records its architecture, "
                            f"but has none")
        elif "arch" in rs and not _version_at_least(rs.get("warden"), (1, 33)):
            problems.append(f"run_start records an architecture, but names the Warden {rs.get('warden')!r}, "
                            f"which records none")
        end = meta.get("run_end")
        if isinstance(end, dict) and end.get("mode") != rs.get("mode"):
            problems.append(f"run_end's mode {end.get('mode')!r} is not run_start's {rs.get('mode')!r}")

    def ev(self, e):
        if e.get("event") == "revoked":
            self.revoked = True
        elif e.get("event") in ("resolution", "dns_question", "synthetic_address"):
            self.one(e, self.dns)

    def rec(self, r):
        if self.wait is not None:            # the old name's record waits on this one
            self.settle(r)
        self.one(r, self.recs)
        # v1.36 step 7 (D6a): in a pod a dry run refuses a connect the policy
        # refuses (and a name the proxy would relay) all the same, saying so:
        # only in a dry run under the node agent, a refusal of the policy's, enforced
        if "dry_run_refused" in r:
            seq, problems = r.get("seq"), self.refused
            if r.get("dry_run_refused") is not True:
                problems.append(f"seq {seq}: \"dry_run_refused\" is {r.get('dry_run_refused')!r}; the Warden writes only true")
            elif not self.dry or not isinstance(self.rs.get("node"), dict):
                problems.append(f"seq {seq}: a dry run's refusal in a pod, in a run that is not a dry run under the node agent")
            elif r.get("action") not in ("net.connect", "net.proxy") or r.get("decision_final") != "DENY" or \
                    "enforced" in r:
                problems.append(f"seq {seq}: a dry run's refusal in a pod that is not a refused connect or proxied name")
        self.prev = r

    def pair(self, r, other):
        """a rename let through: both its names decided and recorded, the old
        then the new (v1.29 review)"""
        seq, act = r.get("seq"), r.get("action")
        want = "file.rename_to" if act == "file.rename_from" else "file.rename_from"
        if not other or other.get("action") != want or other.get("enforced") is not False or \
                other.get("agent_pid") != r.get("agent_pid"):
            self.recs.append(f"seq {seq}: a rename let through without its "
                             f"{'new' if want == 'file.rename_to' else 'old'} name decided and recorded "
                             f"{'next' if want == 'file.rename_to' else 'before it'}")

    def one(self, r, problems):
        if "enforced" not in r:
            return
        seq = r.get("seq", r.get("name"))
        if r.get("enforced") is not False:
            problems.append(f"seq {seq}: \"enforced\" is {r.get('enforced')!r}; the Warden writes only false")
            return
        self.n += 1
        if not self.dry:
            problems.append(f"seq {seq}: a record not enforced, in a run that is not a dry run")
            return
        if r.get("event") == "dns_question":
            if r.get("rule") not in ("no_rule", "wildcard_budget"):
                problems.append(f"seq {seq}: a stub question not enforced with rule {r.get('rule')!r}")
        elif r.get("decision_final") != "DENY":
            problems.append(f"seq {seq}: a record not enforced whose verdict is {r.get('decision_final')!r}: "
                            f"a dry run lets through only what the policy refused")
        if r.get("rule") in DRY_NEVER_LET:
            problems.append(f"seq {seq}: {r.get('rule')} let through: a dry run never lets it through")
        act = r.get("action")
        if act == "file.rename_from" and type(seq) is int:
            self.wait = (r, self.revoked)    # its new name is the next record's
            return
        if act == "file.rename_to" and type(seq) is int:
            self.pair(r, self.prev)
        if self.revoked:
            problems.append(f"seq {seq}: a call let through after the run was revoked")

    def settle(self, nx):
        """the old name's record, with the one after it (or none)"""
        r, late = self.wait
        self.wait = None
        self.pair(r, nx)
        if late:
            self.recs.append(f"seq {r.get('seq')}: a call let through after the run was revoked")

    def finish(self, meta, tail):
        if self.wait is not None:            # the stream ended on a rename's old name
            self.settle(None)
        end = meta.get("run_end")
        if self.dry and isinstance(end, dict) and end.get("not_enforced") != self.n:
            tail.append(f"run_end counts {end.get('not_enforced')!r} calls not enforced; the stream holds {self.n}")
        if not self.dry and isinstance(end, dict) and "not_enforced" in end:
            tail.append("run_end counts calls not enforced in a run that is not a dry run")
        return self.dry


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


class ChangesCheck:
    """v1.29: every change by name is in a run whose policy says require
    warden 1.29; an allowed one carries the flags its kind is decided as; a
    rename's old and new names are recorded together (seq n and n+1, the same
    process and outcome), never one without the other. v1.36 (D9): record by
    record; a rename's two names are the record before or the one after."""

    def __init__(self, openas_policy, problems):
        self.openas, self.problems = openas_policy, problems
        self.prev = self.wait = None

    def rec(self, r):
        if self.wait is not None:
            self.next_of(self.wait, r)
            self.wait = None
        problems = self.problems
        act = r.get("action")
        if act in CHANGE_FLAGS and not self.openas:
            problems.append(f"seq {r.get('seq')}: a change by name ({act}) in a run whose "
                            f"policy does not say require warden 1.29")
        elif act in CHANGE_FLAGS and r.get("decision_final") == "ALLOW":
            self.allowed(r)
        self.prev = r

    def next_of(self, r, nx):
        if not nx or nx.get("action") != "file.rename_to" or nx.get("decision_final") != "ALLOW" or \
                nx.get("agent_pid") != r.get("agent_pid") or nx.get("rule") != r.get("rule"):
            self.problems.append(f"seq {r.get('seq')}: a rename allowed without its new name decided and recorded next")

    def allowed(self, r):
        problems = self.problems
        act, seq = r["action"], r.get("seq")
        if r.get("rule") in MKDIR_EXISTS_RULES:                       # step 6
            if act != "file.mkdir" or r.get("open_flags") != "0x0" or r.get("errno") != 17:
                problems.append(f"seq {seq}: {act} recorded {r.get('rule')}, which the Warden writes only for "
                                f"a mkdir decided as a lookup (0x0) and answered EEXIST")
            return
        if r.get("open_flags") not in CHANGE_FLAGS[act]:
            problems.append(f"seq {seq}: {act} allowed as open flags {r.get('open_flags')!r}, not as its "
                            f"kind is decided ({'/'.join(CHANGE_FLAGS[act])})")
        if (act == "file.chdir") != (r.get("rule") == "chdir_continued"):
            problems.append(f"seq {seq}: {act} allowed with rule {r.get('rule')!r}")
        if act == "file.rename_from":
            if type(seq) is int:
                self.wait = r                # its new name is the next record's
            else:
                self.next_of(r, None)
        if act == "file.rename_to":
            pv = self.prev if type(seq) is int else None
            if not pv or pv.get("action") != "file.rename_from" or pv.get("decision_final") != "ALLOW":
                problems.append(f"seq {seq}: a rename's new name allowed without its old name before it")

    def finish(self):
        if self.wait is not None:
            self.next_of(self.wait, None)
            self.wait = None


def _node_launcher(rs):
    """v1.34: does run_start say a node agent's container ran the launcher
    (varek-init) first?"""
    node = rs.get("node")
    return isinstance(node, dict) and node.get("launcher") is True


V127_RULES = ("exec_allowed", "exec_not_in_ruleset", "exec_no_landlock", "exec_identity_mismatch",
              "exec_identity_unreadable", "open_not_found", "subagent_env")


def check_exec_set(meta, launches, problems, boot=None, bad=None, results=False):
    """v1.27: with launches on, run_start records Landlock (its ABI, or null
    without it) and the launch set, and names a Warden of 1.27 or later;
    without, none of them, and no record or event only launches on writes
    (review findings 4 and 5). v1.36 (D9): of the records, the first of the
    agent's own launch (boot), the first only launches on writes (bad), and
    whether an exec_result was written (results): ExecSetScan."""
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
        if bad is not None:
            problems.append(f"seq {bad.get('seq')}: a record with rule {bad.get('rule')!r}, which "
                            f"only a run with launches on (require warden 1.27) writes")
        if results:
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


def check_noexec(meta, rules, launches, problems, quiet=False):
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
    whose path is not its rule's directory as written is refused.
    v1.36 (D9): returns the entries when the records are to be checked
    against them (NoexecLoop, record by record), else None; quiet, it prints
    nothing (asked at run_start)."""
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
        if not quiet:
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
    return nx


class ExecSetScan:
    """v1.36 (D9): what check_exec_set reads of the records: the first
    record of the agent's own launch, the first record only launches on
    writes, and whether any exec_result was written."""

    def __init__(self):
        self.boot = self.bad = None
        self.results = False

    def rec(self, r):
        if self.boot is None and r.get("rule") == "bootstrap_exec_allow":
            self.boot = r
        if self.bad is None and r.get("rule") in V127_RULES:
            self.bad = r

    def ev(self, e):
        if e.get("event") == "exec_result":
            self.results = True


class NoexecLoop:
    """v1.27.1: every open the stream records the agent making for writing
    under a policy rule is under a directory run_start's noexec lists
    (check_noexec's last part, record by record)."""

    def __init__(self, nx, problems):
        self.nx, self.problems = nx, problems

    def rec(self, rec):
        if rec.get("action") != "file.open" or type(rec.get("policy_line")) is not int or \
                rec["policy_line"] < 1 or \
                not (rec.get("decision_final") == "ALLOW" or rec.get("kernel_verdict") == "ALLOW"):
            return
        try:
            flags = int(rec.get("open_flags", "0x0"), 16)
        except (TypeError, ValueError):
            return
        res = rec.get("resolved")
        if _open_writes(flags) and isinstance(res, str) and res.startswith("/") and \
                not any(_nx_under(res, e["path"]) for e in self.nx):
            self.problems.append(f"seq {rec.get('seq')}: the agent opened {res!r} for writing, under no "
                                 f"directory run_start's noexec lists")


EXEC_REFUSALS = ("policy_match", "default_deny_unknown", "certificate_refused", "exec_no_landlock",
                 "exec_not_in_ruleset", "exec_unresolved",
                 # v1.27 review: a launch by a thread another thread's launch is ending:
                 # its path cannot be read, or its image (the call is refused, nothing run)
                 "intent_derivation_failed", "exec_identity_unreadable",
                 # v1.28.1 step 3: a sub-agent's launch the Warden could not make one
                 "subagent_threaded", "subagent_limit", "subagent_depth", "subagent_failed",
                 "subagent_same_image",
                 # v1.36 step 5: under the node agent, a sub-agent launched by the container's
                 # first process itself (it stays in the container's group)
                 "subagent_first_process",
                 # v1.31 review: a confined subject launched with a variable that names code
                 "subagent_env",
                 # v1.31 (the shared soak): a launch after the run was revoked (checked
                 # against the revocation with every other call refused as revoked)
                 "revoked",
                 # v1.35 step 9 (review): a launch the policy allows and the run's plan does not name
                 "outside_plan")
SUBAGENT_REFUSALS = ("subagent_threaded", "subagent_limit", "subagent_depth", "subagent_failed", "subagent_env",
                     "subagent_same_image", "subagent_first_process")
EXEC_RESULTS = ("launched", "failed", "gone", "killed")


class LaunchesCheck:
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
    Asked of the checker. v1.36 (D9): record by record. What it keeps is the
    allowed launches whose exec_result has not come yet (and the last
    DONE_KEPT whose has, for a second one), and the processes killed (each
    a problem already)."""

    ASKED = ("policy_match", "default_deny_unknown", "exec_not_in_ruleset", "exec_no_landlock",
             "certificate_refused") + SUBAGENT_REFUSALS
    DONE_KEPT = 4096

    def __init__(self, checker, policy, rules, rs, sec):
        self.checker, self.policy, self.rules, self.rs = checker, policy, rules, rs
        self.sec = sec
        ex = rs.get("exec_ruleset") if isinstance(rs.get("exec_ruleset"), list) else []
        self.ex = [e for e in ex if isinstance(e, dict)]
        self.first = None                    # the run's first record
        self.boot = None                     # the agent's own launch
        self.nboot = 0
        self.nallowed = self.nrefused = 0
        self.pending = {}                    # seq of an allowed launch -> waiting on its exec_result
        self.done = collections.OrderedDict()   # seq -> exec_results seen (1, or more: a problem)
        self.many = {}                       # seq -> exec_results seen, more than one
        self.killed = 0
        self.kills = {"envk": [], "mism": []}    # [record, the first allowed call after it]
        self.nkills = {"envk": 0, "mism": 0}
        self.after = {}                      # pid -> the kills waiting on an allowed call
        self.asked = Spool()
        for e in self.ex:
            if e.get("why") == "rule":
                self.asked.add(e["name"].encode("utf-8", "surrogateescape").hex() or "=",
                               ("set", e["name"], e.get("policy_line")))

    def rec(self, r):
        if self.first is None:
            self.first = r
        if r.get("rule") == "bootstrap_exec_allow":
            self.nboot += 1
        act, rule, seq = r.get("action"), r.get("rule"), r.get("seq")
        pid = r.get("agent_pid")
        if r.get("decision_final") == "ALLOW" and pid in self.after:
            for k in self.after.pop(pid):
                k[1] = seq                   # the first allowed call after the kill
        if rule == "exec_allowed":
            self.pending[seq] = act == "process.exec"
        if act == "process.exec" and rule == "bootstrap_exec_allow":
            if self.boot is None:
                self.boot = r
        elif act == "process.exec":
            if r.get("decision_final") != "ALLOW":
                self.refused(r)
            elif rule == "exec_allowed":
                self.nallowed += 1
        kind = "mism" if rule == "exec_identity_mismatch" else \
            "envk" if rule == "subagent_env" and act != "process.exec" else None
        if kind:
            self.nkills[kind] += 1
            if len(self.kills[kind]) < PROBLEMS_SHOWN:
                k = [r, None]
                self.kills[kind].append(k)
                if type(seq) is int:
                    self.after.setdefault(pid, []).append(k)

    def refused(self, r):
        self.nrefused += 1
        seq, rule = r.get("seq"), r.get("rule")
        A, C = self.sec["launches_a"], self.sec["launches_c"]
        if rule in self.ASKED and not (isinstance(r.get("resolved"), str) and r["resolved"]):
            A.append(f"seq {seq}: a launch refused as {rule!r} without the name it was decided on")
        if rule in self.ASKED and isinstance(r.get("resolved"), str) and r["resolved"]:
            self.asked.add(r["resolved"].encode("utf-8", "surrogateescape").hex() or "=",
                           ("rec", seq, rule, r.get("policy_line")))
        rs = self.rs
        if rule == "deny_only_nonfile_v191":
            C.append(f"seq {seq}: a launch refused as before 1.27, but the policy decides launches")
        elif rule == "exec_no_landlock" and rs.get("landlock") is not None:
            C.append(f"seq {seq}: a launch refused for want of Landlock, but run_start records it")
        elif rule == "exec_not_in_ruleset" and rs.get("landlock") is None:      # review finding 5
            C.append(f"seq {seq}: a launch refused as not in the set, but without Landlock the "
                     f"Warden refuses every launch for that")
        if rule in ("exec_not_in_ruleset", "exec_no_landlock", "certificate_refused") + SUBAGENT_REFUSALS and \
                r.get("decision_raw") != "ALLOW":
            C.append(f"seq {seq}: a launch refused as {rule!r}, which follows only a decision to "
                     f"allow it, but the decision was {r.get('decision_raw')!r}")
        elif rule == "exec_unresolved" and r.get("decision_raw") not in ("UNKNOWN", "ALLOW"):
            C.append(f"seq {seq}: a launch refused as unresolved after a decision of "
                     f"{r.get('decision_raw')!r}")
        elif rule == "exec_identity_mismatch":
            pass
        elif rule == "outside_plan" and r.get("decision_raw") != "ALLOW":    # v1.35 step 9 (review)
            C.append(f"seq {seq}: a launch refused as outside the plan, which follows only a decision "
                     f"to allow it, but the decision was {r.get('decision_raw')!r}")
        elif rule not in EXEC_REFUSALS:
            C.append(f"seq {seq}: a launch refused with rule {rule!r}, not one the Warden writes")

    def ev(self, e, pos):
        if e.get("event") != "exec_result":
            return
        if e.get("result") == "killed":
            self.killed += 1                 # review finding 2
        ds = e.get("decision_seq")
        if type(ds) is int and ds < pos and e.get("result") in EXEC_RESULTS:
            if ds in self.pending:
                self.done[ds] = [1, self.pending.pop(ds)]
                if len(self.done) > self.DONE_KEPT:
                    self.done.popitem(last=False)
                return
            if ds in self.done:
                self.done[ds][0] += 1
                if self.done[ds][1]:
                    self.many[ds] = self.done[ds][0]
                return
        self.sec["launches_d"].append(f"an exec_result for seq {ds!r} that is not after an allowed launch, or says "
                                      f"{e.get('result')!r}")

    def finish(self, meta, complete, ndec):
        head, ex = self.sec["launches_head"], self.ex
        boot = self.boot
        # review finding 1: the agent's own launch is the run's first record, and the
        # only one; any other is a launch decided like every later one
        if ndec and (boot is None or self.first is not boot or boot.get("seq") != 0):
            head.append("the agent's own launch (bootstrap_exec_allow) is not the run's first record")
        if self.nboot > 1:
            head.append("more than one record of the agent's own launch")
        ids = [(e.get("dev"), e.get("ino")) for e in ex]
        if len(set(ids)) != len(ids):
            head.append("run_start's launch set holds a file twice")
        whys = [e.get("why") for e in ex]
        # (the bootstrap's own entry may read "rule" when a rule admits it too)
        if whys.count("bootstrap") > 1 or whys.count("interpreter") > 1 or ("interpreter" in whys and boot is None):
            head.append("run_start's launch set has more than one bootstrap or interpreter entry, or an "
                        "interpreter without the agent's own launch")
        if "bootstrap" in whys and boot is not None:
            b = ex[whys.index("bootstrap")]
            if b.get("name") != boot.get("target"):
                head.append(f"run_start's launch set names the bootstrap {b.get('name')!r}, but the agent's "
                            f"own launch was {boot.get('target')!r}")
        if any(not str(e.get("name", "")).startswith("/") for e in ex):
            head.append("run_start's launch set holds a name that is not absolute")
        self.holds(self.sec["launches_b"])
        E = self.sec["launches_e"]
        waiting = sorted([(s, 0) for s, launch in self.pending.items() if launch] if complete else [])
        for seq, n in sorted(waiting + list(self.many.items())):
            E.append(f"seq {seq}: an allowed launch with {n} exec_result records, not one")
        F = self.sec["launches_f"]
        if self.killed and not self.nkills["mism"] and not self.nkills["envk"]:
            F.append(f"{self.killed} exec_result records say killed, but no process was killed by the "
                     f"identity check")
        re_ = meta.get("run_end")
        flag = isinstance(re_, dict) and re_.get("exec_identity_mismatch") is True
        if complete and bool(self.nkills["mism"]) != flag:
            F.append("run_end's exec_identity_mismatch does not match the records")
        H = self.sec["launches_h"]
        for r, later in self.kills["envk"]:
            if r.get("decision_final") != "DENY":
                H.append(f"seq {r.get('seq')}: a subagent_env record that is not a refusal")
            H.append(f"seq {r.get('seq')}: pid {r.get('agent_pid')} was launched as a confined subject with "
                     f"{r.get('env')!r} set (it names code), after its launch was decided; it was killed")
            if later is not None:
                H.append(f"seq {later}: pid {r.get('agent_pid')} was allowed a call after it was killed")
        for _ in range(self.nkills["envk"] - len(self.kills["envk"])):
            H.append("(a process killed for its environment)")
        for r, later in self.kills["mism"]:
            H.append(f"seq {r.get('seq')}: pid {r.get('agent_pid')} ran {r.get('exe')!r}, not a program "
                     f"the Warden decided to run; it was killed (exec_identity_mismatch)")
            if later is not None:
                H.append(f"seq {later}: pid {r.get('agent_pid')} was allowed a call after it was killed")
        for _ in range(self.nkills["mism"] - len(self.kills["mism"])):
            H.append("(a process killed by the identity check)")
        return self.nallowed, self.nrefused

    def holds(self, B):
        if not len(self.asked):
            return
        ok, out, n, err = self.asked.ask(self.checker, self.policy, "holds")
        if not ok or n != len(self.asked):
            B.append(f"checker failed on the launches: {err.strip()}")
            return
        rules = self.rules
        exec_rules = [i for i, r in enumerate(rules) if r["kind"] == "e"]
        for ctx, row in zip(self.asked.contexts(), spool_words(out)):
            first = next((i for i in exec_rules if i < len(row) and row[i] == "1"), None)
            fr = rules[first] if first is not None else None
            if ctx[0] == "set":                              # a set entry admitted by a rule
                _, name, line = ctx
                if fr is None or not fr["allow"] or fr["line"] != line:
                    B.append(f"run_start's launch set holds {name!r} as admitted by line "
                             f"{line!r}, which does not allow it")
                continue
            _, seq, rule, line = ctx
            if rule == "default_deny_unknown" and fr is not None:
                B.append(f"seq {seq}: a launch refused as matching no rule, but line {fr['line']} matches it")
            elif rule == "policy_match" and (fr is None or fr["allow"] or fr["line"] != line):
                B.append(f"seq {seq}: a launch refused by line {line!r}, which is not the deny rule "
                         f"that decides it")
            elif rule in ("exec_not_in_ruleset", "exec_no_landlock", "certificate_refused") + SUBAGENT_REFUSALS \
                    and (fr is None or not fr["allow"]):
                B.append(f"seq {seq}: a launch refused as {rule!r}, but the policy does not "
                         f"allow its name")


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
                      "resolution_failed", "address_refused", "run_ended", "revoked",   # v1.28: revoked
                      "outside_plan")       # v1.35 step 8: a held run's connection the plan names not (check_hold)
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
    always handed over. Asked of the checker; handoffs is a Spool of each
    candidate (the record's seq, the candidate's place among its record's,
    the last of them)."""
    if not len(handoffs):
        return
    ok, out, n, err = handoffs.ask(checker, policy, "holds")
    if not ok or n != len(handoffs):
        problems.append(f"checker failed on the hand-offs' candidates: {err.strip()}")
        return
    hosts = [i for i, r in enumerate(rules) if r["kind"] == "h"]
    best = None                           # (rule index, candidate index)
    for (seq, ci, last), row in zip(handoffs.contexts(), spool_words(out)):
        first = next((i for i in hosts if row[i] == "1"), None)
        if first is not None and (best is None or first < best[0]):
            best = (first, ci)
        if not last:
            continue
        if best is not None:
            r = rules[best[0]]
            if not r["allow"]:
                problems.append(f"seq {seq}: a connect policy line {r['line']} denies was handed "
                                f"to the proxy")
            elif best[1] == 0:
                problems.append(f"seq {seq}: a connect policy line {r['line']} allows by its "
                                f"address was handed to the proxy, not dialed")
        best = None


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
        elif line == "require plan":
            pass                                   # v1.35 step 4b: policy_requires_plan reads it
        elif f[0] == "mcp-resource" and len(f) == 3:                  # v1.31
            mres[f[1]] = None if f[2] == "-" else f[2]
        elif f[0] in ("confined", "for") and len(f) in (3, 6):
            pass                                   # v1.31: policy_confined reads them
        elif line.strip():
            raise ValueError(f"an unexpected line from the checker: {line!r}")
    return iss, dom, sub, req, mres


def policy_requires_plan(checker, policy):
    """v1.35 step 4b (D7): whether the policy says `require plan`, as the
    checker reads it (`identity`)"""
    q = subprocess.run([checker, policy, "identity"], capture_output=True, text=True)
    if q.returncode != 0:
        raise ValueError(q.stderr.strip() or "the checker has no identity mode")
    return "require plan" in q.stdout.splitlines()


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


class SubjectsCheck:
    """v1.31 (section 6): each decision that names a policy line names a
    rule of the subject it was made for: a confined subject's decisions only
    its own `for=` rules, the agent's (and an unconfined sub-agent's) only
    rules without one. The subject is the record's chain's (the Warden's
    attribution), the rule's the policy's, as the checker reads it."""

    def __init__(self, confined, forl, problems):
        self.confined, self.forl, self.problems = confined, forl, problems

    def rec(self, rec):
        line = rec.get("policy_line")
        if "decision_final" not in rec:
            return
        if type(line) is not int:
            # v1.31 review: a line given as a string or a float would pass the check below unseen
            self.problems.append(f"seq {rec.get('seq')}: a decision whose policy_line {line!r} is not an integer")
            return
        if line <= 0:
            return
        ks = expected_subject(rec.get("obo"), self.confined)
        kr = self.forl.get(line, 0)
        if ks != kr:
            self.problems.append(f"seq {rec.get('seq')}: a decision for subject {ks} (its chain {rec.get('obo')!r}) "
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


class TokenScan:
    """v1.31 (section 6): no token value anywhere the Warden or its helpers
    write: no JWT in any record of the run outside the fields that echo what
    the agent sent. (The values the run holds are never written: a
    credential is recorded by its placeholder's SHA-256, the user's token
    by its SHA-256.) v1.36 (D9): each record of the run as it is read (no
    second read of the stream)."""

    def __init__(self, problems):
        self.problems = problems

    def line(self, rec, i):
        problems = self.problems

        def walk(v, key, top, where):
            if isinstance(v, dict):
                for k, x in v.items():
                    walk(x, k, False, where)
            elif isinstance(v, list):
                for x in v:
                    walk(x, key, False, where)
            elif isinstance(v, str) and not (top and key in AGENT_FIELDS) and JWT_RX.search(v):
                problems.append(f"{where}: a token value in the stream (field {key!r})")
        # v1.31 review: only a decision (or a DNS question) echoes what the
        # agent sent; the Warden's other records are its own words
        echo = "decision_final" in rec or rec.get("event") == "dns_question"
        for k, x in rec.items():
            walk(x, k, echo, f"line {i}")
JWT_ALGS = ("RS256", "PS256", "ES256", "EdDSA")


class ChainCheck:
    """v1.28.1 (section 5): who each decision was for. run_start's
    on_behalf_of: a user only verified by an issuer the policy trusts, with
    its audience, not expired at the start (and one if the policy requires
    it); an agent of this run, its SPIFFE ID verified in a trust domain the
    policy trusts, its control group when the policy names a sub-agent; the
    operator, unverified. Every decision record's obo resolves: "user" only
    with a user, then "agent", then each sub-agent after the launch that
    started it (by a rule with that subagent=, from the chain before it),
    never after its launch failed; the proxy's records are their hand-off's.
    finish() returns {sub-agent: decisions}, or None when the Warden predates
    the chain. v1.36 (D9): record by record; what it keeps is the run's
    sub-agents (at most SUB_MAX, the Warden's) and the open connections'
    chains."""

    def __init__(self, ident, rs, run, sec):
        self.ident, self.rs, self.run, self.sec = ident, rs, run, sec
        iss, dom, subrules, req, mres = ident
        self.subrules = subrules
        self.old = not _version_at_least(rs.get("warden"), (1, 28, 1))
        self.any_obo = False
        obo = rs.get("on_behalf_of")
        self.on = not self.old and isinstance(obo, dict) and isinstance(obo.get("agent"), dict) and \
            obo["agent"].get("run") == run
        user = obo.get("user") if self.on else None
        self.cg = obo["agent"].get("cgroup") if self.on else None
        self.base = ["user", "agent"] if user is not None else ["agent"]
        self.started = {}                # "NAME#n" -> (line of its launch record, the launcher's chain, cgroup)
        # v1.28.1 review: how each launch settled (subagent_settled, once, after
        # its launch); a decision for a sub-agent only after it settled launched
        self.settled = {}                # "NAME#n" -> (line, "launched" | "failed")
        self.count, self.per_name, self.conn_obo = {}, {}, {}
        self.launch_of = {}              # seq -> the sub-agent its record names (an exec_result's launch)
        self.waiting = {}                # sub-agent -> the outcomes its exec_result said, until it settled

    def head(self, problems):
        iss, dom, subrules, req, mres = self.ident
        rs = self.rs
        if self.old:
            if "on_behalf_of" in rs or self.any_obo:
                problems.append("run_start or a record names who a decision was for, but only a Warden of 1.28.1 "
                                "or later records it")
            if req or subrules or iss or dom:
                problems.append("the policy trusts an issuer or a trust domain, requires a user or names a "
                                "sub-agent, which only a Warden of 1.28.1 or later reads")
            return
        obo = rs.get("on_behalf_of")
        if not self.on:
            problems.append("run_start has no on_behalf_of naming this run's agent")
            return
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

    def ev(self, e, line):
        event = e.get("event")
        if event == "proxy_close":
            self.conn_obo.pop(e.get("proxy_conn"), None)
        if not self.on:
            return
        if event == "subagent_settled":
            tag = e.get("subagent")
            if not isinstance(tag, str) or e.get("result") not in ("launched", "failed") or tag in self.settled:
                self.sec["chain_settled"].append(f"a subagent_settled event that is malformed, or a second for {tag!r}")
                return
            self.settled[tag] = (line, e["result"])
            for res in self.waiting.pop(tag, []):
                self.outcome(tag, res)
        elif event == "exec_result":
            # each launch's exec_result is its own: the sub-agent its launch
            # record names (by decision_seq), and, once settled, the same outcome
            tag = e.get("subagent")
            want = self.launch_of.get(e.get("decision_seq")) if type(e.get("decision_seq")) is int else None
            if tag != want:
                self.sec["chain_results"].append(f"an exec_result for the launch at seq {e.get('decision_seq')} names "
                                                 f"sub-agent {tag!r}, but that launch started {want!r}")
            elif tag is not None and e.get("result") in ("launched", "failed"):
                if tag in self.settled:
                    self.outcome(tag, e["result"])
                elif len(self.waiting) <= SUB_MAX:
                    self.waiting.setdefault(tag, []).append(e["result"])

    def outcome(self, tag, res):
        if res != self.settled[tag][1]:
            self.sec["chain_results"].append(f"sub-agent {tag}'s exec_result says {res}, but it settled "
                                             f"{self.settled[tag][1]}")

    def rec(self, r, line):
        if "obo" in r:
            self.any_obo = True
        if not self.on:
            return
        problems, base, subrules = self.sec["chain_recs"], self.base, self.subrules
        started, settled = self.started, self.settled
        ob = r.get("obo")
        seq = r.get("seq")
        if "subagent" in r and len(self.launch_of) <= SUB_MAX:
            self.launch_of[seq] = r.get("subagent")
        if r.get("rule") == "subagent_unattributed":
            if ob != [] or r.get("decision_final") != "DENY":
                problems.append(f"seq {seq}: refused as in no group of the run, but not with an empty obo")
            return
        # v1.28.1 review: a call refused because its thread had gone, whose
        # group could not be read either
        if ob == [] and r.get("decision_final") == "DENY" and \
                r.get("rule") in ("intent_derivation_failed", "exec_identity_unreadable", "exec_identity_mismatch"):
            return
        if not (isinstance(ob, list) and all(isinstance(x, str) for x in ob) and ob[:len(base)] == base):
            problems.append(f"seq {seq}: obo {ob!r} does not begin with {base!r}")
            return
        chain = ob[len(base):]
        tags = []
        for k, x in enumerate(chain):
            m = SUBAGENT_TAG.fullmatch(x)
            if not m:
                problems.append(f"seq {seq}: obo names {x!r}, not a sub-agent")
                break
            tag = f"{m.group(1)}#{m.group(2)}"
            st = started.get(tag)
            if st is None:
                problems.append(f"seq {seq}: a decision for sub-agent {tag} before (or without) a launch that "
                                f"started it")
                break
            if st[1] != ob[:len(base) + k]:
                problems.append(f"seq {seq}: sub-agent {tag} in a chain other than the one that launched it")
                break
            se = settled.get(tag)
            if se is None:
                problems.append(f"seq {seq}: a decision for sub-agent {tag} before its launch is known to have "
                                f"happened (subagent_settled)")
                break
            if se[1] != "launched":
                problems.append(f"seq {seq}: a decision for sub-agent {tag} after its launch failed")
                break
            tags.append(tag)
        else:
            if tags:
                self.count[tags[-1]] = self.count.get(tags[-1], 0) + 1
        if r.get("rule") in SUBAGENT_REFUSALS and not subrules.get(r.get("policy_line")):
            problems.append(f"seq {seq}: a launch refused as {r.get('rule')!r}, but policy line "
                            f"{r.get('policy_line')} names no sub-agent")
        # a sub-agent's launch: by a rule with that subagent=, numbered in order
        if "subagent" in r:
            tag, pline = r.get("subagent"), r.get("policy_line")
            m = SUBAGENT_TAG.fullmatch(f"subagent:{tag}") if isinstance(tag, str) else None
            if not (r.get("action") == "process.exec" and r.get("rule") == "exec_allowed" and m):
                problems.append(f"seq {seq}: names a sub-agent {tag!r}, but is not an allowed launch")
            elif subrules.get(pline) != m.group(1):
                problems.append(f"seq {seq}: starts sub-agent {tag}, but policy line {pline} names "
                                f"{subrules.get(pline) or 'no sub-agent'}")
            elif int(m.group(2)) != self.per_name.get(m.group(1), 0) + 1 or tag in started:
                problems.append(f"seq {seq}: sub-agent {tag} is not the next launch of {m.group(1)}")
            else:
                self.per_name[m.group(1)] = int(m.group(2))
                want = (self.cg or "") + "".join("/" + t.replace("#", "-") for t in tags + [tag])
                if r.get("cgroup") != want:
                    problems.append(f"seq {seq}: sub-agent {tag}'s control group is {r.get('cgroup')!r}, not {want!r}")
                started[tag] = (line, ob, r.get("cgroup"))
                self.count.setdefault(tag, 0)
        elif r.get("action") == "process.exec" and r.get("rule") == "exec_allowed" and subrules.get(r.get("policy_line")):
            problems.append(f"seq {seq}: a launch allowed by policy line {r.get('policy_line')}, which names "
                            f"sub-agent {subrules[r.get('policy_line')]}, started none")
        # the proxy's records are for whom the hand-off was
        if r.get("proxy_handoff") is True and type(r.get("proxy_conn")) is int:
            self.conn_obo[r["proxy_conn"]] = ob
        elif r.get("action") in ("net.proxy", "net.request", "net.mcp") and type(r.get("proxy_conn")) is int:
            want = self.conn_obo.get(r["proxy_conn"])
            if want is not None and ob != want:
                problems.append(f"seq {seq}: the proxy's decision on connection {r['proxy_conn']} is for {ob!r}, "
                                f"not {want!r}, whom the agent's connect was for")

    def finish(self):
        self.head(self.sec["chain_head"])
        if self.old:
            return None
        if not self.on:
            return {}
        problems = self.sec["chain_end"]
        for tag, (line, _) in self.settled.items():
            if tag not in self.started or self.started[tag][0] > line:
                problems.append(f"sub-agent {tag} settled, but no launch started it before")
        # a launched sub-agent with no decision of its own counts too (0)
        for tag in self.started:
            if tag not in self.settled or self.settled[tag][1] != "failed":
                self.count.setdefault(tag, 0)
        return self.count


def chain_summary(per_sub):
    """v1.30: the sub-agents by name, as the chain line shows them: how many
    were launched and how many decisions they had, with the range per launch
    when it varies (a 24-hour run launches hundreds of each)."""
    by = {}
    for tag, n in per_sub.items():
        by.setdefault(tag.rsplit("#", 1)[0], []).append(n)
    out = []
    for name in sorted(by):
        ns = by[name]
        each = f"{ns[0]} each" if min(ns) == max(ns) else f"{min(ns)} to {max(ns)} each"
        out.append(f"{name} {len(ns)} launch{'es' if len(ns) != 1 else ''}, "
                   f"{sum(ns)} decision{'s' if sum(ns) != 1 else ''}"
                   f"{f' ({each})' if len(ns) > 1 else ''}")
    return "; ".join(out) if out else "none"


class CredentialsCheck:
    """v1.28 (section 5): run_start lists the policy's credentials (name,
    store, reference, in order; a version, a length, a placeholder's SHA-256;
    the helper's SHA-256), and none when the policy names none. Every
    request that carried a credential was allowed by a rule that names that
    credential and header, and every request such a rule allowed carried it;
    each refused swap follows the allowed request it refused. After
    `revoked` (by root, once) every decision is UNSATISFIED; the proxy's and
    the helper's answers follow it, the proxy holding no value; no lease is
    renewed after the helper revoked them. finish() returns (carried, swaps
    refused, revoked). v1.36 (D9): record by record, in stream order; what
    it keeps is the open connections' requests that carried a credential."""

    def __init__(self, creds, cred_rules, auds, rs, sec, notes):
        self.creds, self.cred_rules, self.auds, self.rs = creds, cred_rules, auds or {}, rs
        self.sec, self.notes = sec, notes
        self.names = {c[0]: c for c in creds}
        obo = rs.get("on_behalf_of") if isinstance(rs.get("on_behalf_of"), dict) else {}
        self.user = obo.get("user") if isinstance(obo.get("user"), dict) else None
        u = self.user
        self.exp_ns = u["expires"] * 1000000000 if u is not None and type(u.get("expires")) is int else None
        self.nrv = self.nex = 0
        self.rv = self.ex = None             # the first revocation, the first expiry of the user's token
        self.rline = self.exline = None
        self.between = 0                     # records and credential events between the expiry and the revocation
        self.prev_ts = None                  # the last timestamp, in stream order
        self.order_bad = False
        self.last_ts = None
        self.allowed_after_expiry = False
        self.carried = 0
        self.allowed_with = {}               # proxy_conn -> {request_seq: (credential, line)}
        self.refused_swaps = 0
        self.rp = self.rl = None
        self.failed_renewal = set()

    def after(self, line):
        return self.rline is not None and line > self.rline

    def stamp(self, x, line):
        """v1.28.1 review: the records are in time order (1 s of slack for the
        clock)"""
        t = x.get("timestamp_ns")
        if type(t) is not int:
            return
        if self.prev_ts is not None and t < self.prev_ts - 1000000000 and not self.order_bad:
            self.order_bad = True
            self.sec["cred_time"].append(f"line {line}: a record timestamped before the one before it (the stream is "
                                         f"not in time order)")
        self.prev_ts = t
        self.last_ts = t if self.last_ts is None else max(self.last_ts, t)

    def ev(self, e, line):
        event = e.get("event")
        if event in ("exec_result", "subagent_settled"):
            self.stamp(e, line)
            return
        if event == "proxy_close":
            # v1.28 review: the proxy's refusals for the revocation follow it
            if e.get("why") == "revoked" and not self.after(line):
                self.sec["cred_closes"].append(f"connection {e.get('proxy_conn')!r} closed as revoked, but no "
                                               f"revocation is recorded before it")
            self.allowed_with.pop(e.get("proxy_conn"), None)
            return
        if event == "dns_question":
            # and after it the stub looks nothing up
            if (e.get("rule") == "revoked") != self.after(line):
                self.sec["cred_dns"].append(f"a stub question {'refused as revoked before' if e.get('rule') == 'revoked' else 'answered after'} "
                                            f"the revocation")
            return
        if event not in CRED_EVENTS:
            return
        self.stamp(e, line)
        if event == "revoked":
            self.nrv += 1
            if self.rv is None:
                self.rv, self.rline = e, line
        elif event == "on_behalf_of_expired":
            self.nex += 1
            if self.ex is None:
                self.ex, self.exline = e, line
        if self.ex is not None and self.rline is None and line > self.exline:
            self.between += 1
        self.event(e, line)

    def event(self, e, line):
        problems, notes = self.sec["cred_events"], self.notes
        ev = e.get("event")
        if ev == "credential_refused":
            key = (e.get("proxy_conn"), e.get("request_seq"))
            got = self.allowed_with.get(key[0], {}).get(key[1]) if all(type(k) is int for k in key) else None
            if got is None or got[0] != e.get("credential") or got[1] >= line or not isinstance(e.get("why"), str):
                problems.append(f"a credential_refused for connection {key[0]!r} request {key[1]!r} that follows "
                                f"no allowed request carrying {e.get('credential')!r}")
            self.refused_swaps += 1
        elif ev in ("revocation_proxy", "revocation_leases"):
            if not self.after(line):
                problems.append(f"{ev} without the run being revoked before it")
                return
            if ev == "revocation_proxy":
                if self.rp is not None:
                    problems.append("revocation_proxy recorded more than once")
                self.rp = e
                if e.get("values_held") != 0:
                    problems.append(f"after the revocation the proxy still held {e.get('values_held')!r} "
                                    f"credential value(s)")
            else:
                if self.rl is not None:
                    problems.append("revocation_leases recorded more than once")
                self.rl = line
                if type(e.get("revoked")) is not int or type(e.get("failed")) is not int:
                    problems.append("a malformed revocation_leases record")
                elif e["failed"]:
                    notes.append(f"{e['failed']} Vault lease(s) could not be revoked (they end at their "
                                 f"duration)")
        elif ev in ("lease_renewed", "lease_renewal_failed"):
            c = self.names.get(e.get("credential"))
            if c is None or c[1] != "vault":
                problems.append(f"{ev} for {e.get('credential')!r}, which is not one of the policy's Vault "
                                f"credentials")
            elif self.rl is not None and line > self.rl:
                problems.append(f"{ev} for {c[0]} after the helper revoked the run's leases")
            elif c[0] in self.failed_renewal:
                problems.append(f"{ev} for {c[0]} after its renewal failed (a failed renewal is not retried)")
            elif ev == "lease_renewed" and type(e.get("ttl")) is not int:
                problems.append(f"lease_renewed for {c[0]} without its new duration")
            elif ev == "lease_renewal_failed":
                self.failed_renewal.add(c[0])
                notes.append(f"the lease of credential {c[0]} could not be renewed: {e.get('why')}")

    def rec(self, rec, line):
        self.stamp(rec, line)
        if self.ex is not None and self.rline is None and line > self.exline:
            self.between += 1
        # nothing is allowed after the user's token's expiry unless an expiry
        # recorded before it says the run goes on
        if self.exp_ns is not None and not self.allowed_after_expiry and \
                rec.get("decision_final") == "ALLOW" and type(rec.get("timestamp_ns")) is int \
                and rec["timestamp_ns"] > self.exp_ns + 2000000000 and \
                not (self.ex is not None and self.ex.get("action") == "record"):
            self.allowed_after_expiry = True
            self.sec["cred_expiry"].append(f"seq {rec.get('seq')}: allowed after the user's token expired, with no "
                                           f"expiry recorded before it that lets the run go on")
        problems = self.sec["cred_recs"]
        if self.after(line) and rec.get("decision_final") != "DENY":
            problems.append(f"seq {rec.get('seq')}: a decision {rec.get('decision_final')!r} after the run was "
                            f"revoked (every decision after it is UNSATISFIED)")
            return
        # v1.28 review: a refusal for the revocation follows it
        if rec.get("rule") == "revoked" and not self.after(line):
            problems.append(f"seq {rec.get('seq')}: refused as revoked, but no revocation is recorded before it")
            return
        if rec.get("action") not in ("net.request", "net.mcp"):          # v1.31: an MCP call too
            return
        has = "credential" in rec or "credential_header" in rec
        allowed = rec.get("decision_final") == "ALLOW" and \
            rec.get("rule") == ("mcp_allowed" if rec.get("action") == "net.mcp" else "request_allowed")
        want = self.cred_rules.get(rec.get("policy_line")) if allowed else None
        if has:
            if not allowed or want is None or (rec.get("credential"), rec.get("credential_header")) != want[:2]:
                problems.append(f"seq {rec.get('seq')}: a request that carried credential "
                                f"{rec.get('credential')!r} in {rec.get('credential_header')!r}, which its "
                                f"deciding rule (line {rec.get('policy_line')!r}) does not name")
                return
            self.carried += 1
            # v1.31 (section 6): an MCP token only on an allowed MCP call to its server
            ad = self.auds.get(rec.get("credential"))
            if ad is not None and (rec.get("action") != "net.mcp" or rec.get("mcp_url") != ad[0]):
                problems.append(f"seq {rec.get('seq')}: MCP token {rec.get('credential')} (for {ad[0]}) released "
                                f"on {'a call to ' + str(rec.get('mcp_url')) if rec.get('action') == 'net.mcp' else 'a request'}")
                return
            # v1.31: an MCP token is not released past its expiry
            rs = self.rs
            ex = next((e.get("expires") for e in (rs.get("credentials") if isinstance(rs.get("credentials"), list) else []) if isinstance(e, dict)
                       and e.get("name") == rec.get("credential") and "audience" in e), None)
            if type(ex) is int and type(rec.get("timestamp_ns")) is int and rec["timestamp_ns"] >= (ex + 1) * 1000000000:
                problems.append(f"seq {rec.get('seq')}: MCP token {rec.get('credential')} released after its expiry")
            key = (rec.get("proxy_conn"), rec.get("request_seq"))
            if all(type(k) is int for k in key):
                self.allowed_with.setdefault(key[0], {})[key[1]] = (rec["credential"], line)
        elif want is not None:
            problems.append(f"seq {rec.get('seq')}: an allowed request whose rule (line {rec.get('policy_line')}) "
                            f"names credential {want[0]}, recorded without it")

    def head(self, complete, problems):
        rs, creds, auds = self.rs, self.creds, self.auds
        listed = rs.get("credentials")
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
                aud = auds.get(c[0])
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
        if self.nrv > 1:
            problems.append("the run is recorded revoked more than once")
        # v1.28.1 step 4: the user's token's expiry. Once at most, for the user
        # run_start names, at or after its expiry, doing what run_start says; a
        # revocation it makes follows it (unless the run was revoked already).
        user, ex, rv = self.user, self.ex, self.rv
        if self.nex > 1:
            problems.append("the user's token is recorded expired more than once")
        if ex is not None:
            e = ex
            if user is None:
                problems.append("on_behalf_of_expired, but run_start names no user")
            elif e.get("expires") != user.get("expires") or e.get("subject") != user.get("subject") \
                    or e.get("action") != user.get("on_expiry", "revoke"):
                problems.append("on_behalf_of_expired does not match the user run_start names (subject, expiry, "
                                "what is done)")
            elif type(e.get("timestamp_ns")) is not int or type(user.get("expires")) is not int \
                    or e["timestamp_ns"] < user["expires"] * 1000000000:
                problems.append("on_behalf_of_expired is recorded before the token expired")
        by_expiry = rv is not None and rv.get("by") == "on_behalf_of_expiry"
        if rv is not None and by_expiry:
            if ex is None or ex.get("action") != "revoke" or self.exline > self.rline:
                problems.append("the run is recorded revoked for the user's token's expiry, but no expiry that "
                                "revokes is recorded before it")
        elif rv is not None and not (rv.get("by_uid") == 0 and type(rv.get("by_pid")) is int and rv["by_pid"] > 0):
            problems.append("the run is recorded revoked by a peer that is not root, or without who asked")
        if ex is not None and ex.get("action") == "revoke" and rv is None:
            problems.append("the user's token expired and the run should have been revoked, but no revocation "
                            "is recorded")
        self.by_expiry = by_expiry

    def finish(self, complete):
        self.head(complete, self.sec["cred_head"])
        # the expiry is recorded as soon as the token expired, its revocation
        # next, with nothing between; a stream, whole or not, that runs past
        # the expiry records it
        if self.ex is not None and self.rv is not None and self.by_expiry and self.between:
            self.sec["cred_between"].append("records between the token's expiry and the revocation it made (it is "
                                            "made at once)")
        if self.exp_ns is not None and self.ex is None and self.last_ts is not None and \
                self.last_ts > self.exp_ns + 2000000000:
            self.sec["cred_unrecorded"].append("the user's token expired during the run, but its expiry is not "
                                               "recorded (on_behalf_of_expired)")
        if self.rline is not None and complete and self.creds and self.rp is None:
            self.notes.append("the run was revoked, but the proxy never answered that it cleared its values")
        return self.carried, self.refused_swaps, self.rline is not None


def check_dialed_denies(checker, policy, rules, dialed, problems):
    """v1.26 review: the Warden dials no address a rule denies: for each
    address a proxied connection dialed (addr:port), the first host rule that
    holds on it must not be a deny. Asked of the checker; dialed is their
    Spool."""
    if not len(dialed):
        return
    ok, out, n, err = dialed.ask(checker, policy, "holds")
    if not ok or n != len(dialed):
        problems.append(f"checker failed on the addresses dialed: {err.strip()}")
        return
    hosts = [i for i, r in enumerate(rules) if r["kind"] == "h"]
    for (seq, d), row in zip(dialed.contexts(), spool_words(out)):
        first = next((i for i in hosts if row[i] == "1"), None)
        if first is not None and not rules[first]["allow"]:
            problems.append(f"seq {seq}: a proxied connection dialed {d}, which policy line "
                            f"{rules[first]['line']} denies")


REQUEST_REFUSE_RULES = ("policy_match", "default_deny_unknown", "certificate_refused", "max_body",
                        "fragment_escape_length", "revoked",       # v1.28: revoked
                        "mcp_query",                               # v1.31: a POST to an MCP endpoint with a query
                        "mcp_endpoint_variant",                    # review: to another spelling of one
                        "outside_plan")                            # v1.35 step 8: a held run (check_hold)

# v1.31 (section 3): an MCP call's refusals (net.mcp): by the policy, or a
# call the proxy could not read (mcp_unreadable), whose Mcp-Method or
# Mcp-Name header disagrees with its body (mcp_header_mismatch), or whose
# body is over the limit (max_body)
MCP_REFUSE_RULES = ("policy_match", "default_deny_unknown", "certificate_refused", "max_body",
                    "fragment_escape_length", "revoked", "mcp_unreadable", "mcp_header_mismatch",
                    # step 5: the agent's own bearer token (D6), a credential past its expiry
                    "mcp_token_user", "mcp_token_audience", "mcp_token_expired", "mcp_token_malformed",
                    "credential_expired",
                    "outside_plan")         # v1.35 step 8: a held run's call no step names (check_hold)
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


class RequestsCheck:
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
    it). v1.36 (D9): in stream order as it comes; what it keeps is the
    connections not yet closed (and the ids of those closed)."""

    def __init__(self, rules, problems, refused):
        self.rules, self.problems, self.refused = rules, problems, refused
        self.conns = {}                  # proxy_conn -> (position, name:port, scheme): passed on to be inspected
        self.state = {}                  # proxy_conn -> {"next", "refused", "closed", "body": pending or None}
        self.closed_insp = IdSet()       # closed, and passed on to be inspected
        self.closed = IdSet()            # closed
        self.n = 0                       # requests (and MCP calls)

    def rec(self, rec, pos):
        if rec.get("action") == "net.proxy" and rec.get("rule") == "proxy_dialed" and \
                rec.get("inspected") is True and type(rec.get("proxy_conn")) is int and \
                rec["proxy_conn"] not in self.closed_insp:
            self.conns.setdefault(rec["proxy_conn"], (pos, rec.get("target"),
                                                      "http" if rec.get("proxy_kind") == "http" else "https"))
        if rec.get("action") in ("net.request", "net.mcp"):
            self.request(rec, pos)
            # v1.26.1 (step 7): a refused request is asked of the policy again
            # (check_refused_requests)
            if rec.get("decision_final") == "DENY" and \
                    rec.get("rule") in ("policy_match", "default_deny_unknown", "max_body") and \
                    isinstance(rec.get("resolved" if rec.get("action") == "net.mcp" else "target"), str) and \
                    (rec.get("action") == "net.request" or rec.get("resolved")):
                obj = rec["resolved"] if rec.get("action") == "net.mcp" else rec["target"]
                self.refused.add(obj.encode().hex(),
                                 {k: rec.get(k) for k in ("seq", "rule", "policy_line", "obo", "action",
                                                          "body_len", "body_declared")})

    def ev(self, e):
        event = e.get("event")
        if event not in ("proxy_close", "request_body"):
            return
        cid = e.get("proxy_conn")
        if type(cid) is not int:
            self.problems.append(f"a {e.get('event')} record with a malformed connection id {cid!r}")
            return
        if event == "proxy_close":
            st = self.state.pop(cid, None)
            if st and st["body"] is not None and e.get("why") != "unreported":
                self.problems.append(f"connection {cid}: closed with the body of request {st['body'][0]} never "
                                     f"recorded (a request_body is missing)")
            if cid in self.conns or cid in self.closed_insp:
                self.closed_insp.add(cid)
            self.conns.pop(cid, None)
            self.closed.add(cid)
            return
        self.body(e, cid)

    def body(self, b, cid):
        problems = self.problems
        rs = b.get("request_seq")
        st = self.state.get(cid)
        if cid in self.closed:
            problems.append(f"connection {cid}: a request_body after the connection's close")
            return
        if not st or st["body"] is None or st["body"][0] != rs:
            problems.append(f"a request_body for connection {cid!r} request {rs!r}, which has no body pending")
            return
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
            st["cut"] = True                             # review: the connection was cut there

    def request(self, rec, pos):
        problems, rules = self.problems, self.rules
        cid = rec.get("proxy_conn")
        if type(cid) is not int:
            problems.append(f"a net.request record with a malformed connection id {cid!r}")
            return
        self.n += 1
        seq, rs = rec.get("seq"), rec.get("request_seq")
        if cid in self.closed and (cid in self.closed_insp or cid in self.conns):
            problems.append(f"seq {seq}: a request of connection {cid} after its close")
            return
        if cid not in self.conns or self.conns[cid][0] >= pos:
            problems.append(f"seq {seq}: a request of connection {cid!r}, which was not passed on to be inspected")
            return
        st = self.state.setdefault(cid, {"next": 1, "refused": False, "closed": False, "body": None})
        if st["refused"]:
            problems.append(f"seq {seq}: a request of connection {cid} after one was refused")
            return
        if st.get("cut"):
            problems.append(f"seq {seq}: a request of connection {cid} after its body passed max_body (it was cut)")
            return
        if rs != st["next"] or st["body"] is not None:
            problems.append(f"seq {seq}: request {rs!r} of connection {cid} out of order, or before the last body")
            return
        st["next"] += 1
        if rec.get("action") == "net.mcp":                 # v1.31
            check_mcp_call(rec, rules, st, self.conns[cid], problems)
            return
        obj, (_, hp, scheme) = rec.get("target"), self.conns[cid]
        m = re.fullmatch(r"([A-Z]{1,20}) " + re.escape(f"{scheme}://{hp}") + r"(/[\x21-\x7e]*)", str(obj))
        if not m or obj != rec.get("resolved") or rec.get("body") not in ("none", "length", "chunked"):
            problems.append(f"seq {seq}: a request object {obj!r} that is not one of connection {cid} ({scheme}://{hp})")
            return
        bad = target_problem(m.group(2))
        if bad:
            problems.append(f"seq {seq}: a request object {obj!r} with {bad}, which the proxy must refuse")
            return
        # v1.31: every POST to an MCP endpoint is an MCP call (net.mcp); one
        # with a query is refused as such, and only that is mcp_query
        url, qm, _ = obj.partition(" ")[2].partition("?")
        ep = m.group(1) == "POST" and mcp_endpoint(rules, url) is not None
        if ep and not qm:
            problems.append(f"seq {seq}: a POST to the MCP endpoint {url} decided as a request, not as an MCP call")
            return
        if rec.get("rule") == "mcp_query" and not ep:
            problems.append(f"seq {seq}: a request refused as a POST with a query to an MCP endpoint, which it is not")
            return
        if ep and rec.get("rule") != "mcp_query":
            problems.append(f"seq {seq}: a POST with a query to the MCP endpoint {url} decided by request rules "
                            f"(it is refused, mcp_query)")
            return
        var = m.group(1) == "POST" and mcp_variant(rules, url)
        if var != (rec.get("rule") == "mcp_endpoint_variant") or (var and rec.get("decision_final") != "DENY"):
            problems.append(f"seq {seq}: a request to {url} " + (
                "decided by request rules, but it is another spelling of an MCP endpoint (it is refused, "
                "mcp_endpoint_variant)" if var else "refused as another spelling of an MCP endpoint, which it is not"))
            return
        decl = rec.get("body_declared")
        if (rec["body"] == "length") != (type(decl) is int and decl >= 0):
            problems.append(f"seq {seq}: a request whose body is {rec['body']!r} with a declared length {decl!r}")
            return
        dfin, rule = rec.get("decision_final"), rec.get("rule")
        if dfin == "ALLOW" and rule == "request_allowed":
            cr = rec.get("cert_rule")
            want = rules[cr]["max_body"] if isinstance(cr, int) and 0 <= cr < len(rules) else None
            if want is None or rules[cr]["kind"] != "r" or rec.get("max_body", 0) != want:
                problems.append(f"seq {seq}: an allowed request whose max_body is not its rule's")
                return
            if want and rec["body"] == "length" and decl > want:
                problems.append(f"seq {seq}: an allowed request declaring a body of {decl} bytes, over its "
                                f"rule's max_body={want}")
                return
            if rec["body"] != "none":
                st["body"] = (rs, want, rec["body"], decl)
        elif dfin == "DENY" and rule in REQUEST_REFUSE_RULES:
            st["refused"] = rec.get("enforced") is not False    # v1.29: a dry run let it through
            if rule == "max_body" and rec.get("body") != "length":
                problems.append(f"seq {seq}: a request refused for max_body without a declared length")
        else:
            problems.append(f"seq {seq}: a request decision {dfin!r} with rule {rule!r}, which the Warden does not write")


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


def check_refused_requests(checker, policy, rules, refused, problems):
    """v1.26.1 (step 7): each refused request is asked of the policy again.
    The first request rule (policy order) that holds on its object decides:
    policy_match must be a deny rule at its policy_line; default_deny_unknown
    must have none; max_body must be an allow rule at its policy_line whose
    max_body is under the declared length. (An allowed request is re-checked
    by its certificate.) Asked of the checker; refused is their Spool."""
    # v1.31: an MCP call too (on the object decided), each by the rules of
    # the subject it was decided for
    if not len(refused):
        return
    try:
        confined, forl = policy_confined(checker, policy)
    except ValueError as e:
        problems.append(f"checker failed: {e}")
        return
    ok, out, n, err = refused.ask(checker, policy, "holds")
    if not ok or n != len(refused):
        problems.append(f"checker failed on the refused requests: {err.strip()}")
        return
    for rec, row in zip(refused.contexts(), spool_words(out)):
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


class ClosesCheck:
    """v1.26 (step 7): every proxy_close is of a connection the Warden passed
    to the proxy (proxy_dialed) before it, once; its byte counts and relay
    time (the proxy's report) are present and whole, or absent for
    "unreported"; and in a complete stream every connection passed on is
    closed. v1.36 (D9): as the closes come; what it keeps is each open
    connection's dial, requests and bodies (and the ids of those closed)."""

    def __init__(self, problems):
        self.problems = problems
        self.open = {}                   # proxy_conn -> {"pos", "up", "insp", "allowed", "nrq", "exceeded", "sent"}
        self.closed = IdSet()
        self.n = 0

    def rec(self, rec, pos):
        cid = rec.get("proxy_conn")
        if type(cid) is not int:
            return
        if rec.get("action") == "net.proxy" and rec.get("rule") == "proxy_dialed" \
                and rec.get("decision_final") == "ALLOW" and cid not in self.closed:
            self.open.setdefault(cid, {"pos": pos, "up": "upstream" in rec, "insp": rec.get("inspected") is True,
                                       "allowed": False, "nrq": 0, "exceeded": False, "sent": 0})
        elif rec.get("action") in ("net.request", "net.mcp") and cid in self.open:
            o = self.open[cid]
            o["nrq"] += 1
            if rec.get("decision_final") == "ALLOW" or rec.get("enforced") is False:
                o["allowed"] = True

    def ev(self, e, pos):
        event = e.get("event")
        if event == "request_body":
            o = self.open.get(e.get("proxy_conn")) if type(e.get("proxy_conn")) is int else None
            if o is not None:
                if e.get("exceeded_max_body") is True:
                    o["exceeded"] = True
                if type(e.get("body_len")) is int:
                    o["sent"] += e["body_len"]
            return
        if event != "proxy_close":
            return
        self.n += 1
        problems = self.problems
        cid, why = e.get("proxy_conn"), e.get("why")
        if type(cid) is int and cid in self.closed:
            problems.append(f"connection {cid}: closed twice")
            return
        o = self.open.get(cid) if type(cid) is int else None
        if o is None or o["pos"] >= pos:
            problems.append(f"a proxy_close of connection {cid!r}, which was not passed to the proxy before it")
            return
        del self.open[cid]
        self.closed.add(cid)
        counts = [e.get(k) for k in ("bytes_up", "bytes_down", "relay_ms")]
        # v1.26.1 (step 4): an inspected connection's close says so, with
        # its own reasons; until requests are decided (step 6) nothing was
        # sent to its server, or to its client from the server
        insp = o["insp"]
        if why != "unreported" and (e.get("inspected") is True) != insp:
            problems.append(f"connection {cid}: a close {'not ' if insp else ''}marked inspected, for a "
                            f"connection {'' if insp else 'not '}passed on to be inspected")
            return
        if why in TLS_CLOSE_WHY and not insp:
            problems.append(f"connection {cid}: a close for {why!r}, which only an inspected connection has")
            return
        # v1.26.1 (step 6): an inspected connection sends its server bytes
        # only after a request was allowed; it is cut (max_body) only after
        # a body that passed its rule's max_body
        if insp and why != "unreported" and not o["allowed"] and e.get("bytes_up") != 0:
            problems.append(f"connection {cid}: an inspected connection relayed bytes though no request was allowed")
            return
        # review: the bodies recorded as sent fit in the bytes relayed to the server
        sent = o["sent"]
        if insp and why != "unreported" and type(e.get("bytes_up")) is int and sent > e["bytes_up"]:
            problems.append(f"connection {cid}: request bodies of {sent} bytes recorded as sent, but "
                            f"{e['bytes_up']} bytes relayed")
            return
        if insp and (why == "max_body") != o["exceeded"]:
            problems.append(f"connection {cid}: a close for {why!r}, but a body that passed max_body "
                            f"{'was' if o['exceeded'] else 'was not'} recorded")
            return
        # step 7: the requests it counts are those recorded on it
        nrq = o["nrq"]
        if why != "unreported" and ((insp and e.get("requests") != nrq) or (not insp and "requests" in e)):
            problems.append(f"connection {cid}: a close counting {e.get('requests')!r} requests, "
                            f"but {nrq} were recorded on it")
            return
        if insp and ("server_cert_sha256" in e and not (isinstance(e["server_cert_sha256"], str) and
                                                         HEX64.fullmatch(e["server_cert_sha256"]))):
            problems.append(f"connection {cid}: a server certificate hash that is not one")
            return
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
        if why == "upstream_refused" and not o["up"]:
            problems.append(f"connection {cid}: refused by an upstream, but not dialed to one")

    def finish(self, complete):
        if complete:
            for cid in sorted(self.open):
                self.problems.append(f"connection {cid}: passed to the proxy but never closed (a proxy_close is "
                                     f"missing)")
        return self.n


class ProxiedCheck:
    """v1.26 (step 6): every net.proxy record (a name:port the proxy read,
    decided by the Warden) is for a hand-off, once each, of a kind the proxy
    reads, decided on the name:port it records; one the Warden dialed names
    the address, which is neither special nor synthetic and is an address of
    the name by the latest resolution record before it (current or in
    grace). v1.36 (D9): as the records come, with the hand-offs so far; what
    it keeps is the hand-offs not yet decided (and the ids of those that
    were), and each name's first charge to a wildcard."""

    def __init__(self, resolutions, problems, dialed_out, upstream=None, exact=None, passthrough=None):
        self.res, self.problems, self.dialed_out = resolutions, problems, dialed_out
        self.upstream, self.exact, self.passthrough = upstream, exact, passthrough
        self.handoffs = IdSet()          # every connection id handed to the proxy so far
        self.port = {}                   # proxy_conn -> the port it was handed over on, until it is decided
        self.seen = IdSet()              # decided
        self.charged = {}                # name -> the earliest time a question charged it as new
        self.n = 0

    def ev(self, e):
        event = e.get("event")
        if event == "dns_question":
            if e.get("new") is True and isinstance(e.get("name"), str) and type(e.get("timestamp_ns")) is int:
                t = self.charged.get(e["name"])
                self.charged[e["name"]] = e["timestamp_ns"] if t is None else min(t, e["timestamp_ns"])
        elif event == "proxy_close":
            self.port.pop(e.get("proxy_conn"), None)

    def rec(self, rec, pos):
        if rec.get("proxy_handoff") is True and type(rec.get("proxy_conn")) is int:
            self.handoffs.add(rec["proxy_conn"])
            self.port.setdefault(rec["proxy_conn"], _host_port(str(rec.get("target", ""))))
        if rec.get("action") != "net.proxy":
            return
        self.n += 1
        problems, upstream = self.problems, self.upstream
        seq, cid, tgt = rec.get("seq"), rec.get("proxy_conn"), rec.get("target")
        if type(cid) is not int or cid not in self.handoffs or cid in self.seen:
            problems.append(f"seq {seq}: a proxied decision for connection {cid!r}, which is not "
                            f"a hand-off or was decided already")
            if type(cid) is not int:
                return                    # v1.26 review: no crash on a malformed id
        self.seen.add(cid)
        hport = self.port.pop(cid, None)
        if rec.get("proxy_kind") not in PROXY_KINDS or not isinstance(tgt, str) or \
                tgt != rec.get("resolved") or _host_port(tgt) in (None, 0) or ":" not in tgt or \
                tgt.startswith("["):
            problems.append(f"seq {seq}: a malformed proxied decision ({tgt!r})")
            return
        # v1.26 review: the decision and its rule agree; a refusal dialed
        # nothing (one refused when the run ended may have been dialing)
        dfin, rule = rec.get("decision_final"), rec.get("rule")
        if not ((dfin == "ALLOW" and rule in PROXY_ALLOW_RULES) or
                (dfin == "DENY" and rule in PROXY_REFUSE_RULES and
                 ("dialed" not in rec or rule in ("run_ended", "revoked")))):
            problems.append(f"seq {seq}: a proxied decision {dfin!r} with rule {rule!r}, which the "
                            f"Warden does not write")
            return
        # v1.26 review: decided on the port the agent connected to (a CONNECT
        # names its own)
        if rec.get("proxy_kind") != "connect" and hport not in (None, _host_port(tgt)):
            problems.append(f"seq {seq}: a proxied decision on {tgt}, not on the port connection "
                            f"{cid} was handed over on ({hport})")
            return
        # v1.26.1: in inspecting mode a host that is not a passthrough host is
        # passed on to be inspected (its requests are then decided one by one)
        name = tgt.rsplit(":", 1)[0]
        insp = rec.get("inspected") is True
        if "inspected" in rec and not insp:
            problems.append(f"seq {seq}: a malformed inspected mark")
            return
        passthrough = self.passthrough
        if passthrough is None and insp:
            problems.append(f"seq {seq}: a proxied decision inspected outside inspecting mode")
            return
        if passthrough is not None:
            should = name not in passthrough
            if insp != (should and rule not in ("policy_match", "default_deny_unknown", "certificate_refused",
                                                "fragment_escape_flags", "fragment_escape_length",
                                                "outside_plan")):     # v1.35 step 8: refused, not inspected
                problems.append(f"seq {seq}: in inspecting mode, {name} was {'' if insp else 'not '}inspected, "
                                f"which {'only a host that is not passthrough is' if insp else 'it must be'}")
                return
        # section 5: an allowed decision went to the policy's upstream, if it
        # names one (a refusal never reaches it, and carries none)
        up = rec.get("upstream")
        if dfin != "ALLOW":
            if up is not None:
                problems.append(f"seq {seq}: a refused proxied decision that names an upstream")
            return
        if up != upstream:
            problems.append(f"seq {seq}: a proxied connection via upstream {up!r}, not the policy's "
                            f"({upstream!r})")
            return
        dl = rec.get("dialed")
        if rec.get("rule") == "proxy_dialed" and not isinstance(dl, str):
            problems.append(f"seq {seq}: a proxied connection passed on without the address dialed")
            return
        if dl is None:
            return
        cd = _canonical_dest(dl)
        if upstream is not None:
            # dialed to the upstream: its address (given, or by the latest
            # resolution of its name before this record) and its port; it is
            # the operator's, so loopback and private addresses are allowed
            uhost, uport = upstream.rsplit(":", 1)
            if cd is None or cd[1] != uport or cd[0] in SYN_NET:
                problems.append(f"seq {seq}: a proxied connection dialed {dl!r}, not the upstream {upstream}")
                return
            # v1.26 review: a name only a wildcard allows reached the upstream
            # charged to that wildcard (a question recorded before it)
            name = tgt.rsplit(":", 1)[0]
            t = self.charged.get(name)
            if self.exact is not None and name not in self.exact and \
                    not (t is not None and t <= rec.get("timestamp_ns", 0)):
                problems.append(f"seq {seq}: {name} reached the upstream, but was never charged to a "
                                f"wildcard's budget")
            if str(cd[0]) == uhost:
                return
            if re.fullmatch(r"[0-9.]+", uhost):
                # v1.26 review: an upstream given as an address is dialed as it is
                problems.append(f"seq {seq}: a proxied connection dialed {cd[0]}, not the upstream's "
                                f"address {uhost}")
                return
            last = self.res.of(uhost)
            if last is None or str(cd[0]) not in set(_addrs(last, "addresses")) | set(_addrs(last, "grace")):
                problems.append(f"seq {seq}: a proxied connection dialed {cd[0]}, which the latest "
                                f"resolution of the upstream {uhost} before it does not list")
            return
        if cd is None or int(cd[1]) != _host_port(tgt):
            problems.append(f"seq {seq}: a proxied connection dialed {dl!r}, not on {tgt}'s port")
            return
        if _special(cd[0]) or cd[0] in SYN_NET:
            problems.append(f"seq {seq}: a proxied connection dialed {cd[0]}, a special or synthetic address")
            return
        # v1.26 review: asked of the policy below (no deny on it)
        self.dialed_out.add(dl.encode().hex(), (seq, dl))
        last = self.res.of(name)
        if last is None or str(cd[0]) not in set(_addrs(last, "addresses")) | set(_addrs(last, "grace")):
            problems.append(f"seq {seq}: a proxied connection dialed {cd[0]}, which the latest "
                            f"resolution of {name} before it does not list")


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


class DnsCheck:
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
    finish() returns (questions, budget refusals). v1.36 (D9): as the
    records come; the rule each name is answered by is asked of the checker
    when the name first comes (the names are the policy's, and its
    wildcards' budgets bound them)."""

    def __init__(self, rs, checker, policy, rules, sec):
        self.rs, self.checker, self.policy, self.rules, self.sec = rs, checker, policy, rules, sec
        self.failed = None                   # "early" (asking the checker) or "loop"
        self.syn_seen = False
        self.by_rule, self.synth = {}, set()     # name -> rule (asked once a name), names only on proxied ports
        self.asked = set()
        self.syn_given, self.syn_taken = {}, set()
        self.charged, self.used, self.window, self.pending, self.latest = {}, {}, {}, {}, {}
        self.dry_sent = set()
        self.last_mono = None
        self.nq = self.nb = 0
        try:
            self.start(sec["dns_head"])
        except Exception as e:      # v1.25 review: hostile input gives a verdict, never a traceback
            self.fail(e, keep=False)

    def start(self, problems):
        rs, rules, checker, policy = self.rs, self.rules, self.checker, self.policy
        self.wild = wild = policy_wildcards(rules)
        self.pports = pports = policy_proxy(checker, policy)                      # v1.26
        self.upstream = upstream = policy_upstream(checker, policy)               # v1.26 section 5
        self.exact_names = {r["c"].rsplit(":", 1)[0] if _host_port(r["c"]) is not None else r["c"]
                            for r in rules if r["kind"] == "h" and r["name"] and not r["wild"]}
        if upstream is not None and not re.fullmatch(r"[0-9.]+", upstream.rsplit(":", 1)[0]):
            self.exact_names.add(upstream.rsplit(":", 1)[0])   # v1.26 section 5: its name is resolved like one
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
        self.per = {ln: {"names": n, "rate": r, "label": DEFAULT_LABEL} for ln, (_s, n, r) in wild.items()}
        self.dry = rs.get("mode") == "dry_run"                           # v1.29

    def fail(self, e, keep=True):
        """an exception: the stub's records cannot be checked; what was found
        before the names were asked of the checker is kept"""
        if not keep:
            self.sec["dns_syn"].clear()
            self.sec["dns_loop"].clear()
        self.sec["dns_exc"].append(f"the stub resolver's records cannot be checked: {type(e).__name__}: {e}")
        self.failed = "loop" if keep else "early"
        self.nq = self.nb = 0

    def name(self, name):
        """the rule the stub answers a name by, and whether the policy allows it
        only on proxied ports, asked of the checker when it first comes"""
        if not (isinstance(name, str) and name) or name in self.asked:
            return
        self.asked.add(name)
        r = stub_rules(self.checker, self.policy, self.rules, {name})
        self.by_rule.update(r)
        if self.pports is not None and proxied_only(self.checker, self.policy, self.rules, {name}, self.pports):
            self.synth.add(name)

    def ev(self, e):
        if self.failed == "early" or e.get("event") not in ("resolution", "dns_question", "synthetic_address"):
            return
        if e.get("event") == "synthetic_address" and isinstance(e.get("name"), str) and e.get("name"):
            self.syn_seen = True
        if self.failed:
            return
        if e.get("event") in ("dns_question", "synthetic_address"):
            try:
                self.name(e.get("name"))
            except Exception as x:
                self.fail(x, keep=False)
                return
        try:
            self.one(e)
        except Exception as x:
            self.fail(x)

    def one(self, e):
        problems, rules, wild, per = self.sec["dns_loop"], self.rules, self.wild, self.per
        by_rule, synth, pports, upstream = self.by_rule, self.synth, self.pports, self.upstream
        charged, used, window, pending, latest = self.charged, self.used, self.window, self.pending, self.latest
        syn_given, dry_sent, exact_names, dry = self.syn_given, self.dry_sent, self.exact_names, self.dry
        line_of = lambda i: rules[i]["line"] if i is not None else -1    # noqa: E731
        name, ts = e.get("name"), e.get("timestamp_ns")
        if not isinstance(name, str) or (e.get("event") == "resolution" and not name):
            problems.append(f"a {e.get('event')} record without a name")
            return
        if e.get("event") == "synthetic_address":
            check_synthetic(e, syn_given, self.syn_taken, synth, by_rule, line_of, problems)
            return
        if e.get("event") == "resolution":
            a = e.get("a")
            if a in ("retired", "grace_end"):    # no lookup: into grace, or out of it
                latest[name] = e
                return
            if a == "unanswered":                # the run ended before the helper answered
                if name not in pending:
                    problems.append(f"{name}: an unanswered lookup that was never sent")
                pending.pop(name, None)
                return
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
            return
        self.nq += 1
        rule, ans, line, mono = e.get("rule"), e.get("answer"), e.get("policy_line"), e.get("mono_ms")
        if type(mono) is not int or (self.last_mono is not None and mono < self.last_mono):
            problems.append(f"{name!r}: a question whose Warden time {mono!r} is missing or earlier "
                            f"than the one before it")
            return
        self.last_mono = mono
        if not isinstance(ans, str) or not isinstance(rule, str) or type(line) is not int:
            problems.append(f"{name!r}: a malformed question record")
            return
        if rule == "revoked":                    # v1.28 review: after `varek revoke`, refused, nothing looked up
            if ans != "refused" or e.get("new") or e.get("upstream") or e.get("synthetic"):
                problems.append(f"{name!r}: a question after the revocation was answered {ans}")
            return
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
                return
            if rule == "wildcard_budget":
                self.nb += 1
            if e.get("upstream") is True:
                if name in pending:
                    problems.append(f"{name}: sent upstream again while its lookup was outstanding")
                pending[name] = ts if type(ts) is int else 0
            dry_sent.add(name)
            return
        if rule in ("no_rule", "not_a_host_name", "malformed"):
            if ans not in ("nxdomain", "formerr") or e.get("new") or e.get("upstream"):
                problems.append(f"{name!r}: a question no rule allows was answered {ans}")
            if rule == "no_rule" and by_rule.get(name) is not None:
                problems.append(f"{name}: recorded as allowed by no rule, but policy line "
                                f"{line_of(by_rule[name])} allows it")
            return
        # v1.25 review: the rule the question was answered by is the policy's
        want = by_rule.get(name)
        if want is None or line != line_of(want):
            problems.append(f"{name}: answered by policy line {line}, but the policy "
                            f"{'allows it by line ' + str(line_of(want)) if want is not None else 'allows it by no rule'}")
            return
        if rule == "exact_name" and (rules[want]["wild"] or name not in exact_names):
            problems.append(f"{name}: recorded as an exact name, but no exact rule allows it")
            return
        # v1.26: a name allowed only on proxied ports is answered with its
        # synthetic address (A) or no data, and nothing else is done for it
        # (v1.26 step 6: a lookup the Warden sent upstream to dial a proxied
        # connection, "transport":"proxy", is charged as a question and never
        # synthetic, and only of a name the proxy may reach)
        if e.get("transport") == "proxy" and (e.get("synthetic") or pports is None or
                                              (ans == "upstream") != (upstream is not None and ans != "nxdomain")):
            problems.append(f"{name}: a proxied lookup that is synthetic, or with the proxy off")
            return
        if e.get("transport") != "proxy" and \
                (e.get("synthetic") is True) != (name in synth and rule in ("policy_match", "exact_name")):
            problems.append(f"{name}: {'answered with' if e.get('synthetic') else 'not answered with'} "
                            f"a synthetic address, but the policy allows it "
                            f"{'off' if name not in synth else 'only on'} the proxied ports")
            return
        if e.get("synthetic") is True:
            want_a = [syn_given[name]] if e.get("type") == 1 and name in syn_given else []
            if e.get("new") or e.get("upstream") or not (
                    (ans == "noerror" and e.get("addresses") == want_a and
                     (e.get("type") != 1 or name in syn_given)) or
                    (ans == "servfail" and e.get("type") == 1 and name not in syn_given
                     and len(syn_given) >= SYN_MAX)):
                problems.append(f"{name}: a synthetic answer {ans} {e.get('addresses')!r} that is not "
                                f"its synthetic address {want_a!r}, or that charged or sent anything")
            return
        if rule == "wildcard_budget":
            self.nb += 1
            if ans != "nxdomain" or e.get("budget") not in ("names", "rate", "label") or \
                    e.get("new") or e.get("upstream") or line not in wild:
                problems.append(f"{name}: a budget refusal that is not a plain NXDOMAIN of a wildcard rule")
            return
        if rule != "policy_match" and rule != "exact_name":
            problems.append(f"{name}: a question answered by rule {rule!r}")
            return
        b, sfx = per.get(line), wild.get(line, ("",))[0]
        if e.get("new") is True:
            if rule != "policy_match" or b is None:
                problems.append(f"{name}: charged to policy line {line}, not a wildcard allow rule")
                return
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
                return
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

    def finish(self, meta):
        if self.failed == "early":
            return 0, 0
        if self.pports is None and self.syn_seen:
            self.sec["dns_syn"].append("synthetic addresses given, but the policy does not turn the proxy on")
        if self.failed:
            return 0, 0
        # v1.25 review: the Warden answers every lookup it sent upstream with a
        # resolution record, or records it unanswered when the run ends first
        if isinstance(meta.get("run_end"), dict):
            for name in self.pending:
                self.sec["dns_tail"].append(f"{name}: a lookup sent upstream was never answered (a resolution "
                                            f"record is missing)")
        return self.nq, self.nb


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
    decided on (for the earlier-rule check). resolutions: the resolution
    records before this one (Resolutions)."""
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
    latest, last = resolutions.latest, resolutions.last     # v1.36 (D9): the table so far
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
    latest, last = resolutions.latest, resolutions.last     # v1.36 (D9): the table so far
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


class AnchorIndex:
    """v1.36 (D9): this run's anchor lines, by chain value, on disk (SQLite,
    in a temporary file), each with its place in the file and whether its
    signature verified; looked up as the stream's signed records come."""

    def __init__(self):
        self.n = self.nvalid = 0
        try:
            import sqlite3
            self.dir = tempfile.TemporaryDirectory()
            self.db = sqlite3.connect(os.path.join(self.dir.name, "anchor.db"))
            self.db.execute("CREATE TABLE a (id INTEGER PRIMARY KEY, chain TEXT, valid INTEGER, inlog INTEGER, "
                            "line BLOB)")
            self.db.execute("CREATE INDEX a_chain ON a (chain)")
        except ImportError:                  # a Python without SQLite: kept in memory
            self.db, self.mem = None, []

    def add(self, e, valid):
        self.n += 1
        self.nvalid += bool(valid)
        if self.db is None:
            self.mem.append([str(e.get("chain")), valid, False, e])
        else:
            self.db.execute("INSERT INTO a (id, chain, valid, inlog, line) VALUES (?, ?, ?, 0, ?)",
                            (self.n, str(e.get("chain")), 1 if valid else 0, pickle.dumps(e)))

    def take(self, ch):
        """the valid lines that carry this chain value, in file order; marked as
        the stream's"""
        if self.db is None:
            out = [m[3] for m in self.mem if m[1] and m[0] == ch]
            for m in self.mem:
                if m[0] == ch:
                    m[2] = True
            return out
        rows = self.db.execute("SELECT line FROM a WHERE chain = ? AND valid = 1 ORDER BY id", (ch,)).fetchall()
        self.db.execute("UPDATE a SET inlog = 1 WHERE chain = ?", (ch,))
        return [pickle.loads(r[0]) for r in rows]

    def foreign(self):
        """the valid lines whose chain value the stream does not hold, in file order"""
        if self.db is None:
            return (m[3] for m in self.mem if m[1] and not m[2])
        return (pickle.loads(r[0]) for r in
                self.db.execute("SELECT line FROM a WHERE valid = 1 AND inlog = 0 ORDER BY id"))


class Integrity:
    """v1.16: signatures and anchor (log_integrity, as the stream is read).
    signed() takes each checkpoint-type record as the chain reaches it,
    anchor_error() each anchor_error; finish() appends the problems in the
    order log_integrity found them and returns the integrity level for the
    report. sealed (a callback) is told the decision records before each
    record that seals what came before it: a signed one, or (anchored without
    a key) one the anchor holds."""

    def __init__(self, a, sec, sealed):
        self.a, self.sec, self.sealed = a, sec, sealed
        self.rs = None
        self.early = []                      # the signed records before run_start was read (run_start's own)
        self.mode = None                     # "signed", "malformed" (a bad log_pubkey) or None
        self.pk = self.pinned = None
        self.nsigned = self.bad = 0
        self.last_event = None
        self.prev = 0                        # the decision records before the last signature
        self.every = None
        self.anchor = None
        self.anchor_errors = Section()
        self.matched_any = False
        self.matched_n = 0
        self.conflicts = 0
        self.end_rx = None
        self.delays = None                   # (min, max, how many)
        self.nlate = 0                       # how many over --max-anchor-delay
        self.sealed_max = None               # anchored without a key: the last record the anchor holds

    def start(self, rs, run):
        """run_start: the key, the pinned key, checkpoint_every, and the anchor's
        lines for this run"""
        self.rs, self.run = rs, run
        a, head = self.a, self.sec["integ_head"]
        self.chained = rs.get("log") == LOG_CHAIN_FORMAT
        stream_key = rs.get("log_pubkey")
        if not self.chained:
            return
        if stream_key is not None:
            self.pk = _hex_key(stream_key)
            if self.pk is None:
                head.append("run_start carries a malformed log_pubkey")
                self.mode = "malformed"
                return
            self.mode = "signed"
            if a.pubkey:
                self.pinned = _cli_pubkey(a.pubkey)
                if self.pinned is None:
                    head.append("--pubkey is not 64 hex characters (or a file holding them)")
                elif self.pinned != self.pk:
                    head.append(f"the stream is signed by {self.pk.hex()}, not by the pinned key "
                                f"{self.pinned.hex()}")
            every = rs.get("checkpoint_every")
            self.every = every if isinstance(every, int) and every >= 1 else None
            self.every_bad = self.every is None
        elif a.pubkey:
            head.append("--pubkey given, but the stream is not signed (the Warden ran "
                        "without --sign-key)")
        if a.anchor:
            self.load_anchor()
        for kind, c in self.early:
            self.take(kind, c)
        self.early = []

    def load_anchor(self):
        """read_anchor, keeping only this run's lines (on disk)"""
        a, skey = self.a, (self.pk if self.mode == "signed" else None)
        self.anchor = AnchorIndex()
        self.other_runs, self.unparsed, self.ignored = set(), 0, 0
        try:
            with open(a.anchor, encoding="utf-8", errors="surrogateescape") as fh:
                for line in fh:
                    try:
                        e = json.loads(line)
                    except ValueError:           # JSONDecodeError, or a huge number
                        self.unparsed += 1
                        continue
                    if not isinstance(e, dict):
                        self.unparsed += 1
                        continue
                    if isinstance(e.get("run"), str):
                        self.other_runs.add(e["run"])
                    if e.get("run") != self.run:
                        continue
                    # Which anchor lines count. In a signed stream, only lines whose
                    # signature verifies (a line appended by someone without the key is
                    # ignored).
                    good = True
                    if skey is not None:
                        ch, sig = str(e.get("chain")), e.get("sig")
                        try:
                            good = isinstance(sig, str) and len(ch) == 64 and \
                                varek_ed25519.verify(skey, LOG_SIG_DOMAIN + bytes.fromhex(ch), bytes.fromhex(sig))
                        except ValueError:
                            good = False
                        if not good:
                            self.ignored += 1
                    self.anchor.add(e, good)
        except OSError as e:
            self.sec["integ_aread"].append(f"anchor {a.anchor}: {e}")
        self.other_runs.discard(self.run)

    def signed(self, kind, c):
        if self.rs is None:
            self.early.append((kind, c))
            return
        self.take(kind, c)

    def take(self, kind, c):
        if kind == "anchor_error":
            self.anchor_errors.append(f"line {c['line']}: the Warden could not anchor a {c['anchoring']} "
                                      f"record (errno {c['errno']})")
            return
        if not self.chained or self.mode == "malformed":
            return
        self.last_event = c["event"]
        self.nsigned += 1
        if self.mode == "signed":
            if c["sig"] is None:
                self.sec["integ_sigs"].append(f"line {c['line']}: {c['event']} record is not signed")
            elif not varek_ed25519.verify(self.pk, LOG_SIG_DOMAIN + c["chain"], bytes.fromhex(c["sig"])):
                self.bad += 1
                self.sec["integ_sigs"].append(f"line {c['line']}: {c['event']} signature does not verify")
            if c["sig"]:
                # The Warden signs at least every checkpoint_every decision records. A
                # longer stretch without a signature means checkpoints were removed
                # (possible only at the unsigned end of an incomplete stream).
                if self.every is not None and c["ndec"] - self.prev > self.every:
                    self.sec["integ_gaps"].append(f"line {c['line']}: {c['ndec'] - self.prev} decision records "
                                                  f"since the previous signature, more than checkpoint_every "
                                                  f"({self.every}): checkpoints were removed")
                self.prev = c["ndec"]
                self.sealed(c["ndec"])
        if self.anchor is not None:
            self.match(c)

    def match(self, c):
        """A record of the stream is anchored if ANY counting line carries its
        chain value with the same event, count and signature; other lines for
        that chain change nothing (the chain value already fixes the record)
        and are noted."""
        ch = c["chain"].hex()
        hit = None
        for e in self.anchor.take(ch):
            if (e.get("event"), e.get("sig"), e.get("records")) == (c["event"], c["sig"], c["records"]):
                if hit is None:
                    hit = e
            else:
                self.conflicts += 1
        if hit is None:
            self.sec["integ_unanchored"].append(f"line {c['line']}: {c['event']} was never anchored")
            return
        self.matched_n += 1
        if hit.get("event") == "run_end" and isinstance(hit.get("received_ns"), int):
            self.end_rx = hit["received_ns"]
        # How late each record reached the anchor host: its receive time (set
        # by the anchor host) against the time in the STREAM's signed record
        # (an anchor line's own timestamp is not trusted).
        if isinstance(hit.get("received_ns"), int) and isinstance(c.get("ts"), int):
            d = (hit["received_ns"] - c["ts"]) / 1e9
            lo, hi, n = self.delays or (d, d, 0)
            self.delays = (min(lo, d), max(hi, d), n + 1)
            if self.a.max_anchor_delay is not None and d > self.a.max_anchor_delay:
                self.nlate += 1
        self.sealed_max = c["ndec"]
        if self.mode != "signed":
            self.sealed(c["ndec"])

    def finish(self, meta, complete):
        """the rest of log_integrity's checks, its notes printed; the level"""
        a, sec, rs = self.a, self.sec, self.rs or {}
        if meta.get("log") is None:
            if a.pubkey or a.anchor:
                sec["integ_head"].append("the stream is not hash-chained (a pre-1.16 Warden): "
                                         "--pubkey / --anchor cannot be checked")
            return "none (pre-1.16 stream: no hash chain)"
        level = "chain"
        if self.mode == "malformed":
            return level
        if self.mode == "signed":
            if complete and (not self.nsigned or self.last_event != "run_end"):
                sec["integ_end"].append("the stream does not end in a signed run_end")
            if self.every_bad:
                sec["integ_every"].append("run_start of a signed stream has no valid checkpoint_every")
            tail = meta["ndecisions"] - self.prev
            if self.every is not None and tail > self.every:
                sec["integ_tail"].append(f"{tail} decision records after the last signature, more than "
                                         f"checkpoint_every ({self.every}): checkpoints were removed")
            meta["signed_through"] = self.prev
            pinned, pk = self.pinned, self.pk
            level = "signed" if (pinned is not None and pinned == pk and not self.bad) \
                else "signed, key not pinned (pass --pubkey to rely on the signatures)"
            if not complete:
                level += f"; covers the first {self.prev} decision records only"
        if a.anchor:
            ap = sec["integ_anchor"]
            # A validly signed anchored record the stream does not hold is evidence
            # the stream was rewritten, unless the anchor host received it after
            # this run's run_end had been anchored (then it was appended later, by
            # someone holding the key, and changes nothing that was anchored).
            late_foreign = 0
            for e in self.anchor.foreign():
                rx = e.get("received_ns")
                if self.end_rx is not None and isinstance(rx, int) and rx > self.end_rx:
                    late_foreign += 1
                    continue
                ap.append(f"anchored {e.get('event')} (records {e.get('records')}) is not in "
                          f"the stream: the stream was rewritten after it was anchored")
            for p in self.anchor_errors:
                ap.append(p)
            for _ in range(len(self.anchor_errors) - len(self.anchor_errors.items)):
                ap.append("(an anchor error)")
            if not self.anchor.nvalid:
                ap.append("the anchor holds nothing for this run")
            if self.ignored:
                print(f"varek_audit: note: {self.ignored} anchor line(s) for this run carry no valid signature "
                      f"and were ignored")
            if self.conflicts:
                print(f"varek_audit: note: {self.conflicts} anchor line(s) repeat a record's chain value with "
                      f"a different event or count; ignored (the chain value fixes the record)")
            if late_foreign:
                print(f"varek_audit: note: {late_foreign} signed anchor line(s) for records the stream "
                      f"does not hold arrived after its run_end was anchored; ignored")
            if self.unparsed:
                print(f"varek_audit: note: {self.unparsed} anchor line(s) are not JSON and were ignored")
            if self.other_runs:
                print(f"varek_audit: note: the anchor also holds {len(self.other_runs)} other run(s); "
                      f"list them with --list-runs")
            # A record received well before it was written means the clocks
            # disagree or the times were changed.
            if self.delays:
                lo, hi, n = self.delays
                print(f"varek_audit: anchoring delay: at most {hi:.1f} s, at least "
                      f"{lo:.1f} s ({n} record(s) with a receive time)")
                if lo < -a.clock_slack:
                    ap.append(f"a record was received {-lo:.1f} s before the stream says it was "
                              f"written: the hosts' clocks disagree, or the times were changed")
                if a.max_anchor_delay is not None and hi > a.max_anchor_delay:
                    ap.append(f"{self.nlate} record(s) reached the anchor more than "
                              f"{a.max_anchor_delay:g} s after they were written (at most "
                              f"{hi:.1f} s): they could have been changed before anchoring")
            elif a.max_anchor_delay is not None:
                ap.append("--max-anchor-delay given, but the anchor has no receive times "
                          "(a v1.16.2 receiver adds them)")
            if not len(sec["integ_aread"]) and not len(sec["integ_unanchored"]) and not len(ap):
                level += ", anchored"
                if rs.get("log_pubkey") is None and not complete:
                    # Anchor only: what reached the anchor is sealed, nothing after it.
                    meta["signed_through"] = self.sealed_max or 0
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


class MainLoop:
    """main's loop over the decision records (v1.36, D9: one record at a
    time): every authorization is a certified open, lookup, connect or
    launch, or one of the Warden's answers the audit checks by itself (a
    lookup of a directory the policy leads to, the stub resolver, a hand-off
    to the proxy, a view). The rows for the checker wait on disk: the
    certificates, the views (each asked whether a deny holds on it), a
    connect's other candidates (whether an earlier rule holds on one), a
    hand-off's candidates."""

    def __init__(self, a, meta, problems, cited, res, prules, rules, names_policy, dry_run, stub_policy,
                 stub_addr, proxy_ports, launches_policy, openas_policy, exact_grace):
        self.a, self.meta, self.problems, self.cited, self.res = a, meta, problems, cited, res
        self.prules, self.rules, self.names_policy, self.dry_run = prules, rules, names_policy, dry_run
        self.stub_policy, self.stub_addr, self.proxy_ports = stub_policy, stub_addr, proxy_ports
        self.launches_policy, self.openas_policy, self.exact_grace = launches_policy, openas_policy, exact_grace
        self.authorized = self.refused = self.lookups = self.connects = self.views = self.stubs = 0
        self.handoffs = self.proxied_ok = self.exec_ok = self.launches = 0
        self.ancestors = self.confined = None
        self.for_lines = {}
        self.handoff_ids = IdSet()       # v1.26: connects handed to the proxy
        self.certs, self.view_recs, self.others, self.handoff_cands = Spool(), Spool(), Spool(), Spool()
        self.nothers = 0                 # connects decided over candidates

    def rec(self, rec, pos):
        a, meta, problems = self.a, self.meta, self.problems
        prules, names_policy, dry_run = self.prules, self.names_policy, self.dry_run
        stub_policy, stub_addr, proxy_ports = self.stub_policy, self.stub_addr, self.proxy_ports
        launches_policy, openas_policy, exact_grace = self.launches_policy, self.openas_policy, self.exact_grace
        allowed = rec.get("decision_final") == "ALLOW" or rec.get("kernel_verdict") == "ALLOW"
        if not allowed:
            if rec.get("rule") == "certificate_refused":
                self.refused += 1                 # the in-line checker stopped it
            return
        if rec.get("action") == "process.exec" and rec.get("rule") == "bootstrap_exec_allow":
            self.launches += 1                    # the agent's own launch, once per run
            if self.launches > 1:
                problems.append(f"seq {rec.get('seq')}: a second launch exec")
            return
        if rec.get("action") in META_ACTIONS + ("file.mkdir",) and \
                rec.get("rule") == ("mkdir_exists_ancestor" if rec.get("action") == "file.mkdir"
                                    else "metadata_ancestor"):
            if self.ancestors is None:
                self.ancestors = policy_ancestors(a.policy)
            if rec.get("resolved") not in self.ancestors:
                problems.append(f"seq {rec.get('seq')}: a lookup answered as a directory the "
                                f"policy leads to, but {rec.get('resolved')!r} is not one")
            elif rec.get("open_flags") != "0x0" or \
                    (rec.get("action") == "file.access" and
                     int(rec.get("access_mode", "7")) & 3):
                problems.append(f"seq {rec.get('seq')}: a lookup answered as a directory the "
                                f"policy leads to, but it asked for more than a read")
            self.lookups += 1
            return
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
            self.stubs += 1
            return
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
            elif type(cid) is not int or cid < 1 or cid in self.handoff_ids:
                problems.append(f"seq {seq}: a hand-off without a connection id of its own ({cid!r})")
            else:
                self.handoff_ids.add(cid)
                if tgt[0] not in SYN_NET and isinstance(rec.get("candidates"), list):
                    cands = [c for c in rec["candidates"] if isinstance(c, str)]
                    for ci, c in enumerate(cands):      # asked of the policy below (check_handoff_rules)
                        self.handoff_cands.add(c.encode().hex(), (rec.get("seq"), ci, ci == len(cands) - 1))
            self.handoffs += 1
            return
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
                self.view_recs.add(rec["resolved"].encode().hex(), (rec.get("seq"), rec["rule"], rec["resolved"], flv))
            self.views += 1
            return
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
                self.view_recs.add(rec["resolved"].encode().hex(), (rec.get("seq"), rec["rule"], rec["resolved"], 0))
            self.views += 1
            return
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
                return
            if not isinstance(rs.get("landlock"), dict):
                problems.append(f"seq {seq}: a launch allowed, but run_start records no Landlock")
                return
            if ent is None or rec.get("exec_dev") != ent.get("dev") or rec.get("exec_ino") != ent.get("ino") \
                    or rec.get("exec_sha256") != ent.get("sha256"):
                problems.append(f"seq {seq}: a launch allowed onto {k!r}, not a file of the launch set "
                                f"as run_start records it")
                return
            if not isinstance(rec.get("resolved"), str) or not rec["resolved"].startswith("/"):
                problems.append(f"seq {seq}: a launch allowed without the absolute name it was decided on")
                return
            self.exec_ok += 1
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
                return
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
            return
        if is_meta:
            self.lookups += 1
        elif is_exec:
            pass                               # v1.27: counted above
        elif is_proxy:
            self.proxied_ok += 1
        elif is_conn:
            self.connects += 1
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
            self.authorized += 1
        cr, cw = rec.get("cert_rule"), rec.get("cert_witness")
        if not isinstance(cr, int) or not isinstance(cw, str) or rec.get("check") != "ok":
            problems.append(f"seq {rec.get('seq')}: authorized open of {rec.get('resolved')!r} "
                            f"without an accepted certificate")
            return
        if prules and (type(cr) is not int or not 0 <= cr < len(prules) or
                       rec.get("policy_line") != prules[cr]["line"]):
            # v1.31 review: the line a decision cites is its certificate's rule's
            self.cited.append(f"seq {rec.get('seq')}: a decision citing policy line {rec.get('policy_line')!r}, "
                            f"but its certificate's rule is "
                            f"{'line ' + str(prules[cr]['line']) if type(cr) is int and 0 <= cr < len(prules) else repr(cr)}")
        s = rec.get("resolved", "")
        fl = rec.get("open_flags")
        if not isinstance(s, str):
            problems.append(f"seq {rec.get('seq')}: a malformed decided destination or path")
            return
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
            return
        if is_conn_like:
            fl = "0x0"                   # host rules carry no flag clause
            if not s:
                problems.append(f"seq {rec.get('seq')}: authorized connect without the "
                                f"destination it was decided on")
                return
        elif not isinstance(fl, str) or not fl.startswith("0x"):
            problems.append(f"seq {rec.get('seq')}: authorized open without its open flags")
            return
        try:
            hx = s.encode("utf-8", errors="surrogateescape").hex() or "="
        except UnicodeEncodeError:
            problems.append(f"seq {rec.get('seq')}: path cannot be encoded")
            return
        if " " in cw or not cw:
            problems.append(f"seq {rec.get('seq')}: malformed certificate witness")
            return
        # v1.31: the certificate is checked as the subject the record's chain
        # makes it (from the policy, not the record), and the record must say so
        if self.confined is None:
            try:
                self.confined, self.for_lines = policy_confined(a.checker, a.policy)
            except ValueError as e:
                problems.append(f"checker failed: {e}")
                self.confined, self.for_lines = {}, {}
        ks = expected_subject(rec.get("obo"), self.confined)
        if rec.get("cert_subject", 0) != ks:
            problems.append(f"seq {rec.get('seq')}: certificate recorded for subject {rec.get('cert_subject', 0)!r}, "
                            f"but the decision was for subject {ks} (its chain {rec.get('obo')!r})")
            return
        self.certs.add(f"{'mcp' if is_mcp else 'request' if is_req else 'exec' if is_exec else 'host' if is_conn_like else 'path'} "
                       f"{fl} {hx} {cr} {cw}" + (f" @{ks}" if ks else ""), (rec.get("seq"), rec.get("resolved")))
        if is_conn and ("candidates" in rec or "candidates_sha256" in rec):
            try:
                oc = check_names(rec, pos, self.res, problems, exact_grace=exact_grace)
            except (TypeError, ValueError, AttributeError, KeyError) as e:
                problems.append(f"seq {rec.get('seq')}: malformed connect or resolution records ({e})")
                return
            self.nothers += 1
            for c in oc:                         # asked of the policy below: no earlier rule holds on it
                self.others.add(c.encode().hex() or "=", (rec.get("seq"), cr, ks, c))


# v1.36 (D9): the sections of the report's problems, in the order the checks
# find them (main's order before the audit read the stream once)
SECTIONS = (
    "integ_head", "integ_sigs", "integ_end", "integ_every", "integ_gaps", "integ_tail", "integ_aread",
    "integ_unanchored", "integ_anchor",
    "run", "testbuild", "phash", "prules", "pproxy", "plaunch", "execset", "popenas", "changes", "openas",
    "baseline", "dry_head", "dry_recs", "dry_dns", "dry_refused", "dry_tail", "hold_head", "hold", "plan",
    "noexec", "noexec_loop", "noexec_exec", "noexec_fail", "shared",
    "dns_head", "dns_syn", "dns_loop", "dns_tail", "dns_exc", "hostnames",
    "loop", "views", "certs", "cited", "others",
    "proxy_start", "trust", "handoff", "proxied", "dialed", "closes", "requests", "refreq",
    "pcreds", "cred_head", "cred_time", "cred_between", "cred_expiry", "cred_unrecorded", "cred_recs",
    "cred_events", "cred_closes", "cred_dns",
    "pident", "chain_head", "chain_settled", "chain_recs", "chain_results", "chain_end",
    "reqplan", "pconf", "subjects", "tokens",
    "launches_head", "launches_a", "launches_b", "launches_c", "launches_d", "launches_e", "launches_f",
    "launches_h",
    "end_proxy", "end_proxied", "end_ids")
SUB_MAX = 1024              # the sub-agent launches a run may make (warden_subagent.inc.c)
PLAN_EVENTS_MAX = 1 << 16   # more plan records than a plan has steps is a problem; kept no further


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
    ap.add_argument("--plan", help="v1.35: the plan file the run was given: its SHA-256 must be the "
                    "one the plan gate (or the hold) recorded")
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
    ap.add_argument("log", nargs="*", help="the verdict stream; v1.36: a stream the node agent rotated "
                    "is its segments, in order (NAME.jsonl, NAME.jsonl.2, ...)")
    a = ap.parse_args(argv)
    if a.list_runs:
        if not a.anchor:
            ap.error("--list-runs needs --anchor")
        return list_runs(a.anchor)
    if not (a.policy and a.checker and a.log):
        ap.error("--policy, --checker and the verdict stream are required")

    sec = Problems(SECTIONS)
    meta = {}
    # what the checks need of the policy, as the checker reads it (each
    # failure reported where main reported it)
    # v1.24 review: whether the policy has host name rules is read from the
    # policy file (the checker's own parse), not taken from run_start.
    try:
        prules = policy_rules(a.checker, a.policy)
    except (OSError, ValueError) as e:
        sec["prules"].append(f"checker failed on the policy's rules: {e}")
        prules = []
    rules = [[r["kind"], "a" if r["allow"] else "d", "n" if r["name"] else "-", r["mask"], r["value"]]
             for r in prules]
    wild_policy = bool(policy_wildcards(prules))
    # v1.26: the proxy's ports (None: off); the stub also runs with the proxy
    # on and a host name rule
    try:
        proxy_ports = policy_proxy(a.checker, a.policy)
    except (OSError, ValueError) as e:
        sec["pproxy"].append(f"checker failed on the policy's proxy directives: {e}")
        proxy_ports = None
    # v1.27: launches after the first decided (require warden 1.27)
    try:
        launches_policy = policy_launches(a.checker, a.policy)
    except (OSError, ValueError) as e:
        sec["plaunch"].append(f"checker failed on the policy's launches: {e}")
        launches_policy = False
    try:
        openas_policy = policy_openas(a.checker, a.policy)          # v1.29
    except (OSError, ValueError) as e:
        sec["popenas"].append(f"checker failed on the policy's openas: {e}")
        openas_policy = False
    names_policy = any(r[0] == "h" and r[2] == "n" for r in rules)
    try:
        passthrough = policy_inspect(a.checker, a.policy)                 # v1.26.1
    except (OSError, ValueError):
        passthrough = None
    try:
        upstream = policy_upstream(a.checker, a.policy)               # section 5
    except (OSError, ValueError):
        upstream = None
    exact_hosts = {r["c"].rsplit(":", 1)[0] if _host_port(r["c"]) is not None else r["c"]
                   for r in prules if r["kind"] == "h" and r["name"] and not r["wild"]}
    cnotes = []                                                                            # v1.28
    try:
        pcreds, pcred_rules, pcred_auds = policy_credentials(a.checker, a.policy)
    except (OSError, ValueError) as e:
        sec["pcreds"].append(f"checker failed on the policy's credentials: {e}")
        pcreds, pcred_rules, pcred_auds = [], {}, {}
    try:                                                                                   # v1.28.1
        ident = policy_identity(a.checker, a.policy)
    except (OSError, ValueError) as e:
        sec["pident"].append(f"checker failed on the policy's identities: {e}")
        ident = ({}, {}, {}, False, {})
    try:                                                                                   # v1.31 (section 6)
        confined6, forl6 = policy_confined(a.checker, a.policy)
    except ValueError as e:
        sec["pconf"].append(f"checker failed: {e}")
        confined6, forl6 = {}, {}

    # the stream, once: each record goes to every check that reads it, then
    # is dropped
    res = Resolutions()
    delay = Delay()
    st = {"ndec": 0, "delaying": False}
    checks = {}
    plan_events = []

    def feed(item):
        kind, rec, line = item[0], item[1], item[2]
        if kind == "dec":
            pos = st["ndec"]
            st["ndec"] += 1
            for c in checks["recs"]:
                c(rec, pos, line)
            return
        before = item[3]
        event = rec.get("event")
        if event == "resolution":
            res.add(rec)
        if event in ("plan_step", "plan_gate"):
            if len(plan_events) < PLAN_EVENTS_MAX:
                plan_events.append((before, rec))
            else:
                sec["plan"].append("more plan records than a plan has steps")
        for c in checks["evs"]:
            c(rec, before, line)

    def sealed(ndec):
        """a record that seals what came before it: what waited is audited"""
        for item in delay.take():
            feed(item)

    def rotated():
        """v1.36 (D9): the stream goes on in a segment it was not given"""
        nxt = f"{a.log[0]}.{len(a.log) + 1}"
        if all(p == f"{a.log[0]}.{k}" for k, p in enumerate(a.log[1:], 2)) and os.path.exists(nxt):
            print(f"varek_audit: note: the stream goes on in {nxt} (the node agent rotated it): give its "
                  f"segments in order")

    integ = Integrity(a, sec, sealed)
    tokens = TokenScan(sec["tokens"])
    run = None
    files = []
    try:
        for p in a.log:
            files.append(open(p, encoding="utf-8", errors="surrogateescape", newline="\n"))
        for item in _iter_log(files if len(files) > 1 else files[0], a.allow_incomplete, meta,
                              on_line=tokens.line, on_signed=integ.signed):
            if item[0] == "start":
                rs = item[1]
                run = rs.get("run")
                integ.start(rs, run)
                st["delaying"] = integ.mode == "signed" or \
                    (integ.chained and rs.get("log_pubkey") is None and bool(a.anchor))
                checks.update(start_checks(a, meta, rs, run, sec, res, prules, rules, names_policy,
                                           proxy_ports, launches_policy, openas_policy, wild_policy,
                                           passthrough, upstream, exact_hosts, pcreds, pcred_rules,
                                           pcred_auds, cnotes, ident, confined6, forl6))
            elif item[0] in ("dec", "ev"):
                if st["delaying"]:
                    delay.put(item)
                else:
                    feed(item)
    except StreamError as e:
        rotated()
        print(f"varek_audit: FAIL: {e}")
        return 1
    finally:
        for fh in files:
            fh.close()
    meta["log"] = meta.pop("chain", None)
    complete = meta.get("run_end") is not None
    if not complete:
        rotated()
    warden = meta.get("_warden", "?")
    meta["plan_events"] = plan_events

    integrity = integ.finish(meta, complete)
    if a.run and a.run != run:
        sec["run"].append(f"the stream is run {run}, not the run asked for ({a.run})")
    # An incomplete signed stream is audited only as far as its last signature:
    # the records after it could have been written by anyone.
    ndec_all = meta["ndecisions"]
    if not complete and "signed_through" in meta and meta["signed_through"] < ndec_all:
        dropped = ndec_all - meta["signed_through"]
        print(f"varek_audit: note: the last {dropped} decision record(s) follow the last "
              f"signature (the stream is incomplete); they are not audited")
        for item in delay.take():
            if item[0] == "ev":
                feed(item)
    else:
        for item in delay.take():
            feed(item)
    nrec = st["ndec"]
    if meta.get("run_start", {}).get("build") and not a.allow_test_build:
        sec["testbuild"].append(f"the stream comes from a test build ({meta['run_start']['build']}), "
                                f"not a Warden that may supervise a real agent")
    with open(a.policy, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    recorded = meta.get("run_start", {}).get("policy_sha256")
    if not recorded:
        sec["phash"].append("run_start has no policy_sha256 (a pre-v1.15 Warden): nothing to check against")
    elif recorded != digest:
        sec["phash"].append(f"the policy file hashes to {digest}, the Warden ran with {recorded}")
    return report(a, meta, sec, checks, integrity, run, warden, complete, nrec, prules, rules, proxy_ports,
                  launches_policy, openas_policy, wild_policy, names_policy, passthrough, upstream, cnotes)


def start_checks(a, meta, rs, run, sec, res, prules, rules, names_policy, proxy_ports, launches_policy,
                 openas_policy, wild_policy, passthrough, upstream, exact_hosts, pcreds, pcred_rules,
                 pcred_auds, cnotes, ident, confined6, forl6):
    """run_start read: the checks that read the records, each with what it
    needs of run_start and the policy"""
    k = {}
    k["execset"] = ExecSetScan()
    k["changes"] = ChangesCheck(openas_policy, sec["changes"])
    k["dry"] = DryCheck(rs, sec)
    k["hold"] = HoldCheck(rs, sec["hold_head"], sec["hold"])
    try:                                                                  # v1.27.1
        nx = check_noexec(meta, policy_rules(a.checker, a.policy), launches_policy, Section(), quiet=True)
    except (OSError, ValueError):
        nx = None
    k["noexec"] = NoexecLoop(nx, sec["noexec_loop"]) if nx is not None else None
    k["dns"] = DnsCheck(rs, a.checker, a.policy, prules, sec)                  # v1.25
    stub_policy = wild_policy or (proxy_ports is not None and any(
        r["kind"] == "h" and r["name"] and not r["wild"] for r in prules)) or \
        rs.get("mode") == "dry_run"                                     # v1.29: the stub runs in a dry run
    k["loop"] = MainLoop(a, meta, sec["loop"], sec["cited"], res, prules, rules, names_policy,
                         rs.get("mode") == "dry_run", stub_policy, stub_of(rs), proxy_ports, launches_policy,
                         openas_policy,
                         # v1.25 review: from 1.25 the Warden records the end of every grace
                         _version_at_least(rs.get("warden"), (1, 25)))
    k["dialed"] = Spool()
    k["proxied"] = ProxiedCheck(res, sec["proxied"], k["dialed"], upstream, exact_hosts, passthrough)
    k["closes"] = ClosesCheck(sec["closes"])
    k["refused_req"] = Spool()
    k["requests"] = RequestsCheck(prules, sec["requests"], k["refused_req"])
    k["creds"] = CredentialsCheck(pcreds, pcred_rules, pcred_auds, rs, sec, cnotes)
    k["chain"] = ChainCheck(ident, rs, run, sec)
    k["subjects"] = SubjectsCheck(confined6, forl6, sec["subjects"])
    k["launches"] = LaunchesCheck(a.checker, a.policy, prules, rs, sec) if launches_policy and prules else None
    recs = [lambda r, pos, line: k["execset"].rec(r),
            lambda r, pos, line: k["changes"].rec(r),
            lambda r, pos, line: k["dry"].rec(r),
            lambda r, pos, line: k["hold"].rec(r),
            lambda r, pos, line: k["loop"].rec(r, pos),
            lambda r, pos, line: k["proxied"].rec(r, pos),
            lambda r, pos, line: k["closes"].rec(r, pos),
            lambda r, pos, line: k["requests"].rec(r, pos),
            lambda r, pos, line: k["creds"].rec(r, line),
            lambda r, pos, line: k["chain"].rec(r, line),
            lambda r, pos, line: k["subjects"].rec(r)]
    if k["noexec"] is not None:
        recs.append(lambda r, pos, line: k["noexec"].rec(r))
    if k["launches"] is not None:
        recs.append(lambda r, pos, line: k["launches"].rec(r))
    evs = [lambda e, before, line: k["execset"].ev(e),
           lambda e, before, line: k["dry"].ev(e),
           lambda e, before, line: k["dns"].ev(e),
           lambda e, before, line: k["proxied"].ev(e),
           lambda e, before, line: k["closes"].ev(e, before),
           lambda e, before, line: k["requests"].ev(e),
           lambda e, before, line: k["creds"].ev(e, line),
           lambda e, before, line: k["chain"].ev(e, line)]
    if k["launches"] is not None:
        evs.append(lambda e, before, line: k["launches"].ev(e, before))
    k["recs"], k["evs"] = recs, evs
    return k


def report(a, meta, sec, k, integrity, run, warden, complete, nrec, prules, rules, proxy_ports,
           launches_policy, openas_policy, wild_policy, names_policy, passthrough, upstream, cnotes):
    """the checks' last parts, in main's order, and the report"""
    if not k:                                # no run_start: _iter_log refused the stream already
        return 1
    check_exec_set(meta, launches_policy, sec["execset"], k["execset"].boot, k["execset"].bad,
                   k["execset"].results)
    k["changes"].finish()
    check_open_as(meta, openas_policy, sec["openas"])                     # v1.29
    check_baseline(meta, a.policy, sec["baseline"])
    k["dry"].head(meta, sec["dry_head"])
    dry_run = k["dry"].finish(meta, sec["dry_tail"])
    plan_gate = check_plan_gate(meta, Count(nrec), sec["plan"], a.plan, complete)    # v1.35 step 7
    try:
        check_noexec(meta, policy_rules(a.checker, a.policy), launches_policy, sec["noexec"])      # v1.27.1
        check_noexec_exec(meta, policy_rules(a.checker, a.policy), openas_policy, sec["noexec_exec"])  # v1.29
    except (OSError, ValueError) as e:
        sec["noexec_fail"].append(f"checker failed on the policy's rules: {e}")
    if wild_policy:
        check_shared_lists(meta, a, sec["shared"])
    questions, budget_hits = k["dns"].finish(meta)
    if (meta.get("run_start", {}).get("host_name_rules") is True) != names_policy:
        sec["hostnames"].append("run_start's host_name_rules does not match the policy file")
    loop = k["loop"]
    # v1.24 review: a view is served unless an explicit deny in the policy
    # holds on its path (and the open's flags): ask the checker which path
    # rules hold, in order.
    if len(loop.view_recs) and rules:
        ok, out, n, err = loop.view_recs.ask(a.checker, a.policy, "holds")
        if not ok or n != len(loop.view_recs):
            sec["views"].append(f"checker failed: {err.strip()}")
        else:
            for (seq, rule, resolved, flv), row in zip(loop.view_recs.contexts(), spool_words(out)):
                for i, r in enumerate(rules):
                    if i < len(row) and row[i] == "1" and r[0] == "p" and \
                            (flv & int(r[3], 16)) == int(r[4], 16):
                        if r[1] == "d":
                            sec["views"].append(f"seq {seq}: a {rule} served, but policy "
                                                f"rule {i} denies {resolved}")
                        break
    checked = 0
    if len(loop.certs) and not sec.before("certs"):
        ok, out, n, err = loop.certs.ask(a.checker, a.policy, "batch")
        if not ok:
            sec["certs"].append(f"checker failed: {err.strip()}")
        else:
            if n != len(loop.certs):
                sec["certs"].append("checker answered a different number of certificates")
            answers = (json.loads(l) for l in out if l.strip())
            for (seq, resolved), o in zip(loop.certs.contexts(), answers):
                checked += 1
                if o.get("check") != "ok":
                    sec["certs"].append(f"seq {seq}: certificate for {resolved!r} refused: {o.get('why')}")
    # v1.24: no earlier host rule holds on any other candidate of a connect
    # decided with names (the checker's own parse and matchers).
    if loop.nothers and not sec.before("others"):
        kq = subprocess.run([a.checker, a.policy, "kinds"], capture_output=True, text=True)
        kinds = kq.stdout.strip() if kq.returncode == 0 else ""
        if not kinds:
            sec["others"].append(f"checker failed: {kq.stderr.strip()}")
        elif len(loop.others):
            ok, out, n, err = loop.others.ask(a.checker, a.policy, "holds")
            if not ok or n != len(loop.others):
                sec["others"].append(f"checker failed: {err.strip()}")
            else:
                # v1.31: a rule's subject, by its policy line
                rline = [r["line"] for r in prules]
                for_lines = loop.for_lines
                for (seq, cr, ksub, c), row in zip(loop.others.contexts(), spool_words(out)):
                    early = [i for i in range(min(cr, len(row))) if kinds[i] == "h" and row[i] == "1"
                             and (for_lines.get(rline[i], 0) if i < len(rline) else 0) == ksub]
                    if early:
                        sec["others"].append(f"seq {seq}: rule {early[0]} holds on candidate "
                                             f"{c!r}, before the rule that decided the connect")
    # v1.26 (step 8): the proxy as run_start names it, and each hand-off as the policy decides
    check_proxy_start(meta, proxy_ports, sec["proxy_start"], policy_upstream(a.checker, a.policy),
                      passthrough is not None)
    check_trust(meta, passthrough, sec["trust"], prules, proxy_ports)
    if prules:
        check_handoff_rules(a.checker, a.policy, prules, loop.handoff_cands, sec["handoff"])
    # v1.26 (step 6): the Warden's decisions on what the proxy read
    proxied = k["proxied"].n
    if prules:
        check_dialed_denies(a.checker, a.policy, prules, k["dialed"], sec["dialed"])
    pcloses = k["closes"].finish(complete)                                              # step 7
    nreq = k["requests"].n                                                               # v1.26.1
    if nreq:
        check_refused_requests(a.checker, a.policy, prules, k["refused_req"], sec["refreq"])   # step 7
    ncarried, nswap_refused, revoked = k["creds"].finish(complete)                     # v1.28
    per_sub = k["chain"].finish()                                                        # v1.28.1
    try:                                                                                   # v1.35 step 4b
        if policy_requires_plan(a.checker, a.policy) and not isinstance(meta.get("run_start", {}).get("hold"), dict):
            sec["reqplan"].append("the policy says `require plan`, and run_start holds the run to no plan")
    except (OSError, ValueError) as e:
        sec["reqplan"].append(f"checker failed on the policy's identities: {e}")
    nlaunch = nlaunch_refused = 0
    if k["launches"] is not None:                                                         # v1.27
        nlaunch, nlaunch_refused = k["launches"].finish(meta, complete, nrec)
    re_ = meta.get("run_end")
    if isinstance(re_, dict) and re_.get("proxy_failed") is True:                        # review
        sec["end_proxy"].append("run_end says the egress proxy exited or sent a malformed report as the run "
                                "ended: its open connections were not reported")
    if proxied and proxy_ports is None:
        sec["end_proxied"].append("proxied decisions, but the policy does not turn the proxy on")
    # v1.26: every connection id the Warden gave a hand-off is recorded once
    ids = loop.handoff_ids
    if complete and ids and not ids.is_range(1, len(ids)):
        sec["end_ids"].append(f"the hand-offs' connection ids are not 1 to {len(ids)}: one is missing")
    print(f"varek_audit: run {run} (Warden {warden}, {'complete' if complete else 'INCOMPLETE'}), "
          f"{nrec} records, {loop.authorized} authorized file opens, {loop.lookups} lookups, "
          f"{loop.connects} authorized connects, "
          f"{loop.views} host-name views, {loop.stubs} stub resolver connects, {loop.handoffs} proxy hand-offs, "
          f"{proxied} proxied decisions ({loop.proxied_ok} allowed), {pcloses} proxy closes, {nreq} inspected requests, "
          f"{nlaunch} launches allowed ({nlaunch_refused} refused), "
          f"{questions} stub questions ({budget_hits} over a budget), "
          f"{checked} certificates "
          f"re-checked, {loop.refused} refused in-line")
    if k["creds"].creds or revoked:                                                       # v1.28
        print(f"varek_audit: credentials: {len(k['creds'].creds)} named, {ncarried} requests carried one, "
              f"{nswap_refused} swaps refused{', the run was revoked' if revoked else ''}")
    if per_sub is not None:                                                               # v1.28.1
        ob_ = meta.get("run_start", {}).get("on_behalf_of")
        u = ob_.get("user") if isinstance(ob_, dict) else None
        who = f"on behalf of {u.get('subject')} ({u.get('issuer')})" if isinstance(u, dict) else "no user"
        print(f"varek_audit: chain: {who}; sub-agents: {chain_summary(per_sub)}")
    if plan_gate is not None:                                                             # v1.35 step 7
        hold_ = meta.get("run_start", {}).get("hold")
        nout = k["hold"].nout
        nsteps = sum(1 for _, e in meta.get("plan_events", []) if e.get("event") == "plan_step")
        print(f"varek_audit: plan: {plan_gate.get('plan')} ({plan_gate.get('actions')} steps"
              f"{', SHA-256 ' + plan_gate['plan_sha256'] if isinstance(plan_gate.get('plan_sha256'), str) else ''}): "
              f"{plan_gate.get('verdict')}"
              f"{f', {nsteps} step(s) not SATISFIED' if nsteps else ''}; "
              f"{f'held to it, {nout} call(s) refused outside it' if isinstance(hold_, dict) and gate_passed(plan_gate) else 'to be held to it, but refused' if isinstance(hold_, dict) else 'not held to it'}")
    for n_ in cnotes:
        print(f"varek_audit: note: {n_}")
    print(f"varek_audit: integrity: {integrity}")
    if isinstance(meta.get("run_start", {}).get("arch"), str):                          # v1.33.0
        print(f"varek_audit: architecture: {meta['run_start']['arch']}")
    t0 = meta.get("run_start", {}).get("timestamp_ns")
    if isinstance(t0, int):
        import datetime
        when = datetime.datetime.fromtimestamp(t0 / 1e9, datetime.timezone.utc)
        print(f"varek_audit: run started {when.isoformat(timespec='seconds')} "
              f"(policy {meta['run_start'].get('policy_path')!r})")
    for pr in sec.shown():
        print(f"  PROBLEM {pr}")
    # v1.29 (D10): a dry run that passes is verified and NOT ENFORCED, with
    # an exit code of its own, so a script that reads 0 as "enforced" cannot
    # mistake it
    if dry_run and not len(sec):
        nd = k["dry"].n
        print(f"varek_audit: VERIFIED: DRY RUN, NOT ENFORCED ({nd} call(s) the policy refuses were let through)")
        return 3
    print(f"varek_audit: {'PASS' if not len(sec) else 'FAIL'}")
    return 0 if not len(sec) else 1


if __name__ == "__main__":
    sys.exit(main())
