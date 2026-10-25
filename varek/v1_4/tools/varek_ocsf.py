#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
varek_ocsf.py — v1.31 (docs/security/v1.31-standards.md, section 1): export a
VAREK Warden verdict stream as OCSF 1.9.0 events, one JSON object per line.

OCSF: the Open Cybersecurity Schema Framework, an LF Projects series whose
schema is licensed under the Apache License 2.0. VAREK and Sober Agentic
Infrastructure, Inc. are not affiliated with, endorsed by, or certified by
the OCSF project; the name describes interoperability with the openly
published schema. See the NOTICE file and schemas/ocsf-1.9.0/.

Each event declares OCSF 1.9.0 and the profiles security_control,
ai_operation and host, and carries:
  * the class and activity of its record (the design's table): File System
    Activity, Process Activity, Network Activity, HTTP Activity, DNS
    Activity, API Activity (an MCP call), Application Lifecycle (the run's
    start and end, a revocation, the user's token's expiry, each signed
    checkpoint, and the audit's verdict);
  * the decision (security_control): action_id Allowed or Denied,
    disposition_id Allowed, Blocked, or Detected for a dry run's would-be
    refusal (never Blocked); status from the kernel's outcome; the policy
    (its file, SHA-256, grammar, the deciding line's text);
  * who (ai_operation, host): the calling process and its Unix user, the
    agent (or the sub-agent, or the MCP server) in ai_agent, and with a
    verified user (v1.28.1) actor.user, actor.idp and the delegation;
  * the link back, in unmapped.varek: the record's report id, seq and chain
    value, the three-state verdict (SATISFIED, UNSATISFIED, UNKNOWN; OCSF
    has no UNKNOWN), and the record itself.

Records with no OCSF counterpart are folded into the event they belong to
(an exec_result into its launch, a request_body into its request, a
rename's second half into its first, v1.35: each plan_step into its plan
gate's event) or not exported. v1.35 step 7: the plan gate's verdict is an
Application Lifecycle event of its own (activity Other, unmapped.varek.event
"plan_gate"): Allowed when the plan is authorized, Denied and Blocked when it
is refused (the agent not started), with the plan's path, SHA-256 and size,
and each step not SATISFIED with its reason and the policy line's text; a
call refused as outside a held run's plan names the plan it is held to.

Usage:
    varek_ocsf.py --log STREAM --policy POLICY --checker vdp_cert_check
        [--pubkey KEY] [--anchor FILE] [--allow-incomplete] [--device NAME]
        [--output EVENTS]
        The stream is audited first (tools/varek_audit.py); a stream the
        audit refuses is not exported.
    varek_ocsf.py --follow STREAM --policy POLICY --checker vdp_cert_check
        [--idle SECONDS] ...
        Tail a live stream: each record's event is written as the record is
        chained (checked one by one); at run_end (or when the stream stops
        growing for --idle seconds) the whole-stream audit runs, and the last
        event says whether it passed.
    varek_ocsf.py --verify EVENTS --log STREAM --policy POLICY
        Check that EVENTS are exactly the events this exporter writes from
        STREAM (none edited, removed, added or reordered), and that the
        stream is intact.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import varek_cyclonedx as cdx      # noqa: E402  the stream's parser and chain check

OCSF_VERSION = "1.9.0"
PROFILES = ["security_control", "ai_operation", "host"]
VENDOR = "Sober Agentic Infrastructure, Inc."
HOLD = 64                          # records an event waits at most for what folds into it

# class: (class_uid, category_uid, class_name, category_name)
FILE = (1001, 1, "File System Activity", "System Activity")
PROC = (1007, 1, "Process Activity", "System Activity")
NET = (4001, 4, "Network Activity", "Network Activity")
HTTP = (4002, 4, "HTTP Activity", "Network Activity")
DNS = (4003, 4, "DNS Activity", "Network Activity")
LIFE = (6002, 6, "Application Lifecycle", "Application Activity")
API = (6003, 6, "API Activity", "Application Activity")

ACTIVITY = {
    FILE: {1: "Create", 2: "Read", 3: "Update", 4: "Delete", 5: "Rename", 6: "Set Attributes",
           8: "Get Attributes", 14: "Open", 99: "Other"},
    PROC: {1: "Launch", 99: "Other"},
    NET: {1: "Open", 5: "Refuse", 7: "Listen", 99: "Other"},
    HTTP: {1: "Connect", 2: "Delete", 3: "Get", 4: "Head", 5: "Options", 6: "Post", 7: "Put", 8: "Trace",
           9: "Patch", 99: "Other"},
    DNS: {1: "Query"},
    LIFE: {3: "Start", 4: "Stop", 7: "Disable", 99: "Other"},
    API: {2: "Read", 99: "Other"},
}
HTTP_METHODS = {"CONNECT": 1, "DELETE": 2, "GET": 3, "HEAD": 4, "OPTIONS": 5, "POST": 6, "PUT": 7, "TRACE": 8,
                "PATCH": 9}
FILE_ACT = {"file.open": 14, "file.readlink": 2, "file.access": 8, "file.stat": 8, "file.mkdir": 1,
            "file.unlink": 4, "file.rmdir": 4, "file.rename_from": 5, "file.rename_to": 5,
            "file.chmod": 6, "file.utime": 6, "file.truncate": 3, "file.chdir": 99}
DIR_ACTIONS = ("file.mkdir", "file.rmdir", "file.chdir")
VERDICT = {"ALLOW": "SATISFIED", "DENY": "UNSATISFIED", "UNKNOWN": "UNKNOWN"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
             65: "HTTPS"}
O_CREAT = 0o100


class ExportError(Exception):
    pass


def _endpoint(s):
    """name:port, [v6]:port, addr:port or unix:PATH, as an OCSF network endpoint"""
    s = str(s or "")
    ep = {"name": s or "unknown"}
    m = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\]:(\d{1,5})", s) or re.fullmatch(r"([^:\[\]]+):(\d{1,5})", s)
    if m and int(m.group(2)) <= 65535:
        host, port = m.group(1), int(m.group(2))
        ep["port"] = port
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) or ":" in host:
            ep["ip"] = host
        else:
            ep["hostname"] = host
    return ep


def _file(path, dirop=False):
    path = str(path or "")
    name = os.path.basename(path.rstrip("/")) or path or "unknown"
    return {"name": name, "path": path, "type_id": 2 if dirop else 0,
            "type": "Folder" if dirop else "Unknown"}


def _policy_grammar(lines, warden):
    for ln in lines:
        m = re.match(r"\s*require\s+warden\s+(\d+\.\d+)", ln)
        if m:
            return m.group(1)
    m = re.match(r"(\d+\.\d+)", str(warden or ""))
    return m.group(1) if m else "unknown"


class Exporter:
    """Feed it a run's records in stream order (each with its chain value);
    it returns the events ready to write, in record order. Batch, follow and
    --verify all use it, so each writes the same events from the same
    stream."""

    def __init__(self, policy_path, device):
        self.policy_path = policy_path
        with open(policy_path, "rb") as fh:
            data = fh.read()
        self.policy_sha = hashlib.sha256(data).hexdigest()
        self.policy_lines = data.decode("utf-8", errors="replace").split("\n")
        self.device = {"type_id": 0, "type": "Unknown", "name": device}
        self.rs = None
        self.agent = None
        self.subagents = {}            # "NAME#n" -> True if an MCP server
        self.plan_steps = []           # v1.35 step 7: plan_step records, folded into their gate's event
        self.queue = []                # [event, waiting-for key or None, records left to wait]
        self.n = 0                     # chained records seen
        self.last_ts = 0

    # ---- the parts every event has ----

    def _base(self, cls, act, rec, ts_ns, uid):
        rs = self.rs or {}
        ev = {
            "class_uid": cls[0], "class_name": cls[2], "category_uid": cls[1], "category_name": cls[3],
            "activity_id": act, "activity_name": ACTIVITY[cls][act], "type_uid": cls[0] * 100 + act,
            "type_name": f"{cls[2]}: {ACTIVITY[cls][act]}",
            "time": int(ts_ns // 1000000) if isinstance(ts_ns, int) else 0,
            "severity_id": 1, "severity": "Informational",
            "metadata": {"version": OCSF_VERSION, "profiles": list(PROFILES), "uid": uid,
                         "correlation_uid": rs.get("run", ""), "log_name": "VAREK verdict stream",
                         "product": {"name": "VAREK Warden", "vendor_name": VENDOR,
                                     "version": str(rs.get("warden", ""))}},
            "device": dict(self.device),
            "unmapped": {"varek": {"chain": rec.get("chain"), "position": self.n,
                                   "record": {k: v for k, v in rec.items() if k != "chain"}}},
        }
        return ev

    def _who(self, ev, rec):
        """actor, ai_agent and the delegation, for a decision record"""
        rs = self.rs or {}
        oa = rs.get("open_as") if isinstance(rs.get("open_as"), dict) else {}
        proc = {"pid": rec.get("agent_pid") if isinstance(rec.get("agent_pid"), int) else 0,
                "uid": f"{rs.get('run', '')}/{rec.get('agent_pid')}"}
        if isinstance(oa.get("uid"), int):
            proc["user"] = {"uid": str(oa["uid"]), "type_id": 1, "type": "User"}
        actor = {"process": proc}
        user = (rs.get("on_behalf_of") or {}).get("user") if isinstance(rs.get("on_behalf_of"), dict) else None
        if isinstance(user, dict) and user.get("subject"):
            actor["user"] = {"uid": str(user["subject"]), "name": str(user["subject"])}
            if user.get("issuer"):
                actor["idp"] = {"uid": str(user["issuer"]), "name": str(user["issuer"])}
            d = {"uid": str(user.get("token_sha256", ""))}
            if user.get("issuer"):
                d["issuer_uid"] = str(user["issuer"])
            ev["delegation"] = d
        ev["actor"] = actor
        obo = rec.get("obo") if isinstance(rec.get("obo"), list) else []
        last = obo[-1] if obo else "agent"
        m = re.fullmatch(r"subagent:([a-z][a-z0-9_]{0,31})#(\d+)", str(last))
        if m:
            tag = f"{m.group(1)}#{m.group(2)}"
            ev["ai_agent"] = {"name": m.group(1), "instance_uid": f"{rs.get('run', '')}/{tag}", "type_id": 99,
                              "type": "mcp_server" if self.subagents.get(tag) else "sub_agent"}
        else:
            ev["ai_agent"] = dict(self.agent or {"name": "agent"})
        ev["unmapped"]["varek"]["obo"] = obo

    def _outcome(self, ev, rec):
        """the decision's outcome (security_control, status, severity)"""
        allowed = rec.get("decision_final") == "ALLOW"
        dry = rec.get("enforced") is False
        ev["action_id"], ev["action"] = (1, "Allowed") if allowed else (2, "Denied")
        ev["disposition_id"], ev["disposition"] = (1, "Allowed") if allowed else \
            ((15, "Detected") if dry else (2, "Blocked"))
        kv = rec.get("kernel_verdict")
        if dry and rec.get("errno") == 0:
            kv = "ALLOW"                   # review: a dry run let it through; the call was carried out
        ev["status_id"], ev["status"] = (1, "Success") if kv == "ALLOW" else (2, "Failure")
        if kv != "ALLOW":
            ev["status_detail"] = str(kv)
        ev["status_code"] = str(rec.get("errno", 0))
        ev["severity_id"], ev["severity"] = (1, "Informational") if allowed else (3, "Medium")

    def _decision(self, ev, rec):
        """security_control and the link back, for a decision record"""
        self._outcome(ev, rec)
        dry = rec.get("enforced") is False
        line = rec.get("policy_line")
        ev["policy"] = self._policy_obj(line)
        v = ev["unmapped"]["varek"]
        v.update({"report_id": rec.get("report_id"), "seq": rec.get("seq"),
                  "decision": VERDICT.get(rec.get("decision_raw"), "UNKNOWN"),
                  "decision_raw": rec.get("decision_raw"), "decision_final": rec.get("decision_final"),
                  "rule": rec.get("rule"), "policy_line": line})
        if "cert_rule" in rec:
            v["certificate"] = {"rule": rec.get("cert_rule"), "witness": rec.get("cert_witness"),
                                "check": rec.get("check"), "subject": rec.get("cert_subject", 0)}
        if dry:
            v["mode"] = "dry_run"
        hold = (self.rs or {}).get("hold")
        if rec.get("rule") == "outside_plan" and isinstance(hold, dict):      # v1.35 step 7
            v["plan"] = {"plan": hold.get("plan"), "plan_sha256": hold.get("plan_sha256"), "held": True}
        ev["metadata"]["sequence"] = rec.get("seq") if isinstance(rec.get("seq"), int) else 0

    # ---- each kind ----

    def _decision_event(self, rec):
        a = rec.get("action")
        obj = rec.get("resolved") or rec.get("target")
        uid = str(rec.get("report_id"))
        if a in FILE_ACT:
            act = FILE_ACT[a]
            fl = rec.get("open_flags")
            if a == "file.open" and isinstance(fl, str) and fl.startswith("0x") and int(fl, 16) & O_CREAT:
                act = 1
            ev = self._base(FILE, act, rec, rec.get("timestamp_ns"), uid)
            ev["file"] = _file(obj, a in DIR_ACTIONS)
        elif a == "process.exec":
            ev = self._base(PROC, 1, rec, rec.get("timestamp_ns"), uid)
            p = _file(obj)
            ev["process"] = {"pid": rec.get("agent_pid") if isinstance(rec.get("agent_pid"), int) else 0,
                             "name": p["name"], "file": p}
            if rec.get("subagent"):
                ev["unmapped"]["varek"]["subagent"] = rec.get("subagent")
        elif a in ("net.connect", "net.send", "net.proxy", "net.bind"):
            refused = rec.get("decision_final") != "ALLOW"
            ev = self._base(NET, 7 if a == "net.bind" else (5 if refused else 1), rec, rec.get("timestamp_ns"), uid)
            ep = _endpoint(obj)
            if a == "net.bind":
                ev["src_endpoint"] = ep
            else:
                ev["dst_endpoint"] = ep
                ev["src_endpoint"] = {"name": self.device["name"]}
        elif a == "net.request":
            m = re.fullmatch(r"([A-Z]{1,20}) (\S+)", str(obj))
            meth, url = (m.group(1), m.group(2)) if m else ("", str(obj))
            ev = self._base(HTTP, HTTP_METHODS.get(meth, 99), rec, rec.get("timestamp_ns"), uid)
            u = re.fullmatch(r"(https?)://([^/:]+):(\d+)(/[^?]*)(?:\?(.*))?", url)
            uo = {"url_string": url}
            if u:
                uo.update({"scheme": u.group(1), "hostname": u.group(2), "port": int(u.group(3)),
                           "path": u.group(4)})
                if u.group(5) is not None:
                    uo["query_string"] = u.group(5)
            ev["http_request"] = {"http_method": meth or "UNKNOWN", "url": uo}
            ev["dst_endpoint"] = _endpoint(f"{u.group(2)}:{u.group(3)}" if u else url)
            ev["src_endpoint"] = {"name": self.device["name"]}
        elif a == "net.mcp":
            meth = str(rec.get("mcp_method") or "")
            act = 2 if (meth.endswith("/list") or meth in ("resources/read", "prompts/get")) else 99
            ev = self._base(API, act, rec, rec.get("timestamp_ns"), uid)
            api = {"operation": meth or "unreadable", "service": {"name": str(rec.get("mcp_url") or "")}}
            if rec.get("rpc_id") is not None:
                api["request"] = {"uid": str(rec.get("rpc_id"))}
            ev["api"] = api
            if rec.get("mcp_name") is not None:
                kind = "tool" if meth == "tools/call" else "resource" if meth.startswith("resources/") else \
                    "prompt" if meth.startswith("prompts/") else "name"
                ev["resources"] = [{"name": str(rec["mcp_name"]), "type": kind}]
            u = re.fullmatch(r"https?://([^/:]+):(\d+)/.*", str(rec.get("mcp_url") or ""))
            ev["dst_endpoint"] = _endpoint(f"{u.group(1)}:{u.group(2)}" if u else rec.get("mcp_url"))
            ev["src_endpoint"] = {"name": self.device["name"]}
        else:                          # a system call the baseline filter decided (v1.29), or another
            ev = self._base(PROC, 99, rec, rec.get("timestamp_ns"), uid)
            ev["process"] = {"pid": rec.get("agent_pid") if isinstance(rec.get("agent_pid"), int) else 0,
                             "uid": f"{(self.rs or {}).get('run', '')}/{rec.get('agent_pid')}"}
            ev["unmapped"]["varek"]["syscall"] = rec.get("target")
        self._who(ev, rec)
        self._decision(ev, rec)
        return ev

    def _life(self, act, rec, what):
        ev = self._base(LIFE, act, rec, rec.get("timestamp_ns"), f"{rec.get('run')}/{what}/{self.n}")
        ev["app"] = {"name": "VAREK Warden", "vendor_name": VENDOR, "version": str((self.rs or {}).get("warden", ""))}
        ev["unmapped"]["varek"]["event"] = what
        return ev

    def _policy_obj(self, line):
        pol = {"name": os.path.basename(str((self.rs or {}).get("policy_path") or self.policy_path)),
               "uid": self.policy_sha, "is_applied": True,
               "version": _policy_grammar(self.policy_lines, (self.rs or {}).get("warden"))}
        if isinstance(line, int) and 1 <= line <= len(self.policy_lines):
            pol["desc"] = self.policy_lines[line - 1].strip()
        return pol

    def _plan_step(self, rec):
        st = {k: rec.get(k) for k in ("label", "kind", "target", "resolved", "decision", "policy_line", "why")}
        line = rec.get("policy_line")
        if isinstance(line, int) and 1 <= line <= len(self.policy_lines):
            st["policy_text"] = self.policy_lines[line - 1].strip()
        st["chain"] = rec.get("chain")
        return st

    def _plan_gate_event(self, rec):
        """v1.35 step 7: the plan gate's verdict, its refused steps folded in"""
        ev = self._life(99, rec, "plan_gate")
        ok = rec.get("verdict") == "SATISFIED"
        ev["action_id"], ev["action"] = (1, "Allowed") if ok else (2, "Denied")
        ev["disposition_id"], ev["disposition"] = (1, "Allowed") if ok else (2, "Blocked")
        ev["status_id"], ev["status"] = (1, "Success") if ok else (2, "Failure")
        if not ok:
            ev["status_detail"] = str(rec.get("error") or "the plan was refused: the agent did not start")
        ev["severity_id"], ev["severity"] = (1, "Informational") if ok else (3, "Medium")
        ev["policy"] = self._policy_obj(None)
        v = ev["unmapped"]["varek"]
        v["plan"] = {k: rec.get(k) for k in ("gate", "plan", "plan_sha256", "actions", "edges") if k in rec}
        v["decision"] = rec.get("verdict") if rec.get("verdict") in VERDICT.values() else "UNKNOWN"
        steps = [x for x in self.plan_steps if x.get("plan") == rec.get("plan")]
        v["plan_steps"] = [self._plan_step(x) for x in steps]
        self.plan_steps = [x for x in self.plan_steps if x.get("plan") != rec.get("plan")]
        return ev

    # ---- feeding ----

    def feed(self, rec):
        """One chained record of the run. Returns the events now ready."""
        self.n += 1
        if isinstance(rec.get("timestamp_ns"), int):
            self.last_ts = rec["timestamp_ns"]
        ev_name = rec.get("event")
        out_ev, wait = None, None
        if "decision_final" in rec:
            ev_name = None                 # review: a decision is one, whatever else the record says
        if ev_name == "run_start":
            self.rs = rec
            boot = [e for e in rec.get("exec_ruleset", []) if isinstance(e, dict) and e.get("why") == "bootstrap"]
            self.agent = {"type_id": 99, "type": "Other", "instance_uid": str(rec.get("run", "")), "name": "agent"}
            if boot and boot[0].get("sha256"):
                self.agent["uid"] = str(boot[0]["sha256"])
                self.agent["name"] = os.path.basename(str(boot[0].get("name") or boot[0].get("path") or "agent"))
            out_ev = self._life(3, rec, "run_start")
        elif ev_name == "run_end":
            out_ev = self._life(4, rec, "run_end")
            out_ev["unmapped"]["varek"]["exit_status"] = rec.get("exit_status")
        elif ev_name in ("revoked", "on_behalf_of_expired"):
            out_ev = self._life(7, rec, ev_name)
        elif ev_name == "checkpoint":
            out_ev = self._life(99, rec, "checkpoint")
            out_ev["unmapped"]["varek"]["checkpoint"] = {"records": rec.get("records"), "chain": rec.get("chain"),
                                                         "signed": "sig" in rec}
        elif ev_name == "dns_question":
            out_ev = self._base(DNS, 1, rec, rec.get("timestamp_ns"), f"{rec.get('run')}/dns/{self.n}")
            t = rec.get("type")
            out_ev["query"] = {"hostname": str(rec.get("name") or ""), "type": DNS_TYPES.get(t, str(t))}
            # v1.34 step 4: under the node agent the stub may be at a later address
            out_ev["dst_endpoint"] = _endpoint(str((getattr(self, "rs", None) or {}).get("dns_stub") or "127.53.53.53:53"))
            out_ev["src_endpoint"] = {"name": self.device["name"]}
            ok = rec.get("rule") in ("policy_match", "exact_name")     # review: an exact rule's name answered
            dry = rec.get("enforced") is False
            out_ev["action_id"], out_ev["action"] = (1, "Allowed") if ok else (2, "Denied")
            out_ev["disposition_id"], out_ev["disposition"] = (1, "Allowed") if ok else \
                ((15, "Detected") if dry else (2, "Blocked"))
            out_ev["unmapped"]["varek"].update({"rule": rec.get("rule"), "policy_line": rec.get("policy_line"),
                                                "answer": rec.get("answer")})
            if dry:
                out_ev["unmapped"]["varek"]["mode"] = "dry_run"
        elif ev_name == "plan_step":                                       # v1.35 step 7
            self.plan_steps.append(rec)
        elif ev_name == "plan_gate":
            out_ev = self._plan_gate_event(rec)
        elif ev_name == "exec_result":
            self._fold(("exec", rec.get("decision_seq")), "exec_result", rec)
        elif ev_name == "request_body":
            self._fold(("body", rec.get("proxy_conn"), rec.get("request_seq")), "request_body", rec)
        elif "decision_final" in rec and "action" in rec:
            a = rec.get("action")
            if a == "file.rename_to" and self.queue and self.queue[-1][1] == ("rename", rec.get("agent_pid")):
                head = self.queue[-1][0]
                head["file_result"] = _file(rec.get("resolved") or rec.get("target"))
                head["unmapped"]["varek"]["rename_to"] = {
                    "report_id": rec.get("report_id"), "seq": rec.get("seq"), "chain": rec.get("chain"),
                    "decision": VERDICT.get(rec.get("decision_raw"), "UNKNOWN"),
                    "record": {k: v for k, v in rec.items() if k != "chain"}}
                if rec.get("decision_final") != "ALLOW" and head.get("action_id") == 1:
                    self._outcome(head, rec)           # the pair is refused if either half is
                self.queue[-1][1] = None
                return self._drain()
            if a == "process.exec" and rec.get("rule") == "bootstrap_exec_allow" and self.agent and \
                    "uid" not in self.agent:          # the agent's program, by its name (no hash recorded)
                self.agent["name"] = os.path.basename(str(rec.get("target") or "agent")) or "agent"
            out_ev = self._decision_event(rec)
            if a == "process.exec" and rec.get("decision_final") == "ALLOW":
                wait = ("exec", rec.get("seq"))
                if rec.get("subagent"):
                    self.subagents[str(rec.get("subagent"))] = rec.get("mcp_server") is True
            elif a == "net.request" and rec.get("decision_final") == "ALLOW" and rec.get("body") in ("length", "chunked"):
                wait = ("body", rec.get("proxy_conn"), rec.get("request_seq"))
            elif a == "file.rename_from":
                wait = ("rename", rec.get("agent_pid"))
        if out_ev is not None:
            self.queue.append([out_ev, wait, 1 if wait and wait[0] == "rename" else HOLD])
        return self._drain()

    def _fold(self, key, name, rec):
        for item in self.queue:
            if item[1] == key:
                v = item[0]["unmapped"]["varek"]
                v[name] = {k: x for k, x in rec.items() if k != "chain"}
                v[name]["chain"] = rec.get("chain")
                if name == "request_body" and isinstance(rec.get("body_len"), int):
                    item[0]["http_request"]["body_length"] = rec["body_len"]
                item[1] = None
                return

    def _drain(self):
        for item in self.queue:            # each record that arrives counts against what waits
            if item[1] is not None:
                item[2] -= 1
                if item[2] < 0:
                    item[1] = None
        out = []
        while self.queue and self.queue[0][1] is None:
            out.append(self.queue.pop(0)[0])
        return out

    def finish(self):
        out = [item[0] for item in self.queue]
        self.queue = []
        for rec in self.plan_steps:        # v1.35 step 7: a step whose gate's record never came
            ev = self._life(99, rec, "plan_step")
            ev["unmapped"]["varek"]["plan_steps"] = [self._plan_step(rec)]
            out.append(ev)
        self.plan_steps = []
        return out


def audit_event(exporter, passed, mode, problems, dry=False):
    """The last event: what the whole-stream audit said"""
    rs = exporter.rs or {}
    rec = {"run": rs.get("run"), "timestamp_ns": None}
    ev = exporter._base(LIFE, 99, rec, exporter.last_ts, f"{rs.get('run')}/audit")
    ev["app"] = {"name": "VAREK audit", "vendor_name": VENDOR, "version": str(rs.get("warden", ""))}
    ev["unmapped"]["varek"] = {"event": "audit", "audit": {"passed": bool(passed), "mode": mode,
                                                           "problems": problems[:50]}}
    if dry:
        ev["unmapped"]["varek"]["audit"]["not_enforced"] = True      # a dry run (v1.29)
    if not passed:
        ev["severity_id"], ev["severity"] = 4, "High"
    return ev


def dumps(ev):
    return json.dumps(ev, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def private_copy(path):
    """review: the stream read once, into a file of the exporter's own, so the
    audit and the export read the same bytes (a stream still being written,
    or a file replaced between two reads, is not exported unaudited).
    Returns (path of the copy, its directory)."""
    d = tempfile.mkdtemp(prefix="varek-ocsf-")
    cp = os.path.join(d, "stream.log")
    with open(path, "rb") as src, open(cp, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return cp, d


def run_records(path, allow_incomplete):
    """The run's records in stream order, the stream checked (chain, seq,
    run id) by the CycloneDX exporter's parser first"""
    meta = {}
    with open(path, encoding="utf-8", errors="surrogateescape", newline="\n") as fh:
        run, _, complete, _ = cdx._parse_log(fh, allow_incomplete, meta)
    out = []
    with open(path, encoding="utf-8", errors="surrogateescape", newline="\n") as fh:
        for raw in fh:
            if not raw.startswith("{"):
                continue
            rec = json.loads(raw)
            if isinstance(rec, dict) and (rec.get("run") == run):
                out.append(rec)
    return out, complete


def audit(args, log):
    argv = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "varek_audit.py"),
            "--policy", args.policy, "--checker", args.checker]
    if args.pubkey:
        argv += ["--pubkey", args.pubkey]
    if args.anchor:
        argv += ["--anchor", args.anchor]
    if args.allow_incomplete:
        argv.append("--allow-incomplete")
    p = subprocess.run(argv + [log], capture_output=True, text=True)
    problems = [ln.strip() for ln in p.stdout.splitlines() if "PROBLEM" in ln]
    # 0: verified; 3: verified, a dry run (not enforced, v1.29)
    return p.returncode in (0, 3), problems, p.stdout + p.stderr, p.returncode == 3


def check_policy(exporter, rs):
    if rs and rs.get("policy_sha256") and rs["policy_sha256"] != exporter.policy_sha:
        raise ExportError(f"the policy file's SHA-256 {exporter.policy_sha} is not the one the run used "
                          f"({rs['policy_sha256']})")


def cmd_batch(args):
    log, d = private_copy(args.log)
    try:
        return _batch(args, log)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _batch(args, log):
    ok, problems, text, dry = audit(args, log)
    if not ok:
        sys.stderr.write(text)
        raise ExportError("the audit refuses this stream; no events are written")
    recs, _ = run_records(log, args.allow_incomplete)
    ex = Exporter(args.policy, args.device)
    events = []
    for r in recs:
        events += ex.feed(r)
        if r.get("event") == "run_start":
            check_policy(ex, r)
    events += ex.finish()
    events.append(audit_event(ex, True, "batch", [], dry))
    out = open(args.output, "w") if args.output else sys.stdout
    for ev in events:
        out.write(dumps(ev) + "\n")
    if args.output:
        out.close()
        print(f"varek_ocsf: {len(events)} OCSF {OCSF_VERSION} events written to {args.output}", file=sys.stderr)
    return 0


def cmd_follow(args):
    path = args.follow
    out = open(args.output, "a") if args.output else sys.stdout
    ex = None
    chained = {"head": cdx.LOG_CHAIN_IV, "n": 0, "signed": [], "since_signed": 0, "anchor_errors": []}
    run, ndec, buf, last = None, 0, "", time.monotonic()
    ended = False

    def fail(lineno, why):
        raise ExportError(f"{path}:{lineno}: {why}")

    for _ in range(200):                       # the stream may not exist yet
        if os.path.exists(path):
            break
        time.sleep(0.1)
    fh = open(path, encoding="utf-8", errors="surrogateescape", newline="\n")
    lineno = 0
    problems = []
    try:
        while not ended:
            chunk = fh.readline()
            if not chunk:
                if args.idle and time.monotonic() - last > args.idle:
                    problems.append(f"the stream stopped growing for {args.idle:g} s with no run_end "
                                    f"(the run ended early, or the Warden was killed)")
                    break
                time.sleep(0.1)
                continue
            buf += chunk
            if not buf.endswith("\n"):
                continue
            raw, buf = buf, ""
            lineno += 1
            last = time.monotonic()
            if not raw.startswith("{"):
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                fail(lineno, "a line that is not JSON")
            if not isinstance(rec, dict):
                fail(lineno, "a record that is not a JSON object")
            if run is None:
                if rec.get("event") != "run_start":
                    continue
                run = rec.get("run")
                ex = Exporter(args.policy, args.device)
            if rec.get("run") != run:
                fail(lineno, "a record of another run")
            cdx._chain_step(chained, raw, rec, lineno, ndec, fail)   # each record checked as it is chained
            if "decision_final" in rec and rec.get("event") is None:
                if rec.get("seq") != ndec:
                    fail(lineno, f"seq {rec.get('seq')} where {ndec} was expected")
                ndec += 1
            try:
                evs = ex.feed(rec)
            except (KeyError, TypeError, ValueError, AttributeError, IndexError) as e:
                fail(lineno, f"a record the exporter cannot read ({type(e).__name__}: {e})")
            if rec.get("event") == "run_start" and "decision_final" not in rec:
                check_policy(ex, rec)           # review: before its event is written
            for ev in evs:
                out.write(dumps(ev) + "\n")
            out.flush()
            if rec.get("event") == "run_end":
                ended = True
    except ExportError as e:
        # review: whatever stops the follow, the last event says so
        if ex is None:
            raise
        problems.append(str(e))
    finally:
        fh.close()
    if ex is None:
        raise ExportError(f"{path}: no run_start")
    for ev in ex.finish():
        out.write(dumps(ev) + "\n")
    dry = False
    if ended:
        ok, probs, _, dry = audit(args, path)
        problems += probs
    else:
        ok = False
    out.write(dumps(audit_event(ex, ok and not problems, "follow", problems, dry)) + "\n")
    out.flush()
    return 0 if ok and not problems else 1


def cmd_verify(args):
    log, d = private_copy(args.log)
    try:
        return _verify(args, log)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _verify(args, log):
    evs = []
    for i, line in enumerate(open(args.verify, encoding="utf-8"), 1):
        if line.strip():
            try:
                evs.append(json.loads(line))
            except ValueError:
                raise ExportError(f"{args.verify}:{i}: not JSON")
    if not evs:
        raise ExportError(f"{args.verify}: no events")
    device = ((evs[0].get("device") or {}).get("name")) or ""
    # review: the stream itself is audited (signatures, certificates, every
    # check), not only its chain, which anyone can recompute
    ok, _, text, dry = audit(args, log)
    if not ok:
        sys.stderr.write(text)
        raise ExportError("the audit refuses the stream: its events cannot be the evidence of a run")
    recs, _ = run_records(log, args.allow_incomplete)
    ex = Exporter(args.policy, device)
    want = []
    for r in recs:
        want += ex.feed(r)
        if r.get("event") == "run_start":
            check_policy(ex, r)
    want += ex.finish()
    last = evs[-1]
    v = (last.get("unmapped") or {}).get("varek", {}) if isinstance(last.get("unmapped"), dict) else {}
    if not isinstance(v, dict) or v.get("event") != "audit" or not isinstance(v.get("audit"), dict):
        raise ExportError("the last event is not the audit's verdict (events were cut off, or added)")
    if v["audit"].get("passed") is not True:
        raise ExportError("the audit's verdict in the events is that the stream did not pass")
    # review: the verdict event is compared too, as the exporter writes it
    mode = v["audit"].get("mode")
    if mode not in ("batch", "follow") or last != audit_event(ex, True, mode, [], dry):
        raise ExportError("the audit's verdict event is not the one the exporter writes for this stream "
                          "(it was edited)")
    got = evs[:-1]
    for i, (g, w) in enumerate(zip(got, want), 1):
        if g != w:
            rid = (w.get("unmapped") or {}).get("varek", {}).get("report_id") or w["metadata"]["uid"]
            raise ExportError(f"event {i} is not the one the exporter writes from its record ({rid}): "
                              f"it was edited, or events were removed or reordered")
    if len(got) != len(want):
        raise ExportError(f"{len(got)} events where the stream gives {len(want)}: events were "
                          f"{'removed' if len(got) < len(want) else 'added'}")
    print(f"varek_ocsf: {len(got)} events are the stream's ({len(recs)} records, chain intact)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Export a VAREK verdict stream as OCSF 1.9.0 events "
                                             "(OCSF is an LF Projects series; VAREK is not affiliated with it).")
    ap.add_argument("--log", help="the verdict stream (batch, --verify)")
    ap.add_argument("--follow", metavar="STREAM", help="tail a live stream")
    ap.add_argument("--verify", metavar="EVENTS", help="check EVENTS against --log")
    ap.add_argument("--policy", required=True, help="the policy file the run used")
    ap.add_argument("--checker", help="tools/vdp_cert_check (for the audit)")
    ap.add_argument("--pubkey")
    ap.add_argument("--anchor")
    ap.add_argument("--allow-incomplete", action="store_true")
    ap.add_argument("--device", default=os.uname().nodename, help="the host's name in each event's device")
    ap.add_argument("--idle", type=float, default=0.0, help="--follow: seconds without a new record before "
                                                            "the run is taken to have ended early (default 0: "
                                                            "wait for run_end; an agent may be quiet for long)")
    ap.add_argument("--output", "-o")
    args = ap.parse_args(argv)
    try:
        if not args.checker:
            ap.error("exporting and --verify need --checker (the stream is audited)")
        if args.verify:
            if not args.log:
                ap.error("--verify needs --log")
            return cmd_verify(args)
        if args.follow:
            return cmd_follow(args)
        if not args.log:
            ap.error("give --log, --follow or --verify")
        return cmd_batch(args)
    except (ExportError, cdx.StreamError) as e:
        print(f"varek_ocsf: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
