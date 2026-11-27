# SPDX-License-Identifier: MIT
"""v1.43 step 2 (docs/security/v1.39-security-operations.md, section 6, G6):
Google SecOps' content in integrations/secops, the four YARA-L rules and the
dashboard, reads only what the export (tools/varek_secops.py) writes. Every
UDM field and additional key a rule or a panel reads is one the export
writes, every value a rule compares with is one it writes, and each rule's
conditions, evaluated here on the export's own UDM events, catch the events
it is for and no others. The YARA-L syntax itself is checked in Google's
development instance at the ship gate (integrations/secops/README.md)."""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_varek_ocsf_v142 as v142  # noqa: E402
import varek_ocsf as ocsf  # noqa: E402
import varek_secops as so  # noqa: E402

SECOPS = os.path.join(HERE, "integrations", "secops")
RULES = os.path.join(SECOPS, "rules")
NAMES = ("varek_action_refused", "varek_audit_failed", "varek_dry_run_let_through", "varek_approval_timeout")
REF = re.compile(r'\$e\.([a-z_]+(?:\.[a-z_]+)*)(?:\["([a-z_]+)"\])?')


def rule_text(name):
    return open(os.path.join(RULES, name + ".yaral")).read()


def sections(text):
    """a rule's sections, by name, as their lines (comments out)"""
    body = "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("//"))
    out, cur = {}, None
    for ln in body.splitlines():
        m = re.match(r"^\s*(meta|events|match|outcome|condition|order|limit):\s*$", ln)
        if m:
            cur = m.group(1)
            out[cur] = []
        elif cur and ln.strip() and ln.strip() != "}":
            out[cur].append(ln.strip())
    return out


def dashboard():
    return json.load(open(os.path.join(SECOPS, "varek-dashboard.json")))


def panels():
    return [(c["displayName"], c["query"]) for c in dashboard()["dashboard"]["charts"]]


def filters(query):
    """a panel's lines before its first section: its event conditions"""
    out = []
    for ln in query.splitlines():
        if re.match(r"^\s*(match|outcome|order|limit):", ln):
            break
        out.append(ln.strip())
    return out


# --- the export's own UDM events, for every kind the content reads ---------

def samples(tmp_path):
    pol = tmp_path / "p.txt"
    pol.write_text(v142.POLICY)
    ex = ocsf.Exporter(str(pol), "node-1")
    evs = []
    for r in v142.records():                            # v1.42's decisions, holds, deferrals and their ends
        evs += ex.feed(r)
    evs += ex.finish()
    dry = json.loads(json.dumps(next(e for e in evs if e["unmapped"]["varek"].get("decision_final") == "DENY")))
    dry["unmapped"]["varek"]["mode"] = "dry_run"        # a dry run's let-through
    net = json.loads(json.dumps(dry))
    net["unmapped"]["varek"].pop("mode")
    net.update(class_uid=4001, class_name="Network Activity", activity_id=1, type_uid=400101,
               type_name="Network Activity: Open", dst_endpoint={"hostname": "api.example.test", "port": 443})
    net.pop("file", None)
    failed = ocsf.audit_event(ex, False, "signed", ["PROBLEM: record 7: the hash chain breaks"])
    passed = ocsf.audit_event(ex, True, "signed", [])
    for a in (failed, passed):
        assert a["metadata"]["correlation_uid"] == v142.RUN and a.get("device")
    return [so.udm(e) for e in evs + [dry, net, failed, passed]]


def flat(u, prefix=""):
    """the dotted paths a UDM event has (lists are transparent: repeated fields)"""
    if isinstance(u, dict):
        for k, v in u.items():
            yield from flat(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(u, list):
        for v in u:
            yield from flat(v, prefix)
    else:
        yield prefix, u


def values(u, path, key=None):
    """the values a YARA-L path reads on one UDM event"""
    if path == "additional.fields":
        v = (u.get("additional") or {}).get(key)
        return [] if v is None else [v]
    path = re.sub(r"\.seconds$", "", path)               # a timestamp's seconds
    return [v for p, v in flat(u) if p == path]


def holds(line, u):
    """one condition line of a rule's events section, on one UDM event"""
    line = line.strip()
    if line.startswith("(") and line.endswith(")"):
        return any(holds(part, u) for part in line[1:-1].split(" or "))
    if line.startswith("$") and not line.startswith("$e."):
        return True                                     # a placeholder: a value to group or show
    m = re.match(r'^\$e\.([a-z_.]+)(?:\["([a-z_]+)"\])?\s*(!=|=)\s*"([^"]*)"$', line)
    assert m, f"a condition this test can't read: {line}"
    vals = values(u, m.group(1), m.group(2))
    return (m.group(4) in vals) if m.group(3) == "=" else (m.group(4) not in vals)


def matches(conditions, events):
    return [u for u in events if all(holds(c, u) for c in conditions)]


# --- the tests -------------------------------------------------------------

def test_each_rule_has_its_sections():
    for name in NAMES:
        t = rule_text(name)
        assert re.search(r"^rule " + name + r" \{$", t, re.M), name
        assert t.count("{") == t.count("}"), name
        s = sections(t)
        assert {"meta", "events", "outcome", "condition"} <= set(s), (name, set(s))
        meta = dict(re.match(r'^(\w+) = "(.*)"$', ln).groups() for ln in s["meta"])
        assert {"author", "description", "severity"} <= set(meta), name
        assert meta["severity"] in ("Informational", "Low", "Medium", "High", "Critical"), name
        assert s["condition"] == ["$e"], name
        assert '$e.metadata.vendor_name = "Sober Agentic Infrastructure"' in s["events"], name
        assert '$e.metadata.product_name = "VAREK"' in s["events"], name
        if "match" in s:                                 # grouped by run, within a window
            assert re.match(r"^\$run(, \$\w+)* over \d+[mhd]$", s["match"][0]), (name, s["match"])
            for var in re.findall(r"\$(\w+)", s["match"][0]):
                assert any(ln.startswith(f"${var} = ") for ln in s["events"]), (name, var)
    sev = {n: dict(re.match(r'^(\w+) = "(.*)"$', ln).groups() for ln in sections(rule_text(n))["meta"])["severity"]
           for n in NAMES}
    assert sev == {"varek_action_refused": "Medium", "varek_audit_failed": "High",      # as Sentinel's rules
                   "varek_dry_run_let_through": "Informational", "varek_approval_timeout": "Medium"}


def test_the_content_reads_only_what_the_export_writes(tmp_path):
    events = samples(tmp_path)
    paths = {p for u in events for p, _ in flat(u) if not p.startswith("additional.")}
    keys = {k for u in events for k in (u.get("additional") or {})}
    texts = [(n, rule_text(n)) for n in NAMES] + panels()
    assert len(texts) == 12                              # 4 rules, the dashboard's 8 panels
    for name, text in texts:
        refs = REF.findall(text)
        assert refs, name
        for path, key in refs:
            if path == "additional.fields":
                assert key in keys, (name, key)
            else:
                assert re.sub(r"\.seconds$", "", path) in paths, (name, path)
        # each value compared with is one the export writes there
        for path, key, op, lit in re.findall(r'\$e\.([a-z_.]+)(?:\["([a-z_]+)"\])?\s*(!=|=)\s*"([^"]*)"', text):
            if op == "=":
                assert any(lit in values(u, path, key or None) for u in events), (name, path, key, lit)


def test_each_rule_catches_what_it_is_for_and_nothing_else(tmp_path):
    events = samples(tmp_path)
    got = {n: matches(sections(rule_text(n))["events"], events) for n in NAMES}
    a = lambda u, k: (u.get("additional") or {}).get(k)  # noqa: E731
    refused = [u for u in events if "BLOCK" in values(u, "security_result.action")]
    assert refused and got["varek_action_refused"] == refused
    assert all(a(u, "varek_mode") != "dry_run" for u in got["varek_action_refused"])
    assert any(values(u, "target.hostname") for u in refused)        # a network refusal among them
    assert [a(u, "varek_audit_passed") for u in got["varek_audit_failed"]] == ["false"]
    assert json.loads(a(got["varek_audit_failed"][0], "varek_audit_problems")) == \
        ["PROBLEM: record 7: the hash chain breaks"]
    assert a(got["varek_audit_failed"][0], "varek_audit_mode") == "signed"
    dry = got["varek_dry_run_let_through"]
    assert len(dry) == 1 and values(dry[0], "security_result.action") == ["ALLOW"]
    assert values(dry[0], "security_result.severity") == ["INFORMATIONAL"]
    late = got["varek_approval_timeout"]
    assert sorted(a(u, "varek_event") for u in late) == ["defer_end", "step_up_end"]
    assert {a(u, "varek_ending") for u in late} == {"timeout"}
    ends = [u for u in events if a(u, "varek_event") in ("step_up_end", "defer_end")]
    endings = {"approved", "denied", "abandoned", "resolved", "escalated", "timeout"}
    assert {a(u, "varek_ending") for u in ends} >= endings              # the others aren't caught
    # what each rule groups and shows on its events is there
    for n in NAMES:
        s = sections(rule_text(n))
        for ln in s["events"]:
            m = re.match(r'^\$\w+ = \$e\.([a-z_.]+)(?:\["([a-z_]+)"\])?$', ln)
            if m:
                for u in got[n]:
                    assert values(u, m.group(1), m.group(2)), (n, ln)


def test_the_dashboards_panels_draw_from_the_same_events(tmp_path):
    events = samples(tmp_path)
    d = dashboard()
    assert "_comment" in d and "ship gate" in d["_comment"]            # marked as a draft
    names = [n for n, _ in panels()]
    assert names == ["Refusals by policy line", "Refusals by agent", "Refusals by run", "Refusals over time",
                     "The latest refusals", "Dry runs: let through, not enforced", "Failed audits",
                     "Approvals nobody gave in time"]
    for n, q in panels():
        assert "match:" in q and "outcome:" in q, n
        conds = [c for c in filters(q) if c]
        assert matches(conds, events), n                  # each panel draws something from a run
    refused = {n: matches(filters(q), events) for n, q in panels() if "Refusals" in n or "refusals" in n}
    assert len({len(v) for v in refused.values()}) == 1   # the refusal panels count the same events


def test_make_install_ships_the_content():
    mk = open(os.path.join(HERE, "Makefile")).read()
    assert "integrations/secops/rules/*.yaral" in mk and "integrations/secops/varek-dashboard.json" in mk
    assert "integrations/secops/README.md" in mk
