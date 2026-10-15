# SPDX-License-Identifier: MIT
"""
varek_suggest: `varek policy suggest` (v1.29, docs/security/v1.29-varek-run.md,
section 4, D8).

From one run's verdict stream (a dry run's, or an enforcing run's refusals),
a draft policy: the run's policy as it was, then a block of suggested rules,
one for each object the policy refused, grouped by kind, each commented with
how many times, by which process and sub-agent, first and last. It installs
nothing.

  - Exact (D8): a rule names the object seen, in the narrowest form that
    admits it: `readonly` for reads, the exact name for writes and changes, a
    launch by the name used, a connect by the name the agent used where the
    record has one (else the address), a request by its object. Where five
    or more objects under one directory were refused alike, a directory rule
    is offered, commented out.
  - Never an active rule (written commented out, with the reason): an object
    a deny rule of the policy refuses; a credential store or key; anything
    in another user's home; a write under /etc/, /usr/, /boot/ or a directory
    on the system's PATH; a launch of sudo, su, doas or pkexec, or of any
    program at a path the agent wrote in the run (a copy of a shell under
    another name is a shell). The
    protected objects and the Warden's other refusals (not the policy's) are
    never suggested; a system call outside the allowlist is a note, not a rule.
  - Every active rule is checked: the draft is linted, and each refused call
    is decided again under it by the decision procedure, which must allow it
    by that rule; one that does not is commented out. `suggest` never removes
    or changes a rule of the policy: the suggestions follow it, so a deny
    rule above still wins.
  - The output is deterministic for a given stream.
"""

import datetime as _dt
import os
import re
import subprocess
import tempfile

POLICY_RULES = ("policy_match", "default_deny_unknown", "fragment_escape_flags", "fragment_escape_length",
                "certificate_refused", "exec_not_in_ruleset", "exec_no_landlock", "max_body", "rename_to_refused",
                "rename_from_refused")
READ_ACTIONS = ("file.stat", "file.access", "file.readlink", "file.chdir")
CHANGE_ACTIONS = ("file.unlink", "file.rmdir", "file.mkdir", "file.rename_from", "file.rename_to",
                  "file.chmod", "file.utime", "file.truncate")
SECTIONS = (("read", "files and directories read"), ("write", "files written, made, removed or changed"),
            ("exec", "programs launched"), ("host", "hosts connected to"), ("request", "requests sent"),
            ("mcp", "MCP calls"))                                              # v1.31
SUBAGENT_TAG = re.compile(r"subagent:([a-z][a-z0-9_]{0,31})#([1-9][0-9]{0,9})")


def confined_subjects(vdp, path):
    """v1.31: {name: subject number} of the policy's confined subjects (vdp_check identity)"""
    r = subprocess.run([vdp, path, "identity"], capture_output=True, text=True)
    out = {}
    for ln in r.stdout.splitlines():
        f = ln.split(" ")
        if len(f) == 6 and f[0] == "confined" and f[1].isdigit():
            out[f[2]] = int(f[1])
    return out


def subject_of(rec, confined):
    """v1.31: the subject a record was decided as (the innermost confined
    sub-agent in its chain), as varek_audit.py's expected_subject"""
    k = 0
    for t in rec.get("obo") if isinstance(rec.get("obo"), list) else []:
        m = SUBAGENT_TAG.fullmatch(t) if isinstance(t, str) else None
        if m and m.group(1) in confined:
            k = confined[m.group(1)]
    return k
CREDENTIAL_RX = re.compile(
    r"/\.(ssh|aws|azure|kube|gnupg|password-store)/|/\.config/gcloud/|/\.docker/config\.json$|"
    r"/\.(netrc|git-credentials|pgpass|my\.cnf|npmrc|pypirc|vault-token|boto|s3cfg)$|"
    r"/\.config/(gh/hosts\.yml$|hub($|/)|rclone/|op/|doctl/)|/\.terraform\.d/credentials\.tfrc\.json$|"
    r"/\.cargo/credentials(\.toml)?$|/\.gem/credentials$|\.[pP][eE][mM]($|[.~])|\.[kK][eE][yY]($|[.~])|"
    r"/\.[eE][nN][vV]([rR][cC])?($|[.~])|/[iI][dD]_([rR][sS][aA]|[dD][sS][aA]|[eE][cC][dD][sS][aA]|[eE][dD]25519)[^/]*$")
SYSTEM_WRITE = ("/etc/", "/usr/", "/boot/", "/bin/", "/sbin/", "/lib/", "/lib64/")
PRIVILEGED = ("sudo", "su", "doas", "pkexec")
O_ACCMODE, O_CREAT, O_TRUNC = 3, 0x40, 0x200


def _syscall_names(arch="x86_64"):
    """the system calls' names by number, for the architecture the run was
    recorded on (run_start's arch, v1.30; x86_64 before it)"""
    if arch == "aarch64":
        # arm64's are the generic table: numbers, and names defined by another
        # (__NR_fstat __NR3264_fstat), the 64-bit one first
        try:
            with open("/usr/include/asm-generic/unistd.h") as fh:
                t = fh.read()
        except OSError:
            return {}
        n3264 = {m.group(1): int(m.group(2)) for m in re.finditer(r"#define __NR3264_(\w+)\s+(\d+)", t)}
        names = {}
        for m in re.finditer(r"#define __NR_(\w+)\s+(\d+|__NR3264_\w+)\b", t):
            v = m.group(2)
            n = int(v) if v.isdigit() else n3264.get(v[len("__NR3264_"):])
            if n is not None and m.group(1) != "syscalls":
                names.setdefault(n, m.group(1))
        return names
    for p in ("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", "/usr/include/asm/unistd_64.h"):
        try:
            with open(p) as fh:
                return {int(m.group(2)): m.group(1) for m in
                        re.finditer(r"#define __NR_(\w+)\s+(\d+)", fh.read())}
        except OSError:
            continue
    return {}


def _when(ns):
    try:
        return _dt.datetime.fromtimestamp(int(ns) / 1e9, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError):
        return "?"


def _writable(s):
    """a constant a policy line can hold (no whitespace, '#' or control bytes)"""
    return bool(s) and not re.search(r"[\s#\x00-\x1f\x7f]", s)


def _name_of(rec, asked):
    """a connect's destination as the agent named it: a name candidate the
    agent asked for in the run (a dns_question), else the address it was
    decided on (a name the address merely belongs to is not how the agent
    reached it)"""
    cands = rec.get("candidates")
    if isinstance(cands, list):
        for c in cands:
            if isinstance(c, str) and not c.startswith("[") and ":" in c and c.rsplit(":", 1)[0] in asked:
                return c
    r = rec.get("resolved") or rec.get("target")
    return r if isinstance(r, str) else ""


def collect(records, keep=None):
    """(run_start, the run's refusals the policy made, the notes) from records
    (v1.31: those keep(record) accepts: one subject's)"""
    rs, run = None, None
    items, notes = {}, {}
    written = set()
    sysnames = None
    asked = {r.get("name") for r in records if isinstance(r, dict) and r.get("event") == "dns_question"}
    for r in records:
        if not isinstance(r, dict):
            continue
        if r.get("event") == "run_start":
            if rs is None:
                rs, run = r, r.get("run")
            continue
        if run is None or r.get("run") != run:
            continue
        act = r.get("action")
        res = r.get("resolved") if isinstance(r.get("resolved"), str) and r.get("resolved") else r.get("target")
        try:
            fl = int(str(r.get("open_flags", "0x0")), 16)
        except ValueError:
            fl = 0
        # paths the agent wrote in this run (for the launch check)
        if r.get("decision_final") == "ALLOW" or r.get("enforced") is False:
            if act == "file.open" and (fl & O_ACCMODE or fl & (O_CREAT | O_TRUNC)) and isinstance(res, str):
                written.add(res)
            if act in CHANGE_ACTIONS and isinstance(res, str):
                written.add(res)
        if r.get("decision_final") != "DENY":
            continue
        if keep is not None and not keep(r):
            continue
        rule = r.get("rule")
        if rule == "syscall_not_admitted":
            if sysnames is None:
                sysnames = _syscall_names(rs.get("arch", "x86_64"))
            t = str(r.get("target", ""))
            n = int(t.split(":")[1]) if t.startswith("syscall:") and t.split(":")[1].isdigit() else -1
            key = ("syscall", n)
            nt = notes.setdefault(key, {"n": 0, "name": sysnames.get(n, "?")})
            nt["n"] += 1
            continue
        # a dry run's record of a call it let through carries what became of
        # it (a dialed connect: dialed_fd_injection); enforced:false says the
        # policy refused it
        if (rule not in POLICY_RULES and r.get("enforced") is not False) or not isinstance(res, str) or not res:
            continue
        if act == "file.open":
            kind = "write" if (fl & O_ACCMODE or fl & (O_CREAT | O_TRUNC)) else "read"
            subj, query = res, ("path", fl)
        elif act in READ_ACTIONS:
            kind, subj, query = "read", res, ("path", 0x10000 if act == "file.chdir" else 0)
        elif act in CHANGE_ACTIONS:
            kind, subj, query = "write", res, ("path", fl)
        elif act == "process.exec":
            kind, subj, query = "exec", res, ("exec", None)
        elif act in ("net.connect", "net.proxy"):
            subj = _name_of(r, asked) if act == "net.connect" else res
            if subj.startswith("unix:"):
                continue
            kind, query = "host", ("host", None)
        elif act == "net.request":
            kind, subj, query = "request", res, ("request", None)
        elif act == "net.mcp":                                                 # v1.31: the object decided
            if not isinstance(r.get("resolved"), str) or r["resolved"].count("#") < 2:
                continue
            kind, subj, query = "mcp", r["resolved"], ("mcp", None)
        else:
            continue
        key = (kind, subj)
        it = items.setdefault(key, {"kind": kind, "subj": subj, "n": 0, "pids": set(), "who": set(),
                                    "first": None, "last": None, "flags": set(), "queries": [],
                                    "deny_line": None, "action": set()})
        it["n"] += 1
        it["action"].add(act)
        if isinstance(r.get("agent_pid"), int):
            it["pids"].add(r["agent_pid"])
        obo = r.get("obo")
        if isinstance(obo, list) and obo and isinstance(obo[-1], str) and obo[-1].startswith("subagent:"):
            it["who"].add(obo[-1][len("subagent:"):])
        ts = r.get("timestamp_ns")
        if isinstance(ts, int):
            it["first"] = ts if it["first"] is None else min(it["first"], ts)
            it["last"] = ts if it["last"] is None else max(it["last"], ts)
        if query[0] == "path":
            it["flags"].add(query[1])
        it["queries"].append((query[0], query[1], res if act != "net.connect" else subj))
        if r.get("decision_raw") == "DENY" and isinstance(r.get("policy_line"), int) and r["policy_line"] > 0:
            it["deny_line"] = r["policy_line"]
    return rs, items, notes, written


def agent_home(rs):
    """the agent user's home, from run_start (the baseline's, or the user
    files were opened as), or None"""
    b = rs.get("baseline") if isinstance(rs, dict) else None
    if isinstance(b, dict) and isinstance(b.get("home"), str):
        return b["home"].rstrip("/")
    oa = rs.get("open_as") if isinstance(rs, dict) else None
    if isinstance(oa, dict) and isinstance(oa.get("uid"), int):
        try:
            import pwd
            return pwd.getpwuid(oa["uid"]).pw_dir.rstrip("/")
        except (KeyError, ImportError):
            return None
    return None


def _user_homes():
    """the homes of root and of the people with accounts (uid 1000 and up)"""
    try:
        import pwd
        return {p.pw_dir.rstrip("/") for p in pwd.getpwall()
                if (p.pw_uid == 0 or 1000 <= p.pw_uid < 65534) and p.pw_dir.rstrip("/") not in ("", "/")}
    except ImportError:
        return set()


def _under(s, d):
    return bool(d) and (s == d or s.startswith(d + "/"))


def why_not(it, home, written, cwd=None):
    """None, or why this suggestion is written commented out"""
    s, kind = it["subj"], it["kind"]
    if it["deny_line"]:
        return f"a deny rule of the policy (line {it['deny_line']}) refuses it; the policy's deny stays"
    if kind in ("read", "write", "exec") and CREDENTIAL_RX.search(s):
        return "a credential store or key"
    if kind in ("read", "write", "exec"):
        m = re.match(r"^(/home/[^/]+|/root)(/|$)", s)
        if m and m.group(1) != home:
            return "in another user's home"
        if any(_under(s, h) and h != home for h in _user_homes()):
            return "in another user's home"
        # v1.29 review: a list of credential stores is never complete, and
        # the baseline closes the user's home; what the agent read in a
        # hidden directory there is for the operator to open, by hand
        if home and _under(s, home) and not _under(s, cwd) and s[len(home) + 1:].startswith("."):
            return ("in a hidden directory of the user's home, where tools keep their settings and "
                    "tokens: read it, and remove the # if it holds none")
    if kind == "write" and any(s.startswith(p) or s == p.rstrip("/") for p in SYSTEM_WRITE):
        return "a write under a system directory"
    if kind == "exec":
        base = os.path.basename(s)
        if base in PRIVILEGED:
            return f"{base} runs programs as another user"
        if s in written:
            return "a program the agent wrote in this run"
    return None


def rule_text(it, for_name=None):
    """the rule for an item, or None when no policy line can hold it
    (v1.31: written for=NAME for a confined subject)"""
    t = _rule_text(it)
    return t if t is None or not for_name else f"{t} for={for_name}"


MCP_WORD_RX = re.compile(r"[\x21-\x7e]+")


def _rule_text(it):
    s, kind = it["subj"], it["kind"]
    if kind == "mcp":
        url, method, name = s.split("#", 2)
        # the name, as a glob: none of its metacharacters, nor a word an mcp rule reads as an option
        if not re.fullmatch(r"[A-Za-z0-9_./-]{1,128}", method) or \
                (name and (not MCP_WORD_RX.fullmatch(name) or any(c in name for c in "*?[]{}\\") or
                           re.match(r"(max_body|credential|header|for)=", name))):
            return None
        return f"allow mcp {url} {method}" + (f" {name}" if name else "")
    if kind == "request":
        parts = s.split(" ", 1)
        if len(parts) != 2 or not re.fullmatch(r"[A-Z]{1,20}", parts[0]) or not _writable(parts[1]):
            return None
        return f"allow request {parts[0]} {parts[1]}"
    if not _writable(s):
        return None
    if kind == "read":
        return f"allow path exact {s} readonly"
    if kind == "write":
        return f"allow path exact {s}"
    if kind == "exec":
        return f"allow exec {s}"
    return f"allow host {s}"


def _comment(it):
    bits = [f"{it['n']} time{'s' if it['n'] != 1 else ''}"]
    if it["pids"]:
        ps = sorted(it["pids"])
        bits.append("pid " + ",".join(str(p) for p in ps[:3]) + ("..." if len(ps) > 3 else ""))
    if it["who"]:
        bits.append("sub-agent " + ",".join(sorted(it["who"])))
    if it["kind"] == "write" and it["flags"]:
        bits.append("flags " + ",".join(f"0x{f:x}" for f in sorted(it["flags"])))
    bits.append(f"{_when(it['first'])}..{_when(it['last'])}")
    return "; ".join(bits)


def _header(rs, policy_path, policy_sha):
    run = rs.get("run", "?") if isinstance(rs, dict) else "?"
    mode = "dry run (not enforcing)" if isinstance(rs, dict) and rs.get("mode") == "dry_run" else "enforcing"
    return [
        "# DRAFT POLICY written by `varek policy suggest` from ONE run. It is not a reviewed policy:",
        "# it writes down what the agent did, not whether it should have done it. Read every",
        "# suggested rule (below the policy as it was) before installing it with `varek policy use`,",
        "# and check it with a dry run: `varek run --dry-run --policy FILE -- <agent>`.",
        f"# run {run}, {mode}; policy {policy_path} (sha256 {policy_sha})",
    ]


def _batch(vdp, path, queries, subj=0):
    """decide each (kind, flags, string) under the policy at path, as subject
    subj (v1.31): [(verdict, line)]"""
    lines = []
    for k, fl, s in queries:
        lines.append(f"{k} {'-' if fl is None else hex(fl)} {s.encode('utf-8', 'surrogateescape').hex() or '='}" +
                     (f" @{subj}" if subj else ""))
    r = subprocess.run([vdp, path, "batch"], input="\n".join(lines) + "\n", capture_output=True, text=True)
    out = []
    import json
    for ln in r.stdout.splitlines():
        try:
            j = json.loads(ln)
            out.append((j.get("verdict"), j.get("line")))
        except ValueError:
            out.append((None, None))
    while len(out) < len(queries):
        out.append((None, None))
    return out


def suggest(records, policy_text, policy_path, policy_sha, vdp, for_name=None):
    """The draft's text, and how many rules it suggests (active, commented).
    v1.31: for one subject: the agent's (for_name None), or the confined
    subject for_name's, each rule written for=NAME."""
    confined = confined_subjects(vdp, policy_path)
    if for_name is not None and for_name not in confined:
        raise ValueError(f"{for_name} is not an MCP server or confined sub-agent of the run's policy"
                         + (f" (it has: {', '.join(sorted(confined))})" if confined else " (it has none)"))
    want = confined[for_name] if for_name else 0
    others = {}
    for r in records:
        if isinstance(r, dict) and r.get("decision_final") == "DENY" and "action" in r:
            k = subject_of(r, confined)
            if k != want:
                others[k] = others.get(k, 0) + 1
    rs, items, notes, written = collect(records, keep=lambda r: subject_of(r, confined) == want)
    if rs is None:
        raise ValueError("the stream has no run_start")
    home = agent_home(rs)
    b = rs.get("baseline") if isinstance(rs, dict) else None
    cwd = b["cwd"].rstrip("/") if isinstance(b, dict) and isinstance(b.get("cwd"), str) else None
    head = _header(rs, policy_path, policy_sha)
    body = []
    for line in policy_text.splitlines():
        if line.startswith("#@ "):               # a baseline's header: no longer this file's
            body.append("# (made from) " + line[3:])
        else:
            body.append(line)
    out = head + [""] + body
    if out[-1] != "":
        out.append("")
    run = rs.get("run", "?")
    out.append(f"# ---- suggested by varek policy suggest from run {run} ----")
    rules = []                                    # (index in out, item, rule) of active rules
    n_active = n_commented = 0
    for kind, title in SECTIONS:
        its = sorted((it for it in items.values() if it["kind"] == kind), key=lambda i: i["subj"])
        if not its:
            continue
        out.append(f"# {title}")
        for it in its:
            rt = rule_text(it, for_name)
            if rt is None:
                out.append(f"# (not written: {it['subj'][:200]!r} cannot be a policy constant) # {_comment(it)}")
                n_commented += 1
                continue
            why = why_not(it, home, written, cwd)
            if why:
                out.append(f"# {rt}    # NOT SUGGESTED: {why}; {_comment(it)}")
                n_commented += 1
                continue
            rules.append((len(out), it, rt))
            out.append(f"{rt}    # {_comment(it)}")
            n_active += 1
        # a directory, where five or more objects under it were refused alike
        if kind in ("read", "write"):
            by_dir = {}
            for it in its:
                if why_not(it, home, written, cwd) is None and _writable(it["subj"]):
                    by_dir.setdefault(os.path.dirname(it["subj"]), []).append(it)
            for d in sorted(by_dir):
                if len(by_dir[d]) >= 5 and d != "/":
                    out.append(f"# allow path {d}/{' readonly' if kind == 'read' else ''}"
                               f"{' for=' + for_name if for_name else ''}    "
                               f"# ALTERNATIVE (not active): {len(by_dir[d])} objects under {d}/ were refused; "
                               f"a directory rule grants what nobody saw the agent need")
    if notes:
        out.append("# notes: not policy rules")
        for (k, n), nt in sorted(notes.items(), key=lambda x: (x[0][0], x[0][1])):
            out.append(f"# system call {n} ({nt['name']}) is outside the Warden's system-call allowlist: "
                       f"{nt['n']} time{'s' if nt['n'] != 1 else ''}; no policy rule admits it")
    names = {k: n for n, k in confined.items()}
    for k, n in sorted(others.items()):                                        # v1.31
        who = f"{names.get(k, '?')}" if k else "the agent"
        out.append(f"# ({n} refusal(s) were for {who}, not suggested here: `varek policy suggest" +
                   (f" --for {names.get(k, '?')}`)" if k else "` without --for)"))
    if not items:
        out.append("# (the policy refused nothing in this run" + (f" for {for_name})" if for_name else ")"))
    out.append("")
    # check: lint, and every refused call decided again under the draft
    with tempfile.NamedTemporaryFile("w", suffix=".policy.txt", delete=False) as fh:
        fh.write("\n".join(out))
        tmp = fh.name
    try:
        if rules:
            qs, owners = [], []
            for idx, it, rt in rules:
                for q in it["queries"]:
                    qs.append(q)
                    owners.append(idx)
            got = _batch(vdp, tmp, qs, want)
            bad = set()
            for (verdict, line), idx in zip(got, owners):
                if verdict != "SATISFIED" or line != idx + 1:
                    bad.add(idx)
            for idx in sorted(bad):
                out[idx] = f"# {out[idx]}    # NOT ACTIVE: under the draft this rule does not decide what was refused"
                n_active -= 1
                n_commented += 1
            if bad:
                with open(tmp, "w") as fh:
                    fh.write("\n".join(out))
        lint = subprocess.run([vdp, tmp, "lint"], capture_output=True, text=True)
        if lint.returncode != 0:
            raise RuntimeError("the draft does not lint (a bug in varek policy suggest):\n" +
                               (lint.stdout + lint.stderr).strip())
    finally:
        os.unlink(tmp)
    return "\n".join(out), n_active, n_commented
