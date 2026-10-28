# SPDX-License-Identifier: MIT
"""
varek_plan.py — what VAREK's plan adapters share (v1.35 step 6,
docs/security/v1.35-frameworks.md): writing a plan in the plan format
(v1_6/plan_parser.h, plan 1.35), the steps every agent's runtime needs, an
MCP server's steps, and the hosts of the model providers frameworks name.

An adapter loads it by its path, beside the adapter (not by putting the
adapter's directory on sys.path, where an adapter's name could hide the
framework's own package: langgraph_plan.py, not langgraph.py).

Python's standard library only.
"""

import functools
import hashlib
import json
import os
import re
import sys
import types
from urllib.parse import urlsplit

VERSION = "1.36.0"
LABEL = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
HOSTPORT = re.compile(r"[A-Za-z0-9.-]{1,253}:[0-9]{1,5}")
MAX_STEPS = 256
# the methods an MCP client sends before its first tool call (each decided by
# the policy as a call, v1.31): the handshake, and the list of tools
MCP_OPENING = ("initialize", "notifications/initialized", "tools/list")


class AdapterError(Exception):
    pass


def warn(adapter, msg):
    print(f"{adapter}: {msg}", file=sys.stderr)


def read_bytes(path, what):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        raise AdapterError(f"no {what} at {path}")
    except OSError as e:
        raise AdapterError(f"cannot read {what} {path}: {e.strerror}")


def read_json(path, what, required=True):
    """(data, SHA-256), or (None, None) for a missing file not required"""
    if not required and not os.path.exists(path):
        return None, None
    data = read_bytes(path, what)
    try:
        return json.loads(data.decode("utf-8")), hashlib.sha256(data).hexdigest()
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise AdapterError(f"{what} {path} is not JSON: {e}")


def field(v):
    """a field's value, bare where it can be, else quoted (plan_parser.h)"""
    v = str(v)
    if v and re.fullmatch(r'[^\s"\\\x00-\x1f\x7f\x85\u2028\u2029]+', v):
        return v
    out = '"'
    for ch in v:
        o = ord(ch)
        if ch in '"\\':
            out += "\\" + ch
        elif ch == "\n":
            out += "\\n"
        elif ch == "\t":
            out += "\\t"
        elif o < 0x20 or o == 0x7f:
            if o == 0:
                raise AdapterError("a field holds a NUL byte")
            out += f"\\x{o:02x}"
        elif o in (0x85, 0x2028, 0x2029):    # a line break to some readers: its UTF-8 bytes, escaped
            out += "".join(f"\\x{b:02x}" for b in ch.encode())
        else:
            out += ch
    return out + '"'


class Plan:
    """a plan being written: comments, then `plan 1.35`, then its steps"""

    def __init__(self):
        self.lines, self.labels, self.n, self.started, self.seen = [], set(), 0, False, set()

    def label(self, *parts):
        base = re.sub(r"[^A-Za-z0-9_-]", "_", "_".join(str(p) for p in parts if p)).strip("-") or "step"
        if not re.match(r"[A-Za-z_]", base):
            base = "s_" + base
        base = base[:56]
        lab, k = base, 2
        while lab in self.labels:
            lab, k = f"{base}_{k}", k + 1
        self.labels.add(lab)
        return lab

    def comment(self, text=""):
        """a comment line: what a framework's file or object gave (a name, a description) can hold a
        newline or a control character, which would end the comment and start a line of the plan's
        own; each is written as '?'"""
        text = re.sub(r"[\x00-\x1f\x7f\x85\u2028\u2029]", "?", str(text))
        self.lines.append(("# " + text).rstrip())

    def start(self):
        if not self.started:
            self.lines.append("plan 1.35")
            self.started = True

    def step(self, kind, target, *labelparts, **fields):
        """one step; the same step twice (kind, target and fields) is written once"""
        self.start()
        if not target or re.search(r"\s", target) or len(target) > 4095:
            raise AdapterError(f"a {kind} step's target {target!r} is not one token of at most 4095 bytes")
        if kind in ("file_open", "process_exec") and not target.startswith("/"):
            raise AdapterError(f"a {kind} step's target {target!r} is not an absolute path")
        key = (kind, target, tuple(sorted(fields.items())))
        if key in self.seen:
            return
        if self.n == MAX_STEPS:
            raise AdapterError(f"the plan would have more than {MAX_STEPS} steps (the plan format's limit)")
        self.seen.add(key)
        out = f"action {self.label(*labelparts)} {kind} {target}"
        for k, v in fields.items():
            out += f" {k}={field(v)}"
        self.lines.append(out)
        self.n += 1

    def text(self):
        self.start()
        return "\n".join(self.lines) + "\n"


def header(P, adapter, source, what, notes=()):
    main = os.path.basename(getattr(sys.modules.get("__main__"), "__file__", "") or f"{adapter}.py")
    P.comment(f"Written by `varek plan generate --from {adapter}` (VAREK {VERSION}, adapters/{main})")
    P.comment(f"from {source}")
    P.comment(what)
    P.comment("Each step names something the agent is given. Held to this plan (varek run --hold-to-plan,")
    P.comment("or a policy's `require plan`), the run is refused a call the policy allows that no step")
    P.comment("covers.")
    for n in notes:
        P.comment(n)
    P.start()


def python_env_dirs():
    """step 10: the directories of this Python's environment outside the
    system's (a virtual environment, a Python of its own): a code adapter
    runs in the agent's own Python (varek plan generate --python), so these
    are where the agent's packages are read from"""
    out = []
    for d in (sys.prefix, sys.base_prefix, os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix)):
        d = os.path.normpath(d)
        if d in ("/", "/usr") or d.startswith(("/usr/", "/lib", "/etc/")):
            continue
        if d not in out:
            out.append(d)
    return out


def runtime_steps(P, app_dir=None, home=None, extra=(), python_env=False):
    """the language runtime's own reads (the system read-only, /proc/self/,
    /dev/null and /dev/urandom, /tmp/), its code read-only, and the files and
    directories it is configured with (extra: (path, read_only)); with
    python_env, the agent's Python environment read-only (python_env_dirs)"""
    P.comment()
    P.comment("the language runtime's own reads, and the agent's code")
    for lab, path, f in (("sys_usr", "/usr/", "read"), ("sys_lib", "/lib/", "read"), ("sys_lib64", "/lib64/", "read"),
                         ("sys_etc", "/etc/", "read"), ("proc_self", "/proc/self/", "read"),
                         ("dev_null", "/dev/null", None), ("dev_urandom", "/dev/urandom", "read"),
                         ("tmp", "/tmp/", None),
                         # step 10: what a runtime reads of the machine as it loads (the CPU count, the
                         # control group's limits, OpenSSL's FIPS switch): a held run is refused the rest
                         ("proc_stat", "/proc/stat", "read"), ("proc_cpuinfo", "/proc/cpuinfo", "read"),
                         ("proc_meminfo", "/proc/meminfo", "read"),
                         ("fips", "/proc/sys/crypto/fips_enabled", "read"),
                         ("sys_cpu", "/sys/devices/system/cpu/", "read"), ("cgroup", "/sys/fs/cgroup/", "read")):
        P.step("file_open", path, lab, **({"open": f} if f else {}))
    if app_dir:
        if not str(app_dir).startswith("/"):     # step 9 (review): where the agent runs, not relative to here
            raise AdapterError(f"--app-dir {app_dir!r}: an absolute path (the agent's code directory where it runs)")
        app_dir = os.path.normpath(app_dir)
        P.step("file_open", "/" if app_dir == "/" else app_dir + "/", "app", open="read")
    if python_env:
        for d in python_env_dirs():
            P.step("file_open", d + "/", "python_env", open="read")
    for path, ro in extra:
        P.step("file_open", path, "file", os.path.basename(path.rstrip("/")), **({"open": "read"} if ro else {}))


def check_url(url, what):
    """an MCP server's URL, as the Warden decides MCP calls over HTTP (v1.31)"""
    u = urlsplit(url) if isinstance(url, str) else None
    if not u or u.scheme not in ("http", "https") or not u.hostname or u.query or u.fragment:
        raise AdapterError(f"{what}'s URL {url!r} is not an http:// or https:// URL without a query")
    return url


def mcp_server_steps(P, url, label, tools=None, why_any=None):
    """an MCP server over HTTP: the opening methods, then tools/call of each
    tool (names), or one step naming no tool, which covers every tool of
    the server, with why_any said in the plan"""
    check_url(url, f"MCP server {label}")
    for m in MCP_OPENING:
        P.step("mcp_call", url, "mcp", label, m.split("/")[-1], method=m)
    if tools is None:
        P.comment(f"  {label}: {why_any or 'its tools are listed by the live server'}, so the step for its")
        P.comment("  tools names none: it covers every tool of the server")
        P.step("mcp_call", url, "mcp", label, "tools", method="tools/call")
    else:
        names = tool_names(tools)
        if len(names) < len(list(tools)):      # step 9 (review): never a step naming "" (or no tool)
            P.comment(f"  {label}: a tool with no name, or a name that is not text, is left out")
        if not names:
            P.comment(f"  {label}: no tool named, so no tools/call step")
        for t in names:
            P.step("mcp_call", url, "mcp", label, t, method="tools/call", name=t)


def tool_names(xs):
    """the tool names a framework's list gives that a step can name: text, not
    empty, at most 4096 bytes (the plan format's field), in order, once each"""
    return list(dict.fromkeys(x for x in xs or () if isinstance(x, str) and x.strip() and
                              len(x.encode("utf-8", "surrogateescape")) <= 4096))


def find_program(prog, path_env=None):
    """a program on a PATH, by its file's mode, as the launch would find it
    (not by access(X_OK): under the Warden the adapter may launch nothing
    after itself, so access(X_OK) fails for every other program)"""
    if os.path.isabs(prog):
        return prog
    for d in (path_env or os.defpath).split(os.pathsep):
        p = os.path.join(d or ".", prog)
        try:
            st = os.stat(p)
        except OSError:
            continue
        if not os.path.isdir(p) and st.st_mode & 0o111:
            return p
    return None


def stdio_server_step(P, name, command, path_env=None):
    """an MCP server the agent launches (stdio): a sub-agent step (D4), its
    program resolved as the launch would be; its calls are not decided
    (v1.31 decides MCP calls over HTTP)"""
    if not isinstance(command, str) or not command.strip():      # step 9 (review)
        raise AdapterError(f"MCP server {name}'s command {command!r} is not a program's name")
    prog = find_program(command, path_env)
    P.comment(f"  {name}: a server the agent launches ({command}); its calls over stdio are not decided,")
    P.comment("  its launch is, as the sub-agent the policy names it (`mcp server` or subagent=)")
    if prog:
        P.step("subagent", re.sub(r"[^a-z0-9_]", "_", name.lower())[:32] or "server", "subagent", name,
               exec=os.path.realpath(prog))
    else:
        P.step("subagent", re.sub(r"[^a-z0-9_]", "_", name.lower())[:32] or "server", "subagent", name)


def host_steps(P, hosts):
    """net_connect steps: (label, host:port, why)"""
    if not hosts:
        return
    P.comment()
    P.comment("the hosts the agent reaches")
    for lab, hp, why in hosts:
        if not isinstance(hp, str) or not HOSTPORT.fullmatch(hp):
            raise AdapterError(f"the host {hp!r} is not HOST:PORT")
        P.comment(f"  {hp}: {why}")
        P.step("net_connect", hp, lab)


def hostport_of_url(url, default_port=443):
    """HOST:PORT of a URL, or None (step 9, review: None too for a URL that
    is not text or whose port is not a port)"""
    try:
        u = urlsplit(url)
        port = u.port
    except (TypeError, ValueError, AttributeError):
        return None
    if not u.hostname:
        return None
    return f"{u.hostname}:{port or (443 if u.scheme == 'https' else 80 if u.scheme == 'http' else default_port)}"


# The model providers' hosts, by the name a framework gives the provider or
# its client's class (each the provider's documented API host)
MODEL_HOSTS = {
    "openai": "api.openai.com:443",
    "anthropic": "api.anthropic.com:443",
    "google": "generativelanguage.googleapis.com:443",
    "gemini": "generativelanguage.googleapis.com:443",
    "mistral": "api.mistral.ai:443",
    "mistralai": "api.mistral.ai:443",
    "groq": "api.groq.com:443",
    "cohere": "api.cohere.com:443",
    "deepseek": "api.deepseek.com:443",
    "xai": "api.x.ai:443",
    "together": "api.together.xyz:443",
    "fireworks": "api.fireworks.ai:443",
    "perplexity": "api.perplexity.ai:443",
}


def bedrock_host(region):
    return f"bedrock-runtime.{region}.amazonaws.com:443" if region and re.fullmatch(r"[a-z]{2}(-gov)?-[a-z]+-[0-9]", region) else None


def claim_stdout():
    """for an adapter that imports the agent's code: the plan's standard
    output kept apart, and what the agent's code prints (Python's or a C
    library's, on file descriptor 1) sent to standard error instead"""
    keep = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    return os.fdopen(keep, "w")


# --- the walk over an imported agent's objects (the code-importing adapters) ---

WALK_LIMIT = 50000


def mro_names(obj):
    try:
        return {c.__name__ for c in type(obj).__mro__}
    except Exception:
        return set()


def _cell_ok(c):
    try:
        c.cell_contents
        return True
    except ValueError:
        return False


def code_names(code, depth=0):
    """the global names a code object and the functions defined in it use"""
    names = set(code.co_names)
    if depth < 8:
        for c in code.co_consts:
            if isinstance(c, types.CodeType):
                names |= code_names(c, depth + 1)
    return names


def children(obj):
    """what an object holds: containers' items, functions' closures, defaults
    and the globals they use, partials' arguments, instances' attributes"""
    if isinstance(obj, dict):
        return list(obj.values())
    if isinstance(obj, (list, tuple, set, frozenset)):
        return list(obj)
    if isinstance(obj, types.FunctionType):
        out = [c.cell_contents for c in (obj.__closure__ or ()) if _cell_ok(c)]
        out += list(obj.__defaults__ or ()) + list((obj.__kwdefaults__ or {}).values())
        # step 9 (review): and the module's names its code uses (a node calling a module-level model),
        # not the whole module: what the agent reaches, not what its file happens to define
        g = getattr(obj, "__globals__", None)
        if isinstance(g, dict):
            out += [g[n] for n in code_names(obj.__code__) if n in g]
        if hasattr(obj, "__wrapped__"):
            out.append(obj.__wrapped__)
        return out
    if isinstance(obj, types.MethodType):
        return [obj.__self__, obj.__func__]
    if isinstance(obj, functools.partial):
        return [obj.func, *obj.args, *obj.keywords.values()]
    if isinstance(obj, (types.ModuleType, type, str, bytes, int, float, bool)) or obj is None:
        return []
    d = getattr(obj, "__dict__", None)
    return list(d.values()) if isinstance(d, dict) else []


def walk_objects(roots, kind, kinds, say=None, limit=WALK_LIMIT):
    """{kind: [objects]} of what the roots reach, kind(obj, its class names)
    naming each object's kind or None; an object of a kind is walked through
    too (a graph holds its nodes, an agent its handoffs)"""
    found = {k: [] for k in kinds}
    seen, stack, n = set(), list(roots), 0
    while stack and n < limit:
        obj = stack.pop()
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        n += 1
        k = kind(obj, mro_names(obj))
        if k:
            found[k].append(obj)
        stack.extend(children(obj))
    if stack and say:
        say(f"the walk stopped at {limit} objects: some of the agent may be left out")
    return found


def placeholder_keys(region=None):
    """each model provider's key a placeholder, before the agent's code is
    imported: its clients are made, never with a real key; and no cloud
    metadata service asked, no trace sent"""
    for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY", "MISTRAL_API_KEY",
              "GROQ_API_KEY", "COHERE_API_KEY", "TAVILY_API_KEY", "AZURE_OPENAI_API_KEY", "DEEPSEEK_API_KEY",
              "XAI_API_KEY", "TOGETHER_API_KEY", "FIREWORKS_API_KEY", "LANGSMITH_API_KEY"):
        os.environ[k] = "varek-plan-generate-placeholder"
    os.environ.setdefault("AWS_DEFAULT_REGION", region or "us-east-1")
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
    os.environ["LANGSMITH_TRACING"] = os.environ["LANGCHAIN_TRACING_V2"] = "false"
    os.environ["OPENAI_AGENTS_DISABLE_TRACING"] = "1"


def import_attr(root, entry, what):
    """FILE.py:ATTR imported from the project (its directory, and the file's,
    on the path): (module, the attribute)"""
    import importlib.util
    path, _, attr = entry.rpartition(":")
    if not path or not attr:
        raise AdapterError(f"the {what}'s entry {entry!r} is not FILE.py:ATTR")
    file = os.path.normpath(os.path.join(root, path))
    if not os.path.isfile(file):
        raise AdapterError(f"no file {file} (the {what}'s entry {entry})")
    for d in (os.path.dirname(file), root):
        if d not in sys.path:
            sys.path.insert(0, d)
    # step 8: a file in a package is imported as its package's module (its
    # relative imports work, as `langgraph dev` loads it); any other is
    # registered in sys.modules before its code is executed (a dataclass looks its module
    # up there as it is defined)
    parts, d = [os.path.basename(file)[:-3]], os.path.dirname(file)
    while os.path.isfile(os.path.join(d, "__init__.py")) and d != os.path.dirname(d):
        parts.insert(0, os.path.basename(d))
        d = os.path.dirname(d)
    try:
        if len(parts) > 1:
            if d not in sys.path:
                sys.path.insert(0, d)
            import importlib
            mod = importlib.import_module(".".join(parts))
        else:
            name = "varek_plan_agent_" + parts[0]
            spec = importlib.util.spec_from_file_location(name, file)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
    except Exception as e:
        raise AdapterError(f"importing {file} failed: {type(e).__name__}: {e}")
    if not hasattr(mod, attr):
        raise AdapterError(f"{file} has no {attr}")
    return mod, getattr(mod, attr)
