# SPDX-License-Identifier: MIT
"""
varek_baseline: the baseline policy `varek run` writes when nothing is set up
(v1.29, docs/security/v1.29-varek-run.md, section 2, D5 to D7, D11).

The baseline is not a new kind of policy: it is an ordinary policy file,
written for one working directory, one agent user and one profile, in the
existing grammar. Its first lines (`#@ ...`, comments to the parsers) say
what it was made for; the Warden copies them into run_start's `baseline`,
from the same bytes it hashes. Files are named by their SHA-256 under
/var/lib/varek/policies/ (VAREK_LIB_DIR), root-owned, never rewritten, so
the audit and `varek refusals` find the policy a run used.

A profile (policies/agents/NAME.profile.txt) adds rules for one known agent:
its own configuration directory and its model provider's API host. Its
header names the commands it is for and the programs it launches; its rules
may use ${HOME}, which is replaced by the agent user's home directory.
"""

import glob
import hashlib
import os
import pwd
import re
import shutil
import stat

BASELINE_FORMAT = 1
DEFAULT_LIB_DIR = "/var/lib/varek"
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Programs the baseline lets the agent launch, where the host has them (each
# resolved to its file and named exactly: the Warden's launch set holds at
# most 256 files a rule, and a list is narrower than a directory).
BASE_PROGRAMS = [
    "sh", "bash", "dash", "env", "true", "false", "test", "echo", "printf", "sleep", "date", "id",
    "uname", "hostname", "whoami", "which", "ls", "cat", "head", "tail", "wc", "sort", "uniq",
    "cut", "tr", "tee", "grep", "egrep", "fgrep", "sed", "awk", "gawk", "mawk", "find", "xargs",
    "diff", "cmp", "patch", "file", "stat", "touch", "mkdir", "rmdir", "rm", "cp", "mv", "ln",
    "chmod", "basename", "dirname", "readlink", "realpath", "mktemp", "tar", "gzip", "gunzip",
    "zcat", "bzip2", "xz", "unzip", "zip", "git", "rg", "fd", "jq", "make", "less", "more",
]

# Credential stores and keys, refused wherever they appear (first in the
# file: no later rule reaches them). The key patterns are the packs' own.
CREDENTIAL_DENIES = [
    ("deny  path contains /.ssh/", "SSH keys and configuration"),
    ("deny  path contains /.aws/", "AWS credentials"),
    ("deny  path contains /.config/gcloud/", "Google Cloud credentials"),
    ("deny  path contains /.azure/", "Azure credentials"),
    ("deny  path contains /.kube/", "Kubernetes credentials"),
    ("deny  path contains /.gnupg/", "GnuPG keys"),
    ("deny  path contains /.password-store/", "pass"),
    ("deny  path suffix /.docker/config.json", "Docker registry credentials"),
    ("deny  path suffix /.netrc", "netrc credentials"),
    ("deny  path suffix /.git-credentials", "git's stored credentials"),
    ("deny  path suffix /.pgpass", "PostgreSQL passwords"),
    ("deny  path suffix /.my.cnf", "MySQL credentials"),
    ("deny  path suffix /.npmrc", "npm tokens"),
    ("deny  path suffix /.pypirc", "PyPI tokens"),
    ("deny  path glob /**/*.[pP][eE][mM]", "private keys and certificates (x.pem, x.PEM)"),
    ("deny  path glob /**/*.[pP][eE][mM].*", "... and copies"),
    ("deny  path glob /**/*.[kK][eE][yY]", "private keys (x.key)"),
    ("deny  path glob /**/*.[kK][eE][yY].*", "... and copies"),
    ("deny  path glob /**/.[eE][nN][vV]", "dotenv credential files, at any depth"),
    ("deny  path glob /**/.[eE][nN][vV].*", "... and their variants (.env.local)"),
    ("deny  path glob /**/[iI][dD]_[rR][sS][aA]*", "SSH private keys wherever they sit"),
    ("deny  path glob /**/[iI][dD]_[eE][cC][dD][sS][aA]*", ""),
    ("deny  path glob /**/[iI][dD]_[eE][dD]25519*", ""),
]

SYSTEM_DENIES = [
    ("deny  path /etc/shadow", ""), ("deny  path /etc/gshadow", ""),
    ("deny  path /etc/sudoers", "and /etc/sudoers.d/"), ("deny  path /etc/ssh/", ""),
    ("deny  path /etc/ssl/private/", ""), ("deny  path /root/", "the administrator's home"),
    ("deny  path /var/log/varek/", "the verdict streams"), ("deny  path /etc/varek/", "the signing key"),
]

SYSTEM_READS = [
    ("allow path /usr/ readonly", "programs, libraries, shared data"),
    ("allow path /etc/ readonly", "configuration, less what is refused above"),
    ("allow path /opt/ readonly", "software installed under /opt"),
    ("allow path /proc/self/ readonly", "the agent's own process"),
    ("allow path exact /proc/cpuinfo readonly", ""),
    ("allow path exact /proc/meminfo readonly", ""),
    ("allow path exact /proc/stat readonly", ""),
    ("allow path /sys/devices/system/cpu/ readonly", "CPU count and topology"),
    ("allow path exact /dev/null", ""), ("allow path exact /dev/zero readonly", ""),
    ("allow path exact /dev/urandom readonly", ""), ("allow path exact /dev/random readonly", ""),
    ("allow path exact /dev/tty", "an interactive agent's terminal"),
    ("allow path /dev/pts/", ""),
]

# A working directory the baseline refuses to make writable.
REFUSED_CWDS = {"/", "/usr", "/etc", "/var", "/boot", "/proc", "/sys", "/dev", "/root", "/bin",
                "/sbin", "/lib", "/lib64", "/opt", "/tmp", "/run", "/srv", "/home", "/var/tmp",
                "/var/lib", "/var/log"}

INTERPRETERS = {"python": "python", "node": "node", "nodejs": "node", "bun": "node", "deno": "node"}
LAUNCHERS = {"npx", "uvx", "bunx", "pipx"}


class BaselineError(Exception):
    pass


def lib_dir():
    return os.environ.get("VAREK_LIB_DIR", DEFAULT_LIB_DIR)


def profiles_dir(home):
    return os.path.join(home, "policies", "agents")


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_profile(path):
    """{name, commands, programs, about, rules (lines), sha256, path}"""
    with open(path, "rb") as fh:
        raw = fh.read()
    prof = {"path": path, "sha256": _sha256(raw), "name": None, "commands": [], "programs": [],
            "about": "", "rules": []}
    for line in raw.decode("utf-8").splitlines():
        if line.startswith("#@ "):
            key, _, val = line[3:].partition(" ")
            if key == "profile":
                prof["name"] = val.strip()
            elif key == "commands":
                prof["commands"] = val.split()
            elif key == "programs":
                prof["programs"] = val.split()
            elif key == "about":
                prof["about"] = val.strip()
            else:
                raise BaselineError(f"{path}: unknown header line #@ {key}")
        else:
            prof["rules"].append(line)
    if not prof["name"] or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", prof["name"]):
        raise BaselineError(f"{path}: no `#@ profile NAME` line, or a bad name")
    return prof


def all_profiles(home):
    out = {}
    for p in sorted(glob.glob(os.path.join(profiles_dir(home), "*.profile.txt"))):
        prof = load_profile(p)
        out[prof["name"]] = prof
    return out


def _script_name(arg):
    base = os.path.basename(arg)
    base = re.sub(r"@[^@/]*$", "", base) if not base.startswith("@") else base
    return re.sub(r"\.(py|js|mjs|cjs|ts)$", "", base)


def command_name(cmd):
    """The name a profile is chosen by: the command's basename, after `env`
    (and its NAME=VALUE arguments), a package runner (npx, uvx, ...) or an
    interpreter (then the script's name). (name, interpreter or None)"""
    args = list(cmd)
    while args and os.path.basename(args[0]) == "env":
        args = args[1:]
        while args and (args[0].startswith("-") or ("=" in args[0] and not args[0].startswith("/"))):
            args = args[1:]
    if not args:
        return None, None
    first = os.path.basename(args[0])
    if first in LAUNCHERS:
        rest = [a for a in args[1:] if not a.startswith("-")]
        if rest:
            pkg = rest[0].split("/")[-1]
            return re.sub(r"@.*$", "", pkg), None
        return first, None
    m = re.fullmatch(r"(python|node|nodejs|bun|deno)[0-9.]*", first)
    if m:
        interp = INTERPRETERS[m.group(1)]
        rest = [a for a in args[1:] if not a.startswith("-")]
        if args[1:2] and args[1] in ("-m", "-c", "-e"):
            mod = args[2] if args[1] == "-m" and len(args) > 2 else None
            return (mod.split(".")[0] if mod else interp), interp
        if rest:
            return _script_name(rest[0]), interp
        return interp, interp
    return first, None


def choose_profile(cmd, profiles, given=None):
    """The profile for this run (a dict), None for the baseline alone, and why."""
    if given:
        if given == "none":
            return None, "--profile none"
        if os.sep in given or given.endswith(".profile.txt"):
            if not os.path.isfile(given):
                raise BaselineError(f"no profile file at {given}")
            return load_profile(given), f"--profile {given}"
        if given not in profiles:
            raise BaselineError(f"no profile named '{given}' (profiles: {', '.join(sorted(profiles))})")
        return profiles[given], f"--profile {given}"
    name, interp = command_name(cmd)
    for prof in profiles.values():
        if name in prof["commands"]:
            return prof, f"the command `{name}`"
    if interp and interp in profiles:
        return profiles[interp], f"the interpreter `{interp}`"
    return None, f"no profile for `{name}`"


def agent_user(run_as=None):
    """The agent's user (D6): --run-as, else the user who ran sudo, else
    nobody. (passwd entry or None, the --run-as value, why)"""
    if run_as:
        try:
            pw = pwd.getpwuid(int(run_as.split(":")[0])) if run_as[0].isdigit() else pwd.getpwnam(run_as)
        except (KeyError, ValueError):
            pw = None
        return pw, run_as, "--run-as"
    uid = os.environ.get("SUDO_UID")
    if uid and uid.isdigit() and int(uid) != 0:
        try:
            pw = pwd.getpwuid(int(uid))
            return pw, pw.pw_name, "the user who ran sudo"
        except KeyError:
            pass
    try:
        pw = pwd.getpwnam("nobody")
    except KeyError:
        pw = None
    return pw, "nobody", "no sudo user"


def check_cwd(cwd, home):
    real = os.path.realpath(cwd)
    if real in REFUSED_CWDS or real.rstrip("/") == os.path.realpath(home or "/nonexistent"):
        raise BaselineError(f"the working directory {real} would be writable by the agent under the "
                            "baseline; run it from a project directory (not /, a system directory or "
                            "a home directory itself)")
    if not re.fullmatch(r"/[\x21-\x7e]*", real) or "#" in real:
        raise BaselineError(f"the working directory {real} has a space, a '#' or a byte outside "
                            "printable ASCII, which a policy line cannot hold; use --policy")
    return real


def tmp_dir(pw, make=True):
    """/tmp/varek-<uid>: the agent's temporary directory, made by root for
    the agent's user, mode 0700. One that exists must be a directory (not a
    link) owned by that user with mode 0700."""
    d = f"/tmp/varek-{pw.pw_uid}"
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        if not make:
            return d
        os.mkdir(d, 0o700)
        os.chown(d, pw.pw_uid, pw.pw_gid)
        os.chmod(d, 0o700)
        st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != pw.pw_uid or stat.S_IMODE(st.st_mode) != 0o700:
        raise BaselineError(f"{d} exists but is not a directory of {pw.pw_name}'s with mode 0700; "
                            "remove it and run again")
    return d


def _root_only(p):
    """the file (or directory) is root's and writable by no one else"""
    try:
        st = os.stat(p)
    except OSError:
        return False
    return st.st_uid == 0 and not st.st_mode & 0o022


def program_names(prog, path):
    """Every name the agent can launch prog by: prog in each directory of its
    PATH, and /bin and /usr/bin (system() and popen() use /bin/sh), then the
    file they lead to. Launches are decided on the name the agent uses (v1.27),
    so each is a rule. A program anyone but root could change is not named."""
    out = []
    dirs = [d for d in path.split(":") if d] + ["/bin", "/usr/bin"]
    for d in dirs:
        n = os.path.join(d, prog)
        if not os.path.isfile(n) or not os.access(n, os.X_OK):
            continue
        r = os.path.realpath(n)
        if not (_root_only(r) and _root_only(os.path.dirname(r)) and _root_only(d)):
            continue
        for x in (os.path.normpath(n), r):
            if x not in out:
                out.append(x)
    return out


def agent_path(cmd, environ):
    """The agent's PATH (D7): the system's, and the directory of the agent's
    own command when it is elsewhere (an install under /opt or the user's
    ~/.local/bin), so the agent and the programs beside it are found."""
    path = SYSTEM_PATH
    args = list(cmd)
    while args and os.path.basename(args[0]) == "env":
        args = [a for a in args[1:] if not ("=" in a and not a.startswith("/"))]
        args = [a for a in args if not a.startswith("-")] or args
    if args:
        w = shutil.which(args[0], path=environ.get("PATH") or SYSTEM_PATH)
        if w:
            d = os.path.dirname(os.path.abspath(w))
            if d not in path.split(":"):
                path = path + ":" + d
    return path


def generate(cwd, pw, tmp, profile, path=SYSTEM_PATH):
    """The baseline's text for this run."""
    home = pw.pw_dir if pw else "/nonexistent"
    user = pw.pw_name if pw else "nobody"
    L = []
    L.append(f"#@ varek baseline {BASELINE_FORMAT}")
    L.append(f"#@ profile {profile['name']} {profile['sha256']}" if profile else "#@ profile none -")
    L.append(f"#@ cwd {cwd}")
    L.append(f"#@ home {home}")
    L.append(f"#@ user {user}")
    L.append(f"#@ tmp {tmp}")
    L.append("# The VAREK baseline policy (v1.29), written by `varek run` for this working")
    L.append("# directory, agent user and profile. It is an ordinary policy: read it, keep it,")
    L.append("# audit runs against it. Rules match the resolved path; the first match wins;")
    L.append("# anything no rule allows is refused. To change it, copy it, edit it and run")
    L.append("# with `varek run --policy FILE` (a dry run first: `--dry-run`).")
    L.append("require warden 1.29")
    L.append("")
    L.append("# --- credential stores and keys, refused wherever they are ---")
    for r, c in CREDENTIAL_DENIES:
        L.append(f"{r:<52} # {c}" if c else r)
    L.append("")
    L.append("# --- the system's secrets and VAREK's own files ---")
    for r, c in SYSTEM_DENIES:
        L.append(f"{r:<52} # {c}" if c else r)
    L.append("")
    L.append("# --- the system, read-only ---")
    for r, c in SYSTEM_READS:
        L.append(f"{r:<52} # {c}" if c else r)
    L.append("")
    L.append("# --- the working directory and the agent's temporary directory (TMPDIR) ---")
    L.append(f"allow path exact {cwd} readonly")
    L.append(f"allow path {cwd}/")
    L.append(f"allow path exact {tmp} readonly")
    L.append(f"allow path {tmp}/")
    L.append("")
    L.append("# --- programs the agent may launch (each file named; lint notes the shells and")
    L.append("# interpreters: with one, the agent can run any code it can read) ---")
    progs = []
    for name in BASE_PROGRAMS + (profile["programs"] if profile else []):
        for r in program_names(name, path):
            if r not in progs:
                progs.append(r)
    for r in progs:
        L.append(f"allow exec {r}")
    if profile:
        L.append("")
        L.append(f"# --- profile {profile['name']}: {profile['about']} ---")
        for line in profile["rules"]:
            L.append(line.replace("${HOME}", home))
    L.append("")
    return "\n".join(L)


def store(text):
    """Write the baseline to <lib>/policies/<sha256>.policy.txt (root-owned,
    0644, never rewritten); its path."""
    data = text.encode("utf-8")
    d = os.path.join(lib_dir(), "policies")
    os.makedirs(d, mode=0o755, exist_ok=True)
    for p in (lib_dir(), d):
        st = os.stat(p)
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise BaselineError(f"{p} must be root's and writable by no one else")
    path = os.path.join(d, _sha256(data) + ".policy.txt")
    if os.path.exists(path):
        with open(path, "rb") as fh:
            if fh.read() != data:
                raise BaselineError(f"{path} exists with other contents; it is not rewritten")
        return path
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    return path


KEEP_ENV = ("TERM", "COLORTERM", "LANG", "LANGUAGE", "TZ", "NO_COLOR")


def agent_env(pw, tmp, names, environ, path=SYSTEM_PATH):
    """The agent's environment (D7): a clean one: its user's HOME, USER,
    LOGNAME and SHELL; PATH (agent_path); the terminal and locale; TMPDIR;
    and each variable named with --env, from varek's own environment."""
    env = {"PATH": path}
    if pw:
        env.update(HOME=pw.pw_dir, USER=pw.pw_name, LOGNAME=pw.pw_name, SHELL=pw.pw_shell or "/bin/sh")
    for k in KEEP_ENV:
        if k in environ:
            env[k] = environ[k]
    for k, v in environ.items():
        if k.startswith("LC_"):
            env[k] = v
    env["TMPDIR"] = tmp
    for n in names:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", n):
            raise BaselineError(f"--env {n}: not a variable name")
        if n not in environ:
            raise BaselineError(f"--env {n}: not set in varek's environment (with sudo, pass it with "
                                f"`sudo --preserve-env={n}`)")
        env[n] = environ[n]
    return env
