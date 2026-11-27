# SPDX-License-Identifier: MIT
"""Tests for the `varek` command (v1.22). Run with `make test-cli`.

The end-to-end tests start the real Warden, so they need Linux, root and a
built runtime (`make`); elsewhere they are skipped.
"""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # varek/v1_4
VAREK = os.path.join(HERE, "tools", "varek")
BUILT = all(os.access(os.path.join(HERE, b), os.X_OK)
            for b in ("warden", "warden-proxy", "tools/vdp_check", "tools/vdp_cert_check", "tools/varek_keygen"))
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
needs_runtime = pytest.mark.skipif(not (BUILT and ROOT and sys.platform.startswith("linux")),
                                   reason="needs Linux, root and a built runtime")


def varek(*args, config=None, varek_bin=VAREK, check=None):
    env = dict(os.environ, NO_COLOR="1")
    if config:
        env["VAREK_CONFIG"] = config
    r = subprocess.run([sys.executable, varek_bin, *args], text=True,
                       capture_output=True, env=env)
    if check is not None:
        assert r.returncode == check, (r.returncode, r.stdout, r.stderr)
    return r


def test_help_lists_commands():
    r = varek("--help", check=0)
    for c in ("doctor", "init", "policy", "preflight", "run", "refusals", "audit", "export"):
        assert c in r.stdout


def test_policy_list_shows_builtin_packs(tmp_path):
    r = varek("policy", "list", config=str(tmp_path / "none.conf"), check=0)
    assert "healthcare" in r.stdout and "finance" in r.stdout


@pytest.mark.skipif(not BUILT, reason="needs a built runtime")
def test_policy_check_rejects_a_bad_policy(tmp_path):
    bad = tmp_path / "bad.policy.txt"
    bad.write_text("require warden 1.14\nallow path /tmp/\nnonsense here\n")
    r = varek("policy", "check", str(bad), config=str(tmp_path / "none.conf"))
    assert r.returncode == 1
    assert "fix the lines above" in r.stdout


def test_commands_without_settings_explain_init(tmp_path):
    # v1.29: commands that read runs work without settings (`varek run` then
    # uses the baseline); one that changes the active policy still needs init
    r = varek("status", config=str(tmp_path / "none.conf"), check=0)
    assert "uses the baseline policy" in r.stdout
    r = varek("policy", "show", config=str(tmp_path / "none.conf"))
    assert r.returncode == 2
    assert "varek init" in r.stderr


def test_doctor_without_settings_warns(tmp_path):
    # v1.36.1's first run on RHEL: a host with no settings (only the baseline,
    # which `varek run` uses) is a warning, not a failure; settings that are
    # there and do not load still fail
    r = varek("doctor", config=str(tmp_path / "none.conf"))
    line = [ln for ln in r.stdout.splitlines() if "none.conf" in ln]
    assert line and "WARN" in line[0] and "FAIL" not in line[0], r.stdout
    assert "varek init --pack" in r.stdout
    bad = tmp_path / "bad.conf"
    bad.write_text("[other]\nx = 1\n")
    r = varek("doctor", config=str(bad))
    assert r.returncode != 0
    assert any("FAIL" in ln and "no [varek] section" in ln for ln in r.stdout.splitlines()), r.stdout


def _init(tmp_path, pack="healthcare"):
    conf = str(tmp_path / "etc" / "varek.conf")
    varek("init", "--pack", pack, "--log-dir", str(tmp_path / "log"), config=conf, check=0)
    return conf


@needs_runtime
def test_init_then_doctor(tmp_path):
    conf = _init(tmp_path)
    assert os.stat(tmp_path / "etc" / "log.key").st_mode & 0o077 == 0
    r = varek("doctor", config=conf)
    assert "settings in" in r.stdout and "loads and lints" in r.stdout
    # A second init without --force refuses rather than replacing the key.
    r = varek("init", "--pack", "finance", config=conf)
    assert r.returncode == 2 and "already exists" in r.stderr


@needs_runtime
def test_run_refusals_audit_export_verify(tmp_path):
    conf = _init(tmp_path)
    r = varek("run", "--", "/bin/sh", "-c", "read x < /etc/hostname 2>/dev/null; echo done",
              config=conf, check=0)
    assert "done" in r.stdout
    assert "refused" in r.stderr

    r = varek("refusals", config=conf, check=0)
    assert "UNSATISFIED" in r.stdout          # /etc/ is denied by the healthcare pack
    assert "deny  path /etc/" in r.stdout     # the rule's own text is shown

    r = varek("audit", config=conf, check=0)
    assert "PASS" in r.stdout + r.stderr

    r = varek("export", config=conf, check=0)
    boms = list((tmp_path / "log").glob("*.cdx.json"))
    assert len(boms) == 1
    bom = json.loads(boms[0].read_text())
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert "signature" in bom

    varek("export", "--verify", str(boms[0]), config=conf, check=0)
    bom["metadata"]["component"]["name"] = "tampered"
    boms[0].write_text(json.dumps(bom))
    assert varek("export", "--verify", str(boms[0]), config=conf).returncode != 0

    r = varek("runs", config=conf, check=0)
    assert "yes" in r.stdout                  # the run completed (run_end present)


@needs_runtime
def test_policy_use_keeps_a_backup(tmp_path):
    conf = _init(tmp_path)
    varek("policy", "use", "finance", config=conf, check=0)
    assert list((tmp_path / "etc").glob("policy.txt.bak-*"))
    r = varek("policy", "list", config=conf, check=0)
    assert any(line.startswith(" * finance") for line in r.stdout.splitlines())


@needs_runtime
def test_installed_layout_runs_preflight(tmp_path):
    prefix, bindir = tmp_path / "opt", tmp_path / "bin"
    subprocess.run(["make", "-s", "-C", HERE, "install", f"PREFIX={prefix}", f"BINDIR={bindir}"],
                   check=True, capture_output=True)
    installed = str(bindir / "varek")
    conf = str(tmp_path / "etc" / "varek.conf")
    varek("init", "--pack", "healthcare", "--log-dir", str(tmp_path / "log"),
          config=conf, varek_bin=installed, check=0)
    r = varek("preflight", "--run", config=conf, varek_bin=installed)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "installed" in r.stdout


@needs_runtime
def test_old_run_is_audited_against_the_policy_it_used(tmp_path):
    conf = _init(tmp_path)
    varek("run", "--", "/bin/sh", "-c", "read x < /etc/hostname 2>/dev/null; true", config=conf, check=0)
    first = sorted((tmp_path / "log").glob("verdicts-*.log"))[0]
    varek("policy", "use", "finance", config=conf, check=0)   # the run's policy is now a backup
    r = varek("audit", str(first), config=conf, check=0)
    assert "PASS" in r.stdout + r.stderr
    r = varek("refusals", str(first), config=conf, check=0)
    assert "deny  path /etc/" in r.stdout


@needs_runtime
def test_pack_added_before_init_and_stderr_and_standalone_verify(tmp_path):
    conf = str(tmp_path / "etc" / "varek.conf")
    pack = tmp_path / "site.policy.txt"
    pack.write_text(open(os.path.join(HERE, "policies", "healthcare.policy.txt")).read())
    varek("policy", "add", str(pack), "--name", "site", config=conf, check=0)   # no settings yet
    varek("init", "--pack", "site", "--log-dir", str(tmp_path / "log"), config=conf, check=0)
    r = varek("run", "--", "/bin/sh", "-c", "echo to-stderr >&2; true", config=conf, check=0)
    assert "to-stderr" in r.stderr                   # the agent's stderr is shown after the run
    varek("export", config=conf, check=0)
    bom = next((tmp_path / "log").glob("*.cdx.json"))
    pub = str(tmp_path / "etc" / "log.key.pub")
    # An auditor with no VAREK settings can verify with the public key alone.
    varek("export", "--verify", str(bom), "--pubkey", pub,
          config=str(tmp_path / "nowhere.conf"), check=0)


def _varek_module():
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader("varek_cli_mod", VAREK)
    spec = importlib.util.spec_from_loader("varek_cli_mod", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_pending_shows_no_control_characters():
    """v1.42 step 8: what `varek pending` shows an approver (the user's
    request, a proposal, the object it names) cannot drive the terminal:
    control, format and bidirectional characters are written as escapes"""
    mod = _varek_module()
    assert mod._shown("read /w/data/r.csv\tok, résumé") == "read /w/data/r.csv\tok, résumé"
    assert mod._shown("ok\x1b[2K\x1b[1Adeny") == "ok\\x1b[2K\\x1b[1Adeny"
    assert mod._shown("a\u202ecod.exe") == "a\\u202ecod.exe" and mod._shown("x\rY\x85\u2028") == "x\\x0dY\\x85\\u2028"
    assert mod._shown("\U000e0041") == "\\U000e0041"


def test_a_long_stream_is_read_as_it_goes(tmp_path):
    """v1.31 (the shared soak): after 24 hours under the baseline a stream is
    about 250 MB, and `varek run`'s summary held it all and was killed on a
    2 GB host. The records are read from the file on each pass, never held."""
    import tracemalloc
    mod = _varek_module()
    log = tmp_path / "verdicts.log"
    n = 60000
    with open(log, "w") as fh:
        fh.write(json.dumps({"event": "run_start", "run": "r1", "warden": "1.31.0"}) + "\n")
        fh.write("[warden] a line of the Warden's own\n")
        for i in range(n):
            fh.write(json.dumps({"report_id": i, "run": "r1", "action": "file.open", "target": "/w/f%d" % i,
                                 "decision_final": "DENY" if i % 1000 == 0 else "ALLOW",
                                 "rule": "default_deny_unknown", "pad": "x" * 200}) + "\n")
        fh.write(json.dumps({"event": "run_end", "run": "r1"}) + "\n")
    recs = mod.read_records(str(log))
    assert sum(1 for _ in recs) == n + 2 and sum(1 for _ in recs) == n + 2     # read again on each pass
    tracemalloc.start()
    s = mod.summarize(mod.read_records(str(log)))
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert s["complete"] and s["refused"] == n // 1000
    assert peak < 4 * 1024 * 1024, peak               # the stream is about 16 MB; holding it as objects is far more
    # a damaged line is still refused, at the end of the pass that finds it
    with open(log, "a") as fh:
        fh.write('{"report_id": broken\n')
    with pytest.raises(mod.CliError, match="cannot be read"):
        mod.summarize(mod.read_records(str(log)))


def test_the_baseline_names_only_the_agents_own_terminal():
    """v1.29 review: `allow path /dev/pts/` let an agent running as its user
    open every terminal of that user's, its other shells among them. The
    baseline names the terminal `varek run` was started on, exactly."""
    import pwd
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
    try:
        import varek_baseline as b
    finally:
        sys.path.pop(0)
    pw = pwd.getpwuid(os.getuid())
    t = b.generate("/srv/proj", pw, "/tmp/varek-x", None)
    rules = [l.split("#")[0].strip() for l in t.splitlines()]
    assert "allow path /dev/pts/" not in rules and not any(r.startswith("allow path /dev/pts") for r in rules)
    assert "allow path exact /dev/tty" in rules
    t = b.generate("/srv/proj", pw, "/tmp/varek-x", None, ttys=["/dev/pts/7"])
    rules = [l.split("#")[0].strip() for l in t.splitlines()]
    assert [r for r in rules if "/dev/pts" in r] == ["allow path exact /dev/pts/7"]
    with pytest.raises(b.BaselineError):
        b.generate("/srv/proj", pw, "/tmp/varek-x", None, ttys=["/dev/pts/../../etc/shadow"])
    assert all(x.startswith("/dev/pts/") for x in b.own_ttys())


def test_the_baseline_reads_but_never_writes_gits_settings_and_hooks():
    """v1.38 (v1.37.0's known limit): the baseline let the agent write the
    working directory's .git/config and .git/hooks/, which git runs (on a
    Mac, the Mac's own git too, outside the Warden). Every write to them is
    refused, first in the policy; reads, git's other files and a clone
    inside the directory go on as before."""
    import pwd
    import shutil
    import subprocess
    tools = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
    sys.path.insert(0, tools)
    try:
        import varek_baseline as b
    finally:
        sys.path.pop(0)
    pw = pwd.struct_passwd(("u", "x", 1000, 1000, "", "/home/u", "/bin/sh"))
    assert b.glob_escape("/srv/a*b?[c]") == "/srv/a\\*b\\?\\[c\\]"
    for cwd in ("/srv/proj", "/srv/we*ird?[x]"):
        t = b.generate(cwd, pw, "/tmp/varek-1000", None)
        rules = [l.split("#")[0].strip() for l in t.splitlines()]
        g = b.glob_escape(cwd)
        first_allow = next(k for k, r in enumerate(rules) if r.startswith("allow "))
        for how, pat in b.GIT_PROTECTED:
            p = (g if how == "glob" else cwd) + pat
            for fl in ("access=wo", "access=rw", "+O_CREAT", "+O_TRUNC"):
                assert rules.index(f"deny  path {how} {p} {fl}") < first_allow   # first: nothing allows it before
        git = [r for r in rules if "/.git/" in r]
        assert not any("**" in r for r in git)                     # no glob across directories (the cross-check)
        assert all(r.startswith("deny ") for r in git if "credentials" not in r)   # reads fall through
        vdp = os.path.join(tools, "vdp_check")
        if not os.access(vdp, os.X_OK):
            continue                                              # built by make (the suites)
        pol = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"varek-git-baseline-{os.getpid()}.txt")
        with open(pol, "w") as fh:
            fh.write(t)
        try:
            assert subprocess.run([vdp, pol, "lint"], capture_output=True).returncode == 0
            R, W, RW, RC, RT, MK = 0, 0x241, 0x2, 0x40, 0x200, 0xc1   # x86-64's encoding, as policies are
            want = [(".git/config", R, "SATISFIED"), (".git/config", W, "UNSATISFIED"),
                    (".git/config", RW, "UNSATISFIED"), (".git/config", RC, "UNSATISFIED"),
                    (".git/config", RT, "UNSATISFIED"), (".git/config.lock", W, "UNSATISFIED"),
                    (".git/hooks/pre-commit", R, "SATISFIED"), (".git/hooks/pre-commit", W, "UNSATISFIED"),
                    (".git/hooks", MK, "UNSATISFIED"), (".git/worktrees/w/config.worktree", W, "UNSATISFIED"),
                    (".git/modules/a/config", W, "UNSATISFIED"), (".git/modules/a/hooks", MK, "UNSATISFIED"),
                    (".git/modules/a/hooks/post-checkout", W, "UNSATISFIED"),
                    (".git/HEAD", W, "SATISFIED"), (".git/index", W, "SATISFIED"),
                    (".git/objects/ab/cd", W, "SATISFIED"), (".git/refs/heads/main", W, "SATISFIED"),
                    ("sub/.git/config", W, "SATISFIED"), ("src/main.py", W, "SATISFIED")]
            q = "".join(f"path {f} {(cwd + '/' + p).encode().hex()}\n" for p, f, _ in want)
            out = subprocess.run([vdp, pol, "batch"], input=q, capture_output=True, text=True).stdout.splitlines()
            got = [json.loads(o)["verdict"] for o in out]
            assert got == [v for _, _, v in want], list(zip([(p, f) for p, f, _ in want], got))
        finally:
            os.unlink(pol)


def test_a_user_whose_home_is_root_gets_no_home_rules():
    """RHEL (the arm64 and RHEL sweeps): nobody's home there is /, and the
    baseline's rules named //.gitconfig, and with a profile //.claude/,
    which the Warden refuses to load. Such a user's rules name /nonexistent."""
    import pwd
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
    try:
        import varek_baseline as b
    finally:
        sys.path.pop(0)
    pw = pwd.struct_passwd(("nobody", "x", 65534, 65534, "nobody", "/", "/sbin/nologin"))
    prof = {"name": "t", "sha256": "0" * 64, "programs": [], "about": "", "commands": [], "rules": ["allow path ${HOME}/.claude/"]}
    t = b.generate("/srv/proj", pw, "/tmp/varek-65534", prof)
    assert "//" not in "\n".join(l.split("#")[0] for l in t.splitlines() if not l.startswith("#"))
    assert "#@ home /nonexistent" in t and "allow path /nonexistent/.claude/" in t
    for name in ("claude", "codex", "gemini", "aider"):
        p = b.load_profile(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "policies", "agents",
                                        name + ".profile.txt"))
        t = b.generate("/srv/proj", pw, "/tmp/varek-65534", p)
        assert "//" not in "\n".join(l.split("#")[0] for l in t.splitlines() if not l.startswith("#")), name
    assert b.policy_home(pwd.struct_passwd(("u", "x", 1000, 1000, "", "/home/u/", "/bin/sh"))) == "/home/u"


def test_suggest_names_arm64s_system_calls_from_the_generic_table():
    """v1.33.0 review: arm64's names came from <asm-generic/unistd.h> with
    its conditional blocks ignored, so 84 read as sync_file_range2 (for
    architectures that want it) and 244 as arch_specific_syscall (a marker,
    no call). The blocks are followed for what arm64 defines."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
    try:
        import varek_suggest as s
    finally:
        sys.path.pop(0)
    t = "\n".join([
        "#define __NR3264_fstat 80",
        "#ifdef __ARCH_WANT_SYNC_FILE_RANGE2",
        "#define __NR_sync_file_range2 84",
        "#else",
        "#define __NR_sync_file_range 84",
        "#endif",
        "#ifdef __ARCH_WANT_RENAMEAT",
        "#define __NR_renameat 38",
        "#endif",
        "#ifndef __ARCH_WANT_NEW_STAT",
        "#define __NR_oldstat 999",
        "#endif",
        "#define __NR_arch_specific_syscall 244",
        "#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32",
        "#define __NR_wait4 260",
        "#endif",
        "#if __BITS_PER_LONG == 64 && !defined(__SYSCALL_COMPAT)",
        "#define __NR_fstat __NR3264_fstat",
        "#else",
        "#define __NR_fstat64 __NR3264_fstat",
        "#endif",
        "#undef __NR_syscalls",
        "#define __NR_syscalls 462",
    ])
    n = s._generic_syscall_names(t, s.ARM64_WANTS)
    assert n == {84: "sync_file_range", 38: "renameat", 260: "wait4", 80: "fstat"}
    if os.path.exists("/usr/include/asm-generic/unistd.h"):
        real = s._syscall_names("aarch64")
        assert real[84] == "sync_file_range" and 244 not in real and real[79] == "newfstatat" and real[80] == "fstat"


PACKS = ("healthcare", "finance", "cybersecurity", "utility", "national-defense")


@needs_runtime
@pytest.mark.skipif(not os.path.exists("/usr/bin/python3"), reason="no /usr/bin/python3")
@pytest.mark.parametrize("pack", PACKS)
def test_a_python_agent_starts_under_each_pack_refused_nothing(tmp_path, pack):
    # v1.40: the packs allow what the loader, the C library and Python read as
    # they start (most of it files that need not exist); before, every run
    # under a pack began with some 19 refusals, noise to an alerting rule
    # (Sentinel's live test, November 16, 2026). CI runs this on Ubuntu, and on
    # Rocky Linux 9 and Amazon Linux 2023 when their host suites run (a change
    # to C code, the charts or packaging): a refusal here is a start-up read a
    # distribution adds, to be allowed in the packs if it is as harmless.
    os.makedirs("/tmp/varek", exist_ok=True)            # the packs' scratch, must exist (noexec)
    log = tmp_path / "run.log"
    env = dict(os.environ, NO_COLOR="1", VAREK_CONFIG=str(tmp_path / "none.conf"),
               HOME="/tmp/varek")                       # the agent's user's packages, not root's (refused)
    r = subprocess.run([sys.executable, VAREK, "run", "--policy", os.path.join(HERE, "policies", f"{pack}.policy.txt"),
                        "--log", str(log), "--", "/usr/bin/python3", "-c", "pass"],
                       cwd="/tmp/varek", stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    refused = []
    for line in log.read_text().splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("decision_final") == "DENY" and "event" not in rec:
            refused.append((rec.get("action"), rec.get("target"), rec.get("resolved"), rec.get("rule"),
                            rec.get("policy_line")))
    for x in refused:                                    # each in full (pytest shortens the assertion's list)
        print("refused:", *x)
    assert not refused, f"{pack}: the start-up reads refused: {refused}"


@needs_runtime
@pytest.mark.skipif(not os.path.exists("/usr/bin/python3"), reason="no /usr/bin/python3")
@pytest.mark.parametrize("pack", PACKS)
def test_each_pack_decides_changes_and_the_legacy_stat_as_the_agent(tmp_path, pack):
    # v1.41: the packs say `require warden 1.29`. Under it (a) the legacy
    # stat(2)/lstat(2) are decided like a read-only open (a Python built
    # against a glibc before 2.33, as python-build-standalone's, finds its
    # library with them, and could not start under 1.27); (b) a change by
    # name is decided as a write on every name it touches: a rename within the
    # scratch space is allowed, a rename to a name a deny rule covers (x.pem)
    # is refused, a removal is allowed, a link stays refused; (c) files are
    # opened as the agent's user, so a directory the policy lets it write but
    # its user cannot is refused by the kernel (EACCES).
    import pwd
    import shutil
    import uuid
    nobody = pwd.getpwnam("nobody")
    os.makedirs("/tmp/varek", exist_ok=True)
    mine = f"/tmp/varek/t-{uuid.uuid4().hex[:8]}"        # the agent's own
    roots = mine + "-root"                               # root's, 0755
    os.makedirs(mine)
    os.chown(mine, nobody.pw_uid, nobody.pw_gid)
    os.makedirs(roots, mode=0o755)
    agent = f"""
import ctypes, json, os, platform
mine, roots = {mine!r}, {roots!r}
out = {{}}
def tried(name, f):
    try:
        f(); out[name] = 0
    except OSError as e:
        out[name] = e.errno
if platform.machine() == "x86_64":
    libc = ctypes.CDLL(None, use_errno=True)
    buf = ctypes.create_string_buffer(256)
    for nr, call in ((4, "stat"), (6, "lstat")):
        r = libc.syscall(nr, b"/usr/lib", buf)
        out[call] = 0 if r == 0 else ctypes.get_errno()
tried("write", lambda: open(mine + "/a", "w").write("x"))
tried("rename", lambda: os.rename(mine + "/a", mine + "/b"))
tried("rename_to_pem", lambda: os.rename(mine + "/b", mine + "/b.pem"))
tried("link", lambda: os.link(mine + "/b", mine + "/c"))
tried("unlink", lambda: os.unlink(mine + "/b"))
tried("write_roots", lambda: open(roots + "/a", "w").write("x"))
print(json.dumps(out))
"""
    log = tmp_path / "run.log"
    env = dict(os.environ, NO_COLOR="1", VAREK_CONFIG=str(tmp_path / "none.conf"), HOME="/tmp/varek")
    try:
        r = subprocess.run([sys.executable, VAREK, "run", "--policy",
                            os.path.join(HERE, "policies", f"{pack}.policy.txt"), "--log", str(log),
                            "--", "/usr/bin/python3", "-c", agent],
                           cwd="/tmp/varek", stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env,
                           timeout=120)
        assert r.returncode == 0, r.stdout + r.stderr
        got = json.loads([x for x in r.stdout.splitlines() if x.startswith("{")][-1])
        import errno
        want = {"write": 0, "rename": 0, "rename_to_pem": errno.EACCES, "link": errno.EPERM, "unlink": 0,
                "write_roots": errno.EACCES}
        if os.uname().machine == "x86_64":
            want.update(stat=0, lstat=0)
        assert got == want, got
        recs = [json.loads(x) for x in log.read_text().splitlines() if x.startswith("{")]
        acts = {(x.get("action"), x.get("decision_final")) for x in recs}
        assert ("file.rename_to", "ALLOW") in acts and ("file.unlink", "ALLOW") in acts
        assert any(x.get("action") == "file.rename_to" and x.get("decision_final") == "DENY"
                   and str(x.get("target", "")).endswith("b.pem") for x in recs)   # refused, and recorded
        assert not os.path.exists(mine + "/b.pem") and not os.path.exists(roots + "/a")
    finally:
        shutil.rmtree(mine, ignore_errors=True)
        shutil.rmtree(roots, ignore_errors=True)


@needs_runtime
def test_doctor_and_run_warn_of_a_writable_directory_the_agents_user_cannot_write(tmp_path):
    # v1.41: under `require warden 1.29` (the packs' since v1.41) files are
    # opened as the agent's user, so a directory the policy lets the agent
    # write must be writable by that user, or the kernel refuses the write.
    # `varek doctor` and `varek run` say which are not (or are not there),
    # and how to fix each; under 1.28 (opened as root) they say nothing.
    import pwd
    import shutil
    import uuid
    nobody = pwd.getpwnam("nobody")
    base = f"/tmp/varek-writes-{uuid.uuid4().hex[:8]}"    # 0755 to the top, so nobody can reach it
    dirs = {k: os.path.join(base, k) for k in ("roots", "mine", "group", "gone")}
    os.makedirs(dirs["roots"], mode=0o755)
    os.makedirs(dirs["mine"])
    os.chown(dirs["mine"], nobody.pw_uid, -1)
    os.makedirs(dirs["group"])
    os.chown(dirs["group"], 0, nobody.pw_gid)
    os.chmod(dirs["group"], 0o775)
    os.chmod(base, 0o755)
    rules = "".join(f"allow path {d}/\n" for d in dirs.values())
    try:
        for req, warned in (("1.29", True), ("1.28", False)):
            pol = tmp_path / f"p{req}.policy.txt"
            pol.write_text(f"require warden {req}\n" + rules)
            conf = str(tmp_path / req / "etc" / "varek.conf")
            varek("init", "--pack", str(pol), "--log-dir", str(tmp_path / req / "log"), config=conf, check=0)
            doc = varek("doctor", config=conf)
            run = varek("run", "--", "/bin/true", config=conf)   # its warning comes before the agent starts
            for out in (doc.stdout + doc.stderr, run.stdout + run.stderr):
                said = [ln for ln in out.splitlines() if base in ln and "WARN" in ln]
                if not warned:
                    assert not said, out
                    continue
                assert len(said) == 2, out
                assert any(dirs["roots"] + " (policy line 2) is not writable by the agent's user nobody" in ln
                           for ln in said), out
                assert any(dirs["gone"] + " (policy line 5) does not exist" in ln for ln in said), out
                assert f"chown nobody {dirs['roots']}" in out and f"install -d -o nobody {dirs['gone']}" in out
    finally:
        shutil.rmtree(base, ignore_errors=True)
