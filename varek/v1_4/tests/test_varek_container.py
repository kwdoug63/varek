# SPDX-License-Identifier: MIT
"""Tests for `varek doctor` in a container (v1.32, D11): the settings read
from the container's state as text (tools/varek_container.py). Run with
`make test-cli`. The mount test itself runs in the container sweep
(tests/container_sweep.sh), where the runtime and its AppArmor or SELinux are
real."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import varek_container as vc  # noqa: E402

TEN = sum(1 << n for n in vc.NEEDED)
ROOTFUL = "0 0 4294967295\n"
CG_RW = "cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0\n"
CG_RO = "cgroup2 /sys/fs/cgroup cgroup2 ro,nosuid,nodev,noexec,relatime 0 0\n"


def status(caps=TEN, seccomp=2, eff=None):
    e = f"CapEff:\t{eff:016x}\n" if eff is not None else ""
    return f"Name:\tpython3\n{e}CapBnd:\t{caps:016x}\nSeccomp:\t{seccomp}\n"


def run(caps=TEN, seccomp=2, label="varek-container (enforce)", mounts=CG_RO, cgroup="0::/\n", uid_map=ROOTFUL):
    return vc.settings(status(caps, seccomp), label, mounts, cgroup, uid_map)


def levels(out):
    return [lv for lv, _, _ in out]


def find(out, word):
    return [(lv, t, f) for lv, t, f in out if word in t]


def test_the_documented_settings_all_pass():
    out = run()
    assert levels(out) == ["ok"] * len(out), out


def test_each_missing_capability_names_its_flag():
    for n, (name, _) in vc.NEEDED.items():
        out = run(caps=TEN & ~(1 << n))
        f = find(out, f"capability {name} is missing")
        assert f and f[0][0] == "fail" and f[0][2] == f"--cap-add {name}", (name, out)


def test_root_counts_the_effective_set(monkeypatch):
    """v1.32 review: as root the Warden holds the effective set, which an
    entrypoint may have dropped below the bounding set"""
    monkeypatch.setattr(vc.os, "geteuid", lambda: 0)
    out = vc.settings(status(eff=TEN & ~(1 << 19)), "varek-container (enforce)", CG_RO, "0::/\n", ROOTFUL)
    assert find(out, "capability SYS_PTRACE is missing")[0][0] == "fail"
    monkeypatch.setattr(vc.os, "geteuid", lambda: 1000)
    out = vc.settings(status(eff=0), "varek-container (enforce)", CG_RO, "0::/\n", ROOTFUL)
    assert not find(out, "is missing")


def test_extra_capabilities_and_privileged_warn():
    out = run(caps=TEN | 1 << 27)                                   # MKNOD
    assert find(out, "beyond the Warden's ten: MKNOD")[0][0] == "warn"
    out = run(caps=(1 << 41) - 1)                                   # every capability: --privileged
    assert find(out, "--privileged?")[0][0] == "warn"


def test_seccomp_unconfined_warns():
    assert find(run(seccomp=0), "seccomp=unconfined")[0][0] == "warn"


def test_apparmor_docker_default_fails_with_the_profile_as_fix():
    lv, text, fix = find(run(label="docker-default (enforce)"), "AppArmor profile docker-default")[0]
    assert lv == "fail" and "denies every mount" in text and "apparmor=varek-container" in fix
    # v1.32 review: a run that mounts nothing is only warned
    quiet = vc.settings(status(), "docker-default (enforce)", CG_RO, "0::/\n", ROOTFUL, cgroups=False, noexec=False)
    assert find(quiet, "AppArmor profile docker-default")[0][0] == "warn"
    assert find(run(label="containers-default-0.50.1 (enforce)"), "containers-default")[0][0] == "fail"
    assert find(run(label="unconfined"), "apparmor=unconfined")[0][0] == "warn"


def test_selinux_types():
    lab = "system_u:system_r:{}:s0:c1,c2"
    assert find(run(label=lab.format("container_init_t")), "container_init_t")[0][0] == "ok"
    lv, _, fix = find(run(label=lab.format("container_t")), "container_t")[0]
    assert lv == "warn" and "label=type:container_init_t" in fix
    assert find(run(label=lab.format("spc_t")), "not confined")[0][0] == "warn"


def test_no_mac_label_says_nothing():
    out = run(label="kernel")
    assert not find(out, "AppArmor") and not find(out, "SELinux")


def test_cgroup_cases():
    lv, _, fix = find(run(cgroup="0::/system.slice/docker-1.scope\n"), "read-only")[0]
    assert lv == "fail" and fix == "--cgroupns=private"
    assert find(run(), "a run remounts it read-write")[0][0] == "ok"
    assert find(run(mounts=CG_RW, cgroup="0::/x\n"), "cgroup v2 at /sys/fs/cgroup")[0][0] == "ok"
    assert find(run(mounts=""), "no cgroup v2")[0][0] == "fail"
    assert find(vc.settings(status(), "x", "", "0::/\n", "", cgroups=False), "no cgroup v2")[0][0] == "warn"


ROOTLESS = "0 1000 1\n1 100000 65536\n"


def test_rootless_is_said():
    assert find(run(uid_map=ROOTLESS, mounts=CG_RW), "rootless (a user namespace)")[0][0] == "ok"
    assert not find(run(), "rootless")


def test_rootless_read_only_cgroups_are_remounted():
    """v1.32.1 (D10 measured): in a user namespace the Warden bind-remounts
    the cgroup mount as elsewhere; --systemd=always is no longer needed"""
    assert find(run(uid_map=ROOTLESS), "a run remounts it read-write")[0][0] == "ok"
    assert not find(run(uid_map=ROOTLESS), "does not remount it")
    assert not [t for lv, t, _ in run(uid_map=ROOTLESS) if lv == "fail"]


def test_rootless_remount_refused_names_systemd_always(monkeypatch):
    """where the remount is refused in a user namespace, the fix names
    --systemd=always first"""
    monkeypatch.setattr(vc.os, "geteuid", lambda: 0)

    real_pipe = os.pipe

    def failed_pipe():                       # the child's report: the cgroup step, EPERM
        r, w = real_pipe()
        os.write(w, b"cgroup 1")
        return r, w
    monkeypatch.setattr(vc.os, "pipe", failed_pipe)
    monkeypatch.setattr(vc.os, "fork", lambda: 1 << 22)
    monkeypatch.setattr(vc.os, "waitpid", lambda pid, f: (pid, 0))
    lv, _, fix = vc.probe_mounts("/sys/fs/cgroup", noexec=False, rootless=True)[0]
    assert lv == "fail" and fix.startswith("--systemd=always")
    lv, _, fix = vc.probe_mounts("/sys/fs/cgroup", noexec=False, rootless=False)[0]
    assert lv == "fail" and not fix.startswith("--systemd=always")


def test_in_container():
    assert vc.in_container({}, exists=lambda p: p == "/.dockerenv") == "docker"
    assert vc.in_container({}, exists=lambda p: p == "/run/.containerenv") == "podman"
    assert vc.in_container({"container": "podman"}, exists=lambda p: False) == "podman"
    assert vc.in_container({}, exists=lambda p: False) is None
    assert vc.in_container({"VAREK_DOCTOR_CONTAINER": "test"}, exists=lambda p: False) == "test"


def test_for_run_counts_what_the_run_needs(monkeypatch):
    """the preflight's share: capabilities always; control groups only for a
    policy with sub-agents or MCP servers; the mount test when the run mounts"""
    probed = []
    monkeypatch.setattr(vc, "in_container", lambda: "docker")
    monkeypatch.setattr(vc, "probe_mounts", lambda cg=None, noexec=True, rootless=False: probed.append(cg) or [("ok", "mounts", None)])
    shared = (status(), "varek-container (enforce)", CG_RO, "0::/system.slice/x\n", ROOTFUL)
    monkeypatch.setattr(vc, "_state", lambda: shared)
    monkeypatch.setattr(vc, "_userns", lambda: False)
    assert vc.for_run(cgroups=False, mounts=True) == [] and probed == [None]
    lacks = vc.for_run(cgroups=True, mounts=True)
    assert [f for _, f in lacks] == ["--cgroupns=private"]
    monkeypatch.setattr(vc, "_state", lambda: (status(TEN & ~(1 << 19)), *shared[1:]))
    lacks = vc.for_run(cgroups=False, mounts=False)
    assert [f for _, f in lacks] == ["--cap-add SYS_PTRACE"] and len(probed) == 2
    # v1.32 review: docker-default refuses only a run that mounts
    monkeypatch.setattr(vc, "_state", lambda: (status(), "docker-default (enforce)", *shared[2:]))
    assert vc.for_run(cgroups=False, mounts=False) == [] and len(probed) == 2
    assert "AppArmor profile docker-default" in vc.for_run(cgroups=False, mounts=True)[0][0]
    monkeypatch.setattr(vc, "in_container", lambda: None)
    assert vc.for_run(cgroups=True, mounts=True) == []


def test_the_probe_mounts_only_what_the_run_does(monkeypatch):
    """v1.32 second review: a run that mounts nothing noexec makes no test
    directory (a read-only /tmp is no reason to refuse it)"""
    monkeypatch.setattr(vc.os, "geteuid", lambda: 0)
    monkeypatch.setattr(vc.tempfile, "mkdtemp", lambda **k: (_ for _ in ()).throw(OSError(30, "ro")))
    assert vc.probe_mounts(None, noexec=False) == []
    assert "cannot make a directory" in vc.probe_mounts(None, noexec=True)[0][1]


def test_userns_on_a_kernel_without_them(monkeypatch):
    """v1.32 second review: no /proc/self/ns/user is no user namespace, as
    the Warden takes it (sub_in_userns, which names --systemd=always where
    the remount is refused in one)"""
    def gone(p):
        raise FileNotFoundError(2, "no", p)
    monkeypatch.setattr(vc.os, "stat", gone)
    assert vc._userns() is False


def test_the_probe_never_returns_in_the_child(monkeypatch):
    """v1.32 review: whatever the child raises, it exits there; the parent
    removes its own directory only"""
    monkeypatch.setattr(vc.os, "geteuid", lambda: 0)
    import tempfile
    other = tempfile.mkdtemp(prefix="varek-doctor.")
    try:
        out = vc.probe_mounts()
        assert out and out[0][0] in ("ok", "fail")
        assert os.path.isdir(other)
    finally:
        os.rmdir(other)
