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


def status(caps=TEN, seccomp=2):
    return f"Name:\tpython3\nCapBnd:\t{caps:016x}\nSeccomp:\t{seccomp}\n"


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
    assert find(run(mounts=""), "no cgroup v2")[0][0] == "warn"


def test_rootless_is_said():
    assert find(run(uid_map="0 1000 1\n1 100000 65536\n"), "rootless")[0][0] == "warn"
    assert not find(run(), "rootless")


def test_in_container():
    assert vc.in_container({}, exists=lambda p: p == "/.dockerenv") == "docker"
    assert vc.in_container({}, exists=lambda p: p == "/run/.containerenv") == "podman"
    assert vc.in_container({"container": "podman"}, exists=lambda p: False) == "podman"
    assert vc.in_container({}, exists=lambda p: False) is None
    assert vc.in_container({"VAREK_DOCTOR_CONTAINER": "test"}, exists=lambda p: False) == "test"
