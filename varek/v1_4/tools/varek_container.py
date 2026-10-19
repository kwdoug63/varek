# SPDX-License-Identifier: MIT
"""varek_container: `varek doctor` in a container (v1.32, D11 in
docs/security/v1.32-containers.md).

Each setting the Warden needs of its container (packaging/container/README.md)
checked, the missing one named with the flag that grants it:

  - the ten capabilities, in the bounding set the runtime gives
    (--cap-drop ALL --cap-add ...), and none beyond them;
  - the runtime's default seccomp profile, on;
  - the AppArmor profile (varek-container) or the SELinux type
    (container_init_t);
  - a cgroup namespace of the container's own (--cgroupns=private), where the
    cgroup filesystem is read-only;
  - a test of the Warden's own mounts, in a child: a mount namespace made
    private, a directory bound onto itself and remounted noexec, and the
    cgroup filesystem remounted read-write where the run would.

settings() reads the container's state from text (the pure part, tested by
tests/test_varek_container.py); probe_mounts() makes the mounts. for_run() is
the preflight's share, which `varek run` refuses on before the agent starts;
run as a program it prints the findings for tools/varek_preflight.sh.
"""
import ctypes
import errno
import os
import sys
import tempfile

# the capabilities the Warden needs (packaging/container/README.md), by number
NEEDED = {
    21: ("SYS_ADMIN", "the agent's namespaces and the noexec mounts"),
    19: ("SYS_PTRACE", "taking the agent's descriptors (pidfd_getfd) and reading its memory"),
    8: ("SETPCAP", "emptying the agent's capability bounding set"),
    7: ("SETUID", "dropping the agent and the helpers to their own users"),
    6: ("SETGID", "dropping the agent and the helpers to their own groups"),
    1: ("DAC_OVERRIDE", "opening, as root, the files the policy lets the agent reach"),
    5: ("KILL", "ending the agent's processes, which run as another user"),
    12: ("NET_ADMIN", "the loopback in the agent's network namespace, for the DNS stub"),
    10: ("NET_BIND_SERVICE", "the DNS stub on port 53"),
    0: ("CHOWN", "`varek run` giving the agent its temporary directory"),
}
NAMES = {
    0: "CHOWN", 1: "DAC_OVERRIDE", 2: "DAC_READ_SEARCH", 3: "FOWNER", 4: "FSETID", 5: "KILL", 6: "SETGID",
    7: "SETUID", 8: "SETPCAP", 9: "LINUX_IMMUTABLE", 10: "NET_BIND_SERVICE", 11: "NET_BROADCAST",
    12: "NET_ADMIN", 13: "NET_RAW", 14: "IPC_LOCK", 15: "IPC_OWNER", 16: "SYS_MODULE", 17: "SYS_RAWIO",
    18: "SYS_CHROOT", 19: "SYS_PTRACE", 20: "SYS_PACCT", 21: "SYS_ADMIN", 22: "SYS_BOOT", 23: "SYS_NICE",
    24: "SYS_RESOURCE", 25: "SYS_TIME", 26: "SYS_TTY_CONFIG", 27: "MKNOD", 28: "LEASE", 29: "AUDIT_WRITE",
    30: "AUDIT_CONTROL", 31: "SETFCAP", 32: "MAC_OVERRIDE", 33: "MAC_ADMIN", 34: "SYSLOG", 35: "WAKE_ALARM",
    36: "BLOCK_SUSPEND", 37: "AUDIT_READ", 38: "PERFMON", 39: "BPF", 40: "CHECKPOINT_RESTORE",
}
APPARMOR_FIX = ("on the host: install -m 644 packaging/container/apparmor/varek-container /etc/apparmor.d/ && "
                "apparmor_parser -r -W /etc/apparmor.d/varek-container; then --security-opt apparmor=varek-container")
SELINUX_FIX = ("on the host: semodule -i packaging/container/selinux/varek_container.cil; then "
               "--security-opt label=type:container_init_t")


def in_container(environ=None, exists=os.path.exists):
    """docker, podman, or None (VAREK_DOCTOR_CONTAINER names one for the tests)"""
    env = os.environ if environ is None else environ
    if env.get("VAREK_DOCTOR_CONTAINER"):
        return env["VAREK_DOCTOR_CONTAINER"]
    if exists("/run/.containerenv") or env.get("container") == "podman":
        return "podman"
    if exists("/.dockerenv"):
        return "docker"
    if env.get("container"):
        return env["container"]
    return None


def _field(status, name):
    for ln in status.splitlines():
        if ln.startswith(name + ":"):
            return ln.split(":", 1)[1].strip()
    return None


def _cgroup2(mounts):
    """(mount point, read-only) of the first cgroup2 mount, or (None, False)"""
    for ln in mounts.splitlines():
        p = ln.split()
        if len(p) > 3 and p[2] == "cgroup2":
            return p[1], "ro" in p[3].split(",")
    return None, False


def settings(status, label, mounts, cgroup, uid_map="", cgroups=True, noexec=True, userns=None):
    """The container's settings, from /proc/self/status, the LSM label
    (/proc/self/attr/current), /proc/self/mounts, /proc/self/cgroup and
    /proc/self/uid_map: [(level, text, fix)], level "ok", "warn" or "fail".
    cgroups: control groups are needed (a policy with sub-agents or MCP
    servers, or not known); without, their absence is a warning. noexec: the
    Warden mounts the writable directories noexec (`vdp_check POLICY mounts`,
    or not known); a profile that denies mounts fails only when the run mounts
    (noexec or cgroups), and warns otherwise. userns: a user namespace (from
    /proc/self/ns/user), or None to tell from uid_map. The capabilities are
    the effective set as root, which is what the Warden holds, and the
    bounding set otherwise."""
    out = []
    bnd, eff = _field(status, "CapBnd"), _field(status, "CapEff")
    have = int(bnd, 16) if bnd else 0
    if eff is not None and os.geteuid() == 0:
        have &= int(eff, 16)
    missing = [n for n in sorted(NEEDED) if not have >> n & 1]
    for n in missing:
        name, why = NEEDED[n]
        out.append(("fail", f"capability {name} is missing: {why}", f"--cap-add {name}"))
    if not missing:
        out.append(("ok", f"the {len(NEEDED)} capabilities the Warden needs", None))
    extra = [NAMES.get(n, str(n)) for n in range(64) if have >> n & 1 and n not in NEEDED]
    if len(extra) >= 25:
        out.append(("warn", f"{len(extra)} capabilities beyond the Warden's ten (--privileged?)",
                    "never --privileged: --cap-drop ALL and the ten --cap-add"))
    elif extra:
        out.append(("warn", "capabilities beyond the Warden's ten: " + ", ".join(extra),
                    "--cap-drop ALL, then only the ten (the agent holds none either way)"))

    sc = _field(status, "Seccomp")
    if sc == "2":
        out.append(("ok", "the runtime's seccomp profile is on", None))
    elif sc == "0":
        out.append(("warn", "no seccomp profile on the container (seccomp=unconfined)",
                    "drop --security-opt seccomp=unconfined: the runtime's default profile suffices"))

    lab = (label or "").strip().rstrip("\x00")
    if ":" in lab and "(" not in lab:                                   # SELinux: user:role:type:level
        t = lab.split(":")[2] if len(lab.split(":")) > 2 else lab
        if t == "container_init_t":
            out.append(("ok", "SELinux type container_init_t (the mount test below shows the host's module)", None))
        elif t == "container_t":
            out.append(("warn", "SELinux type container_t: sub-agents and confined MCP servers cannot make their "
                        "control groups", SELINUX_FIX))
        elif t in ("spc_t", "unconfined_t"):
            out.append(("warn", f"SELinux type {t}: the container is not confined (label=disable or --privileged?)",
                        SELINUX_FIX))
        else:
            out.append(("warn", f"SELinux type {t}: not one the settings were measured with", SELINUX_FIX))
    elif lab == "unconfined" or " (" in lab:                            # AppArmor: name (mode)
        name = lab.split(" (")[0]
        if name.startswith("varek-container"):
            out.append(("ok", f"AppArmor profile {name}", None))
        elif name == "docker-default" or name.startswith("containers-default"):
            out.append(("fail" if noexec or cgroups else "warn", f"AppArmor profile {name}: it denies every mount, "
                        "so the Warden cannot mount the agent's writable directories noexec nor remount the cgroup "
                        "filesystem", APPARMOR_FIX))
        elif name == "unconfined":
            out.append(("warn", "no AppArmor profile on the container (apparmor=unconfined)", APPARMOR_FIX))
        else:
            out.append(("warn", f"AppArmor profile {name}: not one the settings were measured with", APPARMOR_FIX))

    rootless = _rootless(uid_map) if userns is None else userns
    cg, ro = _cgroup2(mounts)
    self_cg = next((ln[3:] for ln in cgroup.splitlines() if ln.startswith("0::")), None)
    if cg is None:
        out.append(("fail" if cgroups else "warn", "no cgroup v2 here: a policy that names a sub-agent or an "
                    "MCP server will not start",
                    "a host with cgroup v2 (the unified hierarchy)"))
    elif ro and self_cg != "/":
        out.append(("fail" if cgroups else "warn", f"the cgroup filesystem {cg} is read-only and this container shares the host's cgroup "
                    "namespace: sub-agents and confined MCP servers cannot have control groups", "--cgroupns=private"))
    elif ro and rootless:
        # in a user namespace the Warden does not remount it (D10; sub_container_cgroup)
        out.append(("fail" if cgroups else "warn", f"the cgroup filesystem {cg} is read-only and the container "
                    "is rootless, where the Warden does not remount it: sub-agents and confined MCP servers cannot "
                    "have control groups", "--systemd=always (Podman then mounts the container's own groups read-write)"))
    elif ro:
        out.append(("ok", f"cgroup v2 at {cg}, read-only, the container's own namespace: a run remounts it "
                    "read-write for itself", None))
    else:
        out.append(("ok", f"cgroup v2 at {cg}", None))

    if rootless:
        out.append(("ok", "rootless (a user namespace): root in the container is a user on the host", None))
    return out


# mount(2) and statvfs flags (linux/mount.h, sys/statvfs.h)
MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC, MS_REMOUNT = 1, 2, 4, 8, 32
MS_NOSYMFOLLOW, MS_NOATIME, MS_NODIRATIME, MS_BIND, MS_REC = 256, 1024, 2048, 4096, 16384
MS_PRIVATE, MS_RELATIME = 1 << 18, 1 << 21
ST_FLAGS = ((1, MS_RDONLY), (2, MS_NOSUID), (4, MS_NODEV), (1024, MS_NOATIME), (2048, MS_NODIRATIME),
            (4096, MS_RELATIME), (8192, MS_NOSYMFOLLOW))


def _keep(path):
    f = os.statvfs(path).f_flag
    return sum(ms for st, ms in ST_FLAGS if f & st)


def probe_mounts(cgroup_mount=None, noexec=True):
    """The Warden's mounts, made in a child (so this process keeps its own
    namespace) as root: [(level, text, fix)]; [] when not root. A directory
    mounted noexec when the run mounts them (noexec); the cgroup filesystem
    bind-remounted and then found read-write, as the Warden does
    (sub_cg_remount)."""
    if os.geteuid() != 0 or not (noexec or cgroup_mount):
        return []
    d = None
    if noexec:
        try:
            d = tempfile.mkdtemp(prefix="varek-doctor.")
        except OSError as e:
            return [("fail", f"a test of the Warden's mounts: cannot make a directory in {tempfile.gettempdir()} "
                     f"({errno.errorcode.get(e.errno, e.errno)})", "a writable /tmp (--tmpfs /tmp)")]
    try:
        r, w = os.pipe()
        sys.stdout.flush()
        sys.stderr.flush()
        pid = os.fork()
    except OSError as e:
        if d:
            os.rmdir(d)
        return [("fail", f"a test of the Warden's mounts: cannot start it ({errno.errorcode.get(e.errno, e.errno)})",
                 None)]
    if pid == 0:
        code = 2
        try:
            os.close(r)
            libc = ctypes.CDLL(None, use_errno=True)
            libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong,
                                   ctypes.c_void_p]

            def step(name, rc):
                if rc != 0:
                    os.write(w, f"{name} {ctypes.get_errno()}".encode())
                    os._exit(1)
            step("unshare", libc.unshare(0x20000))                         # CLONE_NEWNS
            step("private", libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None))
            if d:
                b = d.encode()
                step("bind", libc.mount(b, b, None, MS_BIND | MS_REC, None))
                step("noexec", libc.mount(None, b, None, MS_BIND | MS_REMOUNT | MS_NOEXEC | _keep(d), None))
            if cgroup_mount:
                c = cgroup_mount.encode()
                step("cgroup", libc.mount(None, c, None, MS_BIND | MS_REMOUNT | MS_NOEXEC |
                                          (_keep(cgroup_mount) & ~MS_RDONLY), None))
                if os.statvfs(cgroup_mount).f_flag & 1:                    # ST_RDONLY: still, as the Warden checks
                    os.write(w, f"cgroup {errno.EROFS}".encode())
                    os._exit(1)
            os.write(w, b"ok 0")
            code = 0
        finally:                                                            # never back into the caller
            os._exit(code)
    os.close(w)
    try:
        msg = os.read(r, 64).decode() or "error 0"
    finally:
        os.close(r)
        os.waitpid(pid, 0)
        try:
            if d:
                os.rmdir(d)                                                 # this probe's own directory
        except OSError:
            pass
    what, _, e = msg.partition(" ")
    err = errno.errorcode.get(int(e or 0), e)
    if what == "ok":
        return [("ok", "a test of the Warden's mounts: a mount namespace of its own" +
                 (", a directory mounted noexec" if d else "") +
                 (", the cgroup filesystem remounted read-write" if cgroup_mount else ""), None)]
    fixes = {
        "unshare": ("cannot make a mount namespace", "--cap-add SYS_ADMIN"),
        "private": ("cannot make the mount namespace private", APPARMOR_FIX + " (or, under SELinux, " + SELINUX_FIX + ")"),
        "bind": ("cannot bind a directory onto itself", APPARMOR_FIX),
        "noexec": ("cannot remount a directory noexec", APPARMOR_FIX),
        "cgroup": ("cannot remount the cgroup filesystem read-write (sub-agents and confined MCP servers)",
                   SELINUX_FIX + " (under AppArmor: " + APPARMOR_FIX + ")"),
    }
    text, fix = fixes.get(what, ("the mount test failed", None))
    return [("fail", f"a test of the Warden's mounts: {text} ({err})", fix)]


def _rootless(uid_map):
    first = uid_map.strip().splitlines()[0].split() if uid_map.strip() else []
    return bool(first) and first != ["0", "0", "4294967295"]


def _state():
    def read(p):
        try:
            with open(p) as f:
                return f.read()
        except OSError:
            return ""
    label = read("/proc/self/attr/apparmor/current") or read("/proc/self/attr/current")
    return read("/proc/self/status"), label, read("/proc/self/mounts"), read("/proc/self/cgroup"), \
        read("/proc/self/uid_map")


def _userns():
    """in a user namespace: the initial one's inode is fixed
    (PROC_USER_INIT_INO), as the Warden tells (sub_in_userns)"""
    try:
        return os.stat("/proc/self/ns/user").st_ino != 0xEFFFFFFD
    except FileNotFoundError:
        return False                    # a kernel without user namespaces, as the Warden takes it
    except OSError:
        return None


def check(cgroups=True, noexec=True):
    """Everything, as the run would need it: [(level, text, fix)], or []
    outside a container. `varek doctor` asks for all (the policy is not
    known); the preflight, for its policy's (--cgroups, --noexec). The mount
    test when the run mounts or makes control groups."""
    if not in_container():
        return []
    status, label, mounts, cgroup, uid_map = _state()
    userns = _userns()
    rootless = _rootless(uid_map) if userns is None else userns
    out = settings(status, label, mounts, cgroup, uid_map, cgroups, noexec, rootless)
    if noexec or cgroups:
        cg, ro = _cgroup2(mounts)
        self_cg = next((ln[3:] for ln in cgroup.splitlines() if ln.startswith("0::")), None)
        out += probe_mounts(cg if cgroups and cg and ro and self_cg == "/" and not rootless else None, noexec)
    return out


def for_run(cgroups, mounts):
    """The preflight's share: what this run needs of its container that the
    container lacks, [(text, fix)]; [] outside a container or when it has
    all. cgroups: the policy names a sub-agent or an MCP server; mounts: the
    Warden mounts the writable directories noexec (`vdp_check POLICY
    mounts`, and no --writable-exec). Capabilities always; the profile and the mount test
    when the run mounts or makes control groups."""
    return [(t, f) for lv, t, f in check(cgroups, mounts) if lv == "fail"]


if __name__ == "__main__":
    # tools/varek_preflight.sh: --in-container (exit 0 when in one), or
    # --preflight [--cgroups] [--noexec]: each finding as LEVEL<tab>TEXT<tab>FIX
    if "--in-container" in sys.argv:
        sys.exit(0 if in_container() else 1)
    for lv, t, f in check(cgroups="--cgroups" in sys.argv, noexec="--noexec" in sys.argv):
        print(f"{lv}\t{t}\t{f or ''}")
