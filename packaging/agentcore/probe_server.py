#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The AgentCore Runtime probe (v1.35 step 1, D8; docs/security/v1.35-frameworks.md).

What AgentCore Runtime's container holds, measured from inside it, and then
the Warden supervising an agent there. AgentCore Runtime's API gives a
container no settings but its image, so this is the only way to know.

The container contract AgentCore Runtime runs: HTTP on port 8080,
`GET /ping` answering that the agent is healthy, and `POST /invocations`
answering an invocation. Each invocation runs the probe and answers with its
report (JSON). It reads no secret: of the environment it reports the
variables' names only, never their values.

Run locally (as root, to compare with a host):  python3 probe_server.py --once
"""
import ctypes
import ctypes.util
import errno
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long

# Numbers that differ by architecture; the newer calls (pidfd_open 434,
# pidfd_getfd 438, landlock_create_ruleset 444) are the same on both.
NR = {"x86_64": {"seccomp": 317}, "aarch64": {"seccomp": 277}}.get(platform.machine(), {})
CLONE = {"user": 0x10000000, "mount": 0x00020000, "pid": 0x20000000, "net": 0x40000000,
         "cgroup": 0x02000000, "ipc": 0x08000000, "uts": 0x04000000}
PR_SET_NO_NEW_PRIVS = 38
SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3
SECCOMP_RET_ALLOW = 0x7FFF0000


def err(e):
    return f"{errno.errorcode.get(e, e)} ({os.strerror(e)})"


def read(path, limit=4096):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit).strip()
    except OSError as e:
        return f"unreadable: {err(e.errno)}"


def in_child(fn):
    """Run fn() in a forked child (a namespace or a filter must not touch the
    server); the child's answer comes back through a pipe as JSON."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            out = fn()
        except Exception as e:                     # report, never crash the child silently
            out = f"error: {e!r}"
        os.write(w, json.dumps(out).encode())
        os._exit(0)
    os.close(w)
    data = b""
    while True:
        b = os.read(r, 65536)
        if not b:
            break
        data += b
    os.close(r)
    os.waitpid(pid, 0)
    try:
        return json.loads(data.decode() or "null")
    except ValueError:
        return "error: no answer from the child"


def status():
    keep = ("Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
            "NoNewPrivs", "Seccomp", "Seccomp_filters")
    out = {}
    for line in read("/proc/self/status", 1 << 16).splitlines():
        k, _, v = line.partition(":")
        if k in keep:
            out[k] = v.strip()
    return out


def caps_named(hexmask):
    names = ["chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid",
             "setuid", "setpcap", "linux_immutable", "net_bind_service", "net_broadcast",
             "net_admin", "net_raw", "ipc_lock", "ipc_owner", "sys_module", "sys_rawio",
             "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
             "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write",
             "audit_control", "setfcap", "mac_override", "mac_admin", "syslog", "wake_alarm",
             "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore"]
    try:
        m = int(hexmask, 16)
    except (TypeError, ValueError):
        return []
    return [n for i, n in enumerate(names) if m >> i & 1]


def landlock_abi():
    v = libc.syscall(444, None, 0, 1)            # LANDLOCK_CREATE_RULESET_VERSION
    return v if v >= 0 else err(ctypes.get_errno())


def seccomp_listener(no_new_privs):
    """Can this container load a filter that hands calls to a supervisor
    (SECCOMP_FILTER_FLAG_NEW_LISTENER), as the Warden's agent does?"""
    def go():
        if "seccomp" not in NR:
            return f"not measured on {platform.machine()}"
        if no_new_privs and libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            return "prctl(NO_NEW_PRIVS): " + err(ctypes.get_errno())

        class SockFilter(ctypes.Structure):
            _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                        ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]

        class SockFprog(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]

        prog = (SockFilter * 1)(SockFilter(0x06, 0, 0, SECCOMP_RET_ALLOW))   # BPF_RET|BPF_K: allow
        fp = SockFprog(1, prog)
        fd = libc.syscall(NR["seccomp"], SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER,
                          ctypes.byref(fp))
        return f"loaded, listener fd {fd}" if fd >= 0 else err(ctypes.get_errno())
    return in_child(go)


def namespace(name):
    def go():
        return "made" if libc.unshare(CLONE[name]) == 0 else err(ctypes.get_errno())
    return in_child(go)


def peer_access():
    """What the Warden does to its agent: a pidfd, a descriptor taken from it
    (pidfd_getfd), and its memory read (process_vm_readv)."""
    buf = ctypes.create_string_buffer(b"varek-probe-memory")
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(w)
        os.read(r, 1)                              # wait for the parent's reads
        os._exit(0)
    os.close(r)
    out = {}
    pfd = libc.syscall(434, pid, 0)
    out["pidfd_open"] = "ok" if pfd >= 0 else err(ctypes.get_errno())
    if pfd >= 0:
        fd = libc.syscall(438, pfd, 0, 0)
        out["pidfd_getfd"] = "ok" if fd >= 0 else err(ctypes.get_errno())
        if fd >= 0:
            os.close(fd)
        os.close(pfd)

    class Iovec(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]

    dst = ctypes.create_string_buffer(len(buf))
    local = Iovec(ctypes.cast(dst, ctypes.c_void_p), len(buf))
    remote = Iovec(ctypes.cast(buf, ctypes.c_void_p), len(buf))   # the child's copy, same address
    n = libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    out["process_vm_readv"] = ("ok" if dst.raw == buf.raw else "read other bytes") if n >= 0 \
        else err(ctypes.get_errno())
    os.write(w, b"x")
    os.close(w)
    os.waitpid(pid, 0)
    return out


def cgroups():
    out = {"self": read("/proc/self/cgroup"),
           "fs": next((ln.split()[2] for ln in read("/proc/self/mounts", 1 << 20).splitlines()
                       if ln.split()[1:2] == ["/sys/fs/cgroup"]), "not mounted")}
    rel = out["self"].split("::", 1)[1].strip() if "::" in out["self"] else ""
    here = os.path.join("/sys/fs/cgroup", rel.lstrip("/"))
    out["controllers"] = read(os.path.join(here, "cgroup.controllers"))
    out["subtree_control"] = read(os.path.join(here, "cgroup.subtree_control"))
    probe = os.path.join(here, "varek-probe")
    try:
        os.mkdir(probe)
        os.rmdir(probe)
        out["make_group"] = "ok"
    except OSError as e:
        out["make_group"] = err(e.errno)
    return out


def mounts():
    keep = ("/", "/tmp", "/proc", "/sys", "/sys/fs/cgroup", "/dev", "/var/log/varek")
    out = {}
    for ln in read("/proc/self/mountinfo", 1 << 20).splitlines():
        f = ln.split()
        if len(f) > 9 and f[4] in keep:
            sep = f.index("-")
            out[f[4]] = {"options": f[5], "type": f[sep + 1], "source": f[sep + 2]}
    try:
        p = "/.varek-probe"
        with open(p, "w") as fh:
            fh.write("x")
        os.unlink(p)
        out["root_writable"] = True
    except OSError as e:
        out["root_writable"] = err(e.errno)
    return out


def run(cmd, timeout=120):
    t = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        rc, o, e = r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return {"cmd": cmd, "error": "not found"}
    except subprocess.TimeoutExpired as x:
        rc, o, e = "timeout", x.stdout or "", x.stderr or ""
        o, e = (o.decode(errors="replace") if isinstance(o, bytes) else o,
                e.decode(errors="replace") if isinstance(e, bytes) else e)
    return {"cmd": " ".join(cmd), "exit": rc, "seconds": round(time.monotonic() - t, 2),
            "stdout_tail": o.splitlines()[-15:], "stderr_tail": e.splitlines()[-40:]}


def report():
    st = status()
    rep = {
        "probe": "varek agentcore probe 1",
        "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "machine": platform.machine(),
        "kernel": platform.release(),
        "os_release": read("/etc/os-release").splitlines()[:3],
        "pid": os.getpid(), "ppid": os.getppid(),
        "pid1": read("/proc/1/cmdline").replace("\0", " "),
        "cpus": os.cpu_count(),
        "memory": next((ln for ln in read("/proc/meminfo").splitlines() if ln.startswith("MemTotal")), "?"),
        "status": st,
        "capabilities_effective": caps_named(st.get("CapEff")),
        "capabilities_bounding": caps_named(st.get("CapBnd")),
        "lsm": read("/sys/kernel/security/lsm"),
        "landlock_abi": landlock_abi(),
        "seccomp_listener": seccomp_listener(False),
        "seccomp_listener_after_no_new_privs": seccomp_listener(True),
        "namespaces": {n: namespace(n) for n in CLONE},
        "max_user_namespaces": read("/proc/sys/user/max_user_namespaces"),
        "ptrace_scope": read("/proc/sys/kernel/yama/ptrace_scope"),
        "peer": peer_access(),
        "cgroups": cgroups(),
        "mounts": mounts(),
        "environment_names": sorted(os.environ),        # names only, never values
    }
    varek = shutil.which("varek")
    if varek:
        rep["varek_doctor"] = run([varek, "doctor"])
        # the Warden supervising an agent here, under the baseline policy
        # (v1.29: varek run with nothing set up)
        log = f"/tmp/varek-probe-{int(time.time())}.log"
        rep["varek_run"] = run([varek, "run", "--log", log, "--", "/bin/cat", "/etc/os-release"])
        rep["varek_refusals"] = run([varek, "refusals", log])
    else:
        rep["varek"] = "not in this image"
    return rep


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/ping":
            self._send(200, {"status": "Healthy", "time_of_last_update": int(time.time())})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(min(n, 1 << 20))         # the payload is not used
        if self.path == "/invocations":
            self._send(200, report())
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):            # to CloudWatch through stderr
        sys.stderr.write("[probe] " + (fmt % args) + "\n")


if __name__ == "__main__":
    if "--once" in sys.argv:
        print(json.dumps(report(), indent=1))
        sys.exit(0)
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
