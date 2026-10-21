#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""varek_vm.py — v1.30 (docs/security/v1.30-macos.md, step 4): VAREK on a Mac
with Apple silicon, through a Linux VM.

The VM runs on Apple's Virtualization framework, launched by vfkit, with a
RHEL 9 arm64 guest (9.6 or later; or a rebuild of it). The agent runs inside
it under the Warden as on Linux. The Mac shares one directory with the VM,
the project, mounted at the same path inside; never the home directory or a
directory holding it.

  varek vm init --image FILE --sha256 HEX
                               make the VM from a RHEL 9 aarch64 KVM guest
                               image (qcow2 or raw), and set it up: the
                               Warden built and installed inside
  varek vm start [DIR]         start it with DIR (default: the working
                               directory) shared
  varek vm run [ARGS] -- CMD   `varek run` inside, on the working directory
  varek vm ssh [CMD]           a shell (or CMD) inside, as the VM's user
  varek vm stop | status

What it needs on the Mac: vfkit and qemu-img (`brew install vfkit qemu`),
ssh and ssh-keygen. The RHEL image is downloaded by the user from Red Hat
(access.redhat.com, with their own login), and the guest registered with
their own subscription: varek never asks for or holds a Red Hat password.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))
SRC_ROOT = os.path.realpath(os.path.join(HERE, "..", "..", ".."))   # the VAREK checkout
USER = "varek"                      # the VM's user (sudo); the agent runs as it under varek run
LEASES = "/var/db/dhcpd_leases"     # macOS vmnet's DHCP leases (the VM's address by its MAC)
VM_ROOT = os.path.expanduser(os.environ.get("VAREK_VM_DIR", "~/.varek/vm"))


class VmError(Exception):
    def __init__(self, msg, fix=None):
        super().__init__(msg)
        self.fix = fix


# ------------------------------------------------------------------ pure --

def check_share(path, home=None, refuse=()):
    """the directory to share with the VM, resolved; refused: a non-directory,
    the home directory or any directory holding it, a directory in a hidden
    one of the home directory's (~/.ssh, ~/.varek...) or in its Library
    (keychains, mail, browsers' profiles), a volume's root, the
    system's directories, and each directory in refuse (the VMs' own, the
    VAREK checkout) or one holding it. Compared by the file, not its name:
    the Mac's file system folds case, and firmlinks (/System/Volumes/Data)
    give the same directory a second name."""
    home = os.path.realpath(home or os.path.expanduser("~"))
    p = os.path.realpath(path)
    if not os.path.isdir(p):
        raise VmError(f"{path} is not a directory", fix="share the project directory")
    fix = "share the project directory itself, e.g. ~/src/project"
    st = os.stat(p)

    def holds(d):
        """p is d or a directory holding d"""
        d = os.path.realpath(d)
        while True:
            try:
                if os.path.samestat(os.stat(d), st):
                    return True
            except OSError:
                pass
            up = os.path.dirname(d)
            if up == d:
                return False
            d = up
    if p == "/" or os.path.ismount(p) or holds(home):
        raise VmError(f"{p} would share the home directory or more with the VM", fix=fix)
    low = p.lower().rstrip("/") + "/"
    if low.startswith(("/system/", "/library/", "/private/", "/users/shared/", "/applications/", "/usr/",
                       "/bin/", "/sbin/", "/etc/", "/opt/homebrew/")) or low in ("/users/", "/volumes/"):
        raise VmError(f"{p} is a system directory", fix=fix)
    for r in refuse:
        if r and os.path.exists(r) and (holds(r) or _under(p, r)):
            raise VmError(f"{p} would share {r} with the VM", fix=fix)
    # a directory in one of the home directory's hidden directories
    d = p
    while True:
        up = os.path.dirname(d)
        if up == d:
            break
        try:
            b = os.path.basename(d)
            if os.path.samestat(os.stat(up), os.stat(home)) and (b.startswith(".") or b.lower() == "library"):
                raise VmError(f"{p} is in a hidden directory of the home directory's, or its Library ({d})", fix=fix)
        except OSError:
            pass
        d = up
    return p


def _under(p, r):
    """p is r or under it, by the file"""
    rs = os.stat(r)
    d = p
    while True:
        try:
            if os.path.samestat(os.stat(d), rs):
                return True
        except OSError:
            pass
        up = os.path.dirname(d)
        if up == d:
            return False
        d = up


def new_mac(rand=secrets.token_bytes):
    """a locally administered unicast MAC address for the VM's network device"""
    b = bytearray(rand(6))
    b[0] = (b[0] | 0x02) & 0xFE
    return ":".join(f"{x:02x}" for x in b)


def norm_mac(s):
    """a MAC address as 6 two-digit lower-case octets (vmnet's leases drop
    leading zeros: 5a:4:0:1:2:3)"""
    parts = s.strip().lower().split(":")
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(x, 16):02x}" for x in parts)
    except ValueError:
        return None


def parse_leases(text):
    """{mac: ip} from /var/db/dhcpd_leases, the latest lease for each MAC"""
    out, best = {}, {}
    for block in re.findall(r"\{(.*?)\}", text, re.S):
        kv = dict(re.findall(r"^\s*(\w+)=(.*)$", block, re.M))
        hw = kv.get("hw_address", "")
        mac = norm_mac(hw.split(",", 1)[1] if "," in hw else hw)
        ip = kv.get("ip_address")
        try:
            t = int(kv.get("lease", "0"), 16)
        except ValueError:
            t = 0
        if mac and ip and t >= best.get(mac, -1):
            out[mac], best[mac] = ip.strip(), t
    return out


def user_data(pubkey, hostname):
    """cloud-init user data: the VM's user with the key varek made, and
    nothing else (no password; registration is the user's own)"""
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+( [\w@.-]+)?", pubkey.strip()):
        raise VmError("the VM's public key is not an ed25519 key")
    return ("#cloud-config\n"
            f"hostname: {hostname}\n"
            "users:\n"
            f"  - name: {USER}\n"
            "    gecos: VAREK\n"
            "    groups: [wheel]\n"
            "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
            "    shell: /bin/bash\n"
            "    lock_passwd: true\n"
            "    ssh_authorized_keys:\n"
            f"      - {pubkey.strip()}\n"
            "ssh_pwauth: false\n"
            "disable_root: true\n"
            "growpart:\n  mode: auto\n  devices: ['/']\n")


def meta_data(instance_id, hostname):
    return f"instance-id: {instance_id}\nlocal-hostname: {hostname}\n"


def vfkit_argv(vfkit, vmdir, cfg, shares=(), cloud_init=None):
    """vfkit's command line: EFI boot from the raw disk, NAT networking with
    the VM's MAC, a serial log, an entropy source, and each share (path, tag)
    over virtio-fs; cloud-init's files on the first boot only"""
    efi = os.path.join(vmdir, "efi-variable-store")
    a = [vfkit, "--cpus", str(cfg["cpus"]), "--memory", str(cfg["memory_mib"]),
         "--bootloader", f"efi,variable-store={efi}" + ("" if os.path.exists(efi) else ",create"),
         "--device", f"virtio-blk,path={os.path.join(vmdir, 'disk.raw')}",
         "--device", f"virtio-net,nat,mac={_mac(cfg)}",
         "--device", "virtio-rng",
         "--device", f"virtio-serial,logFilePath={os.path.join(vmdir, 'serial.log')}"]
    for path, tag in shares:
        if "," in path or not re.fullmatch(r"[a-z][a-z0-9-]{0,35}", tag):
            raise VmError(f"cannot share {path} as {tag}: a path with a comma (vfkit's separator), "
                          "or a tag that is not a short lower-case name",
                          fix="share a directory whose path has no comma")
        a += ["--device", f"virtio-fs,sharedDir={path},mountTag={tag}"]
    if cloud_init:
        a += ["--cloud-init", ",".join(cloud_init)]
    return a


def _mac(cfg):
    m = norm_mac(str(cfg.get("mac", "")))
    if not m:
        raise VmError("the VM's MAC address in vm.json is not one", fix="remove the VM's directory and make it again")
    return m


def ssh_argv(vmdir, ip, cmd=None, tty=False):
    """ssh to the VM, with none of the user's own ssh configuration (no
    agent, X11 or port forwarding, no local command, no shared connection):
    the VM is not trusted with the Mac's keys. Its host key is trusted on
    first use, kept under one name whatever its address, then pinned."""
    kh = os.path.join(vmdir, "known_hosts")
    a = ["ssh", "-F", "/dev/null", "-a", "-x", "-i", os.path.join(vmdir, "id_ed25519"),
         "-o", f"UserKnownHostsFile={kh}", "-o", "GlobalKnownHostsFile=/dev/null",
         "-o", "HostKeyAlias=varek-vm",
         "-o", "StrictHostKeyChecking=" + ("yes" if os.path.exists(kh) and os.path.getsize(kh) else "accept-new"),
         "-o", "IdentitiesOnly=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
         "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no", "-o", "ControlPath=none",
         "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR"]
    if tty:
        a.append("-t")
    a.append(f"{USER}@{ip}")
    if cmd:
        a.append(cmd)
    return a


def sh_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


# ----------------------------------------------------------------- state --

def vm_dir(name="default"):
    return os.path.join(VM_ROOT, name)


def load_cfg(vmdir):
    try:
        with open(os.path.join(vmdir, "vm.json")) as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise VmError("there is no VM yet", fix="make it: varek vm init --image rhel-9.6-aarch64-kvm.qcow2")


def save_cfg(vmdir, cfg):
    tmp = os.path.join(vmdir, "vm.json.tmp")
    with open(tmp, "w") as fh:
        json.dump(cfg, fh, indent=2)
    os.replace(tmp, os.path.join(vmdir, "vm.json"))


def running_pid(vmdir):
    """vfkit's pid, if the VM's vfkit is running: the pid file's process,
    if it is vfkit (a pid left from before a crash may be another's now)"""
    try:
        pid = int(open(os.path.join(vmdir, "vfkit.pid")).read())
        os.kill(pid, 0)
        comm = subprocess.run(["ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True).stdout.strip()
        return pid if os.path.basename(comm) == "vfkit" else None
    except (OSError, ValueError):
        return None


def guest_ip(cfg, wait=0):
    end = time.time() + wait
    while True:
        try:
            ip = parse_leases(open(LEASES).read()).get(norm_mac(cfg["mac"]))
        except OSError:
            ip = None
        if ip or time.time() >= end:
            return ip
        time.sleep(1)


def need_mac_host():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise VmError(f"varek vm is for a Mac with Apple silicon (this is {platform.system()} {platform.machine()})",
                      fix="on Linux, run the Warden directly: sudo varek run -- CMD")
    for tool, pkg in (("vfkit", "vfkit"), ("qemu-img", "qemu"), ("ssh", None), ("ssh-keygen", None)):
        if not shutil.which(tool):
            raise VmError(f"{tool} is not installed", fix=f"brew install {pkg}" if pkg else "install OpenSSH")


def boot(vmdir, cfg, shares, cloud_init=None):
    if running_pid(vmdir):
        raise VmError("the VM is already running", fix="varek vm stop")
    argv = vfkit_argv(shutil.which("vfkit"), vmdir, cfg, shares, cloud_init)
    log = open(os.path.join(vmdir, "vfkit.log"), "ab")
    p = subprocess.Popen(argv, stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
    with open(os.path.join(vmdir, "vfkit.pid"), "w") as fh:
        fh.write(str(p.pid))
    ip = guest_ip(cfg, wait=180)
    if not ip:
        raise VmError("the VM did not get an address in 3 minutes",
                      fix=f"see {os.path.join(vmdir, 'serial.log')} and {os.path.join(vmdir, 'vfkit.log')}")
    for _ in range(120):
        if subprocess.run(ssh_argv(vmdir, ip, "true"), capture_output=True).returncode == 0:
            return ip
        time.sleep(2)
    raise VmError(f"the VM at {ip} does not answer ssh", fix=f"see {os.path.join(vmdir, 'serial.log')}")


def ssh(vmdir, ip, cmd, check=True, tty=False, **kw):
    r = subprocess.run(ssh_argv(vmdir, ip, cmd, tty), **kw)
    if check and r.returncode != 0:
        raise VmError(f"in the VM, `{cmd}` failed ({r.returncode})")
    return r


def halt(vmdir, cfg):
    pid = running_pid(vmdir)
    if not pid:
        return False
    ip = guest_ip(cfg)
    if ip:
        ssh(vmdir, ip, "sudo systemctl poweroff", check=False, capture_output=True)
    # the guest may not power off: vfkit is ended, then killed, and the
    # share is not recorded gone until it has
    for sig in (None, signal.SIGTERM, signal.SIGKILL):
        if sig:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
        for _ in range(60 if sig is None else 15):
            if not running_pid(vmdir):
                break
            time.sleep(1)
        else:
            continue
        break
    if running_pid(vmdir):
        raise VmError(f"the VM's vfkit (pid {pid}) does not stop", fix=f"kill -9 {pid}")
    cfg["project"] = None
    save_cfg(vmdir, cfg)
    return True


# -------------------------------------------------------------- commands --

def image_format(fd):
    """qcow2 by its magic, else raw"""
    head = os.pread(fd, 4, 0)
    return "qcow2" if head == b"QFI\xfb" else "raw"


def make_disk(a, vmdir):
    """the VM's disk from the image: checked against the SHA-256 the user
    gives (Red Hat's download page shows it), its format named (by its
    magic), and a qcow2 image refused if it names any other file (a backing
    or data file would copy a Mac file into the guest)"""
    want = (a.sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", want):
        raise VmError("--sha256 is required: the image's SHA-256, as Red Hat's download page shows it",
                      fix="varek vm init --image rhel-9.6-aarch64-kvm.qcow2 --sha256 HEX")
    fd = os.open(a.image, os.O_RDONLY)
    try:
        h = hashlib.sha256()
        off = 0
        while True:
            chunk = os.pread(fd, 1 << 20, off)
            if not chunk:
                break
            h.update(chunk)
            off += len(chunk)
        if h.hexdigest() != want:
            raise VmError(f"the image's SHA-256 is {h.hexdigest()}, not the one given",
                          fix="download the image again, and give the SHA-256 Red Hat's page shows for it")
        print(f"[varek] the image: {a.image} (sha256 {want}, as given)")
        fmt = image_format(fd)
        src = a.image
        if fmt == "qcow2":
            info = json.loads(subprocess.run(["qemu-img", "info", "-f", "qcow2", "--output=json", src],
                                             check=True, capture_output=True, text=True).stdout)
            data = (info.get("format-specific") or {}).get("data") or {}
            if info.get("backing-filename") or info.get("full-backing-filename") or data.get("data-file"):
                raise VmError("the image names another file (a backing or data file): refused",
                              fix="use Red Hat's KVM guest image as downloaded")
        disk = os.path.join(vmdir, "disk.raw")
        subprocess.run(["qemu-img", "convert", "-f", fmt, "-O", "raw", src, disk], check=True)
        subprocess.run(["qemu-img", "resize", "-f", "raw", disk, f"{a.disk_gib}G"], check=True)
        return want
    finally:
        os.close(fd)


def send_source(vmdir, ip, dest):
    """the VAREK checkout copied into the VM over ssh (not shared with it:
    the checkout holds the tools the Mac's user runs)"""
    env = dict(os.environ, COPYFILE_DISABLE="1")
    argv = ["tar"] + (["--no-mac-metadata"] if platform.system() == "Darwin" else []) + \
        ["--exclude", ".git", "-C", SRC_ROOT, "-cf", "-", "."]
    t = subprocess.Popen(argv, stdout=subprocess.PIPE, env=env)
    r = subprocess.run(ssh_argv(vmdir, ip, f"sudo rm -rf {dest} && sudo mkdir -p {dest} && "
                                           f"sudo tar --no-same-owner -C {dest} -xf -"), stdin=t.stdout)
    t.stdout.close()
    if t.wait() != 0 or r.returncode != 0:
        raise VmError("the VAREK checkout could not be copied into the VM")


def register(vmdir, ip, a):
    """the guest registered with the user's activation key, given on stdin
    (not on a command line: sudo would log it)"""
    key = open(a.rh_activation_key_file).read().strip()
    ssh(vmdir, ip, "sudo sh -c 'IFS= read -r k; exec subscription-manager register --org \"$1\" "
                   f"--activationkey \"$k\"' _ {sh_quote(a.rh_org)}",
        input=key + "\n", text=True, capture_output=True)


def cmd_init(a):
    if not a.resume and not a.image:
        raise VmError("--image is required", fix="varek vm init --image rhel-9.6-aarch64-kvm.qcow2 --sha256 HEX (or --resume)")
    need_mac_host()
    if not os.path.isfile(os.path.join(SRC_ROOT, "varek", "v1_4", "packaging", "vm", "provision.sh")):
        raise VmError(f"no VAREK checkout at {SRC_ROOT} (the VM is set up from it)",
                      fix="run varek vm init from a VAREK checkout's tools/varek")
    vmdir = vm_dir()
    if os.path.exists(os.path.join(vmdir, "vm.json")) and not a.resume:
        raise VmError(f"a VM already exists in {vmdir}",
                      fix="use it (varek vm start), or remove that directory to make a new one")
    if a.resume:
        cfg = load_cfg(vmdir)
        if cfg.get("provisioned"):
            raise VmError("the VM is set up already",
                          fix=f"varek vm start; to make it again, remove {vmdir} and run varek vm init --image")
    else:
        os.makedirs(vmdir, mode=0o700, exist_ok=True)
        os.chmod(vmdir, 0o700)
        sha = make_disk(a, vmdir)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "varek-vm",
                        "-f", os.path.join(vmdir, "id_ed25519")], check=True)
        cfg = {"name": "default", "mac": new_mac(), "cpus": a.cpus, "memory_mib": a.memory_mib,
               "disk_gib": a.disk_gib, "image": os.path.abspath(a.image), "image_sha256": sha,
               "provisioned": None, "project": None}
        save_cfg(vmdir, cfg)
    ci = os.path.join(vmdir, "cloud-init")
    os.makedirs(ci, mode=0o700, exist_ok=True)
    pub = open(os.path.join(vmdir, "id_ed25519.pub")).read()
    for f, text in (("user-data", user_data(pub, "varek-vm")), ("meta-data", meta_data("varek-vm-1", "varek-vm"))):
        with open(os.path.join(ci, f), "w") as fh:
            fh.write(text)
    # a resume finds the VM still up (it stays up for the user to register it)
    ip = guest_ip(cfg) if running_pid(vmdir) else None
    if not ip:
        ip = boot(vmdir, cfg, [], [os.path.join(ci, "user-data"), os.path.join(ci, "meta-data")])
    print(f"[varek] the VM is up at {ip}")
    try:
        rhel = ssh(vmdir, ip, ". /etc/os-release; echo $ID", capture_output=True, text=True).stdout.strip() == "rhel"
        if rhel and ssh(vmdir, ip, "sudo subscription-manager status", check=False, capture_output=True).returncode != 0:
            if a.rh_org and a.rh_activation_key_file:
                register(vmdir, ip, a)
            else:
                print("[varek] RHEL needs your subscription before it can install packages. In another terminal:\n"
                      "          varek vm ssh\n"
                      "          sudo subscription-manager register      (your own Red Hat login)\n"
                      "        then: varek vm init --resume   (the VM stays up)")
                return 3
        src = "/var/tmp/varek-src-in"
        send_source(vmdir, ip, src)
        ssh(vmdir, ip, f"sudo bash {src}/varek/v1_4/packaging/vm/provision.sh {src} && sudo rm -rf {src}", tty=True)
    except BaseException:
        halt(vmdir, cfg)
        raise
    cfg["provisioned"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save_cfg(vmdir, cfg)
    halt(vmdir, cfg)
    print("[varek] the VM is ready: varek vm run -- CMD (in your project directory)")
    return 0


def start(project):
    need_mac_host()
    vmdir = vm_dir()
    cfg = load_cfg(vmdir)
    if not cfg.get("provisioned"):
        raise VmError("the VM is not set up yet", fix="varek vm init --resume")
    p = check_share(project, refuse=(VM_ROOT, SRC_ROOT))
    if running_pid(vmdir):
        ip = guest_ip(cfg)
        if cfg.get("project") == p and ip:
            return vmdir, cfg, ip, p
        raise VmError(f"the VM is running with {cfg.get('project')} shared",
                      fix="varek vm stop, then start it in this project")
    ip = boot(vmdir, cfg, [(p, "project")])
    ssh(vmdir, ip, f"sudo mkdir -p {sh_quote(p)} && sudo mount -t virtiofs project {sh_quote(p)}")
    cfg["project"] = p
    save_cfg(vmdir, cfg)
    return vmdir, cfg, ip, p


def cmd_start(a):
    _, _, ip, p = start(a.dir or os.getcwd())
    print(f"[varek] the VM is up at {ip}, with {p} shared at the same path")
    return 0


STREAMS = "sudo sh -c 'ls -t /var/log/varek/verdicts-*.log 2>/dev/null'"


def cmd_run(a):
    vmdir, cfg, ip, p = start(os.getcwd())
    before = set(ssh(vmdir, ip, STREAMS, check=False, capture_output=True, text=True).stdout.split())
    args = " ".join(sh_quote(x) for x in a.args)
    r = ssh(vmdir, ip, f"cd {sh_quote(p)} && sudo varek run {args}", check=False, tty=True)
    copy_stream(vmdir, ip, p, before)
    return r.returncode


def copy_stream(vmdir, ip, p, before):
    """the run's verdict stream (the one it made, in the VM's /var/log/varek,
    root's), copied to the project's .varek/ by the Mac's user: a new file,
    never through a link the agent made there"""
    new = [x for x in ssh(vmdir, ip, STREAMS, check=False, capture_output=True, text=True).stdout.split()
           if x not in before and re.fullmatch(r"/var/log/varek/verdicts-[\w.:-]+\.log", x)]
    if not new:
        print("[varek] the run made no verdict stream", file=sys.stderr)
        return None
    d = os.path.join(p, ".varek")
    try:
        os.mkdir(d, 0o755)
    except FileExistsError:
        pass
    try:
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        print(f"[varek] the stream is not copied: {d} is not a directory ({e.strerror})", file=sys.stderr)
        return None
    name = os.path.basename(new[0])
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd)
    except OSError as e:
        print(f"[varek] the stream is not copied: {d}/{name} ({e.strerror})", file=sys.stderr)
        return None
    finally:
        os.close(dfd)
    try:
        ssh(vmdir, ip, f"sudo cat {sh_quote(new[0])}", check=False, stdout=fd)
    finally:
        os.close(fd)
    print(f"[varek] the run's verdict stream: {d}/{name}", file=sys.stderr)
    return os.path.join(d, name)


def cmd_ssh(a):
    vmdir = vm_dir()
    cfg = load_cfg(vmdir)
    ip = guest_ip(cfg) if running_pid(vmdir) else None
    if not ip:
        raise VmError("the VM is not running", fix="varek vm start")
    return subprocess.run(ssh_argv(vmdir, ip, " ".join(a.cmd) or None, tty=not a.cmd)).returncode


def cmd_stop(a):
    vmdir = vm_dir()
    print("[varek] stopped" if halt(vmdir, load_cfg(vmdir)) else "[varek] the VM is not running")
    return 0


def cmd_status(a):
    vmdir = vm_dir()
    cfg = load_cfg(vmdir)
    pid = running_pid(vmdir)
    print(f"VM        {vmdir}\nset up    {cfg.get('provisioned') or 'no (varek vm init --resume)'}\n"
          f"running   {'yes, pid %d' % pid if pid else 'no'}\n"
          f"address   {(guest_ip(cfg) or '-') if pid else '-'}\nshared    {cfg.get('project') or '-'}")
    return 0


def add_parser(sub):
    """`varek vm`'s subcommands, under the varek CLI's parser"""
    vm = sub.add_parser("vm", help="v1.30: on a Mac, the Linux VM VAREK runs in",
                        description=__doc__.split("\n\n", 1)[1],
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    vs = vm.add_subparsers(dest="vm_cmd", required=True)
    x = vs.add_parser("init", help="make the VM from a RHEL 9 aarch64 KVM guest image, and set it up")
    x.add_argument("--image", help="the guest image (qcow2 or raw)")
    x.add_argument("--sha256", help="the image's SHA-256, as Red Hat's download page shows it")
    x.add_argument("--resume", action="store_true", help="carry on after registering the guest")
    x.add_argument("--cpus", type=int, default=4)
    x.add_argument("--memory-mib", type=int, default=4096)
    x.add_argument("--disk-gib", type=int, default=20)
    x.add_argument("--rh-org", help="register with this organization's activation key")
    x.add_argument("--rh-activation-key-file", help="a file holding the activation key")
    x.set_defaults(vm_func=cmd_init)
    x = vs.add_parser("start", help="start the VM with a project directory shared")
    x.add_argument("dir", nargs="?")
    x.set_defaults(vm_func=cmd_start)
    x = vs.add_parser("run", help="varek run inside the VM, on the working directory (its arguments pass "
                                  "through: varek vm run --profile claude -- claude)")
    x.add_argument("args", nargs="*", help="varek run's arguments")
    x.set_defaults(vm_func=cmd_run)
    x = vs.add_parser("ssh", help="a shell, or a command, inside the VM")
    x.add_argument("cmd", nargs="*")
    x.set_defaults(vm_func=cmd_ssh)
    vs.add_parser("stop", help="stop the VM").set_defaults(vm_func=cmd_stop)
    vs.add_parser("status", help="the VM's state").set_defaults(vm_func=cmd_status)
    return vm


def main(argv=None):
    ap = argparse.ArgumentParser(prog="varek_vm.py")
    add_parser(ap.add_subparsers(dest="cmd", required=True))
    a = ap.parse_args(argv)
    try:
        return a.vm_func(a)
    except VmError as e:
        print(f"varek: {e}", file=sys.stderr)
        if e.fix:
            print(f"  fix: {e.fix}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(["vm"] + sys.argv[1:]))
