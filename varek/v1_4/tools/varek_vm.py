#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""varek_vm.py — v1.30 (docs/security/v1.30-macos.md, step 4): VAREK on a Mac
with Apple silicon, through a Linux VM.

The VM runs on Apple's Virtualization framework, launched by vfkit, with a
RHEL 9 arm64 guest (9.6 or later; or a rebuild of it). The agent runs inside
it under the Warden as on Linux. The Mac shares one directory with the VM,
the project, mounted at the same path inside; never the home directory or a
directory holding it.

  varek vm init --image FILE   make the VM from a RHEL 9 aarch64 KVM guest
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

def check_share(path, home=None):
    """the directory to share with the VM, resolved; refused: the root, the
    home directory or any directory holding it, /Users, a non-directory"""
    home = os.path.realpath(home or os.path.expanduser("~"))
    p = os.path.realpath(path)
    if not os.path.isdir(p):
        raise VmError(f"{path} is not a directory", fix="share the project directory")
    if p == "/" or p in ("/Users", "/Volumes", "/private", "/System") or \
            home == p or home.startswith(p.rstrip("/") + "/"):
        raise VmError(f"{p} would share the home directory or more with the VM",
                      fix="share the project directory itself, e.g. ~/src/project")
    return p


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
         "--device", f"virtio-net,nat,mac={cfg['mac']}",
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


def ssh_argv(vmdir, ip, cmd=None, tty=False):
    a = ["ssh", "-i", os.path.join(vmdir, "id_ed25519"),
         "-o", f"UserKnownHostsFile={os.path.join(vmdir, 'known_hosts')}",
         "-o", "StrictHostKeyChecking=accept-new", "-o", "IdentitiesOnly=yes",
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
    try:
        pid = int(open(os.path.join(vmdir, "vfkit.pid")).read())
        os.kill(pid, 0)
        return pid
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
    for _ in range(60):
        if not running_pid(vmdir):
            break
        time.sleep(1)
    else:
        os.kill(pid, signal.SIGTERM)
    cfg["project"] = None
    save_cfg(vmdir, cfg)
    return True


# -------------------------------------------------------------- commands --

def cmd_init(a):
    if not a.resume and not a.image:
        raise VmError("--image is required", fix="varek vm init --image rhel-9.6-aarch64-kvm.qcow2 (or --resume)")
    need_mac_host()
    vmdir = vm_dir()
    if os.path.exists(os.path.join(vmdir, "vm.json")) and not a.resume:
        raise VmError(f"a VM already exists in {vmdir}",
                      fix="use it (varek vm start), or remove that directory to make a new one")
    if a.resume:
        cfg = load_cfg(vmdir)
    else:
        os.makedirs(vmdir, mode=0o700, exist_ok=True)
        h = hashlib.sha256()
        with open(a.image, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        print(f"[varek] the image: {a.image} (sha256 {h.hexdigest()})")
        disk = os.path.join(vmdir, "disk.raw")
        subprocess.run(["qemu-img", "convert", "-O", "raw", a.image, disk], check=True)
        subprocess.run(["qemu-img", "resize", "-f", "raw", disk, f"{a.disk_gib}G"], check=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "varek-vm",
                        "-f", os.path.join(vmdir, "id_ed25519")], check=True)
        cfg = {"name": "default", "mac": new_mac(), "cpus": a.cpus, "memory_mib": a.memory_mib,
               "disk_gib": a.disk_gib, "image": os.path.abspath(a.image), "image_sha256": h.hexdigest(),
               "provisioned": None, "project": None}
        save_cfg(vmdir, cfg)
    ci = os.path.join(vmdir, "cloud-init")
    os.makedirs(ci, mode=0o700, exist_ok=True)
    pub = open(os.path.join(vmdir, "id_ed25519.pub")).read()
    for f, text in (("user-data", user_data(pub, "varek-vm")), ("meta-data", meta_data("varek-vm-1", "varek-vm"))):
        with open(os.path.join(ci, f), "w") as fh:
            fh.write(text)
    ip = boot(vmdir, cfg, [(SRC_ROOT, "varek-src")],
              [os.path.join(ci, "user-data"), os.path.join(ci, "meta-data")])
    print(f"[varek] the VM is up at {ip}")
    rhel = ssh(vmdir, ip, ". /etc/os-release; echo $ID", capture_output=True, text=True).stdout.strip() == "rhel"
    if rhel and ssh(vmdir, ip, "sudo subscription-manager status", check=False, capture_output=True).returncode != 0:
        if a.rh_org and a.rh_activation_key_file:
            key = open(a.rh_activation_key_file).read().strip()
            ssh(vmdir, ip, f"sudo subscription-manager register --org {sh_quote(a.rh_org)} "
                           f"--activationkey {sh_quote(key)}", capture_output=True)
        else:
            print("[varek] RHEL needs your subscription before it can install packages. In another terminal:\n"
                  "          varek vm ssh\n"
                  "          sudo subscription-manager register      (your own Red Hat login)\n"
                  "        then: varek vm init --resume   (the VM stays up)")
            return 3
    ssh(vmdir, ip, "sudo mkdir -p /mnt/varek-src && (mountpoint -q /mnt/varek-src || "
                   "sudo mount -t virtiofs varek-src /mnt/varek-src) && "
                   "sudo bash /mnt/varek-src/varek/v1_4/packaging/vm/provision.sh /mnt/varek-src", tty=True)
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
    p = check_share(project)
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


def cmd_run(a):
    vmdir, cfg, ip, p = start(os.getcwd())
    args = " ".join(sh_quote(x) for x in a.args)
    r = ssh(vmdir, ip, f"cd {sh_quote(p)} && sudo varek run {args}", check=False, tty=True)
    # the run's verdict stream, kept in the VM, copied to the project
    ssh(vmdir, ip, "sudo sh -c 'f=$(ls -t /var/log/varek/verdicts-*.log 2>/dev/null | head -1); "
                   f"[ -n \"$f\" ] && mkdir -p {sh_quote(p + '/.varek')} && cp \"$f\" {sh_quote(p + '/.varek/')}'",
        check=False)
    return r.returncode


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
