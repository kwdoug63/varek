# SPDX-License-Identifier: MIT
"""v1.30 step 4: varek vm, the parts that need no Mac (the share check, the
VM's MAC, vmnet's leases, cloud-init's files, vfkit's and ssh's command
lines, and the refusal on any other host)."""
import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))
import varek_vm as vm  # noqa: E402


def test_share_refuses_home_and_above(tmp_path):
    home = tmp_path / "Users" / "ken"
    proj = home / "src" / "proj"
    proj.mkdir(parents=True)
    assert vm.check_share(str(proj), home=str(home)) == str(proj)
    for bad in (home, home.parent, tmp_path, "/"):
        with pytest.raises(vm.VmError, match="home directory or more"):
            vm.check_share(str(bad), home=str(home))
    with pytest.raises(vm.VmError, match="not a directory"):
        vm.check_share(str(proj / "missing"), home=str(home))


def test_share_resolves_links(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (tmp_path / "link").symlink_to(home)
    with pytest.raises(vm.VmError):
        vm.check_share(str(tmp_path / "link"), home=str(home))


def test_mac_is_locally_administered_unicast():
    for _ in range(50):
        m = vm.new_mac()
        first = int(m.split(":")[0], 16)
        assert first & 0x02 and not first & 0x01 and vm.norm_mac(m) == m


def test_leases_latest_by_normalized_mac():
    text = """{
\tname=varek-vm
\tip_address=192.168.64.5
\thw_address=1,5a:4:0:1:2:3
\tidentifier=1,5a:4:0:1:2:3
\tlease=0x6500
}
{
\tname=varek-vm
\tip_address=192.168.64.9
\thw_address=1,5a:4:0:1:2:3
\tlease=0x6600
}
{
\tname=other
\tip_address=192.168.64.7
\thw_address=1,de:ad:be:ef:0:1
\tlease=0x6700
}
"""
    leases = vm.parse_leases(text)
    assert leases["5a:04:00:01:02:03"] == "192.168.64.9"
    assert leases["de:ad:be:ef:00:01"] == "192.168.64.7"
    assert vm.norm_mac("zz:1:2:3:4:5") is None and vm.norm_mac("1:2:3") is None


def test_user_data_holds_the_key_and_no_password():
    pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummyKeyForTheTestsOnly0000000000000000 varek-vm"
    ud = vm.user_data(pub, "varek-vm")
    assert ud.startswith("#cloud-config\n") and pub in ud
    assert "lock_passwd: true" in ud and "ssh_pwauth: false" in ud and "passwd:" not in ud.replace("lock_passwd", "")
    with pytest.raises(vm.VmError):
        vm.user_data("ssh-rsa AAAA x\nruncmd: [reboot]", "varek-vm")
    assert vm.meta_data("i-1", "varek-vm") == "instance-id: i-1\nlocal-hostname: varek-vm\n"


def test_vfkit_argv(tmp_path):
    cfg = {"cpus": 4, "memory_mib": 4096, "mac": "5a:04:00:01:02:03"}
    a = vm.vfkit_argv("/opt/homebrew/bin/vfkit", str(tmp_path), cfg, [("/Users/ken/src/p", "project")])
    s = " ".join(a)
    assert a[:5] == ["/opt/homebrew/bin/vfkit", "--cpus", "4", "--memory", "4096"]
    assert f"efi,variable-store={tmp_path}/efi-variable-store,create" in s       # made on the first boot
    assert f"virtio-blk,path={tmp_path}/disk.raw" in s
    assert "virtio-net,nat,mac=5a:04:00:01:02:03" in s and "virtio-rng" in s
    assert "virtio-fs,sharedDir=/Users/ken/src/p,mountTag=project" in s and "--cloud-init" not in a
    (tmp_path / "efi-variable-store").write_bytes(b"x")
    a = vm.vfkit_argv("vfkit", str(tmp_path), cfg, [], ["/x/user-data", "/x/meta-data"])
    assert not any(",create" in x for x in a) and a[-2:] == ["--cloud-init", "/x/user-data,/x/meta-data"]
    assert not any("virtio-fs" in x for x in a)
    with pytest.raises(vm.VmError, match="comma"):
        vm.vfkit_argv("vfkit", str(tmp_path), cfg, [("/Users/ken/a,b", "project")])


def test_ssh_argv_pins_the_vms_key(tmp_path):
    a = vm.ssh_argv("/v", "192.168.64.9", "true")
    assert a[0] == "ssh" and a[-2:] == ["varek@192.168.64.9", "true"]
    assert "UserKnownHostsFile=/v/known_hosts" in a and "IdentitiesOnly=yes" in a and a[a.index("-i") + 1] == "/v/id_ed25519"
    # trusted on first use, under one name whatever the VM's address, then pinned
    assert "HostKeyAlias=varek-vm" in a and "StrictHostKeyChecking=accept-new" in a
    (tmp_path / "known_hosts").write_text("varek-vm ssh-ed25519 AAAA\n")
    assert "StrictHostKeyChecking=yes" in vm.ssh_argv(str(tmp_path), "192.168.64.9")
    assert vm.sh_quote("it's") == "'it'\\''s'"


def test_ssh_argv_takes_nothing_from_the_users_ssh_config():
    a = vm.ssh_argv("/v", "192.168.64.9", "true")
    assert a[a.index("-F") + 1] == "/dev/null" and "-a" in a and "-x" in a
    for o in ("ForwardAgent=no", "ClearAllForwardings=yes", "PermitLocalCommand=no", "ControlPath=none",
              "GlobalKnownHostsFile=/dev/null"):
        assert o in a


def test_share_refuses_hidden_system_and_own_directories(tmp_path):
    home = tmp_path / "Users" / "ken"
    for d in (".ssh/keys", ".varek/vm", "Library/Keychains", "src/proj", "varek"):
        (home / d).mkdir(parents=True)
    for bad in (home / ".ssh", home / ".ssh" / "keys", home / ".varek" / "vm", home / "Library" / "Keychains"):
        with pytest.raises(vm.VmError, match="hidden directory"):
            vm.check_share(str(bad), home=str(home))
    for bad in ("/usr", "/etc"):
        with pytest.raises(vm.VmError):
            vm.check_share(bad, home=str(home))
    # the VMs' own directory and the VAREK checkout, and what holds them
    with pytest.raises(vm.VmError, match="would share"):
        vm.check_share(str(home / "varek"), home=str(home), refuse=(str(home / "varek"),))
    (home / "src" / "proj" / "varek").mkdir()
    with pytest.raises(vm.VmError, match="would share"):
        vm.check_share(str(home / "src"), home=str(home), refuse=(str(home / "src" / "proj" / "varek"),))
    assert vm.check_share(str(home / "src" / "proj"), home=str(home), refuse=(str(home / "varek"),))


def test_share_compares_the_file_not_its_name(tmp_path):
    home = tmp_path / "home"
    (home / "p").mkdir(parents=True)
    os.symlink(home, tmp_path / "second-name")       # a second name for home, as a firmlink is
    with pytest.raises(vm.VmError, match="home directory or more"):
        vm.check_share(str(tmp_path / "second-name"), home=str(home))
    os.mkdir(tmp_path / "bind")
    if subprocess.run(["mount", "--bind", str(home), str(tmp_path / "bind")], capture_output=True).returncode == 0:
        try:                                         # the same directory by another path entirely
            with pytest.raises(vm.VmError):
                vm.check_share(str(tmp_path / "bind"), home=str(home))
        finally:
            subprocess.run(["umount", str(tmp_path / "bind")])


def test_vfkit_refuses_a_bad_mac(tmp_path):
    with pytest.raises(vm.VmError, match="MAC"):
        vm.vfkit_argv("vfkit", str(tmp_path), {"cpus": 1, "memory_mib": 1, "mac": "5a:4:0:1:2:3,mac=x"})


def test_image_checked_by_sha256_and_format(tmp_path):
    import hashlib
    img = tmp_path / "img.raw"
    img.write_bytes(b"\0" * 4096)
    class A:
        image, disk_gib = str(img), 1
    A.sha256 = None
    with pytest.raises(vm.VmError, match="--sha256 is required"):
        vm.make_disk(A, str(tmp_path))
    A.sha256 = "0" * 64
    with pytest.raises(vm.VmError, match="not the one given"):
        vm.make_disk(A, str(tmp_path))
    fd = os.open(img, os.O_RDONLY)
    assert vm.image_format(fd) == "raw"
    os.close(fd)
    (tmp_path / "q").write_bytes(b"QFI\xfb" + b"\0" * 60)
    fd = os.open(tmp_path / "q", os.O_RDONLY)
    assert vm.image_format(fd) == "qcow2"
    os.close(fd)
    if shutil.which("qemu-img"):
        # a qcow2 image naming a backing file (a file of the Mac's) is refused
        secret = tmp_path / "secret"
        secret.write_bytes(b"s" * 4096)
        q = tmp_path / "b.qcow2"
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(secret), "-F", "raw", str(q)], check=True)
        A.image, A.sha256 = str(q), hashlib.sha256(q.read_bytes()).hexdigest()
        with pytest.raises(vm.VmError, match="names another file"):
            vm.make_disk(A, str(tmp_path))
        assert not (tmp_path / "disk.raw").exists()


def test_run_names_the_agent_user_and_takes_no_other():
    """v1.38: the agent runs as the VM's agent user (no sudo), not as the
    VM's user (sudo); a --run-as of the user's own is refused, and one after
    -- is the command's"""
    assert vm.run_argv(["--profile", "python", "--", "python3", "p.py"]) == \
        ["--run-as", "agent", "--profile", "python", "--", "python3", "p.py"]
    assert vm.run_argv([]) == ["--run-as", "agent"]
    for bad in (["--run-as", "varek", "--", "true"], ["--run-as=root", "--", "true"]):
        with pytest.raises(vm.VmError, match="--run-as is not taken"):
            vm.run_argv(bad)
    assert vm.run_argv(["--", "tool", "--run-as", "x"])[:2] == ["--run-as", "agent"]
    assert vm.AGENT != vm.USER


def test_the_agent_user_has_no_sudo_password_key_or_group():
    s = vm.AGENT_USER_SH
    assert s.startswith("set -e; ")
    assert "useradd --create-home --user-group" in s and "passwd -l agent" in s
    assert "usermod -G '' agent" in s and "rm -rf ~agent/.ssh" in s        # wheel, if given, taken away
    assert "sudo -l -n -U agent" in s and "exit 1" in s                    # a sudo rule for it: refused
    assert "wheel" not in s and "NOPASSWD" not in s
    r = subprocess.run(["sh", "-n", "-c", s])
    assert r.returncode == 0


def test_the_packet_filter_keeps_the_vm_from_the_mac_and_its_networks():
    """v1.38 (v1.37.0's known limit: the VM's network reaches the Mac): the
    rules pf loads in the VM's anchor, quick, in this order"""
    r = [l for l in vm.pf_rules("192.168.64.5", "bridge100").splitlines() if not l.startswith("#")]
    assert r == [
        "pass quick inet from self to 192.168.64.5 keep state",            # the Mac's ssh to the VM, and replies
        "pass quick inet proto { udp tcp } from 192.168.64.5 to self port 53 keep state",   # vmnet's DNS
        "pass quick inet proto udp from 192.168.64.5 port 68 to any port 67 keep state",    # DHCP
        "block drop quick inet from 192.168.64.5 to self",
        ("block drop quick inet from 192.168.64.5 to { 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, "
         "192.168.0.0/16, 100.64.0.0/10 }"),
        "block drop in quick on bridge100 inet6 all"]
    for ip, br in (("8.8.8.8", "bridge100"), ("127.0.0.1", "bridge100"), ("169.254.1.2", "bridge100"),
                   ("192.168.64.5", "en0"), ("192.168.64.5", "bridge100; pass all"), ("x", "bridge100")):
        with pytest.raises((vm.VmError, ValueError)):
            vm.pf_rules(ip, br)


def test_the_filter_finds_vmnets_bridge_and_pfs_token():
    text = ("lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n"
            "en0: flags=8863<UP,BROADCAST> mtu 1500\n\tinet 172.31.5.9 netmask 0xfffff000 broadcast 172.31.15.255\n"
            "bridge100: flags=8a63<UP,BROADCAST> mtu 1500\n\toptions=3<RXCSUM,TXCSUM>\n"
            "\tinet 192.168.64.1 netmask 0xffffff00 broadcast 192.168.64.255\n\tmember: vmenet0 flags=3<LEARNING>\n")
    assert vm.bridge_of(text, "192.168.64.1") == "bridge100"
    assert vm.bridge_of(text, "192.168.64.10") is None and vm.bridge_of(text, "192.168.64") is None
    assert vm.pf_token("No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 123456789\n") == "123456789"
    assert vm.pf_token("pfctl: pf already enabled\n") is None
    assert vm.firewall_wanted({}) and vm.firewall_wanted({"VAREK_VM_FIREWALL": "on"})
    assert not vm.firewall_wanted({"VAREK_VM_FIREWALL": "OFF"})


def test_the_filter_is_loaded_before_the_project_and_flushed_at_the_stop(tmp_path, monkeypatch):
    """start: pf's rules loaded (sudo pfctl -a ANCHOR -f -), pf enabled (-E,
    its token kept), the rules read back, then the project mounted; halt:
    the anchor's rules and states flushed and the token released (-X)"""
    calls, mounted = [], []
    cfg = {"mac": "5a:04:00:01:02:03", "provisioned": "t", "project": None}
    monkeypatch.setattr(vm, "save_cfg", lambda d, c: None)
    monkeypatch.setattr(vm, "need_mac_host", lambda: None)
    monkeypatch.setattr(vm, "load_cfg", lambda d: cfg)
    monkeypatch.setattr(vm, "check_share", lambda p, refuse=(): p)
    monkeypatch.setattr(vm, "running_pid", lambda d: None)
    monkeypatch.setattr(vm, "boot", lambda d, c, shares, ci=None: "192.168.64.5")

    def fake_ssh(d, ip, cmd, check=True, **kw):
        if "route" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "192.168.64.1\n", "")
        mounted.append((cmd, len(calls)))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def fake_run(argv, **kw):
        calls.append(argv)
        if argv == ["ifconfig"]:
            return subprocess.CompletedProcess(argv, 0, "bridge100: flags=1<UP>\n\tinet 192.168.64.1 netmask 0xffffff00\n", "")
        if argv[-1] == "-E":
            return subprocess.CompletedProcess(argv, 0, "", "pf enabled\nToken : 42\n")
        if argv[-2:] == ["-s", "rules"]:
            return subprocess.CompletedProcess(argv, 0, "block drop quick inet from 192.168.64.5 to 10.0.0.0/8\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(vm, "ssh", fake_ssh)
    monkeypatch.setattr(vm.subprocess, "run", fake_run)
    monkeypatch.delenv("VAREK_VM_FIREWALL", raising=False)
    vm.start(str(tmp_path))
    assert ["sudo", "/sbin/pfctl", "-a", "com.apple/varek-vm", "-f", "-"] in calls
    assert cfg["pf_token"] == "42" and cfg["pf_vm"] == "192.168.64.5"
    mount = [n for c, n in mounted if "mount -t virtiofs" in c]
    assert mount and mount[0] >= calls.index(["sudo", "/sbin/pfctl", "-E"]) + 1    # after the filter
    calls.clear()
    vm.firewall_off(cfg)
    assert calls == [["sudo", "/sbin/pfctl", "-a", "com.apple/varek-vm", "-F", "rules"],
                     ["sudo", "/sbin/pfctl", "-a", "com.apple/varek-vm", "-F", "states"],
                     ["sudo", "/sbin/pfctl", "-X", "42"]]
    assert cfg["pf_vm"] is None and cfg["pf_token"] is None
    # rules pf did not take: the start refused, the filter taken down
    monkeypatch.setattr(vm.subprocess, "run", lambda argv, **kw: (calls.append(argv), subprocess.CompletedProcess(
        argv, 0, "" if argv[-2:] == ["-s", "rules"] else "bridge100: flags=1<UP>\n\tinet 192.168.64.1 x\n",
        "Token : 7\n" if argv[-1] == "-E" else ""))[1])
    with pytest.raises(vm.VmError, match="did not take"):
        vm.firewall_on(str(tmp_path), cfg, "192.168.64.5")
    assert ["sudo", "/sbin/pfctl", "-X", "7"] in calls and cfg["pf_vm"] is None
    # VAREK_VM_FIREWALL=off: no pfctl at all
    calls.clear()
    monkeypatch.setenv("VAREK_VM_FIREWALL", "off")
    assert vm.firewall_on(str(tmp_path), cfg, "192.168.64.5") is False and calls == []


@pytest.mark.skipif(sys.platform == "darwin", reason="the refusal is for hosts that are not a Mac")
def test_varek_vm_refuses_other_hosts():
    r = subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek"), "vm", "run", "--", "true"],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "for a Mac with Apple silicon" in r.stderr
    r = subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek"), "vm", "init"],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "--image is required" in r.stderr
