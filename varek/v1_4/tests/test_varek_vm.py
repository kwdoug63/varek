# SPDX-License-Identifier: MIT
"""v1.30 step 4: varek vm, the parts that need no Mac (the share check, the
VM's MAC, vmnet's leases, cloud-init's files, vfkit's and ssh's command
lines, and the refusal on any other host)."""
import os
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


def test_ssh_argv_pins_the_vms_key():
    a = vm.ssh_argv("/v", "192.168.64.9", "true")
    assert a[0] == "ssh" and a[-2:] == ["varek@192.168.64.9", "true"]
    assert "UserKnownHostsFile=/v/known_hosts" in a and "IdentitiesOnly=yes" in a and a[a.index("-i") + 1] == "/v/id_ed25519"
    assert vm.sh_quote("it's") == "'it'\\''s'"


@pytest.mark.skipif(sys.platform == "darwin", reason="the refusal is for hosts that are not a Mac")
def test_varek_vm_refuses_other_hosts():
    r = subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek"), "vm", "run", "--", "true"],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "for a Mac with Apple silicon" in r.stderr
    r = subprocess.run([sys.executable, os.path.join(HERE, "tools", "varek"), "vm", "init"],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "--image is required" in r.stderr
