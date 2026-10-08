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
    r = varek("status", config=str(tmp_path / "none.conf"))
    assert r.returncode == 2
    assert "varek init" in r.stderr


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
    r = varek("run", "--", "/bin/sh", "-c", "cat /etc/hostname >/dev/null 2>&1; echo done",
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
    varek("run", "--", "/bin/sh", "-c", "cat /etc/hostname >/dev/null 2>&1; true", config=conf, check=0)
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
