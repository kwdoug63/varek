# SPDX-License-Identifier: MIT
"""Tests for the VAREK Enterprise entitlement check (v1.23, v1.23.1). Run with `make test-cli`.

AWS is never called: a stand-in `aws` script answers CheckoutLicense the way
License Manager does, chosen by FAKE_AWS_MODE (and FAKE_AWS_CHECKIN).
"""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # varek/v1_4
sys.path.insert(0, os.path.join(HERE, "tools"))
import varek_license as vl  # noqa: E402

VAREK = os.path.join(HERE, "tools", "varek")
BUILT = all(os.access(os.path.join(HERE, b), os.X_OK)
            for b in ("warden", "tools/vdp_check", "tools/vdp_cert_check", "tools/varek_keygen"))
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

FAKE_AWS = r"""#!/bin/sh
# Stand-in for `aws license-manager checkout-license | check-in-license`, behaving
# as License Manager did for a real VAREK Enterprise contract (2026-10-04): each
# dimension is a Count entitlement with MaxCount 1, so a checkout must ask for
# Value=1,Unit=Count, and a count stays in use until it is checked in.
echo "$@" >> "$FAKE_AWS_LOG"
HELD="${FAKE_AWS_LOG}.held"
touch "$HELD"
case "$2" in
  check-in-license)
    if [ "$FAKE_AWS_CHECKIN" = "denied" ]; then
      echo "An error occurred (AccessDeniedException) when calling the CheckInLicense operation: not authorized" >&2
      exit 254
    fi
    tok=$(echo "$@" | sed -n 's/.*--license-consumption-token \([^ ]*\).*/\1/p')
    grep -vx "${tok#tok-}" "$HELD" > "$HELD.new"; mv "$HELD.new" "$HELD"
    exit 0 ;;
esac
dim=$(echo "$@" | sed -n 's/.*--entitlements Name=\([A-Za-z0-9_]*\),.*/\1/p')
asks_one=$(echo "$@" | grep -c "Name=$dim,Value=1,Unit=Count")
refuse() {
    echo "An error occurred (NoEntitlementsAllowedException) when calling the CheckoutLicense operation: No Entitlements Allowed." >&2
    exit 254
}
case "$FAKE_AWS_MODE" in
  licensed:*)
    [ "$dim" = "${FAKE_AWS_MODE#licensed:}" ] || refuse
    [ "$asks_one" = 1 ] || refuse                 # e.g. Unit=None, as v1.23.0 asked
    grep -qx "$dim" "$HELD" && refuse             # the one count is in use
    echo "$dim" >> "$HELD"
    echo '{"LicenseConsumptionToken": "tok-'"$dim"'", "EntitlementsAllowed": [{"Name": "'"$dim"'", "Value": "1", "Unit": "Count"}]}'
    exit 0 ;;
  notallowed)
    echo "An error occurred (EntitlementNotAllowedException) when calling the CheckoutLicense operation: x" >&2
    exit 254 ;;
  none)
    refuse ;;
  denied)
    echo "An error occurred (AccessDeniedException) when calling the CheckoutLicense operation: not authorized" >&2
    exit 254 ;;
  nocreds)
    echo "Unable to locate credentials. You can configure credentials by running \"aws configure\"." >&2
    exit 253 ;;
  *)
    echo "An error occurred (InternalError): boom" >&2
    exit 254 ;;
esac
"""

ENTERPRISE_PACK = """# VAREK Test Enterprise Pack 1.0
# Licensed to VAREK Enterprise subscribers under their subscription agreement.
require warden 1.14
allow path /tmp/varek/
"""


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A VAREK_HOME with marketplace.json, plus a fake `aws` on PATH."""
    h = tmp_path / "home"
    h.mkdir()
    (h / "marketplace.json").write_text(json.dumps(
        {"product_id": "prod-test123", "dimensions": ["enterprise_tier_b", "enterprise_tier_a"]}))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    aws = bindir / "aws"
    aws.write_text(FAKE_AWS)
    aws.chmod(0o755)
    log = tmp_path / "aws.log"
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_AWS_LOG", str(log))
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    return h, log


def test_off_the_ami_nothing_is_checked(tmp_path):
    assert vl.load_marketplace(str(tmp_path)) is None
    assert vl.check(str(tmp_path)).status == vl.NOT_MARKETPLACE


def test_bad_marketplace_file_is_reported(tmp_path):
    (tmp_path / "marketplace.json").write_text('{"product_id": ""}')
    r = vl.check(str(tmp_path))
    assert r.status == vl.UNAVAILABLE and "product_id" in r.detail


def test_enterprise_mark(tmp_path):
    ent = tmp_path / "e.policy.txt"
    ent.write_text(ENTERPRISE_PACK)
    core = tmp_path / "c.policy.txt"
    core.write_text("# a core pack\nrequire warden 1.14\n")
    assert vl.is_enterprise_pack(str(ent))
    assert not vl.is_enterprise_pack(str(core))
    assert not vl.is_enterprise_pack(str(tmp_path / "missing"))


def checkouts(log):
    return [c for c in log.read_text().splitlines() if c.startswith("license-manager checkout-license")]


def check_ins(log):
    return [c for c in log.read_text().splitlines() if c.startswith("license-manager check-in-license")]


def test_holds_the_second_dimension(home, monkeypatch):
    h, log = home
    monkeypatch.setenv("FAKE_AWS_MODE", "licensed:enterprise_tier_a")
    r = vl.check(str(h))
    assert r.ok and r.dimension == "enterprise_tier_a"
    calls = checkouts(log)
    assert len(calls) == 2                      # tier_b refused, then tier_a granted
    for c in calls:
        assert "--product-sku prod-test123" in c
        assert "--checkout-type PROVISIONAL" in c
        assert "--key-fingerprint " + vl.ISSUER_FINGERPRINT in c
        assert "--region us-east-1" in c
        assert "Value=1,Unit=Count" in c and "Unit=None" not in c


def test_self_issued_test_license(home, monkeypatch):
    h, log = home
    data = json.loads((h / "marketplace.json").read_text())
    data["issuer_fingerprint"] = "aws:111122223333:Self:issuer-fingerprint"
    (h / "marketplace.json").write_text(json.dumps(data))
    monkeypatch.setenv("FAKE_AWS_MODE", "licensed:enterprise_tier_b")
    assert vl.check(str(h)).ok
    assert "--key-fingerprint aws:111122223333:Self:issuer-fingerprint" in log.read_text()


def test_count_is_returned_so_the_next_check_succeeds(home, monkeypatch):
    # v1.23.1: a Marketplace contract dimension is a Count with MaxCount 1. v1.23.0
    # never checked it back in, so a second check within the hour was refused.
    h, log = home
    monkeypatch.setenv("FAKE_AWS_MODE", "licensed:enterprise_tier_b")
    for _ in range(3):
        r = vl.check(str(h))
        assert r.ok and r.dimension == "enterprise_tier_b"
        assert "returned" in r.detail and "not returned" not in r.detail
    ins = check_ins(log)
    assert len(ins) == 3
    assert all("--license-consumption-token tok-enterprise_tier_b" in c for c in ins)
    assert all("--region us-east-1" in c for c in ins)


def test_check_in_refused_is_reported(home, monkeypatch):
    h, log = home
    monkeypatch.setenv("FAKE_AWS_MODE", "licensed:enterprise_tier_a")
    monkeypatch.setenv("FAKE_AWS_CHECKIN", "denied")
    r = vl.check(str(h))
    assert r.ok                                     # the account is licensed all the same
    assert "not returned" in r.detail and "CheckInLicense" in r.detail
    # ...but the count stays in use, which is why the check-in matters:
    assert vl.check(str(h)).status == vl.NOT_LICENSED


@pytest.mark.parametrize("mode", ["none", "notallowed"])
def test_no_entitlement(home, monkeypatch, mode):
    h, log = home
    monkeypatch.setenv("FAKE_AWS_MODE", mode)
    r = vl.check(str(h))
    assert r.status == vl.NOT_LICENSED and not r.ok
    assert len(checkouts(log)) == 2                  # both tiers were tried
    assert not check_ins(log)


@pytest.mark.parametrize("mode, words", [("denied", "CheckoutLicense"),
                                         ("nocreds", "no IAM role"),
                                         ("other", "InternalError")])
def test_cannot_check(home, monkeypatch, mode, words):
    h, log = home
    monkeypatch.setenv("FAKE_AWS_MODE", mode)
    r = vl.check(str(h))
    assert r.status == vl.UNAVAILABLE and words in r.detail
    assert len(checkouts(log)) == 1                 # stops at the first hard error


def test_no_aws_cli(home, monkeypatch):
    h, _ = home
    monkeypatch.setenv("PATH", "/nonexistent")
    r = vl.check(str(h), aws=None)
    assert r.status == vl.UNAVAILABLE and "AWS CLI" in r.detail


# ----------------------------------------------------------- the varek CLI --

def _cli_home(tmp_path, home):
    """A runtime dir that looks like the AMI: built tools, core packs, one Enterprise pack."""
    h, _ = home
    os.symlink(os.path.join(HERE, "warden"), h / "warden")
    os.symlink(os.path.join(HERE, "tools"), h / "tools")
    pol = h / "policies"
    pol.mkdir()
    for name in ("healthcare", "finance"):
        os.symlink(os.path.join(HERE, "policies", f"{name}.policy.txt"),
                   pol / f"{name}.policy.txt")
    (pol / "hipaa.policy.txt").write_text(ENTERPRISE_PACK)
    return h


def varek(*args, env):
    e = dict(os.environ, NO_COLOR="1", **env)
    return subprocess.run([sys.executable, VAREK, *args], text=True, capture_output=True, env=e)


def test_license_command_off_the_ami(tmp_path):
    r = varek("license", env={"VAREK_HOME": str(tmp_path),
                              "VAREK_CONFIG": str(tmp_path / "none.conf")})
    assert r.returncode == 0 and "VAREK Core" in r.stdout


@pytest.mark.skipif(not BUILT, reason="needs a built runtime")
def test_policy_list_marks_enterprise_packs(tmp_path, home):
    h = _cli_home(tmp_path, home)
    r = varek("policy", "list", env={"VAREK_HOME": str(h),
                                     "VAREK_CONFIG": str(tmp_path / "none.conf")})
    assert r.returncode == 0
    line = [ln for ln in r.stdout.splitlines() if "hipaa" in ln][0]
    assert "enterprise" in line
    assert "enterprise" not in [ln for ln in r.stdout.splitlines() if "finance" in ln][0]


@pytest.mark.skipif(not (BUILT and ROOT), reason="needs a built runtime and root")
def test_init_gates_enterprise_packs_only(tmp_path, home, monkeypatch):
    h = _cli_home(tmp_path, home)
    conf = str(tmp_path / "etc" / "varek.conf")
    env = {"VAREK_HOME": str(h), "VAREK_CONFIG": conf}

    monkeypatch.setenv("FAKE_AWS_MODE", "none")
    r = varek("init", "--pack", "hipaa", "--log-dir", str(tmp_path / "log"), env=env)
    assert r.returncode == 2
    assert "VAREK Enterprise pack" in r.stderr and "finance" in r.stderr
    assert not os.path.exists(conf)                    # nothing was set up

    # A VAREK Core pack needs no license, even with License Manager saying no.
    r = varek("init", "--pack", "finance", "--log-dir", str(tmp_path / "log"), env=env)
    assert r.returncode == 0, r.stdout + r.stderr

    r = varek("license", env=env)
    assert r.returncode == 1 and "no VAREK Enterprise entitlement" in r.stdout

    monkeypatch.setenv("FAKE_AWS_MODE", "licensed:enterprise_tier_a")
    r = varek("policy", "use", "hipaa", env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "enterprise_tier_a" in r.stdout
    r = varek("license", env=env)
    assert r.returncode == 0 and "licensed: enterprise_tier_a" in r.stdout
