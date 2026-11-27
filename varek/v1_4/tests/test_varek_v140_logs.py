# SPDX-License-Identifier: MIT
"""v1.41: logs and evidence written by v1.40 stay verifiable.

tests/v140_fixture holds what the v1.40.0 Warden and exporter wrote (built
from the v1.40.0 tag): a verdict stream in format chain-1 (SHA-256 chain,
Ed25519 signatures), its anchor, a CycloneDX BOM with a JSF Ed25519
signature, the policy and the public key. The private key was not kept.

On a host in FIPS mode Ed25519 is not an approved algorithm and the provider
does not offer it: such a log cannot be checked there, and the audit must say
so, never that its signatures do not verify (which would call a genuine log
forged).
"""
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FX = os.path.join(HERE, "tests", "v140_fixture")
sys.path.insert(0, os.path.join(HERE, "tools"))
import varek_audit as va           # noqa: E402
import varek_cyclonedx as cdx      # noqa: E402
import varek_ed25519               # noqa: E402

CHECKER = os.path.join(HERE, "tools", "vdp_cert_check")
needs_checker = pytest.mark.skipif(not os.access(CHECKER, os.X_OK), reason="tools/vdp_cert_check not built")


def audit(capsys, log, *extra):
    rc = va.main(["--policy", os.path.join(FX, "policy.txt"), "--checker", CHECKER, *extra, log])
    return rc, capsys.readouterr().out


@needs_checker
def test_a_v140_log_verifies_signed_and_anchored(capsys):
    rc, out = audit(capsys, os.path.join(FX, "verdicts.log"),
                    "--pubkey", os.path.join(FX, "log.key.pub"), "--anchor", os.path.join(FX, "anchor"))
    assert rc == 0 and "integrity: signed, anchored" in out and "varek_audit: PASS" in out, out
    assert "crypto provider" not in out          # v1.40 recorded none, and needs none


@needs_checker
def test_an_edit_to_a_v140_log_is_caught_by_its_signatures(tmp_path, capsys):
    edited = tmp_path / "edit.raw"
    src = open(os.path.join(FX, "verdicts.log"), encoding="utf-8").read()
    assert "/data/f2" in src
    edited.write_text(src.replace("/data/f2", "/data/f9", 1), encoding="utf-8")
    rechained = tmp_path / "edit.log"           # the chain made to agree, as its holder could
    with open(rechained, "wb") as fh:
        subprocess.run([sys.executable, os.path.join(HERE, "tests", "log_rechain.py"), str(edited)],
                       stdout=fh, check=True)
    rc, out = audit(capsys, str(rechained), "--pubkey", os.path.join(FX, "log.key.pub"))
    assert rc != 0 and "signature does not verify" in out, out


@needs_checker
def test_on_a_host_without_ed25519_it_cannot_be_checked_and_says_so(monkeypatch, capsys):
    monkeypatch.setattr(varek_ed25519, "ed25519_available", lambda: False)      # a host in FIPS mode
    rc, out = audit(capsys, os.path.join(FX, "verdicts.log"),
                    "--pubkey", os.path.join(FX, "log.key.pub"), "--anchor", os.path.join(FX, "anchor"))
    assert rc != 0 and "cannot be checked here" in out and "host not in FIPS mode" in out, out
    assert "signature does not verify" not in out, out        # not called a forgery
    assert out.count("cannot be checked here") <= 2, out      # said once (stream, anchor), not per record


def test_a_v140_bom_verifies(capsys):
    assert cdx.verify_bom(os.path.join(FX, "bom.cdx.json"), os.path.join(FX, "log.key.pub")) == 0
    assert "signature OK" in capsys.readouterr().out


def test_a_v140_bom_on_a_host_without_ed25519(monkeypatch, capsys):
    monkeypatch.setattr(varek_ed25519, "ed25519_available", lambda: False)
    assert cdx.verify_bom(os.path.join(FX, "bom.cdx.json"), os.path.join(FX, "log.key.pub")) == 1
    err = capsys.readouterr().err
    assert "cannot be checked here" in err and "does NOT verify" not in err, err


def test_the_fixture_is_v140s():
    head = open(os.path.join(FX, "verdicts.log"), encoding="utf-8").readline()
    assert '"warden":"1.40.0"' in head and '"log":"chain-1"' in head
    assert len(open(os.path.join(FX, "log.key.pub")).read().strip()) == 64      # an Ed25519 key
    assert not os.path.exists(os.path.join(FX, "log.key"))                       # never the private key
