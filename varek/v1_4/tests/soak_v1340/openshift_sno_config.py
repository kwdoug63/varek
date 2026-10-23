#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""openshift_sno_config.py — v1.34 step 9 (README.md, section 3): the
single-node OpenShift's install-config.yaml, from openshift-sno-install-
config.yaml with the operator's pull secret and an SSH public key put in.

  openshift_sno_config.py --pull-secret FILE --ssh-key FILE.pub --dir DIR

Writes DIR/install-config.yaml (0600) and, beside DIR, a copy
DIR-install-config.yaml.keep (openshift-install consumes the first; nothing
but its own files is left in DIR). The pull secret is read from
its file, checked to be one (a JSON object with "auths"), and never printed.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "openshift-sno-install-config.yaml")
PULL = "pullSecret: 'PASTE THE PULL SECRET HERE (console.redhat.com, OpenShift, Downloads)'"
SSH = "sshKey: 'PASTE YOUR SSH PUBLIC KEY HERE'"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pull-secret", required=True)
    ap.add_argument("--ssh-key", required=True, help="a public key (.pub)")
    ap.add_argument("--dir", required=True)
    a = ap.parse_args()
    try:
        secret = json.load(open(a.pull_secret))
    except (OSError, ValueError) as e:
        sys.exit(f"openshift_sno_config: {a.pull_secret}: not a pull secret ({type(e).__name__})")
    if not isinstance(secret, dict) or not isinstance(secret.get("auths"), dict) or not secret["auths"]:
        sys.exit(f"openshift_sno_config: {a.pull_secret}: not a pull secret (no \"auths\")")
    key = open(a.ssh_key).read().strip()
    if not key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")) or "PRIVATE" in key:
        sys.exit(f"openshift_sno_config: {a.ssh_key}: not an SSH public key")
    text = open(TEMPLATE).read()
    if PULL not in text or SSH not in text:
        sys.exit("openshift_sno_config: the template's placeholders are not where they were")
    # one line of JSON in single quotes: YAML takes it as is (no ' in it)
    one = json.dumps(secret, separators=(",", ":"))
    if "'" in one or "'" in key:
        sys.exit("openshift_sno_config: a quote in the pull secret or the key")
    text = text.replace(PULL, f"pullSecret: '{one}'").replace(SSH, f"sshKey: '{key}'")
    os.makedirs(a.dir, mode=0o700, exist_ok=True)
    for path in (os.path.join(a.dir, "install-config.yaml"), a.dir.rstrip("/") + "-install-config.yaml.keep"):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
    print(f"openshift_sno_config: {os.path.join(a.dir, 'install-config.yaml')} written "
          f"(pull secret for {len(secret['auths'])} registries, not shown)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
