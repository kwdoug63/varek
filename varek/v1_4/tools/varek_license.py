# SPDX-License-Identifier: MIT
"""AWS Marketplace entitlement check for VAREK Enterprise (v1.23).

The VAREK Enterprise AMI carries /opt/varek/marketplace.json, written at image
build time:

    {"product_id": "<the product's ID for License Manager>",
     "dimensions": ["enterprise_tier_b", "enterprise_tier_a"]}

An optional "issuer_fingerprint" replaces AWS Marketplace's issuer; it exists
only to test the image against a self-issued License Manager license
(aws:<account>:Self:issuer-fingerprint) before the listing is live.

`check()` asks AWS License Manager whether the buyer's account holds one of
those dimensions, by calling CheckoutLicense through the AWS CLI that ships
with Amazon Linux 2023, then returns what it checked out with CheckInLicense.
The instance needs a role allowing license-manager:CheckoutLicense and
license-manager:CheckInLicense; nothing else is called and no data about the
workload is sent.

AWS Marketplace issues each contract dimension as a Count entitlement
(MaxCount 1 for a single-unit contract), so the checkout asks for Value=1,
Unit=Count. A provisional checkout holds that count for up to an hour; the
check only needs to know the account holds it, so it checks the count back in
at once. Otherwise the next check within the hour (another `varek run
--policy`, or another instance) would find the count in use and be refused.
(v1.23.1: v1.23.0 asked for Unit=None, which License Manager refuses for a
Count entitlement, and never checked in.)

The result only decides whether the Enterprise policy packs (the files whose
header says they are licensed to VAREK Enterprise subscribers) may be selected.
The Warden itself never depends on it: with no entitlement, VAREK keeps
running with the open-source packs (VAREK Core).

Off the AMI (no marketplace.json), there is nothing to check and the
Enterprise packs are simply not present.
"""
import json
import os
import shutil
import subprocess
import urllib.request
import uuid

MARKETPLACE_FILE = "marketplace.json"
# The issuer fingerprint AWS Marketplace uses for every seller's licenses.
ISSUER_FINGERPRINT = "aws:294406891311:AWS/Marketplace:issuer-fingerprint"
ENTERPRISE_MARK = "Licensed to VAREK Enterprise subscribers"
IMDS = "http://169.254.169.254"

# Statuses returned in Result.status
LICENSED = "licensed"          # an entitlement was checked out
NOT_LICENSED = "not-licensed"  # License Manager answered: no entitlement
NOT_MARKETPLACE = "not-marketplace"  # no marketplace.json: not the Enterprise AMI
UNAVAILABLE = "unavailable"    # could not ask (no role, no CLI, no network, ...)


class Result:
    def __init__(self, status, detail="", dimension="", product_id=""):
        self.status = status
        self.detail = detail
        self.dimension = dimension
        self.product_id = product_id

    @property
    def ok(self):
        return self.status == LICENSED

    def __repr__(self):
        return f"Result({self.status!r}, {self.detail!r}, {self.dimension!r})"


def load_marketplace(varek_home):
    """The build-time product settings, or None off the AMI."""
    path = os.path.join(varek_home, MARKETPLACE_FILE)
    try:
        with open(path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise ValueError(f"{path} is unreadable: {e}")
    pid = str(data.get("product_id", "")).strip()
    dims = [str(d).strip() for d in data.get("dimensions", []) if str(d).strip()]
    if not pid or not dims:
        raise ValueError(f"{path} needs a product_id and at least one dimension")
    issuer = str(data.get("issuer_fingerprint", "")).strip() or ISSUER_FINGERPRINT
    return {"product_id": pid, "dimensions": dims, "issuer": issuer, "path": path}


def is_enterprise_pack(path):
    """True if the policy file's header marks it as an Enterprise pack."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= 20:   # the build scripts check the same first 20 lines
                    break
                if ENTERPRISE_MARK in line:
                    return True
    except OSError:
        pass
    return False


def instance_region(timeout=2.0):
    """The EC2 Region from the instance metadata service (IMDSv2), or None."""
    # Never send metadata requests through an http_proxy the host may set.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        req = urllib.request.Request(
            IMDS + "/latest/api/token", method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        token = opener.open(req, timeout=timeout).read().decode()
        req = urllib.request.Request(
            IMDS + "/latest/meta-data/placement/region",
            headers={"X-aws-ec2-metadata-token": token})
        return opener.open(req, timeout=timeout).read().decode().strip() or None
    except Exception:
        return None


def _checkout(aws, region, product_id, dimension, timeout, issuer=ISSUER_FINGERPRINT):
    argv = [aws, "license-manager", "checkout-license",
            "--region", region,
            "--product-sku", product_id,
            "--checkout-type", "PROVISIONAL",
            "--key-fingerprint", issuer,
            "--entitlements", f"Name={dimension},Value=1,Unit=Count",
            "--client-token", uuid.uuid4().hex,
            "--output", "json"]
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def _check_in(aws, region, token, timeout):
    """Return a checked-out count; '' on success, else why it was not returned."""
    argv = [aws, "license-manager", "check-in-license",
            "--region", region,
            "--license-consumption-token", token]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return str(e)
    if r.returncode == 0:
        return ""
    err = (r.stderr or r.stdout or "").strip()
    if "AccessDenied" in err or "UnauthorizedOperation" in err:
        return "the instance role does not allow license-manager:CheckInLicense"
    return _first_line(err) or f"aws exited with {r.returncode}"


def _consumption_token(stdout):
    try:
        return str(json.loads(stdout or "{}").get("LicenseConsumptionToken", "")).strip()
    except ValueError:
        return ""


def check(varek_home, region=None, aws=None, timeout=20):
    """Ask License Manager for the first dimension the buyer holds."""
    try:
        mp = load_marketplace(varek_home)
    except ValueError as e:
        return Result(UNAVAILABLE, str(e))
    if mp is None:
        return Result(NOT_MARKETPLACE, "not the VAREK Enterprise image")
    aws = aws or shutil.which("aws")
    if not aws:
        return Result(UNAVAILABLE, "the AWS CLI is not installed", product_id=mp["product_id"])
    region = region or os.environ.get("AWS_REGION") or instance_region()
    if not region:
        return Result(UNAVAILABLE, "could not read the Region from instance metadata",
                      product_id=mp["product_id"])
    last = ""
    for dim in mp["dimensions"]:
        try:
            r = _checkout(aws, region, mp["product_id"], dim, timeout, mp["issuer"])
        except (OSError, subprocess.TimeoutExpired) as e:
            return Result(UNAVAILABLE, f"License Manager did not answer: {e}",
                          product_id=mp["product_id"])
        if r.returncode == 0:
            token = _consumption_token(r.stdout)
            why = _check_in(aws, region, token, timeout) if token else \
                "License Manager returned no consumption token"
            detail = f"entitlement {dim} checked out and returned"
            if why:
                # Licensed all the same; the count stays in use until it expires
                # (up to an hour), so checks made meanwhile are refused.
                detail = (f"entitlement {dim} checked out, but not returned ({why}); "
                          "it stays in use for up to an hour")
            return Result(LICENSED, detail, dim, mp["product_id"])
        err = (r.stderr or r.stdout or "").strip()
        last = err
        # Only "you don't hold this dimension" moves on to the next one.
        if any(e in err for e in ("NoEntitlementsAllowed", "EntitlementNotAllowed",
                                  "ResourceNotFound")):
            continue
        if "AccessDenied" in err or "UnauthorizedOperation" in err:
            return Result(UNAVAILABLE,
                          "the instance role does not allow license-manager:CheckoutLicense",
                          product_id=mp["product_id"])
        if "Unable to locate credentials" in err:
            return Result(UNAVAILABLE, "the instance has no IAM role attached",
                          product_id=mp["product_id"])
        return Result(UNAVAILABLE, _first_line(err) or f"aws exited with {r.returncode}",
                      product_id=mp["product_id"])
    return Result(NOT_LICENSED, _first_line(last) or "no VAREK Enterprise entitlement found",
                  product_id=mp["product_id"])


def _first_line(s):
    for line in s.splitlines():
        line = line.strip()
        if line:
            return line[:300]
    return ""
