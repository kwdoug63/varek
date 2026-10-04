# VAREK v1.23.1 — Enterprise license check fix

Released 2026-10-04 · MIT · github.com/kwdoug63/varek

## Summary

v1.23.1 fixes the VAREK Enterprise license check, which on the v1.23.0 AMI
refused every subscriber. AWS Marketplace issues each contract dimension as a
License Manager Count entitlement (MaxCount 1). v1.23.0 asked for the
dimension with `Unit=None`, which License Manager refuses, so the HIPAA and
SOC 2 packs could not be selected. The check now asks for `Value=1,Unit=Count`
and returns the unit at once with `CheckInLicense`, so the next check is not
refused while a provisional checkout holds the unit for up to an hour.

Found before any customer was affected, by an end-to-end test: a $0 private
offer to a second AWS account, whose license was `AVAILABLE` with
`enterprise_tier_a` while v1.23.0's call was refused. The fixed check was then
run three times in a row against the real License Manager in that account;
each check was licensed and returned its unit.

The Warden's decisions are unchanged from v1.23.0, and so is the
symmetric-suppression invariant (**no extension may move a genuinely unsafe
action to SATISFIED**).

## What changed

- `tools/varek_license.py`: `Value=1,Unit=Count`; `CheckInLicense` after a
  successful checkout; `varek license` warns if the unit was not returned.
- `iam/instance-license-policy.json`: adds `license-manager:CheckInLicense`.
  Buyers on v1.23.0 add it to their instance role.
- The five VAREK Core packs allow `/usr/share/` read-only (time zones, locale).
- `tools/systemd/varek-anchor-forward.service` points at the installed tools.
- `docs/aws-deployment-guide.md`: the deployment guide for VAREK Enterprise on
  AWS, indexed to the AWS Foundational Technical Review requirements.

## Build

```sh
cd varek/v1_4/packaging/aws-marketplace
./build.sh --version 1.23.1 --packs ~/varek-packs --product-id prod-ceonv23mvlzw4
```

`prod-ceonv23mvlzw4` is the product SKU License Manager reports for VAREK
Enterprise licenses (confirmed with a received license on 2026-10-04).

## Upgrading from v1.23.0

Launch the v1.23.1 version from the listing, add `CheckInLicense` to the
instance role, and copy `/etc/varek` from the old instance (deployment guide,
section 11.2). Existing policies, plans and verdict streams work unchanged.
Policy grammar stays at 1.21.
