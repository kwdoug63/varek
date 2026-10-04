# VAREK v1.23.0 — VAREK Enterprise on AWS Marketplace

Released 2026-10-04 · MIT · github.com/kwdoug63/varek

## Summary

v1.23.0 is the first VAREK Enterprise AMI on AWS Marketplace: Amazon Linux
2023 (x86_64) with the Warden, the `varek` command, the Enterprise policy
packs (HIPAA, SOC 2) and a License Manager entitlement check.

The packaging (`varek/v1_4/packaging/aws-marketplace/`) and the license check
(`varek license`, `tools/varek_license.py`) shipped in the source with v1.22.0.
This release is the image built from them. The Warden's decisions are
unchanged from v1.22.0, and so is the symmetric-suppression invariant (**no
extension may move a genuinely unsafe action to SATISFIED**). The only code
change is the version the Warden reports (`run_start`, `varek version`), so
the release, the AMI name and the Marketplace listing all say 1.23.0.

## Build

```sh
cd varek/v1_4/packaging/aws-marketplace
./build.sh --version 1.23.0 --packs ~/varek-packs --product-id <product ID>
```

The Enterprise packs are licensed separately and are never in this
repository. Off the AMI nothing is checked, and the Warden and the Core packs
never depend on a license.

## Compatibility

Existing policies, plans and verdict streams work unchanged. Policy grammar
stays at 1.21.
