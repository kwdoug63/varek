# VAREK v1.39.1 — The Evaluation Listing's License Check

A patch release for AWS Marketplace. VAREK Enterprise gets a second
listing, `VAREK Enterprise: Evaluation (30-Day Free Trial)`, priced by
the hour, because AWS offers free trials on hourly AMI pricing and not on
contract pricing. An hourly listing has no License Manager license, so the
v1.23 check would have refused the HIPAA and SOC 2 packs to an evaluator.
v1.39.1 lets the check accept the listing's product code instead. The
Warden decides nothing differently, and the policy grammar stays 1.35.

> Not reviewed by a human or a third party, or by a separate review pass:
> the changes were tested as below.

MIT · github.com/kwdoug63/varek

## Summary

- **Product-code licensing.** An AMI built with `build.sh --product-code
  <code>` carries the code in `/opt/varek/marketplace.json`. Choosing an
  Enterprise pack then reads the instance's product codes from instance
  metadata (IMDSv2, `/latest/meta-data/product-codes`); AWS Marketplace
  attaches the listing's code to every instance launched from it, and
  meters that instance by the hour after the free trial. The code there
  means licensed (`varek license` shows `licensed: hourly`).
- **No instance role needed** for the hourly listing: nothing calls
  License Manager.
- **Contract listings are unchanged.** A `marketplace.json` with
  dimensions and no product code checks out a License Manager entitlement
  exactly as v1.23.1 does. A file may name both; the code is tried first.
- **The free trial, set from CloudShell.** AWS sets an hourly AMI
  listing's free trial through the Catalog API, not the portal.
  `packaging/aws-marketplace/add_free_trial.py --product-id <id> --days 30`
  reads the public offer's current terms, keeps its prices, and adds (or
  replaces) the trial on every priced instance type; it shows the change
  and submits it only with `--apply`.
- **Messages fit the listing.** `varek license`, `varek doctor` and the
  refusal of an Enterprise pack say what the check needs: instance
  metadata reachable on the launched instance for an hourly listing, the
  License Manager permissions for a contract.

## What changes for a user

On the evaluation listing: launch, `sudo varek init --pack hipaa`, and the
pack is accepted, with no IAM role to attach. On the contract listing:
nothing changes.

This remains a compliance check, not copy protection: the packs are
readable text on the buyer's own instance.

## Tests

`tests/test_varek_license.py` adds 14 cases: the code on the instance
licenses it without calling License Manager; no code, or another
product's code, is NOT_LICENSED; unreachable metadata is UNAVAILABLE; a
file with both a code and dimensions tries the code first; malformed
files are refused; the IMDSv2 exchange (token, then product codes, 404
as "none") against a stand-in; and `varek license` off EC2 names the
metadata service, not the License Manager permissions. 30 of 30 license
tests pass, root and built runtime included.
`tests/test_add_free_trial.py` adds 4 for the free-trial script: prices
kept, an old trial replaced, term IDs not sent back, 5 to 31 days only,
hourly prices required first. `make test-cli`: all pass but one,
`test_bench_proxy_end_to_end`, which fails the same way without this
change in the test sandbox (its outbound proxy) and is unrelated.

Not yet tested on a real Marketplace launch: the product code reaches an
instance only once AWS Marketplace has ingested the image for the
evaluation listing. Check it on the first launch with `varek license`.
