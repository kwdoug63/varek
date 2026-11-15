#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Add (or change) the free trial on an hourly AMI listing's public offer.

AWS Marketplace offers free trials on hourly AMI pricing, set through the
Catalog API, not the portal's wizard. Run this in AWS CloudShell in the seller
account (us-east-1) once the listing has its hourly prices:

    python3 add_free_trial.py --product-id prod-wrdrltp5kybfi --days 30          # shows the change
    python3 add_free_trial.py --product-id prod-wrdrltp5kybfi --days 30 --apply  # submits it

UpdatePricingTerms replaces an offer's pricing terms in their entirety, so this
reads the public offer's current terms, keeps the hourly (and any annual)
prices exactly as they are, replaces any existing free trial, and grants the
trial on every instance type that has an hourly price.
"""
import argparse
import json
import subprocess
import sys

CATALOG = "AWSMarketplace"
PRICING_TERMS = ("UsageBasedPricingTerm", "ConfigurableUpfrontPricingTerm",
                 "FixedUpfrontPricingTerm")


def aws(*args):
    r = subprocess.run(["aws", "marketplace-catalog", *args, "--region", "us-east-1",
                        "--output", "json"], text=True, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"aws marketplace-catalog {args[0]} failed: {r.stderr.strip()}")
    return json.loads(r.stdout or "{}")


def public_offer(product_id):
    filters = {"OfferFilters": {"ProductId": {"ValueList": [product_id]},
                                "Targeting": {"ValueList": ["None"]}}}
    out = aws("list-entities", "--catalog", CATALOG, "--entity-type", "Offer",
              "--entity-type-filters", json.dumps(filters))
    ids = [e["EntityId"] for e in out.get("EntitySummaryList", [])]
    if len(ids) != 1:
        sys.exit(f"expected one public offer for {product_id}, found {ids or 'none'}; "
                 "pass --offer-id (Offers tab of the portal)")
    return ids[0]


def offer_details(offer_id):
    out = aws("describe-entity", "--catalog", CATALOG, "--entity-id", offer_id)
    doc = out.get("DetailsDocument")
    if doc is None:
        doc = json.loads(out.get("Details") or "{}")
    return doc


def _strip_ids(obj):
    if isinstance(obj, dict):
        return {k: _strip_ids(v) for k, v in obj.items() if k != "Id"}
    if isinstance(obj, list):
        return [_strip_ids(v) for v in obj]
    return obj


def pricing_change(offer_id, details, days):
    """The UpdatePricingTerms change: current prices kept, a free trial of `days` days added."""
    if not 5 <= days <= 31:
        raise ValueError("AWS allows a free trial of 5 to 31 days")
    terms = [_strip_ids(t) for t in details.get("Terms", []) if t.get("Type") in PRICING_TERMS]
    hourly = [t for t in terms if t["Type"] == "UsageBasedPricingTerm"]
    if not hourly:
        raise ValueError("the offer has no hourly prices yet: set them in the listing first")
    dims = []
    for t in hourly:
        for card in t.get("RateCards", []):
            for rate in card.get("RateCard", []):
                if rate["DimensionKey"] not in dims:
                    dims.append(rate["DimensionKey"])
    terms.append({"Type": "FreeTrialPricingTerm", "Duration": f"P{days}D",
                  "Grants": [{"DimensionKey": d} for d in dims]})
    return {"ChangeType": "UpdatePricingTerms",
            "Entity": {"Type": "Offer@1.0", "Identifier": offer_id},
            "DetailsDocument": {"PricingModel": details.get("PricingModel") or "Usage",
                                "Terms": terms}}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--product-id", required=True)
    p.add_argument("--offer-id", help="the public offer's ID, if it can't be found")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--apply", action="store_true", help="submit the change (default: show it)")
    a = p.parse_args(argv)

    offer_id = a.offer_id or public_offer(a.product_id)
    try:
        change = pricing_change(offer_id, offer_details(offer_id), a.days)
    except ValueError as e:
        sys.exit(str(e))
    print(json.dumps(change, indent=2))
    if not a.apply:
        print("\nNothing submitted. Check the prices above, then run again with --apply.")
        return 0
    out = aws("start-change-set", "--catalog", CATALOG,
              "--change-set-name", f"free-trial-{a.days}d",
              "--change-set", json.dumps([change]))
    cs = out.get("ChangeSetId", "?")
    print(f"\nSubmitted change set {cs}. Follow it with:")
    print(f"  aws marketplace-catalog describe-change-set --catalog {CATALOG} "
          f"--change-set-id {cs} --region us-east-1 --query Status")
    return 0


if __name__ == "__main__":
    sys.exit(main())
