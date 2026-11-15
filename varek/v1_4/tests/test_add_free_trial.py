# SPDX-License-Identifier: MIT
"""Tests for packaging/aws-marketplace/add_free_trial.py (v1.39.1). AWS is never called."""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # varek/v1_4
sys.path.insert(0, os.path.join(HERE, "packaging", "aws-marketplace"))
import add_free_trial as ft  # noqa: E402

OFFER = {
    "PricingModel": "Usage",
    "Terms": [
        {"Id": "term-1", "Type": "UsageBasedPricingTerm", "CurrencyCode": "USD",
         "RateCards": [{"RateCard": [{"DimensionKey": "t3.medium", "Price": "8.56"},
                                     {"DimensionKey": "m5.large", "Price": "8.56"}]}]},
        {"Id": "term-2", "Type": "LegalTerm", "Documents": [{"Type": "StandardEula"}]},
        {"Id": "term-3", "Type": "FreeTrialPricingTerm", "Duration": "P7D",
         "Grants": [{"DimensionKey": "t3.medium"}]},
        {"Id": "term-4", "Type": "SupportTerm", "RefundPolicy": "x"},
    ],
}


def test_keeps_prices_and_replaces_the_trial():
    c = ft.pricing_change("offer-abc", OFFER, 30)
    assert c["ChangeType"] == "UpdatePricingTerms"
    assert c["Entity"] == {"Type": "Offer@1.0", "Identifier": "offer-abc"}
    terms = c["DetailsDocument"]["Terms"]
    assert [t["Type"] for t in terms] == ["UsageBasedPricingTerm", "FreeTrialPricingTerm"]
    assert terms[0]["RateCards"][0]["RateCard"][0] == {"DimensionKey": "t3.medium", "Price": "8.56"}
    assert terms[1] == {"Type": "FreeTrialPricingTerm", "Duration": "P30D",
                        "Grants": [{"DimensionKey": "t3.medium"}, {"DimensionKey": "m5.large"}]}
    assert "term-" not in str(c)                   # describe-entity's term IDs are not sent back
    assert c["DetailsDocument"]["PricingModel"] == "Usage"


@pytest.mark.parametrize("days", [4, 32])
def test_days_out_of_range(days):
    with pytest.raises(ValueError, match="5 to 31"):
        ft.pricing_change("offer-abc", OFFER, days)


def test_needs_hourly_prices_first():
    with pytest.raises(ValueError, match="no hourly prices"):
        ft.pricing_change("offer-abc", {"Terms": [OFFER["Terms"][1]]}, 30)
