# Baseline: the example sector policies as shipped in v1.13.0

Verbatim copies of `varek/v1_4/policies/*.policy.txt` at tag v1.13.0 (commit
d82ded5). `tools/verdict_harness.py` decides every corpus action against these
files as its "v1.13.0 shipped" view, so the comparison with v1.14 is against
what users actually had.

These files use no v1.14 matchers, so the v1.14 decision procedure decides them
exactly as v1.13.0 did. Do not deploy them: they are the policies v1.14
tightened (key material, dotenv files and sector-specific paths inside trees the
agent may otherwise reach).
