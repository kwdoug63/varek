# Baseline: the example sector policies as shipped in v1.12.4

Verbatim copies of `varek/v1_4/policies/*.policy.txt` at tag v1.12.4 (commit
af8c1f0). `tools/verdict_harness.py` decides every corpus action against these
files as its "v1.12.4 as shipped" view, so the comparison with v1.13 is against
what users actually had, not against a reconstruction.

These files contain no flag clauses, so the v1.13 decision procedure decides
them exactly as the v1.12.4 matcher did for every action in the corpus (the
corpus uses only ABI-defined open flags and never access mode 3). Do not deploy
them: they are the policies v1.13 fixed.
