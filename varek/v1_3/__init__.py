"""
VAREK v1.3 — policy-evaluator prototype (deprecated; see DEPRECATED.md).

The current implementation is the C Warden in varek/v1_4/.

This package once re-exported the VAREK language front end (lexer, parser,
type checker) from a `varek` package that is not part of this repository — the
language lives in varek-v1.0/ — so importing anything under varek.v1_3 failed
and its tests could not be collected. The prototype does not use the language;
its modules (evaluator, policy, decision_log, warden, seccomp_bridge) import
only each other.
"""

__version__ = "1.3.0"
