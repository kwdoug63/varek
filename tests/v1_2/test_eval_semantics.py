"""
VAREK v1.2 Evaluator — Semantic Tests

Maps directly to VAREK v1.2 RFC sections. Each test class corresponds to
a normative claim in the RFC. Test names describe the specific behavior
under test. A reviewer can hold the RFC open in one window and run::

    pytest tests/v1_2/test_eval_semantics.py -v

…to verify the spec section-by-section against the implementation.

Run from repo root with the project venv active.
"""

from __future__ import annotations

import pytest

from varek.v1_2.evaluator import (
    Decision,
    DecisionType,
    Policy,
    Rule,
    Transition,
    evaluate,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_policy(*rules: Rule, default: DecisionType = DecisionType.DENY) -> Policy:
    return Policy(name="test", version="0.0.0", rules=rules, default=default)


def t(syscall: str, **args) -> Transition:
    return Transition(syscall=syscall, args=args)


# ---------------------------------------------------------------------------
# RFC §3.1 — Linear rule evaluation
# ---------------------------------------------------------------------------

class TestSection3_1_LinearEvaluation:
    """§3.1: rules are scanned in declaration order; first match wins."""

    def test_first_matching_rule_wins(self):
        policy = make_policy(
            Rule(id="r1", decision=DecisionType.ALLOW, match_syscall="connect"),
            Rule(id="r2", decision=DecisionType.DENY, match_syscall="connect"),
        )
        d = evaluate(t("connect", host="example.com"), policy)
        assert d.allowed is True
        assert d.policy_id == "r1"

    def test_later_rule_fires_when_earlier_does_not_match(self):
        policy = make_policy(
            Rule(id="r1", decision=DecisionType.ALLOW, match_syscall="open"),
            Rule(id="r2", decision=DecisionType.ALLOW, match_syscall="connect"),
        )
        d = evaluate(t("connect"), policy)
        assert d.allowed is True
        assert d.policy_id == "r2"

    def test_default_decision_when_no_rule_matches(self):
        policy = make_policy(
            Rule(id="r1", decision=DecisionType.ALLOW, match_syscall="open"),
            default=DecisionType.DENY,
        )
        d = evaluate(t("execve"), policy)
        assert d.allowed is False
        assert d.policy_id is None
        assert "default deny" in d.reason

    def test_empty_policy_returns_default(self):
        policy = make_policy(default=DecisionType.DENY)
        d = evaluate(t("connect"), policy)
        assert d.type is DecisionType.DENY
        assert d.policy_id is None


# ---------------------------------------------------------------------------
# RFC §3.2 — Decision types (ALLOW / DENY only; DEFER + TRANSFORM in v1.3)
# ---------------------------------------------------------------------------

class TestSection3_2_DecisionTypes:
    """§3.2: only ALLOW and DENY are supported. Verified by enum membership."""

    def test_only_allow_and_deny_exist(self):
        assert {d.value for d in DecisionType} == {"allow", "deny"}

    def test_allow_decision(self):
        policy = make_policy(
            Rule(id="r1", decision=DecisionType.ALLOW, match_syscall="connect"),
        )
        d = evaluate(t("connect"), policy)
        assert d.type is DecisionType.ALLOW
        assert d.allowed is True

    def test_deny_decision(self):
        policy = make_policy(
            Rule(id="r1", decision=DecisionType.DENY, match_syscall="connect"),
        )
        d = evaluate(t("connect"), policy)
        assert d.type is DecisionType.DENY
        assert d.allowed is False

    def test_custom_default_allow_honored(self):
        policy = make_policy(default=DecisionType.ALLOW)
        d = evaluate(t("connect"), policy)
        assert d.type is DecisionType.ALLOW


# ---------------------------------------------------------------------------
# RFC §3 — Argument matching semantics
# ---------------------------------------------------------------------------

class TestSection3_ArgumentMatching:
    """§3: match_args is AND-conjunctive; matchers are literal, membership,
    or predicate. No interpretation of arg values."""

    def test_syscall_mismatch_does_not_fire(self):
        policy = make_policy(
            Rule(id="r1", decision=DecisionType.ALLOW, match_syscall="connect"),
        )
        d = evaluate(t("write"), policy)
        assert d.policy_id is None  # default fired

    def test_empty_match_args_matches_any_args(self):
        policy = make_policy(
            Rule(id="r1", decision=DecisionType.ALLOW, match_syscall="connect"),
        )
        d = evaluate(t("connect", host="anything", port=12345), policy)
        assert d.policy_id == "r1"

    def test_literal_arg_match(self):
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="connect",
                match_args={"port": 443},
            ),
        )
        assert evaluate(t("connect", port=443), policy).policy_id == "r1"
        assert evaluate(t("connect", port=80), policy).policy_id is None

    def test_membership_matcher(self):
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="connect",
                match_args={"port": [443, 8443]},
            ),
        )
        assert evaluate(t("connect", port=443), policy).policy_id == "r1"
        assert evaluate(t("connect", port=8443), policy).policy_id == "r1"
        assert evaluate(t("connect", port=80), policy).policy_id is None

    def test_callable_predicate_matcher(self):
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="connect",
                match_args={"host": lambda h: h.endswith(".github.com")},
            ),
        )
        assert evaluate(t("connect", host="api.github.com"), policy).policy_id == "r1"
        assert evaluate(t("connect", host="evil.com"), policy).policy_id is None

    def test_missing_arg_fails_match(self):
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="connect",
                match_args={"port": 443},
            ),
        )
        d = evaluate(t("connect", host="example.com"), policy)  # no port
        assert d.policy_id is None

    def test_all_match_args_must_match(self):
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="connect",
                match_args={"host": "api.github.com", "port": 443},
            ),
        )
        # both match → fires
        assert evaluate(t("connect", host="api.github.com", port=443), policy).policy_id == "r1"
        # only host matches → does not fire
        assert evaluate(t("connect", host="api.github.com", port=80), policy).policy_id is None
        # only port matches → does not fire
        assert evaluate(t("connect", host="evil.com", port=443), policy).policy_id is None


# ---------------------------------------------------------------------------
# RFC §4 — Latency instrumentation
# ---------------------------------------------------------------------------

class TestSection4_LatencyInstrumentation:
    """§4: every Decision carries eval_us measured by the evaluator."""

    def test_eval_us_set_on_match(self):
        policy = make_policy(
            Rule(id="r1", decision=DecisionType.ALLOW, match_syscall="connect"),
        )
        d = evaluate(t("connect"), policy)
        assert d.eval_us >= 0
        assert isinstance(d.eval_us, float)

    def test_eval_us_set_on_default(self):
        policy = make_policy(default=DecisionType.DENY)
        d = evaluate(t("connect"), policy)
        assert d.eval_us >= 0

    def test_eval_us_bounded_under_pathological_threshold(self):
        """Generous bound — catches catastrophic regressions, not microbench."""
        rules = [
            Rule(id=f"r{i}", decision=DecisionType.DENY, match_syscall=f"sys{i}")
            for i in range(200)
        ]
        policy = make_policy(*rules)
        d = evaluate(t("sys199"), policy)
        # 200 rules × literal compare should be far under 100ms
        assert d.eval_us < 100_000


# ---------------------------------------------------------------------------
# RFC §5 — Fail-closed semantics
# ---------------------------------------------------------------------------

class TestSection5_FailClosed:
    """§5: any internal evaluator exception → DENY with structured reason.
    No exception propagates to the caller."""

    def test_predicate_exception_yields_deny(self):
        def boom(_value):
            raise ValueError("policy bug")
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="connect",
                match_args={"host": boom},
            ),
        )
        d = evaluate(t("connect", host="anything"), policy)
        assert d.type is DecisionType.DENY
        assert d.reason == "evaluator_error:ValueError"
        assert d.policy_id is None

    def test_fail_closed_forces_audit_log(self):
        def boom(_value):
            raise RuntimeError("kaboom")
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="connect",
                match_args={"host": boom},
            ),
        )
        d = evaluate(t("connect", host="anything"), policy)
        assert d.audit_log is True

    def test_fail_closed_eval_us_still_measured(self):
        def boom(_value):
            raise KeyError("missing")
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="connect",
                match_args={"host": boom},
            ),
        )
        d = evaluate(t("connect", host="anything"), policy)
        assert d.eval_us >= 0

    def test_no_exception_propagates(self):
        def boom(_value):
            raise SystemError("evaluator should swallow this")
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="connect",
                match_args={"host": boom},
            ),
        )
        # If §5 is broken, this raises and pytest fails with the exception.
        d = evaluate(t("connect", host="anything"), policy)
        assert d.type is DecisionType.DENY

    def test_exception_type_recorded_in_reason(self):
        class CustomError(Exception):
            pass

        def boom(_value):
            raise CustomError("specific failure")
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="connect",
                match_args={"host": boom},
            ),
        )
        d = evaluate(t("connect", host="x"), policy)
        assert d.reason == "evaluator_error:CustomError"


# ---------------------------------------------------------------------------
# RFC §6 — Non-claims: matching is literal, no semantic interpretation
# ---------------------------------------------------------------------------

class TestSection6_NonClaims:
    """§6: the evaluator performs literal matching only. It does NOT do
    path normalization, URL parsing, or semantic-layer matching. These
    tests document the boundary by asserting the absence of interpretation."""

    def test_no_path_normalization(self):
        """Rule for /etc/passwd does not match /etc/./passwd."""
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.DENY,
                match_syscall="open",
                match_args={"path": "/etc/passwd"},
            ),
        )
        d = evaluate(t("open", path="/etc/./passwd"), policy)
        assert d.policy_id is None  # default fired, not r1

    def test_no_url_parsing(self):
        """A rule on host='github.com' does not match a url= field
        containing 'github.com' as a substring."""
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="connect",
                match_args={"host": "github.com"},
            ),
        )
        # transition supplies url, not host — no match
        d = evaluate(t("connect", url="https://github.com/foo"), policy)
        assert d.policy_id is None

    def test_semantic_syscall_names_not_interpreted(self):
        """A rule for syscall='connect' does not match a semantic-layer
        transition labeled 'HTTPRequest', and vice versa. Names are
        literals; v1.2 does not bridge layers."""
        policy = make_policy(
            Rule(id="r1", decision=DecisionType.ALLOW, match_syscall="connect"),
        )
        d = evaluate(t("HTTPRequest", host="api.github.com"), policy)
        assert d.policy_id is None

    def test_no_content_inspection(self):
        """Identical syscall + args except for opaque payload: matcher
        cannot distinguish. v1.2 does not inspect content (RFC §6)."""
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="write",
                match_args={"fd": 1},
            ),
        )
        # same fd, different content — both match identically
        d1 = evaluate(t("write", fd=1, payload=b"hello"), policy)
        d2 = evaluate(t("write", fd=1, payload=b"secrets-being-exfiltrated"), policy)
        assert d1.allowed and d2.allowed
        assert d1.policy_id == d2.policy_id == "r1"


# ---------------------------------------------------------------------------
# Decision invariants
# ---------------------------------------------------------------------------

class TestDecisionInvariants:
    """Properties that must hold across any evaluation path."""

    def test_decision_is_immutable(self):
        d = evaluate(t("connect"), make_policy())
        with pytest.raises(Exception):
            d.type = DecisionType.ALLOW  # type: ignore[misc]

    def test_audit_log_propagates_from_rule(self):
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.ALLOW,
                match_syscall="connect",
                audit_log=True,
            ),
        )
        d = evaluate(t("connect"), policy)
        assert d.audit_log is True

    def test_audit_log_default_false_when_unset(self):
        policy = make_policy(
            Rule(id="r1", decision=DecisionType.ALLOW, match_syscall="connect"),
        )
        d = evaluate(t("connect"), policy)
        assert d.audit_log is False

    def test_reason_uses_rule_text_when_provided(self):
        policy = make_policy(
            Rule(
                id="r1",
                decision=DecisionType.DENY,
                match_syscall="connect",
                reason="egress denied: not in allowlist",
            ),
        )
        d = evaluate(t("connect"), policy)
        assert d.reason == "egress denied: not in allowlist"

    def test_reason_falls_back_to_rule_id_when_blank(self):
        policy = make_policy(
            Rule(id="r1", decision=DecisionType.ALLOW, match_syscall="connect"),
        )
        d = evaluate(t("connect"), policy)
        assert "r1" in d.reason