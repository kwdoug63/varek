"""
VAREK v1.2 Policy Evaluator

Implements the policy decision engine described in VAREK v1.2 RFC.

Normative claims this module implements:
  §3.1 — Linear rule evaluation. Rules are scanned in declaration order;
         the first matching rule produces the decision.
  §3.2 — Decision types: ALLOW and DENY only. DEFER and TRANSFORM are
         deferred to v1.3 per §7.2.
  §4   — Per-transition evaluation latency is measured in microseconds
         and reported on every Decision.
  §5   — Fail-closed semantics. Any internal evaluator exception produces
         a DENY decision with reason "evaluator_error:<type>".
  §6   — Non-claims. Matching is performed against literal syscall names
         and argument values only. No semantic-layer matching, no content
         inspection, no covert-channel defense.

This module does NOT perform syscall interception. It evaluates Transition
objects supplied by an upstream layer:
  - In production: the v1.1 seccomp-unotify integration (v1.2.1).
  - In the v1.2 demo: the simulator harness in varek/v1_2/sim/.

Stateful policies (rate limit counters being the only state v1.2 supports)
are not yet implemented in this cut. See TODO marker in evaluate().
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


# ---------------------------------------------------------------------------
# Decision types — RFC §3.2
# ---------------------------------------------------------------------------

class DecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating a single transition against a policy.

    Attributes:
        type:       ALLOW or DENY (RFC §3.2).
        reason:     Human-readable explanation. For matched rules, taken
                    from rule.reason. For default outcomes, supplied by
                    the policy. For fail-closed errors, of the form
                    "evaluator_error:<ExceptionTypeName>".
        policy_id:  ID of the matched rule, or None if the decision came
                    from the policy default or the fail-closed path.
        eval_us:    Wall-clock evaluation time in microseconds (RFC §4).
        audit_log:  Mirrors the matched rule's audit_log flag. The
                    decision_log layer uses this to gate verbose logging.
    """
    type: DecisionType
    reason: str
    policy_id: str | None
    eval_us: float
    audit_log: bool = False

    @property
    def allowed(self) -> bool:
        return self.type is DecisionType.ALLOW


# ---------------------------------------------------------------------------
# Transition input — RFC §3.1
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Transition:
    """A single syscall transition observed (or simulated).

    The args dict is an opaque mapping of syscall-argument names to values
    — destination host, port, file path, mode flags, etc. — surfaced by
    the upstream interception layer. The evaluator treats values as
    literals and does not parse or interpret them (RFC §6).
    """
    syscall: str
    args: Mapping[str, Any] = field(default_factory=dict)
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))


# ---------------------------------------------------------------------------
# Rule + Policy types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    """A single policy rule.

    match_syscall is the syscall name (exact equality).

    match_args is a mapping from arg name to matcher. A matcher is one of:
      - a literal value      → exact equality
      - a list / tuple / set → membership
      - a callable           → predicate(value) → bool

    All entries in match_args must match for the rule to fire. An empty
    match_args means "match any args for this syscall."
    """
    id: str
    decision: DecisionType
    match_syscall: str
    match_args: Mapping[str, Any] = field(default_factory=dict)
    reason: str = ""
    audit_log: bool = False


@dataclass(frozen=True)
class Policy:
    """An ordered rule list with a default decision when no rule matches.

    The default is DENY in the reference bundle and should remain DENY in
    any policy that claims fail-closed semantics. Operators can override
    only with explicit intent.
    """
    name: str
    version: str
    rules: Sequence[Rule]
    default: DecisionType = DecisionType.DENY
    default_reason: str = "no rule matched; default deny"


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _arg_matches(matcher: Any, value: Any) -> bool:
    """Apply a single matcher to an arg value."""
    if callable(matcher):
        return bool(matcher(value))
    if isinstance(matcher, (list, tuple, set, frozenset)):
        return value in matcher
    return matcher == value


def _rule_matches(rule: Rule, transition: Transition) -> bool:
    if rule.match_syscall != transition.syscall:
        return False
    for argname, matcher in rule.match_args.items():
        if argname not in transition.args:
            return False
        if not _arg_matches(matcher, transition.args[argname]):
            return False
    return True


# ---------------------------------------------------------------------------
# Evaluation core
# ---------------------------------------------------------------------------

def _evaluate_inner(
    transition: Transition,
    policy: Policy,
) -> tuple[DecisionType, str, str | None, bool]:
    """Pure decision logic. May raise; evaluate() wraps this fail-closed.

    Returns:
        (decision_type, reason, policy_id, audit_log)
    """
    # TODO §3.4: stateful rate-limit counters. v1.2 supports execution-scoped
    # rate limit state per the RFC. This cut omits it; the three demo
    # scenarios (allow / deny / fail_closed) do not exercise rate limits.
    for rule in policy.rules:
        if _rule_matches(rule, transition):
            reason = rule.reason or f"matched rule {rule.id}"
            return rule.decision, reason, rule.id, rule.audit_log
    return policy.default, policy.default_reason, None, False


def evaluate(transition: Transition, policy: Policy) -> Decision:
    """Evaluate a transition against a policy.

    This is the public entry point and the only function external callers
    should invoke. It guarantees:

      - A Decision is always returned. No exception ever propagates to
        the caller. On any internal error, decision.type is DENY and
        decision.reason is "evaluator_error:<ExceptionTypeName>".
        This is the RFC §5 fail-closed claim.

      - decision.eval_us reflects wall-clock time spent inside this
        function, including the fail-closed path. RFC §4 instrumentation.

    Args:
        transition: The syscall transition to evaluate.
        policy:     The policy to evaluate against.

    Returns:
        A Decision. Never raises.
    """
    start_ns = time.perf_counter_ns()
    try:
        decision_type, reason, policy_id, audit_log = _evaluate_inner(
            transition, policy
        )
    except Exception as exc:  # noqa: BLE001 — fail-closed swallows everything
        eval_us = (time.perf_counter_ns() - start_ns) / 1000.0
        return Decision(
            type=DecisionType.DENY,
            reason=f"evaluator_error:{type(exc).__name__}",
            policy_id=None,
            eval_us=eval_us,
            audit_log=True,  # always log fail-closed events
        )
    eval_us = (time.perf_counter_ns() - start_ns) / 1000.0
    return Decision(
        type=decision_type,
        reason=reason,
        policy_id=policy_id,
        eval_us=eval_us,
        audit_log=audit_log,
    )