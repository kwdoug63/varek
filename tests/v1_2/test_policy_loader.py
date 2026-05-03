import pytest
import yaml
from varek.v1_2.evaluator import DecisionType
from varek.v1_2.policy import load_from_yaml, PolicyLoadError

VALID_YAML = """
name: "agentic-code-execution"
version: "1.2"
default_decision: "deny"
default_reason: "implicit global deny"
rules:
  - id: "allow-github-api"
    decision: "allow"
    match:
      syscall: "connect"
      args:
        dest_port: 443
        dest_host: "api.github.com"
    reason: "allow outbound to Github API"
    audit_log: true
  - id: "allow-pypi-ports"
    decision: "allow"
    match:
      syscall: "connect"
      args:
        dest_port: [80, 443]
"""

class TestPolicyLoader:
    def test_successful_yaml_load(self):
        policy = load_from_yaml(VALID_YAML)
        
        assert policy.name == "agentic-code-execution"
        assert policy.version == "1.2"
        assert policy.default == DecisionType.DENY
        assert len(policy.rules) == 2
        
    def test_rule_parsing_semantics(self):
        policy = load_from_yaml(VALID_YAML)
        rule1 = policy.rules[0]
        
        assert rule1.id == "allow-github-api"
        assert rule1.decision == DecisionType.ALLOW
        assert rule1.match_syscall == "connect"
        assert rule1.match_args["dest_port"] == 443
        assert rule1.audit_log is True

    def test_yaml_list_translates_to_frozenset_for_membership_matching(self):
        policy = load_from_yaml(VALID_YAML)
        rule2 = policy.rules[1]
        
        assert isinstance(rule2.match_args["dest_port"], frozenset)
        assert 80 in rule2.match_args["dest_port"]
        
    def test_malformed_yaml_raises_load_error(self):
        with pytest.raises(PolicyLoadError):
            load_from_yaml("name: [unclosed list")

    def test_invalid_decision_type_raises_error(self):
        bad_yaml = """
        rules:
          - id: "bad-rule"
            decision: "maybe"
        """
        with pytest.raises(PolicyLoadError, match="Invalid decision type"):
            load_from_yaml(bad_yaml)
            
    def test_missing_rule_id_raises_error(self):
        bad_yaml = """
        rules:
          - decision: "allow"
        """
        with pytest.raises(PolicyLoadError, match="missing required 'id'"):
            load_from_yaml(bad_yaml)
