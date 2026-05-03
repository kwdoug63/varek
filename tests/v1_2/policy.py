import yaml
from typing import Any, Dict, List, Union
from pathlib import Path

from varek.v1_2.evaluator import Policy, Rule, DecisionType

class PolicyLoadError(Exception):
    """Raised when a policy YAML is malformed or invalid."""
    pass

def _parse_decision(decision_str: str) -> DecisionType:
    """Safely parse a string into a DecisionType enum."""
    d = str(decision_str).strip().lower()
    if d == "allow":
        return DecisionType.ALLOW
    if d == "deny":
        return DecisionType.DENY
    raise PolicyLoadError(f"Invalid decision type: '{decision_str}'. Must be 'allow' or 'deny'.")

def _compile_match_args(raw_args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms YAML arguments into evaluator-friendly matchers.
    For example, translates YAML lists into Python sets for O(1) membership testing.
    """
    compiled = {}
    for key, value in raw_args.items():
        if isinstance(value, list):
            # Convert YAML lists to frozen sets for the membership matcher
            compiled[key] = frozenset(value)
        else:
            compiled[key] = value
    return compiled

def load_from_yaml(yaml_content: str) -> Policy:
    """Parses a YAML string into a typed Policy object."""
    try:
        data = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        raise PolicyLoadError(f"Failed to parse YAML: {e}")

    if not isinstance(data, dict):
        raise PolicyLoadError("Policy root must be a dictionary")

    rules_data = data.get('rules', [])
    if not isinstance(rules_data, list):
        raise PolicyLoadError("'rules' must be a list")

    rules = []
    for r in rules_data:
        if 'id' not in r:
            raise PolicyLoadError("Rule is missing required 'id' field")
            
        match_block = r.get('match', {})
        
        rule = Rule(
            id=str(r['id']),
            decision=_parse_decision(r.get('decision', 'deny')),
            match_syscall=match_block.get('syscall'),
            match_args=_compile_match_args(match_block.get('args', {})),
            reason=str(r.get('reason', '')),
            audit_log=bool(r.get('audit_log', False))
        )
        rules.append(rule)

    return Policy(
        name=str(data.get('name', 'unnamed_policy')),
        version=str(data.get('version', '1.0')),
        rules=rules,
        default_decision=_parse_decision(data.get('default_decision', 'deny')),
        default_reason=str(data.get('default_reason', 'no rule matched; default deny'))
    )

def load_from_file(file_path: Union[str, Path]) -> Policy:
    """Reads a YAML file from disk and parses it into a typed Policy object."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Policy file not found: {path}")
        
    with open(path, 'r', encoding='utf-8') as f:
        return load_from_yaml(f.read())