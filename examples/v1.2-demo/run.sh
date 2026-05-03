#!/bin/bash
set -e

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Fix: Go up TWO levels (from examples/v1.2-demo) to hit the repo root
REPO_ROOT="$(cd "$DEMO_DIR/../.." && pwd)"
export PYTHONPATH="$REPO_ROOT"

clear
echo "========================================================"
echo " VAREK v1.2 Evaluator Demo - Agentic Code Execution"
echo "========================================================"

echo ""
echo "--------------------------------------------------------"
echo " SCENARIO 1: The Allow Path"
echo " Expectation: Safe egress to GitHub is permitted."
echo "--------------------------------------------------------"
python "$REPO_ROOT/varek/v1_2/sim/agent.py" allow "$DEMO_DIR/policy.yaml"

sleep 2
echo ""
echo "--------------------------------------------------------"
echo " SCENARIO 2: The Deny Path"
echo " Expectation: Exfiltration attempt is blocked and logged."
echo "--------------------------------------------------------"
python "$REPO_ROOT/varek/v1_2/sim/agent.py" deny "$DEMO_DIR/policy.yaml"

sleep 2
echo ""
echo "--------------------------------------------------------"
echo " SCENARIO 3: The Fail-Closed Path"
echo " Expectation: Corrupted data mid-evaluation yields DENY."
echo "--------------------------------------------------------"
python "$REPO_ROOT/varek/v1_2/sim/agent.py" fail_closed "$DEMO_DIR/policy.yaml"
echo ""
echo "========================================================"
echo " Demo complete."