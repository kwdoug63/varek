import json
import time
import sys
from typing import Optional
from pathlib import Path
from varek.v1_2.evaluator import Decision

class DecisionLogger:
    """Streams evaluator decisions as JSONL for audit and compliance."""
    
    def __init__(self, log_path: Optional[str | Path] = None):
        self.log_path = Path(log_path) if log_path else None
        # Ensure directory exists if a path is provided
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, execution_id: str, syscall: str, args: dict, matched_rule_id: str, decision: Decision, eval_us: float) -> None:
        """Writes a single decision record."""
        
        # Format the args for readability in the log (e.g., dest_host:dest_port)
        target = f"{args.get('dest_host', '')}:{args.get('dest_port', '')}".strip(':')
        if not target:
            target = str(args)

        entry = {
            "ts": time.time(),
            "execution_id": execution_id,
            "syscall": syscall,
            "target": target,
            "policy_id": matched_rule_id,
            "decision": decision.type.value, # "allow" or "deny"
            "reason": decision.reason,
            "eval_us": round(eval_us, 2)
        }
        
        payload = json.dumps(entry)
        
        # Always print to stdout for the demo visualization
        # We use stderr or a specific prefix so it can be distinguished from agent stdout
        print(f"  ↳ [VAREK AUDIT] {payload}", file=sys.stderr)
        
        # Append to the audit file if configured
        if self.log_path:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(payload + '\n')
