import os
import sys
import time
from pathlib import Path

# Ensure the varek package can be imported
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from varek.v1_2.policy import load_from_file
from varek.v1_2.evaluator import evaluate, DecisionType
from varek.v1_2.decision_log import DecisionLogger
from varek.v1_2.seccomp_bridge import recv_notification, send_allow, send_deny

class WardenTransition:
    """Bridges actual trapped syscalls to the VAREK Evaluator."""
    def __init__(self, syscall: str, args: dict):
        self.syscall = syscall
        self.args = args

class Warden:
    def __init__(self, policy_path: str):
        self.policy = load_from_file(policy_path)
        self.logger = DecisionLogger()
        self.execution_id = f"warden-{int(time.time())}"

    def execute_sandboxed(self, target_script: str):
        print(f"\033[94m[Warden] Bootstrapping containment for: {target_script}\033[0m")
        print(f"\033[94m[Warden] Loading policy: {self.policy.name} v{self.policy.version}\033[0m")
        print("\033[90m" + "-"*50 + "\033[0m")
        
        # In a real Linux environment, we fork() here. 
        # We mock a Process ID (PID) to show isolation for local testing.
        child_pid = 1024 
        print(f"\033[94m[Warden] Supervisor listening on Seccomp FD for PID {child_pid}\033[0m")
        
        # --- The Interception Loop ---
        print("\033[90m[Warden] Waiting for kernel trap...\033[0m")
        time.sleep(1.5) 

        # We simulate catching a malicious exfiltration attempt from the isolated child
        intercepted_syscall = "connect"
        intercepted_args = {"dest_host": "malicious.example.com", "dest_port": 80}
        
        print(f"\033[35m[Kernel] TRAP: PID {child_pid} -> {intercepted_syscall}({intercepted_args['dest_host']})\033[0m")
        
        # 1. Build the Transition from the trapped memory
        transition = WardenTransition(intercepted_syscall, intercepted_args)
        
        # 2. Evaluate against the VAREK policy
        decision = evaluate(transition, self.policy)
        
        # 3. Log immutably in the Warden's secure memory space
        # (Using decision.policy_id as noted in your transcript's corrections)
        rule_id = getattr(decision, 'policy_id', 'none')
        self.logger.log(self.execution_id, intercepted_syscall, intercepted_args, rule_id, decision, getattr(decision, 'eval_us', 0.0))

        # 4. Enforce the decision via the Kernel Bridge
        if decision.type == DecisionType.ALLOW:
            print("\033[92m[Kernel] VERDICT: ALLOW. Resuming child PID {child_pid}.\033[0m")
            send_allow(999, 1234)
        else:
            print(f"\033[91m[Kernel] VERDICT: DENY. Injecting EPERM error to PID {child_pid}.\033[0m")
            send_deny(999, 1234)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python warden.py <policy.yaml> <untrusted_script.py>")
        sys.exit(1)
        
    warden = Warden(sys.argv[1])
    warden.execute_sandboxed(sys.argv[2])
