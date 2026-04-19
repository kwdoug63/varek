"""
09-prefect-task-intercept.py
Target: Prefect Orchestration Framework
Vector: Untrusted LLM/Dynamic Code Execution within a Prefect Task
Defense: VAREK Defense-in-Depth (AST + PEP 578)
"""
from prefect import flow, task
from varek_guardrails import secure_exec

print("=== INITIALIZING PREFECT ORCHESTRATION SCENARIO ===")

_FORBIDDEN = {'os', 'shutil', 'subprocess', 'ctypes'}

def _varek_import(name, *args, **kwargs):
    if name in _FORBIDDEN:
        raise RuntimeError(f"[VAREK RUNTIME WARDEN] Kinetic Intercept: Dynamic import of '{name}' blocked.")
    return __import__(name, *args, **kwargs)

_RESTRICTED_GLOBALS = {"__builtins__": {**vars(__builtins__), "__import__": _varek_import}}

# 2. The Vulnerable Task (Simulating LLM-generated code execution)
@task
def execute_agentic_payload(code_string):
    print("\n[PREFECT] Task executing dynamic payload...")
    print("[VAREK] Arming AST Static Gate and restricted exec boundary...")
    # AST static gate, then exec inside restricted globals (blocks __import__ bypass)
    secure_exec(code_string)
    exec(code_string, _RESTRICTED_GLOBALS)

# 3. The Orchestration Flow
@flow(name="AI-Orchestrated Pipeline")
def secure_ai_flow():
    # Simulating a prompt-injected LLM response passed into the data pipeline
    # Using obfuscated dynamic import to bypass standard static analysis
    malicious_code = """
# Agent hallucination/injection: Exfiltrate environment variables
env_vars = __import__('o'+'s').environ
with open('exfiltrated_keys.txt', 'w') as f:
    f.write(str(env_vars))
print("Keys secured.")
"""
    execute_agentic_payload(malicious_code)

# 4. Execution & Intercept
if __name__ == "__main__":
    try:
        secure_ai_flow()
    except Exception as e:
        print("\n[!] KINETIC INTERCEPT TRIGGERED [!]")
        print(f"[VAREK] Unauthorized kernel interaction dynamically blocked inside Prefect Task.")
        print(f"[REASON] {e}")

print("\n=== SCENARIO TERMINATED ===")
