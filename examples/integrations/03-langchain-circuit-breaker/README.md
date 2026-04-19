# Hardening LangChain Agents: Building Deterministic Circuit Breakers with LLVM

**Stop securing probabilistic agents with probabilistic glue code.**

Agentic workflows are powerful, but relying purely on runtime Python validation (`pydantic`) for critical API calls can lead to unhandled exceptions and infinite retry loops. When an LLM hallucinates a malformed JSON payload for a database write or API execution, dynamic validation results in silent failures, dropped fields, or infinite retry loops. In a high-consequence enterprise environment, this is a kinetic liability.

For production, you need a physical consequence boundary.

## The Architecture: Physics, Not Policy

This directory demonstrates how to wrap a LangChain `AgentExecutor` with a **VAREK LLVM Gateway**. 

Instead of relying on Python's runtime environment to coerce or reject bad JSON—which triggers LangChain's internal retry mechanisms—VAREK routes the memory pointer directly into a compiled Rust LLVM binary. If the schema violates the deterministic boundary, the circuit physically snaps at the machine-code level in sub-50ms. 

No retry loop. No runtime coercion. A deterministic hard fault.

### 1. The LLVM Physics Engine (`varek_core/src/lib.rs`)
The compiled core. It bypasses Python entirely, operating via FFI. It physically parses the memory geometry of the payload. If the LLM hallucinates an unexpected `DROP TABLE` or schema violation, it returns a hard `false`.

### 2. The LangChain Intercept (`circuit_breaker.py`)
A custom LangChain `BaseTool` that replaces fragile Pydantic validation. It passes the memory pointer to the VAREK compiler. If VAREK rejects the data geometry, the tool raises a fatal `RuntimeError`, physically killing the execution thread and preventing the agent from infinitely retrying.

### 3. The Execution Script (`agent_execution.py`)
The deployment script. We arm a standard `ZeroShotReactDescription` agent with the VAREK-secured tool and intentionally prompt-inject it to execute a destructive database write.

## The Execution Log

When the agent goes rogue, VAREK physically snaps the execution graph before it touches the backend:

```text
> Entering new AgentExecutor chain...
Thought: I need to use the secure_database_write tool.
Action: secure_database_write
Action Input: {"action": "update", "unauthorized_action": "DROP TABLE users;"}
[LANGCHAIN] Agent attempting write: {"action": "update", "unauthorized_action": "DROP TABLE users;"}

[VAREK] KINETIC INTERCEPT TRIGGERED.
[VAREK] Hallucination detected outside consequence boundary.
[VAREK] Execution physically halted. 0.012ms latency.

SRE ALERT: Agent execution terminated by VAREK. Reason: VAREK_HARD_FAULT: Schema violation.
