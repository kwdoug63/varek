# Sovereign AI Security: Kinetic Guardrails for Edge Computing

This repository demonstrates the integration of the **VAREK** defense-in-depth architecture, designed to secure localized, autonomous LLM and AI workloads operating in isolated or edge network environments (C4ISR, UAVs, satellite systems).

## The Tactical Challenge
As defense contractors deploy autonomous AI agents to edge devices, the risk of "Sensor-Driven Prompt Injection" creates a critical vulnerability. Standard static analysis and EDR (Endpoint Detection and Response) are insufficient on low-power edge nodes, and prompt-injected LLMs can execute arbitrary Python commands (`os`, `subprocess`) to compromise host firmware.

## The VAREK Architecture
VAREK establishes a zero-trust, mathematically safe execution loop native to the CPython interpreter:
1. **Static AST Gate:** Pre-execution parsing prevents explicit unauthorized module imports.
2. **PEP 578 Runtime Warden:** Dynamic audit hooks physically snap unauthorized kernel interactions at runtime, neutralizing heavily obfuscated bypass attempts.

## Edge Deployment Proof of Concept
View the simulated C4ISR edge-node intercept telemetry here:
[11-lmco-edge-ai-varek-intercept.py](./11-lmco-edge-ai-varek-intercept.py)

**Status:** Ready for integration with internal DevSecOps Software Factories.