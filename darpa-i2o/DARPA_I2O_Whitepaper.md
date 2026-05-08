# ARCHITECTURE PROPOSAL: Autonomous Cyber Operations (ACO) Guardrails
**Target Directorate:** DARPA Information Innovation Office (I2O)  
**Relevance:** Adversarial Robustness, AI Assurance, Language Security (LangSec)  
**Defense Layer:** VAREK v1.3 (Deterministic OS-Level Containment & Supervisor Architecture)  

---

## 1. Executive Summary: The Gap in ACO Assurance

As the Department of Defense transitions toward Autonomous Cyber Operations (ACO), the deployment of LLM-backed agents at the tactical edge introduces a critical, systemic vulnerability: **Cognitive Bypasses via Untrusted Telemetry.**

Current DARPA portfolios rightly focus on the robustness of AI models. However, when an autonomous agent is granted local system execution privileges (e.g., for automated forensics, lateral movement, or network diagnostics), the ingestion of adversarial data (poisoned PCAPs, weaponized SIGINT) can hijack the agent's execution context. 

This results in **Remote Code Execution (RCE)** at the OS boundary, initiated by the DoD's own AI.

## 2. The Vulnerability: Probabilistic Failure
Current industry standard defenses rely on probabilistic wrappers (LLM-as-a-judge, prompt sanitization, heuristic filtering). In a contested electronic warfare environment, advanced adversaries will invariably find encoding structures that bypass probabilistic filters. 

When probabilistic defenses fail, the agent executes the adversary's instructions. Furthermore, interpreter-level hooks (like Python's PEP 578) are structurally insufficient, as child processes spawned via `subprocess` execute outside the parent's interpreter, blinding the hook to advanced evasion techniques.

## 3. The VAREK v1.3 Solution: Supervisor Architecture & Kernel Interception
**VAREK** abandons probabilistic text-filtering and interpreter-level illusions in favor of deterministic, hardware-enforced execution boundaries governed by a highly privileged parent process ("The Warden"). 

VAREK v1.3 decouples *model integrity* from *execution integrity* by moving admissibility control completely outside the memory space of the untrusted AI agent.

* **Kernel Interception Bridge (`seccomp-unotify`):** Instead of blindly terminating on syscalls, VAREK pauses the untrusted agent's execution thread directly at the kernel boundary to inspect raw system calls. 
* **Zero-Trust Memory Validation:** Operating with a ~22μs context-switch overhead, the Warden reads isolated memory arguments and injects verdicts (`SECCOMP_RET_ALLOW` or `EPERM` denials) directly back to the kernel, eliminating TOCTOU (Time-of-check to time-of-use) race conditions.
* **Stateful Execution Context:** VAREK applies O(1) semantic derivation by tracking file descriptors (FDs) across sequential syscalls to derive high-level intent before execution occurs.

If a hijacked ACO agent attempts an unauthorized syscall or network egress based on weaponized telemetry, the physical circuit breaker drops the execution thread instantly—maintaining mathematical containment.

---

## 4. Operational Proof of Concept

The attached Proof of Concept demonstrates an ACO agent analyzing a poisoned PCAP. The embedded payload successfully achieves a cognitive bypass on the LLM, instructing it to initiate a reverse shell. VAREK's Warden process intercepts the execution at the kernel boundary, evaluates the intent, and deterministically injects an `EPERM` denial.

### Deployment Scenario:
* **Node:** Tactical Edge Research Server
* **Vector:** Weaponized Network Traffic (PCAP)
* **Outcome:** Agent Hijacked -> seccomp-unotify Supervisor Intercept Triggered -> Node Integrity Maintained

**View the Core Architecture and I2O Intercept Implementation:**
[14-darpa-i2o-demo.py](https://github.com/kwdoug63/varek/blob/main/darpa-i2o/14-darpa-i2o-demo.py)

---
*Developed for evaluation by DARPA I2O Program Management.*
