# ARCHITECTURE PROPOSAL: Autonomous Cyber Operations (ACO) Guardrails
**Target Directorate:** DARPA Information Innovation Office (I2O)  
**Relevance:** Adversarial Robustness, AI Assurance, Language Security (LangSec)  
**Defense Layer:** VAREK v1.1 (Hardware-Enforced Agentic Infrastructure)  

---

## 1. Executive Summary: The Gap in ACO Assurance

As the Department of Defense transitions toward Autonomous Cyber Operations (ACO), the deployment of LLM-backed agents at the tactical edge introduces a critical, systemic vulnerability: **Cognitive Bypasses via Untrusted Telemetry.**

Current DARPA portfolios rightly focus on the robustness of AI models. However, when an autonomous agent is granted local system execution privileges (e.g., for automated forensics, lateral movement, or network diagnostics), the ingestion of adversarial data (poisoned PCAPs, weaponized SIGINT) can hijack the agent's execution context. 

This results in **Remote Code Execution (RCE)** at the OS boundary, initiated by the DoD's own AI.

## 2. The Vulnerability: Probabilistic Failure
Current industry standard defenses rely on probabilistic wrappers (LLM-as-a-judge, prompt sanitization, heuristic filtering). In a contested electronic warfare environment, advanced adversaries will invariably find encoding structures that bypass probabilistic filters. 

When probabilistic defenses fail, the agent executes the adversary's instructions. Furthermore, interpreter-level hooks (like Python's PEP 578) are structurally insufficient, as child processes spawned via `subprocess` execute outside the parent's interpreter, blinding the hook to advanced evasion techniques.

## 3. The VAREK v1.1 Solution: Hardware-Enforced Kernel Interdiction
**VAREK** abandons probabilistic text-filtering and interpreter-level illusions in favor of deterministic, hardware-enforced execution boundaries. 

VAREK v1.1 decouples *model integrity* from *execution integrity*. It cages untrusted agentic code execution strictly at the Linux kernel level utilizing a pluggable `IsolationBackend`. 

By strictly enforcing native OS-level primitives—`seccomp-bpf`, `cgroups v2`, user/mount/net namespaces, and the critical `PR_SET_NO_NEW_PRIVS` flag—VAREK operates entirely beneath the AI agent. 

If a hijacked ACO agent attempts an unauthorized syscall or network egress based on weaponized telemetry, VAREK physically snaps the execution thread in microseconds via `SIGSYS`—failing closed and terminating the process before the underlying operating system can process the malicious instruction. (Note: Legacy PEP 578 hooks are retained strictly for structured advisory telemetry to aid in defense-in-depth observability).

---

## 4. Operational Proof of Concept

The attached Proof of Concept demonstrates an ACO agent analyzing a poisoned PCAP. The embedded payload successfully achieves a cognitive bypass on the LLM, instructing it to initiate a reverse shell. VAREK intercepts and terminates the OS-level syscall deterministically.

### Deployment Scenario:
* **Node:** Tactical Edge Research Server
* **Vector:** Weaponized Network Traffic (PCAP)
* **Outcome:** Agent Hijacked -> seccomp-bpf Kernel Intercept Triggered -> Node Integrity Maintained

**View the Core Architecture and I2O Intercept Implementation:**
[14-darpa-i2o-demo.py](https://github.com/kwdoug63/varek/blob/main/darpa-i2o/14-darpa-i2o-demo.py)

---
*Developed for evaluation by DARPA I2O Program Management.*
