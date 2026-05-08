# RFC: VAREK v1.2 - OS-Level System Call Interception & Stateful Semantic Derivation

* **Author:** kwdoug63
* **Status:** Under Review
* **Date:** 2026-05-08

## 1. Summary
This RFC proposes shifting VAREK's containment boundary from the application/API layer down to the Linux kernel layer. We propose implementing a highly privileged "Warden" process that utilizes `seccomp-unotify` to pause an untrusted agent's execution thread, extract its memory, and derive stateful semantic intent from raw system calls before returning a hard kernel-level `EPERM` or `ALLOW`.

## 2. Motivation
Autonomous agents currently rely on stateless API gateways or prompt-engineering for safety. When an agent experiences "Agentic Drift" or hostile subversion, it can bypass these high-level proxies and interact directly with the operating system to open unauthorized files or initiate network sockets. By moving the interception boundary to the kernel, we establish a deterministic, physical circuit breaker that cannot be bypassed by a subverted agent.

## 3. Detailed Design
The proposed architecture introduces three core components:

* **The Warden (Process Isolation):** The untrusted AI agent executes within a restricted child process. The Warden operates as a highly privileged parent process, ensuring the agent cannot tamper with the interception logic or audit logs.
* **Kernel Interception Bridge:** Utilizing Linux `seccomp-unotify`, the kernel pauses the agent's thread upon a system call attempt. The Warden performs cross-process memory extraction (e.g., via `process_vm_readv`) to read the raw arguments (like destination IP or file path) without trusting the agent.
* **Stateful Execution Context:** The Warden maintains a chronological history of system calls, dynamically tracking integer File Descriptors (FDs) to absolute file paths. A Derivation Engine maps these fragmented calls (e.g., `open` -> `read` -> `connect`) into a high-level "Semantic Action" (e.g., `attempted_exfiltration`) for evaluation.

## 4. Drawbacks
* **Platform Dependency:** `seccomp-unotify` is inherently tied to the Linux kernel. This requires building "fail-closed" mock bridges for developers testing on macOS or Windows.
* **Context-Switch Overhead:** Intercepting system calls introduces a microsecond-level latency penalty (currently benchmarked at ~22μs per trap).

## 5. Alternatives
* **eBPF (Extended Berkeley Packet Filter):** Offers lower overhead but can be more complex to deploy securely inside certain containerized environments. 
* **ptrace:** Historically used for this, but `ptrace` is notoriously slow and introduces unacceptable latency for high-frequency agentic workflows.

## 6. Unresolved Questions
* What edge cases exist in Python/Node.js runtime file-descriptor handling that might confuse the Stateful Execution Context?
* Should we officially support an eBPF backend as a fallback/alternative to `seccomp-unotify` in a future v1.x release?
