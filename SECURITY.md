# Security Policy

VAREK takes security seriously. If you've discovered a vulnerability — 
particularly a sandbox bypass, privilege escalation, or syscall filter 
weakness — please report it privately rather than opening a public issue.

## How to Report

**Preferred:** GitHub's private vulnerability reporting
1. Go to the Security tab of this repository
2. Click "Report a vulnerability"
3. Fill out the form with details

**Alternative:** Email: kenneth.douglas@soberagents.ai (subject line format: `VAREK Security: <short description>`)

## What to Include

- Description of the vulnerability
- Steps to reproduce (proof-of-concept code if available)
- Affected VAREK version(s)
- Kernel version and distribution where reproduced
- Suggested mitigation, if known

## Response SLA

| Stage | Timeline |
|-------|----------|
| Initial acknowledgment | 48 hours |
| Triage and severity assessment | 7 days |
| Resolution target (high/critical) | 30 days |
| Coordinated disclosure | 90 days from initial report |

## Scope

**In scope:**
- Sandbox escape from `SeccompBpfBackend` or other isolation backends
- Syscall filter construction errors producing exploitable filter bytecode
- Privilege escalation via user namespace, cgroup, or seccomp misconfiguration
- Information disclosure across the sandbox boundary

**Out of scope:**
- In-process secret extraction (env vars present at sandbox creation 
  are explicitly not protected — see THREAT_MODEL.md)
- AST-layer bypass that is caught by the kernel layer (expected behavior, 
  not a vulnerability — AST is a UX layer)
- Side-channel attacks (Spectre-class, timing, cache)
- Denial of service via resource exhaustion within declared cgroup limits
- Vulnerabilities in dependencies (please report upstream)

## Safe Harbor

We will not pursue legal action against researchers who:
- Report vulnerabilities in good faith via the channels above
- Do not access, modify, or destroy data belonging to others
- Do not test against systems you do not own
- Give reasonable time to respond before public disclosure

## Recognition

Researchers who responsibly disclose vulnerabilities will be acknowledged 
in our security credits. Indicate in your report whether you'd like to be credited.