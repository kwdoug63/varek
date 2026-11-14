# Security Policy

VAREK supervises an AI agent's process from outside it: the Warden decides
each call the agent makes that its policy covers, in the kernel, and records
each decision in a signed stream. A flaw that lets an action the policy
refuses take effect, lets an agent run unsupervised, or lets a forged record
pass the audit is what this policy is for. Report it privately, not in a
public issue.

## How to report

**Preferred:** GitHub's private vulnerability reporting.

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**
   (https://github.com/kwdoug63/varek/security/advisories/new).
3. Fill in the form.

**Or by email:** kenneth.douglas@soberagents.ai, with the subject
`VAREK Security: <a short description>`.

## What to include

- What happens, and what should have happened instead.
- The steps to reproduce it, with code if you have it.
- The version: the output of `varek version` (the command's and the
  Warden's), or the image or chart tag.
- Where it ran: a host (the distribution and kernel), a container (the
  runtime), or Kubernetes (the distribution, the container runtime and its
  version).
- The policy, or the smallest one that shows it, and the plan if one was
  used.
- The verdict stream or `varek audit`'s output, if they bear on it (remove
  anything private first).
- A fix, if you have one in mind.

## What is in scope

Every component that ships in a release:

- **The Warden** (`warden`), on a host, in a container, or as the node
  agent: an action its policy refuses, or does not cover, that takes effect;
  an agent that runs unsupervised, or outlives its supervisor; a call
  decided against the wrong policy; a decision recorded differently from
  how it was made.
- **The egress proxy** (`warden-proxy`), including its inspecting mode: a
  connection or request the policy refuses that reaches its destination; a
  certificate made for the run that is trusted outside it; a memory error
  in its parsers.
- **Credential release** (`warden-secrets`): a credential released for a
  request, subject or audience the policy does not name, or reachable by
  the agent itself.
- **Kubernetes:** the node agent, the NRI plugin (`varek-nri`), the
  admission webhook (`varek-admission`), `varek-init`, `varek-svid` and the
  Helm charts (`varek`, `varek-crds`): a pod that should be supervised and
  starts unsupervised; a pod held to another pod's policy, plan,
  credentials or stream identity; a VAREK object the webhook should refuse
  and admits; a right the chart grants beyond what its README and
  `docs/security/node-agent-privilege.md` say.
- **The evidence:** `varek audit`, `varek export` (CycloneDX), the OCSF
  export and the node keys: a stream that was forged, altered, reordered or
  cut short and that the audit accepts; a key accepted that is not the
  run's or the node's.
- **The policy and plan languages and the decision procedure:** a policy
  line that decides differently from its documentation; a crash or memory
  error from a policy, a plan or a DNS answer.
- **The release artifacts:** the container images and charts on ghcr.io,
  their signatures and attestations, the Marketplace image: a signature
  that verifies for something the release workflow did not build.
- **A crash or hang** of the Warden, the node agent or the proxy caused by
  input that an agent or a pod controls, when it affects anything beyond
  that agent's own run.

## What is out of scope

These are limits VAREK states, not omissions
(`docs/security/threat-model.md`, section 5):

- **A policy that allows something harmful.** VAREK holds an agent to its
  policy as written; whether the policy is right is the operator's
  decision.
- **Kernel, hypervisor and hardware flaws**, including side channels.
  Report them upstream. Tell us as well if VAREK's setup makes one worse.
- **Covert and timing channels.**
- **Secrets an agent is started with**, in its environment or in files its
  policy lets it read: VAREK limits where an agent can send them, not
  whether it can read them.
- **The VAREK language's static checks** (the AST gate): a usability
  layer, not a security boundary. A bypass of it that the
  kernel layer stops is expected.
- **Slowing or stopping your own agent**, within the limits its policy and
  its cgroup set, and forcing a decision to UNKNOWN, which refuses the call
  (fails closed).
- **The known limits** in each release's notes ("Known limits") and in
  `docs/security/bypass-classes.md`. A report that one is wider than stated
  is in scope.
- **Flaws in dependencies.** Report them upstream; tell us if VAREK's use
  of one exposes it.

## How a report is rated

| Severity | For example |
|---|---|
| Critical | An action the policy refuses takes effect; an agent or a pod runs unsupervised; a credential reaches a party the policy does not name; the audit accepts a forged or altered stream |
| High | A pod held to another pod's policy, plan or stream identity; any of the above that needs a precondition, such as root on the node or access to the node agent's socket |
| Medium | A memory error with no shown exploit; a record wrong while the decision was right; one pod or agent able to stop others starting |
| Low | Hardening, a misleading message or document |

## Response times

| Stage | Time |
|---|---|
| Acknowledgment | 48 hours |
| Triage and a severity | 7 days |
| A fix released, critical and high | 30 days |
| A fix released, medium and low | 90 days, or the next release |
| Coordinated disclosure | 90 days from the report, or when the fix is released if sooner, as agreed with the reporter |

## Supported versions

Security fixes go to the latest release line and the one before it, as
patch releases (for example 1.36.3), never as a silent change to a
published release.

| Version | Security fixes |
|---|---|
| 1.38.x | Yes (the latest) |
| 1.37.x | Yes, until 1.39.0 is released |
| 1.36.x and earlier | No: upgrade to 1.38 |

The container images, the charts and VAREK Enterprise's Marketplace image
follow the same lines.

## Advisories

Each fixed vulnerability that affects a released version gets:

- a **GitHub security advisory** on this repository, with a CVE requested
  through GitHub;
- in it: the versions affected and the version that fixes it; whether a
  supervised agent or pod could have run unsupervised or been decided
  against the wrong policy; whether streams recorded by an affected
  version should be audited again; and any workaround;
- a **Security** section in the release's notes and an entry in
  `CHANGELOG.md`.

## Testing VAREK's boundary

Bypass reports are welcome. The classes VAREK mediates, and how, are in
`docs/security/bypass-classes.md`; what it guarantees, and against which
adversary, is in `docs/security/threat-model.md`; what is trusted rather
than checked is in `docs/security/TRUSTED-COMPUTING-BASE.md`. Test against
an installation of your own. A report that shows an action taking effect
that its policy refuses, with the policy and the steps, is the most useful
kind.

## Reviews to date

VAREK's releases have been reviewed by AI review agents; an early external
architecture review by QEEK-AI addressed the language layer's framing and
platform gating. No human security audit of the current code has been made.
The threat model says so, and will name any review when one is made.

## Safe harbor

We will not pursue legal action against researchers who:

- report in good faith through the channels above;
- do not access, change or destroy data that is not theirs;
- test only against systems they own or are allowed to test;
- give us reasonable time to respond before disclosing.

## Recognition

Reporters are credited in the advisory and the release's notes, unless they
ask not to be. Say in your report how you would like to be named.
