# VAREK Governance

**Version:** 1.0  
**Effective:** 2026-01-01  
**Author:** Kenneth Wayne Douglas, MD

---

## Overview

VAREK is an open-source project governed by a lightweight, transparent process
designed to evolve the language responsibly while remaining welcoming to contributors
at all levels.

The governance model has three layers:

1. **Language Design** — Formal RFC process for changes to syntax and semantics
2. **Implementation** — Pull request review and CI/CD gates
3. **Community** — GitHub Discussions, Code of Conduct, contributor ladder

---

## Project Leadership

### Core Team

The Core Team is responsible for:
- Final acceptance or rejection of RFCs
- Resolving disputes in the review process
- Setting the project roadmap
- Maintaining the official registry

| Role | Responsibility |
|------|---------------|
| **Language Lead** | Final say on language semantics and grammar |
| **Compiler Lead** | LLVM backend, codegen, optimization |
| **Library Lead** | Standard library (syn::*) maintenance |
| **Community Lead** | RFC process, contributor experience |

### Decision Making

Decisions are made by **rough consensus**:
- Major language changes require RFC approval by ≥ 2 Core Team members
- Minor changes (bug fixes, documentation) require 1 reviewer
- Controversial RFCs require a 2-week public comment period
- Ties are broken by the Language Lead

---

## RFC Process

### When to Write an RFC

Write an RFC for changes that affect:
- Language syntax or semantics
- The type system
- Standard library public API (syn::*)
- The package format or registry protocol
- Breaking changes of any kind

You do **not** need an RFC for:
- Bug fixes that restore intended behavior
- Performance improvements without semantic change
- Documentation improvements
- New examples or tutorials

### RFC Lifecycle

```
 Draft → Review → Final Comment Period → Accepted / Rejected → Implemented
```

**Draft** (author submits)
- Open a GitHub Discussion in the RFC category
- Use the template from `docs/RFC_TEMPLATE.md`
- Number RFCs sequentially (RFC-0001, RFC-0002, ...)
- File is placed in `rfcs/NNNN-short-title.md`

**Review** (2+ weeks)
- Community comments on the GitHub Discussion
- Author updates the RFC based on feedback
- Core Team members leave formal review comments
- At least one Core Team member must be assigned as shepherd

**Final Comment Period** (1 week)
- Announced on GitHub Discussions and Discord
- No new features added during FCP
- Only clarifications and minor fixes

**Accepted**
- Core Team merges the RFC file into `rfcs/`
- An issue is opened to track implementation
- RFC status updated to "Accepted"

**Rejected**
- RFC is closed with a written explanation
- Rejection is final unless substantial new information emerges
- RFC file archived in `rfcs/rejected/`

**Implemented**
- RFC status updated to "Implemented"
- CHANGELOG updated
- RFC linked from release notes

### RFC Numbering

RFCs are numbered sequentially from 0001. The RFC file is named:

```
rfcs/NNNN-short-descriptive-title.md
```

Examples:
- `rfcs/0001-pipeline-type-system.md`
- `rfcs/0002-tensor-shape-inference.md`
- `rfcs/0003-package-format.md`

---

## Contributor Ladder

| Level | Requirements | Privileges |
|-------|-------------|------------|
| **Contributor** | Any merged PR | Listed in CONTRIBUTORS |
| **Reviewer** | 5+ merged PRs, invited | Can approve PRs |
| **Maintainer** | 20+ merged PRs, 6+ months | Can merge PRs, triage issues |
| **Core Team** | Invited by existing Core Team | RFC votes, roadmap |

---

## Code of Conduct

VAREK follows the [Contributor Covenant](https://www.contributor-covenant.org/)
version 2.1.

**In summary:** Be kind, be constructive, be welcoming. Harassment, discrimination,
and personal attacks are not tolerated.

Report violations to: conduct@varek-lang.org

---

## Stability Guarantees (v1.0+)

From v1.0 onward, VAREK commits to:

**Stable**
- Language syntax (additions require RFC, removals are breaking)
- Type system semantics
- Standard library public API (syn::*)
- Package format (.varekpkg)
- Registry protocol

**Unstable** (may change with notice)
- Compiler internals
- LLVM IR output format
- Error message wording
- Internal AST structure

**Semver**
- `MAJOR` — breaking changes (require RFC + deprecation period)
- `MINOR` — new features (backward compatible)
- `PATCH` — bug fixes (no semantic change)

**Deprecation policy:** Features are deprecated for ≥ 1 major version before removal.

---

## Roadmap Process

The roadmap is maintained in `ROADMAP.md` and updated each minor release.
Community members can propose roadmap items via GitHub Discussions.
The Core Team sets priorities and milestones.

---

## Amendments

This governance document can be amended by:
1. Opening a GitHub Discussion with the `governance` label
2. 2-week public comment period
3. Approval by ≥ 3 Core Team members
