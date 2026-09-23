---
name: security-architect
description: Security architecture review workflow for trust-boundary designs, sandboxed agents, container runtimes, proxy-mediated egress, credential handling, dependency isolation, filesystem mounts, startup lifecycle, and security-sensitive specs. Use when asked to review, design, harden, or critique runtime architecture, network policy, token handling, OS capabilities, Docker or devcontainer topology, firewall rules, or dependency isolation.
---

# Security Architect

## Purpose

Use this skill for adversarial, pragmatic architecture review. Treat the work as a search for bypasses, ambiguous trust boundaries, lifecycle races, false-positive tests, and missing proof.

## Load References

- Always read `references/core-review-method.md`.
- For sandboxed agents, containers, proxy-mediated egress, credential injection, dependency isolation, package-manager stores, filesystem mounts, OS capabilities, Docker networks, DNS, IPv6, firewall rules, approval channels, or pre-sandbox builds, also read `references/sandbox-runtime-patterns.md`.

## Load Project-Owned Context

For every repository-specific review:

1. Read the repository's instruction files and follow their pointers to canonical architecture, security, threat-model, source-map, and verification documentation.
2. If instructions do not identify those documents, discover current project-owned equivalents such as `README.md`, `SECURITY.md`, `docs/architecture.md`, `docs/security.md`, and package or component READMEs. Do not assume these exact paths exist.
3. Inspect the implementation and behavioral or live-runtime tests for the reviewed boundary. Project documentation explains the intended model; code and runtime evidence establish what is implemented.
4. When reviewing the **current design**, use only implemented code, tests, current documentation, and specifications explicitly marked done or implemented. Ignore drafts, proposals, plans, partial specifications, and TODO directions unless the user asks to review future work.
5. Use TODOs and recent commits only to avoid presenting unfinished or superseded work as current behavior.

Project-specific architecture belongs in project-owned documentation, not in this skill's `references/` directory. This keeps the review tied to documentation maintained with the project.

## Workflow

1. State whether the review target is the current implementation or a proposed design.
2. Establish assets, attackers, trusted components, and trust boundaries.
3. Draw the real data, control, credential, build, and traffic paths before judging controls.
4. Separate concepts that are often conflated: authoring, activation, routing, enforcement, identity, authorization, lifecycle, and proof.
5. Review startup, migration, stale-state, restart, policy convergence, and failure behavior.
6. Demand concrete validation evidence.
7. Produce findings first, ordered by severity, with concrete references when available.

## Output Contract

Use this shape unless the user asks for a different format:

1. Findings first, ordered by severity. Each finding should include severity, concrete reference, impact, and required fix.
2. Open questions or assumptions that materially affect the threat model.
3. Test and proof gaps, including checks that could produce false confidence.
4. Concise approval stance: approved, approved after fixes, or blocked.

Keep the review specific. Do not include project-specific assumptions unless they came from the prompt, inspected implementation, runtime evidence, or current project-owned documentation. Label proposal-only behavior explicitly and never present it as shipped.
