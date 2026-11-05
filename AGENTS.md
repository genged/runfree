# AGENTS.md

Runfree is an installable TypeScript CLI that starts Claude Code or Codex in an
isolated Docker Compose workspace for the current project. Treat this repo
as security-sensitive: the agent container is untrusted, the proxy container is
the trust boundary for outbound HTTPS and proxy-managed credentials, and
project policy lives under `.runfree/`.

## Conversational Style

- Keep answers short and concise
- Be direct. Put the bottom line first.
- Answer the user's question in the first sentence, before any tool call, edit, or implementation command.
- Write explanations, design proposals, review results, and decision questions
  in simple English (the `simple-english` skill, when available). Add a small
  ASCII sketch when the answer is about a flow, a topology, or a before/after
  shape.
- Never use a bare label. On first use in each reply, define decision, option,
  finding, priority, phase, gate, shell-variable, subagent, and reviewer labels.
  Write "F3 (token logged on refusal)", not "F3".
- End each open decision with an explicit question, plain options, and a
  recommended choice. Do not leave it as a statement buried in a report.
- "Help me with X" or "how can we X" asks for a proposal. Propose, then wait.
- Give user-facing Runfree repro, diagnosis, and recovery steps as `runfree`
  commands, never raw `docker` commands.

## Context Strategy

- Keep this file short and universally applicable. Prefer pointers to source
  files and docs over copying details here.
- Before any runtime, proxy, network, mount, credential, or sandbox edit, read
  `docs/project-brief.md`, `docs/architecture.md`, `docs/security.md`, and
  `docs/security-rules.md` (rule IDs such as `NET-1`). They and the
  `runfree-source-map` skill are canonical for security reviews; do not
  substitute plans or shared skill references.
- Before editing public docs, follow `docs/writing-docs.md`; `make test-static`
  checks its mechanical rules.
- Check recent commits before assuming a design is finished.
- For reviews of the current design, treat implemented source, behavioral/live tests, and the public project docs as current. Completed specs may explain shipped decisions; ignore drafts, partial specs, plans, and TODO directions unless the user explicitly asks about future work.

## Project Rules

- Do not treat proxy environment variables as enforcement. They route
  cooperative clients; Docker mounts, agent-side firewalling, proxy policy, and
  proxy-side token storage are the enforcement boundary.
- Never put real service tokens in the agent container. Agent env vars may use
  placeholders only; real proxy-managed tokens belong in host-resolved sources
  and proxy-only tmpfs.
- Keep `.runfree/network-policy.json` as the fixed project policy path. It
  allows exact hostnames only: no wildcard hosts. Service host bundles expand
  to exact hostnames at CLI time. The format is in `docs/cli.md` "Network
  Policy".
- Host-side writes to project-controlled paths must reject symlinks, hard
  links, and special files. Use `safeReplaceProjectFile`,
  `ensureSafeProjectDir`, and related helpers.
- Supported backends: Docker Desktop on macOS and native Docker Engine on
  Linux. A live run on one backend is not evidence for the other. OrbStack is
  never tested or supported: do not add OrbStack targets, backend values,
  docs, or owed gates.
- Do not mount host-wide secrets or home config into the agent. Per-project
  Claude/Codex state and generated Git identity are the intended exceptions.

## Design

- Start from the smallest general design that fits the existing commands, flag
  names, and conventions. Check how the repo and prior art already solve it
  before inventing a new concept.
- Every proposal includes the minimal option. For each part beyond it, name the
  user need or the attack it stops. A security check must stop an attack the
  agent cannot already perform; otherwise drop it.
- Design for the general case, not the example that motivated it: no
  service-specific mechanisms, flags, or docs when a general one works.
- When the user points to a reference (an existing script, tool, convention, or
  standard installer), follow it. State any deviation before writing code.
- Verify every review finding against the source before applying it; reviewers
  often misread diff context or removed lines. Report which findings you
  rejected and why. When a finding would add machinery, weigh its cost against
  the attack it stops.

## Security Work

Before implementing or reviewing changes involving `.runfree`, `RUNFREE_*`,
Docker/Compose topology, firewalls, proxy egress, credentials, token sync, CA
material, dependency isolation, or runtime startup, use `security-architect`.
Review the actual trust boundary: assets, attackers, trusted components, data
paths, lifecycle failures, and proof.

Security-sensitive changes need negative tests that prove rejection before a
sensitive side effect: before DNS lookup, upstream connection, credential
injection, policy mutation, or filesystem write. Prefer runtime inspection for
capabilities, routes, mounts, and firewall state when declarative config could
be misleading.

Cadence and performance changes re-run the invariant proofs: coverage that
only held because the system was slow is not proof. Every new fail-closed
refusal ships with the path that reclaims its wedge state, plus a test for
both the refusal and the reclamation.

## Verification

Run the affected Vitest file first, then `pnpm test`; after every change run
`pnpm check` and `pnpm typecheck` before committing or reporting completion.
Runtime asset changes: regenerate assets and run asset-sync tests. Sandbox,
proxy, firewall, Docker network, or credential-boundary changes are not
verified until `make test-runtime-core` passes on the final tree. Releases and
lifecycle, recovery, upgrade, or cleanup changes require `make test-runtime` or
`make test-all`.

If a live gate cannot run, say the work is unverified; do not call it complete
or merge it. End with exact repo-root commands and every gate still owed;
prefer `make` targets. Before classifying a failure, rerun its file alone. An
isolated pass does not clear a failing full suite: fix or disable the failure,
then rerun the required suite.

## User Override

If the user's instructions conflict with any rule in this document,
ask for explicit confirmation before overriding. Only then execute their instructions.

## Local Instructions

If `AGENTS.local.md` exists in the repo root, read it at the start of the
session and follow it. It holds clone-specific instructions and is not tracked.
