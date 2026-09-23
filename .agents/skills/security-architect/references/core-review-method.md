# Core Security Review Method

This file contains generic concepts for security architecture review. It should apply across projects and runtimes.

## Review Stance

- Identify whether the target is the current implementation or a proposal. For current-state reviews, implemented code, behavioral tests, runtime evidence, and current project-owned documentation outrank plans; exclude drafts and unfinished specifications. For proposal reviews, assess the proposal as a target without claiming it already ships.
- Review the enforcement boundary, not the intent.
- Prefer concrete attack paths over broad security commentary.
- Treat lifecycle states as part of the design, including startup, validation, migration, stale state, restart, and failure.
- Separate controls from assumptions. A control must be enforced, observable, and have a defined failure mode.
- Do not accept `should`, `best effort`, or `if supported` language for security gates. Require mandatory behavior, startup refusal, or an explicit unsupported-platform error.

## First Principles

- **Assets:** credentials, source code, policy files, package credentials, host filesystem, network access, logs, build artifacts, package stores, and runtime state.
- **Principals:** user, untrusted workload, trusted broker, proxy, package manager, container runtime, host daemon, CI probe, external service.
- **Trust boundaries:** filesystem mounts, process boundaries, network boundaries, credential boundaries, policy-authoring boundaries, and privilege boundaries.
- **Attacker control:** repository files, package scripts, environment variables, lockfiles, runtime config, generated code, DNS names, protocol requests, and long-lived state may be attacker influenced.

## Concepts To Keep Separate

- **Authoring:** how proposed configuration is validated and stored.
- **Activation:** when configuration becomes live authority for each consumer.
- **Routing:** how cooperative clients choose a path.
- **Enforcement:** what prevents a bypass when a client is uncooperative.
- **Identity:** how the design knows which principal is making a request, and at what scope.
- **Authorization:** what that principal is allowed to do.
- **Lifecycle:** when controls are installed, validated, invalidated, and removed.
- **Proof:** what evidence demonstrates the control works in the real runtime.

## Severity Rubric

- **Critical:** Direct credential exposure, arbitrary host escape, reliable policy bypass, or inability to enforce the stated security boundary.
- **High:** Realistic bypass, validation after secret exposure, optional fail-closed behavior, or a trusted topology that can be perturbed by normal operation.
- **Medium:** Ambiguous enforcement, stale-runtime risk, missing platform behavior, incomplete protocol coverage, or tests that can pass while the bypass remains.
- **Low:** Documentation precision, observability, operator ergonomics, or defense-in-depth gaps that do not directly undermine the boundary.

## Proof Standard

- Prefer runtime inspection over configuration inspection when the runtime can mutate or default behavior.
- Prefer negative tests that prove rejection before sensitive side effects.
- Require pass/fail gates for security requirements.
- Treat "record observed behavior" as insufficient for a security gate.
- Capture enough evidence to debug failures: effective privileges, route tables, network membership, firewall state, policy decisions, connection counters, logs, and secret-injection state.

## Review Output

For each finding, include:

- Severity.
- Location or reference.
- Issue.
- Impact.
- Required fix.

Then include material open questions, test/proof gaps, and an approval stance.
