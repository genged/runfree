# Sandbox And Runtime Security Patterns

This file contains reusable patterns for sandboxed agents, containers, devcontainers, proxy-mediated egress, credential brokers, dependency isolation, and related runtime designs. It avoids project-specific names and constants.

## Network And Proxy Boundaries

- Proxy environment variables route cooperative clients. They do not enforce isolation by themselves.
- A network-enforced design should block direct workload egress except to the trusted proxy or broker.
- A common pattern is a private workload-to-proxy network plus a separate proxy egress network.
- If a proxy is multi-homed, validate ingress and egress independently. Listener binding, firewall rules, and route selection must match the intended interface.
- Do not use broad subnet membership as workload identity when the intended trust relationship is a single workload. A fixed, verified workload address can be a narrow network-admission identity when the runtime proves its unique owner.
- Do not reuse network-admission identity as session, user, process, or approval identity. Multiple sessions or processes inside one workload share its address; broader authorization needs a separately authenticated principal and lifecycle.
- Define behavior for stale networks, reused containers, duplicate peers, and runtime recreation.

## Credentials And Secret Flow

- Untrusted workloads should receive placeholders or handles when a client requires an auth variable, not the real credential.
- Broker-managed credentials should live only in the trusted broker, proxy, host service, or secret store.
- Inventory native workload authentication state separately. Some tools require writable per-workload login or subscription state; document that exception, isolate it from host-wide state, and treat it as readable by compromised workload code.
- Secret sync should happen only after the enforcement topology is validated.
- Failed validation must leave the workload without usable real secrets and must prevent workload attach or session start.
- Logs must not include credential values, auth headers, sensitive query strings, full opaque handles, or request bodies unless explicitly designed and redacted.

## Proxy Protocol Semantics

- Validate raw protocol behavior, not only high-level client behavior.
- For HTTP CONNECT proxies, disallowed hostnames and disallowed ports must be rejected before DNS lookup and before any upstream connection attempt.
- If policy is hostname based, DNS resolution and IP allowlist refresh must be explicit, observable, and resistant to stale policy assumptions.
- Decide how the proxy handles redirects, alternate ports, IPv6 literals, IP literals, wildcard hosts, punycode, trailing dots, and mixed-case hostnames.

## Container And OS Privileges

- Drop privileges that let the workload alter enforcement, such as route, firewall, raw-socket, mount, namespace, or host-device privileges.
- Verify effective privileges from inside the running workload, not only from declarative config.
- Do not depend on "not adding" a privilege when the runtime grants it by default.
- Test the chosen enforcement backend after each capability drop. Some backends need surprising privileges; if a packet-filter path requires raw sockets, either keep that privilege explicitly justified or choose a backend that matches the least-privilege model.
- Avoid mounting host control sockets into the untrusted workload.
- Keep effective enforcement policy and credential material read-only or inaccessible to the workload. Project-authored policy may be intentionally readable; its integrity and activation path, not confidentiality, are the usual security properties.
- Reject unknown production network participants. Declared utility containers may participate when the runtime validates a narrow role-specific contract covering image or command identity, networks, listener bindings, mounts, credentials, capabilities, user, writable state, and lifecycle. Participation does not make a utility an authorization boundary.
- Test-only probes must not become production trust relationships. Keep them tokenless, mountless, short-lived, and absent from production topology.

## Docker And Container Network Details

- A Docker internal network is a useful primitive, but it is not a complete proof by itself.
- Test direct TCP, UDP, DNS, IPv6, host-gateway, service discovery, and route-table behavior.
- If IPv6 is enabled, specify equivalent IPv6 enforcement or disable IPv6 explicitly.
- Confirm embedded DNS behavior and whether it is acceptable for the threat model.
- Ensure host gateway aliases, extra hosts, and additional networks cannot reintroduce bypass paths.

## Policy And Authorization Control Planes

- Separate policy authoring from policy activation. A project may support validated offline policy edits with no running sandbox; reject invalid input before authoring-side mutation, and define exactly when changed bytes become live authority.
- Enumerate every enforcement consumer and require explicit convergence behavior. Request filters, packet filters, credential mediators, approval managers, and caches must either enforce one effective generation or fail closed while generations differ.
- Inventory temporary relaxations and authority channels such as audit or learning modes, human approvals, standing grants, OAuth mediation, MCP or tool-operation policy, and root-owned control records. Define who can activate them, their subject, scope, lifetime, revocation, replay protection, observability, and teardown behavior.
- Do not infer session or user authorization from a workload-level transport unless the design proves a one-to-one authenticated lifecycle.

## Runtime Proof And Side-Effect Ordering

- Treat a running proxy, container, or service as insufficient proof by itself. Validate the live route table, network membership, effective capabilities, firewall state, mounts, and protocol rejection behavior before declaring the boundary ready.
- Token sync, release of broker-managed credentials, and workload attach should happen only after the full runtime proof has passed. Policy authoring may happen offline; live policy activation or widening must have an explicit validation and convergence contract.
- On validation failure, clear stale readiness markers and remove or mark invalid runtime state so a later command cannot reuse a partially trusted topology.
- Prefer structured runtime inspection over source or config substring checks. For example, parse normalized JSON from the runtime tool or inspect kernel state instead of trusting a template file.

## Pre-Sandbox Builds

- Treat project-controlled container builds, image hooks, and build contexts as a separate boundary when they execute before the runtime sandbox or egress proxy exists.
- Determine what the host build daemon can read, what network the build receives, and whether context staging is race-safe. Reject symlinks, hard links, special files, and context escapes before invoking the daemon.
- Bind any broad-context approval to the exact project, build configuration, Dockerfile or build program, and the content scope the approval is intended to cover. Staging bytes proves integrity; it does not by itself authorize execution.
- Include pre-sandbox build behavior in lifecycle ordering and failure tests; sandbox validation performed after a build cannot constrain what the build already did.

## Dependency Isolation

- Distinguish shared source files from dependency artifacts.
- In container sandboxes, dependency directories and package-manager stores should usually be runtime-owned volumes or overlays, not bind-mounted host artifacts.
- Preserve host workflow by leaving host dependency artifacts intact outside the sandbox view.
- Treat host and sandbox dependency divergence as expected when both execution modes are supported.
- Account for stale or corrupt dependency volumes, permissions, lifecycle scripts writing into the workspace, and installs blocked by network policy.
- For pnpm, inspect `node_modules/.modules.yaml` for store path, virtual store path, and package-manager version mismatches.

## Test Integrity

- Unset upper- and lower-case proxy variables before direct-egress tests.
- Use explicit proxy bypass flags where available.
- Use direct IP probes when testing TCP egress independent of DNS.
- Include UDP and DNS-specific probes; TCP-only tests do not prove DNS or UDP policy.
- Include negative tests that prove rejection before DNS lookup, upstream SYN, credential injection, filesystem write, or other sensitive side effects.
- Run tests in an environment that matches production topology. Test helpers should not create trust relationships that production does not have.
