# Project Brief

Runfree is an installable TypeScript CLI that starts coding agents inside a local Docker Compose workspace instead of letting them run directly on the host.

It is designed for Claude Code, Codex, and Pi. The agent sees the project at `/workspace`, runs normal project tools, and uses familiar CLIs. Outbound HTTPS/WSS goes through a Runfree proxy that enforces project policy and injects proxy-managed credentials only after the request is allowed.

## Problem

Coding agents can read, edit, install dependencies, run tests, and call external APIs. That power is useful, but it also increases the blast radius of prompt injection, confused-deputy tool calls, or accidental credential exposure when an agent runs directly on a developer workstation.

Runfree gives each project a local trust boundary:

- desired project policy lives in `.runfree/`, while approvals and effective
  runtime controls live in host-owned XDG state;
- the agent container is treated as untrusted;
- the proxy container is trusted for outbound network decisions and credential injection;
- real service tokens stay host-side or proxy-side, not in the agent environment.

## Product Model

A normal project flow is:

```bash
runfree init
runfree credential source add github-cli -- gh auth token
runfree service enable github --from-source github-cli
runfree
```

`runfree init` creates project-local config and deny-all desired policy.
`runfree` starts or reuses the project runtime and launches the configured
default agent only after the desired policy has an exact host-owned approval
and Runfree has published an immutable effective policy generation. Starting
built-in Claude or Codex first offers its credentialless native operational
service without overwriting stricter user write rules. Other policy changes are
explicit host-side commands such as `runfree service enable`, `runfree host
add`, `runfree credential add`, and `runfree mcp approve`.

## What Runfree Provides

- **Containerized agent workspace** for Claude Code, Codex, Pi, or a project-defined agent command.
- **Reviewable desired network policy** in `.runfree/network-policy.json`, compiled into host-owned exact-host runtime policy only after exact approval.
- **Proxy-held credentials** sourced from host environment variables, 1Password refs, host commands, stdin, JWT sources, or service-specific OAuth seed material.
- **Curated services** for common package ecosystems, Git providers, model providers, native Claude/Codex operation, App Store / Apple Ads, Google Ads, Docker registries, Linux package managers, and more.
- **User-defined services** under `user-*` for repeatable host bundles that are not curated by Runfree.
- **Network audit mode** for time-boxed discovery of hosts during trusted onboarding.
- **Approve-on-write** for held outbound writes and side-effecting MCP tool calls.
- **MCP import and approval** for Claude and Codex, including sanitized project-local config, OAuth login, and tool-call rules.
- **Dependency overlays** so common dependency directories and caches live in Runfree-owned Docker volumes instead of polluting the host checkout.
- **Project image customization** through a Dockerfile that extends the Runfree base image.
- **Diagnostics** for blocked proxy requests, desired/effective runtime component state, upgrade actions, resources, logs, assets, and token sync status.
- **Interrupted-session recovery** with bounded offline current-project inventory, explicit cross-project and agent filtering, and retry-safe Claude/Codex resume claims.

## What Runfree Does Not Promise

Runfree is not a VM isolation layer, a cloud service, or a replacement for code review. It does not make an untrusted project safe to execute arbitrary native code on your host. It narrows the default blast radius for local coding agents by combining Docker isolation, proxy-mediated egress, exact-host policy, and proxy-side credential storage.

Runfree also does not publish Linux or Intel macOS release binaries. They can be built from source; a source build is not a support claim. Public release artifacts are restricted to targets with recorded acceptance evidence.

## Audience

The primary audience is individual developers using Claude Code, Codex, or Pi who want project tooling in a container and service credentials mediated by a host-controlled proxy. Team use is supported by committing desired policy and reviewing it like code — each developer still binds their own credential sources and approves policy on their own machine — but it is secondary. Runfree makes no enterprise or certification claims.

## Supported Release Shape

As of `0.5.1`:

- published binary: `darwin-arm64` only, ad-hoc signed and not notarized, with a SHA-256 manifest;
- host: Apple Silicon macOS;
- container backend: Docker Desktop with Docker Compose;
- package manager: Homebrew tap plus the GitHub release install script (`bash`, not `sh`);
- source build: Node 22, pnpm 10.28.0, and Bun 1.3.14 for `pnpm run build:bin`;

The release target list lives in [`../scripts/release-targets.txt`](../scripts/release-targets.txt), which packaging, signing, checksums, and the CI build matrix all read.

Runtime/security changes should be validated with `make test-runtime-core` on a Docker-capable host, and releases with the full `make test-runtime` or `make test-all`.

## Source Map

| Area | Primary files |
| --- | --- |
| CLI entrypoint and command app | `packages/cli/src/cli.ts`, `packages/cli/src/commands/` |
| Project config and init wizard | `packages/cli/src/config.ts`, `packages/cli/src/init-wizard.ts`, `packages/cli/templates/` |
| Runtime lifecycle and Docker Compose orchestration | `packages/cli/src/runtime.ts`, `packages/cli/src/runtime/env.ts`, `packages/cli/src/network.ts` |
| Desired/effective network contracts | `packages/runtime-contracts/src/desired-network-policy.ts`, `packages/runtime-contracts/src/network-policy.ts` |
| OAuth mediation contracts | `packages/runtime-contracts/src/oauth-mediation-policy.ts` |
| Proxy enforcement | `packages/proxy/src/` |
| Admin policy/token/service/MCP enforcement | `packages/cli/src/admin/`, `scripts/services.ts` |
| Runtime assets | `packages/agent-runtime/agent/`, `packages/proxy/`, `dist/runtime/` |
| Release packaging | `scripts/build-bin.ts`, `scripts/package-homebrew-artifacts.sh`, `scripts/install.sh` |

See also [`index.md`](index.md), [`architecture.md`](architecture.md),
[`security.md`](security.md), and [`cli.md`](cli.md).
