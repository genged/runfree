# AGENTS.md

Runfree is an installable TypeScript CLI that starts Claude Code or Codex in an
isolated Docker Compose workspace for the current project. Treat this repo
as security-sensitive: the agent container is untrusted, the proxy container is
the trust boundary for outbound HTTPS and proxy-managed credentials, and
project policy lives under `.runfree/`.

## Conversational Style

- Keep answers short and concise
- Technical prose only, be direct
- When the user asks a question, answer it first before making edits or running implementation commands.

## Context Strategy

- Keep this file short and universally applicable. Prefer pointers to source
  files and docs over copying details here.
- Read `docs/project-brief.md`, `docs/architecture.md`, and
  `docs/security.md` before changing runtime, proxy, network, mount,
  credential, or sandbox behavior. Together with the source map below, these
  are the canonical project-owned context for current security reviews; shared
  skills must discover and follow them rather than copy Runfree architecture
  into skill references.
- Maintainer-only implementation plans, draft specs, research notes, stack
  notes, todo tracking, and implementation lessons may exist under an ignored
  local `local/` directory in this clone. Do not add public docs that require
  `local/` to exist.
- Check the maintainer todo (`local/todo/INDEX.md`, when `local/` exists) and
  recent commits before assuming a design is finished. There is no public
  TODO file.
- Generation families are defined in `docs/architecture.md` ("Generation
  Families"); name the family (effective policy generation vs control plane
  generation), never the bare phrase "control generation".
- For reviews of the current design, treat implemented source, behavioral/live tests, and the public project docs as current. Completed specs may explain shipped decisions; ignore drafts, partial specs, plans, and TODO directions unless the user explicitly asks about future work.

## Where To Look

| Task | Location | Notes |
| --- | --- | --- |
| CLI entrypoint and public commands | `packages/cli/src/cli.ts`, `packages/cli/src/commands/`, `src/cli.ts`, `bin/runfree.js` | `cli.ts` builds the command context and runs the yargs command app (`commands/app.ts`); each command is a typed module under `commands/` that builds a typed intent and calls shared enforcement directly (no legacy string dispatcher). `src/cli.ts` is a compatibility delegate. |
| Project config and init | `packages/cli/src/config.ts`, `packages/cli/src/init-wizard.ts`, `packages/cli/templates/` | Current config version is 4; older versions and legacy keys are refused, not migrated. The init wizard runs only on a TTY without `--yes`. |
| Runtime lifecycle | `packages/cli/src/runtime.ts`, `packages/cli/src/runtime/env.ts`, `packages/cli/src/network.ts` | Docker Compose orchestration, project state, network selection, stale runtime checks. |
| Per-session admission | `packages/cli/src/runtime/session-admission-{probe,driver}.ts`, `session-file-{publisher,heartbeat,teardown}.ts`, `session-container-{proof,template}.ts`, `session-containers.ts`, `session-internal-network-baseline.ts` | Source-IP session identity, lifecycle records, and Docker-inspection proofs. Reached by every public launch (`claude`/`codex`/`pi`, `shell`, `resume`, `mcp auth`) through `session-public-launch.ts`. See `docs/security.md`. |
| Project custom agent images | `packages/cli/src/agent-image.ts`, `.runfree/image/Dockerfile` | Project Dockerfiles extend `RUNFREE_BASE_IMAGE`; full image overrides are not supported. |
| Embedded runtime assets | `packages/agent-runtime/agent/`, `packages/proxy/src/`, `dist/runtime/` | `pnpm build:runtime` creates `dist/runtime`, then assets are materialized into XDG data state by `packages/cli/src/assets.ts`. The agent image's session entry is `packages/agent-runtime/agent/session-entry.sh`; its readiness probe is TypeScript at `packages/agent-runtime/src/session-ready-probe.cts`, compiled by the same `tsc -b` step as the proxy into `dist/runtime/agent/session-ready-probe.cjs`. The probe embeds the readiness request bytes, pinned to the contract by `scripts/session-entry.test.ts`. |
| Proxy policy and credential injection | `packages/runtime-contracts/src/network-policy.ts`, `packages/runtime-contracts/src/oauth-mediation-policy.ts`, `packages/proxy/src/policy.ts`, `packages/proxy/src/oauth-mediation.ts`, `packages/proxy/src/server.ts` | HTTPS/WSS allowlisting, request-shape rules, header stripping, proxy-only token reads, and OAuth handle mediation. Denial feedback lives in `packages/proxy/src/denial.ts`; audit mode in `packages/proxy/src/audit.ts`. |
| Admin policy/token commands | `packages/cli/src/commands/admin/`, `packages/cli/src/admin/admin-core.ts`, `packages/cli/src/admin/{domain,allow,token,source,service}-policy.ts`, `packages/cli/src/admin/{mcp-admin,diagnostics}.ts`, `scripts/services.ts`, `scripts/domain-diagnostics.ts` | The yargs modules under `commands/admin/` build typed intents; enforcement lives in the per-family `*-policy.ts`/`mcp-admin`/`diagnostics` modules over the shared `admin-core.ts` base (ambient admin state, policy/token/source stores, proxy runtime, token sync, `reloadProxy`). `admin/options.ts` is a thin re-export barrel. `scripts/services.ts` is the unified service registry (host bundles ± static or OAuth credential mode). |
| Safe host project writes | `packages/cli/src/safe-fs.ts` | Use these helpers for writes under project-controlled paths such as `.runfree/`. |
| Live runtime proof | `tests/runtime/live/*.live.test.ts` (Vitest `runtime-live` project), shared `tests/runtime/live/*fixture*.ts` | Per-session live Docker proof: topology/caps, egress containment, CONNECT guard, request-shape, audit SSRF + teardown, allowlist lifecycle, and session admission. Run the whole suite with `make test-runtime`; one tranche as a per-commit Docker smoke with `make test-runtime-smoke`; the migrated non-admission tranches alone with `make test-runtime-live`. The fixture and tranches spawn the Bun-prebuilt CLI and runner bundles from `tests/support/prebuilt-entry.ts` (tsx fallback without Bun). Replaced the retired pre-flip `sandbox.sh`. |
| Release packaging | `scripts/generate-assets.ts`, `scripts/package-homebrew-artifacts.sh`, `scripts/install.sh` | Bun compiles release binaries; generated assets are embedded before packaging; public release artifacts are currently macOS-only. |
| Gate completeness | `scripts/check-test-inventory.ts`, `Makefile` `test-static` | Run by `make test-static`. Compares what `vitest list --filesOnly` would load against the test files git tracks, and checks that every Makefile test filter still names a real file — an unmatched Vitest filter is silently green. `test-static` discovers scripts to syntax-check from `git ls-files` rather than a list. |

## Development Commands

- `pnpm install --frozen-lockfile` installs dependencies.
- `pnpm check` runs Biome checks across the repo.
- `pnpm test` runs the Vitest suite.
- `pnpm typecheck` runs `tsc --noEmit`.
- `make test` runs static checks plus unit tests.
- `make test-runtime` runs the live Docker sandbox test; it requires the Docker
  CLI and a reachable Docker daemon. `make test-runtime-smoke` runs one tranche
  of it as a per-commit check on a Docker host; it is a subset, not a substitute.
- `make test-all` runs static and unit tests, Docker Compose template
  validation, the full live runtime suite, and packaged offline and live E2E.
- `pnpm run build:runtime` compiles proxy/runtime-contract packages and assembles
  `dist/runtime/**` for packaging. Tests and `pnpm typecheck` read workspace
  sources and do not need it first; `scripts/workspace-source-exports.test.ts`
  keeps package exports on `src/`.
- `pnpm run generate:assets` regenerates
  `packages/cli/src/embedded-assets.generated.ts` from `dist/runtime/**`.
- `pnpm run update:agent-tools -- [all|claude|codex|pi@<version>]` updates the
  embedded Claude/Codex/Pi CLI pins and regenerates runtime assets.
- `pnpm run build:bin` compiles `dist/runfree`; release archives use
  `scripts/package-homebrew-artifacts.sh`.
- `scripts/dev-runfree.sh [--state-root DIR] <runfree args>` runs this
  checkout's CLI against an isolated XDG data/state/config root, so a
  development `up` never writes into the installed runfree's state. It does not
  isolate Docker: the Compose project name is derived from the project path
  alone, so development runs need a scratch `--workspace`.

## Project Rules

- Use pnpm and Node 22. Do not switch package managers.
- Keep dependencies deliberate. The repo intentionally runs TypeScript directly
  with `tsx` for scripts and compiles the proxy only for generated runtime
  packaging; `tsc --noEmit` is the normal static gate.
- Ask before adding a dependency, and ask before introducing a new language or
  toolchain. Both are the user's decision, not an implementation detail to be
  settled while solving something else. A new language is the higher bar: it
  brings its own toolchain, build reproducibility story, cross-compilation and
  release pinning, and every one of those becomes permanent maintenance. When a
  dependency may be warranted, search for relevant, useful, and trusted options
  and present a choice rather than picking one. Prefer solving the problem with
  TypeScript and the Node already present in the agent and proxy images.
- Do not edit `packages/cli/src/embedded-assets.generated.ts` by hand. Change
  canonical runtime/package sources, run `pnpm run build:runtime`, then run
  `pnpm run generate:assets`.
- Proxy runtime source is canonical under `packages/proxy/src/`. The generated
  runtime Docker context under `dist/runtime/proxy/` is assembled by
  `scripts/build-runtime.ts`; the proxy Dockerfile lives at
  `packages/proxy/Dockerfile`.
- Do not treat proxy environment variables as enforcement. They route
  cooperative clients; Docker mounts, agent-side firewalling, proxy policy, and
  proxy-side token storage are the enforcement boundary.
- Never put real service tokens in the agent container. Agent env vars may use
  placeholders only; real proxy-managed tokens belong in host-resolved sources
  and proxy-only tmpfs.
- Keep `.runfree/network-policy.json` as the fixed project policy path. Desired
  policy v2 is an exact-hostname allowlist plus per-host `requests` rules
  (methods, path prefixes, git-push deny), `services` records, `tokens`
  (credential destinations), and an optional `writeApproval` default; still no
  wildcard hosts, notes, or category metadata. Service host bundles expand to
  exact hostnames at CLI time and never change the policy format.
- Host-side writes to project-controlled paths must reject symlinks, hard
  links, and special files. Use `safeReplaceProjectFile`,
  `ensureSafeProjectDir`, and related helpers.
- Do not mount host-wide secrets or home config into the agent. Per-project
  Claude/Codex state and generated Git identity are the intended exceptions.

## Security Work

For changes involving `.runfree`, `RUNFREE_*`, Docker/Compose topology,
firewall rules, proxy egress, credential injection, token sync, CA material,
dependency isolation, or runtime startup order, review the actual trust boundary
instead of only the intended flow. Track assets, attackers, trusted components,
data paths, lifecycle failure modes, and proof. If the local
`security-architect` skill or agent is available, use it for these reviews.

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

Run the narrowest relevant tests first, then broaden based on risk. For normal
TypeScript changes, run the affected Vitest file plus `pnpm test` and
`pnpm typecheck`. After every change, run both `pnpm check` and
`pnpm typecheck` before committing or reporting completion. For runtime asset
changes, regenerate embedded assets and run tests that cover asset sync. For
sandbox, proxy, firewall, Docker network, or credential-boundary changes, run
`make test-runtime` or `make test-all` when the Docker CLI and a reachable
Docker daemon are available.


## Local only docs

If `local/` exists locally, it is a separate local only directory.
Read `local/` before large architectural changes.
Do not create public references that require `local/` to exist.

## User Override

If the user's instructions conflict with any rule in this document,
ask for explicit confirmation before overriding. Only then execute their instructions.
