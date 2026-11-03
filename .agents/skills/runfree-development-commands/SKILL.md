---
name: runfree-development-commands
description: Use when installing dependencies or choosing Runfree build, test, asset-generation, packaging, or checkout execution commands.
user-invocable: false
metadata:
  internal: true
---

## Development Commands

- `pnpm install --frozen-lockfile` installs dependencies.
- `pnpm check` runs Biome checks across the repo.
- `pnpm test` runs the Vitest suite.
- `pnpm typecheck` runs `tsc --noEmit`.
- `make test` runs static checks plus unit tests.
- `make test-runtime` runs the whole live Docker suite (the release gate); it
  requires the Docker CLI and a reachable Docker daemon. It has two tiers
  (`tests/runtime/live/tiers.ts`): `make test-runtime-core` proves the trust
  boundary, and `make test-runtime-extended` proves recovery, upgrades, load,
  and optional features. `make test-runtime-smoke` runs one tranche as a
  per-commit check on a Docker host.
- `make test-all` runs static and unit tests, Docker Compose template
  validation, the full live runtime suite, and packaged offline and live E2E.
- `pnpm run build:runtime` compiles proxy/runtime-contract packages and assembles
  `dist/runtime/**` for packaging. Tests and `pnpm typecheck` read workspace
  sources and do not need it first; `scripts/workspace-source-exports.test.ts`
  keeps package exports on `src/`.
- `pnpm run generate:assets` regenerates
  `packages/cli/src/embedded-assets.generated.ts` from `dist/runtime/**`.
- `pnpm run update:agent-tools -- [all|claude|codex|pi@<version>]` updates the
  embedded Claude/Codex/Pi CLI pins and checks their launch contracts; it needs
  a Docker daemon. See `CONTRIBUTING.md` "Dependencies and tooling".
- `pnpm run build:bin` compiles `dist/runfree`; release archives use
  `scripts/package-homebrew-artifacts.sh`.
- `scripts/dev-runfree.sh [--state-root DIR] <runfree args>` runs this
  checkout's CLI against isolated XDG state; it needs a scratch `--workspace`.
  See `CONTRIBUTING.md` "Setup".
