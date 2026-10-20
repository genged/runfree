# Testing

Runfree separates tests by the boundary they prove.

| Layer | Command | Boundary | Main faults found |
| --- | --- | --- | --- |
| Unit and integration | `pnpm test` | TypeScript modules and the source-backed CLI shim | Logic, parsing, state transitions, and component wiring |
| Property soak | `make test-property-soak` | The path, GraphQL, MCP, and `.mcp.json` property tests at 100,000 cases each, run by hand | Rare agent-controlled inputs that 200 cases per change miss; run before a release that changes those classifiers. Not part of any other target |
| Live runtime security (release gate) | `make test-runtime` | Source-backed CLI plus real Docker | Both tiers below |
| Live runtime core | `make test-runtime-core` | The trust-boundary subset of the layer above | Topology, capabilities, egress, CONNECT guard, request shape and write approval, inert policy edits and live revocation, managed-launch file safety, exact session admission, the pinned Claude and Pi `--session-id` contract on the built agent image, and two interrupted conversations resuming at the same time; run for every runtime, proxy, firewall, network, or credential change |
| Live runtime extended | `make test-runtime-extended` | The rest of the live suite | Crash recovery, rolling upgrades and proxy replacement, renewal under load, session-entry ordering, helper cleanup, audit mode |
| Live git providers (gated, before a release) | `TEST_RUNTIME_GIT_PROVIDERS=github,gitlab` with `tests/runtime/live/git-https-provider.live.test.ts` | Source-backed CLI, real Docker, and a real GitHub and GitLab private repository | SSH remotes reaching the provider over HTTPS, injected git credentials, a clean anonymous failure, approved and denied pushes, and Git LFS batch classification; skipped unless the gate is set |
| Live runtime smoke | `make test-runtime-smoke` | One tranche of the layer above (`runtime-topology`) | Fixture drift against the CLI, topology, capability floor, egress containment, and the CONNECT guard; a per-commit subset, not a substitute |
| Packaged CLI end to end | `make test-cli-e2e` | The compiled `dist/runfree` executable | Compilation, embedded assets, entrypoint, first-run workflows, safe refusals, and filesystem compatibility |
| Packaged runtime end to end | `make test-cli-e2e-live` | The compiled executable plus real Docker | First startup, exact approvals, image build, managed session launch, reuse, and teardown |

`make test-release` is the pre-tag gate for a release commit. It runs what the
Test workflow runs on that commit: static checks, unit tests, template
validation, and the offline packaged end-to-end lane. It needs the Docker CLI
and Bun, but not a Docker daemon.

Before a release is tagged, record one green run of the gated git provider
tranche against both providers. The run is not part of `make test-runtime`,
because it needs provider credentials:

```bash
TEST_RUNTIME_BACKEND=docker-desktop \
TEST_RUNTIME_GIT_PROVIDERS=github,gitlab \
TEST_RUNTIME_GITHUB_REPO=https://github.com/<owner>/<repo>.git \
TEST_RUNTIME_GITHUB_SOURCE=<source> \
TEST_RUNTIME_GITLAB_REPO=https://gitlab.com/<group>/<repo>.git \
TEST_RUNTIME_GITLAB_SOURCE=<source> \
pnpm exec vitest run --project runtime-live tests/runtime/live/git-https-provider.live.test.ts
```

Each repository is a dedicated private repository. Each `<source>` names an
existing `runfree credential source` whose token can only read and write that
repository. The tranche never reads `GH_TOKEN`, `GITLAB_TOKEN`, or `gh auth`.
`TEST_RUNTIME_GITHUB_LFS_REPO` and `TEST_RUNTIME_GITLAB_LFS_REPO` are optional
and name a repository with a committed Git LFS object; without them the LFS
case skips. On GitHub the LFS case proves a download batch is a read with the
credential; on GitLab, where LFS is not mediated, it proves the download batch
waits for approval and, once approved, reaches GitLab with no credential and is
refused there. When the gate names a provider and one of its inputs is
missing, the run fails. The file header lists every input.

`make test-all` runs every layer in this table plus Docker Compose template
validation. It requires the Docker CLI and a reachable daemon.

The packaged layer never falls back to `bin/runfree.js`, `src/cli.ts`, an
interpreter, or a binary on `PATH`. `RUNFREE_E2E_ARTIFACT` must name one
absolute executable file. The build-and-test entrypoint is:

```bash
scripts/run-cli-e2e.sh
```

To validate an existing candidate without rebuilding it:

```bash
RUNFREE_E2E_ARTIFACT="$PWD/dist/runfree" scripts/run-cli-e2e.sh --no-build
```

For the real-Docker packaged lifecycle:

```bash
TEST_RUNTIME_BACKEND=docker-desktop scripts/run-cli-e2e.sh --live
```

Set `KEEP_TMP=1` to retain disposable worlds. Each failure prints the command,
working directory, outcome kind, captured output, declared environment names,
and a bounded world tree. Known secret values are redacted.

## Packaged Scenario Scope

The packaged suite covers one scenario per major public contract area:

- artifact, version, and hierarchical help;
- first initialization, stable project identity, and a null second run;
- paths with spaces, non-ASCII paths, and a restrictive `umask`;
- pre-v4 config refusal with no owned-state change;
- credential source plus curated service enablement;
- user-defined service import and pinned definition evolution;
- offline interrupted-session inventory and hostile evidence handling;
- host inbox import, cleanup, compatibility, and unsafe-entry handling;
- parser refusal with unchanged owned state;
- an unsafe-symlink pre-mutation check;
- fail-closed exact control and image approvals before a Docker build;
- one real-Docker lifecycle workflow.

Offline scenarios run in parallel. The Docker scenario runs alone. There are no
blanket retries. A flake is a harness or product defect.

Every test declares one evidence label. The reporter prints the label and can
write a JSON inventory through `RUNFREE_E2E_REPORT`. Each record also names its
scenario, physical layer, cadence, implementation status, selected owned-state
areas, required programs, cleanup contract, exact test file, and exact test
name, and the report lists blocked work separately. Modeled steps name their
limits. The required lane has no real service credentials.

## Output Gates

`scripts/emitted-commands.test.ts` (run by `pnpm test` and `make test-static`)
parses every `runfree ...` command the CLI can print — the remedy registry in
`packages/cli/src/remedies.ts` plus every hand-written `runfree <command>`
string literal in the emitting modules — under the real command parser. A
remedy that names a command, subcommand, or flag that does not exist fails the
suite. Emit next-step commands through the registry rather than as string
literals. The checks on public docs and user-visible terminology are listed in
[What the checks enforce](writing-docs.md#what-the-checks-enforce).

## Proof Limits

- Offline Docker and credential-provider stubs prove CLI orchestration and
  side-effect order. They do not prove daemon or provider compatibility.
- The managed-agent live scenario replaces the pinned Claude executable with a
  project-image recorder. It proves Runfree's managed launch, not Claude Code.
- Detailed runtime security behavior remains in `make test-runtime`; the
  packaged live scenario proves that the shipped executable reaches that
  runtime boundary.
- The suite does not yet allocate a pseudo-terminal. Interactive wizard and
  color-on-terminal cells require an approved maintained PTY dependency.
- Pull-request CI validates the candidate it compiled from source. The release
  pipeline runs the Test workflow's checks (static checks, unit tests, template
  validation, offline packaged E2E on a binary built from source); it does not
  run this lane against the signed archive.
- Nothing in these layers proves the live runtime on a platform where
  `make test-runtime` has not been run. Source tests passing on Linux CI is not
  evidence about macOS with Docker Desktop.

The harness is POSIX-only. Process groups, signals, permission modes, `umask`,
and symlinks need different implementations for Windows.
