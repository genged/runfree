# Testing

Runfree separates tests by the boundary they prove.

| Layer | Command | Boundary | Main faults found |
| --- | --- | --- | --- |
| Unit and integration | `pnpm test` | TypeScript modules and the source-backed CLI shim | Logic, parsing, state transitions, and component wiring |
| Live runtime security | `make test-runtime` | Source-backed CLI plus real Docker | Container topology, capabilities, egress, proxy policy, credentials, and session admission |
| Live runtime smoke | `make test-runtime-smoke` | One tranche of the layer above (`runtime-topology`) | Fixture drift against the CLI, topology, capability floor, egress containment, and the CONNECT guard; a per-commit subset, not a substitute |
| Packaged CLI end to end | `make test-cli-e2e` | The compiled `dist/runfree` executable | Compilation, embedded assets, entrypoint, first-run workflows, safe refusals, and filesystem compatibility |
| Packaged runtime end to end | `make test-cli-e2e-live` | The compiled executable plus real Docker | First startup, exact approvals, image build, managed session launch, reuse, and teardown |

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

The long-horizon scenario catalog is maintainer-only planning material. This
public document describes only the test layers that exist in this checkout.

The packaged suite implements a focused subset of that catalog. It keeps one
scenario per packaging-specific contract area.

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
`LH-*` scenario, physical layer, cadence, implementation status, selected
owned-state areas, required programs, cleanup contract, exact test file, and
exact test name. The report includes all 38 program statuses and separately
lists blocked work. Modeled steps name their limits. The required lane has no
real service credentials.

The offline lane has 25 tests. All 25 passed on 2026-09-16 (`make test-cli-e2e`,
7 files, 25 tests). An earlier version of this page described 23 passing and 2
intentionally failing; that is no longer what the lane does.

The `Implemented-failing` status still carried by LH-09, LH-12, and LH-23 in
`e2e/support/scenario-program.ts` therefore no longer corresponds to a failing
test. A green run does not say whether the underlying defects were fixed or the
scenarios were rewritten to assert something else, so treat those labels as
needing a maintainer disposition rather than as current evidence either way.

The LH-10 refusal proves that `runfree image init` rejects a symlinked
`.runfree/runfree.json` before it writes project, XDG config, XDG data, or XDG
state. The LH-03 tests prove that every command, `init` included, refuses a
pre-v4 config with the remedy and leaves owned state unchanged.

## Output Gates

Two static tests keep user-facing text honest and run inside `pnpm test`
and `make test-static`:

- `scripts/emitted-commands.test.ts` parses every `runfree ...` command the
  CLI can print — the remedy registry in `packages/cli/src/remedies.ts` plus
  every hand-written `runfree <command>` string literal in the emitting
  modules — under the real command parser. A remedy that names a command,
  subcommand, or flag that does not exist fails the suite. Emit next-step
  commands through the registry rather than as string literals.
- `scripts/check-terminology.ts` rejects the bare word "generation" in
  user-visible strings: name the family (effective policy generation, control
  plane generation, session agent generation, runtime generation, ...) as
  `docs/architecture.md` "Generation Families" requires.

When writing a failure message, make the last line state what did not happen
in the user's nouns, reserve "deferred" for work that is actually queued, and
never end a message with the internal step that was about to run.

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
  pipeline runs only unit tests; it does not run this lane against the signed
  archive.
- Nothing in these layers proves the live runtime on a platform where
  `make test-runtime` has not been run. Source tests passing on Linux CI is not
  evidence about macOS with Docker Desktop.

The harness is POSIX-only. Process groups, signals, permission modes, `umask`,
and symlinks need different implementations for Windows.
