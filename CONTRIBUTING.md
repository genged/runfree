# Contributing to Runfree

Thanks for looking. Runfree is a security-sensitive project: the agent container
is untrusted, and the proxy container is the trust boundary for outbound HTTPS
and proxy-managed credentials. Most of what follows exists to keep that boundary
honest.

Nothing here needs private resources. If a step asks for something you do not
have, that is a bug in this document — open an issue.

## Setup

```bash
git clone https://github.com/genged/runfree.git
cd runfree
pnpm install --frozen-lockfile
```

| Tool | Version | Needed for |
| --- | --- | --- |
| Node | 22 | Everything |
| pnpm | The `packageManager` version in `package.json` | Everything. Do not substitute another package manager. |
| Docker | Docker Desktop with Compose on macOS, or native Docker Engine with Compose on Linux | The live runtime and packaged live tests only |

You do not need to install Bun. `pnpm run build:bin`, the test bundles, and
release packaging run Bun through `./bunw`, which uses the version in
`.bun-version`. If the `bun` on your PATH reports a different version, `./bunw`
downloads the declared one from npm on first use, checks its sha512 against the
registry, and caches it in `~/.cache/runfree-dev/bun` (set `RUNFREE_BUN_CACHE`
to move it). The download needs `curl`, `tar`, `openssl`, and `base64`. To
change the Bun version, edit `.bun-version`; CI reads the same file.

Unit tests and static checks do not need Docker.

To try this checkout's CLI without touching your installed Runfree, run
`scripts/dev-runfree.sh [--state-root DIR] <runfree args>`. It points the CLI at
an isolated XDG data, state, and config root, so a development `up` never
writes into the installed Runfree's state. It does not isolate Docker: the
Compose project name comes from the project path alone, so use a scratch
`--workspace`.

## Before you open a pull request

```bash
pnpm check        # Biome
pnpm typecheck    # tsc --noEmit
pnpm test         # the Vitest suite
```

`make test` runs the static checks plus the unit tests.

If your change touches runtime, proxy, firewall, Docker network, mount, or
credential behavior, it also needs a Docker host:

```bash
make test-runtime-core     # trust-boundary live proofs: run for every such change
make test-runtime          # the whole live suite (core + extended): release gate
make test-runtime-smoke    # one tranche, as a quick per-commit check
make test-all              # everything, including packaged offline and live E2E
```

`make test-runtime-smoke` is a subset, not a substitute. Say in the pull request
which of these you ran and on what.

Run the narrowest relevant test first, then widen. [`docs/testing.md`](docs/testing.md)
explains what each layer proves and where its proof stops.

## Pinned Git

The test suite never uses the Git your OS ships. Every Vitest run puts a pinned
Git first on `PATH` (`tests/support/pinned-git.ts`), so a result means the same
thing on every machine and in CI:

```
pnpm test        → whole suite on the default pinned Git (the newest)
make test-git    → the Git-dependent files on every pinned Git
```

The first run downloads the binary for your platform (linux-x64, linux-arm64,
darwin-arm64, or darwin-x64) from this repo's `git-test-bin-<n>` prerelease,
checks its SHA-256 against `tests/git-matrix/git-bins.lock.json` before
unpacking it, and caches it in `~/.cache/runfree-dev/git/<version>/` (under
`XDG_CACHE_HOME` when set). Later runs only check `git --version`. With no
network and no cache the run fails with the fix; it never falls back to the
host Git and never skips.

`make test-git` runs `tests/git-matrix/files.txt` once per locked version and
prints a table: version, result, tests passed, tests not applicable, other
skips, and the first failure. `make test-git GIT=2.43.0` runs one version;
`GIT_TEST=<file>` runs one file. A test whose setup cannot exist on older Git
(relative worktree links need 2.48) uses `needsGit("2.48")` from
`tests/support/git-version.ts` instead of `test`: it runs on the default Git and
counts as "not applicable" on older lanes. A test that skips on one Git and
runs on another without declaring it fails the lane; a skip on every lane (a
Linux-only test on macOS) is only counted. Where
Runfree behaves differently on older Git, prefer one test that checks both
sides with `gitAtLeast` over a skip.

`make test-git-build GIT=<version>` builds one locked version from its
kernel.org tarball into the cache, with the flags the release uses
(`GIT_MAKE_FLAGS` in `scripts/git-bins.ts`). Use it on a platform without a
published binary or before one is published. It needs `cc`, `make`, and libcurl
development files (on macOS, the Xcode command-line tools; on Debian and
Ubuntu, `zlib1g-dev` and `libcurl4-openssl-dev`).

A new test file that spawns `git` belongs in `tests/git-matrix/files.txt`;
`make test-static` fails if an entry is not a tracked test file.

To add or change a version (the weekly "Check for a new Git release" workflow
opens an issue when kernel.org has a newer Git than the lock's `default`):

1. `make git-bins-add GIT=<version>`, with `REPLACE=<version>` to drop one
   (moving the newest lane, for example). It downloads the kernel.org tarball,
   checks its signature against `tests/git-matrix/git-signing-key.asc`, and
   locks its SHA-256. If the lock's release is already published, it moves
   `release.tag` to the next `git-test-bin-<n>` and clears every asset digest,
   because the new release rebuilds every version. `default` becomes the
   newest locked version. It needs `curl`, `gpg`, `gpgv`, and `xz`.
2. Run `make test-git-build GIT=<version>` (it checks the digest), then
   `make test-git GIT=<version>`, and push the branch.
3. A maintainer pushes the lock's `release.tag` on the branch's commit to this
   repo (`git push origin <sha>:refs/tags/git-test-bin-<n>`). The "Build test
   Git binaries" workflow runs from the tagged commit: it builds every locked
   version on all four platforms, verifies kernel.org's signature, runs
   `make test-git` on each build, and publishes a prerelease that never
   becomes "latest". Running the workflow by hand only builds and tests.
4. `make git-bins-pin` records each published asset's digest from the
   release's `SHA256SUMS`; commit it to the pull request. Published releases
   are never replaced or deleted: older commits still download from them.

## Things that will come back in review

**Generated assets are not edited by hand.**
`packages/cli/src/embedded-assets.generated.ts` is generated. Change the
canonical source, then:

```bash
pnpm run build:runtime
pnpm run generate:assets
```

CI regenerates and fails on a diff.

**Security-sensitive changes need negative tests.** Prove the refusal happens
*before* the sensitive side effect: before the DNS lookup, before the upstream
connection, before credential injection, before the policy mutation, before the
filesystem write. A test that only proves the happy path does not show where the
boundary is.

**Every new fail-closed refusal ships with its way out.** If a change can wedge
a user, the pull request also contains the path that unwedges them and a test
for both halves.

**Proxy environment variables are not enforcement.** They route cooperative
clients. Enforcement is Docker mounts, agent-side firewalling, proxy policy, and
proxy-side token storage. Do not rely on an env var to stop anything.

**Real tokens never enter the agent container.** Agent-visible environment
variables carry placeholders or `runfree_oauth_*` handles. Real values live in
host-resolved sources and proxy-only memory.

**Host-side writes to project paths go through the safe helpers.**
`safeReplaceProjectFile`, `ensureSafeProjectDir`, and the rest of
`packages/cli/src/safe-fs.ts` reject symlinks, hard links, and special files.

**Property tests are replayed, not retried.** Files named
`<module>.property.test.ts` use `fast-check` with a random seed on every run
(`tests/support/property.ts`). A failure prints the seed and shrink path; replay
it with
`RUNFREE_PROP_SEED=<seed> RUNFREE_PROP_PATH=<path> pnpm exec vitest run <file> -t "<property name>"`.
Decide whether the failure is a product bug, a wrong property, or an
infrastructure fault before you rerun anything. Keep the shrunk counterexample
as a plain example test in the module's ordinary test file, so it still runs if
the generator changes. `make test-property-soak` runs the agent-input
properties at 100,000 cases each; `RUNFREE_PROP_RUNS` sets the count for any run.

**Prefer runtime inspection over declarative config in tests.** For
capabilities, routes, mounts, and firewall state, ask the running system. A
Compose file that says the right thing is not proof that the container has it.

## Dependencies and tooling

Adding a dependency, a language, or a toolchain is a maintainer decision, not an
implementation detail. Open an issue first and present options rather than
picking one. Runfree deliberately runs TypeScript directly with `tsx` for
scripts and compiles only the proxy for packaging; `tsc --noEmit` is the normal
static gate.

The same applies to new CI actions, scanners, and recording tools. Actions are
pinned to commit SHAs, and an unpinned reference fails
`scripts/release-workflow.test.ts`.

A new language is the higher bar: it brings its own toolchain, build
reproducibility, cross-compilation, and release pinning, and each becomes
permanent maintenance.

`pnpm run update:agent-tools -- [all|claude|codex|pi@<version>]` updates the
embedded Claude, Codex, and Pi CLI pins and regenerates runtime assets. It
first checks that the new Claude and Pi accept `--session-id` the way launch
and resume assume (`scripts/agent-session-id-contract.ts`), and that each
tool's headless argv, stdin prompt, and event stream match `runfree run`
(`scripts/agent-headless-contract.ts`). The host only downloads the locked
tools with `--ignore-scripts`; the rebuild and probes run in a pinned `node:22`
container with no network. It needs a Docker daemon, and a failed check
restores the previous lockfile. `--no-contract` skips the check;
`make test-runtime-core` runs the same check on the built agent image.

## Pull request scope

One reviewable change per pull request. A refactor and a behavior change in the
same diff make both harder to review, and this is a codebase where "harder to
review" has a security cost.

Include in the description: what changed, what you ran, what compatibility
impact it has, and what security impact it has. The pull request template asks
for exactly that.

## Compatibility

- Project config version 4 is current. Config versions below 4 are refused, not migrated.
- `.runfree/network-policy.json` is a fixed path. Do not move it.
- Desired policy allows exact hostnames only, no wildcards; its format is in
  [`docs/cli.md`](docs/cli.md#network-policy).

A change that breaks an existing project's state needs either a migration or a
refusal that names the remedy, and an entry in the release notes.

## Documentation

[`docs/architecture.md`](docs/architecture.md),
[`docs/security.md`](docs/security.md), and
[`docs/security-rules.md`](docs/security-rules.md) are authoritative. Read the
relevant one before changing runtime, proxy, network, mount, credential, or sandbox
behavior — the intended flow is not the same thing as the trust boundary.
A change must not break a rule in `docs/security-rules.md`; cite its ID (for
example `NET-1`) in the pull request when a change touches one.

[`docs/writing-docs.md`](docs/writing-docs.md) says which page owns which
topic and how to write for it. A user-visible change updates its owning page in
the same pull request, or the pull request says why nothing needs to change.
The checks the docs must pass are in
[What the checks enforce](docs/writing-docs.md#what-the-checks-enforce).

## Reporting bugs

GitHub Issues, with the bug or feature template. Include the Runfree version,
your OS and Docker (Desktop or Engine) versions, the command you ran, and a sanitized
reproduction.

Do not paste tokens, full environment dumps, or unredacted logs into an issue.
Runfree's own diagnostics redact known secret values; a hand-copied log has no
such protection.

**Suspected vulnerabilities do not go in a public issue.** Use private reporting
as described in [`SECURITY.md`](SECURITY.md).

## Review

The maintainer is the default reviewer for runtime and proxy changes, release
workflows, and documentation, and is the only person who approves a release.
Support is best effort, with no response-time commitment; that applies to pull
requests too.

Review also checks failure messages: the last line states what did not happen
in the user's nouns, "deferred" is reserved for work that is actually queued,
and no message ends with the internal step that was about to run.

There is no formal code of conduct yet, because there is no designated
enforcement contact to make one mean anything. Be decent to each other in the
meantime.
