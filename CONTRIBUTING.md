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
| pnpm | 10.28.0 | Everything. Do not substitute another package manager. |
| Bun | 1.3.14 | `pnpm run build:bin` and release packaging |
| Docker | Docker Desktop with Compose | The live runtime and packaged live tests only |

Bun is easy to miss: the source build works without it right up until
`pnpm run build:bin`, which runs `bun build --compile`.

Unit tests and static checks do not need Docker.

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

## Pull request scope

One reviewable change per pull request. A refactor and a behavior change in the
same diff make both harder to review, and this is a codebase where "harder to
review" has a security cost.

Include in the description: what changed, what you ran, what compatibility
impact it has, and what security impact it has. The pull request template asks
for exactly that.

## Compatibility

- Project config version 4 is current. Older versions and legacy keys are refused, not migrated.
- `.runfree/network-policy.json` is a fixed path. Do not move it.
- Desired policy v2 is an exact-hostname allowlist plus per-host `requests`
  rules, `services`, `tokens`, and an optional `writeApproval` default. No
  wildcard hosts.
A change that breaks an existing project's state needs a migration and an entry
in the release notes.

## Documentation

[`docs/architecture.md`](docs/architecture.md) and
[`docs/security.md`](docs/security.md) are authoritative. Read the relevant one
before changing runtime, proxy, network, mount, credential, or sandbox
behavior — the intended flow is not the same thing as the trust boundary.

Public documentation must work in a clone that has nothing else:
`make test-static` fails on a relative link or heading anchor that would not
resolve there.

## Reporting bugs

GitHub Issues, with the bug or feature template. Include the Runfree version,
your macOS and Docker Desktop versions, the command you ran, and a sanitized
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

There is no formal code of conduct yet, because there is no designated
enforcement contact to make one mean anything. Be decent to each other in the
meantime.
