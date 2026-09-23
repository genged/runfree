<p align="center">
  <img src="docs/logo.png" alt="" width="200" />
</p>
<h1 align="center">Runfree</h1>
<h3 align="center">Run coding agents in Docker, with project network policy and proxy-held credentials</h3>
<p align="center">
<a href="https://github.com/genged/runfree/actions/workflows/test.yml">
  <img src="https://github.com/genged/runfree/actions/workflows/test.yml/badge.svg" alt="Test status" />
</a>
<a href="https://github.com/genged/runfree/actions/workflows/release.yml">
  <img src="https://github.com/genged/runfree/actions/workflows/release.yml/badge.svg" alt="Release status" />
</a>
<a href="https://github.com/genged/runfree/releases/latest">
  <img src="https://img.shields.io/github/v/release/genged/runfree?sort=semver" alt="Latest release" />
</a>
<img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" />
</p>

A coding agent is useful because it can read your code, edit it, install
packages, run tests, and call APIs. Run it directly on your machine and all of
that happens with your shell's reach and your tokens — so one prompt injection,
one confused tool call, or one bad suggestion acts with everything you have.

Runfree starts Claude Code, Codex, or Pi in a per-project Docker workspace with
no route to the internet, and puts a proxy on the only way out. The proxy
enforces an exact-hostname allowlist you approve on the host, and attaches real
service tokens itself. The agent never holds them.

```bash
runfree init
runfree credential source add github-cli -- gh auth token
runfree service enable github --from-source github-cli
runfree
```

The agent works normally. When it reaches for a host you have not approved, the
request is refused and `runfree doctor` tells you which host and what would
allow it.

## Who it is for

Individual developers running Claude Code, Codex, or Pi on their own projects,
who want the agent's tools in a container and their service credentials out of
its reach. Teams can commit policy and review it like code — see
[`docs/team-workflow.md`](docs/team-workflow.md) — but the primary case is one
developer and one project.

Runfree is not a VM boundary, not a cloud service, and not a substitute for
reading what an agent wrote. It narrows the default blast radius.

## What you get

**Familiar agents and tools.** The real Claude Code, Codex, or Pi CLI, at pinned
versions, with the project at `/workspace` and normal project tooling around it.
Not a wrapper that intercepts prompts.

**An outbound policy you reviewed.** `.runfree/network-policy.json` is
exact-hostname allowlisting plus per-host request rules, committed with the
project. The agent can edit that file; editing it grants nothing. Runtime
authority comes from a host-owned approval that compiles and selects an
effective policy generation.

**Tokens the agent cannot read.** `runfree credential source add` names a
command that runs on your host. The proxy resolves it and attaches the result to
allowed requests. The agent's environment gets a placeholder or a
`runfree_oauth_*` handle.

Each of those has a limit worth knowing before you rely on it —
see [Limitations](#limitations).

## Quickstart

### 1. Install

Runfree 0.5.0 publishes **Apple Silicon macOS** binaries and is supported with
**Docker Desktop**. You also need `git`.

```bash
brew install genged/tap/runfree
```

Without Homebrew:

```bash
curl -fsSL https://raw.githubusercontent.com/genged/runfree/main/scripts/install.sh | bash
```

That downloads the latest release for your architecture, verifies its SHA-256
checksum against the published manifest, and installs to `~/.local/bin/runfree`.
It needs `bash`, not `sh`.

To build from source instead, you need Node 22, pnpm 10.28.0, and Bun 1.3.14:

```bash
pnpm install --frozen-lockfile
pnpm run build:bin
./dist/runfree version
```

Intel macOS and Linux have no published binaries. They can be built from source;
building is not a support claim.

### 2. Initialize a project

```bash
cd ~/code/my-project
runfree init
```

`init` writes project-local config and deny-all desired policy:

```text
.runfree/
  runfree.json
  network-policy.json
  config/
```

Runtime state lives outside the repository, under your XDG state root, for
example `~/.local/state/runfree/projects/<project-hash>/`.

### 3. Run an agent

```bash
runfree          # the configured default agent
runfree claude
runfree codex
runfree pi
```

Starting Claude or Codex first enables its credentialless operational service,
so the login and model hosts are allowed without configuring token injection.
Pi's provider setup stays explicit.

Around a session:

```bash
runfree status
runfree shell
runfree doctor            # why a request was blocked, and what would allow it
runfree logs proxy --verbose
runfree stop
```

### 4. Add network access and credentials

Credentials are resolved on the host and injected only by the proxy. To reuse a
GitHub CLI login without the token entering the container:

```bash
runfree credential source add github-cli -- gh auth token
runfree service enable github --from-source github-cli
runfree credential sync
```

To allow a single host, read-only:

```bash
runfree host add api.example.com --read-only
runfree host explain api.example.com
```

To discover what a project actually needs, during a trusted onboarding task:

```bash
runfree up --audit-network=30m
runfree audit report          # suggests exact host add commands; never edits policy
runfree audit off
```

[`docs/cli.md`](docs/cli.md) is the full command reference.
`runfree help <topic>` has task guides.

## How it works

The agent container is untrusted. The proxy container is the trust boundary.
The host owns approval.

- Direct agent egress and host-gateway egress are blocked by Docker topology.
- Outbound HTTPS/WSS goes through the proxy, which checks the allowlist, then
  the per-host request rules, then write approval, and only then reads a token.
- Desired policy is writable from the container; effective policy is not
  reachable from it.
- Dependency directories live in Runfree-owned volumes rather than your
  checkout.

That is what makes the confused-deputy case bounded: a compromised agent can ask
for an allowed request, but it cannot read the proxy-held token or widen the
policy from inside the container.

See [`docs/architecture.md`](docs/architecture.md) for the runtime model.

## Limitations

Worth reading before you rely on it. The full threat model is
[`docs/security.md`](docs/security.md).

- **Your working tree is writable**, including `.git`. Runfree bounds the
  network, not the repository.
- **Native Claude and Codex logins are not proxy-held.** They live in
  per-project agent state, inside the agent's reach. Only proxy-managed service
  tokens get the credential boundary.
- **An allowed host stays allowed.** Policy controls destination and request
  shape, not the content of what an agent sends to a destination you approved.
  A broad multi-tenant host is a broad allowance.
- **Project image builds run before the sandbox exists**, on the host Docker
  daemon. Review project Dockerfiles as host-side decisions.
- **Audit mode widens what the agent can reach** while it is on. It is a
  time-boxed discovery tool, not a default.
- **Docker and the host are trusted.** This is not VM isolation.

## Comparison

| Approach | What bounds the agent | Where your tokens are |
| --- | --- | --- |
| Agent directly on the host | Nothing, beyond your own file permissions | Your shell environment and config files, fully readable |
| An ordinary devcontainer | Filesystem and process isolation; network is usually wide open | Usually forwarded into the container |
| A remote VM or cloud sandbox | Strong isolation; your code has to go there | Wherever you put them in that environment |
| Runfree | Container isolation, plus egress that is deny-by-default and host-approved | On your host and in the proxy, not in the container |

Runfree is the local option when you want the agent contained but the work to
stay on your machine. If you need protection against native code escaping a
container, you need a VM, not this.

## Project status

Runfree is a security-sensitive beta. The latest release is the only supported
line, on a best-effort basis with no response-time commitment.

Implemented: the Docker/proxy runtime, exact-host network policy, proxy-held
static credentials, OAuth handle mediation, MCP import and approval, dependency
overlays, approve-on-write, audit mode, interrupted-session recovery, and
Homebrew packaging.

Not in this release: Linux and Intel macOS binaries, OrbStack as a supported
backend, prebuilt runtime images, npm distribution, and artifact provenance
attestations.

The published binary is ad-hoc signed, not notarized. Install with Homebrew or
`scripts/install.sh` — both fetch over curl, which sets no quarantine
attribute. If you download the tarball in a browser instead, macOS quarantines
it and Gatekeeper refuses to run it. Verify what you downloaded against the
release's SHA-256 manifest.

Please do not open a public issue for a suspected vulnerability. Use GitHub
private vulnerability reporting, as described in [`SECURITY.md`](SECURITY.md).

## Development

```bash
pnpm install --frozen-lockfile
pnpm check
pnpm typecheck
pnpm test
pnpm run build:bin     # needs Bun
make test-cli-e2e
```

Runtime, proxy, firewall, mount, or credential changes also need a Docker host:

```bash
make test-runtime
make test-cli-e2e-live
# or
make test-all
```

Do not hand-edit `packages/cli/src/embedded-assets.generated.ts`; regenerate it:

```bash
pnpm run build:runtime
pnpm run generate:assets
```

[`CONTRIBUTING.md`](CONTRIBUTING.md) has the rest, including what review will
ask about.

## Further reading

- [`docs/index.md`](docs/index.md) — the documentation map
- [`docs/project-brief.md`](docs/project-brief.md) — product model and release scope
- [`docs/architecture.md`](docs/architecture.md) — runtime, proxy, policy, and state
- [`docs/security.md`](docs/security.md) — threat model and verification
- [`docs/cli.md`](docs/cli.md) — full command reference
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — refusals and recovery
- [`docs/whats-new-0.5.0.md`](docs/whats-new-0.5.0.md) — current release
- [`AGENTS.md`](AGENTS.md) — guidance for coding agents working in this repo
