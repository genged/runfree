# Using Runfree on a Team

Runfree's per-project files are meant to be committed. Its authority is not.

The split that makes this work: `.runfree/network-policy.json` is *desired*
policy, and it is reviewable text in the repository. Approval and effective
runtime authority live in each developer's host-owned XDG state and never travel
with the repository. A teammate who commits a policy change proposes it; it
takes effect on your machine only after you approve it on your machine.

## What goes in the repository

```text
.runfree/
  runfree.json            # agent choice and non-network runtime options
  network-policy.json     # desired hosts, request rules, services, credential destinations
  image/Dockerfile        # optional project agent image
  .gitignore              # excludes state/ and resolved credential files
```

What never goes in the repository: real tokens, resolved credential files, XDG
state, approval records, and proxy CA material. `.runfree/.gitignore` already
excludes `state/`, `config/tokens.json`, and `config/agent.env`. Leave those
rules in place.

This repository dogfoods that arrangement: Runfree's own `.runfree/` directory is
committed as a worked example.

## Setting up

One person scaffolds the project:

```bash
runfree init
runfree service enable node
runfree service enable github
git add .runfree && git commit -m "chore: add runfree project policy"
```

`runfree service enable github` without a `--from-*` source writes the hosts and
the credential *destination*. It does not write a token. The destination says
"a GitHub token belongs in this header on these hosts"; where the token comes
from is each developer's own decision.

Every other developer clones and binds their own sources:

```bash
runfree credential source add github-cli -- gh auth token
runfree service enable github --from-source github-cli
runfree
```

The source is a command that runs on that developer's host, under that
developer's own login. Nobody shares a token, and nobody copies XDG state.

## Reviewing a policy change

A policy change arrives like any other diff, and it is worth reading like one: a
new host is a new place the agent may reach, and a new credential destination is
a new place a token may be sent.

```bash
runfree policy diff       # what changed against your approval
runfree policy review     # canonical desired policy and its authority
runfree policy explain api.example.com
runfree policy approve    # approve exactly one subject
runfree policy use-approved
```

Approving on your machine changes only your machine. There is no team-wide
approval, and that is the point: a teammate's approval is not authority over
your runtime, and a compromised agent in someone else's checkout cannot widen
your policy by pushing a commit.

## Keeping service definitions honest

Curated services are pinned by digest when they are enabled, so a later Runfree
release changing a bundle does not silently change what a project allows.

```bash
runfree service diff            # approved semantics vs this CLI's registry
runfree service diff --apply    # write the reviewed entry after one confirmation
```

For a bundle Runfree does not curate, define it once and commit it:

```bash
runfree service custom add user-internal-api --from-file service.json
```

User-defined service ids live under `user-*`.

## MCP servers

A project `.mcp.json` or `.codex/config.toml` entry is imported only after an
explicit approval on each machine:

```bash
runfree mcp list
runfree mcp explain claude my-server
runfree mcp approve claude my-server --from-source op-token
```

The same rule applies: committing an MCP entry proposes it. Static headers need
a host-owned credential source, so approving still does not put a real token in
the repository or in the container.

## What not to do

- Do not commit a token, a `.env` with real values, or anything from
  `.runfree/state/`.
- Do not copy another developer's XDG state to "skip the approvals". Approval
  records are bound to the checkout path and inode on that machine.
- Do not treat a green review from a teammate as local authority. It is a
  proposal until you approve it.
- Do not put a shared team token in a source command. Use each developer's own
  login, so revoking one person does not mean rotating everyone.
