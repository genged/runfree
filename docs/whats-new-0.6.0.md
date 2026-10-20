# What's New in Runfree 0.6.0

0.6.0 adds host services, git over HTTPS with proxy-held tokens, one-step MCP
setup, and same-terminal resume. Config version 4 is the same as in
[0.5.2](whats-new-0.5.2.md). `.runfree/network-policy.json` gains a version 3,
written only when its content needs it. The platform, install routes, and
support terms are the same as in [0.5.0](whats-new-0.5.0.md).

The concise release body is [`release-notes/0.6.0.md`](release-notes/0.6.0.md).
This page has the detail.

## Host services

A host service lets the agent reach a TCP service on the host's loopback: a
dev server, a database, a model server, or a simulator bridge. Clients in the
agent use it unmodified at `127.0.0.1:<port>`, even when they ignore proxy
settings.

```bash
runfree host-service add devserver --port 3000
runfree host-service list
runfree host-service remove devserver
```

- `add` refuses Runfree's own and Docker's ports, and ports with no visible
  listener or a Docker Desktop listener, before any policy write. It names the
  process it approved.
- The service appears in the next session. `remove` cuts open connections at
  once.
- `runfree status` lists each approved service with its current listener and
  warns when the listener is gone or changed.
- The tunnel is opaque. No request rules, write approval, or credential
  injection apply, so the host service's own authentication is the only check.

See [Host Services](cli.md#host-services) and
[Residual Risks](security.md#residual-risks).

## Git over HTTPS

With the `github` or `gitlab` service enabled at its current revision and a
token bound, `git clone`, `fetch`, `pull`, and `push` over HTTPS work in the
sandbox. The proxy adds the token as HTTP Basic auth only on git smart-HTTP
ref discovery, fetch, and push requests, and on `github.com` Git LFS batch and
lock requests. The token never enters the container. A push is still a git
push write: under the default `ask` posture it waits for `runfree approve`.

```bash
runfree service diff --apply                       # move an existing github service to the new revision
runfree host rules github.com --deny-git-push      # refuse pushes outright
```

The sandbox's Git config rewrites `git@github.com:`, `git@gitlab.com:`, and
their `ssh://` forms to HTTPS, so SSH remotes in your checkout work without
change. Your repository's `.git/config` is not changed. Host aliases from
`~/.ssh/config` and other SSH hosts are not rewritten and fail, because the
sandbox has no SSH egress.

Git LFS on `gitlab.com` is not mediated in this release, because GitLab
answers a batch request with a project-wide token that can push. On
`gitlab.com` and `bitbucket.org`, every LFS batch request, a download
included, is a write that waits for approval under `ask`.

User-defined services can now declare a `basic` scheme with a `username`, and
a `git-http` or `git-lfs` `protocol` scope, so a GitHub Enterprise Server or
self-hosted GitLab host can get a git credential too. See
[Git over HTTPS and SSH remotes](cli.md#git-over-https-and-ssh-remotes) and
[User-defined services](cli.md#user-defined-services).

## One-step MCP setup

`runfree mcp enable <agent> <server>` shows one review and asks once. It
approves a project entry, binds its credential source, finds the server's
OAuth hosts, applies the change to a running proxy, and runs the OAuth login.

```bash
runfree mcp enable claude my-server
runfree mcp enable claude my-server --no-discover --oauth-host auth.example.com --no-login
runfree mcp revoke claude my-server
```

- Discovery reads the server's RFC 9728 and RFC 8414 metadata from the host,
  with no credentials, no proxy, and no redirects, and only to public
  addresses. It needs a terminal unless you pass `--no-discover`.
- OAuth hosts are host-owned records, not lines in
  `.runfree/network-policy.json`. `runfree mcp revoke` removes exactly the
  hosts that `enable` added and clears the proxy's OAuth tokens and handles
  for the server.
- On an `ask` host, a plain login, refresh, or loopback client registration
  to an endpoint that discovery recorded for this server alone is an OAuth
  protocol read and does not wait for approval.
- Each `runfree claude`, `codex`, `pi`, or `shell` session gets its own OAuth
  callback port, so two sessions can log in at the same time.

Loopback HTTP MCP servers, such as `http://127.0.0.1:8089/mcp`, now import
without credentials. To reach one on the host, approve its port with
`runfree host-service add`. An HTTPS MCP server URL and its OAuth metadata and
token endpoints must name a hostname, not an IP address, and the OAuth URLs
must use `https:`. See [MCP](cli.md#mcp).

## Same-terminal resume

Each `runfree claude` and `runfree pi` launch now starts the agent with a
conversation id that the host chooses and records. Bare `runfree resume` in a
terminal uses it:

- When one interrupted Claude or Pi session clearly belongs to this terminal,
  it asks one question: "Resume it", "Not now", or "Forget it".
- Otherwise it shows a picker: strong terminal matches first, then weak
  matches, then the rest, newest first. Any row can be resumed or forgotten.
- Codex sessions without a recorded id can match by time, as capped and
  labelled picker rows.
- Two terminals cannot resume the same conversation: each resume claims it
  first, and a stuck claim is reclaimed.

```bash
runfree resume
runfree resume --list
runfree resume --all
```

`runfree claude`, `runfree codex`, and `runfree pi` never ask: they always
start a fresh session. See [Resume](cli.md#resume).

## Smaller improvements

- Host Git older than 2.48 no longer blocks a launch. Runfree prints one
  warning, and refuses only a worktree layout that old Git cannot read, before
  it writes any launch state. `runfree status` prints
  `host git: <version> (worktrees: enabled|disabled)`. See
  [Git worktrees](cli.md#git-worktrees).
- Warm launches do less work: they skip runtime re-validation, the session
  reconcile, the credential sync, and image cleanup when the warm proof shows
  nothing changed. `RUNFREE_TIMINGS=1` now times every warm-launch step.
- New session containers run under Docker's init, and a session reports
  attached only after its entry hands off to the agent.
- A proxy from another Runfree build is replaced before a policy command
  publishes to it, instead of being handed a policy it might misread.
- `runfree up` starts after `runfree stop` instead of refusing.
- `runfree destroy` removes the session volumes that `docker compose down -v`
  left behind.
- An interrupted session teardown is finished at the next start, once Docker
  proves its state.
- The default agent command rejects unknown flags.
- The `runfree init` wizard groups its review notes per item.
- Credential sync refuses a short or unreadable proxy token write, never
  shares a provider read across accounts, and never removes a token after its
  write client was killed.

## Breaking changes

`runfree mcp approve` is removed. `runfree mcp enable` approves the same
project entries with the same credential flags, and also applies the change to
a running proxy:

```bash
runfree mcp enable claude my-server --source project
```

## Upgrade notes

- **Desired policy version 3.** Runfree writes `.runfree/network-policy.json`
  as version 3 only when it uses a `basic` scheme, a `username`, a `protocol`
  scope, or two destinations for one host and header. Enabling the current
  `github` or `gitlab` service does this. Runfree 0.5.x refuses a version 3
  file with `version must be 2`, so upgrade everyone who shares the project
  before you commit one. A file that needs none of these stays version 2 with
  the same bytes.
- **Committed host services.** Runfree 0.5.x also refuses a desired policy
  with a `hostServices` entry. `runfree host-service add --local` keeps the
  entry in the checkout-local layer, out of the committed file.
- **Git mediation needs the new service revision.** An existing `github` or
  `gitlab` service keeps its old revision, and git requests get no credential.
  Run `runfree service diff --apply`.
- **Bitbucket LFS downloads now wait for approval** under `ask`, public ones
  included.
- **One new MCP OAuth login.** The first start after the upgrade creates the
  record of cleared MCP OAuth state, so each MCP OAuth server needs one new
  login.
- **Image rebuild.** The agent image inputs changed, so the first start
  rebuilds the image and is slow.
