# CLI Reference

Runfree commands are host-side controls for a per-project sandboxed agent runtime.

```bash
runfree [--workspace <project-dir>] [claude|codex|pi]
runfree [--workspace <project-dir>] <command> [args...]
```

Use `runfree help` for generated help from the current binary, and `runfree <command> --help` for exact command options.

## Global Options

| Option | Use |
| --- | --- |
| `--workspace <project-dir>` | Target a project directory other than the current directory. Put it before the command. |
| `--quiet` | Suppress the session-end blocked-host summary for runtime/agent commands. |
| `--verbose`, `-v` | Print extra startup diagnostics for runtime/agent commands, the full `status` diagnosis, and the stack trace of an unexpected error. Every command accepts it. |
| `-h`, `--help`, `help` | Show help. |

## Output Conventions

Runfree separates results from diagnostics by stream and by prefix, so a
script can capture one without the other and an operator can tell a refusal
from a crash at a glance.

| Output | Stream | Shape |
| --- | --- | --- |
| Command result or report | stdout | Unprefixed. The only thing a command writes to stdout. |
| Progress and information | stderr | `runfree: <message>` |
| Warning | stderr | `runfree warning: <message>` |
| Refusal or failure | stderr | `runfree error: <message>`, exit status 1 (or the status the refusal names). No stack trace. |
| Unexpected error | stderr | `runfree error: <name>: <message>` plus the causes; the stack trace prints only with `--verbose`. |
| Interactive prompt | terminal | Never written when stdin or stderr is not a terminal. |

A multi-line diagnostic prefixes its first line and indents the rest by two
spaces. When stderr is not a terminal, every line carries an ISO timestamp;
`RUNFREE_LOG_TIMESTAMPS=1` or `=0` overrides that choice. Warnings observed
during a command print before the command's result or its final error, with
the time they were observed. Ctrl-C and SIGTERM restore the terminal and exit
130 or 143.

`RUNFREE_TIMINGS=1` adds `timing:` lines on stderr: one per lifecycle phase,
and one `startup-ops` line per subprocess category with its count and total
time. A category is the command name plus, for Docker, its subcommand; never
arguments, ids, or output. See
[`troubleshooting.md`](troubleshooting.md#startup-is-slow).

A failure's last line states what did not happen in your nouns ("claude did
not start", "nothing was destroyed"). A next step is always a complete
`runfree ...` command you can paste; a widening suggestion for a host rule
reproduces the host's whole current rule, because `runfree host rules` with
any rule flag replaces the rule rather than adding to it. A policy change made
before the runtime is started reports `effective policy: saved; applies when
the runtime starts` and exits 0.

## First Run

```bash
cd ~/code/my-project
runfree init
runfree
```

On a TTY, `runfree init` opens a short wizard. It detects common project manifests, Git remotes, and host credential helpers, then offers a reviewable policy/source plan. Non-TTY `init` and `init --yes` scaffold only.

The scaffold is desired policy only. The first runtime start reviews exact
project, checkout-local, runtime-isolation, and optional image subjects before
publishing host-owned effective controls. A non-interactive start that needs
new authority fails with exact `policy approve`/`control approve` commands.

Created project files include:

```text
.runfree/runfree.json
.runfree/network-policy.json
.runfree/config/
```

## Agent Runtime

| Command | Purpose |
| --- | --- |
| `runfree` | Start or reuse the sandbox and run the configured default agent. |
| `runfree claude` | Run Claude Code in the sandbox. |
| `runfree codex` | Run Codex in the sandbox. |
| `runfree pi` | Run Pi in the sandbox. |
| `runfree shell` | Open a zsh shell in the agent container. |
| `runfree up` | Start or reuse the Docker Compose runtime without attaching an agent. |
| `runfree rebuild [--yes]` | Rebuild/recreate the runtime. Confirms before killing active sessions unless `--yes` is used. |
| `runfree stop [--force]` | Stop this project's services. Requires `--force` while live or unprovable session owners remain, while a control-plane rebind is pending, or while any session is mid-teardown. |
| `runfree destroy [--force]` | Destroy the whole project runtime: delete this project's session files from the proxy, remove session containers by their lifecycle records, run the Compose teardown (volumes, local images, orphans), then clear the lifecycle records. Without `--force` it refuses whenever ending work or losing state is possible: live sessions, running project containers no record or Compose claims, quarantined unreadable lifecycle records, an unreadable control-plane rebind journal, or a registry that cannot be enumerated. |
| `runfree sessions` | List active sessions plus interrupted or unverified recovery evidence for this project. The CONTAINER TTY column reports each session's heartbeat: `attached, served until <aliveUntil>`, or `attached, NOT served since <lastHeartbeatAt> (heartbeat retrying)`. It also compares the proxy's session files with this project's records, without changing either: a session whose owning host process can be proved neither alive nor dead is named, with `runfree destroy --force` as the remedy, and session files no record claims are named with `runfree up` as the remedy. |
| `runfree resume` | Pick and resume interrupted Claude or Codex work for the current project. |
| `runfree resume --list` / `--json` | Inspect the current project's bounded recovery inventory offline without contacting Docker. |
| `runfree resume --all` | Include interrupted work from every Runfree project; composes with `--list` or `--json`. |
| `runfree resume --agent <agent>` | Include only one agent ID such as `claude` or `codex`; repeat the option to select a union. |
| `runfree status` | List containers, desired/effective runtime component identities and upgrade action, audit state, and the proxy's session files with, for each, either `served until <aliveUntil>` or `on disk, not served (<reason>)`. |
| `runfree resources` | List Runfree Docker resources for this project. |
| `runfree logs proxy` | Follow proxy logs. Use `--verbose` for sanitized allowed request metadata. |
| `runfree runtime reload-policy [--force]` | Reload runtime policy and sync proxy-managed tokens. Refuses under the same conditions as `runfree stop` unless `--force` is given; a restarted proxy republishes session eligibility and the per-session heartbeats refill its session files. |
| `runfree project-id` | Print the stable project id. |
| `runfree project-id --compose-name` | Print the Docker Compose project name. |

Runtime examples:

```bash
runfree --verbose
runfree shell
runfree resume --list
runfree resume --all
runfree resume --agent codex
runfree logs proxy --verbose
runfree runtime reload-policy
runfree rebuild --yes
```

## Network Policy

Runfree policy is exact-host based. There are no wildcard hosts.

`.runfree/network-policy.json` is writable desired policy v2. Editing it does
not change a running proxy or authorize the next start. Runfree captures it
while project agents are quiesced, compares it with host-owned approvals, and
compiles an immutable effective generation only after exact approval.

### Review and activate desired policy

```bash
runfree policy status
runfree policy diff --project
runfree policy diff --local --json
runfree policy review --project
runfree policy explain api.github.com
runfree policy approve --project
runfree policy approve --project --subject-digest sha256:...
runfree control approve runtime-isolation --subject-digest sha256:...
runfree policy use-approved
```

Interactive approval shows the canonical subject before confirmation.
Non-interactive approval requires the full exact subject digest. `--yes`, short
digests, approval-set digests, control-generation digests, and policy-generation
digests are not approval substitutes.

### Manage hosts

```bash
runfree host add <host>
runfree host add <host> --local
runfree host add api.github.com --read-only
runfree host rules api.example.com --method GET --method POST --request-path-prefix /v1/
runfree host rules github.com --deny-git-push
runfree host remove <host>
runfree host list
runfree host explain <host>
runfree host rules <host>
runfree host rules <host> --write allow|ask|deny
runfree host rules <host> --clear
```

`--read-only` is shorthand for `GET`, `HEAD`, and `OPTIONS`. Re-running `host add` or `host rules` with request-rule flags replaces that host's request rules. `host rules --write` sets the action for write-class requests to that host.

`--local` writes the checkout-local ignored desired layer; project scope is the
default. Pre-v4 configs are not migrated: move `.runfree` aside and run
`runfree init` to start a current configuration.

### Audit network discovery

```bash
runfree up --audit-network
runfree up --audit-network=30m
runfree audit status
runfree audit report
runfree audit report --json
runfree audit off
```

Audit mode is for trusted onboarding. It permits and logs non-allowlisted HTTPS hosts for a bounded window, then you explicitly apply only the hosts you trust.

### Diagnose denials

```bash
runfree doctor
runfree doctor --tail 500
runfree doctor --post-failure
```

`doctor` summarizes structured proxy denial events and suggests exact host add or rule-widening commands.

## Credentials

Real credential values should stay host-side or proxy-side. Agent environment variables may contain placeholders only.

### Host-owned sources

A named source is a reusable host-side way to resolve a credential value.

```bash
runfree credential source add github-cli -- gh auth token
runfree credential source add op-token -- op read op://vault/item/credential
runfree credential source add jwt appstore \
  --alg ES256 \
  --private-key-from-1password op://vault/appstore/key \
  --claim iss=ISSUER_ID \
  --ttl 19m
runfree credential source list
runfree credential source show github-cli
runfree credential source remove github-cli
```

Everything after `--` in `credential source add <name> -- <command>` is source command argv, not Runfree options.

### Credential policy and destinations

Allow the destination host explicitly, then configure where the proxy may inject the credential. The persisted policy retains the `tokens` field name for compatibility.

```bash
runfree credential add github --host api.github.com --from-source github-cli
runfree credential link github --host raw.githubusercontent.com
runfree credential unlink github --host raw.githubusercontent.com
runfree credential set-source github --from-env GITHUB_TOKEN
runfree credential set-source github --from-1password op://vault/item/token
runfree credential clear-source github
runfree credential remove github
runfree credential status
runfree credential sync
runfree credential sync --watch
```

Useful options:

| Option | Applies to | Use |
| --- | --- | --- |
| `--header <name>` | `credential add`, `credential link`, `credential unlink` | Header to inject. Default is usually `Authorization`. |
| `--scheme bearer|raw` | `credential add`, `credential link` | Prefix with `Bearer ` or inject raw value. |
| `--path-prefix /path/` | credential destination | Inject only for matching request paths. |
| `--refresh-every 15m` | `credential set-source`, `credential add` | Re-resolve source on an interval. |
| `--from-env`, `--from-1password`, `--from-source`, `--from-stdin` | credential source binding | Choose one credential source. |

Credential commands never widen network policy. Use `service enable` or `mcp approve` when you want a reviewed composite workflow that manages hosts and credentials together.

## Services

Services are complete pinned desired-policy entries for package ecosystems and
providers. An entry records its definition digest, revision, selection, and
resolved hosts/request/token/OAuth semantics in `.runfree/network-policy.json`;
network authority is not stored in `runfree.json`. `runfree claude` and
`runfree codex` review credentialless `agent-claude` and `agent-codex` services
for native login/model traffic; these are separate from credential-bearing
`anthropic` and `openai` API-key services. Pi provider access remains explicit.

```bash
runfree service list
runfree service list --all
runfree service enable node
runfree service enable node --local
runfree service enable python
runfree service enable github --from-source github-cli
runfree service enable openai --from-env OPENAI_API_KEY
runfree service enable apple-ads --from-source apple-ads-jwt --param client-id=SEARCHADS.<uuid>
runfree service explain agent-codex
runfree service explain agent-claude
runfree service disable github
runfree service explain github
runfree service diff
runfree service diff --apply
```

`service list` prints the enabled services with their layer, recorded revision,
and host count. `service list --all` also prints every curated and
user-defined service that is not enabled, with an `ORIGIN` and `STATE` column.

Important enable options:

| Option | Use |
| --- | --- |
| `--from-env`, `--from-1password`, `--from-1password-item`, `--from-source`, `--from-stdin` | Bind a credential-bearing service to a host-owned source. |
| `--param <key>=<value>` | Supply a declared non-secret service parameter (an OAuth client id, an account or team id); repeatable. `service explain <id>` lists a service's parameters. When the flag is absent, the host env var named by the parameter is used, then the value recorded by an earlier enable, then a prompt on a TTY; a `--from-1password-item` enable reads the item field of the same name. A missing or malformed parameter refuses the enable before anything is written. |
| `--replace-source` | Replace an existing source binding. |
| `--skip-broad` | Enable without broad multi-tenant hosts. |
| `--skip-host <host>` | Skip one service host; repeat as needed. A host that receives the service's credential, or that is its OAuth resource host or token endpoint, cannot be skipped. |
| `--read-only` | Stamp read-only/write-deny posture for service hosts. |
| `--allow-write` | Let writes to service hosts proceed without approval. |
| `--local` | Write the checkout-local desired layer instead of the project layer. |
| `--no-reload` | Leave effective controls unchanged after the desired mutation. |

### User-defined services

User-defined service ids use the `user-*` namespace and are not curated by Runfree.

```bash
runfree service custom add user-internal-api --from-file ./internal-api.runfree-service.json
runfree service custom add user-internal-api --from-file ./internal-api.runfree-service.json --replace --yes
runfree service configure user-internal-api
runfree service enable user-internal-api --from-source internal-token
runfree service custom remove user-internal-api
```

A strict JSON user-service definition contains `schemaVersion`, `id`, `label`, `revision`, `hosts`, `explanations`, optional `detect`, optional `credential`, optional `parameters` (declared non-secret inputs: `key`, `envVar`, `description`, optional `pattern` and `example`; supplied with `--param` and projected into the agent env), and optional `neverAutoSuggest`.

## Approve-On-Write

Write-class requests can be held for a host-side decision.

```bash
runfree approvals
runfree approvals --watch
runfree approvals --clear-deny
runfree approve <id>
runfree approve <id> --deny
runfree approve <id> --scope session
runfree approve <id> --scope session --ttl 15m
```

The default approval scope is the single request. Wider scopes are explicit.

Wider scopes are session-specific. A `session` scope grants matching writes to
the requesting session until that session ends; revoking the session's
authority drops the grant. Adding `--ttl` bounds the session grant to the
requested duration, clamped to eight hours. `runfree status` lists live grants
of both signs, with remaining time for time-bounded ones.

`runfree approve <id> --scope deny-session` ("stop asking") denies matching
writes for that session. Session teardown revokes it. A policy edit does not
undo it.

## MCP

Runfree imports supported Claude and Codex MCP config into sanitized per-agent runtime config.

```bash
runfree mcp list
runfree mcp list --json
runfree mcp configure
runfree mcp configure --agent claude
runfree mcp configure --agent claude --agent codex
runfree mcp explain claude my-server
runfree mcp explain claude my-server --source project --json
runfree mcp approve claude my-server --from-source op-token
runfree mcp approve claude my-server --login
runfree mcp auth claude my-server
runfree mcp rules claude my-server
runfree mcp rules claude my-server --tool create_issue --write ask
runfree mcp revoke claude my-server
```

Agent IDs are `claude` (Claude Code) and `codex` (Codex CLI). MCP actions keep the
agent as the first positional argument. The optional `configure --agent <id>`
filter is repeatable; omit it to include both agents.

Project `.mcp.json` and `.codex/config.toml` entries are imported only after approval. Static headers require a host-owned credential source.

## Dependency Overlays

```bash
runfree deps plan
runfree deps install
runfree deps doctor
runfree deps reset --force
```

Dependency overlays install common dependency artifacts inside Runfree-owned Docker volumes instead of host artifact directories.

## Project Agent Image

```bash
runfree image init
$EDITOR .runfree/image/Dockerfile
runfree image approve-context
runfree rebuild
```

Project Dockerfiles extend `RUNFREE_BASE_IMAGE`. Full image overrides are not supported. Wide build contexts require explicit host-state approval.

## Optional Runtime Helpers

### VNC

```bash
runfree vnc
runfree vnc --host-port 5902
runfree vnc --clipboard
runfree vnc status
runfree vnc stop
runfree vnc restart --host-port 5902
```

VNC forwards an agent display to host loopback through a sidecar. The agent image must provide `x11vnc` and an X display. The VNC stream is untrusted input to your viewer.

### Port forwarding

```bash
runfree forward 3000
runfree forward 8080 --agent-port 3000
runfree forward 3000 stop
runfree forward stop
runfree forward status
```

`runfree forward` publishes `127.0.0.1:<port>` on the host to the agent's port
through a labeled ingress forwarder, for previewing a dev server the agent runs
(a web app, a docs site, an API under test). The positional port sets both
sides; `--host-port` and `--agent-port` override each side and are valid only
with `start`. A bare `stop` closes all of this project's port forwards; `stop`
with a port closes that one. The host-facing network is derived from the project
id, so a forward cannot be pointed at a shared bridge.

The forward is host→agent only and never carries egress, so it is not a path
around proxy policy. Two consequences are worth knowing: the splice reaches the
agent's network interface, not its loopback, so a service bound only to
`127.0.0.1` inside the session is unreachable and the forward still reports
success; and content served through the forward renders in your unsandboxed
browser, outside the proxy, so treat it as untrusted output from the agent.

### Runfree inbox

```bash
runfree inbox paste
runfree inbox paste --copy
runfree inbox clean
runfree inbox clean --all
```

On macOS, `inbox paste` imports a clipboard image into Runfree state and prints its read-only `/runfree/inbox/...` container path. `runfree paste-image` remains as a deprecated compatibility alias.

### Git worktrees

```bash
runfree git repair-worktree-links
```

Repairs host Git metadata to use relative worktree links.

Runfree requires host Git with `git worktree --relative-paths` support before
starting a sandbox. This prevents the sandbox from creating repository
metadata that the host Git cannot read.

Sandbox Git defaults to relative worktree links, with an environment setting
that takes precedence over repository includes and per-worktree config.
Explicit Git command-line options can still override it. Create worktrees inside the
mounted project, for example `.worktrees/feature`, so both environments can
reach them. On the host, use `git worktree add --relative-paths`, or set
`git config --local worktree.useRelativePaths true` once for the repository.

When launched from the main checkout, Runfree checks registered nested
worktrees before starting the runtime. Absolute links, including stale
`/workspace` links from a sandbox, stop startup and show the repair command.
Run that command on the host from the main checkout; it also sets the
repository's relative-path default. Host-only worktrees outside the mounted
project are outside this startup check.

## Assets, Updates, And Version

```bash
runfree assets status
runfree assets clean
runfree update
runfree version
```

`runfree update` prints guidance; it does not replace the binary. A patch
release installs over the old executable in place: Homebrew and
`scripts/install.sh` both replace it, and the script refuses on a checksum
mismatch. Stop each project's runtime with `runfree stop` first.

## Uninstalling And Cleaning Up

Removing the binary removes the binary. It does not remove anything Runfree
created, and the things it created are in four separate places.

**1. The binary.**

```bash
brew uninstall runfree
# or, if installed with the script
rm ~/.local/bin/runfree
```

**2. Per-project Docker resources.** Do this *before* removing the binary, from
inside each project, because `destroy` is what knows which resources belong to
that project:

```bash
runfree resources        # what exists for this project
runfree destroy          # stop services, remove volumes, local images, orphans
runfree destroy --force  # also ends live sessions and removes unclaimed residue
```

`destroy` removes this project's dependency overlay volumes. Anything the agent
installed into them is gone with them.

**3. Project files.** `.runfree/` is yours: it is committed policy and config,
and nothing removes it for you. Delete it when you no longer want the project
sandboxed.

**4. Host state outside the repository.** XDG data and state hold materialized
runtime assets, host-owned approvals and effective controls, per-project agent
state, and proxy CA material:

```bash
runfree assets status    # where embedded runtime assets live
runfree assets clean     # remove superseded asset versions
```

Removing a project's state directory (by default
`~/.local/state/runfree/projects/<project-hash>/`) discards its approvals and its
per-project agent state. That includes **native Claude and Codex login state**:
after removing it, those agents log in again from scratch in that project.
Proxy-managed credentials are not stored there — they are resolved from your
host sources each time — so removing state does not lose a token you still hold
elsewhere.

Do not hand-delete XDG runtime materializations while a project still has
lifecycle records or pending transactions referencing them. Use
`runfree destroy` first.

## Common Workflows

### Enable Node and GitHub

```bash
runfree init
runfree credential source add github-cli -- gh auth token
runfree service enable node
runfree service enable github --from-source github-cli
runfree
```

### Discover required hosts safely

```bash
runfree up --audit-network=30m
runfree
runfree audit report
runfree audit off
```

### Add a private API

```bash
runfree credential source add internal-api -- op read op://dev/internal-api/token
runfree host add api.internal.example.com \
  --method GET \
  --method POST \
  --request-path-prefix /v1/
runfree credential add internal-api \
  --host api.internal.example.com \
  --from-source internal-api
```

### Keep writes reviewable

```bash
runfree host rules api.example.com --write ask
runfree approvals --watch
```
