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
.runfree/.gitignore
.runfree/runfree.json
.runfree/network-policy.json
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
| `runfree resume` | Pick and resume interrupted Claude, Codex, or Pi work for the current project. |
| `runfree resume --list` / `--json` | Inspect the current project's bounded recovery inventory offline without contacting Docker. |
| `runfree resume --all` | Include interrupted work from every Runfree project; composes with `--list` or `--json`. |
| `runfree resume --agent <agent>` | Include only one agent ID such as `claude`, `codex`, or `pi`; repeat the option to select a union. |
| `runfree status` | List containers, desired/effective runtime component identities and upgrade action, audit state, and the proxy's session files with, for each, either `served until <aliveUntil>` or `on disk, not served (<reason>)`. With approved [host services](#host-services), it also lists each one with its current listener and the host-service gateway state, and warns about drift. |
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

### Resume

Bare `runfree resume`, on a terminal (stdin and stdout both TTYs), scans only
the current project. One strong terminal match to a Claude or Pi record
carrying an exact conversation id the host recorded when it started or
resumed that session asks one question, default "Resume it":

```text
◆ Interrupted in this terminal (14:02, 6 min ago):
│  "refactor proxy denial messages" — claude
│  ● Resume it
│  ○ Not now
│  ○ Forget it (don't ask again)
```

"Not now" leaves the record for the next `runfree resume`; "Forget it"
discards it immediately.

Any other case shows a picker instead — strong terminal matches first, then
weak matches, then the rest, newest first. Choosing a row asks "Resume it" /
"Forget it" / "Back", so any row can be forgotten, not only a strong match.
`--all` and `--project` show their own labelled picker, each row prefixed
with its project name; it only resumes a row or returns to the list, and
never asks the one question.

Without a TTY, or with `--list`, `runfree resume` only prints the inventory
table; `--json` is unchanged. Records from before this feature, with no
record version, are hidden from the one question and the picker, but still
listed by `--list`.

`runfree claude`, `runfree codex`, and `runfree pi` never scan for
interrupted work and never ask: they always start a fresh session. Resuming
only ever happens through `runfree resume`. See [Interrupted Session
Recovery](architecture.md#interrupted-session-recovery).

## Network Policy

Runfree policy is exact-host based. There are no wildcard hosts.

`.runfree/network-policy.json` is writable desired policy, version 2 or 3.
Runfree writes version 3 only when the content needs it: a credential
destination with the `basic` scheme, a `username`, or a `protocol` scope, or
two destinations for one host and header within the direct `tokens` or within
one service entry. A file that uses
none of these stays version 2, with the same bytes and digest as before. A
file that declares version 2 but uses one of these is refused, and the error
names the fields. Runfree releases before version 3 existed refuse a version 3
file with `version must be 2`. Editing the file does
not change a running proxy or authorize the next start. Runfree captures it
while project agents are quiesced, compares it with host-owned approvals, and
compiles an immutable effective policy generation only after exact approval.

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

## Host Services

```bash
runfree host-service add <name> --port <port>
runfree host-service add <name> --port <port> --local
runfree host-service remove <name>
runfree host-service list
runfree host-service list --repair
```

A host service lets the agent reach a TCP service that runs on the host's
loopback (`127.0.0.1:<port>`): a local dev server, a database, a model server,
a device or simulator bridge, or any other service you run on the host. Clients
in the agent use it unmodified at `127.0.0.1:<port>`, even when they ignore
proxy settings.

1. Start the service on the host. It must listen on `127.0.0.1:<port>` or
   `*:<port>`.
2. Approve it for the project:

   ```bash
   runfree host-service add <name> --port <port>
   ```

3. Start a new session. Inside it, point the client at `127.0.0.1:<port>`.

For example, with a dev server on the host at `127.0.0.1:3000`:

```bash
runfree host-service add devserver --port 3000
runfree claude
# inside the session
curl http://127.0.0.1:3000/
```

Install the client tool in the agent the usual way: allow its package hosts
with `runfree host add`, or build it into the project image
(`.runfree/image/Dockerfile`).

### Host service examples

**iOS Simulator with `idb`.** Run `idb_companion` on the Mac and drive it
from the unmodified `idb` client in the agent:

```bash
# on the host
xcrun simctl list devices booted                 # find the simulator UDID
idb_companion --udid <UDID> --grpc-port 10882
runfree host-service add idb --port 10882
```

```bash
# inside a new session (the agent needs the fb-idb client installed)
idb connect 127.0.0.1 10882
idb list-targets
idb screenshot screen.png
```

`idb_companion` gives full simulator control: install, launch, UI actions,
and file push and pull. Approving it gives every session in the project that
control.

**A database on the host.** A database installed natively on the host (not in
a Docker container, whose published port `add` refuses) works the same way:

```bash
runfree host-service add postgres --port 5432
# inside a new session
psql -h 127.0.0.1 -p 5432 -U <user> <database>
```

- `add` writes a `hostServices` entry to the desired policy (`--local` for the
  checkout-local layer) and approves it. The name matches
  `[a-z][a-z0-9-]{0,62}`; the agent-facing name is
  `<name>.runfree.internal`, which the agent never needs to use.
- Before any policy write, `add` refuses these ports: 2375 and 2376 (Docker
  Engine), 3128, 5901 (Runfree's VNC default), and 47100–48099 (Runfree's MCP
  callback block). It then runs `lsof` and refuses a port with no visible
  listener or with any listener owned by Docker Desktop (`com.docker.*`, a
  published container port). The output names the process and pid you
  approved.
- Each new session starts a relay on `127.0.0.1:<port>` inside the session
  for each approved service. A service added while a session runs appears in
  the next session. `remove` cuts open connections at once in every session.
- `list` prints the effective host services and who listens on each port now.
  `runfree status` repeats that check and warns when the listener is gone,
  changed, or owned by Docker Desktop. It also prints the gateway state:
  `host-service gateway: <ip>`, `host-service gateway: unavailable (<reason>)`,
  `host-service gateway: unknown (proxy not running)` with no warning when the
  proxy is stopped, or `host-service gateway: unknown` with a warning when the
  proxy's gateway status cannot be read or is malformed. These lines never change the exit code.
- An approved port is recorded in a host-global registry. `runfree forward`
  and `runfree vnc` in any other project refuse it and name every owning
  project; several projects may approve the same port. If the registry is
  corrupt, they refuse until `runfree host-service list --repair` rebuilds it.
  The repair refuses, writes nothing, and exits non-zero when a known
  project's state cannot be read; it names that project.
- The tunnel is opaque: no request rules, write approval, or credential
  injection apply, and the host service's own authentication is the only
  check on what the agent does there. Access is per project. See
  [Residual Risks](security.md#residual-risks).
- If the host gateway address changes while the proxy runs, the proxy cuts
  open host-service connections and new ones refuse. `runfree status` then
  shows `host-service gateway: unavailable (... gateway address changed ...)`,
  and `runfree logs proxy` shows the refusals and the cut. Host services stay
  refused until `runfree rebuild`, which recreates the proxy and ends every
  session.

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
| `--scheme bearer|raw` | `credential add`, `credential link` | Prefix with `Bearer ` or inject raw value. `--scheme basic` is refused before any policy write: the `basic` scheme needs a username and is available only through [service definitions](#user-defined-services). |
| `--path-prefix /path/` | credential destination | Inject only for matching request paths. |
| `--refresh-every 15m` | `credential set-source`, `credential add` | Re-resolve source on an interval. |
| `--from-env`, `--from-1password`, `--from-source`, `--from-stdin` | credential source binding | Choose one credential source. |

The CLI selects a destination by host and header only. When a credential
already has a destination on that host and header with a different scope
(path prefix or protocol), `credential add` and `credential link` refuse
rather than report it unchanged. `credential unlink` refuses when more than
one destination of the credential matches. Each refusal names the matching
destinations and writes no policy. To change one of several destinations,
edit `.runfree/network-policy.json`, then approve it with `runfree policy approve --project`.

Credential commands never widen network policy. Use `service enable` or `mcp enable` when you want a reviewed composite workflow that manages hosts and credentials together.

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

### Service revisions

An enabled entry keeps the revision it was enabled with. A newer Runfree
release does not upgrade it and does not warn. `runfree service diff` prints
`<id> (<layer>): revision <old> -> <new>` with the resolved semantics before
and after, and `runfree service diff --apply` writes the new entries:

```bash
runfree service diff
runfree service diff --apply
```

`--apply` keeps each entry's recorded selection: skipped hosts and write mode.
Re-running `runfree service enable <id>` also writes the current revision, but
it builds the entry only from that run's flags, so an earlier `--skip-broad`,
`--skip-host`, `--read-only`, or `--allow-write` is lost unless you repeat it.

Revision changes in this version:

| Service | Revision | Change |
| --- | --- | --- |
| `github` | 2 -> 3 | Adds the `github` token as `Authorization: Basic` (username `x-access-token`) on `github.com`, only on git smart-HTTP requests (`protocol: "git-http"`) and Git LFS requests (`protocol: "git-lfs"`) (see [Git over HTTPS and SSH remotes](#git-over-https-and-ssh-remotes)). Other `github.com` paths, including the web UI, get no credential, and an `Authorization` header the agent sends to `github.com` is now removed or replaced. |
| `gitlab` | 1 -> 2 | Adds the `gitlab` token as `Authorization: Basic` (username `oauth2`) on `gitlab.com` git smart-HTTP requests (`protocol: "git-http"`), beside the existing Bearer destination on `/api/`. Git LFS is not mediated on `gitlab.com`: LFS requests get no credential, and an LFS batch request is a write. With no token stored, `gitlab.com` requests now go out anonymously instead of being refused. |

Both new revisions use the `basic` scheme and a `protocol` scope, so applying
either one makes `.runfree/network-policy.json` desired policy version 3.
Everyone who reads that file needs a Runfree release that accepts version 3;
older releases refuse it with `version must be 2`.

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

The optional `credential` object has `tokenDescription`, `agentEnv` (the
placeholder env names), and `credentials`, a non-empty list of destinations.
Each destination has these fields:

| Field | Required | Rule |
| --- | --- | --- |
| `host` | yes | Exact normalized hostname; one of the service's hosts. |
| `header` | yes | Header the proxy injects. |
| `scheme` | yes | `bearer` (`Bearer <token>`), `raw` (the token as is), or `basic` (`Basic base64(<username>:<token>)`). |
| `username` | with `basic` only | Required with `basic` and refused with any other scheme. 1 to 64 printable ASCII characters, with no space, control character, or `:`. It is policy data, not a secret. |
| `pathPrefix` | no | Inject only on matching request paths. |
| `protocol` | no | `git-http`: inject only on the git smart-HTTP requests (ref discovery, fetch, push) listed in [Git over HTTPS and SSH remotes](#git-over-https-and-ssh-remotes). `git-lfs`: inject only on the Git LFS batch and lock requests listed there. With a `pathPrefix` too, the request must match both. |

On one host and header, at most one destination may have each `protocol`, and
no two destinations may have the same `protocol` and `pathPrefix`. No request
is both a `git-http` and a `git-lfs` request, so at most one `protocol`
destination per header matches a request. The proxy chooses among a host's
destinations per host, not per header: when any `protocol` destination of the
host matches the request, only `protocol` destinations are used, and a
destination without `protocol` is not injected on that request, even on
another header. Otherwise the longest matching `pathPrefix` wins, as before. A
definition that breaks a rule is refused before anything is written. Enabling
a service whose destinations use `basic`, `username`, or `protocol` makes the
desired policy version 3.

A `git-lfs` destination also opts its host into Git LFS mediation: on a host
with a git handling rule, a Git LFS batch request whose body proves it is a
download is a read only when a `git-lfs` destination of that host matches it
(its `pathPrefix`, if any, covers the request path). Use it only for an LFS
server whose batch responses do not hand back a credential broader than one
object transfer (see [security.md](security.md#git-over-https)).

A host with a git handling rule but no matching `git-lfs` destination gets no
LFS read rule: every Git LFS batch request there, a download included, is a
write and waits for approval under `ask`. This applies to `bitbucket.org`
under the `bitbucket` service (its LFS downloads, public ones included, now
wait for approval), to `gitlab.com`, and to any host you give a git rule by
hand, such as with `runfree host rules <host> --deny-git-push`.

These fields let a host with no curated service, such as GitHub Enterprise
Server or self-hosted GitLab, get a git credential. One limitation: a
user-defined service cannot declare git handling for its hosts (the `gitPush`
rule that curated `github` and `gitlab` carry). On such a host every git fetch
(`POST …/git-upload-pack`) and every Git LFS batch request is a write by
method, so under the default `ask` posture each one waits for approval, and a
push is a plain write rather than a git push. The SSH remote rewriting below
covers only `github.com` and `gitlab.com`.

### Git over HTTPS and SSH remotes

With the `github` or `gitlab` service enabled at its current revision and a
token bound, `git clone`, `fetch`, `pull`, and `push` over HTTPS work in the
sandbox. Git sends no credential of its own; the proxy adds the token as HTTP
Basic auth (username `x-access-token` on `github.com`, `oauth2` on
`gitlab.com`). The token never enters the container.

The proxy attaches it only to these requests, where `…` is at least one
repository path segment:

| Request | Method | Path ends with | `protocol` |
| --- | --- | --- | --- |
| Ref discovery | `GET` | `/info/refs`, with exactly one `service=git-upload-pack` or `service=git-receive-pack` query parameter | `git-http` |
| Fetch | `POST` | `/git-upload-pack` | `git-http` |
| Push | `POST` | `/git-receive-pack` | `git-http` |
| Git LFS batch | `POST` | `/info/lfs/objects/batch` | `git-lfs` |
| Git LFS locks | `GET`, `POST` | `/info/lfs/locks` (`GET` or `POST`), `/info/lfs/locks/verify`, `/info/lfs/locks/<id>/unlock` (`POST`) | `git-lfs` |

The `github` service has both a `git-http` and a `git-lfs` destination on
`github.com`. The `gitlab` service has only `git-http` on `gitlab.com`, so Git
LFS is not mediated there in this release: LFS requests to `gitlab.com` get no
credential, and every LFS batch request, a download included, is a write that
waits for approval under `ask`. GitLab answers an authenticated batch request
with a project-wide LFS token that can push, so the agent must not get one
without your approval. A private GitLab LFS fetch therefore fails.

Methods must match exactly, and the raw path and its decoded form must both
end with the same plain endpoint. An encoded, `;param`, trailing `/` or `.`,
or otherwise ambiguous spelling gets no credential. These are not git requests
either, and get no credential:

- a `POST` endpoint with a query string (only the `GET` lock listing takes
  one);
- a ref discovery query that contains a `;`;
- a path whose first segment is `api` (in any case or encoding, and with any
  dots or whitespace around it), including a `github.com` owner named `api`;
- a path with a segment that starts with whitespace, such as `%20repo`;
- a path with a segment that is exactly `-`, such as GitLab's `/-/` routes.

Any other path on the host gets no credential either.

Write approval applies as before. A fetch is a read. A push is a git push
write: under the default `ask` posture it waits for `runfree approve`, and
once approved it goes out with your token. A ref discovery request that names
`service=git-receive-pack` in any case or encoding, or whose query contains a
`;`, counts as a push. To refuse pushes outright:

```bash
runfree host rules github.com --deny-git-push
```

On `github.com`, a Git LFS batch request whose body proves it is a download is
a read; an upload batch and every `POST` lock request are writes. The `GET`
lock listing is a read, and on `github.com` it carries the `git-lfs`
credential. On `gitlab.com`, `bitbucket.org`, and every other host without a
matching `git-lfs` destination, every LFS batch request is a write. The proof
rules are in [security.md](security.md#git-over-https).

#### SSH remotes

The sandbox's global Git config, `/home/agent/.gitconfig`, is written by the
host and mounted read-only. It rewrites exactly these remote prefixes to
HTTPS:

| Remote prefix | Rewritten to |
| --- | --- |
| `git@github.com:` | `https://github.com/` |
| `ssh://git@github.com/` | `https://github.com/` |
| `ssh://git@github.com:22/` | `https://github.com/` |
| `ssh://git@ssh.github.com:443/` | `https://github.com/` |
| `git@gitlab.com:` | `https://gitlab.com/` |
| `ssh://git@gitlab.com/` | `https://gitlab.com/` |
| `ssh://git@gitlab.com:22/` | `https://gitlab.com/` |

- The rewrite is always present, whether or not the service is enabled. A
  rewritten remote on a host that is not allowed fails with the proxy's
  denial for that host, not an SSH connection error.
- It is routing, not enforcement. The agent can undo it with `git -c`,
  `GIT_CONFIG_*` variables, or repository config, and gains nothing: SSH has
  no route out of the sandbox either way.
- Your repository's `.git/config` is not changed; it keeps the SSH URL, and
  host Git never reads the sandbox config. Inside the sandbox, `git remote -v`
  shows the HTTPS URL, and an explicit `pushurl` and submodule URLs with these
  prefixes are rewritten too.
- Git uses the longest matching `insteadOf` prefix across all config files,
  so a repository `insteadOf` overrides these only when its prefix is longer.
- Other SSH forms are not rewritten and fail, because the sandbox has no SSH
  egress: host aliases from your `~/.ssh/config` (for example
  `git@github.com-work:`), other users or ports, and other hosts such as
  GitHub Enterprise Server or self-hosted GitLab. Use an HTTPS remote for
  those.

#### Git failure modes

| Condition | What happens |
| --- | --- |
| No `github` or `gitlab` token stored | The request goes out anonymously, with any agent `Authorization` removed. Public fetches work; private fetches and pushes get 401 from the provider. |
| Token expired or revoked | 401 from the provider. Refresh the source, then run `runfree credential sync`. |
| Token cannot reach the repository | 403 or 404 from the provider. |
| Push refused by policy or approval | The proxy refuses with `git-push-denied`, `write-denied`, or a `write-approval-*` reason, before any upstream connection or token read. |
| Path the proxy cannot read unambiguously | No credential is attached; write classification is unchanged. |
| Agent points a remote back at SSH | The connection fails; the sandbox has no SSH egress. |
| Service enabled at an older revision | Git requests carry no proxy credential, so private fetches and pushes get 401. Run `runfree service diff --apply`. |

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
runfree mcp enable claude my-server
runfree mcp enable claude my-server --no-discover --oauth-host auth.example.com --no-login
runfree mcp enable claude my-server --from-source op-token
runfree mcp auth claude my-server
runfree mcp rules claude my-server
runfree mcp rules claude my-server --tool create_issue --write ask
runfree mcp revoke claude my-server
runfree mcp revoke claude my-server --source user
```

Agent IDs are `claude` (Claude Code) and `codex` (Codex CLI). MCP actions keep the
agent as the first positional argument. The optional `configure --agent <id>`
filter is repeatable; omit it to include both agents.

Project `.mcp.json` and `.codex/config.toml` entries are imported only after approval. Static headers require a host-owned credential source.

A server name must be one that the agent's own `mcp add` accepts: letters,
numbers, `-`, and `_` for Claude, plus `:`, `@`, `/`, and `.` for Codex. It
must be at most 128 characters and must not be `__proto__`. `runfree mcp list`
shows a server with any other name as `unsupported`, and the server is skipped
with a warning. Names that differ only by case, or that map to the same
Runfree ID, are skipped together. If one of them is a user or local server,
that server stays and only the project entries are skipped (`conflict`).

Local STDIO servers run inside the agent container, never on the host. A
command that is a host path is skipped with a warning. The Codex Desktop
built-ins `node_repl` and `computer-use` are skipped silently: `runfree mcp
list` shows them as `skipped`, and `--verbose` prints one line for each. See
[Codex Desktop built-ins](architecture.md#codex-desktop-built-ins).

Loopback HTTP MCP servers, such as a dev server's
`{"type": "http", "url": "http://127.0.0.1:8089/mcp"}`, import without
credentials. Use `127.0.0.1`, not `localhost`. Inside the session the URL
reaches only a process in the session, unless a host service holds the port.
To reach a dev server on the host, approve the port separately:

```bash
runfree host-service add astro --port 8089
```

`runfree mcp enable` and `runfree mcp explain` show the reach, and a launch
warns when no host service backs the port. A loopback entry cannot carry
headers, helpers, or OAuth settings, and its tool calls do not pass the proxy,
so write approval and `runfree mcp rules` do not apply. Plain HTTP to any other
host is refused. An HTTPS server URL, OAuth metadata URL, or OAuth token
endpoint must name a hostname, not an IP address, and an OAuth metadata URL or
token endpoint must itself use `https:`.
`runfree mcp list` shows a refused entry as `unsupported`, target `excluded`.

OAuth login works in any session. When an approved MCP server can use OAuth,
each `runfree claude`, `codex`, `pi`, or `shell` session gets its own loopback
callback port. In Claude, type `/mcp` and select the server; in Codex or a
shell, run `codex mcp login <server>`. Then open the URL the client prints.
Two sessions can log in at the same time. `runfree mcp auth` launches a session
and prints these steps. A provider that accepts only one pre-registered
callback port works only while its session holds the project's first port.

### Enable an MCP server in one step

`runfree mcp enable <agent> <server>` shows one review and asks once. The
review lists every change:

- the project approval (project entries);
- the credential source (static-header entries; `--from-env`,
  `--from-1password`, `--from-source`, or `--from-stdin`);
- the MCP endpoint host;
- each OAuth host, with where it came from: `discovered` (and the metadata
  that named it) or `--oauth-host`.

After you accept, Runfree saves the changes, applies them to a running proxy,
and then runs the OAuth login (`runfree mcp auth`) for OAuth servers. Pass
`--no-login` to skip the login.

To find the OAuth hosts, Runfree reads the server's OAuth metadata from this
computer: RFC 9728 protected-resource metadata on the MCP endpoint host, then
RFC 8414 authorization-server metadata or OpenID configuration from each
authorization server it names. The requests are plain HTTPS GETs with no
credentials, no cookies, no proxy, and no redirects. They go only to public
addresses, with strict time and size limits. For a project entry, Runfree
first asks before it contacts the host that the project file names.

Discovery adds a host only when valid metadata names a token endpoint that the
proxy mediates for this server. When nothing else allows it, a host found by
discovery is limited to GET, HEAD, OPTIONS, and POST on paths that start with
`/.well-known` or one of its OAuth endpoint paths. The
proxy mediates those endpoints, so the agent sees only `runfree_oauth_*`
handles. The browser sign-in page opens on your computer and is never
allowlisted.

Login and refresh do not wait for write approval. On an `ask` host, a POST to
exactly one of the token or registration endpoints that discovery recorded for
this server is an OAuth protocol read, but only while the proxy mediates that
endpoint for this server alone. The body must be a plain login or refresh
(`authorization_code` or `refresh_token` form grant, a `client_id` that is not
a URL, and a `resource` only for the server itself), or a client registration
whose redirect URIs are loopback `http` URLs only, with no other URL field. Any
other method, path (sub-paths too), query, body, an endpoint that another
server also uses, and an `--oauth-host` host with no recorded endpoint follow
the project's write approval setting. A host set to `deny` stays denied. Each
server gets at most 30 such reads a minute; after that, they need approval.

| Option | Meaning |
| --- | --- |
| `--source user\|local\|project` | Choose the entry when more than one matches. User and local entries need no approval; `enable` records only their OAuth hosts. |
| `--oauth-host <host>` | Also allow this exact host for the server (repeatable). It is allowed as given, like `runfree host add`. |
| `--no-discover` | Make no network call. Use only `--oauth-host` hosts. |
| `--no-login` | Do not run the OAuth login after enabling. |
| `--from-env`, `--from-1password`, `--from-source`, `--from-stdin` | Bind a project entry's static header to a host-owned credential source. Choose one. |
| `--replace-source` | Replace an existing credential source for this server. |

Discovery needs a terminal. Without one, `mcp enable` refuses before any DNS
lookup unless you pass `--no-discover`; then the command line names every
change and is itself the approval.

OAuth hosts are not written to `.runfree/network-policy.json`. They are
host-owned records bound to the reviewed server config: if a project entry
changes, or a user entry is deleted, its hosts stop applying. `runfree mcp
revoke <agent> <server>` removes exactly the hosts that `enable` added. A host
that desired policy, a service, or another enabled MCP server also names stays
allowed. `runfree mcp explain` lists the recorded hosts and endpoints.

`runfree mcp revoke` also clears the proxy's OAuth state for the server: its
tokens, its `runfree_oauth_*` handles, and the issuers and endpoints the proxy
found at run time. It does this for every source of that agent and server
name, including user and local entries. A later `mcp enable` needs a new
login. Revoke prints one of these lines:

| Line | Meaning |
| --- | --- |
| `proxy OAuth state for <agent> <server>: cleared (...)` | The running proxy confirmed that it applied the policy that clears the state. |
| `...: not cleared yet; the proxy clears it when it next starts ...` | No proxy runs now. The clear is saved and happens at the next start. |
| `...: not proven cleared; ...` | A proxy runs, but it did not confirm the clear (for example, it is from an older Runfree version). It happens when the proxy next starts on this version. |

If Runfree finds its record of cleared servers damaged or missing, it clears
the OAuth state of every MCP server, and each server needs a new login. A
damaged record also prints a warning. The first start after an upgrade to a
version with this feature creates the record, so each MCP OAuth server needs
one new login then.

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

Runfree detects host Git's worktree capability by checking whether
`git worktree add -h` and `git worktree repair -h` both advertise
`--relative-paths` (Git 2.48+); the version named in messages below comes
from `git --version`, or `unknown` when that fails.

Sandbox Git defaults to relative worktree links, with an environment setting
that takes precedence over repository includes and per-worktree config.
Explicit Git command-line options can still override it. Create worktrees inside the
mounted project, for example `.worktrees/feature`, so both environments can
reach them. On the host, use `git worktree add --relative-paths`, or set
`git config --local worktree.useRelativePaths true` once for the repository.

On host Git older than 2.48, launching a normal repository or a non-Git
project continues with a warning, because sandbox Git still defaults to
relative links and a worktree created inside the sandbox would otherwise make
the repository unreadable to host Git:

`host Git <version> is older than 2.48: Git worktrees created inside the sandbox will make this repository unreadable to host Git; upgrade host Git (Ubuntu: sudo add-apt-repository ppa:git-core/ppa && sudo apt install git)`

When the main checkout's Git config already sets
`extensions.relativeWorktrees = true`, host Git older than 2.48 already
cannot read the repository, so the warning says so instead:

`host Git <version> is older than 2.48 and cannot read this repository, which uses relative worktree links; upgrade host Git (Ubuntu: sudo add-apt-repository ppa:git-core/ppa && sudo apt install git)`

When `git --version` fails, for example because Git is not installed,
launching a non-Git project continues with this warning instead:

`host Git not found: Git worktrees created inside the sandbox will make this repository unreadable to host Git older than 2.48; install Git 2.48 or newer`

Each launch prints at most one of these three warnings.

Runfree reads a Git repository's config through Git to check its worktree
layout. So when `git --version` fails and the project has a `.git` entry,
launch refuses before writing any state:

`host Git not found: Runfree needs Git to check this repository's worktree layout; install Git 2.48 or newer`

When launched from the main checkout, Runfree also checks registered nested
worktrees before starting the runtime. An unsupported layout — absolute
links, including a stale `/workspace` link from a sandbox — stops startup. On
host Git 2.48+ it shows the repair command to run on the host from the main
checkout, which also sets the repository's relative-path default. On older
host Git, that check instead refuses before writing any state, since the
repair itself needs 2.48+:

`this Git worktree layout requires host Git >= 2.48 (found <version>); remove or move the nested worktree (e.g. git worktree remove <path>), or upgrade Git`

Launching directly from a linked worktree on older host Git refuses the same
way, naming the main checkout instead, since running from there is itself a
fix:

`this Git worktree layout requires host Git >= 2.48 (found <version>); run runfree from the main checkout, or upgrade Git`

Host-only worktrees outside the mounted project are outside this check.

Commands that write checkout-local policy, such as `runfree init`, refuse
with the same linked-worktree message on older host Git when run from a
linked worktree. Without host Git, they refuse in any Git repository with
the missing-Git message above. Both refusals come before Runfree asks Git
whether that policy file is tracked, and before it writes the Git exclude
file.

Revalidating a running runtime (a launch that reuses it, or a proxy restart)
and dependency overlay planning can find a Git layout that became unsupported
after the runtime started. On host Git 2.48+ that refusal shows the repair
commands, as above. On older host Git it shows the matching version
requirement message above instead, because the repair needs 2.48+.

`runfree git repair-worktree-links` itself refuses the same way on host Git
older than 2.48:

`repairing worktree links requires host Git >= 2.48 (found <version>); upgrade Git`

Upgrading host Git recovers from any of these refusals; removing or moving
the nested worktree also recovers the main-checkout refusal above. `runfree
status` always prints host Git's version and worktree capability:

`host git: <version> (worktrees: enabled|disabled)`

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
