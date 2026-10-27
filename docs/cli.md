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
130 or 143; `runfree run` stops its session first and exits 67 (see
[Headless runs](#headless-runs)).

`RUNFREE_TIMINGS=1` adds `timing:` lines on stderr: one per lifecycle phase,
and one `startup-ops` line per subprocess category with its count and total
time. A category is the command name plus, for Docker, its subcommand; never
arguments, ids, or output. See
[`troubleshooting.md`](troubleshooting.md#startup-is-slow).

A failure's last line states what did not happen in your nouns ("claude did
not start", "nothing was destroyed"). A next step is always a complete
`runfree ...` command you can paste. A widening suggestion for a host rule
repeats the host's whole current rule plus the change, and prints the rule you
get. `runfree host rules` changes only the fields its flags name, but a new
`--method` or `--request-path-prefix` list replaces the old list. A policy
change made before the runtime is started reports `effective policy: saved;
applies when the runtime starts` and exits 0.

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
| `runfree run <agent> --prompt-file <file>` | Run one agent turn without a terminal, for a scheduler or a script. See [Headless runs](#headless-runs). |
| `runfree up` | Start or reuse the Docker Compose runtime without attaching an agent. |
| `runfree rebuild [--yes]` | Rebuild/recreate the runtime. Confirms before killing active sessions unless `--yes` is used. |
| `runfree stop [--force]` | Stop this project's services. Requires `--force` while live or unprovable session owners remain, while a control-plane rebind is pending, or while any session is mid-teardown. |
| `runfree destroy [--force]` | Destroy the whole project runtime: session containers, volumes, local images, and orphans (see [Lifecycle](architecture.md#runtime-lifecycle)). Without `--force` it refuses on live sessions, running project containers no record or Compose claims, quarantined unreadable lifecycle records, an unreadable control-plane rebind journal, or a registry that cannot be enumerated. |
| `runfree sessions` | List active sessions plus interrupted or unverified recovery evidence for this project. The CONTAINER TTY column reports each session's heartbeat: `attached, served until <aliveUntil>`, or `attached, NOT served since <lastHeartbeatAt> (heartbeat retrying)`. It also compares the proxy's session files with this project's records, without changing either: a session whose owning host process can be proved neither alive nor dead is named, with `runfree destroy --force` as the remedy, and session files no record claims are named with `runfree up` as the remedy. |
| `runfree resume` | Pick and resume interrupted Claude, Codex, or Pi work for the current project. |
| `runfree resume --list` / `--json` | Inspect the current project's bounded recovery inventory offline without contacting Docker. |
| `runfree resume --all` | Include interrupted work from every Runfree project; composes with `--list` or `--json`. |
| `runfree resume --agent <agent>` | Include only one agent ID such as `claude`, `codex`, or `pi`; repeat the option to select a union. |
| `runfree status` | List containers, desired/effective runtime component identities and upgrade action, audit state, and the proxy's session files with, for each, either `served until <aliveUntil>` or `on disk, not served (<reason>)`. With approved [host services](#host-services), it also lists each one with its current listener and the host-service gateway state, and warns about drift. |
| `runfree resources` | List Runfree Docker resources for this project. |
| `runfree logs proxy` | Follow proxy logs. Use `--verbose` for sanitized allowed request metadata. |
| `runfree runtime reload-policy [--force]` | Restart the proxy, reload runtime policy, and sync proxy-managed tokens. Refuses under the same conditions as `runfree stop` unless `--force` is given. |
| `runfree runtime recover` | Resume a pending compatible proxy replacement (a control-plane rebind) with the approved policy. Refuses with `no proxy replacement is pending; use runfree up to prove the current runtime` when none is pending. |
| `runfree runtime recover --retry` | Same, and grant the pending replacement a new allowance (120 seconds, at most two proxy creations). Use it after `automatic allowance ended; sessions remain running` and after you repair the reported failure. See [architecture.md](architecture.md#runtime-lifecycle). |
| `runfree project-id` | Print the stable project id. |
| `runfree project-id --compose-name` | Print the Docker Compose project name. |

The agent commands run the agent's configured command and pass it no extra
arguments. An unknown flag, such as `runfree claude --resume`, is refused with
`Unknown argument` before any project or Docker work; use `runfree resume` to
resume a conversation.

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

Any other case shows a picker, newest first after terminal matches; choosing
a row asks "Resume it" / "Forget it" / "Back". `--all` and `--project` show a
labelled picker, each row prefixed with its project name, that never asks the
one question. Without a TTY, or with `--list`, `runfree resume` only prints the
inventory table. Records with no record version are listed only by `--list`.

`runfree claude`, `runfree codex`, and `runfree pi` always start a fresh
session; resuming happens only through `runfree resume`. See [Interrupted
Session Recovery](architecture.md#interrupted-session-recovery).

### Headless runs

```bash
runfree --workspace ~/proj run claude --prompt-file task.md
runfree run claude --prompt-file task.md --timeout 30m
runfree run claude --prompt-file task.md --accept-denied-writes
runfree run codex --prompt-file task.md
runfree run pi --prompt-file task.md
```

`runfree run` runs one agent turn without a terminal: from launchd, cron, a
script, or a detached tmux pane. It starts a normal per-session container
through the same admission path as `runfree claude`. The agent works on the
live project folder, and its results are the files it writes there.

Runfree sets each agent's headless mode and reads its JSON event stream to
decide the result:

| Agent | Mode Runfree adds | Final success |
| --- | --- | --- |
| `claude` | `-p --output-format stream-json --verbose` | the last `result` event has subtype `success` and `is_error: false` |
| `codex` | `exec --json -` | a `turn.completed` event, no `turn.failed` event, and no `error` event after the last `turn.completed` |
| `pi` | `--mode json -p` | the last `agent_end` event is not retried, and its last assistant message has stop reason `stop` |

Pi in JSON mode exits 0 even when its model request failed, so a Pi run with a
failed request ends unverified (1), not as success. Codex reports a reconnect
it recovered from as an `error` event; a `turn.completed` after it still counts
as success.

| Option | Use |
| --- | --- |
| `--prompt-file <file>` | Required. The prompt, given to the agent as its stdin. The path is resolved from the directory you run `runfree` in, not from `--workspace`. It must be a regular file, not a symlink, and at most 1 MiB. |
| `--timeout <duration>` | Stop the run after this long, from `1s` to `24h` (for example `30m` or `2h`). The run exits 67. |
| `--accept-denied-writes` | Run even if some writes would ask for approval. The proxy denies them, and they do not change the exit code. |
| `--verbose`, `-v` | Print extra startup diagnostics. |

The agent gets no other arguments: Runfree sets the agent's command line, and
an unknown flag or a word after `--` is a usage error (64). Runfree copies the
prompt into the project inbox, the session entry opens the copy as the agent's
stdin, and the run deletes the copy when it ends. The prompt is never part of
the agent's command line. The container has no TTY and no open stdin, so no
keystroke from a terminal reaches the agent.

A run never prompts. A step that needs an answer refuses instead (exit 65):
new authority that `runfree policy approve` or `runfree control approve` must
approve, a service review, and a host credential source
that cannot be read (for example, a locked 1Password).

**The default write action is `ask`, so most projects are refused at first.**
A headless session has no approver, so the proxy denies an `ask` write at
once instead of holding it. Before the launch, `run` refuses with 65 if any
write can resolve to `ask`, and lists each case:

- an allowed host without an explicit write rule (the default is `ask`), or
  with `--write ask`;
- an MCP server, or one of its tools, whose rule is `ask`;
- MCP methods that are not classified, which use the global write action
  (`ask` by default), while any MCP server is configured.

Set each one to `allow` or `deny` (`runfree host rules <host> --write deny`,
`runfree mcp rules claude my-server --write allow`), or pass
`--accept-denied-writes` to run and let those writes be denied. The check is
an early warning; the proxy enforces the denial even if a rule changes to
`ask` during the run. Each denied write is counted. Without
`--accept-denied-writes`, a run that would succeed with any denied write exits
68.

Some authority does not pass write approval: [host services](#host-services),
mediated OAuth exchanges, and STDIO or loopback MCP servers. A run allows them
and lists them in `run.json` under `uncheckedAuthority`.

One run at a time per project. Each run takes a project run lock first; a
second run exits 66 and does nothing. Interactive sessions do not take the
lock. If the stop of a run's container could not be confirmed, the lock stays
until that container is gone. The next run reclaims the lock when its holder
is dead and its container is proven gone; find the session with
`runfree sessions` and remove it with `runfree stop`.

A timeout, SIGINT, SIGTERM, a failure after the launch, and a normal end all
take the same stop routine: revoke the session, stop its container, delete the
prompt copy, finish the run record, and release the lock if the stop was
confirmed. A second signal only shortens the container stop.

| Exit code | Meaning |
| --- | --- |
| 0 | Success: the agent exited 0 and reported a final success. |
| 1–63 | The agent failed (its own code; a code above 63 becomes 1), or the result is unverified (1): no final success, a lost status, an incomplete output stream, or denied writes that could not be counted. |
| 64 | Usage error: a bad flag, agent, timeout, or prompt file. Nothing was started. |
| 65 | Refused before the launch: an invalid project config or network policy, approval, service review, login or credential source, or write posture. |
| 66 | Skipped: another run holds the project lock. |
| 67 | Timeout or signal, whatever the agent returned. |
| 68 | The agent succeeded, but writes were denied and `--accept-denied-writes` was not given. |

Each run keeps a record on the host only, in the project's state directory
(by default `~/.local/state/runfree/projects/<project-hash>/runs/<run-id>/`).
No session can read it, and Runfree writes nothing into the project tree. To
get a summary file in the project, ask for one in the prompt.

```text
runs/<run-id>/
  transcript.jsonl   the agent's raw stdout
  stderr.log         the agent's and Runfree's stderr
  result.md          the agent's final message
  run.json           agent, agentStatus, outcome, exitCode, times, teardown,
                     headlessDenials, uncheckedAuthority
```

When the run ends, it prints the final message, any warning (for example
`warning: 2 writes were denied (headless)`), and the record path to stdout, so
a scheduler's log shows them. A run does not need tmux:
`tail -f <record>/transcript.jsonl` follows its progress. An expired agent
login shows as a failure or an unverified result, never as success.
`runfree resume` never offers a headless run's conversation. Runfree keeps a
headless run's host session record, even after a success, so a Codex run's
conversation is never matched to an interactive session that overlapped it;
the next `runfree run` in the project deletes records older than 7 days.

#### Scheduling on macOS

Use a launchd `LaunchAgent`, which runs in your GUI login session. cron is not
supported: a cron job has no login keychain and no 1Password session, and it
may not find the Docker Desktop socket. A credential source that cannot be
read refuses the run (65). Save this as
`~/Library/LaunchAgents/com.example.runfree-nightly.plist`, with your own
paths:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.runfree-nightly</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/runfree</string>
    <string>--workspace</string>
    <string>/Users/me/proj</string>
    <string>run</string>
    <string>claude</string>
    <string>--prompt-file</string>
    <string>/Users/me/prompts/nightly.md</string>
    <string>--timeout</string>
    <string>30m</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>3</integer>
    <key>Minute</key>
    <integer>0</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>/Users/me/Library/Logs/runfree-nightly.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/me/Library/Logs/runfree-nightly.log</string>
</dict>
</plist>
```

Load it, and start it once to test it:

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.example.runfree-nightly.plist
launchctl kickstart gui/$(id -u)/com.example.runfree-nightly
```

Docker Desktop must be running. Give the prompt file an absolute path, because
launchd does not start the job in your project folder.

## Network Policy

Runfree policy is exact-host based. There are no wildcard hosts.

`.runfree/network-policy.json` is writable desired policy, version 2, 3, or 4.
Runfree writes the lowest version that holds the content:

- Version 4: a service entry has request rule settings
  (`services.<id>.selection.hostRules`, written by `host rules` on a service
  host).
- Version 3: a credential destination with the `basic` scheme, a `username`,
  or a `protocol` scope, or two destinations for one host and header within
  the direct `tokens` or within one service entry.
- Version 2: everything else.

A file that declares a lower version than its content needs is refused with
the fields named. Older releases refuse a newer version: releases that read
only version 2 say `version must be 2`, and releases that read versions 2 and
3 say `version must be one of: 2, 3`. Editing the file does
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

`--read-only` is shorthand for `GET`, `HEAD`, and `OPTIONS`. `host rules --write` sets the action for write-class requests to that host.

Some APIs send reads as `POST`, such as a query endpoint. To keep such an API
read-only without an approval prompt per request, allow only `GET` and `POST`
under the API paths, and let those requests through:

```bash
runfree host rules api.example.com --method GET --method POST \
  --request-path-prefix /v1 --write allow
```

Use this only when every `POST` under the prefixes is a read. The proxy
refuses every other method on the host, and on a method-ruled host it strips
the `X-HTTP-Method-Override`, `X-HTTP-Method`, and `X-Method-Override`
headers. A prefix matches the path itself or a path below it, so `/v1batch` is
outside `/v1`. Keep an endpoint whose body carries other requests, such as a
`/batch` endpoint, outside the prefixes: its inner requests use the outer
credential. The proxy does not strip a method override in the query string or
the body, so also bind a read-only credential where the provider offers one.
On a host with path prefixes the proxy refuses an encoded `/` (`%2F`) in the
path, so an endpoint that puts an encoded identifier containing `/` in the
path is refused under such a rule. `runfree service explain <id>` lists a
service's own setup steps.

`host add` and `host rules` with request-rule flags change only the fields
those flags set. The other fields of the host's rule stay. A field you give
again replaces that field: a new `--method` list replaces the old list.
`--clear` removes the whole rule; there is no way to remove one field.

A host that an enabled service allows gets its rule from that service. On
such a host, `host rules` stores your setting with the service, in
`services.<id>.selection.hostRules`. The enforced rule is the service's rule
with your fields laid over it. `service disable` removes your setting with the
service. Only the permission fields can be set (`--method`,
`--request-path-prefix`, `--read-only`, `--deny-git-push`, `--write`). The
service's own classification fields, such as GraphQL endpoints and read path
prefixes, stay. If the service sets the methods or path prefixes (an OAuth
token endpoint), your setting can only narrow them. `--deny-git-push` is
accepted only on a host where the service has git handling (such as
`github.com`); elsewhere use `--method` or `--write deny`.

A `--write` setting on one host outranks the service's write mode
(`--read-only` or `--allow-write`) for that host. If your setting is weaker
than the write mode, for example `--write allow` under a `--read-only`
service, `service enable`, `service configure`, and `service diff --apply`
warn and name `runfree host rules <host> --clear --service <id>`.

- Run `host rules` in the layer that holds the service entry: with `--local`
  for a checkout-local service, without it for a project service.
- If two services allow the host, name the owner with `--service <id>`. A
  refusal prints your command again with `--service <id>` (and `--local`
  where needed). Without set flags, `--service <id>` must name a service that
  allows the host.
- A checkout-local `service enable <id> --local` replaces the project entry
  of the same id, so the project entry's `host rules` settings stop applying.
  The command warns and names the hosts.
- `host add <host>` with rule flags on a service host is refused. Add the host
  without rule flags, then use `host rules`.
- `host remove` on a host that only a service allows is refused. The message
  names `service disable <id>`, and `service enable <id> --skip-host <host>`
  when the service can skip that host.
- An older policy can hold a direct rule on a host where a service also sets
  a rule. The direct rule replaces the service's whole rule. A set on such a
  host is refused and names `runfree host rules <host> --clear`. The first
  `--clear` removes the direct rule; a second `--clear` removes your service
  setting.

`host rules <host>` without flags prints the enforced rule and who owns it:

```text
scope: project
github.com: methods=all pathPrefixes=all gitPush=deny
owner: service github (project)
  service rule: gitPush=write
  your setting: gitPush=deny
```

The owner is `service <id> (<layer>)`, `direct (<layer>)`, or `none`. A set or
`--clear` prints the owner and the enforced rule `before:` and `after:` the
change.

`--local` writes the checkout-local ignored desired layer; project scope is the
default.

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

Start the service on the host listening on `127.0.0.1:<port>` or
`*:<port>`, approve it, then start a new session. For example, with a dev
server on the host at `127.0.0.1:3000`:

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
  `<name>.runfree.internal`, which the agent never needs to use. A policy
  holds at most 64 host services. A name may be approved in only one layer,
  and a port may appear only once across the project and checkout-local
  layers.
- Before any policy write, `add` refuses these ports: 2375 and 2376 (Docker
  Engine), 3128, 5901 (Runfree's VNC default), and 47100–48099 (Runfree's MCP
  callback block). It then runs `lsof` and refuses a port with no visible
  listener or with any listener owned by Docker Desktop (`com.docker.*`, a
  published container port). The output names the process and pid you
  approved.
- A service added while a session runs appears in the next session.
  `remove` cuts open connections in every session and reports `live now` once
  the proxy and the firewall have both cut it. A port the in-session relay
  cannot bind is skipped with a warning.
- An unapproved host-service connection is refused; the refusal and
  `runfree doctor` may suggest `runfree host-service add <name> --port <port>`,
  labelled as requested by the agent. Check it before you run it.
- `list` prints the effective host services and who listens on each port now.
  `runfree status` repeats that check and warns when the listener is gone,
  changed, or owned by Docker Desktop. It also prints the gateway state:
  `host-service gateway: <ip>`, `host-service gateway: unavailable (<reason>)`,
  `host-service gateway: unknown (proxy not running)` with no warning when the
  proxy is stopped, or `host-service gateway: unknown` with a warning when the
  proxy's gateway status cannot be read or is malformed. These lines never change the exit code.
- `runfree forward` and `runfree vnc` in other projects refuse an approved
  port; `runfree host-service list --repair` rebuilds a corrupt port registry
  (see [troubleshooting.md](troubleshooting.md#a-host-service-is-refused-or-unreachable)).
- The tunnel is opaque: no request rules, write approval, or credential
  injection apply, and the host service's own authentication is the only
  check on what the agent does there. Access is per project. See
  [Residual Risks](security.md#residual-risks).
- If the host gateway address changes, host services stay refused until
  `runfree rebuild`, and `runfree logs proxy` shows
  `proxy: host-service splices cut: <count>; reason: <reason>`.

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
runfree credential source add google-service-account gsc \
  --key-json-from-1password op://vault/gsc-sa/credential.json \
  --scope https://www.googleapis.com/auth/webmasters.readonly
runfree credential source list
runfree credential source show github-cli
runfree credential source remove github-cli
```

Everything after `--` in `credential source add <name> -- <command>` is source command argv, not Runfree options.

A `google-service-account` source signs a Google self-signed RS256 JWT on the
host for the `google-search-console` service, whose setup
`runfree service explain google-search-console` lists. The key JSON stays in
1Password: a one-shot sync reads it for its signature, and
`credential sync --watch` keeps the parsed key in memory for at most 4 hours
and signs each refresh with it (see below). The CLI never stores the key
JSON, the private key, or the key id on disk; the proxy gets only the signed
JWT.

- `--scope` is required and repeatable. Only
  `https://www.googleapis.com/auth/webmasters.readonly` and
  `https://www.googleapis.com/auth/webmasters` are accepted.
- `--ttl` is the JWT lifetime, from `5m` to `60m`; the default is `55m`. A
  binding without `--refresh-every` refreshes one minute before the JWT
  expires (every `54m` at the default), and an explicit `--refresh-every`
  must be shorter than the TTL.
- `add` reads the key JSON once to check it and to sign a test JWT. It refuses
  a key that is not a service-account key, not RSA, shorter than 2048 bits, or
  encrypted, and refuses a `universe_domain` other than `googleapis.com`. The
  refusal names the field and never prints the key.
- The source pins the key's `client_email`. A key JSON for another service
  account fails every later sync until you rerun the same `add` command with
  `--replace-source`, which pins the new account.
- `credential sync --watch` keeps the parsed key in memory for at most 4
  hours, then reads 1Password again. It stops using a key removed from
  1Password within 4 hours plus one TTL (5 hours at the defaults). To stop a
  key at once, delete it in Google Cloud IAM.
- The service account needs no Google Cloud IAM roles. Its access comes from
  the account being a user in the Google product the service calls.

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
and after, and `runfree service diff --apply` writes the new entries.

`--apply` keeps each entry's recorded selection: skipped hosts, write mode,
and the request rule settings made with `host rules`. Re-running
`runfree service enable <id>` also writes the current revision. It keeps the
`host rules` settings, but it builds the rest of the entry only from that
run's flags, so an earlier `--skip-broad`, `--skip-host`, `--read-only`, or
`--allow-write` is lost unless you repeat it. `service configure` keeps the
whole selection.

A saved `host rules` setting must still fit the entry. `service diff --apply`
refuses before it writes if the new revision no longer allows a host that has
a setting, or if a setting is broader than the new revision's methods or path
prefixes for that host, or if it sets `--deny-git-push` on a host where the
new revision has no git handling. A `service enable` that newly skips such a
host is refused the same way. Each refusal names
`runfree host rules <host> --clear --service <id>`, plus `--local` for a
checkout-local service. Without `--apply`, `service diff` lists every one of
these as a `refuses:` line.

`service enable` and `service diff --apply` also check for a direct rule on
one of the service's hosts. A direct rule equal to the service's rule moves to
the service, with a notice, only when it holds no permission field (no
methods, path prefixes, write action, or git push deny); `service disable`
then removes it. Any other direct rule stays and replaces the service's rule,
with a warning that names `runfree host rules <host> --clear`. A direct rule
that restricts the host therefore stays after `service disable`.

A `github` or `gitlab` service enabled at an older revision gets no
git-over-HTTPS credential until you run `runfree service diff --apply`.
Applying either one makes `.runfree/network-policy.json` desired policy
version 3.

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
no two destinations may have the same `protocol` and `pathPrefix`. A
definition that breaks a rule is refused before anything is written. Enabling
a service whose destinations use `basic`, `username`, or `protocol` makes the
desired policy version 3. How the proxy chooses among a host's destinations,
and the Git LFS read rule a `git-lfs` destination turns on, are in
[security.md](security.md#git-over-https).

These fields give a git credential to a host with no curated service, such as
GitHub Enterprise Server or self-hosted GitLab. A user-defined service cannot
declare git handling, so there every fetch and LFS batch is a write that waits
under `ask` (see [Residual Risks](security.md#residual-risks)).

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
`github.com`. The `gitlab` service has only `git-http`, so Git LFS is not
mediated on `gitlab.com`: LFS requests there get no credential, every LFS batch
request is a write, and a private GitLab LFS fetch fails (see
[security.md](security.md#git-over-https)).

Any other path, or an ambiguous spelling of one of these, gets no credential.
A fetch is a read. A push is a git push write: under the default `ask` posture
it waits for `runfree approve`, and once approved it goes out with your token.
On `github.com`, a Git LFS download batch is a read and an upload is a write.
To refuse pushes outright:

```bash
runfree host rules github.com --deny-git-push
```

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
  denial for that host. It is routing, not enforcement: undoing it gains the
  agent nothing, because SSH has no route out of the sandbox.
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

Git failures and their remedies are in
[troubleshooting.md](troubleshooting.md#git-over-https-fails).

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
runfree mcp enable claude my-server --no-discover --oauth-host auth.example.com
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
credentials. Use `127.0.0.1`, not `localhost`: forms such as `127.1`
normalize to it, and `localhost`, `[::1]`, other `127.x` addresses, a URL with
userinfo, a fragment, or `$`, port 0, and a port Runfree reserves are refused.
A loopback entry keeps only `type` and `url` for Claude, and `url`, `enabled`,
`required`, `enabled_tools`, `disabled_tools`, `startup_timeout_sec`, and
`tool_timeout_sec` for Codex; a listed Codex key of the wrong type is refused.
Inside the session the URL
reaches only a process in the session, unless a host service holds the port.
To reach a dev server on the host, approve the port separately:

```bash
runfree host-service add astro --port 8089
```

`runfree mcp enable` and `runfree mcp explain` show the reach as
`host-service`, `container-local`, or `unknown` with a reason, and a launch
warns when no host service backs the port. For a loopback entry, `mcp enable`
makes no discovery call and refuses `--oauth-host`, and `runfree mcp auth`
refuses it. A loopback entry cannot carry
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
Two sessions can log in at the same time. `runfree mcp auth` launches a
session and prints these steps. A provider that accepts only one
pre-registered callback port works only while its session holds the project's
first port. Each session tries up to 32 callback ports; when all are taken,
the launch fails with a retry instruction.

### Enable an MCP server in one step

`runfree mcp enable <agent> <server>` shows one review and asks once. The
review lists every change:

- the project approval (project entries);
- the credential source (static-header entries; `--from-env`,
  `--from-1password`, `--from-source`, or `--from-stdin`);
- the MCP endpoint host;
- each OAuth host, with where it came from: `discovered` (and the metadata
  that named it) or `--oauth-host`;
- for each recorded token endpoint, the line `other apps that log in at
  <url> will stop working in the sandbox`: the proxy mediates every login at
  that exact URL for this server.

After you accept, Runfree saves the changes and applies them to a running
proxy. For OAuth servers it then prints the login command
(`runfree mcp auth`). Pass `--login` to run that login at once; it needs a
terminal.

To find the OAuth hosts, Runfree reads the server's OAuth metadata from this
computer with plain HTTPS GETs that carry no credentials, and asks first
before it contacts a host a project file names. Login and refresh at the
recorded endpoints skip write approval, at most 30 a minute per server; a host
set to `deny` stays denied. The rules are in [security.md](security.md#mcp).

| Option | Meaning |
| --- | --- |
| `--source user\|local\|project` | Choose the entry when more than one matches. User and local entries need no approval; `enable` records only their OAuth hosts. |
| `--oauth-host <host>` | Also allow this exact host for the server (repeatable). It is allowed as given, like `runfree host add`, and it must pass the [host rule](#oauth-hosts-on-another-host). The proxy mediates a token or registration endpoint there that the server's OAuth metadata names. While only MCP records allow the host, the proxy refuses any other OAuth token or registration request to it, and any request with a body it cannot check (see below). |
| `--no-discover` | Make no network call. Use only `--oauth-host` hosts. |
| `--login` | Run the OAuth login (`runfree mcp auth`) after enabling. It starts an agent session and needs a terminal. Without it, `enable` prints the login command. |
| `--from-env`, `--from-1password`, `--from-source`, `--from-stdin` | Bind a project entry's static header to a host-owned credential source. Choose one. |
| `--replace-source` | Replace an existing credential source for this server. |

Discovery needs a terminal. Without one, `mcp enable` refuses before any DNS
lookup unless you pass `--no-discover`; then the command line names every
change and is itself the approval.

#### OAuth hosts on another host

A server's OAuth metadata may put its token endpoint on another host than the
MCP endpoint: for example, the server at `api.example.com` and the token
endpoint at `example.com`. `mcp enable` accepts such an endpoint only when the
metadata came from an authorization server that the server's
protected-resource metadata named, or from a declared `authServerMetadataUrl`.
A registration endpoint on another host is accepted only on the host of that
token endpoint, and the proxy matches it by exact path. The review labels the
host:

```text
  allow host example.com  [OAuth, token endpoint on another host]
      token_endpoint https://example.com/oauth/token
      named by authorization server https://api.example.com/ (its metadata issuer matches)
      which https://api.example.com/.well-known/oauth-protected-resource/mcp named
      this server's OAuth tokens and refresh tokens will be sent to this host
      other apps that log in at https://example.com/oauth/token will stop working in the sandbox
      limited to GET, HEAD, OPTIONS, and POST on paths starting with /.well-known, /oauth/token
```

If the current policy already allows the host (desired policy or `host add`),
its rules stay, and the proxy mediates only the exact endpoint. The label
then says so:

```text
  allow host example.com  [OAuth, token endpoint on another host]
      token_endpoint https://example.com/oauth/token
      named by authorization server https://api.example.com/ (its metadata issuer matches)
      which https://api.example.com/.well-known/oauth-protected-resource/mcp named
      example.com is ALREADY ALLOWED for all paths (current policy); its rules stay
      token replies from https://example.com/oauth/token will be held by the proxy for MCP server claude my-server
      approve only if this address belongs to the same service
      other apps that log in at https://example.com/oauth/token will stop working in the sandbox
```

`for all paths` is left out when the host has request rules. A host with both
endpoints is labeled `[OAuth, token and registration endpoints on another
host]`. `runfree mcp explain` shows the host as `discovered, token endpoint on
another host`, and an exact-path registration endpoint with `(exact path)`.

**Host rule.** An MCP server cannot use an OAuth host or endpoint where
another login's tokens pass. This applies to discovered hosts and endpoints,
`--oauth-host` hosts, and the server's declared token endpoint and
`authServerMetadataUrl`. Runfree refuses the host or endpoint when:

- the proxy injects a credential on the host;
- the host belongs to a curated service, enabled or not (for example
  `github.com` or `oauth2.googleapis.com`; `runfree service list --all` lists
  the services and `runfree service explain <id>` their hosts);
- another MCP server in the project uses the host as its endpoint host, a
  declared OAuth host, or a recorded OAuth host. The same server enabled for
  both agents counts as one server, so two servers cannot share an OAuth host;
- the endpoint is another OAuth provider's token or registration endpoint, or
  overlaps one.

The server's own MCP endpoint host is never refused for itself. At `mcp
enable`:

- A refused `--oauth-host` host or declared endpoint stops the command before
  any discovery call. Nothing is saved.
- A refused endpoint in discovered metadata drops that whole metadata
  document. The review lists it under `not added`.
- When a well-known host is refused and no token endpoint is left, the command
  stops and names a static token instead:

```text
cannot use https://github.com/login/oauth/access_token as a token endpoint for claude gh:
  github.com is a well-known host; other logins there would be captured.
  use a token instead: add "headers": {"Authorization": "Bearer ${GH_MCP_TOKEN}"} to the server entry, remove its OAuth settings, and run
    runfree mcp enable claude gh --source project --from-env GH_MCP_TOKEN
nothing was saved
```

For Codex the header step is `set bearer_token_env_var = "GH_MCP_TOKEN" in
the server entry`. For a user or local entry the command is `runfree
credential set-source <token-name> --from-env <ENV>`, with the token name
Runfree prints. The proxy keeps the token and injects it; the agent sees a
placeholder.

Each launch checks the same rules again. If a later change makes one apply (a
new credential, a service, or another server on the host), Runfree drops the
claim with a warning, and the proxy refuses token requests at its endpoints.
To restore it, remove the conflicting use and run `runfree mcp enable` again,
or remove the server with `runfree mcp revoke`. A later `runfree host add` for
the host does not drop the claim: the host gets its new rules, and the exact
endpoint stays mediated.

**Hosts only MCP allows.** A host that only `mcp enable` records allow, and
not desired policy, `host add`, a service, or an MCP endpoint, is a
record-only host. On a record-only host the proxy refuses a request that no
server mediates, with any method, before any upstream connection and before
any approval prompt, when:

- its query or body carries `grant_type`, `refresh_token`, `redirect_uris`,
  or `code` together with `code_verifier`;
- it is `multipart/form-data`, its body has no `Content-Length` or is larger
  than 16 KiB, its body or content encoding cannot be decoded, it declares a
  charset other than UTF-8 or US-ASCII, or its body contains a NUL byte;
- it is a WebSocket upgrade. The proxy cannot read an upgrade's reply, so it
  also refuses upgrades to any endpoint URL a server claims; send those
  requests over HTTPS.

The denial reason is `oauth-endpoint-not-mediated`. An `--oauth-host` host is
record-only too, so the second and third rules can refuse a large upload or a
WebSocket there. `runfree host add <host>` allows the host outside MCP and
ends these rules, and with them the grant refusal: a token request there that
the proxy does not mediate then returns real tokens to the agent. On a host
where a dropped or disputed claim left a blocked endpoint, the proxy refuses
grant-shaped requests on every path, so variants such as `/oauth/token/` are
caught too. See
[An OAuth request was refused as not mediated](troubleshooting.md#an-oauth-request-was-refused-as-not-mediated).

**One server for both agents.** When the same server (name, source,
endpoint, and OAuth settings) is enabled for Claude and for Codex, both agents
share one OAuth login. The proxy files its tokens under one owner agent: the
one enabled first. When the shared group first forms, and once after an
upgrade, Runfree clears the server's proxy OAuth state and warns that each
agent needs a new login. If Runfree cannot store the owner in its state
directory, it warns, and the proxy refuses the server's logins until a later
launch can write the file.

OAuth hosts are not written to `.runfree/network-policy.json`. They are
host-owned records bound to the reviewed server config: if a project entry
changes, or a user entry is deleted, its hosts stop applying. `runfree mcp
revoke <agent> <server>` removes exactly the hosts that `enable` added. A host
that desired policy or a service also names stays allowed. `runfree mcp
explain` lists the recorded hosts and endpoints.

`runfree mcp revoke` also clears the proxy's OAuth state for the server: its
tokens, its `runfree_oauth_*` handles, and the issuers and endpoints the proxy
found at run time. It does this for every source of that agent and server
name. It also clears the other agent's state when that agent has an entry with
the same server name and source, because such a server shares its login, and
prints `claude and codex share one OAuth login for <server> ...`. The login
stays with its owner while the owner's entry is configured; when the owner's
entry is gone, the next launch moves the login to the other agent and clears
the state again. Revoking only the agent that does not own
the login does not stop that agent from logging in through the owner's
endpoint while the owner stays enabled; revoke both to end it. A later `mcp enable` needs a new login.
Revoke prints one of these lines:

| Line | Meaning |
| --- | --- |
| `proxy OAuth state for <agent> <server>: cleared (...)` | The running proxy confirmed that it applied the policy that clears the state. |
| `...: not cleared yet; the proxy clears it when it next starts ...` | No proxy runs now. The clear is saved and happens at the next start. |
| `...: not proven cleared; ...` | A proxy runs, but it did not confirm the clear (for example, it is from an older Runfree version). It happens when the proxy next starts on this version. |

If Runfree finds its record of cleared servers damaged or missing, it clears
the OAuth state of every MCP server, and each server needs a new login. A
damaged record also prints a warning; a missing one (the first start after
upgrading from a release without it) does not.

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

The forward is host→agent only and never carries egress. It reaches the
agent's network interface, not its loopback, so a service bound only to
`127.0.0.1` inside the session is unreachable while the forward still reports
success. Treat what it serves as untrusted agent output in your unsandboxed
browser (see [Trust Boundary](security.md#trust-boundary)).

### Runfree inbox

```bash
runfree inbox paste
runfree inbox paste --copy
runfree inbox clean
runfree inbox clean --all
```

On macOS, `inbox paste` imports a clipboard image into Runfree state and prints its read-only `/runfree/inbox/...` container path.

### Git worktrees

```bash
runfree git repair-worktree-links
```

Repairs host Git metadata to use relative worktree links.

Create worktrees inside the mounted project, for example `.worktrees/feature`,
so the host and the sandbox can both reach them. Sandbox Git uses relative
worktree links by default. On the host, use `git worktree add --relative-paths`,
or set `git config --local worktree.useRelativePaths true` once for the
repository. Both need host Git 2.48 or newer.

With older host Git, or none, Runfree still launches where it safely can:

| Host Git | What happens |
| --- | --- |
| Older than 2.48 | Launch continues with one warning: a worktree created inside the sandbox would make the repository unreadable to host Git. |
| Older than 2.48, with a nested worktree or launched from a linked worktree | Launch refuses before writing any state, because the layout needs 2.48+. `runfree git repair-worktree-links` refuses too. |
| Not installed, non-Git project | Launch continues with a warning. |
| Not installed, Git repository | Launch refuses, because Runfree reads the repository's layout through Git. |
| 2.48+ with an unsupported layout (absolute links, such as a stale `/workspace` link) | Startup stops and names the repair command to run on the host from the main checkout. |

Upgrading host Git fixes every case. `runfree status` prints host Git's
version and worktree capability:
`host git: <version> (worktrees: enabled|disabled)`. The exact messages and
their remedies are in
[troubleshooting.md](troubleshooting.md#host-git-is-too-old-or-missing).

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
