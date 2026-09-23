// Task-oriented help registry.
//
// This is intentionally separate from yargs command-specific (`--help`) syntax
// help. `runfree help <topic>` explains workflows; yargs explains exact command
// syntax for migrated commands. See the spec's "Task Help And Syntax Help Are
// Different" principle.

import { die } from "../errors.ts";
import { helpAllExamples, renderExampleCommands } from "./examples.ts";

const HELP_TOPICS = [
  "quickstart",
  "run",
  "network",
  "credentials",
  "services",
  "mcp",
  "deps",
  "image",
  "diagnostics",
  "all",
] as const;

type HelpTopic = (typeof HELP_TOPICS)[number];

function knownHelpTopics(): string {
  return HELP_TOPICS.join(", ");
}

function helpQuickstart(): string {
  return `Quickstart

Recommended first run:
  runfree init
  runfree

On a TTY, init opens a short wizard. It detects project files, git remote hosts,
and host credential helpers, then shows a reviewable plan before any policy or
token-source changes are applied. Non-TTY init and init --yes scaffold only.

If the agent is blocked during setup:
  runfree up --audit-network
  runfree
  runfree audit report
  runfree audit off

Then apply only the hosts or services you trust, for example:
  runfree service enable node
  runfree service enable github --from-source github-cli
  runfree host add pypi.org --read-only`;
}

function helpRun(): string {
  return `Runtime

Start or attach:
  runfree [--quiet]
  runfree claude [--quiet]
  runfree codex [--quiet]
  runfree pi [--quiet]
  runfree shell
  runfree up [--verbose]

Held writes:
  runfree approvals [--watch] [--no-bell] [--clear-deny]
  runfree approve <id> [--deny] [--scope request|session|deny-session] [--ttl 15m]

Inspect and manage:
  runfree sessions
  runfree sessions rename <session-id> <name>
  runfree resume [--list|--json] [--all|--project <path>] [--agent <agent>]...
  runfree status
  runfree resources
  runfree logs proxy
  runfree logs proxy --verbose
  runfree rebuild [--yes] [--verbose]
  runfree stop
  runfree destroy [--force]

Use --quiet to suppress the session-end blocked-host summary.`;
}

function helpNetwork(): string {
  return `Network Policy

Allow exact hosts:
  runfree host add <host> [--read-only] [--method <M>]... [--request-path-prefix /path/] [--local]
  runfree host remove <host> [--local]
  runfree host list
  runfree host explain <host>
  runfree host rules <host> [--write allow|ask|deny] [--local]
  runfree host rules <host> [--read-only] [--method <M>]... [--request-path-prefix /path/] [--local]
  runfree host rules <host> [--clear] [--local]

Discover needed hosts without editing policy:
  runfree up --audit-network[=<duration>]
  runfree audit status
  runfree audit report [--json]
  runfree audit off

Diagnose blocked requests:
  runfree doctor [--post-failure] [--tail <lines>]`;
}

function helpCredentials(): string {
  return `Credentials

Named source -> credential -> destination. Runfree keeps real values host-side
or proxy-side; agent environment variables may contain placeholders only.

Curated service:
  runfree credential source add github-cli -- gh auth token
  runfree service enable github --from-source github-cli

Custom host:
  runfree host add api.internal.example.com
  runfree credential add internal-api --host api.internal.example.com --from-source internal-api

Credential commands:
  runfree credential source add <name> -- <command> [args...]
  runfree credential source add jwt <name> --alg ES256 --private-key-from-1password op://... --claim key=value --ttl 19m
  runfree credential add <name> --host <already-allowlisted-host> [--from-env ENV | --from-1password op://... | --from-source <name>]
  runfree credential link <name> --host <already-allowlisted-host>
  runfree credential unlink <name> --host <host> [--header <header>]
  runfree credential remove <name>
  runfree credential set-source <name> [--from-env ENV | --from-1password op://... | --from-source <name>]
  runfree credential clear-source <name>
  runfree credential status [<name>]
  runfree credential sync [--verbose] [--watch]`;
}

function helpServices(): string {
  return `Services

Services are curated or user-defined exact-host bundles for package ecosystems
and providers. They expand into .runfree/network-policy.json at CLI time.

  runfree service list [--all]
  runfree service enable <id> [--from-env ENV | --from-1password op://... | --from-source <name>]
  runfree service enable <id> [--skip-broad] [--skip-host <host>] [--read-only | --allow-write]
  runfree service enable <id> --param <key>=<value>
  runfree service configure <id>
  runfree service custom add user-<id> [--from-file service.json]
  runfree service custom remove user-<id>
  runfree service disable <id>
  runfree service explain <id>
  runfree service diff [--apply]

Credential-bearing services can bind a proxy-managed credential without
exposing its real value to the agent. Broad multi-tenant hosts are called out
before enable.`;
}

function helpMcp(): string {
  return `MCP

Host-native MCP config:
  claude mcp ...
  codex mcp ...

Runfree import and project approval:
  runfree mcp list [--json]
  runfree mcp configure [--agent <agent>]... [--server <name>]
  runfree mcp explain <agent> <server> [--source user|local|project]
  runfree mcp approve <agent> <server> [--from-env ENV | --from-1password op://... | --from-source <name>] [--login]
  runfree mcp auth <agent> <server> [--source user|local|project]
  runfree mcp rules <agent> <server> [--tool <tool>] [--write allow|ask|deny]
  runfree mcp revoke <agent> <server>

Project .mcp.json and .codex/config.toml entries are imported only after
project-local approval. Agent IDs are claude (Claude Code) and codex (Codex CLI).
Static headers require a host-owned credential source.`;
}

function helpDeps(): string {
  return `Dependency Overlays

  runfree deps plan
  runfree deps install
  runfree deps doctor
  runfree deps reset [--force]

Runfree installs dependencies inside Docker volumes instead of writing host
artifact directories into the project. Use deps doctor when host artifacts or
overlay drift are suspected.`;
}

function helpImage(): string {
  return `Project Agent Image

  runfree image init
  runfree image approve-context

image init creates .runfree/image/Dockerfile and configures runtime.agent.build.
Project Dockerfiles extend RUNFREE_BASE_IMAGE; full image overrides are not
supported. Wide build contexts require explicit host-state approval.`;
}

function helpDiagnostics(): string {
  return `Diagnostics And Maintenance

  runfree project-id
  runfree project-id --compose-name
  runfree status
  runfree resources
  runfree logs proxy
  runfree runtime reload-policy
  runfree doctor
  runfree assets status
  runfree assets clean
  runfree update
  runfree version
  runfree git repair-worktree-links
  runfree inbox paste [--copy]
  runfree inbox clean [--all]
  runfree vnc [start|stop|status|restart]
  runfree forward [port] [start|stop|status]`;
}

export function printHelpTopic(topic: string | undefined): void {
  // Bare `runfree help` / `runfree --help` / `runfree -h` show the full,
  // hierarchical command reference (every command grouped by section, global
  // options, and examples) — never a short index that name-drops help topics as
  // if they were commands. `runfree help <topic>` still serves task guides.
  if (topic === undefined || topic === "commands" || topic === "all") {
    printFullReference();
    return;
  }
  if (!HELP_TOPICS.includes(topic as HelpTopic)) {
    die(`unknown help topic: ${topic} (known: ${knownHelpTopics()})`);
  }
  switch (topic as HelpTopic) {
    case "quickstart":
      console.log(helpQuickstart());
      return;
    case "run":
      console.log(helpRun());
      return;
    case "network":
      console.log(helpNetwork());
      return;
    case "credentials":
      console.log(helpCredentials());
      return;
    case "services":
      console.log(helpServices());
      return;
    case "mcp":
      console.log(helpMcp());
      return;
    case "deps":
      console.log(helpDeps());
      return;
    case "image":
      console.log(helpImage());
      return;
    case "diagnostics":
      console.log(helpDiagnostics());
      return;
  }
}

// `runfree help all` complete reference. The command descriptions below remain
// the authoritative per-command reference; the trailing Examples section is
// rendered from the single command-example source (commands/examples.ts) shared
// with each command/group's own `--help`, so the two cannot drift.
export function printFullReference(): void {
  console.log(`runfree - installable sandboxed agent workspace CLI

Usage:
  runfree [--workspace <project-dir>] [claude|codex|pi]
  runfree [--workspace <project-dir>] <command> [args...]

Global options:
  --workspace <project-dir>        Target a project directory other than the current one (pre-command only)
  --quiet                          Suppress the session-end blocked-host summary (runtime/agent commands)
  --verbose, -v                    Show extra startup diagnostics (runtime/agent commands)
  -h, --help, help                 Show this command reference
  runfree <command> --help         Show one command's exact syntax and options

Project setup:
  runfree [--workspace <project-dir>] init [--yes]
      Create .runfree/runfree.json, .runfree/network-policy.json, and project dirs
      On a TTY without --yes, continue into a short wizard that detects
      ecosystems (lockfile/manifest existence only), git remote hosts, and
      host credential helpers, then offers a reviewable services/sources plan;
      --yes and non-TTY runs scaffold only
  runfree [--workspace <project-dir>] image init
      Create .runfree/image/Dockerfile and configure runtime.agent.build
  runfree [--workspace <project-dir>] image approve-context
      Approve a configured wide agent image build context in host state

Agent runtime:
  runfree [--quiet]               Start/reuse the sandbox and run the configured default agent
  runfree claude [--quiet]        Start/reuse the sandbox and run the configured Claude agent
  runfree codex [--quiet]         Start/reuse the sandbox and run the configured Codex agent
  runfree pi [--quiet]            Start/reuse the sandbox and run the configured Pi agent
                                  --quiet suppresses the session-end blocked-host summary
  runfree shell                   Start/reuse the sandbox and open zsh
  runfree [--verbose]             Start/reuse the sandbox with extra startup diagnostics
  runfree up [--verbose]          Start/reuse the Docker Compose runtime
  runfree up --audit-network[=<duration>]
      Start the runtime with network audit mode: non-allowlisted HTTPS hosts
      are PERMITTED and logged instead of denied, for <duration> (default 60m,
      max 8h). Host-only, time-boxed, loud; use for trusted onboarding tasks.
  runfree approvals [--watch] [--no-bell] [--clear-deny]
      Review writes held for approval; --watch stays attached as the approver;
      --clear-deny revokes a "stop asking" decision and goes back to asking,
      and --clear-deny --watch clears first, then attaches
  runfree approve <id> [--deny] [--scope request|session|deny-session] [--ttl 15m] [--mcp-scope tool|method|server-tools] [--save-mcp-rule tool|server-tools]
      Decide one held write; default scope is the single request. session/ttl
      scopes cover the requesting session and expire; the MCP flags bind a
      session decision to one tool, method, or server, or save an allow rule
  runfree audit status            Show whether network audit mode is active and when it expires
  runfree audit report [--json]   Aggregate observed non-allowlisted hosts with suggested host add commands; never edits policy
  runfree audit off               Disable network audit mode immediately; the firewall severs in-flight audited connections
  runfree rebuild [--yes] [--verbose]
                                  Rebuild/recreate the Docker Compose runtime; confirms before killing active sessions
  runfree sessions                List active Runfree sessions for this project
  runfree sessions rename <session-id> <name>
                                  Rename one agent session
  runfree resume                  Pick an interrupted session from this project and resume it
  runfree resume --list           List this project's recovery evidence offline without Docker
  runfree resume --agent claude   Show only interrupted Claude Code sessions
  runfree resume --agent codex    Show only interrupted Codex sessions
  runfree resume --all            Pick from interrupted sessions across all Runfree projects
  runfree resume --all --json     Print the cross-project recovery inventory as JSON
  runfree project-id              Print this project's Runfree id (sha256 prefix of the project path)
  runfree project-id --compose-name  Print the Docker Compose project name (runfree-<id>)
  runfree status                  List Runfree containers for this project and the network audit state
  runfree resources               List Runfree Docker resources for this project
  runfree stop [--force]          Stop this project's compose services; refuses live sessions unless --force
  runfree destroy [--force]       Stop services and remove volumes/local images/orphans; --force ends live sessions and removes unclaimed residue
  runfree logs proxy              Follow logs for the proxy service
  runfree logs proxy --verbose    Also log allowed proxy request metadata while following

Dependency overlays:
  runfree deps plan               Show dependency overlay mounts for this project
  runfree deps install            Install dependencies inside overlay volumes
  runfree deps doctor             Diagnose dependency overlay drift and host artifact risks
  runfree deps reset [--force]    Remove Runfree-owned dependency volumes for this project

Sandbox display (VNC):
  runfree vnc [start] [--host-port 5901] [--agent-port 5901] [--display :0] [--password PASSWORD | --no-password] [--clipboard] [--no-start-server]
      Start x11vnc in the agent and forward vnc://127.0.0.1:<host-port> to it through a loopback-only socat sidecar
      The agent image must provide x11vnc and an X display (for example xvfb with headed Chrome)
      A random password is generated unless --password or RUNFREE_VNC_PASSWORD is set; the loopback port is reachable by all local users
      Clipboard sharing with the untrusted agent display is off unless --clipboard is passed; the VNC stream itself is untrusted input to your viewer
  runfree vnc stop [--host-port PORT]
      Remove this project's vnc forward sidecar(s); runfree stop/destroy also remove them
  runfree vnc status
      Show this project's vnc forward sidecar(s)
  runfree vnc restart [options]
      Replace the forwarder (same options as start)

Host→agent port forward:
  runfree forward <port> [--host-port PORT] [--agent-port PORT]
      Publish 127.0.0.1:<port> and splice it one-way to the agent's <port> through a loopback-only socat sidecar
      For previewing a dev server the agent runs (a web app, docs site, API under test); the forward is host→agent only, never egress
      The active session process must listen on a non-loopback interface (0.0.0.0 or the container IP); a service bound only to the session's 127.0.0.1 is not reachable through the forward
      Content served through the forward renders in your (unsandboxed) browser, outside the proxy — treat it as untrusted
  runfree forward <port> stop
      Close one port forward
  runfree forward stop
      Close every open port forward; runfree stop/destroy also remove them
  runfree forward status
      Show this project's open port forwards

Git worktrees:
  runfree git repair-worktree-links
                                  Repair host Git metadata to use relative worktree links

Runfree inbox:
  runfree inbox paste [--copy]    Import a macOS clipboard image into Runfree state and print its container path
  runfree inbox clean [--all]     Remove old or all Runfree-minted inbox files

Network policy:
  runfree policy status
      Show desired, approved, and selected effective control identities
  runfree policy diff [--project | --local] [--json]
      Classify desired drift against exact host-owned approval
  runfree policy review [--project | --local]
      Print canonical desired policy and its authority classification
  runfree policy explain <host>
      Show desired, approved, and effective host semantics, provenance, approvals, and pending changes
  runfree policy approve [--project | --local] [--subject-digest sha256:...]
      Approve exactly one desired policy subject; full digest is required non-interactively
  runfree policy use-approved
      Compile and select an effective policy generation only from approved controls
  runfree control approve <network-project|network-local|runtime-isolation|image-build> --subject-digest sha256:...
      Approve one exact control subject
  runfree host add <host> [--read-only | --method <M>]... [--request-path-prefix /path/]... [--deny-git-push] [--local] [--no-reload]
      Add a host to the allowlist and optionally restrict its requests.
      --read-only is shorthand for --method GET --method HEAD --method OPTIONS.
      Re-running with rule flags replaces the host's request rules.
  runfree host remove <host> [--local] [--no-reload]
      Remove an unreferenced host from the allowlist
  runfree host list
      Print allowlisted hosts
  runfree host explain <host>
      Show a host's allowlist status, credentials, and request rules
  runfree host rules <host> [--write allow|ask|deny] [--read-only | --method <M>]... [--request-path-prefix /path/]... [--deny-git-push] [--clear] [--local] [--no-reload]
      Show/change effective request rules; --write sets write handling, rule flags replace request-shape rules, and --clear removes rules

Credentials:
  runfree credential source add <name> -- <command> [args...]
      Add a reusable host-owned command source
  runfree credential source add jwt <name> --alg <alg> --private-key-from-1password op://... --claim key=value --ttl 19m
      Add a reusable host-owned JWT source
  runfree credential source list
  runfree credential source show <name>
  runfree credential source remove <name>
  runfree credential add <name> --host <host> [--header <header>] [--scheme bearer|raw] [--path-prefix /path/] [--description <text>] [--from-env ENV | --from-1password op://... | --from-source <name> | --from-stdin] [--refresh-every 15m] [--replace-source] [--no-sync] [--no-reload]
      Create a credential destination on an already-allowlisted host and optionally bind its source
  runfree credential link <name> --host <host> [--header <header>] [--scheme bearer|raw] [--path-prefix /path/] [--no-reload]
      Add another already-allowlisted destination
  runfree credential unlink <name> --host <host> [--header <header>] [--no-reload]
      Remove one destination without changing the host or source
  runfree credential remove <name> [--no-reload]
      Remove a manually managed credential, source binding, and proxy value
  runfree credential set-source <name> [--from-env ENV | --from-1password op://... | --from-source <name> | --from-stdin] [--refresh-every 15m] [--replace-source] [--no-sync]
  runfree credential clear-source <name>
  runfree credential status [<name>]
  runfree credential sync [--verbose] [--watch] [--quiet] [--delay-first-sync] [--no-cache-source-secrets]

Services (curated or user-defined host bundles, optionally carrying a credential):
  runfree service list [--all]
      List enabled services; --all also lists every curated and user-defined
      service that is not enabled
  runfree service enable <id> [--from-env ENV | --from-1password op://... | --from-1password-item op://... | --from-source <name> | --from-stdin] [--replace-source] [--skip-broad] [--skip-host <host>] [--read-only | --allow-write] [--local] [--no-reload]
      Write one complete pinned service entry to desired network policy. For a
      service that carries a credential, a
      credential source (--from-*) also injects it at the proxy without ever
      exposing the real value to the agent; broad multi-tenant hosts print an
      exfiltration-surface warning, --skip-broad enables without them
  runfree service configure <id> [--local] [--no-reload]
      Guided service setup on a TTY
  runfree service custom add <id> [--from-file service.json] [--replace] [--yes]
      Create or import a user-defined service (ids live under user-*)
  runfree service custom remove <id>
      Delete a user-defined service definition
  runfree service disable <id> [--local] [--no-reload]
      Remove the service's hosts unless another service, credential mapping, or
      request rule still requires them (this includes a host you allowlisted
      with 'runfree host add' first), and tear down any credential it added; a
      configured credential source is left for 'runfree credential clear-source'
  runfree service explain <id>
      Show a service's hosts, broad-host warnings, credential, origin, and enable state
  runfree service diff [--apply] [--no-reload]
      Compare approved resolved service semantics against this CLI's registry/definitions;
      --apply writes the reviewed entry to desired policy after one
      confirmation listing the exact edit

MCP servers:
  claude mcp ...                  Configure Claude Code MCP servers on the host with the native CLI
  codex mcp ...                   Configure Codex MCP servers on the host with the native CLI
  runfree mcp list [--json]       Show user, local, and project MCP entries with Runfree decisions
  runfree mcp configure [--agent <agent>]... [--server <name>]
                                  Configure MCP imports and tool-call rules interactively
  runfree mcp explain <agent> <server> [--source user|local|project] [--json]
                                  Show the normalized descriptor and import/approval decision
  runfree mcp approve <agent> <server> [--from-env ENV | --from-1password op://... | --from-source <name> | --from-stdin] [--replace-source] [--login]
                                  Approve a project-local MCP server; static headers require a host-owned credential source
  runfree mcp auth <agent> <server> [--source user|local|project]
                                  Run agent-native MCP OAuth login inside the validated runtime
  runfree mcp rules <agent> <server> [--source user|local|project] [--tool <tool>] [--write allow|ask|deny]
                                  Show or set side-effecting MCP tool-call handling rules
  runfree mcp revoke <agent> <server>
                                  Remove project-local MCP approval without editing project files
      Runfree imports supported host MCP entries when the sandbox starts and writes sanitized per-agent config.
      Agent IDs are claude (Claude Code) and codex (Codex CLI); configure --agent is repeatable.
      Project .mcp.json and .codex/config.toml entries are imported only after runfree mcp approve.

Proxy and diagnostics:
  runfree runtime reload-policy [--force]  Reload runtime policy and sync credentials; a proxy restart refuses live sessions unless --force
  runfree doctor [--post-failure] [--tail <lines>]
      Diagnose blocked proxy hosts from structured proxy denial events (with
      request counts, most recent first) and suggest exact host add/rules
      commands, including method widening for request-rule denials;
      blocked HTTPS requests also receive an in-tunnel 403 naming the host,
      and agent sessions print a denial summary on exit (suppress with --quiet)

Assets and updates:
  runfree assets status           Show installed embedded runtime asset location
  runfree assets clean            Remove old embedded runtime asset versions
  runfree update                  Print update guidance; does not replace the binary

Other:
  runfree version                 Print the Runfree version

Task guides — workflow how-tos, invoked as 'runfree help <topic>' (these are
help topics, not commands):
  runfree help quickstart         First run and common setup flow
  runfree help run                Starting, rebuilding, logs, and sessions
  runfree help network            Allowlist, request rules, audit mode, and doctor
  runfree help credentials        Sources, destinations, and proxy-managed credentials
  runfree help services           Curated host bundles
  runfree help mcp                MCP import and project approvals
  runfree help deps               Dependency overlays
  runfree help image              Project agent image customization
  runfree help diagnostics        Status, resources, assets, and updates

Examples:
${renderExampleCommands(helpAllExamples())}

Without --workspace, runfree uses the current project directory.`);
}
