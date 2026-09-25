// Single source of truth for command examples.
//
// The Help Contract requires that a command/group's own `--help` examples and
// the `runfree help all` reference derive from one place so they cannot drift.
// Command modules apply their slice as native yargs examples (via `withExamples`)
// and `help all` renders its examples section from the same data (via
// `renderExampleCommands`). See the spec's "Help Model → Help Contract".
//
// Aside from the yargs `Argv` type (type-only), this module has no heavy imports
// so both the command layer and the task-help layer can depend on it without
// pulling in the runtime/admin graph.

import type { Argv } from "yargs";

export type CommandExample = {
  // The exact invocation a user would type.
  cmd: string;
  // One-line description shown beside the invocation in command/group help.
  blurb: string;
};

// Keyed by command-module name (e.g. "service", "credential"). `default` and `init`
// carry the top-level runtime/setup examples used only by `help all`.
export const COMMAND_EXAMPLES = {
  default: [
    { cmd: "runfree", blurb: "Start or reuse the sandbox with the default agent" },
    { cmd: "runfree claude", blurb: "Start or reuse the sandbox with Claude" },
    { cmd: "runfree codex", blurb: "Start or reuse the sandbox with Codex" },
    { cmd: "runfree pi", blurb: "Start or reuse the sandbox with Pi" },
    { cmd: "runfree shell", blurb: "Open a shell in the agent container" },
  ],
  init: [
    { cmd: "runfree init", blurb: "Scaffold this project's .runfree config (wizard on a TTY)" },
  ],
  image: [
    { cmd: "runfree image init", blurb: "Create .runfree/image/Dockerfile and configure runtime.agent.build" },
    { cmd: "runfree image approve-context", blurb: "Approve a configured wide agent image build context in host state" },
  ],
  inbox: [
    { cmd: "runfree inbox paste", blurb: "Import a macOS clipboard image and print its container path" },
    { cmd: "runfree inbox paste --copy", blurb: "Also copy the container path to the host clipboard" },
    { cmd: "runfree inbox clean", blurb: "Remove imported files older than 24 hours" },
    { cmd: "runfree inbox clean --all", blurb: "Remove every Runfree-minted inbox file" },
  ],
  resume: [
    { cmd: "runfree resume", blurb: "Pick an interrupted session from the current project" },
    { cmd: "runfree resume --list", blurb: "List current-project recovery evidence without contacting Docker" },
    { cmd: "runfree resume --agent claude", blurb: "Show only interrupted Claude Code sessions" },
    { cmd: "runfree resume --agent codex", blurb: "Show only interrupted Codex sessions" },
    { cmd: "runfree resume --all", blurb: "Pick from interrupted sessions across all Runfree projects" },
    { cmd: "runfree resume --all --json", blurb: "Print the offline cross-project inventory as JSON" },
  ],
  up: [
    { cmd: "runfree up", blurb: "Start the Docker Compose runtime" },
    { cmd: "runfree up --verbose", blurb: "Start with extra startup diagnostics" },
    { cmd: "runfree up --audit-network", blurb: "Start, then permit+log non-allowlisted HTTPS for the default window" },
    { cmd: "runfree up --audit-network=2h", blurb: "Start, then audit non-allowlisted HTTPS for 2 hours (max 8h)" },
    { cmd: "runfree up --audit-network 2h", blurb: "Same as the =2h form" },
  ],
  approvals: [
    { cmd: "runfree approvals", blurb: "List writes held for approval and pick decisions interactively" },
    { cmd: "runfree approvals --watch", blurb: "Stay attached as the approver; prompt as held writes arrive" },
    { cmd: "runfree approvals --clear-deny", blurb: "Undo a \"stop asking\" decision and hold writes for approval again" },
    { cmd: "runfree approvals --clear-deny --watch", blurb: "Undo it, then stay attached as the approver" },
  ],
  approve: [
    { cmd: "runfree approve a1b2c3d4", blurb: "Approve one held write (this request only)" },
    { cmd: "runfree approve a1b2 --scope session", blurb: "Approve writes to that host for the rest of that session" },
    { cmd: "runfree approve a1b2 --scope session --ttl 15m", blurb: "Approve session writes to that host for 15 minutes" },
    { cmd: "runfree approve a1b2 --deny", blurb: "Deny the held write" },
  ],
  audit: [
    { cmd: "runfree audit status", blurb: "Show whether network audit mode is active and its expiry" },
    { cmd: "runfree audit report", blurb: "Summarize non-allowlisted HTTPS hosts observed during audit" },
    { cmd: "runfree audit report --json", blurb: "Emit the observed-host report as JSON" },
    { cmd: "runfree audit off", blurb: "Disable network audit mode immediately" },
  ],
  deps: [
    { cmd: "runfree deps", blurb: "Show the dependency overlay plan" },
    { cmd: "runfree deps plan", blurb: "Show which dependency overlays would be mounted" },
    { cmd: "runfree deps install", blurb: "Install project dependencies into the overlay volumes" },
    { cmd: "runfree deps doctor", blurb: "Report dependency overlay drift" },
    { cmd: "runfree deps reset --force", blurb: "Remove this project's Runfree dependency volumes without confirming" },
  ],
  rebuild: [
    { cmd: "runfree rebuild", blurb: "Rebuild/recreate the runtime (confirms before killing active sessions)" },
    { cmd: "runfree rebuild --yes", blurb: "Skip the confirmation prompt" },
    { cmd: "runfree rebuild --verbose", blurb: "Show extra startup diagnostics" },
  ],
  runtime: [
    { cmd: "runfree runtime reload-policy", blurb: "Reload runtime policy and sync proxy-managed tokens" },
  ],
  logs: [
    { cmd: "runfree logs proxy", blurb: "Follow the proxy container logs" },
    { cmd: "runfree logs proxy --verbose", blurb: "Also log allowed proxy request metadata while following" },
  ],
  git: [
    { cmd: "runfree git repair-worktree-links", blurb: "Repair host Git metadata to use relative worktree links" },
  ],
  vnc: [
    { cmd: "runfree vnc", blurb: "Start x11vnc and forward vnc://127.0.0.1:5901 to the agent" },
    { cmd: "runfree vnc stop", blurb: "Remove this project's vnc forward sidecar(s)" },
    { cmd: "runfree vnc status", blurb: "Show this project's vnc forward sidecar(s)" },
    { cmd: "runfree vnc restart --host-port 5902", blurb: "Replace the forwarder on a different host port" },
  ],
  forward: [
    { cmd: "runfree forward 3000", blurb: "Publish 127.0.0.1:3000 to the agent's :3000 (preview a dev server)" },
    { cmd: "runfree forward 8080 --agent-port 3000", blurb: "Publish a different host port than the agent port" },
    { cmd: "runfree forward 3000 stop", blurb: "Close one port forward" },
    { cmd: "runfree forward stop", blurb: "Close all of this project's port forwards" },
    { cmd: "runfree forward status", blurb: "List this project's open port forwards" },
  ],
  host: [
    { cmd: "runfree host add api.github.com", blurb: "Allow an exact host" },
    { cmd: "runfree host add pypi.org --read-only", blurb: "Allow a host, GET/HEAD/OPTIONS only" },
    { cmd: "runfree host rules api.example.com --method GET --method POST", blurb: "Allow only specific methods (repeatable)" },
    { cmd: "runfree host rules github.com --deny-git-push", blurb: "Allow the host but block git push" },
    { cmd: "runfree host remove api.github.com", blurb: "Remove an unreferenced host" },
    { cmd: "runfree host list", blurb: "List allowlisted hosts" },
    { cmd: "runfree host explain api.github.com", blurb: "Show allowlist status, credentials, and request rules" },
    { cmd: "runfree host rules api.github.com", blurb: "Show the host's request rules (--clear removes them)" },
    { cmd: "runfree host rules api.github.com --write ask", blurb: "Hold writes to this host for approval" },
  ],
  credential: [
    { cmd: "runfree credential source add github-cli -- gh auth token", blurb: "Add a reusable host-owned command source" },
    { cmd: "runfree host add api.github.com", blurb: "Allow a custom credential destination first" },
    { cmd: "runfree credential add github --host api.github.com --from-source github-cli", blurb: "Create a credential destination and bind its source" },
    { cmd: "runfree credential link github --host uploads.github.com", blurb: "Add another already-allowlisted destination" },
    { cmd: "runfree credential unlink github --host uploads.github.com", blurb: "Remove one destination" },
    { cmd: "runfree credential set-source github --from-source github-cli", blurb: "Change the host-owned source binding" },
    { cmd: "runfree credential status", blurb: "Show credential ownership, destinations, source, and sync state" },
    { cmd: "runfree credential sync --watch", blurb: "Keep proxy-only values reconciled" },
  ],
  service: [
    { cmd: "runfree service list", blurb: "List enabled services" },
    { cmd: "runfree service list --all", blurb: "List every curated and user-defined service with its enable state" },
    { cmd: "runfree service enable github --from-source github-cli", blurb: "Allow a service and bind a host-owned credential" },
    { cmd: "runfree service enable node", blurb: "Allow an ecosystem service (no credential)" },
    { cmd: "runfree service enable apple-ads --from-source apple-ads-jwt --param client-id=SEARCHADS.<uuid>", blurb: "Bind an OAuth seed and supply a declared non-secret parameter" },
    { cmd: "runfree service configure github", blurb: "Guided service setup on a TTY" },
    { cmd: "runfree service custom add user-internal-api --from-file ./service.json", blurb: "Import a user-defined service" },
    { cmd: "runfree service disable github", blurb: "Remove a service's hosts and credential" },
    { cmd: "runfree service explain github", blurb: "Show a service's hosts, credential, and warnings" },
    { cmd: "runfree service diff --apply", blurb: "Reconcile recorded service revisions with this CLI" },
  ],
  mcp: [
    { cmd: "runfree mcp list", blurb: "Show user/local/project MCP entries and decisions" },
    { cmd: "runfree mcp configure", blurb: "Configure MCP imports and tool-call rules interactively" },
    { cmd: "runfree mcp configure --agent claude", blurb: "Configure only Claude Code MCP entries" },
    { cmd: "runfree mcp explain claude my-server", blurb: "Show the normalized descriptor and import decision" },
    { cmd: "runfree mcp approve claude my-server --from-source op-token", blurb: "Approve a project-local server" },
    { cmd: "runfree mcp auth claude my-server", blurb: "Run MCP OAuth login inside the validated runtime" },
    { cmd: "runfree mcp rules claude my-server --tool create_issue --write ask", blurb: "Hold one side-effecting tool for approval" },
    { cmd: "runfree mcp revoke claude my-server", blurb: "Remove a project-local MCP approval" },
  ],
  doctor: [
    { cmd: "runfree doctor", blurb: "Diagnose blocked proxy hosts from recent proxy logs" },
    { cmd: "runfree doctor --tail 500", blurb: "Scan more proxy log lines" },
    { cmd: "runfree doctor --post-failure", blurb: "Quiet mode for end-of-session hooks" },
  ],
} satisfies Record<string, readonly CommandExample[]>;

export type CommandExampleKey = keyof typeof COMMAND_EXAMPLES;

const INDENT = "  ";

// Apply a command/group's examples to its yargs builder as native `.example()`
// entries, so `runfree <command> --help` shows them. Single-sourced with the
// `help all` reference (both read COMMAND_EXAMPLES), so they cannot drift.
export function withExamples(cmd: Argv, key: CommandExampleKey): Argv {
  let out = cmd;
  for (const e of COMMAND_EXAMPLES[key]) out = out.example(e.cmd, e.blurb);
  return out;
}

// Render bare invocations (no blurbs) for the `runfree help all` examples list.
export function renderExampleCommands(examples: readonly CommandExample[]): string {
  return examples.map((e) => `${INDENT}${e.cmd}`).join("\n");
}

// Order the `help all` examples section walks. Keeps the single source flat while
// presenting setup → runtime → policy → credentials → diagnostics.
const HELP_ALL_ORDER: readonly CommandExampleKey[] = [
  "init",
  "image",
  "default",
  "inbox",
  "vnc",
  "forward",
  "logs",
  "up",
  "approvals",
  "approve",
  "rebuild",
  "runtime",
  "audit",
  "deps",
  "git",
  "host",
  "credential",
  "service",
  "mcp",
  "doctor",
];

// The flattened example list for `runfree help all`, derived from the same
// per-command data the group/leaf usage blocks use.
export function helpAllExamples(): readonly CommandExample[] {
  return HELP_ALL_ORDER.flatMap((key) => COMMAND_EXAMPLES[key]);
}
