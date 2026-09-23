// init-wizard.ts — interactive `runfree init` wizard.
//
// Runs only on a TTY without `--yes`; every other init invocation produces
// today's scaffold unchanged. Detection is read-only and never executes
// project code (see init-detect.ts); host credential helpers are resolved on
// the sanitized host PATH and are not executed at all (see host-path.ts). The
// wizard shows one consolidated plan with an interactive plan review, confirms
// repo-derived hostnames individually,
// applies only confirmed items through the same admin command paths as the
// manual CLI, writes nothing outside `.runfree/` and host-owned XDG config, and
// never starts the runtime. Declining everything leaves the
// scaffold exactly as `runfree init --yes` would.

import fs from "node:fs";

import {
  cancel as clackCancel,
  confirm as clackConfirm,
  intro,
  isCancel,
  log as clackLog,
  multiselect,
  note,
  outro,
  select,
} from "@clack/prompts";
import { validateDesiredNetworkPolicy } from "@runfree/runtime-contracts/desired-network-policy";

import {
  SERVICES,
  type Service,
  broadHostWarningLines,
  isUserServiceId,
  serviceBroadHosts,
  serviceHostNames,
} from "../../../scripts/services.ts";
import { combinedServiceRegistry } from "./user-services.ts";
import { parseTokenSourceConfig, tokenSourcesEqual } from "./admin/admin-core.ts";
import type { TokenSource } from "./admin/types.ts";
import { readRawProjectConfig } from "./config.ts";
import { agentChoiceLabel, defaultBuiltinAgentCommands } from "./agents.ts";
import { resolveHostHelper } from "./host-path.ts";
import {
  detectFileServices,
  detectGitRemotes,
  type GitRemoteDetection,
} from "./init-detect.ts";
import { safeReplaceProjectFile } from "./safe-fs.ts";
import { remedy } from "./remedies.ts";

const REPO_HOST_LABEL = "this hostname comes from the repo, not from Runfree";
const NO_CHANGES_MESSAGE = "No changes applied; the scaffold is unchanged.";
// The binding the gh plan items would create. Compared with the enforcement's
// own equality so the plan predicts exactly what `service enable` would do.
const GITHUB_CLI_SOURCE: TokenSource = { source: "named", name: "github-cli" };

export type WizardIO = {
  ask(question: string): Promise<string>;
  print(line: string): void;
};

export type WizardUiPlanSelection = {
  confirmed: boolean;
  enabledItemIndexes: Set<number>;
};

// A typed admin action a wizard plan item applies on confirm. The wizard builds
// these where the plan item is constructed; the init command's `admin` callback
// dispatches them straight to the typed `*Intent` enforcement — no argv strings
// are parsed in between. See the spec's "Programmatic callers speak intent, not
// strings." (`--no-reload` is implicit: the wizard never reloads runtime policy.)
export type WizardAdminIntent =
  | { kind: "service-enable"; id: string; fromSource?: string }
  | { kind: "allow-host"; host: string }
  | { kind: "source-add"; name: string; command: string[] };

// The exact `runfree` invocation an intent maps to, for plan-apply failure
// messages (display only; not parsed back into an intent). Every rendering
// must parse under the real command app: the remedy parse test in
// `scripts/emitted-commands.test.ts` runs each one through yargs.
export function describeWizardIntent(intent: WizardAdminIntent): string {
  switch (intent.kind) {
    case "service-enable":
      return `service enable ${intent.id}${intent.fromSource ? ` --from-source ${intent.fromSource}` : ""} --no-reload`;
    case "allow-host":
      return `host add ${intent.host} --no-reload`;
    case "source-add":
      return `credential source add ${intent.name} -- ${intent.command.join(" ")}`;
  }
}

export type WizardPlanItem = {
  kind: "service" | "allow-host" | "source" | "default-agent";
  label: string;
  // Extra display lines under the item (broad-host warnings, repo labels).
  notes: string[];
  // Typed admin actions applied on confirm, in order (empty for default-agent).
  intents: WizardAdminIntent[];
  enabled: boolean;
  // Repo-derived hostnames get an extra per-item confirmation even after the
  // plan-level yes; the host string is attacker-influenced.
  confirmIndividually?: { host: string };
  // Set on default-agent items.
  agent?: string;
};

export type InitWizardUi = {
  chooseAgent(agentNames: string[], defaultAgent: string): Promise<string | undefined>;
  showDetected(detection: WizardDetection): void;
  log(message: string): void;
  choosePlan(items: readonly WizardPlanItem[]): Promise<WizardUiPlanSelection | undefined>;
  confirmRepoHost(host: string, notes: readonly string[]): Promise<boolean | undefined>;
  itemApplied(item: WizardPlanItem): void;
  itemSkipped(item: WizardPlanItem): void;
  itemFailed(item: WizardPlanItem, intent: WizardAdminIntent, status: number): void;
  done(applied: number, failed: number): void;
  cancel(message: string): void;
};

export type WizardDetection = {
  fileServiceIds: string[];
  gitRemotes: GitRemoteDetection;
  ghAvailable: boolean;
  opAvailable: boolean;
  agent: string;
  defaultAgent: string;
  enabledServiceIds: string[];
  allowedHosts: string[];
  // Current credential bindings (token name -> host-owned source), read-only.
  // The planner consults them so it never plans a bind the enforcement would
  // refuse (a different source is already bound) or a bind that is a no-op.
  credentialBindings: Record<string, TokenSource>;
};

// Counts returned to the init command: `failed` decides its exit status.
export type InitWizardOutcome = {
  applied: number;
  failed: number;
};

// Provider services offered per agent choice. Disabled by default in the plan:
// both Claude Code and Codex normally use browser login through Runfree-managed
// state; enabling the API-key credential is an opt-in.
const AGENT_PROVIDER_SERVICE: Record<string, string | undefined> = {
  claude: "anthropic",
  codex: "openai",
  pi: undefined,
};

function servicePlanLabel(svc: Service): string {
  const broadCount = serviceBroadHosts(svc).length;
  const origin = isUserServiceId(svc.id) ? " user-defined (not curated by Runfree)" : "";
  if (broadCount > 0) {
    return `enable service ${svc.id}${origin} (${svc.hosts.length} hosts, ${broadCount} broad — see note below)`;
  }
  return `enable service ${svc.id}${origin} (${serviceHostNames(svc).join(", ")})`;
}

export function buildWizardPlan(
  detection: WizardDetection,
  registry: Record<string, Service> = SERVICES,
): WizardPlanItem[] {
  const items: WizardPlanItem[] = [];
  const allowed = new Set(detection.allowedHosts);
  const alreadyEnabled = new Set(detection.enabledServiceIds);

  const serviceIds = Array.from(new Set([...detection.fileServiceIds, ...detection.gitRemotes.serviceIds])).sort();
  for (const id of serviceIds) {
    const svc = registry[id];
    if (!svc || svc.neverAutoSuggest === true || alreadyEnabled.has(id)) continue;
    items.push({
      kind: "service",
      label: servicePlanLabel(svc),
      notes: [
        ...(isUserServiceId(svc.id) ? ["user-defined service: not curated by Runfree; disabled by default"] : []),
        ...broadHostWarningLines(serviceBroadHosts(svc)),
      ],
      intents: [{ kind: "service-enable", id: svc.id }],
      enabled: !isUserServiceId(svc.id),
    });
  }

  for (const remote of detection.gitRemotes.allowHosts) {
    if (allowed.has(remote.host)) continue;
    const notes = [REPO_HOST_LABEL];
    if (remote.punycode) notes.push("warning: contains a punycode (xn--) label; check for a lookalike hostname");
    items.push({
      kind: "allow-host",
      label: `allow ${remote.host}`,
      notes,
      intents: [{ kind: "allow-host", host: remote.host }],
      enabled: true,
      confirmIndividually: { host: remote.host },
    });
  }

  if (detection.ghAvailable) {
    const bound = detection.credentialBindings.github;
    // Already bound to github-cli: both items would be no-ops (the source must
    // exist while a binding uses it), so the plan omits them.
    if (bound === undefined || !tokenSourcesEqual(bound, GITHUB_CLI_SOURCE)) {
      const sourceNotes: string[] = [];
      if (bound !== undefined) {
        // A different source is bound. The wizard never replaces a credential
        // source (`replaceSource` stays false on its path), so it plans no bind
        // and points at the manual command that does replace, instead of
        // planning a step the enforcement is guaranteed to refuse.
        sourceNotes.push(
          `github credential already bound to ${describeBoundSource(bound)}; kept as is — to switch it, run: runfree service enable github --from-source github-cli --replace-source`,
        );
      }
      items.push({
        kind: "source",
        label: "add source github-cli (gh auth token)",
        notes: sourceNotes,
        intents: [{ kind: "source-add", name: "github-cli", command: ["gh", "auth", "token"] }],
        enabled: true,
      });
      if (bound === undefined) {
        items.push({
          kind: "service",
          label: "enable service github (token via source github-cli)",
          notes: [],
          intents: [{ kind: "service-enable", id: "github", fromSource: "github-cli" }],
          enabled: true,
        });
      }
    }
  }

  const providerService = AGENT_PROVIDER_SERVICE[detection.agent];
  if (providerService) {
    const sourceHint = detection.opAvailable
      ? `runfree service enable ${providerService} --from-1password op://...`
      : `runfree service enable ${providerService} --from-env <ENV>`;
    items.push({
      kind: "service",
      label: `enable service ${providerService} (API key for the ${detection.agent} agent)`,
      notes: [
        "off by default: browser login through Runfree-managed state needs no API key",
        `configure the token source afterwards, for example: ${sourceHint}`,
      ],
      intents: [{ kind: "service-enable", id: providerService }],
      enabled: false,
    });
  }

  if (detection.agent !== detection.defaultAgent) {
    items.push({
      kind: "default-agent",
      label: `set default agent to ${detection.agent}`,
      notes: [],
      intents: [],
      enabled: true,
      agent: detection.agent,
    });
  }

  return items;
}

export function detectedSummary(detection: WizardDetection): string {
  const parts: string[] = [];
  if (detection.fileServiceIds.length > 0) parts.push(`project files match services: ${detection.fileServiceIds.join(", ")}`);
  if (detection.gitRemotes.serviceIds.length > 0) parts.push(`git remotes match services: ${detection.gitRemotes.serviceIds.join(", ")}`);
  if (detection.gitRemotes.allowHosts.length > 0) {
    parts.push(`other git remote hosts: ${detection.gitRemotes.allowHosts.length}${detection.gitRemotes.truncated ? " (more omitted)" : ""}`);
  }
  if (detection.ghAvailable) parts.push("gh CLI on host PATH");
  if (detection.opAvailable) parts.push("1Password CLI on host PATH");
  return parts.length > 0 ? `Detected: ${parts.join("; ")}` : "Detected: nothing to suggest";
}

function readPolicyDomains(policyPath: string): string[] {
  try {
    const raw: unknown = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    return validateDesiredNetworkPolicy(raw).hosts;
  } catch {
    return [];
  }
}

function readEnabledServiceIds(policyPath: string): string[] {
  try {
    const raw: unknown = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    return Object.keys(validateDesiredNetworkPolicy(raw).services ?? {});
  } catch {
    return [];
  }
}

// Display form of an existing binding for the plan note (identity only; a
// 1Password ref or env name stays out of the plan text).
function describeBoundSource(source: TokenSource): string {
  switch (source.source) {
    case "env":
      return `env ${source.env}`;
    case "1password":
      return "1password";
    case "named":
      return `source ${source.name}`;
    case "cmd":
      return "a legacy command source";
    case "file":
      return "a legacy local-file source";
  }
}

// Read-only view of the host-owned credential bindings. A missing file is the
// common case on a fresh project and reads as no bindings. A malformed file
// also reads as no bindings here: the wizard then plans the bind and the
// enforcement reports the parse failure on that item, so nothing is hidden.
export function readCredentialBindings(tokenConfigPath: string): Record<string, TokenSource> {
  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(tokenConfigPath, "utf8"));
  } catch {
    return {};
  }
  try {
    return parseTokenSourceConfig(raw, tokenConfigPath);
  } catch {
    return {};
  }
}

function builtinAgentNames(): string[] {
  return Object.keys(defaultBuiltinAgentCommands());
}

function writeDefaultAgent(projectRoot: string, configPath: string, agent: string): void {
  const raw = readRawProjectConfig(projectRoot, configPath);
  const agents = typeof raw.agents === "object" && raw.agents !== null && !Array.isArray(raw.agents)
    ? raw.agents as Record<string, unknown>
    : {};
  raw.agents = { ...agents, default: agent };
  safeReplaceProjectFile(projectRoot, configPath, `${JSON.stringify(raw, null, 2)}\n`, 0o600);
}

export type InitWizardDeps = {
  projectRoot: string;
  env: NodeJS.ProcessEnv;
  policyPath: string;
  configPath: string;
  // Host-owned token binding file (`project.paths.tokenConfigPath`); read only.
  tokenConfigPath: string;
  defaultAgent: string;
  admin: (intent: WizardAdminIntent) => Promise<number>;
  io?: WizardIO;
  ui?: InitWizardUi;
  // Injectable for tests; defaults to sanitized-PATH resolution, without executing the helper.
  probeHelper?: (command: string) => boolean;
  // Injectable for tests; defaults to a read-only parse of `tokenConfigPath`.
  readCredentialBindings?: (tokenConfigPath: string) => Record<string, TokenSource>;
  registry?: Record<string, Service>;
};

const RELOAD_HINT = "Run `runfree runtime reload-policy` if a sandbox is already running.";
const LEGACY_RELOAD_HINT = `The policy was not reloaded; run \`${remedy.runtimeReloadPolicy()}\` if a sandbox is already running.`;

// The closing line is honest about partial failure: "Done." alone is reserved
// for a run where every selected item applied.
export function doneMessage(applied: number, failed: number, reloadHint: string): string {
  if (failed > 0) {
    const head = `Done with ${failed} failed item${failed === 1 ? "" : "s"}; see the failure${failed === 1 ? "" : "s"} above.`;
    return applied > 0 ? `${head} ${reloadHint}` : `${head} No other changes applied.`;
  }
  return applied > 0 ? `Done. ${reloadHint}` : NO_CHANGES_MESSAGE;
}

function defaultProbeHelper(deps: InitWizardDeps): (command: string) => boolean {
  return (command: string) => resolveHostHelper(deps.projectRoot, deps.env, command) !== undefined;
}

async function askYesNo(io: WizardIO, question: string, defaultYes: boolean): Promise<boolean> {
  const answer = (await io.ask(`${question} ${defaultYes ? "[Y/n]" : "[y/N]"} `)).trim().toLowerCase();
  if (answer === "") return defaultYes;
  return answer === "y" || answer === "yes";
}

function printPlan(io: WizardIO, items: readonly WizardPlanItem[]): void {
  io.print("Plan:");
  for (const [index, item] of items.entries()) {
    io.print(`  ${index + 1}. [${item.enabled ? "x" : " "}] ${item.label}`);
    for (const note of item.notes) io.print(`       ${note}`);
  }
}

function createLegacyInitWizardUi(io: WizardIO): InitWizardUi {
  return {
    chooseAgent: async (agentNames, defaultAgent) => {
      const choices = agentNames.map(agentChoiceLabel).join(" / ");
      return (await io.ask(`Agent [${choices}] (${agentChoiceLabel(defaultAgent)}): `)).trim().toLowerCase();
    },
    showDetected: (detection) => io.print(detectedSummary(detection)),
    log: (message) => io.print(message),
    choosePlan: async (items) => {
      const workingItems = items.map((item) => ({ ...item }));
      while (true) {
        printPlan(io, workingItems);
        const answer = (await io.ask("Apply? [y/N/edit] ")).trim().toLowerCase();
        if (answer === "edit" || answer === "e") {
          for (const item of workingItems) {
            item.enabled = await askYesNo(io, `  ${item.label}?`, item.enabled);
          }
          continue;
        }
        if (answer === "y" || answer === "yes") {
          return {
            confirmed: true,
            enabledItemIndexes: new Set(
              workingItems
                .map((item, index) => item.enabled ? index : -1)
                .filter((index) => index >= 0),
            ),
          };
        }
        return undefined;
      }
    },
    confirmRepoHost: async (host, notes) => {
      io.print(`${host} — ${notes.join("; ")}`);
      return askYesNo(io, `allow ${host}?`, false);
    },
    itemApplied: (item) => io.print(`applied: ${item.label}`),
    itemSkipped: (item) => io.print(`skipped: ${item.label}`),
    itemFailed: (_item, intent, status) => {
      io.print(`failed: runfree ${describeWizardIntent(intent)} (exit ${status})`);
    },
    done: (applied, failed) => io.print(doneMessage(applied, failed, LEGACY_RELOAD_HINT)),
    cancel: (message) => io.print(message),
  };
}

function planHint(item: WizardPlanItem): string | undefined {
  if (item.confirmIndividually) return "repo host; confirm separately";
  if (!item.enabled) return "off by default";
  if (item.notes.length > 0) return "review notes";
  return undefined;
}

function createClackInitWizardUi(): InitWizardUi {
  return {
    chooseAgent: async (agentNames, defaultAgent) => {
      intro("runfree init");
      const selected = await select<string>({
        message: "Agent",
        initialValue: defaultAgent,
        options: agentNames.map((agent) => ({
          value: agent,
          label: agentChoiceLabel(agent),
        })),
      });
      if (isCancel(selected)) return undefined;
      return selected;
    },
    showDetected: (detection) => {
      clackLog.info(detectedSummary(detection));
    },
    log: (message) => clackLog.info(message),
    choosePlan: async (items) => {
      const noteLines = items.flatMap((item, index) => item.notes.map((line) => `${index + 1}. ${item.label}: ${line}`));
      if (noteLines.length > 0) note(noteLines.join("\n"), "Review notes");
      const selected = await multiselect<number>({
        message: "Configure Runfree",
        options: items.map((item, index) => ({
          value: index,
          label: item.label,
          hint: planHint(item),
        })),
        initialValues: items
          .map((item, index) => item.enabled ? index : -1)
          .filter((index) => index >= 0),
        required: false,
      });
      if (isCancel(selected)) return undefined;
      return {
        confirmed: true,
        enabledItemIndexes: new Set(selected),
      };
    },
    confirmRepoHost: async (host, notes) => {
      note(notes.join("\n"), `Repo host: ${host}`);
      const confirmed = await clackConfirm({
        message: `Allow ${host}?`,
        initialValue: false,
      });
      if (isCancel(confirmed)) return undefined;
      return confirmed;
    },
    itemApplied: (item) => clackLog.success(`applied: ${item.label}`),
    itemSkipped: (item) => clackLog.warn(`skipped: ${item.label}`),
    itemFailed: (item, intent, status) => {
      clackLog.error(`failed: ${item.label}: runfree ${describeWizardIntent(intent)} exited ${status}`);
    },
    done: (applied, failed) => outro(doneMessage(applied, failed, RELOAD_HINT)),
    cancel: (message) => clackCancel(message),
  };
}

export async function runInitWizard(deps: InitWizardDeps): Promise<InitWizardOutcome> {
  const registry = deps.registry ?? combinedServiceRegistry(deps.projectRoot, deps.env);
  const ui = deps.ui ?? (deps.io ? createLegacyInitWizardUi(deps.io) : createClackInitWizardUi());
  const probe = deps.probeHelper ?? defaultProbeHelper(deps);
  const readBindings = deps.readCredentialBindings ?? readCredentialBindings;
  const nothing: InitWizardOutcome = { applied: 0, failed: 0 };

  // Agent choice (claude / codex / pi), defaulting to current behavior.
  const agentNames = builtinAgentNames();
  const agentAnswer = await ui.chooseAgent(agentNames, deps.defaultAgent);
  if (agentAnswer === undefined) {
    ui.cancel(NO_CHANGES_MESSAGE);
    return nothing;
  }
  const normalizedAgentAnswer = agentAnswer.trim().toLowerCase();
  const agent = normalizedAgentAnswer === "" ? deps.defaultAgent : normalizedAgentAnswer;
  if (agent !== deps.defaultAgent && !agentNames.includes(agent)) {
    ui.log(`unknown agent ${JSON.stringify(agentAnswer)}; keeping ${deps.defaultAgent}`);
  }

  const detection: WizardDetection = {
    fileServiceIds: detectFileServices(deps.projectRoot, registry),
    gitRemotes: detectGitRemotes(deps.projectRoot, registry),
    ghAvailable: probe("gh"),
    opAvailable: probe("op"),
    agent: agentNames.includes(agent) ? agent : deps.defaultAgent,
    defaultAgent: deps.defaultAgent,
    enabledServiceIds: readEnabledServiceIds(deps.policyPath),
    allowedHosts: readPolicyDomains(deps.policyPath),
    credentialBindings: readBindings(deps.tokenConfigPath),
  };

  ui.showDetected(detection);
  if (detection.opAvailable) {
    ui.log("note: 1Password CLI detected; token sources can use --from-1password op://...");
  }

  const items = buildWizardPlan(detection, registry);
  if (items.length === 0) {
    ui.log("Nothing to configure beyond the scaffold. You can enable services later with: runfree service list");
    return nothing;
  }

  const selection = await ui.choosePlan(items);
  if (!selection?.confirmed) {
    ui.cancel(NO_CHANGES_MESSAGE);
    return nothing;
  }

  const selectedItems = items
    .map((item, index) => ({ item, index }))
    .filter(({ index }) => selection.enabledItemIndexes.has(index));
  const skippedIndexes = new Set<number>();
  for (const { item, index } of selectedItems) {
    if (!item.confirmIndividually) continue;
    const confirmed = await ui.confirmRepoHost(item.confirmIndividually.host, item.notes);
    if (confirmed === undefined) {
      ui.cancel(NO_CHANGES_MESSAGE);
      return nothing;
    }
    if (!confirmed) {
      ui.itemSkipped(item);
      skippedIndexes.add(index);
    }
  }

  let applied = 0;
  let failedCount = 0;
  for (const { item, index } of selectedItems) {
    if (skippedIndexes.has(index)) continue;
    if (item.kind === "default-agent" && item.agent) {
      writeDefaultAgent(deps.projectRoot, deps.configPath, item.agent);
      ui.itemApplied(item);
      applied += 1;
      continue;
    }
    let failed = false;
    for (const intent of item.intents) {
      const status = await deps.admin(intent);
      if (status !== 0) {
        ui.itemFailed(item, intent, status);
        failed = true;
        break;
      }
    }
    if (failed) {
      failedCount += 1;
    } else {
      ui.itemApplied(item);
      applied += 1;
    }
  }

  ui.done(applied, failedCount);
  return { applied, failed: failedCount };
}
