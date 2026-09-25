import path from "node:path";

import { isCancel, select } from "@clack/prompts";
import type { ArgumentsCamelCase } from "yargs";

import { assertProjectPolicy, projectInfo } from "../config.ts";
import { die } from "../errors.ts";
import {
  formatRecoveryInventory,
  recoveryIdIsValid,
  recoveryInventoryJson,
  scanRecoveryInventory,
  type RecoveryItem,
} from "../runtime/recovery.ts";
import type { RuntimeContext } from "../runtime/types.ts";
import { nodeRuntimeIO, resumeRecoveryRuntime } from "../runtime.ts";
import { sanitizeForTerminal } from "../../../../scripts/domain-diagnostics.ts";
import type { RunfreeCommandContext } from "./context.ts";
import { withExamples } from "./examples.ts";
import type { CommandHandlerFactory, CommandModule } from "./types.ts";

type ResumeArgs = {
  id?: string;
  agent?: string[];
  all?: boolean;
  list?: boolean;
  json?: boolean;
  project?: string;
  quiet?: boolean;
  verbose?: boolean;
};

function contextForRecoveryItem(context: RunfreeCommandContext, item: RecoveryItem): RuntimeContext {
  if (!item.projectRoot) die(`recovery item ${item.id} has no valid project mapping`);
  const projectRoot = path.resolve(item.projectRoot);
  const project = projectInfo(projectRoot, context.env);
  assertProjectPolicy(project);
  if (project.paths.stateDir !== item.stateDir) {
    die(`recovery item ${item.id} does not belong to the validated project state directory`);
  }
  return {
    projectRoot,
    project,
    runtimeRoot: context.assets().runtimeDir,
    env: context.env,
  };
}

function pickerLabel(item: RecoveryItem): string {
  const project = sanitizeForTerminal(item.projectName).slice(0, 40);
  const agent = sanitizeForTerminal(item.agent).slice(0, 24);
  const conversation = sanitizeForTerminal(item.conversationName ?? item.conversationId ?? item.sourceId).slice(0, 80);
  return `${project} — ${agent} — ${conversation} (${item.state})`;
}

async function selectedRecoveryItem(
  inventory: ReturnType<typeof scanRecoveryInventory>,
  requestedId: string | undefined,
): Promise<RecoveryItem | undefined> {
  if (requestedId !== undefined) {
    if (!recoveryIdIsValid(requestedId)) die(`invalid recovery id: ${requestedId}`);
    const item = inventory.items.find((candidate) => candidate.id === requestedId);
    if (!item) die(`recovery item not found: ${requestedId}`);
    return item;
  }
  const actionable = inventory.items.filter((item) => item.state === "unverified" || item.state === "interrupted");
  if (actionable.length === 0) return undefined;
  const choice = await select({
    message: "Resume which interrupted session?",
    options: actionable.map((item) => ({ value: item.id, label: pickerLabel(item) })),
  });
  if (isCancel(choice)) return undefined;
  return actionable.find((item) => item.id === choice);
}

export const resumeCommand: CommandModule = {
  name: "resume",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "resume [id]",
      "List or resume interrupted Runfree sessions for the current project",
      (cmd) =>
        withExamples(cmd
          .positional("id", { type: "string", describe: "Recovery item id to resume" })
          .option("agent", {
            type: "string",
            array: true,
            requiresArg: true,
            nargs: 1,
            describe: "Include only this agent (repeatable; e.g. claude or codex)",
          })
          .option("all", { type: "boolean", describe: "Include interrupted sessions from all Runfree projects" })
          .option("list", { type: "boolean", describe: "List recovery evidence without Docker or filesystem mutation" })
          .option("json", { type: "boolean", describe: "Print the read-only recovery inventory as JSON" })
          .option("project", { type: "string", describe: "Restrict inventory to one project path" })
          .option("quiet", { type: "boolean", describe: "Suppress post-session denial summary" })
          .option("verbose", { type: "boolean", alias: "v", describe: "Show extra startup diagnostics" })
          .conflicts("json", "list")
          .conflicts("all", "project")
          .strict(), "resume")
          .epilogue("Defaults to the current project. Use --all for every project. Without an id, a terminal shows a picker; non-interactive use defaults to --list."),
      handler(async (argv: ArgumentsCamelCase<ResumeArgs>) => {
        const projectRoot = argv.all
          ? undefined
          : argv.project
            ? path.resolve(context.invocationCwd, argv.project)
            : context.projectRoot;
        const scannedInventory = scanRecoveryInventory({ env: context.env, projectRoot });
        const selectedAgents = argv.agent?.length ? new Set(argv.agent) : undefined;
        const inventory = selectedAgents
          ? {
              ...scannedInventory,
              items: scannedInventory.items.filter((item) => selectedAgents.has(item.agent)),
            }
          : scannedInventory;
        if (argv.json) {
          process.stdout.write(recoveryInventoryJson(inventory));
          return 0;
        }
        if (argv.list || (!process.stdin.isTTY && argv.id === undefined)) {
          console.log(formatRecoveryInventory(inventory));
          return 0;
        }
        const item = await selectedRecoveryItem(inventory, argv.id);
        if (!item) {
          console.log(formatRecoveryInventory(inventory));
          return 0;
        }
        const runtimeContext = contextForRecoveryItem(context, item);
        return resumeRecoveryRuntime(runtimeContext, nodeRuntimeIO, item, {
          quiet: Boolean(argv.quiet),
          verbose: Boolean(argv.verbose),
        });
      }),
    ),
};
