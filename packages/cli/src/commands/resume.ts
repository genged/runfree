import path from "node:path";

import { isCancel, select } from "@clack/prompts";
import type { ArgumentsCamelCase } from "yargs";

import { assertProjectPolicy, projectInfo } from "../config.ts";
import { die } from "../errors.ts";
import {
  dismissRecoveryItem,
  formatRecoveryInventory,
  recoveryIdIsValid,
  recoveryInventoryJson,
  scanRecoveryInventory,
  type RecoveryInventory,
  type RecoveryItem,
} from "../runtime/recovery.ts";
import { formatResumeRow, selectResumeCandidates, type ResumeSelection } from "../runtime/resume-selection.ts";
import type { RuntimeContext } from "../runtime/types.ts";
import { nodeRuntimeIO, resumeRecoveryRuntime } from "../runtime.ts";
import { currentTerminal, promptResumeSelection, type PromptApi } from "./resume-prompt.ts";
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

function runResume(
  context: RunfreeCommandContext,
  item: RecoveryItem,
  argv: ArgumentsCamelCase<ResumeArgs>,
): Promise<number> {
  const runtimeContext = contextForRecoveryItem(context, item);
  return resumeRecoveryRuntime(runtimeContext, nodeRuntimeIO, item, {
    quiet: Boolean(argv.quiet),
    verbose: Boolean(argv.verbose),
  });
}

// "Forget it" (spec section 5, "After the choice"): dismisses the item
// instead of resuming it. `dismissRecoveryItem` races a concurrent claim or
// lifecycle change the same way a resume does, so every non-"dismissed"
// result is a refusal, not a silent no-op.
async function handleDismiss(context: RunfreeCommandContext, item: RecoveryItem): Promise<number> {
  const result = await dismissRecoveryItem(contextForRecoveryItem(context, item), item);
  if (result === "dismissed") {
    console.log(`forgot the interrupted session from ${shortTime(item)}`);
    return 0;
  }
  if (result === "claimed") die("another terminal is resuming this session");
  if (result === "changed") die("the session record changed; run runfree resume again");
  die("a runtime lifecycle change is in progress; run runfree resume again");
}

// Mirrors `resume-selection.ts`'s own (private) host-field time formatting:
// the dismiss confirmation names the record by that same clock face, after
// `promptResumeSelection` has already reduced the choice to a bare
// `RecoveryItem` and lost the `ResumeRow` the time was first rendered onto.
function shortTime(item: RecoveryItem): string {
  const value = item.updatedAt ?? item.startedAt;
  const parsed = value ? Date.parse(value) : Number.NaN;
  return Number.isFinite(parsed) ? new Date(parsed).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "-";
}

function recoveryItemById(inventory: RecoveryInventory, requestedId: string): RecoveryItem {
  if (!recoveryIdIsValid(requestedId)) die(`invalid recovery id: ${requestedId}`);
  const item = inventory.items.find((candidate) => candidate.id === requestedId);
  if (!item) die(`recovery item not found: ${requestedId}`);
  return item;
}

function filterByAgents(inventory: RecoveryInventory, selectedAgents: Set<string> | undefined): RecoveryInventory {
  if (!selectedAgents) return inventory;
  return { ...inventory, items: inventory.items.filter((item) => selectedAgents.has(item.agent)) };
}

// `--all`/`--project` keep the plain, single-step picker Runfree had before
// same-terminal resume (spec section 3, "Scope": only bare `runfree resume`
// ever asks the one question or shows the labelled two-step picker). Rows
// are still built, filtered, and ordered by `selectResumeCandidates`, with a
// terminal identity that cannot match anything, so a row's `match` is always
// "none" — never "strong" — and the one question can never trigger here.
async function selectFromLabelledPicker(
  items: readonly RecoveryItem[],
  api: PromptApi,
): Promise<RecoveryItem | undefined> {
  const selection = selectResumeCandidates({ items, current: { ids: {} }, now: new Date() });
  if (selection.kind !== "picker") return undefined;
  const choice = await api.select({
    message: "Resume which interrupted session?",
    options: selection.rows.map((row) => ({ value: row.item.id, label: formatResumeRow(row) })),
    initialValue: selection.defaultItemId,
  });
  if (api.isCancel(choice)) return undefined;
  return selection.rows.find((row) => row.item.id === choice)?.item;
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
        const selectedAgents = argv.agent?.length ? new Set(argv.agent) : undefined;
        const inventory = filterByAgents(scanRecoveryInventory({ env: context.env, projectRoot }), selectedAgents);

        if (argv.json) {
          process.stdout.write(recoveryInventoryJson(inventory));
          return 0;
        }

        // Spec section 3, "TTY": both stdin and stdout must be terminals, or
        // `runfree resume` prints the list as it does today.
        const tty = process.stdin.isTTY === true && process.stdout.isTTY === true;
        if (argv.list || (!tty && argv.id === undefined)) {
          console.log(formatRecoveryInventory(inventory));
          return 0;
        }

        if (argv.id !== undefined) {
          return runResume(context, recoveryItemById(inventory, argv.id), argv);
        }

        const promptApi: PromptApi = context.promptApi ?? { select, isCancel };

        if (argv.all || argv.project !== undefined) {
          const item = await selectFromLabelledPicker(inventory.items, promptApi);
          if (!item) {
            console.log(formatRecoveryInventory(inventory));
            return 0;
          }
          return runResume(context, item, argv);
        }

        // Scope: only the current project, and only `runfree resume` without
        // `--all` or `--project` (spec section 3). This is the only path that
        // ever asks the one question, and the only scan that ever opens
        // Codex rollout files (review F5): `includeCodexMatches` ships Codex
        // C1 time-match rows into the picker (decision 4), never the one
        // question.
        let selection: ResumeSelection;
        try {
          const interactive = filterByAgents(
            scanRecoveryInventory({ env: context.env, projectRoot, includeCodexMatches: true }),
            selectedAgents,
          );
          selection = selectResumeCandidates({
            items: interactive.items,
            current: currentTerminal(context, nodeRuntimeIO),
            now: new Date(),
          });
        } catch {
          // A scan or selection failure prints the list without a question,
          // same as every other read-only recovery failure.
          console.log(formatRecoveryInventory(inventory));
          return 0;
        }

        const choice = await promptResumeSelection(selection, promptApi);
        if (choice.kind === "cancel") {
          console.log(formatRecoveryInventory(inventory));
          return 0;
        }
        if (choice.kind === "dismiss") return handleDismiss(context, choice.item);
        return runResume(context, choice.item, argv);
      }),
    ),
};
