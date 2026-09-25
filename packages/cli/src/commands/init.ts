// `runfree init [--yes]` — scaffold this project's `.runfree` config and
// optionally run the interactive setup wizard.
//
// Typed command module: yargs validates the grammar (only --yes/-y), then the
// handler ensures the project, prints the scaffold,
// and — only on a TTY without --yes — runs the wizard (exit 1 when any wizard
// item failed to apply; the scaffold is complete either way). When the desired project
// policy carries authority no approved base covers (desired drift, or a
// hand-written policy), the handler first runs the same
// exact-review approval as `runfree policy approve --project`; declining skips
// the wizard. The wizard's apply step runs through the typed `*Intent`
// enforcement within a single admin state (see `dispatchDesiredWizardAdmin`);
// there is no legacy `runAdmin` / string dispatcher.

import fs from "node:fs";

import type { ArgumentsCamelCase } from "yargs";

import {
  canonicalDesiredNetworkPolicy,
  validateDesiredNetworkPolicy,
} from "@runfree/runtime-contracts/desired-network-policy";
import { createAdminState } from "../admin/context.ts";
import {
  bindDesiredServiceCredentialSources,
  promptForMissingServiceParameters,
  planDesiredServiceEnable,
  runAdminAction,
  sourceAddCommandIntent,
} from "../admin/options.ts";
import { serviceHostState } from "../admin/service-policy.ts";
import type { AdminState } from "../admin/types.ts";
import {
  type ProjectInfo,
  resolveDefaultAgentName,
} from "../config.ts";
import { readApprovedNetworkPolicy } from "../control/approvals.ts";
import { mutateDesiredHost } from "../control/local-host-mutation.ts";
import { mutateDesiredService } from "../control/service-mutation.ts";
import { approveNetworkControl } from "../control/workflow.ts";
import { runInitWizard, type WizardAdminIntent } from "../init-wizard.ts";
import { nodeRuntimeIO } from "../runtime.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import type { RunfreeCommandContext } from "./context.ts";
import { withExamples } from "./examples.ts";
import { printApprovalReview } from "./policy.ts";
import type { CommandHandlerFactory, CommandModule } from "./types.ts";

/** Apply a wizard action through a quiesced desired-policy transaction. The
 * wizard builds the typed intent at its call site, so there is no argv string
 * to parse here, and it never reloads runtime policy (reloadProxy:false). */
export async function dispatchDesiredWizardAdmin(
  intent: WizardAdminIntent,
  context: RuntimeContext,
  io: RuntimeIO,
): Promise<void> {
  switch (intent.kind) {
    case "service-enable": {
      const plan = planDesiredServiceEnable(await promptForMissingServiceParameters({
        id: intent.id,
        tokenSource: intent.fromSource ? { kind: "named", name: intent.fromSource } : { kind: "none" },
        fromOnePasswordItem: undefined,
        replaceSource: false,
        skipBroad: false,
        reloadProxy: false,
      }, { interactive: Boolean(process.stdin.isTTY && process.stdout.isTTY) }));
      await mutateDesiredService(context, io, "project", {
        kind: "enable",
        id: plan.id,
        entry: plan.entry,
      }, serviceHostState(plan.id, () => { bindDesiredServiceCredentialSources(plan, false); }));
      return;
    }
    case "allow-host": {
      const hostResult = await mutateDesiredHost(context, io, "project", {
        kind: "add",
        host: intent.host,
      });
      for (const warning of hostResult.warnings) console.log(`warning: ${warning}`);
      return;
    }
    case "source-add":
      sourceAddCommandIntent({
        name: intent.name,
        replaceSource: false,
        command: intent.command,
      });
      return;
  }
}

/** Run one wizard intent through the shared admin wrapper. Enforcement errors
 * become a nonzero status so the wizard reports the failed plan item and keeps
 * applying the rest instead of crashing init mid-plan. */
export async function runWizardAdminIntent(
  adminState: AdminState,
  intent: WizardAdminIntent,
  context: RuntimeContext,
  io: RuntimeIO,
): Promise<number> {
  try {
    return await runAdminAction(adminState, () => dispatchDesiredWizardAdmin(intent, context, io));
  } catch (error) {
    console.error(`runfree: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
}

const AUTHORITY_FREE_CANONICAL = canonicalDesiredNetworkPolicy({ version: 2, hosts: [] });

/** True when the desired project policy carries authority that no approved
 * base covers — the state desired drift or a hand-written policy produces. The
 * authority-free scaffold never needs a review: the first typed mutation
 * approves it automatically. */
export function projectPolicyNeedsExactApproval(context: RuntimeContext): boolean {
  let canonicalDesired: string;
  try {
    canonicalDesired = canonicalDesiredNetworkPolicy(validateDesiredNetworkPolicy(
      JSON.parse(fs.readFileSync(context.project.paths.policyPath, "utf8")) as unknown,
    ));
  } catch {
    // Unreadable desired input fails loudly inside the typed mutation itself.
    return false;
  }
  if (canonicalDesired === AUTHORITY_FREE_CANONICAL) return false;
  try {
    const approved = readApprovedNetworkPolicy(context.projectRoot, context.project, "network-project");
    return !approved || canonicalDesiredNetworkPolicy(approved) !== canonicalDesired;
  } catch {
    // A selection bound to another checkout or config generation is
    // quarantined and replaced when the exact review below approves.
    return true;
  }
}

/** Establish the approved project base the wizard's typed mutations require.
 * Runs the same exact-review approval as `runfree policy approve --project`;
 * returns false (skip the wizard) when the review is declined. */
export async function ensureWizardApprovedBase(context: RuntimeContext, io: RuntimeIO): Promise<boolean> {
  if (!projectPolicyNeedsExactApproval(context)) return true;
  console.log("The desired project network policy has no matching approved base for this checkout.");
  console.log("The setup wizard needs a one-time exact review before it can apply policy changes.");
  try {
    await approveNetworkControl(context, io, "network-project", {
      mechanism: "interactive",
      confirm: (candidate, subject) => printApprovalReview(context, candidate, subject, "project", io),
    });
    return true;
  } catch (error) {
    if (error instanceof Error && error.message === "control approval declined") {
      console.log("project policy not approved; skipping the setup wizard");
      console.log("review it with: runfree policy review --project");
      console.log("approve it with: runfree policy approve --project");
      return false;
    }
    throw error;
  }
}

function printInit(projectRoot: string, project: ProjectInfo): void {
  console.log(`project: ${projectRoot}`);
  console.log(`runfree config: ${project.paths.configPath}`);
  console.log(`network policy: ${project.paths.policyPath}`);
  if (project.config.runtime?.subnet) console.log(`runtime subnet: ${project.config.runtime.subnet}`);
  if (project.config.runtime?.proxyIp) console.log(`runtime proxy ip: ${project.config.runtime.proxyIp}`);
  if (project.config.runtime?.agentIp) console.log(`runtime agent ip: ${project.config.runtime.agentIp}`);
  const policy = validateDesiredNetworkPolicy(
    JSON.parse(fs.readFileSync(project.paths.policyPath, "utf8")) as unknown,
  );
  if (policy.hosts.length === 0 && Object.keys(policy.services ?? {}).length === 0) {
    console.log("outbound services: none (deny-all)");
    console.log("start Claude or Codex to review its required operational service");
    console.log("after the first start, enable services with: runfree service enable <id>");
    console.log("service ids are listed by: runfree service enable --help");
  }
}

export const initCommand: CommandModule = {
  name: "init",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "init",
      "Scaffold this project's Runfree configuration",
      (cmd) =>
        withExamples(
          cmd.option("yes", { type: "boolean", alias: "y", describe: "Skip the interactive wizard; produce only the scaffold" }),
          "init",
        ).epilogue(
          "Scaffold this project's .runfree configuration. On a terminal without --yes, the interactive setup wizard runs afterward.",
        ),
      handler(async (argv: ArgumentsCamelCase<{ yes?: boolean }>) => {
        const { projectRoot, env } = context;
        const project = context.ensureProject();
        printInit(projectRoot, project);
        // The wizard runs only on a TTY without --yes; every other invocation
        // produces exactly the scaffold above. Declining everything in the wizard
        // leaves the same scaffold.
        if (!argv.yes && process.stdin.isTTY && process.stdout.isTTY) {
          const runtimeDir = context.assets().runtimeDir;
          const runtimeContext: RuntimeContext = { projectRoot, project, runtimeRoot: runtimeDir, env };
          // A drifted project policy has no approved base, and
          // every typed wizard mutation refuses to extend an unapproved base.
          // Review and approve it here, exactly once, before the wizard runs.
          if (!(await ensureWizardApprovedBase(runtimeContext, nodeRuntimeIO))) return 0;
          // The wizard's apply step runs through the typed enforcement within a
          // single admin state (no runAdmin / string dispatcher).
          const adminState = createAdminState({
            agentEnvPath: project.paths.controlAgentEnvPath,
            projectRoot,
            packageRoot: runtimeDir,
            policyPath: project.paths.policyPath,
            policyAccess: "effective-read-only",
            effectiveControlSelected: false,
            tokenConfigPath: project.paths.tokenConfigPath,
            stateDir: project.paths.stateDir,
            env: {
              ...env,
              RUNFREE_PROJECT_ROOT: projectRoot,
              RUNFREE_STATE_DIR: project.paths.stateDir,
              RUNFREE_CLAUDE_JSON: project.paths.claudeConfigPath,
              RUNFREE_CLAUDE_MCP_CONFIG_HOST_PATH: project.paths.claudeMcpConfigPath,
              RUNFREE_CODEX_HOME: project.paths.codexDir,
              RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: project.paths.mcpOperationPolicyPath,
            },
          });
          const outcome = await runInitWizard({
            projectRoot,
            env,
            policyPath: project.paths.policyPath,
            configPath: project.paths.configPath,
            tokenConfigPath: project.paths.tokenConfigPath,
            defaultAgent: resolveDefaultAgentName(project.config),
            admin: (intent) => runWizardAdminIntent(adminState, intent, runtimeContext, nodeRuntimeIO),
          });
          // The scaffold above is complete either way; a nonzero status means
          // "scaffold ok, wizard partly failed" and the failed item was named.
          if (outcome.failed > 0) return 1;
        }
        return 0;
      }),
    ),
};
