// Host-owned desired/effective policy inspection and exact-subject approval.

import type { ArgumentsCamelCase, Argv } from "yargs";

import { nodeRuntimeIO } from "../runtime.ts";
import { assertConfigCurrent } from "../config-notice.ts";
import {
  inspectControlStatus,
  inspectNetworkPolicyReview,
  inspectPolicyHost,
  type NetworkPolicyDiff,
  type PolicyHostView,
} from "../control/status.ts";
import {
  approveNetworkControl,
  requireUsableApprovalSelection,
} from "../control/workflow.ts";
import { desiredPolicyReviewLines } from "../control/review-render.ts";
import { activateApprovedControlsAfterMutation } from "../control/activation.ts";
import { CliError } from "../errors.ts";
import { formatTerminalTable } from "../terminal-table.ts";
import type { DesiredPolicyCandidate } from "../control/candidates.ts";
import type { ControlSubject } from "../control/subjects.ts";
import type { CommandModule } from "./types.ts";
import type { RunfreeCommandContext } from "./context.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";

type ScopeArgs = { local?: boolean; project?: boolean };
type DiffArgs = ScopeArgs & { json?: boolean };
type ApproveArgs = ScopeArgs & { "subject-digest"?: string };
type HostArgs = { host: string };

function scopeFromArgs(input: ScopeArgs): "local" | "project" | undefined {
  if (input.project) return "project";
  if (input.local) return "local";
  return undefined;
}

function scopeOptions(cmd: Argv): Argv {
  return cmd
    .option("project", { type: "boolean", describe: "Inspect or approve the committed project policy layer" })
    .option("local", { type: "boolean", describe: "Inspect or approve the checkout-local policy layer" })
    .conflicts("project", "local");
}

function shortDigest(value: string | undefined): string {
  return value ? `${value.slice(0, 15)}…${value.slice(-6)}` : "none";
}

export type PolicyStatusRow = {
  label: string;
  desiredDigest: string | undefined;
  approvedDigest: string | undefined;
  state: string;
};

export function formatPolicyStatusTable(rows: readonly PolicyStatusRow[]): string {
  return formatTerminalTable({
    columns: [{ label: "SOURCE" }, { label: "DESIRED" }, { label: "APPROVED" }, { label: "STATE" }],
    rows: rows.map((row) => [row.label, shortDigest(row.desiredDigest), shortDigest(row.approvedDigest), row.state]),
  });
}

function printDiff(diff: NetworkPolicyDiff): void {
  console.log(`${diff.scope}: ${diff.classification}`);
  console.log(`  desired:  ${diff.desiredDigest}`);
  console.log(`  approved: ${diff.approvedDigest ?? "none"}`);
  for (const reason of diff.reasons) console.log(`  - ${reason}`);
  for (const change of diff.changes) console.log(`  * ${change}`);
}

export function printApprovalReview(
  runtime: RuntimeContext,
  candidate: DesiredPolicyCandidate,
  subject: ControlSubject,
  scope: "local" | "project",
  io: RuntimeIO = nodeRuntimeIO,
): boolean {
  for (const line of desiredPolicyReviewLines(runtime, candidate, subject, scope)) console.log(line);
  return io.confirm("Approve exact policy? [y/N] ");
}

function printHostView(label: string, view: PolicyHostView | undefined): void {
  if (!view) {
    console.log(`${label}: unavailable`);
    return;
  }
  console.log(`${label}: ${view.allowlisted ? "allowlisted" : "not allowlisted"}`);
  console.log(`  host sources: ${view.hostSources.join(", ") || "none"}`);
  console.log(`  request source: ${view.requestSource ?? "none"}`);
  console.log(`  methods: ${view.requestRule?.methods?.join(", ") ?? "unrestricted"}`);
  console.log(`  paths: ${view.requestRule?.pathPrefixes?.join(", ") ?? "unrestricted"}`);
  console.log(`  git push: ${view.requestRule?.gitPush ?? "not specially restricted"}`);
  console.log(`  graphql: ${view.requestRule?.graphql ? JSON.stringify(view.requestRule.graphql) : "none"}`);
  console.log(`  writes: ${view.writeAction}`);
  console.log(`  credentials: ${view.credentials.join(", ") || "none"}`);
}

function interactiveHost(): boolean {
  return nodeRuntimeIO.isInteractive?.() ?? (process.stdin.isTTY === true && process.stdout.isTTY === true);
}

function approvedControlRuntimeContext(context: RunfreeCommandContext): RuntimeContext {
  const project = context.projectInfo();
  assertConfigCurrent(project);
  return {
    projectRoot: context.projectRoot,
    project,
    runtimeRoot: context.assets().runtimeDir,
    env: context.env,
  };
}

export function policyApprovalIntent(
  argv: ApproveArgs,
  interactive: boolean,
): { expectedDigest?: string; mechanism: "digest-command" | "interactive"; scope: "local" | "project" } {
  const scope = scopeFromArgs(argv);
  if (!scope) throw new CliError("policy approve requires exactly one of --project or --local");
  if (argv["subject-digest"] === undefined && !interactive) {
    throw new CliError("non-interactive policy approval requires --subject-digest sha256:...");
  }
  return {
    scope,
    ...(argv["subject-digest"] ? { expectedDigest: argv["subject-digest"] } : {}),
    mechanism: argv["subject-digest"] ? "digest-command" : "interactive",
  };
}

export const policyCommand: CommandModule = {
  name: "policy",
  group: true,
  register: (parser, context, handler) =>
    parser.command(
      "policy",
      "Inspect, review, and approve desired network policy",
      (policy) => policy
        .command(
          "status",
          "Show desired, approved, and effective control identities",
          (cmd) => cmd,
          handler(async () => {
            const status = await inspectControlStatus(context.runtimeContext(), nodeRuntimeIO);
            console.log("Network policy");
            const statusRows: PolicyStatusRow[] = [];
            for (const [scope, layer] of Object.entries(status.layers) as Array<["local" | "project", typeof status.layers.project]>) {
              const subjectType = scope === "project" ? "network-project" : "network-local";
              const state = layer.drift === "approved"
                && status.active?.selectedSubjects[subjectType] === layer.approvedDigest
                ? "active"
                : layer.drift;
              const label = scope === "local" ? "checkout-local" : scope;
              statusRows.push({ label, desiredDigest: layer.desiredDigest, approvedDigest: layer.approvedDigest, state });
            }
            for (const [label, subjectType, subject] of [
              ["runtime", "runtime-isolation", status.subjects.runtimeIsolation],
              ["image", "image-build", status.subjects.imageBuild],
            ] as const) {
              const state = subject.drift === "approved"
                && status.active?.selectedSubjects[subjectType] === subject.approvedDigest
                ? "active"
                : subject.drift;
              statusRows.push({ label, desiredDigest: subject.desiredDigest, approvedDigest: subject.approvedDigest, state });
            }
            console.log(formatPolicyStatusTable(statusRows));
            console.log(`approval set: ${status.approvalSetDigest ?? "none"}`);
            // `controlGeneration` IS the effective policy generation (see
            // docs/architecture.md "Generation Families"); the payload
            // generation is the proxy's network-policy file digest.
            console.log(`effective policy generation: ${status.active?.controlGeneration ?? "none"}`);
            if (status.active) console.log(`network policy payload generation: ${status.active.policyGeneration}`);
            const converged = status.converged?.controlGeneration === status.active?.controlGeneration
              ? status.converged
              : undefined;
            console.log(`proxy request: ${converged?.requestProxy.controlGeneration ?? "unacknowledged"}`);
            console.log(`proxy firewall: ${converged?.firewall.controlGeneration ?? "unacknowledged"}${converged ? " (ruleset verified)" : ""}`);
            if (status.desiredError) console.log(`desired error: ${status.desiredError}`);
            // Name the record's condition, not just its message: `corrupt` and
            // `mismatch` have different reclamation paths, and an operator
            // reading a wrapped sentence should not have to infer which one.
            if (status.approvalRead !== "valid" && status.approvalRead !== "missing") {
              console.log(`approval record: ${status.approvalRead}`);
            }
            if (status.approvalError) console.log(`approval error: ${status.approvalError}`);
            if (status.activeError) console.log(`effective error: ${status.activeError}`);
            if (status.convergenceError) console.log(`convergence error: ${status.convergenceError}`);
          }),
        )
        .command(
          "explain <host>",
          "Show desired, approved, and effective semantics for one host",
          (cmd) => cmd.positional("host", { type: "string", demandOption: true, describe: "exact hostname" }),
          handler(async (argv: ArgumentsCamelCase<HostArgs>) => {
            const explanation = await inspectPolicyHost(context.runtimeContext(), nodeRuntimeIO, argv.host);
            console.log(explanation.host);
            printHostView("desired", explanation.desired);
            if (explanation.desiredError) console.log(`  error: ${explanation.desiredError}`);
            printHostView("approved", explanation.approved);
            printHostView("effective", explanation.effective);
            for (const scope of ["project", "local"] as const) {
              const approval = explanation.approvals[scope];
              console.log(`current ${scope} approval: ${approval ? `${approval.digest} (${approval.mechanism}, ${approval.approvedAt})` : "none"}`);
              const effectiveApproval = explanation.effectiveApprovals[scope];
              console.log(`effective ${scope} approval: ${effectiveApproval ? `${effectiveApproval.digest} (${effectiveApproval.mechanism})` : "none"}`);
            }
            console.log("pending changes:");
            if (explanation.pendingChanges.length === 0) console.log("  none");
            else for (const change of explanation.pendingChanges) console.log(`  - ${change}`);
          }),
        )
        .command(
          "diff",
          "Classify desired policy drift against approved authority",
          (cmd) => scopeOptions(cmd).option("json", { type: "boolean", describe: "Print machine-readable JSON" }),
          handler(async (argv: ArgumentsCamelCase<DiffArgs>) => {
            const review = await inspectNetworkPolicyReview(
              context.runtimeContext(),
              nodeRuntimeIO,
              scopeFromArgs(argv),
            );
            if (argv.json) console.log(JSON.stringify(review.diffs, null, 2));
            else for (const diff of review.diffs) printDiff(diff);
          }),
        )
        .command(
          "review",
          "Show canonical desired policy and its authority classification",
          (cmd) => scopeOptions(cmd),
          handler(async (argv: ArgumentsCamelCase<ScopeArgs>) => {
            const review = await inspectNetworkPolicyReview(
              context.runtimeContext(),
              nodeRuntimeIO,
              scopeFromArgs(argv),
            );
            for (const diff of review.diffs) {
              printDiff(diff);
              const desired = review.policies[diff.scope];
              if (desired) console.log(JSON.stringify(desired, null, 2));
            }
          }),
        )
        .command(
          "approve",
          "Approve exactly one desired network-policy subject",
          (cmd) => scopeOptions(cmd).option("subject-digest", {
            type: "string",
            requiresArg: true,
            describe: "Exact full digest of the reviewed subject (required non-interactively)",
          }),
          handler(async (argv: ArgumentsCamelCase<ApproveArgs>) => {
            const intent = policyApprovalIntent(argv, interactiveHost());
            const runtime = context.runtimeContext();
            // Under a binding mismatch this renders the review rather than
            // throwing. Exact-digest approval stays per-subject consent: it
            // selects only this layer, and startup reviews the rest.
            await requireUsableApprovalSelection(runtime, nodeRuntimeIO);
            const selection = await approveNetworkControl(
              runtime,
              nodeRuntimeIO,
              intent.scope === "project" ? "network-project" : "network-local",
              {
                expectedDigest: intent.expectedDigest,
                mechanism: intent.mechanism,
                ...(intent.mechanism === "interactive"
                  ? { confirm: (candidate, subject) => printApprovalReview(runtime, candidate, subject, intent.scope) }
                  : {}),
              },
            );
            const subjectType = intent.scope === "project" ? "network-project" : "network-local";
            console.log(`approved ${subjectType}: ${selection.subjects[subjectType]?.digest}`);
          }),
        )
        .command(
          "use-approved",
          "Select a new effective policy generation compiled only from approved controls",
          (cmd) => cmd,
          handler(async () => {
            const runtimeContext = approvedControlRuntimeContext(context);
            const activation = await activateApprovedControlsAfterMutation(runtimeContext, nodeRuntimeIO, {
              recoverInvalidActive: true,
            });
            if (activation.kind === "deferred") {
              throw new CliError(`no effective policy generation was selected: ${activation.reason}`);
            }
            console.log(`selected approved effective policy generation: ${activation.controlGeneration}`);
            console.log(activation.kind === "converged"
              ? "convergence: request proxy and verified firewall acknowledged"
              : "convergence: pending until a proxy runtime is live");
          }),
        )
        .demandCommand(1),
      () => {},
    ),
};
