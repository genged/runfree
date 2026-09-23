import fs from "node:fs";
import path from "node:path";

import {
  validateOAuthMediationPolicy,
  type OAuthMediationPolicyJson,
} from "@runfree/runtime-contracts/oauth-mediation-policy";
import {
  validateNetworkPolicy,
  type PolicyJson,
} from "@runfree/runtime-contracts/network-policy";
import { assertConfigCurrent } from "../config-notice.ts";
import {
  agentBuildConfig,
  classifyAgentBuildContext,
} from "../agent-image.ts";
import { projectInfo } from "../config.ts";
import { CliError } from "../errors.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import {
  approveNetworkCandidate,
  approveRuntimeIsolationSubject,
  publishNetworkSnapshot,
  publishRuntimeSnapshot,
  readControlApprovalRecord,
  readControlApprovalSelection,
  readApprovedNetworkPolicy,
  readApprovedRuntimeIsolation,
  selectSubjectApprovals,
  type ApprovalBindingMismatch,
  type ApprovedRuntimeIsolation,
  type ControlApprovalMechanism,
  type ControlApprovalRead,
  type ControlApprovalSelection,
} from "./approvals.ts";
import { approvalReadRefusal } from "./approval-read.ts";
import { migrateControlApprovalRecord } from "./approval-migration.ts";
import { desiredPolicyReviewLines } from "./review-render.ts";
import {
  captureDesiredPolicyCandidate,
  verifyDesiredPolicyCandidate,
  type DesiredPolicyCandidate,
} from "./candidates.ts";
import {
  compareCompiledAuthority,
  compareRuntimeIsolationAuthority,
  type ReductionComparison,
} from "./comparator.ts";
import { compileDesiredPolicies } from "./compiler.ts";
import { withQuiescedProject } from "./quiesce.ts";
import { parseStrictJson } from "./strict-json.ts";
import {
  approveNarrowImageBuildCandidate,
  captureNarrowImageBuildCandidate,
  type NarrowImageBuildCandidate,
} from "./image-approval.ts";
import {
  checkoutFingerprint,
  runtimeIsolationControlSubject,
  type ControlSubject,
} from "./subjects.ts";
import {
  publishEffectivePolicyGeneration,
  readActiveEffectiveControl,
  type EffectivePolicyGeneration,
} from "./effective.ts";
import { activeLifecycleSessions } from "../runtime/sessions.ts";
import { remedy } from "../remedies.ts";

type QuiescedCandidate<T> = {
  checkoutFingerprint: string;
  value: T;
};

function assertCheckoutUnchanged(projectRoot: string, captured: string): void {
  if (checkoutFingerprint(projectRoot) !== captured) {
    throw new CliError("project checkout identity changed after candidate capture; rerun control review");
  }
}

function exactDigest(expected: string | undefined, subject: ControlSubject): void {
  if (expected === undefined) return;
  if (!/^sha256:[a-f0-9]{64}$/.test(expected)) throw new CliError("subject digest must be a full sha256 digest");
  if (expected !== subject.digest) {
    throw new CliError(`${subject.subjectType} subject digest changed; reviewed ${expected}, current candidate ${subject.digest}`);
  }
}

function readHostControlFile(filePath: string): string | undefined {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new Error(`host control input is not a regular single-link file: ${filePath}`);
  }
  if (stat.size > 1024 * 1024) throw new Error(`host control input exceeds 1048576 bytes: ${filePath}`);
  return fs.readFileSync(filePath, "utf8");
}

function readHostAgentEnv(filePath: string): Record<string, string> {
  const source = readHostControlFile(filePath);
  if (source === undefined) return {};
  const values: Record<string, string> = {};
  for (const line of source.split(/\r?\n/)) {
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) throw new Error(`host agent environment input is malformed: ${filePath}`);
    values[match[1]] = match[2];
  }
  return values;
}

function readHostOAuthSeedHandles(
  stateDir: string,
  compiled: ReturnType<typeof compileDesiredPolicies>,
): Record<string, Record<string, string>> {
  const source = readHostControlFile(path.join(stateDir, "oauth-handles.json"));
  if (source === undefined) return {};
  const raw = parseStrictJson(source) as { providers?: unknown; schemaVersion?: unknown };
  if (!raw || typeof raw !== "object" || raw.schemaVersion !== 1
    || !raw.providers || typeof raw.providers !== "object" || Array.isArray(raw.providers)) {
    throw new Error("host OAuth handle store is malformed");
  }
  const providers = raw.providers as Record<string, unknown>;
  const handles: Record<string, Record<string, string>> = {};
  for (const [providerId, provider] of Object.entries(compiled.oauth)) {
    const stored = providers[providerId];
    if (!stored || typeof stored !== "object" || Array.isArray(stored)) continue;
    for (const seed of provider.seeds ?? []) {
      const handle = (stored as Record<string, unknown>)[seed.field];
      if (typeof handle === "string") {
        handles[providerId] ??= {};
        handles[providerId][seed.envVar] = handle;
      }
    }
  }
  return handles;
}

function readPreparedMcpNetworkPolicy(
  filePath: string,
  compiled: ReturnType<typeof compileDesiredPolicies>,
): PolicyJson | undefined {
  const source = readHostControlFile(filePath);
  if (source === undefined) return undefined;
  const parsed = parseStrictJson(source);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("host MCP network input is malformed");
  }
  const raw = parsed as Record<string, unknown>;
  const unknown = Object.keys(raw).filter((key) =>
    key !== "schemaVersion" && key !== "basePolicyGeneration" && key !== "policy");
  if (unknown.length > 0 || raw.schemaVersion !== 1 || typeof raw.basePolicyGeneration !== "string") {
    throw new Error("host MCP network input is malformed");
  }
  const base = validateNetworkPolicy(compiled.policy);
  if (raw.basePolicyGeneration !== base.generation) return undefined;
  return validateNetworkPolicy(raw.policy).raw;
}

export async function captureQuiescedDesiredPolicyCandidate(
  context: RuntimeContext,
  io: RuntimeIO,
): Promise<DesiredPolicyCandidate> {
  const captured = await withQuiescedProject(context, io, (): QuiescedCandidate<DesiredPolicyCandidate> => ({
    checkoutFingerprint: checkoutFingerprint(context.projectRoot),
    value: captureDesiredPolicyCandidate(context.projectRoot, context.project.paths.controlCandidatesDir),
  }));
  assertCheckoutUnchanged(context.projectRoot, captured.checkoutFingerprint);
  return captured.value;
}

export async function approveNetworkControl(
  context: RuntimeContext,
  io: RuntimeIO,
  subjectType: "network-local" | "network-project",
  input: {
    confirm?: (candidate: DesiredPolicyCandidate, subject: ControlSubject) => boolean;
    expectedDigest?: string;
    mechanism: ControlApprovalMechanism;
    now?: Date;
  },
): Promise<ControlApprovalSelection> {
  const candidate = await captureQuiescedDesiredPolicyCandidate(context, io);
  const subject = subjectType === "network-project" ? candidate.projectSubject : candidate.localSubject;
  exactDigest(input.expectedDigest, subject);
  if (input.confirm && !input.confirm(candidate, subject)) throw new CliError("control approval declined");
  return approveNetworkCandidate(
    context.projectRoot,
    context.project,
    candidate,
    subjectType,
    input.mechanism,
    input.now,
  );
}

export async function captureQuiescedImageBuildCandidate(
  context: RuntimeContext,
  io: RuntimeIO,
): Promise<{ candidate: NarrowImageBuildCandidate; project: ReturnType<typeof projectInfo> }> {
  const captured = await withQuiescedProject(context, io, (): QuiescedCandidate<{
    candidate: NarrowImageBuildCandidate;
    project: ReturnType<typeof projectInfo>;
  }> => {
    const project = projectInfo(context.projectRoot, context.env);
    assertConfigCurrent(project);
    const build = agentBuildConfig(project.config);
    if (!build) throw new CliError(`runtime.agent.build is not configured; run \`${remedy.imageInit()}\` first`);
    if (classifyAgentBuildContext(context.projectRoot, build) !== "narrow") {
      throw new CliError("control image-build approval requires a narrow project image context; use `runfree image approve-context` for a wide-context risk grant");
    }
    return {
      checkoutFingerprint: checkoutFingerprint(context.projectRoot),
      value: {
        project,
        candidate: captureNarrowImageBuildCandidate(
          context.projectRoot,
          build,
          project.paths.controlCandidatesDir,
        ),
      },
    };
  });
  assertCheckoutUnchanged(context.projectRoot, captured.checkoutFingerprint);
  return captured.value;
}

export async function captureQuiescedProjectControlCandidates(
  context: RuntimeContext,
  io: RuntimeIO,
): Promise<{
  image?: NarrowImageBuildCandidate;
  network: DesiredPolicyCandidate;
  project: ReturnType<typeof projectInfo>;
  runtimeSubject: ControlSubject;
}> {
  const captured = await withQuiescedProject(context, io, (): QuiescedCandidate<{
    image?: NarrowImageBuildCandidate;
    network: DesiredPolicyCandidate;
    project: ReturnType<typeof projectInfo>;
    runtimeSubject: ControlSubject;
  }> => {
    const project = projectInfo(context.projectRoot, context.env);
    assertConfigCurrent(project);
    const build = agentBuildConfig(project.config);
    const image = build && classifyAgentBuildContext(context.projectRoot, build) === "narrow"
      ? captureNarrowImageBuildCandidate(context.projectRoot, build, project.paths.controlCandidatesDir)
      : undefined;
    return {
      checkoutFingerprint: checkoutFingerprint(context.projectRoot),
      value: {
        project,
        network: captureDesiredPolicyCandidate(context.projectRoot, project.paths.controlCandidatesDir),
        runtimeSubject: runtimeIsolationControlSubject(project.config),
        ...(image ? { image } : {}),
      },
    };
  });
  assertCheckoutUnchanged(context.projectRoot, captured.checkoutFingerprint);
  return captured.value;
}

export async function approveImageBuild(
  context: RuntimeContext,
  io: RuntimeIO,
  input: { expectedDigest: string; now?: Date },
): Promise<ControlApprovalSelection> {
  const captured = await captureQuiescedImageBuildCandidate(context, io);
  exactDigest(input.expectedDigest, captured.candidate.subject);
  return approveNarrowImageBuildCandidate(
    context.projectRoot,
    captured.project,
    captured.candidate,
    "digest-command",
    input.now,
  ).selection;
}

export async function approveAutomaticNetworkReduction(
  context: RuntimeContext,
  io: RuntimeIO,
  subjectType: "network-local" | "network-project",
  now = new Date(),
): Promise<{ comparison: ReductionComparison; selection: ControlApprovalSelection }> {
  const candidate = await captureQuiescedDesiredPolicyCandidate(context, io);
  const previousProject = readApprovedNetworkPolicy(context.projectRoot, context.project, "network-project");
  const previousLocal = readApprovedNetworkPolicy(context.projectRoot, context.project, "network-local");
  if (!previousProject || !previousLocal) throw new Error("automatic reduction requires both previously approved network subjects");
  const nextProject = subjectType === "network-project" ? candidate.project : previousProject;
  const nextLocal = subjectType === "network-local" ? candidate.local : previousLocal;
  const comparison = compareCompiledAuthority(
    compileDesiredPolicies({ project: previousProject, local: previousLocal }),
    compileDesiredPolicies({ project: nextProject, local: nextLocal }),
  );
  if (!comparison.provenReduction) {
    throw new CliError(`desired change is not a proven authority reduction: ${comparison.reasons.join("; ")}`);
  }
  const selection = approveNetworkCandidate(
    context.projectRoot,
    context.project,
    candidate,
    subjectType,
    "automatic-reduction",
    now,
  );
  return { comparison, selection };
}

export async function captureQuiescedRuntimeIsolationSubject(
  context: RuntimeContext,
  io: RuntimeIO,
): Promise<{ project: ReturnType<typeof projectInfo>; subject: ControlSubject }> {
  const captured = await withQuiescedProject(context, io, (): QuiescedCandidate<{
    project: ReturnType<typeof projectInfo>;
    subject: ControlSubject;
  }> => {
    const project = projectInfo(context.projectRoot, context.env);
    assertConfigCurrent(project);
    return {
      checkoutFingerprint: checkoutFingerprint(context.projectRoot),
      value: { project, subject: runtimeIsolationControlSubject(project.config) },
    };
  });
  assertCheckoutUnchanged(context.projectRoot, captured.checkoutFingerprint);
  return captured.value;
}

export async function approveRuntimeIsolation(
  context: RuntimeContext,
  io: RuntimeIO,
  input: {
    expectedDigest?: string;
    mechanism: ControlApprovalMechanism;
    now?: Date;
  },
): Promise<ControlApprovalSelection> {
  const captured = await captureQuiescedRuntimeIsolationSubject(context, io);
  exactDigest(input.expectedDigest, captured.subject);
  return approveRuntimeIsolationSubject(
    context.projectRoot,
    captured.project,
    captured.subject,
    input.mechanism,
    input.now,
  );
}

export function useApprovedPolicyGeneration(context: RuntimeContext): EffectivePolicyGeneration {
  let baseOAuthPolicy: OAuthMediationPolicyJson | undefined;
  try {
    const source = readHostControlFile(context.project.paths.mcpOAuthPolicyPath);
    if (source === undefined) throw Object.assign(new Error("missing OAuth policy"), { code: "ENOENT" });
    const loaded = validateOAuthMediationPolicy(
      parseStrictJson(source),
    );
    baseOAuthPolicy = {
      providers: Object.fromEntries(loaded.providers.map((provider) => [provider.providerId, {
        kind: provider.kind,
        resourceHost: provider.resourceHost,
        ...(provider.resourcePathPrefix ? { resourcePathPrefix: provider.resourcePathPrefix } : {}),
        tokenEndpoints: provider.tokenEndpoints.map(({ host, path }) => ({ host, path })),
        ...(provider.registrationEndpoints.length > 0
          ? { registrationEndpoints: provider.registrationEndpoints.map(({ host, path }) => ({ host, path })) }
          : {}),
        ...(provider.metadataEndpoints.length > 0
          ? { metadataEndpoints: provider.metadataEndpoints.map(({ host, path }) => ({ host, path })) }
          : {}),
        ...(provider.seeds.length > 0 ? { seeds: provider.seeds } : {}),
      }])),
    };
  } catch (error) {
    if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error;
  }
  const projectPolicy = readApprovedNetworkPolicy(context.projectRoot, context.project, "network-project");
  const localPolicy = readApprovedNetworkPolicy(context.projectRoot, context.project, "network-local");
  const compiled = projectPolicy && localPolicy
    ? compileDesiredPolicies({ project: projectPolicy, local: localPolicy })
    : undefined;
  const effectiveNetworkPolicy = compiled
    ? readPreparedMcpNetworkPolicy(context.project.paths.controlMcpNetworkPolicyPath, compiled)
    : undefined;
  return publishEffectivePolicyGeneration(context.projectRoot, context.project, {
    ...(baseOAuthPolicy ? { baseOAuthPolicy } : {}),
    ...(compiled ? {
      agentEnvValues: readHostAgentEnv(context.project.paths.controlAgentEnvPath),
      ...(effectiveNetworkPolicy ? { effectiveNetworkPolicy } : {}),
      oauthSeedHandles: readHostOAuthSeedHandles(context.project.paths.stateDir, compiled),
    } : {}),
  });
}

export async function usePreparedApprovedPolicyGeneration(
  context: RuntimeContext,
  io: RuntimeIO,
): Promise<EffectivePolicyGeneration> {
  const status = await io.admin({ kind: "prepare" }, context);
  if (status !== 0) {
    throw Object.assign(
      new Error(`host-owned effective control preparation failed with status ${status}`),
      { status },
    );
  }
  return useApprovedPolicyGeneration(context);
}

export type StartupControlPreparation = {
  generation: EffectivePolicyGeneration;
  mechanism: "active-session" | "already-approved" | "automatic-reduction" | "interactive" | "use-approved";
};

function selectedDigest(
  selection: ControlApprovalSelection | undefined,
  subjectType: "network-local" | "network-project" | "runtime-isolation",
): string | undefined {
  return selection?.subjects[subjectType]?.digest;
}

/**
 * Publish the selected configuration snapshots, then record all of them in one
 * replacement. One consent is one write: a partially applied selection is not a
 * state a reviewer ever agreed to.
 */
export function approveConfigurationSubjects(
  context: RuntimeContext,
  candidate: DesiredPolicyCandidate,
  runtimeSubject: ControlSubject,
  mechanism: ControlApprovalMechanism,
  select: { networkLocal: boolean; networkProject: boolean; runtimeIsolation: boolean },
  now = new Date(),
): ControlApprovalSelection {
  verifyDesiredPolicyCandidate(candidate);
  const subjects: ControlSubject[] = [];
  if (select.networkProject) {
    publishNetworkSnapshot(context.project, candidate.projectSubject, candidate.project);
    subjects.push(candidate.projectSubject);
  }
  if (select.networkLocal) {
    publishNetworkSnapshot(context.project, candidate.localSubject, candidate.local);
    subjects.push(candidate.localSubject);
  }
  if (select.runtimeIsolation) {
    publishRuntimeSnapshot(context.project, runtimeSubject);
    subjects.push(runtimeSubject);
  }
  return selectSubjectApprovals(context.projectRoot, context.project, subjects, mechanism, now);
}

function approvalCommands(candidate: DesiredPolicyCandidate, runtimeSubject: ControlSubject): string {
  return [
    `runfree control approve network-project --subject-digest ${candidate.projectSubject.digest}`,
    `runfree control approve network-local --subject-digest ${candidate.localSubject.digest}`,
    `runfree control approve runtime-isolation --subject-digest ${runtimeSubject.digest}`,
    "runfree policy use-approved",
  ].join("\n");
}

const MISMATCH_HEADLINE: Record<ApprovalBindingMismatch, string> = {
  "project-scope": "These saved approvals belong to another project scope.",
  "config-version": "The project config generation changed.",
  "resolved-root": "This path now resolves somewhere else.",
  "root-inode": "The directory at this path was replaced.",
};

/**
 * A v1 record's hash cannot say which field moved, so the headline states the
 * schema and stops. Naming a field would be a guess, and the whole reason the
 * binding became plain fields is that the hash destroyed attribution.
 */
const SUPERSEDED_HEADLINE = "These saved approvals predate this version of runfree and no longer describe this checkout.";

/**
 * Resolve the approvals record into usable authority, or refuse.
 *
 * This runs before any consumer of approved authority — on a launch, and before
 * the typed mutation families — because two of those substitute an empty
 * baseline rather than refusing when no approval is readable, and because a
 * binding mismatch used to throw through the start path rather than rendering
 * the review that would repair it.
 *
 * A mismatch renders the **existing** review: the canonical desired policy
 * body, plus the reason. Consenting to a replaced checkout by three subject
 * digests alone is exactly the case the binding exists to catch, and the
 * semantic-change block cannot render at all when the previous approved
 * policies are unreadable. There is no second review surface here.
 *
 * A `superseded` v1 record takes that same branch. It is the group that
 * rebooted before the binding change shipped, and it is the reason this gate
 * may not treat every v1 record as a refusal: the refusal would have no
 * reclamation, because nothing else this project can run would clear it.
 */
export async function requireUsableApprovalSelection(
  context: RuntimeContext,
  io: RuntimeIO,
): Promise<ControlApprovalRead> {
  let read = readControlApprovalRecord(context.projectRoot, context.project);
  if (read.kind === "valid" || read.kind === "missing") return read;

  // A v1 record that still describes this checkout migrates here, with no
  // prompt and no consent: its own hash proved continuity of path, device, and
  // inode together, which is strictly stronger than the binding it becomes.
  // This is the launch path's only migration site — the lifecycle-locked funnel
  // runs later, and every public launch crosses this gate first.
  if (read.kind === "legacy") {
    const outcome = migrateControlApprovalRecord(context.projectRoot, context.project);
    if (outcome === "unmigratable") {
      // The record's own identity holds but a snapshot it points at does not,
      // so nothing may be carried forward and nothing here can repair it. Name
      // the reclamation that does: remove the record and review from scratch.
      throw new CliError([
        "the saved approvals predate this version of runfree and their approved snapshots no longer verify",
        `inspect the record with: ${remedy.policyStatus()}`,
        `after removing it, re-review with: ${remedy.up()}`,
      ].join("\n"));
    }
    read = readControlApprovalRecord(context.projectRoot, context.project);
    if (read.kind === "valid" || read.kind === "missing") return read;
    // A record still classified `legacy` after a migration that reported no
    // failure means a concurrent writer replaced it; refuse rather than loop.
    if (read.kind === "legacy") throw new CliError(approvalReadRefusal(read));
  }

  // `corrupt` is not a consent problem, so it does not get a prompt: it names
  // its own reclamation path instead.
  if (read.kind === "corrupt") throw new CliError(approvalReadRefusal(read));

  const candidate = await captureQuiescedDesiredPolicyCandidate(context, io);
  const runtimeSubject = runtimeIsolationControlSubject(context.project.config);
  for (const line of [
    "Runfree needs to review this checkout's saved approvals.",
    read.kind === "superseded" ? SUPERSEDED_HEADLINE : MISMATCH_HEADLINE[read.reason],
    "",
    ...desiredPolicyReviewLines(context, candidate, candidate.projectSubject, "project"),
    "",
    ...desiredPolicyReviewLines(context, candidate, candidate.localSubject, "local"),
    "",
    `runtime-isolation subject digest: ${runtimeSubject.digest}`,
  ]) console.log(line);

  // `--yes` is not consent, and a non-TTY is not consent either: the exact
  // digest commands are the only non-interactive path in.
  if (io.isInteractive?.() !== true) {
    throw new CliError(`desired controls require exact approval before startup:\n${approvalCommands(candidate, runtimeSubject)}`);
  }
  if (!io.confirm("Use these settings for this checkout? [y/N] ")) {
    throw new CliError("checkout approval review declined; runtime was not started");
  }

  // Reacquire the lock and re-verify before publishing. A decline or a failed
  // revalidation leaves the previous selector unchanged.
  const verified = await captureQuiescedDesiredPolicyCandidate(context, io);
  if (verified.projectSubject.digest !== candidate.projectSubject.digest
    || verified.localSubject.digest !== candidate.localSubject.digest
    || runtimeIsolationControlSubject(context.project.config).digest !== runtimeSubject.digest) {
    throw new CliError("desired controls changed during the review; rerun the review");
  }
  // Stored subjects from the mismatched record may have been displayed as
  // historical comparison; none of them enters the new selection.
  approveConfigurationSubjects(context, verified, runtimeSubject, "interactive", {
    networkProject: true,
    networkLocal: true,
    runtimeIsolation: true,
  });
  return readControlApprovalRecord(context.projectRoot, context.project);
}

/**
 * Resolve startup authority before Docker planning, image work, credential
 * resolution, or attach. A concurrent launch reuses the verified active
 * generation without reading desired project input or publishing authority.
 * Otherwise, desired bytes are captured only while the project is quiesced;
 * publication consumes the approved snapshots, never the worktree again.
 */
export async function prepareEffectiveControlsForStartup(
  context: RuntimeContext,
  io: RuntimeIO,
  options: { useApprovedPolicy?: boolean } = {},
): Promise<StartupControlPreparation> {
  // Before the active-session short-circuit on purpose. That path returns the
  // published generation without ever reading the selection, and
  // `ensureRuntimeMaterialized` still runs after it — so with image approval
  // prepared on every launch rather than only on a build, a cached custom image
  // on an active-session entry would otherwise be the first thing to meet a
  // non-valid selection.
  await requireUsableApprovalSelection(context, io);

  if (options.useApprovedPolicy) {
    return { generation: await usePreparedApprovedPolicyGeneration(context, io), mechanism: "use-approved" };
  }

  // Per-session admission supports concurrent sessions, but a control capture
  // cannot run beside one: the existing session can edit desired project input.
  // Reuse the exact selected host-owned generation instead. This path performs
  // no preparation or publication, so starting another session cannot activate
  // desired drift or a different approved snapshot.
  if (activeLifecycleSessions(context).length > 0) {
    const active = readActiveEffectiveControl(context.project);
    if (!active) {
      throw new Error("active sessions require an existing verified effective control selection");
    }
    return { generation: active, mechanism: "active-session" };
  }

  const candidate = await captureQuiescedDesiredPolicyCandidate(context, io);
  const runtimeSubject = runtimeIsolationControlSubject(context.project.config);
  let selection = readControlApprovalSelection(context.projectRoot, context.project);
  const networkProjectChanged = selectedDigest(selection, "network-project") !== candidate.projectSubject.digest;
  const networkLocalChanged = selectedDigest(selection, "network-local") !== candidate.localSubject.digest;
  const runtimeChanged = selectedDigest(selection, "runtime-isolation") !== runtimeSubject.digest;
  if (!networkProjectChanged && !networkLocalChanged && !runtimeChanged) {
    return { generation: await usePreparedApprovedPolicyGeneration(context, io), mechanism: "already-approved" };
  }

  const previousProject = readApprovedNetworkPolicy(context.projectRoot, context.project, "network-project");
  const previousLocal = readApprovedNetworkPolicy(context.projectRoot, context.project, "network-local");
  const previousRuntime = readApprovedRuntimeIsolation(context.projectRoot, context.project);
  const networkReduction = previousProject && previousLocal
    ? compareCompiledAuthority(
      compileDesiredPolicies({ project: previousProject, local: previousLocal }),
      compileDesiredPolicies({ project: candidate.project, local: candidate.local }),
    )
    : undefined;
  const runtimeReduction = previousRuntime
    ? compareRuntimeIsolationAuthority(previousRuntime, runtimeSubject.payload.runtime as ApprovedRuntimeIsolation)
    : undefined;
  if (
    ((!networkProjectChanged && !networkLocalChanged) || networkReduction?.provenReduction === true)
    && (!runtimeChanged || runtimeReduction?.provenReduction === true)
  ) {
    // One replacement for however many subjects the reduction covers. Three
    // sequential writers each did their own read-verify-replace, so a
    // concurrent writer could interleave between them and the selection could
    // be observed half-applied.
    selection = approveConfigurationSubjects(context, candidate, runtimeSubject, "automatic-reduction", {
      networkProject: networkProjectChanged,
      networkLocal: networkLocalChanged,
      runtimeIsolation: runtimeChanged,
    });
    if (!selection) throw new Error("automatic control reduction did not persist an approval selection");
    return { generation: await usePreparedApprovedPolicyGeneration(context, io), mechanism: "automatic-reduction" };
  }

  const interactive = io.isInteractive?.() === true;
  if (!interactive) {
    throw new CliError(`desired controls require exact approval before startup:\n${approvalCommands(candidate, runtimeSubject)}`);
  }
  const summary = [
    "Desired controls require approval:",
    `  network-project ${candidate.projectSubject.digest}`,
    `  network-local ${candidate.localSubject.digest}`,
    `  runtime-isolation ${runtimeSubject.digest}`,
  ].join("\n");
  if (!io.confirm(`${summary}\nApprove these exact controls? [y/N] `)) {
    throw new CliError("control approval declined; runtime was not started");
  }
  approveConfigurationSubjects(context, candidate, runtimeSubject, "interactive", {
    networkProject: true,
    networkLocal: true,
    runtimeIsolation: true,
  });
  return { generation: await usePreparedApprovedPolicyGeneration(context, io), mechanism: "interactive" };
}
