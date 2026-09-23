import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { defaultConfig, projectInfo } from "../config.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import {
  convergeEffectivePolicyGeneration,
  publishEffectivePolicyGeneration,
} from "./effective.ts";
import {
  inspectControlStatus,
  inspectNetworkPolicyReview,
  inspectPolicyHost,
} from "./status.ts";

describe("control status", () => {
  let root: string;
  let stateHome: string;
  let context: RuntimeContext;
  let io: RuntimeIO;
  // `docker ps` output stands in for a live proxy container. A convergence
  // receipt is only reported while one is running: the receipt is cleared on a
  // generation change, and the generation no longer moves on a reboot.
  let liveProxyId: string;
  beforeEach(() => {
    liveProxyId = `${"c".repeat(64)}`;
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-control-status-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-control-status-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["example.com"]}`);
    const env = {
      XDG_STATE_HOME: stateHome,
      XDG_CONFIG_HOME: path.join(stateHome, "config"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
      RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
    };
    const project = projectInfo(root, env);
    context = { projectRoot: root, project, runtimeRoot: path.join(root, "runtime"), env };
    io = {
      capture: (_command, args) => args[0] === "ps"
        ? { status: 0, stdout: liveProxyId ? `${liveProxyId}\n` : "", stderr: "" }
        : { status: 1, stdout: "", stderr: "unexpected" },
      run: () => 0,
      commandExists: () => true,
      confirm: () => false,
      admin: async () => 0,
    };
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true });
    fs.rmSync(stateHome, { recursive: true });
  });

  test("reports pending, approved, and effective identities separately", async () => {
    const pending = await inspectControlStatus(context, io);
    expect(pending.layers.project.drift).toBe("pending");
    expect(pending.subjects.runtimeIsolation.drift).toBe("pending");
    expect(pending.subjects.imageBuild.drift).toBe("absent");
    expect(pending.active).toBeUndefined();

    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(root, context.project, "interactive");
    const generation = publishEffectivePolicyGeneration(root, context.project);
    const approved = await inspectControlStatus(context, io);
    expect(approved.layers.project.drift).toBe("approved");
    expect(approved.subjects.runtimeIsolation.drift).toBe("approved");
    expect(approved.approvalSetDigest).toMatch(/^sha256:/);
    expect(approved.active).toMatchObject({
      controlGeneration: generation.controlGeneration,
      policyGeneration: generation.policyGeneration,
    });

    await convergeEffectivePolicyGeneration(context.project, {
      probe: async () => ({
        requestProxy: {
          generation: generation.policyGeneration,
          controlGeneration: generation.controlGeneration,
          policyGeneration: generation.policyGeneration,
        },
        firewall: {
          generation: generation.policyGeneration,
          controlGeneration: generation.controlGeneration,
          policyGeneration: generation.policyGeneration,
          rulesetVerified: true,
        },
      }),
      stopRuntime: async () => {},
      timeoutMs: 0,
    });
    expect((await inspectControlStatus(context, io)).converged?.firewall.rulesetVerified).toBe(true);

    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":[]}`);
    const drifted = await inspectControlStatus(context, io);
    expect(drifted.layers.project.drift).toBe("pending");
    expect(drifted.layers.project.approvedDigest).not.toBe(drifted.layers.project.desiredDigest);
    expect(drifted.active?.controlGeneration).toBe(generation.controlGeneration);
  });

  test("preserves effective status when desired input is invalid", async () => {
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(root, context.project, "interactive");
    const generation = publishEffectivePolicyGeneration(root, context.project);
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":[],"hosts":[]}`);

    const status = await inspectControlStatus(context, io);

    expect(status.desiredError).toContain("duplicate");
    expect(status.layers.project.drift).toBe("invalid");
    expect(status.active?.controlGeneration).toBe(generation.controlGeneration);
  });

  test("explains layer-aware effective provenance and pending desired changes", async () => {
    fs.writeFileSync(
      path.join(root, ".runfree", "network-policy.local.json"),
      `{"version":2,"hosts":["example.com"],"requests":{"example.com":{"methods":["GET"]}}}`,
    );
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, context.project, candidate, "network-local", "digest-command");
    approveRuntimeIsolationControl(root, context.project, "interactive");
    publishEffectivePolicyGeneration(root, context.project);

    const effective = await inspectPolicyHost(context, io, "example.com");
    expect(effective.effective).toMatchObject({
      allowlisted: true,
      hostSources: ["local:direct", "project:direct"],
      requestSource: "local:direct",
      requestRule: { methods: ["GET"] },
    });
    expect(effective.approvals.local?.mechanism).toBe("digest-command");
    expect(effective.effectiveApprovals.local?.mechanism).toBe("digest-command");
    expect(effective.pendingChanges).toEqual([]);

    fs.writeFileSync(
      path.join(root, ".runfree", "network-policy.json"),
      `{"version":2,"hosts":["example.com","new.example.com"]}`,
    );
    const pending = await inspectPolicyHost(context, io, "new.example.com");
    expect(pending.effective?.allowlisted).toBe(false);
    expect(pending.desired?.allowlisted).toBe(true);
    expect(pending.pendingChanges).toContain("allowlisted: false -> true");
  });

  test("reports full-directory narrow image drift", async () => {
    const imageDir = path.join(root, ".runfree", "image");
    fs.mkdirSync(imageDir);
    fs.writeFileSync(
      path.join(root, ".runfree", "runfree.json"),
      `${JSON.stringify({
        ...defaultConfig(),
        runtime: {
          ...defaultConfig().runtime,
          agent: { build: { context: ".runfree/image", dockerfile: ".runfree/image/Dockerfile" } },
        },
      })}\n`,
    );
    fs.writeFileSync(
      path.join(imageDir, "Dockerfile"),
      "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\nCOPY tool.sh /usr/local/bin/tool\n",
    );
    fs.writeFileSync(path.join(imageDir, "tool.sh"), "#!/bin/sh\necho first\n", { mode: 0o755 });
    const first = await inspectControlStatus(context, io);
    expect(first.subjects.imageBuild.desiredDigest).toMatch(/^sha256:/);

    fs.writeFileSync(path.join(imageDir, "tool.sh"), "#!/bin/sh\necho second\n", { mode: 0o755 });
    const second = await inspectControlStatus(context, io);
    expect(second.subjects.imageBuild.desiredDigest).not.toBe(first.subjects.imageBuild.desiredDigest);
  });

  test("classifies scoped reductions and expansions against the complete approved baseline", async () => {
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive");

    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":[]}`);
    const reduction = await inspectNetworkPolicyReview(context, io, "project");
    expect(reduction.diffs[0]).toMatchObject({
      scope: "project",
      classification: "reduction",
      reasons: [],
    });
    expect(reduction.diffs[0].changes).toContain("host example.com: removed");
    expect(reduction.policies.local).toBeUndefined();

    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["example.com","new.example.com"]}`);
    const expansion = await inspectNetworkPolicyReview(context, io, "project");
    expect(expansion.diffs[0]).toMatchObject({
      scope: "project",
      classification: "approval-required",
      reasons: ["new.example.com: host added"],
    });
    expect(expansion.diffs[0].changes).toContain("host new.example.com: added");
  });

  function approveEverythingThenMismatch(): string {
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(root, context.project, "interactive");
    const approvalsPath = context.project.paths.controlApprovalsPath;
    const stored = JSON.parse(fs.readFileSync(approvalsPath, "utf8")) as { checkoutBinding: { rootInode: string } };
    stored.checkoutBinding.rootInode = "999999999";
    const mismatched = `${JSON.stringify(stored, null, 2)}\n`;
    fs.writeFileSync(approvalsPath, mismatched);
    return mismatched;
  }

  test("a convergence receipt is not reported when no proxy is live", async () => {
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(root, context.project, "interactive");
    const generation = publishEffectivePolicyGeneration(root, context.project);
    await convergeEffectivePolicyGeneration(context.project, {
      probe: async () => ({
        requestProxy: {
          generation: generation.policyGeneration,
          controlGeneration: generation.controlGeneration,
          policyGeneration: generation.policyGeneration,
        },
        firewall: {
          generation: generation.policyGeneration,
          controlGeneration: generation.controlGeneration,
          policyGeneration: generation.policyGeneration,
          rulesetVerified: true,
        },
      }),
      stopRuntime: async () => {},
      timeoutMs: 0,
    });
    expect((await inspectControlStatus(context, io)).converged).toBeDefined();

    // The proxy stops. The generation is unchanged, so the stored receipt
    // survives — but status must stop claiming a verified ruleset.
    liveProxyId = "";

    const stopped = await inspectControlStatus(context, io);
    expect(stopped.proxyLive).toBe(false);
    expect(stopped.converged).toBeUndefined();
  });

  test("status names the approval read kind and never rewrites the record", async () => {
    const mismatched = approveEverythingThenMismatch();

    const status = await inspectControlStatus(context, io);

    expect(status.approvalRead).toBe("mismatch");
    expect(status.approvalError).toContain("the directory at this path was replaced");
    expect(status.layers.project.approvedDigest).toBeUndefined();
    expect(status.approvalSetDigest).toBeUndefined();
    expect(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")).toBe(mismatched);
  });

  test("status names a corrupt record as corrupt, never as missing", async () => {
    approveEverythingThenMismatch();
    const approvalsPath = context.project.paths.controlApprovalsPath;
    const garbage = `{"schemaVersion":1,"subjects":\n`;
    fs.writeFileSync(approvalsPath, garbage);

    const status = await inspectControlStatus(context, io);

    expect(status.approvalRead).toBe("corrupt");
    expect(status.approvalError).toContain("could not be read");
    expect(fs.readFileSync(approvalsPath, "utf8")).toBe(garbage);
  });

  test("the review named in the refusal still renders under a mismatch", async () => {
    // `policy review --project` is the reclamation path the refusal names. If
    // it threw here, the refusal would point at a wedge.
    approveEverythingThenMismatch();

    const review = await inspectNetworkPolicyReview(context, io, "project");

    expect(review.diffs[0]).toMatchObject({ scope: "project", classification: "unapproved" });
    expect(review.diffs[0].approvedDigest).toBeUndefined();
    expect(review.policies.project?.hosts).toEqual(["example.com"]);
  });

  test("host explanation degrades under a mismatch instead of throwing", async () => {
    approveEverythingThenMismatch();

    const explanation = await inspectPolicyHost(context, io, "example.com");

    expect(explanation.desired?.allowlisted).toBe(true);
    expect(explanation.approved).toBeUndefined();
    expect(explanation.approvals.project).toBeUndefined();
  });
});
