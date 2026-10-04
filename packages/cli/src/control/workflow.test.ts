import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { projectInfo } from "../config.ts";
import { desiredServiceEntry } from "../admin/service-policy.ts";
import { service } from "../../../../scripts/services.ts";
import { projectHash } from "../project-identity.ts";
import { composeProjectName } from "../runtime/env.ts";
import {
  sessionContainerRecordFixture,
  writeLiveAttachedSessionContainerRecordFixture,
} from "../runtime/session-container.test-harness.ts";
import { writeSessionContainerRecordV2 } from "../runtime/session-containers.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { readApprovedNetworkPolicy, readControlApprovalSelection } from "./approvals.ts";
import {
  approveAutomaticNetworkReduction,
  approveNetworkControl,
  approveRuntimeIsolation,
  captureQuiescedDesiredPolicyCandidate,
  prepareEffectiveControlsForStartup,
  usePreparedApprovedPolicyGeneration,
} from "./workflow.ts";
import { readActiveControlSelection } from "./effective.ts";
import type { HostServiceAdmit } from "./host-service-approval-admission.ts";
import { desiredPolicyReviewLines } from "./review-render.ts";

describe("quiesced control workflow", () => {
  let root: string;
  let stateHome: string;
  let context: RuntimeContext;
  let calls: string[][];

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-control-workflow-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-control-workflow-state-"));
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
    calls = [];
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true });
    fs.rmSync(stateHome, { recursive: true });
  });

  function io(onPs?: () => void): RuntimeIO {
    return {
      capture: (_command, args) => {
        calls.push(args);
        if (args[0] === "ps") {
          onPs?.();
          return { status: 0, stdout: "", stderr: "" };
        }
        throw new Error(`unexpected Docker call: ${args.join(" ")}`);
      },
      run: () => 0,
      commandExists: () => true,
      confirm: () => false,
      admin: async () => 0,
    };
  }

  test("captures recognized desired input under the lock without touching any container", async () => {
    const candidate = await captureQuiescedDesiredPolicyCandidate(context, io());
    expect(candidate.project.hosts).toEqual(["example.com"]);
    expect(calls).toEqual([]);
  });

  test("rejects a digest mismatch without selecting any approval", async () => {
    await expect(approveNetworkControl(context, io(), "network-project", {
      expectedDigest: `sha256:${"0".repeat(64)}`,
      mechanism: "digest-command",
    })).rejects.toThrow("subject digest changed");
    expect(readControlApprovalSelection(root, context.project)).toBeUndefined();
  });

  test("selects exact network and runtime subjects after quiesced capture", async () => {
    const candidate = await captureQuiescedDesiredPolicyCandidate(context, io());
    await approveNetworkControl(context, io(), "network-project", {
      expectedDigest: candidate.projectSubject.digest,
      mechanism: "digest-command",
      now: new Date("2026-08-05T00:00:00.000Z"),
    });
    const runtime = await approveRuntimeIsolation(context, io(), {
      mechanism: "interactive",
      now: new Date("2026-08-05T00:00:01.000Z"),
    });
    expect(runtime.subjects["network-project"]?.digest).toBe(candidate.projectSubject.digest);
    expect(runtime.subjects["runtime-isolation"]?.mechanism).toBe("interactive");
  });

  test("interactive approval binds the captured candidate while later worktree edits remain drift", async () => {
    const captured = await captureQuiescedDesiredPolicyCandidate(context, io());
    const selection = await approveNetworkControl(context, io(), "network-project", {
      mechanism: "interactive",
      confirm: (candidate, subject) => {
        expect(candidate.projectSubject.digest).toBe(captured.projectSubject.digest);
        expect(subject.digest).toBe(captured.projectSubject.digest);
        fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["later.example.com"]}`);
        return true;
      },
    });

    expect(selection.subjects["network-project"]?.digest).toBe(captured.projectSubject.digest);
    const later = await captureQuiescedDesiredPolicyCandidate(context, io());
    expect(later.projectSubject.digest).not.toBe(captured.projectSubject.digest);
  });

  test("declined interactive approval leaves authority unchanged", async () => {
    await expect(approveNetworkControl(context, io(), "network-project", {
      mechanism: "interactive",
      confirm: () => false,
    })).rejects.toThrow("approval declined");
    expect(readControlApprovalSelection(root, context.project)).toBeUndefined();
  });

  test("does not read desired input while a per-session agent is live", async () => {
    // The startup/approval capture keeps the live-session refusal (A2 scope):
    // only the typed desired-policy mutations opt in to live sessions.
    writeLiveAttachedSessionContainerRecordFixture({
      stateDir: context.project.paths.stateDir,
      projectRoot: root,
      env: context.env,
    });
    const policyPath = path.join(root, ".runfree", "network-policy.json");
    fs.chmodSync(policyPath, 0o000);
    await expect(captureQuiescedDesiredPolicyCandidate(context, io()))
      .rejects.toThrow("control change deferred because 1 active per-session agent is running");
    fs.chmodSync(policyPath, 0o600);
    expect(fs.existsSync(context.project.paths.controlCandidatesDir)).toBe(false);
  });

  test("automatically approves only a proven authority reduction", async () => {
    const first = await captureQuiescedDesiredPolicyCandidate(context, io());
    await approveNetworkControl(context, io(), "network-project", {
      expectedDigest: first.projectSubject.digest,
      mechanism: "interactive",
    });
    await approveNetworkControl(context, io(), "network-local", {
      expectedDigest: first.localSubject.digest,
      mechanism: "interactive",
    });
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":[]}`);
    const reduced = await approveAutomaticNetworkReduction(context, io(), "network-project");
    expect(reduced.comparison).toEqual({ provenReduction: true, reasons: [] });
    expect(reduced.selection.subjects["network-project"]?.mechanism).toBe("automatic-reduction");

    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["new.example.com"]}`);
    const selectedBefore = readControlApprovalSelection(root, context.project)?.subjects["network-project"]?.digest;
    await expect(approveAutomaticNetworkReduction(context, io(), "network-project")).rejects.toThrow("not a proven authority reduction");
    expect(readControlApprovalSelection(root, context.project)?.subjects["network-project"]?.digest).toBe(selectedBefore);
  });

  test("an agent-added host service is widening, not an automatic reduction (SR1)", async () => {
    const first = await captureQuiescedDesiredPolicyCandidate(context, io());
    await approveNetworkControl(context, io(), "network-project", {
      expectedDigest: first.projectSubject.digest,
      mechanism: "interactive",
    });
    await approveNetworkControl(context, io(), "network-local", {
      expectedDigest: first.localSubject.digest,
      mechanism: "interactive",
    });

    // As the agent would: added to the project-tracked policy file.
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), JSON.stringify({
      version: 2,
      hosts: ["example.com"],
      hostServices: { idb: { target: "host-loopback", port: 10882 } },
    }));
    const selectedBefore = readControlApprovalSelection(root, context.project)?.subjects["network-project"]?.digest;
    await expect(approveAutomaticNetworkReduction(context, io(), "network-project")).rejects.toThrow("not a proven authority reduction");
    expect(readControlApprovalSelection(root, context.project)?.subjects["network-project"]?.digest).toBe(selectedBefore);
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")?.hostServices).toBeUndefined();

    // Reset, then try the same widening through the checkout-local layer.
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["example.com"]}`);
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.local.json"), JSON.stringify({
      version: 2,
      hosts: [],
      hostServices: { idb: { target: "host-loopback", port: 10882 } },
    }));
    const selectedLocalBefore = readControlApprovalSelection(root, context.project)?.subjects["network-local"]?.digest;
    await expect(approveAutomaticNetworkReduction(context, io(), "network-local")).rejects.toThrow("not a proven authority reduction");
    expect(readControlApprovalSelection(root, context.project)?.subjects["network-local"]?.digest).toBe(selectedLocalBefore);
    expect(readApprovedNetworkPolicy(root, context.project, "network-local")?.hostServices).toBeUndefined();
  });

  const IDB_POLICY = (port: number) => JSON.stringify({
    version: 2,
    hosts: ["example.com"],
    hostServices: { idb: { target: "host-loopback", port } },
  });
  const admitted: HostServiceAdmit = (_runtime, _io, port) => ({ ok: true, owner: { command: `owner-${port}`, pid: 4242 } });
  const refused: HostServiceAdmit = (_runtime, _io, port) => ({ ok: false, reason: `no process listens on 127.0.0.1:${port}` });

  /** Both network layers approved as they stand now (host services admitted by a stub). */
  async function approveBothLayers(): Promise<void> {
    const candidate = await captureQuiescedDesiredPolicyCandidate(context, io());
    for (const subjectType of ["network-project", "network-local"] as const) {
      await approveNetworkControl(context, io(), subjectType, {
        expectedDigest: subjectType === "network-project" ? candidate.projectSubject.digest : candidate.localSubject.digest,
        mechanism: "digest-command",
        admitHostService: admitted,
      });
    }
  }

  test("an agent re-pointing an approved host service to another port is refused by automatic reduction and startup, in both layers (SR1)", async () => {
    const localPath = path.join(root, ".runfree", "network-policy.local.json");
    for (const layer of ["project", "local"] as const) {
      const layerPath = layer === "project" ? path.join(root, ".runfree", "network-policy.json") : localPath;
      const subjectType = layer === "project" ? "network-project" : "network-local";
      // Approved: idb on 10882 in this layer only.
      fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), layer === "project" ? IDB_POLICY(10882) : `{"version":2,"hosts":["example.com"]}`);
      fs.writeFileSync(localPath, layer === "local"
        ? JSON.stringify({ version: 2, hosts: [], hostServices: { idb: { target: "host-loopback", port: 10882 } } })
        : `{"version":2,"hosts":[]}`);
      await approveBothLayers();
      const interactive = io();
      interactive.isInteractive = () => true;
      interactive.confirm = () => true;
      const started = await prepareEffectiveControlsForStartup(context, interactive, { admitHostService: admitted });
      const selectedBefore = readControlApprovalSelection(root, context.project)?.subjects[subjectType]?.digest;

      // As the agent would: the same name, another port.
      const repointed = JSON.parse(fs.readFileSync(layerPath, "utf8")) as { hostServices: Record<string, { port: number }> };
      repointed.hostServices.idb.port = 10883;
      fs.writeFileSync(layerPath, JSON.stringify(repointed));

      await expect(approveAutomaticNetworkReduction(context, io(), subjectType)).rejects.toThrow("not a proven authority reduction");
      const nonInteractive = io();
      nonInteractive.isInteractive = () => false;
      await expect(prepareEffectiveControlsForStartup(context, nonInteractive)).rejects.toThrow(
        "desired controls require exact approval before startup",
      );
      expect(readControlApprovalSelection(root, context.project)?.subjects[subjectType]?.digest, layer).toBe(selectedBefore);
      expect(readApprovedNetworkPolicy(root, context.project, subjectType)?.hostServices?.idb?.port, layer).toBe(10882);
      expect(readActiveControlSelection(context.project)?.controlGeneration, layer).toBe(started.generation.controlGeneration);
    }
  });

  test("policy approval of an agent-added host service runs the port admission and refuses before writing (R21)", async () => {
    await approveBothLayers();
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), IDB_POLICY(10882));
    const before = fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8");
    const admit = vi.fn(refused);
    const confirm = vi.fn(() => true);

    for (const mechanism of ["digest-command", "interactive"] as const) {
      const candidate = await captureQuiescedDesiredPolicyCandidate(context, io());
      await expect(approveNetworkControl(context, io(), "network-project", {
        ...(mechanism === "digest-command" ? { expectedDigest: candidate.projectSubject.digest } : { confirm }),
        mechanism,
        admitHostService: admit,
      })).rejects.toThrow(/failed the port admission[\s\S]*host service idb \(127\.0\.0\.1:10882, project layer\): no process listens[\s\S]*runfree policy review --project/u);
    }
    expect(admit).toHaveBeenCalledTimes(2);
    expect(confirm).not.toHaveBeenCalled();
    expect(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")).toBe(before);
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")?.hostServices).toBeUndefined();

    // An unchanged host service is not re-admitted; only additions and re-ports are.
    const unrelated = vi.fn(admitted);
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["example.com","other.example.com"]}`);
    await approveNetworkControl(context, io(), "network-project", { mechanism: "interactive", confirm: () => true, admitHostService: unrelated });
    expect(unrelated).not.toHaveBeenCalled();
  });

  test("an admitted host service is approved, and the review names the admitted listener (R21)", async () => {
    await approveBothLayers();
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), IDB_POLICY(10882));
    let reviewed: string[] = [];
    const selection = await approveNetworkControl(context, io(), "network-project", {
      mechanism: "interactive",
      admitHostService: admitted,
      confirm: (candidate, subject, owners) => {
        reviewed = desiredPolicyReviewLines(context, candidate, subject, "project", owners);
        return true;
      },
    });
    expect(reviewed).toContain("  - host service idb: null -> 127.0.0.1:10882 (owner-10882, pid 4242)");
    expect(selection.subjects["network-project"]?.mechanism).toBe("interactive");
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")?.hostServices?.idb?.port).toBe(10882);
  });

  test("the interactive startup approval runs the port admission before consent (R21)", async () => {
    const interactive = io();
    interactive.isInteractive = () => true;
    interactive.confirm = () => true;
    const started = await prepareEffectiveControlsForStartup(context, interactive);
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), IDB_POLICY(10882));
    const before = fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8");

    const refusing = io();
    refusing.isInteractive = () => true;
    const confirm = vi.fn(() => true);
    refusing.confirm = confirm;
    await expect(prepareEffectiveControlsForStartup(context, refusing, { admitHostService: refused }))
      .rejects.toThrow("failed the port admission");
    expect(confirm).not.toHaveBeenCalled();
    expect(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")).toBe(before);
    expect(readActiveControlSelection(context.project)?.controlGeneration).toBe(started.generation.controlGeneration);

    const accepting = io();
    accepting.isInteractive = () => true;
    const prompts: string[] = [];
    accepting.confirm = (message: string) => {
      prompts.push(message);
      return true;
    };
    const approved = await prepareEffectiveControlsForStartup(context, accepting, { admitHostService: admitted });
    expect(approved.mechanism).toBe("interactive");
    expect(prompts.join("\n")).toContain("host service idb: 127.0.0.1:10882 (owner-10882, pid 4242)");
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")?.hostServices?.idb?.port).toBe(10882);
  });

  test("refuses first startup non-interactively before selecting effective authority", async () => {
    const nonInteractive = io();
    nonInteractive.isInteractive = () => false;
    await expect(prepareEffectiveControlsForStartup(context, nonInteractive)).rejects.toThrow(
      "runfree control approve network-project --subject-digest sha256:",
    );
    expect(readActiveControlSelection(context.project)).toBeUndefined();
  });

  test("approves one exact interactive startup preflight and reuses it without prompting", async () => {
    const interactive = io();
    interactive.isInteractive = () => true;
    interactive.confirm = () => true;
    const first = await prepareEffectiveControlsForStartup(context, interactive);
    expect(first.mechanism).toBe("interactive");
    expect(readActiveControlSelection(context.project)?.controlGeneration).toBe(first.generation.controlGeneration);
    expect(readControlApprovalSelection(root, context.project)?.subjects).toMatchObject({
      "network-project": { mechanism: "interactive" },
      "network-local": { mechanism: "interactive" },
      "runtime-isolation": { mechanism: "interactive" },
    });

    const reused = io();
    reused.isInteractive = () => false;
    reused.confirm = () => {
      throw new Error("unchanged approved controls must not prompt");
    };
    await expect(prepareEffectiveControlsForStartup(context, reused)).resolves.toMatchObject({
      mechanism: "already-approved",
      generation: { controlGeneration: first.generation.controlGeneration },
    });
  });

  test("reuses active effective controls for a concurrent session without reading desired input", async () => {
    const interactive = io();
    interactive.isInteractive = () => true;
    interactive.confirm = () => true;
    const first = await prepareEffectiveControlsForStartup(context, interactive);
    const projectId = projectHash(context.projectRoot);
    const composeProject = composeProjectName(context.projectRoot);
    const sessionId = "rf-20260826-concur1";
    const base = sessionContainerRecordFixture({
      containerId: "c".repeat(64),
      overrides: {
        projectId,
        composeProject,
        sessionId,
        containerName: `runfree-${projectId}-session-${sessionId}`,
        hostPid: process.pid,
        hostBootId: context.env?.RUNFREE_TEST_HOST_BOOT_ID,
        hostProcessStart: context.env?.RUNFREE_TEST_HOST_PROCESS_START,
        createdAt: "2026-08-26T00:00:00.000Z",
      },
    });
    writeSessionContainerRecordV2(context.project.paths.stateDir, { projectId, composeProject }, {
      ...base,
      state: "attached",
      admittedAt: "2026-08-26T00:00:01.000Z",
      leaseGeneration: "8".repeat(32),
      leaseExpiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    });
    fs.writeFileSync(context.project.paths.policyPath, "invalid desired policy that must remain unread\n");

    calls = [];
    const concurrent = io();
    concurrent.isInteractive = () => false;
    concurrent.admin = async () => {
      throw new Error("concurrent startup must not prepare or publish controls");
    };

    await expect(prepareEffectiveControlsForStartup(context, concurrent)).resolves.toMatchObject({
      mechanism: "active-session",
      generation: { controlGeneration: first.generation.controlGeneration },
    });
    expect(calls).toEqual([]);
    expect(readActiveControlSelection(context.project)?.controlGeneration).toBe(first.generation.controlGeneration);
  });

  // T12. The gate is placed before the active-session short-circuit precisely
  // for this shape: that branch returns the published generation without ever
  // reading the selection, and `ensureRuntimeMaterialized` still runs after it.
  // With image approval prepared on every launch rather than only on a build, a
  // cached custom image on this entry would otherwise be the first thing to meet
  // a record that carries no authority — and it would write a one-subject
  // selection over configuration approvals whose generation is live.
  test("a binding mismatch on the active-session entry refuses before anything is materialized", async () => {
    const interactive = io();
    interactive.isInteractive = () => true;
    interactive.confirm = () => true;
    const first = await prepareEffectiveControlsForStartup(context, interactive);
    writeLiveAttachedSessionContainerRecordFixture({
      stateDir: context.project.paths.stateDir,
      projectRoot: root,
      env: context.env,
    });
    const approvalsPath = context.project.paths.controlApprovalsPath;
    const stored = JSON.parse(fs.readFileSync(approvalsPath, "utf8")) as { checkoutBinding: { rootInode: string } };
    stored.checkoutBinding.rootInode = "999999999";
    const mismatched = `${JSON.stringify(stored, null, 2)}\n`;
    fs.writeFileSync(approvalsPath, mismatched);

    const entry = io();
    entry.isInteractive = () => false;
    entry.admin = async () => { throw new Error("a non-valid selection must not prepare or publish controls"); };

    // Reaching the short-circuit would have resolved with the live generation.
    await expect(prepareEffectiveControlsForStartup(context, entry))
      .rejects.toThrow("control change deferred because 1 active per-session agent is running");

    expect(fs.readFileSync(approvalsPath, "utf8")).toBe(mismatched);
    expect(readActiveControlSelection(context.project)?.controlGeneration).toBe(first.generation.controlGeneration);
  });

  test("publishes a proven startup reduction without interactive approval", async () => {
    const interactive = io();
    interactive.isInteractive = () => true;
    interactive.confirm = () => true;
    const first = await prepareEffectiveControlsForStartup(context, interactive);
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":[]}`);

    const nonInteractive = io();
    nonInteractive.isInteractive = () => false;
    const reduced = await prepareEffectiveControlsForStartup(context, nonInteractive);
    expect(reduced.mechanism).toBe("automatic-reduction");
    expect(reduced.generation.controlGeneration).not.toBe(first.generation.controlGeneration);
    expect(readControlApprovalSelection(root, context.project)?.subjects["network-project"]?.mechanism)
      .toBe("automatic-reduction");
  });

  test("does not auto-approve an agent-added host service at startup (SR1)", async () => {
    const interactive = io();
    interactive.isInteractive = () => true;
    interactive.confirm = () => true;
    const first = await prepareEffectiveControlsForStartup(context, interactive);
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), JSON.stringify({
      version: 2,
      hosts: ["example.com"],
      hostServices: { idb: { target: "host-loopback", port: 10882 } },
    }));

    const nonInteractive = io();
    nonInteractive.isInteractive = () => false;
    await expect(prepareEffectiveControlsForStartup(context, nonInteractive)).rejects.toThrow(
      "desired controls require exact approval before startup",
    );
    expect(readActiveControlSelection(context.project)?.controlGeneration).toBe(first.generation.controlGeneration);
  });

  test("recovers approved controls without reading invalid desired or corrupt active state", async () => {
    const interactive = io();
    interactive.isInteractive = () => true;
    interactive.confirm = () => true;
    const first = await prepareEffectiveControlsForStartup(context, interactive);
    fs.writeFileSync(context.project.paths.policyPath, "not valid desired JSON\n");
    fs.chmodSync(context.project.paths.controlProxyActivePath, 0o600);
    fs.writeFileSync(context.project.paths.controlProxyActivePath, "not valid active JSON\n");

    const recovered = await usePreparedApprovedPolicyGeneration(context, io());

    expect(recovered.policyGeneration).toBe(first.generation.policyGeneration);
    expect(readActiveControlSelection(context.project)?.controlGeneration).toBe(recovered.controlGeneration);
  });

  test("pairs host-approved MCP OAuth policy into the selected immutable generation", async () => {
    fs.mkdirSync(path.dirname(context.project.paths.mcpOAuthPolicyPath), { recursive: true });
    fs.writeFileSync(context.project.paths.mcpOAuthPolicyPath, JSON.stringify({
      providers: {
        "mcp:example": {
          kind: "mcp",
          resourceHost: "example.com",
          tokenEndpoints: [{ host: "example.com", path: "/oauth/token" }],
        },
      },
    }));
    const interactive = io();
    interactive.isInteractive = () => true;
    interactive.confirm = () => true;

    const prepared = await prepareEffectiveControlsForStartup(context, interactive);
    expect(JSON.parse(fs.readFileSync(prepared.generation.oauthPolicyPath, "utf8")))
      .toMatchObject({ providers: { "mcp:example": { kind: "mcp", resourceHost: "example.com" } } });
  });

  test("projects only host-owned OAuth handles and declared parameter values into effective controls", async () => {
    const appleAds = service("apple-ads");
    if (!appleAds) throw new Error("apple-ads service missing");
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), JSON.stringify({
      version: 2,
      hosts: [],
      services: { "apple-ads": desiredServiceEntry(appleAds) },
    }));
    fs.mkdirSync(path.dirname(context.project.paths.controlAgentEnvPath), { recursive: true });
    const handle = "runfree_oauth_secret_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fs.writeFileSync(context.project.paths.controlAgentEnvPath, [
      "APPLE_ADS_CLIENT_ID=SEARCHADS.host-owned",
      `APPLE_ADS_CLIENT_SECRET=${handle}`,
      "",
    ].join("\n"));
    fs.writeFileSync(path.join(context.project.paths.stateDir, "oauth-handles.json"), JSON.stringify({
      schemaVersion: 1,
      providers: { "service:apple-ads": { client_secret: handle } },
    }));
    fs.mkdirSync(path.dirname(context.project.paths.agentEnvPath), { recursive: true });
    fs.writeFileSync(context.project.paths.agentEnvPath, [
      "APPLE_ADS_CLIENT_ID=SEARCHADS.agent-controlled",
      "APPLE_ADS_CLIENT_SECRET=runfree_oauth_secret_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "",
    ].join("\n"));
    const interactive = io();
    interactive.isInteractive = () => true;
    interactive.confirm = () => true;

    const prepared = await prepareEffectiveControlsForStartup(context, interactive);
    expect(fs.readFileSync(prepared.generation.agentEnvPath, "utf8")).toBe([
      "APPLE_ADS_CLIENT_ID=SEARCHADS.host-owned",
      `APPLE_ADS_CLIENT_SECRET=${handle}`,
      "",
    ].join("\n"));
    expect(JSON.parse(fs.readFileSync(prepared.generation.oauthPolicyPath, "utf8")))
      .toMatchObject({ providers: { "service:apple-ads": { seeds: [{ handle }] } } });
  });

  test("still projects parameter values declared by a legacy OAuth passthrough entry", async () => {
    const appleAds = service("apple-ads");
    if (!appleAds) throw new Error("apple-ads service missing");
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), JSON.stringify({
      version: 2,
      hosts: [],
      services: {
        "apple-ads": (() => {
          // A policy approved before `resolved.parameters` existed: the client
          // id was declared under the OAuth provider's `passthrough` list.
          const entry = structuredClone(desiredServiceEntry(appleAds));
          const { parameters: _dropped, ...resolved } = entry.resolved;
          const provider = resolved.oauth?.["service:apple-ads"];
          if (!provider) throw new Error("apple-ads OAuth provider missing");
          provider.passthrough = [{ envVar: "APPLE_ADS_CLIENT_ID", field: "client_id" }];
          return { ...entry, resolved };
        })(),
      },
    }));
    fs.mkdirSync(path.dirname(context.project.paths.controlAgentEnvPath), { recursive: true });
    const handle = "runfree_oauth_secret_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fs.writeFileSync(context.project.paths.controlAgentEnvPath, [
      "APPLE_ADS_CLIENT_ID=SEARCHADS.host-owned",
      `APPLE_ADS_CLIENT_SECRET=${handle}`,
      "",
    ].join("\n"));
    fs.writeFileSync(path.join(context.project.paths.stateDir, "oauth-handles.json"), JSON.stringify({
      schemaVersion: 1,
      providers: { "service:apple-ads": { client_secret: handle } },
    }));
    fs.mkdirSync(path.dirname(context.project.paths.agentEnvPath), { recursive: true });
    fs.writeFileSync(context.project.paths.agentEnvPath, [
      "APPLE_ADS_CLIENT_ID=SEARCHADS.agent-controlled",
      "APPLE_ADS_CLIENT_SECRET=runfree_oauth_secret_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "",
    ].join("\n"));
    const interactive = io();
    interactive.isInteractive = () => true;
    interactive.confirm = () => true;

    const prepared = await prepareEffectiveControlsForStartup(context, interactive);
    expect(fs.readFileSync(prepared.generation.agentEnvPath, "utf8")).toBe([
      "APPLE_ADS_CLIENT_ID=SEARCHADS.host-owned",
      `APPLE_ADS_CLIENT_SECRET=${handle}`,
      "",
    ].join("\n"));
    expect(JSON.parse(fs.readFileSync(prepared.generation.oauthPolicyPath, "utf8")))
      .toMatchObject({ providers: { "service:apple-ads": { seeds: [{ handle }] } } });
  });
});
