import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { projectInfo } from "../config.ts";
import { composeProjectName } from "../runtime/env.ts";
import { projectHash } from "../project-identity.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { activateApprovedControlsAfterMutation } from "./activation.ts";
import {
  approveNetworkCandidate,
  approveRuntimeIsolationControl,
} from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import {
  publishEffectivePolicyGeneration,
  readActiveControlSelection,
  readActiveEffectiveControl,
  readConvergedPolicyReceipt,
  verifyEffectivePolicyGeneration,
} from "./effective.ts";

describe("post-mutation control activation", () => {
  let root: string;
  let stateHome: string;
  let context: RuntimeContext;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-control-activation-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-control-activation-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), '{"version":2,"hosts":["example.com"]}\n');
    const env = { XDG_STATE_HOME: stateHome, XDG_CONFIG_HOME: path.join(stateHome, "config") };
    const project = projectInfo(root, env);
    context = { projectRoot: root, project, runtimeRoot: path.join(root, "runtime"), env };
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true });
    fs.rmSync(stateHome, { recursive: true });
  });

  const unusedIo: RuntimeIO = {
    capture: () => {
      throw new Error("unexpected command");
    },
    run: () => 0,
    commandExists: () => true,
    confirm: () => false,
    admin: async () => 0,
  };

  function approveAll(): void {
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(root, context.project, "interactive");
  }

  function approveChangedProject(hosts: string[]): void {
    fs.writeFileSync(
      path.join(root, ".runfree", "network-policy.json"),
      `${JSON.stringify({ version: 2, hosts })}\n`,
    );
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "typed-host-command");
  }

  test("selects an approved generation without claiming convergence when no proxy is live", async () => {
    approveAll();
    const previous = publishEffectivePolicyGeneration(root, context.project);
    approveChangedProject(["example.com", "new.example.com"]);

    const result = await activateApprovedControlsAfterMutation(context, unusedIo, {
      consumer: { running: false, probe: async () => ({}), stop: async () => {} },
    });

    expect(result.kind).toBe("selected");
    expect(result).not.toMatchObject({ controlGeneration: previous.controlGeneration });
    expect(readConvergedPolicyReceipt(context.project)).toBeUndefined();
  });

  test("requires both live proxy consumers to acknowledge before reporting convergence", async () => {
    approveAll();
    publishEffectivePolicyGeneration(root, context.project);
    approveChangedProject(["example.com", "new.example.com"]);

    const result = await activateApprovedControlsAfterMutation(context, unusedIo, {
      consumer: {
        running: true,
        probe: async () => {
          const active = readActiveControlSelection(context.project);
          if (!active) return {};
          const generation = verifyEffectivePolicyGeneration(context.project, active.controlGeneration);
          return {
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
          };
        },
        stop: async () => {
          throw new Error("must not stop a converged runtime");
        },
      },
      timeoutMs: 0,
    });

    expect(result.kind).toBe("converged");
    expect(readConvergedPolicyReceipt(context.project)?.controlGeneration)
      .toBe(readActiveControlSelection(context.project)?.controlGeneration);
  });

  test("restores the prior selection when live-consumer discovery cannot be proved", async () => {
    approveAll();
    const previous = publishEffectivePolicyGeneration(root, context.project);
    approveChangedProject(["example.com", "new.example.com"]);
    const failingIo: RuntimeIO = {
      ...unusedIo,
      capture: () => ({ status: 1, stdout: "", stderr: "daemon unavailable" }),
    };

    await expect(activateApprovedControlsAfterMutation(context, failingIo))
      .rejects.toThrow("could not identify the live proxy consumer");
    expect(readActiveControlSelection(context.project)?.controlGeneration).toBe(previous.controlGeneration);
  });

  test("can recover an invalid active selection only when explicitly requested", async () => {
    approveAll();
    const generation = publishEffectivePolicyGeneration(root, context.project);
    fs.chmodSync(context.project.paths.controlProxyActivePath, 0o600);
    fs.writeFileSync(context.project.paths.controlProxyActivePath, "not-json\n");

    await expect(activateApprovedControlsAfterMutation(context, unusedIo, {
      consumer: { running: false, probe: async () => ({}), stop: async () => {} },
    })).rejects.toThrow();

    const recovered = await activateApprovedControlsAfterMutation(context, unusedIo, {
      consumer: { running: false, probe: async () => ({}), stop: async () => {} },
      recoverInvalidActive: true,
    });
    expect(recovered).toEqual({ kind: "selected", controlGeneration: generation.controlGeneration });
    expect(readActiveControlSelection(context.project)?.controlGeneration).toBe(generation.controlGeneration);
  });

  test("defers without publishing when the complete approval set is absent", async () => {
    const result = await activateApprovedControlsAfterMutation(context, unusedIo);

    expect(result).toMatchObject({ kind: "deferred" });
    expect(readActiveControlSelection(context.project)).toBeUndefined();
  });

  test.each([false, true])("containment rechecks a replacement under the lock (already converged: %s)", async (converged) => {
    approveAll();
    publishEffectivePolicyGeneration(root, context.project);
    approveChangedProject(["example.com", "new.example.com"]);
    const oldProxyId = "a".repeat(64);
    const replacementId = "b".repeat(64);
    let currentId = oldProxyId;
    let running = true;
    const stops: string[] = [];
    const receiptReads: string[] = [];
    const io: RuntimeIO = { ...unusedIo, capture(_command, args) {
      if (args[0] === "ps") {
        const exact = args.find((arg) => arg.startsWith("id="))?.slice(3);
        return { status: 0, stdout: exact ? exact === currentId ? currentId : "" : running ? currentId : "", stderr: "" };
      }
      if (args[0] === "exec") {
        const id = args[1];
        receiptReads.push(id);
        if (id === oldProxyId) {
          // A concurrent replacement completes after discovery and before
          // failure containment acquires its lifecycle fence.
          currentId = replacementId;
          return { status: 0, stdout: "{}\n{}\n", stderr: "" };
        }
        const selected = readActiveEffectiveControl(context.project);
        const status = converged && selected ? { generation: selected.policyGeneration,
          controlGeneration: selected.controlGeneration, policyGeneration: selected.policyGeneration, rulesetVerified: true } : {};
        return { status: 0, stdout: `${JSON.stringify(status)}\n${JSON.stringify(status)}\n`, stderr: "" };
      }
      if (args[0] === "container" && args[1] === "inspect") {
        expect(args[2]).toBe(replacementId);
        return { status: 0, stdout: JSON.stringify([{ Id: replacementId, State: { Running: running }, Config: { Labels: {
          "io.runfree.project-id": projectHash(root), "io.runfree.container-role": "proxy",
          "com.docker.compose.project": composeProjectName(root), "com.docker.compose.service": "proxy",
        } } }]), stderr: "" };
      }
      if (args[0] === "stop") { stops.push(args.at(-1) as string); running = false; return { status: 0, stdout: replacementId, stderr: "" }; }
      throw new Error(`unexpected Docker effect: ${args.join(" ")}`);
    } };
    await expect(activateApprovedControlsAfterMutation(context, io, { timeoutMs: 0 }))
      .rejects.toThrow(converged ? "proxy preserved; retry policy activation" : "proxy stopped");
    expect(receiptReads).toContain(replacementId);
    expect(stops).toEqual(converged ? [] : [replacementId]);
    expect(running).toBe(converged);
    // A fresh activation can observe the repaired/current proxy and converge.
    if (converged) await expect(activateApprovedControlsAfterMutation(context, io, { timeoutMs: 0 })).resolves.toMatchObject({ kind: "converged" });
  });

});
