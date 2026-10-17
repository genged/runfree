import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { projectInfo } from "../config.ts";
import { RUNFREE_RUNTIME_COMPONENTS } from "../embedded-assets.generated.ts";
import { composeProjectName } from "../runtime/env.ts";
import { projectHash } from "../project-identity.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { activateApprovedControlsAfterMutation, withFencedReceiptRead } from "./activation.ts";
import { activationReportLine } from "./activation-report.ts";
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
        proxyImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest,
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

  test("a timed-out live-proxy discovery is not an absent proxy; a retry once Docker answers selects", async () => {
    approveAll();
    const previous = publishEffectivePolicyGeneration(root, context.project);
    approveChangedProject(["example.com", "new.example.com"]);
    // What capture returns for a Docker call that timed out even when the
    // client itself exited 0: a non-zero status with empty output.
    let wedged = true;
    const io: RuntimeIO = {
      ...unusedIo,
      capture: (_command, args) => {
        expect(args[0]).toBe("ps");
        return wedged ? { status: 124, stdout: "", stderr: "", timedOut: true } : { status: 0, stdout: "", stderr: "" };
      },
    };

    await expect(activateApprovedControlsAfterMutation(context, io))
      .rejects.toThrow("could not identify the live proxy consumer");
    expect(readActiveControlSelection(context.project)?.controlGeneration).toBe(previous.controlGeneration);

    wedged = false;
    const result = await activateApprovedControlsAfterMutation(context, io);
    expect(result.kind).toBe("selected");
    expect(result).not.toMatchObject({ controlGeneration: previous.controlGeneration });
    expect(readActiveControlSelection(context.project)?.controlGeneration).not.toBe(previous.controlGeneration);
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

  describe("same-build fence (T15)", () => {
    const embedded = RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest;
    const otherBuild = `sha256:${"0".repeat(64)}`;

    type Snapshot = { bytes: string; mtimeMs: number };
    function activeSnapshot(): Snapshot {
      const file = context.project.paths.controlProxyActivePath;
      return { bytes: fs.readFileSync(file, "utf8"), mtimeMs: fs.statSync(file).mtimeMs };
    }

    function convergedProbe() {
      const active = readActiveControlSelection(context.project);
      if (!active) return {};
      const generation = verifyEffectivePolicyGeneration(context.project, active.controlGeneration);
      const receipt = { generation: generation.policyGeneration, controlGeneration: generation.controlGeneration,
        policyGeneration: generation.policyGeneration };
      return { requestProxy: receipt, firewall: { ...receipt, rulesetVerified: true } };
    }

    function liveConsumer(proxyImageInputDigest: string | undefined) {
      return {
        running: true,
        ...(proxyImageInputDigest ? { proxyImageInputDigest } : {}),
        probe: async () => convergedProbe(),
        stop: async () => { throw new Error("must not stop"); },
      };
    }

    // A previous effective policy generation is selected and a changed one is
    // approved: activation would write a different active selection.
    function pendingChange(): Snapshot {
      approveAll();
      publishEffectivePolicyGeneration(root, context.project);
      approveChangedProject(["example.com", "new.example.com"]);
      // An mtime that a same-millisecond rewrite could not reproduce.
      fs.utimesSync(context.project.paths.controlProxyActivePath, new Date(1_000_000), new Date(1_000_000));
      return activeSnapshot();
    }

    const compatible = () => ({ action: "proxy-restart" as const, services: ["proxy"] });

    test.each([
      ["differs", otherBuild],
      ["is missing", undefined],
    ])("identity %s: the proxy is replaced before the active selection changes", async (_name, identity) => {
      const before = pendingChange();
      const consumer = liveConsumer(identity);
      const events: string[] = [];
      const errors = vi.spyOn(console, "error").mockImplementation(() => {});
      try {
        const result = await activateApprovedControlsAfterMutation(context, unusedIo, {
          consumer,
          classifyProxyReplacement: () => { events.push("classify"); return compatible(); },
          replaceProxy: async () => {
            events.push("replace");
            // The policy has not reached the old proxy: same bytes, same mtime.
            expect(activeSnapshot()).toEqual(before);
            // The warning came first.
            expect(errors.mock.calls.flat().join("\n")).toContain("lose network access for up to one heartbeat (30 s) plus adoption");
            Object.assign(consumer, { proxyImageInputDigest: embedded });
            return 0;
          },
          timeoutMs: 0,
        });
        expect(events).toEqual(["classify", "replace"]);
        expect(result.kind).toBe("converged");
        expect(activeSnapshot().bytes).not.toBe(before.bytes);
      } finally {
        errors.mockRestore();
      }
    });

    test.each([
      ["admission-epoch", "admission epoch"],
      ["control-plane-topology", "control-plane topology"],
    ] as const)("an incompatible %s waits: no replacement and no selection write", async (reason, text) => {
      const before = pendingChange();
      const replaceProxy = vi.fn(async () => 0);
      const result = await activateApprovedControlsAfterMutation(context, unusedIo, {
        consumer: liveConsumer(otherBuild),
        classifyProxyReplacement: () => ({ action: "blocked-incompatible", reason, services: [] }),
        replaceProxy,
      });
      expect(result).toMatchObject({ kind: "waiting" });
      expect(result.kind === "waiting" && result.reason).toContain(`incompatible ${text}`);
      expect(activationReportLine(result)).toMatch(/^effective policy: saved, not applied: .*runfree policy use-approved.*runfree rebuild/);
      expect(replaceProxy).not.toHaveBeenCalled();
      expect(activeSnapshot()).toEqual(before);
    });

    test.each([
      ["exits non-zero", 1, false, "was not replaced (status 1)"],
      ["leaves the other build running", 0, false, "left a proxy from another Runfree build running"],
      ["leaves an unlabeled proxy running", 0, true, "left a proxy from another Runfree build running"],
    ])("a replacement that %s blocks activation and leaves the selection unchanged", async (_name, status, dropLabel, message) => {
      const before = pendingChange();
      const consumer = liveConsumer(otherBuild);
      vi.spyOn(console, "error").mockImplementation(() => {});
      await expect(activateApprovedControlsAfterMutation(context, unusedIo, {
        consumer,
        classifyProxyReplacement: compatible,
        replaceProxy: async () => {
          if (dropLabel) delete (consumer as { proxyImageInputDigest?: string }).proxyImageInputDigest;
          return status;
        },
      })).rejects.toThrow(message);
      expect(activeSnapshot()).toEqual(before);
      vi.mocked(console.error).mockRestore();
    });

    test("invalid component evidence blocks activation without a replacement", async () => {
      const before = pendingChange();
      const replaceProxy = vi.fn(async () => 0);
      await expect(activateApprovedControlsAfterMutation(context, unusedIo, {
        consumer: liveConsumer(otherBuild),
        classifyProxyReplacement: () => ({ action: "invalid", reason: "duplicate proxy", services: [] }),
        replaceProxy,
      })).rejects.toThrow("component evidence is invalid: duplicate proxy");
      expect(replaceProxy).not.toHaveBeenCalled();
      expect(activeSnapshot()).toEqual(before);
    });

    test("a launch asks to wait: a compatible proxy from another build is not replaced", async () => {
      const before = pendingChange();
      const replaceProxy = vi.fn(async () => 0);
      const result = await activateApprovedControlsAfterMutation(context, unusedIo, {
        consumer: liveConsumer(otherBuild),
        classifyProxyReplacement: compatible,
        proxyFromAnotherBuild: "wait",
        replaceProxy,
      });
      expect(result).toMatchObject({ kind: "waiting" });
      expect(activationReportLine(result)).toContain("replace the proxy with: runfree up, then apply the change with: runfree policy use-approved");
      expect(replaceProxy).not.toHaveBeenCalled();
      expect(activeSnapshot()).toEqual(before);
    });

    test("a matching identity runs neither classification nor replacement", async () => {
      pendingChange();
      const classify = vi.fn(compatible);
      const replaceProxy = vi.fn(async () => 0);
      const result = await activateApprovedControlsAfterMutation(context, unusedIo, {
        consumer: liveConsumer(embedded),
        classifyProxyReplacement: classify,
        replaceProxy,
        timeoutMs: 0,
      });
      expect(result.kind).toBe("converged");
      expect(classify).not.toHaveBeenCalled();
      expect(replaceProxy).not.toHaveBeenCalled();
    });

    test("no running proxy is not a mismatch", async () => {
      pendingChange();
      const replaceProxy = vi.fn(async () => 0);
      const result = await activateApprovedControlsAfterMutation(context, unusedIo, {
        consumer: { running: false, probe: async () => ({}), stop: async () => {} },
        replaceProxy,
      });
      expect(result.kind).toBe("selected");
      expect(replaceProxy).not.toHaveBeenCalled();
    });

    test("a proxy from another build that starts after the fence gets the previous selection back", async () => {
      const before = pendingChange();
      let reads = 0;
      const consumer = {
        running: true,
        // The fence sees this build; the post-publication discovery does not.
        get proxyImageInputDigest() { reads += 1; return reads === 1 ? embedded : otherBuild; },
        probe: async () => convergedProbe(),
        stop: async () => {},
      };
      await expect(activateApprovedControlsAfterMutation(context, unusedIo, { consumer }))
        .rejects.toThrow("previous effective policy generation is restored");
      expect(activeSnapshot().bytes).toBe(before.bytes);
    });

    test("discovery reads the proxy container label, and an unlabeled proxy is another build", async () => {
      const before = pendingChange();
      const proxyId = "c".repeat(64);
      let label = "<no value>";
      const io: RuntimeIO = { ...unusedIo, capture(_command, args) {
        if (args[0] === "ps") return { status: 0, stdout: proxyId, stderr: "" };
        if (args[0] === "container" && args[1] === "inspect" && args[2] === "--format") {
          expect(args[3]).toContain("io.runfree.proxy-image-input-digest");
          expect(args[4]).toBe(proxyId);
          return { status: 0, stdout: [proxyId, "proxy", "2", "<no value>", label, "", "", "img", "true",
            projectHash(root), composeProjectName(root)].join("\t"), stderr: "" };
        }
        if (args[0] === "exec") {
          const { requestProxy, firewall } = convergedProbe();
          return { status: 0, stdout: `${JSON.stringify(firewall ?? {})}\n${JSON.stringify(requestProxy ?? {})}\n`, stderr: "" };
        }
        throw new Error(`unexpected Docker effect: ${args.join(" ")}`);
      } };
      const replaceProxy = vi.fn(async () => {
        expect(activeSnapshot()).toEqual(before);
        label = embedded;
        return 0;
      });
      vi.spyOn(console, "error").mockImplementation(() => {});
      const result = await activateApprovedControlsAfterMutation(context, io, {
        classifyProxyReplacement: compatible,
        replaceProxy,
        timeoutMs: 0,
      });
      vi.mocked(console.error).mockRestore();
      expect(replaceProxy).toHaveBeenCalledOnce();
      expect(result.kind).toBe("converged");
    });

    test("an identity row that is not this project's proxy refuses before any replacement", async () => {
      const before = pendingChange();
      const proxyId = "c".repeat(64);
      const io: RuntimeIO = { ...unusedIo, capture(_command, args) {
        if (args[0] === "ps") return { status: 0, stdout: proxyId, stderr: "" };
        if (args[0] === "container" && args[1] === "inspect") {
          return { status: 0, stdout: [proxyId, "proxy", "2", "", embedded, "", "", "img", "true",
            "someone-else", composeProjectName(root)].join("\t"), stderr: "" };
        }
        throw new Error(`unexpected Docker effect: ${args.join(" ")}`);
      } };
      const replaceProxy = vi.fn(async () => 0);
      await expect(activateApprovedControlsAfterMutation(context, io, { classifyProxyReplacement: compatible, replaceProxy }))
        .rejects.toThrow("malformed or mismatched live proxy identity");
      expect(replaceProxy).not.toHaveBeenCalled();
      expect(activeSnapshot()).toEqual(before);
    });
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
      if (args[0] === "container" && args[1] === "inspect" && args[2] === "--format") {
        // The same-build fence reads the identity row of whichever proxy is live.
        const id = args[4];
        return { status: 0, stdout: [id, "proxy", "2", "", RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest, "", "", "img",
          "true", projectHash(root), composeProjectName(root)].join("\t"), stderr: "" };
      }
      if (args[0] === "container" && args[1] === "inspect") {
        expect(args[2]).toBe(replacementId);
        return { status: 0, stdout: JSON.stringify([{ Id: replacementId, State: { Running: running }, Config: { Labels: {
          "io.runfree.project-id": projectHash(root), "io.runfree.container-role": "proxy",
          "com.docker.compose.project": composeProjectName(root), "com.docker.compose.service": "proxy",
        } } }]), stderr: "" };
      }
      if (args[0] === "container" && args[1] === "stop") { stops.push(args.at(-1) as string); running = false; return { status: 0, stdout: replacementId, stderr: "" }; }
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

describe("fenced receipt read IO", () => {
  const ok = { status: 0, stdout: "{}", stderr: "" };
  const fenced = (held: () => boolean, inner: Partial<RuntimeIO>) => withFencedReceiptRead(inner as RuntimeIO, () => {
    if (!held()) throw new Error("lifecycle lock lost");
  });

  test("an async read is bounded and needs the lock before it starts and after it settles, as a sync read does", async () => {
    let held = true;
    const captureAsync = vi.fn(async (_command: string, _args: string[], _options?: unknown) => ok);
    const capture = vi.fn((_command: string, _args: string[], _options?: unknown) => ok);
    const io = fenced(() => held, { capture, captureAsync });
    expect(io.capture("docker", ["exec", "p"], { timeout: 60_000 })).toBe(ok);
    await expect(io.captureAsync?.("docker", ["exec", "p"], { timeout: 60_000 })).resolves.toBe(ok);
    expect(captureAsync.mock.calls[0]).toEqual(["docker", ["exec", "p"], { timeout: 1000, maxBuffer: 1024 * 1024 }]);
    expect(captureAsync.mock.calls[0]?.[2]).toEqual(capture.mock.calls[0]?.[2]);

    held = false;
    await expect(io.captureAsync?.("docker", ["exec", "p"])).rejects.toThrow("lifecycle lock lost");
    expect(captureAsync).toHaveBeenCalledOnce();

    held = true;
    captureAsync.mockImplementationOnce(async () => { held = false; return ok; });
    await expect(io.captureAsync?.("docker", ["exec", "p"])).rejects.toThrow("lifecycle lock lost");
  });

  test("exposes no captureAsync when the inner IO has none", () => {
    expect("captureAsync" in fenced(() => true, { capture: vi.fn(() => ok) })).toBe(false);
  });
});
