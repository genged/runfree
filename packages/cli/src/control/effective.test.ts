import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { projectInfo } from "../config.ts";
import {
  approveNetworkCandidate,
  approveRuntimeIsolationControl,
} from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import {
  clearConvergedPolicyReceipt,
  cleanupEffectivePolicyGenerations,
  convergeEffectivePolicyGeneration,
  publishEffectivePolicyGeneration,
  readActiveControlSelection,
  readConvergedPolicyReceipt,
  readEffectiveControlProvenance,
  selectEffectivePolicyGeneration,
  verifyEffectivePolicyGeneration,
} from "./effective.ts";

// A reboot renumbers the volume. Nothing else about the checkout changes, so
// this seam moves exactly the observation that used to enter the generation.
const seams = vi.hoisted(() => ({ checkoutFingerprintSuffix: "" }));

vi.mock("./subjects.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./subjects.ts")>();
  return {
    ...actual,
    checkoutFingerprint: (...args: Parameters<typeof actual.checkoutFingerprint>) =>
      `${actual.checkoutFingerprint(...args)}${seams.checkoutFingerprintSuffix}`,
  };
});

describe("effective control generations", () => {
  let root: string;
  let stateHome: string;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-effective-project-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-effective-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["example.com"]}`);
  });
  afterEach(() => {
    seams.checkoutFingerprintSuffix = "";
    fs.rmSync(root, { recursive: true });
    fs.rmSync(stateHome, { recursive: true });
  });

  function approvedProject() {
    const project = projectInfo(root, { XDG_STATE_HOME: stateHome, XDG_CONFIG_HOME: path.join(stateHome, "config") });
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(root, project, "interactive");
    return project;
  }

  test("publishes paired host/proxy manifests before selecting one generation", () => {
    const project = approvedProject();
    const generation = publishEffectivePolicyGeneration(root, project, {
      runtimeNetwork: { subnet: "172.30.1.0/24" },
    });
    expect(readActiveControlSelection(project)).toEqual(generation.active);
    expect(fs.readFileSync(generation.networkPolicyPath, "utf8")).toContain("example.com");
    expect(generation.hostManifest.controlGeneration).toBe(generation.proxyManifest.controlGeneration);
    expect(fs.statSync(generation.oauthPolicyPath).mode & 0o777).toBe(0o444);
    expect(readEffectiveControlProvenance(project, generation.controlGeneration).provenance.sources.hosts)
      .toEqual({ "example.com": ["project:direct"] });
  });

  test("a generation written by an older release (stored provenance payload) still verifies and explains", () => {
    const project = approvedProject();
    const generation = publishEffectivePolicyGeneration(root, project);
    // Recreate the pre-slim on-disk format: older releases stored a
    // runtime/provenance.json payload and listed it in the host manifest.
    const provenance = readEffectiveControlProvenance(project, generation.controlGeneration);
    const provenanceContents = `${JSON.stringify(provenance, null, 2)}\n`;
    const provenancePath = path.join(generation.hostDirectory, "runtime", "provenance.json");
    fs.writeFileSync(provenancePath, provenanceContents, { mode: 0o400 });
    const manifestPath = path.join(generation.hostDirectory, "manifest.json");
    fs.chmodSync(manifestPath, 0o600);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as { files: Record<string, string> };
    const digest = `sha256:${crypto.createHash("sha256").update(provenanceContents).digest("hex")}`;
    manifest.files["runtime/provenance.json"] = digest;
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    fs.chmodSync(manifestPath, 0o444);
    // Re-select so the active pointer matches the old-format manifest bytes.
    selectEffectivePolicyGeneration(project, generation.controlGeneration);

    expect(verifyEffectivePolicyGeneration(project, generation.controlGeneration).hostManifest.files["runtime/provenance.json"]).toBe(digest);
    expect(readEffectiveControlProvenance(project, generation.controlGeneration)).toEqual(provenance);
  });

  test("changes generation when a host-only runtime payload changes", () => {
    const project = approvedProject();
    const first = publishEffectivePolicyGeneration(root, project, { runtimeNetwork: { subnet: "172.30.1.0/24" } });
    const second = publishEffectivePolicyGeneration(root, project, { runtimeNetwork: { subnet: "172.30.2.0/24" } });
    expect(second.controlGeneration).not.toBe(first.controlGeneration);
    expect(second.policyGeneration).toBe(first.policyGeneration);
  });

  test("rejects generation corruption without changing the active pointer", () => {
    const project = approvedProject();
    const generation = publishEffectivePolicyGeneration(root, project);
    const activeBefore = fs.readFileSync(project.paths.controlProxyActivePath, "utf8");
    fs.chmodSync(generation.networkPolicyPath, 0o600);
    fs.writeFileSync(generation.networkPolicyPath, `{"hosts":[]}\n`);
    expect(() => verifyEffectivePolicyGeneration(project, generation.controlGeneration)).toThrow("corrupt");
    expect(fs.readFileSync(project.paths.controlProxyActivePath, "utf8")).toBe(activeBefore);
  });

  test("records convergence only when request proxy and verified firewall acknowledge the selected pair", async () => {
    const project = approvedProject();
    const generation = publishEffectivePolicyGeneration(root, project);

    const receipt = await convergeEffectivePolicyGeneration(project, {
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
      stopRuntime: async () => {
        throw new Error("must not stop a converged runtime");
      },
      timeoutMs: 0,
    });

    expect(receipt.controlGeneration).toBe(generation.controlGeneration);
    expect(readConvergedPolicyReceipt(project)).toEqual(receipt);
  });

  test("retries the parent fsync when a removed receipt is already absent", async () => {
    const project = approvedProject();
    const generation = publishEffectivePolicyGeneration(root, project);
    await convergeEffectivePolicyGeneration(project, {
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

    const firstFsync = vi.spyOn(fs, "fsyncSync").mockImplementationOnce(() => {
      throw new Error("simulated receipt directory fsync failure");
    });
    try {
      expect(() => clearConvergedPolicyReceipt(project)).toThrow("simulated receipt directory fsync failure");
    } finally {
      firstFsync.mockRestore();
    }
    expect(readConvergedPolicyReceipt(project)).toBeUndefined();

    const retryFsync = vi.spyOn(fs, "fsyncSync");
    try {
      clearConvergedPolicyReceipt(project);
      expect(retryFsync).toHaveBeenCalled();
    } finally {
      retryFsync.mockRestore();
    }
  });

  test("failed convergence selects and proves the previous generation before reporting rollback", async () => {
    const project = approvedProject();
    const previous = publishEffectivePolicyGeneration(root, project, { runtimeNetwork: { subnet: "172.30.1.0/24" } });
    const selected = publishEffectivePolicyGeneration(root, project, { runtimeNetwork: { subnet: "172.30.2.0/24" } });
    let stopped = false;

    await expect(convergeEffectivePolicyGeneration(project, {
      previous: previous.active,
      probe: async () => {
        const active = readActiveControlSelection(project);
        if (active?.controlGeneration !== previous.controlGeneration) return {};
        return {
          requestProxy: {
            generation: previous.policyGeneration,
            controlGeneration: previous.controlGeneration,
            policyGeneration: previous.policyGeneration,
          },
          firewall: {
            generation: previous.policyGeneration,
            controlGeneration: previous.controlGeneration,
            policyGeneration: previous.policyGeneration,
            rulesetVerified: true,
          },
        };
      },
      stopRuntime: async () => {
        stopped = true;
      },
      timeoutMs: 0,
    })).rejects.toThrow(`rolled back to ${previous.controlGeneration}`);

    expect(selected.controlGeneration).not.toBe(previous.controlGeneration);
    expect(readActiveControlSelection(project)?.controlGeneration).toBe(previous.controlGeneration);
    expect(readConvergedPolicyReceipt(project)?.controlGeneration).toBe(previous.controlGeneration);
    expect(stopped).toBe(false);
  });

  test("failed rollback clears stale convergence and stops the runtime", async () => {
    const project = approvedProject();
    const previous = publishEffectivePolicyGeneration(root, project, { runtimeNetwork: { subnet: "172.30.1.0/24" } });
    const selected = publishEffectivePolicyGeneration(root, project, { runtimeNetwork: { subnet: "172.30.2.0/24" } });
    let stopped = false;

    await expect(convergeEffectivePolicyGeneration(project, {
      previous: previous.active,
      probe: async () => ({
        requestProxy: {
          generation: selected.policyGeneration,
          controlGeneration: selected.controlGeneration,
          policyGeneration: selected.policyGeneration,
        },
      }),
      stopRuntime: async () => {
        stopped = true;
      },
      timeoutMs: 0,
    })).rejects.toThrow("proxy stopped");

    expect(readConvergedPolicyReceipt(project)).toBeUndefined();
    expect(stopped).toBe(true);
  });

  test("bounded cleanup preserves selected, converged, rollback, approved, and live generations", async () => {
    const project = approvedProject();
    const generations = [1, 2, 3, 4, 5, 6].map((value) => publishEffectivePolicyGeneration(root, project, {
      runtimeNetwork: { subnet: `172.30.${value}.0/24` },
    }));
    const selected = generations[5];
    await convergeEffectivePolicyGeneration(project, {
      probe: async () => ({
        requestProxy: {
          generation: selected.policyGeneration,
          controlGeneration: selected.controlGeneration,
          policyGeneration: selected.policyGeneration,
        },
        firewall: {
          generation: selected.policyGeneration,
          controlGeneration: selected.controlGeneration,
          policyGeneration: selected.policyGeneration,
          rulesetVerified: true,
        },
      }),
      stopRuntime: async () => {},
      timeoutMs: 0,
    });

    const removed = cleanupEffectivePolicyGenerations(project, {
      approvedControlGenerations: [generations[1].controlGeneration],
      liveControlGenerations: [generations[2].controlGeneration],
      rollbackControlGeneration: generations[3].controlGeneration,
      retainUnprotected: 1,
    });
    expect(removed).toHaveLength(1);
    for (const generation of [generations[1], generations[2], generations[3], selected]) {
      expect(fs.existsSync(generation.hostDirectory)).toBe(true);
      expect(fs.existsSync(generation.proxyDirectory)).toBe(true);
    }

    fs.writeFileSync(path.join(project.paths.controlEffectiveDir, "generations", "unexpected"), "unsafe");
    expect(() => cleanupEffectivePolicyGenerations(project, { retainUnprotected: 0 })).toThrow("unexpected effective generation entry");
  });

  test("a changed checkout observation does not change the effective policy generation", () => {
    const project = approvedProject();
    const generations: string[] = [];

    generations.push(publishEffectivePolicyGeneration(root, project).controlGeneration);
    // The reboot: the observation moves, the approvals and the policy do not.
    seams.checkoutFingerprintSuffix = "-renumbered";
    generations.push(publishEffectivePolicyGeneration(root, project).controlGeneration);
    generations.push(publishEffectivePolicyGeneration(root, project).controlGeneration);

    // Assert the change COUNT, not equality at one point. Equality at a single
    // point can pass without ever exercising the field removal.
    expect(new Set(generations).size).toBe(1);
  });

  test("an unchanged publish rewrites no approval state", () => {
    const project = approvedProject();
    const before = fs.readFileSync(project.paths.controlApprovalsPath);

    publishEffectivePolicyGeneration(root, project);
    publishEffectivePolicyGeneration(root, project);

    expect(fs.readFileSync(project.paths.controlApprovalsPath)).toEqual(before);
  });

  /** Rewrite a published host manifest in place and re-point the selection. */
  function rewriteHostManifest(
    project: ReturnType<typeof approvedProject>,
    generation: ReturnType<typeof publishEffectivePolicyGeneration>,
    mutate: (manifest: Record<string, unknown>) => void,
    options: { reselect?: boolean } = {},
  ): void {
    const manifestPath = path.join(generation.hostDirectory, "manifest.json");
    fs.chmodSync(manifestPath, 0o600);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    mutate(manifest);
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    fs.chmodSync(manifestPath, 0o444);
    // Re-point the active selection at the rewritten bytes, unless the rewrite
    // is the one being proved unreadable — selection verifies the manifest too.
    if (options.reselect !== false) selectEffectivePolicyGeneration(project, generation.controlGeneration);
  }

  test("a host manifest from an older approval schema still parses and keeps its own version", () => {
    const project = approvedProject();
    const generation = publishEffectivePolicyGeneration(root, project);
    expect(generation.hostManifest.approvalSchemaVersion).toBe(2);

    rewriteHostManifest(project, generation, (manifest) => { manifest.approvalSchemaVersion = 1; });

    // Pinning to the current constant would make every manifest published
    // before the bump unparseable, and substituting the constant back would
    // report a version that was never written.
    const parsed = verifyEffectivePolicyGeneration(project, generation.controlGeneration);
    expect(parsed.hostManifest.approvalSchemaVersion).toBe(1);
  });

  test("an unsupported approval schema version in a host manifest is refused explicitly", () => {
    const project = approvedProject();
    const generation = publishEffectivePolicyGeneration(root, project);

    rewriteHostManifest(project, generation, (manifest) => { manifest.approvalSchemaVersion = 99; }, { reselect: false });

    expect(() => verifyEffectivePolicyGeneration(project, generation.controlGeneration))
      .toThrow("host manifest identity is malformed");
  });
});
