import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect } from "vitest";

import { E2E_ARTIFACT_ENV, resolveArtifact } from "../support/artifact.ts";
import { assertExit, assertFileMode, assertOutputContains, assertOutputExcludes } from "../support/assertions.ts";
import { describeCommandResult, redact, runCommand, type CommandResult } from "../support/command.ts";
import { scenario, validateEvidence, validateScenarioMetadata } from "../support/evidence.ts";
import { buildEvidenceReport } from "../support/reporter.ts";
import { PROGRAM_SCENARIOS, validateProgramScenarios } from "../support/scenario-program.ts";
import { assertOwnedStateUnchanged, snapshotOwnedState } from "../support/snapshot.ts";
import { createWorld, withWorld } from "../support/world.ts";

const harnessEvidence = {
  kind: "constructed-recovery-state",
  constructedState: "The harness creates a deliberately invalid artifact, process, environment, or filesystem state.",
  unproved: "Harness self-tests do not prove a Runfree product workflow.",
} as const;

const harnessScenario = {
  scenarioIds: ["HARNESS"],
  layer: "P",
  cadence: "pull-request",
  implementationStatus: "Implemented",
  evidence: harnessEvidence,
  ownedStateAreas: ["disposable harness fixtures"],
  requiredPrograms: ["Node.js"],
  cleanup: "Remove every temporary fixture and process tree created by the self-test.",
} as const;

function fakeResult(overrides: Partial<CommandResult> = {}): CommandResult {
  return Object.freeze({
    command: Object.freeze(["test-command"]),
    cwd: "/tmp",
    durationMs: 0,
    outcome: Object.freeze({ kind: "exit", exitCode: 1 }),
    stdout: "",
    stderr: "",
    environmentNames: Object.freeze([]),
    secrets: Object.freeze([]),
    ...overrides,
  });
}

describe("CLI e2e harness self-tests", () => {
  scenario("artifact resolution refuses every source fallback and invalid file shape", harnessScenario, () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-e2e-artifact-self-test-"));
    try {
      expect(() => resolveArtifact({})).toThrow(E2E_ARTIFACT_ENV);
      expect(() => resolveArtifact({ [E2E_ARTIFACT_ENV]: "relative/runfree" })).toThrow("absolute path");
      expect(() => resolveArtifact({ [E2E_ARTIFACT_ENV]: path.join(root, "missing") })).toThrow("readable file");

      const directory = path.join(root, "directory");
      fs.mkdirSync(directory);
      expect(() => resolveArtifact({ [E2E_ARTIFACT_ENV]: directory })).toThrow("must name a file");

      const source = path.join(root, "runfree.js");
      fs.writeFileSync(source, "#!/usr/bin/env node\n");
      fs.chmodSync(source, 0o755);
      expect(() => resolveArtifact({ [E2E_ARTIFACT_ENV]: source })).toThrow("not source");

      const notExecutable = path.join(root, "runfree-no-exec");
      fs.writeFileSync(notExecutable, "binary-shaped fixture\n", { mode: 0o600 });
      expect(() => resolveArtifact({ [E2E_ARTIFACT_ENV]: notExecutable })).toThrow("not executable");

      const executable = path.join(root, "runfree-exec");
      fs.writeFileSync(executable, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
      expect(resolveArtifact({ [E2E_ARTIFACT_ENV]: executable })).toBe(fs.realpathSync(executable));
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  scenario("process outcomes distinguish exit, signal, spawn failure, and bounded process-tree termination", harnessScenario, async () => {
    const cwd = fs.realpathSync(os.tmpdir());
    const env = { PATH: process.env.PATH ?? "/usr/bin:/bin" };
    const exited = await runCommand({ executable: process.execPath, args: ["-e", "process.exit(7)"], cwd, env });
    expect(exited.outcome).toEqual({ kind: "exit", exitCode: 7 });

    const signaled = await runCommand({
      executable: process.execPath,
      args: ["-e", "process.kill(process.pid, 'SIGTERM')"],
      cwd,
      env,
    });
    expect(signaled.outcome).toEqual({ kind: "signal", signal: "SIGTERM" });

    const missing = await runCommand({ executable: path.join(cwd, "definitely-missing-runfree-e2e-command"), cwd, env });
    expect(missing.outcome.kind).toBe("spawn-error");

    const heartbeat = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-e2e-heartbeat-")), "heartbeat");
    try {
      const grandchild = [
        "const fs=require('node:fs');",
        "process.on('SIGTERM',()=>{});",
        `setInterval(()=>fs.appendFileSync(${JSON.stringify(heartbeat)},'x'),20);`,
      ].join("");
      const parent = [
        "const {spawn}=require('node:child_process');",
        `spawn(process.execPath,['-e',${JSON.stringify(grandchild)}],{stdio:'inherit'});`,
        "setInterval(()=>{},1000);",
      ].join("");
      const timedOut = await runCommand({
        executable: process.execPath,
        args: ["-e", parent],
        cwd,
        env,
        timeoutMs: 250,
        termGraceMs: 250,
      });
      expect(timedOut.outcome).toEqual({ kind: "timeout", timeoutMs: 250, finalSignal: "SIGKILL" });
      const stoppedAt = fs.statSync(heartbeat).size;
      await new Promise((resolve) => setTimeout(resolve, 200));
      expect(fs.statSync(heartbeat).size).toBe(stoppedAt);
    } finally {
      fs.rmSync(path.dirname(heartbeat), { recursive: true, force: true });
    }

    const cooperative = await runCommand({
      executable: process.execPath,
      args: ["-e", "process.on('SIGTERM',()=>process.exit(0));setInterval(()=>{},1000)"],
      cwd,
      env,
      timeoutMs: 100,
      termGraceMs: 500,
    });
    expect(cooperative.outcome).toEqual({ kind: "timeout", timeoutMs: 100, finalSignal: "SIGTERM" });
  }, 10_000);

  scenario("worlds isolate ambient input, remain unique, and clean up", harnessScenario, async () => {
    const ambientName = "RUNFREE_AMBIENT_E2E_TRAP";
    process.env[ambientName] = "must-not-cross-world-boundary";
    let cleanedRoot = "";
    try {
      await withWorld({}, async (world) => {
        cleanedRoot = world.baseRoot;
        const observed = await world.runExternal(process.execPath, [
          "-e",
          `process.stdout.write(JSON.stringify({home:process.env.HOME,ambient:process.env.${ambientName},term:process.env.TERM}))`,
        ]);
        expect(observed.outcome).toEqual({ kind: "exit", exitCode: 0 });
        expect(JSON.parse(observed.stdout)).toEqual({ home: world.home, term: "dumb" });

        const declared = await world.runExternal(process.execPath, [
          "-e",
          "process.stdout.write(process.env.RUNFREE_DECLARED_E2E_INPUT ?? '')",
        ], { env: { RUNFREE_DECLARED_E2E_INPUT: "declared-value" } });
        expect(declared.stdout).toBe("declared-value");

        const second = createWorld();
        try {
          expect(second.baseRoot).not.toBe(world.baseRoot);
        } finally {
          second.cleanup();
        }
      });
    } finally {
      delete process.env[ambientName];
    }
    expect(fs.existsSync(cleanedRoot)).toBe(false);

    let failedRoot = "";
    await expect(withWorld({}, async (world) => {
      failedRoot = world.baseRoot;
      throw new Error("deliberate world failure");
    })).rejects.toThrow(/deliberate world failure[\s\S]*world:/u);
    expect(fs.existsSync(failedRoot)).toBe(false);

    const preserved = createWorld();
    preserved.preserve();
    preserved.cleanup();
    expect(fs.existsSync(preserved.baseRoot)).toBe(true);
    fs.rmSync(preserved.baseRoot, { recursive: true, force: true });
  });

  scenario("assertions, snapshots, metadata, and redaction fail against wrong state", harnessScenario, async () => {
    await withWorld({}, async (world) => {
      const file = path.join(world.projectRoot, "state.txt");
      fs.writeFileSync(file, "before\n");
      const selection = [{ name: "project", path: world.projectRoot }] as const;
      const before = snapshotOwnedState(selection);
      fs.writeFileSync(file, "after\n");
      expect(() => assertOwnedStateUnchanged(before, snapshotOwnedState(selection))).toThrow("owned state changed");
      expect(() => snapshotOwnedState([])).toThrow("at least one");
    });

    expect(() => validateEvidence(undefined)).toThrow("no evidence label");
    expect(() => validateEvidence({ kind: "modeled-external-step", modeledSteps: [], proofLimits: "none" })).toThrow("name every modeled step");
    expect(() => validateEvidence({ kind: "constructed-recovery-state", constructedState: "fixture", unproved: "" })).toThrow("remains unproved");
    expect(() => validateScenarioMetadata(undefined)).toThrow("no scenario metadata");
    expect(() => validateScenarioMetadata({ ...harnessScenario, scenarioIds: [] })).toThrow("scenario IDs");
    expect(() => validateScenarioMetadata({ ...harnessScenario, layer: "D" })).toThrow("physical layer");
    expect(() => validateProgramScenarios(PROGRAM_SCENARIOS.slice(1))).toThrow("38 scenarios");
    expect(PROGRAM_SCENARIOS.map((entry) => entry.id)).toEqual(
      Array.from({ length: 38 }, (_, index) => `LH-${String(index + 1).padStart(2, "0")}`),
    );
    const report = buildEvidenceReport([{
      test: "contract test",
      file: "e2e/example.test.ts",
      status: "failed",
      scenario: { ...harnessScenario, scenarioIds: ["LH-10"] },
    }]) as {
      version: number;
      scenarios: readonly { id: string; tests: readonly { test: string; result: string }[] }[];
      blockedWork: readonly unknown[];
    };
    expect(report.version).toBe(2);
    expect(report.scenarios).toHaveLength(38);
    expect(report.scenarios.find((entry) => entry.id === "LH-10")?.tests)
      .toEqual([{ file: "e2e/example.test.ts", test: "contract test", result: "failed" }]);
    expect(report.blockedWork.length).toBeGreaterThan(0);

    expect(() => assertExit(fakeResult(), 0)).toThrow("expected exit 0");
    expect(() => assertOutputContains(fakeResult(), "missing output")).toThrow("expected output to contain");
    expect(() => assertOutputExcludes(fakeResult({ stdout: "forbidden output" }), "forbidden")).toThrow("expected output to exclude");
    const modeRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-e2e-mode-self-test-"));
    try {
      const modeFile = path.join(modeRoot, "mode");
      fs.writeFileSync(modeFile, "mode\n", { mode: 0o600 });
      expect(() => assertFileMode(modeFile, 0o644)).toThrow("mode 644");
    } finally {
      fs.rmSync(modeRoot, { recursive: true, force: true });
    }

    const secret = "sensitive-diagnostic-value";
    const rendered = describeCommandResult(fakeResult({
      command: Object.freeze(["command", secret]),
      stdout: `${secret}\n`,
      stderr: `${secret}\n`,
      environmentNames: Object.freeze(["SERVICE_TOKEN"]),
      secrets: Object.freeze([secret]),
    }));
    expect(rendered).not.toContain(secret);
    expect(rendered).toContain("SERVICE_TOKEN");
    expect(redact(`prefix ${secret} suffix`, [secret])).toBe("prefix <redacted> suffix");
  });
});
