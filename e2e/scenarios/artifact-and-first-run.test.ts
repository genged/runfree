import fs from "node:fs";
import path from "node:path";

import { describe, expect } from "vitest";

import { artifactPath } from "../support/artifact.ts";
import { assertExit, assertFileMode, assertOutputContains, assertOutputExcludes, readJson } from "../support/assertions.ts";
import { scenario } from "../support/evidence.ts";
import { assertOwnedStateUnchanged, snapshotOwnedState } from "../support/snapshot.ts";
import { withWorld, type WorldPathFlavor } from "../support/world.ts";

type RunfreeConfig = Readonly<{
  version: number;
  agents: Readonly<Record<string, unknown>>;
  runtime: Readonly<{ dependencyOverlays?: string }>;
  project?: unknown;
  paths?: unknown;
}>;

type DesiredPolicy = Readonly<{ version: number; hosts: readonly unknown[] }>;

const packagedCleanup = "Remove the disposable project, home, and XDG roots after the test.";

const artifactMetadata = {
  scenarioIds: ["LH-01"],
  layer: "P",
  cadence: "pull-request",
  implementationStatus: "Partial",
  evidence: { kind: "reproduced-user-workflow" },
  ownedStateAreas: ["project", "XDG config", "XDG data", "XDG state", "packaged executable"],
  requiredPrograms: ["packaged Runfree executable"],
  cleanup: packagedCleanup,
} as const;

const firstRunMetadata = {
  scenarioIds: ["LH-02"],
  layer: "P",
  cadence: "pull-request",
  implementationStatus: "Partial",
  evidence: { kind: "reproduced-user-workflow" },
  ownedStateAreas: ["project", "XDG config", "XDG data", "XDG state"],
  requiredPrograms: ["packaged Runfree executable"],
  cleanup: packagedCleanup,
} as const;

const helpInvocations: readonly (readonly string[])[] = [
  ["-h"],
  ["--help"],
  ...[
    "quickstart", "run", "network", "credentials", "services", "mcp",
    "deps", "image", "diagnostics", "all",
  ].map((topic) => ["help", topic] as const),
  ...[
    "version", "project-id", "assets status", "assets clean", "init", "update",
    "image init", "image approve-context", "policy status", "policy explain", "policy diff",
    "policy review", "policy approve", "policy use-approved", "control approve", "inbox paste",
    "inbox clean", "paste-image", "up", "audit status", "audit off", "audit report",
    "approvals", "approve", "deps plan", "deps install", "deps doctor", "deps reset",
    "status", "resources", "sessions", "sessions rename", "resume", "stop", "destroy",
    "shell", "rebuild", "logs", "vnc", "forward", "git repair-worktree-links", "host add",
    "host remove", "host list", "host explain", "host rules", "doctor",
    "runtime reload-policy", "credential add", "credential link", "credential unlink",
    "credential remove", "credential set-source", "credential clear-source", "credential status",
    "credential sync", "credential source add", "credential source list", "credential source show",
    "credential source remove", "service list", "service enable", "service disable",
    "service explain", "service configure", "service diff", "service custom add",
    "service custom remove", "mcp list", "mcp configure", "mcp explain", "mcp approve",
    "mcp auth", "mcp rules", "mcp revoke",
  ].map((command) => [...command.split(" "), "--help"]),
];

describe("packaged artifact and first run", () => {
  scenario("the packaged executable exposes the installable CLI contract", artifactMetadata, async () => {
    await withWorld({}, async (world) => {
      expect(path.extname(artifactPath())).toBe("");
      const version = await world.runfree(["version"]);
      assertExit(version, 0);
      const packageVersion = (JSON.parse(fs.readFileSync(path.join(process.cwd(), "package.json"), "utf8")) as { version: string }).version;
      expect(version.stdout.trim()).toBe(packageVersion);
      expect(version.stderr).toBe("");

      const help = await world.runfree(["help"]);
      assertExit(help, 0);
      for (const contract of [
        "runfree [--workspace <project-dir>] [claude|codex|pi]",
        "runfree [--workspace <project-dir>] init [--yes]",
        "runfree up",
        "runfree service enable <id>",
        "runfree credential source add <name>",
        "runfree policy approve [--project",
      ]) assertOutputContains(help, contract);
      assertOutputExcludes(help, "\u001b[");

      const selections = [
        { name: "project", path: world.projectRoot },
        { name: "config", path: world.configHome },
        { name: "data", path: world.dataHome },
        { name: "state", path: world.stateHome },
      ] as const;
      const beforeHelpSweep = snapshotOwnedState(selections);
      for (const invocation of helpInvocations) {
        const result = await world.runfree(invocation);
        assertExit(result, 0);
        assertOutputExcludes(result, "\u001b[");
        assertOutputExcludes(result, "at async");
      }
      assertOwnedStateUnchanged(beforeHelpSweep, snapshotOwnedState(selections));

      const executableBefore = fs.statSync(artifactPath());
      const update = await world.runfree(["update"]);
      assertExit(update, 0);
      assertOutputContains(update, "does not replace the running binary yet");
      assertOwnedStateUnchanged(beforeHelpSweep, snapshotOwnedState(selections));
      const executableAfter = fs.statSync(artifactPath());
      expect({ size: executableAfter.size, mtimeMs: executableAfter.mtimeMs })
        .toEqual({ size: executableBefore.size, mtimeMs: executableBefore.mtimeMs });
    });
  }, 60_000);

  scenario("removed command forms refuse with runnable replacements and no state change", {
    ...artifactMetadata,
    scenarioIds: ["LH-01", "LH-26"],
  }, async () => {
    await withWorld({}, async (world) => {
      const selections = [
        { name: "project", path: world.projectRoot },
        { name: "config", path: world.configHome },
        { name: "data", path: world.dataHome },
        { name: "state", path: world.stateHome },
      ] as const;
      const before = snapshotOwnedState(selections);
      const cases = [
        { args: ["domain", "add", "example.com"], recovery: "runfree host" },
        { args: ["source", "add", "example"], recovery: "runfree credential source" },
        { args: ["token", "add", "example"], recovery: "runfree credential" },
        { args: ["host", "add", "example.com", "--token", "example"], recovery: "runfree credential add" },
        { args: ["host", "remove", "example.com", "--remove-credential"], recovery: "runfree credential unlink" },
      ] as const;
      for (const refusal of cases) {
        const result = await world.runfree(refusal.args);
        assertExit(result, 1);
        assertOutputContains(result, refusal.recovery);
        assertOutputExcludes(result, "\u001b[");
        assertOutputExcludes(result, "at async");
        assertOwnedStateUnchanged(before, snapshotOwnedState(selections));
      }
    });
  });

  scenario("workspace selection is leading-only and overrides ambient project paths", firstRunMetadata, async () => {
    await withWorld({}, async (world) => {
      const ambientRoot = path.join(world.root, "ambient-project");
      fs.mkdirSync(ambientRoot);
      const initialized = await world.runfree(["init"], {
        env: {
          RUNFREE_PROJECT_ROOT: ambientRoot,
          RUNFREE_INVOCATION_CWD: ambientRoot,
        },
      });
      assertExit(initialized, 0);
      expect(fs.existsSync(path.join(world.projectRoot, ".runfree", "runfree.json"))).toBe(true);
      expect(fs.existsSync(path.join(ambientRoot, ".runfree"))).toBe(false);

      const selections = [
        { name: "project", path: world.projectRoot },
        { name: "ambient project", path: ambientRoot },
        { name: "config", path: world.configHome },
        { name: "data", path: world.dataHome },
        { name: "state", path: world.stateHome },
      ] as const;
      const beforeLateOption = snapshotOwnedState(selections);
      const late = await world.runExternal(artifactPath(), ["init", "--workspace", ambientRoot]);
      assertExit(late, 1);
      assertOutputContains(late, "Unknown argument: workspace");
      assertOwnedStateUnchanged(beforeLateOption, snapshotOwnedState(selections));
    });
  });

  const cells: readonly Readonly<{ name: string; flavor: WorldPathFlavor; umask?: string }>[] = [
    { name: "baseline", flavor: "baseline" },
    { name: "path with spaces", flavor: "spaces" },
    { name: "non-ASCII path", flavor: "non-ascii" },
    { name: "restrictive umask", flavor: "baseline", umask: "027" },
  ];

  for (const cell of cells) {
    scenario(`init converges in the ${cell.name} environment cell`, firstRunMetadata, async () => {
      await withWorld({ pathFlavor: cell.flavor }, async (world) => {
        if (cell.umask) {
          const probe = await world.runExternal("/bin/sh", ["-c", `umask ${cell.umask}; umask`]);
          assertExit(probe, 0);
          expect(probe.stdout.trim()).toMatch(/^0?027$/u);
        }

        const initialized = await world.runfree(["init"], { umask: cell.umask });
        assertExit(initialized, 0);
        assertOutputContains(initialized, `project: ${world.projectRoot}`);
        assertOutputContains(initialized, "outbound services: none (deny-all)");

        const runfreeDir = path.join(world.projectRoot, ".runfree");
        const configPath = path.join(runfreeDir, "runfree.json");
        const policyPath = path.join(runfreeDir, "network-policy.json");
        const config = readJson<RunfreeConfig>(configPath);
        const policy = readJson<DesiredPolicy>(policyPath);
        expect(config.version).toBe(4);
        expect(config.agents.default).toBe("claude");
        expect(config.runtime.dependencyOverlays).toBe("auto");
        expect(config.project).toBeUndefined();
        expect(config.paths).toBeUndefined();
        expect(policy).toEqual({ version: 2, hosts: [] });
        assertFileMode(runfreeDir, 0o700);
        assertFileMode(configPath, 0o600);
        assertFileMode(policyPath, 0o600);

        const id = await world.runfree(["project-id"]);
        const composeName = await world.runfree(["project-id", "--compose-name"]);
        assertExit(id, 0);
        assertExit(composeName, 0);
        expect(id.stdout.trim()).toMatch(/^[a-f0-9]{12}$/u);
        expect(composeName.stdout.trim()).toBe(`runfree-${id.stdout.trim()}`);

        const selections = [
          { name: "project", path: world.projectRoot },
          { name: "config", path: world.configHome },
          { name: "data", path: world.dataHome },
          { name: "state", path: world.stateHome },
        ] as const;
        const beforeSecondRun = snapshotOwnedState(selections);
        const second = await world.runfree(["init"], { umask: cell.umask });
        assertExit(second, 0);
        assertOwnedStateUnchanged(beforeSecondRun, snapshotOwnedState(selections));
      });
    });
  }

  scenario("init --yes produces the same scaffold and a null second run", firstRunMetadata, async () => {
    await withWorld({}, async (world) => {
      const initialized = await world.runfree(["init", "--yes"]);
      assertExit(initialized, 0);
      const selections = [
        { name: "project", path: world.projectRoot },
        { name: "config", path: world.configHome },
        { name: "data", path: world.dataHome },
        { name: "state", path: world.stateHome },
      ] as const;
      const beforeSecondRun = snapshotOwnedState(selections);
      assertExit(await world.runfree(["init", "--yes"]), 0);
      assertOwnedStateUnchanged(beforeSecondRun, snapshotOwnedState(selections));
    });
  });

  scenario("project identity is stable for normalized paths and distinct projects", firstRunMetadata, async () => {
    await withWorld({}, async (first) => {
      await withWorld({}, async (second) => {
        assertExit(await first.runfree(["init"]), 0);
        assertExit(await second.runfree(["init"]), 0);
        const firstId = await first.runfree(["project-id"]);
        const secondId = await second.runfree(["project-id"]);
        assertExit(firstId, 0);
        assertExit(secondId, 0);
        expect(secondId.stdout.trim()).not.toBe(firstId.stdout.trim());

        const normalizedAlias = path.join(first.projectRoot, "..", path.basename(first.projectRoot));
        const aliasId = await first.runExternal(artifactPath(), ["--workspace", normalizedAlias, "project-id"]);
        assertExit(aliasId, 0);
        expect(aliasId.stdout.trim()).toBe(firstId.stdout.trim());
      });
    });
  });

});
