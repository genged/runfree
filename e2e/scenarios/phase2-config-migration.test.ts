import fs from "node:fs";
import path from "node:path";

import { describe, expect } from "vitest";

import { assertExit, assertOutputContains, readJson } from "../support/assertions.ts";
import { scenario } from "../support/evidence.ts";
import { assertOwnedStateUnchanged, snapshotOwnedState } from "../support/snapshot.ts";
import { withWorld } from "../support/world.ts";

type RunfreeConfig = Readonly<{
  version: number;
  project?: unknown;
  paths?: unknown;
  services?: unknown;
}>;

type DesiredPolicy = Readonly<{
  version: number;
  hosts: readonly string[];
  requests?: Readonly<Record<string, unknown>>;
  services?: Readonly<Record<string, unknown>>;
}>;

const cleanup = "Remove the disposable project, home, and XDG roots after the test.";

const refusalMetadata = {
  scenarioIds: ["LH-03"],
  layer: "P",
  cadence: "pull-request",
  implementationStatus: "Partial",
  evidence: { kind: "reproduced-user-workflow" },
  ownedStateAreas: ["project", "XDG config", "XDG data", "XDG state"],
  requiredPrograms: ["packaged Runfree executable"],
  cleanup,
} as const;

const migrationMetadata = {
  scenarioIds: ["LH-03"],
  layer: "P",
  cadence: "pull-request",
  implementationStatus: "Partial",
  evidence: {
    kind: "modeled-external-step",
    modeledSteps: ["Docker container inventory with no live project agents"],
    proofLimits: "The Docker stub proves migration quiescence orchestration, not daemon compatibility or active-session handling.",
  },
  ownedStateAreas: ["project", "XDG config", "XDG data", "XDG state", "modeled Docker invocation log"],
  requiredPrograms: ["packaged Runfree executable", "POSIX shell"],
  cleanup,
} as const;

function writeLegacyProject(projectRoot: string): void {
  const runfreeDir = path.join(projectRoot, ".runfree");
  const legacyPolicyDir = path.join(projectRoot, "legacy-policy");
  fs.mkdirSync(runfreeDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(legacyPolicyDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(runfreeDir, "runfree.json"), `${JSON.stringify({
    version: 3,
    project: { mount: "read-only" },
    paths: {
      projects: "legacy-runtimes",
      networkPolicy: "legacy-policy/custom-policy.json",
    },
    agents: {
      default: "claude",
      claude: { command: "claude --dangerously-skip-permissions" },
    },
    services: {
      "retired-acme": {
        revision: 1,
        hosts: ["api.legacy.example"],
      },
    },
  }, null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(path.join(legacyPolicyDir, "custom-policy.json"), `${JSON.stringify({
    hosts: ["api.legacy.example", "custom.example"],
    requests: {
      "api.legacy.example": { methods: ["GET"] },
    },
  }, null, 2)}\n`, { mode: 0o600 });
}

describe("packaged phase 2 config migration", () => {
  scenario("legacy readers and version-4 writers do not silently migrate or mutate owned state", refusalMetadata, async () => {
    await withWorld({}, async (world) => {
      writeLegacyProject(world.projectRoot);
      const selections = [
        { name: "project", path: world.projectRoot },
        { name: "config", path: world.configHome },
        { name: "data", path: world.dataHome },
        { name: "state", path: world.stateHome },
      ] as const;
      const before = snapshotOwnedState(selections);

      const projectId = await world.runfree(["project-id"]);
      assertExit(projectId, 0);
      expect(projectId.stdout.trim()).toMatch(/^[a-f0-9]{12}$/u);
      assertOwnedStateUnchanged(before, snapshotOwnedState(selections));

      const requiresMigration = [
        ["policy", "status"],
        ["status"],
        ["host", "add", "new.example", "--no-reload"],
        ["service", "enable", "node", "--no-reload"],
        ["image", "approve-context"],
      ] as const;
      for (const args of requiresMigration) {
        const refused = await world.runfree(args);
        assertExit(refused, 1);
        assertOutputContains(
          refused,
          ".runfree/runfree.json uses legacy config version 3; run `runfree init` to migrate to version 4",
        );
        assertOwnedStateUnchanged(before, snapshotOwnedState(selections));
      }
    });
  });

  scenario("init preserves custom legacy authority and has a null second migration run", migrationMetadata, async () => {
    await withWorld({}, async (world) => {
      writeLegacyProject(world.projectRoot);
      world.installEmptyDockerInventory();
      const legacyPolicyPath = path.join(world.projectRoot, "legacy-policy", "custom-policy.json");
      const legacyPolicyBefore = fs.readFileSync(legacyPolicyPath, "utf8");

      const migrated = await world.runfree(["init"]);
      assertExit(migrated, 0);
      assertOutputContains(migrated, "migrated .runfree/runfree.json from version 3 to 4");
      assertOutputContains(migrated, "service retired-acme kept as direct hosts");
      assertOutputContains(migrated, "runfree service enable retired-acme");

      const runfreeDir = path.join(world.projectRoot, ".runfree");
      const config = readJson<RunfreeConfig>(path.join(runfreeDir, "runfree.json"));
      const policy = readJson<DesiredPolicy>(path.join(runfreeDir, "network-policy.json"));
      expect(config.version).toBe(4);
      expect(config.project).toBeUndefined();
      expect(config.paths).toBeUndefined();
      expect(config.services).toBeUndefined();
      expect(policy).toEqual({
        version: 2,
        hosts: ["api.legacy.example", "custom.example"],
        requests: {
          "api.legacy.example": { methods: ["GET"] },
        },
      });
      expect(fs.readFileSync(legacyPolicyPath, "utf8")).toBe(legacyPolicyBefore);
      expect(fs.existsSync(path.join(world.projectRoot, "legacy-runtimes"))).toBe(false);

      const selections = [
        { name: "project", path: world.projectRoot },
        { name: "config", path: world.configHome },
        { name: "data", path: world.dataHome },
        { name: "state", path: world.stateHome },
        { name: "Docker invocation log", path: world.dockerLog },
      ] as const;
      const beforeSecondRun = snapshotOwnedState(selections);
      const second = await world.runfree(["init"]);
      assertExit(second, 0);
      assertOwnedStateUnchanged(beforeSecondRun, snapshotOwnedState(selections));
    });
  });
});
