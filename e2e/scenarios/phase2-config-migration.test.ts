import fs from "node:fs";
import path from "node:path";

import { describe, expect } from "vitest";

import { assertExit, assertOutputContains } from "../support/assertions.ts";
import { scenario } from "../support/evidence.ts";
import { assertOwnedStateUnchanged, snapshotOwnedState } from "../support/snapshot.ts";
import { withWorld } from "../support/world.ts";

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

describe("packaged phase 2 legacy config boundary", () => {
  scenario("pre-v4 configs are refused with the init remedy, never migrated, and owned state is unchanged", refusalMetadata, async () => {
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

      const refusedCommands = [
        ["init", "--yes"],
        ["policy", "status"],
        ["status"],
        ["host", "add", "new.example", "--no-reload"],
        ["service", "enable", "node", "--no-reload"],
        ["image", "approve-context"],
      ] as const;
      for (const args of refusedCommands) {
        const refused = await world.runfree(args);
        assertExit(refused, 1);
        assertOutputContains(refused, ".runfree/runfree.json uses config version 3, which this release no longer migrates");
        assertOutputContains(refused, "move .runfree aside and run `runfree init`");
        assertOwnedStateUnchanged(before, snapshotOwnedState(selections));
      }
    });
  });
});
