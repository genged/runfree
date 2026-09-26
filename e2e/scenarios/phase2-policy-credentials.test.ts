import fs from "node:fs";
import path from "node:path";

import { describe, expect } from "vitest";

import {
  assertExit,
  assertFileMode,
  assertOutputContains,
  assertOutputExcludes,
  readJson,
} from "../support/assertions.ts";
import { scenario } from "../support/evidence.ts";
import { assertOwnedStateUnchanged, snapshotOwnedState } from "../support/snapshot.ts";
import { withWorld, type E2EWorld } from "../support/world.ts";

type UserServiceDefinition = Readonly<{
  schemaVersion: 1;
  id: "user-acme";
  label: string;
  revision: number;
  hosts: readonly Readonly<{ host: string; broad?: true; explanation?: string }>[];
  explanations: readonly string[];
  detect: readonly Readonly<{ kind: "file"; path: string }>[];
  credential: Readonly<{
    tokenDescription: string;
    agentEnv: readonly string[];
    credentials: readonly Readonly<{
      host: string;
      header: string;
      scheme: "bearer";
    }>[];
  }>;
}>;

type DesiredPolicy = Readonly<{
  version: number;
  hosts: readonly string[];
  services?: Readonly<Record<string, Readonly<{
    definitionDigest: string;
    revision: number;
    selection?: Readonly<{ skippedHosts?: readonly string[] }>;
    resolved: Readonly<{
      hosts: readonly string[];
      agentEnv?: readonly string[];
      tokens?: Readonly<Record<string, Readonly<{
        description: string;
        credentials: readonly Readonly<{
          host: string;
          header: string;
          scheme: string;
        }>[];
      }>>>;
    }>;
  }>>>;
}>;

type TokenSources = Readonly<Record<string, Readonly<{
  source?: string;
  env?: string;
  runfreeUserServiceOwner?: string;
}>>>;

const cleanup = "Remove the disposable project, import fixtures, home, XDG roots, and modeled Docker log after the test.";

const importMetadata = {
  scenarioIds: ["LH-09"],
  layer: "P",
  cadence: "pull-request",
  implementationStatus: "Partial",
  evidence: {
    kind: "constructed-recovery-state",
    constructedState: "A downloaded user-service definition with one unknown top-level field",
    unproved: "This non-terminal cell does not prove the interactive wizard, the preview-to-import race guard, duplicate-key refusal, or unsafe source-file variants.",
  },
  ownedStateAreas: ["project desired policy", "host XDG config", "host XDG data", "host XDG state"],
  requiredPrograms: ["packaged Runfree executable"],
  cleanup,
} as const;

const evolutionMetadata = {
  scenarioIds: ["LH-09"],
  layer: "P",
  cadence: "pull-request",
  implementationStatus: "Partial",
  evidence: {
    kind: "modeled-external-step",
    modeledSteps: ["Docker container inventory with no live project agents"],
    proofLimits: "The local Docker stub proves packaged host-side authoring and activation-barrier behavior, not proxy reload, effective-policy convergence, credential resolution, or live credential injection.",
  },
  ownedStateAreas: ["project desired policy", "host user-service catalog", "host credential-source config", "modeled Docker invocation log"],
  requiredPrograms: ["packaged Runfree executable", "POSIX shell"],
  cleanup,
} as const;

function definition(revision: 1 | 2): UserServiceDefinition {
  const apiHost = revision === 1 ? "api.acme.example" : "api-v2.acme.example";
  return {
    schemaVersion: 1,
    id: "user-acme",
    label: revision === 1 ? "Acme internal API" : "Acme internal API v2",
    revision,
    hosts: [
      { host: apiHost },
      {
        host: "cdn.acme.example",
        broad: true,
        explanation: "Shared Acme CDN host that can serve arbitrary tenant content.",
      },
    ],
    explanations: [`Acme REST API revision ${revision}: ${apiHost}`],
    detect: [{ kind: "file", path: ".acme.toml" }],
    credential: {
      tokenDescription: "Acme API token",
      agentEnv: ["ACME_TOKEN"],
      credentials: [{ host: apiHost, header: "Authorization", scheme: "bearer" }],
    },
  };
}

function writeImportFixture(world: E2EWorld, name: string, value: unknown): string {
  const directory = path.join(world.root, "downloaded-definitions");
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const file = path.join(directory, name);
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  return file;
}

function policyPath(world: E2EWorld): string {
  return path.join(world.projectRoot, ".runfree", "network-policy.json");
}

function userServicePath(world: E2EWorld): string {
  return path.join(world.configHome, "runfree", "services", "user-acme.json");
}

describe("Phase 2 user-defined service evolution through the packaged CLI", () => {
  scenario("strict from-file import requires confirmation and writes only validated definitions to XDG config", importMetadata, async () => {
    await withWorld({}, async (world) => {
      assertExit(await world.runfree(["init"]), 0);
      const validSource = writeImportFixture(world, "acme-v1.json", definition(1));
      const invalidSource = writeImportFixture(world, "acme-invalid.json", {
        ...definition(1),
        unexpectedAuthority: true,
      });
      const selections = [
        { name: "project", path: world.projectRoot },
        { name: "host config", path: world.configHome },
        { name: "host data", path: world.dataHome },
        { name: "host state", path: world.stateHome },
      ] as const;

      const beforeConfirmationRefusal = snapshotOwnedState(selections);
      const confirmationRefusal = await world.runfree([
        "service", "custom", "add", "user-acme", "--from-file", validSource,
      ]);
      assertExit(confirmationRefusal, 1);
      assertOutputContains(confirmationRefusal, "service custom add --from-file requires an interactive TTY");
      assertOwnedStateUnchanged(beforeConfirmationRefusal, snapshotOwnedState(selections));

      const beforeValidationRefusal = snapshotOwnedState(selections);
      const validationRefusal = await world.runfree([
        "service", "custom", "add", "user-acme", "--from-file", invalidSource, "--yes",
      ]);
      assertExit(validationRefusal, 1);
      assertOutputContains(validationRefusal, "definition: unknown key unexpectedAuthority");
      assertOwnedStateUnchanged(beforeValidationRefusal, snapshotOwnedState(selections));

      const policyBeforeImport = fs.readFileSync(policyPath(world));
      const imported = await world.runfree([
        "service", "custom", "add", "user-acme", "--from-file", validSource, "--yes",
      ]);
      assertExit(imported, 0);
      assertOutputContains(imported, "user-defined service user-acme imported");
      assertOutputContains(imported, "enable it with: runfree service enable user-acme");
      const destination = userServicePath(world);
      expect(destination.startsWith(`${world.configHome}${path.sep}`)).toBe(true);
      expect(destination.startsWith(`${world.projectRoot}${path.sep}`)).toBe(false);
      expect(readJson<UserServiceDefinition>(destination)).toEqual(definition(1));
      assertFileMode(destination, 0o600);
      expect(fs.readFileSync(policyPath(world))).toEqual(policyBeforeImport);

      const metadataPath = path.join(path.dirname(destination), ".metadata", "user-acme.json");
      expect(readJson<Record<string, unknown>>(metadataPath)).toMatchObject({
        importedFrom: validSource,
        digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
        importedAt: expect.any(String),
      });
      assertFileMode(metadataPath, 0o600);

      const afterImport = snapshotOwnedState(selections);
      const repeatedCreate = await world.runfree([
        "service", "custom", "add", "user-acme", "--from-file", validSource, "--yes",
      ]);
      assertExit(repeatedCreate, 1);
      assertOutputContains(repeatedCreate, "already exists; pass --replace to overwrite");
      assertOwnedStateUnchanged(afterImport, snapshotOwnedState(selections));
    });
  });

  scenario("enabled semantics stay pinned across definition replacement until explicit diff apply", evolutionMetadata, async () => {
    await withWorld({}, async (world) => {
      assertExit(await world.runfree(["init"]), 0);
      world.installEmptyDockerInventory();
      const localReview = await world.runfree(["policy", "diff", "--local", "--json"]);
      assertExit(localReview, 0);
      const localDiffs = JSON.parse(localReview.stdout) as readonly Readonly<{
        scope: string;
        desiredDigest: string;
      }>[];
      const localDigest = localDiffs.find((diff) => diff.scope === "local")?.desiredDigest;
      expect(localDigest).toMatch(/^sha256:[a-f0-9]{64}$/u);
      assertExit(await world.runfree([
        "policy", "approve", "--local", "--subject-digest", localDigest ?? "missing-local-digest",
      ]), 0);
      const v1Source = writeImportFixture(world, "acme-v1.json", definition(1));
      const v2Source = writeImportFixture(world, "acme-v2.json", definition(2));
      assertExit(await world.runfree([
        "service", "custom", "add", "user-acme", "--from-file", v1Source, "--yes",
      ]), 0);

      const sentinel = "RUNFREE_E2E_SECRET_MUST_NOT_BE_STORED";
      const enabled = await world.runfree([
        "service", "enable", "user-acme", "--from-env", "RUNFREE_E2E_ACME_TOKEN", "--skip-broad", "--no-reload",
      ], { env: { RUNFREE_E2E_ACME_TOKEN: sentinel } });
      assertExit(enabled, 0);
      assertOutputContains(enabled, "service user-acme: updated in project desired policy");
      assertOutputContains(enabled, "effective policy: unchanged (--no-reload)");
      assertOutputExcludes(enabled, sentinel);

      const pinnedV1 = readJson<DesiredPolicy>(policyPath(world));
      const v1Entry = pinnedV1.services?.["user-acme"];
      expect(pinnedV1.hosts).toEqual([]);
      expect(v1Entry).toMatchObject({
        definitionDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
        revision: 1,
        selection: { skippedHosts: ["cdn.acme.example"] },
        resolved: {
          hosts: ["api.acme.example"],
          agentEnv: ["ACME_TOKEN"],
          tokens: {
            "user-acme": {
              description: "Acme API token",
              credentials: [{ host: "api.acme.example", header: "Authorization", scheme: "bearer" }],
            },
          },
        },
      });
      expect(fs.readFileSync(policyPath(world), "utf8")).not.toContain(sentinel);

      const projectId = await world.runfree(["project-id"]);
      assertExit(projectId, 0);
      const tokenSourcePath = path.join(
        world.configHome,
        "runfree",
        "projects",
        projectId.stdout.trim(),
        "tokens.json",
      );
      expect(readJson<TokenSources>(tokenSourcePath)["user-acme"]).toEqual({
        source: "env",
        env: "RUNFREE_E2E_ACME_TOKEN",
        runfreeUserServiceOwner: "user-acme",
      });
      expect(fs.readFileSync(tokenSourcePath, "utf8")).not.toContain(sentinel);

      const enabledState = [
        { name: "project", path: world.projectRoot },
        { name: "host config", path: path.join(world.configHome, "runfree") },
        { name: "host state", path: path.join(world.stateHome, "runfree") },
      ] as const;
      const beforeSecondEnable = snapshotOwnedState(enabledState);
      const secondEnable = await world.runfree([
        "service", "enable", "user-acme", "--from-env", "RUNFREE_E2E_ACME_TOKEN", "--skip-broad", "--no-reload",
      ], { env: { RUNFREE_E2E_ACME_TOKEN: sentinel } });
      assertExit(secondEnable, 0);
      assertOutputContains(secondEnable, "service user-acme: unchanged in project desired policy");
      const afterSecondEnable = snapshotOwnedState(enabledState);

      const pinnedV1Bytes = fs.readFileSync(policyPath(world));
      const replaced = await world.runfree([
        "service", "custom", "add", "user-acme", "--from-file", v2Source, "--replace", "--yes",
      ]);
      assertExit(replaced, 0);
      expect(readJson<UserServiceDefinition>(userServicePath(world))).toEqual(definition(2));
      expect(fs.readFileSync(policyPath(world))).toEqual(pinnedV1Bytes);

      const beforeReviewOnlyDiff = snapshotOwnedState(enabledState);
      const reviewed = await world.runfree(["service", "diff", "--no-reload"]);
      assertExit(reviewed, 0);
      assertOutputContains(reviewed, "user-acme (project): revision 1 -> 2");
      assertOutputContains(reviewed, "api.acme.example");
      assertOutputContains(reviewed, "api-v2.acme.example");
      assertOutputContains(reviewed, "apply with: runfree service diff --apply");
      assertOwnedStateUnchanged(beforeReviewOnlyDiff, snapshotOwnedState(enabledState));

      const applied = await world.runfree(["service", "diff", "--apply", "--no-reload"]);
      assertExit(applied, 0);
      assertOutputContains(applied, "effective policy: unchanged (--no-reload)");
      const pinnedV2 = readJson<DesiredPolicy>(policyPath(world));
      expect(pinnedV2.services?.["user-acme"]).toMatchObject({
        definitionDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
        revision: 2,
        selection: { skippedHosts: ["cdn.acme.example"] },
        resolved: {
          hosts: ["api-v2.acme.example"],
          agentEnv: ["ACME_TOKEN"],
          tokens: {
            "user-acme": {
              credentials: [{ host: "api-v2.acme.example", header: "Authorization", scheme: "bearer" }],
            },
          },
        },
      });
      expect(pinnedV2.services?.["user-acme"]?.definitionDigest).not.toBe(v1Entry?.definitionDigest);

      const beforeSecondApply = snapshotOwnedState(enabledState);
      assertExit(await world.runfree(["service", "diff", "--apply", "--no-reload"]), 0);
      assertOwnedStateUnchanged(beforeSecondApply, snapshotOwnedState(enabledState));

      const pinnedV2Bytes = fs.readFileSync(policyPath(world));
      const removed = await world.runfree(["service", "custom", "remove", "user-acme"]);
      assertExit(removed, 0);
      assertOutputContains(removed, "user-defined service user-acme removed");
      expect(fs.existsSync(userServicePath(world))).toBe(false);
      expect(fs.readFileSync(policyPath(world))).toEqual(pinnedV2Bytes);

      const unavailableDiff = await world.runfree(["service", "diff", "--no-reload"]);
      assertExit(unavailableDiff, 0);
      assertOutputContains(unavailableDiff, "user-acme (project): definition unavailable; approved semantics retained");
      expect(fs.readFileSync(policyPath(world))).toEqual(pinnedV2Bytes);
      const explanation = await world.runfree(["service", "explain", "user-acme"]);
      assertExit(explanation, 0);
      assertOutputContains(explanation, '"revision": 2');
      assertOutputContains(explanation, '"api-v2.acme.example"');

      const afterRemoval = snapshotOwnedState(enabledState);
      const secondRemoval = await world.runfree(["service", "custom", "remove", "user-acme"]);
      assertExit(secondRemoval, 0);
      assertOutputContains(secondRemoval, "user-defined service user-acme is not defined");
      assertOwnedStateUnchanged(afterRemoval, snapshotOwnedState(enabledState));
      expect(fs.readFileSync(world.dockerLog, "utf8").split("\n").filter(Boolean).every((line) => line.startsWith("ps "))).toBe(true);

      // Preserve the packaged defect after the rest of the lifecycle runs:
      // an unchanged typed mutation still refreshes approval metadata.
      assertOwnedStateUnchanged(beforeSecondEnable, afterSecondEnable);
    });
  }, 60_000);
});
