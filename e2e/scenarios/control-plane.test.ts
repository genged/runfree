import fs from "node:fs";
import path from "node:path";

import { describe, expect } from "vitest";

import { assertExit, assertOutputContains, assertOutputExcludes, readJson } from "../support/assertions.ts";
import { scenario } from "../support/evidence.ts";
import { assertOwnedStateUnchanged, snapshotOwnedState } from "../support/snapshot.ts";
import { withWorld } from "../support/world.ts";

type DesiredPolicy = Readonly<{
  version: number;
  hosts: readonly string[];
  services?: Readonly<Record<string, {
    definitionDigest: string;
    revision: number;
    resolved: Readonly<{
      hosts: readonly string[];
      tokens?: Readonly<Record<string, unknown>>;
    }>;
  }>>;
}>;

type SourceConfig = Readonly<Record<string, { type?: string; displayArgv?: readonly string[] }>>;

const modeledDockerOnlyEvidence = {
  kind: "modeled-external-step",
  modeledSteps: ["Docker daemon availability", "Docker container inventory with no live project agents"],
  proofLimits: "The local Docker stub proves host-side CLI orchestration and preflight order, not daemon or container-runtime compatibility.",
} as const;

const modeledQuickstartEvidence = {
  kind: "modeled-external-step",
  modeledSteps: [
    "A host credential command that returns a sentinel value",
  ],
  proofLimits: "The local credential stub proves host-side CLI orchestration, source isolation, and that the --no-reload desired-policy path issues no Docker command at all; it proves nothing about real credential-provider compatibility, nor about the reload path that does reach Docker.",
} as const;

const packagedCleanup = "Remove the disposable project, home, XDG roots, and modeled Docker log after the test.";

const quickstartMetadata = {
  scenarioIds: ["LH-06", "LH-08"],
  layer: "P",
  cadence: "pull-request",
  implementationStatus: "Partial",
  evidence: modeledQuickstartEvidence,
  ownedStateAreas: ["project", "host credential sources", "modeled Docker invocation log"],
  requiredPrograms: ["packaged Runfree executable", "POSIX shell"],
  cleanup: packagedCleanup,
} as const;

const refusalMetadata = {
  scenarioIds: ["LH-26"],
  layer: "P",
  cadence: "pull-request",
  implementationStatus: "Partial",
  evidence: { kind: "reproduced-user-workflow" },
  ownedStateAreas: ["project", "XDG config", "XDG state", "modeled Docker invocation log"],
  requiredPrograms: ["packaged Runfree executable", "POSIX shell"],
  cleanup: packagedCleanup,
} as const;

describe("host control workflows through the packaged CLI", () => {
  scenario("the documented credential-source, Node, and GitHub service workflow converges", quickstartMetadata, async () => {
    await withWorld({}, async (world) => {
      const initialized = await world.runfree(["init"]);
      assertExit(initialized, 0);
      world.installEmptyDockerInventory();
      const sourceCommand = path.join(world.fakeBin, "e2e-credential-source");
      fs.writeFileSync(sourceCommand, "#!/bin/sh\nprintf '%s\\n' SOURCE_STDOUT_MUST_NOT_BE_STORED\n", { mode: 0o755 });

      const source = await world.runfree(["credential", "source", "add", "github-cli", "--", "e2e-credential-source"]);
      assertExit(source, 0);
      assertOutputContains(source, "github-cli source configured");
      assertOutputContains(source, "agent exposure: no");
      assertOutputExcludes(source, "SOURCE_STDOUT_MUST_NOT_BE_STORED");

      const sourcePath = path.join(world.configHome, "runfree", "sources.json");
      const sourceConfig = readJson<SourceConfig>(sourcePath);
      expect(sourceConfig["github-cli"]?.type).toBe("command");
      expect(sourceConfig["github-cli"]?.displayArgv).toEqual(["e2e-credential-source"]);
      expect(fs.readFileSync(sourcePath, "utf8")).not.toContain("SOURCE_STDOUT_MUST_NOT_BE_STORED");
      expect(fs.existsSync(path.join(world.projectRoot, ".runfree", "config", "sources.json"))).toBe(false);

      const sourceSnapshot = snapshotOwnedState([{ name: "host sources", path: sourcePath }]);
      const sourceSecondRun = await world.runfree(["credential", "source", "add", "github-cli", "--", "e2e-credential-source"]);
      assertExit(sourceSecondRun, 0);
      assertOwnedStateUnchanged(sourceSnapshot, snapshotOwnedState([{ name: "host sources", path: sourcePath }]));

      const nodeEnabled = await world.runfree(["service", "enable", "node", "--no-reload"]);
      assertExit(nodeEnabled, 0);
      assertOutputContains(nodeEnabled, "effective policy: unchanged (--no-reload)");
      const policyPath = path.join(world.projectRoot, ".runfree", "network-policy.json");
      const nodePolicy = readJson<DesiredPolicy>(policyPath);
      expect(nodePolicy.services?.node?.resolved.hosts).toEqual(expect.arrayContaining([
        "registry.npmjs.org",
        "registry.yarnpkg.com",
      ]));
      const nodeSnapshot = snapshotOwnedState([{ name: "project", path: world.projectRoot }]);
      assertExit(await world.runfree(["service", "enable", "node", "--no-reload"]), 0);
      assertOwnedStateUnchanged(nodeSnapshot, snapshotOwnedState([{ name: "project", path: world.projectRoot }]));

      const enabled = await world.runfree(["service", "enable", "github", "--from-source", "github-cli", "--no-reload"]);
      assertExit(enabled, 0);
      assertOutputContains(enabled, "effective policy: unchanged (--no-reload)");

      const policy = readJson<DesiredPolicy>(policyPath);
      const github = policy.services?.github;
      expect(policy.version).toBe(2);
      expect(github?.definitionDigest).toMatch(/^sha256:[a-f0-9]{64}$/u);
      expect(github?.revision).toBeGreaterThan(0);
      expect(github?.resolved.hosts).toContain("api.github.com");
      expect(github?.resolved.hosts).toContain("github.com");
      expect(github?.resolved.tokens?.github).toBeDefined();
      const policyBytes = fs.readFileSync(policyPath, "utf8");
      expect(policyBytes).not.toContain("gh auth token");
      expect(policyBytes).not.toContain("test-token");

      const converged = snapshotOwnedState([
        { name: "project", path: world.projectRoot },
        { name: "host sources", path: sourcePath },
      ]);
      const secondEnable = await world.runfree(["service", "enable", "github", "--from-source", "github-cli", "--no-reload"]);
      assertExit(secondEnable, 0);
      assertOwnedStateUnchanged(converged, snapshotOwnedState([
        { name: "project", path: world.projectRoot },
        { name: "host sources", path: sourcePath },
      ]));
      // A2 (2026-09-01) removed the Compose-agent pause from the desired-policy
      // mutation path: liveness is now decided from host session-container
      // records, and --no-reload never reaches the proxy runtime, so the whole
      // converged workflow above must touch Docker zero times. The empty log is
      // measured, not vacuous: the "startup accepts only exact current
      // authority" scenario below installs the same stub inventory into the
      // same log and asserts "info" and "ps" come back out of it.
      expect(fs.readFileSync(world.dockerLog, "utf8")).toBe("");
    });
  });

  scenario("strict option parsing refuses before project or Docker mutation", refusalMetadata, async () => {
    await withWorld({}, async (world) => {
      const initialized = await world.runfree(["init"]);
      assertExit(initialized, 0);
      world.installEmptyDockerInventory();
      const selections = [
        { name: "project", path: world.projectRoot },
        { name: "config", path: world.configHome },
        { name: "state", path: world.stateHome },
      ] as const;
      const before = snapshotOwnedState(selections);

      const refused = await world.runfree(["host", "add", "bad.example", "--bogus"]);
      assertExit(refused, 1);
      assertOutputContains(refused, "Unknown argument: bogus");
      assertOwnedStateUnchanged(before, snapshotOwnedState(selections));
      expect(fs.readFileSync(world.dockerLog, "utf8")).toBe("");
    });
  });

  scenario("image init refuses a symlinked control file before any write", {
    scenarioIds: ["LH-10"],
    layer: "P",
    cadence: "pull-request",
    implementationStatus: "Implemented",
    evidence: {
      kind: "constructed-recovery-state",
      constructedState: ".runfree/runfree.json is a symlink to an external regular file",
      unproved: "The scenario does not claim that a real interruption or attack created the symlink.",
    },
    ownedStateAreas: ["project", "external symlink target", "XDG config", "XDG data", "XDG state"],
    requiredPrograms: ["packaged Runfree executable"],
    cleanup: packagedCleanup,
  }, async () => {
    await withWorld({}, async (world) => {
      const runfreeDir = path.join(world.projectRoot, ".runfree");
      const outside = path.join(world.root, "outside-runfree.json");
      fs.mkdirSync(runfreeDir, { recursive: true });
      const outsideBytes = `${JSON.stringify({
        version: 4,
        agents: {
          default: "claude",
          claude: { command: "claude --dangerously-skip-permissions" },
          codex: { command: "codex --dangerously-bypass-approvals-and-sandbox" },
        },
        runtime: {},
      }, null, 2)}\n`;
      fs.writeFileSync(outside, outsideBytes);
      fs.symlinkSync(outside, path.join(runfreeDir, "runfree.json"));
      const selections = [
        { name: "project", path: world.projectRoot },
        { name: "outside target", path: outside },
        { name: "config", path: world.configHome },
        { name: "data", path: world.dataHome },
        { name: "state", path: world.stateHome },
      ] as const;
      const before = snapshotOwnedState(selections);

      const refused = await world.runfree(["image", "init"]);
      assertExit(refused, 1);
      assertOutputContains(refused, "refusing to write unsafe project-controlled path: .runfree/runfree.json");
      assertOwnedStateUnchanged(before, snapshotOwnedState(selections));
      expect(fs.readFileSync(outside, "utf8")).toBe(outsideBytes);
    });
  });

  scenario("startup accepts only exact current authority and refuses image input before Docker build", {
    scenarioIds: ["LH-04", "LH-10"],
    layer: "P",
    cadence: "pull-request",
    implementationStatus: "Partial",
    evidence: modeledDockerOnlyEvidence,
    ownedStateAreas: ["project", "host approval selection", "modeled Docker invocation log"],
    requiredPrograms: ["packaged Runfree executable", "POSIX shell"],
    cleanup: packagedCleanup,
  }, async () => {
    await withWorld({}, async (world) => {
      assertExit(await world.runfree(["init"]), 0);
      assertExit(await world.runfree(["image", "init"]), 0);
      world.installEmptyDockerInventory();
      const projectSelection = [{ name: "project", path: world.projectRoot }] as const;
      const projectBefore = snapshotOwnedState(projectSelection);

      const authorityRefusal = await world.runfree(["up"]);
      assertExit(authorityRefusal, 1);
      assertOutputContains(authorityRefusal, "desired controls require exact approval before startup");
      // The refusal is one multi-line message; the shared formatter indents its
      // continuation lines under the attributed first line, so the anchor tolerates
      // that indent and nothing else before the command.
      const approvalPattern = /^ *runfree control approve ([a-z-]+) --subject-digest (sha256:[a-f0-9]{64})$/gmu;
      const approvals = [...`${authorityRefusal.stdout}${authorityRefusal.stderr}`.matchAll(approvalPattern)]
        .map((match) => ({ subject: match[1], digest: match[2] }));
      expect(approvals.map((approval) => approval.subject).sort()).toEqual(["network-local", "network-project", "runtime-isolation"]);
      assertOwnedStateUnchanged(projectBefore, snapshotOwnedState(projectSelection));
      assertOutputExcludes(authorityRefusal, "at async");

      const projectId = await world.runfree(["project-id"]);
      assertExit(projectId, 0);
      const approvalPath = path.join(
        world.stateHome,
        "runfree",
        "projects",
        projectId.stdout.trim(),
        "control",
        "approvals.json",
      );
      const approvalSelections = [
        { name: "project", path: world.projectRoot },
        { name: "host approval selection", path: approvalPath },
      ] as const;
      const projectApproval = approvals.find((approval) => approval.subject === "network-project");
      if (!projectApproval) throw new Error("startup refusal omitted the network-project approval command");
      const shortDigest = projectApproval.digest.slice(0, -1);
      const shortBefore = snapshotOwnedState(approvalSelections);
      const shortRefusal = await world.runfree([
        "control", "approve", "network-project", "--subject-digest", shortDigest,
      ]);
      assertExit(shortRefusal, 1);
      assertOutputContains(shortRefusal, "subject digest must be a full sha256 digest");
      assertOwnedStateUnchanged(shortBefore, snapshotOwnedState(approvalSelections));

      const lastCharacter = projectApproval.digest.at(-1);
      const wrongDigest = `${projectApproval.digest.slice(0, -1)}${lastCharacter === "0" ? "1" : "0"}`;
      const wrongBefore = snapshotOwnedState(approvalSelections);
      const wrongRefusal = await world.runfree([
        "control", "approve", "network-project", "--subject-digest", wrongDigest,
      ]);
      assertExit(wrongRefusal, 1);
      assertOutputContains(wrongRefusal, "network-project subject digest changed");
      assertOwnedStateUnchanged(wrongBefore, snapshotOwnedState(approvalSelections));

      const wrongSubjectBefore = snapshotOwnedState(approvalSelections);
      const wrongSubjectRefusal = await world.runfree([
        "control", "approve", "network-local", "--subject-digest", projectApproval.digest,
      ]);
      assertExit(wrongSubjectRefusal, 1);
      assertOutputContains(wrongSubjectRefusal, "network-local subject digest changed");
      assertOwnedStateUnchanged(wrongSubjectBefore, snapshotOwnedState(approvalSelections));

      const policyPath = path.join(world.projectRoot, ".runfree", "network-policy.json");
      const driftedPolicy = readJson<DesiredPolicy>(policyPath);
      fs.writeFileSync(policyPath, `${JSON.stringify({ ...driftedPolicy, hosts: ["stale.example"] }, null, 2)}\n`);
      const staleBefore = snapshotOwnedState(approvalSelections);
      const staleRefusal = await world.runfree([
        "control", "approve", "network-project", "--subject-digest", projectApproval.digest,
      ]);
      assertExit(staleRefusal, 1);
      assertOutputContains(staleRefusal, "network-project subject digest changed");
      assertOwnedStateUnchanged(staleBefore, snapshotOwnedState(approvalSelections));

      const updatedAuthorityRefusal = await world.runfree(["up"]);
      assertExit(updatedAuthorityRefusal, 1);
      assertOutputContains(updatedAuthorityRefusal, "desired controls require exact approval before startup");
      const updatedApprovals = [...`${updatedAuthorityRefusal.stdout}${updatedAuthorityRefusal.stderr}`.matchAll(approvalPattern)]
        .map((match) => ({ subject: match[1], digest: match[2] }));
      expect(updatedApprovals.map((approval) => approval.subject).sort())
        .toEqual(["network-local", "network-project", "runtime-isolation"]);

      for (const approval of updatedApprovals) {
        const accepted = await world.runfree(["control", "approve", approval.subject, "--subject-digest", approval.digest]);
        assertExit(accepted, 0);
      }

      const beforeBuildRefusal = snapshotOwnedState(projectSelection);
      const buildRefusal = await world.runfree(["up"]);
      assertExit(buildRefusal, 1);
      assertOutputContains(buildRefusal, "exact pre-sandbox Docker build approval is required");
      assertOutputContains(buildRefusal, "runfree image approve-context");
      assertOwnedStateUnchanged(beforeBuildRefusal, snapshotOwnedState(projectSelection));
      const dockerCalls = fs.readFileSync(world.dockerLog, "utf8");
      const dockerSubcommands = dockerCalls.split("\n").filter(Boolean).map((call) => call.split(" ", 1)[0]);
      // Reach first, so the two refusals below are measured and not vacuous:
      // startup did probe the daemon and its container inventory, and the stub
      // recorded that into the log the negative assertions then read.
      expect(dockerSubcommands).toContain("info");
      expect(dockerSubcommands).toContain("ps");
      expect(dockerSubcommands).not.toContain("build");
      expect(dockerSubcommands).not.toContain("compose");
    });
  }, 90_000);
});
