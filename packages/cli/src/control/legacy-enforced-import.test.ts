import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { validateNetworkPolicy } from "@runfree/runtime-contracts/network-policy";
import {
  ensureProject,
  projectInfo,
  QUIESCED_CONFIG_MIGRATION,
} from "../config.ts";
import { projectHash } from "../project-identity.ts";
import { readControlApprovalSelection } from "./approvals.ts";
import { checkoutFingerprint } from "./subjects.ts";

const digest = (character: string): string => `sha256:${character.repeat(64)}`;

// The runtime-side proof producer was deleted with the pre-v4 runtime paths,
// so a proof can only have been recorded by an older release. These tests
// write that older-release proof file directly and prove the authoring-side
// consumer (`importProvenLegacyNetworkApproval`, reached through config
// migration) imports only an exact, checkout-bound, generation-matching proof
// — and falls back to the normal exact-review path otherwise.
describe("legacy enforced network import", () => {
  let root: string;
  let hostRoot: string;
  let templates: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-legacy-network-")));
    hostRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-legacy-network-host-")));
    templates = path.join(root, "templates");
    env = {
      XDG_STATE_HOME: path.join(hostRoot, "state"),
      XDG_CONFIG_HOME: path.join(hostRoot, "config"),
    };
    fs.mkdirSync(path.join(root, ".runfree"));
    fs.mkdirSync(templates);
    fs.writeFileSync(path.join(root, ".runfree", "runfree.json"), JSON.stringify({
      version: 3,
      agents: { default: "claude", claude: { command: "claude" } },
      runtime: {},
    }));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), JSON.stringify({
      hosts: ["example.com"],
      requests: { "example.com": { methods: ["GET"] } },
    }));
    fs.writeFileSync(path.join(templates, "runfree.json"), JSON.stringify({
      version: 4,
      agents: { default: "claude", claude: { command: "claude" } },
      runtime: {},
    }));
    fs.writeFileSync(path.join(templates, "network-policy.json"), JSON.stringify({ version: 2, hosts: [] }));
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(hostRoot, { recursive: true, force: true });
  });

  // Writes the proof exactly as the retired pre-v4 runtime recorded it.
  function recordOlderReleaseProof(overrides: Record<string, unknown> = {}): string {
    const legacyProject = projectInfo(root, env);
    const generation = validateNetworkPolicy(JSON.parse(
      fs.readFileSync(legacyProject.paths.policyPath, "utf8"),
    ) as unknown).generation;
    const proof = {
      schemaVersion: 1,
      projectId: projectHash(root),
      checkoutFingerprint: checkoutFingerprint(root),
      configVersion: 3,
      overlayModel: "none",
      policyGeneration: generation,
      runtimeGenerationDigest: digest("9"),
      agentId: "a".repeat(12),
      proxyId: "b".repeat(12),
      recordedAt: "2026-08-05T12:00:00.000Z",
      ...overrides,
    };
    fs.mkdirSync(path.dirname(legacyProject.paths.controlLegacyEnforcedNetworkPath), { recursive: true });
    fs.writeFileSync(
      legacyProject.paths.controlLegacyEnforcedNetworkPath,
      `${JSON.stringify(proof, null, 2)}\n`,
      { mode: 0o600 },
    );
    return legacyProject.paths.controlLegacyEnforcedNetworkPath;
  }

  function migrate() {
    return ensureProject(root, templates, env, {
      migrateConfig: true,
      migrationProof: QUIESCED_CONFIG_MIGRATION,
    });
  }

  test("imports the exact previously validated policy recorded by an older release", () => {
    recordOlderReleaseProof();

    const project = migrate();
    expect(readControlApprovalSelection(root, project)?.subjects["network-project"]).toMatchObject({
      mechanism: "legacy-enforced-generation",
    });
  });

  test("leaves changed policy pending instead of importing stale proof", () => {
    recordOlderReleaseProof();
    const legacyProject = projectInfo(root, env);
    fs.writeFileSync(legacyProject.paths.policyPath, JSON.stringify({ hosts: ["changed.example"] }));

    const project = migrate();
    expect(readControlApprovalSelection(root, project)).toBeUndefined();
  });

  test("rejects proof bound to another checkout fingerprint", () => {
    recordOlderReleaseProof({ checkoutFingerprint: digest("f") });

    const project = migrate();
    expect(readControlApprovalSelection(root, project)).toBeUndefined();
  });

  test("rejects a malformed or wrong-shape proof file", () => {
    const proofPath = recordOlderReleaseProof({ overlayModel: "unexpected" });

    const project = migrate();
    expect(readControlApprovalSelection(root, project)).toBeUndefined();
    expect(fs.existsSync(proofPath)).toBe(true);
  });
});
