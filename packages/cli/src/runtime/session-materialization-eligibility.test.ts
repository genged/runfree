import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test } from "vitest";

import {
  bindSessionAgentImageV2,
  createSessionAgentGenerationInputsV2,
  publishSessionAgentMaterializationV2,
} from "./component-state-v2.ts";
import { sha256Digest } from "./component-state.ts";
import {
  classifySessionAgentMaterializationEligibilityV2,
  compileAllowedSessionAgentMaterializationsV2,
} from "./session-materialization-eligibility.ts";
import {
  effectiveControlPlaneFixture,
  sessionAgentMaterializationFixture,
  sessionContainerRecordFixture,
  sessionGenerationFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import { sessionContainerName } from "./session-containers.ts";

let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-materialization-eligibility-"));
});

afterEach(() => fs.rmSync(stateDir, { recursive: true, force: true }));

test("admits exact current and retained direct-session generations together", () => {
  const current = sessionGenerationFixture();
  const olderGeneration = bindSessionAgentImageV2(createSessionAgentGenerationInputsV2({
    selectedAgentImageInputDigest: sha256Digest("older-direct-session-image-input"),
    sessionTemplateDigest: sha256Digest("older-direct-session-template"),
    admissionContractEpoch: current.target.controlPlane.admissionContractEpoch,
  }), sha256Digest("older-direct-session-image-id"));
  const currentManifest = sessionAgentMaterializationFixture({ generation: current.generation });
  const olderManifest = sessionAgentMaterializationFixture({ generation: olderGeneration });
  publishSessionAgentMaterializationV2(stateDir, currentManifest, "session-template-artifact");
  publishSessionAgentMaterializationV2(stateDir, olderManifest, "session-template-artifact");
  const olderRecord = sessionContainerRecordFixture({
    target: current.target,
    generation: olderGeneration,
    containerId: "a".repeat(64),
  });

  const allowed = compileAllowedSessionAgentMaterializationsV2({
    stateDir,
    expectedProject: SESSION_TEST_PROJECT,
    effectiveControlPlane: effectiveControlPlaneFixture({ target: current.target }),
    records: [olderRecord],
    candidate: currentManifest,
  });

  expect(allowed.map((manifest) => manifest.sessionAgentMaterializationDigest).sort()).toEqual([
    currentManifest.sessionAgentMaterializationDigest,
    olderManifest.sessionAgentMaterializationDigest,
  ].sort());
});

test("isolates only the record whose exact materialization evidence is invalid", () => {
  const current = sessionGenerationFixture();
  const manifest = sessionAgentMaterializationFixture({ generation: current.generation });
  publishSessionAgentMaterializationV2(stateDir, manifest, "session-template-artifact");
  const valid = sessionContainerRecordFixture({
    target: current.target,
    generation: current.generation,
    containerId: "a".repeat(64),
  });
  const invalid = sessionContainerRecordFixture({
    target: current.target,
    generation: current.generation,
    containerId: "b".repeat(64),
    overrides: {
      sessionId: "rf-20260808-fedcba",
      sessionIncarnation: "c".repeat(64),
      sessionPrincipal: "d".repeat(64),
      containerName: sessionContainerName(SESSION_TEST_PROJECT.projectId, "rf-20260808-fedcba"),
      sourceIp: "172.31.90.21",
      selectedAgentImageId: sha256Digest("contradictory-image-id"),
    },
  });

  const classified = classifySessionAgentMaterializationEligibilityV2({
    stateDir,
    expectedProject: SESSION_TEST_PROJECT,
    effectiveControlPlane: effectiveControlPlaneFixture({ target: current.target }),
    records: [valid, invalid],
    candidate: manifest,
  });

  expect(classified.invalidRecords.map((record) => record.sessionId)).toEqual([invalid.sessionId]);
  expect(classified.allowed).toEqual([manifest]);
});

test("rejects duplicate registry claims and bounded-set overflow", () => {
  const current = sessionGenerationFixture();
  const manifest = sessionAgentMaterializationFixture({ generation: current.generation });
  publishSessionAgentMaterializationV2(stateDir, manifest, "session-template-artifact");
  const record = sessionContainerRecordFixture({
    target: current.target,
    generation: current.generation,
    containerId: "a".repeat(64),
  });
  const input = {
    stateDir,
    expectedProject: SESSION_TEST_PROJECT,
    effectiveControlPlane: effectiveControlPlaneFixture({ target: current.target }),
    candidate: manifest,
  };

  expect(() => classifySessionAgentMaterializationEligibilityV2({
    ...input,
    records: [record, record],
  })).toThrow("duplicates a session id claim");
  expect(() => classifySessionAgentMaterializationEligibilityV2({
    ...input,
    records: Array.from({ length: 65 }, () => record),
  })).toThrow("bounded record limit");
});
