import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import {
  parseSessionAdmissionEligibility,
  serializeSessionAdmissionEligibility,
} from "@runfree/runtime-contracts/session-admission";
import { SESSION_ELIGIBILITY_PATH } from "@runfree/runtime-contracts/session-file";

import {
  bindSessionAgentImageV2,
  createControlPlaneMaterializationManifestV2,
  createSessionAgentDesiredSelectionV2,
  createSessionAgentGenerationInputsV2,
  publishControlPlaneMaterializationV2,
  publishSessionAgentMaterializationV2,
  readPublishedSessionEligibilityV2,
  readRetainedDesiredSessionAgentV2,
  selectDesiredSessionAgentV2,
  selectEffectiveControlPlaneV2,
  readEffectiveControlPlaneV2,
  type ControlPlaneMaterializationManifestV2,
} from "./component-state-v2.ts";
import { sha256Digest } from "./component-state.ts";
import { ensureSessionEligibilityPublished } from "./session-eligibility-publication.ts";
import {
  effectiveControlPlaneFixture,
  sessionAgentMaterializationFixture,
  sessionContainerRecordFixture,
  sessionGenerationFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import { writeSessionContainerRecordV2, type SessionContainerRecordV2 } from "./session-containers.ts";
import type { CaptureResult, RuntimeIO } from "./types.ts";

const TEMPLATE_ARTIFACT = "session-template-artifact";
let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admission-source-"));
});

afterEach(() => fs.rmSync(stateDir, { recursive: true, force: true }));

type PublishedCall = { args: readonly string[]; input?: string };

function recordingIo(status = 0): { io: RuntimeIO; calls: PublishedCall[] } {
  const calls: PublishedCall[] = [];
  const capture = vi.fn((
    _command: string,
    args: string[],
    options?: { input?: string },
  ): CaptureResult => {
    calls.push({ args: [...args], ...(options?.input !== undefined ? { input: options.input } : {}) });
    return { status, stdout: "", stderr: status === 0 ? "" : "refused" };
  });
  return { io: { capture } as unknown as RuntimeIO, calls };
}

/** Publishes the control-plane materialization and its effective selection. */
function selectControlPlane(): ControlPlaneMaterializationManifestV2 {
  const target = sessionGenerationFixture().target;
  const selection = effectiveControlPlaneFixture({ target });
  const manifest = createControlPlaneMaterializationManifestV2({
    ...SESSION_TEST_PROJECT,
    generation: target.controlPlane,
    proxyImageRef: "runfree/proxy:test",
    proxyImageId: selection.proxyImageId,
    renderedControlPlaneSha256: target.controlPlane.controlPlaneTopologyDigest,
    sessionAdmissionSource: "files",
  });
  publishControlPlaneMaterializationV2(stateDir, manifest);
  selectEffectiveControlPlaneV2(stateDir, {
    ...selection,
    controlPlaneMaterializationDigest: manifest.controlPlaneMaterializationDigest,
  });
  return manifest;
}

function selectDesiredAgent(): void {
  const manifest = sessionAgentMaterializationFixture();
  publishSessionAgentMaterializationV2(stateDir, manifest, TEMPLATE_ARTIFACT);
  selectDesiredSessionAgentV2(stateDir, createSessionAgentDesiredSelectionV2(manifest));
}

function olderAgentRecord(): SessionContainerRecordV2 {
  const target = sessionGenerationFixture().target;
  const generation = bindSessionAgentImageV2(createSessionAgentGenerationInputsV2({
    selectedAgentImageInputDigest: sha256Digest("older-agent-image-input"),
    sessionTemplateDigest: sha256Digest("older-session-template"),
    admissionContractEpoch: target.controlPlane.admissionContractEpoch,
  }), sha256Digest("older-agent-image-id"));
  publishSessionAgentMaterializationV2(
    stateDir,
    sessionAgentMaterializationFixture({ generation }),
    TEMPLATE_ARTIFACT,
  );
  const record = sessionContainerRecordFixture({ target, generation, containerId: "a".repeat(64) });
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);
  return record;
}

function requireEffective() {
  const effective = readEffectiveControlPlaneV2(stateDir);
  if (!effective) throw new Error("fixture has no effective control plane");
  return effective;
}

function requireDesired() {
  const desired = readRetainedDesiredSessionAgentV2(stateDir);
  if (!desired) throw new Error("fixture has no desired session agent");
  return desired;
}

const STARTED_AT = "2026-08-08T12:00:05.123456789Z";

function publication(input: {
  io: RuntimeIO;
  records?: readonly SessionContainerRecordV2[];
  proxyId?: string;
  proxyStartedAt?: string;
  ignorePublicationRecord?: boolean;
}) {
  const effective = requireEffective();
  const desired = requireDesired();
  return ensureSessionEligibilityPublished({
    io: input.io,
    proxyId: input.proxyId ?? effective.selection.proxyContainerId,
    proxyStartedAt: input.proxyStartedAt ?? STARTED_AT,
    stateDir,
    effective,
    desired,
    records: input.records ?? [],
    ...(input.ignorePublicationRecord !== undefined
      ? { ignorePublicationRecord: input.ignorePublicationRecord }
      : {}),
  });
}

describe("session eligibility publication", () => {
  test("publishes one eligibility file carrying the desired and every live agent identity", () => {
    selectControlPlane();
    selectDesiredAgent();
    const record = olderAgentRecord();
    const { io, calls } = recordingIo();

    const result = publication({ io, records: [record] });

    const { selection } = requireEffective();
    expect(result.published).toBe(true);
    expect(calls).toHaveLength(1);
    const [call] = calls;
    expect(call.args.slice(0, 6))
      .toEqual(["exec", "--user", "0:0", "-i", selection.proxyContainerId, "node"]);
    expect(call.args).toContain(SESSION_ELIGIBILITY_PATH);
    const published = parseSessionAdmissionEligibility(JSON.parse(call.input ?? ""));
    if (!published) throw new Error("the published bytes are not a session admission eligibility");
    expect(published).toEqual(result.eligibility);
    expect(published.projectId).toBe(SESSION_TEST_PROJECT.projectId);
    expect(published.controlPlaneGenerationDigest).toBe(selection.controlPlaneGenerationDigest);
    expect(published.agentInternalNetworkId).toBe(selection.networkIds.agentInternal);
    expect(published.allowedSessionAgents.map((agent) => agent.sessionAgentGenerationDigest).sort())
      .toEqual([
        record.sessionAgentGenerationDigest,
        requireDesired().selection.sessionAgentGenerationDigest,
      ].sort());
    expect(readPublishedSessionEligibilityV2(stateDir)).toEqual({
      schemaVersion: 2,
      ...SESSION_TEST_PROJECT,
      proxyContainerId: selection.proxyContainerId,
      proxyStartedAt: STARTED_AT,
      eligibilitySha256: sha256Digest(serializeSessionAdmissionEligibility(published)),
    });
  });

  test("republishes only when the eligibility bytes or the proxy incarnation change", () => {
    selectControlPlane();
    selectDesiredAgent();
    const { io, calls } = recordingIo();

    expect(publication({ io }).published).toBe(true);
    expect(publication({ io }).published).toBe(false);
    expect(calls).toHaveLength(1);

    // A rolling agent upgrade leaves an older live session referencing another
    // agent identity: the widened set is different bytes, so it republishes.
    const record = olderAgentRecord();
    expect(publication({ io, records: [record] }).published).toBe(true);
    expect(publication({ io, records: [record] }).published).toBe(false);
    expect(calls).toHaveLength(2);

    // An in-place restart keeps the container id and recreates the session-file
    // directory empty, taking eligibility.json with it. Only the start time
    // tells the two incarnations apart, so identical bytes must publish again.
    const restarted = "2026-08-08T13:30:00.000000000Z";
    expect(publication({ io, records: [record], proxyStartedAt: restarted }).published).toBe(true);
    expect(publication({ io, records: [record], proxyStartedAt: restarted }).published).toBe(false);
    expect(calls).toHaveLength(3);
    expect(readPublishedSessionEligibilityV2(stateDir)?.proxyStartedAt).toBe(restarted);
  });

  test("publishes unconditionally when the caller knows the proxy file tree was recreated", () => {
    selectControlPlane();
    selectDesiredAgent();
    const { io, calls } = recordingIo();

    expect(publication({ io }).published).toBe(true);
    expect(publication({ io, ignorePublicationRecord: true }).published).toBe(true);
    expect(publication({ io, ignorePublicationRecord: true }).published).toBe(true);
    expect(calls).toHaveLength(3);
  });

  test("refuses to publish into a proxy the selected control plane does not name", () => {
    selectControlPlane();
    selectDesiredAgent();
    const { io, calls } = recordingIo();

    expect(() => publication({ io, proxyId: "b".repeat(64) }))
      .toThrow(/selected control plane/);
    expect(calls).toEqual([]);
    expect(readPublishedSessionEligibilityV2(stateDir)).toBeUndefined();
  });

  test("leaves no publication record when the sealed write is refused", () => {
    selectControlPlane();
    selectDesiredAgent();
    const { io, calls } = recordingIo(1);

    expect(() => publication({ io })).toThrow();
    expect(calls).toHaveLength(1);
    expect(readPublishedSessionEligibilityV2(stateDir)).toBeUndefined();
  });
});
