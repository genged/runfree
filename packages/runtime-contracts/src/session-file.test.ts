import { describe, expect, test } from "vitest";

import { createSessionAdmissionEligibility, type SessionAdmissionEligibility } from "./session-admission.ts";
import {
  isSessionFileEligible,
  mintSessionFileNonce,
  parseSessionFileV1,
  serializeSessionFileV1,
  sessionFilePath,
  SESSION_FILE_MAX_BYTES,
  type SessionFileV1,
} from "./session-file.ts";

const SESSION_KEY = "5".repeat(64);

const base: SessionFileV1 = {
  v: 1 as const,
  projectId: "abcdef012345",
  sessionKey: SESSION_KEY,
  sessionId: "rf-20260907-abc123",
  sessionIncarnation: "1".repeat(64),
  sourceIp: "172.30.194.20",
  containerId: "c".repeat(64),
  networkId: "e".repeat(64),
  selectedAgentImageId: `sha256:${"a".repeat(64)}`,
  sessionAgentGenerationDigest: `sha256:${"b".repeat(64)}`,
  controlPlaneGenerationDigest: `sha256:${"d".repeat(64)}`,
  admissionContractEpoch: 3,
  name: "claude",
  command: "claude",
  startedAt: "2026-09-07T07:00:00.000Z",
  nonce: "0".repeat(32),
  inspectedAt: "2026-09-07T07:00:03.090Z",
  aliveUntil: "2026-09-07T07:05:03.090Z",
};

function eligibilityForBase(overrides: Partial<{
  selectedAgentImageId: string;
  sessionAgentGenerationDigest: string;
}> = {}): SessionAdmissionEligibility {
  return createSessionAdmissionEligibility({
    projectId: base.projectId,
    controlPlaneGenerationDigest: base.controlPlaneGenerationDigest,
    admissionContractEpoch: base.admissionContractEpoch,
    agentInternalNetworkId: base.networkId,
    allowedSessionAgents: [{
      selectedAgentImageId: overrides.selectedAgentImageId ?? base.selectedAgentImageId,
      sessionAgentGenerationDigest: overrides.sessionAgentGenerationDigest ?? base.sessionAgentGenerationDigest,
    }],
  });
}

describe("session file contract", () => {
  test("round-trips a valid file", () => {
    expect(parseSessionFileV1(serializeSessionFileV1(base), SESSION_KEY)).toEqual(base);
  });

  test("refuses a file whose name does not match its embedded key", () => {
    expect(parseSessionFileV1(serializeSessionFileV1(base), "6".repeat(64))).toBeUndefined();
  });

  test("refuses aliveUntil more than the lease maximum after inspectedAt", () => {
    expect(parseSessionFileV1(
      serializeSessionFileV1({ ...base, aliveUntil: "2026-09-07T07:05:03.091Z" }),
      SESSION_KEY,
    )).toBeUndefined();
  });

  test("refuses aliveUntil not after inspectedAt, unknown keys, bad nonce, and oversize input", () => {
    expect(parseSessionFileV1(
      serializeSessionFileV1({ ...base, aliveUntil: base.inspectedAt }),
      SESSION_KEY,
    )).toBeUndefined();
    expect(parseSessionFileV1(serializeSessionFileV1(base).replace("}\n", ',"extra":1}\n'), SESSION_KEY)).toBeUndefined();
    expect(parseSessionFileV1(serializeSessionFileV1({ ...base, nonce: "zz" }), SESSION_KEY)).toBeUndefined();
    expect(parseSessionFileV1(" ".repeat(SESSION_FILE_MAX_BYTES + 1), SESSION_KEY)).toBeUndefined();
  });

  test("nonce is 32 lowercase hex and path is confined to the sessions dir", () => {
    expect(mintSessionFileNonce()).toMatch(/^[a-f0-9]{32}$/);
    expect(sessionFilePath(SESSION_KEY)).toBe(`/run/runfree-sessions/sessions/${SESSION_KEY}.json`);
    expect(() => sessionFilePath("../x")).toThrow();
    expect(() => sessionFilePath("sk-1")).toThrow();
    expect(() => sessionFilePath("a".repeat(63))).toThrow();
  });

  test("refuses an over-long name and a name containing a control character", () => {
    expect(parseSessionFileV1(serializeSessionFileV1({ ...base, name: "x".repeat(81) }), SESSION_KEY)).toBeUndefined();
    expect(parseSessionFileV1(serializeSessionFileV1({ ...base, name: "badname" }), SESSION_KEY)).toBeUndefined();
  });

  test("refuses a projectId, sessionId, or sessionIncarnation that violates the registry's field shape", () => {
    expect(parseSessionFileV1(serializeSessionFileV1({ ...base, projectId: "bad id!" }), SESSION_KEY)).toBeUndefined();
    expect(parseSessionFileV1(serializeSessionFileV1({ ...base, sessionId: "not-an-rf-id" }), SESSION_KEY)).toBeUndefined();
    expect(parseSessionFileV1(serializeSessionFileV1({ ...base, sessionIncarnation: "zz" }), SESSION_KEY)).toBeUndefined();
  });

  test("refuses a source IP with an out-of-range or non-canonical octet", () => {
    expect(parseSessionFileV1(serializeSessionFileV1({ ...base, sourceIp: "999.1.1.1" }), SESSION_KEY)).toBeUndefined();
    expect(parseSessionFileV1(serializeSessionFileV1({ ...base, sourceIp: "192.168.001.001" }), SESSION_KEY)).toBeUndefined();
  });

  test("refuses an admissionContractEpoch below the registry's minimum", () => {
    expect(parseSessionFileV1(serializeSessionFileV1({ ...base, admissionContractEpoch: 0 }), SESSION_KEY)).toBeUndefined();
  });

  test("eligibility requires a matching agent generation digest", () => {
    const eligibility = eligibilityForBase();
    expect(isSessionFileEligible(base, eligibility)).toBe(true);
    const mismatched = eligibilityForBase({ sessionAgentGenerationDigest: `sha256:${"9".repeat(64)}` });
    expect(isSessionFileEligible(base, mismatched)).toBe(false);
  });
});
