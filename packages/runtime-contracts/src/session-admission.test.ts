import { describe, expect, test } from "vitest";

import {
  createSessionAdmissionEligibility,
  parseSessionAdmissionEligibility,
  SESSION_ADMISSION_PROVISIONING_REQUEST,
  serializeSessionAdmissionEligibility,
} from "./session-admission.js";

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}

function currentEligibility() {
  return createSessionAdmissionEligibility({
    projectId: "0123456789ab",
    controlPlaneGenerationDigest: digest("7"),
    admissionContractEpoch: 1,
    agentInternalNetworkId: "4".repeat(64),
    allowedSessionAgents: [{
      sessionAgentGenerationDigest: digest("6"),
      selectedAgentImageId: digest("5"),
    }],
  });
}

describe("session admission eligibility", () => {
  test("canonicalizes the current control-plane eligibility", () => {
    const eligibility = createSessionAdmissionEligibility({
      projectId: "0123456789ab",
      controlPlaneGenerationDigest: digest("7"),
      admissionContractEpoch: 1,
      agentInternalNetworkId: "4".repeat(64),
      allowedSessionAgents: [
        {
          sessionAgentGenerationDigest: digest("9"),
          selectedAgentImageId: digest("b"),
        },
        {
          sessionAgentGenerationDigest: digest("6"),
          selectedAgentImageId: digest("5"),
        },
      ],
    });
    expect(eligibility.allowedSessionAgents).toEqual([
      {
        sessionAgentGenerationDigest: digest("6"),
        selectedAgentImageId: digest("5"),
      },
      {
        sessionAgentGenerationDigest: digest("9"),
        selectedAgentImageId: digest("b"),
      },
    ]);
    expect(parseSessionAdmissionEligibility(
      JSON.parse(serializeSessionAdmissionEligibility(eligibility)),
    )).toEqual(eligibility);
  });

  test("eligibility rejects duplicate pairs and noncanonical or malformed authority", () => {
    const input = {
      projectId: "0123456789ab",
      controlPlaneGenerationDigest: digest("7"),
      admissionContractEpoch: 1,
      agentInternalNetworkId: "4".repeat(64),
      allowedSessionAgents: [
        {
          sessionAgentGenerationDigest: digest("6"),
          selectedAgentImageId: digest("5"),
        },
        {
          sessionAgentGenerationDigest: digest("6"),
          selectedAgentImageId: digest("5"),
        },
      ],
    };
    expect(() => createSessionAdmissionEligibility(input)).toThrow("repeats");
    expect(parseSessionAdmissionEligibility({
      ...input,
      v: 2,
      allowedSessionAgents: [
        {
          sessionAgentGenerationDigest: digest("9"),
          selectedAgentImageId: digest("b"),
        },
        {
          sessionAgentGenerationDigest: digest("6"),
          selectedAgentImageId: digest("5"),
        },
      ],
    })).toBeUndefined();
    expect(parseSessionAdmissionEligibility({ ...input, v: 2, unexpected: true })).toBeUndefined();
    expect(parseSessionAdmissionEligibility({ ...input, v: 2, admissionContractEpoch: 0 })).toBeUndefined();
    expect(parseSessionAdmissionEligibility({
      ...currentEligibility(),
      allowedSessionAgents: [{
        sessionAgentGenerationDigest: digest("6"),
        selectedAgentImageId: digest("5"),
        finalizedSessionImageId: digest("a"),
      }],
    })).toBeUndefined();
    expect(createSessionAdmissionEligibility({ ...input, allowedSessionAgents: [] }).allowedSessionAgents).toEqual([]);
  });

  test("the readiness request bytes are exactly the contract", () => {
    expect(SESSION_ADMISSION_PROVISIONING_REQUEST).toBe([
      "GET http://runfree-provisioning.invalid/.well-known/runfree/session-ready HTTP/1.1",
      "Host: runfree-provisioning.invalid",
      "Connection: close",
      "",
      "",
    ].join("\r\n"));
  });
});
