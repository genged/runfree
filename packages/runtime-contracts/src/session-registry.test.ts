import { describe, expect, test } from "vitest";

import {
  SESSION_DISPLAY_NAME_MAX_CHARACTERS,
  isExactSessionSourceIpv4,
  parsePendingApprovalSession,
  pendingApprovalSession,
  proxySessionStableIdentity,
  sameProxySessionStableIdentity,
} from "./session-registry.ts";

const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;
const KEY = "c".repeat(64);

type StableIdentity = {
  sessionKey: string;
  sessionIncarnation: string;
  containerId: string;
  sourceIp: string;
  networkId: string;
  selectedAgentImageId: string;
  sessionAgentGenerationDigest: string;
  controlPlaneGenerationDigest: string;
  admissionContractEpoch: number;
};

function session(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sessionId: "rf-20260805-abcdef",
    name: "payments refactor",
    command: "codex",
    agentCommand: "codex --resume",
    hostTty: "/dev/ttys004",
    hostTermProgram: "iTerm.app",
    startedAt: "2026-08-05T12:00:00.000Z",
    ...overrides,
  };
}

function identity(overrides: Partial<StableIdentity> = {}): StableIdentity {
  return {
    sessionKey: KEY,
    sessionIncarnation: "d".repeat(64),
    containerId: "e".repeat(64),
    sourceIp: "172.30.0.21",
    networkId: "f".repeat(64),
    selectedAgentImageId: DIGEST_A,
    sessionAgentGenerationDigest: DIGEST_A,
    controlPlaneGenerationDigest: DIGEST_B,
    admissionContractEpoch: 1,
    ...overrides,
  };
}

describe("proxy session identity contract", () => {
  test("projects only display metadata, never the session key", () => {
    const parsed = parsePendingApprovalSession(session());
    expect(parsed).toBeDefined();
    if (!parsed) throw new Error("expected a valid pending approval session");
    expect(pendingApprovalSession(parsed)).toEqual({
      sessionId: "rf-20260805-abcdef",
      name: "payments refactor",
      command: "codex",
      agentCommand: "codex --resume",
      hostTty: "/dev/ttys004",
      hostTermProgram: "iTerm.app",
      startedAt: "2026-08-05T12:00:00.000Z",
    });
    expect(pendingApprovalSession(parsed)).not.toHaveProperty("sessionKey");
  });

  test("rejects malformed identity, display, and unknown fields", () => {
    const malformed = [
      session({ sessionId: "../escape" }),
      session({ name: "" }),
      session({ name: " padded " }),
      session({ name: `bad${String.fromCharCode(0x0a)}name` }),
      session({ name: "x".repeat(SESSION_DISPLAY_NAME_MAX_CHARACTERS + 1) }),
      session({ command: `bad${String.fromCharCode(0x00)}command` }),
      session({ command: "" }),
      session({ agentCommand: `bad${String.fromCharCode(0x1b)}command` }),
      session({ hostTty: "x".repeat(129) }),
      session({ startedAt: "yesterday" }),
      session({ unexpected: true }),
    ];
    for (const value of malformed) {
      expect(parsePendingApprovalSession(value), JSON.stringify(value)).toBeUndefined();
    }
  });

  test("requires canonical exact IPv4 text", () => {
    expect(isExactSessionSourceIpv4("172.30.0.21")).toBe(true);
    expect(isExactSessionSourceIpv4("172.30.0.021")).toBe(false);
    expect(isExactSessionSourceIpv4("172.30.0.21 ")).toBe(false);
    expect(isExactSessionSourceIpv4("::ffff:172.30.0.21")).toBe(false);
  });

  test("stable identity changes when any exact runtime field does", () => {
    const base = identity();
    expect(sameProxySessionStableIdentity(base, identity())).toBe(true);
    for (const field of Object.keys(base) as Array<keyof StableIdentity>) {
      const current = base[field];
      const changed = identity({
        [field]: typeof current === "number" ? current + 1 : `${current}0`,
      } as Partial<StableIdentity>);
      expect(sameProxySessionStableIdentity(base, changed), field).toBe(false);
    }
    // Field-separated, so no reshuffling of adjacent values collides.
    expect(proxySessionStableIdentity(base).split(String.fromCharCode(0))).toHaveLength(Object.keys(base).length);
  });
});
