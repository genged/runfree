import { describe, expect, test } from "vitest";

import { AdmissionRegistry } from "./admission.ts";

describe("proxy admission registry", () => {
  test("requires an observed physical connection before resolving a request", () => {
    const registry = new AdmissionRegistry();
    const record = registry.mint("API.EXAMPLE.COM", "sha256:policy-a");

    expect(record.host).toBe("api.example.com");
    expect(registry.resolveRequest(40_001, record.connectionSerial)).toBeUndefined();

    registry.bind(40_001, record);
    expect(registry.resolveRequest(40_001, undefined)).toBeUndefined();
    expect(registry.observeTls(40_001, "api.example.com")).toMatchObject({
      kind: "admitted",
      record: { connectionSerial: record.connectionSerial, stage: "sni" },
    });
    expect(registry.resolveRequest(40_001, record.connectionSerial)).toMatchObject({
      connectionSerial: record.connectionSerial,
      stage: "request",
    });
  });

  test("carries a guard-authenticated session across SNI to the decrypted request", () => {
    const registry = new AdmissionRegistry();
    const principal = {
      kind: "session" as const,
      authenticated: true as const,
      sessionKey: "a".repeat(64),
      sessionId: "rf-20260805-aaaaaa",
      name: "payments",
      command: "codex",
      startedAt: "2026-08-05T12:00:00.000Z",
    };
    const record = registry.mint("api.example.com", "sha256:policy", { sourceIp: "172.30.0.21", principal });
    registry.bind(40_010, record);
    expect(registry.observeTls(40_010, "api.example.com")).toMatchObject({ kind: "admitted" });
    expect(registry.resolveRequest(40_010, record.connectionSerial)).toMatchObject({
      sourceIp: "172.30.0.21",
      principal,
      stage: "request",
    });
  });

  test("SNI may narrow but never replace the admitted host", () => {
    const registry = new AdmissionRegistry();
    const record = registry.mint("api.example.com", "sha256:policy-a");
    registry.bind(40_002, record);

    expect(registry.observeTls(40_002, undefined)).toMatchObject({ kind: "admitted" });

    const second = registry.mint("api.example.com", "sha256:policy-a");
    registry.bind(40_003, second);
    expect(registry.observeTls(40_003, "other.example.com")).toMatchObject({
      kind: "host-mismatch",
      observedHost: "other.example.com",
    });
    expect(registry.resolveRequest(40_003, second.connectionSerial)).toBeUndefined();
  });

  test("port reuse cannot inherit an old serial and a late close cannot delete the replacement", () => {
    const registry = new AdmissionRegistry();
    const first = registry.mint("first.example.com", "sha256:policy-a");
    registry.bind(40_004, first);
    registry.observeTls(40_004, "first.example.com");
    expect(registry.resolveRequest(40_004, first.connectionSerial)?.host).toBe("first.example.com");

    const second = registry.mint("second.example.com", "sha256:policy-b");
    registry.bind(40_004, second);
    expect(registry.resolveRequest(40_004, first.connectionSerial)).toBeUndefined();

    registry.release(40_004, first.connectionSerial);
    expect(registry.size()).toBe(1);
    expect(registry.observeTls(40_004, "second.example.com")).toMatchObject({ kind: "admitted" });
    expect(registry.resolveRequest(40_004, second.connectionSerial)?.host).toBe("second.example.com");
  });

  test("dropping a live record makes every later request fail closed", () => {
    const registry = new AdmissionRegistry();
    const record = registry.mint("api.example.com", "sha256:policy-a");
    registry.bind(40_005, record);
    registry.observeTls(40_005, "api.example.com");
    expect(registry.resolveRequest(40_005, record.connectionSerial)).toBeDefined();

    registry.release(40_005, record.connectionSerial);
    expect(registry.resolveRequest(40_005, record.connectionSerial)).toBeUndefined();
  });

  test("revokes every live admission bound to one authenticated session", () => {
    const registry = new AdmissionRegistry();
    const sessionBinding = {
      sessionKey: "a".repeat(64),
      sessionIncarnation: "b".repeat(64),
      containerId: "c".repeat(64),
      sourceIp: "172.30.0.20",
      networkId: "d".repeat(64),
      selectedAgentImageId: `sha256:${"e".repeat(64)}`,
      sessionAgentGenerationDigest: `sha256:${"f".repeat(64)}`,
      controlPlaneGenerationDigest: `sha256:${"1".repeat(64)}`,
      admissionContractEpoch: 1,
    };
    const session = registry.mint("api.example.com", "sha256:policy", { sessionBinding });
    const other = registry.mint("api.example.com", "sha256:policy");
    registry.bind(40_006, session);
    registry.bind(40_007, other);

    expect(registry.revokeSession(sessionBinding.sessionKey)).toBe(1);
    expect(registry.size()).toBe(1);
    expect(registry.observeTls(40_006, "api.example.com")).toEqual({ kind: "missing" });
    expect(registry.observeTls(40_007, "api.example.com")).toMatchObject({ kind: "admitted" });
  });
});
