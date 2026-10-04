import { describe, expect, test } from "vitest";

import { parseGenerationStatusLine, parseHostServiceGatewayStatus, serializeGenerationStatus } from "./proxy-status.ts";

describe("request-proxy generation status", () => {
  test("carries the OAuth state epoch capability through the one-line framing", () => {
    const line = serializeGenerationStatus({
      generation: "g1",
      controlGeneration: "c1",
      policyGeneration: "g1",
      appliedAt: "2026-09-30T00:00:00.000Z",
      oauthStateEpochs: 1,
    }).trim();
    expect(parseGenerationStatusLine(line)).toEqual({
      generation: "g1",
      controlGeneration: "c1",
      policyGeneration: "g1",
      oauthStateEpochs: true,
    });
  });

  test.each([
    ["absent", {}],
    ["true instead of 1", { oauthStateEpochs: true }],
    ["another version", { oauthStateEpochs: 2 }],
  ])("does not claim the capability when the marker is %s", (_label, marker) => {
    const parsed = parseGenerationStatusLine(JSON.stringify({ generation: "g1", ...marker }));
    expect(parsed?.oauthStateEpochs).toBeUndefined();
  });
});

describe("host-service gateway status", () => {
  const valid = {
    schemaVersion: 1,
    policyGeneration: `sha256:${"a".repeat(64)}`,
    gatewayIp: "192.168.65.254",
    writtenAt: "2026-10-04T00:00:00.000Z",
  };

  test("parses a valid available file", () => {
    expect(parseHostServiceGatewayStatus(JSON.stringify(valid))).toEqual(valid);
  });

  test("parses a valid unavailable file", () => {
    const { gatewayIp: _gatewayIp, ...rest } = valid;
    const unavailable = { ...rest, unavailableReason: "gateway address changed; run runfree rebuild" };
    expect(parseHostServiceGatewayStatus(JSON.stringify(unavailable))).toEqual(unavailable);
  });

  test("refuses an unknown key", () => {
    expect(() => parseHostServiceGatewayStatus(JSON.stringify({ ...valid, extra: true }))).toThrow(/extra/);
  });

  test("refuses both gatewayIp and unavailableReason", () => {
    expect(() => parseHostServiceGatewayStatus(JSON.stringify({ ...valid, unavailableReason: "x" }))).toThrow(/exactly one/);
  });

  test("refuses neither gatewayIp nor unavailableReason", () => {
    const { gatewayIp: _gatewayIp, ...rest } = valid;
    expect(() => parseHostServiceGatewayStatus(JSON.stringify(rest))).toThrow(/exactly one/);
  });

  test.each([
    ["a hostname", "gateway.runfree.internal"],
    ["an IPv6 address", "fdc4:f303:9324::254"],
    ["a leading zero", "192.168.065.254"],
    ["an octet over 255", "192.168.65.256"],
    ["three octets", "192.168.65"],
    ["surrounding space", " 192.168.65.254"],
    ["a number", 3232252414],
  ])("refuses a gatewayIp that is %s", (_label, gatewayIp) => {
    expect(() => parseHostServiceGatewayStatus(JSON.stringify({ ...valid, gatewayIp }))).toThrow(/gatewayIp/);
  });

  test.each([
    ["another schema version", { schemaVersion: 2 }],
    ["an empty policy generation", { policyGeneration: "" }],
    ["a non-string writtenAt", { writtenAt: 5 }],
    ["an empty unavailableReason", { gatewayIp: undefined, unavailableReason: "" }],
  ])("refuses %s", (_label, override) => {
    expect(() => parseHostServiceGatewayStatus(JSON.stringify({ ...valid, ...override }))).toThrow();
  });

  test("refuses non-JSON and non-object input", () => {
    expect(() => parseHostServiceGatewayStatus("not json")).toThrow();
    expect(() => parseHostServiceGatewayStatus("[]")).toThrow();
    expect(() => parseHostServiceGatewayStatus("null")).toThrow();
  });
});

describe("host-service status fields", () => {
  test("carries the firewall host-service set digest and draining count", () => {
    const line = serializeGenerationStatus({
      generation: "g1",
      rulesetVerified: true,
      appliedAt: "2026-10-04T00:00:00.000Z",
      hostServiceSetDigest: "sha256:abc",
      hostServiceDraining: 2,
    }).trim();
    expect(parseGenerationStatusLine(line)).toEqual({
      generation: "g1",
      rulesetVerified: true,
      hostServiceSetDigest: "sha256:abc",
      hostServiceDraining: 2,
    });
  });

  test("carries the request-proxy live splice counts", () => {
    const line = serializeGenerationStatus({
      generation: "g1",
      appliedAt: "2026-10-04T00:00:00.000Z",
      hostServiceSplices: { echo: 2, idb: 1 },
    }).trim();
    expect(parseGenerationStatusLine(line)?.hostServiceSplices).toEqual({ echo: 2, idb: 1 });
  });

  test("carries an empty splice map", () => {
    const parsed = parseGenerationStatusLine(JSON.stringify({ generation: "g1", hostServiceSplices: {} }));
    expect(parsed?.hostServiceSplices).toEqual({});
  });

  test.each([
    ["an empty digest", { hostServiceSetDigest: "" }],
    ["a negative draining count", { hostServiceDraining: -1 }],
    ["a fractional draining count", { hostServiceDraining: 1.5 }],
    ["splices that are not an object", { hostServiceSplices: [1] }],
    ["a splice count that is not an integer", { hostServiceSplices: { echo: "1" } }],
    ["a splice name that is not a host-service name", { hostServiceSplices: { "Bad Name": 1 } }],
  ])("drops %s", (_label, field) => {
    const parsed = parseGenerationStatusLine(JSON.stringify({ generation: "g1", ...field }));
    expect(parsed).toEqual({ generation: "g1" });
  });
});
