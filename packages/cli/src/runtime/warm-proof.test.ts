import { expect, test } from "vitest";

import { proxyNftablesTableJson } from "../proxy-nftables-proof.fixture.ts";
import { parseDockerDaemonIdentity } from "./docker.ts";
import { assertWarmValidation, nftRulesetShapeSha256 } from "./warm-proof.ts";

function withSessionMembers(raw: string, members: readonly string[]): string {
  const parsed = JSON.parse(raw) as { nftables: Array<Record<string, unknown>> };
  return JSON.stringify({
    nftables: parsed.nftables.map((statement) => {
      const set = statement.set as Record<string, unknown> | undefined;
      return set && set.name === "session_ipv4" ? { set: { ...set, elem: [...members] } } : statement;
    }),
  });
}

test("the ruleset shape ignores set members and nothing else", () => {
  const base = proxyNftablesTableJson();
  const shape = nftRulesetShapeSha256(base);
  expect(shape).toMatch(/^sha256:[a-f0-9]{64}$/);
  // Sessions come and go: members change, the enforcement shape does not.
  expect(nftRulesetShapeSha256(withSessionMembers(base, ["172.31.90.20", "172.31.90.21"]))).toBe(shape);
  // A rule change is a shape change.
  const parsed = JSON.parse(base) as { nftables: unknown[] };
  const added = JSON.stringify({ nftables: [...parsed.nftables, { rule: { family: "inet", table: "runfree_proxy", chain: "input", expr: [{ accept: null }] } }] });
  expect(nftRulesetShapeSha256(added)).not.toBe(shape);
  expect(nftRulesetShapeSha256("{not json")).toBeUndefined();
  expect(nftRulesetShapeSha256(JSON.stringify({ tables: [] }))).toBeUndefined();
});

test("the daemon identity parses only a complete docker info JSON", () => {
  const info = { ID: "abc", ServerVersion: "29.0.0", KernelVersion: "6.10.14-linuxkit", LiveRestoreEnabled: false };
  expect(parseDockerDaemonIdentity(JSON.stringify(info))).toEqual({
    id: "abc",
    serverVersion: "29.0.0",
    kernelVersion: "6.10.14-linuxkit",
    liveRestoreEnabled: false,
  });
  expect(parseDockerDaemonIdentity(JSON.stringify({ ...info, LiveRestoreEnabled: true }))?.liveRestoreEnabled).toBe(true);
  for (const broken of [
    "Client:\n Version: 29",
    JSON.stringify({ ...info, ID: "" }),
    JSON.stringify({ ...info, ServerVersion: undefined }),
    JSON.stringify({ ...info, LiveRestoreEnabled: "no" }),
    JSON.stringify([info]),
  ]) {
    expect(parseDockerDaemonIdentity(broken)).toBeUndefined();
  }
});

test("a warm validation cannot be built by hand", () => {
  expect(() => assertWarmValidation({ runtimeProof: {}, proxyStartedAt: "2026-06-13T00:00:00.000Z" })).toThrow(
    "warm validation was not minted by the warm-proof comparison",
  );
});
