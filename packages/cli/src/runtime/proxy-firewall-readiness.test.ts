import { expect, test, vi } from "vitest";
import { waitForProxyFirewallReadiness } from "./proxy-firewall-readiness.ts";
import { RuntimeObservationError } from "./observation-failure.ts";

const proxyId = "a".repeat(64);
const effectivePolicyGeneration = `sha256:${"b".repeat(64)}`;
const startedAt = "2026-09-05T12:00:00.000Z";
const ready = {
  generation: `sha256:${"c".repeat(64)}`, policyGeneration: `sha256:${"c".repeat(64)}`,
  controlGeneration: effectivePolicyGeneration, rulesetVerified: true, appliedAt: startedAt,
};

test.each(["missing", "malformed", "stale", "wrong-generation", "unverified", "wrong-container"])("refuses %s readiness within a fixed budget, then permits a fresh retry", async (failure) => {
  let clock = 0;
  let repaired = false;
  const capture = vi.fn((_command: string, args: string[]) => {
    expect(args).toContain(proxyId);
    if (args[0] === "container") return { status: 0, stdout: JSON.stringify([{
      Id: !repaired && failure === "wrong-container" ? "d".repeat(64) : proxyId,
      State: { Running: true, StartedAt: startedAt },
    }]), stderr: "" };
    const status = { ...ready };
    if (!repaired && failure === "stale") status.appliedAt = "2026-09-05T11:59:59.000Z";
    if (!repaired && failure === "wrong-generation") status.controlGeneration = `sha256:${"d".repeat(64)}`;
    if (!repaired && failure === "unverified") status.rulesetVerified = false;
    return { status: !repaired && failure === "missing" ? 1 : 0,
      stdout: !repaired && failure === "malformed" ? "{" : JSON.stringify(status), stderr: "" };
  });
  const args = {
    io: { capture }, proxyId, effectivePolicyGeneration, dockerEnv: {},
    nowMs: () => clock, delay: async (ms: number) => { clock += ms; },
  };
  await expect(waitForProxyFirewallReadiness(args)).rejects.toBeInstanceOf(RuntimeObservationError);
  expect(clock).toBe(10_000);
  expect(capture.mock.calls.length).toBeLessThanOrEqual(200);
  repaired = true;
  await expect(waitForProxyFirewallReadiness(args)).resolves.toBeUndefined();
  expect(capture.mock.calls.flatMap(([, argv]) => argv)).not.toContain("nft");
});

test("readiness inspects the proxy under the shared 64 KiB bound", async () => {
  const capture = vi.fn((_command: string, args: string[], _options?: { maxBuffer?: number }) => {
    if (args[0] === "container") {
      // A realistic Compose-labelled inspect is well past 8 KiB.
      const labels = Object.fromEntries(Array.from({ length: 200 }, (_, index) => [`com.example.label-${index}`, "x".repeat(40)]));
      return { status: 0, stdout: JSON.stringify([{ Id: proxyId, State: { Running: true, StartedAt: startedAt }, Config: { Labels: labels } }]), stderr: "" };
    }
    return { status: 0, stdout: JSON.stringify(ready), stderr: "" };
  });
  await expect(waitForProxyFirewallReadiness({ io: { capture }, proxyId, effectivePolicyGeneration, dockerEnv: {} })).resolves.toBeUndefined();
  expect(capture.mock.calls[0][2]?.maxBuffer).toBe(64 * 1024);
  expect(capture.mock.calls[0][1]).not.toContain("--format");
});

test("a lost fence stops polling before further Docker calls", async () => {
  let held = true;
  const capture = vi.fn(() => {
    held = false;
    return { status: 0, stdout: "[]", stderr: "" };
  });
  await expect(waitForProxyFirewallReadiness({
    io: { capture }, proxyId, effectivePolicyGeneration, dockerEnv: {},
    assertAuthority: () => { if (!held) throw new Error("fence lost"); },
  })).rejects.toThrow("fence lost");
  expect(capture).toHaveBeenCalledOnce();
});
