import { performance } from "node:perf_hooks";
import { firewallStatusPath, parseGenerationStatusLine } from "@runfree/runtime-contracts/proxy-status";
import type { RuntimeIO } from "./types.ts";
import { RuntimeObservationError } from "./observation-failure.ts";

const READY_TIMEOUT_MS = 10_000;
const POLL_MS = 100;

/** Status closes the startup race; callers must still validate the live table. */
export async function waitForProxyFirewallReadiness(input: {
  io: Pick<RuntimeIO, "capture">;
  proxyId: string;
  effectivePolicyGeneration: string;
  dockerEnv: NodeJS.ProcessEnv;
  assertAuthority?: () => void;
  nowMs?: () => number;
  delay?: (ms: number) => Promise<void>;
}): Promise<void> {
  if (!/^[a-f0-9]{64}$/.test(input.proxyId) || !/^sha256:[a-f0-9]{64}$/.test(input.effectivePolicyGeneration)) {
    throw new Error("firewall readiness requires exact proxy and effective policy generation identities");
  }
  const now = input.nowMs ?? (() => performance.now());
  const delay = input.delay ?? ((ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const deadline = now() + READY_TIMEOUT_MS;
  let lastObservation = "no readable status";
  while (now() < deadline) {
    input.assertAuthority?.();
    const options = { env: input.dockerEnv, shell: false as const, timeout: Math.max(1, Math.min(1000, deadline - now())), maxBuffer: 8192 };
    const inspection = input.io.capture("docker", ["container", "inspect", input.proxyId], options);
    input.assertAuthority?.();
    let startedAt: string | undefined;
    try {
      const inspected: unknown = JSON.parse(inspection.stdout);
      if (inspection.status === 0 && Array.isArray(inspected) && inspected.length === 1
        && inspected[0]?.Id === input.proxyId && inspected[0]?.State?.Running === true
        && typeof inspected[0]?.State?.StartedAt === "string") startedAt = inspected[0].State.StartedAt;
    } catch { /* Missing observation cannot establish readiness. */ }
    if (!startedAt || !Number.isFinite(Date.parse(startedAt))) {
      lastObservation = "exact running proxy start time is unavailable";
    } else if (now() < deadline) {
      const status = input.io.capture("docker", ["exec", "--user", "0:0", input.proxyId, "cat", firewallStatusPath()], {
        ...options, timeout: Math.max(1, Math.min(1000, deadline - now())),
      });
      input.assertAuthority?.();
      let appliedAt: unknown;
      try { appliedAt = (JSON.parse(status.stdout) as { appliedAt?: unknown }).appliedAt; } catch { /* Refuse below. */ }
      const parsed = parseGenerationStatusLine(status.stdout);
      if (status.status === 0 && parsed?.rulesetVerified === true
        && parsed.controlGeneration === input.effectivePolicyGeneration
        && typeof appliedAt === "string" && Number.isFinite(Date.parse(appliedAt))
        && Date.parse(appliedAt) >= Date.parse(startedAt) && now() < deadline) return;
      lastObservation = "firewall status is missing, stale, malformed, unverified, or names another effective policy generation";
    }
    if (now() < deadline) await delay(Math.min(POLL_MS, deadline - now()));
  }
  throw new RuntimeObservationError({
    kind: "observation-unavailable", subject: "proxy", expectedIdentity: input.proxyId,
    phase: "firewall-readiness", observation: `${lastObservation}; readiness timed out after ${READY_TIMEOUT_MS}ms; retry after inspecting the proxy`,
  });
}
