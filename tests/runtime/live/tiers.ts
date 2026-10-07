// Live runtime tiers: which live proofs run on every security-relevant change
// (core) and which run only in the full release gate (extended).
//
// Core proves the trust boundary itself (docs/security.md "Core Rules"): the
// network shape and capability floor, egress containment, request shape and
// write approval, inert agent policy edits and live revocation, managed-launch
// host-file safety, exact per-session admission, the approved host-service
// path and its refusals, that the warm launch path never skips what a
// changed runtime needs, and that the pinned claude/pi binaries still accept
// and refuse `--session-id` the way the launch and resume paths assume.
// Extended proves
// availability, recovery, and optional features: crash recovery, rolling
// upgrades and proxy replacement, renewal under load, the session-entry start
// ordering, helper cleanup, and audit mode.
//
// A file is core by listing it here; every other live file is extended, so a
// new live file can never drop out of both tiers. A mixed file splits its
// cases with `liveTierTest` and appears in `MIXED_LIVE_FILES`.
//
// Data only: `vitest.config.ts` imports this, so it must not import vitest.

export const LIVE_TIERS = ["core", "extended", "all"] as const;
export type LiveTier = typeof LIVE_TIERS[number];

export const LIVE_TIER_ENV = "TEST_RUNTIME_TIER";

/** Files whose every case is core. */
export const CORE_LIVE_FILES = [
  "tests/runtime/live/agent-session-id-contract.live.test.ts",
  "tests/runtime/live/runtime-topology.live.test.ts",
  "tests/runtime/live/request-shape.live.test.ts",
  "tests/runtime/live/allowlist-lifecycle.live.test.ts",
  "tests/runtime/live/live-policy-mutation.live.test.ts",
  "tests/runtime/live/managed-launch.live.test.ts",
  "tests/runtime/live/mcp-enable.live.test.ts",
  "tests/runtime/live/session-admission-negative.live.test.ts",
  "tests/runtime/live/session-admission-drift.live.test.ts",
  "tests/runtime/live/host-service.live.test.ts",
] as const;

/** Files that hold cases of both tiers, split per case with `liveTierTest`. */
export const MIXED_LIVE_FILES = [
  "tests/runtime/live/session-admission-attached.live.test.ts",
  "tests/runtime/live/session-admission-crash.live.test.ts",
  "tests/runtime/live/ingress-forwarder.live.test.ts",
  "tests/runtime/live/launch-latency.live.test.ts",
] as const;

/**
 * The selected tier. Refused rather than defaulted when malformed: a typo
 * that silently ran every tier would put the host under the load the tier
 * was meant to avoid.
 */
export function selectedLiveTier(env: NodeJS.ProcessEnv = process.env): LiveTier {
  const value = env[LIVE_TIER_ENV];
  if (value === undefined || value === "") return "all";
  if (!(LIVE_TIERS as readonly string[]).includes(value)) {
    throw new Error(`${LIVE_TIER_ENV} must be one of ${LIVE_TIERS.join(", ")}, got ${JSON.stringify(value)}`);
  }
  return value as LiveTier;
}

/** Whether a case of `tier` runs under the selected tier. */
export function liveTierSelected(tier: Exclude<LiveTier, "all">, env: NodeJS.ProcessEnv = process.env): boolean {
  const selected = selectedLiveTier(env);
  return selected === "all" || selected === tier;
}
