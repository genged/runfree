import { type SessionFileV1 } from "@runfree/runtime-contracts/session-file";

import { type SessionFileScan } from "./session-files.js";

// The one validity rule both proxy consumers run: the request proxy's
// registry (session-file-registry.ts) and the root firewall supervisor. They
// keep independent observation maps — the root process must not consume the
// uid-1001 process's decision — so the rule lives here as a pure function
// over (scan, the caller's observations, both clocks) and the two consumers
// cannot disagree by more than one 100 ms loop.
//
// This is the file-backed form of `SourceIpSessionRegistry#leaseActive`
// (session-registry.ts): the same dual-clock test, keyed on the file's
// `nonce` instead of the retired lease generation.

export type SessionFileObservation = {
  // The observation key. Identical bytes carry the same nonce and therefore
  // never create a new observation, so a replay extends neither clock.
  nonce: string;
  // Wall deadline as first observed for this nonce. A later rewrite of the
  // same nonce cannot raise it (review F7a).
  aliveUntilMs: number;
  observedAtMonotonicMs: number;
  observedDurationMs: number;
};

export type ServedSessionFiles = {
  served: Map<string, SessionFileV1>;
  // Session keys whose live contexts (sockets, approval grants) must be
  // dropped this round: every scanned key that is not served because a clock
  // elapsed, plus every key whose new nonce superseded an observation that
  // had already elapsed on either clock (review F7b — the file-level
  // equivalent of `replacedExpiredLease`; such a key is served again, but
  // only after its previous authority ends).
  expired: string[];
};

/**
 * Decides which scanned session files are served right now.
 *
 * `observations` is the caller's own state and is the only thing mutated:
 * new nonces are recorded, and observations for keys whose file left the
 * directory are pruned. An unreadable scan serves nothing and prunes nothing —
 * it carries no information about which sessions still exist, and dropping
 * observations there would hand a replayed file a fresh monotonic bound.
 *
 * Pruning reads `scan.presentKeys`, not `scan.files`. `files` is the served
 * set, so a file the scanner dropped by rule — ineligible during a rolling
 * control-plane rebind, or one of two claimants on an address — is absent
 * from it while still sitting on disk. Pruning on that would give a file that
 * flickers out of eligibility and back a fresh monotonic bound under its
 * unchanged nonce, which is the exact replay window the first-observation
 * bound exists to close.
 */
export function servedSessionFiles(
  scan: SessionFileScan,
  observations: Map<string, SessionFileObservation>,
  nowMs: number,
  monotonicNowMs: number,
  leaseMaxMs: number,
): ServedSessionFiles {
  const served = new Map<string, SessionFileV1>();
  const expired = new Set<string>();
  if (scan.kind !== "ok") return { served, expired: [] };

  for (const [sessionKey, file] of scan.files) {
    const aliveUntilMs = Date.parse(file.aliveUntil);
    const previous = observations.get(sessionKey);
    let observation = previous;
    if (!observation || observation.nonce !== file.nonce) {
      if (previous && !observationActive(previous, nowMs, monotonicNowMs)) expired.add(sessionKey);
      observation = {
        nonce: file.nonce,
        aliveUntilMs,
        observedAtMonotonicMs: monotonicNowMs,
        observedDurationMs: Math.min(aliveUntilMs - nowMs, leaseMaxMs),
      };
      observations.set(sessionKey, observation);
    }
    // A replay of the same nonce with a later wall deadline extends neither
    // the wall term nor the first observed monotonic bound.
    const wallActive = Math.min(aliveUntilMs, observation.aliveUntilMs) > nowMs;
    const monotonicActive = monotonicNowMs - observation.observedAtMonotonicMs < observation.observedDurationMs;
    if (wallActive && monotonicActive) served.set(sessionKey, file);
    else expired.add(sessionKey);
  }

  for (const sessionKey of Array.from(observations.keys())) {
    if (!scan.presentKeys.has(sessionKey)) observations.delete(sessionKey);
  }
  return { served, expired: Array.from(expired) };
}

function observationActive(
  observation: SessionFileObservation,
  nowMs: number,
  monotonicNowMs: number,
): boolean {
  return observation.aliveUntilMs > nowMs
    && monotonicNowMs - observation.observedAtMonotonicMs < observation.observedDurationMs;
}
