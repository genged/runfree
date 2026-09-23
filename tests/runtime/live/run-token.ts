// The token every live fixture provisioned by one Vitest invocation shares.
//
// Exists only because the live project runs files in parallel. The fixture
// refuses to provision when a sandbox runtime from an *earlier* run is still up
// — those hold Docker networks and the MCP OAuth callback port, and both have
// broken later runs in ways that name no cause. That check reads the daemon,
// which cannot tell a leaked runtime from a sibling file's live one: with more
// than one worker, every fixture after the first would refuse.
//
// Stamping the run into the generated project directory name resolves it
// without weakening the check. A sandbox container mounting *this* run's token
// is a sibling; one mounting any other token is exactly the leak the guard
// exists for.
//
// The main Vitest process sets `RUNFREE_LIVE_RUN_ID` in the live project's
// globalSetup, before any worker is forked, so every worker inherits the same
// value.

import crypto from "node:crypto";

export const LIVE_RUN_ID_ENV = "RUNFREE_LIVE_RUN_ID";

/** 12 lowercase hex characters: short enough to keep temp paths readable. */
const TOKEN_PATTERN = /^[0-9a-f]{12}$/u;

export function newLiveRunToken(): string {
  return crypto.randomBytes(6).toString("hex");
}

let processLocalToken: string | undefined;

/**
 * This run's token.
 *
 * Falls back to a process-local token when the environment carries none, which
 * is the case for a direct import outside the live project (the fixture's own
 * unit tests) — there, one process provisions everything, so a per-process
 * token is the correct scope rather than a degraded one.
 *
 * A malformed value is refused rather than normalized: it would otherwise flow
 * into a generated directory name and into the substring match that classifies
 * leaks, where a stray `.` or `/` silently changes which containers count.
 */
export function liveRunToken(): string {
  const provided = process.env[LIVE_RUN_ID_ENV];
  if (provided !== undefined) {
    if (!TOKEN_PATTERN.test(provided)) {
      throw new Error(`${LIVE_RUN_ID_ENV} must be 12 lowercase hex characters, got ${JSON.stringify(provided)}`);
    }
    return provided;
  }
  processLocalToken ??= newLiveRunToken();
  return processLocalToken;
}
