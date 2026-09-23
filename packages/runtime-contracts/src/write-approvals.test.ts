import { describe, expect, test } from "vitest";

import {
  approvalControlFileName,
  formatApprovalDuration,
  isApprovalControlFileName,
  parseApprovalDecisionRecord,
  parsePendingApprovalRecord,
  parseApprovalControlRecord,
  parseWriteApprovalsStatus,
} from "./write-approvals.ts";

const NONCE = "0123456789abcdef0123456789abcdef";
const SESSION = {
  sessionId: "rf-20260805-abcdef",
  name: "payments refactor",
  command: "codex",
  hostTty: "/dev/ttys004",
  startedAt: "2026-08-05T12:00:00.000Z",
};

function statusJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    held: 1,
    denyId: NONCE,
    grants: [],
    updatedAt: "2026-07-27T00:00:00.000Z",
    ...overrides,
  });
}

const HOST_GRANT = {
  effect: "allow",
  scope: "session",
  subject: "session",
  coverage: "host",
  host: "api.github.com",
  expiresInSeconds: 3600,
  session: SESSION,
};

const MCP_DENY_GRANT = {
  effect: "deny",
  scope: "session",
  subject: "session",
  coverage: "mcp-tool",
  mcp: { agent: "codex", server: "posthog", method: "tools/call", tool: "delete_flag" },
  session: SESSION,
};

describe("write approvals status snapshot", () => {
  test("parses a snapshot carrying the deny nonce and both grant signs", () => {
    const parsed = parseWriteApprovalsStatus(statusJson({
      grants: [HOST_GRANT, MCP_DENY_GRANT],
    }));

    expect(parsed).toEqual({
      held: 1,
      denyId: NONCE,
      grants: [HOST_GRANT, MCP_DENY_GRANT],
      updatedAt: "2026-07-27T00:00:00.000Z",
    });
  });

  test("a negative grant may omit its expiry; a positive one is still parsed as written", () => {
    const parsed = parseWriteApprovalsStatus(statusJson({ grants: [MCP_DENY_GRANT] }));
    expect(parsed?.grants[0].expiresInSeconds).toBeUndefined();
    expect(parsed?.grants[0].effect).toBe("deny");
  });

  test("only an authenticated session grant may omit an expiry", () => {
    const { expiresInSeconds: _dropped, ...unbounded } = HOST_GRANT;
    expect(parseWriteApprovalsStatus(statusJson({ grants: [unbounded] }))).toBeDefined();
    expect(parseWriteApprovalsStatus(statusJson({ grants: [{ ...unbounded, subject: "runtime", session: undefined }] }))).toBeUndefined();
    expect(parseWriteApprovalsStatus(statusJson({ grants: [{ ...unbounded, subject: "request", session: undefined }] }))).toBeUndefined();
    expect(parseWriteApprovalsStatus(statusJson({ grants: [{ ...unbounded, expiresInSeconds: 1 }] }))).toBeDefined();
  });

  test("one-shot request grants carry the shape they readmit", () => {
    const requestGrant = {
      effect: "allow",
      scope: "request",
      subject: "request",
      coverage: "request",
      host: "api.github.com",
      method: "POST",
      path: "/repos/o/r/issues",
      expiresInSeconds: 300,
    };
    expect(parseWriteApprovalsStatus(statusJson({ grants: [requestGrant] }))?.grants).toEqual([requestGrant]);
    expect(parseWriteApprovalsStatus(statusJson({ grants: [{ ...requestGrant, method: "" }] }))).toBeUndefined();
    expect(parseWriteApprovalsStatus(statusJson({ grants: [{ ...requestGrant, path: 5 }] }))).toBeUndefined();
  });

  test("rejects malformed snapshots instead of trusting partial authority", () => {
    const malformed = [
      "not-json",
      "[]",
      statusJson({ denyId: undefined }),
      statusJson({ denyId: "short" }),
      statusJson({ denyId: NONCE.toUpperCase() }),
      statusJson({ held: -1 }),
      statusJson({ held: 1.5 }),
      statusJson({ grants: {} }),
      statusJson({ updatedAt: 5 }),
      // The retired runtime-wide deny key is rejected outright, even in its
      // once-valid shape: no snapshot may claim runtime-scoped authority.
      statusJson({ runtimeDeny: { since: "2026-07-27T00:00:00.000Z" } }),
      statusJson({ runtimeDeny: {} }),
      statusJson({ runtimeDeny: "yes" }),
      statusJson({ grants: [{ ...HOST_GRANT, effect: "maybe" }] }),
      statusJson({ grants: [{ ...HOST_GRANT, scope: "forever" }] }),
      statusJson({ grants: [{ ...HOST_GRANT, subject: "runtime" }] }),
      statusJson({ grants: [{ ...HOST_GRANT, session: undefined }] }),
      statusJson({ grants: [{ ...HOST_GRANT, subject: "request" }] }),
      statusJson({ grants: [{ ...HOST_GRANT, coverage: "everything" }] }),
      statusJson({ grants: [{ ...HOST_GRANT, host: "" }] }),
      statusJson({ grants: [{ ...HOST_GRANT, expiresInSeconds: -1 }] }),
      statusJson({ grants: [{ ...HOST_GRANT, expiresInSeconds: "600" }] }),
      statusJson({ grants: [{ ...MCP_DENY_GRANT, mcp: { agent: "gemini", server: "x", method: "tools/call" } }] }),
      statusJson({ grants: ["allow everything"] }),
    ];

    for (const raw of malformed) {
      expect(parseWriteApprovalsStatus(raw), raw).toBeUndefined();
    }
  });
});

describe("session-scoped approval records", () => {
  const pending = {
    v: 1,
    id: NONCE,
    host: "api.github.com",
    method: "POST",
    path: "/repos/o/r/issues",
    category: "method",
    tokenNames: ["github"],
    session: SESSION,
    generation: "sha256:policy",
    heldAt: "2026-08-05T12:00:00.000Z",
    expiresAt: "2026-08-05T12:02:00.000Z",
  };

  test("parses bounded display metadata without an internal session key", () => {
    const parsed = parsePendingApprovalRecord(JSON.stringify(pending));
    expect(parsed?.session).toEqual(SESSION);
    expect(parsed?.session).not.toHaveProperty("sessionKey");
    expect(parsePendingApprovalRecord(JSON.stringify({ ...pending, session: { ...SESSION, sessionKey: "secret" } }))).toBeUndefined();
    expect(parsePendingApprovalRecord(JSON.stringify({
      ...pending,
      session: undefined,
      requestOnlyPrincipal: { kind: "anonymous-utility", label: "utility forwarder (request-only)" },
    }))?.requestOnlyPrincipal?.kind).toBe("anonymous-utility");
    // The retired shared-agent principal kind no longer parses.
    expect(parsePendingApprovalRecord(JSON.stringify({
      ...pending,
      session: undefined,
      requestOnlyPrincipal: { kind: "legacy-shared-agent", label: "legacy shared agent (request-only)" },
    }))).toBeUndefined();
  });

  test("TTL is only a modifier on an approving session decision", () => {
    const base = { v: 1, id: NONCE, decision: "approve", decidedAt: "2026-08-05T12:00:00.000Z" };
    expect(parseApprovalDecisionRecord(JSON.stringify({ ...base, scope: "session", ttlMs: 900_000 })))
      .toMatchObject({ scope: "session", ttlMs: 900_000 });
    expect(parseApprovalDecisionRecord(JSON.stringify({ ...base, scope: "ttl", ttlMs: 900_000 }))).toBeUndefined();
    expect(parseApprovalDecisionRecord(JSON.stringify({ ...base, scope: "request", ttlMs: 900_000 }))).toBeUndefined();
    expect(parseApprovalDecisionRecord(JSON.stringify({ ...base, ttlMs: 900_000 }))).toBeUndefined();
    expect(parseApprovalDecisionRecord(JSON.stringify({ ...base, decision: "deny", scope: "session", ttlMs: 900_000 }))).toBeUndefined();
  });
});

describe("clear-write-deny control records", () => {
  test("parses a well-formed control record", () => {
    expect(parseApprovalControlRecord(JSON.stringify({
      v: 1,
      control: "clear-write-deny",
      denyId: NONCE,
      issuedAt: "2026-07-27T00:00:00.000Z",
    }))).toEqual({
      v: 1,
      control: "clear-write-deny",
      denyId: NONCE,
      issuedAt: "2026-07-27T00:00:00.000Z",
    });
  });

  test("rejects unknown verbs, wrong versions, and malformed nonces", () => {
    const malformed = [
      "not-json",
      "[]",
      JSON.stringify({ v: 2, control: "clear-write-deny", denyId: NONCE, issuedAt: "t" }),
      JSON.stringify({ v: 1, control: "grant-everything", denyId: NONCE, issuedAt: "t" }),
      JSON.stringify({ v: 1, control: "clear-write-deny", denyId: "nope", issuedAt: "t" }),
      JSON.stringify({ v: 1, control: "clear-write-deny", issuedAt: "t" }),
      JSON.stringify({ v: 1, control: "clear-write-deny", denyId: NONCE }),
    ];

    for (const raw of malformed) {
      expect(parseApprovalControlRecord(raw), raw).toBeUndefined();
    }
  });

  test("control file names are nonce-shaped and distinct from decision file names", () => {
    expect(approvalControlFileName(NONCE)).toBe(`control-${NONCE}.json`);
    expect(isApprovalControlFileName(approvalControlFileName(NONCE))).toBe(true);
    expect(isApprovalControlFileName(`${NONCE}.json`)).toBe(false);
    expect(isApprovalControlFileName("control-.json")).toBe(false);
    expect(isApprovalControlFileName("control-../../escape.json")).toBe(false);
    expect(isApprovalControlFileName("watcher-heartbeat")).toBe(false);
  });
});

describe("grant durations", () => {
  test("durations render the same way everywhere they are shown", () => {
    expect(formatApprovalDuration(60 * 60_000)).toBe("1h");
    expect(formatApprovalDuration(15 * 60_000)).toBe("15m");
    expect(formatApprovalDuration(90_000)).toBe("90s");
    expect(formatApprovalDuration(500)).toBe("1s");
  });
});
