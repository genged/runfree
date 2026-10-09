// Property tests for the write-approval record parsers (spec Phase 6).
//
// The records cross the host↔proxy channel as tmpfs files and docker exec
// output, so each parser must turn any string into a record or `undefined`,
// never invent a value the JSON did not carry, and accept every record the
// other half of the channel can write.
import fc from "fast-check";
import { describe, expect, test } from "vitest";

import { propertyParameters } from "../../../tests/support/property.ts";
import {
  APPROVAL_CONTROL_FILE_PREFIX,
  WRITE_APPROVAL_GRANT_TTL_MAX_MS,
  approvalControlFileName,
  isApprovalControlFileName,
  parseApprovalControlRecord,
  parseApprovalDecisionRecord,
  parsePendingApprovalRecord,
  parseWriteApprovalsStatus,
  type ApprovalControlRecord,
  type ApprovalDecisionRecord,
  type PendingApprovalMcp,
  type PendingApprovalRecord,
  type WriteApprovalGrantSummary,
  type WriteApprovalsStatus,
} from "./write-approvals.ts";
import type { PendingApprovalSession } from "./session-registry.ts";

// --- Well-formed records, built from the documented record shapes ----------

const hex = (length: number) => fc.string({ unit: fc.constantFrom(..."0123456789abcdef"), minLength: length, maxLength: length });
const approvalId = hex(32);
const processEpoch = hex(64);
const anyString = fc.string({ unit: "binary", maxLength: 24 });
const nonEmptyString = fc.string({ unit: "binary", minLength: 1, maxLength: 24 });
const isoTimestamp = fc
  .date({ min: new Date("2000-01-01T00:00:00.000Z"), max: new Date("2099-12-31T23:59:59.999Z"), noInvalidDate: true })
  .map((date) => date.toISOString());
// Display text the session parser admits: trimmed, no C0/C1 controls.
const displayText = (maxLength: number) => fc
  .string({ unit: "grapheme", minLength: 1, maxLength: 12 })
  .map((value) => value.trim())
  .filter((value) => value !== "" && Array.from(value).length <= maxLength && !/[\u0000-\u001f\u007f-\u009f]/u.test(value));

const session: fc.Arbitrary<PendingApprovalSession> = fc.record({
  sessionId: fc.stringMatching(/^rf-[0-9]{8}-[a-z0-9]{6,32}$/),
  name: displayText(80),
  command: displayText(64),
  agentCommand: displayText(256),
  hostTty: displayText(128),
  hostTermProgram: displayText(128),
  startedAt: isoTimestamp,
}, { requiredKeys: ["sessionId", "name", "command", "startedAt"] });

const mcp: fc.Arbitrary<PendingApprovalMcp> = fc.record({
  agent: fc.constantFrom("claude", "codex"),
  serverId: nonEmptyString,
  server: nonEmptyString,
  method: nonEmptyString,
  tool: nonEmptyString,
}, { requiredKeys: ["agent", "server", "method"] });

const pendingRecord: fc.Arbitrary<PendingApprovalRecord> = fc.tuple(
  fc.record({
    processEpoch,
    v: fc.constant(1 as const),
    id: approvalId,
    host: nonEmptyString,
    method: anyString,
    path: anyString,
    category: fc.constantFrom(
      "method", "method-override", "git-push", "graphql", "write-path", "websocket", "mcp-tool", "mcp-unknown",
    ),
    tokenNames: fc.array(anyString, { maxLength: 3 }),
    mcp,
    generation: anyString,
    heldAt: anyString,
    expiresAt: anyString,
  }, { requiredKeys: ["v", "id", "host", "method", "path", "category", "tokenNames", "generation", "heldAt", "expiresAt"] }),
  // A session and a request-only principal are mutually exclusive.
  fc.oneof(
    fc.constant({}),
    session.map((value) => ({ session: value })),
    fc.string({ unit: "binary", minLength: 1, maxLength: 40 })
      .map((label) => ({ requestOnlyPrincipal: { kind: "anonymous-utility" as const, label } })),
  ),
).map(([base, principal]) => ({ ...base, ...principal }));

const decisionCommon = fc.record({
  processEpoch,
  v: fc.constant(1 as const),
  id: approvalId,
  mcpScope: fc.constantFrom("tool", "method", "server-tools"),
  saveMcpRule: fc.constantFrom("tool", "server-tools"),
  decidedAt: anyString,
}, { requiredKeys: ["v", "id", "decidedAt"] });

const decisionRecord: fc.Arbitrary<ApprovalDecisionRecord> = fc.oneof(
  // An approve carries a TTL only at session scope.
  fc.tuple(
    decisionCommon,
    fc.oneof(
      fc.record({ scope: fc.constantFrom("request" as const) }, { requiredKeys: [] }),
      fc.record({
        scope: fc.constant("session" as const),
        ttlMs: fc.integer({ min: 1, max: WRITE_APPROVAL_GRANT_TTL_MAX_MS }),
      }, { requiredKeys: ["scope"] }),
    ),
    fc.option(fc.constant(false), { nil: undefined }),
  ).map(([common, scope, denySession]) => ({
    ...common,
    decision: "approve" as const,
    ...scope,
    ...(denySession === undefined ? {} : { denySession }),
  })),
  // "Stop asking" is a deny with no scope.
  fc.tuple(
    decisionCommon,
    fc.oneof(
      fc.record({ scope: fc.constantFrom("request" as const, "session" as const), denySession: fc.constant(false) }, { requiredKeys: [] }),
      fc.constant({ denySession: true }),
    ),
  ).map(([common, rest]) => ({ ...common, decision: "deny" as const, ...rest })),
);

const controlRecord: fc.Arbitrary<ApprovalControlRecord> = fc.record({
  processEpoch,
  v: fc.constant(1 as const),
  control: fc.constant("clear-write-deny" as const),
  denyId: approvalId,
  issuedAt: anyString,
}, { requiredKeys: ["v", "control", "denyId", "issuedAt"] });

const grantSummary: fc.Arbitrary<WriteApprovalGrantSummary> = fc.tuple(
  fc.record({
    effect: fc.constantFrom("allow" as const, "deny" as const),
    scope: fc.constantFrom("request" as const, "session" as const),
    coverage: fc.constantFrom("request" as const, "host" as const, "mcp-tool" as const, "mcp-method" as const, "mcp-server-tools" as const),
    host: nonEmptyString,
    method: nonEmptyString,
    path: anyString,
    mcp,
    expiresInSeconds: fc.oneof(fc.nat(), fc.double({ min: 0, max: 1e9, noNaN: true }).filter((value) => !Object.is(value, -0))),
  }, { requiredKeys: ["effect", "scope", "coverage"] }),
  // A session subject always names its session; a request subject never does.
  fc.oneof(
    fc.constant({ subject: "request" as const }),
    session.map((value) => ({ subject: "session" as const, session: value })),
  ),
).map(([base, subject]) => ({ ...base, ...subject }))
  // Only a session grant of session scope may be an allow with no expiry.
  .filter((grant) => grant.effect !== "allow" || grant.expiresInSeconds !== undefined
    || (grant.subject === "session" && grant.scope === "session"));

const statusSnapshot: fc.Arbitrary<WriteApprovalsStatus> = fc.record({
  processEpoch,
  held: fc.nat(),
  denyId: approvalId,
  grants: fc.array(grantSummary, { maxLength: 3 }),
  updatedAt: anyString,
}, { requiredKeys: ["held", "denyId", "grants", "updatedAt"] });

// --- Near-valid inputs: one well-formed record with one edit ---------------

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

// Every (container, key) slot in a JSON tree, so an edit can reach nested
// objects such as `mcp`, `session`, and the status grants.
function slots(value: Json, out: Array<[Json[] | { [key: string]: Json }, string | number]> = []) {
  if (Array.isArray(value)) value.forEach((item, index) => { out.push([value, index]); slots(item, out); });
  else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) { out.push([value, key]); slots(item, out); }
  }
  return out;
}

const edit = fc.record({
  kind: fc.constantFrom("none", "delete", "replace", "add"),
  at: fc.nat(),
  key: fc.oneof(fc.constantFrom("v", "id", "mcp", "session", "tool", "__proto__", "extra"), fc.string({ maxLength: 6 })),
  value: fc.jsonValue({ maxDepth: 2 }) as fc.Arbitrary<Json>,
});

function nearValid<T>(record: fc.Arbitrary<T>): fc.Arbitrary<string> {
  return fc.tuple(record, edit).map(([value, change]) => {
    const tree = JSON.parse(JSON.stringify(value)) as Json;
    const all = slots(tree);
    if (change.kind === "none" || all.length === 0) return JSON.stringify(tree);
    const [container, key] = all[change.at % all.length];
    if (change.kind === "delete") {
      if (Array.isArray(container)) container.splice(key as number, 1);
      else delete container[key as string];
    } else if (change.kind === "replace") {
      (container as Record<string | number, Json>)[key] = change.value;
    } else if (!Array.isArray(container)) {
      Object.defineProperty(container, change.key, { value: change.value, enumerable: true, configurable: true, writable: true });
    }
    return JSON.stringify(tree);
  });
}

const parsers = [
  ["parsePendingApprovalRecord", parsePendingApprovalRecord, pendingRecord],
  ["parseApprovalDecisionRecord", parseApprovalDecisionRecord, decisionRecord],
  ["parseApprovalControlRecord", parseApprovalControlRecord, controlRecord],
  ["parseWriteApprovalsStatus", parseWriteApprovalsStatus, statusSnapshot],
] as const;

const anyRaw = fc.oneof(
  fc.string({ unit: "binary" }),
  fc.json({ maxDepth: 3 }),
  nearValid(pendingRecord),
  nearValid(decisionRecord),
  nearValid(controlRecord),
  nearValid(statusSnapshot),
);

// True when every value in `output` was read from the same place in `input`:
// the parser may drop fields, never add or change one.
function isProjection(output: unknown, input: unknown): boolean {
  if (Array.isArray(output)) {
    return Array.isArray(input) && input.length === output.length && output.every((item, index) => isProjection(item, input[index]));
  }
  if (output !== null && typeof output === "object") {
    if (input === null || typeof input !== "object" || Array.isArray(input)) return false;
    return Object.entries(output).every(([key, item]) =>
      Object.hasOwn(input, key) && isProjection(item, (input as Record<string, unknown>)[key]));
  }
  return Object.is(output, input);
}

describe("write-approval record parsers", () => {
  test("P6.1: every parser returns a projection of the JSON or undefined, and never throws", () => {
    fc.assert(
      fc.property(anyRaw, (raw) => {
        for (const [, parse] of parsers) {
          const result = parse(raw);
          if (result === undefined) continue;
          expect(typeof result).toBe("object");
          expect(isProjection(result, JSON.parse(raw))).toBe(true);
          // A parsed record is a fixed point: re-serializing it changes nothing.
          expect(parse(JSON.stringify(result))).toEqual(result);
        }
      }),
      propertyParameters(),
    );
  });

  for (const [name, parse, record] of parsers) {
    test(`P6.2: ${name} round-trips every well-formed record`, () => {
      fc.assert(
        fc.property(record as fc.Arbitrary<unknown>, (value) => {
          expect((parse as (raw: string) => unknown)(JSON.stringify(value))).toEqual(value);
        }),
        propertyParameters(),
      );
    });
  }

  test("P6.3: control file names round-trip, and every accepted name is a minted one", () => {
    // Names assembled from the pieces a real name has, so the gate sees near
    // misses (right prefix and id, wrong suffix) and not only noise.
    const name = fc
      .tuple(
        fc.oneof(fc.constant(APPROVAL_CONTROL_FILE_PREFIX), fc.string({ maxLength: 10 })),
        fc.oneof(approvalId, fc.string({ maxLength: 34 })),
        fc.oneof(fc.constant(".json"), fc.string({ minLength: 5, maxLength: 5 }), fc.string({ maxLength: 8 })),
      )
      .map((parts) => parts.join(""));
    fc.assert(
      fc.property(approvalId, name, (id, candidate) => {
        const minted = approvalControlFileName(id);
        expect(isApprovalControlFileName(minted)).toBe(true);
        expect(minted).not.toContain("/");
        expect(minted).not.toContain("..");
        if (isApprovalControlFileName(candidate)) {
          const inner = candidate.slice(APPROVAL_CONTROL_FILE_PREFIX.length, -".json".length);
          expect(inner).toMatch(/^[0-9a-f]{32}$/);
          expect(candidate).toBe(approvalControlFileName(inner));
        }
      }),
      propertyParameters(),
    );
  });
});
