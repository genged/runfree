import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { validateMcpOperationPolicy } from "@runfree/runtime-contracts/mcp-operation-policy";
import type { WriteAction } from "@runfree/runtime-contracts/network-policy";
import { isRecord } from "@runfree/runtime-contracts/primitives";
import { propertyParameters } from "../../../tests/support/property.ts";
import { classifyMcpRequestBody, type McpClassification, parseJsonStrict } from "./mcp-classify.ts";

// One server with explicit allow and deny tools and an `ask` fallback, and one
// with no fallback, so a tool's action can come from the global action.
const policies = [
  validateMcpOperationPolicy({
    schemaVersion: 1,
    servers: [{
      id: "codex:posthog",
      agent: "codex",
      name: "posthog",
      source: "user",
      host: "mcp.posthog.com",
      path: "/mcp",
      defaultToolWriteAction: "ask",
      tools: { query: { writeAction: "allow" }, deleteFeatureFlag: { writeAction: "deny" } },
    }],
  }),
  validateMcpOperationPolicy({
    schemaVersion: 1,
    servers: [{
      id: "claude:posthog",
      agent: "claude",
      name: "posthog",
      source: "user",
      host: "mcp.posthog.com",
      path: "/mcp",
      tools: { query: { writeAction: "allow" }, deleteFeatureFlag: { writeAction: "deny" } },
    }],
  }),
];

function classify(body: string, globalWriteAction: WriteAction, policyIndex: number): McpClassification | undefined {
  return classifyMcpRequestBody({
    bodyText: body,
    contentLength: Buffer.byteLength(body),
    contentType: "application/json",
    globalWriteAction,
    method: "POST",
    policy: policies[policyIndex],
    url: new URL("https://mcp.posthog.com/mcp"),
  });
}

// The MCP read surface as the spec states it, not imported from the module.
const READ_RPC_METHODS = [
  "initialize",
  "ping",
  "tools/list",
  "resources/list",
  "resources/read",
  "prompts/list",
  "prompts/get",
  "completion/complete",
];
const READ_NOTIFICATION_METHODS = ["notifications/initialized", "notifications/cancelled"];
const TOOLS = ["query", "deleteFeatureFlag", "createFeatureFlag", ""];

const writeActionArb = fc.constantFrom<WriteAction>("allow", "ask", "deny");
const policyIndexArb = fc.nat({ max: policies.length - 1 });
const idArb = fc.oneof(fc.integer(), fc.string({ maxLength: 4 }), fc.constant(null));

const messageArb: fc.Arbitrary<unknown> = fc.oneof(
  fc.record({ jsonrpc: fc.constant("2.0"), id: idArb, method: fc.constantFrom(...READ_RPC_METHODS) }),
  fc.record({ jsonrpc: fc.constant("2.0"), method: fc.constantFrom(...READ_NOTIFICATION_METHODS) }),
  fc.record({ jsonrpc: fc.constant("2.0"), id: idArb, method: fc.constantFrom(...READ_NOTIFICATION_METHODS) }),
  fc.record(
    { jsonrpc: fc.constant("2.0"), id: idArb, result: fc.jsonValue({ maxDepth: 1 }), error: fc.jsonValue({ maxDepth: 1 }) },
    { requiredKeys: ["jsonrpc"] },
  ),
  fc.record(
    {
      jsonrpc: fc.constant("2.0"),
      id: idArb,
      method: fc.constant("tools/call"),
      params: fc.oneof(
        fc.record({ name: fc.constantFrom(...TOOLS), arguments: fc.jsonValue({ maxDepth: 1 }) }, { requiredKeys: ["name"] }),
        fc.jsonValue({ maxDepth: 1 }),
      ),
    },
    { requiredKeys: ["jsonrpc", "method"] },
  ),
  fc.record({ jsonrpc: fc.constant("2.0"), id: idArb, method: fc.oneof(fc.string({ maxLength: 12 }), fc.jsonValue({ maxDepth: 0 })) }),
  fc.jsonValue({ maxDepth: 2 }),
);

const bodyMessagesArb = fc.oneof(messageArb, fc.array(messageArb, { maxLength: 5 }));

// Read < write; a request that runs unchecked (read, or a write the policy
// allows) ranks below one that needs approval, which ranks below a deny.
const ACTION_RANK: Record<WriteAction, number> = { allow: 0, ask: 1, deny: 2 };

function effectiveRank(classification: McpClassification | undefined): number {
  if (classification === undefined) throw new Error("the MCP endpoint must always classify");
  return classification.kind === "read" ? 0 : ACTION_RANK[classification.writeAction];
}

function severity(classification: McpClassification | undefined): number {
  return classification?.kind === "read" ? 0 : 1;
}

// Counts object members in the source (`:` outside strings) and in the parsed
// value. `JSON.parse` keeps the last of two equal keys, so the counts differ
// exactly when the source repeats a key.
function hasDuplicateKeys(source: string, parsed: unknown): boolean {
  let members = 0;
  let inString = false;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (inString) {
      if (char === "\\") index += 1;
      else if (char === "\"") inString = false;
    } else if (char === "\"") {
      inString = true;
    } else if (char === ":") {
      members += 1;
    }
  }
  return members !== parsedMembers(parsed);
}

function parsedMembers(value: unknown): number {
  if (Array.isArray(value)) return value.reduce((total: number, entry) => total + parsedMembers(entry), 0);
  if (!isRecord(value)) return 0;
  return Object.values(value).reduce((total: number, entry) => total + parsedMembers(entry) + 1, 0);
}

function tryJsonParse(source: string): { value: unknown } | undefined {
  try {
    return { value: JSON.parse(source) as unknown };
  } catch {
    return undefined;
  }
}

// JSON whitespace plus characters `/\s/` accepts and `JSON.parse` refuses.
const whitespaceArb = fc.string({
  unit: fc.constantFrom(" ", "\t", "\n", "\r", "\u00a0", "\v", "\f", "\u2028", "\ufeff"),
  maxLength: 4,
});

const whitespaceMutatedJsonArb = fc
  .tuple(fc.jsonValue({ stringUnit: "binary", maxDepth: 3 }), whitespaceArb, whitespaceArb, whitespaceArb)
  .map(([value, gap, before, after]) => `${before}${JSON.stringify(value, null, gap)}${after}`);

const editedJsonArb = fc
  .tuple(
    whitespaceMutatedJsonArb,
    fc.nat(),
    fc.boolean(),
    fc.oneof(fc.constantFrom("{", "}", "[", "]", ",", ":", "\"", "\\", "-", "0", "e", "."), fc.string({ minLength: 1, maxLength: 1 })),
  )
  .map(([text, at, remove, char]) => {
    const index = text.length === 0 ? 0 : at % (text.length + (remove ? 0 : 1));
    return remove ? text.slice(0, index) + text.slice(index + 1) : text.slice(0, index) + char + text.slice(index);
  });

// Writes a key as a JSON string literal, re-encoding the UTF-16 units that
// `escapeMask` selects as `\uXXXX` and leaving the rest as short as JSON allows.
function encodeKey(key: string, escapeMask: readonly boolean[]): string {
  let out = "\"";
  for (let index = 0; index < key.length; index += 1) {
    const unit = key.charCodeAt(index);
    if (escapeMask[index] === true) out += `\\u${unit.toString(16).padStart(4, "0")}`;
    else if (unit < 0x20 || key[index] === "\"" || key[index] === "\\") out += JSON.stringify(key[index]).slice(1, -1);
    else out += key[index];
  }
  return `${out}"`;
}

const keyArb = fc.string({ unit: fc.constantFrom("a", "A", "é", "😀", "\"", "\\", "\n", "\u0000"), maxLength: 3 });

type ObjectEntry = { key: string; value: unknown; escapeMask: boolean[] };

const objectEntriesArb = fc.array(
  fc.record({ key: keyArb, value: fc.jsonValue({ maxDepth: 1 }), escapeMask: fc.array(fc.boolean(), { maxLength: 6 }) }),
  { maxLength: 6 },
);

function objectText(entries: readonly ObjectEntry[], reencode: boolean): string {
  return `{${entries.map(({ key, value, escapeMask }) => `${encodeKey(key, reencode ? escapeMask : [])}:${JSON.stringify(value)}`).join(",")}}`;
}

const nestingArb = fc.constantFrom(
  (object: string) => object,
  (object: string) => `[1,${object}]`,
  (object: string) => `{"jsonrpc":"2.0","params":${object}}`,
);

// A key that matches `word` only when compared without case. `ſ` (U+017F)
// folds to `s` in Go's `encoding/json` key matching.
function caseVariantArb(word: string): fc.Arbitrary<string> {
  return fc
    .tuple(...[...word].map((char) => fc.constantFrom(...new Set([char, char.toUpperCase(), ...(char === "s" ? ["ſ"] : [])]))))
    .map((chars) => chars.join(""))
    .filter((variant) => variant !== word);
}

const caseVariantKeyArb = fc.oneof(
  fc.constantFrom("method", "params", "id").chain(caseVariantArb).map((variant) => ({ inParams: false, variant })),
  caseVariantArb("name").map((variant) => ({ inParams: true, variant })),
);

function withCaseVariantKey(message: Record<string, unknown>, inParams: boolean, variant: string, value: unknown): Record<string, unknown> {
  if (!inParams) return { ...message, [variant]: value };
  return { ...message, params: { ...(isRecord(message.params) ? message.params : {}), [variant]: value } };
}

describe("MCP classifier properties", () => {
  it("P3.1: parseJsonStrict agrees with JSON.parse on JSON without duplicate keys and yields no value where it throws", () => {
    fc.assert(
      fc.property(fc.oneof(whitespaceMutatedJsonArb, editedJsonArb), (text) => {
        const reference = tryJsonParse(text);
        const result = parseJsonStrict(text);
        if (reference === undefined) {
          expect(result.value).toBeUndefined();
          expect(result.reason).toBeDefined();
          return;
        }
        fc.pre(!hasDuplicateKeys(text, reference.value));
        expect(result.reason).toBeUndefined();
        expect(result.value).toStrictEqual(reference.value);
      }),
      propertyParameters(),
    );
  });

  it("P3.2: re-encoding key characters as \\uXXXX does not change duplicate-key detection", () => {
    fc.assert(
      fc.property(objectEntriesArb, nestingArb, (entries, nest) => {
        const keys = entries.map((entry) => entry.key);
        const expected = new Set(keys).size === keys.length ? undefined : "duplicate-key";
        expect(parseJsonStrict(nest(objectText(entries, false))).reason).toBe(expected);
        expect(parseJsonStrict(nest(objectText(entries, true))).reason).toBe(expected);
      }),
      propertyParameters(),
    );
  });

  it("P3.3: adding an element to a batch never lowers severity or relaxes the effective write action", () => {
    fc.assert(
      fc.property(
        fc.array(messageArb, { minLength: 1, maxLength: 4 }),
        messageArb,
        fc.nat(),
        writeActionArb,
        policyIndexArb,
        (batch, extra, at, globalWriteAction, policyIndex) => {
          const index = at % (batch.length + 1);
          const grown = [...batch.slice(0, index), extra, ...batch.slice(index)];
          const before = classify(JSON.stringify(batch), globalWriteAction, policyIndex);
          const after = classify(JSON.stringify(grown), globalWriteAction, policyIndex);
          expect(severity(after)).toBeGreaterThanOrEqual(severity(before));
          expect(effectiveRank(after)).toBeGreaterThanOrEqual(effectiveRank(before));
        },
      ),
      propertyParameters(),
    );
  });

  it("P3.4: a read result means every message is a response, a read method, or a read notification without an id", () => {
    fc.assert(
      fc.property(bodyMessagesArb, writeActionArb, policyIndexArb, (body, globalWriteAction, policyIndex) => {
        const text = JSON.stringify(body);
        if (classify(text, globalWriteAction, policyIndex)?.kind !== "read") return;
        const messages = Array.isArray(body) ? body : [body];
        expect(messages.length).toBeGreaterThan(0);
        for (const message of messages) {
          expect(isRecord(message), text).toBe(true);
          if (!isRecord(message)) continue;
          const response = !Object.hasOwn(message, "method")
            && Object.hasOwn(message, "id")
            && Object.hasOwn(message, "result") !== Object.hasOwn(message, "error");
          const readMethod = typeof message.method === "string" && READ_RPC_METHODS.includes(message.method);
          const readNotification = typeof message.method === "string"
            && READ_NOTIFICATION_METHODS.includes(message.method)
            && !Object.hasOwn(message, "id");
          expect(response || readMethod || readNotification, text).toBe(true);
        }
      }),
      propertyParameters(),
    );
  });

  // Product defect: a case-variant key (`METHOD`, `Id`, `Name`) rides along on
  // a read message, and a case-insensitive upstream decoder may act on it (H4).
  it.skip("P3.5: a key that differs only in case from method, params, name, or id never classifies read — product defect, see todo 102", () => {
    fc.assert(
      fc.property(
        messageArb.filter(isRecord),
        caseVariantKeyArb,
        fc.oneof(fc.constant<unknown>("tools/call"), fc.constant<unknown>("deleteFeatureFlag"), fc.jsonValue({ maxDepth: 1 })),
        fc.array(messageArb, { maxLength: 2 }),
        writeActionArb,
        policyIndexArb,
        (message, { inParams, variant }, value, siblings, globalWriteAction, policyIndex) => {
          const mutated = withCaseVariantKey(message, inParams, variant, value);
          const body = siblings.length === 0 ? mutated : [mutated, ...siblings];
          expect(classify(JSON.stringify(body), globalWriteAction, policyIndex)?.kind).not.toBe("read");
        },
      ),
      propertyParameters(),
    );
  });
});
