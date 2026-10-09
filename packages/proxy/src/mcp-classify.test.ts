import { describe, expect, test } from "vitest";

import { validateMcpOperationPolicy } from "@runfree/runtime-contracts/mcp-operation-policy";
import { classifyMcpRequestBody } from "./mcp-classify.ts";

const policy = validateMcpOperationPolicy({
  schemaVersion: 1,
  servers: [
    {
      id: "codex:posthog",
      agent: "codex",
      name: "posthog",
      source: "user",
      host: "mcp.posthog.com",
      path: "/mcp",
      defaultToolWriteAction: "ask",
      tools: {
        query: { writeAction: "allow" },
        deleteFeatureFlag: { writeAction: "deny" },
      },
    },
  ],
});

function classify(input: {
  body?: string;
  contentEncoding?: string;
  contentType?: string;
  globalWriteAction?: "allow" | "ask" | "deny";
  method?: string;
  path?: string;
}) {
  const body = input.body ?? "";
  return classifyMcpRequestBody({
    bodyText: body,
    contentEncoding: input.contentEncoding,
    contentLength: Buffer.byteLength(body),
    contentType: input.contentType ?? "application/json",
    globalWriteAction: input.globalWriteAction ?? "ask",
    method: input.method ?? "POST",
    policy,
    url: new URL(`https://mcp.posthog.com${input.path ?? "/mcp"}`),
  });
}

describe("MCP protocol classifier", () => {
  test("classifies lifecycle, discovery, client response, and DELETE as MCP reads", () => {
    for (const method of ["initialize", "tools/list", "resources/read", "prompts/get", "completion/complete"]) {
      expect(classify({ body: JSON.stringify({ jsonrpc: "2.0", id: 1, method }) }), method).toMatchObject({
        kind: "read",
        operation: { kind: "mcp", rpcMethod: method, serverId: "codex:posthog" },
      });
    }

    expect(classify({ body: JSON.stringify({ jsonrpc: "2.0", id: "server-request-1", result: { ok: true } }) })).toMatchObject({
      kind: "read",
      operation: { kind: "mcp", rpcMethod: "<response>", serverId: "codex:posthog" },
    });
    expect(classify({ method: "DELETE" })).toMatchObject({
      kind: "read",
      operation: { kind: "mcp", rpcMethod: "<delete>", serverId: "codex:posthog" },
    });
  });

  test("classifies tool calls from explicit Runfree rules and the server fallback", () => {
    expect(classify({
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "query", arguments: { sql: "select 1" } } }),
    })).toMatchObject({
      kind: "write",
      writeAction: "allow",
      category: "mcp-tool",
      operation: { kind: "mcp", rpcMethod: "tools/call", serverId: "codex:posthog", tool: "query" },
    });
    expect(classify({
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "deleteFeatureFlag" } }),
    })).toMatchObject({ kind: "write", writeAction: "deny", category: "mcp-tool" });
    expect(classify({
      body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "createFeatureFlag" } }),
    })).toMatchObject({ kind: "write", writeAction: "ask", category: "mcp-tool" });
  });

  test("fails closed for duplicate keys, compressed bodies, wrong content type, and path confusion", () => {
    expect(classify({ body: "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"method\":\"initialize\"}" })).toMatchObject({
      kind: "unclassifiable",
      reason: "duplicate-key",
    });
    expect(classify({ contentEncoding: "gzip", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }) })).toMatchObject({
      kind: "unclassifiable",
      reason: "compressed",
    });
    expect(classify({ contentType: "text/plain", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }) })).toMatchObject({
      kind: "unclassifiable",
      reason: "non-json",
    });
    expect(classify({ path: "/mcp/%2e%2e/other", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }) })).toBeUndefined();
  });

  // Known defect (todo 102, property P3.5): a key that
  // differs from `method`, `params`, `name`, or `id` only in case rides along on
  // a read, and a case-insensitive upstream decoder (Go `encoding/json`) may
  // act on it. Turn these into plain tests when the classifier refuses them.
  test.fails("known defect: a METHOD key beside a read method still classifies read", () => {
    expect(classify({
      body: "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"METHOD\":\"tools/call\",\"params\":{\"name\":\"deleteFeatureFlag\"}}",
    })?.kind).not.toBe("read");
  });

  test.fails("known defect: a case-variant params name on a response still classifies read", () => {
    expect(classify({
      body: "{\"jsonrpc\":\"2.0\",\"id\":\"\",\"result\":[],\"params\":{\"namE\":\"tools/call\"}}",
    })?.kind).not.toBe("read");
  });

  // A batch is one HTTP request, so one classification must stand for every
  // message in it: no element may lend the batch a weaker action or a display
  // that a grant for a different element would match.
  describe("JSON-RPC batches", () => {
    const call = (id: number, name: string) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name } });
    const read = (id: number) => ({ jsonrpc: "2.0", id, method: "tools/list" });

    test("a malformed element never erases a denied tool's deny", () => {
      expect(classify({ globalWriteAction: "allow", body: JSON.stringify([call(1, "deleteFeatureFlag"), 5]) })).toMatchObject({
        kind: "write",
        writeAction: "deny",
      });
      expect(classify({ globalWriteAction: "allow", body: JSON.stringify([5, call(1, "deleteFeatureFlag")]) })).toMatchObject({
        kind: "write",
        writeAction: "deny",
      });
    });

    test("a malformed element beside an allowed tool takes the global action, not allow", () => {
      expect(classify({ globalWriteAction: "ask", body: JSON.stringify([call(1, "query"), { jsonrpc: "2.0", id: 2 }]) })).toMatchObject({
        kind: "write",
        writeAction: "ask",
      });
    });

    test("two or more writes classify as one batch write with the strictest action and no single tool", () => {
      const twoAsks = classify({ body: JSON.stringify([call(1, "createFeatureFlag"), call(2, "updateFeatureFlag")]) });
      expect(twoAsks).toMatchObject({
        kind: "write",
        category: "mcp-unknown",
        writeAction: "ask",
        operation: { rpcMethod: "<batch>" },
        display: { method: "<batch>" },
      });
      expect(twoAsks?.kind === "write" && twoAsks.display.tool).toBeUndefined();
      expect(classify({ body: JSON.stringify([call(1, "query"), call(2, "deleteFeatureFlag")]) })).toMatchObject({
        kind: "write",
        writeAction: "deny",
      });
      expect(classify({ body: JSON.stringify([call(1, "query"), call(2, "query")]) })).toMatchObject({
        kind: "write",
        writeAction: "allow",
      });
    });

    test("reads beside one write leave that write's classification unchanged", () => {
      expect(classify({ body: JSON.stringify([read(1), call(2, "deleteFeatureFlag"), read(3)]) })).toMatchObject({
        kind: "write",
        category: "mcp-tool",
        writeAction: "deny",
        display: { method: "tools/call", tool: "deleteFeatureFlag" },
      });
      expect(classify({ body: JSON.stringify([read(1), read(2)]) })).toMatchObject({ kind: "read" });
      expect(classify({ body: JSON.stringify([read(1), 5]) })).toMatchObject({
        kind: "unclassifiable",
        reason: "unsupported-envelope",
      });
    });
  });
});
