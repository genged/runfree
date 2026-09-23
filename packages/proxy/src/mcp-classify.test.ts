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
  method?: string;
  path?: string;
}) {
  const body = input.body ?? "";
  return classifyMcpRequestBody({
    bodyText: body,
    contentEncoding: input.contentEncoding,
    contentLength: Buffer.byteLength(body),
    contentType: input.contentType ?? "application/json",
    globalWriteAction: "ask",
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
});
