import { describe, expect, test } from "vitest";

import {
  effectiveMcpToolAction,
  mcpOperationPolicyGeneration,
  validateMcpOperationPolicy,
} from "./mcp-operation-policy.ts";

describe("MCP operation policy contract", () => {
  test("validates exact MCP endpoints, tool rules, generation, and endpoint overlaps", () => {
    const loaded = validateMcpOperationPolicy({
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
        {
          id: "claude:posthog",
          agent: "claude",
          name: "posthog",
          source: "local",
          host: "mcp.posthog.com",
          path: "/mcp",
          defaultToolWriteAction: "deny",
        },
      ],
    }, "/runtime/mcp-operation-policy.json");

    expect(loaded.generation).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(loaded.generation).toBe(mcpOperationPolicyGeneration(loaded.servers));
    expect(loaded.endpointMap.get("mcp.posthog.com\0/mcp")?.map((server) => server.id)).toEqual([
      "codex:posthog",
      "claude:posthog",
    ]);
    expect(loaded.overlaps).toEqual([
      {
        host: "mcp.posthog.com",
        path: "/mcp",
        serverIds: ["claude:posthog", "codex:posthog"],
      },
    ]);
    expect(effectiveMcpToolAction(loaded.servers[0], "query", "ask")).toBe("allow");
    expect(effectiveMcpToolAction(loaded.servers[0], "deleteFeatureFlag", "ask")).toBe("deny");
    expect(effectiveMcpToolAction(loaded.servers[0], "unknown", "ask")).toBe("ask");
  });

  test("rejects malformed server entries and unsafe tool names", () => {
    expect(() => validateMcpOperationPolicy({
      schemaVersion: 1,
      servers: [
        {
          id: "codex:bad",
          agent: "codex",
          name: "bad",
          source: "user",
          host: "MCP.POSTHOG.COM",
          path: "mcp",
          defaultToolWriteAction: "forever",
          tools: {
            "": { writeAction: "allow" },
          },
        },
        {
          id: "codex:bad",
          agent: "codex",
          name: "bad2",
          source: "project",
          host: "mcp.posthog.com",
          path: "/mcp",
        },
      ],
    })).toThrow(/invalid MCP operation policy/);
  });
});
