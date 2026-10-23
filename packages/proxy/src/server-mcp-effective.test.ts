// Live-proxy proof that, under an effective proxy root, the MCP operation
// policy comes from the selected effective policy generation: the legacy
// separately mounted file is ignored, a generation whose MCP payload is
// truncated keeps the last valid policy, and the next valid generation
// reclaims it.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { EFFECTIVE_CONTROL_COMPILER_VERSION } from "@runfree/runtime-contracts/effective-control";
import { validateNetworkPolicy } from "@runfree/runtime-contracts/network-policy";
import {
  httpsViaProxy,
  startHttpsUpstream,
  startProxy,
  tmp,
  waitUntil,
} from "./server.test-harness.ts";

function digest(source: string): string {
  return `sha256:${crypto.createHash("sha256").update(source).digest("hex")}`;
}

// The host allows writes, so without an MCP operation policy every MCP POST
// is forwarded; only the MCP policy's tool rules can refuse `dropTable`.
const NETWORK_POLICY = {
  hosts: ["127.0.0.1"],
  tokens: {
    example: {
      description: "Example token",
      credentials: [{ host: "127.0.0.1", header: "Authorization", scheme: "bearer", pathPrefix: "/mcp" }],
    },
  },
  requests: { "127.0.0.1": { writeAction: "allow" } },
};

function mcpPolicy(dropTable: "allow" | "deny") {
  return {
    schemaVersion: 1,
    servers: [{
      id: "codex:local",
      agent: "codex",
      name: "local",
      source: "user",
      host: "127.0.0.1",
      path: "/mcp",
      tools: { dropTable: { writeAction: dropTable } },
    }],
  };
}

let generationCounter = 0;

function publishGeneration(root: string, mcpSource: string, mcpDigestSource = mcpSource): string {
  generationCounter += 1;
  const controlGeneration = digest(`generation-${generationCounter}-${Date.now()}`);
  const directory = path.join(root, "generations", controlGeneration.slice("sha256:".length));
  fs.mkdirSync(directory, { recursive: true });
  const networkSource = `${JSON.stringify(NETWORK_POLICY, null, 2)}\n`;
  const oauthSource = `${JSON.stringify({ providers: {} }, null, 2)}\n`;
  fs.writeFileSync(path.join(directory, "network-policy.json"), networkSource);
  fs.writeFileSync(path.join(directory, "oauth-mediation-policy.json"), oauthSource);
  fs.writeFileSync(path.join(directory, "mcp-operation-policy.json"), mcpSource);
  const manifestSource = `${JSON.stringify({
    schemaVersion: 1,
    compilerVersion: EFFECTIVE_CONTROL_COMPILER_VERSION,
    controlGeneration,
    policyGeneration: validateNetworkPolicy(NETWORK_POLICY).generation,
    files: {
      "network-policy.json": digest(networkSource),
      "oauth-mediation-policy.json": digest(oauthSource),
      "mcp-operation-policy.json": digest(mcpDigestSource),
    },
  }, null, 2)}\n`;
  fs.writeFileSync(path.join(directory, "manifest.json"), manifestSource);
  const activePath = path.join(root, "active.json");
  const tempPath = `${activePath}.tmp`;
  fs.writeFileSync(tempPath, `${JSON.stringify({
    schemaVersion: 1,
    controlGeneration,
    proxyManifestDigest: digest(manifestSource),
    hostManifestDigest: digest("host"),
  }, null, 2)}\n`);
  fs.renameSync(tempPath, activePath);
  return controlGeneration;
}

function toolCall(name: string): string {
  return JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: {} } });
}

describe("proxy server MCP operation policy from the effective generation", () => {
  test("ignores the legacy mounted file, keeps the last valid policy over a truncated payload, and reclaims on the next generation", async () => {
    const root = fs.mkdtempSync(path.join(tmp, "mcp-effective-root-"));
    publishGeneration(root, `${JSON.stringify(mcpPolicy("deny"), null, 2)}\n`);
    // A stale legacy file that would allow the tool: it must not be read.
    const legacyPath = path.join(fs.mkdtempSync(path.join(tmp, "mcp-legacy-")), "mcp-operation-policy.json");
    fs.writeFileSync(legacyPath, `${JSON.stringify(mcpPolicy("allow"))}\n`);

    const upstream = await startHttpsUpstream();
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_EFFECTIVE_PROXY_ROOT: root,
        RUNFREE_MCP_OPERATION_POLICY_PATH: legacyPath,
      },
      policy: NETWORK_POLICY,
      secretFiles: { example: "real-proxy-token\n" },
    });
    const call = () => httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/mcp",
      headers: { "content-type": "application/json" },
      body: toolCall("dropTable"),
    });

    expect((await call()).statusCode).toBe(403);
    expect(upstream.requests).toHaveLength(0);

    // A torn payload: new bytes cut short. The digest names the full bytes,
    // so the whole generation is refused and the deny stays in force.
    const allowSource = `${JSON.stringify(mcpPolicy("allow"), null, 2)}\n`;
    publishGeneration(root, allowSource.slice(0, 60), allowSource);
    await waitUntil(() => proxy.output().includes("policy reload failed"), "refused truncated generation");
    expect((await call()).statusCode).toBe(403);
    expect(upstream.requests).toHaveLength(0);

    // Reclaim: the next valid generation applies without a restart.
    publishGeneration(root, allowSource);
    await waitUntil(() => /proxy: policy reloaded, .*mcp_operation_generation=sha256:/.test(proxy.output()), "valid generation reload");
    expect((await call()).statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBe("Bearer real-proxy-token");
  }, 30_000);
});
