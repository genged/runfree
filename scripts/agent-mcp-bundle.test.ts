// The committed portable MCP bundle: consistency with its sources and pins,
// and behavior of the shipped bytes (not the TypeScript sources).

import { type ChildProcessWithoutNullStreams, spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import {
  NODE_REPL_LIMITS,
  NODE_REPL_MESSAGES,
  PORTABLE_MCP_CONTRACT_VERSIONS,
  PORTABLE_MCP_SERVER_IDS,
  RUNFREE_MCP_BUNDLE_VERSION,
} from "../packages/agent-runtime/src/mcp/capabilities.ts";
import { BoundedOutput, parseJsArguments } from "../packages/agent-runtime/src/mcp/node-repl-server.ts";
import { PORTABLE_MCP_CATALOG } from "../packages/cli/src/runtime/portable-mcp.ts";
import {
  ALLOWED_BUNDLE_LICENSES,
  assertBundlePackagePolicy,
  FORBIDDEN_BUNDLE_PACKAGES,
  lockfileIntegrity,
  MCP_BUNDLE_DIR,
  MCP_BUNDLE_ENTRIES,
  type McpBundleManifest,
  mcpSourceDigests,
  REQUIRED_BUN_VERSION,
  repoRoot,
  sha256,
} from "./bundle-agent-mcp.ts";
import { RUNTIME_ASSET_DESCRIPTORS } from "./build-runtime.ts";

const manifest = JSON.parse(fs.readFileSync(path.join(MCP_BUNDLE_DIR, "manifest.json"), "utf8")) as McpBundleManifest;
const DISPATCHER = path.join(MCP_BUNDLE_DIR, "runfree-mcp.mjs");

describe("committed portable MCP bundle manifest", () => {
  test("records the current sources, found by glob rather than by the manifest", () => {
    expect(manifest.sources).toEqual(mcpSourceDigests());
  });

  test("records the bytes of every bundle file and nothing else", () => {
    const expectedFiles = MCP_BUNDLE_ENTRIES.map((entry) => `${entry}.mjs`).sort();
    expect(Object.keys(manifest.files).sort()).toEqual(expectedFiles);
    expect(fs.readdirSync(MCP_BUNDLE_DIR).sort()).toEqual([...expectedFiles, "manifest.json"].sort());
    for (const [name, digest] of Object.entries(manifest.files)) {
      expect(sha256(fs.readFileSync(path.join(MCP_BUNDLE_DIR, name))), name).toBe(digest);
    }
  });

  test("pins every bundled package to the lockfile with an accepted license and no HTTP transport package", () => {
    expect(manifest.packages.map((entry) => entry.name)).toContain("@modelcontextprotocol/sdk");
    for (const entry of manifest.packages) {
      expect(lockfileIntegrity(entry.name, entry.version), `${entry.name}@${entry.version}`).toBe(entry.integrity);
      expect(ALLOWED_BUNDLE_LICENSES as readonly string[]).toContain(entry.license);
      expect(FORBIDDEN_BUNDLE_PACKAGES as readonly string[]).not.toContain(entry.name);
    }
    const sdk = JSON.parse(fs.readFileSync(path.join(repoRoot, "packages", "agent-runtime", "package.json"), "utf8")) as { devDependencies: Record<string, string> };
    expect(manifest.packages.find((entry) => entry.name === "@modelcontextprotocol/sdk")?.version).toBe(sdk.devDependencies["@modelcontextprotocol/sdk"]);
  });

  test("the bundle script refuses an unaccepted license or an HTTP transport package", () => {
    const base = { integrity: "sha512-x", version: "1.0.0" };
    expect(() => assertBundlePackagePolicy([{ ...base, name: "copyleft", license: "GPL-3.0" }])).toThrow("not in the accepted list");
    expect(() => assertBundlePackagePolicy([{ ...base, name: "unknown-license", license: "UNKNOWN" }])).toThrow("not in the accepted list");
    expect(() => assertBundlePackagePolicy([{ ...base, name: "express", license: "MIT" }])).toThrow("must not ship");
    expect(() => assertBundlePackagePolicy(manifest.packages)).not.toThrow();
  });

  test("agrees with the compiled server ids, the CLI catalog, and the bundle version", () => {
    expect(manifest.bundleVersion).toBe(RUNFREE_MCP_BUNDLE_VERSION);
    expect(manifest.capabilities).toEqual(PORTABLE_MCP_SERVER_IDS.map((id) => ({ id, contractVersion: PORTABLE_MCP_CONTRACT_VERSIONS[id] })));
    expect(Object.keys(PORTABLE_MCP_CATALOG).sort()).toEqual([...PORTABLE_MCP_SERVER_IDS].sort());
    for (const id of PORTABLE_MCP_SERVER_IDS) {
      expect(PORTABLE_MCP_CATALOG[id].contractVersion).toBe(PORTABLE_MCP_CONTRACT_VERSIONS[id]);
      expect(PORTABLE_MCP_CATALOG[id].bundleVersion).toBe(RUNFREE_MCP_BUNDLE_VERSION);
      expect(PORTABLE_MCP_CATALOG[id].launcher.args).toEqual([id]);
    }
  });

  test("was built by the Bun version CI pins", () => {
    const verify = fs.readFileSync(path.join(repoRoot, ".github", "workflows", "verify.yml"), "utf8");
    expect(/RUNFREE_BUN_VERSION:\s*(\S+)/.exec(verify)?.[1]).toBe(REQUIRED_BUN_VERSION);
    expect(verify).toContain("pnpm run bundle:agent-mcp -- --check");
    expect(manifest.bundler).toEqual({ name: "bun", version: REQUIRED_BUN_VERSION });
  });

  test("ships every bundle file and the dispatcher wrapper as agent-image assets", () => {
    for (const name of [...Object.keys(manifest.files), "manifest.json"]) {
      expect(RUNTIME_ASSET_DESCRIPTORS.find((descriptor) => descriptor.path === `agent/mcp/${name}`)?.roles).toEqual(["agent-image"]);
    }
    expect(RUNTIME_ASSET_DESCRIPTORS.find((descriptor) => descriptor.path === "agent/runfree-mcp.sh")?.roles).toEqual(["agent-image"]);
  });
});

describe("node-repl argument and output bounds", () => {
  test("parseJsArguments accepts the Codex-compatible shape and refuses anything else", () => {
    expect(parseJsArguments({ code: "1", timeout_ms: 5, title: "t" })).toEqual({ code: "1", timeoutMs: 5 });
    expect(parseJsArguments({ code: "1" })).toEqual({ code: "1", timeoutMs: NODE_REPL_LIMITS.defaultTimeoutMs });
    expect(parseJsArguments({})).toBe("js requires a string code argument");
    expect(parseJsArguments({ code: "1", extra: true })).toBe('js does not accept argument "extra"');
    expect(parseJsArguments({ code: "1", timeout_ms: 0 })).toMatch(/timeout_ms must be an integer/);
    expect(parseJsArguments({ code: "1", timeout_ms: 1.5 })).toMatch(/timeout_ms must be an integer/);
    expect(parseJsArguments({ code: "1", timeout_ms: NODE_REPL_LIMITS.maxTimeoutMs + 1 })).toMatch(/timeout_ms must be an integer/);
    expect(parseJsArguments({ code: "1", title: "x".repeat(NODE_REPL_LIMITS.maxTitleChars + 1) })).toMatch(/title must be/);
    expect(parseJsArguments({ code: "é".repeat(NODE_REPL_LIMITS.maxCodeBytes / 2 + 1) })).toMatch(/code exceeds/);
    expect(parseJsArguments(["code"])).toBe("js arguments must be an object");
  });

  test("BoundedOutput caps UTF-8 bytes on a character boundary and marks truncation", () => {
    const output = new BoundedOutput(5);
    output.append("ab");
    output.append("cdé");
    output.append("more");
    expect(output.text()).toBe(`abcd\n${NODE_REPL_MESSAGES.truncated}`);
    expect(Buffer.byteLength(output.text().split("\n")[0], "utf8")).toBeLessThanOrEqual(5);
  });
});

type ToolResult = { content: Array<{ text: string; type: string }>; isError?: boolean };

class McpClient {
  private buffer = "";
  private nextId = 1;
  private readonly waiting = new Map<number, (message: Record<string, unknown>) => void>();
  readonly stdoutNoise: string[] = [];

  constructor(readonly child: ChildProcessWithoutNullStreams) {
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      this.buffer += chunk;
      for (let index = this.buffer.indexOf("\n"); index >= 0; index = this.buffer.indexOf("\n")) {
        const line = this.buffer.slice(0, index);
        this.buffer = this.buffer.slice(index + 1);
        let message: Record<string, unknown>;
        try {
          message = JSON.parse(line) as Record<string, unknown>;
        } catch {
          this.stdoutNoise.push(line);
          continue;
        }
        if (typeof message.id === "number") this.waiting.get(message.id)?.(message);
      }
    });
  }

  request(method: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    const id = this.nextId++;
    return new Promise((resolve) => {
      this.waiting.set(id, resolve);
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }

  async initialize(): Promise<Record<string, unknown>> {
    const result = await this.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } });
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    return result;
  }

  async call(name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
    const response = await this.request("tools/call", { name, arguments: args });
    return response.result as ToolResult;
  }

  async js(code: string, extra: Record<string, unknown> = {}): Promise<ToolResult> {
    return this.call("js", { code, ...extra });
  }
}

function text(result: ToolResult): string {
  return result.content.map((entry) => entry.text).join("");
}

// A killed process whose parent is gone may stay a zombie until init reaps
// it; a zombie runs nothing, so it counts as dead.
function processAlive(pid: number): boolean {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    return stat.slice(stat.lastIndexOf(")") + 2, stat.lastIndexOf(")") + 3) !== "Z";
  } catch {
    try {
      process.kill(pid, 0);
      return process.platform !== "linux";
    } catch {
      return false;
    }
  }
}

async function waitUntil(predicate: () => boolean, timeoutMs = 5000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return predicate();
}

describe("shipped node-repl server", () => {
  const children: ChildProcessWithoutNullStreams[] = [];
  const dirs: string[] = [];

  afterEach(() => {
    for (const child of children.splice(0)) child.kill("SIGKILL");
    for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  function start(): { client: McpClient; workspace: string } {
    const workspace = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-node-repl-ws-")));
    dirs.push(workspace);
    const child = spawn(process.execPath, [DISPATCHER, "node-repl"], { cwd: workspace, stdio: ["pipe", "pipe", "pipe"] });
    children.push(child);
    return { client: new McpClient(child), workspace };
  }

  test("the dispatcher accepts only one compiled capability id", () => {
    for (const args of [[], ["node_repl"], ["../node-repl"], ["node-repl", "extra"], ["--help"], ["computer-use"]]) {
      const result = spawnSync(process.execPath, [DISPATCHER, ...args], { encoding: "utf8", timeout: 10_000 });
      expect(result.status, JSON.stringify(args)).toBe(64);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("supported capabilities: node-repl");
    }
  });

  test("the self-check passes against the committed bundle", () => {
    const result = spawnSync(process.execPath, [path.join(MCP_BUNDLE_DIR, "self-check.mjs")], { encoding: "utf8", timeout: 60_000 });
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`bundle ${manifest.bundleVersion}`);
  });

  test("answers initialize and tools/list with the Codex-compatible tool surface", async () => {
    const { client } = start();
    const init = await client.initialize();
    expect((init.result as { serverInfo: unknown }).serverInfo).toEqual({ name: "runfree-node-repl", version: RUNFREE_MCP_BUNDLE_VERSION });
    const list = await client.request("tools/list", {});
    const tools = (list.result as { tools: Array<{ name: string; inputSchema: { required?: string[] } }> }).tools;
    expect(tools.map((tool) => tool.name)).toEqual(["js", "js_reset"]);
    expect(tools[0].inputSchema.required).toEqual(["code"]);
    const unknown = await client.call("js_add_node_module_dir", { dir: "/tmp" });
    expect(unknown.isError).toBe(true);
    expect(text(unknown)).toContain("unknown tool");
  }, 30_000);

  test("keeps state across calls, supports top-level await, and never corrupts the MCP stream", async () => {
    const { client, workspace } = start();
    await client.initialize();
    expect(text(await client.js("let counter = 40; counter += 1"))).toBe("41");
    expect(text(await client.js("counter + 1"))).toBe("42");
    expect(text(await client.js("console.log('hello'); process.stdout.write('raw\\n'); nodeRepl.write('done')"))).toBe("hello\nraw\ndone");
    expect(text(await client.js("globalThis.later = await Promise.resolve(7); nodeRepl.write(String(later))"))).toBe("7");
    expect(text(await client.js("later * 6"))).toBe("42");
    expect(text(await client.js("return await Promise.resolve('returned')"))).toBe("returned");
    expect(text(await client.js("nodeRepl.write(nodeRepl.cwd)"))).toBe(workspace);
    await client.js("require('node:fs').writeFileSync('from-repl.txt', 'written')");
    expect(fs.readFileSync(path.join(workspace, "from-repl.txt"), "utf8")).toBe("written");
    expect(text(await client.js("return (await import('node:path')).posix.join('a', 'b')"))).toBe("a/b");
    const error = await client.js("throw new Error('boom')");
    expect(error.isError).toBe(true);
    expect(text(error)).toContain("Error: boom");
    expect(text(await client.js("counter"))).toBe("41");
    expect(text(await client.js("typeof process.send"))).toBe("undefined");
    expect(client.stdoutNoise).toEqual([]);
  }, 30_000);

  test("a timeout kills the kernel and its subprocesses, resets state, and the next call works", async () => {
    const { client } = start();
    await client.initialize();
    await client.js("globalThis.kept = 1");
    const pid = Number(text(await client.js("globalThis.sleeper = require('node:child_process').spawn('sleep', ['300']); String(sleeper.pid)")));
    expect(processAlive(pid)).toBe(true);
    const timedOut = await client.js("while (true) {}", { timeout_ms: 300 });
    expect(timedOut).toEqual({ content: [{ type: "text", text: NODE_REPL_MESSAGES.timeout }], isError: true });
    expect(await waitUntil(() => !processAlive(pid))).toBe(true);
    expect(text(await client.js("typeof kept"))).toBe("undefined");
  }, 30_000);

  test("js_reset discards state and a kernel crash is reported as a tool error", async () => {
    const { client } = start();
    await client.initialize();
    await client.js("globalThis.kept = 1");
    expect(text(await client.call("js_reset"))).toBe(NODE_REPL_MESSAGES.reset);
    expect(text(await client.js("typeof kept"))).toBe("undefined");
    const crashed = await client.js("process.exit(3)");
    expect(crashed.isError).toBe(true);
    expect(text(crashed)).toContain("js kernel exited unexpectedly (exit code 3)");
    expect(text(await client.js("1 + 1"))).toBe("2");
  }, 30_000);

  test("bounds request and output sizes", async () => {
    const { client } = start();
    await client.initialize();
    const tooBig = await client.js("x".repeat(NODE_REPL_LIMITS.maxCodeBytes + 1));
    expect(tooBig.isError).toBe(true);
    expect(text(tooBig)).toContain("js code exceeds");
    const flood = await client.js("nodeRepl.write('y'.repeat(3 * 1024 * 1024)); 'tail'");
    const body = text(flood);
    expect(Buffer.byteLength(body, "utf8")).toBeLessThanOrEqual(NODE_REPL_LIMITS.maxOutputBytes + 200);
    expect(body).toContain(NODE_REPL_MESSAGES.truncated);
    const bigValue = await client.js("'z'.repeat(3 * 1024 * 1024)");
    expect(Buffer.byteLength(text(bigValue), "utf8")).toBeLessThanOrEqual(NODE_REPL_LIMITS.maxOutputBytes + 200);
    expect(text(await client.js("'still alive'"))).toBe("still alive");
  }, 30_000);
});
