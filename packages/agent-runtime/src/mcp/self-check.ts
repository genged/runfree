// Portable MCP bundle self-check. The agent image build runs it with no
// network (`RUN --network=none`). It proves that the installed files match the
// manifest, that the dispatcher refuses an unknown capability, and that the
// node-repl server starts, answers MCP initialize and tools/list with the
// manifest's version, and runs one `js` call.
//
// Usage: node self-check.mjs [--dispatcher <path>]
// Without --dispatcher it runs the bundled `runfree-mcp.mjs` beside this file
// with the current Node binary.

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

type Manifest = {
  bundleVersion: string;
  capabilities: Array<{ id: string; contractVersion: number }>;
  files: Record<string, string>;
  schemaVersion: number;
};

const here = path.dirname(fileURLToPath(import.meta.url));

function fail(message: string): never {
  process.stderr.write(`runfree-mcp self-check: ${message}\n`);
  process.exit(1);
}

function readManifest(): Manifest {
  const parsed = JSON.parse(fs.readFileSync(path.join(here, "manifest.json"), "utf8")) as Manifest;
  if (parsed.schemaVersion !== 1 || typeof parsed.bundleVersion !== "string" || typeof parsed.files !== "object") {
    fail("manifest.json has an unsupported shape");
  }
  return parsed;
}

function checkFiles(manifest: Manifest): void {
  for (const [name, digest] of Object.entries(manifest.files)) {
    if (name.includes("/") || name.startsWith(".")) fail(`manifest names an unexpected file: ${name}`);
    const bytes = fs.readFileSync(path.join(here, name));
    const actual = `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
    if (actual !== digest) fail(`${name} does not match manifest.json (${actual} != ${digest})`);
  }
}

function dispatcherCommand(argv: readonly string[]): { command: string; args: string[] } {
  if (argv.length === 0) return { command: process.execPath, args: [path.join(here, "runfree-mcp.mjs")] };
  if (argv.length === 2 && argv[0] === "--dispatcher") return { command: argv[1], args: [] };
  fail("usage: self-check.mjs [--dispatcher <path>]");
}

function checkRefusal(dispatcher: { command: string; args: string[] }): void {
  for (const args of [["not-a-capability"], ["node-repl", "extra"], []]) {
    const result = spawnSync(dispatcher.command, [...dispatcher.args, ...args], { encoding: "utf8", timeout: 10_000 });
    if (result.status !== 64) fail(`dispatcher accepted ${JSON.stringify(args)} (status ${result.status})`);
  }
}

async function checkServer(dispatcher: { command: string; args: string[] }, manifest: Manifest): Promise<void> {
  const child = spawn(dispatcher.command, [...dispatcher.args, "node-repl"], { stdio: ["pipe", "pipe", "inherit"] });
  const responses = new Map<number, (value: Record<string, unknown>) => void>();
  let buffer = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    buffer += chunk;
    for (let index = buffer.indexOf("\n"); index >= 0; index = buffer.indexOf("\n")) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      if (line.trim() === "") continue;
      const message = JSON.parse(line) as Record<string, unknown>;
      if (typeof message.id === "number") responses.get(message.id)?.(message);
    }
  });
  const timer = setTimeout(() => {
    child.kill("SIGKILL");
    fail("node-repl server did not answer within 30 seconds");
  }, 30_000);
  let nextId = 1;
  const request = (method: string, params: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const id = nextId++;
    return new Promise((resolve) => {
      responses.set(id, resolve);
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  };

  const init = await request("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "runfree-self-check", version: manifest.bundleVersion },
  });
  const serverInfo = (init.result as { serverInfo?: { version?: string } } | undefined)?.serverInfo;
  if (serverInfo?.version !== manifest.bundleVersion) {
    fail(`server version ${String(serverInfo?.version)} does not match manifest ${manifest.bundleVersion}`);
  }
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
  const list = await request("tools/list", {});
  const names = ((list.result as { tools?: Array<{ name: string }> } | undefined)?.tools ?? []).map((tool) => tool.name).sort();
  if (JSON.stringify(names) !== JSON.stringify(["js", "js_reset"])) fail(`unexpected tools: ${names.join(", ")}`);
  const call = await request("tools/call", { name: "js", arguments: { code: "nodeRepl.write(String(6 * 7))" } });
  const result = call.result as { content?: Array<{ text?: string }>; isError?: boolean } | undefined;
  if (result?.isError || result?.content?.[0]?.text !== "42") fail(`js call returned ${JSON.stringify(call)}`);
  clearTimeout(timer);
  child.stdin.end();
  child.kill("SIGTERM");
}

const manifest = readManifest();
checkFiles(manifest);
const dispatcher = dispatcherCommand(process.argv.slice(2));
checkRefusal(dispatcher);
await checkServer(dispatcher, manifest);
process.stdout.write(`runfree-mcp self-check: ok (bundle ${manifest.bundleVersion}; ${manifest.capabilities.map((entry) => `${entry.id}@${entry.contractVersion}`).join(", ")})\n`);
