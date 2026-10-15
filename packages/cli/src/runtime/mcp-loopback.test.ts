import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { flushWarnings, setOutputWriterForTest } from "../warnings.ts";
import { mcpApprovalPath, mcpInventory } from "./mcp.ts";

// S8: every MCP preparation refusal carries its specific reason into the
// inventory decision, and the inventory prints exactly one warning line for it.
const REFUSED: Record<string, { config: Record<string, unknown>; reason: string }> = {
  badUrl: { config: { type: "http", url: "not a url" }, reason: "invalid URL" },
  plainHttp: { config: { type: "http", url: "http://insecure.example.com/mcp" }, reason: "remote HTTP MCP must use https" },
  ipLiteral: { config: { type: "http", url: "https://127.0.0.1/mcp" }, reason: "HTTPS MCP endpoint must be a hostname, not an IP address" },
  helper: { config: { type: "http", url: "https://x.example.com/mcp", headersHelper: "x" }, reason: "headersHelper would execute a host command" },
  hostCommand: { config: { command: "/usr/bin/tool" }, reason: "local stdio command must be installed in the container PATH" },
};

describe("structured MCP refusal reasons", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let stateDir: string;
  let output: string[];

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-loopback-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    stateDir = path.join(tmp, "state");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.mkdirSync(path.join(hostHome, ".codex"), { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true });
    const mcpServers = Object.fromEntries(Object.entries(REFUSED).map(([name, { config }]) => [name, config]));
    fs.writeFileSync(path.join(hostHome, ".claude.json"), `${JSON.stringify({ mcpServers }, null, 2)}\n`);
    flushWarnings();
    output = [];
    setOutputWriterForTest((line) => output.push(line));
  });

  afterEach(() => {
    flushWarnings();
    setOutputWriterForTest(undefined);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const env = () => ({ HOME: hostHome, CODEX_HOME: path.join(hostHome, ".codex") });

  function warnings(): string[] {
    flushWarnings();
    const lines = output;
    output = [];
    return lines;
  }

  function inventory() {
    return mcpInventory({ projectRoot, env: env(), approvalPath: mcpApprovalPath(stateDir) });
  }

  test("each refusal reports its specific reason and is excluded from generated config", () => {
    const entries = inventory().entries.filter((entry) => entry.agent === "claude");
    warnings();
    const byName = new Map(entries.map((entry) => [entry.name, entry]));
    for (const [name, { reason }] of Object.entries(REFUSED)) {
      const entry = byName.get(name);
      expect(entry?.decision, name).toEqual({ status: "unsupported", reason });
      expect(entry?.target, name).toBe("excluded");
    }
  });

  test("each refusal prints exactly one warning line per inventory call", () => {
    for (let call = 0; call < 2; call += 1) {
      inventory();
      const lines = warnings();
      for (const [name, { reason }] of Object.entries(REFUSED)) {
        const matching = lines.filter((line) => line.includes(`server ${name} `));
        expect(matching, `${name} call ${call}`).toHaveLength(1);
        expect(matching[0]?.endsWith(` runfree warning: mcp: skipped claude server ${name} reason=${reason}`), `${name} call ${call}`).toBe(true);
      }
    }
  });

  test("inventory JSON carries the reason", () => {
    const json = JSON.stringify(inventory().entries);
    warnings();
    for (const { reason } of Object.values(REFUSED)) expect(json).toContain(reason);
  });
});
