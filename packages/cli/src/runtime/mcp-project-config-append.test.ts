import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { flushWarnings, setOutputWriterForTest } from "../warnings.ts";
import { mcpApprovalPath, mcpInventory } from "./mcp.ts";

// A server appended to the end of `.mcp.json` must show up as a project entry
// whatever the file's formatting. The base file is the reported one: mixed
// indentation, the last entry indented differently from the rest.
const REPORTED_MCP_JSON = `{
  "mcpServers": {
    "astro": {
      "type": "http",
      "url": "http://127.0.0.1:8089/mcp"
    },
    "context7": {
        "type": "http",
      "url": "https://mcp.context7.com/mcp"
    },
    "deepwiki": {
        "type": "http",
      "url": "https://mcp.deepwiki.com/mcp"
    },
    "meta_ads": {
      "type": "http",
      "url": "https://mcp.facebook.com/ads"
    },
    "posthog": {
      "type": "http",
      "url": "https://mcp.posthog.com/mcp"
    },
    "revenuecat": {
      "type": "http",
      "url": "https://mcp.revenuecat.ai/mcp"
    },
    "supabase": {
      "type": "http",
      "url": "https://mcp.supabase.com/mcp?project_ref=oivanwyokyiajtmnqomx&read_only=true"
    },
    "vercel": {
      "type": "http",
      "url": "https://mcp.vercel.com"
    },
      "sentry": {
          "type": "http",
          "url": "https://mcp.sentry.dev/mcp/everhue"
      }
  }
}
`;

const REPORTED_NAMES = ["astro", "context7", "deepwiki", "meta_ads", "posthog", "revenuecat", "supabase", "vercel", "sentry"];

describe(".mcp.json server appended at the end", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let stateDir: string;
  let output: string[];

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-append-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    stateDir = path.join(tmp, "state");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.mkdirSync(path.join(hostHome, ".codex"), { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true });
    flushWarnings();
    output = [];
    setOutputWriterForTest((line) => output.push(line));
  });

  afterEach(() => {
    flushWarnings();
    setOutputWriterForTest(undefined);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const mcpJsonPath = () => path.join(projectRoot, ".mcp.json");

  function projectClaudeNames(): string[] {
    const inventory = mcpInventory({
      projectRoot,
      env: { HOME: hostHome, CODEX_HOME: path.join(hostHome, ".codex") },
      approvalPath: mcpApprovalPath(stateDir),
    });
    return inventory.entries
      .filter((entry) => entry.agent === "claude" && entry.source === "project")
      .map((entry) => entry.name);
  }

  function warnings(): string[] {
    flushWarnings();
    const lines = output;
    output = [];
    return lines;
  }

  test("the reported file lists every server, the oddly indented last one included", () => {
    fs.writeFileSync(mcpJsonPath(), REPORTED_MCP_JSON);
    expect(projectClaudeNames()).toEqual(REPORTED_NAMES);
  });

  // Each variant appends `posthog` as the last server of a file that already
  // has `sentry`, in a different format.
  const appendVariants: Record<string, string> = {
    "two-space indent": JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" }, posthog: { type: "http", url: "https://mcp.posthog.com/mcp" } } }, null, 2),
    "tab indent": JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" }, posthog: { type: "http", url: "https://mcp.posthog.com/mcp" } } }, null, "\t"),
    "minified, no trailing newline": JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" }, posthog: { type: "http", url: "https://mcp.posthog.com/mcp" } } }),
    "CRLF line endings": JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" }, posthog: { type: "http", url: "https://mcp.posthog.com/mcp" } } }, null, 2).replaceAll("\n", "\r\n"),
    "last entry indented deeper than the rest": `{
  "mcpServers": {
    "sentry": { "type": "http", "url": "https://mcp.sentry.dev/mcp" },
          "posthog": {
                "type": "http",
        "url": "https://mcp.posthog.com/mcp"
          }
  }
}`,
    "last entry on the closing-brace line": `{"mcpServers": {"sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"},
"posthog": {"type": "http", "url": "https://mcp.posthog.com/mcp"}}}`,
    "trailing whitespace and blank lines after the root": `${JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" }, posthog: { type: "http", url: "https://mcp.posthog.com/mcp" } } }, null, 2)}\n\n   \n`,
    "unicode escape in the name": `{"mcpServers": {"sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"}, "post\\u0068og": {"type": "http", "url": "https://mcp.posthog.com/mcp"}}}`,
    "other top-level keys after mcpServers": JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" }, posthog: { type: "http", url: "https://mcp.posthog.com/mcp" } }, other: { posthog: {} } }, null, 2),
    "extra fields on the appended entry": JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" }, posthog: { type: "http", url: "https://mcp.posthog.com/mcp", headers: {} } } }, null, 2),
    "url-only entry, no type": JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" }, posthog: { url: "https://mcp.posthog.com/mcp" } } }, null, 2),
  };

  for (const [label, content] of Object.entries(appendVariants)) {
    test(`detects an appended server: ${label}`, () => {
      fs.writeFileSync(mcpJsonPath(), content);
      expect(projectClaudeNames()).toEqual(["sentry", "posthog"]);
      expect(warnings().filter((line) => line.includes(".mcp.json"))).toEqual([]);
    });
  }

  test("a UTF-8 BOM is not silently read as an empty server list", () => {
    fs.writeFileSync(mcpJsonPath(), `﻿${JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" }, posthog: { type: "http", url: "https://mcp.posthog.com/mcp" } } })}`);
    const names = projectClaudeNames();
    const fileWarnings = warnings().filter((line) => line.includes(".mcp.json"));
    // Either every server is found, or the read is refused with a warning.
    expect(names.length === 2 || fileWarnings.length > 0, `names=${names.join(",")} warnings=${fileWarnings.join("|")}`).toBe(true);
  });

  // Invalid JSON an editor can leave behind after an append. None may drop
  // servers without a warning.
  const brokenVariants: Record<string, string> = {
    "trailing comma after the appended entry": `{"mcpServers": {"sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"}, "posthog": {"type": "http", "url": "https://mcp.posthog.com/mcp"},}}`,
    "missing comma before the appended entry": `{"mcpServers": {"sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"} "posthog": {"type": "http", "url": "https://mcp.posthog.com/mcp"}}}`,
    "JSONC line comment": `{"mcpServers": {"sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"},\n// new\n"posthog": {"type": "http", "url": "https://mcp.posthog.com/mcp"}}}`,
    "appended after the closing brace": `{"mcpServers": {"sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"}}}\n"posthog": {"type": "http", "url": "https://mcp.posthog.com/mcp"}`,
  };

  for (const [label, content] of Object.entries(brokenVariants)) {
    test(`warns instead of silently dropping servers: ${label}`, () => {
      fs.writeFileSync(mcpJsonPath(), content);
      const names = projectClaudeNames();
      const fileWarnings = warnings().filter((line) => line.includes(".mcp.json"));
      expect(names.includes("posthog") || fileWarnings.length > 0, `names=${names.join(",")}`).toBe(true);
    });
  }

  test("the appended entry placed outside mcpServers is not reported as a server", () => {
    // The closing brace of mcpServers lands before the new entry: valid JSON,
    // but posthog is a top-level key. This is the shape an append can produce.
    fs.writeFileSync(mcpJsonPath(), `{
  "mcpServers": {
    "sentry": { "type": "http", "url": "https://mcp.sentry.dev/mcp" }
  },
  "posthog": { "type": "http", "url": "https://mcp.posthog.com/mcp" }
}`);
    expect(projectClaudeNames()).toEqual(["sentry"]);
  });

  test("a duplicate key keeps the last value and its first position", () => {
    fs.writeFileSync(mcpJsonPath(), `{"mcpServers": {"posthog": {"type": "http", "url": "https://old.example/mcp"}, "sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"}, "posthog": {"type": "http", "url": "https://mcp.posthog.com/mcp"}}}`);
    expect(projectClaudeNames()).toEqual(["posthog", "sentry"]);
  });

  test("an append is seen by the next read in the same process", () => {
    fs.writeFileSync(mcpJsonPath(), JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" } } }, null, 2));
    expect(projectClaudeNames()).toEqual(["sentry"]);
    const inode = fs.statSync(mcpJsonPath()).ino;
    const mtime = fs.statSync(mcpJsonPath()).mtime;
    // In-place rewrite, same inode, same mtime: an mtime- or inode-keyed cache would miss it.
    fs.writeFileSync(mcpJsonPath(), JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" }, posthog: { type: "http", url: "https://mcp.posthog.com/mcp" } } }, null, 2));
    fs.utimesSync(mcpJsonPath(), mtime, mtime);
    expect(fs.statSync(mcpJsonPath()).ino).toBe(inode);
    expect(projectClaudeNames()).toEqual(["sentry", "posthog"]);
  });

  test("an atomic-rename save (new inode) is seen by the next read", () => {
    fs.writeFileSync(mcpJsonPath(), JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" } } }));
    expect(projectClaudeNames()).toEqual(["sentry"]);
    const staged = path.join(projectRoot, ".mcp.json.tmp");
    fs.writeFileSync(staged, JSON.stringify({ mcpServers: { sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" }, posthog: { type: "http", url: "https://mcp.posthog.com/mcp" } } }));
    fs.renameSync(staged, mcpJsonPath());
    expect(projectClaudeNames()).toEqual(["sentry", "posthog"]);
  });

  test("reordering the reported file keeps the same server set", () => {
    fs.writeFileSync(mcpJsonPath(), REPORTED_MCP_JSON);
    const before = projectClaudeNames();
    const parsed = JSON.parse(REPORTED_MCP_JSON) as { mcpServers: Record<string, unknown> };
    const reversed = Object.fromEntries(Object.entries(parsed.mcpServers).reverse());
    fs.writeFileSync(mcpJsonPath(), JSON.stringify({ mcpServers: reversed }, null, 2));
    expect([...projectClaudeNames()].sort()).toEqual([...before].sort());
  });
});
