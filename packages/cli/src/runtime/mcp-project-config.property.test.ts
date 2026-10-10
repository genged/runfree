import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { propertyParameters } from "../../../../tests/support/property.ts";
import { flushWarnings, setOutputWriterForTest } from "../warnings.ts";
import { mcpApprovalPath, mcpInventory, prepareMcpRuntime, saveMcpApproval } from "./mcp.ts";

// Properties of reading project MCP config: every server written to
// `.mcp.json` is an inventory entry however the JSON is formatted, a name
// outside the agent's own rule is listed but skipped, a file that is not valid
// JSON is never read as a shorter server list without a warning, no name makes
// a launch throw, and no warning carries a control character from the config.
// Example cases live in mcp-project-config-append.test.ts.

type Entry = { name: string; value: unknown };

// The rule as each agent's own `mcp add` states it (Claude Code; codex-cli
// 0.156.1), plus Runfree's length cap and reserved name. Stated here, not
// imported, so the test does not copy the implementation.
const CLAUDE_NAME = /^[A-Za-z0-9_-]{1,128}$/;
const CODEX_NAME = /^[A-Za-z0-9_\-:@/.]{1,128}$/;
const allowed = (agent: "claude" | "codex", name: string) => name !== "__proto__" && (agent === "claude" ? CLAUDE_NAME : CODEX_NAME).test(name);

// Names: arbitrary strings, lone surrogates, names a JS object handles
// specially, terminal escapes, and names that differ only by case or by a
// character an ID slug folds.
const nameArb = fc.oneof(
  { weight: 5, arbitrary: fc.string({ unit: "binary", maxLength: 12 }) },
  { weight: 1, arbitrary: fc.string({ unit: fc.integer({ min: 0xd7f0, max: 0xe010 }).map((code) => String.fromCharCode(code)), maxLength: 4 }) },
  { weight: 2, arbitrary: fc.stringMatching(/^[a-z][a-z0-9_-]{0,10}$/u) },
  { weight: 2, arbitrary: fc.constantFrom("Foo", "foo", "FOO", "-foo", "foo-", "f.oo", "f-oo", "f:oo", "f@oo", "f/oo", "x".repeat(97), `${"x".repeat(96)}y`, "x".repeat(129)) },
  { weight: 1, arbitrary: fc.constantFrom("__proto__", "constructor", "toString", "hasOwnProperty", "", " ", "0", "7", "4294967295", "posthog", "\u001b[2J", "\u001b]52;c;eA==\u0007", "a‮b") },
);

const serverArb = fc.record(
  {
    type: fc.constantFrom("http", "sse", "stdio"),
    url: fc.constantFrom("https://mcp.posthog.com/mcp", "https://mcp.example.com/mcp", "http://127.0.0.1:8089/mcp", "not a url"),
    command: fc.constantFrom("npx", "/usr/bin/tool"),
    headers: fc.dictionary(fc.stringMatching(/^[A-Za-z-]{1,8}$/u), fc.string({ maxLength: 6 }), { maxKeys: 2 }),
    extra: fc.jsonValue({ maxDepth: 2 }),
  },
  { requiredKeys: [] },
);

// Non-object values the reader must skip, not count as servers.
const nonServerArb = fc.oneof(fc.string({ maxLength: 4 }), fc.integer(), fc.boolean(), fc.constant(null), fc.array(fc.integer(), { maxLength: 2 }));

const entryArb: fc.Arbitrary<Entry> = fc.record({
  name: nameArb,
  value: fc.oneof({ weight: 5, arbitrary: serverArb }, { weight: 1, arbitrary: nonServerArb }),
});

const entriesArb = fc.uniqueArray(entryArb, { selector: (entry) => entry.name, maxLength: 8 });

// Whitespace between tokens: what editors and hand edits leave behind.
const gapArb = fc.array(fc.constantFrom(" ", "  ", "\t", "\n", "\r\n", "\n    ", "\n\t\t"), { maxLength: 3 }).map((parts) => parts.join(""));

type Style = { gaps: string[]; escapeNames: boolean[]; trailing: string; otherTopLevel: boolean };

const styleArb: fc.Arbitrary<Style> = fc.record({
  gaps: fc.array(gapArb, { minLength: 64, maxLength: 64 }),
  escapeNames: fc.array(fc.boolean(), { minLength: 16, maxLength: 16 }),
  trailing: fc.constantFrom("", "\n", "\r\n", "\n\n  \n"),
  otherTopLevel: fc.boolean(),
});

function escapeEveryUnit(value: string): string {
  let out = '"';
  for (let index = 0; index < value.length; index += 1) out += `\\u${value.charCodeAt(index).toString(16).padStart(4, "0")}`;
  return `${out}"`;
}

// Hand-rendered JSON so the formatting varies per token and `__proto__` stays
// an ordinary key (an object literal passed to JSON.stringify would not keep it).
function render(entries: Entry[], style: Style): string {
  let gapIndex = 0;
  const gap = () => style.gaps[gapIndex++ % style.gaps.length];
  const nameText = (name: string, index: number) => (style.escapeNames[index % style.escapeNames.length] ? escapeEveryUnit(name) : JSON.stringify(name));
  const members = entries.map((entry, index) => `${gap()}${nameText(entry.name, index)}${gap()}:${gap()}${JSON.stringify(entry.value, null, gap().includes("\t") ? "\t" : 2)}${gap()}`);
  const servers = `{${members.join(",") || gap()}}`;
  const other = style.otherTopLevel ? `,${gap()}"other"${gap()}:${gap()}{"posthog":{"type":"http"}}` : "";
  return `${gap()}{${gap()}"mcpServers"${gap()}:${gap()}${servers}${other}${gap()}}${style.trailing}`;
}

// The same servers as a project `.codex/config.toml`. JSON string escapes are
// valid TOML basic-string escapes; a name TOML cannot hold makes the file
// invalid, which must warn rather than throw.
function renderToml(entries: Entry[]): string {
  return entries
    .filter((entry) => isServer(entry.value))
    .map((entry) => {
      const value = entry.value as { url?: string; command?: string };
      const body = value.url ? `url = ${JSON.stringify(value.url)}` : `command = ${JSON.stringify(value.command ?? "npx")}`;
      return `[mcp_servers.${escapeEveryUnit(entry.name)}]\n${body}\n`;
    })
    .join("\n");
}

const isServer = (value: unknown) => value !== null && typeof value === "object" && !Array.isArray(value);

// Object.entries lists array-index keys first, in numeric order, then the rest
// in insertion order. The oracle states that rule instead of calling it.
const isArrayIndex = (name: string) => /^(?:0|[1-9][0-9]*)$/u.test(name) && Number(name) < 2 ** 32 - 1;

function expectedNames(entries: Entry[]): string[] {
  const names = entries.filter((entry) => isServer(entry.value)).map((entry) => entry.name);
  const indices = names.filter(isArrayIndex).sort((left, right) => Number(left) - Number(right));
  return [...indices, ...names.filter((name) => !isArrayIndex(name))];
}

const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f‪-‮⁦-⁩]/u;

describe("project MCP config reading properties", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let stateDir: string;
  let output: string[] = [];

  beforeAll(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-prop-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    stateDir = path.join(tmp, "state");
    fs.mkdirSync(path.join(projectRoot, ".codex"), { recursive: true });
    fs.mkdirSync(path.join(hostHome, ".codex"), { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true });
    flushWarnings();
    setOutputWriterForTest((line) => output.push(line));
  });

  afterAll(() => {
    flushWarnings();
    setOutputWriterForTest(undefined);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const env = () => ({ HOME: hostHome, CODEX_HOME: path.join(hostHome, ".codex") });
  const approvalPath = () => mcpApprovalPath(stateDir);

  function takeOutput(): string[] {
    flushWarnings();
    const lines = output;
    output = [];
    return lines;
  }

  // Every line printed while reading. Config text must never reach the
  // terminal raw.
  function expectNoControlCharacters(lines: string[], context: string): void {
    for (const line of lines) expect(CONTROL.test(line), `${JSON.stringify(line)} from ${context}`).toBe(false);
  }

  // Writes the file, reads the inventory, and returns the project Claude
  // entries with any `.mcp.json` warning the read printed.
  function read(content: string, toml = "") {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), content);
    fs.writeFileSync(path.join(projectRoot, ".codex", "config.toml"), toml);
    takeOutput();
    const inventory = mcpInventory({ projectRoot, env: env(), approvalPath: approvalPath() });
    const lines = takeOutput();
    expectNoControlCharacters(lines, content);
    const entries = inventory.entries.filter((entry) => entry.agent === "claude" && entry.source === "project");
    return {
      entries,
      inventory,
      names: entries.map((entry) => entry.name),
      warnings: lines.filter((line) => line.includes(".mcp.json")),
    };
  }

  it("P1: every object-valued server in a valid file is an entry, in Object.entries order; a name outside the agent rule is listed and unsupported", () => {
    fc.assert(
      fc.property(entriesArb, styleArb, (entries, style) => {
        const content = render(entries, style);
        const result = read(content);
        expect(result.warnings, content).toEqual([]);
        expect(result.names, content).toEqual(expectedNames(entries));
        for (const entry of result.entries) {
          if (allowed("claude", entry.name)) {
            expect(entry.decision.reason ?? "", `${JSON.stringify(entry.name)} in ${content}`).not.toMatch(/^server name (must|__proto__)/);
          } else {
            expect(entry.decision.status, `${JSON.stringify(entry.name)} in ${content}`).toBe("unsupported");
            expect(entry.target).toBe("excluded");
          }
        }
      }),
      propertyParameters(),
    );
  });

  it("P2: a server appended to the end is found on the next read, under any reformatting", () => {
    fc.assert(
      fc.property(entriesArb, entryArb.filter((entry) => isServer(entry.value)), styleArb, styleArb, (base, added, before, after) => {
        fc.pre(!base.some((entry) => entry.name === added.name));
        const first = read(render(base, before));
        const content = render([...base, added], after);
        const second = read(content);
        expect(second.warnings, content).toEqual([]);
        expect([...second.names].sort(), content).toEqual([...first.names, added.name].sort());
      }),
      propertyParameters(),
    );
  });

  // One edit of a valid file. Deleting or inserting one character, or cutting
  // the file short, is what an interrupted save or a hand edit leaves.
  const editArb = fc.oneof(
    fc.record({ kind: fc.constant("delete" as const), at: fc.nat() }),
    fc.record({ kind: fc.constant("insert" as const), at: fc.nat(), text: fc.constantFrom(",", "}", "{", '"', ":", "/", "//x\n", "]", "﻿", "\u001b[2J") }),
    fc.record({ kind: fc.constant("truncate" as const), at: fc.nat() }),
  );

  function applyEdit(content: string, edit: { kind: "delete" | "insert" | "truncate"; at: number; text?: string }): string {
    const at = edit.at % (content.length + 1);
    if (edit.kind === "delete") return content.slice(0, at) + content.slice(at + 1);
    if (edit.kind === "insert") return content.slice(0, at) + (edit.text ?? "") + content.slice(at);
    return content.slice(0, at);
  }

  function parses(content: string): boolean {
    try {
      JSON.parse(content);
      return true;
    } catch {
      return false;
    }
  }

  it("P3: a file that is not valid JSON always warns; it is never silently read as fewer servers", () => {
    fc.assert(
      fc.property(entriesArb, styleArb, editArb, (entries, style, edit) => {
        const content = applyEdit(render(entries, style), edit);
        // Runfree reads a whitespace-only file as no servers on purpose.
        fc.pre(content.trim() !== "");
        const result = read(content);
        if (!parses(content)) {
          expect(result.warnings.length, content).toBeGreaterThan(0);
          expect(result.names, content).toEqual([]);
        }
      }),
      propertyParameters(),
    );
  });

  // Any names, in `.mcp.json` and `.codex/config.toml` at once, every project
  // entry approved: the launch preparation never throws, and every allowed,
  // non-colliding name is generated.
  it("P4: no set of server names makes the launch preparation throw", () => {
    fc.assert(
      fc.property(entriesArb, entriesArb, styleArb, (claudeEntries, codexEntries, style) => {
        const content = render(claudeEntries, style);
        const toml = renderToml(codexEntries);
        fs.rmSync(approvalPath(), { force: true });
        const { inventory } = read(content, toml);
        for (const entry of inventory.entries) {
          if (entry.source === "project" && (entry.decision.status === "unapproved" || entry.decision.status === "changed")) {
            saveMcpApproval(projectRoot, approvalPath(), entry);
          }
        }
        takeOutput();
        const runDir = fs.mkdtempSync(path.join(tmp, "run-"));
        expect(() => prepareMcpRuntime({
          approvalPath: approvalPath(),
          callbackPort: 47638,
          claudeConfigPath: path.join(runDir, "claude.json"),
          claudeMcpConfigPath: path.join(runDir, "claude-mcp.json"),
          codexDir: path.join(runDir, "codex"),
          env: env(),
          mcpOAuthPolicyPath: path.join(runDir, "mcp-oauth-policy.json"),
          mcpOperationPolicyPath: path.join(runDir, "mcp-operation-policy.json"),
          policy: { hosts: [], tokens: {} },
          projectRoot,
          tokenConfig: {},
        }), `${content}\n${toml}`).not.toThrow();
        expectNoControlCharacters(takeOutput(), `${content}\n${toml}`);
        const generated = JSON.parse(fs.readFileSync(path.join(runDir, "claude-mcp.json"), "utf8")) as { mcpServers?: Record<string, unknown> };
        for (const name of Object.keys(generated.mcpServers ?? {})) expect(allowed("claude", name), name).toBe(true);
        fs.rmSync(runDir, { recursive: true, force: true });
      }),
      propertyParameters(),
    );
  });
});
