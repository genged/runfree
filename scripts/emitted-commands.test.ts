// The remedy parse gate (output contract D4).
//
// Every `runfree ...` command the CLI can print as a next step must parse
// under the real yargs app. Two sources feed it: the remedy registry
// (`packages/cli/src/remedies.ts`), which must parse in full, and a lint over
// string literals in the emitting modules that names a `runfree <command>`.
// The lint catches hand-written strings that bypass the registry — the class
// of defect where the init wizard printed `runfree allow ...` (never a
// command) and `runfree source add` (a removed shim), and nothing could tell.
import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { parseEmittedCommandArgs } from "../packages/cli/src/commands/app.ts";
import { createCommandContext } from "../packages/cli/src/commands/context.ts";
import { sampleRemedyRenderings } from "../packages/cli/src/remedies.ts";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

// Emitting modules: everything under the CLI package plus the shared
// diagnostics/services modules and the proxy denial text (read by the agent).
// Help surfaces (`help-topics.ts`, `examples.ts`) document syntax with
// brackets and alternations and are covered by the help tests.
const EMITTING_GLOBS = [
  "packages/cli/src",
  "scripts/domain-diagnostics.ts",
  "scripts/services.ts",
  "packages/proxy/src/denial.ts",
  "packages/proxy/src/server.ts",
];
const EXCLUDED_FILES = [
  /\.test\.ts$/,
  /test-harness\.ts$/,
  /embedded-assets\.generated\.ts$/,
  /commands\/help-topics\.ts$/,
  /commands\/examples\.ts$/,
  /remedies\.ts$/,
];

// Fragments that name a removed or deprecated command on purpose (the
// message says it no longer exists). Anything else that fails to parse is a
// defect.
const REMOVED_COMMAND_FRAGMENTS = new Set([
  "runfree domain",
  "runfree source",
  "runfree token",
  "runfree paste-image",
]);

// English words that end a command fragment inside prose ("runfree update
// does not ..."). None is a Runfree command word or flag.
const PROSE_STOP_WORDS = new Set([
  "a", "an", "and", "are", "as", "at", "be", "before", "by", "can", "cannot", "did", "directly", "does", "first", "for",
  "command", "config", "exited", "from", "if", "in", "is", "it", "its", "must", "needs", "no", "not", "now", "of", "on", "or",
  "requires", "root", "so", "that", "the", "then", "this", "to", "was", "were", "when", "will", "with", "without", "yet",
]);

const PLACEHOLDER_VALUES: Record<string, string> = {
  host: "api.example.com",
  hostname: "api.example.com",
  id: "github",
  name: "tok",
  source: "src",
  prefix: "/api/",
  port: "8080",
  duration: "30m",
  "session-id": "session-a1b2",
  agent: "claude",
  server: "srv",
  env: "TOKEN_ENV",
  "jwt-source": "jwtsrc",
};

const FLAG_VALUE_FOR_TEMPLATE: Record<string, string> = {
  "--write": "ask",
  "--scope": "request",
  "--agent": "claude",
  "--from-env": "TOKEN_ENV",
  "--from-source": "src",
  "--from-1password": "op://vault/item/field",
  "--host": "api.example.com",
  "--subject-digest": `sha256:${"a".repeat(64)}`,
};

type Candidate = {
  file: string;
  line: number;
  fragment: string;
  argv: string[];
  // Prose continues after the fragment on the same line: the string mentions
  // the command ("use runfree service enable or disable") rather than
  // presenting it as the next step. A mention may name a command prefix
  // whose positionals are missing; a remedy may not.
  mention: boolean;
};

function listEmittingFiles(): string[] {
  const output = childProcess.spawnSync("git", ["ls-files", "-z", "--", ...EMITTING_GLOBS], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  expect(output.status, output.stderr).toBe(0);
  return output.stdout
    .split("\0")
    .filter((entry) => entry.endsWith(".ts") && !EXCLUDED_FILES.some((pattern) => pattern.test(entry)))
    .sort();
}

const TEMPLATE_EXPRESSION = /\$\{(?:[^{}]|\{[^{}]*\})*\}/g;
const STRING_LITERAL = /`((?:[^`\\]|\\.)*)`|"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'/gs;
const FRAGMENT = /(?<![\w.$/-])runfree ([^\n]*)/g;
const WORD = /^[a-z][a-z0-9-]*$/;
const FLAG = /^--?[a-z][a-z0-9-]*(?:=.*)?$/;
const PLACEHOLDER = /^<([a-z][a-z0-9-]*)>$/i;

// Remove comments but keep every newline so reported line numbers hold.
function stripComments(source: string): string {
  return source
    .replace(/^[ \t]*\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, ""));
}

// Tokenize a fragment into argv, stopping where prose begins. Returns
// undefined when the fragment is syntax documentation (brackets, alternation,
// ellipsis), a bare "runfree" with nothing after it, or shorthand prose.
function candidateArgv(rest: string): { argv: string[]; mention: boolean } | undefined {
  if (/[[\]|]|\.\.\.|…/.test(rest)) return undefined;
  const argv: string[] = [];
  let previousFlag: string | undefined;
  const words = rest.split(/\s+/);
  let consumed = 0;
  for (const raw of words) {
    if (raw === "") break;
    // A closing quote or backtick ends the fragment after this token.
    const closesQuote = /[`'"]/.test(raw);
    let token = raw.replace(/[`'"]/g, "").replace(/[.,;)\\]+$/, "");
    if (raw.startsWith("#")) break;
    // A label ("runfree config:"), not a command.
    if (raw.endsWith(":")) break;
    if (token === "") break;
    if (token.includes("/") && !token.startsWith("/") && !token.startsWith("op://") && !token.includes("PLACEHOLDER")) {
      // "add/rules" shorthand: prose, not a command.
      return undefined;
    }
    if (PROSE_STOP_WORDS.has(token)) break;
    const placeholder = PLACEHOLDER.exec(token);
    if (placeholder) {
      token = PLACEHOLDER_VALUES[placeholder[1].toLowerCase()] ?? placeholder[1].toLowerCase();
    } else if (token.includes("PLACEHOLDER")) {
      const flagValue = previousFlag === undefined ? undefined : FLAG_VALUE_FOR_TEMPLATE[previousFlag];
      token = token.startsWith("--") ? "--project" : (flagValue ?? token.replace(/PLACEHOLDER/g, "placeholder"));
    } else if (!(WORD.test(token) || FLAG.test(token) || token === "--" || previousFlag !== undefined || token.startsWith("/") || token.startsWith("op://"))) {
      break;
    }
    argv.push(token);
    consumed += 1;
    previousFlag = token.startsWith("--") && !token.includes("=") ? token : undefined;
    if (closesQuote || (raw !== token && /[.;)]$/.test(raw))) break;
  }
  if (argv.length === 0) return undefined;
  // A templated command word cannot be checked here (the wizard's intents
  // have their own rendering test).
  if (argv[0].includes("placeholder")) return undefined;
  // Prose follows, or the quoted fragment ends a sentence ("... after
  // 'runfree mcp approve'."): a mention, not a presented next step.
  const mention = words.slice(consumed).some((word) => word !== "" && !word.startsWith("#"))
    || /[`'"][.,;]$/.test(words[consumed - 1] ?? "");
  return { argv, mention };
}

function extractCandidates(): Candidate[] {
  const candidates: Candidate[] = [];
  for (const file of listEmittingFiles()) {
    const source = stripComments(fs.readFileSync(path.join(repoRoot, file), "utf8"));
    for (const literal of source.matchAll(STRING_LITERAL)) {
      const text = literal[1] ?? literal[2] ?? literal[3] ?? "";
      if (!text.includes("runfree ")) continue;
      const line = source.slice(0, literal.index).split("\n").length;
      const substituted = text.replace(TEMPLATE_EXPRESSION, "PLACEHOLDER").replace(/\\n/g, "\n");
      for (const fragment of substituted.matchAll(FRAGMENT)) {
        const candidate = candidateArgv(fragment[1]);
        if (!candidate) continue;
        candidates.push({ file, line, fragment: `runfree ${candidate.argv.join(" ")}`, ...candidate });
      }
    }
  }
  return candidates;
}

function parseContext() {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-emitted-commands-"));
  return createCommandContext({ projectRoot, invocationCwd: projectRoot, commandName: "", env: { ...process.env } });
}

async function parseFailure(argv: string[]): Promise<string | undefined> {
  try {
    await parseEmittedCommandArgs(parseContext(), argv);
    return undefined;
  } catch (error) {
    return error instanceof Error ? error.message.split("\n")[0] : String(error);
  }
}

describe("emitted commands parse under the real command app", () => {
  test("every remedy registry rendering parses", async () => {
    const failures: string[] = [];
    for (const rendering of sampleRemedyRenderings()) {
      expect(rendering.startsWith("runfree ")).toBe(true);
      const failure = await parseFailure(rendering.slice("runfree ".length).split(" "));
      if (failure) failures.push(`${rendering}: ${failure}`);
    }
    expect(failures).toEqual([]);
  });

  test("the registry samples exercise every registry entry", async () => {
    const { remedy } = await import("../packages/cli/src/remedies.ts");
    const rendered = sampleRemedyRenderings();
    for (const [name, render] of Object.entries(remedy)) {
      const sample = (render as (...args: string[]) => string)("x.example", "y.example", "z");
      const root = sample.split(" ").slice(0, 3).join(" ");
      expect(rendered.some((line) => line.startsWith(root)), `${name} has no sample`).toBe(true);
    }
  });

  test("every hand-written `runfree ...` string in an emitting module parses", async () => {
    const candidates = extractCandidates();
    // The lint must actually see the emitting modules; an empty scan would
    // pass vacuously.
    expect(candidates.length).toBeGreaterThan(40);
    const failures: string[] = [];
    for (const candidate of candidates) {
      if (REMOVED_COMMAND_FRAGMENTS.has(candidate.fragment)) continue;
      const failure = await parseFailure(candidate.argv);
      if (!failure) continue;
      // A prose mention may name a command prefix; a presented next step may
      // not (that is the bare `service configure` class).
      if (candidate.mention && /^Not enough non-option arguments/.test(failure)) continue;
      failures.push(`${candidate.file}:${candidate.line}: ${candidate.fragment} — ${failure}`);
    }
    expect(failures).toEqual([]);
  });

  test("the lint catches the defect classes it exists for", async () => {
    expect(await parseFailure(["allow", "api.example.com", "--no-reload"])).toContain("unknown command: allow");
    expect(await parseFailure(["source", "add", "gh", "--", "gh"])).toContain("unknown command: source");
    expect(await parseFailure(["service", "configure"])).toMatch(/Not enough non-option arguments/);
    expect(await parseFailure(["host", "add", "api.example.com", "--bogus"])).toContain("Unknown argument: bogus");
    expect(await parseFailure(["host", "add", "api.example.com", "--no-reload"])).toBeUndefined();
    expect(await parseFailure(["credential", "source", "add", "gh", "--", "gh", "auth", "token"])).toBeUndefined();
  });
});
