// Drift guard for the read-only `runfree` skill the agent image ships
// (packages/agent-runtime/agent/skills/runfree/SKILL.md). The skill is a
// static file, so this test holds it to the code it describes: every
// `runfree ...` command it names parses under the real command app, its sample
// denial is byte-equal to the body the proxy renders, the status and header it
// names are what a real proxy answers, and it carries no host path, project
// policy, or token-like string.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { parseEmittedCommandArgs } from "../packages/cli/src/commands/app.ts";
import { createCommandContext } from "../packages/cli/src/commands/context.ts";
import { syntheticDenialBody } from "../packages/proxy/src/denial.ts";
import { httpsViaProxy, startProxy } from "../packages/proxy/src/server.test-harness.ts";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const SKILL_PATH = path.join(repoRoot, "packages", "agent-runtime", "agent", "skills", "runfree", "SKILL.md");
const skill = fs.readFileSync(SKILL_PATH, "utf8");
const SAMPLE_HOST = "api.example.com";

function frontMatter(markdown: string): Record<string, string> {
  const match = /^---\n([\s\S]*?)\n---\n/.exec(markdown);
  if (!match) throw new Error("SKILL.md has no front matter");
  return Object.fromEntries(match[1].split("\n").map((line) => {
    const separator = line.indexOf(":");
    return [line.slice(0, separator).trim(), line.slice(separator + 1).trim()];
  }));
}

// Every `runfree <words>` anywhere in the file, as argv: in a fenced block, an
// inline code span, or prose. It runs to the end of the code span or line, so
// a command named in prose must still parse in full; the bare word `runfree`
// (followed by a backtick, not a space) is not a command.
function namedCommands(markdown: string): string[][] {
  const commands: string[][] = [];
  for (const line of markdown.split("\n")) {
    for (const match of line.matchAll(/(?<![\w./-])runfree ([^`\n]+)/g)) {
      const argv = match[1].trim().replace(/[.,;:]$/, "").split(/\s+/);
      if (argv.length > 0 && argv[0] !== "") commands.push(argv);
    }
  }
  return commands;
}

// Absolute paths of one or more segments (`/secrets`, `/etc/x/y`) and
// home-relative ones (`~/x`, `~user/x`, `$HOME/x`, `${HOME}/x`). A slash
// after a word character, a colon, a slash, or `<` is not a path start, so
// `HTTP/1.1`, `and/or`, URLs, and closing tags stay allowed.
function hostPaths(text: string): string[] {
  return text.match(/(?<![\w.:<>/~$}-])(?:~[\w.-]*|\$\{?\w+\}?)?\/[\w.-]+[\w./-]*/g) ?? [];
}

// The body of the one ```text block: the sample denial.
function sampleDenial(markdown: string): string {
  const blocks = [...markdown.matchAll(/^```text\n([\s\S]*?)^```$/gm)].map((match) => match[1]);
  expect(blocks, "SKILL.md must hold exactly one ```text sample denial").toHaveLength(1);
  return blocks[0] as string;
}

async function parseFailure(argv: string[]): Promise<string | undefined> {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-skill-commands-"));
  try {
    await parseEmittedCommandArgs(createCommandContext({ projectRoot, invocationCwd: projectRoot, commandName: "", env: { ...process.env } }), argv);
    return undefined;
  } catch (error) {
    return error instanceof Error ? error.message.split("\n")[0] : String(error);
  } finally {
    fs.rmSync(projectRoot, { recursive: true, force: true });
  }
}

async function commandFailures(markdown: string): Promise<string[]> {
  const failures: string[] = [];
  for (const argv of namedCommands(markdown)) {
    const failure = await parseFailure(argv);
    if (failure) failures.push(`runfree ${argv.join(" ")}: ${failure}`);
  }
  return failures;
}

describe("the shipped runfree skill", () => {
  test("front matter names the skill and says when to load it", () => {
    const fields = frontMatter(skill);
    expect(fields.name).toBe("runfree");
    expect(fields.description).toContain("403");
    expect(fields.description).toContain("Runfree blocked this request");
  });

  test("covers the sandbox, denials, placeholder tokens, and how to ask for access", () => {
    for (const heading of ["## Network", "## What a denial looks like", "## Tokens", "## Asking the human for access"]) {
      expect(skill, heading).toContain(`\n${heading}\n`);
    }
  });

  test("every runfree command it names parses under the real command app", async () => {
    const commands = namedCommands(skill).map((argv) => argv.join(" "));
    // An empty scan would pass vacuously; the skill names these on purpose.
    expect(commands).toEqual(expect.arrayContaining([`host add ${SAMPLE_HOST}`, `host explain ${SAMPLE_HOST}`, "doctor"]));
    expect(await commandFailures(skill)).toEqual([]);
  });

  test("the command check rejects a command the CLI does not have", async () => {
    const mutated = [
      skill,
      "```bash",
      `runfree host grant ${SAMPLE_HOST}`,
      "```",
      `Or ask for \`runfree allow ${SAMPLE_HOST}\`, or run runfree host add ${SAMPLE_HOST} --bogus now.`,
    ].join("\n");
    const failures = await commandFailures(mutated);
    expect(failures).toHaveLength(3);
    expect(failures[0]).toContain(`runfree host grant ${SAMPLE_HOST}`);
    expect(failures[1]).toContain("unknown command: allow");
    expect(failures[2]).toContain("Unknown argument");
  });

  test("the sample denial is the body the proxy renders for a host that is not allowlisted", () => {
    expect(sampleDenial(skill)).toBe(syntheticDenialBody(SAMPLE_HOST, "host-not-allowlisted"));
  });

  test("a real proxy answers that denial with the status, header, and body the skill names", async () => {
    const proxy = await startProxy({ policy: { hosts: [], tokens: {} } });
    try {
      const denied = await httpsViaProxy({ proxyPort: proxy.port, targetHost: SAMPLE_HOST, targetPort: 443, path: "/" });
      expect(skill).toContain(`HTTP status ${denied.statusCode}`);
      expect(denied.statusCode).toBe(403);
      expect(denied.headers["x-runfree-blocked"]).toBe("host-not-allowlisted");
      expect(skill).toContain("`x-runfree-blocked: <reason>`");
      expect(denied.body).toBe(sampleDenial(skill));
    } finally {
      await proxy.stop();
    }
  }, 20_000);

  test("the host-path guard catches single-segment, multi-segment, and home-relative paths", () => {
    for (const sample of [
      "Host configuration: /secrets",
      "/secrets",
      "see (/secrets)",
      "/etc/claude-code/skills",
      "`/Users/alice/project`",
      "~/.ssh/id_ed25519",
      "~alice/notes",
      "$HOME/.config/runfree",
      "${HOME}/.codex",
    ]) {
      expect(hostPaths(sample), sample).not.toEqual([]);
    }
    // Slashes that are not paths stay allowed.
    for (const sample of ["HTTP/1.1", "and/or", "https://api.example.com/v1", "403 / 404", "a</b>"]) {
      expect(hostPaths(sample), sample).toEqual([]);
    }
  });

  test("holds no host path, project policy, real hostname, or token-like string", () => {
    // Absolute paths of any length, and home-relative paths.
    expect(hostPaths(skill)).toEqual([]);
    expect(skill).not.toMatch(/~\//);
    // Project policy lives under .runfree/; the skill names none of it.
    expect(skill).not.toMatch(/\.runfree\b|network-policy/);
    // The only hostnames are the documentation example ones.
    const hosts = new Set(skill.match(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b/g) ?? []);
    for (const host of hosts) expect(host, host).toMatch(/(^|\.)example\.com$/);
    for (const pattern of [
      /\bsk-[A-Za-z0-9_-]{8,}/,
      /\bgh[pousr]_[A-Za-z0-9]{20,}/,
      /\bgithub_pat_/,
      /\bxox[abprs]-/,
      /\bAKIA[0-9A-Z]{16}\b/,
      /\beyJ[A-Za-z0-9_-]{16,}/,
      /\brunfree_oauth_/,
      /\bBearer\s+\S/,
      /-----BEGIN/,
      /\b[A-Fa-f0-9]{32,}\b/,
      /[A-Za-z0-9+/]{40,}={0,2}/,
    ]) {
      expect(skill, String(pattern)).not.toMatch(pattern);
    }
  });
});
