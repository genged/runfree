import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { userServiceDigest, type UserServiceDefinitionJson } from "../../user-services.ts";
import { flushWarnings, setOutputWriterForTest } from "../../warnings.ts";
import { runCommandApp } from "../app.ts";
import type { RunfreeCommandContext } from "../context.ts";

// Drives `runfree service custom add|remove` through the real yargs command
// tree. Only the command context is faked (so no project ensure and no Docker);
// user-services.ts runs for real against files in a temp HOME/XDG tree.

let root: string;
let projectRoot: string;
let home: string;
let env: NodeJS.ProcessEnv;
let stdout: string[];
let stderr: string[];
let stdinTty: PropertyDescriptor | undefined;
let stdoutTty: PropertyDescriptor | undefined;

beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-service-custom-")));
  projectRoot = path.join(root, "project");
  home = path.join(root, "home");
  fs.mkdirSync(projectRoot);
  fs.mkdirSync(home);
  env = {
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_STATE_HOME: path.join(home, ".local", "state"),
    XDG_DATA_HOME: path.join(home, ".local", "share"),
    XDG_CACHE_HOME: path.join(home, ".cache"),
    RUNFREE_TEST_FAKE_DOCKER: "1",
    RUNFREE_LOG_TIMESTAMPS: "0",
  };
  stdout = [];
  stderr = [];
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    stdout.push(args.map(String).join(" "));
  });
  setOutputWriterForTest((line) => stderr.push(line));
  // The stderr renderer reads its timestamp policy from process.env.
  vi.stubEnv("RUNFREE_LOG_TIMESTAMPS", "0");
  // Force a non-interactive run regardless of how vitest was started.
  stdinTty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
  stdoutTty = Object.getOwnPropertyDescriptor(process.stdout, "isTTY");
  Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
  Object.defineProperty(process.stdout, "isTTY", { value: false, configurable: true });
});

afterEach(() => {
  flushWarnings();
  setOutputWriterForTest(undefined);
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  for (const [stream, saved] of [[process.stdin, stdinTty], [process.stdout, stdoutTty]] as const) {
    if (saved) Object.defineProperty(stream, "isTTY", saved);
    else delete (stream as { isTTY?: boolean }).isTTY;
  }
  fs.rmSync(root, { recursive: true, force: true });
});

const servicesDir = () => path.join(home, ".config", "runfree", "services");
const destination = (id: string) => path.join(servicesDir(), `${id}.json`);
const metadata = (id: string) => path.join(servicesDir(), ".metadata", `${id}.json`);
const displayed = (id: string) => `~/.config/runfree/services/${id}.json`;

function context(): RunfreeCommandContext {
  const unavailable = (name: string) => () => {
    throw new Error(`${name}() must not be called`);
  };
  return {
    env,
    projectRoot,
    commandName: "service",
    invocationCwd: projectRoot,
    assets: unavailable("assets"),
    templatesDir: unavailable("templatesDir"),
    projectInfo: unavailable("projectInfo"),
    ensureProject: unavailable("ensureProject"),
    adminContext: () => ({
      projectRoot,
      packageRoot: root,
      tokenConfigPath: path.join(home, ".config", "runfree", "tokens.json"),
      stateDir: path.join(root, "state"),
      env,
    }),
    sourceAdminContext: unavailable("sourceAdminContext"),
    runtimeContext: unavailable("runtimeContext"),
  } as unknown as RunfreeCommandContext;
}

async function runfree(...args: string[]): Promise<number> {
  const status = await runCommandApp(context(), ["service", ...args], async () => 0);
  // Success paths leave buffered warnings for the process exit; render them now.
  flushWarnings();
  return status;
}

function definition(overrides: Partial<UserServiceDefinitionJson> = {}): UserServiceDefinitionJson {
  return {
    schemaVersion: 1,
    id: "user-acme",
    label: "Acme internal API",
    revision: 1,
    hosts: [
      { host: "api.acme.example", explanation: "Acme REST API" },
      { host: "uploads.acme.example" },
    ],
    explanations: ["Acme API for the build"],
    credential: {
      tokenDescription: "Acme API token",
      agentEnv: ["ACME_TOKEN"],
      credentials: [{ host: "api.acme.example", header: "Authorization", scheme: "bearer" }],
    },
    ...overrides,
  };
}

// A definition with no credential block (an undefined key would change the digest).
function credentialFree(overrides: Partial<UserServiceDefinitionJson>): UserServiceDefinitionJson {
  const { credential: _credential, ...rest } = definition(overrides);
  return rest;
}

function sourceFile(name: string, content: unknown): string {
  const file = path.join(root, name);
  fs.writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content, null, 2));
  return file;
}

const ESC = "\u001b";

describe("runfree service custom add --from-file", () => {
  test("C1: imports the previewed definition, records provenance, and prints the enable hint", async () => {
    const def = definition();
    const file = sourceFile("acme.json", def);

    expect(await runfree("custom", "add", "user-acme", "--from-file", file, "--yes")).toBe(0);

    const written = destination("user-acme");
    expect(JSON.parse(fs.readFileSync(written, "utf8"))).toEqual(def);
    expect(fs.statSync(written).mode & 0o777).toBe(0o600);

    const digest = userServiceDigest(def);
    const meta = JSON.parse(fs.readFileSync(metadata("user-acme"), "utf8")) as Record<string, unknown>;
    expect(meta).toMatchObject({ importedFrom: file, digest });
    expect(Number.isNaN(Date.parse(String(meta.importedAt)))).toBe(false);

    expect(stdout).toContain(`source: ${file}`);
    expect(stdout).toContain(`destination: ${displayed("user-acme")}`);
    expect(stdout).toContain(`definition digest: ${digest}`);
    expect(stdout).toContain("definition contents:");
    expect(stdout).toContain("host: api.acme.example — Acme REST API");
    expect(stdout).toContain("host: uploads.acme.example");
    expect(stdout).toContain("credential token: user-acme");
    expect(stdout).toContain("agent env: ACME_TOKEN placeholders");
    expect(stdout).toContain(`user-defined service user-acme imported to ${displayed("user-acme")}`);
    expect(stdout.at(-1)).toBe("enable it with: runfree service enable user-acme");
    expect(stderr).toEqual([]);
  });

  test("a bare id is canonicalized to user-<id> rather than refused", async () => {
    const file = sourceFile("acme.json", definition());
    expect(await runfree("custom", "add", "acme", "--from-file", file, "--yes")).toBe(0);
    expect(fs.existsSync(destination("user-acme"))).toBe(true);
    expect(stdout.at(-1)).toBe("enable it with: runfree service enable user-acme");
  });

  describe("C2: refusals write nothing", () => {
    const refusals: Array<{ name: string; id: string; file: () => string; message: RegExp }> = [
      {
        name: "an id outside the user-* pattern",
        id: "acme_corp",
        file: () => sourceFile("acme.json", definition()),
        message: /user-defined service id must match user-\[a-z0-9\]\[a-z0-9-\]\*/,
      },
      {
        name: "a path-traversal id",
        id: "../evil",
        file: () => sourceFile("acme.json", definition()),
        message: /user-defined service id must match/,
      },
      {
        name: "a definition id that differs from the requested id",
        id: "user-other",
        file: () => sourceFile("acme.json", definition()),
        message: /definition id user-acme does not match requested id user-other/,
      },
      {
        name: "a file that is not JSON",
        id: "user-acme",
        file: () => sourceFile("acme.json", "{ not json"),
        message: /invalid JSON:/,
      },
      {
        name: "an unknown top-level key",
        id: "user-acme",
        file: () => sourceFile("acme.json", { ...definition(), allowAll: true }),
        message: /definition: unknown key allowAll/,
      },
      {
        name: "a wildcard host",
        id: "user-acme",
        file: () => sourceFile("acme.json", definition({ hosts: [{ host: "*.acme.example" }] })),
        message: /hosts\[0\]\.host/,
      },
      {
        name: "a missing file",
        id: "user-acme",
        file: () => path.join(root, "missing.json"),
        message: /ENOENT|no such file|missing\.json/,
      },
    ];

    for (const refusal of refusals) {
      test(refusal.name, async () => {
        const file = refusal.file();
        expect(await runfree("custom", "add", refusal.id, "--from-file", file, "--yes")).toBe(1);
        expect(stderr.join("\n")).toMatch(refusal.message);
        expect(stderr.join("\n")).toMatch(/^runfree error: /);
        // Refused before the preview and before any write.
        expect(stdout).toEqual([]);
        expect(fs.existsSync(servicesDir())).toBe(false);
      });
    }
  });

  describe("C3: terminal control sequences are refused", () => {
    const hostile: Array<{ name: string; def: UserServiceDefinitionJson; owner: string }> = [
      { name: "in the label", def: definition({ label: `Acme${ESC}[2J` }), owner: "label" },
      {
        name: "in a host explanation",
        def: definition({ hosts: [{ host: "api.acme.example", explanation: `Acme ${ESC}]0;pwned${ESC}\\ API` }] }),
        owner: "hosts[0].explanation",
      },
    ];

    for (const entry of hostile) {
      test(entry.name, async () => {
        const file = sourceFile("acme.json", entry.def);
        expect(fs.readFileSync(file, "utf8")).toContain("\\u001b");

        expect(await runfree("custom", "add", "user-acme", "--from-file", file, "--yes")).toBe(1);
        expect(stderr.join("\n")).toContain(`${entry.owner} must be printable single-line text`);
        expect(fs.existsSync(destination("user-acme"))).toBe(false);
        expect(fs.existsSync(metadata("user-acme"))).toBe(false);
        expect(stdout.join("\n")).not.toContain(ESC);
        expect(stderr.join("\n")).not.toContain(ESC);
      });
    }
  });

  test("C4: without --yes a non-TTY run previews, then refuses and writes nothing", async () => {
    const file = sourceFile("acme.json", definition());

    expect(await runfree("custom", "add", "user-acme", "--from-file", file)).toBe(1);

    expect(stdout).toContain(`definition digest: ${userServiceDigest(definition())}`);
    expect(stdout.some((line) => line.startsWith("enable it with:"))).toBe(false);
    expect(stderr.join("\n")).toContain("service custom add --from-file requires an interactive TTY");
    expect(fs.existsSync(servicesDir())).toBe(false);
  });

  describe("C5: an existing definition is replaced only with --replace", () => {
    test("without --replace the existing file is left byte-for-byte unchanged", async () => {
      expect(await runfree("custom", "add", "user-acme", "--from-file", sourceFile("v1.json", definition()), "--yes")).toBe(0);
      const before = fs.readFileSync(destination("user-acme"));
      const metaBefore = fs.readFileSync(metadata("user-acme"));
      stdout.length = 0;

      const v2 = sourceFile("v2.json", credentialFree({ revision: 2, hosts: [{ host: "evil.example" }] }));
      // The refusal is a plain Error from user-services.ts, not an AdminExit, so
      // it escapes the admin runner; cli.ts main() renders it and exits 1.
      await expect(runfree("custom", "add", "user-acme", "--from-file", v2, "--yes"))
        .rejects.toThrow(`${destination("user-acme")} already exists; pass --replace to overwrite`);

      expect(fs.readFileSync(destination("user-acme")).equals(before)).toBe(true);
      expect(fs.readFileSync(metadata("user-acme")).equals(metaBefore)).toBe(true);
      expect(stdout.some((line) => line.includes("imported to"))).toBe(false);
      expect(fs.readdirSync(servicesDir()).filter((name) => name.endsWith(".tmp"))).toEqual([]);
    });

    test("with --replace the new definition and provenance overwrite the old", async () => {
      expect(await runfree("custom", "add", "user-acme", "--from-file", sourceFile("v1.json", definition()), "--yes")).toBe(0);

      const def2 = credentialFree({ revision: 2, hosts: [{ host: "api2.acme.example" }] });
      const v2 = sourceFile("v2.json", def2);
      expect(await runfree("custom", "add", "user-acme", "--from-file", v2, "--yes", "--replace")).toBe(0);

      expect(JSON.parse(fs.readFileSync(destination("user-acme"), "utf8"))).toEqual(def2);
      expect(JSON.parse(fs.readFileSync(metadata("user-acme"), "utf8"))).toMatchObject({
        importedFrom: v2,
        digest: userServiceDigest(def2),
      });
    });
  });
});

describe("runfree service custom remove", () => {
  test("C6: deletes an existing definition and its provenance", async () => {
    expect(await runfree("custom", "add", "user-acme", "--from-file", sourceFile("acme.json", definition()), "--yes")).toBe(0);
    stdout.length = 0;

    expect(await runfree("custom", "remove", "user-acme")).toBe(0);

    expect(stdout).toEqual([`user-defined service user-acme removed from ${displayed("user-acme")}`]);
    expect(fs.existsSync(destination("user-acme"))).toBe(false);
    expect(fs.existsSync(metadata("user-acme"))).toBe(false);
    expect(stderr).toEqual([]);
  });

  test("C6: an undefined id reports where it looked and exits 0", async () => {
    expect(await runfree("custom", "remove", "user-acme")).toBe(0);
    expect(stdout).toEqual([`user-defined service user-acme is not defined at ${displayed("user-acme")}`]);
  });

  test("C6: a non-user-* id is refused", async () => {
    expect(await runfree("custom", "remove", "../evil")).toBe(1);
    expect(stderr.join("\n")).toContain("user-defined service id must match user-[a-z0-9][a-z0-9-]*");
    expect(stdout).toEqual([]);
  });

  test("C6: warns when the service is still enabled in the project, and still removes it", async () => {
    expect(await runfree("custom", "add", "user-acme", "--from-file", sourceFile("acme.json", definition()), "--yes")).toBe(0);
    fs.mkdirSync(path.join(projectRoot, ".runfree"));
    fs.writeFileSync(path.join(projectRoot, ".runfree", "runfree.json"), JSON.stringify({ services: { "user-acme": { revision: 1 } } }));
    stdout.length = 0;

    expect(await runfree("custom", "remove", "user-acme")).toBe(0);

    expect(stderr).toEqual([
      "runfree warning: user-acme is enabled in this project; disable it with: runfree service disable user-acme",
    ]);
    expect(stdout).toEqual([`user-defined service user-acme removed from ${displayed("user-acme")}`]);
    expect(fs.existsSync(destination("user-acme"))).toBe(false);
  });
});
