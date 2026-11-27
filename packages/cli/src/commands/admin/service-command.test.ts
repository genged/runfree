import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  type DesiredNetworkPolicyJson,
  type DesiredServiceEntry,
  withRequiredDesiredNetworkPolicyVersion,
} from "@runfree/runtime-contracts/desired-network-policy";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { SERVICES } from "../../../../../scripts/services.ts";
import { desiredServiceEntry } from "../../admin/service-policy.ts";
import { projectInfo } from "../../config.ts";
import { approveNetworkCandidate, readControlApprovalSelection } from "../../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../../control/candidates.ts";
import { CliError } from "../../errors.ts";
import type { RuntimeContext } from "../../runtime/types.ts";
import { flushWarnings, setOutputWriterForTest } from "../../warnings.ts";
import { runCommandApp } from "../app.ts";
import type { RunfreeCommandContext } from "../context.ts";

// Drives `runfree service list|explain|enable|disable|diff` through the real
// yargs command tree. Only the command context is faked; approvals are seeded
// for real (capture + approve) and the policy files are read back from disk.

let root: string;
let projectRoot: string;
let home: string;
let env: NodeJS.ProcessEnv;
let runtime: RuntimeContext;
let stdout: string[];
let stderr: string[];
let stdinTty: PropertyDescriptor | undefined;
let stdoutTty: PropertyDescriptor | undefined;

beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-service-command-")));
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
    RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
    RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
  };
  runtime = { projectRoot, project: projectInfo(projectRoot, env), runtimeRoot: path.join(root, "runtime"), env };
  stdout = [];
  stderr = [];
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    stdout.push(args.map(String).join(" "));
  });
  setOutputWriterForTest((line) => stderr.push(line));
  vi.stubEnv("RUNFREE_LOG_TIMESTAMPS", "0");
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
    runtimeContext: () => runtime,
  } as unknown as RunfreeCommandContext;
}

async function runfree(...args: string[]): Promise<number> {
  const status = await runCommandApp(context(), ["service", ...args], async () => 0);
  flushWarnings();
  return status;
}

async function refusal(...args: string[]): Promise<string> {
  try {
    await runfree(...args);
  } catch (error) {
    expect(error).toBeInstanceOf(CliError);
    return (error as Error).message;
  }
  throw new Error(`service ${args.join(" ")} did not refuse`);
}

const projectFile = () => path.join(projectRoot, ".runfree", "network-policy.json");
const localFile = () => path.join(projectRoot, ".runfree", "network-policy.local.json");
const readPolicy = (file: string): DesiredNetworkPolicyJson => JSON.parse(fs.readFileSync(file, "utf8")) as DesiredNetworkPolicyJson;
const snapshot = (file: string): string | undefined => (fs.existsSync(file) ? fs.readFileSync(file, "utf8") : undefined);
const selection = () => readControlApprovalSelection(projectRoot, runtime.project);
const normalized = () => stdout.flatMap((block) => block.split("\n")).map((line) => line.trim().replace(/\s+/g, " "));

function layer(services: Record<string, DesiredServiceEntry> = {}): DesiredNetworkPolicyJson {
  return withRequiredDesiredNetworkPolicyVersion({ version: 2, hosts: [], services });
}

// Write the desired layers and approve both, as `runfree up` review would.
function seed(input: { project?: Record<string, DesiredServiceEntry>; local?: Record<string, DesiredServiceEntry> } = {}): void {
  fs.mkdirSync(path.join(projectRoot, ".runfree"), { recursive: true });
  fs.writeFileSync(projectFile(), `${JSON.stringify(layer(input.project), null, 2)}\n`);
  if (input.local) fs.writeFileSync(localFile(), `${JSON.stringify(layer(input.local), null, 2)}\n`);
  const candidate = captureDesiredPolicyCandidate(projectRoot, runtime.project.paths.controlCandidatesDir);
  approveNetworkCandidate(projectRoot, runtime.project, candidate, "network-project", "interactive");
  approveNetworkCandidate(projectRoot, runtime.project, candidate, "network-local", "interactive");
}

const oldDigest = (marker: string): string => `sha256:${marker.repeat(64)}`;
const current = (id: string, picked: Parameters<typeof desiredServiceEntry>[1] = {}): DesiredServiceEntry =>
  desiredServiceEntry(SERVICES[id], picked);
// node revision 1: only registry.npmjs.org, so the current definition adds registry.yarnpkg.com.
const staleNodeNarrow = (): DesiredServiceEntry => {
  const entry = current("node");
  return { ...entry, revision: 1, definitionDigest: oldDigest("1"), resolved: { ...entry.resolved, hosts: ["registry.npmjs.org"] } };
};
// python with an extra legacy host, so the current definition only removes hosts.
const stalePythonWide = (): DesiredServiceEntry => {
  const entry = current("python");
  return { ...entry, definitionDigest: oldDigest("2"), resolved: { ...entry.resolved, hosts: [...entry.resolved.hosts, "legacy.pypi.example"] } };
};
const retiredEntry = (): DesiredServiceEntry => ({
  revision: 1,
  definitionDigest: oldDigest("3"),
  resolved: { hosts: ["retired.example.com"] },
});

const NO_APPROVALS = [
  "approved project and local network controls are required before services can be listed or changed",
  "start the runtime to review and select controls: runfree up",
  "inspect approval state with: runfree policy status",
].join("\n");

describe("C1: service commands without approved controls", () => {
  test("list, list --all, diff and diff --apply refuse before any write; explain still works", async () => {
    fs.mkdirSync(path.join(projectRoot, ".runfree"));
    fs.writeFileSync(projectFile(), `${JSON.stringify(layer({ node: staleNodeNarrow() }))}\n`);
    const before = snapshot(projectFile());

    for (const args of [["list"], ["list", "--all"], ["diff"], ["diff", "--apply"]]) {
      expect(await refusal(...args)).toBe(NO_APPROVALS);
    }
    expect(snapshot(projectFile())).toBe(before);
    expect(fs.existsSync(localFile())).toBe(false);
    expect(stdout).toEqual([]);

    expect(await runfree("explain", "node")).toBe(0);
    expect(stdout).toContain(`state: not enabled; current revision ${SERVICES.node.revision}`);
    expect(snapshot(projectFile())).toBe(before);
  });
});

describe("C2: service list", () => {
  test("lists approved services in id order with layer, revision and host count", async () => {
    seed({
      project: { python: current("python"), node: current("node") },
      local: { go: current("go", { skippedHosts: ["storage.googleapis.com"] }) },
    });
    expect(await runfree("list")).toBe(0);
    expect(normalized()).toEqual([
      "SERVICE LAYER REVISION HOSTS",
      "go local 1 2",
      `node project ${SERVICES.node.revision} 2`,
      `python project ${SERVICES.python.revision} 2`,
    ]);
  });

  test("--all adds available services with layer -", async () => {
    seed({ project: { node: staleNodeNarrow() } });
    expect(await runfree("list", "--all")).toBe(0);
    const lines = normalized();
    expect(lines[0]).toBe("SERVICE ORIGIN STATE LAYER REVISION HOSTS");
    expect(lines).toContain("node curated enabled project 1 1");
    expect(lines).toContain(`rust curated available - ${SERVICES.rust.revision} ${SERVICES.rust.hosts.length}`);
    expect(lines).toContain(`github curated available - ${SERVICES.github.revision} ${SERVICES.github.hosts.length}`);
  });

  test("approvals with no services print the hint line", async () => {
    seed();
    expect(await runfree("list")).toBe(0);
    expect(stdout).toEqual(["no approved services; list every known service with: runfree service list --all"]);
  });
});

describe("C3: service explain text", () => {
  test("an entry behind the registry names both revisions", async () => {
    seed({ project: { node: staleNodeNarrow() } });
    expect(await runfree("explain", "node")).toBe(0);
    expect(stdout.slice(0, 4)).toEqual([
      `service node: ${SERVICES.node.label}`,
      "origin: curated",
      "state: enabled (project layer), approved revision 1",
      `current revision: ${SERVICES.node.revision}; review with: runfree service diff`,
    ]);
    expect(stdout).toContain("hosts:");
    expect(stdout).toContain("  registry.yarnpkg.com");
  });

  test("a local --skip-broad entry shows the local layer and the skipped broad host", async () => {
    seed({ local: { go: current("go", { skippedHosts: ["storage.googleapis.com"] }) } });
    expect(await runfree("explain", "go")).toBe(0);
    expect(stdout).toContain("state: enabled (local layer), approved revision 1");
    expect(stdout.some((line) => line.startsWith("current revision:"))).toBe(false);
    expect(stdout).toContain("  storage.googleapis.com (broad, skipped)");
    expect(stdout).toContain("  proxy.golang.org");
  });

  test("an approved id absent from the registry keeps only the approved semantics", async () => {
    seed({ project: { retired: retiredEntry() } });
    expect(await runfree("explain", "retired")).toBe(0);
    expect(stdout).toEqual([
      "service retired",
      "origin: curated",
      "state: enabled (project layer), approved revision 1",
      "definition: unavailable; approved semantics retained",
    ]);
  });

  test("ids are lowercased, credentials and notes are shown", async () => {
    expect(await runfree("explain", "NODE")).toBe(0);
    expect(stdout[0]).toBe(`service node: ${SERVICES.node.label}`);
    stdout.length = 0;
    expect(await runfree("explain", "github")).toBe(0);
    expect(stdout).toContain("  objects.githubusercontent.com (broad)");
    expect(stdout).toContain("  agent env placeholders: GH_TOKEN, GITHUB_TOKEN");
    expect(stdout).toContain("  with no token stored, requests go out without one");
    expect(stdout).toContain("notes:");
    expect(stdout).toContain(`  - ${SERVICES.github.explanations[0]}`);
  });

  test("an unknown id is refused", async () => {
    expect(await refusal("explain", "nosuch")).toBe("unknown service: nosuch; list every known service with: runfree service list --all");
  });
});

describe("C4: service explain --json", () => {
  test("a not-enabled curated service has its definition and no approved keys", async () => {
    expect(await runfree("explain", "python", "--json")).toBe(0);
    const out = JSON.parse(stdout.join("\n")) as Record<string, unknown>;
    expect(out).toMatchObject({
      id: "python",
      origin: "curated",
      state: "available",
      definition: { label: SERVICES.python.label, revision: SERVICES.python.revision, explanations: SERVICES.python.explanations },
    });
    expect(out).not.toHaveProperty("layer");
    expect(out).not.toHaveProperty("resolved");
  });

  test("an enabled service carries the approved entry", async () => {
    const go = current("go", { skippedHosts: ["storage.googleapis.com"] });
    seed({ local: { go } });
    expect(await runfree("explain", "go", "--json")).toBe(0);
    const out = JSON.parse(stdout.join("\n")) as Record<string, unknown>;
    expect(out).toMatchObject({
      id: "go",
      state: "enabled",
      layer: "local",
      revision: go.revision,
      definitionDigest: go.definitionDigest,
      selection: go.selection,
      resolved: go.resolved,
    });
    expect(out).toHaveProperty("definition");
  });

  test("an approved id absent from the registry has no definition key", async () => {
    seed({ project: { retired: retiredEntry() } });
    expect(await runfree("explain", "retired", "--json")).toBe(0);
    const out = JSON.parse(stdout.join("\n")) as Record<string, unknown>;
    expect(out).toMatchObject({ id: "retired", state: "enabled", layer: "project", selection: {}, resolved: retiredEntry().resolved });
    expect(out).not.toHaveProperty("definition");
  });
});

describe("C5: service diff (read-only)", () => {
  test("current entries print only current lines", async () => {
    seed({ project: { node: current("node") }, local: { go: current("go") } });
    expect(await runfree("diff")).toBe(0);
    expect(stdout).toEqual(["node (project): current", "go (local): current"]);
  });

  test("a stale entry that adds a host is a widening and nothing is written", async () => {
    const stale = staleNodeNarrow();
    seed({ project: { node: stale, python: current("python") } });
    const before = snapshot(projectFile());
    const approvals = selection();
    const next = current("node");

    expect(await runfree("diff")).toBe(0);
    expect(stdout).toEqual([
      `node (project): revision 1 -> ${SERVICES.node.revision}`,
      `  definition ${stale.definitionDigest} -> ${next.definitionDigest}`,
      `  before ${JSON.stringify(stale.resolved)}`,
      `  after  ${JSON.stringify(next.resolved)}`,
      "python (project): current",
      "authority: widening or incomparable",
      "  registry.yarnpkg.com: host added",
      "apply with: runfree service diff --apply",
    ]);
    expect(snapshot(projectFile())).toBe(before);
    expect(fs.existsSync(localFile())).toBe(false);
    expect(selection()).toEqual(approvals);
  });

  test("a stale entry that only removes hosts is a proven reduction", async () => {
    seed({ project: { python: stalePythonWide() } });
    expect(await runfree("diff")).toBe(0);
    expect(stdout).toContain("authority: proven reduction or equivalent");
    expect(stdout).not.toContain("authority: widening or incomparable");
    expect(stdout.at(-1)).toBe("apply with: runfree service diff --apply");
  });

  test("an approved id absent from the registry keeps its semantics", async () => {
    seed({ local: { retired: retiredEntry() } });
    expect(await runfree("diff")).toBe(0);
    expect(stdout).toEqual(["retired (local): definition unavailable; approved semantics retained"]);
  });
});

describe("C6: service diff refusals", () => {
  const RULE_HOST = "registry.old-npm.example";
  const NODE_REFUSAL = `service node revision ${SERVICES.node.revision} no longer allows ${RULE_HOST}, which has a host rule setting; remove it first with: runfree host rules ${RULE_HOST} --clear --service node`;
  const seedRefused = () => {
    const entry = staleNodeNarrow();
    seed({
      project: {
        node: {
          ...entry,
          selection: { hostRules: { [RULE_HOST]: { methods: ["GET"] } } },
          resolved: { ...entry.resolved, hosts: ["registry.npmjs.org", RULE_HOST] },
        },
      },
      local: { python: stalePythonWide() },
    });
  };

  test("plain diff lists the refusal and stops before the authority comparison", async () => {
    seedRefused();
    expect(await runfree("diff")).toBe(0);
    expect(stdout).toContain(`  refuses: ${NODE_REFUSAL}`);
    expect(stdout.filter((line) => line.startsWith("  refuses: "))).toHaveLength(1);
    expect(stdout.some((line) => line.startsWith("authority:"))).toBe(false);
    expect(stdout).not.toContain("apply with: runfree service diff --apply");
  });

  test("--apply refuses the whole batch before any write", async () => {
    seedRefused();
    const project = snapshot(projectFile());
    const local = snapshot(localFile());
    const approvals = selection();

    expect(await refusal("diff", "--apply", "--no-reload")).toBe(NODE_REFUSAL);
    expect(snapshot(projectFile())).toBe(project);
    expect(snapshot(localFile())).toBe(local);
    expect(selection()).toEqual(approvals);
    expect(stdout).not.toContain("effective policy: unchanged (--no-reload)");
  });
});

describe("C7: service diff --apply", () => {
  test("rewrites stale entries in both layers, carrying saved host rules", async () => {
    const hostRules = { "registry.npmjs.org": { methods: ["GET" as const] } };
    seed({ project: { node: { ...staleNodeNarrow(), selection: { hostRules } } }, local: { python: stalePythonWide() } });
    const approvals = selection();

    expect(await runfree("diff", "--apply", "--no-reload")).toBe(0);
    expect(stdout.at(-1)).toBe("effective policy: unchanged (--no-reload)");
    expect(readPolicy(projectFile()).services?.node).toEqual(current("node", { hostRules }));
    expect(readPolicy(localFile()).services?.python).toEqual(current("python"));
    const after = selection();
    expect(after?.subjects["network-project"]?.digest).not.toBe(approvals?.subjects["network-project"]?.digest);
    expect(after?.subjects["network-local"]?.digest).not.toBe(approvals?.subjects["network-local"]?.digest);

    stdout.length = 0;
    expect(await runfree("diff")).toBe(0);
    expect(stdout).toEqual(["node (project): current", "python (local): current"]);
  });

  test("without --no-reload the change is saved for the next runtime start", async () => {
    seed({ project: { python: stalePythonWide() } });
    expect(await runfree("diff", "--apply")).toBe(0);
    expect(stdout.at(-1)).toBe("effective policy: saved; applies when the runtime starts");
    expect(readPolicy(projectFile()).services?.python).toEqual(current("python"));
  });
});

describe("C8: service enable and disable", () => {
  const DIGEST = /^project digest: sha256:[0-9a-f]{64}$/;

  test("enable writes the project layer, is idempotent, and disable removes it", async () => {
    seed();
    expect(await runfree("enable", "python", "--no-reload")).toBe(0);
    expect(stdout[0]).toBe("service python: updated in project desired policy");
    const digestLine = stdout.find((line) => DIGEST.test(line));
    expect(digestLine).toBeDefined();
    expect(stdout.at(-1)).toBe("effective policy: unchanged (--no-reload)");
    expect(readPolicy(projectFile()).services?.python).toEqual(current("python"));

    stdout.length = 0;
    expect(await runfree("list")).toBe(0);
    expect(normalized()).toContain(`python project ${SERVICES.python.revision} 2`);

    stdout.length = 0;
    expect(await runfree("enable", "python", "--no-reload")).toBe(0);
    expect(stdout[0]).toBe("service python: unchanged in project desired policy");
    expect(stdout).toContain(digestLine);

    stdout.length = 0;
    expect(await runfree("disable", "python", "--no-reload")).toBe(0);
    expect(stdout).toHaveLength(4);
    expect(stdout[0]).toBe("service python: disabled in project desired policy");
    expect(stdout[1]).toMatch(DIGEST);
    expect(stdout.slice(2)).toEqual(["host-owned credential sources: unchanged", "effective policy: unchanged (--no-reload)"]);
    expect(readPolicy(projectFile()).services?.python).toBeUndefined();
  });

  test("enable --local --skip-broad records the skipped broad host in the local layer", async () => {
    seed();
    const project = snapshot(projectFile());
    expect(await runfree("enable", "go", "--local", "--skip-broad", "--no-reload")).toBe(0);
    expect(stdout[0]).toBe("service go: updated in local desired policy");
    expect(stdout).toContainEqual(expect.stringMatching(/^local digest: sha256:[0-9a-f]{64}$/));
    expect(readPolicy(localFile()).services?.go?.selection?.skippedHosts).toEqual(["storage.googleapis.com"]);
    expect(snapshot(projectFile())).toBe(project);
  });

  test("disable of a service not in the layer is refused", async () => {
    seed();
    expect(await refusal("disable", "rust", "--no-reload")).toBe("rust service is not enabled in the selected desired policy layer");
  });

  test("enable --from-env with an empty variable fails before any write", async () => {
    seed();
    vi.stubEnv("RUNFREE_TEST_UNSET_9F3A", "");
    const project = snapshot(projectFile());
    const approvals = selection();
    expect(await runfree("enable", "github", "--from-env", "RUNFREE_TEST_UNSET_9F3A", "--no-reload")).not.toBe(0);
    expect(stderr.join("\n")).toContain("RUNFREE_TEST_UNSET_9F3A is unset or empty");
    expect(snapshot(projectFile())).toBe(project);
    expect(fs.existsSync(localFile())).toBe(false);
    expect(selection()).toEqual(approvals);
  });

  test("without --no-reload enable and disable save for the next runtime start", async () => {
    seed();
    expect(await runfree("enable", "python")).toBe(0);
    expect(stdout.at(-1)).toBe("effective policy: saved; applies when the runtime starts");
    stdout.length = 0;
    expect(await runfree("disable", "python")).toBe(0);
    expect(stdout.at(-1)).toBe("effective policy: saved; applies when the runtime starts");
  });
});
