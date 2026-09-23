import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import type { Service } from "../../../scripts/services.ts";
import { createAdminState } from "./admin/context.ts";
import { runAdminAction, sourceList } from "./admin/options.ts";
import { dispatchDesiredWizardAdmin } from "./commands/init.ts";
import { ensureProject } from "./config.ts";
import type { RuntimeIO } from "./runtime/types.ts";
import {
  type WizardAdminIntent,
  buildWizardPlan,
  describeWizardIntent,
  detectedSummary,
  type InitWizardUi,
  runInitWizard,
  type WizardDetection,
  type WizardIO,
  type WizardUiPlanSelection,
} from "./init-wizard.ts";
import { cliEntryArgv } from "../../../tests/support/prebuilt-entry.ts";

const repoRoot = path.resolve(new URL("../../..", import.meta.url).pathname);
const templatesDir = path.join(repoRoot, "packages/cli/templates");

let tmp: string;

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-init-wizard-")));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function hostEnv(): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    HOME: path.join(tmp, "home"),
    XDG_CONFIG_HOME: path.join(tmp, "xdg-config"),
    XDG_DATA_HOME: path.join(tmp, "xdg-data"),
    XDG_STATE_HOME: path.join(tmp, "xdg-state"),
  };
}

function scaffoldProject(name: string): string {
  const projectRoot = path.join(tmp, name);
  fs.mkdirSync(projectRoot, { recursive: true });
  ensureProject(projectRoot, templatesDir, hostEnv());
  return projectRoot;
}

function scriptedIO(answers: string[]): { io: WizardIO; printed: string[]; asked: string[] } {
  let index = 0;
  const printed: string[] = [];
  const asked: string[] = [];
  return {
    io: {
      ask: async (question: string) => {
        asked.push(question);
        const answer = answers[index] ?? "";
        index += 1;
        return answer;
      },
      print: (line: string) => printed.push(line),
    },
    printed,
    asked,
  };
}

function snapshotTree(dir: string): Record<string, string> {
  const snapshot: Record<string, string> = {};
  const walk = (current: string) => {
    const entries = fs.readdirSync(current, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      const relative = path.relative(dir, full);
      if (entry.isDirectory()) {
        snapshot[`${relative}/`] = "<dir>";
        walk(full);
      } else {
        snapshot[relative] = fs.readFileSync(full, "latin1");
      }
    }
  };
  walk(dir);
  return snapshot;
}

type WizardDeps = Parameters<typeof runInitWizard>[0];

function wizardDeps(projectRoot: string, overrides: Partial<WizardDeps> = {}): WizardDeps & { adminCalls: WizardAdminIntent[] } {
  const adminCalls: WizardAdminIntent[] = [];
  return {
    projectRoot,
    env: hostEnv(),
    policyPath: path.join(projectRoot, ".runfree", "network-policy.json"),
    configPath: path.join(projectRoot, ".runfree", "runfree.json"),
    tokenConfigPath: path.join(tmp, "xdg-config", "runfree", "wizard-tokens.json"),
    defaultAgent: "claude",
    admin: async (intent: WizardAdminIntent) => {
      adminCalls.push(intent);
      return 0;
    },
    probeHelper: () => false,
    adminCalls,
    ...overrides,
  };
}

function fakeWizardUi(options: {
  agent?: string | undefined;
  choosePlan: (items: Parameters<InitWizardUi["choosePlan"]>[0]) => WizardUiPlanSelection | undefined;
  confirmRepoHost?: InitWizardUi["confirmRepoHost"];
}): { ui: InitWizardUi; events: string[] } {
  const events: string[] = [];
  return {
    events,
    ui: {
      chooseAgent: async (_agentNames, defaultAgent) => options.agent ?? defaultAgent,
      showDetected: (detection) => events.push(detectedSummary(detection)),
      log: (message) => events.push(message),
      choosePlan: async (items) => {
        events.push(`plan:${items.map((item) => item.label).join("|")}`);
        return options.choosePlan(items);
      },
      confirmRepoHost: async (host, notes) => {
        events.push(`confirm-host:${host}:${notes.join("|")}`);
        return options.confirmRepoHost ? options.confirmRepoHost(host, notes) : true;
      },
      itemApplied: (item) => events.push(`applied:${item.label}`),
      itemSkipped: (item) => events.push(`skipped:${item.label}`),
      itemFailed: (item, intent, status) => events.push(`failed:${item.label}:${describeWizardIntent(intent)}:${status}`),
      done: (applied, failed) => events.push(`done:${applied}:${failed}`),
      cancel: (message) => events.push(`cancel:${message}`),
    },
  };
}

const baseDetection: WizardDetection = {
  fileServiceIds: [],
  gitRemotes: { serviceIds: [], allowHosts: [], truncated: false },
  ghAvailable: false,
  opAvailable: false,
  agent: "claude",
  defaultAgent: "claude",
  enabledServiceIds: [],
  allowedHosts: [],
  credentialBindings: {},
};

const GITHUB_CLI_ENABLE: WizardAdminIntent = { kind: "service-enable", id: "github", fromSource: "github-cli" };
const GITHUB_CLI_SOURCE_ADD: WizardAdminIntent = { kind: "source-add", name: "github-cli", command: ["gh", "auth", "token"] };

describe("describeWizardIntent", () => {
  test("renders each intent as a runnable runfree command (no removed shims)", () => {
    // `allow` was never a command and `runfree source` is a removed shim; the
    // remedy parse test proves each of these parses under the real app.
    expect(describeWizardIntent({ kind: "allow-host", host: "api.example.com" })).toBe("host add api.example.com --no-reload");
    expect(describeWizardIntent({ kind: "source-add", name: "gh", command: ["gh", "auth", "token"] }))
      .toBe("credential source add gh -- gh auth token");
    expect(describeWizardIntent({ kind: "service-enable", id: "github", fromSource: "gh" }))
      .toBe("service enable github --from-source gh --no-reload");
  });
});

describe("buildWizardPlan", () => {
  test("maps detected signals to service, repo-host, source, and agent items", () => {
    const detection: WizardDetection = {
      ...baseDetection,
      fileServiceIds: ["node"],
      gitRemotes: {
        serviceIds: ["github"],
        allowHosts: [
          { host: "git.corp.example.com", punycode: false },
          { host: "xn--gthub-zra.com", punycode: true },
        ],
        truncated: false,
      },
      ghAvailable: true,
      opAvailable: true,
      agent: "codex",
      enabledServiceIds: ["node"],
      allowedHosts: ["git.corp.example.com"],
    };

    const items = buildWizardPlan(detection);
    const labels = items.map((item) => item.label);
    // node is already enabled and git.corp.example.com already allowlisted.
    expect(labels).toEqual([
      "enable service github (6 hosts, 1 broad — see note below)",
      "allow xn--gthub-zra.com",
      "add source github-cli (gh auth token)",
      "enable service github (token via source github-cli)",
      "enable service openai (API key for the codex agent)",
      "set default agent to codex",
    ]);

    const github = items[0];
    expect(github.enabled).toBe(true);
    expect(github.notes.join("\n")).toContain("note: objects.githubusercontent.com");
    expect(github.intents).toEqual([{ kind: "service-enable", id: "github" }]);

    const repoHost = items[1];
    expect(repoHost.confirmIndividually).toEqual({ host: "xn--gthub-zra.com" });
    expect(repoHost.notes[0]).toBe("this hostname comes from the repo, not from Runfree");
    expect(repoHost.notes[1]).toContain("punycode");
    expect(repoHost.intents).toEqual([{ kind: "allow-host", host: "xn--gthub-zra.com" }]);

    expect(items[2].intents).toEqual([{ kind: "source-add", name: "github-cli", command: ["gh", "auth", "token"] }]);
    expect(items[3].intents).toEqual([{ kind: "service-enable", id: "github", fromSource: "github-cli" }]);

    const provider = items[4];
    expect(provider.enabled).toBe(false);
    expect(provider.notes.join("\n")).toContain("--from-1password");

    expect(items[5]).toMatchObject({ kind: "default-agent", agent: "codex", enabled: true });
  });

  test("user-defined service detections are labeled and disabled by default", () => {
    const userService: Service = {
      id: "user-acme",
      label: "Acme internal API",
      revision: 1,
      hosts: [{ host: "api.acme.example" }],
      detect: [{ kind: "file", path: ".acme.toml" }],
      explanations: ["Acme API"],
    };
    const items = buildWizardPlan({ ...baseDetection, fileServiceIds: ["user-acme"] }, { "user-acme": userService });
    expect(items[0].label).toContain("user-defined (not curated by Runfree)");
    expect(items[0].enabled).toBe(false);
    expect(items[0].notes).toContain("user-defined service: not curated by Runfree; disabled by default");
  });

  test("an empty detection offers only the opt-in provider service, and never ubuntu-apt", () => {
    // The provider service for the chosen agent is always offered but disabled
    // by default; nothing else appears without a detection signal.
    const empty = buildWizardPlan(baseDetection);
    expect(empty.map((item) => item.kind)).toEqual(["service"]);
    expect(empty[0].enabled).toBe(false);
    const ubuntu = buildWizardPlan({ ...baseDetection, fileServiceIds: ["ubuntu-apt"] });
    expect(ubuntu.some((item) => item.label.includes("ubuntu-apt"))).toBe(false);
  });

  // The wizard's `service enable github --from-source github-cli` runs with
  // replaceSource:false, and the enforcement refuses to replace a binding to a
  // different source. The planner reads the binding first so it never plans a
  // step that is guaranteed to fail (the transcript in the todo item), and it
  // never plans a replacement either: the note names the manual command.
  test("gh available with github bound to another source plans the note, not the refused bind", () => {
    const items = buildWizardPlan({
      ...baseDetection,
      ghAvailable: true,
      enabledServiceIds: ["github"],
      credentialBindings: { github: { source: "1password", ref: "op://vault/github/token" } },
    });
    const intents = items.flatMap((item) => item.intents);
    expect(intents).not.toContainEqual(GITHUB_CLI_ENABLE);
    expect(intents).toContainEqual(GITHUB_CLI_SOURCE_ADD);
    const sourceItem = items.find((item) => item.kind === "source");
    expect(sourceItem?.notes).toEqual([
      "github credential already bound to 1password; kept as is — to switch it, run: runfree service enable github --from-source github-cli --replace-source",
    ]);
    // The note names the source kind only, never the 1Password reference.
    expect(JSON.stringify(items)).not.toContain("op://");
    expect(items.some((item) => item.label.startsWith("enable service github"))).toBe(false);
  });

  test("gh available with github already bound to github-cli plans neither gh item", () => {
    const items = buildWizardPlan({
      ...baseDetection,
      ghAvailable: true,
      enabledServiceIds: ["github"],
      credentialBindings: { github: { source: "named", name: "github-cli" } },
    });
    const intents = items.flatMap((item) => item.intents);
    expect(intents).not.toContainEqual(GITHUB_CLI_ENABLE);
    expect(intents).not.toContainEqual(GITHUB_CLI_SOURCE_ADD);
    expect(items.some((item) => item.notes.some((line) => line.includes("--replace-source")))).toBe(false);
  });

  test("gh available with github bound to github-cli under a refresh cadence still plans no gh item", () => {
    // Identity is compared with the enforcement's own equality: a binding that
    // differs only by refresh cadence would be refused, and the wizard cannot
    // reconcile that, so it points at the manual command instead of planning it.
    const items = buildWizardPlan({
      ...baseDetection,
      ghAvailable: true,
      credentialBindings: { github: { source: "named", name: "github-cli", refreshEverySeconds: 300 } },
    });
    expect(items.flatMap((item) => item.intents)).not.toContainEqual(GITHUB_CLI_ENABLE);
    expect(items.find((item) => item.kind === "source")?.notes.join("\n")).toContain("already bound to source github-cli");
  });

  test("summary names the detected signals", () => {
    expect(detectedSummary(baseDetection)).toBe("Detected: nothing to suggest");
    expect(detectedSummary({ ...baseDetection, fileServiceIds: ["node"], ghAvailable: true }))
      .toBe("Detected: project files match services: node; gh CLI on host PATH");
  });
});

describe("runInitWizard", () => {
  test("UI multiselect applies only selected plan items", async () => {
    const projectRoot = scaffoldProject("ui-multiselect");
    fs.writeFileSync(path.join(projectRoot, "package.json"), "{}");
    fs.writeFileSync(path.join(projectRoot, "pyproject.toml"), "");

    const { ui, events } = fakeWizardUi({
      choosePlan: (items) => ({
        confirmed: true,
        enabledItemIndexes: new Set(items.map((item, index) => item.label.includes("python") ? index : -1).filter((index) => index >= 0)),
      }),
    });
    const deps = wizardDeps(projectRoot, { ui });
    await runInitWizard(deps);

    expect(deps.adminCalls).toEqual([{ kind: "service-enable", id: "python" }]);
    expect(events).toContain("applied:enable service python (pypi.org, files.pythonhosted.org)");
    expect(events).toContain("done:1:0");
  });

  test("a failed item is counted, reported, and returned so init can exit nonzero", async () => {
    const projectRoot = scaffoldProject("ui-failed-item");
    fs.writeFileSync(path.join(projectRoot, "package.json"), "{}");

    const { ui, events } = fakeWizardUi({
      choosePlan: (items) => ({
        confirmed: true,
        enabledItemIndexes: new Set(items.map((item, index) => item.enabled ? index : -1).filter((index) => index >= 0)),
      }),
    });
    const adminCalls: WizardAdminIntent[] = [];
    const deps = wizardDeps(projectRoot, {
      ui,
      probeHelper: (command) => command === "gh",
      admin: async (intent) => {
        adminCalls.push(intent);
        return intent.kind === "service-enable" && intent.fromSource === "github-cli" ? 1 : 0;
      },
    });
    const outcome = await runInitWizard(deps);

    expect(outcome).toEqual({ applied: 2, failed: 1 });
    expect(adminCalls).toEqual([
      { kind: "service-enable", id: "node" },
      GITHUB_CLI_SOURCE_ADD,
      GITHUB_CLI_ENABLE,
    ]);
    expect(events).toContain(
      "failed:enable service github (token via source github-cli):service enable github --from-source github-cli --no-reload:1",
    );
    expect(events).not.toContain("applied:enable service github (token via source github-cli)");
    expect(events).toContain("done:2:1");
  });

  test("the legacy closing line never says plain Done. after a failed item", async () => {
    const projectRoot = scaffoldProject("legacy-failed-item");
    fs.writeFileSync(path.join(projectRoot, "package.json"), "{}");

    const { io, printed } = scriptedIO(["", "y"]);
    const deps = wizardDeps(projectRoot, {
      io,
      probeHelper: (command) => command === "gh",
      admin: async (intent) => (intent.kind === "service-enable" && intent.fromSource === "github-cli" ? 1 : 0),
    });
    const outcome = await runInitWizard(deps);

    expect(outcome.failed).toBe(1);
    const output = printed.join("\n");
    expect(output).toContain("failed: runfree service enable github --from-source github-cli --no-reload (exit 1)");
    expect(output).toContain("Done with 1 failed item; see the failure above.");
    expect(output).not.toMatch(/^Done\. /m);
  });

  test("the wizard reads the real token binding file and skips the bind github-cli cannot replace", async () => {
    const projectRoot = scaffoldProject("bound-elsewhere");
    const deps = wizardDeps(projectRoot, { probeHelper: (command) => command === "gh" });
    fs.mkdirSync(path.dirname(deps.tokenConfigPath), { recursive: true });
    fs.writeFileSync(deps.tokenConfigPath, JSON.stringify({
      github: { source: "1password", ref: "op://vault/github/token" },
    }));
    const before = fs.readFileSync(deps.tokenConfigPath, "utf8");

    const { ui, events } = fakeWizardUi({
      choosePlan: (items) => ({
        confirmed: true,
        enabledItemIndexes: new Set(items.map((item, index) => item.enabled ? index : -1).filter((index) => index >= 0)),
      }),
    });
    const outcome = await runInitWizard({ ...deps, ui });

    expect(outcome).toEqual({ applied: 1, failed: 0 });
    expect(deps.adminCalls).toEqual([GITHUB_CLI_SOURCE_ADD]);
    expect(events.find((event) => event.startsWith("plan:"))).not.toContain("enable service github");
    // Read-only: the binding file is untouched and its reference never surfaces.
    expect(fs.readFileSync(deps.tokenConfigPath, "utf8")).toBe(before);
    expect(events.join("\n")).not.toContain("op://");
  });

  test("a missing or malformed token binding file reads as no bindings", async () => {
    const projectRoot = scaffoldProject("no-bindings");
    const missing = wizardDeps(projectRoot, { probeHelper: (command) => command === "gh" });
    const { io: missingIo } = scriptedIO(["", "y"]);
    await runInitWizard({ ...missing, io: missingIo });
    expect(missing.adminCalls).toEqual([GITHUB_CLI_SOURCE_ADD, GITHUB_CLI_ENABLE]);

    const malformed = wizardDeps(projectRoot, { probeHelper: (command) => command === "gh" });
    fs.mkdirSync(path.dirname(malformed.tokenConfigPath), { recursive: true });
    fs.writeFileSync(malformed.tokenConfigPath, "{not json");
    const { io: malformedIo } = scriptedIO(["", "y"]);
    await runInitWizard({ ...malformed, io: malformedIo });
    // The bind is still planned; the enforcement reports the parse failure on
    // that item instead of the wizard hiding it.
    expect(malformed.adminCalls).toEqual([GITHUB_CLI_SOURCE_ADD, GITHUB_CLI_ENABLE]);
  });

  test("UI cancellation applies no plan items", async () => {
    const projectRoot = scaffoldProject("ui-cancel");
    const control = scaffoldProject("ui-cancel-control");
    fs.writeFileSync(path.join(projectRoot, "package.json"), "{}");
    fs.writeFileSync(path.join(control, "package.json"), "{}");

    const { ui, events } = fakeWizardUi({
      choosePlan: () => undefined,
    });
    const deps = wizardDeps(projectRoot, { ui });
    await runInitWizard(deps);

    expect(deps.adminCalls).toEqual([]);
    expect(events.some((event) => event.startsWith("cancel:"))).toBe(true);
    expect(snapshotTree(projectRoot)).toEqual(snapshotTree(control));
  });

  test("UI-selected repo hostnames still require separate default-deny confirmation before any admin command", async () => {
    const projectRoot = scaffoldProject("ui-repo-hosts");
    fs.writeFileSync(path.join(projectRoot, "package.json"), "{}");
    fs.mkdirSync(path.join(projectRoot, ".git"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".git", "config"), [
      '[remote "origin"]',
      "\turl = https://git.corp.example.com/o/r.git",
    ].join("\n"));

    const { ui, events } = fakeWizardUi({
      choosePlan: (items) => ({
        confirmed: true,
        enabledItemIndexes: new Set(items.map((item, index) => item.enabled ? index : -1).filter((index) => index >= 0)),
      }),
      confirmRepoHost: async () => false,
    });
    const deps = wizardDeps(projectRoot, { ui });
    await runInitWizard(deps);

    expect(deps.adminCalls).toEqual([{ kind: "service-enable", id: "node" }]);
    expect(events).toContain("confirm-host:git.corp.example.com:this hostname comes from the repo, not from Runfree");
    expect(events).toContain("skipped:allow git.corp.example.com");
    const skippedHostIndex = events.indexOf("skipped:allow git.corp.example.com");
    const appliedNodeIndex = events.findIndex((event) => event.startsWith("applied:enable service node "));
    expect(appliedNodeIndex).toBeGreaterThan(-1);
    expect(skippedHostIndex).toBeLessThan(appliedNodeIndex);
  });

  test("declining everything applies nothing and leaves the scaffold byte-for-byte identical", async () => {
    const declined = scaffoldProject("declined");
    const control = scaffoldProject("control");
    fs.writeFileSync(path.join(declined, "package.json"), "{}");
    fs.writeFileSync(path.join(control, "package.json"), "{}");

    const { io, printed } = scriptedIO(["", "n"]);
    const deps = wizardDeps(declined, { io });
    await runInitWizard(deps);

    expect(deps.adminCalls).toEqual([]);
    expect(printed.join("\n")).toContain("No changes applied");
    expect(snapshotTree(declined)).toEqual(snapshotTree(control));
  });

  test("applies confirmed items through the admin command path", async () => {
    const projectRoot = scaffoldProject("apply");
    fs.writeFileSync(path.join(projectRoot, "package.json"), "{}");

    const { io, printed } = scriptedIO(["", "y"]);
    const deps = wizardDeps(projectRoot, { io, probeHelper: (command) => command === "gh" });
    await runInitWizard(deps);

    expect(deps.adminCalls).toEqual([
      { kind: "service-enable", id: "node" },
      { kind: "source-add", name: "github-cli", command: ["gh", "auth", "token"] },
      { kind: "service-enable", id: "github", fromSource: "github-cli" },
    ]);
    expect(printed.join("\n")).toContain("applied: enable service node");
    expect(printed.join("\n")).toContain("runfree runtime reload-policy");
  });

  test("repo-derived hostnames require individual confirmation even after the plan-level yes", async () => {
    const projectRoot = scaffoldProject("repo-hosts");
    fs.mkdirSync(path.join(projectRoot, ".git"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".git", "config"), [
      '[remote "origin"]',
      "\turl = https://git.corp.example.com/o/r.git",
      '[remote "fork"]',
      "\turl = https://git.fork.example.com/o/r.git",
    ].join("\n"));

    // Agent default, plan yes, decline first host, confirm second host.
    const { io, printed } = scriptedIO(["", "y", "n", "y"]);
    const deps = wizardDeps(projectRoot, { io });
    await runInitWizard(deps);

    expect(deps.adminCalls).toEqual([{ kind: "allow-host", host: "git.fork.example.com" }]);
    expect(printed.join("\n")).toContain("this hostname comes from the repo, not from Runfree");
    expect(printed.join("\n")).toContain("skipped: allow git.corp.example.com");
  });

  test("edit toggles individual items before applying", async () => {
    const projectRoot = scaffoldProject("edit");
    fs.writeFileSync(path.join(projectRoot, "package.json"), "{}");
    fs.writeFileSync(path.join(projectRoot, "pyproject.toml"), "");

    // Agent default; edit; node off, python on, anthropic provider off; apply.
    const { io } = scriptedIO(["", "edit", "n", "y", "n", "y"]);
    const deps = wizardDeps(projectRoot, { io });
    await runInitWizard(deps);

    expect(deps.adminCalls).toEqual([{ kind: "service-enable", id: "python" }]);
  });

  test("choosing a different agent records agents.default through the raw config", async () => {
    const projectRoot = scaffoldProject("agent-choice");

    const { io } = scriptedIO(["codex", "y"]);
    const deps = wizardDeps(projectRoot, { io });
    await runInitWizard(deps);

    const raw = JSON.parse(fs.readFileSync(deps.configPath, "utf8")) as { agents: { default: string }; version: number };
    expect(raw.agents.default).toBe("codex");
    expect(raw.version).toBe(4);
    // The provider service stays an explicit opt-in (default off).
    expect(deps.adminCalls).toEqual([]);
  });
});

describe("non-interactive init never prompts", () => {
  function runTsCli(projectRoot: string, args: string[]): childProcess.SpawnSyncReturns<string> {
    return childProcess.spawnSync(process.execPath, [...cliEntryArgv(), "--workspace", projectRoot, ...args], {
      cwd: repoRoot,
      encoding: "utf8",
      // Piped stdio: stdin/stdout are not TTYs, so the wizard must not run.
      input: "",
      env: {
        ...process.env,
        HOME: path.join(tmp, "home"),
        XDG_CONFIG_HOME: path.join(tmp, "xdg-config"),
        XDG_DATA_HOME: path.join(tmp, "xdg-data"),
        XDG_STATE_HOME: path.join(tmp, "xdg-state"),
      },
    });
  }

  test("non-TTY init and init --yes both scaffold without prompting and produce identical projects", () => {
    const nonTty = path.join(tmp, "non-tty");
    const explicitYes = path.join(tmp, "explicit-yes");
    fs.mkdirSync(nonTty, { recursive: true });
    fs.mkdirSync(explicitYes, { recursive: true });
    // A detectable ecosystem signal that must NOT trigger prompts here.
    fs.writeFileSync(path.join(nonTty, "package.json"), "{}");
    fs.writeFileSync(path.join(explicitYes, "package.json"), "{}");

    const nonTtyResult = runTsCli(nonTty, ["init"]);
    expect(nonTtyResult.status, nonTtyResult.stderr).toBe(0);
    expect(nonTtyResult.stdout).not.toContain("Apply?");
    expect(nonTtyResult.stdout).not.toContain("Agent [");

    const yesResult = runTsCli(explicitYes, ["init", "--yes"]);
    expect(yesResult.status, yesResult.stderr).toBe(0);
    expect(yesResult.stdout).not.toContain("Apply?");

    expect(snapshotTree(path.join(nonTty, ".runfree"))).toEqual(snapshotTree(path.join(explicitYes, ".runfree")));
  });

  test("init rejects unknown flags", () => {
    const projectRoot = path.join(tmp, "bad-flag");
    fs.mkdirSync(projectRoot, { recursive: true });
    const result = runTsCli(projectRoot, ["init", "--bogus"]);
    expect(result.status).toBe(1);
    // `init` is a typed command; the strict yargs grammar reports the offending
    // flag instead of the legacy hand-written usage line.
    expect(result.stderr).toContain("Unknown argument: bogus");
  });
});

describe("dispatchDesiredWizardAdmin (wizard apply -> typed enforcement)", () => {
  function wizardAdminState(): ReturnType<typeof createAdminState> {
    const projectRoot = path.join(tmp, "wizard-proj");
    fs.mkdirSync(path.join(projectRoot, ".runfree"), { recursive: true });
    fs.writeFileSync(
      path.join(projectRoot, ".runfree", "network-policy.json"),
      JSON.stringify({ hosts: [], tokens: {} }),
    );
    const stateDir = path.join(tmp, "wizard-state");
    return createAdminState({
      projectRoot,
      policyPath: path.join(projectRoot, ".runfree", "network-policy.json"),
      tokenConfigPath: path.join(stateDir, "tokens.json"),
      // Isolate the host-owned source registry under tmp; otherwise it resolves
      // to ~/.config/runfree/sources.json and both leaks host state and makes the
      // 'source add applies' assertion a tautology once that file persists.
      sourceConfigPath: path.join(stateDir, "sources.json"),
      stateDir,
      env: { ...process.env, RUNFREE_STATE_DIR: stateDir },
    });
  }

  // The wizard's intent vocabulary is a closed union (WizardAdminIntent), so an
  // unknown action is a compile error, not a runtime string to reject. The
  // source-add case manages host-owned source config only, so it needs no
  // runtime context or IO.
  test("applies 'source add' through the typed enforcement (no runAdmin)", async () => {
    const adminState = wizardAdminState();
    const noContext = undefined as unknown as Parameters<typeof dispatchDesiredWizardAdmin>[1];
    const noIo = undefined as unknown as Parameters<typeof dispatchDesiredWizardAdmin>[2];

    const status = await runAdminAction(adminState, () =>
      dispatchDesiredWizardAdmin(
        { kind: "source-add", name: "wizard-src", command: ["node", "-e", "process.stdout.write('tok')"] },
        noContext,
        noIo,
      ),
    );
    expect(status).toBe(0);

    const lines: string[] = [];
    const originalLog = console.log;
    console.log = (...args: unknown[]) => {
      lines.push(args.join(" "));
    };
    try {
      await runAdminAction(adminState, () => sourceList());
    } finally {
      console.log = originalLog;
    }
    expect(lines).toContain("wizard-src");
  });

  test("applies v4 host and service choices as approved desired-policy transactions", async () => {
    const projectRoot = scaffoldProject("desired-wizard-proj");
    const env = hostEnv();
    const project = ensureProject(projectRoot, templatesDir, env);
    const runtime = { projectRoot, project, runtimeRoot: repoRoot, env };
    const io: RuntimeIO = {
      capture: () => ({ status: 0, stdout: "", stderr: "" }),
      run: () => 0,
      commandExists: () => false,
      confirm: () => false,
      admin: async () => 0,
    };
    const adminState = createAdminState({
      agentEnvPath: project.paths.controlAgentEnvPath,
      projectRoot,
      packageRoot: repoRoot,
      policyPath: project.paths.policyPath,
      policyAccess: "effective-read-only",
      tokenConfigPath: project.paths.tokenConfigPath,
      stateDir: project.paths.stateDir,
      env,
    });

    expect(await runAdminAction(adminState, () =>
      dispatchDesiredWizardAdmin({ kind: "allow-host", host: "git.example.com" }, runtime, io))).toBe(0);
    expect(await runAdminAction(adminState, () =>
      dispatchDesiredWizardAdmin({ kind: "service-enable", id: "node" }, runtime, io))).toBe(0);

    const policy = JSON.parse(fs.readFileSync(project.paths.policyPath, "utf8")) as {
      hosts: string[];
      services?: Record<string, unknown>;
      version: number;
    };
    expect(policy.version).toBe(2);
    expect(policy.hosts).toContain("git.example.com");
    expect(policy.services).toHaveProperty("node");
    expect(fs.existsSync(path.join(projectRoot, ".runfree", "services.json"))).toBe(false);
  });
});
