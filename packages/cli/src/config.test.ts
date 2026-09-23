import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  defaultConfig,
  ensureProject,
  projectInfo,
  QUIESCED_CONFIG_MIGRATION,
  readConfig,
  readRawProjectConfig,
  resolveAgentCommand,
  resolveAgentResumeCommand,
  resolveDefaultAgentCommand,
} from "./config.ts";
import { CliError } from "./errors.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-config-tests-")));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("runfree config", () => {
  test("rejects a symlinked .runfree root before reading config descendants", () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-outside-config-"));
    try {
      fs.writeFileSync(path.join(outside, "runfree.json"), `${JSON.stringify({ version: 3 })}\n`);
      fs.symlinkSync(outside, path.join(tmp, ".runfree"), "dir");

      expect(() => readConfig(tmp)).toThrow("project .runfree root is not a normal directory: .runfree (symlink)");
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  test("rejects a dangling .runfree root symlink instead of treating config as absent", () => {
    fs.symlinkSync(path.join(tmp, "missing-runfree-target"), path.join(tmp, ".runfree"), "dir");

    expect(() => readConfig(tmp)).toThrow("project .runfree root is not a normal directory: .runfree (symlink)");
  });

  test("rejects a non-directory .runfree root before reading config descendants", () => {
    fs.writeFileSync(path.join(tmp, ".runfree"), "not a directory\n");

    expect(() => readConfig(tmp)).toThrow("project .runfree root is not a directory: .runfree (regular file)");
  });

  test("rejects a symlinked config file before parsing its external target", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"));
    const outside = path.join(tmp, "outside-runfree.json");
    fs.writeFileSync(outside, `${JSON.stringify({ version: 4 })}\n`);
    fs.symlinkSync(outside, path.join(tmp, ".runfree", "runfree.json"));

    expect(() => readConfig(tmp))
      .toThrow("refusing to write unsafe project-controlled path: .runfree/runfree.json");
  });

  test("rejects a hard-linked config file before parsing it", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"));
    const outside = path.join(tmp, "outside-runfree.json");
    fs.writeFileSync(outside, `${JSON.stringify({ version: 4 })}\n`);
    fs.linkSync(outside, path.join(tmp, ".runfree", "runfree.json"));

    expect(() => readConfig(tmp))
      .toThrow("refusing to write unsafe project-controlled path: .runfree/runfree.json");
  });

  test("default and existing project configs include Pi without a version bump", () => {
    expect(resolveAgentCommand(readConfig(tmp), "pi")).toBe("pi");

    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 3,
      agents: {
        default: "claude",
        claude: { command: "claude --dangerously-skip-permissions" },
        codex: { command: "codex --dangerously-bypass-approvals-and-sandbox" },
      },
    }, null, 2)}\n`);

    const config = readConfig(tmp);

    expect(resolveAgentCommand(config, "pi")).toBe("pi");
    expect(config.version).toBe(3);
  });

  test("resolves former built-in defaults to the current managed command without changing custom commands", () => {
    const config = defaultConfig();
    config.agents.claude = { command: "claude --dangerously-skip-permissions" };
    config.agents.codex = { command: "codex --dangerously-bypass-approvals-and-sandbox" };

    expect(resolveAgentCommand(config, "claude"))
      .toBe("claude --dangerously-skip-permissions --add-dir /runfree/inbox");
    expect(resolveAgentCommand(config, "codex"))
      .toBe("codex -c check_for_update_on_startup=false --dangerously-bypass-approvals-and-sandbox");

    config.agents.claude = { command: "claude --model opus --dangerously-skip-permissions" };
    expect(resolveAgentCommand(config, "claude"))
      .toBe("claude --model opus --dangerously-skip-permissions");
  });

  test("normalizes legacy agent.command as the Claude agent command", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 1,
      agent: {
        command: "claude --model opus --dangerously-skip-permissions",
      },
    }, null, 2)}\n`);

    const config = readConfig(tmp);

    expect(resolveAgentCommand(config, "claude")).toBe("claude --model opus --dangerously-skip-permissions");
    expect(resolveDefaultAgentCommand(config)).toBe("claude --model opus --dangerously-skip-permissions");
    expect(resolveAgentCommand(config, "codex"))
      .toBe("codex -c check_for_update_on_startup=false --dangerously-bypass-approvals-and-sandbox");
    expect(resolveAgentCommand(config, "pi")).toBe("pi");
  });

  test("rejects unsupported agent config keys", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 3,
      agents: {
        default: "claude",
        claude: {
          command: "claude --dangerously-skip-permissions",
          env: {
            AWS_PROFILE: "host",
          },
        },
      },
    }, null, 2)}\n`);

    expect(() => readConfig(tmp)).toThrow("agents.claude.env is not supported; agent config only supports command");
  });

  test("accepts an explicit custom resume command without interpreting it", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 3,
      agents: {
        default: "claude",
        claude: {
          command: "claude --model opus",
          resumeCommand: "claude --model opus --resume \"$RUNFREE_RESUME_SESSION\"",
        },
      },
    }, null, 2)}\n`);

    const config = readConfig(tmp);

    expect(resolveAgentResumeCommand(config, "claude")).toBe(
      "claude --model opus --resume \"$RUNFREE_RESUME_SESSION\"",
    );
  });

  test("accepts project.name without treating project config as legacy", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 4,
      project: { name: "  Client / API  " },
      agents: {
        default: "claude",
        claude: { command: "claude --dangerously-skip-permissions" },
      },
    }, null, 2)}\n`);

    const project = projectInfo(tmp, { XDG_STATE_HOME: path.join(tmp, "state") });

    expect(project.config.project).toEqual({ name: "  Client / API  " });
    expect(project.configMigration).toBeUndefined();
  });

  test("refuses legacy migration outside a quiesced transaction before policy writes", () => {
    const runfreeDir = path.join(tmp, ".runfree");
    fs.mkdirSync(runfreeDir, { recursive: true });
    const configPath = path.join(runfreeDir, "runfree.json");
    const policyPath = path.join(runfreeDir, "network-policy.json");
    fs.writeFileSync(configPath, '{"version":3,"agents":{"default":"claude"}}\n');
    fs.writeFileSync(policyPath, '{"hosts":["example.com"]}\n');
    const templatesDir = path.join(tmp, "templates");
    fs.mkdirSync(templatesDir);
    fs.writeFileSync(path.join(templatesDir, "network-policy.json"), '{"version":2,"hosts":[]}\n');
    fs.writeFileSync(path.join(templatesDir, "runfree.json"), '{"version":4,"agents":{"default":"claude"}}\n');
    const configBefore = fs.readFileSync(configPath, "utf8");
    const policyBefore = fs.readFileSync(policyPath, "utf8");

    expect(() => ensureProject(tmp, templatesDir, {
      XDG_STATE_HOME: path.join(tmp, "state"),
    }, { migrateConfig: true })).toThrow("requires a quiesced runtime transaction");

    expect(fs.readFileSync(configPath, "utf8")).toBe(configBefore);
    expect(fs.readFileSync(policyPath, "utf8")).toBe(policyBefore);
  });

  test("migrates legacy project keys while preserving project.name", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 3,
      project: { mount: "read-only", name: "visible-repo" },
      agents: {
        default: "claude",
        claude: { command: "claude --dangerously-skip-permissions" },
      },
    }, null, 2)}\n`);

    const templatesDir = path.join(tmp, "templates");
    fs.mkdirSync(templatesDir);
    fs.writeFileSync(path.join(templatesDir, "network-policy.json"), `${JSON.stringify({ hosts: [], tokens: {} }, null, 2)}\n`);
    fs.writeFileSync(path.join(templatesDir, "runfree.json"), `${JSON.stringify({ version: 3, agents: { default: "claude" }, runtime: {} }, null, 2)}\n`);

    const project = ensureProject(tmp, templatesDir, {
      XDG_STATE_HOME: path.join(tmp, "state"),
    }, { migrateConfig: true, migrationProof: QUIESCED_CONFIG_MIGRATION });
    const stored = JSON.parse(fs.readFileSync(path.join(tmp, ".runfree", "runfree.json"), "utf8")) as {
      project?: Record<string, unknown>;
    };

    expect(project.configMigrated).toEqual({ fromVersion: 3, toVersion: 4 });
    expect(stored.project).toEqual({ name: "visible-repo" });
  });

  test("config v4 migration moves legacy service authority into desired policy", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 1,
      agent: { command: "claude --dangerously-skip-permissions" },
      services: {
        python: { revision: 1, hosts: ["pypi.org"] },
      },
    }, null, 2)}\n`);

    const templatesDir = path.join(tmp, "templates");
    fs.mkdirSync(templatesDir);
    fs.writeFileSync(path.join(tmp, ".runfree", "network-policy.json"), `${JSON.stringify({
      hosts: ["pypi.org"],
      requests: { "pypi.org": { methods: ["GET"] } },
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(templatesDir, "network-policy.json"), `${JSON.stringify({ version: 2, hosts: [] }, null, 2)}\n`);
    fs.writeFileSync(path.join(templatesDir, "runfree.json"), `${JSON.stringify({ version: 4, agents: { default: "claude" }, runtime: {} }, null, 2)}\n`);

    const project = ensureProject(tmp, templatesDir, {
      XDG_STATE_HOME: path.join(tmp, "state"),
    }, { migrateConfig: true, migrationProof: QUIESCED_CONFIG_MIGRATION });
    const stored = JSON.parse(fs.readFileSync(path.join(tmp, ".runfree", "runfree.json"), "utf8")) as Record<string, unknown>;

    const desired = JSON.parse(fs.readFileSync(path.join(tmp, ".runfree", "network-policy.json"), "utf8")) as {
      services?: Record<string, unknown>;
      version?: number;
    };
    expect(project.configMigrated).toEqual({ fromVersion: 1, toVersion: 4 });
    expect(stored.version).toBe(4);
    expect(stored.services).toBeUndefined();
    expect(desired.version).toBe(2);
    expect(desired.services?.python).toMatchObject({
      revision: 1,
      resolved: {
        hosts: ["pypi.org"],
      },
    });
    expect((desired as { requests?: unknown }).requests).toEqual({
      "pypi.org": { methods: ["GET"] },
    });
    expect((stored as { config?: unknown }).config).toBeUndefined();
  });

  test("readRawProjectConfig exposes unknown keys the typed config drops", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    const configPath = path.join(tmp, ".runfree", "runfree.json");
    fs.writeFileSync(configPath, `${JSON.stringify({
      version: 3,
      services: { node: { revision: 1 } },
    }, null, 2)}\n`);

    expect(readRawProjectConfig(tmp, configPath)).toEqual({
      version: 3,
      services: { node: { revision: 1 } },
    });
    expect((readConfig(tmp) as unknown as { services?: unknown }).services).toBeUndefined();
  });

  test("ensureProject leaves a legacy domains policy untouched", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    const policyPath = path.join(tmp, ".runfree", "network-policy.json");
    const legacy = `${JSON.stringify({ domains: ["api.github.com"], tokens: {} }, null, 2)}\n`;
    fs.writeFileSync(policyPath, legacy);

    const templatesDir = path.join(tmp, "templates");
    fs.mkdirSync(templatesDir);
    fs.writeFileSync(path.join(templatesDir, "network-policy.json"), `${JSON.stringify({ hosts: [], tokens: {} }, null, 2)}\n`);
    fs.writeFileSync(path.join(templatesDir, "runfree.json"), `${JSON.stringify({ version: 3, agents: { default: "claude" }, runtime: {} }, null, 2)}\n`);

    ensureProject(tmp, templatesDir, { XDG_STATE_HOME: path.join(tmp, "state") });
    expect(fs.readFileSync(policyPath, "utf8")).toBe(legacy);
  });

  test("initializes local .runfree gitignore entries for host-owned config and state", () => {
    const templatesDir = path.join(tmp, "templates");
    fs.mkdirSync(templatesDir);
    fs.writeFileSync(path.join(templatesDir, "network-policy.json"), `${JSON.stringify({ hosts: [], tokens: {} }, null, 2)}\n`);
    fs.writeFileSync(path.join(templatesDir, "runfree.json"), `${JSON.stringify({ version: 3, agents: { default: "claude" }, runtime: {} }, null, 2)}\n`);

    ensureProject(tmp, templatesDir, {
      XDG_STATE_HOME: path.join(tmp, "state"),
    });

    expect(fs.readFileSync(path.join(tmp, ".runfree", ".gitignore"), "utf8")).toBe([
      "state/",
      "config/tokens.json",
      "config/agent.env",
      "",
    ].join("\n"));
  });

  test("rejects blank project.name", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 3,
      project: { name: "  " },
    }, null, 2)}\n`);

    expect(() => readConfig(tmp)).toThrow("project.name must be a non-empty string");
  });

  test("accepts dependency overlay runtime policy", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 3,
      runtime: {
        dependencyOverlays: "off",
      },
    }, null, 2)}\n`);

    expect(readConfig(tmp).runtime.dependencyOverlays).toBe("off");
  });

  test("rejects unsupported dependency overlay runtime policy", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 3,
      runtime: {
        dependencyOverlays: "required",
      },
    }, null, 2)}\n`);

    expect(() => readConfig(tmp)).toThrow("runtime.dependencyOverlays must be either \"auto\" or \"off\"");
  });

  test("validates the write-approval posture and hold window before any runtime startup", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    const writeRuntime = (runtime: Record<string, unknown>) => {
      fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({ version: 3, runtime }, null, 2)}\n`);
    };

    writeRuntime({ writeApproval: "allow", writeApprovalHoldSeconds: 60 });
    expect(readConfig(tmp).runtime.writeApproval).toBe("allow");
    expect(readConfig(tmp).runtime.writeApprovalHoldSeconds).toBe(60);

    writeRuntime({ writeApproval: "block" });
    expect(() => readConfig(tmp)).toThrow("runtime.writeApproval must be \"allow\", \"ask\", or \"deny\"");

    for (const value of [4, 301, 12.5, "120"]) {
      writeRuntime({ writeApprovalHoldSeconds: value });
      expect(() => readConfig(tmp), String(value)).toThrow("runtime.writeApprovalHoldSeconds must be an integer between 5 and 300");
    }
  });

  test("rejects legacy write authority and unknown runtime keys in config v4", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    const writeRuntime = (runtime: Record<string, unknown>) => {
      fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({ version: 4, runtime }, null, 2)}\n`);
    };

    writeRuntime({ writeApproval: "ask" });
    expect(() => readConfig(tmp)).toThrow("runtime.writeApproval is not supported by config version 4");

    writeRuntime({ unexpectedAuthority: true });
    expect(() => readConfig(tmp)).toThrow("runtime.unexpectedAuthority is not supported by config version 4");
  });

  test("new v4 projects do not create the inert legacy agent env file", () => {
    const templatesDir = path.join(tmp, "templates");
    fs.mkdirSync(templatesDir);
    fs.writeFileSync(path.join(templatesDir, "network-policy.json"), `${JSON.stringify({ version: 2, hosts: [] }, null, 2)}\n`);
    fs.writeFileSync(path.join(templatesDir, "runfree.json"), `${JSON.stringify({ version: 4, agents: { default: "claude" }, runtime: {} }, null, 2)}\n`);

    ensureProject(tmp, templatesDir, { XDG_STATE_HOME: path.join(tmp, "state") });

    expect(fs.existsSync(path.join(tmp, ".runfree", "config", "agent.env"))).toBe(false);
  });

  test("marks removed project and paths config keys for migration", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 3,
      project: { mount: "read-only" },
      paths: {
        projects: "reports",
        networkPolicy: "network-policy.json",
      },
      agents: {
        default: "claude",
        claude: { command: "claude --dangerously-skip-permissions" },
      },
    }, null, 2)}\n`);

    const project = projectInfo(tmp, { XDG_STATE_HOME: path.join(tmp, "state") });

    expect(project.configMigration).toEqual({ fromVersion: 3, toVersion: 4 });
    expect(project.paths.policyPath).toBe(path.join(tmp, ".runfree", "network-policy.json"));
  });

  test("rejects host-owned token config paths that realpath into the project", () => {
    const projectRoot = path.join(tmp, "project");
    const projectOwnedConfig = path.join(projectRoot, "project-owned-config");
    const hostConfigLink = path.join(tmp, "host-config-link");
    fs.mkdirSync(projectOwnedConfig, { recursive: true });
    fs.symlinkSync(projectOwnedConfig, hostConfigLink, "dir");

    expect(() => ensureProject(projectRoot, path.join(tmp, "templates"), {
      XDG_CONFIG_HOME: hostConfigLink,
      XDG_STATE_HOME: path.join(tmp, "state"),
    })).toThrow("token source config path must be outside the project");
  });

  test("normalizes project agent build config", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 2,
      runtime: {
        agent: {
          build: {
            dockerfile: ".runfree/Dockerfile",
            target: "runfree-agent",
            args: {
              EXAMPLE_VERSION: "1.2.3",
            },
          },
        },
      },
    }, null, 2)}\n`);

    const config = readConfig(tmp);

    expect(config.runtime.agent?.build).toEqual({
      context: ".",
      dockerfile: ".runfree/Dockerfile",
      target: "runfree-agent",
      args: {
        EXAMPLE_VERSION: "1.2.3",
      },
    });
  });

  test("rejects unsupported runtime agent image override", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 2,
      runtime: {
        agent: {
          image: "example/custom-agent:latest",
        },
      },
    }, null, 2)}\n`);

    expect(() => readConfig(tmp)).toThrow(CliError);
    expect(() => readConfig(tmp)).toThrow("runtime.agent.image is not supported");
  });

  test("rejects reserved project agent build args", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 2,
      runtime: {
        agent: {
          build: {
            dockerfile: ".runfree/Dockerfile",
            args: {
              RUNFREE_BASE_IMAGE: "other",
            },
          },
        },
      },
    }, null, 2)}\n`);

    expect(() => readConfig(tmp)).toThrow("reserved RUNFREE_ build arg");
  });

  test("rejects project agent build paths outside the project root", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree", "runfree.json"), `${JSON.stringify({
      version: 2,
      runtime: {
        agent: {
          build: {
            context: "..",
            dockerfile: ".runfree/Dockerfile",
          },
        },
      },
    }, null, 2)}\n`);

    expect(() => readConfig(tmp)).toThrow("runtime.agent.build.context must resolve inside the project root");
  });
});
