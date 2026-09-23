import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { tmp, tmpBase, repoRoot, runTsCli, runCliInProject } from "./installable-cli.test-harness.ts";

describe("installable runfree CLI: init and image", () => {
  test("initializes the current project with runfree config and state", () => {
    const result = runCliInProject(["init"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`project: ${tmp}`);
    expect(result.stdout).toContain("outbound services: none (deny-all)");
    expect(result.stdout).toContain("start Claude or Codex to review its required operational service");
    expect(result.stdout).toContain("after the first start, enable services with: runfree service enable <id>");
    expect(result.stdout).toContain("service ids are listed by: runfree service enable --help");
    expect(result.stdout).not.toContain("runfree service configure");
    expect(result.stdout).not.toContain("reports:");
    expect(fs.existsSync(path.join(tmp, ".runfree/runfree.json"))).toBe(true);
    expect(fs.existsSync(path.join(tmp, ".runfree/network-policy.json"))).toBe(true);
    expect(fs.existsSync(path.join(tmp, "projects"))).toBe(false);
    expect(fs.existsSync(path.join(tmp, ".runfree/config"))).toBe(false);
    expect(JSON.parse(fs.readFileSync(path.join(tmp, ".runfree/network-policy.json"), "utf8"))).toEqual({ version: 2, hosts: [] });
    const config = JSON.parse(fs.readFileSync(path.join(tmp, ".runfree/runfree.json"), "utf8")) as Record<string, unknown>;
    expect(config.services).toBeUndefined();
  });

  test("image init seeds a project Dockerfile and agent build config", () => {
    const result = runTsCli(["image", "init"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`project: ${tmp}`);
    expect(result.stdout).toContain(`agent Dockerfile: ${path.join(tmp, ".runfree/image/Dockerfile")}`);
    expect(result.stdout).toContain("agent build: .runfree/image/Dockerfile");
    expect(fs.readFileSync(path.join(tmp, ".runfree/image/Dockerfile"), "utf8")).toBe([
      "ARG RUNFREE_BASE_IMAGE=runfree/agent-base:missing-runfree-base-image-build-arg",
      "FROM ${RUNFREE_BASE_IMAGE}",
      "",
      "USER root",
      "# Add project-specific packages here, for example browser dependencies.",
      "",
      "USER agent",
      "",
    ].join("\n"));
    expect(fs.existsSync(path.join(tmp, ".runfree/Dockerfile"))).toBe(false);
    expect(fs.readFileSync(path.join(tmp, ".runfree/image/.dockerignore"), "utf8")).toBe("# Build size hints only; Runfree validates the whole selected context.\n");
    const config = JSON.parse(fs.readFileSync(path.join(tmp, ".runfree/runfree.json"), "utf8")) as {
      runtime?: {
        agent?: {
          build?: unknown;
        };
      };
    };
    expect(config.runtime?.agent?.build).toEqual({
      context: ".runfree/image",
      dockerfile: ".runfree/image/Dockerfile",
    });
    expect(fs.existsSync(path.join(tmp, ".runfree/network-policy.json"))).toBe(true);
  });

  test("image approve-context rejects an unknown flag before approving any build context", () => {
    // Spec security-regression example: `runfree image approve-context --bad-flag`
    // must fail at the parser, before any host-state build-context approval write.
    const init = runTsCli(["image", "init"]);
    expect(init.status, init.stderr).toBe(0);
    const configBefore = fs.readFileSync(path.join(tmp, ".runfree/runfree.json"), "utf8");

    const result = runTsCli(["image", "approve-context", "--bad-flag"]);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("Unknown argument: bad-flag");
    expect(fs.readFileSync(path.join(tmp, ".runfree/runfree.json"), "utf8")).toBe(configBefore);
  });

  test("image init preserves an existing project Dockerfile while adding config", () => {
    const init = runTsCli(["init"]);
    expect(init.status, init.stderr).toBe(0);
    const dockerfilePath = path.join(tmp, ".runfree/image/Dockerfile");
    fs.mkdirSync(path.dirname(dockerfilePath), { recursive: true });
    const existingDockerfile = "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\nRUN echo custom\n";
    fs.writeFileSync(dockerfilePath, existingDockerfile);

    const result = runTsCli(["image", "init"]);

    expect(result.status, result.stderr).toBe(0);
    expect(fs.readFileSync(dockerfilePath, "utf8")).toBe(existingDockerfile);
    const config = JSON.parse(fs.readFileSync(path.join(tmp, ".runfree/runfree.json"), "utf8")) as {
      runtime?: {
        agent?: {
          build?: unknown;
        };
      };
    };
    expect(config.runtime?.agent?.build).toEqual({
      context: ".runfree/image",
      dockerfile: ".runfree/image/Dockerfile",
    });
  });

  test("image init leaves an existing legacy Dockerfile untouched while creating the new narrow scaffold", () => {
    const init = runTsCli(["init"]);
    expect(init.status, init.stderr).toBe(0);
    const legacyDockerfilePath = path.join(tmp, ".runfree/Dockerfile");
    const legacyDockerfile = "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\nRUN echo legacy\n";
    fs.writeFileSync(legacyDockerfilePath, legacyDockerfile);

    const result = runTsCli(["image", "init"]);

    expect(result.status, result.stderr).toBe(0);
    expect(fs.readFileSync(legacyDockerfilePath, "utf8")).toBe(legacyDockerfile);
    expect(fs.existsSync(path.join(tmp, ".runfree/image/Dockerfile"))).toBe(true);
    const config = JSON.parse(fs.readFileSync(path.join(tmp, ".runfree/runfree.json"), "utf8")) as {
      runtime?: {
        agent?: {
          build?: unknown;
        };
      };
    };
    expect(config.runtime?.agent?.build).toEqual({
      context: ".runfree/image",
      dockerfile: ".runfree/image/Dockerfile",
    });
  });

  test("image init rejects an unsafe Dockerfile path before changing config", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    const configPath = path.join(tmp, ".runfree/runfree.json");
    fs.writeFileSync(configPath, `${JSON.stringify({
      version: 4,
      agents: {
        default: "claude",
        claude: { command: "claude --dangerously-skip-permissions" },
        codex: { command: "codex --dangerously-bypass-approvals-and-sandbox" },
      },
      runtime: {},
    }, null, 2)}\n`);
    const originalConfig = fs.readFileSync(configPath, "utf8");
    const outsideDockerfile = path.join(tmp, "outside-Dockerfile");
    fs.writeFileSync(outsideDockerfile, "FROM scratch\n");
    fs.mkdirSync(path.join(tmp, ".runfree/image"), { recursive: true });
    fs.symlinkSync(outsideDockerfile, path.join(tmp, ".runfree/image/Dockerfile"));

    const result = runTsCli(["image", "init"]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("refusing to write unsafe project-controlled path: .runfree/image/Dockerfile");
    expect(fs.readFileSync(configPath, "utf8")).toBe(originalConfig);
  });

  test("image init rejects an unsafe config path before creating a Dockerfile", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    const outsideConfig = path.join(tmp, "outside-runfree.json");
    fs.writeFileSync(outsideConfig, `${JSON.stringify({
      version: 4,
      agents: {
        default: "claude",
        claude: { command: "claude --dangerously-skip-permissions" },
        codex: { command: "codex --dangerously-bypass-approvals-and-sandbox" },
      },
      runtime: {},
    }, null, 2)}\n`);
    fs.symlinkSync(outsideConfig, path.join(tmp, ".runfree/runfree.json"));

    const result = runTsCli(["image", "init"]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("refusing to write unsafe project-controlled path: .runfree/runfree.json");
    expect(fs.existsSync(path.join(tmp, ".runfree/image/Dockerfile"))).toBe(false);
  });

  test("image approve-context stores wide build approval in XDG state", () => {
    const init = runTsCli(["init"]);
    expect(init.status, init.stderr).toBe(0);
    fs.writeFileSync(path.join(tmp, ".runfree/Dockerfile"), "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n");
    fs.writeFileSync(path.join(tmp, ".runfree/runfree.json"), `${JSON.stringify({
      version: 4,
      agents: {
        default: "claude",
        claude: { command: "claude --dangerously-skip-permissions" },
        codex: { command: "codex --dangerously-bypass-approvals-and-sandbox" },
      },
      runtime: {
        agent: {
          build: {
            context: ".",
            dockerfile: ".runfree/Dockerfile",
          },
        },
      },
    }, null, 2)}\n`);

    const result = runTsCli(["image", "approve-context"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("approved wide agent build context: .");
    expect(result.stdout).toContain("Docker build runs before the Runfree sandbox");
    expect(fs.existsSync(path.join(tmp, ".runfree/approved-build-contexts.json"))).toBe(false);
    const projectsDir = path.join(tmpBase, "xdg-state/runfree/projects");
    const approvalFiles = fs.readdirSync(projectsDir)
      .map((entry) => path.join(projectsDir, entry, "approved-build-contexts.json"))
      .filter((file) => fs.existsSync(file));
    expect(approvalFiles).toHaveLength(1);
    expect(fs.readFileSync(approvalFiles[0], "utf8")).toContain("\"context\": \".\"");
  });

  test("resolves relative workspace paths from the caller directory", () => {
    const workspaceName = `relative-project-${path.basename(tmp)}`;
    const result = runCliInProject(["--workspace", workspaceName, "init"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`project: ${path.join(tmp, workspaceName)}`);
    expect(fs.existsSync(path.join(tmp, `${workspaceName}/.runfree/network-policy.json`))).toBe(true);
    expect(fs.existsSync(path.join(repoRoot, `${workspaceName}/.runfree/network-policy.json`))).toBe(false);
  });

  test("init removes legacy project and paths keys while copying a custom policy", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree/runfree.json"), `${JSON.stringify({
      version: 3,
      project: { mount: "read-only" },
      paths: {
        projects: "reports",
        networkPolicy: "custom-policy.json",
      },
      agents: {
        default: "claude",
        claude: { command: "claude --dangerously-skip-permissions" },
      },
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(tmp, "custom-policy.json"), `${JSON.stringify({ hosts: ["custom.example"], tokens: {} }, null, 2)}\n`);

    const result = runCliInProject(["init"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("migrated .runfree/runfree.json from version 3 to 4");
    const config = JSON.parse(fs.readFileSync(path.join(tmp, ".runfree/runfree.json"), "utf8")) as {
      version?: number;
      project?: unknown;
      paths?: unknown;
    };
    expect(config.version).toBe(4);
    expect(config.project).toBeUndefined();
    expect(config.paths).toBeUndefined();
    expect(fs.readFileSync(path.join(tmp, ".runfree/network-policy.json"), "utf8")).toContain("custom.example");
    expect(fs.existsSync(path.join(tmp, "projects"))).toBe(false);
  });

  test("init leaves an existing projects symlink untouched because it no longer manages that path", () => {
    const outside = path.join(tmp, "outside-projects");
    fs.mkdirSync(outside);
    fs.symlinkSync(outside, path.join(tmp, "projects"));

    const result = runTsCli(["init"]);

    expect(result.status, result.stderr).toBe(0);
    expect(fs.lstatSync(path.join(tmp, "projects")).isSymbolicLink()).toBe(true);
  });

  test("non-mutating project commands tell users to migrate legacy runfree config with init", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree/runfree.json"), `${JSON.stringify({
      version: 1,
      project: { mount: "read-write" },
      paths: {
        projects: "projects",
        networkPolicy: ".runfree/network-policy.json",
      },
      agent: {
        command: "claude --model opus --dangerously-skip-permissions",
      },
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(tmp, ".runfree/network-policy.json"), `${JSON.stringify({ hosts: [], tokens: {} }, null, 2)}\n`);

    const result = runTsCli(["status"], { RUNFREE_RUNTIME_DRY_RUN: "1" });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("run `runfree init` to migrate");
    const config = JSON.parse(fs.readFileSync(path.join(tmp, ".runfree/runfree.json"), "utf8")) as {
      version: number;
      agent?: unknown;
    };
    expect(config.version).toBe(1);
    expect(config.agent).toEqual({ command: "claude --model opus --dangerously-skip-permissions" });
  });

  test("admin commands require migration before mutating legacy runfree config", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree/runfree.json"), `${JSON.stringify({
      version: 3,
      paths: {
        projects: "reports",
        networkPolicy: "custom-policy.json",
      },
      agents: {
        default: "claude",
        claude: { command: "claude --dangerously-skip-permissions" },
      },
    }, null, 2)}\n`);

    const result = runTsCli(["host", "add", "example.org", "--no-reload"]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("uses legacy config version 3");
    expect(result.stderr).toContain("run `runfree init` to migrate to version 4");
    expect(fs.existsSync(path.join(tmp, ".runfree/config/agent.env"))).toBe(false);
    expect(fs.existsSync(path.join(tmp, ".runfree/network-policy.json"))).toBe(false);
  });

  test("init migrates legacy runfree config to the current agents shape", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree/runfree.json"), `${JSON.stringify({
      version: 1,
      project: { mount: "read-only" },
      paths: {
        projects: "projects",
        networkPolicy: ".runfree/network-policy.json",
      },
      agent: {
        command: "claude --model opus --dangerously-skip-permissions",
      },
    }, null, 2)}\n`);

    const result = runTsCli(["init"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("migrated .runfree/runfree.json from version 1 to 4");
    const config = JSON.parse(fs.readFileSync(path.join(tmp, ".runfree/runfree.json"), "utf8")) as {
      version: number;
      agent?: unknown;
      agents?: Record<string, { command?: string } | string>;
      project?: unknown;
      paths?: unknown;
    };
    expect(config.version).toBe(4);
    expect(config.agent).toBeUndefined();
    expect(config.project).toBeUndefined();
    expect(config.paths).toBeUndefined();
    expect(config.agents?.default).toBe("claude");
    expect(config.agents?.claude).toEqual({ command: "claude --model opus --dangerously-skip-permissions" });
    expect(config.agents?.codex).toEqual({
      command: "codex -c check_for_update_on_startup=false --dangerously-bypass-approvals-and-sandbox",
    });
  });

  test("init ignores unrelated dot directories instead of migrating them", () => {
    fs.mkdirSync(path.join(tmp, ".some-tool/config"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".some-tool/config/agent.env"), "GITHUB_TOKEN=do-not-copy\n");
    fs.writeFileSync(path.join(tmp, ".some-tool/network-policy.json"), `${JSON.stringify({ hosts: ["ignored.example"], tokens: {} }, null, 2)}\n`);

    const result = runTsCli(["init"]);

    expect(result.status, result.stderr).toBe(0);
    expect(fs.existsSync(path.join(tmp, ".some-tool/network-policy.json"))).toBe(true);
    expect(fs.readFileSync(path.join(tmp, ".runfree/network-policy.json"), "utf8")).not.toContain("ignored.example");
    expect(fs.existsSync(path.join(tmp, ".runfree/config/agent.env"))).toBe(false);
  });

});
