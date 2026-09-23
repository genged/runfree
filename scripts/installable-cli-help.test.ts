import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { RUNFREE_VERSION } from "../packages/cli/src/embedded-assets.generated.ts";
import { projectHash } from "../packages/cli/src/project-identity.ts";
import { tmp, runTsCli, runCliInProject } from "./installable-cli.test-harness.ts";

describe("installable runfree CLI: help and usage", () => {
  test("help and --help default to the full hierarchical command reference", () => {
    const result = runCliInProject(["help"]);

    expect(result.status, result.stderr).toBe(0);
    // Hierarchical: sectioned, listing every command group and global options —
    // not a short index that name-drops topics as if they were commands.
    expect(result.stdout).toContain("Global options:");
    expect(result.stdout).toContain("Project setup:");
    expect(result.stdout).toContain("Network policy:");
    expect(result.stdout).toContain("runfree service enable <id>");
    expect(result.stdout).toContain("runfree service diff [--apply] [--no-reload]");
    expect(result.stdout).not.toContain("Common paths:");
    // Task guides are clearly framed as `runfree help <topic>`, never as a bare
    // `credentials`/`network` command.
    expect(result.stdout).toContain("runfree help quickstart");
    expect(result.stdout).toContain("runfree help credentials");

    // --help and -h render the same reference.
    const dashHelp = runCliInProject(["--help"]);
    expect(dashHelp.status, dashHelp.stderr).toBe(0);
    expect(dashHelp.stdout).toContain("Project setup:");
    expect(dashHelp.stdout).toContain("Network policy:");
  });

  test("help topics show focused task guidance", () => {
    const result = runCliInProject(["help", "quickstart"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Quickstart");
    expect(result.stdout).toContain("runfree init");
    expect(result.stdout).toContain("runfree");
    expect(result.stdout).toContain("runfree up --audit-network");
    expect(result.stdout).toContain("runfree audit report");
    expect(result.stdout).not.toContain("runfree mcp approve");
  });

  test("unknown help topics fail with available topics", () => {
    const result = runCliInProject(["help", "bogus"]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("unknown help topic: bogus");
    expect(result.stderr).toContain("quickstart");
    expect(result.stderr).toContain("all");
  });

  test("help all lists every public command group and subcommand", () => {
    const result = runCliInProject(["help", "all"]);

    expect(result.status, result.stderr).toBe(0);
    for (const text of [
      "runfree [--workspace <project-dir>] [claude|codex|pi]",
      "runfree init",
      "runfree image init",
      "runfree image approve-context",
      "runfree codex",
      "runfree pi",
      "runfree shell",
      "runfree deps plan",
      "runfree deps install",
      "runfree deps doctor",
      "runfree deps reset",
      "runfree git repair-worktree-links",
      "runfree inbox paste [--copy]    Import a macOS clipboard image",
      "runfree inbox clean [--all]     Remove old or all Runfree-minted inbox files",
      "runfree up",
      "runfree rebuild",
      "runfree sessions",
      "runfree resume",
      "runfree project-id",
      "runfree status",
      "runfree resources",
      "runfree stop",
      "runfree destroy",
      "runfree logs proxy",
      "runfree logs proxy --verbose",
      "runfree assets status",
      "runfree assets clean",
      "runfree host add <host>",
      "runfree host rules <host>",
      "runfree host remove <host>",
      "runfree host list",
      "runfree host explain <host>",
      "runfree credential source add <name>",
      "runfree credential source list",
      "runfree credential source show <name>",
      "runfree credential source remove <name>",
      "runfree credential add <name>",
      "runfree credential link <name>",
      "runfree credential unlink <name>",
      "runfree credential remove <name>",
      "runfree credential set-source <name>",
      "runfree credential clear-source <name>",
      "runfree credential status",
      "runfree credential sync",
      "runfree service list",
      "runfree service enable <id>",
      "runfree service custom add <id>",
      "runfree service custom remove <id>",
      "runfree service disable <id> [--local] [--no-reload]",
      "runfree service explain <id>",
      "runfree service diff [--apply] [--no-reload]",
      "runfree [--workspace <project-dir>] init [--yes]",
      "MCP servers:",
      "claude mcp",
      "codex mcp",
      "runfree mcp list [--json]",
      "runfree mcp explain <agent> <server>",
      "runfree mcp approve <agent> <server>",
      "runfree mcp revoke <agent> <server>",
      "Runfree imports supported host MCP entries when the sandbox starts",
      "runfree runtime reload-policy",
      "runfree doctor",
      "runfree update",
      "runfree version",
      "runfree help quickstart",
      "runfree help credentials",
    ]) {
      expect(result.stdout).toContain(text);
    }
    expect(result.stdout).not.toContain("runfree paste-image");
    expect(result.stdout).toContain("runfree deps plan               Show dependency overlay mounts for this project");
    expect(result.stdout).not.toContain("Show JavaScript dependency overlay mounts");
    expect(result.stdout).toContain("--from-source <name>");
    expect(result.stdout).not.toContain("runfree allow ");
    expect(result.stdout).not.toContain("runfree down");
    expect(result.stdout).not.toContain("runfree token create");
    expect(result.stdout).not.toContain("runfree reload-proxy");
    expect(result.stdout).not.toContain("runfree service define");
    expect(result.stdout).not.toContain("runfree service undefine");
    expect(result.stdout).not.toContain("runfree prepare");
  });

  test("credential source inspection does not initialize project files", () => {
    const result = runTsCli(["credential", "source", "list"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("");
    expect(fs.existsSync(path.join(tmp, ".runfree"))).toBe(false);
  });

  test("project-id prints the project hash and compose name without initializing the project", () => {
    const id = runCliInProject(["project-id"]);
    expect(id.status, id.stderr).toBe(0);
    expect(id.stdout.trim()).toBe(projectHash(tmp));

    const composeName = runCliInProject(["project-id", "--compose-name"]);
    expect(composeName.status, composeName.stderr).toBe(0);
    expect(composeName.stdout.trim()).toBe(`runfree-${projectHash(tmp)}`);

    expect(fs.existsSync(path.join(tmp, ".runfree"))).toBe(false);
  });

  test("accepts --workspace before a migrated command", () => {
    const result = runCliInProject(["--workspace", ".", "project-id"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe(projectHash(tmp));
  });

  test("rejects --workspace after a migrated command without initializing the project", () => {
    const result = runCliInProject(["project-id", "--workspace", "."]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Unknown argument: workspace");
    expect(fs.existsSync(path.join(tmp, ".runfree"))).toBe(false);
  });

  test("reports unknown options on a migrated command as a usage error", () => {
    const result = runCliInProject(["project-id", "--bogus"]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Unknown argument: bogus");
    expect(fs.existsSync(path.join(tmp, ".runfree"))).toBe(false);
  });

  test("prints command-specific help for migrated commands", () => {
    const version = runCliInProject(["version", "--help"]);
    expect(version.status, version.stderr).toBe(0);
    expect(version.stdout).toContain("runfree version");
    expect(version.stdout).toContain("Print the Runfree version");

    const assets = runCliInProject(["assets", "--help"]);
    expect(assets.status, assets.stderr).toBe(0);
    // Native yargs help: synopsis from the command string + the choices positional.
    expect(assets.stdout).toContain("runfree assets <subcommand>");
    expect(assets.stdout).toContain("status");
    expect(assets.stdout).toContain("clean");
  });

  test("subcommand help documents grouped, described options (Approach 1 contract)", () => {
    // The value of native per-command help is that every option is documented
    // under its group with a description. Guard the flagship credential command
    // so a dropped describe/group regresses loudly (it otherwise passes silently).
    const help = runCliInProject(["mcp", "approve", "--help"]);
    expect(help.status, help.stderr).toBe(0);
    expect(help.stdout).toContain("runfree mcp approve <agent> <server>");
    expect(help.stdout).toContain("Credential source (choose at most one):");
    expect(help.stdout).toContain("--from-env");
    expect(help.stdout).toContain("Read the token from this host env var");
    expect(help.stdout).toContain("--from-source");
    expect(help.stdout).toContain("Bind a previously-saved host-owned source");
  });

  test("assets status reports the installed embedded runtime asset version", () => {
    const result = runTsCli(["assets", "status"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`version: ${RUNFREE_VERSION}`);
    expect(result.stdout).toContain("current:");
  });

});
