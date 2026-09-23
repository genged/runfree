import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { expect, test } from "vitest";

import { claudeMcpConfigMount, ensureMcpProjectMasks, mcpProjectMaskMounts } from "./mcp.ts";

function makeMaskProject(root: string) {
  const masksDir = path.join(root, ".runfree", "state", "mounts");
  return {
    paths: {
      claudeMcpConfigPath: path.join(masksDir, "claude-mcp.json"),
      projectCodexDirMaskPath: path.join(masksDir, "project-codex-mask"),
    },
  };
}

test("ensureMcpProjectMasks creates only the read-only Codex project mask", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-masks-"));
  const project = makeMaskProject(root);

  ensureMcpProjectMasks(project.paths);

  expect(fs.existsSync(path.join(root, ".runfree", "state", "mounts", "project-mcp.json"))).toBe(false);
  expect(fs.statSync(project.paths.projectCodexDirMaskPath).isDirectory()).toBe(true);
  expect(fs.statSync(project.paths.projectCodexDirMaskPath).mode & 0o777).toBe(0o555);
});

test("ensureMcpProjectMasks replaces stale Codex project mask contents", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-stale-codex-mask-"));
  const project = makeMaskProject(root);
  fs.mkdirSync(path.join(project.paths.projectCodexDirMaskPath, "config"), { recursive: true });
  fs.writeFileSync(path.join(project.paths.projectCodexDirMaskPath, "config", "config.toml"), "stale = true\n");

  ensureMcpProjectMasks(project.paths);

  expect(fs.readdirSync(project.paths.projectCodexDirMaskPath)).toEqual([]);
  expect(fs.statSync(project.paths.projectCodexDirMaskPath).mode & 0o777).toBe(0o555);
});

test("mcpProjectMaskMounts always masks project Codex state", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-mounts-"));
  const project = makeMaskProject(root);

  const mounts = mcpProjectMaskMounts(root, project, "/workspace");

  expect(mounts).toEqual([{
    type: "bind",
    source: project.paths.projectCodexDirMaskPath,
    target: "/workspace/.codex",
    readOnly: true,
  }]);
});

test("claudeMcpConfigMount uses the fixed Runfree-owned read-only target", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-claude-mcp-mount-"));
  const project = makeMaskProject(root);

  expect(claudeMcpConfigMount(project)).toEqual({
    type: "bind",
    source: project.paths.claudeMcpConfigPath,
    target: "/runfree/mcp/claude.json",
    readOnly: true,
  });
});
