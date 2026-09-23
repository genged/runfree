import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { expect, test, vi } from "vitest";

import { loadPolicy, runAdminAction } from "./admin-core.ts";
import { createAdminState } from "./context.ts";

test("createAdminState resolves host-owned token config outside project", () => {
  const projectRoot = "/workspace/project";
  const state = createAdminState({
    projectRoot,
    packageRoot: "/workspace",
    env: {
      HOME: "/home/user",
      XDG_CONFIG_HOME: "/home/user/.config",
      RUNFREE_PROJECT_ID: "project-id",
    },
  });

  expect(state.projectRoot).toBe(projectRoot);
  expect(state.tokenConfigPath).toContain(path.join(".config", "runfree", "projects", "project-id", "tokens.json"));
  expect(state.tokenConfigPath.startsWith(projectRoot)).toBe(false);
});

test("createAdminState keeps docker env sanitized", () => {
  const state = createAdminState({
    projectRoot: "/workspace/project",
    packageRoot: "/workspace",
    env: { PATH: "/bin", SECRET: "hidden", DOCKER_HOST: "unix:///docker.sock" },
  });

  expect(state.env.dockerClient.DOCKER_HOST).toBe("unix:///docker.sock");
  expect(state.env.dockerClient.SECRET).toBeUndefined();
});

test("effective policy inspection fails explicitly when no generation is selected", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admin-no-effective-"));
  const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admin-no-effective-state-"));
  const desiredPath = path.join(root, ".runfree", "network-policy.json");
  fs.mkdirSync(path.dirname(desiredPath), { recursive: true });
  fs.writeFileSync(desiredPath, '{"version":2,"hosts":["agent-controlled.example.com"]}\n');
  const error = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    const status = await runAdminAction(createAdminState({
      projectRoot: root,
      packageRoot: "/workspace",
      policyPath: desiredPath,
      policyAccess: "effective-read-only",
      effectiveControlSelected: false,
      stateDir: stateRoot,
      env: { XDG_CONFIG_HOME: path.join(stateRoot, "config") },
    }), () => {
      loadPolicy();
    });

    expect(status).toBe(1);
    const rendered = error.mock.calls.flat().join("\n");
    expect(rendered).toContain("no effective policy generation is selected for this project yet");
    expect(rendered).toContain("runfree up");
    expect(rendered).toContain("runfree policy status");
  } finally {
    fs.rmSync(root, { recursive: true });
    fs.rmSync(stateRoot, { recursive: true });
  }
});
