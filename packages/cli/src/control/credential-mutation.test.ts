import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { projectInfo } from "../config.ts";
import { writeLiveAttachedSessionContainerRecordFixture } from "../runtime/session-container.test-harness.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import {
  desiredCredentialFromFields,
  mutateDesiredCredential,
} from "./credential-mutation.ts";
import { mutateDesiredHost } from "./local-host-mutation.ts";

describe("desired credential mutations", () => {
  let root: string;
  let stateHome: string;
  let context: RuntimeContext;
  const io: RuntimeIO = {
    capture: () => ({ status: 0, stdout: "", stderr: "" }),
    run: () => 0,
    commandExists: () => false,
    confirm: () => false,
    admin: async () => 0,
  };

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-credential-mutation-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-credential-mutation-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), '{"version":2,"hosts":[]}\n');
    const env = {
      XDG_STATE_HOME: stateHome,
      XDG_CONFIG_HOME: path.join(stateHome, "config"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
      RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
    };
    context = { projectRoot: root, project: projectInfo(root, env), runtimeRoot: root, env };
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true });
    fs.rmSync(stateHome, { recursive: true });
  });

  async function allow(host: string): Promise<void> {
    await mutateDesiredHost(context, io, "project", { kind: "add", host });
  }

  function policy(): {
    tokens?: Record<string, { credentials: Array<{ host: string }> }>;
    version: number;
  } {
    return JSON.parse(fs.readFileSync(context.project.paths.policyPath, "utf8")) as ReturnType<typeof policy>;
  }

  test("mutates a desired credential while a per-session agent is live", async () => {
    await allow("api.example.com");
    writeLiveAttachedSessionContainerRecordFixture({
      stateDir: context.project.paths.stateDir,
      projectRoot: root,
      env: context.env,
    });

    const result = await mutateDesiredCredential(context, io, {
      kind: "add",
      name: "example",
      credential: desiredCredentialFromFields({ host: "api.example.com" }),
    });

    expect(result.changed).toBe(true);
    expect(result.selection.subjects["network-project"]?.mechanism).toBe("typed-host-command");
  });

  test("adds, links, unlinks, and removes a direct token through approved v2 transactions", async () => {
    await allow("api.example.com");
    await allow("uploads.example.com");
    const first = desiredCredentialFromFields({ host: "api.example.com" });
    const second = desiredCredentialFromFields({ host: "uploads.example.com", pathPrefix: "/v1" });

    await mutateDesiredCredential(context, io, {
      kind: "add",
      name: "example",
      description: "Example API token",
      credential: first,
    });
    await mutateDesiredCredential(context, io, { kind: "link", name: "example", credential: second });
    expect(policy().version).toBe(2);
    expect(policy().tokens?.example.credentials).toHaveLength(2);

    await mutateDesiredCredential(context, io, {
      kind: "unlink",
      name: "example",
      host: "api.example.com",
    });
    expect(policy().tokens?.example.credentials).toEqual([{ host: "uploads.example.com", header: "Authorization", scheme: "bearer", pathPrefix: "/v1" }]);

    await mutateDesiredCredential(context, io, { kind: "remove", name: "example" });
    expect(policy().tokens).toBeUndefined();
  });

  test("rejects a proxy credential bound to a Claude Code login host before the project file changes", async () => {
    // Negative-before-side-effect: proxy tokens are hidden from the agent, so
    // they can never satisfy Claude Code's login prompt — the binding must be
    // refused before the desired policy mutates.
    await allow("api.anthropic.com");
    const before = fs.readFileSync(context.project.paths.policyPath, "utf8");
    await expect(mutateDesiredCredential(context, io, {
      kind: "add",
      name: "claude-login",
      description: "misconfigured",
      credential: desiredCredentialFromFields({ host: "api.anthropic.com" }),
    })).rejects.toThrow("Claude Code login uses Runfree-managed Claude state");
    expect(fs.readFileSync(context.project.paths.policyPath, "utf8")).toBe(before);
  });

  test("rejects an unapproved destination before the project file changes", async () => {
    const before = fs.readFileSync(context.project.paths.policyPath, "utf8");

    await expect(mutateDesiredCredential(context, io, {
      kind: "add",
      name: "example",
      credential: desiredCredentialFromFields({ host: "blocked.example.com" }),
    })).rejects.toThrow("not directly allowlisted in project desired policy");

    expect(fs.readFileSync(context.project.paths.policyPath, "utf8")).toBe(before);
  });
});
