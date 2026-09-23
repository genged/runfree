import { afterEach, describe, expect, test, vi } from "vitest";

import { runCommandApp } from "./app.ts";
import type { RunfreeCommandContext } from "./context.ts";
import { policyApprovalIntent } from "./policy.ts";

function strictContext(): RunfreeCommandContext {
  const unavailable = () => {
    throw new Error("command context must not be reached");
  };
  return {
    env: {},
    projectRoot: "/tmp/runfree-control-command-test",
    commandName: "",
    invocationCwd: "/tmp",
    assets: unavailable,
    templatesDir: unavailable,
    projectInfo: unavailable,
    ensureProject: unavailable,
    adminContext: unavailable,
    sourceAdminContext: unavailable,
    runtimeContext: unavailable,
  };
}

afterEach(() => vi.restoreAllMocks());

describe("policy and control command parsing", () => {
  test("bare groups show scoped command help without running a handler", async () => {
    await expect(runCommandApp(strictContext(), ["policy"], async () => 0)).rejects.toMatchObject({
      message: "runfree policy needs a subcommand",
      detail: expect.stringContaining("runfree policy status"),
    });
    await expect(runCommandApp(strictContext(), ["control"], async () => 0)).rejects.toMatchObject({
      message: "runfree control needs a subcommand",
      detail: expect.stringContaining("runfree control approve"),
    });
  });

  test("policy approval rejects ambiguous scope and unsupported authority shortcuts before project access", async () => {
    await expect(runCommandApp(strictContext(), ["policy", "approve", "--project", "--local"], async () => 0))
      .rejects.toMatchObject({ message: expect.stringContaining("mutually exclusive") });
    await expect(runCommandApp(strictContext(), ["policy", "approve", "--project", "--yes"], async () => 0))
      .rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: yes") });
    await expect(runCommandApp(strictContext(), ["policy", "approve", "--project", "--digest", `sha256:${"a".repeat(64)}`], async () => 0))
      .rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: digest") });
    await expect(runCommandApp(strictContext(), ["policy", "approve"], async () => 0))
      .rejects.toThrow("requires exactly one of --project or --local");
  });

  test("non-interactive approval intent requires an exact-digest option", () => {
    expect(() => policyApprovalIntent({ project: true }, false)).toThrow("non-interactive");
    expect(policyApprovalIntent({
      local: true,
      "subject-digest": `sha256:${"a".repeat(64)}`,
    }, false)).toEqual({
      scope: "local",
      expectedDigest: `sha256:${"a".repeat(64)}`,
      mechanism: "digest-command",
    });
  });

  test("control approve requires one known subject and the unambiguous subject-digest spelling", async () => {
    await expect(runCommandApp(strictContext(), ["control", "approve", "network-project"], async () => 0))
      .rejects.toMatchObject({ message: expect.stringContaining("subject-digest") });
    await expect(runCommandApp(strictContext(), ["control", "approve", "unknown", "--subject-digest", `sha256:${"a".repeat(64)}`], async () => 0))
      .rejects.toMatchObject({ message: expect.stringContaining("Invalid values") });
    await expect(runCommandApp(strictContext(), ["control", "approve", "network-project", "--digest", `sha256:${"a".repeat(64)}`], async () => 0))
      .rejects.toMatchObject({ message: expect.stringContaining("subject-digest") });
    await expect(runCommandApp(
      strictContext(),
      ["control", "approve", "network-project", "--subject-digest", `sha256:${"a".repeat(64)}`],
      async () => 0,
    )).rejects.toThrow("command context must not be reached");
  });

  test("subcommands reject unrelated flags and valid inspection reaches runtime context", async () => {
    await expect(runCommandApp(strictContext(), ["policy", "status", "--json"], async () => 0))
      .rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: json") });
    await expect(runCommandApp(strictContext(), ["policy", "use-approved", "--project"], async () => 0))
      .rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: project") });
    await expect(runCommandApp(strictContext(), ["policy", "diff", "--project"], async () => 0))
      .rejects.toThrow("command context must not be reached");
    await expect(runCommandApp(strictContext(), ["policy", "explain", "example.com"], async () => 0))
      .rejects.toThrow("command context must not be reached");
  });
});
