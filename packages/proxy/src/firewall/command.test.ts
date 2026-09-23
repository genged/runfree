import { describe, expect, test } from "vitest";

import { CommandExecutionError, createCommandRunner } from "./command.ts";

describe("proxy firewall command runner", () => {
  test("invokes allowed commands with fixed env, timeout, bounded output, and shell disabled", async () => {
    const calls: unknown[] = [];
    const runner = createCommandRunner({
      execFile: (file, args, options, callback) => {
        calls.push([file, args, options]);
        callback(null, "ok\n", "");
        return { kill: () => true } as never;
      },
      timeoutMs: 1234,
      maxOutputBytes: 8,
    });

    await expect(runner.run("ip", ["-json", "route", "get", "1.1.1.1"])).resolves.toEqual({
      stdout: "ok\n",
      stderr: "",
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject([
      "ip",
      ["-json", "route", "get", "1.1.1.1"],
      {
        shell: false,
        timeout: 1234,
        env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin" },
        maxBuffer: 8,
      },
    ]);
  });

  test("rejects commands outside the firewall allowlist", async () => {
    const runner = createCommandRunner({
      execFile: () => {
        throw new Error("should not run");
      },
    });

    await expect(runner.run("sh" as never, ["-c", "nft flush ruleset"])).rejects.toThrow(/command is not allowed/);
  });

  test("includes command, argv, exit code, and stderr in failures", async () => {
    const runner = createCommandRunner({
      execFile: (_file, _args, _options, callback) => {
        const error = Object.assign(new Error("failed"), { code: 17 });
        callback(error, "", "permission denied\n");
        return { kill: () => true } as never;
      },
    });

    await expect(runner.run("nft", ["list", "ruleset"])).rejects.toMatchObject({
      name: "CommandExecutionError",
      command: "nft",
      args: ["list", "ruleset"],
      exitCode: 17,
      stderr: "permission denied\n",
    } satisfies Partial<CommandExecutionError>);
  });
});
