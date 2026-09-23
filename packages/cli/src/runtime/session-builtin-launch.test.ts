import { describe, expect, test } from "vitest";

import { assertSessionLaunchTarget, SESSION_ENTRY_PATH } from "./session-launch.ts";
import {
  createBuiltinSessionLaunchTarget,
  createBuiltinSessionResumeLaunchTarget,
  createBuiltinSessionShellLaunchTarget,
} from "./session-builtin-launch.ts";

// Every minted target names the image's session entry as `Path` and carries
// the real launch as `Args` (activation-gate design D3): the entry waits for
// the proxy to report the session active, then execs `args[0]` with the rest.
// The inner path is asserted at `args[0]` in every case so a minter that
// forgot the wrapper, or wrapped the wrong thing, fails here rather than in a
// live launch that answers the agent's first request 403.

describe("built-in session direct launch", () => {
  test.each([
    [
      "claude",
      "claude --dangerously-skip-permissions --add-dir /runfree/inbox",
      "/usr/local/bin/claude",
      ["--dangerously-skip-permissions", "--add-dir", "/runfree/inbox"],
    ],
    [
      "codex",
      "codex -c check_for_update_on_startup=false --dangerously-bypass-approvals-and-sandbox",
      "/usr/local/bin/codex",
      ["-c", "check_for_update_on_startup=false", "--dangerously-bypass-approvals-and-sandbox"],
    ],
    ["pi", "pi", "/usr/local/bin/pi", []],
  ])("mints the exact typed %s launch target behind the session entry", (agentId, configuredCommand, innerPath, innerArgs) => {
    const target = createBuiltinSessionLaunchTarget({ agentId, configuredCommand });

    expect(target).toMatchObject({
      path: SESSION_ENTRY_PATH,
      args: [innerPath, ...innerArgs],
      interactive: true,
      tty: true,
    });
    expect(target.args[0]).toBe(innerPath);
    expect(() => assertSessionLaunchTarget(target)).not.toThrow();
  });

  test("rejects custom, legacy, and shell-expanded commands before launch", () => {
    // Raw legacy defaults are rejected *here* on purpose: their acceptance
    // lives in the config layer (`resolveAgentCommand` normalizes them to the
    // current default before any caller reaches this builder), so the builder
    // itself never widens beyond one exact string.
    expect(() => createBuiltinSessionLaunchTarget({
      agentId: "claude",
      configuredCommand: "claude --dangerously-skip-permissions",
    })).toThrow("exact claude built-in command");
    expect(() => createBuiltinSessionLaunchTarget({
      agentId: "codex",
      configuredCommand: "codex $(touch /tmp/never)",
    })).toThrow("exact codex built-in command");
    expect(() => createBuiltinSessionLaunchTarget({
      agentId: "custom",
      configuredCommand: "custom",
    })).toThrow("unknown built-in session agent");
  });

  test("the custom-command refusal names the command, the required default, and the way out", () => {
    // Cutover decision D-3 (2026-08-17): fail explicitly with exact guidance.
    // The operator must be able to act from the message alone.
    const refusal = (() => {
      try {
        createBuiltinSessionLaunchTarget({ agentId: "codex", configuredCommand: "codex --my-flag" });
      } catch (error) {
        return String(error);
      }
      throw new Error("a customized command was not refused");
    })();
    expect(refusal).toContain('"codex --my-flag"');
    expect(refusal).toContain(
      '"codex -c check_for_update_on_startup=false --dangerously-bypass-approvals-and-sandbox"',
    );
    expect(refusal).toContain("agents.codex.command");
    expect(refusal).toContain(".runfree/runfree.json");
    expect(refusal).toContain("runfree shell");
  });
});

describe("built-in session shell launch", () => {
  test("mints the login shell behind the session entry", () => {
    const target = createBuiltinSessionShellLaunchTarget();

    expect(target).toMatchObject({
      path: SESSION_ENTRY_PATH,
      args: ["/usr/bin/zsh", "-il"],
      interactive: true,
      tty: true,
    });
    expect(target.args[0]).toBe("/usr/bin/zsh");
    expect(() => assertSessionLaunchTarget(target)).not.toThrow();
  });
});

describe("built-in session resume launch", () => {
  const CONVERSATION_ID = "0f8b1a2c-3d4e-4f5a-8b6c-7d8e9f0a1b2c";

  test("mints the exact claude conversation resume target behind the session entry", () => {
    const target = createBuiltinSessionResumeLaunchTarget({
      agentId: "claude",
      configuredCommand: "claude --dangerously-skip-permissions --add-dir /runfree/inbox",
      conversationId: CONVERSATION_ID,
    });

    expect(target).toMatchObject({
      path: SESSION_ENTRY_PATH,
      args: [
        "/usr/local/bin/claude",
        "--dangerously-skip-permissions",
        "--add-dir",
        "/runfree/inbox",
        "--resume",
        CONVERSATION_ID,
      ],
      interactive: true,
      tty: true,
    });
    expect(target.args[0]).toBe("/usr/local/bin/claude");
    expect(() => assertSessionLaunchTarget(target)).not.toThrow();
  });

  test("normalizes an uppercase conversation UUID into one argv spelling", () => {
    const target = createBuiltinSessionResumeLaunchTarget({
      agentId: "claude",
      configuredCommand: "claude --dangerously-skip-permissions --add-dir /runfree/inbox",
      conversationId: CONVERSATION_ID.toUpperCase(),
    });

    expect(target.args.at(-1)).toBe(CONVERSATION_ID);
  });

  test("mints the picker targets for claude and codex", () => {
    expect(createBuiltinSessionResumeLaunchTarget({
      agentId: "claude",
      configuredCommand: "claude --dangerously-skip-permissions --add-dir /runfree/inbox",
    })).toMatchObject({
      path: SESSION_ENTRY_PATH,
      args: ["/usr/local/bin/claude", "--dangerously-skip-permissions", "--add-dir", "/runfree/inbox", "--resume"],
    });
    expect(createBuiltinSessionResumeLaunchTarget({
      agentId: "codex",
      configuredCommand: "codex -c check_for_update_on_startup=false --dangerously-bypass-approvals-and-sandbox",
    })).toMatchObject({
      path: SESSION_ENTRY_PATH,
      args: [
        "/usr/local/bin/codex",
        "-c",
        "check_for_update_on_startup=false",
        "resume",
        "--dangerously-bypass-approvals-and-sandbox",
      ],
    });
  });

  test("refuses before minting: bad UUID, no resume capability, custom command, exact-resume gap", () => {
    expect(() => createBuiltinSessionResumeLaunchTarget({
      agentId: "claude",
      configuredCommand: "claude --dangerously-skip-permissions --add-dir /runfree/inbox",
      conversationId: "not-a-uuid; rm -rf /",
    })).toThrow("not a valid conversation UUID");
    expect(() => createBuiltinSessionResumeLaunchTarget({
      agentId: "pi",
      configuredCommand: "pi",
    })).toThrow("resume is not supported");
    expect(() => createBuiltinSessionResumeLaunchTarget({
      agentId: "claude",
      configuredCommand: "claude --dangerously-skip-permissions",
      conversationId: CONVERSATION_ID,
    })).toThrow("exact claude built-in command");
    expect(() => createBuiltinSessionResumeLaunchTarget({
      agentId: "codex",
      configuredCommand: "codex -c check_for_update_on_startup=false --dangerously-bypass-approvals-and-sandbox",
      conversationId: CONVERSATION_ID,
    })).toThrow("does not support exact conversation resume");
  });
});
