import { describe, expect, test } from "vitest";

import { builtinAgent } from "../agents.ts";
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

  // Claude, Codex, and Pi all define `resume` (Codex and Pi gained exact
  // resume in the same-terminal-resume design), so no built-in agent can
  // demonstrate a missing resume capability any more; that refusal path
  // remains in `createBuiltinSessionResumeLaunchTarget` for any future
  // descriptor that omits `resume`, but only the two agent-independent
  // refusals below still have a built-in agent to exercise them.
  test("refuses before minting: bad UUID and custom command", () => {
    expect(() => createBuiltinSessionResumeLaunchTarget({
      agentId: "claude",
      configuredCommand: "claude --dangerously-skip-permissions --add-dir /runfree/inbox",
      conversationId: "not-a-uuid; rm -rf /",
    })).toThrow("not a valid conversation UUID");
    expect(() => createBuiltinSessionResumeLaunchTarget({
      agentId: "claude",
      configuredCommand: "claude --dangerously-skip-permissions",
      conversationId: CONVERSATION_ID,
    })).toThrow("exact claude built-in command");
  });
});

// Host-chosen conversation id (spec `2026-10-04-same-terminal-session-resume-design.md`
// section 2): the host mints the id once per public launch and appends it to
// a fresh launch's argv only. Claude and Pi accept it; Codex does not. The
// flag must never reach resume or picker argv (asserted above and in
// `agents.test.ts`).
function requireDefaultCommand(agentId: string): string {
  const descriptor = builtinAgent(agentId);
  if (!descriptor) throw new Error(`missing built-in agent: ${agentId}`);
  return descriptor.defaultCommand;
}

describe("host-chosen conversation id", () => {
  const ID = "3f1c2b9e-8a4d-4c1e-9f2a-0b6d7e8f9a10";

  test.each([
    [
      "claude",
      "claude --dangerously-skip-permissions --add-dir /runfree/inbox",
      "/usr/local/bin/claude",
      ["--dangerously-skip-permissions", "--add-dir", "/runfree/inbox"],
    ],
    ["pi", "pi", "/usr/local/bin/pi", []],
  ])("a fresh %s launch carries --session-id and the id as two separate elements", (agentId, configuredCommand, innerPath, innerArgs) => {
    const target = createBuiltinSessionLaunchTarget({ agentId, configuredCommand, launchConversationId: ID });
    expect(target.args).toEqual([innerPath, ...innerArgs, "--session-id", ID]);
  });

  test("refuses an id for an agent without the flag, and a malformed id, before minting", () => {
    expect(() => createBuiltinSessionLaunchTarget({
      agentId: "codex",
      configuredCommand: "codex -c check_for_update_on_startup=false --dangerously-bypass-approvals-and-sandbox",
      launchConversationId: ID,
    })).toThrow("does not accept a host-chosen conversation id");
    expect(() => createBuiltinSessionLaunchTarget({ agentId: "pi", configuredCommand: "pi", launchConversationId: "x; rm -rf /" }))
      .toThrow("not a valid conversation UUID");
    expect(() => createBuiltinSessionLaunchTarget({ agentId: "pi", configuredCommand: "pi", launchConversationId: ID.toUpperCase() }))
      .toThrow("not a valid conversation UUID");
  });

  test.each(["claude", "pi", "codex"])("resume and picker argv for %s never carry --session-id", (agentId) => {
    const configuredCommand = requireDefaultCommand(agentId);
    const exact = createBuiltinSessionResumeLaunchTarget({ agentId, configuredCommand, conversationId: ID });
    const picker = createBuiltinSessionResumeLaunchTarget({ agentId, configuredCommand });
    expect(exact.args).not.toContain("--session-id");
    expect(picker.args).not.toContain("--session-id");
    expect(exact.args.at(-1)).toBe(ID);
  });

  test("pi and codex exact resume use the descriptor argv", () => {
    expect(createBuiltinSessionResumeLaunchTarget({ agentId: "pi", configuredCommand: "pi", conversationId: ID }).args)
      .toEqual(["/usr/local/bin/pi", "--session", ID]);
    expect(createBuiltinSessionResumeLaunchTarget({
      agentId: "codex",
      configuredCommand: requireDefaultCommand("codex"),
      conversationId: ID,
    }).args).toEqual(["/usr/local/bin/codex", "-c", "check_for_update_on_startup=false", "resume", "--dangerously-bypass-approvals-and-sandbox", ID]);
  });
});
