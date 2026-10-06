import { describe, expect, test } from "vitest";
import { captureTerminalIdentity, matchTerminal, parseTerminalIdentity } from "./terminal-identity.ts";

const BOOT = "linux:boot-a";

describe("captureTerminalIdentity", () => {
  test("keeps TERM_SESSION_ID only under Apple Terminal and ITERM_SESSION_ID only under iTerm", () => {
    expect(captureTerminalIdentity({ TERM_PROGRAM: "Apple_Terminal", TERM_SESSION_ID: "A1" })).toEqual({ appleTerminal: "A1" });
    // A VS Code or tmux pane inherits its tab's TERM_SESSION_ID; it is not that tab.
    expect(captureTerminalIdentity({ TERM_PROGRAM: "vscode", TERM_SESSION_ID: "A1" })).toEqual({});
    expect(captureTerminalIdentity({ TERM_PROGRAM: "tmux", TERM_SESSION_ID: "A1", ITERM_SESSION_ID: "w0t0p0:X" })).toEqual({});
    expect(captureTerminalIdentity({ TERM_PROGRAM: "iTerm.app", ITERM_SESSION_ID: "w0t0p0:X" })).toEqual({ iterm: "w0t0p0:X" });
  });

  test("qualifies multiplexer panes with their server identity and drops a bare pane number", () => {
    expect(captureTerminalIdentity({ TMUX: "/tmp/tmux-501/default,4242,0", TMUX_PANE: "%3" }))
      .toEqual({ tmux: { pane: "%3", socket: "/tmp/tmux-501/default", serverPid: "4242" } });
    expect(captureTerminalIdentity({ TMUX_PANE: "%3" })).toEqual({});
    expect(captureTerminalIdentity({ KITTY_WINDOW_ID: "2", KITTY_PID: "77" })).toEqual({ kitty: { window: "2", instance: "77" } });
    expect(captureTerminalIdentity({ KITTY_WINDOW_ID: "2" })).toEqual({});
    expect(captureTerminalIdentity({ WEZTERM_PANE: "5", WEZTERM_UNIX_SOCKET: "/run/wez/sock" })).toEqual({ wezterm: { pane: "5", socket: "/run/wez/sock" } });
    expect(captureTerminalIdentity({ WT_SESSION: "guid" })).toEqual({ windowsTerminal: "guid" });
  });

  test("drops values that are too long or carry control characters", () => {
    expect(captureTerminalIdentity({ WT_SESSION: "x".repeat(257) })).toEqual({});
    expect(captureTerminalIdentity({ WT_SESSION: "a\u001b[2Jb" })).toEqual({});
  });
});

describe("matchTerminal", () => {
  const side = (ids: object, extra: object = {}) => ({ ids, bootId: BOOT, ...extra });

  test("strong only when every strong id is present on both sides and equal", () => {
    expect(matchTerminal(side({ iterm: "X" }), side({ iterm: "X" }))).toBe("strong");
    expect(matchTerminal(side({ iterm: "X", tmux: { pane: "%1", socket: "/s", serverPid: "1" } }), side({ iterm: "X" }))).not.toBe("strong");
    expect(matchTerminal(side({ iterm: "X" }), side({ iterm: "Y" }))).not.toBe("strong");
  });

  test("the same pane number in another tmux server or after a reboot is not strong", () => {
    const pane = { pane: "%3", socket: "/tmp/tmux-501/default", serverPid: "4242" };
    expect(matchTerminal(side({ tmux: pane }), side({ tmux: { ...pane, serverPid: "9999" } }))).not.toBe("strong");
    expect(matchTerminal(side({ tmux: pane }), { ids: { tmux: pane }, bootId: "linux:boot-b" })).not.toBe("strong");
    expect(matchTerminal(side({ tmux: pane }), { ids: { tmux: pane } })).not.toBe("strong"); // unknown boot proves nothing
  });

  test("weak when tty and terminal program agree; none otherwise; empty ids are never strong", () => {
    expect(matchTerminal(side({}, { tty: "/dev/ttys004", termProgram: "iTerm.app" }), side({}, { tty: "/dev/ttys004", termProgram: "iTerm.app" }))).toBe("weak");
    expect(matchTerminal(side({}, { tty: "/dev/ttys004", termProgram: "iTerm.app" }), side({}, { tty: "/dev/ttys004", termProgram: "Apple_Terminal" }))).toBe("none");
    expect(matchTerminal(side({}), side({}))).toBe("none");
  });
});

test("parseTerminalIdentity accepts captured shapes and rejects unknown keys and unbounded values", () => {
  expect(parseTerminalIdentity({ iterm: "X" })).toEqual({ iterm: "X" });
  expect(parseTerminalIdentity({ iterm: 1 })).toBeUndefined();
  expect(parseTerminalIdentity({ other: "x" })).toBeUndefined();
  expect(parseTerminalIdentity({ tmux: { pane: "%1", socket: "/s" } })).toBeUndefined();
  expect(parseTerminalIdentity({ wezterm: { pane: "1", socket: "x".repeat(1025) } })).toBeUndefined();
});
