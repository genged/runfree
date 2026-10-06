// Terminal ids identify one terminal tab so a later command in the same tab
// can find the session it ran. They stay on the host: nothing here reaches a
// session container (spec "No leak").

const MAX_ID = 256;
const MAX_PATH = 1024;
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/u;

export type TerminalIdentity = Readonly<{
  appleTerminal?: string;
  iterm?: string;
  windowsTerminal?: string;
  tmux?: Readonly<{ pane: string; socket: string; serverPid: string }>;
  kitty?: Readonly<{ window: string; instance: string }>;
  wezterm?: Readonly<{ pane: string; socket: string }>;
}>;

export type TerminalMatch = "strong" | "weak" | "none";
export type TerminalSide = Readonly<{ ids: TerminalIdentity; tty?: string; termProgram?: string; bootId?: string }>;

function bounded(value: unknown, max = MAX_ID): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max && !CONTROL.test(value);
}

function read(env: NodeJS.ProcessEnv | undefined, name: string, max = MAX_ID): string | undefined {
  const value = env?.[name]?.trim();
  return bounded(value, max) ? value : undefined;
}

export function captureTerminalIdentity(env: NodeJS.ProcessEnv | undefined): TerminalIdentity {
  const program = read(env, "TERM_PROGRAM");
  const apple = program === "Apple_Terminal" ? read(env, "TERM_SESSION_ID") : undefined;
  const iterm = program === "iTerm.app" ? read(env, "ITERM_SESSION_ID") : undefined;
  const windowsTerminal = read(env, "WT_SESSION");
  // $TMUX is "<socket>,<server pid>,<session index>".
  const tmuxParts = read(env, "TMUX", MAX_PATH)?.split(",");
  const tmuxPane = read(env, "TMUX_PANE");
  const tmux = tmuxPane && tmuxParts && tmuxParts.length >= 2 && bounded(tmuxParts[0], MAX_PATH) && /^[0-9]+$/.test(tmuxParts[1] ?? "")
    ? { pane: tmuxPane, socket: tmuxParts[0], serverPid: tmuxParts[1] as string }
    : undefined;
  const kittyWindow = read(env, "KITTY_WINDOW_ID");
  const kittyInstance = read(env, "KITTY_PID") ?? read(env, "KITTY_LISTEN_ON", MAX_PATH);
  const weztermPane = read(env, "WEZTERM_PANE");
  const weztermSocket = read(env, "WEZTERM_UNIX_SOCKET", MAX_PATH);
  return {
    ...(apple ? { appleTerminal: apple } : {}),
    ...(iterm ? { iterm } : {}),
    ...(windowsTerminal ? { windowsTerminal } : {}),
    ...(tmux ? { tmux } : {}),
    ...(kittyWindow && kittyInstance ? { kitty: { window: kittyWindow, instance: kittyInstance } } : {}),
    ...(weztermPane && weztermSocket ? { wezterm: { pane: weztermPane, socket: weztermSocket } } : {}),
  };
}

const SHAPES: Record<string, readonly (readonly [string, number])[] | number> = {
  appleTerminal: MAX_ID,
  iterm: MAX_ID,
  windowsTerminal: MAX_ID,
  tmux: [["pane", MAX_ID], ["socket", MAX_PATH], ["serverPid", MAX_ID]],
  kitty: [["window", MAX_ID], ["instance", MAX_PATH]],
  wezterm: [["pane", MAX_ID], ["socket", MAX_PATH]],
};

export function parseTerminalIdentity(value: unknown): TerminalIdentity | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  for (const [key, field] of Object.entries(value)) {
    const shape = SHAPES[key];
    if (shape === undefined) return undefined;
    if (typeof shape === "number") {
      if (!bounded(field, shape)) return undefined;
      continue;
    }
    if (typeof field !== "object" || field === null) return undefined;
    const record = field as Record<string, unknown>;
    if (Object.keys(record).length !== shape.length) return undefined;
    for (const [name, max] of shape) if (!bounded(record[name], max)) return undefined;
  }
  return value as TerminalIdentity;
}

// Pane numbers repeat after a restart, so multiplexer ids count only with a
// known boot id, which becomes part of the compared value.
function strongEntries(side: TerminalSide): Map<string, string> {
  const out = new Map<string, string>();
  const { ids, bootId } = side;
  if (ids.appleTerminal) out.set("apple", ids.appleTerminal);
  if (ids.iterm) out.set("iterm", ids.iterm);
  if (ids.windowsTerminal) out.set("wt", ids.windowsTerminal);
  if (bootId) {
    if (ids.tmux) out.set("tmux", [bootId, ids.tmux.socket, ids.tmux.serverPid, ids.tmux.pane].join("\0"));
    if (ids.kitty) out.set("kitty", [bootId, ids.kitty.instance, ids.kitty.window].join("\0"));
    if (ids.wezterm) out.set("wezterm", [bootId, ids.wezterm.socket, ids.wezterm.pane].join("\0"));
  }
  return out;
}

export function matchTerminal(current: TerminalSide, recorded: TerminalSide): TerminalMatch {
  const left = strongEntries(current);
  const right = strongEntries(recorded);
  if (left.size > 0 && left.size === right.size && [...left].every(([key, value]) => right.get(key) === value)) {
    return "strong";
  }
  if (current.tty && current.termProgram && current.tty === recorded.tty && current.termProgram === recorded.termProgram) {
    return "weak";
  }
  return "none";
}
