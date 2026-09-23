import childProcess from "node:child_process";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_TERM_GRACE_MS = 750;
const DRAIN_MS = 100;
const CAPTURE_LIMIT_BYTES = 2 * 1024 * 1024;
const SECRET_NAME = /(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|(?:^|_)KEY(?:_|$))/iu;

export type CommandOutcome =
  | Readonly<{ kind: "exit"; exitCode: number }>
  | Readonly<{ kind: "signal"; signal: NodeJS.Signals }>
  | Readonly<{ kind: "timeout"; timeoutMs: number; finalSignal?: NodeJS.Signals }>
  | Readonly<{ kind: "spawn-error"; message: string }>;

export type CommandResult = Readonly<{
  command: readonly string[];
  cwd: string;
  durationMs: number;
  outcome: CommandOutcome;
  stdout: string;
  stderr: string;
  environmentNames: readonly string[];
  secrets: readonly string[];
}>;

export type RunCommandInput = Readonly<{
  executable: string;
  args?: readonly string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  displayCommand?: readonly string[];
  timeoutMs?: number;
  termGraceMs?: number;
  stdin?: string;
  secrets?: readonly string[];
}>;

function captureSecrets(env: NodeJS.ProcessEnv, registered: readonly string[]): readonly string[] {
  const values = Object.entries(env)
    .filter(([name, value]) => SECRET_NAME.test(name) && typeof value === "string")
    .map(([, value]) => value as string);
  return [...new Set([...registered, ...values].filter((value) => value.length >= 4))];
}

function appendBounded(current: Buffer[], chunk: Buffer | string, state: { bytes: number; truncated: boolean }): void {
  if (state.truncated) return;
  const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
  const remaining = CAPTURE_LIMIT_BYTES - state.bytes;
  if (remaining <= 0) {
    state.truncated = true;
    return;
  }
  current.push(buffer.subarray(0, remaining));
  state.bytes += Math.min(buffer.length, remaining);
  if (buffer.length > remaining) state.truncated = true;
}

function capturedText(chunks: readonly Buffer[], truncated: boolean): string {
  return `${Buffer.concat(chunks).toString("utf8")}${truncated ? "\n<output truncated by e2e harness>\n" : ""}`;
}

function signalGroup(pid: number | undefined, signal: NodeJS.Signals): boolean {
  if (!pid) return false;
  try {
    process.kill(-pid, signal);
    return true;
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? error.code : undefined;
    if (code === "ESRCH") return false;
    throw error;
  }
}

function groupExists(pid: number | undefined): boolean {
  if (!pid) return false;
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? error.code : undefined;
    if (code === "ESRCH") return false;
    throw error;
  }
}

export function runCommand(input: RunCommandInput): Promise<CommandResult> {
  const args = [...(input.args ?? [])];
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const termGraceMs = input.termGraceMs ?? DEFAULT_TERM_GRACE_MS;
  const startedAt = Date.now();
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  const stdoutState = { bytes: 0, truncated: false };
  const stderrState = { bytes: 0, truncated: false };
  const secrets = captureSecrets(input.env, input.secrets ?? []);

  return new Promise((resolve) => {
    let finished = false;
    let timedOut = false;
    let finalSignal: NodeJS.Signals | undefined;
    let deadline: NodeJS.Timeout | undefined;
    let escalation: NodeJS.Timeout | undefined;
    let drain: NodeJS.Timeout | undefined;

    const child = childProcess.spawn(input.executable, args, {
      cwd: input.cwd,
      detached: true,
      env: input.env,
      shell: false,
      stdio: [input.stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"],
      windowsHide: true,
    });

    child.stdout?.on("data", (chunk: Buffer) => appendBounded(stdout, chunk, stdoutState));
    child.stderr?.on("data", (chunk: Buffer) => appendBounded(stderr, chunk, stderrState));
    if (input.stdin !== undefined) child.stdin?.end(input.stdin);

    const finish = (outcome: CommandOutcome): void => {
      if (finished) return;
      finished = true;
      if (deadline) clearTimeout(deadline);
      if (escalation) clearTimeout(escalation);
      if (drain) clearTimeout(drain);
      resolve(Object.freeze({
        command: Object.freeze([...(input.displayCommand ?? [input.executable, ...args])]),
        cwd: input.cwd,
        durationMs: Date.now() - startedAt,
        outcome,
        stdout: capturedText(stdout, stdoutState.truncated),
        stderr: capturedText(stderr, stderrState.truncated),
        environmentNames: Object.freeze(Object.keys(input.env).sort()),
        secrets,
      }));
    };

    child.once("error", (error) => {
      if (!timedOut) finish(Object.freeze({ kind: "spawn-error", message: error.message }));
    });
    child.once("close", (code, signal) => {
      if (timedOut) return;
      if (signal) finish(Object.freeze({ kind: "signal", signal }));
      else finish(Object.freeze({ kind: "exit", exitCode: code ?? 1 }));
    });

    deadline = setTimeout(() => {
      timedOut = true;
      if (signalGroup(child.pid, "SIGTERM")) finalSignal = "SIGTERM";
      escalation = setTimeout(() => {
        if (groupExists(child.pid) && signalGroup(child.pid, "SIGKILL")) finalSignal = "SIGKILL";
        drain = setTimeout(() => {
          child.stdout?.destroy();
          child.stderr?.destroy();
          finish(Object.freeze({ kind: "timeout", timeoutMs, finalSignal }));
        }, DRAIN_MS);
      }, termGraceMs);
    }, timeoutMs);
  });
}

export function redact(value: string, secrets: readonly string[]): string {
  return secrets.reduce((result, secret) => result.split(secret).join("<redacted>"), value);
}

export function describeCommandResult(result: CommandResult): string {
  const outcome = result.outcome.kind === "exit"
    ? `exit ${result.outcome.exitCode}`
    : result.outcome.kind === "signal"
      ? `signal ${result.outcome.signal}`
      : result.outcome.kind === "timeout"
        ? `timeout ${result.outcome.timeoutMs}ms${result.outcome.finalSignal ? `, final signal ${result.outcome.finalSignal}` : ""}`
        : `spawn error: ${result.outcome.message}`;
  return redact([
    `command: ${result.command.join(" ")}`,
    `cwd: ${result.cwd}`,
    `outcome: ${outcome}`,
    `environment names: ${result.environmentNames.join(", ")}`,
    `stdout:\n${result.stdout || "<empty>"}`,
    `stderr:\n${result.stderr || "<empty>"}`,
  ].join("\n"), result.secrets);
}
