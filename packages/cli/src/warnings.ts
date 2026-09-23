// The one host-side output formatter (output contract D1/D3).
//
// Every operator-facing stderr line goes through `emit`: info/progress,
// warnings, and fatal diagnostics render with a severity token, every line of
// a multi-line message is attributed (first line prefixed, continuation lines
// indented under it), and timestamps follow one policy: off when stderr is a
// terminal, on otherwise (logs, CI), overridable with RUNFREE_LOG_TIMESTAMPS.
//
// Warnings are buffered so a command's result is not interleaved with its
// qualifiers, but each warning captures its own timestamp at `warn()` time —
// the flush renders when the warning was observed, not when the process
// ended. Flush points are explicit: before an interactive prompt, before the
// terminal error render, and at exit.
//
// Emissions are a small typed union so a later structured output mode is a
// new renderer, not a rewrite. Severity tokens complement — never replace —
// the stream and exit-code conventions.

export type OutputSeverity = "info" | "warning" | "error";

export type OutputEvent = {
  severity: OutputSeverity;
  message: string;
  // When the event was observed; defaults to render time.
  at?: Date;
  // Raw text rendered after the message with no prefix or indent (usage
  // blocks). Never used for the message itself.
  detail?: string;
};

const SEVERITY_PREFIX: Record<OutputSeverity, string> = {
  info: "runfree:",
  warning: "runfree warning:",
  error: "runfree error:",
};

const CONTINUATION_INDENT = "  ";

export type TimestampPolicyInput = {
  env?: NodeJS.ProcessEnv;
  stderrIsTTY?: boolean;
};

// Timestamps: on for non-TTY stderr (logs, CI), off for a terminal.
// RUNFREE_LOG_TIMESTAMPS=1 forces them on, =0 forces them off.
export function timestampsEnabled(input: TimestampPolicyInput = {}): boolean {
  const env = input.env ?? process.env;
  const override = env.RUNFREE_LOG_TIMESTAMPS;
  if (override === "1") return true;
  if (override === "0") return false;
  const isTTY = input.stderrIsTTY ?? process.stderr.isTTY === true;
  return !isTTY;
}

export type RenderOptions = { timestamps: boolean };

export function renderOutputEvent(event: OutputEvent, options: RenderOptions): string {
  const stamp = options.timestamps ? `${(event.at ?? new Date()).toISOString()} ` : "";
  const prefix = `${stamp}${SEVERITY_PREFIX[event.severity]}`;
  const [first = "", ...rest] = event.message.split("\n");
  const lines = [
    `${prefix} ${first}`,
    ...rest.map((line) => (line === "" ? "" : `${CONTINUATION_INDENT}${line}`)),
  ];
  if (event.detail !== undefined && event.detail !== "") {
    lines.push("", event.detail.replace(/\n$/, ""));
  }
  return lines.join("\n");
}

// Timestamped info rendering, kept for callers that build a line themselves.
export function formatRunfreeLog(message: string, now = new Date(), severity: OutputSeverity = "info"): string {
  return renderOutputEvent({ severity, message, at: now }, { timestamps: true });
}

let stderrWriter: (line: string) => void = (line) => console.error(line);

// Test seam: capture rendered lines without touching process.stderr.
export function setOutputWriterForTest(writer: ((line: string) => void) | undefined): void {
  stderrWriter = writer ?? ((line) => console.error(line));
}

export function emit(event: OutputEvent): void {
  stderrWriter(renderOutputEvent(event, { timestamps: timestampsEnabled() }));
}

// Progress / info line, stderr.
export function runfreeLog(message: string): void {
  emit({ severity: "info", message });
}

// Fatal diagnostic line, stderr. Rendering only: callers set the exit status.
export function runfreeError(message: string, detail?: string): void {
  emit({ severity: "error", message, ...(detail !== undefined ? { detail } : {}) });
}

const buffer: OutputEvent[] = [];

// Buffered warning; the timestamp is captured now and rendered at flush.
export function warn(message: string): void {
  buffer.push({ severity: "warning", message, at: new Date() });
}

export function pendingWarningsForTest(): readonly OutputEvent[] {
  return buffer;
}

export function flushWarnings(): void {
  if (buffer.length === 0) return;
  const pending = buffer.splice(0, buffer.length);
  for (const event of pending) emit(event);
}
