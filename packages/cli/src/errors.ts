// An operator-actionable refusal. Rendered by `main()` at error severity with
// no stack trace; `status` is the exit code. `detail` is raw text printed after
// the message without prefixing (a usage block); it is never the message.
export class CliError extends Error {
  readonly status: number;
  readonly detail?: string;

  constructor(message: string, status = 1, options: { detail?: string } = {}) {
    super(message);
    this.name = "CliError";
    this.status = status;
    if (options.detail !== undefined) this.detail = options.detail;
  }
}

export function die(message: string): never {
  throw new CliError(message);
}

export const VERBOSE_STACK_HINT = "run the command again with --verbose to print the stack trace";

export const UNEXPECTED_ERROR_RENDER_LIMITS = Object.freeze({
  maxDepth: 6,
  maxNodes: 24,
  maxMessageCharacters: 2_048,
  maxOutputBytes: 16 * 1_024,
});

type UnexpectedErrorRenderLimits = typeof UNEXPECTED_ERROR_RENDER_LIMITS;

function limitedCharacters(value: string, maximum: number): string {
  if (value.length <= maximum) return value;
  return `${value.slice(0, Math.max(0, maximum - 1))}…`;
}

function limitedBytes(value: string, maximum: number): string {
  if (Buffer.byteLength(value) <= maximum) return value;
  const marker = "\n[output truncated]";
  const available = Math.max(0, maximum - Buffer.byteLength(marker));
  let bytes = 0;
  let result = "";
  for (const character of value) {
    const width = Buffer.byteLength(character);
    if (bytes + width > available) break;
    result += character;
    bytes += width;
  }
  return `${result}${marker}`;
}

function nonErrorLabel(value: unknown): string {
  if (value === null) return "NonErrorThrown: null";
  if (Array.isArray(value)) return "NonErrorThrown: array";
  return `NonErrorThrown: ${typeof value}`;
}

function safeErrorText(error: Error, key: "name" | "message", maximum: number): string {
  try {
    const value = error[key];
    if (typeof value !== "string" || value === "") return key === "name" ? "Error" : "";
    return limitedCharacters(value, maximum);
  } catch {
    return key === "name" ? "Error" : "<unavailable>";
  }
}

function errorHeader(error: Error, maximum: number): string {
  const name = safeErrorText(error, "name", maximum);
  const message = safeErrorText(error, "message", maximum);
  return message === "" ? name : `${name}: ${message}`;
}

function topLevelStack(error: Error, maximumBytes: number): string {
  try {
    const stack = error.stack;
    const name = error.name;
    const message = error.message;
    if (typeof stack !== "string" || stack === "") return "";
    if (typeof name !== "string" || typeof message !== "string") return "";

    let headerEnd = name.length;
    if (!stack.startsWith(name)) return "";
    if (message !== "") {
      if (!stack.startsWith(": ", headerEnd) || !stack.startsWith(message, headerEnd + 2)) return "";
      headerEnd += 2 + message.length;
    }
    const separatorLength = stack.startsWith("\r\n", headerEnd) ? 2 : stack.startsWith("\n", headerEnd) ? 1 : 0;
    if (separatorLength === 0) return "";
    const suffixStart = headerEnd + separatorLength;
    return limitedBytes(stack.slice(suffixStart, suffixStart + maximumBytes), maximumBytes);
  } catch {
    return "";
  }
}

export type UnexpectedErrorRenderOptions = {
  // Print the top-level stack. Off by default: the stack is a debugging aid
  // and hides the message; `--verbose` turns it on and a hint names the flag.
  stack?: boolean;
};

export function renderUnexpectedError(
  thrown: unknown,
  limits: UnexpectedErrorRenderLimits = UNEXPECTED_ERROR_RENDER_LIMITS,
  options: UnexpectedErrorRenderOptions = { stack: true },
): string {
  if (!(thrown instanceof Error)) {
    return limitedBytes(nonErrorLabel(thrown), limits.maxOutputBytes);
  }

  const lines = [errorHeader(thrown, limits.maxMessageCharacters)];
  const stack = options.stack === false ? "" : topLevelStack(thrown, limits.maxOutputBytes);
  const seen = new Set<Error>([thrown]);
  let nodes = 1;

  const nestedValues = (error: Error): Array<{ label: string; value: unknown }> => {
    const result: Array<{ label: string; value: unknown }> = [];
    if (error instanceof AggregateError) {
      try {
        if (Array.isArray(error.errors)) {
          for (let index = 0; index < error.errors.length && result.length < limits.maxNodes; index += 1) {
            result.push({ label: `error[${index}]`, value: error.errors[index] });
          }
        }
      } catch {
        result.push({ label: "errors", value: new Error("<unavailable>") });
      }
    }
    try {
      const cause = error.cause;
      if (cause !== undefined) result.push({ label: "cause", value: cause });
    } catch {
      result.push({ label: "cause", value: new Error("<unavailable>") });
    }
    return result;
  };

  const appendNested = (label: string, value: unknown, depth: number, indent: string): void => {
    lines.push(`${indent}${label}:`);
    const childIndent = `${indent}  `;
    if (!(value instanceof Error)) {
      lines.push(`${childIndent}${nonErrorLabel(value)}`);
      return;
    }
    if (seen.has(value)) {
      lines.push(`${childIndent}[cycle: ${errorHeader(value, limits.maxMessageCharacters)}]`);
      return;
    }
    if (depth > limits.maxDepth) {
      lines.push(`${childIndent}[depth limit reached]`);
      return;
    }
    if (nodes >= limits.maxNodes) {
      lines.push(`${childIndent}[error node limit reached]`);
      return;
    }

    nodes += 1;
    seen.add(value);
    lines.push(`${childIndent}${errorHeader(value, limits.maxMessageCharacters)}`);
    for (const nested of nestedValues(value)) {
      appendNested(nested.label, nested.value, depth + 1, childIndent);
    }
  };

  for (const nested of nestedValues(thrown)) {
    appendNested(nested.label, nested.value, 1, "  ");
  }
  if (stack !== "") lines.push(stack);
  else if (options.stack === false) lines.push(VERBOSE_STACK_HINT);
  return limitedBytes(lines.join("\n"), limits.maxOutputBytes);
}
