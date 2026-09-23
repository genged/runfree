import { execFile as nodeExecFile } from "node:child_process";

export const FIREWALL_COMMAND_PATH = "/usr/sbin:/usr/bin:/sbin:/bin";

const ALLOWED_COMMANDS = new Set([
  "ip",
  "nft",
]);

export type FirewallCommand = "ip" | "nft";

export type CommandResult = {
  stdout: string;
  stderr: string;
};

export type CommandRunOptions = {
  input?: string;
};

type ExecFileError = Error & { code?: string | number };
type ExecFileCallback = (error: ExecFileError | null, stdout: string | Buffer, stderr: string | Buffer) => void;
export type ExecFileFn = (
  file: string,
  args: readonly string[],
  options: {
    encoding: "utf8";
    env: NodeJS.ProcessEnv;
    maxBuffer: number;
    shell: false;
    timeout: number;
  },
  callback: ExecFileCallback,
) => { kill?: (signal?: NodeJS.Signals | number) => boolean; stdin?: { end: (input?: string) => void } };

export class CommandExecutionError extends Error {
  readonly args: readonly string[];
  readonly command: string;
  readonly exitCode: number | null;
  readonly stderr: string;
  readonly systemCode: string | undefined;

  constructor(input: {
    args: readonly string[];
    command: string;
    exitCode: number | null;
    stderr: string;
    systemCode?: string;
  }) {
    super([
      `firewall command failed: ${input.command} ${input.args.join(" ")}`,
      `exitCode=${input.exitCode ?? "<none>"}`,
      input.systemCode ? `code=${input.systemCode}` : undefined,
      input.stderr.trim() ? `stderr=${input.stderr.trim()}` : undefined,
    ].filter(Boolean).join("; "));
    this.name = "CommandExecutionError";
    this.args = input.args;
    this.command = input.command;
    this.exitCode = input.exitCode;
    this.stderr = input.stderr;
    this.systemCode = input.systemCode;
  }
}

export type CommandRunner = {
  run(command: FirewallCommand, args: readonly string[], options?: CommandRunOptions): Promise<CommandResult>;
};

export function createCommandRunner(options: {
  execFile?: ExecFileFn;
  maxOutputBytes?: number;
  timeoutMs?: number;
} = {}): CommandRunner {
  const execFile = options.execFile ?? (nodeExecFile as unknown as ExecFileFn);
  const maxOutputBytes = options.maxOutputBytes ?? 64 * 1024;
  const timeoutMs = options.timeoutMs ?? 10_000;

  return {
    async run(command, args, runOptions = {}) {
      if (!ALLOWED_COMMANDS.has(command)) {
        throw new Error(`firewall command is not allowed: ${command}`);
      }

      return await new Promise<CommandResult>((resolve, reject) => {
        const child = execFile(command, args, {
          encoding: "utf8",
          env: { PATH: FIREWALL_COMMAND_PATH },
          maxBuffer: maxOutputBytes,
          shell: false,
          timeout: timeoutMs,
        }, (error, stdout, stderr) => {
          const stdoutText = boundedText(stdout, maxOutputBytes);
          const stderrText = boundedText(stderr, maxOutputBytes);
          if (error) {
            reject(new CommandExecutionError({
              args,
              command,
              exitCode: typeof error.code === "number" ? error.code : null,
              stderr: stderrText,
              systemCode: typeof error.code === "string" ? error.code : undefined,
            }));
            return;
          }

          resolve({ stdout: stdoutText, stderr: stderrText });
        });

        if (runOptions.input !== undefined) {
          child.stdin?.end(runOptions.input);
        }
      });
    },
  };
}

function boundedText(value: string | Buffer, maxBytes: number): string {
  const text = Buffer.isBuffer(value) ? value.toString("utf8") : value;
  const buffer = Buffer.from(text, "utf8");
  if (buffer.length <= maxBytes) return text;
  return buffer.subarray(0, maxBytes).toString("utf8");
}
