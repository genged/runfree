// Messages between the node-repl server and its kernel child process. They
// travel over the Node IPC channel only; the kernel's stdout and stderr are
// separate pipes owned by the server, so kernel code can never write into the
// MCP JSON-RPC stream on the server's stdout.

export type KernelRunRequest = {
  type: "run";
  id: number;
  code: string;
};

export type KernelOutputMessage = {
  type: "output";
  id: number;
  text: string;
};

export type KernelDoneMessage = {
  type: "done";
  id: number;
  ok: boolean;
  // util.inspect text of the completion value, when there is one.
  value?: string;
  // Error stack or message when ok is false.
  error?: string;
};

export type KernelToServerMessage = KernelOutputMessage | KernelDoneMessage;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isKernelToServerMessage(value: unknown): value is KernelToServerMessage {
  if (!isRecord(value) || typeof value.id !== "number" || !Number.isSafeInteger(value.id)) return false;
  if (value.type === "output") return typeof value.text === "string";
  if (value.type === "done") {
    return typeof value.ok === "boolean"
      && (value.value === undefined || typeof value.value === "string")
      && (value.error === undefined || typeof value.error === "string");
  }
  return false;
}

export function isKernelRunRequest(value: unknown): value is KernelRunRequest {
  return isRecord(value)
    && value.type === "run"
    && typeof value.id === "number"
    && Number.isSafeInteger(value.id)
    && typeof value.code === "string";
}
