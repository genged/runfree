import {
  effectiveMcpToolAction,
  mcpEndpointKey,
  mcpMostRestrictiveWriteAction,
  type LoadedMcpOperationPolicy,
  type LoadedMcpOperationServer,
} from "@runfree/runtime-contracts/mcp-operation-policy";
import { DEFAULT_WRITE_ACTION, type WriteAction } from "@runfree/runtime-contracts/network-policy";
import { isRecord } from "@runfree/runtime-contracts/primitives";

export const MCP_BODY_CAP_BYTES = 256 * 1024;

export type McpOperationIdentity = {
  kind: "mcp";
  serverId: string;
  rpcMethod: string;
  tool?: string;
};

export type McpDisplayFields = {
  agent: "claude" | "codex";
  serverId?: string;
  server: string;
  method: string;
  tool?: string;
};

export type McpClassification =
  | { kind: "read"; operation: McpOperationIdentity; display: McpDisplayFields }
  | {
    kind: "write";
    category: "mcp-tool" | "mcp-unknown";
    writeAction: WriteAction;
    operation: McpOperationIdentity;
    display: McpDisplayFields;
  }
  | {
    kind: "unclassifiable";
    category: "mcp-unknown";
    reason: McpUnclassifiableReason;
    writeAction: WriteAction;
    display?: McpDisplayFields;
  };

export type McpUnclassifiableReason =
  | "compressed"
  | "duplicate-key"
  | "malformed-json"
  | "non-json"
  | "oversize"
  | "truncated"
  | "unsupported-envelope";

const READ_RPC_METHODS = new Set([
  "initialize",
  "ping",
  "tools/list",
  "resources/list",
  "resources/read",
  "prompts/list",
  "prompts/get",
  "completion/complete",
]);

const READ_NOTIFICATION_METHODS = new Set([
  "notifications/initialized",
  "notifications/cancelled",
]);

const ENCODED_PATH_TRAVERSAL_RE = /%2e|%2f|%5c/i;
const MAX_PATH_DECODE_ITERATIONS = 5;

class DuplicateJsonKeyError extends Error {
  constructor() {
    super("duplicate JSON object key");
    this.name = "DuplicateJsonKeyError";
  }
}

class JsonKeyScanner {
  private index = 0;

  constructor(private readonly source: string) {}

  scan(): void {
    this.skipWhitespace();
    this.parseValue();
    this.skipWhitespace();
    if (this.index !== this.source.length) throw new Error("trailing JSON content");
  }

  private current(): string | undefined {
    return this.source[this.index];
  }

  private skipWhitespace(): void {
    while (/\s/.test(this.current() ?? "")) this.index += 1;
  }

  private parseValue(): void {
    this.skipWhitespace();
    const char = this.current();
    if (char === "{") {
      this.parseObject();
      return;
    }
    if (char === "[") {
      this.parseArray();
      return;
    }
    if (char === "\"") {
      this.parseString();
      return;
    }
    if (char === "-" || (char !== undefined && char >= "0" && char <= "9")) {
      this.parseNumber();
      return;
    }
    if (this.source.startsWith("true", this.index)) {
      this.index += 4;
      return;
    }
    if (this.source.startsWith("false", this.index)) {
      this.index += 5;
      return;
    }
    if (this.source.startsWith("null", this.index)) {
      this.index += 4;
      return;
    }
    throw new Error("invalid JSON value");
  }

  private parseObject(): void {
    const keys = new Set<string>();
    this.index += 1;
    this.skipWhitespace();
    if (this.current() === "}") {
      this.index += 1;
      return;
    }
    while (true) {
      this.skipWhitespace();
      if (this.current() !== "\"") throw new Error("expected JSON object key");
      const key = this.parseString();
      if (keys.has(key)) throw new DuplicateJsonKeyError();
      keys.add(key);
      this.skipWhitespace();
      if (this.current() !== ":") throw new Error("expected JSON object colon");
      this.index += 1;
      this.parseValue();
      this.skipWhitespace();
      const separator = this.current();
      if (separator === "}") {
        this.index += 1;
        return;
      }
      if (separator !== ",") throw new Error("expected JSON object comma");
      this.index += 1;
    }
  }

  private parseArray(): void {
    this.index += 1;
    this.skipWhitespace();
    if (this.current() === "]") {
      this.index += 1;
      return;
    }
    while (true) {
      this.parseValue();
      this.skipWhitespace();
      const separator = this.current();
      if (separator === "]") {
        this.index += 1;
        return;
      }
      if (separator !== ",") throw new Error("expected JSON array comma");
      this.index += 1;
    }
  }

  private parseString(): string {
    const start = this.index;
    this.index += 1;
    while (this.index < this.source.length) {
      const char = this.source[this.index];
      if (char === "\"") {
        this.index += 1;
        return JSON.parse(this.source.slice(start, this.index)) as string;
      }
      if (char === "\\") {
        this.index += 2;
      } else {
        this.index += 1;
      }
    }
    throw new Error("unterminated JSON string");
  }

  private parseNumber(): void {
    const start = this.index;
    if (this.current() === "-") this.index += 1;
    while ((this.current() ?? "") >= "0" && (this.current() ?? "") <= "9") this.index += 1;
    if (this.current() === ".") {
      this.index += 1;
      while ((this.current() ?? "") >= "0" && (this.current() ?? "") <= "9") this.index += 1;
    }
    const char = this.current();
    if (char === "e" || char === "E") {
      this.index += 1;
      if (this.current() === "+" || this.current() === "-") this.index += 1;
      while ((this.current() ?? "") >= "0" && (this.current() ?? "") <= "9") this.index += 1;
    }
    if (this.index === start || this.index === start + 1 && this.source[start] === "-") throw new Error("invalid JSON number");
  }
}

export function parseJsonStrict(raw: string): { value?: unknown; reason?: "duplicate-key" | "malformed-json" } {
  try {
    new JsonKeyScanner(raw).scan();
  } catch (error) {
    return { reason: error instanceof DuplicateJsonKeyError ? "duplicate-key" : "malformed-json" };
  }
  try {
    return { value: JSON.parse(raw) as unknown };
  } catch {
    return { reason: "malformed-json" };
  }
}

function decodeToFixedPoint(value: string): string {
  let current = value;
  for (let iteration = 0; iteration < MAX_PATH_DECODE_ITERATIONS; iteration += 1) {
    const next = decodeURIComponent(current);
    if (next === current) return next;
    current = next;
  }
  return current;
}

function isTraversalSegment(segment: string): boolean {
  return segment.split(";", 1)[0] === "..";
}

function hasPathConfusion(pathName: string): boolean {
  let decoded: string;
  try {
    decoded = decodeToFixedPoint(pathName);
  } catch {
    return true;
  }
  for (const candidate of [pathName, decoded]) {
    if (ENCODED_PATH_TRAVERSAL_RE.test(candidate)) return true;
    if (candidate.includes("\\")) return true;
    if (candidate.split("/").some(isTraversalSegment)) return true;
  }
  return false;
}


function jsonContentType(value: string | undefined): boolean {
  if (!value) return false;
  const mediaType = value.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/json" || mediaType?.endsWith("+json") === true;
}

function representativeServer(servers: readonly LoadedMcpOperationServer[]): LoadedMcpOperationServer {
  return [...servers].sort((left, right) => left.id.localeCompare(right.id))[0];
}

function displayFor(server: LoadedMcpOperationServer, rpcMethod: string, tool?: string): McpDisplayFields {
  return {
    agent: server.agent,
    serverId: server.id,
    server: server.name,
    method: rpcMethod,
    ...(tool !== undefined ? { tool } : {}),
  };
}

function operationFor(server: LoadedMcpOperationServer, rpcMethod: string, tool?: string): McpOperationIdentity {
  return {
    kind: "mcp",
    serverId: server.id,
    rpcMethod,
    ...(tool !== undefined ? { tool } : {}),
  };
}

function toolNameFromMessage(message: Record<string, unknown>): string | undefined {
  const params = message.params;
  if (!isRecord(params)) return undefined;
  return typeof params.name === "string" && params.name !== "" ? params.name : undefined;
}

function classifyMessage(
  message: unknown,
  servers: readonly LoadedMcpOperationServer[],
  globalWriteAction: WriteAction,
): McpClassification {
  const server = representativeServer(servers);
  if (!isRecord(message)) {
    return { kind: "unclassifiable", category: "mcp-unknown", reason: "unsupported-envelope", writeAction: globalWriteAction, display: displayFor(server, "<unknown>") };
  }

  const hasMethod = Object.hasOwn(message, "method");
  const method = typeof message.method === "string" ? message.method : undefined;
  if (!hasMethod && Object.hasOwn(message, "id")) {
    const hasResult = Object.hasOwn(message, "result");
    const hasError = Object.hasOwn(message, "error");
    if (hasResult !== hasError) {
      return { kind: "read", operation: operationFor(server, "<response>"), display: displayFor(server, "<response>") };
    }
  }

  if (!method) {
    return { kind: "unclassifiable", category: "mcp-unknown", reason: "unsupported-envelope", writeAction: globalWriteAction, display: displayFor(server, "<unknown>") };
  }

  if (READ_RPC_METHODS.has(method) || (!Object.hasOwn(message, "id") && READ_NOTIFICATION_METHODS.has(method))) {
    return { kind: "read", operation: operationFor(server, method), display: displayFor(server, method) };
  }

  if (method === "tools/call") {
    const tool = toolNameFromMessage(message);
    if (!tool) {
      return { kind: "unclassifiable", category: "mcp-unknown", reason: "unsupported-envelope", writeAction: globalWriteAction, display: displayFor(server, method) };
    }
    const writeAction = mcpMostRestrictiveWriteAction(
      servers.map((entry) => effectiveMcpToolAction(entry, tool, globalWriteAction)),
    );
    return {
      kind: "write",
      category: "mcp-tool",
      writeAction,
      operation: operationFor(server, method, tool),
      display: displayFor(server, method, tool),
    };
  }

  return {
    kind: "write",
    category: "mcp-unknown",
    writeAction: globalWriteAction,
    operation: operationFor(server, method),
    display: displayFor(server, method),
  };
}

// A JSON-RPC batch is one HTTP request, so one classification must stand for
// every message in it. Reads add nothing. A single non-read message keeps its
// own classification. Two or more non-read messages that include a write
// become one `<batch>` write carrying the most restrictive action of every
// element (an unclassifiable element contributes the global action): no
// element may lend the batch a weaker action than another element needs, and
// no grant for one tool may match a display that stands for several.
function classifyBatch(
  classifications: readonly McpClassification[],
  server: LoadedMcpOperationServer,
  globalWriteAction: WriteAction,
): McpClassification {
  const nonRead = classifications.filter((entry) => entry.kind !== "read");
  if (nonRead.length === 0) return classifications[0];
  if (nonRead.length === 1) return nonRead[0];
  const writes = nonRead.filter((entry) => entry.kind === "write");
  if (writes.length === 0) return nonRead[0];
  const writeAction = mcpMostRestrictiveWriteAction(
    nonRead.map((entry) => (entry.kind === "write" ? entry.writeAction : globalWriteAction)),
  );
  return {
    kind: "write",
    category: "mcp-unknown",
    writeAction,
    operation: operationFor(server, "<batch>"),
    display: displayFor(server, "<batch>"),
  };
}

export function classifyMcpRequestBody(input: {
  bodyText?: string;
  contentEncoding?: string;
  contentLength?: number;
  contentType?: string;
  globalWriteAction?: WriteAction;
  method: string;
  policy: LoadedMcpOperationPolicy;
  url: URL;
}): McpClassification | undefined {
  const pathName = input.url.pathname || "/";
  if (hasPathConfusion(pathName)) return undefined;
  const servers = input.policy.endpointMap.get(mcpEndpointKey(input.url.hostname.toLowerCase(), pathName));
  if (!servers || servers.length === 0) return undefined;
  const server = representativeServer(servers);
  const globalWriteAction = input.globalWriteAction ?? DEFAULT_WRITE_ACTION;

  if (input.method === "DELETE") {
    return { kind: "read", operation: operationFor(server, "<delete>"), display: displayFor(server, "<delete>") };
  }
  if (input.method !== "POST") return undefined;

  if (input.contentEncoding !== undefined && input.contentEncoding !== "" && input.contentEncoding.toLowerCase() !== "identity") {
    return { kind: "unclassifiable", category: "mcp-unknown", reason: "compressed", writeAction: globalWriteAction, display: displayFor(server, "<unknown>") };
  }
  if (!jsonContentType(input.contentType)) {
    return { kind: "unclassifiable", category: "mcp-unknown", reason: "non-json", writeAction: globalWriteAction, display: displayFor(server, "<unknown>") };
  }
  if (input.contentLength !== undefined && input.contentLength > MCP_BODY_CAP_BYTES) {
    return { kind: "unclassifiable", category: "mcp-unknown", reason: "oversize", writeAction: globalWriteAction, display: displayFor(server, "<unknown>") };
  }
  const bodyText = input.bodyText;
  if (bodyText === undefined) {
    return { kind: "unclassifiable", category: "mcp-unknown", reason: "malformed-json", writeAction: globalWriteAction, display: displayFor(server, "<unknown>") };
  }
  const actualLength = Buffer.byteLength(bodyText);
  if (actualLength > MCP_BODY_CAP_BYTES) {
    return { kind: "unclassifiable", category: "mcp-unknown", reason: "oversize", writeAction: globalWriteAction, display: displayFor(server, "<unknown>") };
  }
  if (input.contentLength !== undefined && input.contentLength > actualLength) {
    return { kind: "unclassifiable", category: "mcp-unknown", reason: "truncated", writeAction: globalWriteAction, display: displayFor(server, "<unknown>") };
  }

  const parsed = parseJsonStrict(bodyText);
  if (parsed.reason !== undefined) {
    return { kind: "unclassifiable", category: "mcp-unknown", reason: parsed.reason, writeAction: globalWriteAction, display: displayFor(server, "<unknown>") };
  }
  const messages = Array.isArray(parsed.value) ? parsed.value : [parsed.value];
  if (messages.length === 0) {
    return { kind: "unclassifiable", category: "mcp-unknown", reason: "unsupported-envelope", writeAction: globalWriteAction, display: displayFor(server, "<unknown>") };
  }
  return classifyBatch(
    messages.map((message) => classifyMessage(message, servers, globalWriteAction)),
    server,
    globalWriteAction,
  );
}
