#!/usr/bin/env node
// Runfree session readiness probe, run by `session-entry` once per poll.
//
// Compiled by `pnpm build:runtime` (`tsc -b packages/agent-runtime`) into
// `dist/runtime/agent/session-ready-probe.cjs`, which the agent Dockerfile
// installs as `/usr/local/libexec/runfree/session-ready-probe`. The source is
// written in the repo's ESM syntax; the `.cts` extension makes `tsc` emit
// CommonJS, which is what the agent image's apt-pinned Node runs for an
// extensionless file. The one CommonJS idiom that cannot be spelled as ESM
// is the entrypoint test at the bottom: `import.meta` is not available in a
// file that compiles to CommonJS, so `require.main === module` stays.
//
// Each attempt opens one TCP connection to the request proxy at `PROXY_IP` and
// sends the exact admission readiness request from
// `packages/runtime-contracts/src/session-admission.ts`
// (`SESSION_ADMISSION_PROVISIONING_REQUEST`), byte for byte. The bytes are
// embedded here because the agent image carries no contracts package; a unit
// test pins them to the contract so drift fails before release.
//
// The proxy answers the request locally in every state and forwards nothing:
//   200 with the body `active` once this session's file is served;
//   403 for an unknown, expired, or removed peer.
// Before the session file lands the firewall drops the SYN outright (no RST),
// so the ordinary sequence a session sees is "dropped" until `active`. Between
// the firewall admitting the address and the request proxy serving the file
// the answer can be a 403, since the two consumers reconcile independently.
//
// One run retries (launch plan Task 7). A dropped SYN is only retransmitted
// after Linux's 1 s initial RTO, so a single attempt started before the file
// landed used to hold the entry for its whole 1 s connect timeout. A run now
// makes attempts with a short connect timeout (`ATTEMPT_CONNECT_TIMEOUT_MS`;
// the SYN-ACK on the session's own bridge is answered by the proxy's kernel,
// so no healthy host needs more) and a `RETRY_PAUSE_MS` pause, retrying every
// answer except `active`, until one `TOTAL_TIMEOUT_MS` budget for the whole
// run is spent. A connected attempt may use the rest of that budget for its
// answer. Once the file is served, the entry is released within one attempt
// and one pause, plus one Node start when the file lands between two runs.
//
// Exit codes (for logs; the entry treats every non-zero code the same). A
// run's code is its last answer's (0, 3, 5); 4 only when no attempt was
// answered:
//   0  active
//   3  refused (403)
//   4  connect failure or timeout
//   5  any other answer
//  64  PROXY_IP is not an IPv4 literal (refused before any connection)
//
// The probe performs no DNS lookup, reads no file, connects only to
// `PROXY_IP`, and sends no bytes but the readiness request, once per
// connection.

import net from "node:net";

export const PROXY_PORT = 8080;
/** Per-attempt connect timeout (capped by what is left of the run's budget). */
export const ATTEMPT_CONNECT_TIMEOUT_MS = 250;
export const RETRY_PAUSE_MS = 20;
/** The whole run's budget, every attempt and pause included. */
export const TOTAL_TIMEOUT_MS = 2_000;
const RESPONSE_LIMIT_BYTES = 4_096;
const READINESS_HOST = "runfree-provisioning.invalid";
const READINESS_PATH = "/.well-known/runfree/session-ready";
export const READINESS_REQUEST = [
  `GET http://${READINESS_HOST}${READINESS_PATH} HTTP/1.1`,
  `Host: ${READINESS_HOST}`,
  "Connection: close",
  "",
  "",
].join("\r\n");
const ACTIVE_BODY = "active";

export const EXIT_ACTIVE = 0;
export const EXIT_REFUSED = 3;
export const EXIT_UNREACHABLE = 4;
export const EXIT_UNEXPECTED = 5;
export const EXIT_USAGE = 64;

const IPV4_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
const IPV4_LITERAL = new RegExp(`^${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}$`);

function classifyResponse(raw: Buffer): number {
  const text = raw.toString("latin1");
  const headEnd = text.indexOf("\r\n\r\n");
  if (headEnd === -1) return EXIT_UNEXPECTED;
  const status = /^HTTP\/1\.[01] (\d{3})(?: |\r\n)/.exec(text);
  if (!status) return EXIT_UNEXPECTED;
  const code = Number(status[1]);
  const body = text.slice(headEnd + 4);
  if (code === 200) return body === ACTIVE_BODY ? EXIT_ACTIVE : EXIT_UNEXPECTED;
  if (code === 403) return EXIT_REFUSED;
  return EXIT_UNEXPECTED;
}

/** Opens one connection, like `net.connect`; a test seam for a dropped SYN. */
export type ProbeConnect = (options: Readonly<{ host: string; port: number; family: 4 }>) => net.Socket;

type AttemptOptions = Readonly<{
  host: string;
  port: number;
  connect: ProbeConnect;
  connectTimeoutMs: number;
  totalTimeoutMs: number;
}>;

function attempt(options: AttemptOptions): Promise<number> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let received = 0;
    let settled = false;
    const finish = (code: number): void => {
      if (settled) return;
      settled = true;
      clearTimeout(connectTimer);
      clearTimeout(totalTimer);
      socket.destroy();
      resolve(code);
    };
    const answer = (): number => (chunks.length === 0 ? EXIT_UNREACHABLE : classifyResponse(Buffer.concat(chunks)));
    // An IPv4 literal with `family: 4` never enters a resolver.
    const socket = options.connect({ host: options.host, port: options.port, family: 4 });
    const connectTimer = setTimeout(() => finish(EXIT_UNREACHABLE), options.connectTimeoutMs);
    const totalTimer = setTimeout(() => finish(EXIT_UNREACHABLE), options.totalTimeoutMs);
    socket.once("connect", () => {
      clearTimeout(connectTimer);
      socket.write(READINESS_REQUEST, "latin1");
    });
    socket.on("data", (chunk: Buffer) => {
      received += chunk.length;
      if (received > RESPONSE_LIMIT_BYTES) {
        finish(EXIT_UNEXPECTED);
        return;
      }
      chunks.push(chunk);
    });
    socket.once("end", () => finish(classifyResponse(Buffer.concat(chunks))));
    socket.once("close", () => finish(answer()));
    socket.once("error", () => finish(answer()));
  });
}

/**
 * One probe run: attempts until the proxy answers `active` or the run's one
 * total budget is spent, and returns the last attempt's code.
 */
export async function probeUntilActive(options: Readonly<{
  host: string;
  port: number;
  connect?: ProbeConnect;
  nowMs?: () => number;
}>): Promise<number> {
  const connect = options.connect ?? ((connectOptions) => net.connect(connectOptions));
  const nowMs = options.nowMs ?? (() => performance.now());
  const deadline = nowMs() + TOTAL_TIMEOUT_MS;
  let code = EXIT_UNREACHABLE;
  for (;;) {
    const remaining = deadline - nowMs();
    if (remaining <= 0) return code;
    const result = await attempt({
      host: options.host,
      port: options.port,
      connect,
      connectTimeoutMs: Math.min(ATTEMPT_CONNECT_TIMEOUT_MS, remaining),
      totalTimeoutMs: remaining,
    });
    // A failed or timed-out connection says less than an answer: on a loaded
    // host, or when the run's budget cuts the last attempt short, it would
    // otherwise hide what the proxy last said. So it never replaces one.
    if (result !== EXIT_UNREACHABLE || code === EXIT_UNREACHABLE) code = result;
    if (code === EXIT_ACTIVE || deadline - nowMs() <= RETRY_PAUSE_MS) return code;
    await new Promise((resolve) => setTimeout(resolve, RETRY_PAUSE_MS));
  }
}

function parsePort(value: string | undefined): number | undefined {
  if (value === undefined || value === "") return PROXY_PORT;
  if (!/^[1-9][0-9]{0,4}$/.test(value) || Number(value) > 65_535) return undefined;
  return Number(value);
}

async function main(): Promise<number> {
  const host = process.env.PROXY_IP;
  if (typeof host !== "string" || !IPV4_LITERAL.test(host)) {
    process.stderr.write(`session-ready-probe: PROXY_IP must be an IPv4 literal, got: ${host === undefined ? "<unset>" : host}\n`);
    return EXIT_USAGE;
  }
  // Test seam only: unit tests cannot bind the fixed proxy port. The session
  // environment is host-pinned and never renders this name, so a session
  // always probes the proxy port.
  const port = parsePort(process.env.RUNFREE_SESSION_READY_PROBE_PORT);
  if (port === undefined) {
    process.stderr.write("session-ready-probe: RUNFREE_SESSION_READY_PROBE_PORT must be a TCP port\n");
    return EXIT_USAGE;
  }
  return await probeUntilActive({ host, port });
}

if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (error: unknown) => {
      process.stderr.write(`session-ready-probe: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exit(EXIT_UNEXPECTED);
    },
  );
}
