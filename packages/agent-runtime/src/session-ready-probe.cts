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
// Opens one TCP connection to the request proxy at `PROXY_IP` and sends the
// exact admission readiness request from
// `packages/runtime-contracts/src/session-admission.ts`
// (`SESSION_ADMISSION_PROVISIONING_REQUEST`), byte for byte. The bytes are
// embedded here because the agent image carries no contracts package; a unit
// test pins them to the contract so drift fails before release.
//
// The proxy answers the request locally in every state and forwards nothing:
//   200 with the body `active` once this session's file is served;
//   403 for an unknown, expired, or removed peer.
// Before the session file lands the firewall drops the connection outright, so
// the ordinary sequence a session sees is exit 4 (dropped) until exit 0.
//
// Exit codes (for logs; the entry treats every non-zero code the same):
//   0  active
//   3  refused (403)
//   4  connect failure or timeout
//   5  any other answer
//  64  PROXY_IP is not an IPv4 literal (refused before any connection)
//
// The probe performs no DNS lookup, opens no other connection, reads no file,
// and sends no other bytes.

import net from "node:net";

export const PROXY_PORT = 8080;
const CONNECT_TIMEOUT_MS = 1_000;
const TOTAL_TIMEOUT_MS = 2_000;
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

function probe(options: Readonly<{ host: string; port: number }>): Promise<number> {
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
    const socket = net.connect({ host: options.host, port: options.port, family: 4 });
    const connectTimer = setTimeout(() => finish(EXIT_UNREACHABLE), CONNECT_TIMEOUT_MS);
    const totalTimer = setTimeout(() => finish(EXIT_UNREACHABLE), TOTAL_TIMEOUT_MS);
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
  return await probe({ host, port });
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
