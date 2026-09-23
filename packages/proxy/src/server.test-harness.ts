// Shared harness for the proxy server test files. Importing this module
// registers the per-test temp-dir and child/server cleanup hooks, so it must
// only be imported from Vitest test files. The tests are split across several
// files so their proxy subprocess spawns run on parallel worker threads.
import childProcess from "node:child_process";
import fs from "node:fs";
import type { ServerResponse } from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { afterEach, beforeEach } from "vitest";

import {
  createSessionAdmissionEligibility,
  serializeSessionAdmissionEligibility,
} from "@runfree/runtime-contracts/session-admission";
import {
  serializeSessionFileV1,
  type SessionFileV1,
} from "@runfree/runtime-contracts/session-file";

import { proxyServerEntryArgv } from "../../../tests/support/prebuilt-entry.ts";

const repoRoot = path.resolve(new URL("../../..", import.meta.url).pathname);

export let tmp: string;
const children = new Set<childProcess.ChildProcess>();
export const servers = new Set<https.Server>();

export type RunningProxy = {
  caCertPath: string;
  caKeyPath: string;
  output: () => string;
  policyPath: string;
  port: number;
  secretDir: string;
  // Present when the harness provisioned the default session-identity fixture.
  sessionRegistryDir?: string;
  stop: () => Promise<void>;
  verboseDir: string;
  waitForOutput: (pattern: string | RegExp, label?: string) => Promise<void>;
};

export type ProxyResponse = {
  body: string;
  headers: Record<string, string>;
  raw: string;
  statusCode: number;
};

const HOST_PROXY_ENV_KEYS = [
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "no_proxy",
] as const;

const TEST_UPSTREAM_CERT = `-----BEGIN CERTIFICATE-----
MIIDsTCCApmgAwIBAgIUO+k0qSqcKuQLuiXidd08ZSoySYIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MDYyMjA3MDIxM1oXDTM2MDYx
OTA3MDIxM1owFDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA9VYOjFJ+oxqYo8SL0YEi3LoXh94Gd/xiBXtn+p96bX/D
o3FD+X0AWu765yjM3qN+TilPg/988nK41c2y86oeXfWZvkTFnwlx97qyxY9C2h18
sP7RZkGy11tibSkI3riQhGIo49VRHd6PHU3E2y2GZjklaB7c8g48FkJaYwVOvVvi
rpOirE4MnUNSVLBM43gDe1WW8SUBrshID39DMYdbDYgkyauIJWp6ojoOcAD7uqFr
z09zDU2SOP+D5RoVsE+MnnIrtYAWzlKpyqeuR8K0En2PrTBDY9oM22k9+4GGbu1S
2Zi1jtNy4VddVFoAdM4hz5oTJZUG3ybHhC/dnCj+uwIDAQABo4H6MIH3MB0GA1Ud
DgQWBBQV/GoZu9RJh0rCwcAwVUED1NCf7TAfBgNVHSMEGDAWgBQV/GoZu9RJh0rC
wcAwVUED1NCf7TAPBgNVHRMBAf8EBTADAQH/MIGjBgNVHREEgZswgZiHBH8AAAGC
EGJsb2NrZWQtZG5zLnRlc3SCE2RlbmllZC5leGFtcGxlLnRlc3SCGmFsbG93ZWQt
bGF0ZXIuZXhhbXBsZS50ZXN0gh51cGdyYWRlLWtlZXBhbGl2ZS5leGFtcGxlLnRl
c3SCFGF1ZGl0ZWQuZXhhbXBsZS50ZXN0ghdhdWRpdGVkLXdzLmV4YW1wbGUudGVz
dDANBgkqhkiG9w0BAQsFAAOCAQEAnZoNzVY6pFdmtqIPuNrCroFcKaBCbNz4jsT9
f65VMhqCBmWbHldpfSQlXRVbNwHe7yGtiKyBA2V0DtJemqplwmna6irElkMGlywi
pVmRbUNjRtSbBmnPYkRHoSRPTYUa54Zc82Iw6MGN29mcCAU4RhTI0XU55MBjA0qN
w9LwTPWVHIIDlPOCNtc3DHj7YDhTQ3mmT8XMuQYKy14kUI5o02p53cThDX2B9qxL
2jNLJq03Vyj7yXRuuuBv+epumslalkKS0Uoh6495ONf0sWrge38A4mnhuYUtGLmj
SsXJcxZgwwxzFgQZzvggPdx5pyxVNRLFKYKl/jDEMlLhkSST/w==
-----END CERTIFICATE-----
`;

const TEST_UPSTREAM_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD1Vg6MUn6jGpij
xIvRgSLcuheH3gZ3/GIFe2f6n3ptf8OjcUP5fQBa7vrnKMzeo35OKU+D/3zycrjV
zbLzqh5d9Zm+RMWfCXH3urLFj0LaHXyw/tFmQbLXW2JtKQjeuJCEYijj1VEd3o8d
TcTbLYZmOSVoHtzyDjwWQlpjBU69W+Kuk6KsTgydQ1JUsEzjeAN7VZbxJQGuyEgP
f0Mxh1sNiCTJq4glanqiOg5wAPu6oWvPT3MNTZI4/4PlGhWwT4yeciu1gBbOUqnK
p65HwrQSfY+tMENj2gzbaT37gYZu7VLZmLWO03LhV11UWgB0ziHPmhMllQbfJseE
L92cKP67AgMBAAECggEAPVmWTL/KXDYn6ngZcLwGwESm4rqCSpnp1y4be+BKiLxU
63fFBEwefR7azlh1Fs2ypZAOCtemYqiOkSSdtfIaIuvqVNq0wobloYnl76JaGNob
1tT5/0S5mMII9Hw49B0aQoibahHrdXk0t6K9cgPJ4qEyuf1RyhQGMZjJKo7muFIX
GfO1VseFqjYvmtwoSBopZfx525MqlH8UmfZf65w3lHXhzw7ZumHkSjZxJTwlHoJ7
Q5Mr6IsnpiJ1GntWJq4iTh9aHuiOJEnpUQy1ZOfwSxOcYOQ19WdBmSJRgG6nfc0N
GFVLwhnS6nEA368SFSaqib8/oXjBNttEVTYkA4s6fQKBgQD/g349rqSkRUDN1Rnu
4h60DGkt3gDlBn3obWkNxbyKrm87lO2JSq8ztLvOSHWWAdMULvtm6MM9ggUjh6HO
fz9YGbxskwBShGDfcN8poAoejomayin8ffW4Z1sh5G7SXG2QUnPtbF6kqgnfMB+R
wPplACMSOMu2Y+DBg2udzWEeXwKBgQD1zZq6c7Op2HgU9z7nlqMKPzJEyX0xxieh
r0VgktGFI609swp6VR4xSJjq2NXFE3uQWh0+ECuCnJfOV/rnebn0pCznyJliSXWc
qSbWP4aUO/tmiwYbgnx1wCcXyl94+tVA7rfvbBtMcV27vSXnFHnyXgvU8v9V8HHc
Kct4ZhBFJQKBgAMSfa4YL3qaKpFPAqTQqzXXAFzA0pnuXg0xY5X6zq2MM2IwBDsm
Xrzsa2WrkV5gXz1a40L1gYN30MAAnX1yIjzY8l8L1XEojlGhdc12UyjS5eyqiZ6z
lQTGmV3q9ToqSlb15tbv+qNYOA4q8fY6r8gPHFzXuftTcBxjjCO1mHlZAoGBAIHX
kSNq2P4gThZtILp/FTLlfS1e7hYr4WWES3afN7RHy0yrVh6W9fL8sWJlFk8bYos3
Pvk423MMOxiR2wUJhRRY4SuzCGsl+M2/gLduKS4GnV9mktxXSl19GmlzyokCn0HE
mD8N8UGpJOV2Hh5574z65u8fSYfhEpRFM6ku6OtNAoGAJ3e1rzY7vglPuPc1qw4Q
/AWUOOMI16Oxg/rHqs6HItDzbcoYkwz+w/xL5+V8KXifwcQs0T8mfSFhUiSsyKd2
uv34B2gBz1xKF/M5FmyOIkhFsyjG1+URtU1pfpl8LwOoRGoBI0oWbFQTwjGRWuqq
2q8jzM9nunrH1LBgvdj/xzs=
-----END PRIVATE KEY-----
`;

// Source-IP session identity is mandatory, so every harness-spawned proxy gets
// one served session file for 127.0.0.1 (the address every harness client
// connects from) unless the caller manages identity env itself.
const HARNESS_UID = String(process.getuid?.() ?? 0);
export const HARNESS_PROJECT_ID = "0123456789ab";
export const HARNESS_SESSION_KEY = "a".repeat(64);
const HARNESS_DIGEST = `sha256:${"c".repeat(64)}`;

export function harnessSessionFile(overrides: Partial<SessionFileV1> = {}): SessionFileV1 {
  const inspectedAt = new Date(Date.now() - 1_000);
  return {
    v: 1,
    projectId: HARNESS_PROJECT_ID,
    sessionKey: HARNESS_SESSION_KEY,
    sessionId: "rf-20260805-aaaaaa",
    sessionIncarnation: "d".repeat(64),
    sourceIp: "127.0.0.1",
    containerId: "f".repeat(64),
    networkId: "2".repeat(64),
    selectedAgentImageId: HARNESS_DIGEST,
    sessionAgentGenerationDigest: HARNESS_DIGEST,
    controlPlaneGenerationDigest: HARNESS_DIGEST,
    admissionContractEpoch: 1,
    name: "harness",
    command: "codex",
    startedAt: new Date(Date.now() - 60_000).toISOString(),
    nonce: "3".repeat(32),
    inspectedAt: inspectedAt.toISOString(),
    // Comfortably longer than any single test, well under the five-minute
    // maximum the file validity rule clamps to.
    aliveUntil: new Date(inspectedAt.getTime() + 240_000).toISOString(),
    ...overrides,
  };
}

export function harnessSessionEligibility(): string {
  return serializeSessionAdmissionEligibility(createSessionAdmissionEligibility({
    projectId: HARNESS_PROJECT_ID,
    controlPlaneGenerationDigest: HARNESS_DIGEST,
    admissionContractEpoch: 1,
    agentInternalNetworkId: "2".repeat(64),
    allowedSessionAgents: [{
      sessionAgentGenerationDigest: HARNESS_DIGEST,
      selectedAgentImageId: HARNESS_DIGEST,
    }],
  }));
}

export function writeHarnessSessionFiles(registryDir: string, files: readonly SessionFileV1[]): void {
  fs.mkdirSync(path.join(registryDir, "sessions"), { recursive: true, mode: 0o755 });
  // Atomic like the host publisher: the proxy scans every 100 ms and reads a
  // torn eligibility file as "nothing is admitted".
  replaceFileAtomically(path.join(registryDir, "eligibility.json"), harnessSessionEligibility());
  for (const file of files) {
    replaceFileAtomically(
      path.join(registryDir, "sessions", `${file.sessionKey}.json`),
      serializeSessionFileV1(file),
    );
  }
}

function provisionHarnessSessionIdentity(stateDir: string): { registryDir: string; env: NodeJS.ProcessEnv } {
  const registryDir = path.join(stateDir, "session-registry");
  fs.mkdirSync(registryDir, { recursive: true, mode: 0o755 });
  writeHarnessSessionFiles(registryDir, [harnessSessionFile()]);
  return {
    registryDir,
    env: {
      RUNFREE_PROJECT_ID: HARNESS_PROJECT_ID,
      RUNFREE_SESSION_IDENTITY_MODE: "source-ip-v1",
      RUNFREE_SESSION_ADMISSION_SOURCE: "files",
      RUNFREE_SESSION_REGISTRY_DIR: registryDir,
      RUNFREE_SESSION_REGISTRY_OWNER_UID: HARNESS_UID,
    },
  };
}

function proxyServerEnv(extraEnv: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env = { ...process.env, ...extraEnv };
  for (const key of HOST_PROXY_ENV_KEYS) {
    delete env[key];
  }
  return env;
}

export function writeJson(filePath: string, value: unknown): void {
  const policy = value !== null && typeof value === "object" && !Array.isArray(value) && "servers" in value
    ? {
      providers: Object.fromEntries(Object.entries((value as { servers: Record<string, unknown> }).servers)
        .map(([name, provider]) => [name, { kind: "mcp", ...(provider as Record<string, unknown>) }])),
    }
    : value;
  fs.writeFileSync(filePath, `${JSON.stringify(policy, null, 2)}\n`);
}

export function readJson<T = unknown>(filePath: string): T {
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
}

export function replaceJson(filePath: string, value: unknown): void {
  const tmpPath = `${filePath}.${process.pid}.tmp`;
  writeJson(tmpPath, value);
  fs.renameSync(tmpPath, filePath);
}

/**
 * Replaces a file the proxy process polls, the way the publisher does: a
 * sibling temp file renamed over the target. A plain writeFileSync truncates
 * first, and the proxy's 100ms session-admission poll can read the empty
 * selection in that window; the registry treats an unreadable selection as
 * "no sessions" and revokes every live grant and socket, which turned a valid
 * lease-only rollover into a 403 under load.
 */
export function replaceFileAtomically(filePath: string, contents: string): void {
  const tmpPath = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, contents);
  fs.renameSync(tmpPath, filePath);
}

export async function waitUntil(predicate: () => boolean, label: string, timeoutMs = 8_000): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`timed out waiting for ${label}`);
}

async function stopChild(child: childProcess.ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const exited = await Promise.race([
    new Promise<boolean>((resolve) => child.once("exit", () => resolve(true))),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 2_000)),
  ]);
  if (!exited && child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
  }
}

export async function unusedTcpPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("temporary server did not report a TCP port");
  }
  const port = address.port;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
  return port;
}

export async function startProxy(options: {
  extraEnv?: NodeJS.ProcessEnv;
  policy: unknown;
  // Set false to spawn without any session-identity env (startup-refusal
  // tests). Callers that set RUNFREE_SESSION_IDENTITY_MODE in extraEnv manage
  // identity themselves and skip the default fixture automatically.
  provisionSession?: boolean;
  secretFiles?: Record<string, string>;
  stateDir?: string;
  umask?: number;
}): Promise<RunningProxy> {
  const stateDir = options.stateDir ?? fs.mkdtempSync(path.join(tmp, "proxy-state-"));
  const policyPath = path.join(stateDir, "network-policy.json");
  const secretDir = path.join(stateDir, "secrets");
  const verboseDir = path.join(stateDir, "verbose");
  const caCertPath = path.join(stateDir, "ca", "public", "proxy-ca.crt");
  const caKeyPath = path.join(stateDir, "ca", "private", "proxy-ca.key");
  fs.mkdirSync(secretDir, { recursive: true });
  fs.mkdirSync(verboseDir, { recursive: true });
  writeJson(policyPath, options.policy);
  for (const [name, value] of Object.entries(options.secretFiles ?? {})) {
    fs.writeFileSync(path.join(secretDir, name), value);
  }
  const sessionIdentity = options.provisionSession !== false
    && options.extraEnv?.RUNFREE_SESSION_IDENTITY_MODE === undefined
    ? provisionHarnessSessionIdentity(stateDir)
    : undefined;

  const registryRoot = options.extraEnv?.RUNFREE_SESSION_REGISTRY_DIR ?? sessionIdentity?.registryDir;
  if (registryRoot && fs.existsSync(registryRoot)) {
    for (const directory of ["requests", "firewall", "request-proxy"]) {
      fs.mkdirSync(path.join(registryRoot, "ip-reuse", directory), { recursive: true, mode: 0o755 });
    }
  }
  let output = "";
  const umaskArgs = options.umask === undefined ? [] : ["--import", `data:text/javascript,process.umask(${options.umask})`];
  const child = childProcess.spawn(process.execPath, [...umaskArgs, ...proxyServerEntryArgv()], {
    cwd: repoRoot,
    env: proxyServerEnv({
      PORT: "0",
      PROXY_POLICY_PATH: policyPath,
      PROXY_SECRET_DIR: secretDir,
      PROXY_POLICY_WATCH_MS: "50",
      PROXY_VERBOSE_MARKER_DIR: verboseDir,
      CA_CERT: caCertPath,
      CA_KEY: caKeyPath,
      ...sessionIdentity?.env,
      RUNFREE_APPROVALS_PENDING_DIR: fs.mkdtempSync(path.join(tmp, "proxy-approvals-pending-")),
      RUNFREE_APPROVALS_DECISIONS_DIR: fs.mkdtempSync(path.join(tmp, "proxy-approvals-decisions-")),
      ...options.extraEnv,
    }),
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.add(child);
  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => {
    output += chunk;
  });
  child.stderr?.on("data", (chunk: string) => {
    output += chunk;
  });

  const waitForOutput = async (pattern: string | RegExp, label = String(pattern)): Promise<void> => {
    await waitUntil(() => {
      const current = output;
      return typeof pattern === "string" ? current.includes(pattern) : pattern.test(current);
    }, `${label}\n${output}`);
  };

  await Promise.race([
    waitForOutput(/proxy: listening on :\d+/),
    new Promise<never>((_, reject) => {
      child.once("exit", (code, signal) => {
        reject(new Error(`proxy exited before listening: code=${code} signal=${signal}\n${output}`));
      });
    }),
  ]);
  const port = Number(/proxy: listening on :(\d+)/.exec(output)?.[1]);
  if (!Number.isInteger(port) || port < 1) {
    throw new Error(`proxy did not report a usable listen port\n${output}`);
  }

  return {
    caCertPath,
    caKeyPath,
    output: () => output,
    policyPath,
    port,
    secretDir,
    ...(sessionIdentity !== undefined ? { sessionRegistryDir: sessionIdentity.registryDir } : {}),
    stop: async () => {
      await stopChild(child);
      children.delete(child);
    },
    verboseDir,
    waitForOutput,
  };
}

export function createUpstreamCertificate(dir: string, options: {
  commonName?: string;
  subjectAltName?: string;
} = {}): { certPath: string; keyPath: string } {
  const certPath = path.join(dir, "upstream.crt");
  const keyPath = path.join(dir, "upstream.key");
  if (options.commonName || options.subjectAltName) {
    const commonName = options.commonName ?? "127.0.0.1";
    const subjectAltName = options.subjectAltName ?? (commonName === "127.0.0.1" ? "IP:127.0.0.1" : `DNS:${commonName}`);
    childProcess.execFileSync("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-subj",
      `/CN=${commonName}`,
      "-days",
      "1",
      "-addext",
      `subjectAltName=${subjectAltName}`,
    ], { stdio: "ignore" });
    return { certPath, keyPath };
  }
  fs.writeFileSync(certPath, TEST_UPSTREAM_CERT);
  fs.writeFileSync(keyPath, TEST_UPSTREAM_KEY);
  return { certPath, keyPath };
}

export async function startHttpsUpstream(options: {
  commonName?: string;
  subjectAltName?: string;
} = {}): Promise<{
  acceptedConnections: () => number;
  certPath: string;
  keyPath: string;
  port: number;
  requests: Array<{ headers: Record<string, string | string[] | undefined>; url?: string }>;
  stop: () => Promise<void>;
}> {
  const { certPath, keyPath } = createUpstreamCertificate(tmp, options);
  const requests: Array<{ headers: Record<string, string | string[] | undefined>; url?: string }> = [];
  let acceptedConnections = 0;
  const server = https.createServer({
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
  }, (request, response) => {
    requests.push({ headers: request.headers, url: request.url });
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ ok: true, url: request.url }));
  });
  servers.add(server);
  server.on("connection", () => {
    acceptedConnections += 1;
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("upstream server did not report a TCP port");
  }
  return {
    acceptedConnections: () => acceptedConnections,
    certPath,
    keyPath,
    port: address.port,
    requests,
    stop: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
      servers.delete(server);
    },
  };
}

// An allowlisted upstream that opens a Server-Sent Events response, flushes one
// chunk immediately, then holds the connection open until the test releases it.
// A correctly streaming proxy delivers the first chunk to the client right away;
// a proxy that buffers the whole response (mockttp's beforeResponse behaviour)
// delivers nothing until the upstream ends, so a bounded read for the first
// chunk times out.
export async function startSseUpstream(): Promise<{
  certPath: string;
  finishAll: () => void;
  port: number;
  requests: Array<{ method?: string; url?: string }>;
  stop: () => Promise<void>;
}> {
  const { certPath, keyPath } = createUpstreamCertificate(tmp);
  const requests: Array<{ method?: string; url?: string }> = [];
  const open = new Set<ServerResponse>();
  const server = https.createServer({
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
  }, (request, response) => {
    requests.push({ method: request.method, url: request.url });
    response.statusCode = 200;
    response.setHeader("content-type", "text/event-stream");
    response.setHeader("cache-control", "no-cache");
    response.flushHeaders();
    response.write("data: first\n\n");
    open.add(response);
    response.once("close", () => open.delete(response));
  });
  servers.add(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("upstream server did not report a TCP port");
  }
  return {
    certPath,
    finishAll: () => {
      for (const response of open) {
        response.write("data: last\n\n");
        response.end();
      }
      open.clear();
    },
    port: address.port,
    requests,
    stop: async () => {
      for (const response of open) {
        response.destroy();
      }
      open.clear();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
      servers.delete(server);
    },
  };
}

export async function startMcpOAuthUpstream(options: {
  tokenContentType?: string | null;
  tokenResponseDelayMs?: number;
  tokenPaths?: string[];
  tokenResponseBody?: string;
} = {}): Promise<{
  port: number;
  requests: Array<{
    body: string;
    headers: Record<string, string | string[] | undefined>;
    method?: string;
    url?: string;
  }>;
  stop: () => Promise<void>;
}> {
  const { certPath, keyPath } = createUpstreamCertificate(tmp);
  const requests: Array<{
    body: string;
    headers: Record<string, string | string[] | undefined>;
    method?: string;
    url?: string;
  }> = [];
  const tokenPaths = new Set(options.tokenPaths ?? ["/oauth/token"]);
  const server = https.createServer({
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
  }, (request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      requests.push({ body, headers: request.headers, method: request.method, url: request.url });
      if (request.url === "/.well-known/oauth-authorization-server") {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({
          issuer: `https://${request.headers.host}`,
          token_endpoint: `https://${request.headers.host}/oauth/token`,
          registration_endpoint: `https://${request.headers.host}/oauth/register`,
        }));
        return;
      }
      if (request.url === "/oauth/register" && request.method === "POST") {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({
          client_id: "registered-client-id",
          client_secret: "real-registered-client-secret-1",
          registration_access_token: "real-registration-access-token-1",
          registration_client_uri: `https://${request.headers.host}/oauth/register/registered-client-id`,
        }));
        return;
      }
      if (request.url === "/oauth/register/registered-client-id") {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ ok: request.headers.authorization === "Bearer real-registration-access-token-1" }));
        return;
      }
      if (request.url && tokenPaths.has(request.url) && request.method === "POST") {
        const writeTokenResponse = () => {
          if (options.tokenContentType !== null) {
            response.setHeader("content-type", options.tokenContentType ?? "application/json");
          }
          if (options.tokenResponseBody !== undefined) {
            response.end(options.tokenResponseBody);
            return;
          }
          const params = new URLSearchParams(body);
          if (params.get("grant_type") === "refresh_token") {
            response.end(JSON.stringify({
              access_token: "real-access-token-2",
              refresh_token: "real-refresh-token-2",
              expires_in: 3600,
              token_type: "Bearer",
            }));
            return;
          }
          response.end(JSON.stringify({
            access_token: "real-access-token-1",
            refresh_token: "real-refresh-token-1",
            id_token: "real-id-token-1",
            client_secret: "real-client-secret-1",
            registration_access_token: "real-registration-token-1",
            expires_in: 3600,
            token_type: "Bearer",
          }));
        };
        if (options.tokenResponseDelayMs && options.tokenResponseDelayMs > 0) {
          setTimeout(writeTokenResponse, options.tokenResponseDelayMs);
        } else {
          writeTokenResponse();
        }
        return;
      }
      if (request.url === "/mcp") {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ ok: request.headers.authorization === "Bearer real-access-token-1" }));
        return;
      }
      response.setHeader("content-type", "application/json");
      response.statusCode = 404;
      response.end(JSON.stringify({ error: "not found" }));
    });
  });
  servers.add(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("upstream server did not report a TCP port");
  }
  return {
    port: address.port,
    requests,
    stop: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
      servers.delete(server);
    },
  };
}

export async function readUntil(socket: net.Socket | tls.TLSSocket, delimiter: string): Promise<Buffer> {
  const delimiterBuffer = Buffer.from(delimiter);
  let buffer = Buffer.alloc(0);
  return await new Promise((resolve, reject) => {
    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.includes(delimiterBuffer)) {
        socket.off("data", onData);
        resolve(buffer);
      }
    };
    socket.on("data", onData);
    socket.once("error", reject);
    socket.once("end", () => reject(new Error(`socket ended before ${JSON.stringify(delimiter)}`)));
  });
}

// Resolve when `delimiter` arrives on the socket, or reject after `timeoutMs`.
// The timeout is the regression signal: a buffering proxy never delivers the
// first streamed chunk before the upstream ends, so this rejects instead of
// hanging for the whole test budget.
export async function readUntilWithTimeout(
  socket: net.Socket | tls.TLSSocket,
  delimiter: string,
  timeoutMs: number,
): Promise<Buffer> {
  const delimiterBuffer = Buffer.from(delimiter);
  let buffer = Buffer.alloc(0);
  return await new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("error", onError);
    };
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`timed out after ${timeoutMs}ms before ${JSON.stringify(delimiter)}; received ${JSON.stringify(buffer.toString("utf8"))}`));
    }, timeoutMs);
    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.includes(delimiterBuffer)) {
        cleanup();
        resolve(buffer);
      }
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    socket.on("data", onData);
    socket.once("error", onError);
  });
}

export function parseHttpResponse(rawBuffer: Buffer): ProxyResponse {
  const raw = rawBuffer.toString("utf8");
  const [head, ...bodyParts] = raw.split("\r\n\r\n");
  const headerLines = head.split("\r\n").slice(1);
  const headers = Object.fromEntries(headerLines.flatMap((line) => {
    const separator = line.indexOf(":");
    if (separator === -1) return [];
    return [[line.slice(0, separator).toLowerCase(), line.slice(separator + 1).trim()]];
  }));
  const statusCode = Number(/^HTTP\/\S+\s+(\d+)/.exec(head)?.[1] ?? 0);
  return {
    body: bodyParts.join("\r\n\r\n"),
    headers,
    raw,
    statusCode,
  };
}

export function proxyRequestEvents(output: string): Array<Record<string, unknown>> {
  return output
    .split("\n")
    .filter((line) => line.startsWith("proxy-request: "))
    .map((line) => JSON.parse(line.slice("proxy-request: ".length)) as Record<string, unknown>);
}

export async function httpsViaProxy(options: {
  body?: string;
  headers?: Record<string, string>;
  method?: string;
  path: string;
  proxyPort: number;
  targetHost?: string;
  targetPort: number;
}): Promise<ProxyResponse> {
  const targetHost = options.targetHost ?? "127.0.0.1";
  const tunnel = await openConnectTunnel({
    authority: `${targetHost}:443`,
    proxyPort: options.proxyPort,
  });
  if (tunnel.head.statusCode !== 200) return tunnel.head;
  const socket = await tlsHandshakeOverTunnel(
    tunnel.socket,
    net.isIP(targetHost) === 0 ? targetHost : undefined,
  );
  const headerLines = Object.entries(options.headers ?? {})
    .map(([name, value]) => `${name}: ${value}`);
  const body = options.body ?? "";
  const method = options.method ?? "GET";
  socket.write([
    `${method} https://${targetHost}:${options.targetPort}${options.path} HTTP/1.1`,
    `Host: ${targetHost}:${options.targetPort}`,
    ...headerLines,
    ...(body === "" ? [] : [`Content-Length: ${Buffer.byteLength(body)}`]),
    "Connection: close",
    "",
    body,
  ].join("\r\n"));

  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.once("end", () => resolve());
    socket.once("error", reject);
  });
  return parseHttpResponse(Buffer.concat(chunks));
}

// Absolute-form plain-HTTP proxy request (http:// origin) toward an allowlisted
// host. The proxy admits the host then denies the cleartext scheme.
export async function httpViaProxyPlain(options: {
  path: string;
  proxyPort: number;
  targetHost?: string;
  targetPort: number;
}): Promise<ProxyResponse> {
  const socket = net.connect({ host: "127.0.0.1", port: options.proxyPort });
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", () => resolve());
    socket.once("error", reject);
  });
  const targetHost = options.targetHost ?? "127.0.0.1";
  socket.write([
    `GET http://${targetHost}:${options.targetPort}${options.path} HTTP/1.1`,
    `Host: ${targetHost}:${options.targetPort}`,
    "Connection: close",
    "",
    "",
  ].join("\r\n"));

  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.once("end", () => resolve());
    socket.once("error", reject);
  });
  return parseHttpResponse(Buffer.concat(chunks));
}

export async function rawConnectViaProxy(options: {
  authority: string;
  proxyPort: number;
}): Promise<ProxyResponse> {
  const { socket, head } = await openConnectTunnel(options);
  socket.destroy();
  return head;
}

export async function openConnectTunnel(options: {
  authority: string;
  proxyPort: number;
}): Promise<{ socket: net.Socket; head: ProxyResponse }> {
  const socket = net.connect({ host: "127.0.0.1", port: options.proxyPort });
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", () => resolve());
    socket.once("error", reject);
  });
  socket.on("error", () => {});
  socket.write([
    `CONNECT ${options.authority} HTTP/1.1`,
    `Host: ${options.authority}`,
    "",
    "",
  ].join("\r\n"));
  const raw = await readUntil(socket, "\r\n\r\n");
  return { socket, head: parseHttpResponse(raw) };
}

export async function tlsHandshakeOverTunnel(socket: net.Socket, servername?: string): Promise<tls.TLSSocket> {
  const tlsSocket = tls.connect({ socket, servername, rejectUnauthorized: false });
  await new Promise<void>((resolve, reject) => {
    tlsSocket.once("secureConnect", () => resolve());
    tlsSocket.once("error", reject);
  });
  return tlsSocket;
}

export async function httpsRequestOverTunnel(tlsSocket: tls.TLSSocket, options: {
  host: string;
  method?: string;
  path: string;
  targetPort?: number;
}): Promise<ProxyResponse> {
  const authority = options.targetPort === undefined ? options.host : `${options.host}:${options.targetPort}`;
  const requestTarget = options.targetPort === undefined ? options.path : `https://${authority}${options.path}`;
  tlsSocket.write([
    `${options.method ?? "GET"} ${requestTarget} HTTP/1.1`,
    `Host: ${authority}`,
    "Connection: close",
    "",
    "",
  ].join("\r\n"));
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    tlsSocket.on("data", (chunk: Buffer) => chunks.push(chunk));
    tlsSocket.once("end", () => resolve());
    tlsSocket.once("close", () => resolve());
    tlsSocket.once("error", reject);
  });
  return parseHttpResponse(Buffer.concat(chunks));
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-proxy-server-tests-")));
});

afterEach(async () => {
  for (const child of Array.from(children)) {
    await stopChild(child);
    children.delete(child);
  }
  for (const server of Array.from(servers)) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    servers.delete(server);
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});
