import type * as childProcess from "node:child_process";

import {
  serializeSessionAdmissionEligibility,
  SESSION_ADMISSION_ELIGIBILITY_SCHEMA_VERSION,
  type SessionAdmissionEligibility,
} from "@runfree/runtime-contracts/session-admission";
import {
  parseSessionFileV1,
  serializeSessionFileV1,
  sessionFilePath,
  SESSION_ELIGIBILITY_PATH,
  SESSION_FILES_DIR,
  SESSION_IP_REUSE_DIR,
  SESSION_FILE_MAX_BYTES,
  SESSION_FILE_SCHEMA_VERSION,
  type SessionFileV1,
} from "@runfree/runtime-contracts/session-file";

import { parseStrictJson } from "../control/strict-json.ts";
import { pollForExactAck } from "../generation-kernel.ts";
import { sha256Digest } from "../strict-primitives.ts";
import { ROOT_UID_GID } from "./constants.ts";
import { isExactSessionSourceIpv4 } from "@runfree/runtime-contracts/session-registry";
import { RuntimeObservationError } from "./observation-failure.ts";
import type { CaptureResult, RuntimeIO } from "./types.ts";

// The host's only writer for the per-session file tree
// (`/run/runfree-sessions/sessions/<sessionKey>.json` and its sibling
// `eligibility.json`). Every write, delete, and read goes through one pinned
// `docker exec --user 0:0 -i <exact proxy id> node -e <sealed script>` argv:
// no shell, no interpolated path, and a sha256 of the exact stdin bytes as a
// separate argument so the proxy-side script refuses a payload that is not the
// one the host digested.
//
// The scripts run in the proxy container's own Node runtime. They do not
// `require` the runtime-contracts package the proxy image ships under
// `/app/proxy/contracts`: that would bind this pinned command to the image's
// file layout and to `require(esm)` support in whatever Node the image's apt
// pin installs, and nothing in the unit suite could prove either. Instead the
// rules each script needs are inlined, deliberately narrow, and pinned to the
// contracts by tests in `session-file-publisher.test.ts` (the served-set read's
// verdicts are compared against `parseSessionFileV1` and
// `isSessionFileEligible` case by case). The write command applies the full
// `parseSessionFileV1` contract host-side before the file can be built, so a
// file the proxy's own reader would reject never reaches the proxy.

const DOCKER_CONTAINER_ID_PATTERN = /^[a-f0-9]{64}$/;

// Selection/status payloads are small; this is the spawn buffer for the
// session-admission channel, unchanged from where it used to live.
export const SESSION_ADMISSION_MAX_OUTPUT_BYTES = 32 * 1024;
// The served-set read returns one ~190-byte record per session file, so this
// holds well over the 256 records a project's session set can reach.
export const SESSION_FILE_MAX_OUTPUT_BYTES = 256 * 1024;
// The eligibility file is a handful of digests plus up to
// SESSION_ADMISSION_MAX_RECORDS agent-generation pairs; the same bound the
// proxy-side reader (`packages/proxy/src/session-files.ts`) applies when it
// reads the file back.
const SESSION_ELIGIBILITY_MAX_BYTES = 64 * 1024;

declare const sealedSessionAdmissionDockerCommandBrand: unique symbol;

export type SessionAdmissionDockerCommand = {
  readonly [sealedSessionAdmissionDockerCommandBrand]: true;
  executable: "docker";
  args: readonly string[];
  input?: string;
  effect:
    | "read-firewall-set"
    | "write-session-file"
    | "delete-session-file"
    | "publish-eligibility"
    | "read-served-set"
    | "fence-session-ip"
    | "read-ip-assignment";
};

export type SessionAdmissionDockerExecutor = Pick<RuntimeIO, "capture">;

const sealedCommands = new WeakSet<object>();

/**
 * Seals a Docker command so `executeSessionAdmissionDockerCommand` and
 * `executeSessionFileCommand` will run it. Only the two publisher modules may
 * mint one (a test in `session-file-publisher.test.ts` holds that line): a
 * forged object with the same shape is refused before Docker is reached.
 */
export function sealCommand(
  command: Omit<SessionAdmissionDockerCommand, typeof sealedSessionAdmissionDockerCommandBrand>,
): SessionAdmissionDockerCommand {
  const sealed = Object.freeze({ ...command, args: Object.freeze([...command.args]) }) as SessionAdmissionDockerCommand;
  sealedCommands.add(sealed);
  return sealed;
}

export function exactProxyId(proxyId: string): string {
  if (!DOCKER_CONTAINER_ID_PATTERN.test(proxyId)) throw new Error("proxy id must be an exact Docker container id");
  return proxyId;
}

function pinnedExec(proxyId: string, script: string, trailing: readonly string[]): readonly string[] {
  return ["exec", "--user", ROOT_UID_GID, "-i", exactProxyId(proxyId), "node", "-e", script, ...trailing];
}

// Shared by every script: the pinned destinations and the uid that must own
// them. `ownerUid` is a literal 0 in the bytes that ship; the unit test
// rewrites this one statement (and the two path literals) to run the same
// script against a tmpdir owned by the test user.
const SCRIPT_PREAMBLE = `
const ownerUid = 0;
const sessionsDir = ${JSON.stringify(SESSION_FILES_DIR)};
const eligibilityPath = ${JSON.stringify(SESSION_ELIGIBILITY_PATH)};
const sessionFileName = /^[a-f0-9]{64}\\.json$/;
function fail(message) { console.error(message); process.exit(1); }
function assertSafeDir(directory) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== ownerUid || (stat.mode & 0o022) !== 0) fail("unsafe session file directory");
}`;

// Writes one session file or the eligibility file. argv: final path, sha256 of
// the stdin bytes. Every rule is checked before the first open: the path is one
// of the two pinned destinations, the name is a session key (or exactly
// `eligibility.json`), the payload is within its size bound, its digest matches
// the argument, it parses to a JSON object, and a session file's embedded
// `sessionKey` is the one its name claims. Only then is the parent directory
// proved root-owned and the target proved a replaceable regular file. The
// temp file is created O_EXCL|O_NOFOLLOW in the destination directory, fsynced,
// renamed, and the directory fsynced; failures inside that block throw (rather
// than exit) so the finally always removes the temp file. An outer catch turns
// any of those throws — `assertReplaceable`'s refusals included — into the
// script's normal one-line `fail(<reason>)` exit instead of an uncaught
// exception's multi-line stack trace on stderr.
const WRITE_SESSION_FILE_SCRIPT = `
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
${SCRIPT_PREAMBLE}
function assertReplaceable(filePath) {
  try {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== ownerUid || stat.nlink !== 1) throw new Error("unsafe session file target");
  } catch (error) { if (!error || error.code !== "ENOENT") throw error; }
}
function fsyncDir(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}
const finalPath = process.argv[1];
const expectedSourceDigest = process.argv[2];
const payload = fs.readFileSync(0, "utf8");
const directory = path.dirname(finalPath);
const name = path.basename(finalPath);
let expectedKey;
let maxBytes;
if (directory === sessionsDir) {
  if (!sessionFileName.test(name)) fail("invalid session file name");
  expectedKey = name.slice(0, name.length - 5);
  maxBytes = ${SESSION_FILE_MAX_BYTES};
} else if (finalPath === eligibilityPath) {
  maxBytes = ${SESSION_ELIGIBILITY_MAX_BYTES};
} else {
  fail("invalid session file path");
}
if (Buffer.byteLength(payload) > maxBytes) fail("session file payload too large");
if ("sha256:" + crypto.createHash("sha256").update(payload).digest("hex") !== expectedSourceDigest) fail("session file input digest mismatch");
let parsed;
try { parsed = JSON.parse(payload); } catch { fail("malformed session file input"); }
if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail("session file input is not an object");
if (expectedKey !== undefined && parsed.sessionKey !== expectedKey) fail("session file input names another session");
assertSafeDir(directory);
try {
  assertReplaceable(finalPath);
  const temporaryPath = directory + "/.runfree-" + process.pid + "-" + crypto.randomBytes(8).toString("hex") + ".tmp";
  let descriptor;
  try {
    descriptor = fs.openSync(temporaryPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o644);
    fs.writeFileSync(descriptor, payload);
    fs.fchmodSync(descriptor, 0o644);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    assertReplaceable(finalPath);
    fs.renameSync(temporaryPath, finalPath);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try { fs.unlinkSync(temporaryPath); } catch {}
  }
  fsyncDir(directory);
  assertReplaceable(finalPath);
  if (fs.readFileSync(finalPath, "utf8") !== payload) fail("written session file differs from input");
} catch (error) {
  fail(error && error.message ? error.message : "unsafe session file target");
}
`;

// Removes one session file. argv: final path. Confined to the sessions
// directory by the same name rule as the write, and it unlinks only a regular,
// non-symlink, single-linked file. An absent file (or an absent sessions
// directory) is success, so a repeated delete after a mismatch is idempotent;
// anything else exits non-zero having unlinked nothing.
const DELETE_SESSION_FILE_SCRIPT = `
const fs = require("node:fs");
const path = require("node:path");
${SCRIPT_PREAMBLE}
const finalPath = process.argv[1];
if (path.dirname(finalPath) !== sessionsDir) fail("invalid session file path");
if (!sessionFileName.test(path.basename(finalPath))) fail("invalid session file name");
try { fs.lstatSync(sessionsDir); }
catch (error) { if (error && error.code === "ENOENT") process.exit(0); throw error; }
assertSafeDir(sessionsDir);
let stat;
try { stat = fs.lstatSync(finalPath); }
catch (error) { if (error && error.code === "ENOENT") process.exit(0); throw error; }
if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail("unsafe session file");
fs.unlinkSync(finalPath);
const descriptor = fs.openSync(sessionsDir, fs.constants.O_RDONLY);
try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
try { fs.lstatSync(finalPath); }
catch (error) { if (error && error.code === "ENOENT") process.exit(0); throw error; }
fail("session file still present after unlink");
`;

// Reports what the proxy currently holds: one JSON array on stdout with an
// entry per `sessions/*.json` file. A well-formed file contributes its
// identity plus `eligible` (the eligibility file on disk, false when it is
// missing or unparseable) and `wallActive` (its lease against the proxy's own
// clock). A file that fails to parse, or whose name does not match its
// embedded key, contributes `{ sessionKey?, name, malformed: true }` and no
// claimed fields, so the caller can delete it. This is an observation of the
// files only: it never claims which sessions a consumer has actually served,
// which stays internal to the request proxy and the firewall.
const READ_SERVED_SET_SCRIPT = `
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
${SCRIPT_PREAMBLE}
const sessionKeyPattern = /^[a-f0-9]{64}$/;
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const noncePattern = /^[a-f0-9]{32}$/;
function readOwned(filePath, maxBytes) {
  let before;
  try { before = fs.lstatSync(filePath); }
  catch (error) { if (error && error.code === "ENOENT") return null; return false; }
  if (before.isSymbolicLink() || !before.isFile() || before.uid !== ownerUid || before.nlink !== 1 || before.size > maxBytes) return false;
  let descriptor;
  try { descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)); }
  catch (error) { if (error && error.code === "ENOENT") return null; return false; }
  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.uid !== ownerUid || opened.nlink !== 1
      || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) return false;
    return fs.readFileSync(descriptor, "utf8");
  } finally { fs.closeSync(descriptor); }
}
function timestamp(value) {
  if (typeof value !== "string") return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : undefined;
}
function exactIpv4(value) {
  if (typeof value !== "string" || net.isIP(value) !== 4) return false;
  return value.split(".").map(function (part) { return String(Number(part)); }).join(".") === value;
}
function parseFile(raw, expectedKey) {
  if (Buffer.byteLength(raw) > ${SESSION_FILE_MAX_BYTES}) return undefined;
  let value;
  try { value = JSON.parse(raw); } catch { return undefined; }
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  if (value.v !== ${SESSION_FILE_SCHEMA_VERSION}) return undefined;
  if (typeof value.sessionKey !== "string" || value.sessionKey !== expectedKey) return undefined;
  if (typeof value.projectId !== "string" || value.projectId.length === 0) return undefined;
  if (!exactIpv4(value.sourceIp)) return undefined;
  if (typeof value.nonce !== "string" || !noncePattern.test(value.nonce)) return undefined;
  if (timestamp(value.aliveUntil) === undefined) return undefined;
  if (typeof value.networkId !== "string" || !sessionKeyPattern.test(value.networkId)) return undefined;
  if (typeof value.selectedAgentImageId !== "string" || !digestPattern.test(value.selectedAgentImageId)) return undefined;
  if (typeof value.sessionAgentGenerationDigest !== "string" || !digestPattern.test(value.sessionAgentGenerationDigest)) return undefined;
  if (typeof value.controlPlaneGenerationDigest !== "string" || !digestPattern.test(value.controlPlaneGenerationDigest)) return undefined;
  if (typeof value.admissionContractEpoch !== "number" || !Number.isSafeInteger(value.admissionContractEpoch) || value.admissionContractEpoch < 1) return undefined;
  return value;
}
let eligibility;
const eligibilityRaw = readOwned(eligibilityPath, ${SESSION_ELIGIBILITY_MAX_BYTES});
if (typeof eligibilityRaw === "string") {
  let value;
  try { value = JSON.parse(eligibilityRaw); } catch { value = undefined; }
  if (value && typeof value === "object" && !Array.isArray(value)
    && value.v === ${SESSION_ADMISSION_ELIGIBILITY_SCHEMA_VERSION}
    && typeof value.projectId === "string"
    && typeof value.controlPlaneGenerationDigest === "string" && digestPattern.test(value.controlPlaneGenerationDigest)
    && typeof value.admissionContractEpoch === "number"
    && typeof value.agentInternalNetworkId === "string" && sessionKeyPattern.test(value.agentInternalNetworkId)
    && Array.isArray(value.allowedSessionAgents)) eligibility = value;
}
function eligibleFor(file) {
  if (!eligibility) return false;
  return file.projectId === eligibility.projectId
    && file.controlPlaneGenerationDigest === eligibility.controlPlaneGenerationDigest
    && file.admissionContractEpoch === eligibility.admissionContractEpoch
    && file.networkId === eligibility.agentInternalNetworkId
    && eligibility.allowedSessionAgents.some(function (candidate) {
      return Boolean(candidate)
        && candidate.sessionAgentGenerationDigest === file.sessionAgentGenerationDigest
        && candidate.selectedAgentImageId === file.selectedAgentImageId;
    });
}
try { fs.lstatSync(sessionsDir); }
catch (error) {
  if (error && error.code === "ENOENT") { process.stdout.write("[]\\n"); process.exit(0); }
  throw error;
}
assertSafeDir(sessionsDir);
const names = fs.readdirSync(sessionsDir);
const now = Date.now();
const entries = [];
for (const name of names.slice().sort()) {
  if (!name.endsWith(".json")) continue;
  const stem = name.slice(0, name.length - 5);
  const key = sessionKeyPattern.test(stem) ? stem : undefined;
  const raw = readOwned(path.join(sessionsDir, name), ${SESSION_FILE_MAX_BYTES});
  if (raw === null) continue;
  const file = raw === false || key === undefined ? undefined : parseFile(raw, key);
  if (!file) {
    entries.push(key === undefined ? { name: name, malformed: true } : { sessionKey: key, name: name, malformed: true });
    continue;
  }
  entries.push({
    sessionKey: file.sessionKey,
    sourceIp: file.sourceIp,
    aliveUntil: file.aliveUntil,
    nonce: file.nonce,
    eligible: eligibleFor(file),
    wallActive: Date.parse(file.aliveUntil) > now,
  });
}
process.stdout.write(JSON.stringify(entries) + "\\n");
`;

/**
 * The one command that mints a session file. Refuses host-side, before any
 * command exists, a file the proxy's own reader would drop: the key must be
 * exact (so the path is confined to the sessions directory by construction)
 * and the serialized bytes must parse back under the full `parseSessionFileV1`
 * contract for that key.
 *
 * Only the heartbeat (`session-file-heartbeat.ts`) may call this.
 */
export function sessionFileWriteCommand(proxyId: string, file: SessionFileV1): SessionAdmissionDockerCommand {
  const finalPath = sessionFilePath(typeof file.sessionKey === "string" ? file.sessionKey : "");
  const input = serializeSessionFileV1(file);
  if (!parseSessionFileV1(input, file.sessionKey)) throw new Error("session file is invalid");
  return sealCommand({
    executable: "docker",
    effect: "write-session-file",
    input,
    args: pinnedExec(proxyId, WRITE_SESSION_FILE_SCRIPT, [finalPath, sha256Digest(input)]),
  });
}

export function sessionFileDeleteCommand(proxyId: string, sessionKey: string): SessionAdmissionDockerCommand {
  const finalPath = sessionFilePath(sessionKey);
  return sealCommand({
    executable: "docker",
    effect: "delete-session-file",
    args: pinnedExec(proxyId, DELETE_SESSION_FILE_SCRIPT, [finalPath]),
  });
}

export function eligibilityPublishCommand(
  proxyId: string,
  eligibility: SessionAdmissionEligibility,
): SessionAdmissionDockerCommand {
  const input = serializeSessionAdmissionEligibility(eligibility);
  return sealCommand({
    executable: "docker",
    effect: "publish-eligibility",
    input,
    args: pinnedExec(proxyId, WRITE_SESSION_FILE_SCRIPT, [SESSION_ELIGIBILITY_PATH, sha256Digest(input)]),
  });
}

// Read-only observation before the executor takes its kernel lock. A delayed
// executor must still find these exact bytes before it may change an address.
const READ_IP_ASSIGNMENT_SCRIPT = `
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
${SCRIPT_PREAMBLE}
const root = process.argv[1];
const sourceIp = process.argv[2];
if (root !== ${JSON.stringify(SESSION_IP_REUSE_DIR)} || require("node:net").isIP(sourceIp) !== 4) fail("invalid IP assignment read");
assertSafeDir(root);
assertSafeDir(path.join(root, "requests"));
const target = path.join(root, "requests", sourceIp + ".json");
try {
  const stat = fs.lstatSync(target);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== ownerUid || stat.nlink !== 1 || stat.size > 512) fail("unsafe IP assignment");
  process.stdout.write(crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex"));
} catch (error) {
  if (error && error.code === "ENOENT") process.stdout.write("-");
  else fail(error && error.message ? error.message : "IP assignment read failed");
}
`;

export function sessionIpAssignmentReadCommand(proxyId: string, sourceIp: string): SessionAdmissionDockerCommand {
  if (!isExactSessionSourceIpv4(sourceIp)) throw new Error("session source IP must be exact IPv4");
  return sealCommand({ executable: "docker", effect: "read-ip-assignment", args: pinnedExec(proxyId, READ_IP_ASSIGNMENT_SCRIPT, [SESSION_IP_REUSE_DIR, sourceIp]) });
}

// Run only under the lifecycle lock, after allocating an unattached address
// and before Docker create. This is a per-address fence, not a lease renewal.
const FENCE_SESSION_IP_SCRIPT = `
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const { performance } = require("node:perf_hooks");
${SCRIPT_PREAMBLE}
const requestProxyUid = 1001;
const reuseRoot = process.argv[1];
const sourceIp = process.argv[2];
const sessionKey = process.argv[3];
const expectedDigest = process.argv[4];
if (!/^(?:-|[a-f0-9]{64})$/.test(expectedDigest || "")) fail("invalid IP assignment precondition");
if (reuseRoot !== ${JSON.stringify(SESSION_IP_REUSE_DIR)}) fail("invalid IP reuse root");
if (require("node:net").isIP(sourceIp) !== 4 || !/^[a-f0-9]{64}$/.test(sessionKey)) fail("invalid IP assignment");
assertSafeDir(reuseRoot);
assertSafeDir(path.join(reuseRoot, "requests"));
const target = path.join(reuseRoot, "requests", sourceIp + ".json");
function safeFile(filePath, uid) {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== uid || stat.nlink !== 1 || stat.size > 512) throw new Error("unsafe IP reuse file");
}
function publish(state, nonce) {
  try { safeFile(target, ownerUid); } catch (error) { if (!error || error.code !== "ENOENT") throw error; }
  const temporary = target + "." + crypto.randomBytes(16).toString("hex") + ".tmp";
  try {
    const fd = fs.openSync(temporary, "wx", 0o644);
    try {
      fs.writeFileSync(fd, JSON.stringify({ v: 1, sourceIp, sessionKey, nonce, state }) + "\\n");
      fs.fchmodSync(fd, 0o644);
    } finally { fs.closeSync(fd); }
    fs.renameSync(temporary, target);
  } finally { fs.rmSync(temporary, { force: true }); }
}
function acknowledged(consumer, nonce) {
  const filePath = path.join(reuseRoot, consumer, sourceIp + ".json");
  try {
    safeFile(filePath, consumer === "firewall" ? ownerUid : requestProxyUid);
    return fs.readFileSync(filePath, "utf8") === nonce + "\\n";
  } catch { return false; }
}
const deadline = performance.now() + 20000;
function waitFor(consumers, nonce) {
  while (!consumers.every((consumer) => acknowledged(consumer, nonce))) {
    if (performance.now() >= deadline) throw new Error("IP reuse fence timed out; retry the launch to reclaim it");
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
  }
}
try {
  let actualDigest = "-";
  try {
    safeFile(target, ownerUid);
    actualDigest = crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex");
  } catch (error) { if (!error || error.code !== "ENOENT") throw error; }
  if (actualDigest !== expectedDigest) throw new Error("IP assignment changed; retry the launch");
  let nonce = crypto.randomBytes(16).toString("hex");
  publish("draining", nonce);
  waitFor(["firewall"], nonce);
  // Firewall exclusion precedes kernel drain. ss --kill may silently skip
  // unsupported sockets, so only the subsequent empty dump proves retirement.
  const port = process.env.PORT || "8080";
  if (!/^[0-9]+$/.test(port) || Number(port) < 1 || Number(port) > 65535) throw new Error("invalid proxy port");
  const filter = ["state", "connected", "exclude", "time-wait", "dst", sourceIp, "sport", "=", ":" + port];
  const options = { encoding: "utf8", env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin" }, shell: false, timeout: 5000, maxBuffer: 65536 };
  for (;;) {
    execFileSync("ss", ["-K", "-4", "-t", ...filter], options);
    if (execFileSync("ss", ["-H", "-n", "-4", "-t", ...filter], options).trim() === "") break;
    // Linux can retain unaccepted sockets after ss -K. The request proxy
    // keeps accepting and destroying this blocked IP while we wait. A stuck
    // consumer never turns a nonempty kernel dump into permission to reuse.
    if (performance.now() >= deadline) throw new Error("old TCP connections remain; retry the launch to reclaim the IP");
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
  }
  // A fresh nonce fences request-proxy work queued before the kernel drain.
  nonce = crypto.randomBytes(16).toString("hex");
  publish("draining", nonce);
  waitFor(["firewall", "request-proxy"], nonce);
  // Keep the binding for this proxy lifetime: a late file from the old owner
  // cannot reclaim this address even after its connections were destroyed.
  publish("ready", nonce);
  process.stdout.write("ok\\n");
} catch (error) { fail(error && error.message ? error.message : "IP reuse fence failed"); }
`;

export function sessionIpReuseFenceCommand(proxyId: string, sourceIp: string, sessionKey: string, expectedDigest: string): SessionAdmissionDockerCommand {
  if (!isExactSessionSourceIpv4(sourceIp)) throw new Error("session source IP must be exact IPv4");
  sessionFilePath(sessionKey);
  if (!/^(?:-|[a-f0-9]{64})$/.test(expectedDigest)) throw new Error("invalid IP assignment precondition");
  const args = [...pinnedExec(proxyId, FENCE_SESSION_IP_SCRIPT, [SESSION_IP_REUSE_DIR, sourceIp, sessionKey, expectedDigest])];
  // util-linux is already pinned in the proxy image. The kernel releases this
  // directory lock on executor exit, including a host-orphaned Docker exec.
  args.splice(5, 0, "flock", "--exclusive", "--wait", "20", "--no-fork", SESSION_IP_REUSE_DIR);
  return sealCommand({
    executable: "docker",
    effect: "fence-session-ip",
    args,
  });
}

export function servedSetReadCommand(proxyId: string): SessionAdmissionDockerCommand {
  return sealCommand({
    executable: "docker",
    effect: "read-served-set",
    args: pinnedExec(proxyId, READ_SERVED_SET_SCRIPT, []),
  });
}

function captureSealed(
  io: SessionAdmissionDockerExecutor,
  command: SessionAdmissionDockerCommand,
  dockerOptions: childProcess.SpawnSyncOptions,
  maxBuffer: number,
): CaptureResult {
  if (!sealedCommands.has(command)) throw new Error("refusing an unsealed session admission Docker command");
  return io.capture("docker", [...command.args], {
    ...dockerOptions,
    ...(command.input !== undefined ? { input: command.input } : {}),
    maxBuffer,
  });
}

export function executeSessionAdmissionDockerCommand(
  io: SessionAdmissionDockerExecutor,
  command: SessionAdmissionDockerCommand,
  dockerOptions: childProcess.SpawnSyncOptions = {},
): CaptureResult {
  return captureSealed(io, command, dockerOptions, SESSION_ADMISSION_MAX_OUTPUT_BYTES);
}

/**
 * Runs one sealed session-file command and classifies its failure. A non-zero
 * exit is an observation the host could not make — the proxy is gone, the exec
 * failed, or the script refused the payload — so it raises a typed
 * `RuntimeObservationError` the callers already branch on, never a plain Error.
 */
export function executeSessionFileCommand(
  io: SessionAdmissionDockerExecutor,
  command: SessionAdmissionDockerCommand,
  dockerOptions: childProcess.SpawnSyncOptions = {},
): CaptureResult {
  const result = captureSealed(io, command, dockerOptions, SESSION_FILE_MAX_OUTPUT_BYTES);
  if (result.status !== 0) {
    // `pinnedExec` always places `-i` at index 3 and the exact proxy id right
    // after it at index 4. Reading index 4 without checking that guard would
    // let a command built some other way (e.g. missing `-i`) misreport
    // whatever landed there — `"node"`, in `pinnedExec`'s own layout — as the
    // proxy identity.
    throw new RuntimeObservationError({
      kind: "observation-unavailable",
      subject: "proxy",
      expectedIdentity: command.args[3] === "-i" ? (command.args[4] ?? "") : "",
      phase: command.effect,
      observation: result.stderr.trim() || result.stdout.trim() || `exit ${result.status}`,
    });
  }
  return result;
}

// Bounds for the one remaining kernel-state wait. Short: the firewall's own
// reconcile loop runs every 100 ms, so a set that has not emptied within this
// window is not slow, it is stuck.
const DEFAULT_FIREWALL_SET_TIMEOUT_MS = 5_000;
const DEFAULT_FIREWALL_SET_POLL_MS = 50;

export type SessionAdmissionFirewallSetOptions = {
  timeoutMs?: number;
  pollMs?: number;
  nowMs?: () => number;
  delay?: (milliseconds: number) => Promise<void>;
  dockerOptions?: childProcess.SpawnSyncOptions;
  assertAuthority?: () => void;
};

/** Reads the live `session_ipv4` set from the proxy's own nftables ruleset. */
export function sessionAdmissionFirewallSetReadCommand(proxyId: string): SessionAdmissionDockerCommand {
  return sealCommand({
    executable: "docker",
    effect: "read-firewall-set",
    args: [
      "exec",
      "--user",
      ROOT_UID_GID,
      exactProxyId(proxyId),
      "nft",
      "-j",
      "list",
      "set",
      "inet",
      "runfree_proxy",
      "session_ipv4",
    ],
  });
}

function parseEmptySessionAdmissionFirewallSet(stdout: string): boolean {
  let value: unknown;
  try {
    value = parseStrictJson(stdout);
  } catch {
    return false;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const nftables = (value as { nftables?: unknown }).nftables;
  if (!Array.isArray(nftables)) return false;
  const sets = nftables.flatMap((entry): Record<string, unknown>[] => {
    const set = typeof entry === "object" && entry !== null ? (entry as { set?: unknown }).set : undefined;
    return typeof set === "object" && set !== null && !Array.isArray(set) ? [set as Record<string, unknown>] : [];
  }).filter((set) => set.family === "inet" && set.table === "runfree_proxy" && set.name === "session_ipv4");
  if (sets.length !== 1) return false;
  const elements = sets[0]?.elem;
  return elements === undefined || (Array.isArray(elements) && elements.length === 0);
}

function positiveInteger(value: number | undefined, fallback: number, label: string): number {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1) throw new Error(`${label} must be a positive integer`);
  return selected;
}

/**
 * Proves deny-by-default from the live kernel ruleset rather than inferring it.
 *
 * A restarted proxy comes back with an empty session-file directory, so its
 * firewall supervisor's next scan admits nothing — but "the loop will get
 * there" is an assumption, and the caller that wants to declare the project
 * denied-by-default needs the observation. Bounded and fail-closed: a set that
 * never empties raises rather than passing.
 */
export async function waitForSessionAdmissionFirewallSetEmpty(
  io: SessionAdmissionDockerExecutor,
  proxyId: string,
  options: SessionAdmissionFirewallSetOptions = {},
): Promise<void> {
  const empty = await pollForExactAck({
    beforeProbe: () => options.assertAuthority?.(),
    probe: () => {
      const result = executeSessionAdmissionDockerCommand(io, sessionAdmissionFirewallSetReadCommand(proxyId), options.dockerOptions);
      return result.status === 0
          && Buffer.byteLength(result.stdout) <= SESSION_ADMISSION_MAX_OUTPUT_BYTES
          && parseEmptySessionAdmissionFirewallSet(result.stdout)
        ? true
        : undefined;
    },
    afterProbe: () => options.assertAuthority?.(),
    timeoutMs: positiveInteger(options.timeoutMs, DEFAULT_FIREWALL_SET_TIMEOUT_MS, "session admission firewall set timeout"),
    pollIntervalMs: positiveInteger(options.pollMs, DEFAULT_FIREWALL_SET_POLL_MS, "session admission firewall set poll interval"),
    deadline: "before-probe",
    ...(options.nowMs ? { nowMs: options.nowMs } : {}),
    ...(options.delay ? { delay: options.delay } : {}),
  });
  if (!empty) {
    throw new Error("session-admission firewall set did not converge to empty after the proxy restart");
  }
}
