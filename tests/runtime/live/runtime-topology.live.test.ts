// The three read-only runtime security tranches, sharing one provisioned
// fixture and one standing session: runtime topology and capability floor,
// egress containment, and the pre-TLS CONNECT guard. All were ported from the
// retired `tests/runtime/sandbox.sh`.
//
// They live in one file because the runtime-live project runs files in a
// single sequential fork, and everything below only READS the provisioned
// runtime: Docker inspects, in-container probes, proxy log greps, and denied
// requests that mutate nothing durable. Sharing the fixture cuts three full
// provisions (and three standing-session launches) down to one per run.
// The Git portability proof also writes disposable repository metadata in the
// fixture workspace; it does not alter the network or security configuration.
// Ordering is deliberate: topology's log assertions run before the denial
// probes flood the proxy log tail, and the CONNECT-guard probes run after the
// egress tranche's own bounded log-tail assertions.
//
// Topology tranche: proves the shape of the running runtime on real Docker —
// the uniform container taxonomy, the two-network topology and its membership,
// the agent capability floor (a property of the per-session container), the
// proxy's NET_ADMIN-without-NET_RAW posture and unprivileged uid-1001 server,
// the egress route and the exact owned nftables ruleset, that the egress
// network is not a client path, the startup logs, and that uid-1001 cannot
// write the root-owned firewall status. Everything is read back from the
// daemon or the live kernel state, never from the render that produced it.
//
// Egress tranche: proves the network boundary from inside the live per-session
// agent — direct DNS and direct egress blocked with the proxy env unset, no
// host-gateway / default-route / bridge-gateway / IPv6 bypass, loopback still
// works, an allowlisted host reaches upstream, a denied host receives an
// in-tunnel synthetic 403 with remediation and no credential, the denial is
// private, and the agent sees placeholders only and none of the proxy-only CA
// or secret material.
//
// CONNECT-guard tranche: proves the proxy rejects unsafe tunnels before TLS
// and before any upstream dial — non-443 refused on the port even for an
// allowlisted host, malformed CONNECT refused, and a CONNECT whose authority
// disagrees with the TLS SNI terminated before the handshake completes.
//
// Reads that a negative check depends on are assigned to a variable first, so
// an unreadable source fails the test instead of vacuously satisfying an
// absence.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { validateProxyNftablesTableJson } from "../../../packages/cli/src/proxy-nftables-proof.ts";
import { NON_RESOLVING_CONNECT_PROBE_HOST } from "../../../packages/cli/src/runtime/probes.ts";
import {
  firewallStatusPath,
  requestProxyStatusPath,
} from "../../../packages/runtime-contracts/src/proxy-status.ts";
import {
  composeProjectName,
  composeServiceContainerId,
  containerImageRef,
  docker,
  dockerOrThrow,
} from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  provisionSandboxFixture,
  startStandingSession,
  type CaptureResult,
  type LiveFixture,
  type LiveRuntimeBackend,
  type StandingSessionHandle,
} from "./fixture.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 10 * 60_000;
const DENIED_PROBE_HOST = "denied.sandbox.invalid";

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the read-only runtime tranches");
  }
  return backend;
}

// ---------------------------------------------------------------------------
// Shared probe helpers (topology).
// ---------------------------------------------------------------------------

/** `docker exec` on a container, optionally as an explicit uid:gid. */
function containerExec(containerId: string, argv: readonly string[], user?: string) {
  return docker(["exec", ...(user ? ["--user", user] : []), containerId, ...argv]);
}

function inspectField(containerId: string, format: string): string {
  return dockerOrThrow(`inspect ${format}`, ["inspect", "-f", format, containerId]);
}

function inspectJson<T>(containerId: string, format: string): T {
  return JSON.parse(inspectField(containerId, format)) as T;
}

/** Sorted keys of a container's attached networks. */
function containerNetworkNames(containerId: string): readonly string[] {
  const networks = inspectJson<Record<string, unknown>>(containerId, "{{json .NetworkSettings.Networks}}");
  return Object.keys(networks).filter(Boolean).sort();
}

/** A container's IPv4 address on one named network endpoint. */
function containerAddressOnNamedNetwork(containerId: string, networkName: string): string {
  const ip = inspectField(containerId, `{{with index .NetworkSettings.Networks "${networkName}"}}{{.IPAddress}}{{end}}`);
  if (!/^\d{1,3}(\.\d{1,3}){3}$/u.test(ip)) {
    throw new Error(`${containerId.slice(0, 12)} has no IPv4 address on ${networkName}: ${describeOutput(ip)}`);
  }
  return ip;
}

/** The four uniform taxonomy labels, read from the live container. */
function taxonomyLabels(containerId: string): string {
  return inspectField(
    containerId,
    '{{ index .Config.Labels "io.runfree.managed" }} {{ index .Config.Labels "io.runfree.container-role" }}'
      + ' {{ index .Config.Labels "io.runfree.lifecycle-owner" }} {{ index .Config.Labels "io.runfree.label-schema" }}',
  );
}

/** Whether an nftables CapBnd-style hex mask has a capability bit set. */
function capBitSet(hex: string, bit: bigint): boolean {
  return (BigInt(`0x${hex}`) & (1n << bit)) !== 0n;
}
const CAP_NET_ADMIN = 12n;
const CAP_NET_RAW = 13n;

function procStatusField(status: string, field: string): string {
  const line = status.split("\n").find((candidate) => candidate.startsWith(`${field}:`));
  if (!line) throw new Error(`/proc status has no ${field} line: ${describeOutput(status)}`);
  return line.slice(field.length + 1).trim();
}

/** The `dev <iface>` of an `ip -o route get` line. */
function routeDevice(routeLine: string): string {
  const tokens = routeLine.trim().split(/\s+/u);
  const index = tokens.indexOf("dev");
  if (index === -1 || !tokens[index + 1]) throw new Error(`route line names no device: ${describeOutput(routeLine)}`);
  return tokens[index + 1];
}

// ---------------------------------------------------------------------------
// Shared probe helpers (egress containment).
// ---------------------------------------------------------------------------

// The exact set the agent env carries; unsetting all of them proves the firewall
// blocks rather than the (cooperative) proxy env routing.
const PROXY_ENV_UNSET = [
  "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "http_proxy", "-u", "https_proxy",
  "-u", "ALL_PROXY", "-u", "all_proxy", "-u", "NO_PROXY", "-u", "no_proxy",
] as const;

/** A login-shell script inside the session. */
function sessionExec(id: string, script: string): CaptureResult {
  return docker(["exec", id, "zsh", "-lc", script]);
}
/** A login-shell script inside the session with all proxy env unset. */
function sessionExecNoProxy(id: string, script: string): CaptureResult {
  return docker(["exec", id, "env", ...PROXY_ENV_UNSET, "zsh", "-lc", script]);
}
/** A Node program inside the session (argv, never shell-quoted) with proxy env unset. */
function sessionNodeNoProxy(id: string, program: string): CaptureResult {
  return docker(["exec", id, "env", ...PROXY_ENV_UNSET, "node", "-e", program]);
}

const DIRECT_EGRESS_PROGRAM = `
const net = require("node:net");
const socket = net.connect({ host: "1.1.1.1", port: 443 });
const timeout = setTimeout(() => { socket.destroy(); console.log("blocked: timeout"); process.exit(0); }, 3000);
socket.on("connect", () => { clearTimeout(timeout); console.error("direct TCP egress connected"); socket.destroy(); process.exit(1); });
socket.on("error", (error) => { clearTimeout(timeout); console.log("blocked: " + (error.code || error.message)); process.exit(0); });
`;

const LOOPBACK_PROGRAM = `
const net = require("node:net");
const server = net.createServer((socket) => socket.end("ok\\n"));
const timeout = setTimeout(() => { console.error("timeout"); process.exit(1); }, 2000);
server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  const client = net.connect({ host: "127.0.0.1", port: address.port });
  let output = "";
  client.on("data", (chunk) => { output += chunk.toString("utf8"); });
  client.on("end", () => { clearTimeout(timeout); server.close(() => process.stdout.write(output)); });
  client.on("error", (error) => { clearTimeout(timeout); console.error(error.message); process.exit(1); });
});
`;

const TOKEN_ENV_PROGRAM = `
const placeholder = "runfree-placeholder-overwritten-by-proxy";
const tokenish = Object.entries(process.env)
  .filter(([key]) => /(?:TOKEN|API_KEY|SECRET|PASSWORD)$/i.test(key))
  .sort(([left], [right]) => left.localeCompare(right));
for (const key of ["GH_TOKEN", "GITHUB_TOKEN"]) {
  if (process.env[key] !== placeholder) { console.error(key + " is not the Runfree placeholder"); process.exit(1); }
}
const unexpected = tokenish.filter(([, value]) => value !== placeholder);
if (unexpected.length > 0) { console.error("non-placeholder token-like env vars: " + unexpected.map(([key]) => key).join(", ")); process.exit(1); }
for (const [key] of tokenish) console.log(key + "=<placeholder>");
`;

// ---------------------------------------------------------------------------
// Shared probe helpers (CONNECT guard).
// ---------------------------------------------------------------------------

/** A raw CONNECT to the proxy over `nc`, returning what the proxy answered. */
function rawConnect(sessionId: string, proxyIp: string, authority: string): CaptureResult {
  const request = `CONNECT ${authority} HTTP/1.1\\r\\nHost: ${authority}\\r\\n\\r\\n`;
  return docker(["exec", sessionId, "sh", "-lc", `printf '${request}' | nc -w 3 ${proxyIp} 8080`]);
}

// Admits the CONNECT, then offers a TLS ClientHello whose SNI disagrees with the
// admitted authority; the proxy must terminate before the handshake completes.
const SNI_MISMATCH_PROGRAM = `
const net = require("node:net");
const tls = require("node:tls");
const proxyHost = process.argv[1];
const connectHost = "api.github.com";
const mismatchedSni = "registry.npmjs.org";
const socket = net.connect({ host: proxyHost, port: 8080 });
let buffered = Buffer.alloc(0);
let settled = false;
const finish = (code, message) => {
  if (settled) return;
  settled = true;
  clearTimeout(timeout);
  socket.destroy();
  console.log(message);
  process.exit(code);
};
const timeout = setTimeout(() => finish(1, "timed out waiting for SNI mismatch rejection"), 10000);
socket.once("connect", () => { socket.write("CONNECT " + connectHost + ":443 HTTP/1.1\\r\\nHost: " + connectHost + ":443\\r\\n\\r\\n"); });
socket.on("data", function onData(chunk) {
  buffered = Buffer.concat([buffered, chunk]);
  const headEnd = buffered.indexOf("\\r\\n\\r\\n");
  if (headEnd === -1) return;
  socket.off("data", onData);
  const head = buffered.subarray(0, headEnd).toString("latin1");
  if (!/^HTTP\\/1\\.1 200\\b/.test(head)) { finish(1, "CONNECT was not admitted for the SNI probe: " + head); return; }
  socket.removeAllListeners("error");
  const tlsSocket = tls.connect({ socket, servername: mismatchedSni, rejectUnauthorized: false });
  tlsSocket.once("secureConnect", () => finish(1, "mismatched SNI unexpectedly completed TLS"));
  tlsSocket.once("error", (error) => finish(0, "blocked: " + (error.code || error.message)));
  tlsSocket.once("close", () => finish(0, "blocked: connection closed before TLS completed"));
});
socket.once("error", (error) => finish(1, "proxy TCP error before TLS: " + (error.code || error.message)));
`;

// ---------------------------------------------------------------------------
// One shared provisioned fixture + one standing session for all three
// tranches below. Everything after provisioning is read-only.
// ---------------------------------------------------------------------------

let fixture: LiveFixture;
let project: string;
let internalNetwork: string;
let egressNetwork: string;
let proxyId: string;
let proxyIp: string;
let standing: StandingSessionHandle;
let sessionId: string;
let agentImage: string;

beforeAll(async () => {
  requiredBackend();
  fixture = provisionSandboxFixture(REPO_ROOT);
  project = composeProjectName(fixture);
  internalNetwork = `${project}_agent_internal`;
  egressNetwork = `${project}_proxy_egress`;
  proxyId = composeServiceContainerId(project, "proxy");
  proxyIp = dockerOrThrow("proxy internal address", [
    "inspect", "-f", `{{with index .NetworkSettings.Networks "${project}_agent_internal"}}{{.IPAddress}}{{end}}`, proxyId,
  ]);
  standing = await startStandingSession(fixture);
  sessionId = standing.session.containerId;
  agentImage = containerImageRef(sessionId);
}, PROVISION_TIMEOUT_MS);

afterAll(async () => {
  if (standing) await standing.release();
  if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
}, PROVISION_TIMEOUT_MS);

describe("runtime topology and capability floor on real Docker", () => {
  test("worktrees created by sandbox Git remain usable on the host and vice versa", () => {
    const sandboxGit = (cwd: string, args: string[]) => {
      const result = containerExec(sessionId, ["git", "-C", cwd, ...args], "1000:1000");
      expect(result.status, describeOutput(result.output)).toBe(0);
      return result.stdout;
    };
    const hostGit = (cwd: string, args: string[]) => {
      const result = childProcess.spawnSync("git", ["-C", cwd, ...args], {
        encoding: "utf8",
        env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" },
      });
      expect(result.status, describeOutput(`${result.stdout}${result.stderr}`)).toBe(0);
      return result.stdout;
    };
    sandboxGit("/workspace", ["init", "-q"]);
    sandboxGit("/workspace", ["-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "--allow-empty", "-qm", "initial"]);
    // This conditional include matches only the container path. Checking host
    // config alone would miss its override; the sandbox's command scope wins.
    const overrideFile = path.join(fixture.projectRoot, ".git", "relative-override");
    fs.writeFileSync(overrideFile, "[worktree]\nuseRelativePaths = false\n");
    fs.appendFileSync(path.join(fixture.projectRoot, ".git", "config"), '\n[includeIf "gitdir:/workspace/.git"]\npath = relative-override\n');
    sandboxGit("/workspace", ["config", "extensions.worktreeConfig", "true"]);
    sandboxGit("/workspace", ["config", "--worktree", "worktree.useRelativePaths", "false"]);
    expect(sandboxGit("/workspace", ["config", "--type=bool", "--get", "worktree.useRelativePaths"]).trim()).toBe("true");
    sandboxGit("/workspace", ["worktree", "add", "-qb", "sandbox-feature", ".worktrees/sandbox-feature"]);
    const sandboxWorktree = path.join(fixture.projectRoot, ".worktrees", "sandbox-feature");
    hostGit(sandboxWorktree, ["status", "--porcelain"]);
    expect(hostGit(fixture.projectRoot, ["worktree", "list", "--porcelain"])).not.toContain("prunable");

    hostGit(fixture.projectRoot, ["worktree", "add", "--relative-paths", "-qb", "host-feature", ".worktrees/host-feature"]);
    sandboxGit("/workspace/.worktrees/host-feature", ["status", "--porcelain"]);
    expect(sandboxGit("/workspace", ["worktree", "list", "--porcelain"])).not.toContain("prunable");
    const gitfile = path.join(sandboxWorktree, ".git");
    const before = fs.readFileSync(gitfile, "utf8");
    sandboxGit("/workspace", ["worktree", "repair"]);
    expect(fs.readFileSync(gitfile, "utf8")).toBe(before);
    hostGit(sandboxWorktree, ["status", "--porcelain"]);
  }, TEST_TIMEOUT_MS);

  test("proxy and session containers carry the uniform taxonomy labels", () => {
    expect(taxonomyLabels(proxyId), "proxy taxonomy labels").toBe("true proxy compose 1");
    // The per-session container's lifecycle owner is `session`, not `compose`:
    // its ownership is the lifecycle registry, not a Compose project.
    expect(taxonomyLabels(sessionId), "session-agent taxonomy labels").toBe("true session-agent session 1");
  }, TEST_TIMEOUT_MS);

  test("the Compose runtime is the proxy alone, with no shared agent service", () => {
    // Shape-exact both ways, and the reason the negative half matters: the
    // per-session runtime's fixed control plane is the proxy, so asserting only
    // `toContain("proxy")` would still pass if a shared `agent` service came
    // back — the pre-cutover shape this must never silently accept. Inherited
    // from the retired nominal admission tranche, which owned this guard and
    // paid a whole fixture for it; here it is a read-only census of a runtime
    // that is already up.
    const services = dockerOrThrow("running compose services", [
      "ps",
      "--filter", `label=com.docker.compose.project=${project}`,
      // `.Label "name"` is the accessor for a single label. In `docker ps`
      // templates `.Labels` renders as one comma-joined string rather than a
      // map, so indexing it fails the template outright and the command exits
      // non-zero without listing anything.
      "--format", '{{.Label "com.docker.compose.service"}}',
    ]).split("\n").map((line) => line.trim()).filter(Boolean);
    expect(services, "the proxy is the runtime's control plane").toContain("proxy");
    expect(services, "no shared agent service survives the per-session cutover").not.toContain("agent");
  }, TEST_TIMEOUT_MS);

  test("the runtime is exactly the two-network Shape B, with correct membership", () => {
    expect(containerNetworkNames(sessionId), "session container joins only the internal network")
      .toEqual([internalNetwork]);
    expect(containerNetworkNames(proxyId), "proxy joins the internal and egress networks")
      .toEqual([internalNetwork, egressNetwork].sort());

    const internal = JSON.parse(dockerOrThrow("internal network inspect", ["network", "inspect", internalNetwork]))[0];
    const egress = JSON.parse(dockerOrThrow("egress network inspect", ["network", "inspect", egressNetwork]))[0];
    expect(internal.Internal, "internal network is Docker-internal").toBe(true);
    expect(internal.EnableIPv6, "internal network has IPv6 disabled").toBe(false);
    expect(egress.EnableIPv6, "egress network has IPv6 disabled").toBe(false);
    expect(
      internal.Options?.["com.docker.network.bridge.inhibit_ipv4"],
      "internal network inhibits the Docker bridge IPv4 gateway",
    ).toBe("true");

    // Membership is a census of the daemon's own view: exactly the proxy and the
    // one standing session, by container name.
    const members = Object.values(internal.Containers as Record<string, { Name: string }>)
      .map((entry) => entry.Name).sort();
    const expectedMembers = [
      inspectField(proxyId, "{{.Name}}").replace(/^\//u, ""),
      inspectField(sessionId, "{{.Name}}").replace(/^\//u, ""),
    ].sort();
    expect(members, "internal network members are exactly the proxy and the session").toEqual(expectedMembers);
  }, TEST_TIMEOUT_MS);

  test("neither the proxy nor the session publishes a host port", () => {
    for (const [label, id] of [["proxy", proxyId], ["session", sessionId]] as const) {
      const ports = inspectJson<Record<string, unknown> | null>(id, "{{json .NetworkSettings.Ports}}") ?? {};
      const bindings = inspectJson<Record<string, unknown> | null>(id, "{{json .HostConfig.PortBindings}}") ?? {};
      const published = [...Object.values(ports), ...Object.values(bindings)].some(
        (binding) => Array.isArray(binding) && binding.length > 0,
      );
      expect(published, `${label} publishes a host port`).toBe(false);
    }
  }, TEST_TIMEOUT_MS);

  test("the session agent has no NET_ADMIN or NET_RAW, is uid 1000, and setuid stays 1000", () => {
    expect(inspectField(sessionId, "{{.Config.User}}"), "session numeric user").toContain("1000:1000");
    expect(inspectField(sessionId, "{{json .HostConfig.SecurityOpt}}"), "session no-new-privileges")
      .toContain("no-new-privileges:true");
    const capDrop = inspectField(sessionId, "{{json .HostConfig.CapDrop}}");
    const capAdd = inspectField(sessionId, "{{json .HostConfig.CapAdd}}");
    expect(capDrop, "session drops NET_ADMIN").toContain("NET_ADMIN");
    expect(capDrop, "session drops NET_RAW").toContain("NET_RAW");
    expect(capAdd, "session does not add NET_ADMIN").not.toContain("NET_ADMIN");
    expect(capAdd, "session does not add NET_RAW").not.toContain("NET_RAW");

    const pid1 = containerExec(sessionId, ["awk", "/^(Uid|Gid|NoNewPrivs|CapBnd):/ { print }", "/proc/1/status"], "1000:1000");
    expect(pid1.status, `could not read session PID 1 status: ${describeOutput(pid1.output)}`).toBe(0);
    expect(procStatusField(pid1.stdout, "Uid").split(/\s+/)[0], "session PID 1 UID is fixed").toBe("1000");
    expect(procStatusField(pid1.stdout, "Gid").split(/\s+/)[0], "session PID 1 GID is fixed").toBe("1000");
    expect(procStatusField(pid1.stdout, "NoNewPrivs"), "session PID 1 no-new-privileges").toBe("1");
    const capBnd = procStatusField(pid1.stdout, "CapBnd");
    expect(capBitSet(capBnd, CAP_NET_ADMIN), "NET_ADMIN remains in session CapBnd").toBe(false);
    expect(capBitSet(capBnd, CAP_NET_RAW), "NET_RAW remains in session CapBnd").toBe(false);

    const idProbe = containerExec(sessionId, ["sh", "-lc", 'printf "uid=%s gid=%s\\n" "$(id -u)" "$(id -g)"'], "1000:1000");
    expect(idProbe.stdout.trim(), "session exec uid/gid fixed").toBe("uid=1000 gid=1000");

    const setuid = containerExec(sessionId, ["/usr/local/bin/runfree-setuid-id", "-u"], "1000:1000");
    expect(setuid.status, `setuid probe failed: ${describeOutput(setuid.output)}`).toBe(0);
    expect(setuid.stdout.trim(), "a setuid helper still runs as uid 1000").toBe("1000");
  }, TEST_TIMEOUT_MS);

  test("the proxy keeps NET_ADMIN without NET_RAW for the nftables backend", () => {
    expect(inspectField(proxyId, "{{json .HostConfig.CapAdd}}"), "proxy adds NET_ADMIN").toContain("NET_ADMIN");
    expect(inspectField(proxyId, "{{json .HostConfig.CapAdd}}"), "proxy does not add NET_RAW").not.toContain("NET_RAW");
    expect(inspectField(proxyId, "{{json .HostConfig.CapDrop}}"), "proxy drops NET_RAW").toContain("NET_RAW");
    expect(inspectField(proxyId, "{{json .HostConfig.SecurityOpt}}"), "proxy no-new-privileges")
      .toContain("no-new-privileges:true");

    const pid1 = containerExec(proxyId, ["awk", "/^CapBnd:/ { print }", "/proc/1/status"], "0:0");
    expect(pid1.status, `could not read proxy PID 1 CapBnd: ${describeOutput(pid1.output)}`).toBe(0);
    const capBnd = procStatusField(pid1.stdout, "CapBnd");
    expect(capBitSet(capBnd, CAP_NET_ADMIN), "NET_ADMIN missing from proxy PID 1 CapBnd").toBe(true);
    expect(capBitSet(capBnd, CAP_NET_RAW), "NET_RAW present in proxy PID 1 CapBnd").toBe(false);
  }, TEST_TIMEOUT_MS);

  test("the proxy reports readiness through its request-proxy status file", () => {
    const status = containerExec(proxyId, ["cat", requestProxyStatusPath()]);
    expect(status.status, `could not read the request-proxy status file: ${describeOutput(status.output)}`).toBe(0);
    expect(status.stdout, "request-proxy status names a generation").toMatch(/"generation":"sha256:[a-f0-9]{64}"/u);
  }, TEST_TIMEOUT_MS);

  test("the proxy server process is unprivileged and cannot reach DNS, nftables, or routes", () => {
    const serverStatus = containerExec(proxyId, [
      "sh", "-lc",
      `for status in /proc/[0-9]*/status; do
         proc="\${status%/status}"
         [ -r "$status" ] || continue
         [ -r "$proc/cmdline" ] || continue
         uid="$(awk '/^Uid:/ { print $2 }' "$status" 2>/dev/null)" || continue
         [ "$uid" = "1001" ] || continue
         cmdline="$(tr '\\000' ' ' < "$proc/cmdline" 2>/dev/null)" || continue
         case "$cmdline" in *"/app/proxy/server.js"*) ;; *) continue ;; esac
         awk '/^(Uid|Gid|NoNewPrivs|CapAmb|CapInh|CapPrm|CapEff|CapBnd):/ { print }' "$status" 2>/dev/null
         exit 0
       done
       exit 1`,
    ], "0:0");
    expect(serverStatus.status, `could not locate the proxy server process: ${describeOutput(serverStatus.output)}`).toBe(0);
    expect(procStatusField(serverStatus.stdout, "Uid").split(/\s+/)[0], "proxy server UID is runfree-proxy").toBe("1001");
    expect(procStatusField(serverStatus.stdout, "Gid").split(/\s+/)[0], "proxy server GID is runfree-proxy").toBe("1001");
    expect(procStatusField(serverStatus.stdout, "NoNewPrivs"), "proxy server no-new-privileges").toBe("1");
    for (const field of ["CapAmb", "CapInh"]) {
      expect(BigInt(`0x${procStatusField(serverStatus.stdout, field)}`), `${field} is not empty`).toBe(0n);
    }
    for (const field of ["CapPrm", "CapEff", "CapBnd"]) {
      const hex = procStatusField(serverStatus.stdout, field);
      expect(capBitSet(hex, CAP_NET_ADMIN), `NET_ADMIN remains in proxy server ${field}`).toBe(false);
      expect(capBitSet(hex, CAP_NET_RAW), `NET_RAW remains in proxy server ${field}`).toBe(false);
    }

    // The uid-1001 server cannot reach external or Docker DNS, inspect nftables,
    // or alter routes. Each attempt runs as the server uid and must fail.
    const externalDns = containerExec(proxyId, ["sh", "-lc", "timeout 3 dig +time=2 +tries=1 @1.1.1.1 example.com >/dev/null"], "1001:1001");
    expect(externalDns.status, "proxy server uid reached external DNS").not.toBe(0);
    const dockerDns = containerExec(proxyId, ["sh", "-lc", "timeout 3 dig +time=2 +tries=1 @127.0.0.11 example.com >/dev/null"], "1001:1001");
    expect(dockerDns.status, "proxy server uid reached Docker loopback DNS").not.toBe(0);
    const nftRuleset = containerExec(proxyId, ["nft", "list", "ruleset"], "1001:1001");
    expect(nftRuleset.status, "proxy server uid inspected the nftables ruleset").not.toBe(0);
    const routeAdmin = containerExec(proxyId, [
      "sh", "-lc",
      "if ip route add blackhole 203.0.113.254/32; then ip route del blackhole 203.0.113.254/32 >/dev/null 2>&1 || true; exit 0; fi; exit 1",
    ], "1001:1001");
    expect(routeAdmin.status, "proxy server uid altered routes").not.toBe(0);
  }, TEST_TIMEOUT_MS);

  test("the proxy egress route, ingress firewall, and owned nftables ruleset are exact", () => {
    const proxyEgressIp = containerAddressOnNamedNetwork(proxyId, egressNetwork);
    const sourceIp = standing.session.sourceIp;

    const egressRoute = dockerOrThrow("proxy egress route", ["exec", proxyId, "ip", "-o", "route", "get", "1.1.1.1"]);
    expect(egressRoute, "proxy route uses the egress source address").toContain(`src ${proxyEgressIp}`);
    const egressIface = routeDevice(egressRoute);
    const internalRoute = dockerOrThrow("proxy internal route", ["exec", proxyId, "ip", "-o", "route", "get", sourceIp]);
    const internalIface = routeDevice(internalRoute);
    expect(internalIface && egressIface && internalIface !== egressIface, "internal and egress interfaces are distinct").toBe(true);

    const tableJson = dockerOrThrow("proxy nftables table", ["exec", "--user", "0:0", proxyId, "nft", "-j", "list", "table", "inet", "runfree_proxy"]);
    // Session-only mode: no fixed-agent accept rules are expected post-cutover,
    // so `agentIp` is omitted and their presence would be an error.
    const issues = validateProxyNftablesTableJson({
      rawJson: tableJson,
      internalIface,
      egressIface,
      serverUid: "1001",
    });
    expect(issues, `proxy owned nftables table has unexpected rules:\n${issues.join("\n")}`).toEqual([]);

    const allowedSet = dockerOrThrow("allowed_ipv4 set", ["exec", "--user", "0:0", proxyId, "nft", "list", "set", "inet", "runfree_proxy", "allowed_ipv4"]);
    expect(allowedSet, "allowed_ipv4 set is inspectable").toContain("set allowed_ipv4");
    // Both always-present audit sets exist and are empty in enforce mode.
    for (const setName of ["audit_ipv4", "audit_draining_ipv4"]) {
      const set = dockerOrThrow(`${setName} set`, ["exec", "--user", "0:0", proxyId, "nft", "list", "set", "inet", "runfree_proxy", setName]);
      expect(set, `${setName} present in enforce mode`).toContain(`set ${setName}`);
      expect(set, `${setName} empty in enforce mode`).not.toContain("elements");
    }

    const rootDns = containerExec(proxyId, ["sh", "-lc", "timeout 3 dig +time=2 +tries=1 @127.0.0.11 example.com >/dev/null"], "0:0");
    expect(rootDns.status, "proxy root supervisor cannot use Docker DNS").toBe(0);
  }, TEST_TIMEOUT_MS);

  test("the proxy egress network is not a proxy client path", () => {
    const proxyEgressIp = containerAddressOnNamedNetwork(proxyId, egressNetwork);
    const probe = docker([
      "run", "--rm", "--network", egressNetwork, "--entrypoint", "sh", agentImage, "-lc",
      `printf 'CONNECT api.github.com:443 HTTP/1.1\\r\\nHost: api.github.com:443\\r\\n\\r\\n' | nc -w 3 ${proxyEgressIp} 8080`,
    ]);
    // A CONNECT from the egress side must never be admitted (no 200 tunnel).
    expect(
      probe.status === 0 && probe.output.includes("HTTP/1.1 200"),
      `proxy accepted client traffic from the egress network: ${describeOutput(probe.output)}`,
    ).toBe(false);
  }, TEST_TIMEOUT_MS);

  test("the proxy startup logs show the loaded allowlist and installed ruleset", () => {
    const logs = dockerOrThrow("proxy logs", ["logs", proxyId]);
    expect(logs, "proxy hostname allowlist loaded").toContain("allowed_hosts=[");
    expect(logs, "proxy firewall policy loaded").toContain("proxy-firewall: policy loaded");
    expect(logs, "proxy DNS refresh ran").toContain("proxy-firewall: DNS refresh");
    expect(logs, "proxy installed the nftables ruleset").toContain("proxy-firewall: installed nftables ruleset internal=");
    const recent = dockerOrThrow("proxy recent logs", ["logs", "--tail", "120", proxyId]);
    expect(recent, "proxy refresh has no proc-fd redirect error").not.toContain("/proc/1/fd/1: Permission denied");
  }, TEST_TIMEOUT_MS);

  test("uid-1001 cannot write the root-owned firewall status file", () => {
    const write = containerExec(proxyId, ["sh", "-c", `: > ${firewallStatusPath()}`], "1001:1001");
    expect(write.status, "uid-1001 wrote the root-owned firewall status file").not.toBe(0);
  }, TEST_TIMEOUT_MS);
});

describe("egress containment inside a live per-session agent", () => {
  test("direct external DNS is blocked over both UDP and TCP", () => {
    const udp = sessionExecNoProxy(sessionId, "dig +time=1 +tries=1 @1.1.1.1 example.com");
    expect(udp.status, `agent external UDP DNS unexpectedly succeeded: ${describeOutput(udp.output)}`).not.toBe(0);
    const tcp = sessionExecNoProxy(sessionId, "dig +tcp +time=1 +tries=1 @1.1.1.1 example.com");
    expect(tcp.status, `agent external TCP DNS unexpectedly succeeded: ${describeOutput(tcp.output)}`).not.toBe(0);
  }, TEST_TIMEOUT_MS);

  test("container-local loopback IPC still works", () => {
    const probe = docker(["exec", sessionId, "node", "-e", LOOPBACK_PROGRAM]);
    expect(probe.stdout, `loopback IPC failed: ${describeOutput(probe.output)}`).toContain("ok");
  }, TEST_TIMEOUT_MS);

  test("an allowlisted host is reachable through the proxy", () => {
    const probe = sessionExec(sessionId,
      "curl -sS --retry 3 --retry-delay 1 --retry-all-errors --max-time 15 -o /dev/null -w '%{http_code}' https://api.github.com/rate_limit");
    expect(probe.stdout.trim(), `allowlisted host was not reachable: ${describeOutput(probe.output)}`).toBe("200");
  }, TEST_TIMEOUT_MS);

  test("direct egress fails with the proxy environment unset", () => {
    const probe = sessionNodeNoProxy(sessionId, DIRECT_EGRESS_PROGRAM);
    expect(probe.status, `direct egress bypass unexpectedly succeeded: ${describeOutput(probe.output)}`).toBe(0);
    expect(probe.stdout, "direct TCP egress was not blocked").toContain("blocked:");
  }, TEST_TIMEOUT_MS);

  test("there is no host-gateway, default-route, bridge-gateway, or IPv6 bypass", () => {
    const hostGateway = sessionExecNoProxy(sessionId, "getent hosts host.docker.internal");
    expect(hostGateway.status, `agent resolved the Docker host gateway: ${describeOutput(hostGateway.output)}`).not.toBe(0);
    const defaultRoute = sessionExec(sessionId, "ip -4 route show default || true");
    expect(defaultRoute.stdout.trim(), `agent has an IPv4 default route: ${describeOutput(defaultRoute.output)}`).toBe("");
    const ipv6Default = sessionExec(sessionId, "ip -6 route show default || true");
    expect(ipv6Default.stdout.trim(), `agent has an IPv6 default route: ${describeOutput(ipv6Default.output)}`).toBe("");

    const internal = JSON.parse(dockerOrThrow("internal network inspect", ["network", "inspect", internalNetwork]))[0];
    const gateways = ((internal.IPAM?.Config ?? []) as { Gateway?: string }[])
      .map((entry) => entry.Gateway).filter((gateway): gateway is string => Boolean(gateway));
    for (const gateway of gateways) {
      const reach = sessionExecNoProxy(sessionId, `timeout 3 zsh -lc '</dev/tcp/${gateway}/80'`);
      expect(reach.status, `agent reached numeric Docker bridge gateway ${gateway}: ${describeOutput(reach.output)}`).not.toBe(0);
    }
  }, TEST_TIMEOUT_MS);

  test("a non-allowlisted host fails closed for a certificate-validating client", () => {
    const probe = sessionExec(sessionId,
      "curl -sS -o /tmp/example-block.txt -w '\\n%{http_code}' --max-time 10 https://example.com");
    expect(probe.status, `curl to a non-allowlisted host unexpectedly succeeded: ${describeOutput(probe.output)}`).not.toBe(0);
  }, TEST_TIMEOUT_MS);

  test("a denied host receives an in-tunnel synthetic 403 with remediation and no credential", () => {
    const probe = sessionExec(sessionId, `
      set -euo pipefail
      rm -f /tmp/denied-headers.txt /tmp/denied-body.txt
      http_code="$(curl -ksS --max-time 10 -D /tmp/denied-headers.txt -o /tmp/denied-body.txt -w '%{http_code}' 'https://${DENIED_PROBE_HOST}/v1/data?secret_param=should-not-be-logged')"
      printf 'http_code=%s\\n' "$http_code"
      cat /tmp/denied-headers.txt
      cat /tmp/denied-body.txt
    `);
    expect(probe.status, `in-tunnel denial probe failed: ${describeOutput(probe.output)}`).toBe(0);
    const out = probe.output;
    expect(out, "in-tunnel denial does not return 403").toContain("http_code=403");
    expect(out, "denial reason header missing").toContain("x-runfree-blocked: host-not-allowlisted");
    expect(out, "denial does not name the host").toContain(`host:   ${DENIED_PROBE_HOST}`);
    expect(out, "denial does not name the host add command").toContain(`runfree host add ${DENIED_PROBE_HOST}`);
    expect(out, "denial body is not the synthetic template").toContain("Runfree blocked this request.");
    // Even a denied response must carry no injected credential.
    expect(out.toLowerCase(), "denial response carries an authorization header").not.toContain("authorization:");
    expect(out, "denial response carries a bearer value").not.toContain("Bearer ");
  }, TEST_TIMEOUT_MS);

  test("the denial is private: no query string logged, and no DNS resolution of the denied host", () => {
    const logs = dockerOrThrow("proxy logs", ["logs", "--tail", "400", proxyId]);
    expect(logs, "structured denial event missing").toContain("proxy-denial: ");
    expect(logs, "denial event does not name the host").toContain(`"host":"${DENIED_PROBE_HOST}"`);
    expect(logs, "denial event does not carry pathname only").toContain('"path":"/v1/data"');
    expect(logs, "denial event leaked the query string key").not.toContain("secret_param");
    expect(logs, "denial event leaked a query value").not.toContain("should-not-be-logged");
    // The structured event names the denial reason; the retired free-text
    // "proxy: blocked host=" line no longer exists.
    expect(logs, "denial event does not carry the structured reason").toContain('"reason":"host-not-allowlisted"');

    // No DNS resolution: the denied host must be absent from the resolved-hosts
    // snapshot and from the firewall's DNS-refresh logs. Both reads are asserted
    // non-empty first so an unreadable source cannot satisfy the absence.
    const snapshot = docker(["exec", "--user", "0:0", proxyId, "cat", "/run/runfree-resolved-hosts.json"]);
    expect(snapshot.status, `could not read the resolved-hosts snapshot: ${describeOutput(snapshot.output)}`).toBe(0);
    expect(snapshot.stdout.trim(), "resolved-hosts snapshot is empty").not.toBe("");
    expect(snapshot.stdout, "denied host present in the resolved-hosts snapshot").not.toContain(DENIED_PROBE_HOST);
    const firewallDnsLines = dockerOrThrow("proxy full logs", ["logs", proxyId])
      .split("\n").filter((line) => line.includes("proxy-firewall:"));
    expect(firewallDnsLines.length, "proxy emitted no proxy-firewall log lines to check").toBeGreaterThan(0);
    expect(firewallDnsLines.join("\n"), "denied host present in firewall DNS logs").not.toContain(DENIED_PROBE_HOST);
  }, TEST_TIMEOUT_MS);

  test("runfree doctor names the blocked host and the host add command", () => {
    const doctor = fixture.runfree(["doctor"]);
    expect(doctor.output, "doctor does not name the denied host").toContain(`${DENIED_PROBE_HOST} is not allowlisted`);
    expect(doctor.output, "doctor does not suggest the host add command").toContain(`runfree host add ${DENIED_PROBE_HOST}`);
  }, TEST_TIMEOUT_MS);

  test("the agent's token-like env vars are placeholders only", () => {
    const probe = docker(["exec", sessionId, "node", "-e", TOKEN_ENV_PROGRAM]);
    expect(probe.status, `token env probe failed: ${describeOutput(probe.output)}`).toBe(0);
    expect(probe.stdout, "GH_TOKEN placeholder not visible").toContain("GH_TOKEN=<placeholder>");
    expect(probe.stdout, "GITHUB_TOKEN placeholder not visible").toContain("GITHUB_TOKEN=<placeholder>");
  }, TEST_TIMEOUT_MS);

  test("the agent sees none of the proxy-only CA or secret material", () => {
    // The proxy holds its private CA key and secret tmpfs with the expected
    // ownership and filesystem types.
    const proxy = docker(["exec", proxyId, "sh", "-lc", `
      set -eu
      test -f /ca/private/proxy-ca.key
      test -f /ca/public/proxy-ca.crt
      test "$(findmnt -T /run/runfree-proxy-secrets -n -o FSTYPE)" = tmpfs
      test "$(findmnt -T /run/runfree-proxy-status -n -o FSTYPE)" = tmpfs
      test "$(stat -c '%u:%g:%a' /run/runfree-proxy-secrets)" = 1001:1001:700
      test "$(stat -c '%u:%g:%a' /run/runfree-proxy-status)" = 0:0:755
    `]);
    expect(proxy.status, `proxy credential material check failed: ${describeOutput(proxy.output)}`).toBe(0);

    // The agent sees only the public CA cert, and none of the private material.
    const agent = docker(["exec", sessionId, "zsh", "-lc", `
      set -euo pipefail
      test -f /etc/proxy-ca/proxy-ca.crt
      test ! -e /etc/proxy-ca/proxy-ca.key
      test ! -e /ca/private/proxy-ca.key
      test ! -e /run/runfree-proxy-secrets
      test ! -e /run/runfree-proxy-status
    `]);
    expect(agent.status, `agent credential-material isolation check failed: ${describeOutput(agent.output)}`).toBe(0);
  }, TEST_TIMEOUT_MS);
});

describe("pre-TLS CONNECT guard", () => {
  test("a denied host on 443 is tunneled (for the in-tunnel 403), but non-443 and malformed CONNECTs are refused pre-TLS", () => {
    const denied443 = rawConnect(sessionId, proxyIp, "disallowed.example:443");
    expect(denied443.status, `raw CONNECT probe failed: ${describeOutput(denied443.output)}`).toBe(0);
    expect(denied443.output, "a denied 443 host was not tunneled for the in-tunnel denial").toContain("200");

    // Non-443 is refused on the port, before the host allowlist and before DNS —
    // proven with a reserved non-resolving host so no policy host or third party
    // is a dependency of the proof.
    const nonHttps = rawConnect(sessionId, proxyIp, `${NON_RESOLVING_CONNECT_PROBE_HOST}:22`);
    expect(nonHttps.status, `raw CONNECT non-443 probe failed: ${describeOutput(nonHttps.output)}`).toBe(0);
    expect(nonHttps.output, "non-443 CONNECT not rejected").toContain("403");
    expect(nonHttps.output, "non-443 rejection does not cite the port").toContain("blocked non-HTTPS CONNECT port: 22");

    // The port check runs before the host check: allowlisting must not buy a
    // non-HTTPS tunnel.
    const allowlistedNonHttps = rawConnect(sessionId, proxyIp, "api.github.com:22");
    expect(allowlistedNonHttps.status, `raw CONNECT allowlisted non-443 probe failed: ${describeOutput(allowlistedNonHttps.output)}`).toBe(0);
    expect(allowlistedNonHttps.output, "non-443 CONNECT not rejected for an allowlisted host").toContain("403");
    expect(allowlistedNonHttps.output, "allowlisted non-443 rejection does not cite the port")
      .toContain("blocked non-HTTPS CONNECT port: 22");

    const malformed = docker(["exec", sessionId, "sh", "-lc",
      `printf 'CONNECT bad authority HTTP/1.1\\r\\nHost: bad\\r\\n\\r\\n' | nc -w 3 ${proxyIp} 8080`]);
    expect(malformed.status, `raw CONNECT malformed probe failed: ${describeOutput(malformed.output)}`).toBe(0);
    expect(malformed.output, "malformed CONNECT not rejected").toContain("403");
  }, TEST_TIMEOUT_MS);

  test("a CONNECT whose authority disagrees with the TLS SNI is terminated before the handshake", () => {
    const probe = docker(["exec", sessionId, "node", "-e", SNI_MISMATCH_PROGRAM, proxyIp]);
    expect(probe.status, `CONNECT/SNI mismatch was not rejected: ${describeOutput(probe.output)}`).toBe(0);
    expect(probe.stdout, "CONNECT/SNI mismatch did not terminate the handshake").toContain("blocked:");

    const logs = dockerOrThrow("proxy logs", ["logs", "--tail", "200", proxyId]);
    expect(logs, "CONNECT/SNI mismatch emitted no structured denial").toContain('"reason":"connect-sni-mismatch"');
    expect(logs, "CONNECT/SNI denial does not name the admitted host").toContain('"host":"api.github.com"');
  }, TEST_TIMEOUT_MS);
});
