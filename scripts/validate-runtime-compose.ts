#!/usr/bin/env node

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { RUNFREE_VERSION } from "../packages/cli/src/embedded-assets.generated.ts";
import { renderRuntimeCompose } from "../packages/cli/src/runtime/compose.ts";
import { runtimeInputBuildEnvironment } from "../packages/cli/src/runtime-inputs.ts";

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const runtimeRoot = path.join(repoRoot, "dist", "runtime");

function renderComposeForValidation(destination: string): string {
  const source = path.join(runtimeRoot, "agent", "compose.yaml");
  const rendered = renderRuntimeCompose(fs.readFileSync(source, "utf8"), {});
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.mkdirSync(path.join(path.dirname(path.dirname(destination)), "proxy"), { recursive: true });
  fs.writeFileSync(destination, rendered);
  return rendered;
}

function fail(message: string): never {
  console.error(`validate-runtime-compose: ${message}`);
  process.exit(1);
}

function requireCommand(command: string): void {
  const result = childProcess.spawnSync(command, ["--version"], {
    encoding: "utf8",
    stdio: "ignore",
    shell: false,
  });
  if (result.error || result.status !== 0) fail(`missing required command: ${command}`);
}

type ComposeConfig = {
  networks?: Record<string, Record<string, unknown>>;
  services?: Record<string, Record<string, unknown>>;
};

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} missing or invalid`);
  return value as Record<string, unknown>;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function assert(condition: boolean, message: string): void {
  if (!condition) fail(message);
}

function assertRenderedIsAgentless(compose: string): void {
  const lines = compose.split(/\r?\n/);
  // Shape B (per-session cutover): the fixed control plane renders proxy-only.
  // An agent is a per-session container admitted onto agent_internal by source
  // IP at launch — it is never a Compose service. Lock that in so a regression
  // that reintroduces a shared `agent:` service is caught before render, and so
  // the retired agent env_file raw-format concern (now owned by the per-session
  // admission path) cannot silently return here.
  assert(!lines.some((line) => line === "  agent:"), "rendered compose must not define a shared agent service (per-session shape)");
}

function serviceNetworks(service: Record<string, unknown>): string[] {
  const networks = service.networks;
  if (Array.isArray(networks)) return networks.filter((entry): entry is string => typeof entry === "string").sort();
  if (networks && typeof networks === "object") return Object.keys(networks).sort();
  return [];
}

function hasTmpfs(service: Record<string, unknown>, target: string): boolean {
  return asStringArray(service.tmpfs).some((entry) => entry === target || entry.startsWith(`${target}:`));
}

function assertNoPublishedPorts(service: Record<string, unknown>, label: string): void {
  const ports = service.ports;
  assert(ports === undefined || (Array.isArray(ports) && ports.length === 0), `${label} must not publish host ports`);
}

function assertNetwork(config: ComposeConfig, name: string, expected: {
  enableIpv6?: boolean;
  internal?: boolean;
  inhibitIpv4?: boolean;
}): void {
  const network = asRecord(asRecord(config.networks, "networks")[name], `network ${name}`);
  if (expected.internal !== undefined) assert(network.internal === expected.internal, `${name} internal must be ${expected.internal}`);
  if (expected.enableIpv6 !== undefined) assert(network.enable_ipv6 === expected.enableIpv6, `${name} enable_ipv6 must be ${expected.enableIpv6}`);
  if (expected.inhibitIpv4 !== undefined) {
    const driverOpts = asRecord(network.driver_opts, `${name} driver_opts`);
    assert(driverOpts["com.docker.network.bridge.inhibit_ipv4"] === "true", `${name} must inhibit the bridge IPv4 gateway`);
  }
}

function assertRuntimeComposeConfig(config: ComposeConfig): void {
  const services = asRecord(config.services, "services");
  // Shape B: the fixed topology is proxy-only. A shared `agent` service must
  // never reappear in the rendered config — agents are per-session containers
  // admitted by source IP at launch, with their mounts, caps, and proxy env
  // attested at admission (session-container-proof), not here.
  assert(!("agent" in services), "compose config must not include a shared agent service (per-session shape)");
  const proxy = asRecord(services.proxy, "service proxy");

  assert(typeof proxy.image === "string" && proxy.image.length > 0, "proxy service must use a prebuilt image");
  assert(!("build" in proxy), "proxy service must not define an inline build");
  assert(asStringArray(proxy.cap_add).includes("NET_ADMIN"), "proxy must add NET_ADMIN for the firewall supervisor");
  assert(!asStringArray(proxy.cap_add).includes("NET_RAW"), "proxy must not add NET_RAW");
  assert(asStringArray(proxy.cap_drop).includes("NET_RAW"), "proxy must drop NET_RAW");
  assert(asStringArray(proxy.security_opt).includes("no-new-privileges:true"), "proxy must set no-new-privileges");
  assertNoPublishedPorts(proxy, "proxy");
  assert(serviceNetworks(proxy).join(",") === "agent_internal,proxy_egress", "proxy must join internal and egress networks");
  assert(hasTmpfs(proxy, "/run/runfree-proxy-secrets"), "proxy must keep credentials in tmpfs");
  assert(hasTmpfs(proxy, "/run/runfree-proxy-audit"), "proxy must declare the audit marker tmpfs");
  assert(hasTmpfs(proxy, "/run/runfree-proxy-audit-spool"), "proxy must declare the audit spool tmpfs");
  assert(hasTmpfs(proxy, "/run/runfree-proxy-status"), "proxy must declare the policy-generation status tmpfs");
  // The marker dir must stay root-owned: a uid=1001 tmpfs here would let the
  // agent-facing proxy server self-enable audit mode.
  const auditMarkerTmpfs = asStringArray(proxy.tmpfs).find((entry) => entry === "/run/runfree-proxy-audit" || entry.startsWith("/run/runfree-proxy-audit:"));
  assert(auditMarkerTmpfs !== undefined && !auditMarkerTmpfs.includes("uid="), "audit marker tmpfs must not be uid-owned by the proxy server");
  // The status root must stay root-owned: firewall.json is the convergence
  // claim that matters for policy removals, and the uid-1001 request proxy
  // must not be able to write it.
  const statusTmpfs = asStringArray(proxy.tmpfs).find((entry) => entry === "/run/runfree-proxy-status" || entry.startsWith("/run/runfree-proxy-status:"));
  assert(statusTmpfs !== undefined && !statusTmpfs.includes("uid="), "status tmpfs must not be uid-owned by the proxy server");

  assertNetwork(config, "agent_internal", { enableIpv6: false, inhibitIpv4: true, internal: true });
  assertNetwork(config, "proxy_egress", { enableIpv6: false });
}

requireCommand("docker");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-compose-config-"));
try {
  const mcpOperationPolicy = path.join(tmp, "mcp-operation-policy.json");
  const effectiveProxyDir = path.join(tmp, "effective-proxy");
  const proxyCaPrivate = path.join(tmp, "proxy-ca-private");
  const proxyCaPublic = path.join(tmp, "proxy-ca-public");
  const composeFile = path.join(tmp, "runtime", "agent", "compose.yaml");

  fs.writeFileSync(mcpOperationPolicy, "{\"schemaVersion\":1,\"servers\":[]}\n");
  for (const dir of [effectiveProxyDir, proxyCaPrivate, proxyCaPublic]) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const renderedCompose = renderComposeForValidation(composeFile);
  assertRenderedIsAgentless(renderedCompose);

  const result = childProcess.spawnSync("docker", ["compose", "-f", composeFile, "config", "--format", "json"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      ...runtimeInputBuildEnvironment(runtimeRoot),
      RUNFREE_PROJECT_ID: "static-check",
      RUNFREE_COMPOSE_PROJECT_NAME: "runfree-static-check",
      RUNFREE_EFFECTIVE_PROXY_DIR: effectiveProxyDir,
      RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: mcpOperationPolicy,
      RUNFREE_PROXY_CA_KEY_DIR: proxyCaPrivate,
      RUNFREE_PROXY_CA_CERT_DIR: proxyCaPublic,
      RUNFREE_PROXY_IMAGE: "runfree/proxy-runtime:static-compose-check",
      RUNFREE_PROXY_IMAGE_INPUT_DIGEST: "sha256:static-compose-check-proxy-image",
      RUNFREE_PROXY_EGRESS_SUBNET: "172.30.1.0/24",
      RUNFREE_PROXY_EGRESS_IP: "172.30.1.10",
      RUNFREE_PROXY_EGRESS_GATEWAY: "172.30.1.1",
      RUNFREE_TOPOLOGY_DIGEST: "sha256:static-compose-check-topology",
      RUNFREE_VERSION,
    },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    shell: false,
  });
  if (result.error || result.status !== 0) {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
  let config: ComposeConfig;
  try {
    config = JSON.parse(result.stdout) as ComposeConfig;
  } catch (error) {
    fail(`docker compose config did not produce JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  assertRuntimeComposeConfig(config);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
