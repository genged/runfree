import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parse as parseToml } from "smol-toml";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { SESSION_ELIGIBILITY_PATH } from "@runfree/runtime-contracts/session-file";

import { defaultConfig, projectControlPaths, type RunfreeConfig, type ProjectInfo } from "./config.ts";
import { service, serviceHostNames } from "../../../scripts/services.ts";
import { agentRuntimeImageTag, effectiveRuntimeDigest, proxyRuntimeImageTag } from "./agent-image.ts";
import { desiredServiceEntry } from "./admin/service-policy.ts";
import {
  approveNetworkCandidate,
  approveRuntimeIsolationControl,
} from "./control/approvals.ts";
import { captureDesiredPolicyCandidate } from "./control/candidates.ts";
import { clearActiveControlSelection, publishEffectivePolicyGeneration, } from "./control/effective.ts";
import { RUNFREE_RUNTIME_DIGEST, RUNFREE_VERSION } from "./embedded-assets.generated.ts";
import {
  mcpApprovalPath,
  mcpInventory,
  prepareMcpRuntime,
  setMcpLogContext,
  saveMcpApproval,
} from "./runtime/mcp.ts";
import type { RuntimeNetwork } from "./network.ts";
import type { PiProviderChoice, PiProviderOption } from "./runtime/types.ts";
import { composeProjectName, projectHash } from "./project-identity.ts";
import { proxyNftablesTableFixture, proxyNftablesTableJson } from "./proxy-nftables-proof.fixture.ts";
import {
  createDependencyOverlayPlan,
  dependencyOverlayRuntimeSignature,
  depsRuntime,
  serializeDependencyOverlayPlan,
  serializeDependencyOverlayRuntimeSignature,
} from "./runtime/dependency-overlays.ts";
import { runtimeEnvironment } from "./runtime/env.ts";
import {
  CONTROL_PLANE_PROOF_SCHEMA_VERSION,
  createControlPlaneGenerationV2,
  createControlPlaneMaterializationManifestV2,
  controlPlaneEffectiveSelectionPathV2,
  controlPlaneMaterializationManifestPathV2,
  publishControlPlaneMaterializationV2,
  readDesiredSessionAgentV2,
  readEffectiveControlPlaneV2,
  selectEffectiveControlPlaneV2,
} from "./runtime/component-state-v2.ts";
import {
  createRuntimeComponentState,
  readEffectiveRuntimeGeneration,
  runtimeMaterializationRoot,
  selectEffectiveRuntimeGeneration,
  serializeRuntimeGenerationManifest,
  sha256Digest,
  type RuntimeComponentState,
} from "./runtime/component-state.ts";
import { createRuntimePlan } from "./runtime/plan.ts";
import { NON_RESOLVING_CONNECT_PROBE_HOST } from "./runtime/probes.ts";
import {
  bindAllocatedSessionContainerIdV2,
  createAllocatedSessionContainerRecordV2,
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  writeSessionContainerRecordV2,
} from "./runtime/session-containers.ts";
import { sessionContainerRecordFixture } from "./runtime/session-container.test-harness.ts";
import { hostBootId, hostProcessStart } from "./runtime/host-identity.ts";
import { createSessionLaunchTarget } from "./runtime/session-launch.ts";
import { buildTokenAutoRefreshSpawnPlan, containerMissingNetwork, resolveRunfreeSelfInvocation } from "./runtime.ts";
import {
  formatSessionFileStatusLine,
  logsRuntime,
  nodeRuntimeIO,
  resolveRuntimeAdminEnvironment,
  resourcesRuntime,
  runAgentCommand,
  sessionsRuntime,
  statusRuntime,
  stopRuntime,
  type CaptureResult,
  type RuntimeAdminIntent,
  type RuntimeContext,
  type RuntimeIO,
} from "./runtime.ts";
import { createRuntimeAdapters } from "./runtime/adapters.ts";
import {
  AGENT_PROJECT_IMAGE_ROLE,
  AGENT_RUNTIME_IMAGE_ROLE,
  PROJECT_ID_LABEL,
  PROXY_RUNTIME_IMAGE_ROLE,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
  RUNFREE_MANAGED_IMAGE_LABEL,
} from "./runtime/constants.ts";
import { runtimeDryRun } from "./runtime/front.ts";
import { repairWorktreeLinks } from "./runtime/git-layout.ts";
import { subprocessCategory } from "./runtime/operation-histogram.ts";
import { COMPOSE_UP_FAILURE_REMEDY, startRuntime, up } from "./runtime/startup.ts";
import { flushWarnings, pendingWarningsForTest } from "./warnings.ts";

// Real `docker ps -q`/`-aq` prints 12-character short IDs unless `--no-trunc`
// is passed, while `docker inspect` resolves a prefix but always reports the
// full 64-hex `.Id`. Modelling that here is load-bearing: a double that lists
// full IDs from a truncating command hides every short-vs-exact identity
// defect, and those defects only surface against a live daemon.
function fakeListedContainerIds(args: string[], ids: string[]): string {
  const listed = args.includes("--no-trunc") ? ids : ids.map((id) => id.slice(0, 12));
  return `${listed.join("\n")}\n`;
}

const FAKE_AGENT_CONTAINER_ID = "1".repeat(64);
const FAKE_PROXY_CONTAINER_ID = "2".repeat(64);
const FAKE_AGENT_INTERNAL_NETWORK_ID = "3".repeat(64);
const FAKE_PROXY_EGRESS_NETWORK_ID = "4".repeat(64);
const FAKE_CALLBACK_HOST_NETWORK_ID = "5".repeat(64);
const FAKE_PROXY_CA_PEM = "-----BEGIN CERTIFICATE-----\nfake-proxy-ca\n-----END CERTIFICATE-----\n";
const FAKE_SYSTEM_ROOTS_PEM = "-----BEGIN CERTIFICATE-----\nfake-system-roots\n-----END CERTIFICATE-----\n";

let tmp: string;
let previousPath: string | undefined;

function projectInfo(projectRoot: string, config: RunfreeConfig = defaultConfig()): ProjectInfo {
  const runfreeDir = path.join(projectRoot, ".runfree");
  const stateDir = path.join(path.dirname(projectRoot), "state");
  return {
    config,
    paths: {
      runfreeDir,
      agentEnvPath: path.join(runfreeDir, "config", "agent.env"),
      claudeConfigPath: path.join(stateDir, "claude.json"),
      claudeMcpConfigPath: path.join(stateDir, "mounts", "claude-mcp.json"),
      claudeDir: path.join(stateDir, "claude"),
      codexDir: path.join(stateDir, "codex"),
      configPath: path.join(runfreeDir, "runfree.json"),
      ...projectControlPaths(stateDir),
      gitConfigPath: path.join(stateDir, "gitconfig"),
      inboxDir: path.join(stateDir, "inbox"),
      projectCodexDirMaskPath: path.join(stateDir, "mounts", "project-codex-mask"),
      mcpOperationPolicyPath: path.join(stateDir, "mcp-operation-policy.json"),
      mcpOAuthPolicyPath: path.join(stateDir, "oauth-mediation-policy.json"),
      proxyCaCertDir: path.join(stateDir, "proxy-ca", "public"),
      proxyCaKeyDir: path.join(stateDir, "proxy-ca", "private"),
      policyPath: path.join(runfreeDir, "network-policy.json"),
      sessionsDir: path.join(stateDir, "sessions"),
      stateDir,
      tokenConfigPath: path.join(path.dirname(projectRoot), "config", "runfree", "projects", projectHash(projectRoot), "tokens.json"),
    },
  };
}

function writeExecutable(filePath: string, source: string): void {
  fs.writeFileSync(filePath, source, { mode: 0o755 });
}

function readJsonLines(filePath: string): Array<Record<string, unknown>> {
  return fs.readFileSync(filePath, "utf8").trim().split(/\n+/).filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

function onlyMaterializedRuntimeRoot(project: ProjectInfo): string {
  const root = path.join(project.paths.stateDir, "runtime", "materializations");
  const entries = fs.readdirSync(root).filter((entry) => entry.startsWith("sha256-"));
  expect(entries).toHaveLength(1);
  return path.join(root, entries[0]);
}

function publishMaterializedRuntimeGenerationV1(
  context: RuntimeContext,
  overrides: Partial<Pick<RuntimeComponentState,
    "selectedAgentImageInputDigest" | "proxyImageInputDigest" | "topologyDigest" | "hostHelperDigest">>,
): RuntimeComponentState {
  const desired = createRuntimePlan(context, { dockerSubnets: [], persistNetwork: false });
  const components = createRuntimeComponentState({ ...desired.components, ...overrides });
  const root = runtimeMaterializationRoot(context.project.paths.stateDir, components.materializationDigest);
  writeRuntimeAssets(root);
  fs.writeFileSync(path.join(root, "agent", "compose.yaml"), desired.renderedCompose);
  const manifest = {
    schemaVersion: 1 as const,
    projectId: desired.projectId,
    composeProject: desired.composeProjectName,
    components,
    images: {
      agent: desired.agentImage?.projectImage ?? agentRuntimeImageTag(components.selectedAgentImageInputDigest),
      proxy: proxyRuntimeImageTag(components.proxyImageInputDigest),
    },
    renderedComposeSha256: sha256Digest(desired.renderedCompose),
  };
  fs.writeFileSync(path.join(root, "generation.json"), serializeRuntimeGenerationManifest(manifest), { mode: 0o600 });
  selectEffectiveRuntimeGeneration(context.project.paths.stateDir, components.materializationDigest);
  return components;
}

function runtimeContainerLabelRows(
  components: RuntimeComponentState,
  identity: { composeProject: string; projectId: string },
  services: readonly ("agent" | "proxy")[],
): string {
  return `${services.map((service) => [
    `${service}-id`,
    service,
    "1",
    service === "agent" ? components.selectedAgentImageInputDigest : "<no value>",
    service === "proxy" ? components.proxyImageInputDigest : "<no value>",
    components.topologyDigest,
    "<no value>",
    service === "agent"
      ? agentRuntimeImageTag(components.selectedAgentImageInputDigest)
      : proxyRuntimeImageTag(components.proxyImageInputDigest),
    "true",
    identity.projectId,
    identity.composeProject,
  ].join("\t")).join("\n")}\n`;
}

function installFakeRuntimeCommands(fakeBin: string): { fakeBin: string; dockerLog: string; markerLog: string } {
  fs.mkdirSync(fakeBin, { recursive: true });
  const dockerLog = path.join(tmp, "docker.jsonl");
  const markerLog = path.join(tmp, "markers.jsonl");

  writeExecutable(path.join(fakeBin, "docker"), `#!/usr/bin/env node
const fs = require("node:fs");
const crypto = require("node:crypto");
const args = process.argv.slice(2);
const logPath = process.env.FAKE_DOCKER_LOG;
if (logPath) fs.appendFileSync(logPath, JSON.stringify({
  args,
  env: {
    RUNFREE_AGENT_ENV_FILE: process.env.RUNFREE_AGENT_ENV_FILE,
    RUNFREE_EFFECTIVE_PROXY_DIR: process.env.RUNFREE_EFFECTIVE_PROXY_DIR,
    RUNFREE_CLAUDE_DIR: process.env.RUNFREE_CLAUDE_DIR,
    RUNFREE_CLAUDE_JSON: process.env.RUNFREE_CLAUDE_JSON,
    RUNFREE_CODEX_HOME: process.env.RUNFREE_CODEX_HOME,
    RUNFREE_GIT_CONFIG: process.env.RUNFREE_GIT_CONFIG,
    RUNFREE_PROJECT_RUNFREE_DIR: process.env.RUNFREE_PROJECT_RUNFREE_DIR,
    RUNFREE_INBOX_DIR: process.env.RUNFREE_INBOX_DIR,
    RUNFREE_INBOX_CONTAINER_DIR: process.env.RUNFREE_INBOX_CONTAINER_DIR,
    RUNFREE_GIT_LAYOUT_KIND: process.env.RUNFREE_GIT_LAYOUT_KIND,
    RUNFREE_GIT_COMMON_DIR: process.env.RUNFREE_GIT_COMMON_DIR,
    RUNFREE_AGENT_STATE_CLAUDE_CONFIG_DIR: process.env.RUNFREE_AGENT_STATE_CLAUDE_CONFIG_DIR,
    RUNFREE_AGENT_STATE_CLAUDE_CONFIG_JSON: process.env.RUNFREE_AGENT_STATE_CLAUDE_CONFIG_JSON,
    RUNFREE_AGENT_STATE_CODEX_HOME: process.env.RUNFREE_AGENT_STATE_CODEX_HOME,
    RUNFREE_AGENT_STATE_PI_AGENT_DIR: process.env.RUNFREE_AGENT_STATE_PI_AGENT_DIR,
    RUNFREE_MCP_OAUTH_CALLBACK_PORT: process.env.RUNFREE_MCP_OAUTH_CALLBACK_PORT,
    RUNFREE_MCP_OAUTH_CALLBACK_URL: process.env.RUNFREE_MCP_OAUTH_CALLBACK_URL,
    RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: process.env.RUNFREE_MCP_OPERATION_POLICY_HOST_PATH,
    RUNFREE_OAUTH_POLICY_HOST_PATH: process.env.RUNFREE_OAUTH_POLICY_HOST_PATH,
    RUNFREE_AGENT_IMAGE: process.env.RUNFREE_AGENT_IMAGE,
    RUNFREE_PROXY_IMAGE: process.env.RUNFREE_PROXY_IMAGE,
    RUNFREE_AGENT_BASE_IMAGE: process.env.RUNFREE_AGENT_BASE_IMAGE,
    RUNFREE_UV_IMAGE: process.env.RUNFREE_UV_IMAGE,
    RUNFREE_PROXY_BASE_IMAGE: process.env.RUNFREE_PROXY_BASE_IMAGE,
    RUNFREE_APT_SOURCE_UBUNTU_URL: process.env.RUNFREE_APT_SOURCE_UBUNTU_URL,
    RUNFREE_APT_SOURCE_UBUNTU_SECURITY_URL: process.env.RUNFREE_APT_SOURCE_UBUNTU_SECURITY_URL,
    RUNFREE_APT_SIGNED_BY: process.env.RUNFREE_APT_SIGNED_BY,
    RUNFREE_APT_PACKAGE_GIT: process.env.RUNFREE_APT_PACKAGE_GIT,
    RUNFREE_APT_PACKAGE_NODEJS: process.env.RUNFREE_APT_PACKAGE_NODEJS,
    RUNFREE_APT_PACKAGE_NPM: process.env.RUNFREE_APT_PACKAGE_NPM,
    RUNFREE_GH_VERSION: process.env.RUNFREE_GH_VERSION,
    RUNFREE_PNPM_VERSION: process.env.RUNFREE_PNPM_VERSION,
    RUNFREE_POLICY_DIR: process.env.RUNFREE_POLICY_DIR,
    RUNFREE_POLICY_FILE: process.env.RUNFREE_POLICY_FILE,
    RUNFREE_PROXY_CA_CERT_DIR: process.env.RUNFREE_PROXY_CA_CERT_DIR,
    RUNFREE_PROXY_CA_KEY_DIR: process.env.RUNFREE_PROXY_CA_KEY_DIR,
    RUNFREE_SUBNET: process.env.RUNFREE_SUBNET,
    RUNFREE_PROXY_IP: process.env.RUNFREE_PROXY_IP,
    RUNFREE_CONTAINER_IP: process.env.RUNFREE_CONTAINER_IP,
    RUNFREE_CALLBACK_RELAY_IP: process.env.RUNFREE_CALLBACK_RELAY_IP,
    RUNFREE_PROXY_EGRESS_SUBNET: process.env.RUNFREE_PROXY_EGRESS_SUBNET,
    RUNFREE_PROXY_EGRESS_GATEWAY: process.env.RUNFREE_PROXY_EGRESS_GATEWAY,
    RUNFREE_PROXY_EGRESS_IP: process.env.RUNFREE_PROXY_EGRESS_IP,
    RUNFREE_RUNTIME_DIGEST: process.env.RUNFREE_RUNTIME_DIGEST,
    RUNFREE_PROJECT_COMPAT_ROOT: process.env.RUNFREE_PROJECT_COMPAT_ROOT,
    RUNFREE_PROJECT_PHYSICAL_ROOT: process.env.RUNFREE_PROJECT_PHYSICAL_ROOT,
    RUNFREE_VERSION: process.env.RUNFREE_VERSION,
    DOCKER_CLI_HINTS: process.env.DOCKER_CLI_HINTS,
  },
}) + "\\n");
function out(value) { if (value !== undefined) process.stdout.write(String(value)); }
function projectName() { return process.env.FAKE_COMPOSE_PROJECT || "fake-project"; }
function agentIp() { return process.env.FAKE_AGENT_IP || "172.31.90.11"; }
function proxyIp() { return process.env.FAKE_PROXY_IP || "172.31.90.10"; }
function callbackIp() { return process.env.FAKE_CALLBACK_RELAY_IP || "172.31.90.12"; }
function proxyEgressIp() { return process.env.FAKE_PROXY_EGRESS_IP || "172.31.91.10"; }
const agentContainerId = ${JSON.stringify(FAKE_AGENT_CONTAINER_ID)};
const proxyContainerId = ${JSON.stringify(FAKE_PROXY_CONTAINER_ID)};
const agentInternalNetworkId = ${JSON.stringify(FAKE_AGENT_INTERNAL_NETWORK_ID)};
const proxyEgressNetworkId = ${JSON.stringify(FAKE_PROXY_EGRESS_NETWORK_ID)};
const callbackHostNetworkId = ${JSON.stringify(FAKE_CALLBACK_HOST_NETWORK_ID)};
function imageId(reference) {
  return "sha256:" + crypto.createHash("sha256").update(reference).digest("hex");
}
function builtImageTags() {
  if (!logPath || !fs.existsSync(logPath)) return [];
  const tags = [];
  for (const line of fs.readFileSync(logPath, "utf8").trim().split(/\\n+/)) {
    if (!line) continue;
    const entry = JSON.parse(line);
    if (!Array.isArray(entry.args) || entry.args[0] !== "build") continue;
    for (let index = 0; index < entry.args.length; index += 1) {
      if (entry.args[index] === "--tag" && entry.args[index + 1]) tags.push(entry.args[index + 1]);
    }
  }
  return tags;
}
const quiescedAgentId = "a".repeat(64);
const quiescedAgentPausedPath = logPath ? logPath + ".agent-paused" : undefined;
function mount(destination, mode = "rw") {
  if (mode === "tmpfs") return { Destination: destination, RW: true, Type: "tmpfs" };
  return { Destination: destination, Mode: mode, RW: mode === "rw", Type: "bind" };
}
const text = args.join(" ");
if (args[0] === "info") process.exit(0);
// The trust-bundle ephemeral helper reads the agent image's system roots.
if (args[0] === "run" && args.includes("io.runfree.helper-purpose=trust-bundle")) {
  out("-----BEGIN CERTIFICATE-----\\nfake-system-roots\\n-----END CERTIFICATE-----\\n");
  process.exit(0);
}
// L3: the batched deny probes exit 0 with one denied (nonzero) record per probe.
if (args[0] === "run" && args.includes("io.runfree.helper-purpose=deny-probe") && text.includes("RUNFREE_DENY_PROBE")) {
  const probes = (text.match(/runfree_pid_\\d+=\\$!/g) || []).length;
  const records = [];
  for (let index = 0; index < probes; index += 1) records.push("RUNFREE_DENY_PROBE " + index + " exit=1");
  out(records.join("\\n") + "\\n");
  process.exit(0);
}
// L2: the two batched dependency-prep helpers answer with indexed records.
if (args[0] === "run" && args.includes("io.runfree.helper-purpose=dependency-prep")) {
  const volumes = args.filter((arg) => arg === "-v").length;
  const records = [];
  for (let index = 0; index < volumes; index += 1) {
    records.push(args.includes("--cap-add")
      ? "RUNFREE_DEP_PREP " + index + " owner=1000:1000 fixed=0"
      : "RUNFREE_DEP_PREP " + index + " probe=ok");
  }
  out(records.join("\\n") + "\\n");
  process.exit(0);
}
if (args[0] === "image" && args[1] === "inspect" && args[2]) {
  const reference = args[2];
  const tags = builtImageTags();
  const tag = tags.find((candidate) => candidate === reference
    || "sha256:" + crypto.createHash("sha256").update(candidate).digest("hex") === reference);
  if (!tag) process.exit(1);
  const taggedDigest = /sha256-([a-f0-9]{64})$/.exec(tag)?.[1];
  const projectTagId = /^runfree\\/agent-project:([a-f0-9]+)-sha256-/.exec(tag)?.[1];
  const role = tag.startsWith("runfree/agent-project:")
    ? "agent-project"
    : tag.startsWith("runfree/agent-base:")
      ? "agent-base"
      : tag.startsWith("runfree/proxy-runtime:") ? "proxy-runtime" : "agent-runtime";
  out(JSON.stringify([{
    Architecture: process.arch === "arm64" ? "arm64" : "amd64",
    Id: "sha256:" + crypto.createHash("sha256").update(tag).digest("hex"),
    Os: "linux",
    Config: { Labels: {
      "io.runfree.managed": "true",
      "io.runfree.digest-schema": "1",
      "io.runfree.image-input-digest": taggedDigest ? "sha256:" + taggedDigest : "",
      "io.runfree.image-role": role,
      ...(projectTagId ? { "io.runfree.project-id": projectTagId } : {})
    } }
  }]));
  process.exit(0);
}
if (args[0] === "network" && args[1] === "ls") process.exit(0);
if (args[0] === "network" && args[1] === "inspect") {
  const project = projectName();
  const networks = [];
  if (args.includes(project + "_agent_internal")) {
    networks.push({
      Id: agentInternalNetworkId,
      Name: project + "_agent_internal",
      Internal: true,
      EnableIPv6: false,
      Options: { "com.docker.network.bridge.inhibit_ipv4": "true" },
      IPAM: { Config: [{ Subnet: process.env.FAKE_RUNTIME_SUBNET || "172.31.90.0/24" }] },
      Containers: {
        [proxyContainerId]: { Name: project + "-proxy-1" },
        ...(process.env.FAKE_PREEXISTING_AGENT_ID ? { [agentContainerId]: { Name: project + "-agent-1" } } : {}),
        ...(process.env.FAKE_MCP_CALLBACK_SIDECAR_ID ? { [process.env.FAKE_MCP_CALLBACK_SIDECAR_ID]: { Name: project + "-mcp_callback-1" } } : {})
      }
    });
  }
  if (args.includes(project + "_proxy_egress")) {
    networks.push({
      Id: proxyEgressNetworkId,
      Name: project + "_proxy_egress",
      Internal: false,
      EnableIPv6: false,
      IPAM: { Config: [{ Subnet: process.env.FAKE_PROXY_EGRESS_SUBNET || "172.31.91.0/24", Gateway: process.env.FAKE_PROXY_EGRESS_GATEWAY || "172.31.91.1" }] },
      Containers: {
        [proxyContainerId]: { Name: project + "-proxy-1" }
      }
    });
  }
  if (args.includes(project + "_callback_host")) {
    networks.push({
      Id: callbackHostNetworkId,
      Name: project + "_callback_host",
      Internal: true,
      EnableIPv6: false,
      Containers: process.env.FAKE_MCP_CALLBACK_SIDECAR_ID
        ? { [process.env.FAKE_MCP_CALLBACK_SIDECAR_ID]: { Name: project + "-mcp_callback-1" } }
        : {}
    });
  }
  if (networks.length === 0) {
    const target = args.at(-1);
    process.stderr.write("Error response from daemon: network " + target + " not found\\n");
    process.exit(1);
  }
  out(JSON.stringify(networks));
  process.exit(0);
}
  if (args[0] === "rm") process.exit(0);
if (args[0] === "compose") {
  if (args.includes("up") && logPath) {
    fs.writeFileSync(logPath + ".components", JSON.stringify({
      agentImageInputDigest: process.env.RUNFREE_AGENT_IMAGE_INPUT_DIGEST,
      agentImage: process.env.RUNFREE_AGENT_IMAGE,
      proxyImageInputDigest: process.env.RUNFREE_PROXY_IMAGE_INPUT_DIGEST,
      proxyImage: process.env.RUNFREE_PROXY_IMAGE,
      topologyDigest: process.env.RUNFREE_TOPOLOGY_DIGEST,
      projectId: process.env.RUNFREE_PROJECT_ID,
      composeProject: process.env.RUNFREE_COMPOSE_PROJECT_NAME
    }));
  }
  process.exit(Number(process.env.FAKE_DOCKER_COMPOSE_STATUS ?? "0"));
}
if (args[0] === "ps") {
  // Per-session runtime: \`docker compose up\` creates no shared agent. Only a
  // leftover pre-flip agent (FAKE_PREEXISTING_AGENT_ID) is ever listed.
  if (text.includes("io.runfree.project-id=") && text.includes("com.docker.compose.service=agent")) {
    if (process.env.FAKE_PREEXISTING_AGENT_ID) out(quiescedAgentId + "\\n");
  }
  else if (text.includes("com.docker.compose.service=proxy")) out(proxyContainerId + "\\n");
  else if (text.includes("com.docker.compose.service=mcp_callback") && process.env.FAKE_MCP_CALLBACK_SIDECAR_ID) {
    const dockerLog = process.env.FAKE_DOCKER_LOG;
    const startedByCompose = dockerLog && fs.existsSync(dockerLog) && fs.readFileSync(dockerLog, "utf8").includes('"up"');
    if (startedByCompose || process.env.FAKE_PREEXISTING_MCP_CALLBACK_ID) out(process.env.FAKE_MCP_CALLBACK_SIDECAR_ID + "\\n");
  }
  else if (text.includes("com.docker.compose.service=agent")) {
    if (process.env.FAKE_PREEXISTING_AGENT_ID) out(agentContainerId + "\\n");
  }
  else if (text.includes("com.docker.compose.project=")) {
    const startedByCompose = logPath && fs.existsSync(logPath) && fs.readFileSync(logPath, "utf8").includes('"up"');
    const startedContainers = startedByCompose
      ? [proxyContainerId, ...(process.env.FAKE_PREEXISTING_AGENT_ID ? [agentContainerId] : []), ...(process.env.FAKE_MCP_CALLBACK_SIDECAR_ID ? [process.env.FAKE_MCP_CALLBACK_SIDECAR_ID] : [])].join("\\n") + "\\n"
      : "";
    out(process.env.FAKE_COMPOSE_CONTAINERS ?? startedContainers);
  }
  process.exit(0);
}
if (args[0] === "pause" && args.includes(quiescedAgentId)) {
  if (quiescedAgentPausedPath) fs.writeFileSync(quiescedAgentPausedPath, "1");
  process.exit(0);
}
if (args[0] === "unpause" && args.includes(quiescedAgentId)) {
  if (quiescedAgentPausedPath) fs.rmSync(quiescedAgentPausedPath, { force: true });
  process.exit(0);
}
if (args[0] === "container" && args[1] === "inspect") {
  const project = projectName();
  const composed = logPath && fs.existsSync(logPath + ".components")
    ? JSON.parse(fs.readFileSync(logPath + ".components", "utf8"))
    : {};
  const proxyImage = imageId(composed.proxyImage || process.env.RUNFREE_PROXY_IMAGE || "runfree/proxy-runtime:unknown");
  const requested = args.slice(2);
  const containers = [];
  if (requested.includes(proxyContainerId)) {
    containers.push({
      Id: proxyContainerId,
      Image: proxyImage,
      State: { Running: true, StartedAt: "2026-06-13T00:00:00.000Z" },
      NetworkSettings: { Networks: {
        [project + "_agent_internal"]: { NetworkID: agentInternalNetworkId },
        [project + "_proxy_egress"]: { NetworkID: proxyEgressNetworkId }
      } }
    });
  }
  if (process.env.FAKE_MCP_CALLBACK_SIDECAR_ID && requested.includes(process.env.FAKE_MCP_CALLBACK_SIDECAR_ID)) {
    containers.push({
      Id: process.env.FAKE_MCP_CALLBACK_SIDECAR_ID,
      Image: proxyImage,
      State: { Running: true, StartedAt: "2026-06-13T00:00:00.000Z" },
      NetworkSettings: { Networks: {
        [project + "_agent_internal"]: { NetworkID: agentInternalNetworkId },
        [project + "_callback_host"]: { NetworkID: callbackHostNetworkId }
      } }
    });
  }
  out(JSON.stringify(containers));
  process.exit(0);
}
if (args[0] === "inspect") {
  if (args.length === 2 && args[1] === quiescedAgentId) {
    out(JSON.stringify([{
      Id: quiescedAgentId,
      Config: { Labels: {
        "io.runfree.project-id": process.env.RUNFREE_PROJECT_ID,
        "com.docker.compose.project": process.env.RUNFREE_COMPOSE_PROJECT_NAME,
        "com.docker.compose.service": "agent"
      } },
      State: { Running: true, Paused: Boolean(quiescedAgentPausedPath && fs.existsSync(quiescedAgentPausedPath)) }
    }]));
    process.exit(0);
  }
  if (args.includes(proxyContainerId) && !text.includes("--format")) {
    const project = projectName();
    // Post-cutover the security/topology probes inspect only the proxy (and an
    // optional pre-flip agent). Return exactly the requested containers.
    const securityEntries = [
      {
        Id: agentContainerId,
        Config: { User: "1000:1000", Env: [] },
        Mounts: [
          mount("/workspace", "rw"),
          mount("/runfree/inbox", "ro"),
          mount("/runfree/mcp/claude.json", "ro"),
          mount("/workspace/.codex", "ro"),
          mount("/etc/proxy-ca", "ro")
        ],
        HostConfig: { CapAdd: null, CapDrop: ["CAP_NET_ADMIN", "CAP_NET_RAW"], NetworkMode: project + "_agent_internal", PortBindings: {}, SecurityOpt: ["no-new-privileges:true"] },
        NetworkSettings: { Ports: {}, Networks: { [project + "_agent_internal"]: { IPAddress: agentIp() } } }
      },
      {
        Id: proxyContainerId,
        Mounts: [
          mount("/ca/private", "rw"),
          mount("/ca/public", "rw"),
          mount("/app/runfree-effective", "ro"),
          mount("/app/proxy/mcp-operation-policy.json", "ro")
        ],
        HostConfig: {
          CapAdd: ["NET_ADMIN"],
          CapDrop: ["NET_RAW"],
          NetworkMode: project + "_agent_internal",
          PortBindings: {},
          SecurityOpt: ["no-new-privileges:true"],
          Tmpfs: {
            "/run/runfree-proxy-secrets": "",
            "/run/runfree-proxy-audit": "",
            "/run/runfree-proxy-audit-spool": "",
            "/run/runfree-proxy-status": "",
            "/run/runfree-sessions": "",
            "/run/runfree-approvals/pending": "",
            "/run/runfree-approvals/decisions": ""
          }
        },
        NetworkSettings: {
          Ports: { "8080/tcp": null },
          Networks: {
            [project + "_agent_internal"]: { IPAddress: proxyIp() },
            [project + "_proxy_egress"]: { IPAddress: proxyEgressIp() }
          }
        }
      }
    ];
    out(JSON.stringify(securityEntries.filter((entry) => args.includes(entry.Id))));
    process.exit(0);
  }
  if (process.env.FAKE_MCP_CALLBACK_SIDECAR_ID && args.includes(process.env.FAKE_MCP_CALLBACK_SIDECAR_ID) && !text.includes("--format")) {
    const project = projectName();
    const port = process.env.RUNFREE_MCP_OAUTH_CALLBACK_PORT || "47123";
    out(JSON.stringify([{
      Id: process.env.FAKE_MCP_CALLBACK_SIDECAR_ID,
      Config: {
        Cmd: ["node", "/app/proxy/mcp-callback-relay.js"],
        Env: [
          "RUNFREE_CALLBACK_LISTEN_HOST=0.0.0.0",
          "RUNFREE_CALLBACK_LISTEN_PORT=" + port,
          "RUNFREE_CALLBACK_TARGET_HOST=" + agentIp(),
          "RUNFREE_CALLBACK_TARGET_PORT=" + port,
          "RUNFREE_CALLBACK_RELAY_IP=" + callbackIp()
        ],
        Labels: {
          "io.runfree.project-id": process.env.RUNFREE_PROJECT_ID,
          "io.runfree.utility-role": "mcp-callback-relay",
          "io.runfree.utility-version": "1"
        },
        User: "1001:1001"
      },
      HostConfig: {
        CapAdd: [],
        CapDrop: ["ALL"],
        NetworkMode: project + "_callback_host",
        PidsLimit: 64,
        PortBindings: { [port + "/tcp"]: [{ HostIp: "127.0.0.1", HostPort: port }] },
        Privileged: false,
        ReadonlyRootfs: true,
        SecurityOpt: ["no-new-privileges:true"]
      },
      Mounts: [],
      NetworkSettings: {
        Ports: { [port + "/tcp"]: [{ HostIp: "127.0.0.1", HostPort: port }] },
        Networks: {
          [project + "_callback_host"]: { IPAddress: "172.31.0.2" },
          [project + "_agent_internal"]: { IPAddress: callbackIp() }
        }
      },
      State: { Running: true, StartedAt: "2026-06-13T00:00:00.000Z" }
    }]));
    process.exit(0);
  }
  if (args.includes(agentContainerId) && !text.includes("--format")) {
    out(JSON.stringify([{ Id: agentContainerId, Config: { Env: [] }, Mounts: [
      mount("/workspace", "rw"),
      mount("/runfree/inbox", "ro"),
      mount("/runfree/mcp/claude.json", "ro"),
      mount("/workspace/.codex", "ro"),
      mount("/etc/proxy-ca", "ro")
    ] }]));
    process.exit(0);
  }
  if (text.includes("io.runfree.runtime-digest")) {
    const digest = process.env.FAKE_RUNTIME_DIGEST ?? "sha256:missing";
    let components = {};
    if (logPath && fs.existsSync(logPath + ".components")) {
      components = JSON.parse(fs.readFileSync(logPath + ".components", "utf8"));
    }
    const ids = args.slice(3);
    for (const id of ids) {
      const service = id === proxyContainerId
        ? "proxy"
        : id === process.env.FAKE_MCP_CALLBACK_SIDECAR_ID ? "mcp_callback" : "agent";
      const agentDigest = service === "agent" ? (components.agentImageInputDigest || process.env.RUNFREE_AGENT_IMAGE_INPUT_DIGEST || "<no value>") : "<no value>";
      const proxyDigest = service === "proxy" ? (components.proxyImageInputDigest || process.env.RUNFREE_PROXY_IMAGE_INPUT_DIGEST || "<no value>") : "<no value>";
      out([
        id,
        service,
        "1",
        agentDigest,
        proxyDigest,
        components.topologyDigest || process.env.RUNFREE_TOPOLOGY_DIGEST || "<no value>",
        digest,
        service === "agent"
          ? (components.agentImage || process.env.RUNFREE_AGENT_IMAGE || "<no value>")
          : (components.proxyImage || process.env.RUNFREE_PROXY_IMAGE || "<no value>"),
        "true",
        components.projectId || process.env.RUNFREE_PROJECT_ID || projectName().replace(/^runfree-/, ""),
        components.composeProject || process.env.RUNFREE_COMPOSE_PROJECT_NAME || projectName()
      ].join("\\t") + "\\n");
    }
    process.exit(0);
  }
  if (text.includes(".State.Running")) { out("true\\n"); process.exit(0); }
  if (text.includes("com.docker.compose.project")) { out(projectName() + "\\n"); process.exit(0); }
  if (text.includes("NetworkSettings.Networks")) {
    const expected = process.env.FAKE_EXPECTED_NETWORK ?? "fake-project_agent_net";
    const ids = args.slice(3);
    for (const id of ids) {
      out(id + "\\t" + (id === "stale-id" ? "wrong_default" : expected) + "\\n");
    }
    process.exit(0);
  }
  const id = args[args.length - 1];
  const expected = process.env.FAKE_EXPECTED_NETWORK ?? "fake-project_agent_net";
  out(id === "stale-id" ? "wrong_default\\n" : expected + "\\n");
  process.exit(0);
}
if (args[0] === "exec") {
  if (args.includes(proxyContainerId) && text.includes("existsSync")) {
    out(JSON.stringify([false]));
    process.exit(0);
  }
  if (args.includes(proxyContainerId) && text.includes("nft -j list set inet runfree_proxy session_ipv4")) {
    out(JSON.stringify({ nftables: [{ set: {
      family: "inet",
      table: "runfree_proxy",
      name: "session_ipv4",
      type: "ipv4_addr"
    } }] }));
    process.exit(0);
  }
  if (text.includes("/run/runfree-proxy-status/firewall.json")) {
    const effectiveRoot = process.env.RUNFREE_EFFECTIVE_PROXY_DIR
      || (logPath ? require("node:path").join(require("node:path").dirname(logPath), "state", "control", "effective", "proxy") : undefined);
    if (effectiveRoot) {
      const active = JSON.parse(fs.readFileSync(effectiveRoot + "/active.json", "utf8"));
      const manifest = JSON.parse(fs.readFileSync(effectiveRoot + "/generations/" + active.controlGeneration.slice("sha256:".length) + "/manifest.json", "utf8"));
      const identity = {
        generation: manifest.policyGeneration,
        controlGeneration: active.controlGeneration,
        policyGeneration: manifest.policyGeneration,
        appliedAt: "2026-06-14T00:00:00.000Z"
      };
      out(JSON.stringify({ ...identity, rulesetVerified: true }) + (text.includes("/run/runfree-proxy-status/request-proxy/request-proxy.json") ? "\\n" + JSON.stringify(identity) + "\\n" : ""));
      process.exit(0);
    }
  }
  if (text.includes("runfree_security_contract_probe")) {
    const fs = require("node:fs");
    const crypto = require("node:crypto");
    const mcpDigest = crypto.createHash("sha256")
      .update(fs.readFileSync(process.env.FAKE_CLAUDE_MCP_CONFIG_HOST_PATH))
      .digest("hex");
    if (args.includes(agentContainerId)) {
      out([
        "mount\\t/workspace\\t0\\t/workspace\\text4\\trw,relatime",
        "mount\\t/runfree/inbox\\t0\\t/runfree/inbox\\text4\\tro,relatime",
        "mount\\t/runfree/mcp/claude.json\\t0\\t/runfree/mcp/claude.json\\text4\\tro,relatime",
        "mount\\t/workspace/.codex\\t0\\t/workspace/.codex\\text4\\tro,relatime",
        "mount\\t/etc/proxy-ca\\t0\\t/etc/proxy-ca\\text4\\tro,relatime",
        "content\\t/runfree/mcp/claude.json\\t0\\t" + mcpDigest,
        "directory\\t/workspace/.codex\\t0\\t1",
        "absence\\t/ca/private/proxy-ca.key\\t0"
      ].join("\\n") + "\\n");
      process.exit(0);
    }
    if (args.includes(proxyContainerId)) {
      out([
        "mount\\t/ca/private\\t0\\t/ca/private\\text4\\trw,relatime",
        "mount\\t/ca/public\\t0\\t/ca/public\\text4\\trw,relatime",
        "mount\\t/app/runfree-effective\\t0\\t/app/runfree-effective\\text4\\tro,relatime",
        "mount\\t/app/proxy/mcp-operation-policy.json\\t0\\t/app/proxy/mcp-operation-policy.json\\text4\\tro,relatime",
        "mount\\t/run/runfree-proxy-secrets\\t0\\t/run/runfree-proxy-secrets\\ttmpfs\\trw,nosuid,nodev,noexec,relatime",
        "mount\\t/run/runfree-proxy-audit\\t0\\t/run/runfree-proxy-audit\\ttmpfs\\trw,nosuid,nodev,noexec,relatime",
        "mount\\t/run/runfree-proxy-audit-spool\\t0\\t/run/runfree-proxy-audit-spool\\ttmpfs\\trw,nosuid,nodev,noexec,relatime",
        "mount\\t/run/runfree-proxy-status\\t0\\t/run/runfree-proxy-status\\ttmpfs\\trw,nosuid,nodev,noexec,relatime",
        "mount\\t/run/runfree-sessions\\t0\\t/run/runfree-sessions\\ttmpfs\\trw,nosuid,nodev,noexec,relatime",
        "mount\\t/run/runfree-approvals/pending\\t0\\t/run/runfree-approvals/pending\\ttmpfs\\trw,nosuid,nodev,noexec,relatime",
        "mount\\t/run/runfree-approvals/decisions\\t0\\t/run/runfree-approvals/decisions\\ttmpfs\\trw,nosuid,nodev,noexec,relatime",
        "stat\\t/run/runfree-proxy-secrets\\t0\\t1001:1001:700",
        "stat\\t/run/runfree-proxy-audit\\t0\\t0:0:755",
        "stat\\t/run/runfree-proxy-audit-spool\\t0\\t1001:1001:755",
        "stat\\t/run/runfree-proxy-status\\t0\\t0:0:755",
        "stat\\t/run/runfree-proxy-status/request-proxy\\t0\\t1001:1001:755",
        "stat\\t/run/runfree-sessions\\t0\\t0:0:755",
        "stat\\t/run/runfree-sessions/sessions\\t0\\t0:0:755",
        "stat\\t/run/runfree-approvals/pending\\t0\\t1001:1001:700",
        "stat\\t/run/runfree-approvals/decisions\\t0\\t0:0:755"
      ].join("\\n") + "\\n");
      process.exit(0);
    }
  }
  if (text.includes("rev-parse --path-format=absolute --git-dir")) {
    out("gitDir=" + process.env.FAKE_GIT_CONTAINER_DIR + "\\ncommonDir=" + process.env.FAKE_GIT_CONTAINER_COMMON_DIR + "\\ntopLevel=" + process.env.FAKE_GIT_CONTAINER_TOP_LEVEL + "\\n");
    process.exit(0);
  }
  if (text.includes("CapBnd")) {
    out(args.includes(proxyContainerId) ? "0000000000001000\\n" : "0000000000000000\\n");
    process.exit(0);
  }
  if (text.includes("/proc/1/status") && text.includes("NoNewPrivs")) {
    out("Uid:\\t1000\\t1000\\t1000\\t1000\\nGid:\\t1000\\t1000\\t1000\\t1000\\nNoNewPrivs:\\t1\\n");
    process.exit(0);
  }
  if (text.includes("/proc/self/status") && text.includes("NoNewPrivs")) {
    out("uid=1000 gid=1000\\nNoNewPrivs:\\t1\\n");
    process.exit(0);
  }
  // L5b: firewall probes arrive merged per exec identity group with
  // RUNFREE_FIREWALL_SECTION framing; answer each embedded command with the
  // same per-probe semantics the individual handlers below encode.
  if (text.includes("RUNFREE_FIREWALL_SECTION")) {
    const commands = [];
    const commandPattern = /runfree_out_(\\d+)=\\$\\(\\{ (.*?); \\} 2>&1\\); runfree_status_\\1=\\$\\?/g;
    let embeddedMatch;
    while ((embeddedMatch = commandPattern.exec(text)) !== null) commands.push(embeddedMatch[2]);
    const sections = [];
    for (let index = 0; index < commands.length; index += 1) {
      const embedded = commands[index];
      let exitCode = 1;
      let body = "unexpected batched firewall command";
      if (embedded.includes("ip -o route get 1.1.1.1")) {
        exitCode = 0;
        body = "1.1.1.1 via 172.31.91.1 dev eth1 src " + proxyEgressIp() + " uid 1001";
      } else if (embedded.includes("ip -o route get")) {
        exitCode = 0;
        body = agentIp() + " dev eth0 src " + proxyIp() + " uid 1001";
      } else if (embedded.includes("nft list set inet runfree_proxy allowed_ipv4")) {
        exitCode = 0;
        body = "table inet runfree_proxy {\\n  set allowed_ipv4 { type ipv4_addr; elements = { 140.82.112.5 } }\\n}";
      } else if (embedded.includes("@127.0.0.11 example.com")) {
        exitCode = 0;
        body = "";
      }
      sections.push("RUNFREE_FIREWALL_SECTION " + index + " exit=" + exitCode + "\\n" + body + "\\nRUNFREE_FIREWALL_SECTION_END " + index);
    }
    out(sections.join("\\n") + "\\n");
    process.exit(0);
  }
  // L5b: the five server-UID denial probes arrive as one batch that exits 0
  // with one denied (nonzero) record per probe.
  if (args.includes("1001:1001") && text.includes("RUNFREE_FIREWALL_PROBE")) {
    const records = [];
    for (let index = 0; index < 5; index += 1) records.push("RUNFREE_FIREWALL_PROBE " + index + " exit=1");
    out(records.join("\\n") + "\\n");
    process.exit(0);
  }
  if (text.includes("ip -o route get " + agentIp())) {
    out(agentIp() + " dev eth0 src " + proxyIp() + " uid 1001\\n");
    process.exit(0);
  }
  if (args.includes("1001:1001") && text.includes("nft list ruleset")) {
    process.stderr.write("Operation not permitted\\n");
    process.exit(1);
  }
  if (args.includes("1001:1001") && text.includes("nft list set inet runfree_proxy allowed_ipv4")) {
    process.stderr.write("Operation not permitted\\n");
    process.exit(1);
  }
  if (args.includes("1001:1001") && text.includes("ip route add blackhole 203.0.113.254/32")) {
    process.stderr.write("Operation not permitted\\n");
    process.exit(1);
  }
  if (text.includes("ip -4 route show default")) process.exit(1);
  if (text.includes("nft -j list table inet runfree_proxy")) {
    const table = ${JSON.stringify(proxyNftablesTableFixture())};
    out(JSON.stringify(table));
    process.exit(0);
  }
  if (text.includes("nft list ruleset")) {
    process.stderr.write("unexpected root nft ruleset inspection\\n");
    process.exit(1);
  }
  if (text.includes("nft list set inet runfree_proxy allowed_ipv4")) {
    out("table inet runfree_proxy {\\n  set allowed_ipv4 { type ipv4_addr; elements = { 140.82.112.5 } }\\n}\\n");
    process.exit(0);
  }
  if (text.includes("/dev/tcp/" + proxyIp() + "/8080")) process.exit(0);
  if (text.includes("/dev/tcp/1.1.1.1/443")) process.exit(1);
  if (text.includes("@1.1.1.1 example.com")) process.exit(1);
  if (text.includes("@127.0.0.11 example.com")) process.exit(args.includes("0:0") ? 0 : 1);
  if (text.includes("host.docker.internal")) process.exit(1);
  if (text.includes("CONNECT disallowed.example:443")) { out("HTTP/1.1 200 Connection Established\\r\\n\\r\\n"); process.exit(0); }
  if (text.includes("https://disallowed.example/")) { out("HTTP/1.1 403 Forbidden\\r\\nx-runfree-blocked: host-not-allowlisted\\r\\n\\r\\n"); process.exit(0); }
  if (text.includes("CONNECT deny-all.runfree.invalid:22")) { out("HTTP/1.1 403 Forbidden\\r\\ncontent-type: text/plain\\r\\nconnection: close\\r\\n\\r\\nblocked by agent proxy policy\\nreason: blocked unregistered session peer (no admitted session holds this address)\\nhost: deny-all.runfree.invalid\\n"); process.exit(0); }
  const command = args[args.length - 1] ?? "";
  if (command.includes("/run/runfree-proxy-verbose")) {
    if (args[1] !== "--user" || args[2] !== "0:0") {
      process.stderr.write("permission denied\\n");
      process.exit(1);
    }
    if (command.startsWith("mkdir -p")) {
      fs.appendFileSync(process.env.FAKE_MARKER_LOG, JSON.stringify({ action: "set" }) + "\\n");
      process.exit(0);
    }
    if (command.startsWith("rm -f")) {
      fs.appendFileSync(process.env.FAKE_MARKER_LOG, JSON.stringify({ action: "clear" }) + "\\n");
      process.exit(0);
    }
  }
  process.exit(0);
}
process.exit(0);
`);

  writeExecutable(path.join(fakeBin, "git"), `#!/usr/bin/env node
const args = process.argv.slice(2);
const key = args[args.length - 1];
if (args[0] === "worktree" && key === "-h") {
  process.stdout.write("--relative-paths\\n");
  process.exit(129);
}
if (args[0] === "-C" && args[2] === "config" && args[3] === "--get") {
  if (key === "user.name" && process.env.FAKE_GIT_USER_NAME) {
    process.stdout.write(process.env.FAKE_GIT_USER_NAME + "\\n");
    process.exit(0);
  }
  if (key === "user.email" && process.env.FAKE_GIT_USER_EMAIL) {
    process.stdout.write(process.env.FAKE_GIT_USER_EMAIL + "\\n");
    process.exit(0);
  }
}
if (args[0] === "-C" && args[2] === "config" && args[3] === "--local" && args[4] === "--get") {
  if (key === "user.name" && process.env.FAKE_GIT_LOCAL_USER_NAME) {
    process.stdout.write(process.env.FAKE_GIT_LOCAL_USER_NAME + "\\n");
    process.exit(0);
  }
  if (key === "user.email" && process.env.FAKE_GIT_LOCAL_USER_EMAIL) {
    process.stdout.write(process.env.FAKE_GIT_LOCAL_USER_EMAIL + "\\n");
    process.exit(0);
  }
}
process.exit(1);
`);

  return { fakeBin, dockerLog, markerLog };
}

function approveAndPublishEffectiveControlsForTest(projectRoot: string, project: ProjectInfo): void {
  if (project.config.version >= 4) {
    const candidate = captureDesiredPolicyCandidate(projectRoot, project.paths.controlCandidatesDir);
    approveNetworkCandidate(projectRoot, project, candidate, "network-project", "interactive");
    approveNetworkCandidate(projectRoot, project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(projectRoot, project, "interactive");
    publishEffectivePolicyGeneration(projectRoot, project);
  }
}

function prepareProject(projectRoot: string, config: RunfreeConfig = defaultConfig()): ProjectInfo {
  const project = projectInfo(projectRoot, config);
  fs.mkdirSync(path.dirname(project.paths.policyPath), { recursive: true });
  fs.writeFileSync(project.paths.policyPath, `${JSON.stringify({ version: 2, hosts: ["api.github.com"] }, null, 2)}\n`);
  // The proxy publishes its CA into this host directory at first boot; the
  // fixture seeds it so the host-side CA bundle render has its input, the
  // same way the fake trust-setup exec already stood in for the wait.
  fs.mkdirSync(project.paths.proxyCaCertDir, { recursive: true });
  fs.writeFileSync(path.join(project.paths.proxyCaCertDir, "proxy-ca.crt"), FAKE_PROXY_CA_PEM);
  approveAndPublishEffectiveControlsForTest(projectRoot, project);
  return project;
}

function prepareRelativeLinkedWorktree(projectRoot: string): { gitCommonDir: string; gitDir: string } {
  const repoRoot = path.dirname(path.dirname(projectRoot));
  const gitCommonDir = path.join(repoRoot, ".git");
  const gitDir = path.join(gitCommonDir, "worktrees", path.basename(projectRoot));
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.mkdirSync(path.join(gitCommonDir, "objects", "info"), { recursive: true });
  fs.mkdirSync(gitDir, { recursive: true });
  fs.writeFileSync(path.join(projectRoot, ".git"), `gitdir: ../../.git/worktrees/${path.basename(projectRoot)}\n`);
  fs.writeFileSync(path.join(gitDir, "commondir"), "../..\n");
  fs.writeFileSync(path.join(gitDir, "gitdir"), `../../../.worktrees/${path.basename(projectRoot)}/.git\n`);
  fs.writeFileSync(path.join(gitCommonDir, "config"), [
    "[extensions]",
    "\trelativeWorktrees = true",
    "[worktree]",
    "\tuseRelativePaths = true",
    "",
  ].join("\n"));
  return { gitCommonDir, gitDir };
}

function persistRuntimeNetwork(project: ProjectInfo, network: RuntimeNetwork): void {
  fs.mkdirSync(project.paths.stateDir, { recursive: true });
  fs.writeFileSync(path.join(project.paths.stateDir, "runtime-network.json"), `${JSON.stringify(network, null, 2)}\n`);
}

function writeRuntimeInputLock(runtimeRoot: string): void {
  fs.mkdirSync(path.join(runtimeRoot, "agent", "agent-tools"), { recursive: true });
  fs.mkdirSync(path.join(runtimeRoot, "proxy"), { recursive: true });
  fs.writeFileSync(path.join(runtimeRoot, "agent", "agent-tools", "package-lock.json"), `${JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": {
        dependencies: {
          pnpm: "10.28.0",
        },
      },
      "node_modules/pnpm": {
        version: "10.28.0",
        resolved: "https://registry.npmjs.org/pnpm/-/pnpm-10.28.0.tgz",
        integrity: "sha512-test",
      },
    },
  }, null, 2)}\n`);
  fs.writeFileSync(path.join(runtimeRoot, "proxy", "package-lock.json"), "{\"lockfileVersion\":3}\n");
  fs.writeFileSync(path.join(runtimeRoot, "runtime-inputs.lock.json"), `${JSON.stringify({
    schemaVersion: 1,
    images: {
      agentBase: { ref: "ubuntu:26.04@sha256:f3d28607ddd78734bb7f71f117f3c6706c666b8b76cbff7c9ff6e5718d46ff64" },
      uv: { ref: "ghcr.io/astral-sh/uv:0.5.27@sha256:5adf09a5a526f380237408032a9308000d14d5947eafa687ad6c6a2476787b4f" },
      proxyBase: { ref: "ubuntu:26.04@sha256:f3d28607ddd78734bb7f71f117f3c6706c666b8b76cbff7c9ff6e5718d46ff64" },
    },
    apt: {
      family: "ubuntu",
      sources: {
        ubuntu: {
          url: "http://archive.ubuntu.com/ubuntu",
          suites: ["resolute", "resolute-updates"],
          components: ["main", "universe"],
          signedBy: "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
        },
        ubuntuSecurity: {
          url: "http://security.ubuntu.com/ubuntu",
          suites: ["resolute-security"],
          components: ["main", "universe"],
          signedBy: "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
        },
      },
      packages: {
        "ca-certificates": "20260223",
        curl: "8.18.0-1ubuntu2.5",
        sudo: "1.9.17p2-1ubuntu3",
        git: "1:2.53.0-1ubuntu1",
        jq: "1.8.1-4ubuntu2",
        ripgrep: "15.1.0-1ubuntu1",
        zsh: "5.9-8ubuntu3",
        iproute2: "6.19.0-1ubuntu1",
        "netcat-openbsd": "1.234-1",
        "bind9-dnsutils": "1:9.20.24-1ubuntu0.3",
        "dumb-init": "1.2.5-3build1",
        nftables: "1.1.6-1",
        bash: "5.3-2ubuntu1",
        "util-linux": "2.41.3-3ubuntu2",
        nodejs: "22.22.1+dfsg+~cs22.19.15-1ubuntu1",
        npm: "9.2.0~ds3-1",
      },
    },
    releaseArtifacts: {
      githubCli: {
        version: "2.83.1",
        linuxAmd64Deb: {
          url: "https://github.com/cli/cli/releases/download/v2.83.1/gh_2.83.1_linux_amd64.deb",
          sha256: "835afbb0404889c5595929117eccb2681547c387f6a711b50b08288436de7b22",
        },
        linuxArm64Deb: {
          url: "https://github.com/cli/cli/releases/download/v2.83.1/gh_2.83.1_linux_arm64.deb",
          sha256: "cc21469d749a88fdd53f9242dc3005bd4f8fe4dcd2a2d2a9adf1681c97827ef8",
        },
      },
    },
    npm: {
      agentToolsPackageLock: "agent/agent-tools/package-lock.json",
      proxyPackageLock: "proxy/package-lock.json",
      pnpmVersion: "10.28.0",
    },
  }, null, 2)}\n`);
}

function writeRuntimeAssets(runtimeRoot: string): void {
  fs.mkdirSync(path.join(runtimeRoot, "agent"), { recursive: true });
  fs.mkdirSync(path.join(runtimeRoot, "proxy"), { recursive: true });
  writeRuntimeInputLock(runtimeRoot);
  fs.writeFileSync(path.join(runtimeRoot, "agent", "Dockerfile"), "FROM ubuntu:24.04\n");
  fs.copyFileSync(
    path.resolve("packages/agent-runtime/agent/inspect-active-sessions.sh"),
    path.join(runtimeRoot, "agent", "inspect-active-sessions.sh"),
  );
  fs.copyFileSync(
    path.resolve("packages/agent-runtime/agent/compose.yaml"),
    path.join(runtimeRoot, "agent", "compose.yaml"),
  );
  fs.writeFileSync(path.join(runtimeRoot, "proxy", "Dockerfile"), "FROM node:22-alpine\n");
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-runtime-tests-")));
  previousPath = process.env.PATH;
  writeRuntimeAssets(path.join(tmp, "runtime"));
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  flushWarnings();
  vi.restoreAllMocks();
  if (previousPath === undefined) {
    delete process.env.PATH;
  } else {
    process.env.PATH = previousPath;
  }
  delete process.env.FAKE_COMPOSE_CONTAINERS;
  delete process.env.FAKE_DOCKER_COMPOSE_STATUS;
  delete process.env.FAKE_DOCKER_LOG;
  delete process.env.FAKE_EXPECTED_NETWORK;
  delete process.env.FAKE_MARKER_LOG;
  delete process.env.FAKE_MCP_CALLBACK_PORT;
  delete process.env.FAKE_MCP_CALLBACK_SIDECAR_ID;
  delete process.env.FAKE_PREEXISTING_MCP_CALLBACK_ID;
  delete process.env.FAKE_PREEXISTING_AGENT_ID;
  delete process.env.FAKE_RUNTIME_DIGEST;
  delete process.env.RUNFREE_TEST_SESSION_RANDOM;
  fs.rmSync(tmp, { recursive: true, force: true });
});

function useFakeRuntime(logs: { fakeBin: string; dockerLog: string; markerLog: string }, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    ...process.env,
    // Isolate the host home so MCP import never reads the developer's real
    // ~/.claude.json / ~/.codex (hostHome() falls back to os.homedir() in
    // process). Without this, a host that configures MCP servers (e.g. a
    // posthog entry) leaks into the "isolated Claude state" assertions.
    HOME: path.join(tmp, "host-home"),
    CODEX_HOME: path.join(tmp, "host-home", ".codex"),
    PATH: `${logs.fakeBin}${path.delimiter}${previousPath ?? ""}`,
    RUNFREE_TEST_FAKE_DOCKER: "1",
    FAKE_DOCKER_LOG: logs.dockerLog,
    FAKE_MARKER_LOG: logs.markerLog,
    FAKE_RUNTIME_DIGEST: RUNFREE_RUNTIME_DIGEST,
    ...extra,
  };
}

const fixedNetwork: RuntimeNetwork = {
  subnet: "172.31.90.0/24",
  proxyIp: "172.31.90.10",
  agentIp: "172.31.90.11",
  callbackSidecarIp: "172.31.90.12",
  proxyEgressSubnet: "172.31.91.0/24",
  proxyEgressGateway: "172.31.91.1",
  proxyEgressIp: "172.31.91.10",
};

type RuntimeIoCall = {
  method: "admin" | "capture" | "choosePiProvider" | "commandExists" | "confirm" | "run";
  command?: string;
  args: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  input?: string;
};

function captureResult(status: number, stdout = "", stderr = ""): CaptureResult {
  return { status, stdout, stderr };
}

function inspectMount(destination: string, mode: "ro" | "rw" | "tmpfs" = "rw"): {
  Destination: string;
  Mode?: string;
  RW: boolean;
  Type: string;
} {
  if (mode === "tmpfs") return { Destination: destination, RW: true, Type: "tmpfs" };
  return {
    Destination: destination,
    Mode: mode,
    RW: mode === "rw",
    Type: "bind",
  };
}

function securityContractInspectPair(options: {
  containerProjectRoot?: string;
  inboxMode?: "ro" | "rw";
  projectName?: string;
  runfreeMode?: "ro" | "rw";
} = {}): [Record<string, unknown>, Record<string, unknown>] {
  const containerProjectRoot = options.containerProjectRoot ?? "/workspace";
  const projectName = options.projectName ?? "runfree-test";
  const agent = {
    Id: FAKE_AGENT_CONTAINER_ID,
    Config: { User: "1000:1000" },
    HostConfig: {
      CapAdd: null,
      CapDrop: ["CAP_NET_ADMIN", "CAP_NET_RAW"],
      NetworkMode: "agent_internal",
      PortBindings: {},
      SecurityOpt: ["no-new-privileges:true"],
    },
    Mounts: [
      inspectMount(containerProjectRoot, "rw"),
      ...(options.runfreeMode ? [inspectMount(`${containerProjectRoot}/.runfree`, options.runfreeMode)] : []),
      inspectMount("/runfree/mcp/claude.json", "ro"),
      inspectMount("/runfree/inbox", options.inboxMode ?? "ro"),
      inspectMount(`${containerProjectRoot}/.codex`, "ro"),
      inspectMount("/etc/proxy-ca", "ro"),
    ],
    NetworkSettings: { Ports: {}, Networks: { [`${projectName}_agent_internal`]: { IPAddress: fixedNetwork.agentIp } } },
  };
  const proxy = {
    Id: FAKE_PROXY_CONTAINER_ID,
    HostConfig: {
      CapAdd: ["NET_ADMIN"],
      CapDrop: ["NET_RAW"],
      NetworkMode: "agent_internal",
      PortBindings: {},
      SecurityOpt: ["no-new-privileges:true"],
      Tmpfs: {
        "/run/runfree-proxy-secrets": "",
        "/run/runfree-proxy-audit": "",
        "/run/runfree-proxy-audit-spool": "",
        "/run/runfree-proxy-status": "",
        "/run/runfree-sessions": "",
        "/run/runfree-approvals/pending": "",
        "/run/runfree-approvals/decisions": "",
      },
    },
    Mounts: [
      inspectMount("/ca/private", "rw"),
      inspectMount("/ca/public", "rw"),
      inspectMount("/app/runfree-effective", "ro"),
      inspectMount("/app/proxy/mcp-operation-policy.json", "ro"),
    ],
    NetworkSettings: {
      Ports: { "8080/tcp": null },
      Networks: {
        [`${projectName}_agent_internal`]: { IPAddress: fixedNetwork.proxyIp },
        [`${projectName}_proxy_egress`]: { IPAddress: fixedNetwork.proxyEgressIp },
      },
    },
  };
  return [agent, proxy];
}

function securityContractProbeOutput(container: "agent" | "proxy", containerProjectRoot = "/workspace"): string {
  if (container === "agent") {
    const claudeMcpConfigPath = path.join(tmp, "state", "mounts", "claude-mcp.json");
    const claudeMcpConfig = fs.existsSync(claudeMcpConfigPath)
      ? fs.readFileSync(claudeMcpConfigPath)
      : Buffer.from(`${JSON.stringify({ mcpServers: {} }, null, 2)}\n`);
    const claudeMcpDigest = crypto.createHash("sha256").update(claudeMcpConfig).digest("hex");
    return [
      `mount\t${containerProjectRoot}\t0\t${containerProjectRoot}\text4\trw,relatime`,
      "mount\t/runfree/mcp/claude.json\t0\t/runfree/mcp/claude.json\text4\tro,relatime",
      "mount\t/runfree/inbox\t0\t/runfree/inbox\text4\tro,relatime",
      `mount\t${containerProjectRoot}/.codex\t0\t${containerProjectRoot}/.codex\text4\tro,relatime`,
      "mount\t/etc/proxy-ca\t0\t/etc/proxy-ca\text4\tro,relatime",
      `content\t/runfree/mcp/claude.json\t0\t${claudeMcpDigest}`,
      `directory\t${containerProjectRoot}/.codex\t0\t1`,
      "absence\t/ca/private/proxy-ca.key\t0",
      "",
    ].join("\n");
  }
  return [
    "mount\t/ca/private\t0\t/ca/private\text4\trw,relatime",
    "mount\t/ca/public\t0\t/ca/public\text4\trw,relatime",
    "mount\t/app/runfree-effective\t0\t/app/runfree-effective\text4\tro,relatime",
    "mount\t/app/proxy/mcp-operation-policy.json\t0\t/app/proxy/mcp-operation-policy.json\text4\tro,relatime",
    "mount\t/run/runfree-proxy-secrets\t0\t/run/runfree-proxy-secrets\ttmpfs\trw,nosuid,nodev,noexec,relatime",
    "mount\t/run/runfree-proxy-audit\t0\t/run/runfree-proxy-audit\ttmpfs\trw,nosuid,nodev,noexec,relatime",
    "mount\t/run/runfree-proxy-audit-spool\t0\t/run/runfree-proxy-audit-spool\ttmpfs\trw,nosuid,nodev,noexec,relatime",
    "mount\t/run/runfree-proxy-status\t0\t/run/runfree-proxy-status\ttmpfs\trw,nosuid,nodev,noexec,relatime",
    "mount\t/run/runfree-sessions\t0\t/run/runfree-sessions\ttmpfs\trw,nosuid,nodev,noexec,relatime",
    "mount\t/run/runfree-approvals/pending\t0\t/run/runfree-approvals/pending\ttmpfs\trw,nosuid,nodev,noexec,relatime",
    "mount\t/run/runfree-approvals/decisions\t0\t/run/runfree-approvals/decisions\ttmpfs\trw,nosuid,nodev,noexec,relatime",
    "stat\t/run/runfree-proxy-secrets\t0\t1001:1001:700",
    "stat\t/run/runfree-proxy-audit\t0\t0:0:755",
    "stat\t/run/runfree-proxy-audit-spool\t0\t1001:1001:755",
    "stat\t/run/runfree-proxy-status\t0\t0:0:755",
    "stat\t/run/runfree-proxy-status/request-proxy\t0\t1001:1001:755",
    "stat\t/run/runfree-sessions\t0\t0:0:755",
    "stat\t/run/runfree-sessions/sessions\t0\t0:0:755",
    "stat\t/run/runfree-approvals/pending\t0\t1001:1001:700",
    "stat\t/run/runfree-approvals/decisions\t0\t0:0:755",
    "",
  ].join("\n");
}

function gitIdentityCapture(values: {
  email?: string;
  name?: string;
}): (command: string, args: string[]) => CaptureResult | undefined {
  return (command, args) => {
    if (command !== "git" || args[0] !== "-C" || args[2] !== "config" || args[3] !== "--get") return undefined;
    if (args[4] === "user.name" && values.name) return captureResult(0, `${values.name}\n`);
    if (args[4] === "user.email" && values.email) return captureResult(0, `${values.email}\n`);
    return captureResult(1);
  };
}

// The production RuntimeIO.admin seam takes a typed RuntimeAdminIntent. The test
// harness records and asserts admin calls as compact string arrays (and the
// `overrides.admin` mocks are written against them), so the mock derives that
// form from the intent. This keeps the call-recording assertions a stable surface.
function applyAgentServiceIntentForTest(intent: Extract<RuntimeAdminIntent, { kind: "ensure-agent-service" }>, context: RuntimeContext): number {
  const svc = service(intent.id);
  if (!svc) return 1;
  const policyPath = context.project.paths.policyPath;
  const policy = JSON.parse(fs.readFileSync(policyPath, "utf8")) as {
    domains?: unknown;
    hosts: string[];
    requests?: Record<string, { writeAction?: "allow" | "ask" | "deny" }>;
    services?: Record<string, ReturnType<typeof desiredServiceEntry>>;
    tokens?: Record<string, unknown>;
    version?: number;
  };
  if (policy.domains !== undefined) return 1;
  if (context.project.config.version >= 4) {
    policy.services = {
      ...(policy.services ?? {}),
      [svc.id]: desiredServiceEntry(svc, { writeMode: svc.defaultWriteMode }),
    };
    fs.writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`);
    const candidate = captureDesiredPolicyCandidate(context.projectRoot, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(context.projectRoot, context.project, candidate, "network-project", "typed-host-command");
    return 0;
  }
  policy.hosts = Array.from(new Set([...policy.hosts, ...serviceHostNames(svc)])).sort();
  if (svc.defaultWriteMode) {
    policy.requests ??= {};
    const writeAction = svc.defaultWriteMode === "allow-write" ? "allow" : "deny";
    for (const host of serviceHostNames(svc)) {
      const rule = policy.requests[host] ?? {};
      if (rule.writeAction === undefined) rule.writeAction = writeAction;
      policy.requests[host] = rule;
    }
  }
  fs.writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`);
  return 0;
}

function runtimeIntentToArgs(intent: RuntimeAdminIntent): string[] {
  switch (intent.kind) {
    case "converge-proxy-policy":
      return ["converge-proxy-policy"];
    case "ensure-agent-service":
      return ["service", "ensure", intent.id, ...(intent.quiet ? ["--quiet"] : [])];
    case "token-sync":
      return intent.verbose ? ["token", "sync", "--verbose"] : ["token", "sync"];
    case "prepare-token-sources":
      return ["prepare-token-sources"];
    case "prepare":
      return ["prepare"];
  }
}

function dockerOperationProfile(calls: readonly RuntimeIoCall[]): Record<string, number> {
  const profile: Record<string, number> = {};
  for (const call of calls) {
    if ((call.method !== "capture" && call.method !== "run") || call.command !== "docker") continue;
    const category = subprocessCategory(call.command, call.args);
    profile[category] = (profile[category] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(profile).sort(([left], [right]) => left.localeCompare(right)));
}

function createRuntimeIO(overrides: {
  admin?: (args: string[], context: RuntimeContext) => Promise<number>;
  capture?: (command: string, args: string[]) => CaptureResult | undefined;
  choosePiProvider?: (options: readonly PiProviderOption[]) => PiProviderChoice | undefined;
  commandExists?: (command: string) => boolean;
  confirm?: (question: string) => boolean;
  isInteractive?: () => boolean;
  run?: (command: string, args: string[]) => number;
  startTokenAutoRefresh?: RuntimeIO["startTokenAutoRefresh"];
  takeTokenResolutionReceipts?: RuntimeIO["takeTokenResolutionReceipts"];
} = {}): RuntimeIO & { calls: RuntimeIoCall[] } {
  const calls: RuntimeIoCall[] = [];
  let observedProject = "runfree-test";
  let observedContainerProjectRoot = "/workspace";
  let observedComposeEnv: NodeJS.ProcessEnv = {};
  let composeStarted = false;
  const inspectedImagesById = new Map<string, Record<string, unknown>>();
  const builtImageReferences = new Set<string>();
  const quiescedAgentId = "a".repeat(64);
  let quiescedAgentPaused = false;
  // The runtime validation marker the code writes (via docker exec stdin) is
  // replayed verbatim on read, so its exact contract hash / component digests
  // match what the per-session launch recomputes. Falls back to the fixed
  // marker below when nothing has been written yet.
  let capturedValidationMarker: string | undefined;
  const rememberProject = (args: string[]): void => {
    const filter = args.find((arg) => arg.startsWith("label=com.docker.compose.project="));
    if (filter) observedProject = filter.slice("label=com.docker.compose.project=".length);
  };
  const defaultCapture = (command: string, args: string[], env?: NodeJS.ProcessEnv): CaptureResult => {
    if (command === "git" && args[0] === "worktree" && args.at(-1) === "-h") return captureResult(129, "--relative-paths");
    if (command !== "docker") return captureResult(0);
    rememberProject(args);
    // The trust-setup exec's contract is that it returns 0 only after the
    // proxy published its CA into the shared host directory (the script waits
    // for it in-container). The double mirrors that side effect, because the
    // CA bundle render that follows reads the file host-side.
    if (args[0] === "exec" && args.includes("0:0") && args.includes("sh") && args.includes("-s")) {
      const certDir = path.join(tmp, "state", "proxy-ca", "public");
      fs.mkdirSync(certDir, { recursive: true });
      fs.writeFileSync(path.join(certDir, "proxy-ca.crt"), FAKE_PROXY_CA_PEM);
      return captureResult(0);
    }
    // The trust-bundle helper runs the agent image to read its system roots.
    if (args[0] === "run" && args.includes("io.runfree.helper-purpose=trust-bundle")) {
      return captureResult(0, FAKE_SYSTEM_ROOTS_PEM);
    }
    if (args[0] === "run" && args.includes("io.runfree.helper-purpose=deny-probe")) {
      // Per-session agent-position confinement runs in an ephemeral helper. The
      // deny-by-default probe proves the unregistered-peer rejection; every
      // direct-egress probe is denied (non-zero) in that position.
      if (args.join(" ").includes("CONNECT deny-all.runfree.invalid:22")) {
        return captureResult(0, [
          "HTTP/1.1 403 Forbidden",
          "reason: blocked unregistered session peer (no admitted session holds this address)",
          "",
        ].join("\r\n"));
      }
      // L3: the direct-egress probes arrive as ONE batch whose contract is
      // exit 0 with one indexed record per probe; a denied probe is a nonzero
      // per-record exit, never a nonzero batch exit.
      if (args.join(" ").includes("RUNFREE_DENY_PROBE")) {
        const probes = [...args.join(" ").matchAll(/runfree_pid_(\d+)=\$!/g)].length;
        return captureResult(0, `${Array.from({ length: probes }, (_, index) => `RUNFREE_DENY_PROBE ${index} exit=1`).join("\n")}\n`);
      }
      return captureResult(1, "", "denied");
    }
    // L2: dependency-volume prep arrives as two batched helper runs mounting
    // every volume; answer each with its strict indexed records.
    if (args[0] === "run" && args.includes("io.runfree.helper-purpose=dependency-prep")) {
      const volumes = args.filter((arg) => arg === "-v").length;
      const record = args.includes("--cap-add")
        ? (index: number) => `RUNFREE_DEP_PREP ${index} owner=1000:1000 fixed=0`
        : (index: number) => `RUNFREE_DEP_PREP ${index} probe=ok`;
      return captureResult(0, `${Array.from({ length: volumes }, (_, index) => record(index)).join("\n")}\n`);
    }
    // Startup creates the Compose-managed session named volumes the removed
    // shared `agent` service used to make `compose up` create, then re-inspects
    // each one; the per-session launch proof inspects the whole expected set in
    // one call. A blank success is not a neutral answer to either inspection —
    // it is malformed JSON — so answer with the shape Docker reports for a
    // plain, Compose-labelled local volume named `<project>_<logical>`.
    if (args[0] === "volume" && args[1] === "create") return captureResult(0);
    if (args[0] === "volume" && args[1] === "inspect") {
      const names = args.slice(2).filter((arg) => !arg.startsWith("-"));
      return captureResult(0, `${JSON.stringify(names.map((name) => {
        const separator = name.indexOf("_");
        return {
          Name: name,
          Driver: "local",
          Scope: "local",
          Mountpoint: `/var/lib/docker/volumes/${name}/_data`,
          Labels: {
            "com.docker.compose.project": name.slice(0, separator),
            "com.docker.compose.volume": name.slice(separator + 1),
          },
          Options: {},
        };
      }), null, 2)}\n`);
    }
    const runningOnly = args.includes("-q") && !args.includes("-a") && !args.includes("-aq");
    const callbackSidecarId = process.env.FAKE_MCP_CALLBACK_SIDECAR_ID;
    const projectId = observedProject.replace(/^runfree-/, "");
    const derivedCallbackPort = /^[0-9a-f]{6}/.test(projectId)
      ? String(47100 + (Number.parseInt(projectId.slice(0, 6), 16) % 1000))
      : "47123";
    const callbackPort = process.env.FAKE_MCP_CALLBACK_PORT ?? derivedCallbackPort;
    const effectiveManifest = readEffectiveRuntimeGeneration(path.join(tmp, "state"));
    const desiredManifest = (() => {
      const root = path.join(tmp, "state", "runtime", "materializations");
      if (!fs.existsSync(root)) return undefined;
      for (const entry of fs.readdirSync(root).sort().reverse()) {
        const manifestPath = path.join(root, entry, "generation.json");
        if (!fs.existsSync(manifestPath)) continue;
        const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
          composeProject?: string;
          components?: RuntimeComponentState;
          images?: { agent?: string; proxy?: string };
        };
        if (manifest.composeProject === observedProject && manifest.components) return manifest;
      }
      return undefined;
    })();
    const selectedManifest = effectiveManifest ?? desiredManifest;
    const selectedComponents = selectedManifest?.components;
    const componentEnv = {
      RUNFREE_AGENT_IMAGE_INPUT_DIGEST: observedComposeEnv.RUNFREE_AGENT_IMAGE_INPUT_DIGEST
        ?? selectedComponents?.selectedAgentImageInputDigest,
      RUNFREE_PROXY_IMAGE_INPUT_DIGEST: observedComposeEnv.RUNFREE_PROXY_IMAGE_INPUT_DIGEST
        ?? selectedComponents?.proxyImageInputDigest,
      RUNFREE_TOPOLOGY_DIGEST: observedComposeEnv.RUNFREE_TOPOLOGY_DIGEST ?? selectedComponents?.topologyDigest,
      RUNFREE_RUNTIME_GENERATION_DIGEST: observedComposeEnv.RUNFREE_RUNTIME_GENERATION_DIGEST
        ?? selectedComponents?.runtimeGenerationDigest,
    };
    if (args[0] === "ps"
      && args.includes("-q")
      && args.some((arg) => arg.startsWith(`label=${PROJECT_ID_LABEL}=`))
      && args.includes("label=com.docker.compose.service=agent")) {
      return captureResult(0, process.env.FAKE_PREEXISTING_AGENT_ID
        ? fakeListedContainerIds(args, [quiescedAgentId])
        : "");
    }
    if (args[0] === "inspect" && args.length === 2 && quiescedAgentId.startsWith(args[1])) {
      return captureResult(0, JSON.stringify([{
        Id: quiescedAgentId,
        Config: {
          Labels: {
            [PROJECT_ID_LABEL]: projectId,
            "com.docker.compose.project": observedProject,
            "com.docker.compose.service": "agent",
          },
        },
        State: { Running: true, Paused: quiescedAgentPaused },
      }]));
    }
    if ((args[0] === "pause" || args[0] === "unpause")
      && args.slice(1).some((id) => quiescedAgentId.startsWith(id))) {
      quiescedAgentPaused = args[0] === "pause";
      return captureResult(0);
    }
    if (args[0] === "ps"
      && args.includes("-aq")
      && args.some((arg) => arg.startsWith("label=com.docker.compose.project="))
      && !args.some((arg) => arg.includes("com.docker.compose.service="))
      && (composeStarted || Boolean(process.env.FAKE_PREEXISTING_AGENT_ID))) {
      // Not truncated: these ids are only ever handed back to `docker inspect`,
      // and production reads identity from the inspection's `.Id`. Modelling
      // truncation here would require every inspect branch below to resolve
      // prefixes without exposing any additional short-vs-exact defect.
      return captureResult(0, [
        ...(process.env.FAKE_PREEXISTING_AGENT_ID ? [FAKE_AGENT_CONTAINER_ID] : []),
        FAKE_PROXY_CONTAINER_ID,
        ...(callbackSidecarId ? [callbackSidecarId] : []),
      ].join("\n"));
    }
    if (args[0] === "inspect" && args.includes("--format") && args.some((arg) => arg.includes("io.runfree.runtime-digest"))) {
      const ids = args.slice(args.indexOf("--format") + 2);
      const hasComponentEvidence = Boolean(
        componentEnv.RUNFREE_AGENT_IMAGE_INPUT_DIGEST
          && componentEnv.RUNFREE_PROXY_IMAGE_INPUT_DIGEST
          && componentEnv.RUNFREE_TOPOLOGY_DIGEST,
      );
      return captureResult(0, ids.map((id) => {
        const service = id === FAKE_PROXY_CONTAINER_ID ? "proxy" : id === callbackSidecarId ? "mcp_callback" : "agent";
        return [
          id,
          service,
          hasComponentEvidence ? "1" : "<no value>",
          service === "agent" ? componentEnv.RUNFREE_AGENT_IMAGE_INPUT_DIGEST ?? "<no value>" : "<no value>",
          service !== "agent" ? componentEnv.RUNFREE_PROXY_IMAGE_INPUT_DIGEST ?? "<no value>" : "<no value>",
          componentEnv.RUNFREE_TOPOLOGY_DIGEST ?? "<no value>",
          env?.RUNFREE_RUNTIME_DIGEST ?? "<no value>",
          service === "agent"
            ? observedComposeEnv.RUNFREE_AGENT_IMAGE
              ?? selectedManifest?.images?.agent
              ?? (componentEnv.RUNFREE_AGENT_IMAGE_INPUT_DIGEST
                ? agentRuntimeImageTag(componentEnv.RUNFREE_AGENT_IMAGE_INPUT_DIGEST)
                : "<no value>")
            : observedComposeEnv.RUNFREE_PROXY_IMAGE
              ?? selectedManifest?.images?.proxy
              ?? (componentEnv.RUNFREE_PROXY_IMAGE_INPUT_DIGEST
                ? proxyRuntimeImageTag(componentEnv.RUNFREE_PROXY_IMAGE_INPUT_DIGEST)
                : "<no value>"),
          "true",
          projectId,
          observedProject,
        ].join("\t");
      }).join("\n"));
    }
    if (args[0] === "image" && args[1] === "inspect" && args[2]) {
      const tag = args[2];
      const exactImage = inspectedImagesById.get(tag);
      if (exactImage) return captureResult(0, JSON.stringify([exactImage]));
      const projectImage = tag.startsWith("runfree/agent-project:");
      const proxyImage = tag.startsWith("runfree/proxy-runtime:");
      const taggedDigest = /sha256-([a-f0-9]{64})$/.exec(tag)?.[1];
      const inputDigest = taggedDigest ? `sha256:${taggedDigest}` : "";
      const projectTagId = /^runfree\/agent-project:([a-f0-9]+)-sha256-/.exec(tag)?.[1];
      const inspectedImage = {
        Architecture: process.arch === "arm64" ? "arm64" : "amd64",
        Id: `sha256:${crypto.createHash("sha256").update(tag).digest("hex")}`,
        Os: "linux",
        Config: {
          Labels: {
            [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
            [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
            [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: inputDigest,
            [RUNFREE_IMAGE_ROLE_LABEL]: projectImage
              ? AGENT_PROJECT_IMAGE_ROLE
              : proxyImage ? PROXY_RUNTIME_IMAGE_ROLE : AGENT_RUNTIME_IMAGE_ROLE,
            ...(projectTagId ? { [PROJECT_ID_LABEL]: projectTagId } : {}),
          },
        },
      };
      inspectedImagesById.set(inspectedImage.Id, inspectedImage);
      return captureResult(0, JSON.stringify([inspectedImage]));
    }
    const callbackSidecarInspect = callbackSidecarId ? {
      Id: callbackSidecarId,
      Config: {
        Cmd: ["node", "/app/proxy/mcp-callback-relay.js"],
        Env: [
          "RUNFREE_CALLBACK_LISTEN_HOST=0.0.0.0",
          `RUNFREE_CALLBACK_LISTEN_PORT=${callbackPort}`,
          `RUNFREE_CALLBACK_TARGET_HOST=${fixedNetwork.agentIp}`,
          `RUNFREE_CALLBACK_TARGET_PORT=${callbackPort}`,
          `RUNFREE_CALLBACK_RELAY_IP=${fixedNetwork.callbackSidecarIp}`,
        ],
        Labels: {
          "io.runfree.project-id": projectId,
          "io.runfree.utility-role": "mcp-callback-relay",
          "io.runfree.utility-version": "1",
        },
        User: "1001:1001",
      },
      HostConfig: {
        CapAdd: [],
        CapDrop: ["ALL"],
        NetworkMode: `${observedProject}_callback_host`,
        PidsLimit: 64,
        PortBindings: { [`${callbackPort}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: callbackPort }] },
        Privileged: false,
        ReadonlyRootfs: true,
        SecurityOpt: ["no-new-privileges:true"],
      },
      Mounts: [],
      NetworkSettings: {
        Ports: { [`${callbackPort}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: callbackPort }] },
        Networks: {
          [`${observedProject}_callback_host`]: { IPAddress: "172.31.0.2" },
          [`${observedProject}_agent_internal`]: { IPAddress: fixedNetwork.callbackSidecarIp },
        },
      },
      State: { Running: true, StartedAt: "2026-06-13T00:00:00.000Z" },
    } : undefined;
    if (args[0] === "container" && args[1] === "inspect") {
      const proxyImageRef = observedComposeEnv.RUNFREE_PROXY_IMAGE
        ?? selectedManifest?.images?.proxy
        ?? proxyRuntimeImageTag(componentEnv.RUNFREE_PROXY_IMAGE_INPUT_DIGEST);
      const proxyImageId = sha256Digest(proxyImageRef);
      const requested = new Set(args.slice(2));
      return captureResult(0, JSON.stringify([
        ...(requested.has(FAKE_PROXY_CONTAINER_ID) ? [{
          Id: FAKE_PROXY_CONTAINER_ID,
          Image: proxyImageId,
          State: { Running: true, StartedAt: "2026-06-13T00:00:00.000Z" },
          NetworkSettings: { Networks: {
            [`${observedProject}_agent_internal`]: { NetworkID: FAKE_AGENT_INTERNAL_NETWORK_ID },
            [`${observedProject}_proxy_egress`]: { NetworkID: FAKE_PROXY_EGRESS_NETWORK_ID },
          } },
        }] : []),
        ...(callbackSidecarInspect && requested.has(callbackSidecarInspect.Id) ? [{
          Id: callbackSidecarInspect.Id,
          Image: proxyImageId,
          State: { Running: true, StartedAt: "2026-06-13T00:00:00.000Z" },
          NetworkSettings: { Networks: {
            [`${observedProject}_agent_internal`]: { NetworkID: FAKE_AGENT_INTERNAL_NETWORK_ID },
            [`${observedProject}_callback_host`]: { NetworkID: FAKE_CALLBACK_HOST_NETWORK_ID },
          } },
        }] : []),
      ]));
    }
    // These are the `serviceContainerId` lookups. Their results become the
    // runtime validation marker's agent/proxy identity, the deny-by-default
    // base observation, and the control-plane participant authority, all of
    // which compare against exact 64-hex inspect identities — so the double
    // truncates unless production asks for `--no-trunc`.
    if (args[0] === "ps" && args.some((arg) => arg.includes("com.docker.compose.service=agent"))) {
      // Per-session runtime: `docker compose up` no longer creates a shared
      // agent. Only a leftover pre-flip agent (FAKE_PREEXISTING_AGENT_ID) is
      // ever listed — which the marker-status check then flags as forbidden.
      if (!process.env.FAKE_PREEXISTING_AGENT_ID) return captureResult(0);
      return captureResult(0, fakeListedContainerIds(args, [FAKE_AGENT_CONTAINER_ID]));
    }
    if (args[0] === "ps" && args.some((arg) => arg.includes("com.docker.compose.service=proxy"))) {
      if (runningOnly && !process.env.FAKE_PREEXISTING_AGENT_ID && !composeStarted) return captureResult(0);
      return captureResult(0, fakeListedContainerIds(args, [FAKE_PROXY_CONTAINER_ID]));
    }
    if (args[0] === "ps" && args.some((arg) => arg.includes("com.docker.compose.service=mcp_callback"))) {
      if (!callbackSidecarId) return captureResult(0);
      if (runningOnly && !composeStarted && !process.env.FAKE_PREEXISTING_MCP_CALLBACK_ID) return captureResult(0);
      return captureResult(0, fakeListedContainerIds(args, [callbackSidecarId]));
    }
    if (args[0] === "inspect" && args.includes(FAKE_PROXY_CONTAINER_ID) && !args.includes("--format")) {
      const [agentInspect, proxyInspect] = securityContractInspectPair({
        containerProjectRoot: observedContainerProjectRoot,
        projectName: observedProject,
      });
      // Post-cutover the topology/security probes inspect only the proxy (and an
      // optional callback); pre-cutover they also inspect the shared agent.
      // Return exactly the requested containers so both shapes work.
      const entries = [
        {
          ...agentInspect,
          Id: FAKE_AGENT_CONTAINER_ID,
          Config: { User: "1000:1000" },
          HostConfig: {
            ...(agentInspect.HostConfig as Record<string, unknown>),
            CapAdd: null,
            CapDrop: ["CAP_NET_ADMIN", "CAP_NET_RAW"],
            NetworkMode: `${observedProject}_agent_internal`,
            PortBindings: {},
            SecurityOpt: ["no-new-privileges:true"],
          },
          NetworkSettings: { Ports: {}, Networks: { [`${observedProject}_agent_internal`]: { IPAddress: fixedNetwork.agentIp } } },
        },
        {
          ...proxyInspect,
          Id: FAKE_PROXY_CONTAINER_ID,
          HostConfig: {
            ...(proxyInspect.HostConfig as Record<string, unknown>),
            CapAdd: ["NET_ADMIN"],
            CapDrop: ["NET_RAW"],
            NetworkMode: `${observedProject}_agent_internal`,
            PortBindings: {},
            SecurityOpt: ["no-new-privileges:true"],
          },
          NetworkSettings: {
            Ports: { "8080/tcp": null },
            Networks: {
              [`${observedProject}_agent_internal`]: { IPAddress: fixedNetwork.proxyIp },
              [`${observedProject}_proxy_egress`]: { IPAddress: fixedNetwork.proxyEgressIp },
            },
          },
        },
        ...(callbackSidecarInspect ? [callbackSidecarInspect] : []),
      ];
      return captureResult(0, JSON.stringify(entries.filter((entry) => args.includes(entry.Id))));
    }
    if (callbackSidecarInspect && args[0] === "inspect" && args.includes(FAKE_AGENT_CONTAINER_ID) && args.includes(callbackSidecarInspect.Id)) {
      return captureResult(0, JSON.stringify([
        {
          Id: FAKE_AGENT_CONTAINER_ID,
          HostConfig: { PortBindings: {} },
          NetworkSettings: { Ports: {} },
        },
        callbackSidecarInspect,
      ]));
    }
    if (args[0] === "inspect" && args.includes(FAKE_AGENT_CONTAINER_ID)) {
      return captureResult(0, JSON.stringify([{
        Id: FAKE_AGENT_CONTAINER_ID,
        HostConfig: { PortBindings: {} },
        NetworkSettings: { Ports: {} },
      }]));
    }
    if (args[0] === "network" && args[1] === "inspect") {
      const networks: Array<Record<string, unknown>> = [];
      if (args.includes(`${observedProject}_agent_internal`)) networks.push({
        Id: FAKE_AGENT_INTERNAL_NETWORK_ID,
        Name: `${observedProject}_agent_internal`,
        Internal: true,
        EnableIPv6: false,
        Options: { "com.docker.network.bridge.inhibit_ipv4": "true" },
        IPAM: { Config: [{ Subnet: fixedNetwork.subnet }] },
        // Per-session runtime: only the proxy is a fixed participant on
        // agent_internal; session agents attach transiently at admission.
        Containers: {
          [FAKE_PROXY_CONTAINER_ID]: { Name: `${observedProject}-proxy-1` },
          ...(callbackSidecarInspect ? { [callbackSidecarInspect.Id]: { Name: `${observedProject}-mcp_callback-1` } } : {}),
        },
      });
      if (args.includes(`${observedProject}_proxy_egress`)) networks.push({
        Id: FAKE_PROXY_EGRESS_NETWORK_ID,
        Name: `${observedProject}_proxy_egress`,
        Internal: false,
        EnableIPv6: false,
        IPAM: { Config: [{ Subnet: fixedNetwork.proxyEgressSubnet, Gateway: fixedNetwork.proxyEgressGateway }] },
        Containers: {
          [FAKE_PROXY_CONTAINER_ID]: { Name: `${observedProject}-proxy-1` },
        },
      });
      if (args.includes(`${observedProject}_callback_host`)) networks.push({
        Id: FAKE_CALLBACK_HOST_NETWORK_ID,
        Name: `${observedProject}_callback_host`,
        Internal: true,
        EnableIPv6: false,
        Containers: callbackSidecarInspect ? {
          [callbackSidecarInspect.Id]: { Name: `${observedProject}-mcp_callback-1` },
        } : {},
      });
      return networks.length > 0
        ? captureResult(0, JSON.stringify(networks))
        : captureResult(1, "", `Error response from daemon: network ${args.at(-1)} not found`);
    }
    const text = args.join(" ");
    if (args[0] === "exec"
      && args.includes(FAKE_PROXY_CONTAINER_ID)
      && args.includes(SESSION_ELIGIBILITY_PATH)
      && text.includes("existsSync")) {
      return captureResult(0, JSON.stringify([false]));
    }
    if (args[0] === "exec"
      && args.includes(FAKE_PROXY_CONTAINER_ID)
      && text.includes("fs.readdirSync(sessionsDir)")) {
      return captureResult(0, "[]\n");
    }
    if (args[0] === "exec"
      && args.includes(FAKE_PROXY_CONTAINER_ID)
      && text.includes("nft -j list set inet runfree_proxy session_ipv4")) {
      return captureResult(0, JSON.stringify({
        nftables: [{ set: { family: "inet", table: "runfree_proxy", name: "session_ipv4", type: "ipv4_addr" } }],
      }));
    }
    if (args[0] === "exec"
      && args.includes(FAKE_PROXY_CONTAINER_ID)
      && text.includes("/run/runfree-proxy-status/firewall.json")) {
      const effectiveRoot = observedComposeEnv.RUNFREE_EFFECTIVE_PROXY_DIR
        ?? path.join(tmp, "state", "control", "effective", "proxy");
      const activePath = path.join(effectiveRoot, "active.json");
      if (fs.existsSync(activePath)) {
        const active = JSON.parse(fs.readFileSync(activePath, "utf8")) as { controlGeneration: string };
        const manifestPath = path.join(
          effectiveRoot,
          "generations",
          active.controlGeneration.slice("sha256:".length),
          "manifest.json",
        );
        const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as { policyGeneration: string };
        const identity = {
          generation: manifest.policyGeneration,
          controlGeneration: active.controlGeneration,
          policyGeneration: manifest.policyGeneration,
          appliedAt: "2026-06-14T00:00:00.000Z",
        };
        if (!text.includes("/run/runfree-proxy-status/request-proxy/request-proxy.json")) {
          return captureResult(0, JSON.stringify({ ...identity, rulesetVerified: true }));
        }
        return captureResult(0, [
          JSON.stringify({ ...identity, rulesetVerified: true }),
          JSON.stringify(identity),
          "",
        ].join("\n"));
      }
    }
    if (args[0] === "exec" && args.includes(FAKE_PROXY_CONTAINER_ID) && args.includes("cat") && args.includes("/run/runfree-runtime-validation.json")) {
      if (capturedValidationMarker !== undefined) return captureResult(0, capturedValidationMarker);
      return captureResult(0, JSON.stringify({
        components: {
          digestSchemaVersion: 1,
          selectedAgentImageInputDigest: componentEnv.RUNFREE_AGENT_IMAGE_INPUT_DIGEST,
          proxyImageInputDigest: componentEnv.RUNFREE_PROXY_IMAGE_INPUT_DIGEST,
          topologyDigest: componentEnv.RUNFREE_TOPOLOGY_DIGEST,
          runtimeGenerationDigest: componentEnv.RUNFREE_RUNTIME_GENERATION_DIGEST,
        },
        mcpOAuthCallbackPort: Number(callbackPort),
        mcpOAuthCallbackTopologyVersion: 2,
        proofVersion: 4,
        projectId,
        proxyId: FAKE_PROXY_CONTAINER_ID,
        validatedAt: "2026-06-14T00:00:00.000Z",
      }));
    }
    if (args[0] === "exec" && args.includes(FAKE_AGENT_CONTAINER_ID) && text.includes("test -e /ca/private/proxy-ca.key")) {
      return captureResult(0);
    }
    if (args[0] === "exec" && args.includes(FAKE_AGENT_CONTAINER_ID) && text.includes("runfree_security_contract_probe")) {
      return captureResult(0, securityContractProbeOutput("agent", observedContainerProjectRoot));
    }
    if (args[0] === "exec" && args.includes(FAKE_PROXY_CONTAINER_ID) && text.includes("runfree_security_contract_probe")) {
      return captureResult(0, securityContractProbeOutput("proxy"));
    }
    // L5b: firewall probes arrive merged per exec identity group, framed with
    // RUNFREE_FIREWALL_SECTION markers. Answer each embedded command with the
    // same per-probe semantics the individual handlers below encode.
    if (args[0] === "exec" && args.includes(FAKE_PROXY_CONTAINER_ID) && text.includes("RUNFREE_FIREWALL_SECTION")) {
      const commands = [...text.matchAll(/runfree_out_(\d+)=\$\(\{ (.*?); \} 2>&1\); runfree_status_\1=\$\?/g)]
        .map((match) => match[2]);
      const sections = commands.map((embedded) => {
        if (embedded.includes("ip -o route get 1.1.1.1")) {
          return { exit: 0, body: `1.1.1.1 via ${fixedNetwork.proxyEgressGateway} dev eth1 src ${fixedNetwork.proxyEgressIp} uid 1001` };
        }
        const target = /ip -o route get ([^\s]+)/.exec(embedded)?.[1];
        if (target) return { exit: 0, body: `${target} dev eth0 src ${fixedNetwork.proxyIp} uid 1001` };
        if (embedded.includes("nft list set inet runfree_proxy allowed_ipv4")) {
          return {
            exit: 0,
            body: [
              "table inet runfree_proxy {",
              "  set allowed_ipv4 {",
              "    type ipv4_addr",
              "    elements = { 140.82.112.5 }",
              "  }",
              "}",
            ].join("\n"),
          };
        }
        if (embedded.includes("@127.0.0.11 example.com")) return { exit: 0, body: "" };
        return { exit: 1, body: "unexpected batched firewall command" };
      });
      return captureResult(0, `${sections.map((section, index) => [
        `RUNFREE_FIREWALL_SECTION ${index} exit=${section.exit}`,
        section.body,
        `RUNFREE_FIREWALL_SECTION_END ${index}`,
      ].join("\n")).join("\n")}\n`);
    }
    // L5b: the five server-UID denial probes arrive as one batch under the
    // server identity; every probe is denied (nonzero record) and the batch
    // itself exits 0.
    if (args[0] === "exec" && args.includes(FAKE_PROXY_CONTAINER_ID) && args.includes("1001:1001") && text.includes("RUNFREE_FIREWALL_PROBE")) {
      return captureResult(0, `${[0, 1, 2, 3, 4].map((index) => `RUNFREE_FIREWALL_PROBE ${index} exit=1`).join("\n")}\n`);
    }
    const routeTarget = /ip -o route get ([^\s]+)/.exec(text)?.[1];
    if (args[0] === "exec" && args.includes(FAKE_PROXY_CONTAINER_ID) && routeTarget && routeTarget !== "1.1.1.1") {
      return captureResult(0, `${routeTarget} dev eth0 src ${fixedNetwork.proxyIp} uid 1001\n`);
    }
    if (args[0] === "exec" && args.includes(FAKE_PROXY_CONTAINER_ID) && args.includes("1001:1001") && text.includes("nft list ruleset")) {
      return captureResult(1, "", "Operation not permitted\n");
    }
    if (args[0] === "exec" && args.includes(FAKE_PROXY_CONTAINER_ID) && args.includes("1001:1001") && text.includes("nft list set inet runfree_proxy allowed_ipv4")) {
      return captureResult(1, "", "Operation not permitted\n");
    }
    if (args[0] === "exec" && args.includes(FAKE_PROXY_CONTAINER_ID) && args.includes("1001:1001") && text.includes("ip route add blackhole 203.0.113.254/32")) {
      return captureResult(1, "", "Operation not permitted\n");
    }
    if (args[0] === "exec" && args.includes(FAKE_PROXY_CONTAINER_ID) && text.includes("nft -j list table inet runfree_proxy")) {
      return captureResult(0, proxyNftablesTableJson());
    }
    if (args[0] === "exec" && args.includes(FAKE_PROXY_CONTAINER_ID) && text.includes("nft list ruleset")) {
      return captureResult(1, "", "unexpected root nft ruleset inspection\n");
    }
    if (args[0] === "exec" && args.includes(FAKE_PROXY_CONTAINER_ID) && text.includes("nft list set inet runfree_proxy allowed_ipv4")) {
      return captureResult(0, [
        "table inet runfree_proxy {",
        "  set allowed_ipv4 {",
        "    type ipv4_addr",
        "    elements = { 140.82.112.5 }",
        "  }",
        "}",
      ].join("\n"));
    }
    if (args[0] === "exec" && text.includes("CapBnd")) {
      return captureResult(0, args.includes(FAKE_PROXY_CONTAINER_ID) ? "0000000000001000\n" : "0000000000000000\n");
    }
    if (args[0] === "exec" && text.includes("/proc/1/status") && text.includes("NoNewPrivs")) {
      return captureResult(0, "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nNoNewPrivs:\t1\n");
    }
    if (args[0] === "exec" && text.includes("/proc/self/status") && text.includes("NoNewPrivs")) {
      return captureResult(0, "uid=1000 gid=1000\nNoNewPrivs:\t1\n");
    }
    if (args[0] === "exec" && text.includes(`/dev/tcp/${fixedNetwork.proxyIp}/8080`)) return captureResult(0);
    if (args[0] === "exec" && text.includes("/dev/tcp/1.1.1.1/443")) return captureResult(1, "", "blocked\n");
    if (args[0] === "exec" && text.includes("@1.1.1.1 example.com")) return captureResult(1, "", "blocked\n");
    if (args[0] === "exec" && text.includes("@127.0.0.11 example.com")) {
      return args.includes("0:0") ? captureResult(0) : captureResult(1, "", "blocked\n");
    }
    if (args[0] === "exec" && text.includes("ip -4 route show default")) return captureResult(1, "", "blocked\n");
    if (args[0] === "exec" && text.includes("host.docker.internal")) return captureResult(1, "", "blocked\n");
    if (args[0] === "exec" && text.includes("CONNECT disallowed.example:443")) return captureResult(0, "HTTP/1.1 200 Connection Established\r\n\r\n");
    if (args[0] === "exec" && text.includes("https://disallowed.example/")) return captureResult(0, "HTTP/1.1 403 Forbidden\r\nx-runfree-blocked: host-not-allowlisted\r\n\r\n");
    // The non-443 CONNECT probe always targets the reserved non-resolving
    // hostname, never a policy host, so one stub covers every project policy.
    if (args[0] === "exec" && text.includes(`CONNECT ${NON_RESOLVING_CONNECT_PROBE_HOST}:22`)) {
      return captureResult(0, `HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\nblocked by agent proxy policy\nreason: blocked non-HTTPS CONNECT port: 22\nhost: ${NON_RESOLVING_CONNECT_PROBE_HOST}\n`);
    }
    return captureResult(0);
  };
  const isTopologyCapture = (command: string, args: string[]): boolean => {
    if (command !== "docker") return false;
    const text = args.join(" ");
    if (args[0] === "image" && args[1] === "inspect") return true;
    if (args[0] === "ps"
      && (composeStarted || Boolean(process.env.FAKE_PREEXISTING_AGENT_ID))
      && args.includes("-aq")
      && text.includes("com.docker.compose.project=")
      && !text.includes("com.docker.compose.service=")) return true;
    if (args[0] === "ps" && text.includes("com.docker.compose.service=")) return true;
    if (args[0] === "inspect" && args.includes("--format") && text.includes("io.runfree.runtime-digest")) return true;
    if (args[0] === "container" && args[1] === "inspect") return true;
    if (args[0] === "inspect" && args.includes(FAKE_AGENT_CONTAINER_ID) && args.includes(FAKE_PROXY_CONTAINER_ID)) return true;
    if (args[0] === "inspect" && args.includes(FAKE_AGENT_CONTAINER_ID) && !args.includes("--format")) return true;
    // Post-cutover the topology/security probes inspect only the proxy.
    if (args[0] === "inspect" && args.includes(FAKE_PROXY_CONTAINER_ID) && !args.includes("--format")) return true;
    if (args[0] === "network" && args[1] === "inspect" && (text.includes("_agent_internal") || text.includes("_proxy_egress"))) return true;
    // Blank success is malformed JSON to the named-volume proof, not a neutral
    // answer, so a test's generic stub must not shadow the fake's inspection.
    if (args[0] === "volume" && args[1] === "inspect") return true;
    // Post-cutover agent-position confinement runs in an ephemeral deny-probe
    // helper; classify it so the shared fake's denial answer is not shadowed.
    if (args[0] === "run" && text.includes("io.runfree.helper-purpose=deny-probe")) return true;
    if (args[0] !== "exec") return false;
    return text.includes("ip -o route get")
      || text.includes("/run/runfree-proxy-status/firewall.json")
      || text.includes("nft -j list table inet runfree_proxy")
      || text.includes("nft -j list set inet runfree_proxy session_ipv4")
      || text.includes("nft list ruleset")
      || text.includes("nft list set inet runfree_proxy allowed_ipv4")
      || text.includes("ip route add blackhole 203.0.113.254/32")
      || text.includes("CapBnd")
      || text.includes("NoNewPrivs")
      || text.includes("rev-parse --path-format=absolute --git-dir")
      || text.includes("runfree_security_contract_probe")
      || text.includes("/dev/tcp/")
      || text.includes("@1.1.1.1 example.com")
      || text.includes("@127.0.0.11 example.com")
      || text.includes("ip -4 route show default")
      || text.includes("host.docker.internal")
      || text.includes("CONNECT disallowed.example:443")
      || text.includes("https://disallowed.example/")
      || text.includes(`CONNECT ${NON_RESOLVING_CONNECT_PROBE_HOST}:22`)
      || (text.includes(SESSION_ELIGIBILITY_PATH) && text.includes("existsSync"))
      || text.includes("fs.readdirSync(sessionsDir)");
  };
  const isQuiesceCapture = (command: string, args: string[]): boolean => {
    if (command !== "docker") return false;
    if (args[0] === "pause" || args[0] === "unpause") return args.slice(1).includes(quiescedAgentId);
    if (args[0] === "inspect" && args.length === 2) return args[1] === quiescedAgentId;
    return args[0] === "ps"
      && args.includes("-q")
      && args.some((arg) => arg.startsWith(`label=${PROJECT_ID_LABEL}=`))
      && args.includes("label=com.docker.compose.service=agent");
  };
  const isControlReceiptCapture = (command: string, args: string[]): boolean => command === "docker"
    && args[0] === "exec"
    && args.includes(FAKE_PROXY_CONTAINER_ID)
    && args.join(" ").includes("/run/runfree-proxy-status/firewall.json")
    && args.join(" ").includes("/run/runfree-proxy-status/request-proxy/request-proxy.json");
  const normalizeFakeDockerIds = (command: string, result: CaptureResult): CaptureResult => command === "docker"
    ? {
        ...result,
        stdout: result.stdout
          .replaceAll("agent-id", FAKE_AGENT_CONTAINER_ID)
          .replaceAll("proxy-id", FAKE_PROXY_CONTAINER_ID),
        stderr: result.stderr
          .replaceAll("agent-id", FAKE_AGENT_CONTAINER_ID)
          .replaceAll("proxy-id", FAKE_PROXY_CONTAINER_ID),
      }
    : result;
  return {
    calls,
    async admin(intent, context) {
      const args = runtimeIntentToArgs(intent);
      calls.push({ method: "admin", args });
      if (intent.kind === "ensure-agent-service") {
        const status = applyAgentServiceIntentForTest(intent, context);
        if (status !== 0) return status;
      }
      return overrides.admin?.(args, context) ?? 0;
    },
    capture(command, args, options) {
      if (command === "docker") rememberProject(args);
      calls.push({
        method: "capture",
        command,
        args: [...args],
        cwd: typeof options?.cwd === "string" ? options.cwd : undefined,
        env: options?.env,
        input: typeof options?.input === "string" ? options.input : undefined,
      });
      if (command === "docker" && args[0] === "exec" && typeof options?.input === "string"
        && args.some((arg) => typeof arg === "string" && arg.includes("runtime-validation.json"))) {
        capturedValidationMarker = options.input;
      }
      if (isQuiesceCapture(command, args) || isControlReceiptCapture(command, args)) {
        return defaultCapture(command, args, options?.env);
      }
      // The trust-bundle helper extraction must answer with a PEM regardless
      // of a test's own generic capture stub, exactly like the quiesce and
      // control-receipt captures above: a blank success here is not a neutral
      // answer, it is an implausible root bundle that fails startup.
      if (command === "docker" && args[0] === "run" && args.includes("io.runfree.helper-purpose=trust-bundle")) {
        return defaultCapture(command, args, options?.env);
      }
      if (command === "docker"
        && args[0] === "network"
        && args[1] === "inspect"
        && args.some((arg) => arg.startsWith("runfree-ingress-host-"))) {
        return defaultCapture(command, args, options?.env);
      }
      if (command === "docker"
        && args[0] === "image"
        && args[1] === "inspect"
        && args[2]
        && (builtImageReferences.has(args[2]) || inspectedImagesById.has(args[2]))) {
        return defaultCapture(command, args, options?.env);
      }
      const overridden = overrides.capture?.(command, args);
      if (command === "git" && args[0] === "worktree" && args.at(-1) === "-h"
        && overridden?.status === 0 && !overridden.stdout && !overridden.stderr) {
        return defaultCapture(command, args, options?.env);
      }
      if (composeStarted && isTopologyCapture(command, args)
        && ((args[0] === "ps"
          && args.includes("-aq")
          && args.some((arg) => arg.startsWith("label=com.docker.compose.project="))
          && !args.some((arg) => arg.includes("com.docker.compose.service=")))
          || (args[0] === "inspect"
            && args.includes("--format")
            && args.some((arg) => arg.includes("io.runfree.runtime-digest"))))) {
        return defaultCapture(command, args, options?.env);
      }
      if (overridden && isTopologyCapture(command, args) && overridden.status === 0 && !overridden.stdout && !overridden.stderr) {
        return defaultCapture(command, args, options?.env);
      }
      return normalizeFakeDockerIds(command, overridden ?? defaultCapture(command, args, options?.env));
    },
    commandExists(command, options) {
      calls.push({
        method: "commandExists",
        command,
        args: [],
        cwd: typeof options?.cwd === "string" ? options.cwd : undefined,
        env: options?.env,
      });
      return overrides.commandExists?.(command) ?? true;
    },
    confirm(question) {
      calls.push({ method: "confirm", args: [question] });
      return overrides.confirm?.(question)
        ?? (question.startsWith("Enable agent-") || question.includes("Approve this build input for this checkout?") || question.includes("Approve this changed build input for this checkout?"));
    },
    choosePiProvider(options) {
      calls.push({ method: "choosePiProvider", args: options.map((option) => `${option.value}: ${option.label}`) });
      return overrides.choosePiProvider?.(options) ?? "custom";
    },
    isInteractive: () => overrides.isInteractive?.() ?? true,
    startTokenAutoRefresh(context, receipts) {
      if (overrides.startTokenAutoRefresh) return overrides.startTokenAutoRefresh(context, receipts);
      const logPath = context.env?.RUNFREE_TEST_TOKEN_AUTO_REFRESH_LOG;
      if (logPath) {
        fs.appendFileSync(logPath, `${JSON.stringify({
          event: "start",
          args: [
            "--workspace",
            context.projectRoot,
            "credential",
            "sync",
            "--watch",
            "--quiet",
            "--delay-first-sync",
          ],
          parentPid: process.pid,
        })}\n`);
      }
      return {
        stop: () => {
          if (logPath) fs.appendFileSync(logPath, `${JSON.stringify({ event: "stop", parentPid: process.pid })}\n`);
        },
      };
    },
    takeTokenResolutionReceipts: overrides.takeTokenResolutionReceipts,
    run(command, args, options) {
      calls.push({
        method: "run",
        command,
        args: [...args],
        cwd: typeof options?.cwd === "string" ? options.cwd : undefined,
        env: options?.env,
      });
      const status = overrides.run?.(command, args) ?? 0;
      if (status === 0 && command === "docker" && args[0] === "build") {
        for (let index = 0; index < args.length; index += 1) {
          if (args[index] === "--tag" && args[index + 1]) builtImageReferences.add(args[index + 1] as string);
        }
      }
      if (status === 0 && command === "docker" && args[0] === "compose" && args.includes("up")) {
        observedContainerProjectRoot = options?.env?.RUNFREE_PROJECT_PHYSICAL_ROOT ?? observedContainerProjectRoot;
        observedComposeEnv = { ...options?.env };
        composeStarted = true;
      }
      if (status === 0 && command === "docker" && args[0] === "compose" && args.includes("down")) {
        composeStarted = false;
      }
      return status;
    },
  };
}

function composeUpCall(io: { calls: RuntimeIoCall[] }): RuntimeIoCall | undefined {
  return io.calls.find((call) => call.method === "run"
    && call.command === "docker"
    && call.args[0] === "compose"
    && call.args.includes("up"));
}

function runtimeValidationMarkerWriteIndex(io: { calls: RuntimeIoCall[] }): number {
  return io.calls.findIndex((call) => call.method === "capture"
    && call.command === "docker"
    && typeof call.input === "string"
    && call.args.join(" ").includes("/run/runfree-runtime-validation.json"));
}

function agentTrustSetupCall(io: { calls: RuntimeIoCall[] }): RuntimeIoCall | undefined {
  return io.calls.find((call) => call.method === "capture"
    && call.command === "docker"
    && call.args[0] === "exec"
    && call.args.includes("--user")
    && call.args.includes("0:0")
    && call.args.includes("sh")
    && call.args.includes("-s"));
}

function configuredAgentExecCall(
  io: { calls: RuntimeIoCall[] },
  agentCommand = "claude --dangerously-skip-permissions --add-dir /runfree/inbox",
): RuntimeIoCall | undefined {
  return io.calls.find((call) => call.method === "run"
    && call.command === "docker"
    && call.args[0] === "exec"
    && call.args.includes(`RUNFREE_AGENT_COMMAND=${agentCommand}`));
}

describe("runtime recovery", () => {
  test("detects compose containers missing the expected project network", () => {
    expect(containerMissingNetwork({
      id: FAKE_AGENT_CONTAINER_ID,
      networks: ["runfree-c07a61836c19_default"],
    }, "runfree-c07a61836c19_agent_internal")).toBe(true);
    expect(containerMissingNetwork({
      id: FAKE_AGENT_CONTAINER_ID,
      networks: ["runfree-c07a61836c19_agent_internal"],
    }, "runfree-c07a61836c19_agent_internal")).toBe(false);
    expect(containerMissingNetwork({
      id: FAKE_AGENT_CONTAINER_ID,
      networks: [],
    }, "runfree-c07a61836c19_agent_internal")).toBe(true);
  });






  test.each(["linked", "main"])("up from %s refuses absolute worktree metadata before compose or token sync", async (launchFrom) => {
    const linkedRoot = path.join(tmp, "main", ".worktrees", "feature");
    const { gitDir } = prepareRelativeLinkedWorktree(linkedRoot);
    fs.writeFileSync(path.join(linkedRoot, ".git"), `gitdir: ${gitDir}\n`);
    const projectRoot = launchFrom === "main" ? path.join(tmp, "main") : linkedRoot;
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO();

    await expect(up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {})).rejects.toThrow("Runfree only supports Git linked worktrees that use relative links");

    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
    expect(io.calls.find((call) => call.method === "run" && call.command === "docker" && call.args.includes("up"))).toBeUndefined();
    expect(fs.existsSync(project.paths.gitConfigPath)).toBe(false);
    expect(fs.existsSync(path.join(project.paths.stateDir, "git-layout-plan.json"))).toBe(false);
  });

  test("up refuses unsupported host Git before publishing sandbox config or starting Compose", async () => {
    const projectRoot = path.join(tmp, "project");
    fs.mkdirSync(projectRoot);
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => command === "git" && args[0] === "worktree"
        ? captureResult(129, "usage: git worktree (old Git)")
        : undefined,
    });
    await expect(up({
      projectRoot, project, runtimeRoot: path.join(tmp, "runtime"), env: { PATH: "/fake-bin" }, network: fixedNetwork,
    }, io, false, {})).rejects.toThrow("host Git does not support relative worktree links");
    expect(fs.existsSync(project.paths.gitConfigPath)).toBe(false);
    expect(io.calls.find((call) => call.method === "run" && call.command === "docker" && call.args.includes("up"))).toBeUndefined();
  });


  // Invariant 3 from the `up` end: every `up` reconciles the proxy's session
  // files, its own records, and its session containers before any launch can
  // allocate an address — and it does so after the eligibility publication, so
  // the admitted set is widened before the sweep and narrowed by what the
  // sweep left.
  test("up reconciles the proxy's session files", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const sessionFileEffects: string[] = [];
    const io = createRuntimeIO({
      capture(command, args) {
        if (command !== "docker" || args[0] !== "exec" || args[6] !== "-e") return undefined;
        if (args.length === 8) {
          sessionFileEffects.push("read-served-set");
          return captureResult(0, "[]\n");
        }
        sessionFileEffects.push(args[8] === SESSION_ELIGIBILITY_PATH
          ? "publish-eligibility"
          : `session-file:${args.length > 9 ? "write" : "delete"}`);
        return undefined;
      },
    });

    const status = await up({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    expect(sessionFileEffects).toContain("read-served-set");
    expect(sessionFileEffects.indexOf("publish-eligibility"))
      .toBeLessThan(sessionFileEffects.indexOf("read-served-set"));
    // Nothing to sweep in a fresh runtime, and the host never writes a session
    // file outside a session's own heartbeat.
    expect(sessionFileEffects).not.toContain("session-file:delete");
    expect(sessionFileEffects).not.toContain("session-file:write");
  });

  test("up leaves dependency overlay mounts out when disabled", async () => {
    const projectRoot = path.join(tmp, "project");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.writeFileSync(path.join(projectRoot, "package.json"), JSON.stringify({ packageManager: "pnpm@10.28.0" }));
    fs.writeFileSync(path.join(projectRoot, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    const config = defaultConfig();
    config.runtime.dependencyOverlays = "off";
    const project = prepareProject(projectRoot, config);
    const io = createRuntimeIO();

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    const generatedRoot = onlyMaterializedRuntimeRoot(project);
    const generatedCompose = fs.readFileSync(path.join(generatedRoot, "agent", "compose.yaml"), "utf8");
    const plan = JSON.parse(fs.readFileSync(path.join(project.paths.stateDir, "dependency-overlays.json"), "utf8")) as {
      mode: string;
      overlays: Array<{ hostRelativePath: string; volume: string }>;
      workspaceHash: string;
    };

    expect(status).toBe(0);
    expect(plan.mode).toBe("off");
    expect(plan.overlays).toMatchObject([
      {
        hostRelativePath: "node_modules",
        volume: `runfree-deps-${plan.workspaceHash}-root-node-modules`,
      },
    ]);
    expect(generatedCompose).not.toContain("target: \"/workspace/node_modules\"");
    expect(generatedCompose).not.toContain("NPM_CONFIG_STORE_DIR");
    expect(generatedCompose).not.toContain(`  runfree-deps-${plan.workspaceHash}-root-node-modules:`);
    expect(generatedCompose).not.toContain(`  runfree-deps-${plan.workspaceHash}-pnpm-store:`);
  });

  // The pre-cutover `deps install` refusals (PyPI-preflight-before-runtime-start
  // and overlays-off) tested reachable paths that the per-session gate in
  // dependency-overlays.ts now short-circuits before, so they were retired with
  // the rest of the pre-flip runtime.test.ts coverage. The current behavior — a
  // deliberate refusal with a `runfree shell` workaround — is covered by
  // dependency-overlays.test.ts "deps install is refused with a supported
  // message in the per-session runtime". Those preflight/overlay checks return
  // with the per-session deps install follow-up (see local handoff §4.1).

  // Unknown-flag rejection for `deps <sub>` is parser-level and now covered by
  // the typed yargs grammar — see commands/app.test.ts "deps: ... bad input
  // rejects" (per-subcommand .strict()).

  test("deps doctor reports diagnostic drift without requiring recreate", async () => {
    const projectRoot = path.join(tmp, "project");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.writeFileSync(path.join(projectRoot, "package.json"), JSON.stringify({ packageManager: "npm@10.0.0" }));
    fs.writeFileSync(path.join(projectRoot, "package-lock.json"), "{}\n");
    const project = prepareProject(projectRoot);
    fs.mkdirSync(project.paths.stateDir, { recursive: true });
    const previousPlan = createDependencyOverlayPlan(projectRoot);
    previousPlan.installCommands = previousPlan.installCommands.map((command) => ({ ...command, command: "npm install" }));
    previousPlan.installCommand = "npm install";
    fs.writeFileSync(path.join(project.paths.stateDir, "dependency-overlays.json"), serializeDependencyOverlayPlan(previousPlan));
    fs.writeFileSync(
      path.join(project.paths.stateDir, "dependency-overlays.signature.json"),
      serializeDependencyOverlayRuntimeSignature(dependencyOverlayRuntimeSignature(previousPlan, "/workspace")),
    );
    fs.mkdirSync(path.join(projectRoot, "scratch-checkouts"), { recursive: true });
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "git" && args.includes("--ignored")) return captureResult(0, "scratch-checkouts/\0");
        if (command === "git" && args.includes("ls-files")) return captureResult(0, "");
        return undefined;
      },
    });

    const status = await depsRuntime({ kind: "doctor" }, {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, createRuntimeAdapters({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io), startRuntime);

    const output = vi.mocked(console.log).mock.calls.flat().join("\n");
    expect(status).toBe(0);
    expect(output).toContain("runtime recreate required: no");
    expect(output).toContain("dependency overlay diagnostic drift detected; runtime recreate is not required");
    expect(output).not.toContain("dependency overlay mount drift detected");
  });

  test("git repair-worktree-links runs host repair and revalidates metadata", async () => {
    const projectRoot = path.join(tmp, "main", ".worktrees", "feature");
    const { gitCommonDir, gitDir } = prepareRelativeLinkedWorktree(projectRoot);
    fs.writeFileSync(path.join(projectRoot, ".git"), `gitdir: ${gitDir}\n`);
    fs.writeFileSync(path.join(gitDir, "gitdir"), `${path.join(projectRoot, ".git")}\n`);
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "git" && args[0] === "worktree" && args.at(-1) === "-h") {
          return captureResult(129, "", "usage: git worktree\n    --[no-]relative-paths use relative paths\n");
        }
        return undefined;
      },
      run: (command, args) => {
        if (command === "git" && args.includes("repair")) {
          fs.writeFileSync(path.join(projectRoot, ".git"), "gitdir: ../../.git/worktrees/feature\n");
          fs.writeFileSync(path.join(gitDir, "gitdir"), "../../../.worktrees/feature/.git\n");
          return 0;
        }
        if (command === "git" && args.includes("config")) {
          fs.writeFileSync(path.join(gitCommonDir, "config"), [
            "[extensions]",
            "\trelativeWorktrees = true",
            "[worktree]",
            "\tuseRelativePaths = true",
            "",
          ].join("\n"));
          return 0;
        }
        return 0;
      },
    });

    const status = await repairWorktreeLinks({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io);

    expect(status).toBe(0);
    expect(io.calls.filter((call) => call.method === "run" && call.command === "git").map((call) => call.args)).toEqual([
      ["-C", projectRoot, "worktree", "repair", "--relative-paths"],
      ["-C", projectRoot, "config", "--local", "worktree.useRelativePaths", "true"],
    ]);
  });

  test("deps reset removes only persisted Runfree dependency volumes", async () => {
    const projectRoot = path.join(tmp, "project");
    fs.mkdirSync(path.join(projectRoot, "node_modules"), { recursive: true });
    const project = prepareProject(projectRoot);
    fs.mkdirSync(project.paths.stateDir, { recursive: true });
    const workspaceHash = projectHash(projectRoot);
    fs.writeFileSync(path.join(project.paths.stateDir, "dependency-overlays.json"), `${JSON.stringify({
      version: 1,
      projectRoot,
      workspaceHash,
      packageManagers: ["npm"],
      workspaceRoots: [],
      overlays: [{
        path: "/workspace/node_modules",
        hostRelativePath: "node_modules",
        volume: `runfree-deps-${workspaceHash}-root-node-modules`,
        reason: "npm workspace root",
      }, {
        path: "/workspace/external",
        hostRelativePath: "external",
        volume: "not-runfree-owned",
        reason: "malformed persisted plan entry",
      }],
      ignoredCandidates: [],
      storeVolumes: [{
        packageManager: "npm",
        volume: `runfree-deps-${workspaceHash}-npm-cache`,
        target: "/home/agent/.npm",
        environment: { NPM_CONFIG_CACHE: "/home/agent/.npm" },
      }],
      installCommand: "npm ci",
    }, null, 2)}\n`);
    const io = createRuntimeIO();

    const status = await depsRuntime({ kind: "reset", force: true }, {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, createRuntimeAdapters({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io), startRuntime);

    expect(status).toBe(0);
    expect(fs.existsSync(path.join(projectRoot, "node_modules"))).toBe(true);
    expect(io.calls).toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: ["volume", "rm", `runfree-deps-${workspaceHash}-npm-cache`, `runfree-deps-${workspaceHash}-root-node-modules`],
    }));
    expect(io.calls).not.toContainEqual(expect.objectContaining({
      args: expect.arrayContaining(["not-runfree-owned"]),
    }));
  });

  test("deps reset recognizes volumes created through a symlinked workspace", async () => {
    const realProjectRoot = path.join(tmp, "real-project");
    const linkedProjectRoot = path.join(tmp, "linked-project");
    fs.mkdirSync(realProjectRoot, { recursive: true });
    fs.symlinkSync(realProjectRoot, linkedProjectRoot, "dir");
    const project = prepareProject(linkedProjectRoot);
    fs.mkdirSync(project.paths.stateDir, { recursive: true });
    const workspaceHash = projectHash(fs.realpathSync(linkedProjectRoot));
    fs.writeFileSync(path.join(project.paths.stateDir, "dependency-overlays.json"), `${JSON.stringify({
      version: 1,
      projectRoot: realProjectRoot,
      workspaceHash,
      packageManagers: ["npm"],
      workspaceRoots: [],
      overlays: [{
        path: "/workspace/node_modules",
        hostRelativePath: "node_modules",
        volume: `runfree-deps-${workspaceHash}-root-node-modules`,
        reason: "npm workspace root",
      }],
      ignoredCandidates: [],
      storeVolumes: [],
      installCommand: "npm install",
    }, null, 2)}\n`);
    const io = createRuntimeIO();

    const status = await depsRuntime({ kind: "reset", force: true }, {
      projectRoot: linkedProjectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, createRuntimeAdapters({
      projectRoot: linkedProjectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io), startRuntime);

    expect(status).toBe(0);
    expect(io.calls).toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: ["volume", "rm", `runfree-deps-${workspaceHash}-root-node-modules`],
    }));
  });


  test("MCP import lines report only the launched agent's servers and collapse per-agent duplicates", () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const hostHome = path.join(tmp, "host-home");
    const hostCodexDir = path.join(hostHome, ".codex");
    fs.mkdirSync(hostCodexDir, { recursive: true });
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), [
      "[mcp_servers.posthog]",
      'url = "https://mcp.posthog.com/mcp"',
      "oauth = true",
      "",
    ].join("\n"));
    fs.writeFileSync(path.join(hostHome, ".claude.json"), JSON.stringify({
      mcpServers: { posthog: { type: "http", url: "https://mcp.posthog.com/mcp", oauth: true } },
    }));
    const prepare = () => prepareMcpRuntime({
      callbackPort: 47638,
      claudeConfigPath: project.paths.claudeConfigPath,
      claudeMcpConfigPath: project.paths.claudeMcpConfigPath,
      codexDir: project.paths.codexDir,
      env: { HOME: hostHome, CODEX_HOME: hostCodexDir },
      mcpOAuthPolicyPath: project.paths.mcpOAuthPolicyPath,
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });
    const warnedLines = () => {
      const lines = pendingWarningsForTest().map((event) => event.message);
      flushWarnings();
      return lines;
    };

    try {
      flushWarnings();
      setMcpLogContext({ agent: "claude" });
      prepare();
      const claudeLines = warnedLines().filter((line) => line.startsWith("mcp: imported"));
      expect(claudeLines).toEqual(["mcp: imported user claude server posthog transport=http auth=oauth"]);

      setMcpLogContext({ agent: "codex" });
      prepare();
      const codexLines = warnedLines().filter((line) => line.startsWith("mcp: imported"));
      expect(codexLines).toEqual(["mcp: imported user codex server posthog transport=http auth=oauth"]);

      // No launched agent (`runfree up`): one line for both agents' import.
      setMcpLogContext({});
      prepare();
      const bothLines = warnedLines().filter((line) => line.startsWith("mcp: imported"));
      expect(bothLines).toEqual(["mcp: imported user server (claude, codex) posthog transport=http auth=oauth"]);

      // OAuth callback guidance is verbose-only.
      setMcpLogContext({ agent: "claude", verbose: true });
      prepare();
      expect(warnedLines().some((line) => line.includes("OAuth login for posthog returns through http://localhost:47638/callback"))).toBe(true);
    } finally {
      setMcpLogContext({});
      flushWarnings();
    }
  });

  test("MCP import writes Codex callback globals before existing TOML tables", () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const hostHome = path.join(tmp, "host-home");
    const hostCodexDir = path.join(hostHome, ".codex");
    const callbackPort = 47638;
    fs.mkdirSync(hostCodexDir, { recursive: true });
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), [
      "[mcp_servers.posthog]",
      'url = "https://mcp.posthog.com/mcp"',
      "",
    ].join("\n"));
    fs.mkdirSync(project.paths.codexDir, { recursive: true });
    fs.writeFileSync(path.join(project.paths.codexDir, "config.toml"), [
      "[tui]",
      "model_availability_nux = 1",
      "",
    ].join("\n"));

    prepareMcpRuntime({
      callbackPort,
      claudeConfigPath: project.paths.claudeConfigPath,
      claudeMcpConfigPath: project.paths.claudeMcpConfigPath,
      codexDir: project.paths.codexDir,
      env: { HOME: hostHome, CODEX_HOME: hostCodexDir },
      mcpOAuthPolicyPath: project.paths.mcpOAuthPolicyPath,
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });

    const configToml = fs.readFileSync(path.join(project.paths.codexDir, "config.toml"), "utf8");
    const callbackIndex = configToml.indexOf("mcp_oauth_callback_url");
    const tuiTableIndex = configToml.indexOf("[tui]");
    expect(callbackIndex).toBeGreaterThanOrEqual(0);
    expect(tuiTableIndex).toBeGreaterThanOrEqual(0);
    expect(callbackIndex).toBeLessThan(tuiTableIndex);
    expect(configToml).toContain(`mcp_oauth_callback_port = ${callbackPort}`);
    expect(configToml).toContain(`mcp_oauth_callback_url = "http://localhost:${callbackPort}/callback"`);
    expect(configToml).toContain([
      "[tui]",
      "model_availability_nux = 1",
    ].join("\n"));
    expect(configToml).toContain([
      "[mcp_servers.posthog]",
      'url = "https://mcp.posthog.com/mcp"',
    ].join("\n"));
    const parsed = parseToml(configToml) as Record<string, unknown>;
    expect(parsed.mcp_oauth_callback_port).toBe(callbackPort);
    expect(parsed.mcp_oauth_callback_url).toBe(`http://localhost:${callbackPort}/callback`);
    expect(parsed.tui).toEqual({ model_availability_nux: 1 });
  });

  test("MCP import skips an unsafe Codex config and continues other projections", () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const hostHome = path.join(tmp, "host-home");
    const hostCodexDir = path.join(hostHome, ".codex");
    const outside = path.join(tmp, "outside.toml");
    const configPath = path.join(project.paths.codexDir, "config.toml");
    fs.mkdirSync(hostCodexDir, { recursive: true });
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), [
      "[mcp_servers.posthog]",
      'url = "https://mcp.posthog.com/mcp"',
      "",
    ].join("\n"));
    fs.mkdirSync(project.paths.codexDir, { recursive: true });
    fs.writeFileSync(outside, "outside = true\n", { mode: 0o640 });
    const outsideMode = fs.statSync(outside).mode & 0o777;
    fs.symlinkSync(outside, configPath);

    prepareMcpRuntime({
      callbackPort: 47638,
      claudeConfigPath: project.paths.claudeConfigPath,
      claudeMcpConfigPath: project.paths.claudeMcpConfigPath,
      codexDir: project.paths.codexDir,
      env: { HOME: hostHome, CODEX_HOME: hostCodexDir },
      mcpOAuthPolicyPath: project.paths.mcpOAuthPolicyPath,
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });

    expect(fs.readFileSync(outside, "utf8")).toBe("outside = true\n");
    expect(fs.statSync(outside).mode & 0o777).toBe(outsideMode);
    expect(fs.lstatSync(configPath).isSymbolicLink()).toBe(true);
    expect(JSON.parse(fs.readFileSync(project.paths.claudeMcpConfigPath, "utf8"))).toMatchObject({
      mcpServers: {},
    });
    expect(JSON.parse(fs.readFileSync(project.paths.mcpOAuthPolicyPath, "utf8"))).toMatchObject({
      providers: {},
    });
    expect(pendingWarningsForTest().map((event) => event.message).join("\n")).toContain("Codex config update skipped");
    expect(fs.readdirSync(project.paths.codexDir)).toEqual(["config.toml"]);
  });

  test("MCP import writes operation policy only for imported and approved HTTP servers", () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const hostHome = path.join(tmp, "host-home");
    const hostCodexDir = path.join(hostHome, ".codex");
    fs.mkdirSync(hostCodexDir, { recursive: true });
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), [
      "[mcp_servers.posthog]",
      'url = "https://mcp.posthog.com/mcp"',
      "",
    ].join("\n"));
    fs.mkdirSync(path.join(projectRoot, ".codex"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".codex", "config.toml"), [
      "[mcp_servers.project_tool]",
      'url = "https://project.example.com/mcp"',
      "",
    ].join("\n"));

    prepareMcpRuntime({
      callbackPort: 47638,
      claudeConfigPath: project.paths.claudeConfigPath,
      claudeMcpConfigPath: project.paths.claudeMcpConfigPath,
      codexDir: project.paths.codexDir,
      env: { HOME: hostHome, CODEX_HOME: hostCodexDir },
      mcpOperationPolicyPath: project.paths.mcpOperationPolicyPath,
      mcpOAuthPolicyPath: project.paths.mcpOAuthPolicyPath,
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });

    expect(JSON.parse(fs.readFileSync(project.paths.mcpOperationPolicyPath ?? "", "utf8"))).toMatchObject({
      schemaVersion: 1,
      servers: [
        {
          id: "codex:user:posthog",
          agent: "codex",
          name: "posthog",
          source: "user",
          host: "mcp.posthog.com",
          path: "/mcp",
        },
      ],
    });

    const approvalFile = mcpApprovalPath(project.paths.stateDir);
    const projectEntry = mcpInventory({
      projectRoot,
      env: { HOME: hostHome, CODEX_HOME: hostCodexDir },
      approvalPath: approvalFile,
    }).entries.find((entry) => entry.source === "project" && entry.agent === "codex" && entry.name === "project_tool");
    if (!projectEntry) throw new Error("project MCP inventory entry missing");
    saveMcpApproval(projectRoot, approvalFile, projectEntry);

    prepareMcpRuntime({
      approvalPath: approvalFile,
      callbackPort: 47638,
      claudeConfigPath: project.paths.claudeConfigPath,
      claudeMcpConfigPath: project.paths.claudeMcpConfigPath,
      codexDir: project.paths.codexDir,
      env: { HOME: hostHome, CODEX_HOME: hostCodexDir },
      mcpOperationPolicyPath: project.paths.mcpOperationPolicyPath,
      mcpOAuthPolicyPath: project.paths.mcpOAuthPolicyPath,
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });

    expect((JSON.parse(fs.readFileSync(project.paths.mcpOperationPolicyPath ?? "", "utf8")) as { servers: Array<{ id: string }> }).servers.map((server) => server.id)).toEqual([
      "codex:project:project_tool",
      "codex:user:posthog",
    ]);
  });

  test("MCP import only replaces whole-line generated Codex blocks", () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const hostHome = path.join(tmp, "host-home");
    const hostCodexDir = path.join(hostHome, ".codex");
    fs.mkdirSync(hostCodexDir, { recursive: true });
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), [
      "[mcp_servers.posthog]",
      'url = "https://mcp.posthog.com/mcp"',
      "",
    ].join("\n"));
    fs.mkdirSync(project.paths.codexDir, { recursive: true });
    fs.writeFileSync(path.join(project.paths.codexDir, "config.toml"), [
      'begin_note = "literal # BEGIN RUNFREE GENERATED MCP"',
      'end_note = "literal # END RUNFREE GENERATED MCP"',
      "",
      "[tui]",
      "model_availability_nux = 1",
      "",
    ].join("\n"));

    prepareMcpRuntime({
      callbackPort: 47638,
      claudeConfigPath: project.paths.claudeConfigPath,
      claudeMcpConfigPath: project.paths.claudeMcpConfigPath,
      codexDir: project.paths.codexDir,
      env: { HOME: hostHome, CODEX_HOME: hostCodexDir },
      mcpOAuthPolicyPath: project.paths.mcpOAuthPolicyPath,
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });

    const configToml = fs.readFileSync(path.join(project.paths.codexDir, "config.toml"), "utf8");
    expect(configToml).toContain('begin_note = "literal # BEGIN RUNFREE GENERATED MCP"');
    expect(configToml).toContain('end_note = "literal # END RUNFREE GENERATED MCP"');
    expect(configToml).toContain("[mcp_servers.posthog]");
  });







  test("up fails closed when stale runtime validation marker cannot be removed", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker"
          && args[0] === "exec"
          && args.includes(FAKE_PROXY_CONTAINER_ID)
          && args.join(" ").includes("rm -f '/run/runfree-runtime-validation.json'")) {
          return captureResult(1, "", "permission denied\n");
        }
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(runtimeValidationMarkerWriteIndex(io)).toBe(-1);
    expect(agentTrustSetupCall(io)).toBeUndefined();
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.some((call) => call.method === "admin" && call.args.join(" ") === "token sync")).toBe(false);
  });

  test("up defers cold runtime materialization while a lifecycle lock is held", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const lockDir = path.join(project.paths.stateDir, "runtime-lifecycle.lock");
    fs.mkdirSync(lockDir, { recursive: true });
    fs.writeFileSync(path.join(lockDir, "pid"), `${process.pid}\n`);
    const io = createRuntimeIO();

    vi.useFakeTimers();
    let status: number;
    try {
      const pending = up( {
        projectRoot,
        project,
        runtimeRoot: path.join(tmp, "runtime"),
        env: { PATH: "/fake-bin" },
        network: fixedNetwork,
      }, io, false, {});
      await vi.advanceTimersByTimeAsync(60_000);
      status = await pending;
    } finally {
      vi.useRealTimers();
    }

    expect(status).toBe(1);
    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n"))
      .toContain("another Runfree runtime lifecycle or control change is in progress");
    expect(composeUpCall(io)).toBeUndefined();
    expect(io.calls).not.toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: expect.arrayContaining(["compose", "-p", projectName, "up"]),
    }));
  });

  test("rebuild writes resolved git identity fallback even when local git identity exists", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    const project = prepareProject(projectRoot);
    fs.mkdirSync(path.join(projectRoot, ".git"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".git", "config"), [
      "[user]",
      "\tname = Repo Local",
      "\temail = repo-local@example.test",
      "",
    ].join("\n"));
    const io = createRuntimeIO({
      capture: gitIdentityCapture({
        email: "repo-local@example.test",
        name: "Repo Local",
      }),
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, true, {});

    expect(status).toBe(0);
    expect(fs.readFileSync(project.paths.gitConfigPath, "utf8")).toBe([
      "[worktree]",
      "\tuseRelativePaths = true",
      "[safe]",
      "\tdirectory = /workspace",
      "\tdirectory = /workspace/*",
      "\tdirectory = /runfree/git-layout",
      "\tdirectory = /runfree/git-layout/*",
      "[user]",
      "\tname = \"Repo Local\"",
      "\temail = \"repo-local@example.test\"",
      "",
    ].join("\n"));
    expect(fs.statSync(project.paths.gitConfigPath).mode & 0o777).toBe(0o644);
  });

  test("rebuild fills sandbox git fallback when local git config has no identity", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    const project = prepareProject(projectRoot);
    fs.mkdirSync(path.join(projectRoot, ".git"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".git", "config"), [
      "[remote \"origin\"]",
      "\turl = git@example.test:repo.git",
      "",
    ].join("\n"));
    const io = createRuntimeIO({
      capture: gitIdentityCapture({
        email: "host-global@example.test",
        name: "Host Global",
      }),
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, true, {});

    expect(status).toBe(0);
    expect(fs.readFileSync(project.paths.gitConfigPath, "utf8")).toBe([
      "[worktree]",
      "\tuseRelativePaths = true",
      "[safe]",
      "\tdirectory = /workspace",
      "\tdirectory = /workspace/*",
      "\tdirectory = /runfree/git-layout",
      "\tdirectory = /runfree/git-layout/*",
      "[user]",
      "\tname = \"Host Global\"",
      "\temail = \"host-global@example.test\"",
      "",
    ].join("\n"));
  });

  test("up removes stale compose containers before starting Compose", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    let staleRemoved = false;
    const io = createRuntimeIO({
      capture(command, args) {
        if (
          command === "docker"
          && args[0] === "ps"
          && args[1] === "-aq"
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && !args.some((arg) => arg.includes("com.docker.compose.service="))
        ) {
          return captureResult(0, staleRemoved ? "fresh-id\n" : "stale-id\nfresh-id\n");
        }
        if (command === "docker" && args[0] === "inspect" && args.some((arg) => arg.includes("NetworkSettings.Networks"))) {
          const lines = [`fresh-id\t${projectName}_agent_internal`];
          if (!staleRemoved) lines.unshift("stale-id\twrong_default");
          return captureResult(0, [...lines, ""].join("\n"));
        }
        return undefined;
      },
      run(command, args) {
        if (command === "docker" && args[0] === "rm" && args.includes("stale-id")) staleRemoved = true;
        return 0;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    expect(io.calls).toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: ["rm", "-f", "stale-id"],
    }));
    expect(io.calls).not.toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: ["rm", "-f", "fresh-id"],
    }));
  });

  test("verbose proxy logs clear the proxy marker through root docker exec when log streaming fails", async () => {
    const fakeBin = path.join(tmp, "fake-bin");
    const logs = installFakeRuntimeCommands(fakeBin);
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    persistRuntimeNetwork(project, fixedNetwork);
    const env = useFakeRuntime(logs, {
      FAKE_COMPOSE_PROJECT: composeProjectName(projectRoot),
      FAKE_COMPOSE_CONTAINERS: `${FAKE_AGENT_CONTAINER_ID}\n`,
      FAKE_DOCKER_COMPOSE_STATUS: "17",
    });

    const status = await logsRuntime({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env,
    }, nodeRuntimeIO, { service: "proxy", verbose: true });

    expect(status).toBe(17);
    expect(readJsonLines(logs.markerLog)).toEqual([{ action: "set" }, { action: "clear" }]);
    const logsCall = readJsonLines(logs.dockerLog).find((entry) => Array.isArray(entry.args)
      && entry.args.includes("compose")
      && entry.args.includes("logs"));
    expect(logsCall?.env).toMatchObject({
      RUNFREE_SUBNET: fixedNetwork.subnet,
      RUNFREE_PROXY_IP: fixedNetwork.proxyIp,
      RUNFREE_CONTAINER_IP: fixedNetwork.agentIp,
      RUNFREE_PROXY_EGRESS_SUBNET: fixedNetwork.proxyEgressSubnet,
      RUNFREE_PROXY_EGRESS_GATEWAY: fixedNetwork.proxyEgressGateway,
      RUNFREE_PROXY_EGRESS_IP: fixedNetwork.proxyEgressIp,
    });
  });

  test("logs use the generated project runtime compose file when available", async () => {
    const fakeBin = path.join(tmp, "fake-bin");
    const logs = installFakeRuntimeCommands(fakeBin);
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    persistRuntimeNetwork(project, fixedNetwork);
    const generatedRuntimeRoot = path.join(project.paths.stateDir, "runtime");
    writeRuntimeAssets(generatedRuntimeRoot);
    const generatedComposeDir = path.join(generatedRuntimeRoot, "agent");
    const generatedComposeFile = path.join(generatedComposeDir, "compose.yaml");
    fs.writeFileSync(generatedComposeFile, "services:\n  proxy: {}\n");
    const env = useFakeRuntime(logs, {
      FAKE_COMPOSE_PROJECT: composeProjectName(projectRoot),
      FAKE_COMPOSE_CONTAINERS: `${FAKE_AGENT_CONTAINER_ID}\n`,
    });

    const status = await logsRuntime({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env,
    }, nodeRuntimeIO, { service: "proxy", verbose: false });

    expect(status).toBe(0);
    const logsCall = readJsonLines(logs.dockerLog).find((entry) => Array.isArray(entry.args)
      && entry.args.includes("compose")
      && entry.args.includes("logs"));
    expect(logsCall?.args).toEqual(expect.arrayContaining([
      "--project-directory",
      generatedComposeDir,
      "-f",
      generatedComposeFile,
      "logs",
      "-f",
      "proxy",
    ]));
  });

  test("stop refuses a live session before Compose down unless --force", async () => {
    // T5a for session protection during intentional proxy restarts: the
    // explicit stop entry point refuses under the lifecycle fence before any
    // disruptive step (no ingress-forwarder teardown, no Compose down) and
    // names the remedy; explicit --force then proceeds from a clean state.
    const fakeBin = path.join(tmp, "fake-bin");
    const logs = installFakeRuntimeCommands(fakeBin);
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    persistRuntimeNetwork(project, fixedNetwork);
    const env = useFakeRuntime(logs, {
      FAKE_COMPOSE_PROJECT: composeProjectName(projectRoot),
      FAKE_COMPOSE_CONTAINERS: `${FAKE_AGENT_CONTAINER_ID}\n`,
    });
    const projectId = projectHash(projectRoot);
    const composeProject = composeProjectName(projectRoot);
    const sessionId = "rf-20260906-live01";
    // The session's owner is this test process on this boot, so the guard
    // classifies it alive rather than as unknown residue.
    const bootId = hostBootId(env);
    const processStart = hostProcessStart(process.pid, env);
    const base = sessionContainerRecordFixture({
      containerId: "c".repeat(64),
      overrides: {
        projectId,
        composeProject,
        sessionId,
        containerName: `runfree-${projectId}-session-${sessionId}`,
        hostPid: process.pid,
        ...(bootId === undefined ? {} : { hostBootId: bootId }),
        ...(processStart === undefined ? {} : { hostProcessStart: processStart }),
        createdAt: "2026-09-06T19:00:00.000Z",
      },
    });
    writeSessionContainerRecordV2(project.paths.stateDir, { projectId, composeProject }, {
      ...base,
      state: "attached",
      admittedAt: "2026-09-06T19:00:00.000Z",
      leaseGeneration: "8".repeat(32),
      leaseExpiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    });
    const context = { projectRoot, project, runtimeRoot: path.join(tmp, "runtime"), env };
    const dockerCalls = () => (fs.existsSync(logs.dockerLog) ? readJsonLines(logs.dockerLog) : []);
    const composeDowns = () => dockerCalls().filter((entry) => Array.isArray(entry.args)
      && entry.args.includes("compose")
      && entry.args.includes("down"));
    const forwarderListings = () => dockerCalls().filter((entry) => Array.isArray(entry.args)
      && entry.args[0] === "ps"
      && entry.args.includes("label=io.runfree.container-role=ingress-forwarder"));

    await expect(stopRuntime(context, nodeRuntimeIO)).rejects.toThrow(
      `runfree stop refuses disruption while sessions or a lifecycle transaction remain: ${sessionId}`,
    );
    expect(composeDowns()).toHaveLength(0);
    expect(forwarderListings()).toHaveLength(0);

    // The refusal released the lifecycle lock and left no state behind:
    // explicit authorization proceeds through forwarder teardown to Compose down.
    expect(await stopRuntime(context, nodeRuntimeIO, { force: true })).toBe(0);
    expect(composeDowns()).toHaveLength(1);
    expect(forwarderListings().length).toBeGreaterThan(0);
  });

  test("stop passes the explicit Compose file with persisted runtime network env", async () => {
    const fakeBin = path.join(tmp, "fake-bin");
    const logs = installFakeRuntimeCommands(fakeBin);
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    persistRuntimeNetwork(project, fixedNetwork);
    const env = useFakeRuntime(logs, {
      FAKE_COMPOSE_PROJECT: composeProjectName(projectRoot),
      FAKE_COMPOSE_CONTAINERS: `${FAKE_AGENT_CONTAINER_ID}\n`,
    });

    const status = await stopRuntime({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env,
    }, nodeRuntimeIO);

    expect(status).toBe(0);
    const downCall = readJsonLines(logs.dockerLog).find((entry) => Array.isArray(entry.args)
      && entry.args.includes("compose")
      && entry.args.includes("down"));
    expect(downCall?.args).toEqual(expect.arrayContaining([
      "--project-directory",
      path.join(tmp, "runtime", "agent"),
      "-f",
      path.join(tmp, "runtime", "agent", "compose.yaml"),
      "down",
      "--remove-orphans",
    ]));
    expect(downCall?.env).toMatchObject({
      RUNFREE_SUBNET: fixedNetwork.subnet,
      RUNFREE_PROXY_IP: fixedNetwork.proxyIp,
      RUNFREE_CONTAINER_IP: fixedNetwork.agentIp,
      RUNFREE_PROXY_EGRESS_SUBNET: fixedNetwork.proxyEgressSubnet,
      RUNFREE_PROXY_EGRESS_GATEWAY: fixedNetwork.proxyEgressGateway,
      RUNFREE_PROXY_EGRESS_IP: fixedNetwork.proxyEgressIp,
    });
    // Stop tears down ingress forwarders before Compose down, so no dual-homed
    // sidecar or published loopback port outlives the runtime.
    const ingressList = readJsonLines(logs.dockerLog).find((entry) => Array.isArray(entry.args)
      && entry.args[0] === "ps"
      && entry.args.includes("label=io.runfree.container-role=ingress-forwarder"));
    expect(ingressList).toBeDefined();
  });

  test("stop uses the generated project runtime compose file when available", async () => {
    const fakeBin = path.join(tmp, "fake-bin");
    const logs = installFakeRuntimeCommands(fakeBin);
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    persistRuntimeNetwork(project, fixedNetwork);
    publishMaterializedRuntimeGenerationV1({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, {});
    const generatedRuntimeRoot = onlyMaterializedRuntimeRoot(project);
    const generatedComposeDir = path.join(generatedRuntimeRoot, "agent");
    const generatedComposeFile = path.join(generatedComposeDir, "compose.yaml");
    fs.writeFileSync(generatedComposeFile, "services:\n  proxy: {}\n");
    const env = useFakeRuntime(logs, {
      FAKE_COMPOSE_PROJECT: composeProjectName(projectRoot),
      FAKE_COMPOSE_CONTAINERS: `${FAKE_AGENT_CONTAINER_ID}\n`,
    });

    const status = await stopRuntime({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env,
    }, nodeRuntimeIO);

    expect(status).toBe(0);
    const downCall = readJsonLines(logs.dockerLog).find((entry) => Array.isArray(entry.args)
      && entry.args.includes("compose")
      && entry.args.includes("down"));
    expect(downCall?.args).toEqual(expect.arrayContaining([
      "--project-directory",
      generatedComposeDir,
      "-f",
      generatedComposeFile,
      "down",
      "--remove-orphans",
    ]));
  });
});

describe("token auto refresh invocation", () => {
  test("uses the current source script when running through node or tsx", () => {
    const invocation = resolveRunfreeSelfInvocation({
      argv: ["/usr/bin/node", "/repo/packages/cli/src/cli.ts", "claude"],
      execArgv: ["--import", "tsx"],
      execPath: "/usr/bin/node",
      existsSync: (filePath) => filePath === "/repo/packages/cli/src/cli.ts",
      sameExistingFile: () => false,
    });

    expect(invocation).toEqual({
      command: "/usr/bin/node",
      args: ["--import", "tsx", "/repo/packages/cli/src/cli.ts"],
    });
  });

  test("uses the executable directly when the argv script is the compiled binary", () => {
    const invocation = resolveRunfreeSelfInvocation({
      argv: ["/usr/local/bin/runfree", "/usr/local/bin/runfree", "claude"],
      execArgv: [],
      execPath: "/usr/local/bin/runfree",
      existsSync: (filePath) => filePath === "/usr/local/bin/runfree",
      sameExistingFile: () => true,
    });

    expect(invocation).toEqual({
      command: "/usr/local/bin/runfree",
      args: [],
    });
  });

  test("uses the executable directly when Bun reports its virtual bundled entrypoint", () => {
    const invocation = resolveRunfreeSelfInvocation({
      argv: ["/usr/local/bin/runfree", "/$bunfs/root/runfree", "codex"],
      execArgv: [],
      execPath: "/usr/local/bin/runfree",
      existsSync: (filePath) => filePath === "/$bunfs/root/runfree",
      sameExistingFile: () => false,
    });

    expect(invocation).toEqual({
      command: "/usr/local/bin/runfree",
      args: [],
    });
  });

  test("detaches from terminal and delays the first automatic refresh", () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);

    const plan = buildTokenAutoRefreshSpawnPlan({
      base: { command: "/usr/local/bin/runfree", args: [] },
      context: {
        projectRoot,
        project,
        runtimeRoot: path.join(tmp, "runtime"),
        env: { PATH: "/fake-bin", OP_SERVICE_ACCOUNT_TOKEN: "op-token" },
      },
      parentPid: 12345,
    });

    expect(plan.command).toBe("/usr/local/bin/runfree");
    expect(plan.args).toEqual([
      "--workspace",
      projectRoot,
      "credential",
      "sync",
      "--watch",
      "--quiet",
      "--delay-first-sync",
    ]);
    expect(plan.options.detached).toBe(process.platform !== "win32");
    expect(plan.options.stdio).toEqual(["ignore", "ignore", "ignore", "pipe"]);
    expect(plan.options.env).toMatchObject({
      OP_SERVICE_ACCOUNT_TOKEN: "op-token",
      RUNFREE_TOKEN_SYNC_WATCH_PARENT_PID: "12345",
      RUNFREE_TOKEN_SYNC_LIFETIME_FD: "3",
    });
    expect(plan.lifetimeFd).toBe(3);
    expect(plan.options.env).not.toHaveProperty("RUNFREE_TOKEN_SYNC_RECEIPT_FD");
  });

  test("passes token resolution receipts to the watcher over an inherited pipe", () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);

    const plan = buildTokenAutoRefreshSpawnPlan({
      base: { command: "/usr/local/bin/runfree", args: [] },
      context: {
        projectRoot,
        project,
        runtimeRoot: path.join(tmp, "runtime"),
        env: { PATH: "/fake-bin" },
      },
      parentPid: 12345,
      receipts: [{
        tokenName: "github",
        sourceFingerprint: "source-fingerprint",
        proxyStoreGeneration: "proxy-generation",
        resolvedAt: 1_771_200_000_000,
      }],
    });

    expect(plan.args).not.toContain("source-fingerprint");
    expect(plan.options.env).toMatchObject({
      RUNFREE_TOKEN_SYNC_RECEIPT_FD: "3",
      RUNFREE_TOKEN_SYNC_WATCH_PARENT_PID: "12345",
    });
    expect(JSON.stringify(plan.options.env)).not.toContain("source-fingerprint");
    expect(plan.options.stdio).toEqual(["ignore", "ignore", "ignore", "pipe", "pipe"]);
    expect(plan.receiptFd).toBe(3);
    expect(plan.lifetimeFd).toBe(4);
    expect(plan.options.env).toMatchObject({ RUNFREE_TOKEN_SYNC_LIFETIME_FD: "4" });
    expect(plan.receiptPayload).toContain("source-fingerprint");
  });
});

describe("runtime command flow", () => {
  test("up starts the runtime with direct Docker Compose and a sanitized command environment", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    let selectedAtTokenSync: ReturnType<typeof readEffectiveControlPlaneV2>;
    const io = createRuntimeIO({
      admin: async (args) => {
        if (args.join(" ") === "token sync") {
          selectedAtTokenSync = readEffectiveControlPlaneV2(project.paths.stateDir);
        }
        return 0;
      },
    });
    const ambientEnv = {
      PATH: "/runfree-test-bin",
      DOCKER_HOST: "unix:///tmp/runfree-test.sock",
      OP_SERVICE_ACCOUNT_TOKEN: "op-token",
      COMPOSE_PROJECT_NAME: "attacker-compose-project",
      RUNFREE_CLAUDE_DIR: "/attacker/claude",
      RUNFREE_EVIL: "/attacker/value",
    };

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: ambientEnv,
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    const generatedRuntimeRoot = onlyMaterializedRuntimeRoot(project);
    const composeDir = path.join(generatedRuntimeRoot, "agent");
    const composeFile = path.join(composeDir, "compose.yaml");
    const composeRun = composeUpCall(io);
    expect(composeRun?.args).toEqual([
      "compose",
      "--project-directory",
      composeDir,
      "-p",
      projectName,
      "-f",
      composeFile,
      "up",
      "-d",
      "--remove-orphans",
    ]);
    expect(composeRun?.env).toMatchObject({
      PATH: "/runfree-test-bin",
      DOCKER_HOST: "unix:///tmp/runfree-test.sock",
      RUNFREE_CLAUDE_DIR: project.paths.claudeDir,
      RUNFREE_COMPOSE_PROJECT_NAME: projectName,
      RUNFREE_PROXY_IMAGE: proxyRuntimeImageTag(),
      RUNFREE_SUBNET: fixedNetwork.subnet,
      DOCKER_CLI_HINTS: "false",
    });
    expect(composeRun?.env).not.toHaveProperty("COMPOSE_PROJECT_NAME");
    expect(composeRun?.env).not.toHaveProperty("OP_SERVICE_ACCOUNT_TOKEN");
    expect(composeRun?.env).not.toHaveProperty("RUNFREE_EVIL");
    expect(composeRun).toMatchObject({ cwd: composeDir });
    expect(selectedAtTokenSync?.selection).toMatchObject({
      proxyContainerId: FAKE_PROXY_CONTAINER_ID,
      proxyImageId: sha256Digest(proxyRuntimeImageTag()),
      networkIds: {
        agentInternal: FAKE_AGENT_INTERNAL_NETWORK_ID,
        proxyEgress: FAKE_PROXY_EGRESS_NETWORK_ID,
      },
    });
    const exactContainerInspections = io.calls.filter((call) => call.method === "capture"
      && call.command === "docker"
      && call.args[0] === "container"
      && call.args[1] === "inspect");
    const exactNetworkInspections = io.calls.filter((call) => call.method === "capture"
      && call.command === "docker"
      && call.args[0] === "network"
      && call.args[1] === "inspect"
      && call.args.includes(`${projectName}_agent_internal`)
      && call.args.includes(`${projectName}_proxy_egress`));
    const baseStateInspections = io.calls.filter((call) => call.method === "capture"
      && call.command === "docker"
      && call.args.includes(SESSION_ELIGIBILITY_PATH)
      && call.args.join(" ").includes("existsSync"));
    const sessionSetInspections = io.calls.filter((call) => call.method === "capture"
      && call.command === "docker"
      && call.args.join(" ").includes("nft -j list set inet runfree_proxy session_ipv4"));
    expect(exactContainerInspections).toHaveLength(5);
    expect(exactContainerInspections.every((call) => call.args.includes(FAKE_PROXY_CONTAINER_ID))).toBe(true);
    expect(exactNetworkInspections).toHaveLength(2);
    expect(baseStateInspections).toHaveLength(2);
    expect(sessionSetInspections).toHaveLength(2);
  });

  // A runtime materialized before the session-file cutover has a manifest with
  // no `sessionAdmissionSource`. That manifest is not "not files", it is
  // unreadable — so the durable selection it backs is refused, and `up` must
  // answer the refusal by materializing the control plane again rather than
  // wedging the project on state it can no longer parse.
  test("up recreates the control plane a pre-cutover materialization can no longer back", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const context: RuntimeContext = {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    };
    const io = createRuntimeIO();

    expect((await startRuntime(context, io, false, {})).status).toBe(0);
    const warm = readEffectiveControlPlaneV2(project.paths.stateDir);
    if (!warm) throw new Error("first startup did not publish the v2 control plane");

    // Republish the same control plane as its pre-cutover self: its own
    // content-addressed digest, its manifest without the one field the flip
    // made required, and the durable selection pointing at it.
    const legacyDigest = `sha256:${"9".repeat(64)}`;
    const { sessionAdmissionSource: _retired, ...legacy } = JSON.parse(fs.readFileSync(
      controlPlaneMaterializationManifestPathV2(
        project.paths.stateDir,
        warm.selection.controlPlaneMaterializationDigest,
      ),
      "utf8",
    )) as Record<string, unknown>;
    const legacyManifestPath = controlPlaneMaterializationManifestPathV2(project.paths.stateDir, legacyDigest);
    fs.mkdirSync(path.dirname(legacyManifestPath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      legacyManifestPath,
      `${JSON.stringify({ ...legacy, controlPlaneMaterializationDigest: legacyDigest })}\n`,
      { mode: 0o400 },
    );
    const selectionPath = controlPlaneEffectiveSelectionPathV2(project.paths.stateDir);
    fs.writeFileSync(selectionPath, `${JSON.stringify({
      ...warm.selection,
      controlPlaneMaterializationDigest: legacyDigest,
    })}\n`);
    expect(() => readEffectiveControlPlaneV2(project.paths.stateDir))
      .toThrow("v2 control-plane materialization manifest is invalid");

    // `up` refuses rather than starting against evidence it cannot read, and
    // names the command that reclaims it.
    expect(await up(context, io, false, {})).toBe(1);
    flushWarnings();
    const refusal = vi.mocked(console.error).mock.calls.flat().join("\n");
    expect(refusal).toContain("component evidence is invalid: v2 control-plane materialization manifest is invalid");
    expect(refusal).toContain("runfree rebuild");

    // And the named remedy is the reclamation: the control plane is
    // materialized again, carrying the field this CLI requires.
    vi.mocked(console.error).mockClear();
    expect(await up(context, createRuntimeIO(), true, {})).toBe(0);
    const recreated = readEffectiveControlPlaneV2(project.paths.stateDir);
    expect(recreated?.manifest.sessionAdmissionSource).toBe("files");
    expect(recreated?.selection.controlPlaneMaterializationDigest).not.toBe(legacyDigest);
  });

  test("up reuses a proxy-only warm runtime while a stale session record awaits admission recovery", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    const project = prepareProject(projectRoot);
    const context: RuntimeContext = {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    };
    const io = createRuntimeIO();

    const first = await startRuntime(context, io, false, {});
    expect(first.status).toBe(0);
    const desiredSessionAgent = readDesiredSessionAgentV2(project.paths.stateDir);
    const effectiveControlPlane = readEffectiveControlPlaneV2(project.paths.stateDir);
    if (!desiredSessionAgent || !effectiveControlPlane) {
      throw new Error("first startup did not publish the v2 runtime selections");
    }
    const allocated = createAllocatedSessionContainerRecordV2({
      sessionId: "rf-20260823-abcdef",
      displayName: "stale-session",
      command: "codex",
      launch: createSessionLaunchTarget({
        path: "/usr/local/bin/codex",
        args: ["--dangerously-bypass-approvals-and-sandbox"],
        interactive: true,
        tty: true,
      }),
      sourceIp: "172.31.90.20",
      materialization: desiredSessionAgent.manifest,
      effectiveControlPlane: effectiveControlPlane.selection,
      // A lapsed lease does not prove death. This record has a dead owner.
      hostPid: 99_999_999,
      createdAt: "2026-08-23T19:00:00.000Z",
    });
    const bound = bindAllocatedSessionContainerIdV2(allocated, "7".repeat(64));
    const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
      transitionBoundAllocatedSessionContainerToProvisioningRunningV2(bound, {
        admittedAt: "2026-08-23T19:00:00.000Z",
        leaseGeneration: "8".repeat(32),
        leaseExpiresAt: "2026-08-23T19:05:00.000Z",
      }),
    );
    writeSessionContainerRecordV2(project.paths.stateDir, {
      projectId: desiredSessionAgent.selection.projectId,
      composeProject: desiredSessionAgent.selection.composeProject,
    }, attached);

    const second = await startRuntime(context, io, false, {});
    expect(second.status).toBe(0);
    expect(second.fastPath).toBe(true);
    expect(io.calls.filter((call) => call.method === "run"
      && call.command === "docker"
      && call.args[0] === "compose"
      && call.args.includes("up"))).toHaveLength(1);
  });

  // The Docker operations one warm `up` issues, by category. A change that
  // removes a launch operation shows its reduction as a diff of this
  // snapshot; an unexplained increase is a regression, not a snapshot to
  // refresh.
  test("warm up Docker operation profile", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const context: RuntimeContext = {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    };
    const io = createRuntimeIO();
    expect((await startRuntime(context, io, false, {})).status).toBe(0);
    const warmStart = io.calls.length;
    const warm = await startRuntime(context, io, false, {});
    expect(warm.status).toBe(0);
    expect(warm.fastPath).toBe(true);
    expect(dockerOperationProfile(io.calls.slice(warmStart))).toMatchInlineSnapshot(`
      {
        "docker container inspect": 4,
        "docker container ls": 2,
        "docker exec": 12,
        "docker image inspect": 9,
        "docker info": 1,
        "docker inspect": 5,
        "docker network inspect": 3,
        "docker ps": 12,
        "docker run": 1,
        "docker volume create": 1,
        "docker volume inspect": 1,
      }
    `);
  });

  test("warm up reads the validation marker only for verbose output", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const context: RuntimeContext = {
      projectRoot, project, runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" }, network: fixedNetwork,
    };
    const io = createRuntimeIO();
    expect((await startRuntime(context, io, false, {})).status).toBe(0);
    const markerReads = (from: number) => io.calls.slice(from).filter((call) => call.method === "capture"
      && call.command === "docker" && call.args[0] === "exec"
      && call.args.includes("/run/runfree-runtime-validation.json") && call.args.includes("cat")).length;

    const quietStart = io.calls.length;
    expect((await startRuntime(context, io, false, {})).status).toBe(0);
    const verboseStart = io.calls.length;
    expect((await startRuntime(context, io, false, { verbose: true })).status).toBe(0);

    expect(markerReads(quietStart) - markerReads(verboseStart)).toBe(0);
    expect(markerReads(verboseStart)).toBe(1);
  });

  test("up refuses token sync when the final session-admission base-set proof is non-empty", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    const project = prepareProject(projectRoot);
    let sessionSetInspections = 0;
    const io = createRuntimeIO({
      capture(command, args) {
        if (command === "docker" && args.join(" ").includes("nft -j list set inet runfree_proxy session_ipv4")) {
          sessionSetInspections += 1;
          if (sessionSetInspections === 2) {
            return captureResult(0, JSON.stringify({
              nftables: [{ set: {
                family: "inet",
                table: "runfree_proxy",
                name: "session_ipv4",
                type: "ipv4_addr",
                elem: [fixedNetwork.agentIp],
              } }],
            }));
          }
        }
        return undefined;
      },
    });

    const status = await up({
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(sessionSetInspections).toBe(2);
    expect(readEffectiveControlPlaneV2(project.paths.stateDir)).toBeUndefined();
    expect(io.calls.some((call) => call.method === "admin" && call.args.join(" ") === "token sync")).toBe(false);
  });

  test("up refuses token sync when legacy selection persistence fails before v2 authority publication", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    const project = prepareProject(projectRoot);
    const dependencyPlanPath = path.join(project.paths.stateDir, "dependency-overlays.json");
    let blockedLegacySelection = false;
    const io = createRuntimeIO({
      capture(command, args) {
        if (!blockedLegacySelection
          && command === "docker"
          && args[0] === "exec"
          && args.join(" ").includes("cat >")
          && args.join(" ").includes("/run/runfree-runtime-validation.json")) {
          blockedLegacySelection = true;
          fs.rmSync(dependencyPlanPath, { force: true });
          fs.mkdirSync(dependencyPlanPath);
        }
        return undefined;
      },
    });

    const status = await up({
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(blockedLegacySelection).toBe(true);
    expect(readEffectiveControlPlaneV2(project.paths.stateDir)).toBeUndefined();
    expect(io.calls.some((call) => call.method === "admin" && call.args.join(" ") === "token sync")).toBe(false);
  });

  test("up contains lifecycle-lock replacement after live proof without publishing v2 authority", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    const project = prepareProject(projectRoot);
    const lifecycleLockPath = path.join(project.paths.stateDir, "runtime-lifecycle.lock");
    const displacedLockPath = `${lifecycleLockPath}.displaced`;
    let sessionSetInspections = 0;
    const io = createRuntimeIO({
      capture(command, args) {
        if (command === "docker" && args.join(" ").includes("nft -j list set inet runfree_proxy session_ipv4")) {
          sessionSetInspections += 1;
          if (sessionSetInspections === 2) {
            fs.renameSync(lifecycleLockPath, displacedLockPath);
            fs.mkdirSync(lifecycleLockPath);
          }
        }
        return undefined;
      },
    });

    const status = await up({
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(sessionSetInspections).toBe(2);
    expect(readEffectiveControlPlaneV2(project.paths.stateDir)).toBeUndefined();
    expect(fs.existsSync(lifecycleLockPath)).toBe(true);
    expect(fs.existsSync(displacedLockPath)).toBe(true);
    expect(io.calls.some((call) => call.method === "admin" && call.args.join(" ") === "token sync")).toBe(false);
  });

  test("admin runtime environment preserves host credential env while removing retired authority paths", () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    const project = prepareProject(projectRoot);

    const env = runtimeEnvironment(projectRoot, project, runtimeRoot, {
      HOME: "/host/home",
      OP_SERVICE_ACCOUNT_TOKEN: "op-token",
      RUNFREE_PROJECT_ROOT: "/attacker/project",
      RUNFREE_POLICY_DIR: "/attacker/policy",
      RUNFREE_TOKEN_CONFIG_PATH: "/attacker/tokens.json",
      PATH: "/usr/local/bin",
    }, fixedNetwork);

    expect(env.HOME).toBe("/host/home");
    expect(env.OP_SERVICE_ACCOUNT_TOKEN).toBe("op-token");
    expect(env.PATH).toBe("/usr/local/bin");
    expect(env.RUNFREE_PROJECT_ROOT).toBe(projectRoot);
    expect(env).not.toHaveProperty("RUNFREE_POLICY_DIR");
    expect(env).not.toHaveProperty("RUNFREE_TOKEN_CONFIG_PATH");
    expect(env.RUNFREE_SUBNET).toBe(fixedNetwork.subnet);
  });



  test("the in-process runtime admin rejects an unknown intent before any side effect", async () => {
    // The runtime only issues policy reload/token sync/prepare in-process. The
    // closed RuntimeAdminIntent union makes anything else a compile error; a
    // cast-in invalid intent must still be rejected before policy/token state is
    // touched (the defensive default branch).
    const projectRoot = path.join(tmp, "bad-admin");
    const project = prepareProject(projectRoot);

    await expect(
      nodeRuntimeIO.admin(
        { kind: "totally-bogus" } as unknown as RuntimeAdminIntent,
        { projectRoot, project, runtimeRoot: path.join(tmp, "runtime"), env: { PATH: "/fake-bin" }, network: fixedNetwork },
      ),
    ).rejects.toThrow("unsupported in-process runtime admin intent");
  });

  describe("resolveRuntimeAdminEnvironment: effective-control-gated admin env", () => {
    function adminContext(projectRoot: string, project: ProjectInfo): RuntimeContext {
      return { projectRoot, project, runtimeRoot: path.join(tmp, "runtime"), env: { PATH: "/fake-bin" }, network: fixedNetwork };
    }

    test("v4 ensure-agent-service without a selected control takes the minimal env, not the full runtime env", () => {
      // Reproduces the fresh-project launch order: reviewAgentOperationalServices
      // enables a required service through the admin seam BEFORE startRuntime
      // publishes and selects the first effective control generation. Building the
      // full runtime env here calls selectedAgentEnvironmentPath, which throws on a
      // v4 project with no selection. The authoring intent must instead take the
      // minimal env and never read the selected generation.
      const projectRoot = path.join(tmp, "fresh-ensure");
      const project = prepareProject(projectRoot);
      clearActiveControlSelection(project);

      const { env, activeEffective } = resolveRuntimeAdminEnvironment(
        { kind: "ensure-agent-service", id: "agent-claude", quiet: true },
        adminContext(projectRoot, project),
      );

      expect(activeEffective).toBeUndefined();
      expect(env.RUNFREE_PROJECT_ROOT).toBe(projectRoot);
      // The minimal env omits the runtime-network variables the full env carries;
      // their absence proves runtimeEnvironment (and its throwing generation read)
      // was never called.
      expect(env).not.toHaveProperty("RUNFREE_SUBNET");
    });

    test("v4 prepare without a selected control takes the minimal env", () => {
      const projectRoot = path.join(tmp, "fresh-prepare");
      const project = prepareProject(projectRoot);
      clearActiveControlSelection(project);

      const { env, activeEffective } = resolveRuntimeAdminEnvironment(
        { kind: "prepare" },
        adminContext(projectRoot, project),
      );

      expect(activeEffective).toBeUndefined();
      expect(env).not.toHaveProperty("RUNFREE_SUBNET");
    });

    test("v4 token-sync fails closed when no effective control is selected", () => {
      const projectRoot = path.join(tmp, "fresh-token-sync");
      const project = prepareProject(projectRoot);
      clearActiveControlSelection(project);

      expect(() =>
        resolveRuntimeAdminEnvironment({ kind: "token-sync", verbose: false }, adminContext(projectRoot, project)),
      ).toThrow("token-sync requires a selected effective policy generation");
    });

    test("v4 converge-proxy-policy fails closed when no effective control is selected", () => {
      // Regression guard: converge-proxy-policy is a real v4 intent — the MCP-rule
      // approval flow issues it right after a prepare that selects a generation —
      // so it must fail closed on a missing selection, not be rejected outright as
      // an unreachable v4 intent.
      const projectRoot = path.join(tmp, "fresh-converge");
      const project = prepareProject(projectRoot);
      clearActiveControlSelection(project);

      expect(() =>
        resolveRuntimeAdminEnvironment({ kind: "converge-proxy-policy" }, adminContext(projectRoot, project)),
      ).toThrow("converge-proxy-policy requires a selected effective policy generation");
    });

    test("v4 live intents take the full runtime env once a control is selected", () => {
      const projectRoot = path.join(tmp, "selected-live");
      const project = prepareProject(projectRoot); // publishes AND selects a generation

      for (const intent of [
        { kind: "token-sync", verbose: false },
        { kind: "converge-proxy-policy" },
      ] satisfies RuntimeAdminIntent[]) {
        const { env, activeEffective } = resolveRuntimeAdminEnvironment(intent, adminContext(projectRoot, project));
        expect(activeEffective).toBeDefined();
        expect(env.RUNFREE_SUBNET).toBe(fixedNetwork.subnet);
      }
    });

    test("v4 unknown intent takes the minimal env and defers rejection to dispatch", () => {
      const projectRoot = path.join(tmp, "unknown-intent-env");
      const project = prepareProject(projectRoot);
      clearActiveControlSelection(project);

      const { env } = resolveRuntimeAdminEnvironment(
        { kind: "totally-bogus" } as unknown as RuntimeAdminIntent,
        adminContext(projectRoot, project),
      );
      // An unknown intent is neither live nor authoring: no fail-closed throw, and
      // the minimal env leaves rejection to the dispatch default branch.
      expect(env).not.toHaveProperty("RUNFREE_SUBNET");
    });
  });

  test("runAgentCommand: an unknown agent name is an unknown-command error", async () => {
    const projectRoot = path.join(tmp, "unknown-agent");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO();

    await expect(
      runAgentCommand(
        { projectRoot, project, runtimeRoot: path.join(tmp, "runtime"), env: { PATH: "/fake-bin" }, network: fixedNetwork },
        io,
        "totally-bogus",
        { quiet: false, verbose: false },
      ),
    ).rejects.toThrow("unknown command: totally-bogus");
  });

  test("runAgentCommand: a configured custom agent is refused before any Docker command", async () => {
    // The refusal itself is a membership test against a frozen list of
    // built-ins, so it depends on nothing a runtime produces. It used to run
    // inside the launch, after `startRuntime`: `runfree <custom>` built the
    // whole runtime and only then reported that custom agents are unsupported
    // — measured at 5.5 s idle and 18.1 s under load in the live suite.
    //
    // Asserting the message alone cannot catch a regression to that ordering,
    // because the text is identical either way. The load-bearing assertion is
    // the empty Docker call list: a runtime was never started.
    const projectRoot = path.join(tmp, "custom-agent-refusal");
    const config = defaultConfig();
    config.agents = { ...config.agents, customTool: { command: "some-custom-tool" } };
    const project = prepareProject(projectRoot, config);
    const io = createRuntimeIO();

    await expect(
      runAgentCommand(
        { projectRoot, project, runtimeRoot: path.join(tmp, "runtime"), env: { PATH: "/fake-bin" }, network: fixedNetwork },
        io,
        "customTool",
        { quiet: false, verbose: false },
      ),
    ).rejects.toThrow("per-session launch supports only the built-in agents");

    expect(
      io.calls.filter((call) => call.command === "docker"),
      "the custom-agent refusal issued Docker commands, so it ran after startup rather than before it",
    ).toEqual([]);
    // Nothing else ran either: no approval read, no service review, no admin
    // intent. The gate is genuinely first, not merely ahead of Docker.
    expect(io.calls.map((call) => call.method), "the refusal did work before deciding").toEqual([]);
  });


  test("up does not start token auto refresh after initial token sync", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const autoRefreshLog = path.join(tmp, "up-token-auto-refresh.jsonl");
    const io = createRuntimeIO();

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: {
        PATH: "/fake-bin",
        RUNFREE_TEST_TOKEN_AUTO_REFRESH_LOG: autoRefreshLog,
      },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    expect(fs.existsSync(autoRefreshLog)).toBe(false);
  });


  test("up stops after admin prepare failure before touching Docker Compose", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      admin: async () => 42,
      capture: () => {
        throw new Error("Docker should not be touched after prepare fails");
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(42);
    expect(fs.existsSync(project.paths.claudeConfigPath)).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin")).toEqual([{ method: "admin", args: ["prepare"] }]);
    expect(composeUpCall(io)).toBeUndefined();
  });

  test("up skips token sync when Compose startup fails", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      run: (command, args) => command === "docker" && args[0] === "compose" && args.includes("up") ? 23 : 0,
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(23);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
    flushWarnings();
    const remedyLines = vi.mocked(console.error).mock.calls.flat().filter((line) => String(line).includes(COMPOSE_UP_FAILURE_REMEDY));
    expect(remedyLines).toHaveLength(1);
    expect(COMPOSE_UP_FAILURE_REMEDY).toContain("`runfree stop`");
    expect(COMPOSE_UP_FAILURE_REMEDY).toContain("`runfree up`");
    expect(COMPOSE_UP_FAILURE_REMEDY).toContain("`runfree rebuild`");
    expect(COMPOSE_UP_FAILURE_REMEDY).not.toContain("--yes");
  });

  test("up prints no Compose remedy when Compose startup succeeds", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO();

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    expect(composeUpCall(io)).toBeDefined();
    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n")).not.toContain(COMPOSE_UP_FAILURE_REMEDY);
  });

  test("rebuild prints no Compose remedy when Compose startup fails", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      run: (command, args) => command === "docker" && args[0] === "compose" && args.includes("up") ? 23 : 0,
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, true, {});

    expect(status).toBe(23);
    expect(composeUpCall(io)).toBeDefined();
    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n")).not.toContain(COMPOSE_UP_FAILURE_REMEDY);
  });

  test("up passes sanitized Docker client env through Docker checks and Compose launch", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const env = {
      DOCKER_HOST: "unix:///tmp/runfree-test.sock",
      PATH: "/runfree-test-bin",
    };
    const io = createRuntimeIO();

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env,
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    expect(io.calls.find((call) => call.method === "commandExists" && call.command === "docker")?.env).toMatchObject({
      DOCKER_HOST: "unix:///tmp/runfree-test.sock",
      PATH: "/runfree-test-bin",
      DOCKER_CLI_HINTS: "false",
    });
    expect(io.calls.find((call) => call.method === "capture" && call.command === "docker" && call.args[0] === "info")?.env).toMatchObject({
      DOCKER_HOST: "unix:///tmp/runfree-test.sock",
      PATH: "/runfree-test-bin",
      DOCKER_CLI_HINTS: "false",
    });
    const composeRun = composeUpCall(io);
    expect(composeRun?.env).toMatchObject({
      DOCKER_HOST: "unix:///tmp/runfree-test.sock",
      PATH: "/runfree-test-bin",
      RUNFREE_SUBNET: fixedNetwork.subnet,
      RUNFREE_PROXY_IP: fixedNetwork.proxyIp,
      RUNFREE_CONTAINER_IP: fixedNetwork.agentIp,
      RUNFREE_PROXY_EGRESS_SUBNET: fixedNetwork.proxyEgressSubnet,
      RUNFREE_PROXY_EGRESS_GATEWAY: fixedNetwork.proxyEgressGateway,
      RUNFREE_PROXY_EGRESS_IP: fixedNetwork.proxyEgressIp,
      RUNFREE_RUNTIME_DIGEST: effectiveRuntimeDigest(projectRoot, project.config),
      RUNFREE_VERSION,
    });
    expect(composeRun?.env).not.toHaveProperty("COMPOSE_PROJECT_NAME");
  });

  test("up rejects symlinked runtime policy files before starting the agent", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const visibleTarget = path.join(projectRoot, "visible-policy.json");
    fs.writeFileSync(visibleTarget, fs.readFileSync(project.paths.policyPath));
    fs.rmSync(project.paths.policyPath);
    fs.symlinkSync(path.relative(path.dirname(project.paths.policyPath), visibleTarget), project.paths.policyPath);
    const io = createRuntimeIO();

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n"))
      .toContain(".runfree/network-policy.json must be a regular, non-hard-linked file");
    expect(io.calls.filter((call) => call.method === "admin")).toEqual([]);
  });

  test("up rejects hard-linked runtime policy files for read-write projects", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    fs.linkSync(project.paths.policyPath, path.join(projectRoot, "policy-hardlink.json"));
    const io = createRuntimeIO();

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n"))
      .toContain(".runfree/network-policy.json must be a regular, non-hard-linked file");
    expect(io.calls.filter((call) => call.method === "admin")).toEqual([]);
  });

  test("agent launch refuses a legacy domains policy before rewriting it", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const legacy = `${JSON.stringify({ domains: ["api.openai.com"], tokens: {} }, null, 2)}\n`;
    fs.writeFileSync(project.paths.policyPath, legacy);

    const status = await runAgentCommand({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, createRuntimeIO(), "codex", { quiet: false, verbose: false });

    expect(status).toBe(1);
    expect(fs.readFileSync(project.paths.policyPath, "utf8")).toBe(legacy);
  });


  // Partial runtime loss: one container removed while the other survives. This
  // used to classify as unattestable evidence and refuse, so a project stayed
  // unstartable until someone rebuilt it by hand, while total loss recovered.

  // The recreate this path plans runs `compose down` before the validation gate
  // that would reject a foreign container, so the identity check has to happen
  // while that container still exists.

  test("up refuses duplicated proxy evidence before token sync instead of recreating", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const context = {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    } satisfies RuntimeContext;
    const desired = createRuntimePlan(context, { dockerSubnets: [], persistNetwork: false });
    const proxyImageId = sha256Digest("duplicate-proxy-image");
    const materialization = createControlPlaneMaterializationManifestV2({
      projectId: desired.projectId,
      composeProject: desired.composeProjectName,
      generation: desired.generationV2.controlPlane,
      proxyImageRef: proxyRuntimeImageTag(desired.generationV2.controlPlane.proxyImageInputDigest),
      proxyImageId,
      renderedControlPlaneSha256: desired.generationV2.controlPlane.controlPlaneTopologyDigest,
    
      sessionAdmissionSource: "files",
    });
    publishControlPlaneMaterializationV2(project.paths.stateDir, materialization);
    selectEffectiveControlPlaneV2(project.paths.stateDir, {
      schemaVersion: 2,
      projectId: desired.projectId,
      composeProject: desired.composeProjectName,
      controlPlaneGenerationDigest: desired.generationV2.controlPlane.controlPlaneGenerationDigest,
      controlPlaneMaterializationDigest: materialization.controlPlaneMaterializationDigest,
      proxyContainerId: FAKE_PROXY_CONTAINER_ID,
      proxyImageId,
      sidecarContainerIds: [],
      networkIds: { agentInternal: FAKE_AGENT_INTERNAL_NETWORK_ID, proxyEgress: FAKE_PROXY_EGRESS_NETWORK_ID },
      securityContractHash: sha256Digest("duplicate-proxy-security-contract"),
      proofSchemaVersion: CONTROL_PLANE_PROOF_SCHEMA_VERSION,
      admissionContractEpoch: desired.generationV2.controlPlane.admissionContractEpoch,
      denyByDefaultBaseProofHash: sha256Digest("duplicate-proxy-deny-proof"),
      selectedAt: "2026-08-27T00:00:00.000Z",
      runfreeVersion: RUNFREE_VERSION,
    });
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "ps"
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && args.includes("label=com.docker.compose.service=proxy")) {
          return captureResult(0, `${FAKE_PROXY_CONTAINER_ID}\n${"3".repeat(64)}\n`);
        }
        return undefined;
      },
    });

    const status = await up(context, io, false, {});

    expect(status).toBe(1);
    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n"))
      .toContain("the runtime did not start: component evidence is invalid: live proxy evidence is duplicated");
    // Two containers claim to be the proxy, so nothing may pick between them:
    // no teardown, no creation, and above all no credentials.
    expect(composeUpCall(io)).toBeUndefined();
    expect(io.calls).not.toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: expect.arrayContaining(["compose", "down"]),
    }));
    expect(io.calls).not.toContainEqual(expect.objectContaining({ method: "admin", args: ["token", "sync"] }));
  });



  test.each(["list", "inspect", "churn", "relist"])("up fails before persisting a network when Docker network discovery fails (%s)", async (failure) => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const networkStatePath = path.join(project.paths.stateDir, "runtime-network.json");
    let lists = 0;
    const io = createRuntimeIO({
      admin: async () => 0,
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "network" && args[1] === "ls") {
          lists += 1;
          return failure === "list" || (failure === "relist" && lists > 1)
            ? captureResult(19, "", "network list failed")
            : captureResult(0, "1395a4232aaa\n");
        }
        if (command === "docker" && args[0] === "network" && args[1] === "inspect") {
          return captureResult(1, "[]", failure === "inspect"
            ? "permission denied"
            : "Error response from daemon: network 1395a4232aaa not found");
        }
        return captureResult(0);
      },
    });

    await expect(up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
    }, io, false, {})).rejects.toThrow("could not inspect Docker networks");

    expect(fs.existsSync(networkStatePath)).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
    expect(io.calls.filter((call) => call.method === "run")).toEqual([]);
    expect(lists).toBe(failure === "churn" ? 3 : failure === "relist" ? 2 : 1);
  });

  test("up inspects only the current compose project for runtime freshness", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const otherProject = "runfree-otherproject";
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "ps" && args.some((arg) => arg.includes(`com.docker.compose.project=${projectName}`))) {
          return captureResult(0);
        }
        if (command === "docker" && args[0] === "ps" && args.some((arg) => arg.includes(`com.docker.compose.project=${otherProject}`))) {
          return captureResult(0, "stale-other-id\n");
        }
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    expect(io.calls).toContainEqual(expect.objectContaining({
      method: "capture",
      command: "docker",
      args: ["ps", "-aq", "--filter", `label=com.docker.compose.project=${projectName}`],
    }));
    expect(io.calls).not.toContainEqual(expect.objectContaining({
      method: "capture",
      command: "docker",
      args: expect.arrayContaining([`label=com.docker.compose.project=${otherProject}`]),
    }));
  });

  test("dry run reports a network without persisting runtime network state", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const networkStatePath = path.join(project.paths.stateDir, "runtime-network.json");
    // Dry run plans the same generation the real command would, which means
    // discovering overlays the way startup does: read-only Git queries are
    // expected, Docker calls are not.
    const io = createRuntimeIO({
      capture: (command) => {
        if (command === "docker") throw new Error("dry run should not inspect Docker");
        return undefined;
      },
    });

    const status = await runtimeDryRun({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: {
        RUNFREE_RUNTIME_DRY_RUN: "1",
        PATH: "/fake-bin",
      },
    }, io, "status");

    const [printed] = vi.mocked(console.log).mock.calls[0] ?? [];
    const dryRun = JSON.parse(String(printed)) as { network: RuntimeNetwork };
    expect(status).toBe(0);
    expect(dryRun.network.subnet).toMatch(/^172\.(30|31|28|29)\.\d+\.0\/24$/);
    expect(fs.existsSync(networkStatePath)).toBe(false);
    expect(io.calls).not.toContainEqual(expect.objectContaining({ command: "docker" }));
    expect(io.calls.every((call) => call.method === "capture" && call.command === "git")).toBe(true);
    const gitScans = io.calls.filter((call) => call.command === "git" && call.args.includes("ls-files"));
    expect(gitScans).toHaveLength(2);
    expect(gitScans.map((call) => call.args.slice(0, 2))).toEqual([
      ["-c", "core.fsmonitor="],
      ["-c", "core.fsmonitor="],
    ]);
  });

  test("status reports no migration action for retained v1 materialization state", () => {
    // The v1 materialization layout (generation.json / effective.json) is the
    // live runtime-files record, but the migrate-legacy-v1 planner arm is gone:
    // retained v1 state must not surface any migration action or evidence line.
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const context = {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    } satisfies RuntimeContext;
    publishMaterializedRuntimeGenerationV1(context, {});
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        return captureResult(0);
      },
    });

    expect(statusRuntime(context, io)).toBe(0);
    const output = vi.mocked(console.log).mock.calls.map((call) => call.join(" ")).join("\n");
    // The default view is the actionable posture with short digests; the
    // component/lifecycle dump sits behind --verbose.
    expect(output).not.toContain("launch behavior: per-session schema v2");
    expect(output).not.toMatch(/[0-9a-f]{64}/);
    expect(output).toContain("effective control plane: ");
    expect(output).toContain("runtime component and lifecycle detail: runfree status --verbose");
    expect(output).not.toContain("migrate legacy runtime state");
    expect(output).not.toContain("legacy v1 migration evidence");
    expect(output).toContain("next safe action: start the v2 runtime");
    // Session files are the only admission source, so the section is always
    // reported; with no runtime started it can only be unavailable.
    expect(output).toContain("session files: unavailable (proxy not running)");
    expect(output).not.toContain("Session files");

    vi.mocked(console.log).mockClear();
    expect(statusRuntime(context, io, { verbose: true })).toBe(0);
    const verbose = vi.mocked(console.log).mock.calls.map((call) => call.join(" ")).join("\n");
    expect(verbose).toContain("launch behavior: per-session schema v2");
    expect(verbose).toContain("next safe action: start the v2 runtime");
    expect(verbose).toContain("session files: unavailable (proxy not running)");
  });

  test("status surfaces open ingress forwarders", () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const context = {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    } satisfies RuntimeContext;
    const components = publishMaterializedRuntimeGenerationV1(context, {});
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        // The ingress-forwarder listing: two open forwards for this project.
        if (command === "docker" && args[0] === "ps"
          && args.includes("label=io.runfree.container-role=ingress-forwarder")) {
          return captureResult(0, `runfree-ingress-port-${projectHash(projectRoot)}-3000\nrunfree-ingress-port-${projectHash(projectRoot)}-8080\n`);
        }
        // The status container table reads `{{json .}}` rows.
        if (command === "docker" && args[0] === "ps" && args.includes("{{json .}}")) {
          return captureResult(0, `${JSON.stringify({ Names: `${projectName}-proxy-1`, Status: "Up 4 minutes", Image: `${projectName}-proxy` })}\n`);
        }
        if (command === "docker" && args[0] === "ps"
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && !args.some((arg) => arg.includes("com.docker.compose.service="))) {
          return captureResult(0, "agent-id\nproxy-id\n");
        }
        if (command === "docker" && args[0] === "inspect" && args.some((arg) => arg.includes("io.runfree.runtime-digest"))) {
          return captureResult(0, runtimeContainerLabelRows(components, {
            composeProject: projectName,
            projectId: projectHash(projectRoot),
          }, ["agent", "proxy"]));
        }
        return captureResult(0);
      },
    });

    expect(statusRuntime(context, io)).toBe(0);
    const output = vi.mocked(console.log).mock.calls.map((call) => call.join(" ")).join("\n");
    expect(output).toContain("ingress forwarders: 2 open");
    expect(output).toContain("NAME");
    expect(output).toMatch(new RegExp(`${projectName}-proxy-1\\s+Up 4 minutes\\s+${projectName}-proxy`));
    expect(output).not.toContain("\t");
  });

  /** Selects a `files`-backed effective control plane for `context`'s project. */
  function selectFileBackedControlPlaneForStatus(context: RuntimeContext, proxyContainerId: string): void {
    const stateDir = context.project.paths.stateDir;
    const projectId = projectHash(context.projectRoot);
    const composeProject = composeProjectName(context.projectRoot);
    const generation = createControlPlaneGenerationV2({
      projectId,
      composeProject,
      proxyImageInputDigest: sha256Digest("proxy-image-input"),
      controlPlaneTopologyDigest: sha256Digest("control-plane-topology"),
      admissionContractEpoch: 1,
    });
    const manifest = createControlPlaneMaterializationManifestV2({
      projectId,
      composeProject,
      generation,
      proxyImageRef: "runfree/proxy:test",
      proxyImageId: sha256Digest("proxy-image-id"),
      renderedControlPlaneSha256: generation.controlPlaneTopologyDigest,
      sessionAdmissionSource: "files",
    });
    publishControlPlaneMaterializationV2(stateDir, manifest);
    selectEffectiveControlPlaneV2(stateDir, {
      schemaVersion: 2,
      projectId,
      composeProject,
      controlPlaneGenerationDigest: generation.controlPlaneGenerationDigest,
      controlPlaneMaterializationDigest: manifest.controlPlaneMaterializationDigest,
      proxyContainerId,
      proxyImageId: manifest.proxyImageId,
      sidecarContainerIds: [],
      networkIds: { agentInternal: "8".repeat(64), proxyEgress: "9".repeat(64) },
      securityContractHash: sha256Digest("security-contract"),
      proofSchemaVersion: CONTROL_PLANE_PROOF_SCHEMA_VERSION,
      admissionContractEpoch: 1,
      denyByDefaultBaseProofHash: sha256Digest("deny-by-default-base-proof"),
      selectedAt: "2026-09-07T11:59:00.000Z",
      runfreeVersion: "0.3.0",
    });
  }

  test("formats one session-file status line per the proxy's own verdict", () => {
    const served = "a".repeat(64);
    expect(formatSessionFileStatusLine({
      sessionKey: served,
      name: `${served}.json`,
      sourceIp: "172.31.90.10",
      malformed: false,
      aliveUntil: "2026-09-07T12:05:00.000Z",
      eligible: true,
      wallActive: true,
    })).toBe(`${served}: served until 2026-09-07T12:05:00.000Z`);

    const ineligible = "b".repeat(64);
    expect(formatSessionFileStatusLine({
      sessionKey: ineligible,
      name: `${ineligible}.json`,
      sourceIp: "172.31.90.11",
      malformed: false,
      aliveUntil: "2026-09-07T12:05:00.000Z",
      eligible: false,
      wallActive: true,
    })).toBe(`${ineligible}: on disk, not served (ineligible)`);

    const expired = "c".repeat(64);
    expect(formatSessionFileStatusLine({
      sessionKey: expired,
      name: `${expired}.json`,
      sourceIp: "172.31.90.12",
      malformed: false,
      aliveUntil: "2026-08-01T00:00:00.000Z",
      eligible: true,
      wallActive: false,
    })).toBe(`${expired}: on disk, not served (expired)`);

    expect(formatSessionFileStatusLine({
      name: "notes.json",
      malformed: true,
    })).toBe("notes.json: on disk, not served (malformed)");
  });

  test("status lists served and not-served session files under the files source", () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const context = {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    } satisfies RuntimeContext;
    publishMaterializedRuntimeGenerationV1(context, {});
    const proxyContainerId = "7".repeat(64);
    selectFileBackedControlPlaneForStatus(context, proxyContainerId);
    const servedKey = "a".repeat(64);
    const expiredKey = "b".repeat(64);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "ps" && args.includes("-q") && args.includes("--no-trunc")
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && args.includes("label=com.docker.compose.service=proxy")) {
          return captureResult(0, `${proxyContainerId}\n`);
        }
        if (command === "docker" && args[0] === "exec" && args[4] === proxyContainerId) {
          return captureResult(0, `${JSON.stringify([
            { sessionKey: servedKey, sourceIp: "172.31.90.10", aliveUntil: "2026-09-07T12:05:00.000Z", nonce: "a".repeat(32), eligible: true, wallActive: true },
            { sessionKey: expiredKey, sourceIp: "172.31.90.11", aliveUntil: "2026-08-01T00:00:00.000Z", nonce: "b".repeat(32), eligible: true, wallActive: false },
          ])}\n`);
        }
        return captureResult(0);
      },
    });

    expect(statusRuntime(context, io)).toBe(0);
    const output = vi.mocked(console.log).mock.calls.map((call) => call.join(" ")).join("\n");
    expect(output).toContain("Session files:");
    expect(output).toContain(`${servedKey}: served until 2026-09-07T12:05:00.000Z`);
    expect(output).toContain(`${expiredKey}: on disk, not served (expired)`);
  });

  test("status reports session files unavailable when the proxy is not running", () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const context = {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    } satisfies RuntimeContext;
    publishMaterializedRuntimeGenerationV1(context, {});
    selectFileBackedControlPlaneForStatus(context, "7".repeat(64));
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        // No running proxy container for this project: status must report,
        // not throw or hang.
        if (command === "docker" && args[0] === "ps" && args.includes("-q") && args.includes("--no-trunc")
          && args.includes("label=com.docker.compose.service=proxy")) {
          return captureResult(0, "");
        }
        return captureResult(0);
      },
    });

    expect(statusRuntime(context, io)).toBe(0);
    const output = vi.mocked(console.log).mock.calls.map((call) => call.join(" ")).join("\n");
    expect(output).toContain("session files: unavailable (");
    expect(output).not.toContain("Session files:");
  });

  test("status reports session files unavailable when the served-set read fails", () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const context = {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    } satisfies RuntimeContext;
    publishMaterializedRuntimeGenerationV1(context, {});
    const proxyContainerId = "7".repeat(64);
    selectFileBackedControlPlaneForStatus(context, proxyContainerId);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "ps" && args.includes("-q") && args.includes("--no-trunc")
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && args.includes("label=com.docker.compose.service=proxy")) {
          return captureResult(0, `${proxyContainerId}\n`);
        }
        // The served-set read fails outright.
        if (command === "docker" && args[0] === "exec" && args[4] === proxyContainerId) {
          return captureResult(1, "", "no such container");
        }
        return captureResult(0);
      },
    });

    expect(statusRuntime(context, io)).toBe(0);
    const output = vi.mocked(console.log).mock.calls.map((call) => call.join(" ")).join("\n");
    expect(output).toContain("session files: unavailable (");
    expect(output).not.toContain("Session files:");
  });

  test("resources lists Docker resources scoped to the project", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const projectId = projectHash(projectRoot);
    const json = (rows: Array<Record<string, string>>) => `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`;
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        // Every list command reads structured rows; only `image inspect` differs.
        if (command === "docker" && ["ps", "network", "volume"].includes(args[0] ?? "")) expect(args).toContain("{{json .}}");
        if (command === "docker" && args[0] === "image" && args[1] === "ls") expect(args).toContain("{{json .}}");
        if (command === "docker" && args[0] === "ps") {
          expect(args).toContain(`label=io.runfree.project-id=${projectId}`);
          expect(args).toContain(`label=com.docker.compose.project=${projectName}`);
          return captureResult(0, json([
            {
              Names: `runfree-session-${projectId}-rf-20260827-example`,
              Status: "Up 2 minutes",
              Image: "runfree/agent-runtime:abc123",
              Labels: `com.docker.compose.service=session-agent,io.runfree.runtime-digest=sha256:runtime,com.docker.compose.project.config_files=a.yml,b.yml`,
            },
            {
              Names: `${projectName}-proxy-1`,
              Status: "Exited (0)",
              Image: `${projectName}-proxy`,
              Labels: "com.docker.compose.service=proxy,io.runfree.runtime-digest=sha256:runtime",
            },
          ]));
        }
        if (command === "docker" && args[0] === "network" && args[1] === "ls") {
          expect(args).toContain(`label=com.docker.compose.project=${projectName}`);
          return captureResult(0, json([
            { Name: `${projectName}_agent_internal`, Driver: "bridge", Scope: "local" },
            { Name: `${projectName}_proxy_egress`, Driver: "bridge", Scope: "local" },
          ]));
        }
        if (command === "docker" && args[0] === "volume" && args[1] === "ls") {
          if (args.includes(`label=com.docker.compose.project=${projectName}`)) {
            return captureResult(0, json([
              { Name: `${projectName}_runfree-commandhistory`, Driver: "local", Scope: "local" },
              { Name: `runfree-deps-${projectId}-root-node-modules`, Driver: "local", Scope: "local" },
              { Name: `${projectName}_runfree-oauth-state`, Driver: "local", Scope: "local" },
            ]));
          }
          if (args.includes(`name=runfree-deps-${projectId}-`)) {
            return captureResult(0, json([
              { Name: `runfree-deps-${projectId}-root-node-modules`, Driver: "local", Scope: "local" },
              { Name: `runfree-deps-${projectId}-npm-cache`, Driver: "local", Scope: "local" },
              { Name: `not-runfree-deps-${projectId}-leak`, Driver: "local", Scope: "local" },
            ]));
          }
        }
        if (command === "docker" && args[0] === "image" && args[1] === "ls") {
          if (args.includes(`label=io.runfree.project-id=${projectId}`)) {
            return captureResult(0, json([
              { Repository: "runfree/agent-runtime", Tag: "abc123", ID: "img-runtime", CreatedSince: "2 hours ago", Size: "1.2GB" },
              { Repository: `${projectName}-proxy`, Tag: "latest", ID: "img-proxy", CreatedSince: "2 hours ago", Size: "420MB" },
              { Repository: "<none>", Tag: "<none>", ID: "img-dangling", CreatedSince: "3 hours ago", Size: "1MB" },
            ]));
          }
        }
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") {
          // Dangling `<none>:<none>` refs are never passed to inspect.
          expect(args).toEqual([
            "image",
            "inspect",
            "--format",
            "{{json .Config.Labels}}",
            "runfree/agent-runtime:abc123",
            `${projectName}-proxy:latest`,
          ]);
          return captureResult(0, [
            JSON.stringify({ "io.runfree.image-role": "agent-runtime", "io.runfree.runtime-digest": "sha256:runtime" }),
            JSON.stringify({ "io.runfree.image-role": "proxy-runtime", "io.runfree.runtime-digest": "sha256:runtime" }),
            "",
          ].join("\n"));
        }
        return captureResult(0);
      },
    });

    const status = await resourcesRuntime({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io);

    expect(status).toBe(0);
    const output = vi.mocked(console.log).mock.calls.map((call) => call.join(" ")).join("\n");
    expect(output).toContain(`project: ${projectName}`);
    expect(output).toContain(`project id: ${projectId}`);
    expect(output).not.toContain("\t");
    expect(output).toMatch(new RegExp(`runfree-session-${projectId}-rf-20260827-example\\s+Up 2 minutes\\s+runfree/agent-runtime:abc123\\s+session-agent\\s+sha256:runtime`));
    expect(output).toMatch(new RegExp(`${projectName}-proxy-1\\s+Exited \\(0\\)\\s+${projectName}-proxy\\s+proxy\\s+sha256:runtime`));
    expect(output).toContain(`${projectName}_agent_internal  bridge  local`);
    expect(output).toMatch(new RegExp(`${projectName}_runfree-commandhistory\\s+local\\s+local\\s+compose`));
    expect(output).toMatch(new RegExp(`runfree-deps-${projectId}-root-node-modules\\s+local\\s+local\\s+dependency-overlay`));
    expect(output).not.toMatch(new RegExp(`runfree-deps-${projectId}-root-node-modules\\s+local\\s+local\\s+compose`));
    expect(output).not.toContain(`not-runfree-deps-${projectId}-leak`);
    expect(output).toMatch(/runfree\/agent-runtime:abc123\s+img-runtime\s+2 hours ago\s+1\.2GB\s+agent-runtime\s+sha256:runtime/);
    expect(output).toMatch(/<none>:<none>\s+img-dangling\s+3 hours ago\s+1MB/);
  });

  test("up aborts when stale compose container removal fails", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "ps"
          && args.some((arg) => arg.includes(`com.docker.compose.project=${projectName}`))) {
          if (args.some((arg) => arg.includes("com.docker.compose.service="))) return captureResult(0);
          return captureResult(0, "stale-id\n");
        }
        if (command === "docker" && args[0] === "inspect" && args.some((arg) => arg.includes("NetworkSettings.Networks"))) {
          return captureResult(0, "stale-id\twrong_default\n");
        }
        if (command === "docker" && args[0] === "inspect") return captureResult(0, "wrong_default\n");
        return captureResult(0);
      },
      run: (command, args) => {
        if (command === "docker" && args[0] === "rm") return 17;
        return 0;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(17);
  });

  test("up accepts exposed-but-unpublished proxy ports before token sync", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(31);
  });

  test("up rejects loopback-only published agent TCP ports before token sync", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        if (command === "docker" && args[0] === "inspect" && args.includes(FAKE_PROXY_CONTAINER_ID) && !args.includes("--format")) {
          return captureResult(0, JSON.stringify([
            {
              Id: FAKE_AGENT_CONTAINER_ID,
              Config: { User: "1000:1000" },
              HostConfig: {
                CapAdd: null,
                CapDrop: ["NET_ADMIN", "NET_RAW"],
                NetworkMode: `${projectName}_agent_internal`,
                PortBindings: { "47123/tcp": [{ HostIp: "127.0.0.1", HostPort: "47123" }] },
                SecurityOpt: ["no-new-privileges:true"],
              },
              NetworkSettings: {
                Ports: { "47123/tcp": [{ HostIp: "127.0.0.1", HostPort: "47123" }] },
                Networks: { [`${projectName}_agent_internal`]: { IPAddress: fixedNetwork.agentIp } },
              },
            },
            {
              Id: FAKE_PROXY_CONTAINER_ID,
              HostConfig: {
                CapAdd: ["NET_ADMIN"],
                CapDrop: ["NET_RAW"],
                NetworkMode: `${projectName}_agent_internal`,
                PortBindings: {},
                SecurityOpt: ["no-new-privileges:true"],
              },
              NetworkSettings: {
                Ports: { "8080/tcp": null },
                Networks: {
                  [`${projectName}_agent_internal`]: { IPAddress: fixedNetwork.proxyIp },
                  [`${projectName}_proxy_egress`]: { IPAddress: fixedNetwork.proxyEgressIp },
                },
              },
            },
          ]));
        }
        if (command === "docker" && args[0] === "exec" && args.includes(FAKE_PROXY_CONTAINER_ID) && args.join(" ").includes("CapBnd")) {
          return captureResult(0, "0000000000001000\n");
        }
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.some((call) => call.method === "admin" && call.args.join(" ") === "token sync")).toBe(false);
  });

  test("up reuses the persisted runtime network while its own Docker networks are active", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    fs.mkdirSync(project.paths.stateDir, { recursive: true });
    fs.writeFileSync(
      path.join(project.paths.stateDir, "runtime-network.json"),
      `${JSON.stringify(fixedNetwork, null, 2)}\n`,
    );
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        if (command === "docker" && args[0] === "network" && args[1] === "ls") {
          return captureResult(0, "own-agent-internal\nown-proxy-egress\nforeign-network\n");
        }
        if (command === "docker" && args[0] === "network" && args[1] === "inspect" && args.includes("--format")) {
          return captureResult(0, [
            fixedNetwork.subnet,
            fixedNetwork.proxyEgressSubnet,
            "172.31.200.0/24",
            "",
          ].join("\n"));
        }
        if (command === "docker" && args[0] === "network" && args[1] === "inspect" && args.includes("own-agent-internal")) {
          return captureResult(0, JSON.stringify([
            {
              Name: `${projectName}_agent_internal`,
              IPAM: { Config: [{ Subnet: fixedNetwork.subnet }] },
            },
            {
              Name: `${projectName}_proxy_egress`,
              IPAM: { Config: [{ Subnet: fixedNetwork.proxyEgressSubnet, Gateway: fixedNetwork.proxyEgressGateway }] },
            },
            {
              Name: "foreign-network",
              IPAM: { Config: [{ Subnet: "172.31.200.0/24" }] },
            },
          ]));
        }
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
    }, io, false, {});

    expect(status).toBe(31);
    expect(composeUpCall(io)?.env).toMatchObject({
      RUNFREE_SUBNET: fixedNetwork.subnet,
      RUNFREE_PROXY_IP: fixedNetwork.proxyIp,
      RUNFREE_CONTAINER_IP: fixedNetwork.agentIp,
      RUNFREE_PROXY_EGRESS_SUBNET: fixedNetwork.proxyEgressSubnet,
      RUNFREE_PROXY_EGRESS_GATEWAY: fixedNetwork.proxyEgressGateway,
      RUNFREE_PROXY_EGRESS_IP: fixedNetwork.proxyEgressIp,
    });
  });

  test("up refuses a mislabelled session named volume before syncing proxy-managed tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        // A pre-placed local volume that `docker volume create` reused keeps its
        // own labels, so it is not owned by this Compose project.
        if (command === "docker" && args[0] === "volume" && args[1] === "inspect") {
          return captureResult(0, JSON.stringify(args.slice(2).map((name) => ({
            Name: name,
            Driver: "local",
            Scope: "local",
            Mountpoint: `/var/lib/docker/volumes/${name}/_data`,
            Labels: { "com.docker.compose.project": "someone-else" },
            Options: {},
          }))));
        }
        return undefined;
      },
    });

    const status = await up({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    flushWarnings();
    const warningText = vi.mocked(console.error).mock.calls.flat().join("\n");
    expect(warningText).toContain("has invalid Compose ownership labels");
    expect(warningText).toContain("session named-volume setup failed");
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });

  test("up validates the runtime topology before syncing proxy-managed tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "inspect" && args.includes(FAKE_PROXY_CONTAINER_ID) && !args.includes("--format")) {
          return captureResult(0, JSON.stringify([
            {
              Id: FAKE_AGENT_CONTAINER_ID,
              HostConfig: { CapAdd: null, CapDrop: ["NET_ADMIN", "NET_RAW"], NetworkMode: `${projectName}_agent_internal`, PortBindings: {} },
              NetworkSettings: { Ports: {}, Networks: { [`${projectName}_agent_internal`]: { IPAddress: fixedNetwork.agentIp } } },
            },
            {
              Id: FAKE_PROXY_CONTAINER_ID,
              HostConfig: { NetworkMode: `${projectName}_agent_internal`, PortBindings: {} },
              NetworkSettings: {
                Ports: { "8080/tcp": null },
                Networks: {
                  [`${projectName}_agent_internal`]: { IPAddress: fixedNetwork.proxyIp },
                  [`${projectName}_proxy_egress`]: { IPAddress: fixedNetwork.proxyEgressIp },
                },
              },
            },
          ]));
        }
        if (command === "docker" && args[0] === "network" && args[1] === "inspect") {
          if (args.includes(`${projectName}_proxy_egress`)) {
            return captureResult(0, JSON.stringify([{
              Name: `${projectName}_proxy_egress`,
              Internal: false,
              EnableIPv6: false,
              IPAM: { Config: [{ Subnet: fixedNetwork.proxyEgressSubnet, Gateway: fixedNetwork.proxyEgressGateway }] },
              Containers: {
                [FAKE_PROXY_CONTAINER_ID]: { Name: `${projectName}-proxy-1` },
              },
            }]));
          }
          return captureResult(0, JSON.stringify([{
            Name: `${projectName}_agent_internal`,
            Internal: true,
            EnableIPv6: false,
            Options: { "com.docker.network.bridge.inhibit_ipv4": "true" },
            IPAM: { Config: [{ Subnet: fixedNetwork.subnet }] },
            Containers: {
              [FAKE_AGENT_CONTAINER_ID]: { Name: `${projectName}-agent-1` },
              [FAKE_PROXY_CONTAINER_ID]: { Name: `${projectName}-proxy-1` },
            },
          }]));
        }
        if (command === "docker"
          && args[0] === "exec"
          && args.includes(FAKE_AGENT_CONTAINER_ID)
          && args.join(" ").includes("/dev/tcp/1.1.1.1/443")) {
          return captureResult(0, "direct TCP egress unexpectedly connected\n");
        }
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n")).toContain("runtime topology validation failed");
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });

  // Startup waits for firewall readiness against one exact proxy, and only
  // afterwards fetches and validates the live nftables table that mints the
  // deny-by-default observation. Readiness therefore attests a container that
  // validation has not yet looked at, and Docker can recreate the proxy in
  // between. `expectedProxyId` threads the readiness identity into topology
  // validation and the marker write so a replacement cannot inherit its
  // predecessor's readiness.
  test("up refuses a proxy replaced between firewall readiness and live-table validation", async () => {
    // Readiness reads firewall.json alone; the admin convergence receipt reads
    // it together with request-proxy.json in one shell exec, so an exact
    // argument match is what separates the two.
    const isReadinessFirewallRead = (call: RuntimeIoCall): boolean => call.method === "capture"
      && call.command === "docker"
      && call.args[0] === "exec"
      && call.args.includes("cat")
      && call.args.includes("/run/runfree-proxy-status/firewall.json");
    const isLiveTableFetch = (call: RuntimeIoCall): boolean => call.method === "capture"
      && call.command === "docker"
      && call.args.join(" ").includes("nft -j list table inet runfree_proxy");

    // The window is real: a clean startup reads readiness first and fetches the
    // live table only afterwards. Without that order there is nothing for the
    // readiness identity to be carried across, and the guard below guards
    // nothing.
    const baselineRoot = path.join(tmp, "project");
    const baselineProject = prepareProject(baselineRoot);
    const baselineIo = createRuntimeIO();
    expect(await up({
      projectRoot: baselineRoot,
      project: baselineProject,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, baselineIo, false, {})).toBe(0);
    // Baseline also fixes what the refusal below has to withhold: a startup
    // that reaches the end publishes the durable selection sessions launch
    // against, in its own state directory.
    expect(readEffectiveControlPlaneV2(baselineProject.paths.stateDir)).toBeDefined();
    const readinessRead = baselineIo.calls.findIndex(isReadinessFirewallRead);
    const liveTableFetch = baselineIo.calls.findIndex(isLiveTableFetch);
    expect(readinessRead).toBeGreaterThanOrEqual(0);
    expect(liveTableFetch).toBeGreaterThan(readinessRead);

    // Now recreate the proxy inside that window: readiness observes the proxy
    // the fake answers for, and every service-container lookup after it
    // resolves a different exact identity.
    const replacedProxyId = "b".repeat(64);
    const projectRoot = path.join(tmp, "replaced-proxy", "project");
    const project = prepareProject(projectRoot);
    let readinessSettled = false;
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        if (isReadinessFirewallRead({ method: "capture", command, args })) {
          readinessSettled = true;
          return undefined;
        }
        if (readinessSettled
          && command === "docker"
          && args[0] === "ps"
          && args.some((arg) => arg.includes("com.docker.compose.service=proxy"))) {
          return captureResult(0, `${replacedProxyId}\n`);
        }
        return undefined;
      },
    });

    const status = await up({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n"))
      .toContain("proxy container changed after firewall readiness");
    // The refusal lands before the replacement's table is ever fetched, so no
    // deny-by-default observation is minted from it.
    expect(io.calls.some(isLiveTableFetch)).toBe(false);
    // And nothing downstream of validation ran: no proxy-managed token sync,
    // and no durable control-plane selection to launch sessions against.
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
    expect(readEffectiveControlPlaneV2(project.paths.stateDir)).toBeUndefined();
  });

  test("up rejects proxy nftables table without server-UID DNS denial before syncing tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        const text = args.join(" ");
        if (command === "docker" && args[0] === "exec" && text.includes("nft -j list table inet runfree_proxy")) {
          return captureResult(0, JSON.stringify({
            nftables: [
              { table: { family: "inet", name: "runfree_proxy" } },
              { set: { family: "inet", table: "runfree_proxy", name: "allowed_ipv4", type: "ipv4_addr" } },
              { chain: { family: "inet", table: "runfree_proxy", name: "input", type: "filter", hook: "input", prio: 0, policy: "drop" } },
              { chain: { family: "inet", table: "runfree_proxy", name: "output", type: "filter", hook: "output", prio: 0, policy: "drop" } },
              { chain: { family: "inet", table: "runfree_proxy", name: "forward", type: "filter", hook: "forward", prio: 0, policy: "drop" } },
            ],
          }));
        }
        return undefined;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });

  test("up rejects incomplete owned-table nftables proof before syncing tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        const text = args.join(" ");
        if (command === "docker" && args[0] === "exec" && text.includes("nft -j list table inet runfree_proxy")) {
          return captureResult(0, JSON.stringify({
            nftables: [
              { table: { family: "inet", name: "runfree_proxy" } },
              { set: { family: "inet", table: "runfree_proxy", name: "allowed_ipv4", type: "ipv4_addr" } },
            ],
          }));
        }
        return undefined;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
    expect(io.calls.some((call) => call.method === "capture"
      && call.command === "docker"
      && call.args.includes("0:0")
      && call.args.join(" ").includes("nft list ruleset"))).toBe(false);
  });

  test("up rejects proxy server nftables command access before syncing tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        const text = args.join(" ");
        if (
          command === "docker"
          && args[0] === "exec"
          && args.includes("1001:1001")
          && text.includes("nft list ruleset")
        ) {
          return captureResult(0, "table inet runfree_proxy {}\n");
        }
        return undefined;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });

  test("up rejects missing proxy nftables allowlist set before syncing tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        const text = args.join(" ");
        if (command === "docker" && args[0] === "exec" && text.includes("nft list set inet runfree_proxy allowed_ipv4")) {
          return captureResult(1, "", "Error: No such file or directory\n");
        }
        return undefined;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });

  test("up rejects broken proxy root Docker DNS after nftables install before syncing tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    // Every retry attempt fails: a persistently broken DNS path must still
    // fail closed before token sync despite the bounded probe retry.
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        const text = args.join(" ");
        if (
          command === "docker"
          && args[0] === "exec"
          && args.includes("0:0")
          && text.includes("@127.0.0.11 example.com")
        ) {
          return captureResult(1, "", "Docker DNS unreachable\n");
        }
        return undefined;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });

  test("up survives one transient proxy root Docker DNS failure via the bounded probe retry", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    let dnsAttempts = 0;
    const io = createRuntimeIO({
      capture: (command, args) => {
        const text = args.join(" ");
        if (
          command === "docker"
          && args[0] === "exec"
          && args.includes("0:0")
          && text.includes("@127.0.0.11 example.com")
        ) {
          dnsAttempts += 1;
          // First attempt rides the root batch (L5b): the allowlist section
          // passes while the DNS section loses one UDP query. Only the DNS
          // probe retries, solo — the second attempt is a bare exec.
          if (text.includes("RUNFREE_FIREWALL_SECTION")) {
            return captureResult(0, [
              "RUNFREE_FIREWALL_SECTION 0 exit=0",
              "table inet runfree_proxy {",
              "  set allowed_ipv4 {",
              "    type ipv4_addr",
              "    elements = { 140.82.112.5 }",
              "  }",
              "}",
              "RUNFREE_FIREWALL_SECTION_END 0",
              "RUNFREE_FIREWALL_SECTION 1 exit=1",
              "one lost UDP query",
              "RUNFREE_FIREWALL_SECTION_END 1",
              "",
            ].join("\n"));
          }
          return captureResult(0);
        }
        return undefined;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    expect(dnsAttempts).toBe(2);
  });

  test("up rejects proxy nftables OUTPUT chain without chain-local default drop before syncing tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        const text = args.join(" ");
        if (command === "docker" && args[0] === "exec" && text.includes("nft -j list table inet runfree_proxy")) {
          const table = JSON.parse(proxyNftablesTableJson()) as { nftables: Array<{ chain?: { name?: string; policy?: string } }> };
          for (const statement of table.nftables) {
            if (statement.chain?.name === "output") statement.chain.policy = "accept";
          }
          return captureResult(0, JSON.stringify(table));
        }
        return undefined;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });

  test("up rejects proxy nftables ingress rule with inverted agent match before syncing tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        const text = args.join(" ");
        if (command === "docker" && args[0] === "exec" && text.includes("nft -j list table inet runfree_proxy")) {
          const table = JSON.parse(proxyNftablesTableJson()) as {
            nftables: Array<{ rule?: { chain?: string; expr?: Array<{ match?: { left?: unknown; op?: string } }> } }>;
          };
          for (const statement of table.nftables) {
            const expr = statement.rule?.expr;
            const ipSourceMatch = expr?.find((entry) => {
              const payload = entry.match?.left && typeof entry.match.left === "object" && "payload" in entry.match.left
                ? (entry.match.left as { payload?: { field?: string; protocol?: string } }).payload
                : undefined;
              return statement.rule?.chain === "input" && payload?.protocol === "ip" && payload.field === "saddr";
            });
            if (ipSourceMatch?.match) {
              ipSourceMatch.match.op = "!=";
              break;
            }
          }
          return captureResult(0, JSON.stringify(table));
        }
        return undefined;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });

  test("up rejects proxy nftables egress rule with inverted allowlist match before syncing tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        const text = args.join(" ");
        if (command === "docker" && args[0] === "exec" && text.includes("nft -j list table inet runfree_proxy")) {
          const table = JSON.parse(proxyNftablesTableJson()) as {
            nftables: Array<{ rule?: { chain?: string; expr?: Array<{ match?: { left?: unknown; right?: unknown; op?: string } }> } }>;
          };
          for (const statement of table.nftables) {
            const expr = statement.rule?.expr;
            const allowlistMatch = expr?.find((entry) => {
              const payload = entry.match?.left && typeof entry.match.left === "object" && "payload" in entry.match.left
                ? (entry.match.left as { payload?: { field?: string; protocol?: string } }).payload
                : undefined;
              return statement.rule?.chain === "output"
                && payload?.protocol === "ip"
                && payload.field === "daddr"
                && entry.match?.right === "@allowed_ipv4";
            });
            if (allowlistMatch?.match) {
              allowlistMatch.match.op = "!=";
              break;
            }
          }
          return captureResult(0, JSON.stringify(table));
        }
        return undefined;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });

  test("up rejects a proxy default egress route whose source address is not the proxy_egress address", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        const text = args.join(" ");
        // Isolate the unprivileged route-inspection batch (no --user flag) from
        // the root nftables/DNS batch and the server-uid denial probes, which
        // both run under an explicit --user.
        if (
          command === "docker"
          && args[0] === "exec"
          && args.includes(FAKE_PROXY_CONTAINER_ID)
          && !args.includes("--user")
          && text.includes("RUNFREE_FIREWALL_SECTION")
          && text.includes("ip -o route get 1.1.1.1")
        ) {
          const sections = [
            { exit: 0, body: `${fixedNetwork.agentIp} dev eth0 src ${fixedNetwork.proxyIp} uid 1001` },
            // Wrong source address: not fixedNetwork.proxyEgressIp.
            { exit: 0, body: `1.1.1.1 via ${fixedNetwork.proxyEgressGateway} dev eth1 src 10.99.99.99 uid 1001` },
          ];
          return captureResult(0, `${sections.map((section, index) => [
            `RUNFREE_FIREWALL_SECTION ${index} exit=${section.exit}`,
            section.body,
            `RUNFREE_FIREWALL_SECTION_END ${index}`,
          ].join("\n")).join("\n")}\n`);
        }
        return undefined;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n")).toContain("must use proxy_egress address");
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });

  test("up rejects proxy NET_RAW capability before syncing tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      admin: async (args) => args[0] === "token" ? 31 : 0,
      capture: (command, args) => {
        if (command === "docker" && args[0] === "inspect" && args.includes(FAKE_PROXY_CONTAINER_ID) && !args.includes("--format")) {
          return captureResult(0, JSON.stringify([
            {
              Id: FAKE_AGENT_CONTAINER_ID,
              Config: { User: "1000:1000" },
              HostConfig: {
                CapAdd: null,
                CapDrop: ["NET_ADMIN", "NET_RAW"],
                NetworkMode: `${projectName}_agent_internal`,
                PortBindings: {},
                SecurityOpt: ["no-new-privileges:true"],
              },
              NetworkSettings: { Ports: {}, Networks: { [`${projectName}_agent_internal`]: { IPAddress: fixedNetwork.agentIp } } },
            },
            {
              Id: FAKE_PROXY_CONTAINER_ID,
              HostConfig: {
                CapAdd: ["NET_ADMIN", "NET_RAW"],
                CapDrop: null,
                NetworkMode: `${projectName}_agent_internal`,
                PortBindings: {},
                SecurityOpt: ["no-new-privileges:true"],
              },
              NetworkSettings: {
                Ports: { "8080/tcp": null },
                Networks: {
                  [`${projectName}_agent_internal`]: { IPAddress: fixedNetwork.proxyIp },
                  [`${projectName}_proxy_egress`]: { IPAddress: fixedNetwork.proxyEgressIp },
                },
              },
            },
          ]));
        }
        return undefined;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });


  test("up rejects published runtime host ports before syncing proxy-managed tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "inspect" && args.includes(FAKE_PROXY_CONTAINER_ID) && !args.includes("--format")) {
          return captureResult(0, JSON.stringify([
            {
              Id: FAKE_AGENT_CONTAINER_ID,
              HostConfig: { CapAdd: null, CapDrop: ["NET_ADMIN", "NET_RAW"], NetworkMode: `${projectName}_agent_internal`, PortBindings: {} },
              NetworkSettings: { Ports: {}, Networks: { [`${projectName}_agent_internal`]: { IPAddress: fixedNetwork.agentIp } } },
            },
            {
              Id: FAKE_PROXY_CONTAINER_ID,
              HostConfig: {
                NetworkMode: `${projectName}_agent_internal`,
                PortBindings: { "8080/tcp": [{ HostIp: "0.0.0.0", HostPort: "8080" }] },
              },
              NetworkSettings: {
                Ports: { "8080/tcp": [{ HostIp: "0.0.0.0", HostPort: "8080" }] },
                Networks: {
                  [`${projectName}_agent_internal`]: { IPAddress: fixedNetwork.proxyIp },
                  [`${projectName}_proxy_egress`]: { IPAddress: fixedNetwork.proxyEgressIp },
                },
              },
            },
          ]));
        }
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });

  test("up rejects non-loopback published agent ports before syncing proxy-managed tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "inspect" && args.includes(FAKE_PROXY_CONTAINER_ID) && !args.includes("--format")) {
          return captureResult(0, JSON.stringify([
            {
              Id: FAKE_AGENT_CONTAINER_ID,
              Config: { User: "1000:1000" },
              HostConfig: {
                CapAdd: null,
                CapDrop: ["NET_ADMIN", "NET_RAW"],
                NetworkMode: `${projectName}_agent_internal`,
                PortBindings: { "47123/tcp": [{ HostIp: "0.0.0.0", HostPort: "47123" }] },
                SecurityOpt: ["no-new-privileges:true"],
              },
              NetworkSettings: {
                Ports: { "47123/tcp": [{ HostIp: "0.0.0.0", HostPort: "47123" }] },
                Networks: { [`${projectName}_agent_internal`]: { IPAddress: fixedNetwork.agentIp } },
              },
            },
            {
              Id: FAKE_PROXY_CONTAINER_ID,
              HostConfig: { NetworkMode: `${projectName}_agent_internal`, PortBindings: {} },
              NetworkSettings: {
                Ports: { "8080/tcp": null },
                Networks: {
                  [`${projectName}_agent_internal`]: { IPAddress: fixedNetwork.proxyIp },
                  [`${projectName}_proxy_egress`]: { IPAddress: fixedNetwork.proxyEgressIp },
                },
              },
            },
          ]));
        }
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });



  test("up rejects an internal network with a bridge gateway before syncing proxy-managed tokens", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "network" && args[1] === "inspect") {
          if (args.includes(`${projectName}_proxy_egress`)) {
            return captureResult(0, JSON.stringify([{
              Name: `${projectName}_proxy_egress`,
              Internal: false,
              EnableIPv6: false,
              IPAM: { Config: [{ Subnet: fixedNetwork.proxyEgressSubnet, Gateway: fixedNetwork.proxyEgressGateway }] },
              Containers: {
                [FAKE_PROXY_CONTAINER_ID]: { Name: `${projectName}-proxy-1` },
              },
            }]));
          }
          return captureResult(0, JSON.stringify([{
            Name: `${projectName}_agent_internal`,
            Internal: true,
            EnableIPv6: false,
            Options: {},
            IPAM: { Config: [{ Subnet: fixedNetwork.subnet, Gateway: "172.31.90.1" }] },
            Containers: {
              [FAKE_AGENT_CONTAINER_ID]: { Name: `${projectName}-agent-1` },
              [FAKE_PROXY_CONTAINER_ID]: { Name: `${projectName}-proxy-1` },
            },
          }]));
        }
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });

  test("up reports stopped proxy logs and preserves runtime resources", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "inspect" && args.includes(FAKE_PROXY_CONTAINER_ID) && !args.includes("--format")) {
          // Post-cutover the topology inspects only the proxy; return exactly it.
          return captureResult(0, JSON.stringify([
            {
              Id: FAKE_PROXY_CONTAINER_ID,
              State: { Running: false, Status: "exited", ExitCode: 1 },
              HostConfig: { NetworkMode: `${projectName}_agent_internal`, PortBindings: {} },
              NetworkSettings: { Ports: { "8080/tcp": null }, Networks: {} },
            },
          ]));
        }
        if (command === "docker" && args[0] === "logs" && args.includes(FAKE_PROXY_CONTAINER_ID)) {
          return captureResult(0, "proxy-firewall: startup failed: could not identify interface for agent 172.31.90.11\n");
        }
        if (command === "docker" && args[0] === "network" && args[1] === "inspect") {
          if (args.includes(`${projectName}_proxy_egress`)) {
            return captureResult(0, JSON.stringify([{
              Name: `${projectName}_proxy_egress`,
              Internal: false,
              EnableIPv6: false,
              IPAM: { Config: [{ Subnet: fixedNetwork.proxyEgressSubnet, Gateway: fixedNetwork.proxyEgressGateway }] },
              Containers: {},
            }]));
          }
          return captureResult(0, JSON.stringify([{
            Name: `${projectName}_agent_internal`,
            Internal: true,
            EnableIPv6: false,
            Options: { "com.docker.network.bridge.inhibit_ipv4": "true" },
            IPAM: { Config: [{ Subnet: fixedNetwork.subnet }] },
            Containers: {
              [FAKE_PROXY_CONTAINER_ID]: { Name: `${projectName}-proxy-1` },
            },
          }]));
        }
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(1);
    flushWarnings();
    const warningText = vi.mocked(console.error).mock.calls.flat().join("\n");
    expect(warningText).toContain("proxy container is exited exit=1");
    expect(warningText).toContain("proxy-firewall: startup failed: could not identify interface");
    expect(warningText).not.toContain("proxy egress route inspection failed");
    expect(io.calls.some((call) => call.command === "docker" && call.args.includes("down"))).toBe(false);
    expect(io.calls.filter((call) => call.method === "admin").map((call) => call.args)).toEqual([["prepare"]]);
  });


  test("project agent base image build fails before docker build when runtime input lock is missing", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    fs.mkdirSync(path.join(projectRoot, ".runfree", "image"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".runfree", "image", "Dockerfile"), [
      "ARG RUNFREE_BASE_IMAGE",
      "FROM ${RUNFREE_BASE_IMAGE}",
      "",
    ].join("\n"));
    writeRuntimeAssets(runtimeRoot);
    fs.rmSync(path.join(runtimeRoot, "runtime-inputs.lock.json"));

    const config = {
      ...defaultConfig(),
      runtime: {
        agent: {
          build: {
            context: ".runfree/image",
            dockerfile: ".runfree/image/Dockerfile",
          },
        },
      },
    } satisfies RunfreeConfig;
    const project = prepareProject(projectRoot, config);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") return captureResult(1);
        return captureResult(0);
      },
    });

    await expect(up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {})).rejects.toThrow("runtime input lock missing");
    expect(io.calls.some((call) => call.method === "run" && call.command === "docker" && call.args[0] === "build")).toBe(false);
  });

  test("project agent base image build fails before docker build when runtime input lock is malformed", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    fs.mkdirSync(path.join(projectRoot, ".runfree", "image"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".runfree", "image", "Dockerfile"), [
      "ARG RUNFREE_BASE_IMAGE",
      "FROM ${RUNFREE_BASE_IMAGE}",
      "",
    ].join("\n"));
    writeRuntimeAssets(runtimeRoot);
    const lockPath = path.join(runtimeRoot, "runtime-inputs.lock.json");
    const lock = JSON.parse(fs.readFileSync(lockPath, "utf8")) as { images: { agentBase: { ref: string } } };
    lock.images.agentBase.ref = "ubuntu:26.04";
    fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

    const config = {
      ...defaultConfig(),
      runtime: {
        agent: {
          build: {
            context: ".runfree/image",
            dockerfile: ".runfree/image/Dockerfile",
          },
        },
      },
    } satisfies RunfreeConfig;
    const project = prepareProject(projectRoot, config);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") return captureResult(1);
        return captureResult(0);
      },
    });

    await expect(up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {})).rejects.toThrow("runtime input images.agentBase.ref must include @sha256:");
    expect(io.calls.some((call) => call.method === "run" && call.command === "docker" && call.args[0] === "build")).toBe(false);
  });

  test.each([
    {
      name: "snapshot apt source",
      mutate: (lock: Record<string, any>) => {
        lock.apt.sources.ubuntu.url = "http://snapshot.ubuntu.com/ubuntu/20260531T000000Z";
      },
      expected: "runtime input apt.sources.ubuntu.url must point at http://archive.ubuntu.com/ubuntu",
    },
    {
      name: "https apt bootstrap source",
      mutate: (lock: Record<string, any>) => {
        lock.apt.sources.ubuntu.url = "https://archive.ubuntu.com/ubuntu";
      },
      expected: "runtime input apt.sources.ubuntu.url must be an http URL",
    },
    {
      name: "apt source with port",
      mutate: (lock: Record<string, any>) => {
        lock.apt.sources.ubuntu.url = "http://archive.ubuntu.com:8080/ubuntu";
      },
      expected: "runtime input apt.sources.ubuntu.url must not include username, password, or port",
    },
    {
      name: "unexpected top-level field",
      mutate: (lock: Record<string, any>) => {
        lock.project = "not part of schema";
      },
      expected: "runtime input lock unexpected root.project",
    },
    {
      name: "unexpected GitHub CLI release URL",
      mutate: (lock: Record<string, any>) => {
        lock.releaseArtifacts.githubCli.linuxAmd64Deb.url = "https://example.com/gh.deb";
      },
      expected: "runtime input releaseArtifacts.githubCli.linuxAmd64Deb.url must point at /cli/cli/releases/download/v2.83.1/gh_2.83.1_linux_amd64.deb",
    },
    {
      name: "GitHub CLI release URL with userinfo",
      mutate: (lock: Record<string, any>) => {
        lock.releaseArtifacts.githubCli.linuxAmd64Deb.url = "https://user:pass@github.com/cli/cli/releases/download/v2.83.1/gh_2.83.1_linux_amd64.deb";
      },
      expected: "runtime input releaseArtifacts.githubCli.linuxAmd64Deb.url must not include username, password, or port",
    },
    {
      name: "unlocked pnpm package",
      mutate: (_lock: Record<string, any>, runtimeRoot: string) => {
        const packageLockPath = path.join(runtimeRoot, "agent", "agent-tools", "package-lock.json");
        const packageLock = JSON.parse(fs.readFileSync(packageLockPath, "utf8")) as Record<string, any>;
        packageLock.packages["node_modules/pnpm"].integrity = "";
        fs.writeFileSync(packageLockPath, `${JSON.stringify(packageLock, null, 2)}\n`);
      },
      expected: "runtime input lock missing agent/agent-tools/package-lock.json.packages[\"node_modules/pnpm\"].integrity",
    },
  ])("project agent base image build fails before docker build with $name", async ({ mutate, expected }) => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    fs.mkdirSync(path.join(projectRoot, ".runfree", "image"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".runfree", "image", "Dockerfile"), [
      "ARG RUNFREE_BASE_IMAGE",
      "FROM ${RUNFREE_BASE_IMAGE}",
      "",
    ].join("\n"));
    writeRuntimeAssets(runtimeRoot);
    const lockPath = path.join(runtimeRoot, "runtime-inputs.lock.json");
    const lock = JSON.parse(fs.readFileSync(lockPath, "utf8")) as Record<string, any>;
    mutate(lock, runtimeRoot);
    fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

    const config = {
      ...defaultConfig(),
      runtime: {
        agent: {
          build: {
            context: ".runfree/image",
            dockerfile: ".runfree/image/Dockerfile",
          },
        },
      },
    } satisfies RunfreeConfig;
    const project = prepareProject(projectRoot, config);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") return captureResult(1);
        return captureResult(0);
      },
    });

    await expect(up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {})).rejects.toThrow(expected);
    expect(io.calls.some((call) => call.method === "run" && call.command === "docker" && call.args[0] === "build")).toBe(false);
  });



  test("up builds a stale project agent image before tearing down the old runtime", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    fs.mkdirSync(path.join(projectRoot, ".runfree", "image"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".runfree", "image", "Dockerfile"), [
      "ARG RUNFREE_BASE_IMAGE",
      "FROM ${RUNFREE_BASE_IMAGE}",
      "",
    ].join("\n"));
    writeRuntimeAssets(runtimeRoot);

    const config = {
      ...defaultConfig(),
      runtime: {
        agent: {
          build: {
            context: ".runfree/image",
            dockerfile: ".runfree/image/Dockerfile",
          },
        },
      },
    } satisfies RunfreeConfig;
    const project = prepareProject(projectRoot, config);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "ps"
          && args.some((arg) => arg.includes(`com.docker.compose.project=${projectName}`))
          && !args.some((arg) => arg.includes("com.docker.compose.service="))) {
          return captureResult(0, "agent-id\nproxy-id\n");
        }
        if (command === "docker" && args[0] === "inspect" && args.some((arg) => arg.includes("io.runfree.runtime-digest"))) {
          return captureResult(0, "agent-id\tagent\tsha256:old-runtime\nproxy-id\tproxy\tsha256:old-runtime\n");
        }
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") return captureResult(1);
        return captureResult(0);
      },
      run: (command, args) => {
        if (command === "docker" && args[0] === "build") return 27;
        return 0;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(27);
    expect(io.calls).toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: expect.arrayContaining(["build"]),
    }));
    expect(io.calls).not.toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: expect.arrayContaining(["compose", "down"]),
    }));
  });

  test("rebuild never uses tag-based or broad prune image cleanup", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    fs.mkdirSync(path.join(projectRoot, ".runfree", "image"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".runfree", "image", "Dockerfile"), [
      "ARG RUNFREE_BASE_IMAGE",
      "FROM ${RUNFREE_BASE_IMAGE}",
      "",
    ].join("\n"));
    writeRuntimeAssets(runtimeRoot);

    const config = {
      ...defaultConfig(),
      runtime: {
        agent: {
          build: {
            context: ".runfree/image",
            dockerfile: ".runfree/image/Dockerfile",
          },
        },
      },
    } satisfies RunfreeConfig;
    const project = prepareProject(projectRoot, config);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") return captureResult(0);
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, true, {});

    expect(status).toBe(0);
    expect(io.calls).not.toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: expect.arrayContaining(["image", "prune"]),
    }));
  });

  test("rebuild runs fenced teardown when Compose discovery is empty", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") return captureResult(0);
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, true, {});

    expect(status).toBe(0);
    // The fake daemon reports no pre-existing Compose project. Rebuild must
    // still run its whole-project fenced inventory before the new Compose up.
    expect(io.calls).toContainEqual(expect.objectContaining({
      method: "capture",
      command: "docker",
      args: [
        "ps",
        "-aq",
        "--no-trunc",
        "--filter",
        `label=${PROJECT_ID_LABEL}=${projectHash(projectRoot)}`,
      ],
    }));
    expect(io.calls).not.toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: expect.arrayContaining(["build"]),
    }));
    expect(io.calls).toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: expect.arrayContaining(["compose", "down"]),
    }));
    expect(io.calls).toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: expect.arrayContaining(["compose", "up", "--force-recreate"]),
    }));
    expect(composeUpCall(io)?.args).not.toContain("--build");
  });


  test("up builds a missing tagged proxy runtime image before compose without compose build", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") {
          return captureResult(args[2] === proxyRuntimeImageTag() ? 1 : 0);
        }
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    // Quiet default (contract D7): the start line is the only progress line;
    // step-level progress sits behind --verbose. A larger budget here means a
    // new unconditional line slipped into the warm launch.
    const progressLines = vi.mocked(console.error).mock.calls.flat().map(String).filter((line) => / runfree: /.test(line));
    expect(progressLines).toHaveLength(1);
    expect(progressLines[0]).toContain("runfree: starting runtime");
    expect(vi.mocked(console.error).mock.calls.flat().join("\n")).not.toContain("topology:");
    const dockerBuilds = io.calls.filter((call) => call.method === "run" && call.command === "docker" && call.args[0] === "build");
    expect(dockerBuilds).toHaveLength(1);
    expect(dockerBuilds[0].args).toEqual(expect.arrayContaining([
      "--tag",
      proxyRuntimeImageTag(),
      "--label",
      "io.runfree.image-role=proxy-runtime",
      "--file",
      path.join(runtimeRoot, "proxy", "Dockerfile"),
      path.join(runtimeRoot, "proxy"),
    ]));
    expect(composeUpCall(io)?.args).not.toContain("--build");
  });

  test("up --verbose prints startup diagnostics and enables verbose token sync", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") return captureResult(0);
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, { verbose: true });

    expect(status).toBe(0);
    const output = vi.mocked(console.error).mock.calls.flat().join("\n");
    expect(output).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z runfree: starting runtime/);
    expect(output).toContain("runfree: starting runtime");
    expect(output).toContain("runfree: verbose: checking Docker CLI and daemon");
    expect(output).toContain("runfree: verbose: runtime agent image present:");
    expect(output).toContain("runfree: verbose: effective control plane");
    expect(output).toContain("runfree: verbose: upgrade action: none");
    expect(output).toContain("runfree: syncing proxy-managed tokens");
    expect(io.calls).toContainEqual(expect.objectContaining({
      method: "admin",
      args: ["token", "sync", "--verbose"],
    }));
  });

  test("up with RUNFREE_TIMINGS=1 emits startup-ops category lines that never carry the proxy container id", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") return captureResult(0);
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin", RUNFREE_TIMINGS: "1" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    const emittedLines = vi.mocked(console.error).mock.calls.flat().map(String);
    const timingLines = emittedLines.filter((line) => line.includes("timing: "));
    expect(timingLines.some((line) => line.includes("timing: startup-ops docker exec count="))).toBe(true);
    for (const line of timingLines) {
      expect(line).not.toContain(FAKE_PROXY_CONTAINER_ID);
    }
  });

  test("up reports a missing project agent Dockerfile before building images", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    fs.mkdirSync(projectRoot, { recursive: true });
    writeRuntimeAssets(runtimeRoot);

    const config = {
      ...defaultConfig(),
      runtime: {
        agent: {
          build: {
            context: ".",
            dockerfile: ".runfree/Dockerfile",
          },
        },
      },
    } satisfies RunfreeConfig;
    const project = prepareProject(projectRoot, config);
    const io = createRuntimeIO();

    await expect(up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {})).rejects.toThrow("agent Dockerfile not found: .runfree/Dockerfile");

    expect(io.calls).not.toContainEqual(expect.objectContaining({ method: "run", command: "docker" }));
  });

  test("rebuild forces project agent image builds without rebuilding the unchanged base image", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    fs.mkdirSync(path.join(projectRoot, ".runfree", "image"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".runfree", "image", "Dockerfile"), [
      "ARG RUNFREE_BASE_IMAGE",
      "FROM ${RUNFREE_BASE_IMAGE}",
      "",
    ].join("\n"));
    writeRuntimeAssets(runtimeRoot);

    const config = {
      ...defaultConfig(),
      runtime: {
        agent: {
          build: {
            context: ".runfree/image",
            dockerfile: ".runfree/image/Dockerfile",
          },
        },
      },
    } satisfies RunfreeConfig;
    const project = prepareProject(projectRoot, config);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") return captureResult(0);
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, true, {});

    expect(status).toBe(0);
    const dockerBuilds = io.calls.filter((call) => call.method === "run" && call.command === "docker" && call.args[0] === "build");
    expect(dockerBuilds).toHaveLength(1);
    expect(dockerBuilds[0].args).toEqual(expect.arrayContaining([
      "--label",
      "io.runfree.image-role=agent-project",
      "--build-arg",
      expect.stringMatching(/^RUNFREE_BASE_IMAGE=runfree\/agent-base:/),
    ]));
    expect(io.calls).toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: expect.arrayContaining(["compose", "up", "--force-recreate"]),
    }));
    expect(composeUpCall(io)?.args).not.toContain("--build");
  });

  test("wide project agent build fails closed without approval before docker build", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    fs.mkdirSync(path.join(projectRoot, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".runfree", "Dockerfile"), [
      "ARG RUNFREE_BASE_IMAGE",
      "FROM ${RUNFREE_BASE_IMAGE}",
      "",
    ].join("\n"));
    writeRuntimeAssets(runtimeRoot);

    const config = {
      ...defaultConfig(),
      runtime: {
        agent: {
          build: {
            context: ".",
            dockerfile: ".runfree/Dockerfile",
          },
        },
      },
    } satisfies RunfreeConfig;
    const project = prepareProject(projectRoot, config);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") return captureResult(1);
        return captureResult(0);
      },
    });

    await expect(up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {})).rejects.toThrow("pre-sandbox Docker build context approval is required");

    expect(io.calls).not.toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: expect.arrayContaining(["build"]),
    }));
  });

  test("interactive approval stores wide context approval and allows the build", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    fs.mkdirSync(path.join(projectRoot, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".runfree", "Dockerfile"), [
      "ARG RUNFREE_BASE_IMAGE",
      "FROM ${RUNFREE_BASE_IMAGE}",
      "",
    ].join("\n"));
    writeRuntimeAssets(runtimeRoot);

    const config = {
      ...defaultConfig(),
      runtime: {
        agent: {
          build: {
            context: ".",
            dockerfile: ".runfree/Dockerfile",
          },
        },
      },
    } satisfies RunfreeConfig;
    const project = prepareProject(projectRoot, config);
    const io = createRuntimeIO({
      confirm: (question) => question.includes("build context \".\""),
      capture: (command, args) => {
        if (command === "docker" && args[0] === "image" && args[1] === "inspect") return captureResult(1);
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    expect(fs.existsSync(path.join(project.paths.stateDir, "approved-build-contexts.json"))).toBe(true);
    const dockerBuilds = io.calls.filter((call) => call.method === "run" && call.command === "docker" && call.args[0] === "build");
    expect(dockerBuilds.at(-1)?.args).toEqual(expect.arrayContaining([
      "--file",
      path.join(projectRoot, ".runfree", "Dockerfile"),
      projectRoot,
    ]));
  });

  test("rebuild aborts by default when active agent sessions would be killed", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "ps"
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && args.includes("label=com.docker.compose.service=agent")) {
          return captureResult(0, "agent-id\n");
        }
        if (command === "docker" && args[0] === "exec" && args[1] === "-i" && args.includes("1000:1000") && args.includes(FAKE_AGENT_CONTAINER_ID)) {
          return captureResult(0, [
            "101\t/dev/pts/0\tzsh",
            "122\t/dev/pts/0\tclaude --dangerously-skip-permissions",
            "201\t/dev/pts/1\tnode /usr/bin/codex --dangerously-bypass-approvals-and-sandbox",
            "202\t/dev/pts/1\t/usr/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/codex/codex --dangerously-bypass-approvals-and-sandbox",
            "301\t/dev/pts/2\t/usr/local/bin/pi",
            "",
          ].join("\n"));
        }
        return captureResult(0);
      },
      confirm: () => {
        expect(fs.existsSync(path.join(project.paths.stateDir, "runtime-lifecycle.lock"))).toBe(false);
        return false;
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
    }, io, true, {});

    expect(status).toBe(1);
    flushWarnings();
    const warningText = vi.mocked(console.error).mock.calls.flat().join("\n");
    expect(warningText).toContain("runfree rebuild will recreate the runtime");
    expect(warningText).toContain(
      "legacy session claude code: claude --da 0 (/dev/pts/0): Claude Code: claude --dangerously-skip-permissions (2 processes)",
    );
    expect(warningText).toContain(
      "legacy session codex cli: codex --dange 1 (/dev/pts/1): Codex CLI: codex --dangerously-bypass-approvals-and-sandbox (2 processes)",
    );
    expect(warningText).toContain("legacy session pi: pi 2 (/dev/pts/2): Pi: pi");
    expect(warningText).not.toContain("@openai/codex");
    expect(warningText).toContain("rebuild aborted");
    expect(io.calls).toContainEqual({ method: "confirm", args: ["Continue with rebuild? [y/N] "] });
    const probeCall = io.calls.find((call) => call.method === "capture"
      && call.command === "docker"
      && call.args[0] === "exec"
      && call.args.includes(FAKE_AGENT_CONTAINER_ID));
    const probeScript = probeCall?.input;
    expect(probeCall?.args).toEqual(["exec", "-i", "--user", "1000:1000", FAKE_AGENT_CONTAINER_ID, "sh", "-s"]);
    expect(probeScript).toContain("\n");
    const syntax = childProcess.spawnSync("sh", ["-n"], { encoding: "utf8", input: probeScript ?? "" });
    expect(syntax.status, syntax.stderr).toBe(0);
  });

  test("rebuild warns about an attached per-session container after host metadata expires", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    const projectId = projectHash(projectRoot);
    const sessionId = "rf-20260824-longrun";
    const base = sessionContainerRecordFixture({
      containerId: "7".repeat(64),
      overrides: {
        projectId,
        composeProject: composeProjectName(projectRoot),
        sessionId,
        containerName: `runfree-${projectId}-session-${sessionId}`,
        displayName: "long-running codex",
        command: "codex",
        hostPid: process.pid,
        createdAt: "2026-08-24T00:00:00.000Z",
      },
    });
    writeSessionContainerRecordV2(project.paths.stateDir, {
      projectId,
      composeProject: composeProjectName(projectRoot),
    }, {
      ...base,
      state: "attached",
      admittedAt: "2026-08-24T00:00:00.000Z",
      leaseGeneration: "8".repeat(32),
      leaseExpiresAt: "2099-08-24T00:05:00.000Z",
    });
    const io = createRuntimeIO({ confirm: () => false });

    const status = await up({
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
    }, io, true, {});

    expect(status).toBe(1);
    flushWarnings();
    const warningText = vi.mocked(console.error).mock.calls.flat().join("\n");
    expect(warningText).toContain(`session ${sessionId}`);
    expect(warningText).toContain("long-running codex");
    expect(io.calls).toContainEqual({ method: "confirm", args: ["Continue with rebuild? [y/N] "] });
  });

  test("rebuild defers when a new active session appears before the lifecycle lock", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    let confirmationFinished = false;
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "ps"
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && args.includes("label=com.docker.compose.service=agent")) {
          return captureResult(0, "agent-id\n");
        }
        if (command === "docker" && args[0] === "exec" && args[1] === "-i"
          && args.includes("1000:1000") && args.includes(FAKE_AGENT_CONTAINER_ID)) {
          return captureResult(0, confirmationFinished
            ? "201\t/dev/pts/1\tcodex --dangerously-bypass-approvals-and-sandbox\n"
            : "101\t/dev/pts/0\tclaude --dangerously-skip-permissions\n");
        }
        return captureResult(0);
      },
      confirm: () => {
        expect(fs.existsSync(path.join(project.paths.stateDir, "runtime-lifecycle.lock"))).toBe(false);
        confirmationFinished = true;
        return true;
      },
    });

    const status = await up({
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
    }, io, true, {});

    expect(status).toBe(1);
    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n"))
      .toContain("a new active session appeared during preparation");
    expect(io.calls.some((call) => call.method === "run" && call.command === "docker"
      && call.args.includes("down"))).toBe(false);
  });

  test("rebuild accepts volatile process-count changes for the confirmed session", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    let confirmationFinished = false;
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "ps"
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && args.includes("label=com.docker.compose.service=agent")) {
          return captureResult(0, "agent-id\n");
        }
        if (command === "docker" && args[0] === "exec" && args[1] === "-i"
          && args.includes("1000:1000") && args.includes(FAKE_AGENT_CONTAINER_ID)) {
          return captureResult(0, confirmationFinished
            ? "101\t/dev/pts/0\tclaude --dangerously-skip-permissions\n102\t/dev/pts/0\tbash tool.sh\n"
            : "101\t/dev/pts/0\tclaude --dangerously-skip-permissions\n");
        }
        return captureResult(0);
      },
      confirm: () => {
        confirmationFinished = true;
        return true;
      },
    });

    await up({
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
    }, io, true, {});

    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n"))
      .not.toContain("a new active session appeared during preparation");
    expect(io.calls.some((call) => call.method === "run" && call.command === "docker"
      && call.args.includes("down"))).toBe(true);
  });

  test("rebuild --yes does not apply an interactive session recheck", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    let activeProbeCount = 0;
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "ps"
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && args.includes("label=com.docker.compose.service=agent")) {
          return captureResult(0, "agent-id\n");
        }
        if (command === "docker" && args[0] === "exec" && args[1] === "-i"
          && args.includes("1000:1000") && args.includes(FAKE_AGENT_CONTAINER_ID)) {
          activeProbeCount += 1;
          return captureResult(0, "101\t/dev/pts/0\tclaude --dangerously-skip-permissions\n");
        }
        return captureResult(0);
      },
      confirm: () => {
        throw new Error("--yes must not prompt");
      },
    });

    await up({
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
    }, io, true, { assumeYes: true });

    expect(activeProbeCount).toBe(1);
    expect(io.calls.some((call) => call.method === "run" && call.command === "docker"
      && call.args.includes("down"))).toBe(true);
  });


  test("codex refuses to start while a runtime lifecycle lock is held", async () => {
    process.env.FAKE_PREEXISTING_AGENT_ID = "1";
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const lockDir = path.join(project.paths.stateDir, "runtime-lifecycle.lock");
    fs.mkdirSync(lockDir, { recursive: true });
    fs.writeFileSync(path.join(lockDir, "pid"), `${process.pid}\n`);
    const io = createRuntimeIO();

    vi.useFakeTimers();
    let status: number;
    try {
      const pending = runAgentCommand( {
        projectRoot,
        project,
        runtimeRoot: path.join(tmp, "runtime"),
        env: { PATH: "/fake-bin" },
        network: fixedNetwork,
      }, io, "codex", { quiet: false, verbose: false });
      await vi.advanceTimersByTimeAsync(60_000);
      status = await pending;
    } finally {
      vi.useRealTimers();
    }

    expect(status).toBe(1);
    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n"))
      .toContain("another Runfree runtime lifecycle or control change is in progress");
    expect(configuredAgentExecCall(io)).toBeUndefined();
  });

  test("sessions lists active stamped sessions with host terminal metadata without starting runtime", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    fs.mkdirSync(project.paths.sessionsDir, { recursive: true });
    fs.writeFileSync(path.join(project.paths.sessionsDir, "rf-20260517-a1b2c3.json"), `${JSON.stringify({
      id: "rf-20260517-a1b2c3",
      projectRoot,
      composeProject: composeProjectName(projectRoot),
      command: "codex",
      agentCommand: "codex --dangerously-bypass-approvals-and-sandbox",
      hostPid: process.pid,
      hostParentPid: 48001,
      hostTty: "/dev/ttys004",
      termProgram: "iTerm.app",
      startedAt: "2026-05-17T14:32:05.000Z",
      lastSeenAt: "2026-05-17T14:32:05.000Z",
    })}\n`);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "ps"
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && args.includes("label=com.docker.compose.service=agent")) {
          return captureResult(0, "agent-id\n");
        }
        if (command === "docker" && args[0] === "exec" && args[1] === "-i" && args.includes("1000:1000") && args.includes(FAKE_AGENT_CONTAINER_ID)) {
          return captureResult(0, "201\t/dev/pts/1\trf-20260517-a1b2c3\t/usr/bin/codex --dangerously-bypass-approvals-and-sandbox\n");
        }
        return captureResult(0);
      },
    });

    const status = await sessionsRuntime({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
    }, io);

    expect(status).toBe(0);
    const output = vi.mocked(console.log).mock.calls.flat().join("\n");
    expect(output).not.toContain("\t");
    expect(output).toBe([
      "ID                  NAME                 COMMAND  HOST TTY      TERMINAL   STARTED  CONTAINER TTY",
      "rf-20260517-a1b2c3  codex ttys004 14:32  codex    /dev/ttys004  iTerm.app  14:32    /dev/pts/1",
    ].join("\n"));
    expect(composeUpCall(io)).toBeUndefined();
    expect(io.calls).not.toContainEqual(expect.objectContaining({ method: "admin" }));
  });

  test("sessions lists live per-session lifecycle sessions without a Compose agent", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const projectId = projectHash(projectRoot);
    const composeProject = composeProjectName(projectRoot);
    const sessionId = "rf-20260831-lcycle1";
    const base = sessionContainerRecordFixture({
      containerId: "c".repeat(64),
      overrides: {
        projectId,
        composeProject,
        sessionId,
        containerName: `runfree-${projectId}-session-${sessionId}`,
        hostPid: process.pid,
        createdAt: "2026-08-31T00:00:00.000Z",
      },
    });
    writeSessionContainerRecordV2(project.paths.stateDir, { projectId, composeProject }, {
      ...base,
      state: "attached",
      admittedAt: "2026-08-31T00:00:00.000Z",
      leaseGeneration: "8".repeat(32),
      leaseExpiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    });
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "ps" && args.includes("label=com.docker.compose.service=agent")) {
          return captureResult(0, "");
        }
        return captureResult(0);
      },
    });

    const status = await sessionsRuntime({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
    }, io);

    expect(status).toBe(0);
    const output = vi.mocked(console.log).mock.calls.flat().join("\n");
    expect(output).toContain(sessionId);
    expect(output).toContain(base.displayName);
    expect(output).toContain("<session-container>");
    expect(composeUpCall(io)).toBeUndefined();
  });

  test("sessions ignores host-detached stamped container sessions", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    fs.mkdirSync(project.paths.sessionsDir, { recursive: true });
    fs.writeFileSync(path.join(project.paths.sessionsDir, "rf-20260618-stale1.json"), `${JSON.stringify({
      id: "rf-20260618-stale1",
      projectRoot,
      composeProject: composeProjectName(projectRoot),
      command: "claude",
      agentCommand: "claude --dangerously-skip-permissions",
      hostPid: 99_999_999,
      hostTty: "/dev/ttys019",
      termProgram: "iTerm.app",
      startedAt: "2026-06-18T09:52:05.000Z",
      lastSeenAt: "2026-06-18T09:52:05.000Z",
    })}\n`);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "ps"
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && args.includes("label=com.docker.compose.service=agent")) {
          return captureResult(0, "agent-id\n");
        }
        if (command === "docker" && args[0] === "exec" && args[1] === "-i" && args.includes("1000:1000") && args.includes(FAKE_AGENT_CONTAINER_ID)) {
          return captureResult(0, "201\t/dev/pts/1\trf-20260618-stale1\t/usr/bin/claude --dangerously-skip-permissions\n");
        }
        return captureResult(0);
      },
    });

    const status = await sessionsRuntime({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
    }, io);

    expect(status).toBe(0);
    expect(vi.mocked(console.log).mock.calls.flat().join("\n")).toContain("no active Runfree sessions");
  });

  test("sessions reports no active sessions without starting runtime", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "ps" && args.includes("label=com.docker.compose.service=agent")) {
          return captureResult(0, "");
        }
        return captureResult(0);
      },
    });

    const status = await sessionsRuntime({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
    }, io);

    expect(status).toBe(0);
    expect(vi.mocked(console.log).mock.calls.flat().join("\n")).toContain("no active Runfree sessions");
    expect(composeUpCall(io)).toBeUndefined();
  });

  test("rebuild warning prefers stamped session metadata over container-local tty", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    fs.mkdirSync(project.paths.sessionsDir, { recursive: true });
    fs.writeFileSync(path.join(project.paths.sessionsDir, "rf-20260517-a1b2c3.json"), `${JSON.stringify({
      id: "rf-20260517-a1b2c3",
      projectRoot,
      composeProject: composeProjectName(projectRoot),
      command: "codex",
      agentCommand: "codex --dangerously-bypass-approvals-and-sandbox",
      hostPid: process.pid,
      hostTty: "/dev/ttys004",
      termProgram: "iTerm.app",
      startedAt: "2026-05-17T14:32:05.000Z",
      lastSeenAt: "2026-05-17T14:32:05.000Z",
    })}\n`);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "ps"
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && args.includes("label=com.docker.compose.service=agent")) {
          return captureResult(0, "agent-id\n");
        }
        if (command === "docker" && args[0] === "exec" && args[1] === "-i" && args.includes("1000:1000") && args.includes(FAKE_AGENT_CONTAINER_ID)) {
          return captureResult(0, "201\t/dev/pts/1\trf-20260517-a1b2c3\t/usr/bin/codex --dangerously-bypass-approvals-and-sandbox\n");
        }
        return captureResult(0);
      },
      confirm: () => false,
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
    }, io, true, {});

    expect(status).toBe(1);
    flushWarnings();
    const warningText = vi.mocked(console.error).mock.calls.flat().join("\n");
    expect(warningText).toContain(
      "session rf-20260517-a1b2c3 (codex ttys004 14:32): Codex CLI, host tty /dev/ttys004, iTerm.app, started 14:32",
    );
    expect(warningText).not.toContain("/dev/pts/1: Codex CLI");
    expect(warningText).toContain("rebuild aborted");
  });


  test("legacy host metadata does not replace the per-session proxy runtime", async () => {
    // The mirror of the test above: an unclean end leaves the same metadata
    // behind, because the cleanup in attach.ts runs in a `finally` that a
    // SIGKILL or power loss never reaches. Treating that leftover as a pending
    // start would block the recreate for the whole recency window, right when
    // the operator is trying to get back to work after a crash.
    const { pid: reapedPid } = childProcess.spawnSync("/bin/sh", ["-c", "exit 0"], { stdio: "ignore" });
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    fs.mkdirSync(project.paths.sessionsDir, { recursive: true });
    fs.writeFileSync(path.join(project.paths.sessionsDir, "rf-20260517-crashed.json"), `${JSON.stringify({
      id: "rf-20260517-crashed",
      projectRoot,
      composeProject: composeProjectName(projectRoot),
      command: "codex",
      agentCommand: "codex --dangerously-bypass-approvals-and-sandbox",
      hostPid: reapedPid,
      hostTty: "/dev/ttys004",
      termProgram: "iTerm.app",
      startedAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
    })}\n`);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "ps"
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && args.includes("label=com.docker.compose.service=agent")) {
          return captureResult(0, "agent-id\n");
        }
        if (command === "docker" && args[0] === "ps"
          && args.some((arg) => arg.includes(`com.docker.compose.project=${projectName}`))
          && !args.some((arg) => arg.includes("com.docker.compose.service="))) {
          return captureResult(0, "agent-id\nproxy-id\n");
        }
        if (command === "docker" && args[0] === "inspect" && args.some((arg) => arg.includes("io.runfree.runtime-digest"))) {
          return captureResult(0, "agent-id\tagent\tsha256:old-runtime\nproxy-id\tproxy\tsha256:old-runtime\n");
        }
        if (command === "docker" && args[0] === "exec" && args[1] === "-i" && args.includes("1000:1000") && args.includes(FAKE_AGENT_CONTAINER_ID)) {
          return captureResult(0, "");
        }
        return captureResult(0);
      },
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    flushWarnings();
    expect(vi.mocked(console.error).mock.calls.flat().join("\n")).not.toContain("rf-20260517-crashed");
    expect(io.calls).not.toContainEqual(expect.objectContaining({
      method: "run",
      command: "docker",
      args: expect.arrayContaining(["compose", "down"]),
    }));
  });

  test("rebuild warning includes stderr when active session inspection fails", async () => {
    const projectRoot = path.join(tmp, "project");
    const runtimeRoot = path.join(tmp, "runtime");
    writeRuntimeAssets(runtimeRoot);
    const project = prepareProject(projectRoot);
    const projectName = composeProjectName(projectRoot);
    const io = createRuntimeIO({
      capture: (command, args) => {
        if (command === "docker" && args[0] === "info") return captureResult(0);
        if (command === "docker" && args[0] === "ps"
          && args.includes(`label=com.docker.compose.project=${projectName}`)
          && args.includes("label=com.docker.compose.service=agent")) {
          return captureResult(0, "agent-id\n");
        }
        if (command === "docker" && args[0] === "exec" && args[1] === "-i" && args.includes("1000:1000") && args.includes(FAKE_AGENT_CONTAINER_ID)) {
          return captureResult(126, "", "container is paused\ntry again later\n");
        }
        return captureResult(0);
      },
      confirm: () => false,
    });

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot,
      env: { PATH: "/fake-bin" },
    }, io, true, {});

    expect(status).toBe(1);
    flushWarnings();
    const warningText = vi.mocked(console.error).mock.calls.flat().join("\n");
    expect(warningText).toContain("could not inspect active agent sessions");
    expect(warningText).toContain("container is paused try again later");
    expect(warningText).toContain(`legacy session unknown session (<unknown>): agent container ${FAKE_AGENT_CONTAINER_ID}`);
  });


  test("claude preserves the up failure status", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const io = createRuntimeIO({
      admin: async () => 42,
    });

    const status = await runAgentCommand( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, "claude", { quiet: false, verbose: false });

    expect(status).toBe(42);
  });

  test("non-interactive Claude launch fails before policy mutation or runtime attach with exact remediation", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const before = fs.readFileSync(project.paths.policyPath, "utf8");
    const io = createRuntimeIO({ isInteractive: () => false });

    const status = await runAgentCommand({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, "claude", { quiet: false, verbose: false });

    expect(status).toBe(1);
    expect(vi.mocked(console.error).mock.calls.flat().join("\n")).toContain("Run: runfree service enable agent-claude");
    expect(fs.readFileSync(project.paths.policyPath, "utf8")).toBe(before);
    expect(io.calls.some((call) => call.method === "admin")).toBe(false);
    expect(composeUpCall(io)).toBeUndefined();
    expect(configuredAgentExecCall(io)).toBeUndefined();
  });

  test("declining exact-host Claude review leaves policy and runtime untouched", async () => {
    const projectRoot = path.join(tmp, "project");
    const project = prepareProject(projectRoot);
    const before = fs.readFileSync(project.paths.policyPath, "utf8");
    const io = createRuntimeIO({ confirm: () => false });

    const status = await runAgentCommand({
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, "claude", { quiet: false, verbose: false });

    expect(status).toBe(1);
    const review = vi.mocked(console.log).mock.calls.flat().join("\n");
    expect(review).toContain("service: agent-claude");
    expect(review).toContain("api.anthropic.com");
    expect(review).toContain("platform.claude.com");
    expect(io.calls).toContainEqual({ method: "confirm", args: ["Enable agent-claude for this project? [y/N] "] });
    expect(fs.readFileSync(project.paths.policyPath, "utf8")).toBe(before);
    expect(io.calls.some((call) => call.method === "admin")).toBe(false);
    expect(composeUpCall(io)).toBeUndefined();
    expect(configuredAgentExecCall(io)).toBeUndefined();
  });


  test("runtime management commands take precedence over configured agent names", async () => {
    const projectRoot = path.join(tmp, "project");
    const config = {
      ...defaultConfig(),
      agents: {
        default: "claude",
        claude: { command: "claude --dangerously-skip-permissions" },
        codex: { command: "codex --dangerously-bypass-approvals-and-sandbox" },
        up: { command: "codex --model gpt-5.2 --dangerously-bypass-approvals-and-sandbox" },
      },
    } as RunfreeConfig;
    const project = prepareProject(projectRoot, config);
    const io = createRuntimeIO();

    const status = await up( {
      projectRoot,
      project,
      runtimeRoot: path.join(tmp, "runtime"),
      env: { PATH: "/fake-bin" },
      network: fixedNetwork,
    }, io, false, {});

    expect(status).toBe(0);
    expect(configuredAgentExecCall(io)).toBeUndefined();
    expect(composeUpCall(io)).toBeDefined();
  });

});
