import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import {
  assertDockerfileBuildArgumentCompleteness,
  assertDockerfileLocalSourceCompleteness,
  assertGeneratedRuntimeManifest,
  assertRuntimeAssetDescriptors,
  expectedRuntimeAssetPaths,
  isDirectEntrypoint,
  RUNTIME_ASSET_DESCRIPTORS,
  RUNTIME_ASSET_EXECUTABLE_MODE,
  RUNTIME_ASSET_REGULAR_MODE,
  runtimeAssetMode,
  runtimeAssetsForRole,
} from "./build-runtime.ts";
import { SESSION_ENTRY_PATH } from "../packages/cli/src/runtime/session-launch.ts";
import { runtimeInputBuildArgumentDescriptors } from "../packages/cli/src/runtime-inputs.ts";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const runtimeRoot = path.join(repoRoot, "dist", "runtime");
const staleProxyOutput = path.join(repoRoot, "packages", "proxy", "dist", "stale-proxy.js");
const staleContractOutput = path.join(repoRoot, "packages", "runtime-contracts", "dist", "stale-contract.js");

// The umask is set inside the child rather than on this process: Vitest runs
// tests in worker threads, where `process.umask()` is read-only, and mutating it
// here would leak into every other test in the worker.
function runBuildRuntime(umask = 0o022): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync(
    "sh",
    ["-c", `umask ${umask.toString(8).padStart(4, "0")} && exec pnpm build:runtime`],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        CI: "1",
      },
    },
  );
}

function read(relativePath: string): string {
  return fs.readFileSync(path.join(runtimeRoot, relativePath), "utf8");
}

function cleanRuntimeRootForTest(dir: string): void {
  if (!fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory() && entry.name === "node_modules") continue;
    if (entry.isDirectory()) {
      cleanRuntimeRootForTest(entryPath);
      continue;
    }
    fs.rmSync(entryPath, { force: true });
  }
}

afterEach(() => {
  cleanRuntimeRootForTest(runtimeRoot);
  fs.rmSync(staleProxyOutput, { force: true });
  fs.rmSync(staleContractOutput, { force: true });
});

describe("runtime bundle build", () => {
  test("expectedRuntimeAssetPaths excludes generated dependency directories", () => {
    const paths = expectedRuntimeAssetPaths();
    expect(paths.some((entry) => entry.includes("node_modules"))).toBe(false);
    expect(paths).toContain("agent/compose.yaml");
    expect(paths).toContain("agent/Dockerfile");
    expect(paths).toContain("agent/claude-runfree.sh");
    expect(paths).toContain("agent/session-entry.sh");
    expect(paths).toContain("agent/session-ready-probe.cjs");
    expect(paths).not.toContain("agent/session-finalizer.Dockerfile");
    expect(paths).not.toContain("agent/session-supervisor.c");
    expect(paths).toContain("proxy/Dockerfile");
    expect(paths).toContain("proxy/contracts/desired-network-policy.js");
    expect(paths).toContain("proxy/contracts/effective-control.js");
    expect(paths).toContain("runtime-inputs.lock.json");
  });

  test("classifies every generated runtime asset with an explicit role", () => {
    expect(() => assertRuntimeAssetDescriptors()).not.toThrow();
    expect(runtimeAssetsForRole("agent-image").map(({ path: assetPath }) => assetPath)).toContain("agent/Dockerfile");
    expect(runtimeAssetsForRole("proxy-image").map(({ path: assetPath }) => assetPath)).toContain("proxy/server.js");
    expect(runtimeAssetsForRole("host-helper").map(({ path: assetPath }) => assetPath))
      .toContain("agent/inspect-active-sessions.sh");
    expect(() => assertRuntimeAssetDescriptors([
      ...RUNTIME_ASSET_DESCRIPTORS,
      { path: "agent/unclassified", roles: [] },
    ])).toThrow("runtime asset has no declared role: agent/unclassified");
  });

  test("declares a mode for every runtime asset and refuses to invent one", () => {
    for (const assetPath of expectedRuntimeAssetPaths()) {
      expect([RUNTIME_ASSET_REGULAR_MODE, RUNTIME_ASSET_EXECUTABLE_MODE], assetPath)
        .toContain(runtimeAssetMode(assetPath));
    }
    // Only the host helper is executed directly from host state; the agent image
    // chmods its own copied scripts, so nothing else ships the execute bit.
    expect(RUNTIME_ASSET_DESCRIPTORS
      .filter(({ executable }) => executable === true)
      .map(({ path: assetPath }) => assetPath))
      .toEqual(["agent/inspect-active-sessions.sh"]);
    expect(() => runtimeAssetMode("agent/not-a-declared-asset"))
      .toThrow("undeclared runtime asset: agent/not-a-declared-asset");
  });

  test("rejects Dockerfile copies without matching component ownership", () => {
    const agentFiles = expectedRuntimeAssetPaths()
      .filter((entry) => entry.startsWith("agent/"))
      .map((entry) => entry.slice("agent/".length));
    expect(() => assertDockerfileLocalSourceCompleteness(
      "COPY compose.yaml /runtime/compose.yaml",
      "agent-image",
      agentFiles,
    )).toThrow("COPY/ADD source lacks agent-image role: compose.yaml");
    expect(() => assertDockerfileLocalSourceCompleteness(
      "COPY missing.sh /usr/local/bin/missing",
      "agent-image",
      agentFiles,
    )).toThrow("source has no generated runtime match: missing.sh");
  });

  test("rejects unknown or unused runtime Dockerfile build arguments", () => {
    expect(() => assertDockerfileBuildArgumentCompleteness(
      "ARG RUNFREE_UNKNOWN_INPUT\n",
      "agent-image",
    )).toThrow("unmapped RUNFREE_* input: RUNFREE_UNKNOWN_INPUT");
    const declaredButUnused = runtimeInputBuildArgumentDescriptors("agent-image")
      .map(({ name }) => `ARG ${name}`)
      .join("\n");
    expect(() => assertDockerfileBuildArgumentCompleteness(
      declaredButUnused,
      "agent-image",
    )).toThrow("runtime input mapping is unused by Dockerfile");
  });

  test("rejects external Dockerfile references that bypass the lock mapping", () => {
    expect(() => assertDockerfileBuildArgumentCompleteness(
      "FROM ubuntu:latest\n",
      "agent-image",
    )).toThrow("FROM bypasses the runtime input mapping: ubuntu:latest");
    expect(() => assertDockerfileBuildArgumentCompleteness(
      "RUN curl https://example.invalid/tool\n",
      "agent-image",
    )).toThrow("unlocked external URL");
  });

  test("entrypoint detection handles URL-encoded checkout paths", () => {
    expect(isDirectEntrypoint(
      "file:///tmp/runfree%20checkout/scripts/build-runtime.ts",
      "/tmp/runfree checkout/scripts/build-runtime.ts",
    )).toBe(true);
    expect(isDirectEntrypoint(
      "file:///tmp/runfree%20checkout/scripts/build-runtime.ts",
      "/tmp/other checkout/scripts/build-runtime.ts",
    )).toBe(false);
  });

  test("builds a self-contained proxy JavaScript bundle and agent runtime", () => {
    cleanRuntimeRootForTest(runtimeRoot);
    fs.mkdirSync(path.dirname(staleProxyOutput), { recursive: true });
    fs.mkdirSync(path.dirname(staleContractOutput), { recursive: true });
    fs.writeFileSync(staleProxyOutput, "console.log('stale proxy output');\n");
    fs.writeFileSync(staleContractOutput, "console.log('stale contract output');\n");

    // Build under a restrictive umask: `tsc` would otherwise emit every proxy
    // file at 0600 and the copy would carry that into the embedded manifest.
    const result = runBuildRuntime(0o077);

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(fs.existsSync(path.join(runtimeRoot, "agent", "compose.yaml"))).toBe(true);
    expect(fs.existsSync(path.join(runtimeRoot, "agent", "Dockerfile"))).toBe(true);
    expect(fs.existsSync(path.join(runtimeRoot, "agent", "claude-runfree.sh"))).toBe(true);
    expect(fs.existsSync(path.join(runtimeRoot, "agent", "session-finalizer.Dockerfile"))).toBe(false);
    expect(fs.existsSync(path.join(runtimeRoot, "agent", "session-supervisor.c"))).toBe(false);
    expect(fs.existsSync(path.join(runtimeRoot, "agent", "agent-tools", "package-lock.json"))).toBe(true);
    expect(fs.existsSync(path.join(runtimeRoot, "proxy", "entrypoint.js"))).toBe(true);
    expect(fs.existsSync(path.join(runtimeRoot, "proxy", "server.js"))).toBe(true);
    expect(fs.existsSync(path.join(runtimeRoot, "proxy", "contracts", "network-policy.js"))).toBe(true);
    expect(fs.existsSync(path.join(runtimeRoot, "proxy", "entrypoint.ts"))).toBe(false);
    expect(fs.existsSync(path.join(runtimeRoot, "proxy", "server.ts"))).toBe(false);
    expect(fs.existsSync(path.join(runtimeRoot, "runtime-inputs.lock.json"))).toBe(true);

    const proxyDockerfile = read("proxy/Dockerfile");
    expect(proxyDockerfile).toContain('CMD ["node", "/app/proxy/entrypoint.js"]');
    expect(proxyDockerfile).not.toContain("tsx");

    const agentDockerfile = read("agent/Dockerfile");
    expect(agentDockerfile).toContain("COPY claude-runfree.sh /usr/local/libexec/runfree/claude");
    // The image must install the entry at the path every typed launch target
    // names as the container's `Path`, and the probe beside it where the entry
    // resolves it.
    expect(agentDockerfile).toContain(`COPY session-entry.sh ${SESSION_ENTRY_PATH}`);
    expect(agentDockerfile).toContain(`COPY session-ready-probe.cjs ${path.posix.dirname(SESSION_ENTRY_PATH)}/session-ready-probe`);
    expect(fs.existsSync(path.join(runtimeRoot, "agent", "session-entry.sh"))).toBe(true);
    expect(fs.existsSync(path.join(runtimeRoot, "agent", "session-ready-probe.cjs"))).toBe(true);
    expect(agentDockerfile).toContain("/usr/local/libexec/runfree/claude-real");
    expect(agentDockerfile).not.toContain("musl-gcc");
    expect(agentDockerfile).not.toContain("/usr/local/libexec/runfree/session-supervisor");

    const entrypoint = read("proxy/entrypoint.js");
    expect(entrypoint).not.toContain("@runfree/runtime-contracts");
    expect(entrypoint).not.toContain("/packages/");
    expect(entrypoint).not.toContain("/src/");

    const server = read("proxy/server.js");
    expect(server).not.toContain("@runfree/runtime-contracts");
    expect(server).not.toContain("/packages/");
    expect(server).not.toContain("/src/");
    expect(fs.existsSync(path.join(runtimeRoot, "proxy", "stale-proxy.js"))).toBe(false);
    expect(fs.existsSync(path.join(runtimeRoot, "proxy", "contracts", "stale-contract.js"))).toBe(false);
    expect(fs.existsSync(staleProxyOutput)).toBe(false);
    expect(fs.existsSync(staleContractOutput)).toBe(false);

    // Every generated asset carries its declared mode, not one derived from the
    // build machine's umask or from the mode of the file it was copied from.
    const generatedModes = Object.fromEntries(expectedRuntimeAssetPaths()
      .map((assetPath) => [assetPath, fs.statSync(path.join(runtimeRoot, assetPath)).mode & 0o777]));
    expect(generatedModes).toEqual(Object.fromEntries(expectedRuntimeAssetPaths()
      .map((assetPath) => [assetPath, runtimeAssetMode(assetPath)])));
    expect(() => assertGeneratedRuntimeManifest(runtimeRoot)).not.toThrow();

    // And a mode that drifts afterwards is refused rather than embedded: this is
    // the check `pnpm run generate:assets` runs before reading the tree.
    const drifted = path.join(runtimeRoot, "proxy", "server.js");
    fs.chmodSync(drifted, 0o600);
    expect(() => assertGeneratedRuntimeManifest(runtimeRoot))
      .toThrow("proxy/server.js is 600, declared 644");
    fs.chmodSync(drifted, RUNTIME_ASSET_REGULAR_MODE);
  });
});
