import fs from "node:fs";
import path from "node:path";

import { die } from "./errors.ts";

type JsonRecord = Record<string, unknown>;

export type RuntimeImageComponent = "agent-image" | "proxy-image";
export type RuntimeBuildArgumentOwner = RuntimeImageComponent | "shared";

export const RUNTIME_INPUT_BUILD_ARGUMENTS = [
  { name: "RUNFREE_AGENT_BASE_IMAGE", owner: "agent-image", lockPaths: ["images.agentBase.ref"] },
  { name: "RUNFREE_UV_IMAGE", owner: "agent-image", lockPaths: ["images.uv.ref"] },
  { name: "RUNFREE_PROXY_BASE_IMAGE", owner: "proxy-image", lockPaths: ["images.proxyBase.ref"] },
  { name: "RUNFREE_APT_SOURCE_UBUNTU_URL", owner: "shared", lockPaths: ["apt.sources.ubuntu.url"] },
  { name: "RUNFREE_APT_SOURCE_UBUNTU_SUITES", owner: "shared", lockPaths: ["apt.sources.ubuntu.suites"] },
  { name: "RUNFREE_APT_SOURCE_UBUNTU_COMPONENTS", owner: "shared", lockPaths: ["apt.sources.ubuntu.components"] },
  {
    name: "RUNFREE_APT_SOURCE_UBUNTU_SECURITY_URL",
    owner: "shared",
    lockPaths: ["apt.sources.ubuntuSecurity.url"],
  },
  {
    name: "RUNFREE_APT_SOURCE_UBUNTU_SECURITY_SUITES",
    owner: "shared",
    lockPaths: ["apt.sources.ubuntuSecurity.suites"],
  },
  {
    name: "RUNFREE_APT_SOURCE_UBUNTU_SECURITY_COMPONENTS",
    owner: "shared",
    lockPaths: ["apt.sources.ubuntuSecurity.components"],
  },
  {
    name: "RUNFREE_APT_SIGNED_BY",
    owner: "shared",
    lockPaths: ["apt.sources.ubuntu.signedBy", "apt.sources.ubuntuSecurity.signedBy"],
  },
  { name: "RUNFREE_APT_PACKAGE_CA_CERTIFICATES", owner: "shared", lockPaths: ["apt.packages.ca-certificates"] },
  { name: "RUNFREE_APT_PACKAGE_CURL", owner: "agent-image", lockPaths: ["apt.packages.curl"] },
  { name: "RUNFREE_APT_PACKAGE_SUDO", owner: "agent-image", lockPaths: ["apt.packages.sudo"] },
  { name: "RUNFREE_APT_PACKAGE_GIT", owner: "agent-image", lockPaths: ["apt.packages.git"] },
  { name: "RUNFREE_APT_PACKAGE_JQ", owner: "agent-image", lockPaths: ["apt.packages.jq"] },
  { name: "RUNFREE_APT_PACKAGE_RIPGREP", owner: "agent-image", lockPaths: ["apt.packages.ripgrep"] },
  { name: "RUNFREE_APT_PACKAGE_ZSH", owner: "agent-image", lockPaths: ["apt.packages.zsh"] },
  { name: "RUNFREE_APT_PACKAGE_IPROUTE2", owner: "shared", lockPaths: ["apt.packages.iproute2"] },
  {
    name: "RUNFREE_APT_PACKAGE_NETCAT_OPENBSD",
    owner: "agent-image",
    lockPaths: ["apt.packages.netcat-openbsd"],
  },
  { name: "RUNFREE_APT_PACKAGE_BIND9_DNSUTILS", owner: "shared", lockPaths: ["apt.packages.bind9-dnsutils"] },
  { name: "RUNFREE_APT_PACKAGE_DUMB_INIT", owner: "proxy-image", lockPaths: ["apt.packages.dumb-init"] },
  { name: "RUNFREE_APT_PACKAGE_NFTABLES", owner: "proxy-image", lockPaths: ["apt.packages.nftables"] },
  { name: "RUNFREE_APT_PACKAGE_BASH", owner: "proxy-image", lockPaths: ["apt.packages.bash"] },
  { name: "RUNFREE_APT_PACKAGE_UTIL_LINUX", owner: "proxy-image", lockPaths: ["apt.packages.util-linux"] },
  { name: "RUNFREE_APT_PACKAGE_NODEJS", owner: "shared", lockPaths: ["apt.packages.nodejs"] },
  { name: "RUNFREE_APT_PACKAGE_NPM", owner: "shared", lockPaths: ["apt.packages.npm"] },
  { name: "RUNFREE_GH_VERSION", owner: "agent-image", lockPaths: ["releaseArtifacts.githubCli.version"] },
  {
    name: "RUNFREE_GH_LINUX_AMD64_DEB_URL",
    owner: "agent-image",
    lockPaths: ["releaseArtifacts.githubCli.linuxAmd64Deb.url"],
  },
  {
    name: "RUNFREE_GH_LINUX_AMD64_DEB_SHA256",
    owner: "agent-image",
    lockPaths: ["releaseArtifacts.githubCli.linuxAmd64Deb.sha256"],
  },
  {
    name: "RUNFREE_GH_LINUX_ARM64_DEB_URL",
    owner: "agent-image",
    lockPaths: ["releaseArtifacts.githubCli.linuxArm64Deb.url"],
  },
  {
    name: "RUNFREE_GH_LINUX_ARM64_DEB_SHA256",
    owner: "agent-image",
    lockPaths: ["releaseArtifacts.githubCli.linuxArm64Deb.sha256"],
  },
  { name: "RUNFREE_PNPM_VERSION", owner: "agent-image", lockPaths: ["npm.pnpmVersion"] },
] as const satisfies readonly {
  name: `RUNFREE_${string}`;
  owner: RuntimeBuildArgumentOwner;
  lockPaths: readonly string[];
}[];

export type RuntimeInputBuildArgumentName = typeof RUNTIME_INPUT_BUILD_ARGUMENTS[number]["name"];

export const RUNTIME_INPUT_BUILD_ARG_NAMES: readonly RuntimeInputBuildArgumentName[] =
  RUNTIME_INPUT_BUILD_ARGUMENTS.map(({ name }) => name);

export const RUNTIME_INPUT_FILE_REFERENCES = [
  {
    lockPath: "npm.agentToolsPackageLock",
    runtimeAssetPath: "agent/agent-tools/package-lock.json",
    owner: "agent-image",
  },
  {
    lockPath: "npm.proxyPackageLock",
    runtimeAssetPath: "proxy/package-lock.json",
    owner: "proxy-image",
  },
] as const satisfies readonly {
  lockPath: string;
  runtimeAssetPath: string;
  owner: RuntimeImageComponent;
}[];

const REQUIRED_APT_PACKAGES = [
  "ca-certificates",
  "curl",
  "sudo",
  "git",
  "jq",
  "ripgrep",
  "zsh",
  "iproute2",
  "netcat-openbsd",
  "bind9-dnsutils",
  "dumb-init",
  "nftables",
  "bash",
  "util-linux",
  "nodejs",
  "npm",
] as const;

const IMAGE_REF_PATTERN = /@sha256:[a-f0-9]{64}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const PACKAGE_VERSION_PATTERN = /^[0-9A-Za-z:.+~\-]+$/;
const PNPM_VERSION_PATTERN = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const APT_SIGNED_BY = "/usr/share/keyrings/ubuntu-archive-keyring.gpg";

function readLock(runtimeRoot: string): unknown {
  const lockPath = path.join(runtimeRoot, "runtime-inputs.lock.json");
  if (!fs.existsSync(lockPath)) {
    die(`runtime input lock missing: ${lockPath}`);
  }
  try {
    return JSON.parse(fs.readFileSync(lockPath, "utf8")) as unknown;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    die(`runtime input lock malformed: ${detail}`);
  }
}

function requireObject(value: unknown, label: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    die(`runtime input lock missing ${label}`);
  }
  return value as JsonRecord;
}

function requireOnlyFields(value: unknown, label: string, allowedFields: readonly string[]): JsonRecord {
  const object = requireObject(value, label);
  const allowed = new Set(allowedFields);
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) {
      die(`runtime input lock unexpected ${label}.${key}`);
    }
  }
  return object;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    die(`runtime input lock missing ${label}`);
  }
  return value;
}

function requiredImageRef(value: unknown, label: string): string {
  const ref = requiredString(value, label);
  if (!IMAGE_REF_PATTERN.test(ref)) {
    die(`runtime input ${label} must include @sha256:`);
  }
  return ref;
}

function requiredPackageVersion(value: unknown, label: string): string {
  const version = requiredString(value, label);
  if (!PACKAGE_VERSION_PATTERN.test(version)) {
    die(`runtime input ${label} must be an exact package version`);
  }
  return version;
}

function requiredSha(value: unknown, label: string): string {
  const sha = requiredString(value, label);
  if (!SHA256_PATTERN.test(sha)) {
    die(`runtime input ${label} must be a 64-character sha256`);
  }
  return sha;
}

function requiredUrlWithProtocol(value: unknown, label: string, protocol: "http:" | "https:"): URL {
  const url = requiredString(value, label);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    die(`runtime input ${label} must be a URL`);
  }
  if (parsed.protocol !== protocol) {
    die(`runtime input ${label} must be an ${protocol.slice(0, -1)} URL`);
  }
  if (parsed.username !== "" || parsed.password !== "" || parsed.port !== "") {
    die(`runtime input ${label} must not include username, password, or port`);
  }
  if (parsed.search !== "" || parsed.hash !== "") {
    die(`runtime input ${label} must not include query or fragment`);
  }
  return parsed;
}

function requiredUrl(value: unknown, label: string): URL {
  return requiredUrlWithProtocol(value, label, "https:");
}

function requiredGithubCliDebUrl(value: unknown, label: string, version: string, arch: "amd64" | "arm64"): string {
  const parsed = requiredUrl(value, label);
  const expectedPath = `/cli/cli/releases/download/v${version}/gh_${version}_linux_${arch}.deb`;
  if (parsed.hostname !== "github.com" || parsed.pathname !== expectedPath) {
    die(`runtime input ${label} must point at ${expectedPath}`);
  }
  return parsed.toString();
}

function requiredAptSourceUrl(value: unknown, label: string, expectedHost: string): string {
  // These sources intentionally use HTTP because the first apt-get update may
  // run before ca-certificates has been installed. Ubuntu repository
  // signatures plus direct package pins remain the integrity boundary.
  const parsed = requiredUrlWithProtocol(value, label, "http:");
  if (parsed.hostname !== expectedHost || (parsed.pathname !== "/ubuntu" && parsed.pathname !== "/ubuntu/")) {
    die(`runtime input ${label} must point at http://${expectedHost}/ubuntu`);
  }
  return parsed.toString().replace(/\/$/, "");
}

function requiredLiteral(value: unknown, label: string, expected: string): string {
  const actual = requiredString(value, label);
  if (actual !== expected) {
    die(`runtime input ${label} must be ${expected}`);
  }
  return actual;
}

function requiredStringList(value: unknown, label: string, expected: readonly string[]): string {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string" || entry.trim() === "")) {
    die(`runtime input lock missing ${label}`);
  }
  if (value.length !== expected.length || value.some((entry, index) => entry !== expected[index])) {
    die(`runtime input ${label} must be ${expected.join(" ")}`);
  }
  return value.join(" ");
}

function packageArgName(packageName: string): RuntimeInputBuildArgumentName {
  return `RUNFREE_APT_PACKAGE_${packageName.toUpperCase().replace(/-/g, "_")}` as RuntimeInputBuildArgumentName;
}

function assertPackageLock(runtimeRoot: string, value: unknown, label: string, expectedPath: string): string {
  const relativePath = requiredString(value, label);
  if (relativePath !== expectedPath) {
    die(`runtime input ${label} must be ${expectedPath}`);
  }
  if (path.isAbsolute(relativePath) || relativePath.split(/[\\/]/).includes("..")) {
    die(`runtime input ${label} must be relative to runtime root`);
  }
  const lockPath = path.join(runtimeRoot, relativePath);
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(lockPath);
  } catch {
    die(`runtime input package lock missing: ${relativePath}`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    die(`runtime input package lock is not a regular file: ${relativePath}`);
  }
  return relativePath;
}

function assertPnpmLockedPackage(runtimeRoot: string, relativePath: string, pnpmVersion: string): void {
  const lockPath = path.join(runtimeRoot, relativePath);
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(lockPath, "utf8")) as unknown;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    die(`runtime input ${relativePath} malformed: ${detail}`);
  }
  const packages = requireObject(requireObject(parsed, relativePath).packages, `${relativePath}.packages`);
  const root = requireObject(packages[""], `${relativePath}.packages[\"\"]`);
  const dependencies = requireObject(root.dependencies, `${relativePath}.packages[\"\"].dependencies`);
  if (dependencies.pnpm !== pnpmVersion) {
    die(`runtime input ${relativePath} must pin pnpm ${pnpmVersion}`);
  }
  const pnpm = requireObject(packages["node_modules/pnpm"], `${relativePath}.packages["node_modules/pnpm"]`);
  if (pnpm.version !== pnpmVersion) {
    die(`runtime input ${relativePath} must lock pnpm ${pnpmVersion}`);
  }
  const resolved = requiredString(pnpm.resolved, `${relativePath}.packages["node_modules/pnpm"].resolved`);
  if (resolved !== `https://registry.npmjs.org/pnpm/-/pnpm-${pnpmVersion}.tgz`) {
    die(`runtime input ${relativePath} pnpm resolved URL must match pnpm ${pnpmVersion}`);
  }
  const integrity = requiredString(pnpm.integrity, `${relativePath}.packages["node_modules/pnpm"].integrity`);
  if (!integrity.startsWith("sha512-")) {
    die(`runtime input ${relativePath} pnpm integrity must be sha512`);
  }
}

export function runtimeInputBuildEnvironment(runtimeRoot: string): NodeJS.ProcessEnv {
  const lock = requireOnlyFields(readLock(runtimeRoot), "root", ["schemaVersion", "images", "apt", "releaseArtifacts", "npm"]);
  if (lock.schemaVersion !== 1) {
    die("runtime input lock missing schemaVersion 1");
  }

  const images = requireOnlyFields(lock.images, "images", ["agentBase", "uv", "proxyBase"]);
  const agentBase = requireOnlyFields(images.agentBase, "images.agentBase", ["ref"]);
  const uv = requireOnlyFields(images.uv, "images.uv", ["ref"]);
  const proxyBase = requireOnlyFields(images.proxyBase, "images.proxyBase", ["ref"]);

  const apt = requireOnlyFields(lock.apt, "apt", ["family", "sources", "packages"]);
  if (apt.family !== "ubuntu") {
    die("runtime input lock apt.family must be ubuntu");
  }
  const sources = requireOnlyFields(apt.sources, "apt.sources", ["ubuntu", "ubuntuSecurity"]);
  const ubuntuSource = requireOnlyFields(sources.ubuntu, "apt.sources.ubuntu", ["url", "suites", "components", "signedBy"]);
  const ubuntuSecuritySource = requireOnlyFields(
    sources.ubuntuSecurity,
    "apt.sources.ubuntuSecurity",
    ["url", "suites", "components", "signedBy"],
  );
  const packages = requireOnlyFields(apt.packages, "apt.packages", REQUIRED_APT_PACKAGES);

  const releaseArtifacts = requireOnlyFields(lock.releaseArtifacts, "releaseArtifacts", ["githubCli"]);
  const githubCli = requireOnlyFields(releaseArtifacts.githubCli, "releaseArtifacts.githubCli", [
    "version",
    "linuxAmd64Deb",
    "linuxArm64Deb",
  ]);
  const ghVersion = requiredString(githubCli.version, "releaseArtifacts.githubCli.version");
  const githubCliAmd64 = requireOnlyFields(githubCli.linuxAmd64Deb, "releaseArtifacts.githubCli.linuxAmd64Deb", ["url", "sha256"]);
  const githubCliArm64 = requireOnlyFields(githubCli.linuxArm64Deb, "releaseArtifacts.githubCli.linuxArm64Deb", ["url", "sha256"]);
  const npm = requireOnlyFields(lock.npm, "npm", ["agentToolsPackageLock", "proxyPackageLock", "pnpmVersion"]);
  const pnpmVersion = requiredString(npm.pnpmVersion, "npm.pnpmVersion");
  if (!PNPM_VERSION_PATTERN.test(pnpmVersion)) {
    die("runtime input npm.pnpmVersion must be an exact pnpm version");
  }
  const aptSignedBy = requiredLiteral(ubuntuSource.signedBy, "apt.sources.ubuntu.signedBy", APT_SIGNED_BY);

  const result: NodeJS.ProcessEnv = {
    RUNFREE_AGENT_BASE_IMAGE: requiredImageRef(agentBase.ref, "images.agentBase.ref"),
    RUNFREE_UV_IMAGE: requiredImageRef(uv.ref, "images.uv.ref"),
    RUNFREE_PROXY_BASE_IMAGE: requiredImageRef(proxyBase.ref, "images.proxyBase.ref"),
    RUNFREE_APT_SOURCE_UBUNTU_URL: requiredAptSourceUrl(ubuntuSource.url, "apt.sources.ubuntu.url", "archive.ubuntu.com"),
    RUNFREE_APT_SOURCE_UBUNTU_SUITES: requiredStringList(
      ubuntuSource.suites,
      "apt.sources.ubuntu.suites",
      ["resolute", "resolute-updates"],
    ),
    RUNFREE_APT_SOURCE_UBUNTU_COMPONENTS: requiredStringList(
      ubuntuSource.components,
      "apt.sources.ubuntu.components",
      ["main", "universe"],
    ),
    RUNFREE_APT_SOURCE_UBUNTU_SECURITY_URL: requiredAptSourceUrl(
      ubuntuSecuritySource.url,
      "apt.sources.ubuntuSecurity.url",
      "security.ubuntu.com",
    ),
    RUNFREE_APT_SOURCE_UBUNTU_SECURITY_SUITES: requiredStringList(
      ubuntuSecuritySource.suites,
      "apt.sources.ubuntuSecurity.suites",
      ["resolute-security"],
    ),
    RUNFREE_APT_SOURCE_UBUNTU_SECURITY_COMPONENTS: requiredStringList(
      ubuntuSecuritySource.components,
      "apt.sources.ubuntuSecurity.components",
      ["main", "universe"],
    ),
    RUNFREE_APT_SIGNED_BY: aptSignedBy,
    RUNFREE_GH_VERSION: ghVersion,
    RUNFREE_GH_LINUX_AMD64_DEB_URL: requiredGithubCliDebUrl(
      githubCliAmd64.url,
      "releaseArtifacts.githubCli.linuxAmd64Deb.url",
      ghVersion,
      "amd64",
    ),
    RUNFREE_GH_LINUX_AMD64_DEB_SHA256: requiredSha(
      githubCliAmd64.sha256,
      "releaseArtifacts.githubCli.linuxAmd64Deb.sha256",
    ),
    RUNFREE_GH_LINUX_ARM64_DEB_URL: requiredGithubCliDebUrl(
      githubCliArm64.url,
      "releaseArtifacts.githubCli.linuxArm64Deb.url",
      ghVersion,
      "arm64",
    ),
    RUNFREE_GH_LINUX_ARM64_DEB_SHA256: requiredSha(
      githubCliArm64.sha256,
      "releaseArtifacts.githubCli.linuxArm64Deb.sha256",
    ),
    RUNFREE_PNPM_VERSION: pnpmVersion,
  };
  requiredLiteral(ubuntuSecuritySource.signedBy, "apt.sources.ubuntuSecurity.signedBy", aptSignedBy);

  for (const packageName of REQUIRED_APT_PACKAGES) {
    result[packageArgName(packageName)] = requiredPackageVersion(packages[packageName], `apt package ${packageName}`);
  }

  const agentToolsPackageLock = assertPackageLock(
    runtimeRoot,
    npm.agentToolsPackageLock,
    "npm.agentToolsPackageLock",
    RUNTIME_INPUT_FILE_REFERENCES[0].runtimeAssetPath,
  );
  assertPackageLock(
    runtimeRoot,
    npm.proxyPackageLock,
    "npm.proxyPackageLock",
    RUNTIME_INPUT_FILE_REFERENCES[1].runtimeAssetPath,
  );
  assertPnpmLockedPackage(runtimeRoot, agentToolsPackageLock, pnpmVersion);

  return Object.fromEntries(RUNTIME_INPUT_BUILD_ARG_NAMES.map((name) => [name, result[name]]));
}

export function runtimeInputBuildArgumentDescriptors(
  component: RuntimeImageComponent,
): readonly typeof RUNTIME_INPUT_BUILD_ARGUMENTS[number][] {
  return RUNTIME_INPUT_BUILD_ARGUMENTS.filter(({ owner }) => owner === component || owner === "shared");
}

export function runtimeInputBuildEnvironmentForComponent(
  runtimeRoot: string,
  component: RuntimeImageComponent,
): Readonly<Partial<Record<RuntimeInputBuildArgumentName, string>>> {
  const complete = runtimeInputBuildEnvironment(runtimeRoot);
  return Object.fromEntries(runtimeInputBuildArgumentDescriptors(component).map(({ name }) => {
    const value = complete[name];
    if (value === undefined) {
      die(`runtime input build argument missing: ${name}`);
    }
    return [name, value];
  })) as Readonly<Partial<Record<RuntimeInputBuildArgumentName, string>>>;
}

export function runtimeInputBuildArgFlags(runtimeRoot: string, component?: RuntimeImageComponent): string[] {
  const environment = component === undefined
    ? runtimeInputBuildEnvironment(runtimeRoot)
    : runtimeInputBuildEnvironmentForComponent(runtimeRoot, component);
  return Object.entries(environment)
    .flatMap(([name, value]) => ["--build-arg", `${name}=${value}`]);
}
