import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const lockPath = path.join(repoRoot, "packages", "agent-runtime", "runtime-inputs.lock.json");
const runtimeRoot = path.join(repoRoot, "packages", "agent-runtime");

type RuntimeInputLock = {
  schemaVersion: 1;
  images: Record<string, { ref: string }>;
  apt: {
    sources: {
      ubuntu: { url: string };
      ubuntuSecurity: { url: string };
    };
  };
  releaseArtifacts: {
    githubCli: {
      version: string;
      linuxAmd64Deb: { url: string; sha256: string };
      linuxArm64Deb: { url: string; sha256: string };
    };
  };
  npm: Record<string, string>;
};

const OCI_ACCEPT = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
].join(", ");

function parseImageRef(ref: string): { registry: string; repository: string; tag: string } {
  const [nameAndTag] = ref.split("@sha256:");
  const tagIndex = nameAndTag.lastIndexOf(":");
  if (tagIndex === -1) throw new Error(`image ref must include a tag: ${ref}`);
  const name = nameAndTag.slice(0, tagIndex);
  const tag = nameAndTag.slice(tagIndex + 1);
  if (name.includes("/")) {
    const [first, ...rest] = name.split("/");
    if (first.includes(".") || first.includes(":") || first === "localhost") {
      return { registry: first, repository: rest.join("/"), tag };
    }
  }
  return { registry: "registry-1.docker.io", repository: name.includes("/") ? name : `library/${name}`, tag };
}

function authHeader(headers: Headers): string | undefined {
  return headers.get("www-authenticate") ?? undefined;
}

function parseBearerChallenge(value: string): Record<string, string> {
  const match = /^Bearer\s+(.+)$/i.exec(value);
  if (!match) return {};
  const result: Record<string, string> = {};
  for (const part of match[1].matchAll(/([a-z_]+)="([^"]*)"/gi)) {
    result[part[1]] = part[2];
  }
  return result;
}

async function bearerToken(challenge: string): Promise<string | undefined> {
  const parsed = parseBearerChallenge(challenge);
  if (!parsed.realm) return undefined;
  const url = new URL(parsed.realm);
  if (parsed.service) url.searchParams.set("service", parsed.service);
  if (parsed.scope) url.searchParams.set("scope", parsed.scope);
  const response = await fetch(url);
  if (!response.ok) throw new Error(`registry auth failed: ${response.status} ${response.statusText}`);
  const body = await response.json() as { token?: string; access_token?: string };
  return body.token ?? body.access_token;
}

async function fetchManifestDigest(ref: string): Promise<string> {
  const image = parseImageRef(ref);
  const url = `https://${image.registry}/v2/${image.repository}/manifests/${image.tag}`;
  let response = await fetch(url, { method: "HEAD", headers: { Accept: OCI_ACCEPT } });
  const challenge = authHeader(response.headers);
  if (response.status === 401 && challenge) {
    const token = await bearerToken(challenge);
    response = await fetch(url, {
      method: "HEAD",
      headers: {
        Accept: OCI_ACCEPT,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    });
  }
  if (!response.ok) throw new Error(`manifest lookup failed for ${ref}: ${response.status} ${response.statusText}`);
  const digest = response.headers.get("docker-content-digest");
  if (!digest) throw new Error(`manifest lookup did not return docker-content-digest for ${ref}`);
  return digest;
}

function imageRefWithDigest(ref: string, digest: string): string {
  const [nameAndTag] = ref.split("@sha256:");
  return `${nameAndTag}@${digest}`;
}

async function resolveImageRefs(lock: RuntimeInputLock): Promise<string[]> {
  const changed: string[] = [];
  for (const [name, image] of Object.entries(lock.images).sort(([left], [right]) => left.localeCompare(right))) {
    const digest = await fetchManifestDigest(image.ref);
    const nextRef = imageRefWithDigest(image.ref, digest);
    if (nextRef !== image.ref) {
      image.ref = nextRef;
      changed.push(`image ${name}`);
    }
  }
  return changed;
}

function updateAptSources(lock: RuntimeInputLock): string[] {
  const changed: string[] = [];
  const expected = {
    ubuntu: "http://archive.ubuntu.com/ubuntu",
    ubuntuSecurity: "http://security.ubuntu.com/ubuntu",
  };
  for (const [name, url] of Object.entries(expected) as Array<[keyof typeof expected, string]>) {
    if (lock.apt.sources[name].url !== url) {
      lock.apt.sources[name].url = url;
      changed.push(`apt source ${name}`);
    }
  }
  return changed;
}

async function updateGitHubCliChecksums(lock: RuntimeInputLock): Promise<string[]> {
  const gh = lock.releaseArtifacts.githubCli;
  const checksumsUrl = `https://github.com/cli/cli/releases/download/v${gh.version}/gh_${gh.version}_checksums.txt`;
  const response = await fetch(checksumsUrl);
  if (!response.ok) throw new Error(`GitHub CLI checksum lookup failed: ${response.status} ${response.statusText}`);
  const checksums = await response.text();
  const changed: string[] = [];
  const apply = (asset: { url: string; sha256: string }, filename: string): void => {
    const line = checksums.split(/\r?\n/).find((entry) => entry.endsWith(`  ${filename}`));
    if (!line) throw new Error(`GitHub CLI checksums missing ${filename}`);
    const sha = line.slice(0, 64);
    if (asset.sha256 !== sha) {
      asset.sha256 = sha;
      changed.push(filename);
    }
  };
  apply(gh.linuxAmd64Deb, `gh_${gh.version}_linux_amd64.deb`);
  apply(gh.linuxArm64Deb, `gh_${gh.version}_linux_arm64.deb`);
  return changed;
}

function verifyNpmLockfiles(lock: RuntimeInputLock): string[] {
  const checked: string[] = [];
  for (const [name, relativePath] of Object.entries(lock.npm).sort(([left], [right]) => left.localeCompare(right))) {
    if (name === "pnpmVersion") continue;
    const lockfilePath = sourceLockfilePath(relativePath);
    if (!fs.existsSync(lockfilePath)) throw new Error(`missing npm lockfile: ${relativePath}`);
    checked.push(relativePath);
  }
  const agentToolsLockPath = sourceLockfilePath(lock.npm.agentToolsPackageLock);
  const agentToolsLock = JSON.parse(fs.readFileSync(agentToolsLockPath, "utf8")) as {
    packages?: Record<string, { dependencies?: Record<string, string>; integrity?: string; resolved?: string; version?: string }>;
  };
  const pnpm = agentToolsLock.packages?.["node_modules/pnpm"];
  if (!pnpm || agentToolsLock.packages?.[""]?.dependencies?.pnpm !== lock.npm.pnpmVersion || pnpm.version !== lock.npm.pnpmVersion) {
    throw new Error(`agent-tools package lock must pin pnpm ${lock.npm.pnpmVersion}`);
  }
  if (pnpm.resolved !== `https://registry.npmjs.org/pnpm/-/pnpm-${lock.npm.pnpmVersion}.tgz` || !pnpm.integrity?.startsWith("sha512-")) {
    throw new Error("agent-tools package lock must include pnpm tarball URL and integrity");
  }
  return checked;
}

function sourceLockfilePath(runtimeRelativePath: string): string {
  if (runtimeRelativePath === "proxy/package-lock.json") {
    return path.join(repoRoot, "packages", "proxy", "package-lock.json");
  }
  return path.join(runtimeRoot, runtimeRelativePath);
}

function runTsxScript(scriptName: string, failureMessage: string): void {
  const result = childProcess.spawnSync(process.execPath, [
    "--import",
    "tsx",
    path.join(repoRoot, "scripts", scriptName),
  ], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: "inherit",
  });
  if ((result.status ?? 1) !== 0) {
    throw new Error(failureMessage);
  }
}

function buildRuntimeBundle(): void {
  runTsxScript("build-runtime.ts", "runtime bundle build failed; run `pnpm run build:runtime` after fixing the error");
}

function generateEmbeddedAssets(): void {
  runTsxScript("generate-assets.ts", "embedded asset generation failed; run `pnpm run generate:assets` after fixing the error");
}

async function main(): Promise<void> {
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8")) as RuntimeInputLock;
  const imageChanges = await resolveImageRefs(lock);
  const aptSourceChanges = updateAptSources(lock);
  const checksumChanges = await updateGitHubCliChecksums(lock);
  const npmLocks = verifyNpmLockfiles(lock);
  fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  buildRuntimeBundle();
  generateEmbeddedAssets();
  console.log(`runtime input lock updated: ${path.relative(repoRoot, lockPath)}`);
  console.log(`images checked: ${Object.keys(lock.images).sort().join(", ")}`);
  console.log("apt sources checked against regular Ubuntu archives");
  console.log(`GitHub CLI checksums checked for v${lock.releaseArtifacts.githubCli.version}`);
  console.log(`npm lockfiles checked: ${npmLocks.join(", ")}`);
  if (imageChanges.length > 0 || aptSourceChanges.length > 0 || checksumChanges.length > 0) {
    console.log(`changed: ${[...imageChanges, ...aptSourceChanges, ...checksumChanges].join(", ")}`);
  } else {
    console.log("changed: none");
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
