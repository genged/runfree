import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { readBoundedRegularFile } from "../strict-primitives.ts";
import { stableJson, sha256Digest } from "../strict-primitives.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import type { RuntimeIO } from "./types.ts";
import { createDockerClient } from "./docker-client.ts";

/**
 * No private bytes enter the journal, and the host never reads the proxy CA
 * key. The proxy (UID 1001) writes it to the host bind mount with mode 0600,
 * so on native Linux Docker Engine the host user cannot read it (Docker
 * Desktop's file sharing hides this by presenting it as host-owned). Its
 * identity is captured with `lstat` instead. Key/cert agreement is not checked
 * here: a mismatched pair fails closed at TLS. Missing retained trust refuses
 * creation.
 */
export function captureRebindTrustReceipt(plan: ActiveRuntimePlan, io: RuntimeIO, assertAuthority: () => void): string {
  assertAuthority();
  const read = (file: string): string => {
    const result = readBoundedRegularFile(file, { maxBytes: 1024 * 1024, sizeRecheck: "exact",
      notFileMessage: () => "retained proxy trust file is unsafe; restore it before recovery",
      changedMessage: () => "retained proxy trust file changed during read; retry recovery" });
    if (!result) throw new Error("retained proxy trust material is missing; restore the original CA before recovery");
    return result.source;
  };
  const directories = [plan.paths.proxyCaKeyDir, plan.paths.proxyCaCertDir].map((directory) => {
    const stat = fs.lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("retained CA directory is unsafe; restore its exact mount before recovery");
    return { path: directory, device: stat.dev, inode: stat.ino };
  });
  const certificate = new crypto.X509Certificate(read(path.join(plan.paths.proxyCaCertDir, "proxy-ca.crt")));
  const keyPath = path.join(plan.paths.proxyCaKeyDir, "proxy-ca.key");
  let keyStat: fs.Stats;
  try {
    keyStat = fs.lstatSync(keyPath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      throw new Error("retained proxy trust material is missing; restore the original CA before recovery");
    }
    throw error;
  }
  if (!keyStat.isFile() || keyStat.isSymbolicLink()) throw new Error("retained proxy trust file is unsafe; restore it before recovery");
  const keyIdentity = { dev: keyStat.dev, ino: keyStat.ino, size: keyStat.size, mtimeMs: keyStat.mtimeMs, mode: keyStat.mode };
  const bundle = read(path.join(plan.paths.proxyCaCertDir, "ca-bundle.crt"));
  if (!bundle.includes(certificate.toString().trim())) throw new Error("retained agent trust bundle does not contain the proxy CA; restore original trust before recovery");
  const volumeName = `${plan.composeProjectName}_runfree-oauth-state`;
  const inspected = createDockerClient(io, { env: plan.execution.dockerClientEnv, timeout: 1000, maxBuffer: 64 * 1024 })
    .inspect([volumeName], { type: "volume" });
  assertAuthority();
  if (inspected.status !== 0 || inspected.stderr.trim()) throw new Error("retained OAuth volume inspection is unavailable; no proxy creation is authorized");
  const volumes = JSON.parse(inspected.stdout) as Array<Record<string, unknown>>;
  const volume = Array.isArray(volumes) && volumes.length === 1 ? volumes[0] : undefined;
  const labels = volume?.Labels as Record<string, unknown> | undefined;
  if (!volume || volume.Name !== volumeName || labels?.["com.docker.compose.project"] !== plan.composeProjectName
    || labels?.["com.docker.compose.volume"] !== "runfree-oauth-state"
    || typeof volume.CreatedAt !== "string" || !Number.isFinite(Date.parse(volume.CreatedAt))
    || typeof volume.Mountpoint !== "string" || typeof volume.Driver !== "string" || typeof volume.Scope !== "string") {
    throw new Error("retained OAuth volume identity is incomplete or foreign; restore the exact project volume before recovery");
  }
  return stableJson({ certificateDigest: sha256Digest(certificate.raw), keyIdentity, directories,
    volume: { name: volume.Name, createdAt: volume.CreatedAt, mountpoint: volume.Mountpoint, driver: volume.Driver, scope: volume.Scope } });
}
