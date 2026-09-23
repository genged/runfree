import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { readBoundedRegularFile } from "../strict-primitives.ts";
import { stableJson, sha256Digest } from "../strict-primitives.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import type { RuntimeIO } from "./types.ts";

/** No private bytes enter the journal. Missing retained trust refuses creation. */
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
  const publicKey = crypto.createPublicKey(crypto.createPrivateKey(read(path.join(plan.paths.proxyCaKeyDir, "proxy-ca.key"))))
    .export({ type: "spki", format: "der" });
  if (!certificate.publicKey.export({ type: "spki", format: "der" }).equals(publicKey)) {
    throw new Error("retained CA key and certificate disagree; restore the original pair before recovery");
  }
  const bundle = read(path.join(plan.paths.proxyCaCertDir, "ca-bundle.crt"));
  if (!bundle.includes(certificate.toString().trim())) throw new Error("retained agent trust bundle does not contain the proxy CA; restore original trust before recovery");
  const volumeName = `${plan.composeProjectName}_runfree-oauth-state`;
  const inspected = io.capture("docker", ["volume", "inspect", volumeName],
    { env: plan.execution.dockerClientEnv, timeout: 1000, maxBuffer: 64 * 1024 });
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
  return stableJson({ certificateDigest: sha256Digest(certificate.raw), publicKeyDigest: sha256Digest(publicKey), directories,
    volume: { name: volume.Name, createdAt: volume.CreatedAt, mountpoint: volume.Mountpoint, driver: volume.Driver, scope: volume.Scope } });
}
