// Host-rendered CA bundle for agent-side TLS trust (cutover decision D-4).
//
// The legacy shared agent gets the proxy CA into its *system* trust store by a
// root exec of `update-ca-certificates` at startup. Session containers never
// run that exec — their first process is the validated launch argv, by design —
// so every tool that reads the system store (`SSL_CERT_FILE`,
// `REQUESTS_CA_BUNDLE`: Python, OpenSSL CLIs, rustls-native-certs consumers)
// silently lacked the proxy CA in sessions.
//
// The remedy renders the trust the exec used to install, host-side, once: the
// selected agent image's own system roots (extracted through a hardened
// ephemeral helper, since the roots ship inside the image) concatenated with
// the proxy CA, written into the project CA directory that is already mounted
// read-only at /etc/proxy-ca in every agent-position container. The agent
// environment points the file-based trust variables at the result, so
// intercepted TLS verifies against the proxy CA and audit-mode passthrough
// TLS still verifies against the real roots — with no container-side setup at
// all. The legacy root exec becomes redundant and retires with the cutover.
//
// Rendering is cached on (agent image reference, proxy CA content): image
// references are input-addressed, so a rebuilt image changes the key, and a
// rotated CA changes it too. The warm startup path re-checks with two file
// reads and no Docker call.

import fs from "node:fs";
import path from "node:path";

import { warn } from "../warnings.ts";
import { EPHEMERAL_HELPER_FENCE_REQUIRED, runEphemeralHelper, type EphemeralHelperFence } from "./ephemeral-helper.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";
import { sha256Digest as sha256 } from "../strict-primitives.ts";

export const CA_BUNDLE_FILE = "ca-bundle.crt";
export const CA_BUNDLE_CONTAINER_PATH = "/etc/proxy-ca/ca-bundle.crt";
const CA_BUNDLE_META_FILE = "ca-bundle.meta.json";
const PROXY_CA_FILE = "proxy-ca.crt";
const CA_BUNDLE_META_VERSION = 1;
const MAX_SYSTEM_ROOTS_BYTES = 2 * 1024 * 1024;
const CERTIFICATE_MARKER = "-----BEGIN CERTIFICATE-----";
const CERTIFICATE_END_MARKER = "-----END CERTIFICATE-----";
const PROXY_CA_WAIT_ATTEMPTS = 100;
const PROXY_CA_WAIT_DELAY_MS = 100;

type CaBundleMeta = Readonly<{
  version: typeof CA_BUNDLE_META_VERSION;
  agentImage: string;
  proxyCaSha256: string;
  /**
   * Digest of the rendered bundle itself. The bundle and its metadata are two
   * files replaced in sequence, so a crash between the renames leaves a torn
   * pair; verifying this on every cache hit is what makes them transactional —
   * a bundle that does not match the metadata's inputs re-renders instead of
   * being served as someone else's trust.
   */
  bundleSha256: string;
}>;


function readMeta(metaPath: string): CaBundleMeta | undefined {
  let source: string;
  try {
    source = fs.readFileSync(metaPath, "utf8");
  } catch {
    return undefined;
  }
  try {
    const parsed = JSON.parse(source) as Record<string, unknown>;
    if (parsed.version !== CA_BUNDLE_META_VERSION) return undefined;
    if (typeof parsed.agentImage !== "string"
      || typeof parsed.proxyCaSha256 !== "string"
      || typeof parsed.bundleSha256 !== "string") {
      return undefined;
    }
    return {
      version: CA_BUNDLE_META_VERSION,
      agentImage: parsed.agentImage,
      proxyCaSha256: parsed.proxyCaSha256,
      bundleSha256: parsed.bundleSha256,
    };
  } catch {
    return undefined;
  }
}

/**
 * Renders (or reuses) the combined CA bundle beside the proxy CA.
 *
 * Requires the proxy CA to exist already — the caller runs after proxy
 * readiness, which is what publishes it. Returns 0 on success; any failure
 * warns with its exact cause and returns 1, and the caller is expected to
 * fail startup closed: the agent environment points at the bundle, so
 * continuing without it would trade a loud startup error for quiet TLS
 * failures inside every session.
 */
export function ensureAgentCaBundle(
  context: RuntimeContext,
  io: RuntimeIO,
  input: Readonly<{
    agentImage: string;
    projectId: string;
    /** The image the extraction helper runs: the bound selected image id when known. */
    helperImage?: string;
    /** Required to run the extraction helper; without it rendering fails closed. */
    helperFence?: EphemeralHelperFence;
  }>,
): number {
  const certDir = context.project.paths.proxyCaCertDir;
  const proxyCaPath = path.join(certDir, PROXY_CA_FILE);
  let proxyCa: string;
  try {
    proxyCa = fs.readFileSync(proxyCaPath, "utf8");
  } catch (error) {
    warn(`agent CA bundle failed: proxy CA is not readable at ${proxyCaPath}: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
  if (!proxyCa.includes(CERTIFICATE_MARKER)) {
    warn(`agent CA bundle failed: ${proxyCaPath} does not contain a PEM certificate`);
    return 1;
  }
  const proxyCaSha256 = sha256(proxyCa);
  const bundlePath = path.join(certDir, CA_BUNDLE_FILE);
  const metaPath = path.join(certDir, CA_BUNDLE_META_FILE);
  const meta = readMeta(metaPath);
  if (meta && meta.agentImage === input.agentImage && meta.proxyCaSha256 === proxyCaSha256) {
    // A hit is accepted only when the bundle on disk is byte-exactly the one
    // this metadata described: existence alone would accept a torn pair left
    // by a crash between the two renames below.
    let existing: string | undefined;
    try {
      existing = fs.readFileSync(bundlePath, "utf8");
    } catch {
      existing = undefined;
    }
    if (existing !== undefined && sha256(existing) === meta.bundleSha256) return 0;
  }

  if (!input.helperFence) {
    warn(`agent CA bundle failed: ${EPHEMERAL_HELPER_FENCE_REQUIRED}`);
    return 1;
  }
  const extracted = runEphemeralHelper(context, io, {
    purpose: "trust-bundle",
    projectId: input.projectId,
    image: input.helperImage ?? input.agentImage,
    user: "1000:1000",
    command: ["cat", "/etc/ssl/certs/ca-certificates.crt"],
  }, input.helperFence);
  if (extracted.status !== 0) {
    const detail = extracted.stderr.trim().slice(0, 300);
    warn(`agent CA bundle failed: could not extract system roots from ${input.agentImage}${detail ? `: ${detail}` : ""}`);
    return 1;
  }
  const systemRoots = extracted.stdout;
  if (!systemRoots.includes(CERTIFICATE_MARKER) || Buffer.byteLength(systemRoots) > MAX_SYSTEM_ROOTS_BYTES) {
    warn(`agent CA bundle failed: ${input.agentImage} produced an implausible system root bundle`);
    return 1;
  }

  const bundle = `${systemRoots.trimEnd()}\n${proxyCa.trimEnd()}\n`;
  try {
    // Atomic within the directory: containers see either the previous bundle
    // or the new one, never a partial write, through the read-only mount.
    const temporary = path.join(certDir, `.${CA_BUNDLE_FILE}.${process.pid}.tmp`);
    fs.writeFileSync(temporary, bundle, { mode: 0o644 });
    fs.renameSync(temporary, bundlePath);
    const temporaryMeta = path.join(certDir, `.${CA_BUNDLE_META_FILE}.${process.pid}.tmp`);
    fs.writeFileSync(
      temporaryMeta,
      `${JSON.stringify({
        version: CA_BUNDLE_META_VERSION,
        agentImage: input.agentImage,
        proxyCaSha256,
        bundleSha256: sha256(bundle),
      } satisfies CaBundleMeta)}\n`,
      { mode: 0o644 },
    );
    fs.renameSync(temporaryMeta, metaPath);
  } catch (error) {
    warn(`agent CA bundle failed: could not write ${bundlePath}: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
  return 0;
}

/**
 * Waits (bounded) for the proxy to publish its CA into the shared cert dir.
 *
 * Pre-cutover this synchronization was a side effect of the shared-agent trust
 * setup exec, whose in-container wait blocked until the proxy wrote its CA.
 * Per-session runtimes have no such exec, so on a fresh runtime the host-side
 * bundle render would otherwise race the proxy's first-start CA generation and
 * fail closed on ENOENT. Requires a complete PEM (both markers) so a torn read
 * of the proxy's non-atomic write is never mistaken for readiness. Returns true
 * once the CA is published, false on timeout — the caller fails startup closed.
 */
export async function waitForProxyCaPublished(
  context: RuntimeContext,
  options: Readonly<{ attempts?: number; delayMs?: number }> = {},
): Promise<boolean> {
  const attempts = options.attempts ?? PROXY_CA_WAIT_ATTEMPTS;
  const delayMs = options.delayMs ?? PROXY_CA_WAIT_DELAY_MS;
  const proxyCaPath = path.join(context.project.paths.proxyCaCertDir, PROXY_CA_FILE);
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const proxyCa = fs.readFileSync(proxyCaPath, "utf8");
      if (proxyCa.includes(CERTIFICATE_MARKER) && proxyCa.includes(CERTIFICATE_END_MARKER)) return true;
    } catch {
      // Not published yet; keep waiting until the bound elapses.
    }
    if (attempt < attempts - 1) await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  return false;
}
