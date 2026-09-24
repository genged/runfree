import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { ensureAgentCaBundle, waitForProxyCaPublished } from "./ca-bundle.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const PROJECT_ID = "0123456789ab";
const CERT = "-----BEGIN CERTIFICATE-----\nproxyca\n-----END CERTIFICATE-----\n";
const ROOTS = "-----BEGIN CERTIFICATE-----\nsystemroot\n-----END CERTIFICATE-----\n";

let tmp: string;
let certDir: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-ca-bundle-"));
  certDir = path.join(tmp, "proxy-ca", "public");
  fs.mkdirSync(certDir, { recursive: true });
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function context(): RuntimeContext {
  return {
    projectRoot: path.join(tmp, "project"),
    env: {},
    project: { paths: { proxyCaCertDir: certDir, stateDir: path.join(tmp, "state") } },
  } as unknown as RuntimeContext;
}

function extractionIo(stdout = ROOTS, status = 0) {
  const capture = vi.fn(() => ({ status, stdout, stderr: "" }));
  return { io: { capture } as unknown as RuntimeIO, capture };
}

describe("ensureAgentCaBundle", () => {
  test("renders system roots plus the proxy CA through a hardened helper and caches on image+CA", () => {
    fs.writeFileSync(path.join(certDir, "proxy-ca.crt"), CERT);
    const { io, capture } = extractionIo();

    expect(ensureAgentCaBundle(context(), io, { agentImage: "runfree-agent:abc", projectId: PROJECT_ID })).toBe(0);

    const bundle = fs.readFileSync(path.join(certDir, "ca-bundle.crt"), "utf8");
    expect(bundle.indexOf("systemroot")).toBeLessThan(bundle.indexOf("proxyca"));
    expect(bundle.endsWith("-----END CERTIFICATE-----\n")).toBe(true);
    // The extraction is one hardened helper run of the selected image itself.
    const [command, args] = capture.mock.calls[0] as unknown as [string, string[]];
    expect(command).toBe("docker");
    expect(args).toEqual(expect.arrayContaining([
      "run",
      "--rm",
      "--network",
      "none",
      "--cap-drop",
      "ALL",
      "--label",
      "io.runfree.helper-purpose=trust-bundle",
      "runfree-agent:abc",
      "cat",
      "/etc/ssl/certs/ca-certificates.crt",
    ]));

    // Unchanged inputs: no second extraction.
    expect(ensureAgentCaBundle(context(), io, { agentImage: "runfree-agent:abc", projectId: PROJECT_ID })).toBe(0);
    expect(capture).toHaveBeenCalledTimes(1);
  });

  test("re-renders when the proxy CA rotates or the selected image changes", () => {
    fs.writeFileSync(path.join(certDir, "proxy-ca.crt"), CERT);
    const { io, capture } = extractionIo();
    ensureAgentCaBundle(context(), io, { agentImage: "runfree-agent:abc", projectId: PROJECT_ID });

    fs.writeFileSync(path.join(certDir, "proxy-ca.crt"), CERT.replace("proxyca", "rotatedca"));
    expect(ensureAgentCaBundle(context(), io, { agentImage: "runfree-agent:abc", projectId: PROJECT_ID })).toBe(0);
    expect(capture).toHaveBeenCalledTimes(2);
    expect(fs.readFileSync(path.join(certDir, "ca-bundle.crt"), "utf8")).toContain("rotatedca");

    expect(ensureAgentCaBundle(context(), io, { agentImage: "runfree-agent:def", projectId: PROJECT_ID })).toBe(0);
    expect(capture).toHaveBeenCalledTimes(3);
  });

  test("re-renders a torn pair: a bundle that does not match the surviving metadata is never a cache hit", () => {
    // A crash between the bundle rename and the metadata rename leaves a new
    // bundle beside old metadata. If the inputs later revert to match that old
    // metadata (an image downgrade), existence alone would serve the wrong
    // trust; the digest check re-renders instead.
    fs.writeFileSync(path.join(certDir, "proxy-ca.crt"), CERT);
    const { io, capture } = extractionIo();
    ensureAgentCaBundle(context(), io, { agentImage: "runfree-agent:abc", projectId: PROJECT_ID });
    fs.writeFileSync(path.join(certDir, "ca-bundle.crt"), "-----BEGIN CERTIFICATE-----\ntorn\n-----END CERTIFICATE-----\n");

    expect(ensureAgentCaBundle(context(), io, { agentImage: "runfree-agent:abc", projectId: PROJECT_ID })).toBe(0);
    expect(capture).toHaveBeenCalledTimes(2);
    expect(fs.readFileSync(path.join(certDir, "ca-bundle.crt"), "utf8")).toContain("systemroot");
  });

  test("re-renders when the bundle file was removed even though the meta survives", () => {
    fs.writeFileSync(path.join(certDir, "proxy-ca.crt"), CERT);
    const { io, capture } = extractionIo();
    ensureAgentCaBundle(context(), io, { agentImage: "runfree-agent:abc", projectId: PROJECT_ID });
    fs.rmSync(path.join(certDir, "ca-bundle.crt"));

    expect(ensureAgentCaBundle(context(), io, { agentImage: "runfree-agent:abc", projectId: PROJECT_ID })).toBe(0);
    expect(capture).toHaveBeenCalledTimes(2);
    expect(fs.existsSync(path.join(certDir, "ca-bundle.crt"))).toBe(true);
  });

  test("fails closed before any extraction when the proxy CA is missing or not a certificate", () => {
    const { io, capture } = extractionIo();
    expect(ensureAgentCaBundle(context(), io, { agentImage: "runfree-agent:abc", projectId: PROJECT_ID })).toBe(1);

    fs.writeFileSync(path.join(certDir, "proxy-ca.crt"), "not a pem\n");
    expect(ensureAgentCaBundle(context(), io, { agentImage: "runfree-agent:abc", projectId: PROJECT_ID })).toBe(1);
    expect(capture).not.toHaveBeenCalled();
    expect(fs.existsSync(path.join(certDir, "ca-bundle.crt"))).toBe(false);
  });

  test.each([
    ["extraction failure", "", 1],
    ["implausible output", "hello, not a certificate", 0],
  ] as const)("fails closed on %s without writing a bundle", (_label, stdout, status) => {
    fs.writeFileSync(path.join(certDir, "proxy-ca.crt"), CERT);
    const { io } = extractionIo(stdout, status);

    expect(ensureAgentCaBundle(context(), io, { agentImage: "runfree-agent:abc", projectId: PROJECT_ID })).toBe(1);
    expect(fs.existsSync(path.join(certDir, "ca-bundle.crt"))).toBe(false);
  });
});

describe("waitForProxyCaPublished", () => {
  const proxyCaPath = () => path.join(certDir, "proxy-ca.crt");

  test("returns immediately once the proxy CA is a complete PEM", async () => {
    fs.writeFileSync(proxyCaPath(), CERT);
    expect(await waitForProxyCaPublished(context(), { attempts: 5, delayMs: 1 })).toBe(true);
  });

  test("tolerates a CA that the proxy publishes a few polls late (the race this closes)", async () => {
    // The per-session flip removed the shared-agent trust exec whose in-container
    // wait used to block until the proxy wrote its CA. This wait is the
    // replacement: it must succeed when the CA lands after the render would
    // otherwise have raced it.
    setTimeout(() => fs.writeFileSync(proxyCaPath(), CERT), 30);
    expect(await waitForProxyCaPublished(context(), { attempts: 50, delayMs: 10 })).toBe(true);
  });

  test("fails closed on timeout when the proxy never publishes its CA", async () => {
    expect(await waitForProxyCaPublished(context(), { attempts: 3, delayMs: 1 })).toBe(false);
  });

  test("does not mistake a torn write (BEGIN marker only) for readiness", async () => {
    // The proxy writes its CA non-atomically, so a partial read must not pass:
    // requiring the END marker keeps a half-written cert from being rendered.
    fs.writeFileSync(proxyCaPath(), "-----BEGIN CERTIFICATE-----\nhalf");
    expect(await waitForProxyCaPublished(context(), { attempts: 3, delayMs: 1 })).toBe(false);
  });
});
