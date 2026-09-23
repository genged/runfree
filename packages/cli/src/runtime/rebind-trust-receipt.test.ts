import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test, vi } from "vitest";

import type { ActiveRuntimePlan } from "./plan.ts";
import { captureRebindTrustReceipt } from "./rebind-trust-receipt.ts";
import type { RuntimeIO } from "./types.ts";

const COMPOSE_PROJECT = "runfree-trust-receipt";
const OAUTH_VOLUME = `${COMPOSE_PROJECT}_runfree-oauth-state`;
const SYSTEM_ROOTS = "-----BEGIN CERTIFICATE-----\nsystemroot\n-----END CERTIFICATE-----\n";

type CaMaterial = { certificate: string; privateKey: string };

// Node parses X.509 but cannot issue it, so the pairs are minted at test time
// by the same `openssl` the proxy server harness already depends on. Nothing
// is checked into the repo: a retained CA private key is the one input this
// module exists to guard.
function mintCa(directory: string): CaMaterial {
  const certPath = path.join(directory, "minted.crt");
  const keyPath = path.join(directory, "minted.key");
  childProcess.execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
    "-keyout", keyPath, "-out", certPath, "-subj", "/CN=runfree-test-proxy-ca", "-days", "1",
  ], { stdio: "ignore" });
  return { certificate: fs.readFileSync(certPath, "utf8"), privateKey: fs.readFileSync(keyPath, "utf8") };
}

let mintDir: string;
let retained: CaMaterial;
let foreign: CaMaterial;
let tmp: string;
let keyDir: string;
let certDir: string;

beforeAll(() => {
  mintDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-trust-receipt-ca-"));
  retained = mintCa(mintDir);
  foreign = mintCa(mintDir);
});

afterAll(() => {
  fs.rmSync(mintDir, { recursive: true, force: true });
});

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-trust-receipt-"));
  keyDir = path.join(tmp, "proxy-ca", "private");
  certDir = path.join(tmp, "proxy-ca", "public");
  fs.mkdirSync(keyDir, { recursive: true });
  fs.mkdirSync(certDir, { recursive: true });
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** Lays down the retained trust exactly as the proxy publishes it. */
function publish(material: CaMaterial, options: { key?: CaMaterial; bundle?: string } = {}, target = { keyDir, certDir }): void {
  fs.writeFileSync(path.join(target.certDir, "proxy-ca.crt"), material.certificate);
  fs.writeFileSync(path.join(target.keyDir, "proxy-ca.key"), (options.key ?? material).privateKey);
  fs.writeFileSync(path.join(target.certDir, "ca-bundle.crt"), options.bundle ?? SYSTEM_ROOTS + material.certificate);
}

function planFixture(paths = { keyDir, certDir }): ActiveRuntimePlan {
  return {
    composeProjectName: COMPOSE_PROJECT,
    paths: { proxyCaKeyDir: paths.keyDir, proxyCaCertDir: paths.certDir },
    execution: { dockerClientEnv: {} },
  } as unknown as ActiveRuntimePlan;
}

/**
 * One `docker volume inspect` listing. An override set to `undefined` drops
 * that field from the emitted JSON, which is how a real daemon on another
 * version would present a field this module requires.
 */
function volumeJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify([{
    Name: OAUTH_VOLUME,
    Driver: "local",
    Mountpoint: `/var/lib/docker/volumes/${OAUTH_VOLUME}/_data`,
    Scope: "local",
    CreatedAt: "2026-08-27T00:00:00Z",
    Labels: {
      "com.docker.compose.project": COMPOSE_PROJECT,
      "com.docker.compose.volume": "runfree-oauth-state",
      "com.docker.compose.version": "2.30.0",
    },
    ...overrides,
  }]);
}

function inspectionIo(result: { status?: number; stdout?: string; stderr?: string } = {}) {
  const capture = vi.fn((_command: string, _args: string[], _options?: unknown) => ({
    status: result.status ?? 0,
    stdout: result.stdout ?? volumeJson(),
    stderr: result.stderr ?? "",
  }));
  return { io: { capture } as unknown as RuntimeIO, capture };
}

describe("captureRebindTrustReceipt", () => {
  test("refuses a CA key and certificate that do not pair, before it inspects anything", () => {
    // A replacement proxy handed a certificate it holds no key for would serve
    // trust it cannot use; worse, the key could be an attacker's. The SPKI
    // compare is the only thing that ties the two retained files together.
    publish(retained, { key: foreign });
    const { io, capture } = inspectionIo();

    expect(() => captureRebindTrustReceipt(planFixture(), io, () => undefined))
      .toThrow(/retained CA key and certificate disagree/);
    expect(capture).not.toHaveBeenCalled();
  });

  test.each([
    ["a foreign CA", (): string => SYSTEM_ROOTS + foreign.certificate],
    ["system roots only", (): string => SYSTEM_ROOTS],
    ["a truncated copy of the proxy CA", (): string => `${SYSTEM_ROOTS}${retained.certificate.slice(0, retained.certificate.length - 40)}\n`],
  ] as const)("refuses an agent trust bundle carrying %s instead of the proxy CA", (_label, bundle) => {
    // The agent trusts the bundle, not the CA file. A bundle that lost the
    // proxy CA means the retained trust no longer describes what the agent
    // would accept from a replacement proxy.
    publish(retained, { bundle: bundle() });
    const { io, capture } = inspectionIo();

    expect(() => captureRebindTrustReceipt(planFixture(), io, () => undefined))
      .toThrow(/retained agent trust bundle does not contain the proxy CA/);
    expect(capture).not.toHaveBeenCalled();
  });

  test.each([
    ["the inspection exits nonzero", { status: 1, stdout: "" }],
    ["the daemon writes to stderr despite a zero status", { stderr: "Error response from daemon: volume not found" }],
  ] as const)("refuses creation when %s", (_label, result) => {
    // Unavailable is not absent. Treating an unreadable daemon as "no volume"
    // would let a replacement proxy be created beside an OAuth volume nobody
    // has identified.
    publish(retained);

    expect(() => captureRebindTrustReceipt(planFixture(), inspectionIo(result).io, () => undefined))
      .toThrow(/retained OAuth volume inspection is unavailable/);
  });

  test.each([
    ["the volume answers to another name", volumeJson({ Name: "someone-elses_runfree-oauth-state" })],
    ["the compose project label names another project", volumeJson({
      Labels: { "com.docker.compose.project": "other-project", "com.docker.compose.volume": "runfree-oauth-state" },
    })],
    ["the compose volume label names another volume", volumeJson({
      Labels: { "com.docker.compose.project": COMPOSE_PROJECT, "com.docker.compose.volume": "runfree-workspace" },
    })],
    ["the compose labels are absent entirely", volumeJson({ Labels: undefined })],
    ["CreatedAt is missing", volumeJson({ CreatedAt: undefined })],
    ["CreatedAt is unparseable", volumeJson({ CreatedAt: "recently" })],
    ["CreatedAt is not a string, even one Date.parse would accept", volumeJson({ CreatedAt: 2026 })],
    ["Mountpoint is missing", volumeJson({ Mountpoint: undefined })],
    ["Driver is missing", volumeJson({ Driver: undefined })],
    ["Scope is missing", volumeJson({ Scope: undefined })],
    ["no volume was listed", "[]"],
    ["more than one volume was listed", `[${volumeJson().slice(1, -1)},${volumeJson().slice(1, -1)}]`],
    ["the listing is not an array", volumeJson().slice(1, -1)],
  ] as const)("refuses creation when %s", (_label, stdout) => {
    // Every field here is either the volume's identity or a component of the
    // receipt. An incomplete answer cannot be compared later, and a foreign
    // one would hand a replacement proxy another project's OAuth state.
    publish(retained);

    expect(() => captureRebindTrustReceipt(planFixture(), inspectionIo({ stdout }).io, () => undefined))
      .toThrow(/retained OAuth volume identity is incomplete or foreign/);
  });

  test("returns a receipt that is stable across observations and moves with every input the coordinator compares", () => {
    publish(retained);
    const authority = vi.fn();
    const { io, capture } = inspectionIo();

    const receipt = captureRebindTrustReceipt(planFixture(), io, authority);

    // The inspection names this project's own OAuth volume, not a guess.
    expect(capture.mock.calls[0]?.slice(0, 2)).toEqual(["docker", ["volume", "inspect", OAUTH_VOLUME]]);
    // Authority is re-asserted after the Docker round trip, not only before
    // it: the lifecycle lock can be lost while the daemon is answering.
    expect(authority.mock.invocationCallOrder[0]).toBeLessThan(capture.mock.invocationCallOrder[0] as number);
    expect(authority.mock.invocationCallOrder[1] as number | undefined)
      .toBeGreaterThan(capture.mock.invocationCallOrder[0] as number);
    // The receipt is journalled, so no private bytes may enter it.
    expect(receipt).not.toContain(retained.privateKey.split("\n")[1] as string);

    // Stable: unchanged inputs re-observed must produce the identical string,
    // or the coordinator would refuse every recovery it is meant to allow.
    expect(captureRebindTrustReceipt(planFixture(), inspectionIo().io, () => undefined)).toBe(receipt);

    // Sensitive: a rotated CA pair moves the receipt.
    publish(foreign);
    expect(captureRebindTrustReceipt(planFixture(), inspectionIo().io, () => undefined)).not.toBe(receipt);
    publish(retained);

    // Sensitive: each volume identity field the receipt records moves it, so a
    // volume recreated or re-homed under the same name cannot pass.
    for (const mutation of [
      { CreatedAt: "2026-09-01T00:00:00Z" },
      { Mountpoint: "/var/lib/docker/volumes/elsewhere/_data" },
      { Driver: "overlay" },
      { Scope: "global" },
    ]) {
      expect(captureRebindTrustReceipt(planFixture(), inspectionIo({ stdout: volumeJson(mutation) }).io, () => undefined))
        .not.toBe(receipt);
    }

    // Sensitive: the same trust material mounted from different directories is
    // a different retained mount, and the receipt says so.
    const moved = { keyDir: path.join(tmp, "moved", "private"), certDir: path.join(tmp, "moved", "public") };
    fs.mkdirSync(moved.keyDir, { recursive: true });
    fs.mkdirSync(moved.certDir, { recursive: true });
    publish(retained, {}, moved);
    expect(captureRebindTrustReceipt(planFixture(moved), inspectionIo().io, () => undefined)).not.toBe(receipt);
  });
});
