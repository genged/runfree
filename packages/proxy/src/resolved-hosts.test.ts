import dns from "node:dns";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, test, vi } from "vitest";

import {
  createResolvedHostLookup,
  readResolvedHostsFile,
  writeResolvedHostsFile,
  type DnsLookupFunction,
} from "./resolved-hosts.ts";

type LookupResult = {
  address: string;
  family: number;
};

function lookupOne(lookup: ReturnType<typeof createResolvedHostLookup>, hostname: string): Promise<LookupResult> {
  return new Promise((resolve, reject) => {
    lookup(hostname, {}, (error, address, family) => {
      if (error) {
        reject(error);
        return;
      }
      if (typeof address !== "string") {
        reject(new Error("expected one address"));
        return;
      }
      resolve({ address, family: family ?? 0 });
    });
  });
}

function lookupAll(lookup: ReturnType<typeof createResolvedHostLookup>, hostname: string): Promise<dns.LookupAddress[]> {
  return new Promise((resolve, reject) => {
    lookup(hostname, { all: true }, (error, addresses) => {
      if (error) {
        reject(error);
        return;
      }
      if (!Array.isArray(addresses)) {
        reject(new Error("expected all addresses"));
        return;
      }
      resolve(addresses);
    });
  });
}

describe("proxy resolved host lookup", () => {
  test("answers allowed hostnames from the privileged firewall snapshot without process DNS fallback", async () => {
    const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resolved-hosts-")));
    const snapshotPath = path.join(tmp, "hosts.json");
    const fallbackLookupMock = vi.fn((hostname: string, optionsOrCallback: unknown, maybeCallback?: unknown) => {
      const cb = typeof optionsOrCallback === "function" ? optionsOrCallback : maybeCallback;
      if (!cb) throw new Error("missing callback");
      (cb as (error: NodeJS.ErrnoException | null, address: string, family: number) => void)(null, "127.0.0.1", 4);
    });
    const fallbackLookup = fallbackLookupMock as unknown as DnsLookupFunction;

    writeResolvedHostsFile(snapshotPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: {
        "api.github.com": ["140.82.112.5", "140.82.113.5"],
      },
    });

    const lookup = createResolvedHostLookup({ path: snapshotPath, fallbackLookup });
    await expect(lookupOne(lookup, "api.github.com")).resolves.toEqual({ address: "140.82.112.5", family: 4 });
    await expect(lookupAll(lookup, "api.github.com")).resolves.toEqual([
      { address: "140.82.112.5", family: 4 },
      { address: "140.82.113.5", family: 4 },
    ]);
    await expect(lookupOne(lookup, "unmapped.example")).rejects.toMatchObject({
      code: "ENOTFOUND",
      hostname: "unmapped.example",
      syscall: "getaddrinfo",
    });
    expect(fallbackLookupMock).not.toHaveBeenCalledWith(
      "unmapped.example",
      expect.anything(),
      expect.anything(),
    );

    fs.rmSync(tmp, { recursive: true, force: true });
  });

  test("consults the dedicated audit snapshot as a secondary source", async () => {
    const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resolved-hosts-")));
    const snapshotPath = path.join(tmp, "hosts.json");
    const auditPath = path.join(tmp, "audit-hosts.json");
    writeResolvedHostsFile(snapshotPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: { "api.github.com": ["140.82.112.5"] },
    });
    writeResolvedHostsFile(auditPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: { "observed.example": ["203.0.113.9"] },
    });

    const lookup = createResolvedHostLookup({
      path: snapshotPath,
      auditPath,
      auditRetry: { totalMs: 0 },
    });
    // The enforce snapshot stays primary; the audit snapshot only answers
    // hosts the enforce snapshot does not know.
    await expect(lookupOne(lookup, "api.github.com")).resolves.toEqual({ address: "140.82.112.5", family: 4 });
    await expect(lookupOne(lookup, "observed.example")).resolves.toEqual({ address: "203.0.113.9", family: 4 });

    fs.rmSync(tmp, { recursive: true, force: true });
  });

  test("retries briefly for just-observed audit hosts and fails immediately without an audit snapshot", async () => {
    const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resolved-hosts-")));
    const snapshotPath = path.join(tmp, "hosts.json");
    const auditPath = path.join(tmp, "audit-hosts.json");
    writeResolvedHostsFile(snapshotPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: {},
    });
    const lookup = createResolvedHostLookup({
      path: snapshotPath,
      auditPath,
      auditRetry: { totalMs: 500, intervalMs: 20 },
    });

    // Enforce mode: the audit snapshot is absent, so failures surface
    // immediately as before (no retry window).
    const started = Date.now();
    await expect(lookupOne(lookup, "observed.example")).rejects.toMatchObject({ code: "ENOTFOUND" });
    expect(Date.now() - started).toBeLessThan(200);

    // Audit mode: the supervisor installs the host on its next fast tick;
    // the bounded retry picks it up instead of erroring.
    writeResolvedHostsFile(auditPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: {},
    });
    const pending = lookupOne(lookup, "observed.example");
    setTimeout(() => {
      writeResolvedHostsFile(auditPath, {
        generation: `sha256:${"a".repeat(64)}`,
        hosts: { "observed.example": ["203.0.113.9"] },
      });
    }, 60);
    await expect(pending).resolves.toEqual({ address: "203.0.113.9", family: 4 });

    // The retry window is bounded: a host that never appears still errors.
    const missing = lookupOne(lookup, "never-installed.example");
    await expect(missing).rejects.toMatchObject({ code: "ENOTFOUND" });

    fs.rmSync(tmp, { recursive: true, force: true });
  });

  test("writes and reads a normalized resolved-host snapshot", () => {
    const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resolved-hosts-")));
    const snapshotPath = path.join(tmp, "hosts.json");
    const generation = `sha256:${"b".repeat(64)}`;

    writeResolvedHostsFile(snapshotPath, {
      generation,
      hosts: {
        "Api.GitHub.Com": ["140.82.113.5", "140.82.112.5", "140.82.112.5"],
        "empty.example": [],
      },
      // Diagnostic only. Normalized like hosts are, deduped, sorted, and never
      // allowed to name a host that did resolve, so the file stays internally
      // consistent: allowlist state is hosts ∪ unresolvedHosts.
      unresolvedHosts: ["Raw.GitHubusercontent.Com", "raw.githubusercontent.com", "Api.GitHub.Com", ""],
    });

    expect(readResolvedHostsFile(snapshotPath)).toEqual({
      schemaVersion: 1,
      generation,
      hosts: {
        "api.github.com": ["140.82.112.5", "140.82.113.5"],
      },
      unresolvedHosts: ["raw.githubusercontent.com"],
    });
    expect(fs.statSync(snapshotPath).mode & 0o777).toBe(0o644);

    fs.rmSync(tmp, { recursive: true, force: true });
  });
});
