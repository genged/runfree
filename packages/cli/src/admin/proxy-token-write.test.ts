import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { proxyTokenWriteScript } from "./admin-core.ts";

// The proxy-side half of a token write, run by a real `sh` against a scratch
// directory standing in for the proxy's secret tmpfs. A Docker client killed
// mid-stdin can hand the remote `cat` an early end of file; the declared
// length is what keeps that short value from replacing the held token.
let secrets: string;

beforeEach(() => {
  secrets = fs.mkdtempSync(path.join(os.tmpdir(), "proxy-token-write-"));
});

afterEach(() => {
  fs.rmSync(secrets, { recursive: true, force: true });
});

function write(tokenFile: string, declared: string, received: string): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync("/bin/sh", ["-c", proxyTokenWriteScript(tokenFile, Buffer.byteLength(declared, "utf8"))], {
    encoding: "utf8",
    input: received,
  });
}

describe("proxy token write", () => {
  test("a short stdin does not replace the existing token", () => {
    const tokenFile = path.join(secrets, "github");
    fs.writeFileSync(tokenFile, "held-value", { mode: 0o600 });
    const value = "rotated-value-0123456789";

    const result = write(tokenFile, value, value.slice(0, 7));

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("proxy token write incomplete; the held token is unchanged");
    expect(fs.readFileSync(tokenFile, "utf8")).toBe("held-value");
    expect(fs.existsSync(`${tokenFile}.tmp`)).toBe(false);
  });

  test("a stdin longer than declared is refused the same way", () => {
    const tokenFile = path.join(secrets, "github");
    fs.writeFileSync(tokenFile, "held-value", { mode: 0o600 });

    const result = write(tokenFile, "short", "short-and-then-more");

    expect(result.status).not.toBe(0);
    expect(fs.readFileSync(tokenFile, "utf8")).toBe("held-value");
  });

  test("the full declared value replaces the token with owner-only permissions", () => {
    const tokenFile = path.join(secrets, "github");
    fs.writeFileSync(tokenFile, "held-value", { mode: 0o600 });
    // Multi-byte characters: the declared length counts bytes, as `wc -c` does.
    const value = "rotated-välue-\u{1F511}";

    const result = write(tokenFile, value, value);

    expect(result.status, result.stderr).toBe(0);
    expect(fs.readFileSync(tokenFile, "utf8")).toBe(value);
    expect(fs.statSync(tokenFile).mode & 0o777).toBe(0o600);
    expect(fs.existsSync(`${tokenFile}.tmp`)).toBe(false);
  });

  test("a write with no bytes to declare is refused before any command is built", () => {
    expect(() => proxyTokenWriteScript("/run/runfree-proxy-secrets/github", 0)).toThrow();
  });
});
