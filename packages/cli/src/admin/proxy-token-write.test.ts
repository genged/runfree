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

function write(tokenFile: string, declared: string, received: string, env: NodeJS.ProcessEnv = process.env): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync("/bin/sh", ["-c", proxyTokenWriteScript(tokenFile, Buffer.byteLength(declared, "utf8"))], {
    encoding: "utf8",
    env,
    input: received,
  });
}

function temporaries(tokenFile: string): string[] {
  const base = `${path.basename(tokenFile)}.tmp`;
  return fs.readdirSync(path.dirname(tokenFile)).filter((name) => name === base || name.startsWith(`${base}.`));
}

describe("proxy token write", () => {
  test("a short stdin does not replace the existing token", () => {
    const tokenFile = path.join(secrets, "github");
    fs.writeFileSync(tokenFile, "held-value", { mode: 0o600 });
    const value = "rotated-value-0123456789";

    const result = write(tokenFile, value, value.slice(0, 7));

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("proxy token write incomplete; the partial value was discarded");
    expect(fs.readFileSync(tokenFile, "utf8")).toBe("held-value");
    expect(temporaries(tokenFile)).toEqual([]);
  });

  test("a byte count that cannot be obtained refuses the write", () => {
    const tokenFile = path.join(secrets, "github");
    fs.writeFileSync(tokenFile, "held-value", { mode: 0o600 });
    // A `wc` that prints nothing and fails, ahead of the real tools.
    const brokenTools = path.join(secrets, "broken-tools");
    fs.mkdirSync(brokenTools);
    fs.writeFileSync(path.join(brokenTools, "wc"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
    const value = "rotated-value-0123456789";

    const result = write(tokenFile, value, value, { ...process.env, PATH: `${brokenTools}${path.delimiter}${process.env.PATH ?? ""}` });

    expect(result.status).not.toBe(0);
    expect(fs.readFileSync(tokenFile, "utf8")).toBe("held-value");
    expect(temporaries(tokenFile)).toEqual([]);
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
    expect(temporaries(tokenFile)).toEqual([]);
  });

  test("a lingering write keeps its own temporary file, so a later write cannot mix bytes with it", async () => {
    const tokenFile = path.join(secrets, "github");
    fs.writeFileSync(tokenFile, "held-value", { mode: 0o600 });
    const lingering = "lingering-value-0123456789";
    // A write whose client was killed but whose remote shell still runs: it
    // has its temporary file open and only part of its value written.
    const first = childProcess.spawn("/bin/sh", ["-c", proxyTokenWriteScript(tokenFile, Buffer.byteLength(lingering, "utf8"))], { stdio: ["pipe", "ignore", "pipe"] });
    const firstExit = new Promise<number | null>((resolve) => first.on("exit", (code) => resolve(code)));
    first.stdin.write(lingering.slice(0, 9));
    const deadline = Date.now() + 5_000;
    while (temporaries(tokenFile).length === 0 || fs.statSync(path.join(secrets, temporaries(tokenFile)[0])).size < 9) {
      if (Date.now() > deadline) throw new Error("the first write never created its temporary file");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    const [firstTemporary] = temporaries(tokenFile);

    const next = "next-value-abcdefghijklmnop";
    const second = write(tokenFile, next, next);
    expect(second.status, second.stderr).toBe(0);
    expect(fs.readFileSync(tokenFile, "utf8")).toBe(next);
    // The later write neither removed nor wrote into the lingering one's file.
    expect(temporaries(tokenFile)).toEqual([firstTemporary]);
    expect(fs.readFileSync(path.join(secrets, firstTemporary), "utf8")).toBe(lingering.slice(0, 9));

    first.stdin.end(lingering.slice(9));
    expect(await firstExit).toBe(0);
    expect(fs.readFileSync(tokenFile, "utf8")).toBe(lingering);
    expect(temporaries(tokenFile)).toEqual([]);
  });

  test("a write with no bytes to declare is refused before any command is built", () => {
    expect(() => proxyTokenWriteScript("/run/runfree-proxy-secrets/github", 0)).toThrow();
  });
});
