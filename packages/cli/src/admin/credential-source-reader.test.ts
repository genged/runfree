import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { TokenResolutionError } from "../token-resolution.ts";
import { type CommandSourceInvocation, type OnePasswordRead, readOnePasswordRef } from "./admin-core.ts";
import { type CredentialLifetime, createCredentialLifetime } from "./credential-cancellation.ts";
import { type CredentialReadInput, readCredentialSource, runOwnedProvider } from "./credential-source-reader.ts";

// Real processes throughout: the reader's bounds are about what a real
// provider and its descendants do, so no fake stands in for them.
let tmp: string;
let lifetimes: CredentialLifetime[];

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "credential-source-reader-"));
  lifetimes = [];
});

afterEach(async () => {
  for (const lifetime of lifetimes) await lifetime.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

// A watch lifetime with no pipe and no signal listeners: only `close()` stops it.
function watchLifetime(): CredentialLifetime {
  const lifetime = createCredentialLifetime({ signals: [] });
  lifetimes.push(lifetime);
  return lifetime;
}

function script(name: string, body: string): string {
  const file = path.join(tmp, name);
  fs.writeFileSync(file, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  return file;
}

const env = Object.freeze({ PATH: process.env.PATH ?? "/usr/bin:/bin" });

function commandRead(executable: string, timeoutMs = 10_000): CredentialReadInput {
  const invocation: CommandSourceInvocation = { executable, args: [], cwd: tmp, env, timeoutMs, commandName: path.basename(executable) };
  return { tokenName: "probe", fingerprint: "f".repeat(64), plan: { kind: "command", invocation } };
}

function onePasswordRead(executable: string, ref = "op://Private/Item/field"): OnePasswordRead {
  return { executable, ref, env, timeoutMs: 10_000, quiet: true };
}

function processGone(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return false;
  } catch {
    return true;
  }
}

async function waitFor(predicate: () => boolean, timeoutMs = 10_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate() && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
  return predicate();
}

function readPid(file: string): number {
  return Number(fs.readFileSync(file, "utf8").trim());
}

describe("readCredentialSource", () => {
  test("a successful read carries its value and the time the read started", async () => {
    const before = Date.now();
    const result = await readCredentialSource(commandRead(script("ok", "printf 'probe-value\\n'")), watchLifetime());
    expect(result).toEqual({ kind: "success", value: "probe-value", resolvedAt: expect.any(Number) });
    if (result.kind === "success") expect(result.resolvedAt).toBeGreaterThanOrEqual(before);
  });

  test("a provider failure is classified exactly as the synchronous resolver classifies it", async () => {
    for (const [mode, body] of [
      ["empty stderr", "exit 1"],
      ["unmatched stderr", "echo 'not a field secret reference' >&2; exit 1"],
      ["transient stderr", "echo 'connection reset by peer' >&2; exit 1"],
    ] as const) {
      const op = script(`op-${mode.replace(" ", "-")}`, body);
      let synchronous: unknown;
      try {
        readOnePasswordRef(op, "op://Private/Item/field", { quiet: true });
      } catch (error) {
        synchronous = error;
      }
      const owned = await readCredentialSource({ tokenName: "probe", fingerprint: "f".repeat(64), plan: { kind: "1password", read: onePasswordRead(op) } }, watchLifetime());
      expect(synchronous, mode).toBeInstanceOf(TokenResolutionError);
      expect(owned.kind, mode).toBe("source-failure");
      const error = owned.kind === "source-failure" ? owned.error as TokenResolutionError : undefined;
      const expected = synchronous as TokenResolutionError;
      expect({ classification: error?.classification, code: error?.code, message: error?.safeMessage }, mode)
        .toEqual({ classification: expected.classification, code: expected.code, message: expected.safeMessage });
    }
  });

  test("a provider ended by its own signal while the watch is active keeps its definitive classification", async () => {
    const op = script("op-self-term", "kill -TERM $$; sleep 5");
    const result = await readCredentialSource({ tokenName: "probe", fingerprint: "f".repeat(64), plan: { kind: "1password", read: onePasswordRead(op) } }, watchLifetime());
    expect(result.kind).toBe("source-failure");
    const error = result.kind === "source-failure" ? result.error as TokenResolutionError : undefined;
    expect({ classification: error?.classification, code: error?.code }).toEqual({ classification: "definitive", code: "op-read-failed" });
  });

  test("cancellation ends the provider's whole process group, a descendant holding its output included", async () => {
    const pids = path.join(tmp, "pids");
    const provider = script("hang", `sleep 30 & echo $! > '${pids}.child'; echo $$ > '${pids}.leader'; wait`);
    const lifetime = watchLifetime();
    const reading = readCredentialSource(commandRead(provider), lifetime);
    expect(await waitFor(() => fs.existsSync(`${pids}.child`) && fs.existsSync(`${pids}.leader`))).toBe(true);
    const started = Date.now();
    await lifetime.close();
    expect(await reading).toEqual({ kind: "cancelled" });
    expect(Date.now() - started).toBeLessThan(3_500);
    expect(processGone(readPid(`${pids}.leader`))).toBe(true);
    expect(await waitFor(() => processGone(readPid(`${pids}.child`)), 2_000)).toBe(true);
  });

  test("late provider completion cannot publish", async () => {
    // Answers the stop with a value and a clean exit, after the stop.
    const marker = path.join(tmp, "started");
    const provider = script("late", `trap 'echo late-value; exit 0' TERM; touch '${marker}'; while :; do sleep 0.1; done`);
    const lifetime = watchLifetime();
    const reading = readCredentialSource(commandRead(provider), lifetime);
    expect(await waitFor(() => fs.existsSync(marker))).toBe(true);
    await lifetime.close();
    expect(await reading).toEqual({ kind: "cancelled" });
  });

  test("a stopped lifetime starts no provider", async () => {
    const marker = path.join(tmp, "ran");
    const lifetime = watchLifetime();
    await lifetime.close();
    const result = await readCredentialSource(commandRead(script("never", `touch '${marker}'; echo value`)), lifetime);
    expect(result).toEqual({ kind: "cancelled" });
    expect(fs.existsSync(marker)).toBe(false);
  });

  test("a stop during the first op read starts no document fallback", async () => {
    const log = path.join(tmp, "op.log");
    // A document reference whose read hangs: the fallback would run `document get`.
    const op = script("op-doc", `echo "$1" >> '${log}'; [ "$1" = read ] && while :; do sleep 0.1; done; echo document-value`);
    const lifetime = watchLifetime();
    const reading = readCredentialSource({ tokenName: "probe", fingerprint: "f".repeat(64), plan: { kind: "1password", read: onePasswordRead(op, "op://Private/AuthKey") } }, lifetime);
    expect(await waitFor(() => fs.existsSync(log))).toBe(true);
    await lifetime.close();
    expect(await reading).toEqual({ kind: "cancelled" });
    expect(fs.readFileSync(log, "utf8").split("\n").filter(Boolean)).toEqual(["read"]);
  });
});

describe("runOwnedProvider bounds", () => {
  const tight = { graceMs: 300, joinMs: 300 };

  test("a provider that ignores SIGTERM is killed within the bound on cancellation", async () => {
    const pidFile = path.join(tmp, "pid");
    const provider = script("ignore-term", `trap '' TERM; echo $$ > '${pidFile}'; sleep 30`);
    const lifetime = watchLifetime();
    const running = runOwnedProvider(provider, [], { env, timeoutMs: 30_000, maxBytes: 1024 }, lifetime, tight);
    expect(await waitFor(() => fs.existsSync(pidFile))).toBe(true);
    const started = Date.now();
    await lifetime.close();
    expect(await running).toEqual({ kind: "cancelled" });
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(await waitFor(() => processGone(readPid(pidFile)), 2_000)).toBe(true);
  });

  test("a provider that answers the stop with a value and a clean exit reports only the cancellation", async () => {
    const marker = path.join(tmp, "started");
    const provider = script("late-owned", `trap 'echo late-value; exit 0' TERM; touch '${marker}'; while :; do sleep 0.1; done`);
    const lifetime = watchLifetime();
    const running = runOwnedProvider(provider, [], { env, timeoutMs: 30_000, maxBytes: 1024 }, lifetime, tight);
    expect(await waitFor(() => fs.existsSync(marker))).toBe(true);
    await lifetime.close();
    expect(await running).toEqual({ kind: "cancelled" });
  });

  test("a timeout is a hard bound even for a provider that ignores SIGTERM", async () => {
    const pidFile = path.join(tmp, "pid");
    const provider = script("ignore-term-timeout", `trap '' TERM; echo $$ > '${pidFile}'; sleep 30`);
    const started = Date.now();
    const run = await runOwnedProvider(provider, [], { env, timeoutMs: 300, maxBytes: 1024 }, watchLifetime(), tight);
    expect(run).toEqual({ kind: "timeout" });
    expect(Date.now() - started).toBeLessThan(3_000);
    expect(await waitFor(() => processGone(readPid(pidFile)), 2_000)).toBe(true);
  });

  test("a descendant that keeps the output open after the provider exits cannot hold the read past its timeout", async () => {
    const pidFile = path.join(tmp, "pid");
    const provider = script("orphan", `sleep 30 & echo $! > '${pidFile}'; echo value`);
    const started = Date.now();
    const run = await runOwnedProvider(provider, [], { env, timeoutMs: 500, maxBytes: 1024 }, watchLifetime(), tight);
    expect(run).toEqual({ kind: "timeout" });
    expect(Date.now() - started).toBeLessThan(3_000);
    expect(await waitFor(() => processGone(readPid(pidFile)), 2_000)).toBe(true);
  });

  test("output past the bound ends the provider as an overflow, with nothing kept", async () => {
    const run = await runOwnedProvider(script("flood", "while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done"), [], { env, timeoutMs: 10_000, maxBytes: 4096 }, watchLifetime(), tight);
    expect(run).toEqual({ kind: "overflow" });
  });

  test("a missing executable is a spawn error, not an exit", async () => {
    const run = await runOwnedProvider(path.join(tmp, "absent"), [], { env, timeoutMs: 10_000, maxBytes: 1024 }, watchLifetime(), tight);
    expect(run.kind).toBe("spawn-error");
  });
});
