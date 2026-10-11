import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { TokenResolutionError } from "../token-resolution.ts";
import { type CommandSourceInvocation, type CredentialReadPlan, type OnePasswordRead, createCredentialPreparationScope, readOnePasswordRef } from "./admin-core.ts";
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
function watchLifetime(providerGroup: "own" | "terminal" = "own"): CredentialLifetime {
  const lifetime = createCredentialLifetime({ signals: [], providerGroup });
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

function onePasswordRead(executable: string, ref = "op://Private/Item/field", environment: NodeJS.ProcessEnv = env): OnePasswordRead {
  return { executable, ref, env: environment, timeoutMs: 10_000, quiet: true };
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

describe("providers of a watch run at a terminal", () => {
  function processGroup(pid: number): number {
    return Number(childProcess.spawnSync("ps", ["-o", "pgid=", "-p", String(pid)], { encoding: "utf8" }).stdout.trim());
  }

  test("stay in the watch's own process group, and a stop still ends them as a cancellation", async () => {
    const pidFile = path.join(tmp, "pid");
    const provider = script("terminal-hang", `echo $$ > '${pidFile}'; while :; do sleep 0.1; done`);
    const lifetime = watchLifetime("terminal");
    const reading = readCredentialSource(commandRead(provider), lifetime);
    expect(await waitFor(() => fs.existsSync(pidFile))).toBe(true);
    const pid = readPid(pidFile);
    expect(processGroup(pid)).toBe(processGroup(process.pid));
    await lifetime.close();
    expect(await reading).toEqual({ kind: "cancelled" });
    expect(await waitFor(() => processGone(pid), 2_000)).toBe(true);
  });

  test("a watcher-owned provider leads its own process group", async () => {
    const pidFile = path.join(tmp, "pid");
    const provider = script("own-hang", `echo $$ > '${pidFile}'; while :; do sleep 0.1; done`);
    const lifetime = watchLifetime("own");
    const reading = readCredentialSource(commandRead(provider), lifetime);
    expect(await waitFor(() => fs.existsSync(pidFile))).toBe(true);
    const pid = readPid(pidFile);
    expect(processGroup(pid)).toBe(pid);
    await lifetime.close();
    expect(await reading).toEqual({ kind: "cancelled" });
  });

  // A provider that prompts (`op` asking on /dev/tty) needs the controlling
  // terminal, which a provider in a new session does not have. Needs a pty:
  // util-linux `script`, as on the Linux CI host.
  const utilLinuxScript = /util-linux/.test(childProcess.spawnSync("script", ["--version"], { encoding: "utf8" }).stdout ?? "");
  test.skipIf(!utilLinuxScript)("can open the controlling terminal only when the watch keeps them in its group", () => {
    const readerUrl = new URL("./credential-source-reader.ts", import.meta.url).href;
    const cancellationUrl = new URL("./credential-cancellation.ts", import.meta.url).href;
    const provider = script("tty-probe", "if (exec 3</dev/tty) 2>/dev/null; then echo tty-ok; else echo no-tty; fi");
    const probe = path.join(tmp, "probe.mts");
    fs.writeFileSync(probe, `
import { runOwnedProvider } from ${JSON.stringify(readerUrl)};
import { createCredentialLifetime, hasControllingTerminal } from ${JSON.stringify(cancellationUrl)};
const result: Record<string, unknown> = { watchHasTerminal: hasControllingTerminal() };
for (const providerGroup of ["terminal", "own"] as const) {
  const lifetime = createCredentialLifetime({ signals: [], providerGroup });
  const run = await runOwnedProvider(${JSON.stringify(provider)}, [], { env: process.env, timeoutMs: 10_000, maxBytes: 1024 }, lifetime);
  result[providerGroup] = run.kind === "exited" ? run.stdout.trim() : run.kind;
  await lifetime.close();
}
console.log("RESULT " + JSON.stringify(result));
`);
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
    const command = [process.execPath, "--import", "tsx", probe].map((part) => `'${part.replaceAll("'", "'\\''")}'`).join(" ");
    const run = childProcess.spawnSync("script", ["-qec", command, "/dev/null"], { cwd: repoRoot, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 60_000 });
    const line = run.stdout.split(/\r?\n/).find((entry) => entry.startsWith("RESULT "));
    expect(line, `${run.stdout}${run.stderr}`).toBeDefined();
    expect(JSON.parse((line as string).slice("RESULT ".length))).toEqual({ watchHasTerminal: true, terminal: "tty-ok", own: "no-tty" });
  }, 60_000);
});

// F01: a fresh preparation-pass scope shares one successful direct 1Password
// read across every destination that uses the identical executable and exact
// reference. Only a success is ever shared; a failure or a cancellation is
// not, so every destination still gets its own attempt.
describe("createCredentialPreparationScope", () => {
  function countingOp(name: string, logPath: string, output = "shared-value"): string {
    return script(name, `printf 'x\\n' >> '${logPath}'; echo '${output}'`);
  }

  function invocationCount(logPath: string): number {
    if (!fs.existsSync(logPath)) return 0;
    return fs.readFileSync(logPath, "utf8").split("\n").filter(Boolean).length;
  }

  function onePasswordInput(tokenName: string, executable: string, ref = "op://Private/Item/field"): CredentialReadInput {
    return { tokenName, fingerprint: "f".repeat(64), plan: { kind: "1password", read: onePasswordRead(executable, ref) } };
  }

  test("a successful read is shared for every destination using the identical executable and reference", async () => {
    const log = path.join(tmp, "invocations.log");
    const op = countingOp("op-shared", log);
    const scope = createCredentialPreparationScope();
    const lifetime = watchLifetime();
    const first = await scope.read(onePasswordInput("one", op), lifetime);
    const second = await scope.read(onePasswordInput("two", op), lifetime);
    expect(first).toEqual({ kind: "success", value: "shared-value", resolvedAt: expect.any(Number) });
    expect(second).toEqual(first);
    expect(invocationCount(log)).toBe(1);
  });

  test("distinct refs stay distinct", async () => {
    const log = path.join(tmp, "invocations.log");
    const op = countingOp("op-distinct", log);
    const scope = createCredentialPreparationScope();
    const lifetime = watchLifetime();
    await scope.read(onePasswordInput("one", op, "op://Private/Item/one"), lifetime);
    await scope.read(onePasswordInput("two", op, "op://Private/Item/two"), lifetime);
    expect(invocationCount(log)).toBe(2);
  });

  test("changed account or executable is not shared", async () => {
    // Executable axis: same account/context, different resolved binary.
    const execLog = path.join(tmp, "exec-invocations.log");
    const opAccountA = countingOp("op-exec-a", execLog);
    const opAccountB = countingOp("op-exec-b", execLog);
    const execScope = createCredentialPreparationScope();
    const lifetime = watchLifetime();
    await execScope.read(onePasswordInput("one", opAccountA), lifetime);
    await execScope.read(onePasswordInput("two", opAccountB), lifetime);
    expect(invocationCount(execLog)).toBe(2);

    // Account axis: the identical executable and reference, but a different
    // 1Password account selection in the environment (e.g. OP_ACCOUNT).
    // Sharing must not cross accounts even though nothing else differs.
    const accountLog = path.join(tmp, "account-invocations.log");
    const op = countingOp("op-account", accountLog);
    const accountScope = createCredentialPreparationScope();
    const accountA: NodeJS.ProcessEnv = { ...env, OP_ACCOUNT: "team-a.1password.com" };
    const accountB: NodeJS.ProcessEnv = { ...env, OP_ACCOUNT: "team-b.1password.com" };
    const firstAccount = await accountScope.read({ tokenName: "one", fingerprint: "f".repeat(64), plan: { kind: "1password", read: onePasswordRead(op, "op://Private/Item/field", accountA) } }, lifetime);
    await accountScope.read({ tokenName: "two", fingerprint: "f".repeat(64), plan: { kind: "1password", read: onePasswordRead(op, "op://Private/Item/field", accountB) } }, lifetime);
    expect(firstAccount).toEqual({ kind: "success", value: "shared-value", resolvedAt: expect.any(Number) });
    // The discriminating proof: a different account made its own real read
    // rather than reusing the first account's value.
    expect(invocationCount(accountLog)).toBe(2);
  });

  test("a shared document-fallback result shares only the final value", async () => {
    const log = path.join(tmp, "invocations.log");
    // `op read` fails as "not a field secret reference" (the document
    // fallback's trigger), then `op document get` succeeds. Only the final,
    // fully-resolved value is ever shared: a second destination must not
    // reuse an intermediate step, nor cause the two-step fallback to run
    // again.
    const op = script("op-doc-fallback", `printf 'x\\n' >> '${log}'; if [ "$1" = read ]; then echo 'not a field secret reference' >&2; exit 1; fi; echo document-value`);
    const scope = createCredentialPreparationScope();
    const lifetime = watchLifetime();
    const first = await scope.read(onePasswordInput("one", op, "op://Private/AuthKey"), lifetime);
    const second = await scope.read(onePasswordInput("two", op, "op://Private/AuthKey"), lifetime);
    expect(first).toEqual({ kind: "success", value: "document-value", resolvedAt: expect.any(Number) });
    expect(second).toEqual(first);
    // Two invocations total: the first destination's own `read` then
    // `document get`; the second destination makes none.
    expect(invocationCount(log)).toBe(2);
  });

  test("next pass reads again", async () => {
    const log = path.join(tmp, "invocations.log");
    const op = countingOp("op-next-pass", log);
    const lifetime = watchLifetime();
    const firstPass = createCredentialPreparationScope();
    await firstPass.read(onePasswordInput("one", op), lifetime);
    await firstPass.read(onePasswordInput("two", op), lifetime);
    expect(invocationCount(log)).toBe(1);
    // A later preparation pass gets its own fresh scope: nothing persists
    // from the first pass's cache.
    const secondPass = createCredentialPreparationScope();
    await secondPass.read(onePasswordInput("three", op), lifetime);
    expect(invocationCount(log)).toBe(2);
  });

  test("failed read is not cached", async () => {
    const log = path.join(tmp, "invocations.log");
    const op = script("op-fails", `printf 'x\\n' >> '${log}'; echo 'connection reset by peer' >&2; exit 1`);
    const scope = createCredentialPreparationScope();
    const lifetime = watchLifetime();
    const first = await scope.read(onePasswordInput("one", op), lifetime);
    const second = await scope.read(onePasswordInput("two", op), lifetime);
    expect(first.kind).toBe("source-failure");
    expect(second.kind).toBe("source-failure");
    // Not cached: each destination made its own attempt.
    expect(invocationCount(log)).toBe(2);
  });

  test("cancelled read does not become a destination failure", async () => {
    const marker = path.join(tmp, "started");
    // The first invocation touches the marker and hangs, to be cancelled.
    // A second invocation of the identical executable and reference only
    // happens if the cancelled attempt was never cached, and then succeeds
    // for real: if it had been cached (as a success, or — the bug this test
    // guards against — as if a cancellation were a destination failure),
    // the script would never run again and this would not observe a fresh
    // `success`.
    const op = script("op-cancel-then-real", `if [ -f '${marker}' ]; then echo real-value; exit 0; fi; touch '${marker}'; while :; do sleep 0.1; done`);
    const scope = createCredentialPreparationScope();
    const lifetime = watchLifetime();
    const reading = scope.read(onePasswordInput("one", op), lifetime);
    expect(await waitFor(() => fs.existsSync(marker))).toBe(true);
    await lifetime.close();
    expect(await reading).toEqual({ kind: "cancelled" });

    // A later destination with the identical executable and reference, on a
    // fresh active lifetime, makes its own real read rather than reusing
    // anything from the cancelled attempt.
    const freshLifetime = watchLifetime();
    const second = await scope.read(onePasswordInput("two", op), freshLifetime);
    expect(second).toEqual({ kind: "success", value: "real-value", resolvedAt: expect.any(Number) });
  });

  test("dispose clears the scope's asynchronous shared-read cache", async () => {
    const log = path.join(tmp, "invocations.log");
    const op = countingOp("op-dispose-async", log);
    const scope = createCredentialPreparationScope();
    const lifetime = watchLifetime();
    await scope.read(onePasswordInput("one", op), lifetime);
    expect(invocationCount(log)).toBe(1);
    scope.dispose();
    // A later read for the identical executable and reference, after
    // disposal, finds nothing cached: the provider runs again.
    await scope.read(onePasswordInput("two", op), lifetime);
    expect(invocationCount(log)).toBe(2);
  });

  test("dispose clears the scope's synchronous shared-read cache", () => {
    const log = path.join(tmp, "invocations.log");
    const op = countingOp("op-dispose-sync", log);
    const scope = createCredentialPreparationScope();
    const plan: CredentialReadPlan = { kind: "1password", read: onePasswordRead(op) };
    expect(scope.readSync(plan)).toBe("shared-value");
    expect(invocationCount(log)).toBe(1);
    scope.dispose();
    expect(scope.readSync(plan)).toBe("shared-value");
    expect(invocationCount(log)).toBe(2);
  });
});
