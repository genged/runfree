import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { CredentialCancellationError, createCredentialLifetime } from "./credential-cancellation.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const moduleUrl = new URL("./credential-cancellation.ts", import.meta.url).href;
const signalExitUrl = new URL("../signal-exit.ts", import.meta.url).href;

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "credential-cancellation-"));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

// A probe in its own process, holding the read end of a lifetime pipe at fd 3
// the way the watcher does: its own signals and an inherited pipe are process
// state a test worker must not share. It reports one JSON line per step.
function startProbe(body: string): { child: childProcess.ChildProcess; lines: () => Record<string, unknown>[]; exited: Promise<number | null> } {
  const file = path.join(tmp, "probe.mts");
  fs.writeFileSync(file, `
import { createCredentialLifetime, CredentialCancellationError } from ${JSON.stringify(moduleUrl)};
import { installSignalExit } from ${JSON.stringify(signalExitUrl)};
const report = (line: Record<string, unknown>) => process.stdout.write(JSON.stringify(line) + "\\n");
const blockFor = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
void CredentialCancellationError; void installSignalExit; void blockFor;
${body}
`);
  const child = childProcess.spawn(process.execPath, ["--import", "tsx", file], {
    cwd: repoRoot,
    stdio: ["ignore", "pipe", "pipe", "pipe"],
  });
  let out = "";
  child.stdout?.on("data", (chunk) => {
    out += String(chunk);
  });
  child.stderr?.on("data", () => {});
  child.stdio[3]?.on("error", () => {});
  const exited = new Promise<number | null>((resolve) => child.on("exit", (code) => resolve(code)));
  return {
    child,
    lines: () => out.split("\n").filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>),
    exited,
  };
}

async function waitFor(predicate: () => boolean, timeoutMs = 30_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate() && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
  return predicate();
}

describe("credential lifetime", () => {
  test("a closed lifetime pipe is seen by a synchronous check, with no event-loop turn", async () => {
    // The probe never yields: only the synchronous pipe probe can see the end.
    const probe = startProbe(`
const lifetime = createCredentialLifetime({ lifetimeFd: 3, signals: [] });
lifetime.assertActive();
report({ step: "open" });
let cause: unknown;
for (let waited = 0; waited < 20_000 && cause === undefined; waited += 20) {
  try {
    lifetime.assertActive();
    blockFor(20);
  } catch (error) {
    cause = error instanceof CredentialCancellationError ? error.stopCause : String(error);
  }
}
report({ step: "stopped", cause, aborted: lifetime.signal.aborted });
await lifetime.close();
`);
    expect(await waitFor(() => probe.lines().some((line) => line.step === "open"))).toBe(true);
    probe.child.stdio[3]?.destroy();
    expect(await probe.exited).toBe(0);
    expect(probe.lines()).toContainEqual({ step: "stopped", cause: "lifetime-closed", aborted: true });
  }, 60_000);

  test("a stop signal stops the lifetime instead of exiting, and close releases the signal exit", async () => {
    const probe = startProbe(`
const exits: number[] = [];
installSignalExit({ flush: () => {}, restore: () => {}, exit: (code) => exits.push(code) });
const baseline = process.listenerCount("SIGINT");
const lifetime = createCredentialLifetime({ lifetimeFd: 3 });
process.kill(process.pid, "SIGINT");
await new Promise((resolve) => setTimeout(resolve, 200));
let cause: unknown;
try { lifetime.assertActive(); } catch (error) { cause = (error as CredentialCancellationError).stopCause; }
await lifetime.close();
report({ cause, aborted: lifetime.signal.aborted, exits, listenersRestored: process.listenerCount("SIGINT") === baseline - 1 });
`);
    expect(await probe.exited).toBe(0);
    // The CLI's own one-shot handler ran (and was consumed) but did not exit.
    expect(probe.lines()).toEqual([{ cause: "SIGINT", aborted: true, exits: [], listenersRestored: true }]);
  }, 60_000);

  test("a closed lifetime lets the process exit while the parent still holds the pipe", async () => {
    const probe = startProbe(`
const lifetime = createCredentialLifetime({ lifetimeFd: 3 });
process.kill(process.pid, "SIGTERM");
await new Promise((resolve) => setTimeout(resolve, 100));
await lifetime.close();
report({ closed: lifetime.stopCause() });
`);
    // The test keeps its end of the pipe open throughout.
    const code = await Promise.race([probe.exited, new Promise<"hung">((resolve) => setTimeout(() => resolve("hung"), 15_000))]);
    if (code === "hung") probe.child.kill("SIGKILL");
    expect(code).toBe(0);
    expect(probe.lines()).toEqual([{ closed: "SIGTERM" }]);
  }, 60_000);

  test("a failed parent probe stops the lifetime", () => {
    let alive = true;
    const lifetime = createCredentialLifetime({ signals: [], parentAlive: () => alive });
    expect(() => lifetime.assertActive()).not.toThrow();
    alive = false;
    expect(() => lifetime.assertActive()).toThrow(CredentialCancellationError);
    expect(lifetime.stopCause()).toBe("parent-gone");
    return lifetime.close();
  });

  test("close aborts and joins owned work before it resolves, and never throws", async () => {
    const lifetime = createCredentialLifetime({ signals: [] });
    const order: string[] = [];
    void lifetime.own(new Promise<void>((resolve) => {
      lifetime.signal.addEventListener("abort", () => setTimeout(() => {
        order.push("owned work settled");
        resolve();
      }, 50));
    }));
    void lifetime.own(Promise.reject(new Error("owned work failed")));
    await lifetime.close();
    order.push("closed");
    expect(order).toEqual(["owned work settled", "closed"]);
    expect(() => lifetime.assertActive()).toThrow(CredentialCancellationError);
  });
});
