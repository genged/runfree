import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { describe, expect, test, vi } from "vitest";

import {
  createHeadlessForegroundSpawner,
  type HeadlessPipedChild,
  type HeadlessPipedSpawn,
} from "./headless-foreground.ts";

// Headless-run spec §3.1 "drain": EOF on both captured streams, the end of
// the parser, and the end of the record writes, all with a bound. The Docker
// child's `exit` can come before its last stdout chunk
// (`session-container-start.ts:181`), so exit is never the drain signal.

class FakeChild extends EventEmitter {
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  pid = 4242;
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  kill(): boolean {
    return true;
  }

  exit(code: number): void {
    this.exitCode = code;
    this.emit("exit", code, null);
  }
}

function harness() {
  const children: FakeChild[] = [];
  const calls: Array<{ executable: string; args: readonly string[]; options: unknown }> = [];
  const spawnProcess: HeadlessPipedSpawn = (executable, args, options) => {
    calls.push({ executable, args, options });
    const child = new FakeChild();
    children.push(child);
    return child as unknown as HeadlessPipedChild;
  };
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  const streamEnds: number[] = [];
  const capture = createHeadlessForegroundSpawner({
    stdout: (chunk) => stdout.push(Buffer.from(chunk)),
    stderr: (chunk) => stderr.push(Buffer.from(chunk)),
    stdoutEnded: () => streamEnds.push(Buffer.concat(stdout).length),
  }, { spawnProcess, orderBoundMs: 40 });
  const spawn = (args: readonly string[] = ["start", "--attach", "c1"]) => capture.spawn("docker", args, {
    shell: false,
    stdio: "inherit",
    env: { DOCKER_HOST: "unix:///var/run/docker.sock" },
  });
  return { capture, children, calls, stdout, stderr, streamEnds, spawn };
}

async function settle(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve));
}

describe("headless foreground spawner", () => {
  test("ignores the inherited stdio: no stdin, both output streams piped", () => {
    const { calls, spawn } = harness();
    spawn();
    expect(calls).toEqual([{
      executable: "docker",
      args: ["start", "--attach", "c1"],
      options: { shell: false, stdio: ["ignore", "pipe", "pipe"], env: { DOCKER_HOST: "unix:///var/run/docker.sock" } },
    }]);
  });

  test("an exit before the last stdout chunk drains only after both streams close, with every byte", async () => {
    const { capture, children, stdout, stderr, spawn } = harness();
    spawn();
    const [child] = children;
    if (!child) throw new Error("no child");
    child.stdout.write(Buffer.from("first\n"));
    child.stderr.write(Buffer.from("warn\n"));
    child.exit(0);
    let settled = false;
    const drained = capture.drain(5_000).then((value) => {
      settled = true;
      return value;
    });
    await settle();
    expect(settled).toBe(false);
    child.stdout.end(Buffer.from([0xff, 0x00, 0x0a]));
    await settle();
    expect(settled).toBe(false);
    child.stderr.end();
    expect(await drained).toEqual({ drained: true });
    expect(Buffer.concat(stdout)).toEqual(Buffer.concat([Buffer.from("first\n"), Buffer.from([0xff, 0x00, 0x0a])]));
    expect(Buffer.concat(stderr).toString()).toBe("warn\n");
  });

  test("a stream that never closes is not drained at the bound", async () => {
    const { capture, children, spawn } = harness();
    spawn();
    children[0]?.stdout.end();
    children[0]?.exit(0);
    expect(await capture.drain(30)).toEqual({ drained: false });
  });

  test("a broken stream counts as not drained", async () => {
    const { capture, children, spawn } = harness();
    spawn();
    const child = children[0];
    if (!child) throw new Error("no child");
    child.stdout.destroy(new Error("EPIPE"));
    child.stderr.end();
    expect(await capture.drain(1_000)).toEqual({ drained: false });
  });

  test("nothing spawned is not drained", async () => {
    const { capture } = harness();
    expect(await capture.drain(10)).toEqual({ drained: false });
  });

  test("a re-attached stream is appended after the first stream's last byte", async () => {
    const { capture, children, stdout, streamEnds, spawn } = harness();
    spawn();
    children[0]?.stdout.write("one-a\n");
    children[0]?.exit(1);
    spawn(["attach", "--no-stdin", "c1"]);
    expect(capture.reattached()).toBe(true);
    // The re-attach child prints before the first stream's last chunk lands.
    children[1]?.stdout.write("two\n");
    await settle();
    children[0]?.stdout.end("one-b\n");
    children[0]?.stderr.end();
    await settle();
    children[1]?.stdout.end();
    children[1]?.stderr.end();
    expect(await capture.drain(1_000)).toEqual({ drained: true });
    expect(Buffer.concat(stdout).toString()).toBe("one-a\none-b\ntwo\n");
    expect(streamEnds).toEqual([12, 16]);
  });

  test("a first stream that never closes releases the re-attach after the order bound, undrained", async () => {
    const { capture, children, stdout, spawn } = harness();
    spawn();
    children[0]?.stdout.write("one\n");
    spawn(["attach", "--no-stdin", "c1"]);
    children[1]?.stdout.end("two\n");
    children[1]?.stderr.end();
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(Buffer.concat(stdout).toString()).toBe("one\ntwo\n");
    expect(await capture.drain(20)).toEqual({ drained: false });
  });

  test("a sink that throws never escapes and fails the drain", async () => {
    const children: FakeChild[] = [];
    const capture = createHeadlessForegroundSpawner({
      stdout: () => {
        throw new Error("ENOSPC");
      },
      stderr: () => {},
    }, {
      spawnProcess: () => {
        const child = new FakeChild();
        children.push(child);
        return child as unknown as HeadlessPipedChild;
      },
    });
    capture.spawn("docker", ["start", "--attach", "c1"], { shell: false, stdio: "inherit", env: {} });
    children[0]?.stdout.end("x\n");
    children[0]?.stderr.end();
    expect(await capture.drain(1_000)).toEqual({ drained: false });
  });

  test("the drain waits for the sinks' own flush and fails when it rejects", async () => {
    const flush = vi.fn(async () => {
      throw new Error("fsync failed");
    });
    const children: FakeChild[] = [];
    const capture = createHeadlessForegroundSpawner({ stdout: () => {}, stderr: () => {}, flush }, {
      spawnProcess: () => {
        const child = new FakeChild();
        children.push(child);
        return child as unknown as HeadlessPipedChild;
      },
    });
    capture.spawn("docker", ["start", "--attach", "c1"], { shell: false, stdio: "inherit", env: {} });
    children[0]?.stdout.end();
    children[0]?.stderr.end();
    expect(await capture.drain(1_000)).toEqual({ drained: false });
    expect(flush).toHaveBeenCalledTimes(1);
  });
});
