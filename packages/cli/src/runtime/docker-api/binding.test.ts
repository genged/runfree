import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { socketIdentity } from "./binding.ts";

const cleanups: Array<() => void> = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
});

async function listeningSocket(dir: string, name: string): Promise<string> {
  const socketPath = path.join(dir, name);
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  cleanups.push(() => server.close());
  return socketPath;
}

describe("socketIdentity", () => {
  it("names a socket by real path and inode, through a symlink, and changes when the socket is re-created", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-socket-identity-"));
    cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
    const first = await listeningSocket(dir, "a.sock");
    const link = path.join(dir, "docker.sock");
    fs.symlinkSync(first, link);
    const before = socketIdentity(link);
    expect(before?.startsWith(`${fs.realpathSync(first)}\u0000`)).toBe(true);
    // The symlink re-pointed to another engine's socket.
    const second = await listeningSocket(dir, "b.sock");
    fs.rmSync(link);
    fs.symlinkSync(second, link);
    expect(socketIdentity(link)).not.toBe(before);
  });

  it("is undefined for a missing path or a regular file", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-socket-identity-"));
    cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dir, "file"), "");
    expect(socketIdentity(path.join(dir, "file"))).toBeUndefined();
    expect(socketIdentity(path.join(dir, "absent.sock"))).toBeUndefined();
  });
});
