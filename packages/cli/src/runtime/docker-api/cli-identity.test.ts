import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createNativeDockerCliProbe, nativeDockerCliOnPath, spawnSearchPath } from "./cli-identity.ts";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function binDir(docker?: { bytes: Buffer; mode?: number }): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-cli-identity-"));
  dirs.push(dir);
  if (docker) fs.writeFileSync(path.join(dir, "docker"), docker.bytes, { mode: docker.mode ?? 0o755 });
  return dir;
}

const ELF = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60)]);
const MACHO = Buffer.concat([Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), Buffer.alloc(60)]);
const SCRIPT = Buffer.from("#!/bin/sh\nexec podman \"$@\"\n");

describe("nativeDockerCliOnPath", () => {
  it("accepts an ELF or Mach-O docker first on PATH", () => {
    expect(nativeDockerCliOnPath(binDir({ bytes: ELF }))).toBe(true);
    expect(nativeDockerCliOnPath(binDir({ bytes: MACHO }))).toBe(true);
  });

  it("refuses a script docker (a shim, a wrapper, or a test fake), even with a native one later on PATH", () => {
    expect(nativeDockerCliOnPath(binDir({ bytes: SCRIPT }))).toBe(false);
    expect(nativeDockerCliOnPath(`${binDir({ bytes: SCRIPT })}:${binDir({ bytes: ELF })}`)).toBe(false);
  });

  it("skips directories without an executable docker, as the PATH search does", () => {
    expect(nativeDockerCliOnPath(`${binDir()}:${binDir({ bytes: ELF, mode: 0o644 })}:${binDir({ bytes: ELF })}`)).toBe(true);
  });

  it("refuses a relative or empty PATH entry reached before a docker, and an empty PATH", () => {
    expect(nativeDockerCliOnPath(`bin:${binDir({ bytes: ELF })}`)).toBe(false);
    expect(nativeDockerCliOnPath(`:${binDir({ bytes: ELF })}`)).toBe(false);
    expect(nativeDockerCliOnPath("")).toBe(false);
    expect(nativeDockerCliOnPath(binDir())).toBe(false);
  });
});

describe("spawnSearchPath", () => {
  it("follows spawnSync's lookup: the call env's PATH, /usr/bin:/bin for an env without PATH", () => {
    expect(spawnSearchPath({ PATH: "/a:/b" }, true)).toBe("/a:/b");
    expect(spawnSearchPath({}, true)).toBe("/usr/bin:/bin");
  });
});

describe("createNativeDockerCliProbe", () => {
  it("answers per search path", () => {
    const probe = createNativeDockerCliProbe();
    expect(probe({ PATH: binDir({ bytes: ELF }) }, true)).toBe(true);
    expect(probe({ PATH: binDir({ bytes: SCRIPT }) }, true)).toBe(false);
  });
});
