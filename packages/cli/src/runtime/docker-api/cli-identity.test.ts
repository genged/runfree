import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createNativeDockerCliProbe, firstDockerOnPath, spawnSearchPath } from "./cli-identity.ts";

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

const probe = (searchPath: string) => createNativeDockerCliProbe()({ PATH: searchPath }, true);

describe("native Docker CLI probe", () => {
  it("names an ELF or Mach-O docker first on PATH by its real path", () => {
    const elfDir = binDir({ bytes: ELF });
    expect(probe(elfDir)?.startsWith(`${fs.realpathSync(path.join(elfDir, "docker"))}\u0000`)).toBe(true);
    expect(probe(binDir({ bytes: MACHO }))).toBeDefined();
  });

  it("refuses a script docker (a shim, a wrapper, or a test fake), even with a native one later on PATH", () => {
    expect(probe(binDir({ bytes: SCRIPT }))).toBeUndefined();
    expect(probe(`${binDir({ bytes: SCRIPT })}:${binDir({ bytes: ELF })}`)).toBeUndefined();
  });

  it("skips directories without an executable docker, as the PATH search does", () => {
    expect(probe(`${binDir()}:${binDir({ bytes: ELF, mode: 0o644 })}:${binDir({ bytes: ELF })}`)).toBeDefined();
  });

  it("refuses a relative or empty PATH entry reached before a docker, and an empty PATH", () => {
    expect(probe(`bin:${binDir({ bytes: ELF })}`)).toBeUndefined();
    expect(probe(`:${binDir({ bytes: ELF })}`)).toBeUndefined();
    expect(probe(`.:${binDir({ bytes: ELF })}`)).toBeUndefined();
    expect(probe("")).toBeUndefined();
    expect(probe(binDir())).toBeUndefined();
  });

  it("notices a docker replaced or shadowed mid-process", () => {
    const later = binDir({ bytes: ELF });
    const early = binDir();
    const check = createNativeDockerCliProbe();
    const env = { PATH: `${early}:${later}` };
    const first = check(env, true);
    expect(first).toBeDefined();
    // A script shim put ahead on PATH.
    fs.writeFileSync(path.join(early, "docker"), SCRIPT, { mode: 0o755 });
    expect(check(env, true)).toBeUndefined();
    // The native binary replaced in place by a script.
    fs.rmSync(path.join(early, "docker"));
    fs.rmSync(path.join(later, "docker"));
    fs.writeFileSync(path.join(later, "docker"), SCRIPT, { mode: 0o755 });
    expect(check(env, true)).toBeUndefined();
  });

  it("gives a different identity for a different binary", () => {
    const a = firstDockerOnPath(binDir({ bytes: ELF }));
    const b = firstDockerOnPath(binDir({ bytes: ELF }));
    expect(a?.identity).toBeDefined();
    expect(a?.identity).not.toBe(b?.identity);
  });
});

describe("spawnSearchPath", () => {
  it("follows spawnSync's lookup: the call env's PATH, /usr/bin:/bin for an env without PATH", () => {
    expect(spawnSearchPath({ PATH: "/a:/b" }, true)).toBe("/a:/b");
    expect(spawnSearchPath({}, true)).toBe("/usr/bin:/bin");
    // No call env: process.env without PATH searches nothing.
    expect(spawnSearchPath({}, false)).toBe("");
    expect(spawnSearchPath({ PATH: "/a" }, false)).toBe("/a");
  });
});
