import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  resolveHostHelper,
  regularExecutableRealpath,
  resolveHostExecutable,
  sanitizedHostExecutionEnv,
  sanitizedPathEntries,
} from "./host-path.ts";

let tmp: string;
let projectRoot: string;
let hostBin: string;

function writeExecutable(filePath: string, contents: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, contents, { mode: 0o755 });
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-host-path-")));
  projectRoot = path.join(tmp, "project");
  hostBin = path.join(tmp, "host-bin");
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.mkdirSync(hostBin, { recursive: true });
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("sanitized host PATH resolution", () => {
  test("drops project-local and node_modules/.bin PATH entries", () => {
    const projectBin = path.join(projectRoot, "bin");
    const dotBin = path.join(tmp, "node_modules", ".bin");
    fs.mkdirSync(projectBin, { recursive: true });
    fs.mkdirSync(dotBin, { recursive: true });
    const env = { PATH: [projectBin, dotBin, "relative/bin", hostBin].join(path.delimiter) };

    expect(sanitizedPathEntries(projectRoot, env)).toEqual([hostBin]);
  });

  test("refuses executables that resolve into the project, even through symlinks", () => {
    writeExecutable(path.join(projectRoot, "evil-gh"), "#!/bin/sh\nexit 0\n");
    fs.symlinkSync(path.join(projectRoot, "evil-gh"), path.join(hostBin, "gh"));
    const env = { PATH: hostBin };

    expect(resolveHostExecutable(projectRoot, env, "gh")).toBeUndefined();
    expect(regularExecutableRealpath(projectRoot, path.join(projectRoot, "evil-gh"))).toBeUndefined();
  });

  test("resolves a host executable outside the project to its real path", () => {
    writeExecutable(path.join(hostBin, "gh"), "#!/bin/sh\nexit 0\n");
    const env = { PATH: hostBin };

    expect(resolveHostExecutable(projectRoot, env, "gh")).toBe(path.join(hostBin, "gh"));
  });

  test("sanitized execution env keeps only identity/XDG vars with non-project path values", () => {
    const env = {
      PATH: hostBin,
      HOME: path.join(tmp, "home"),
      USER: "tester",
      XDG_CONFIG_HOME: path.join(projectRoot, "xdg"),
      SECRET_TOKEN: "leak-me",
    };
    fs.mkdirSync(env.HOME, { recursive: true });

    const clean = sanitizedHostExecutionEnv(projectRoot, env);
    expect(clean.HOME).toBe(env.HOME);
    expect(clean.USER).toBe("tester");
    expect(clean.XDG_CONFIG_HOME).toBeUndefined();
    expect(clean.SECRET_TOKEN).toBeUndefined();
    expect(clean.PATH).toBe(hostBin);
  });
});

describe("resolveHostHelper", () => {
  test("detects a host-resolved helper without running it", () => {
    // The helper writes a file if it ever executes. Detection must not run it:
    // executing a vendor CLI to prove it works also runs whatever that CLI
    // decides to run. `op --version` was observed spawning `ngrok --version`.
    const canary = path.join(tmp, "executed-canary");
    writeExecutable(path.join(hostBin, "gh"), `#!/bin/sh\ntouch ${JSON.stringify(canary)}\nexit 0\n`);

    const probe = resolveHostHelper(projectRoot, { PATH: hostBin }, "gh");

    expect(probe).toEqual({ command: "gh", realPath: path.join(hostBin, "gh") });
    expect(fs.existsSync(canary)).toBe(false);
  });

  test("detects a helper that resolves but would exit non-zero", () => {
    // Deliberate: a broken helper is reported as present and fails where it is
    // actually used. The alternative is executing it here to find out.
    writeExecutable(path.join(hostBin, "broken"), "#!/bin/sh\nexit 3\n");

    expect(resolveHostHelper(projectRoot, { PATH: hostBin }, "broken")).toEqual({
      command: "broken",
      realPath: path.join(hostBin, "broken"),
    });
  });

  test("returns undefined for missing, slash-bearing, or project-resolved helpers", () => {
    const env = { PATH: hostBin };
    expect(resolveHostHelper(projectRoot, env, "gh")).toBeUndefined();

    writeExecutable(path.join(hostBin, "gh"), "#!/bin/sh\nexit 0\n");
    expect(resolveHostHelper(projectRoot, env, "./gh")).toBeUndefined();
    expect(resolveHostHelper(projectRoot, env, "/usr/bin/gh")).toBeUndefined();

    // A helper resolving into the project is never reported, so project
    // content cannot be offered as a host credential helper.
    writeExecutable(path.join(projectRoot, "op"), "#!/bin/sh\nexit 0\n");
    expect(resolveHostHelper(projectRoot, { PATH: path.join(projectRoot) }, "op")).toBeUndefined();
  });
});
