import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import {
  relativeDisplay,
  safeReadProjectFile,
  safeRemoveEmptyProjectDir,
  safeReplaceProjectFile,
  statKind,
} from "./safe-fs.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-safe-fs-tests-")));
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("safe project filesystem writes", () => {
  test("relativeDisplay formats paths under root", () => {
    expect(relativeDisplay("/project", "/project/.runfree/image/Dockerfile")).toBe(".runfree/image/Dockerfile");
  });

  test("statKind describes regular files", () => {
    const stat = fs.statSync(path.resolve("packages/cli/src/safe-fs.test.ts"));
    expect(statKind(stat)).toBe("regular file");
  });

  test("optional reads treat missing parent directories as absent", () => {
    expect(safeReadProjectFile(tmp, path.join(tmp, ".runfree", "config", "agent.env"))).toBeUndefined();
  });

  test("rejects symlinked parent directories before writing", () => {
    const outside = path.join(tmp, "..", "outside-safe-fs-target");
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.mkdirSync(outside, { recursive: true });
    fs.symlinkSync(outside, path.join(tmp, ".runfree", "config"), "dir");

    expect(() => safeReplaceProjectFile(
      tmp,
      path.join(tmp, ".runfree", "config", "agent.env"),
      "TOKEN=placeholder\n",
    )).toThrow("refusing to write unsafe project-controlled path: .runfree/config");
    expect(fs.existsSync(path.join(outside, "agent.env"))).toBe(false);
  });

  test("rejects symlinked files before reading", () => {
    const outside = path.join(tmp, "..", "outside-agent.env");
    fs.writeFileSync(outside, "SECRET=real\n");
    fs.mkdirSync(path.join(tmp, ".runfree", "config"), { recursive: true });
    fs.symlinkSync(outside, path.join(tmp, ".runfree", "config", "agent.env"));

    expect(() => safeReadProjectFile(tmp, path.join(tmp, ".runfree", "config", "agent.env")))
      .toThrow("refusing to write unsafe project-controlled path: .runfree/config/agent.env");
  });

  test("rejects existing hard-linked destination files", () => {
    const policyPath = path.join(tmp, ".runfree", "network-policy.json");
    fs.mkdirSync(path.dirname(policyPath), { recursive: true });
    fs.writeFileSync(policyPath, "{\"hosts\":[],\"tokens\":{}}\n");
    fs.linkSync(policyPath, path.join(tmp, "policy-hardlink.json"));

    expect(() => safeReplaceProjectFile(tmp, policyPath, "{\"hosts\":[\"example.com\"],\"tokens\":{}}\n"))
      .toThrow("links=2");
    expect(fs.readFileSync(policyPath, "utf8")).toBe("{\"hosts\":[],\"tokens\":{}}\n");
  });

  test("removes only a normal empty direct child of the real project root", () => {
    const legacyInbox = path.join(tmp, ".runfree-images");
    fs.mkdirSync(legacyInbox);
    expect(safeRemoveEmptyProjectDir(tmp, legacyInbox)).toBe("removed");
    expect(fs.existsSync(legacyInbox)).toBe(false);

    const nested = path.join(tmp, "nested", ".runfree-images");
    fs.mkdirSync(nested, { recursive: true });
    expect(safeRemoveEmptyProjectDir(tmp, nested)).toBe("kept");
    expect(fs.existsSync(nested)).toBe(true);
  });

  test("keeps non-empty, symlinked, and symlink-parent legacy directories", () => {
    const legacyInbox = path.join(tmp, ".runfree-images");
    fs.mkdirSync(legacyInbox);
    fs.writeFileSync(path.join(legacyInbox, "keep"), "data");
    expect(safeRemoveEmptyProjectDir(tmp, legacyInbox)).toBe("kept");

    fs.rmSync(legacyInbox, { recursive: true });
    const outside = path.join(tmp, "outside");
    fs.mkdirSync(outside);
    fs.symlinkSync(outside, legacyInbox, "dir");
    expect(safeRemoveEmptyProjectDir(tmp, legacyInbox)).toBe("kept");
    expect(fs.lstatSync(legacyInbox).isSymbolicLink()).toBe(true);
    expect(fs.existsSync(outside)).toBe(true);

    const parent = path.dirname(tmp);
    const rootAlias = path.join(parent, `${path.basename(tmp)}-alias`);
    fs.symlinkSync(tmp, rootAlias, "dir");
    fs.mkdirSync(path.join(tmp, "empty"));
    expect(safeRemoveEmptyProjectDir(rootAlias, path.join(rootAlias, "empty"))).toBe("kept");
    expect(fs.existsSync(path.join(tmp, "empty"))).toBe(true);
    fs.rmSync(rootAlias);
  });

  test("keeps the directory when rmdir fails", () => {
    const legacyInbox = path.join(tmp, ".runfree-images");
    fs.mkdirSync(legacyInbox);
    vi.spyOn(fs, "rmdirSync").mockImplementationOnce(() => {
      throw Object.assign(new Error("permission denied"), { code: "EACCES" });
    });
    expect(safeRemoveEmptyProjectDir(tmp, legacyInbox)).toBe("kept");
    expect(fs.existsSync(legacyInbox)).toBe(true);
  });
});
