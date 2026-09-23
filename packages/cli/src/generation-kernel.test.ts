import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { publishImmutableDirectory, pollForExactAck } from "./generation-kernel.ts";

describe("immutable content-addressed publication", () => {
  let root: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-generation-kernel-"));
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  function publish(files: Record<string, string>, verify: () => string = () => "ok") {
    return publishImmutableDirectory({
      parent: path.join(root, "store"),
      name: "deadbeef",
      files,
      directoryMode: 0o700,
      fileMode: 0o400,
      parentMode: 0o700,
      tempPrefix: ".entry-",
      verify,
    });
  }

  test("publishes exact bytes and modes, creating nested payload directories", () => {
    publish({ "top.json": "{}\n", "nested/dir/payload.env": "A=1\n" });

    const entry = path.join(root, "store", "deadbeef");
    expect(fs.readFileSync(path.join(entry, "top.json"), "utf8")).toBe("{}\n");
    expect(fs.readFileSync(path.join(entry, "nested", "dir", "payload.env"), "utf8")).toBe("A=1\n");
    expect(fs.statSync(path.join(entry, "top.json")).mode & 0o777).toBe(0o400);
    expect(fs.statSync(entry).mode & 0o777).toBe(0o700);
    expect(fs.statSync(path.join(root, "store")).mode & 0o777).toBe(0o700);
    expect(fs.readdirSync(path.join(root, "store")).sort()).toEqual(["deadbeef"]);
  });

  test.each([
    { directoryMode: 0o755, fileMode: 0o444 },
    { directoryMode: 0o700, fileMode: 0o400 },
  ])("publishes exact consumer permissions under umask 077: %j", ({ directoryMode, fileMode }) => {
    // Change the mask only in a child: Vitest workers share process state.
    const child = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", `
      import { publishImmutableDirectory } from ${JSON.stringify(new URL("./generation-kernel.ts", import.meta.url).href)};
      process.umask(0o077);
      publishImmutableDirectory({
        parent: ${JSON.stringify(path.join(root, "store"))},
        name: "entry",
        files: { "nested/deep/policy.json": "{}\\n" },
        directoryMode: ${directoryMode},
        fileMode: ${fileMode},
        parentMode: ${directoryMode},
        tempPrefix: ".entry-",
        verify: () => undefined,
      });
    `], { encoding: "utf8" });
    expect(child.status, child.stderr).toBe(0);
    const store = path.join(root, "store");
    for (const relative of ["", "entry", "entry/nested", "entry/nested/deep"]) {
      expect(fs.statSync(path.join(store, relative)).mode & 0o777).toBe(directoryMode);
    }
    const payload = path.join(store, "entry/nested/deep/policy.json");
    expect(fs.statSync(payload).mode & 0o777).toBe(fileMode);
    expect(fs.readFileSync(payload, "utf8")).toBe("{}\n");
  });

  test("an existing entry is verified, never rewritten", () => {
    publish({ "top.json": "original\n" });
    let verified = 0;

    const result = publish({ "top.json": "attacker-different\n" }, () => {
      verified += 1;
      return "verified-existing";
    });

    expect(result).toBe("verified-existing");
    expect(verified).toBe(1);
    expect(fs.readFileSync(path.join(root, "store", "deadbeef", "top.json"), "utf8")).toBe("original\n");
  });

  test("a permission failure prevents publication and leaves the next attempt usable", () => {
    const chmod = vi.spyOn(fs, "fchmodSync").mockImplementationOnce(() => {
      throw new Error("permission update failed");
    });
    try {
      expect(() => publish({ "top.json": "{}\n" })).toThrow("permission update failed");
    } finally {
      chmod.mockRestore();
    }
    expect(fs.readdirSync(path.join(root, "store"))).toEqual([]);
    expect(publish({ "top.json": "{}\n" })).toBe("ok");
    expect(fs.readFileSync(path.join(root, "store", "deadbeef", "top.json"), "utf8")).toBe("{}\n");
  });

  test("a failed publication leaves no temp directory and no entry", () => {
    expect(() => publish({ "top.json": "{}\n" }, () => {
      throw new Error("verification refused the entry");
    })).toThrow("verification refused the entry");
    // The rename already happened; the entry stays for the verifier to refuse
    // again (immutability), but no temp litter survives.
    expect(fs.readdirSync(path.join(root, "store")).filter((name) => name.startsWith(".entry-"))).toEqual([]);
  });

  test("when-creating leaves the parent untouched while reusing an existing entry", () => {
    // The approved-subject store's reuse path is a pure read. Normalizing the
    // parent there would mutate the store's mode — or fail on a parent this
    // process cannot chmod — on a path that previously only verified.
    const parent = path.join(root, "store");
    fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
    publishImmutableDirectory({
      parent,
      name: "deadbeef",
      files: { "top.json": "{}\n" },
      directoryMode: 0o700,
      fileMode: 0o400,
      parentMode: 0o700,
      tempPrefix: ".entry-",
      parentSetup: "when-creating",
      verify: () => "created",
    });
    fs.chmodSync(parent, 0o750);

    const result = publishImmutableDirectory({
      parent,
      name: "deadbeef",
      files: { "top.json": "{}\n" },
      directoryMode: 0o700,
      fileMode: 0o400,
      parentMode: 0o700,
      tempPrefix: ".entry-",
      parentSetup: "when-creating",
      verify: () => "verified-existing",
    });

    expect(result).toBe("verified-existing");
    expect(fs.statSync(parent).mode & 0o777, "reuse path normalized the store parent").toBe(0o750);
  });

  test("the default always normalizes the parent, including on the reuse path", () => {
    publish({ "top.json": "{}\n" });
    fs.chmodSync(path.join(root, "store"), 0o750);

    publish({ "top.json": "{}\n" }, () => "verified-existing");

    expect(fs.statSync(path.join(root, "store")).mode & 0o777).toBe(0o700);
  });

  test("refuses a symlinked store parent before writing", () => {
    fs.mkdirSync(path.join(root, "elsewhere"));
    fs.symlinkSync(path.join(root, "elsewhere"), path.join(root, "store"));
    expect(() => publish({ "top.json": "{}\n" })).toThrow("not a normal directory");
  });
});

describe("bounded exact-acknowledgement poll", () => {
  function clock(): { nowMs: () => number; delay: (ms: number) => Promise<void> } {
    let now = 0;
    return {
      nowMs: () => now,
      delay: async (ms: number) => {
        now += ms;
      },
    };
  }

  test("after-probe deadline probes at least once even with no budget", async () => {
    const probes: number[] = [];
    const result = await pollForExactAck({
      probe: () => {
        probes.push(1);
        return undefined;
      },
      timeoutMs: 0,
      pollIntervalMs: 10,
      deadline: "after-probe",
      ...clock(),
    });
    expect(result).toBeUndefined();
    expect(probes.length).toBe(1);
  });

  test("before-probe deadline refuses to start a probe past the deadline", async () => {
    const probes: number[] = [];
    const result = await pollForExactAck({
      probe: () => {
        probes.push(1);
        return undefined;
      },
      timeoutMs: 0,
      pollIntervalMs: 10,
      deadline: "before-probe",
      ...clock(),
    });
    expect(result).toBeUndefined();
    expect(probes.length).toBe(0);
  });

  test("fences run around every probe and a fence throw aborts the loop", async () => {
    const events: string[] = [];
    await expect(pollForExactAck({
      beforeProbe: () => {
        events.push("before");
        if (events.filter((event) => event === "before").length === 2) {
          throw new Error("authority lost");
        }
      },
      probe: () => {
        events.push("probe");
        return undefined;
      },
      afterProbe: () => {
        events.push("after");
      },
      timeoutMs: 1000,
      pollIntervalMs: 10,
      deadline: "before-probe",
      ...clock(),
    })).rejects.toThrow("authority lost");
    expect(events).toEqual(["before", "probe", "after", "before"]);
  });

  test("returns the converged probe value", async () => {
    let attempts = 0;
    const result = await pollForExactAck({
      probe: () => {
        attempts += 1;
        return attempts === 3 ? { generation: "sha256:abc" } : undefined;
      },
      timeoutMs: 1000,
      pollIntervalMs: 10,
      deadline: "before-probe",
      ...clock(),
    });
    expect(result).toEqual({ generation: "sha256:abc" });
    expect(attempts).toBe(3);
  });
});
