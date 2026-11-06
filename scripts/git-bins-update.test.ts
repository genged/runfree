import { describe, expect, test } from "vitest";

import { assetName, GIT_PLATFORMS, type GitBinsLock } from "./git-bins.ts";
import { addVersion, newestStableGit, parseSha256Sums, pinAssets } from "./git-bins-update.ts";

const A = "a".repeat(64);
const B = "b".repeat(64);
const C = "c".repeat(64);

function lock(assets: GitBinsLock["versions"][string]["assets"] = {}): GitBinsLock {
  return {
    release: { repository: "genged/runfree", tag: "git-test-bin-1" },
    default: "2.56.0",
    versions: {
      "2.43.0": { sourceSha256: A, assets },
      "2.56.0": { sourceSha256: B, assets },
    },
  };
}

function sums(versions: string[], digest = C): string {
  return versions.flatMap((version) => GIT_PLATFORMS.map((platform) => `${digest}  ${assetName(version, platform)}`)).join("\n");
}

describe("kernel.org listing", () => {
  test("picks the newest stable tarball, skipping release candidates and other files", () => {
    const listing = [
      "-----BEGIN PGP SIGNED MESSAGE-----",
      "Hash: SHA256",
      "",
      `${A}  git-2.9.5.tar.xz`,
      `${A}  git-2.56.0.tar.xz`,
      `${A}  git-2.57.0.rc2.tar.xz`,
      `${A}  git-2.10.0.tar.gz`,
      `${A}  git-htmldocs-2.99.0.tar.xz`,
      `${A}  git-2.55.4.tar.xz`,
    ].join("\n");
    expect(newestStableGit(listing)).toBe("2.56.0");
  });

  test("refuses a listing with no stable tarball", () => {
    expect(() => newestStableGit("nothing here")).toThrow(/no git-<x.y.z>/);
  });

  test("reads sha256sum output in text and binary mode", () => {
    expect(parseSha256Sums(`${A}  one.tar.gz\n${B} *two.tar.gz\nnot a line\n`)).toEqual(
      new Map([
        ["one.tar.gz", A],
        ["two.tar.gz", B],
      ]),
    );
  });
});

describe("add", () => {
  test("before the release is published: keeps the tag and pinned assets, and moves default to the newest", () => {
    const updated = addVersion(lock(), { version: "2.57.0", sourceSha256: C, releasePublished: false });
    expect(updated.release.tag).toBe("git-test-bin-1");
    expect(updated.default).toBe("2.57.0");
    expect(Object.keys(updated.versions)).toEqual(["2.43.0", "2.56.0", "2.57.0"]);
    expect(updated.versions["2.57.0"]).toEqual({ sourceSha256: C, assets: {} });
  });

  test("after the release is published: moves to the next tag and clears every asset digest", () => {
    const updated = addVersion(lock(), { version: "2.57.0", sourceSha256: C, releasePublished: true });
    expect(updated.release.tag).toBe("git-test-bin-2");
    expect(Object.values(updated.versions).map((entry) => entry.assets)).toEqual([{}, {}, {}]);
  });

  test("pinned asset digests count as published even if the release lookup says no", () => {
    const updated = addVersion(lock({ "linux-x64": A }), { version: "2.57.0", sourceSha256: C, releasePublished: false });
    expect(updated.release.tag).toBe("git-test-bin-2");
    expect(updated.versions["2.43.0"].assets).toEqual({});
  });

  test("--replace drops the old version; default stays the newest locked", () => {
    const updated = addVersion(lock(), { version: "2.57.0", sourceSha256: C, replace: "2.56.0", releasePublished: true });
    expect(Object.keys(updated.versions)).toEqual(["2.43.0", "2.57.0"]);
    expect(updated.default).toBe("2.57.0");

    const older = addVersion(lock(), { version: "2.39.5", sourceSha256: C, releasePublished: false });
    expect(older.default).toBe("2.56.0");
    expect(Object.keys(older.versions)).toEqual(["2.39.5", "2.43.0", "2.56.0"]);
  });

  test("refuses a version already locked or a --replace that is not locked", () => {
    expect(() => addVersion(lock(), { version: "2.56.0", sourceSha256: C, releasePublished: false })).toThrow(/already locked/);
    expect(() => addVersion(lock(), { version: "2.57.0", sourceSha256: C, replace: "2.1.0", releasePublished: false })).toThrow(
      /--replace 2.1.0: not locked/,
    );
  });
});

describe("pin", () => {
  test("records every platform's digest for every locked version", () => {
    const pinned = pinAssets(lock(), `${sums(["2.43.0", "2.56.0"])}\n${A}  unrelated.txt\n`);
    for (const entry of Object.values(pinned.versions)) {
      expect(Object.keys(entry.assets).sort()).toEqual([...GIT_PLATFORMS].sort());
      expect(Object.values(entry.assets)).toEqual([C, C, C, C]);
    }
    expect(pinned.versions["2.43.0"].sourceSha256).toBe(A);
  });

  test("refuses a SHA256SUMS that misses any locked asset, and names it", () => {
    const partial = sums(["2.43.0", "2.56.0"]).split("\n").slice(1).join("\n");
    expect(() => pinAssets(lock(), partial)).toThrow(new RegExp(`lacks ${assetName("2.43.0", GIT_PLATFORMS[0]).replace(/\./g, "\\.")}`));
    expect(() => pinAssets(lock(), sums(["2.43.0"]))).toThrow(/git-2\.56\.0-/);
  });
});
