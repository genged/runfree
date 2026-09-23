// One release contract, not six.
//
// The version, the supported platform list, the release notes, the installer,
// and the support policy are stated in different files for different readers,
// and they drift silently: the 2026-09-14 readiness assessment found the package
// at 0.4.0, the README pointing at 0.2.0 as current, and the project brief
// saying "as of 0.2.0", all at the same commit. Nothing failed, because nothing
// compared them.

import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

function read(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

const packageVersion = (JSON.parse(read("package.json")) as { version: string }).version;

const releaseTargets = read("scripts/release-targets.txt")
  .split("\n")
  .map((line) => line.replace(/#.*$/, "").trim())
  .filter((line) => line.length > 0)
  .map((line) => line.split(/\s+/)[0]);

describe("release contract", () => {
  test("the package version has a release body and a detailed page", () => {
    expect(fs.existsSync(path.join(repoRoot, "docs/release-notes", `${packageVersion}.md`))).toBe(true);
    expect(fs.existsSync(path.join(repoRoot, "docs", `whats-new-${packageVersion}.md`))).toBe(true);
  });

  test("the package version is the newest release body, so nothing ships under a stale one", () => {
    const versions = fs
      .readdirSync(path.join(repoRoot, "docs/release-notes"))
      .filter((name) => name.endsWith(".md"))
      .map((name) => name.replace(/\.md$/, ""));

    const order = (version: string) => version.split(".").map((part) => Number.parseInt(part, 10));
    const newest = versions.sort((a, b) => {
      const [aMajor, aMinor, aPatch] = order(a);
      const [bMajor, bMinor, bPatch] = order(b);
      return bMajor - aMajor || bMinor - aMinor || bPatch - aPatch;
    })[0];

    expect(newest).toBe(packageVersion);
  });

  test("the release body names every archive the release publishes, and no other", () => {
    const notes = read(`docs/release-notes/${packageVersion}.md`);

    for (const target of releaseTargets) {
      expect(notes).toContain(`runfree-${packageVersion}-${target}.tar.gz`);
    }
    for (const absent of ["darwin-x64", "linux-x64", "linux-arm64"]) {
      if (releaseTargets.includes(absent)) continue;
      expect(notes).not.toContain(`runfree-${packageVersion}-${absent}.tar.gz`);
    }
  });

  test("the README and the project brief name the current version, not an older one", () => {
    const readme = read("README.md");
    const brief = read("docs/project-brief.md");

    expect(readme).toContain(`Runfree ${packageVersion}`);
    expect(brief).toContain(`As of \`${packageVersion}\``);

    // The concrete drift the assessment found: documents still advertising a
    // version the package no longer is.
    expect(readme).not.toMatch(/Runfree 0\.[0-4]\.\d+ publishes/);
    expect(brief).not.toMatch(/As of `0\.[0-4]\.\d+`/);
  });

  test("the supported platform claim is the same everywhere it appears", () => {
    expect(releaseTargets).toEqual(["darwin-arm64"]);

    for (const [file, contents] of [
      ["README.md", read("README.md")],
      ["docs/project-brief.md", read("docs/project-brief.md")],
      [`docs/whats-new-${packageVersion}.md`, read(`docs/whats-new-${packageVersion}.md`)],
    ] as const) {
      expect(contents, `${file} must name the supported host`).toMatch(/Apple Silicon/);
      expect(contents, `${file} must name the supported backend`).toMatch(/Docker Desktop/);
    }

    // OrbStack is deferred in the Makefile and gates nothing, so no public
    // document may present it as supported.
    expect(read("README.md")).not.toMatch(/OrbStack with Docker Compose/);
    expect(read("docs/project-brief.md")).not.toMatch(/OrbStack with Docker Compose/);
  });

  test("the support policy is latest-release-only with no response-time commitment", () => {
    const security = read("SECURITY.md");

    expect(security.replace(/\s+/g, " ")).toContain("latest release is the only supported line");
    expect(security).toMatch(/no response-time commitment/);
    expect(read("README.md")).toMatch(/no response-time commitment/);
  });

  test("the documented install command uses bash, because the installer needs bash", () => {
    // `curl ... | sh` ignores the shebang and runs under /bin/sh; the installer
    // uses bash arrays, so on a dash /bin/sh it fails partway through.
    const installer = read("scripts/install.sh");
    expect(installer).toContain("checksum_command=(");

    for (const file of ["README.md", `docs/release-notes/${packageVersion}.md`, `docs/whats-new-${packageVersion}.md`]) {
      const contents = read(file);
      if (!contents.includes("install.sh")) continue;
      expect(contents, `${file} must pipe install.sh into bash`).toContain("install.sh | bash");
      expect(contents, `${file} must not pipe install.sh into sh`).not.toContain("install.sh | sh");
    }
  });
});
