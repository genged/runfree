import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  GIT_REMOTE_SUGGESTION_LIMIT,
  detectFileServices,
  detectGitRemotes,
  hasPunycodeLabel,
  hostFromGitRemoteUrl,
  parseGitRemoteUrls,
  readGitConfigText,
} from "./init-detect.ts";

let tmp: string;

function writeGitConfig(contents: string): void {
  fs.mkdirSync(path.join(tmp, ".git"), { recursive: true });
  fs.writeFileSync(path.join(tmp, ".git", "config"), contents);
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-init-detect-")));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("file-rule detection", () => {
  test("triggers on root-level existence only and never recurses", () => {
    fs.writeFileSync(path.join(tmp, "package.json"), "{}");
    fs.writeFileSync(path.join(tmp, "pyproject.toml"), "");
    fs.mkdirSync(path.join(tmp, "nested"));
    fs.writeFileSync(path.join(tmp, "nested", "Cargo.toml"), "");

    expect(detectFileServices(tmp)).toEqual(["node", "python"]);
  });

  test("symlinked and special-file detection paths neither error nor get followed", () => {
    // Dangling symlink: existence (lstat) still suggests the service; nothing
    // is opened, so the target is irrelevant.
    fs.symlinkSync(path.join(tmp, "does-not-exist"), path.join(tmp, "package.json"));
    childProcess.execFileSync("mkfifo", [path.join(tmp, "Dockerfile")]);

    expect(detectFileServices(tmp)).toEqual(["docker-registry", "node"]);
  });

  test("an empty project suggests nothing, and ubuntu-apt is never suggested", () => {
    expect(detectFileServices(tmp)).toEqual([]);
    fs.writeFileSync(path.join(tmp, "archive.ubuntu.com"), "");
    expect(detectFileServices(tmp)).not.toContain("ubuntu-apt");
  });
});

describe("readGitConfigText", () => {
  test("reads a small regular .git/config", () => {
    writeGitConfig("[remote \"origin\"]\n\turl = https://github.com/o/r.git\n");
    expect(readGitConfigText(tmp)).toContain("github.com");
  });

  test("rejects a symlinked .git/config without reading the target", () => {
    const target = path.join(tmp, "target-config");
    fs.writeFileSync(target, "[remote \"origin\"]\n\turl = https://evil.example.com/o/r.git\n");
    fs.mkdirSync(path.join(tmp, ".git"), { recursive: true });
    fs.symlinkSync(target, path.join(tmp, ".git", "config"));

    expect(readGitConfigText(tmp)).toBeUndefined();
    expect(detectGitRemotes(tmp)).toEqual({ serviceIds: [], allowHosts: [], truncated: false });
  });

  test("rejects a FIFO .git/config via lstat before any open (never blocks)", () => {
    fs.mkdirSync(path.join(tmp, ".git"), { recursive: true });
    childProcess.execFileSync("mkfifo", [path.join(tmp, ".git", "config")]);

    expect(readGitConfigText(tmp)).toBeUndefined();
  });

  test("skips oversized and missing configs silently", () => {
    expect(readGitConfigText(tmp)).toBeUndefined();
    writeGitConfig(`[remote "origin"]\n\turl = https://github.com/o/r.git\n${"#".repeat(65 * 1024)}\n`);
    expect(readGitConfigText(tmp)).toBeUndefined();
  });
});

describe("minimal INI remote parsing", () => {
  test("extracts url values from remote sections of a representative config", () => {
    const text = [
      "[core]",
      "\trepositoryformatversion = 0",
      "\tfsmonitor = /tmp/evil-hook",
      '[remote "origin"]',
      "\turl = https://github.com/owner/repo.git",
      "\tfetch = +refs/heads/*:refs/remotes/origin/*",
      '[remote "fork"]',
      "\turl = git@gitlab.example.com:owner/repo.git",
      '[branch "main"]',
      "\tremote = origin",
      "; comment",
      "# comment",
    ].join("\n");

    expect(parseGitRemoteUrls(text)).toEqual([
      "https://github.com/owner/repo.git",
      "git@gitlab.example.com:owner/repo.git",
    ]);
  });

  test("ignores include/includeIf and path-valued directives, proven by a FIFO sentinel that would block on read", () => {
    const sentinel = path.join(tmp, "sentinel");
    // If detection honored include.path, opening this FIFO would block and
    // the test would time out; content from it must also never surface.
    childProcess.execFileSync("mkfifo", [sentinel]);
    writeGitConfig([
      "[include]",
      `\tpath = ${sentinel}`,
      '[includeIf "gitdir:/"]',
      `\tpath = ${sentinel}`,
      '[remote "origin"]',
      "\turl = https://github.com/owner/repo.git",
      `\tpath = ${sentinel}`,
    ].join("\n"));

    const detection = detectGitRemotes(tmp);
    expect(detection.serviceIds).toEqual(["github"]);
    expect(detection.allowHosts).toEqual([]);
  });

  test("a sentinel file's remotes are never read through include directives", () => {
    const sentinel = path.join(tmp, "sentinel-config");
    fs.writeFileSync(sentinel, '[remote "evil"]\n\turl = https://evil-included.example.com/x.git\n');
    writeGitConfig(`[include]\n\tpath = ${sentinel}\n[remote "origin"]\n\turl = https://github.com/o/r.git\n`);

    const detection = detectGitRemotes(tmp);
    expect(detection.serviceIds).toEqual(["github"]);
    expect(detection.allowHosts.map((entry) => entry.host)).not.toContain("evil-included.example.com");
  });
});

describe("remote URL host extraction", () => {
  const cases: Array<[string, string | undefined]> = [
    ["https://github.com/owner/repo.git", "github.com"],
    ["http://internal.example.com/repo.git", "internal.example.com"],
    ["git://github.com/owner/repo.git", "github.com"],
    // Userinfo-bearing web URLs are rejected: evil.com must not surface as
    // "your GitHub remote".
    ["https://github.com@evil.com/owner/repo.git", undefined],
    ["https://user:secret@host.example.com/repo.git", undefined],
    // ssh URLs may carry a bare username but never a password.
    ["ssh://git@github.com/owner/repo.git", "github.com"],
    ["ssh://git@github.com:2222/owner/repo.git", "github.com"],
    ["ssh://git:secret@github.com/owner/repo.git", undefined],
    // SCP-style only in the canonical user@host:path form.
    ["git@github.com:owner/repo.git", "github.com"],
    ["git@gitlab.example.com:owner/repo.git", "gitlab.example.com"],
    ["github.com:owner/repo.git", undefined],
    ["git@evil.com@github.com:owner/repo.git", undefined],
    // Opaque transport helpers are commands, never hosts.
    ["ext::ssh -e none github.com %S /repo", undefined],
    ["fd::17", undefined],
    // Local paths and single-label hosts are skipped.
    ["/srv/git/repo.git", undefined],
    ["./relative/repo", undefined],
    ["file:///srv/git/repo.git", undefined],
    ["ssh://git@localhost/repo.git", undefined],
    ["", undefined],
    // Punycode hosts parse but are flagged separately.
    ["https://xn--gthub-zra.com/owner/repo.git", "xn--gthub-zra.com"],
  ];

  test.each(cases)("%s -> %s", (url, expected) => {
    expect(hostFromGitRemoteUrl(url)).toBe(expected);
  });

  test("punycode labels are flagged as possible lookalikes", () => {
    expect(hasPunycodeLabel("xn--gthub-zra.com")).toBe(true);
    expect(hasPunycodeLabel("docs.xn--gthub-zra.com")).toBe(true);
    expect(hasPunycodeLabel("github.com")).toBe(false);
  });
});

describe("detectGitRemotes", () => {
  test("maps known remote hosts to service ids and others to capped single-host suggestions", () => {
    const remotes = [
      "https://github.com/o/r.git",
      "https://git.corp1.example.com/o/r.git",
      "https://git.corp2.example.com/o/r.git",
      "https://git.corp3.example.com/o/r.git",
      "https://xn--gthub-zra.com/o/r.git",
      "https://git.corp5.example.com/o/r.git",
      "https://git.corp6.example.com/o/r.git",
      "https://git.corp7.example.com/o/r.git",
    ];
    writeGitConfig(remotes.map((url, index) => `[remote "r${index}"]\n\turl = ${url}\n`).join(""));

    const detection = detectGitRemotes(tmp);
    expect(detection.serviceIds).toEqual(["github"]);
    expect(detection.allowHosts).toHaveLength(GIT_REMOTE_SUGGESTION_LIMIT);
    expect(detection.truncated).toBe(true);
    expect(detection.allowHosts.map((entry) => entry.host)).toEqual([
      "git.corp1.example.com",
      "git.corp2.example.com",
      "git.corp3.example.com",
      "xn--gthub-zra.com",
      "git.corp5.example.com",
    ]);
    expect(detection.allowHosts.find((entry) => entry.host === "xn--gthub-zra.com")?.punycode).toBe(true);
    expect(detection.allowHosts.find((entry) => entry.host === "git.corp1.example.com")?.punycode).toBe(false);
  });

  test("duplicate remotes collapse to one suggestion and malformed configs detect nothing", () => {
    writeGitConfig([
      '[remote "a"]',
      "\turl = https://git.corp.example.com/o/r.git",
      '[remote "b"]',
      "\turl = https://git.corp.example.com/o/other.git",
      "not an ini line at all [[[",
    ].join("\n"));

    const detection = detectGitRemotes(tmp);
    expect(detection.allowHosts.map((entry) => entry.host)).toEqual(["git.corp.example.com"]);
    expect(detection.truncated).toBe(false);
  });

  test("a project without .git detects nothing", () => {
    expect(detectGitRemotes(tmp)).toEqual({ serviceIds: [], allowHosts: [], truncated: false });
  });
});
