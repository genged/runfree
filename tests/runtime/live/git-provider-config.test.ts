import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import { gitProviderSuiteConfig, hostCommandSourceArgv, parseProviderRepository } from "./git-provider-config.ts";

const GITHUB_INPUTS = {
  TEST_RUNTIME_GITHUB_REPO: "https://github.com/runfree-test/private-probe",
  TEST_RUNTIME_GITHUB_SOURCE: "git-probe-github",
};
const GITLAB_INPUTS = {
  TEST_RUNTIME_GITLAB_REPO: "https://gitlab.com/runfree-test/nested/private-probe.git/",
  TEST_RUNTIME_GITLAB_SOURCE: "git-probe-gitlab",
};

describe("gitProviderSuiteConfig", () => {
  test.each([undefined, "", "  "])("skips with a reason when the gate is %j", (gate) => {
    const config = gitProviderSuiteConfig({ ...GITHUB_INPUTS, ...(gate === undefined ? {} : { TEST_RUNTIME_GIT_PROVIDERS: gate }) });
    expect(config.kind).toBe("skip");
    expect(config.kind === "skip" && config.reason).toContain("TEST_RUNTIME_GIT_PROVIDERS is unset");
  });

  test("ignores provider inputs without the gate, so ambient values never opt a run in", () => {
    expect(gitProviderSuiteConfig({ ...GITHUB_INPUTS, ...GITLAB_INPUTS }).kind).toBe("skip");
  });

  test("fails, not skips, when a gated provider's inputs are missing", () => {
    expect(() => gitProviderSuiteConfig({ TEST_RUNTIME_GIT_PROVIDERS: "github" }))
      .toThrow(/TEST_RUNTIME_GITHUB_REPO is unset.*TEST_RUNTIME_GITHUB_SOURCE is unset/u);
    expect(() => gitProviderSuiteConfig({ TEST_RUNTIME_GIT_PROVIDERS: "github,gitlab", ...GITHUB_INPUTS }))
      .toThrow("TEST_RUNTIME_GITLAB_REPO is unset");
  });

  test.each([
    ["bitbucket", "unknown provider"],
    ["github,github", "more than once"],
    ["github,", "unknown provider \"\""],
  ])("refuses the gate %j", (gate, message) => {
    expect(() => gitProviderSuiteConfig({ TEST_RUNTIME_GIT_PROVIDERS: gate, ...GITHUB_INPUTS })).toThrow(message);
  });

  test("refuses a malformed source name and a malformed optional LFS repository", () => {
    expect(() => gitProviderSuiteConfig({ TEST_RUNTIME_GIT_PROVIDERS: "github", ...GITHUB_INPUTS, TEST_RUNTIME_GITHUB_SOURCE: "Bad Name" }))
      .toThrow("is not a credential source name");
    expect(() => gitProviderSuiteConfig({
      TEST_RUNTIME_GIT_PROVIDERS: "github",
      ...GITHUB_INPUTS,
      TEST_RUNTIME_GITHUB_LFS_REPO: "https://gitlab.com/a/b",
    })).toThrow("TEST_RUNTIME_GITHUB_LFS_REPO");
  });

  test("returns every gated provider in order with canonical repository forms", () => {
    const config = gitProviderSuiteConfig({
      TEST_RUNTIME_GIT_PROVIDERS: "gitlab, github",
      ...GITHUB_INPUTS,
      ...GITLAB_INPUTS,
      TEST_RUNTIME_GITHUB_LFS_REPO: "https://github.com/runfree-test/lfs-probe.git",
    });
    if (config.kind !== "run") throw new Error("expected a run");
    expect(config.providers.map((provider) => provider.id)).toEqual(["gitlab", "github"]);
    const [gitlab, github] = config.providers;
    expect(gitlab.repository).toEqual({
      httpsUrl: "https://gitlab.com/runfree-test/nested/private-probe.git",
      sshUrl: "git@gitlab.com:runfree-test/nested/private-probe.git",
      path: "runfree-test/nested/private-probe.git",
    });
    expect(gitlab.lfsRepository).toBeUndefined();
    expect(github.repository.httpsUrl).toBe("https://github.com/runfree-test/private-probe.git");
    expect(github.source).toBe("git-probe-github");
    expect(github.lfsRepository?.sshUrl).toBe("git@github.com:runfree-test/lfs-probe.git");
  });
});

describe("parseProviderRepository", () => {
  test.each([
    ["http://github.com/a/b", "https://"],
    ["https://gitlab.com/a/b", "must be on github.com"],
    ["https://x-access-token:secret@github.com/a/b", "credentials"],
    ["https://github.com:8443/a/b", "port"],
    ["https://github.com/a/b?x=1", "query"],
    ["https://github.com/only-owner", "<owner>/<repository>"],
    ["https://github.com/a/../b", "<owner>/<repository>"],
    ["git@github.com:a/b.git", "is not a URL"],
  ])("refuses %j", (value, message) => {
    expect(() => parseProviderRepository("github.com", value)).toThrow(message);
  });
});

describe("hostCommandSourceArgv", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
  });

  function registry(content: unknown): NodeJS.ProcessEnv {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-git-provider-config-"));
    roots.push(root);
    fs.mkdirSync(path.join(root, "runfree"));
    fs.writeFileSync(path.join(root, "runfree", "sources.json"), JSON.stringify(content));
    return { XDG_CONFIG_HOME: root };
  }

  test("returns the named command source's argv from the operator's registry", () => {
    const env = registry({ probe: { type: "command", argv: ["/usr/bin/op", "read", "op://v/i/t"], displayArgv: ["op"], createdAt: "x" } });
    expect(hostCommandSourceArgv("probe", env)).toEqual(["/usr/bin/op", "read", "op://v/i/t"]);
  });

  test("refuses a missing source, a JWT source and an empty argv", () => {
    const env = registry({
      jwt: { type: "jwt" },
      empty: { type: "command", argv: [] },
    });
    expect(() => hostCommandSourceArgv("absent", env)).toThrow("no credential source named absent");
    expect(() => hostCommandSourceArgv("jwt", env)).toThrow("not a command source");
    expect(() => hostCommandSourceArgv("empty", env)).toThrow("has no command argv");
  });

  test("names the registry path when there is no registry", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-git-provider-config-"));
    roots.push(root);
    expect(() => hostCommandSourceArgv("probe", { XDG_CONFIG_HOME: root }))
      .toThrow(path.join(root, "runfree", "sources.json"));
  });
});
