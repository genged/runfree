import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const sha = "a".repeat(40);
const otherSha = "b".repeat(40);
const repository = "genged/runfree";
let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-release-coordination-"));
  fs.mkdirSync(path.join(tmp, "bin"));
  fs.writeFileSync(path.join(tmp, "event.json"), "{}");
  fs.writeFileSync(path.join(tmp, "releases.json"), "[[]]");
  fs.writeFileSync(path.join(tmp, "bin", "gh"), `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FIXTURE/api.log"
case "$*" in
  *"/commits/refs/tags/"*) printf '%s\\n' '${sha}' ;;
  *"/releases?"*) cat "$FIXTURE/releases.json" ;;
  *) exit 99 ;;
esac
`, { mode: 0o755 });
});

afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

function write(name: string, value: unknown) {
  fs.writeFileSync(path.join(tmp, `${name}.json`), JSON.stringify(value));
}

function run(script: string, env: NodeJS.ProcessEnv = {}) {
  fs.writeFileSync(path.join(tmp, "output"), "");
  return childProcess.spawnSync("bash", [path.join(repoRoot, "scripts", script)], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${path.join(tmp, "bin")}${path.delimiter}${process.env.PATH ?? ""}`,
      FIXTURE: tmp,
      GITHUB_REPOSITORY: repository,
      GITHUB_EVENT_PATH: path.join(tmp, "event.json"),
      GITHUB_OUTPUT: path.join(tmp, "output"),
      GITHUB_EVENT_NAME: "push",
      REPO: repository,
      TAG: "v0.5.0",
      SHA: sha,
      ...env,
    },
  });
}

function outputs() {
  return Object.fromEntries(fs.readFileSync(path.join(tmp, "output"), "utf8").trim().split("\n").filter(Boolean).map((line) => {
    const split = line.indexOf("=");
    return [line.slice(0, split), line.slice(split + 1)];
  }));
}

describe("release request discovery", () => {
  test.each(["push", "workflow_dispatch"])("resolves an explicit %s request", (event) => {
    write("event", { inputs: { tag: "v0.5.0-rc.1" } });
    const result = run("resolve-release-request.sh", { GITHUB_EVENT_NAME: event, GITHUB_REF: "refs/tags/v0.5.0-rc.1" });
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(outputs().targets)).toEqual([{ tag: "v0.5.0-rc.1", sha }]);
  });

  test("no longer accepts Test completion events", () => {
    const result = run("resolve-release-request.sh", { GITHUB_EVENT_NAME: "workflow_run" });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("unsupported release event");
    expect(fs.existsSync(path.join(tmp, "api.log"))).toBe(false);
  });

  test("rejects an invalid manual tag before any API access", () => {
    write("event", { inputs: { tag: "v0.5.0; touch injected" } });
    const result = run("resolve-release-request.sh", { GITHUB_EVENT_NAME: "workflow_dispatch" });
    expect(result.status).not.toBe(0);
    expect(fs.existsSync(path.join(tmp, "api.log"))).toBe(false);
  });
});

describe("release preparation", () => {
  test("becomes ready for an unpublished tag without consulting CI", () => {
    const result = run("prepare-release.sh");
    expect(result.status, result.stderr).toBe(0);
    expect(outputs().ready).toBe("true");
    expect(fs.readFileSync(path.join(tmp, "api.log"), "utf8")).not.toContain("/actions/workflows/");
  });

  test("skips an already published tag, including duplicate events", () => {
    write("releases", [[], [{ tag_name: "v0.5.0", draft: false, target_commitish: sha }]]);
    const result = run("prepare-release.sh");
    expect(result.status, result.stderr).toBe(0);
    expect(outputs().ready).toBe("false");
  });

  test.each([otherSha, "main", undefined])("refuses to skip a published release without matching source SHA: %s", (target) => {
    write("releases", [[{ tag_name: "v0.5.0", draft: false, target_commitish: target }]]);
    const result = run("prepare-release.sh");
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("published source");
    expect(outputs().ready).toBe("false");
  });

  test("leaves a draft eligible for the existing explicit recovery checks", () => {
    write("releases", [[{ tag_name: "v0.5.0", draft: true }]]);
    const result = run("prepare-release.sh");
    expect(result.status, result.stderr).toBe(0);
    expect(outputs().ready).toBe("true");
  });

  test("fails rather than proceeding when the release listing fails", () => {
    fs.writeFileSync(path.join(tmp, "bin", "gh"), "#!/usr/bin/env bash\nexit 1\n");
    const result = run("prepare-release.sh");
    expect(result.status).not.toBe(0);
    expect(outputs().ready).toBe("false");
  });
});
