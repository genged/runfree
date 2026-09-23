import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const script = path.join(repoRoot, "scripts", "check-spec-citations.ts");

type RunResult = { status: number; stdout: string; stderr: string };

function runGate(args: readonly string[]): RunResult {
  const result = childProcess.spawnSync(process.execPath, ["--import", "tsx", script, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    shell: false,
  });
  return { status: result.status ?? 1, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function git(cwd: string, args: readonly string[]): void {
  const result = childProcess.spawnSync("git", args, { cwd, encoding: "utf8", shell: false });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
}

describe("spec-citation static gate", () => {
  let fixtureRoot: string;
  let specsDir: string;

  beforeEach(() => {
    fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-spec-citations-"));
    specsDir = path.join(fixtureRoot, "local", "specs");
    fs.mkdirSync(path.join(fixtureRoot, "packages"), { recursive: true });
    git(fixtureRoot, ["init", "-q"]);
    git(fixtureRoot, ["config", "user.email", "gate@test"]);
    git(fixtureRoot, ["config", "user.name", "gate"]);
  });

  afterEach(() => {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  });

  function writeSpec(name: string, body: string): void {
    fs.mkdirSync(specsDir, { recursive: true });
    fs.writeFileSync(path.join(specsDir, name), body);
  }

  const CURRENCY = "Verified against the implemented tree at `abc1234`.\n\n";

  test("no-ops when the local specs directory is absent", () => {
    const result = runGate(["--repo-root", fixtureRoot]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("nothing to check");
  });

  test("fails when a currency-claiming spec cites a path git once tracked but the tree lost", () => {
    fs.writeFileSync(path.join(fixtureRoot, "packages", "thing.ts"), "export {};\n");
    git(fixtureRoot, ["add", "packages/thing.ts"]);
    git(fixtureRoot, ["commit", "-qm", "add thing"]);
    fs.rmSync(path.join(fixtureRoot, "packages", "thing.ts"));
    writeSpec("2026-09-01-sample-design.md", `${CURRENCY}The proof lives in \`packages/thing.ts:12\`.\n`);

    const result = runGate(["--repo-root", fixtureRoot]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("cited path no longer resolves: packages/thing.ts");
  });

  test("treats a never-tracked citation as planned and a resolving one as proof", () => {
    fs.writeFileSync(path.join(fixtureRoot, "packages", "real.ts"), "export {};\n");
    writeSpec(
      "2026-09-01-sample-design.md",
      `${CURRENCY}Existing \`packages/real.ts\` and planned \`packages/future-module.ts\`.\n`,
    );

    const result = runGate(["--repo-root", fixtureRoot]);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("never-tracked citation (treated as planned): packages/future-module.ts");
    expect(result.stdout).toContain("all resolve");
  });

  test("fails a currency-claiming spec whose citations are all unrecognized shorthand", () => {
    // `control/thing.ts` is not rooted at a repo top-level directory, so the
    // gate cannot resolve it. Passing such a spec would assert currency while
    // verifying nothing.
    writeSpec("2026-09-01-shorthand-design.md", `${CURRENCY}The proof lives in \`control/thing.ts:12\`.\n`);

    const result = runGate(["--repo-root", fixtureRoot]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("resolves no citation against the current tree");
  });

  test("fails a currency-claiming spec whose only citation is a planned file", () => {
    // Planned citations are deliberately non-fatal, but a spec resting entirely
    // on them has verified nothing about the current tree.
    writeSpec("2026-09-01-planned-only-design.md", `${CURRENCY}It will live in \`packages/future-module.ts\`.\n`);

    const result = runGate(["--repo-root", fixtureRoot]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("resolves no citation against the current tree");
  });

  test("still checks citations under a top-level tree deleted from the working tree", () => {
    // The gate's blind spot if roots came from the current tree only: delete
    // `packages/` wholesale and every citation under it stops looking like a
    // path, so the drift is never reported.
    fs.writeFileSync(path.join(fixtureRoot, "packages", "thing.ts"), "export {};\n");
    fs.mkdirSync(path.join(fixtureRoot, "docs"), { recursive: true });
    fs.writeFileSync(path.join(fixtureRoot, "docs", "guide.md"), "# guide\n");
    git(fixtureRoot, ["add", "packages/thing.ts", "docs/guide.md"]);
    git(fixtureRoot, ["commit", "-qm", "add sources"]);
    fs.rmSync(path.join(fixtureRoot, "packages"), { recursive: true });
    writeSpec(
      "2026-09-01-deleted-root-design.md",
      `${CURRENCY}Surviving \`docs/guide.md\` and vanished \`packages/thing.ts\`.\n`,
    );

    const result = runGate(["--repo-root", fixtureRoot]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("cited path no longer resolves: packages/thing.ts");
  });

  test("fails on a broken relative link and refuses a vacuous gate", () => {
    writeSpec("2026-09-01-linked-design.md", `${CURRENCY}See [the other spec](./missing-design.md).\n`);
    const broken = runGate(["--repo-root", fixtureRoot]);
    expect(broken.status).toBe(1);
    expect(broken.stderr).toContain("linked file does not resolve: ./missing-design.md");

    writeSpec("2026-09-01-linked-design.md", "Citation gate: disabled — narrates an older tree.\n");
    const vacuous = runGate(["--repo-root", fixtureRoot]);
    expect(vacuous.status).toBe(1);
    expect(vacuous.stderr).toContain("every active spec opted out");
  });

  test("gates a spec that makes no currency claim, and honors an explicit opt-out", () => {
    fs.writeFileSync(path.join(fixtureRoot, "packages", "gone.ts"), "export {};\n");
    git(fixtureRoot, ["add", "packages/gone.ts"]);
    git(fixtureRoot, ["commit", "-qm", "add gone"]);
    fs.rmSync(path.join(fixtureRoot, "packages", "gone.ts"));
    // No currency claim: still gated, because that is the corpus the drift
    // gate exists to protect.
    writeSpec("2026-09-01-plain-design.md", "Implementation lives in `packages/gone.ts`.\n");

    const gated = runGate(["--repo-root", fixtureRoot]);
    expect(gated.status).toBe(1);
    expect(gated.stderr).toContain("cited path no longer resolves: packages/gone.ts");

    // A spec may opt out deliberately, and says so in its own text.
    writeSpec(
      "2026-09-01-plain-design.md",
      "Citation gate: disabled — cites its pre-rename baseline.\n\nSee `packages/gone.ts`.\n",
    );
    // A second, gated spec keeps the run non-vacuous.
    fs.writeFileSync(path.join(fixtureRoot, "packages", "live.ts"), "export {};\n");
    writeSpec("2026-09-01-other-design.md", "Implementation lives in `packages/live.ts`.\n");

    const optedOut = runGate(["--repo-root", fixtureRoot]);
    expect(optedOut.status).toBe(0);
    expect(optedOut.stdout).toContain("spec opted out of the gate");
  });

  test("still checks citations under a top-level root deleted in a COMMIT", () => {
    // The working-tree case is covered above. This is the one that would
    // otherwise go permanently invisible: once the deletion is committed the
    // root is in neither the working tree nor HEAD.
    fs.writeFileSync(path.join(fixtureRoot, "packages", "gone.ts"), "export {};\n");
    fs.mkdirSync(path.join(fixtureRoot, "docs"), { recursive: true });
    fs.writeFileSync(path.join(fixtureRoot, "docs", "guide.md"), "# guide\n");
    git(fixtureRoot, ["add", "packages/gone.ts", "docs/guide.md"]);
    git(fixtureRoot, ["commit", "-qm", "add sources"]);
    fs.rmSync(path.join(fixtureRoot, "packages"), { recursive: true });
    git(fixtureRoot, ["add", "-A"]);
    git(fixtureRoot, ["commit", "-qm", "remove packages root"]);
    writeSpec(
      "2026-09-01-committed-delete-design.md",
      `${CURRENCY}Surviving \`docs/guide.md\` and vanished \`packages/gone.ts\`.\n`,
    );

    const result = runGate(["--repo-root", fixtureRoot]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("cited path no longer resolves: packages/gone.ts");
  });

  test("rejects a link that escapes the repository instead of counting it as evidence", () => {
    writeSpec(
      "2026-09-01-escape-design.md",
      `${CURRENCY}See [outside](../../../../etc/hosts).\n`,
    );

    const result = runGate(["--repo-root", fixtureRoot]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("linked file escapes the repository");
  });

  test("refuses a run where the whole corpus resolves nothing", () => {
    // Gating specs is not the same as checking something: prose-only and
    // planned-only corpora must not report success.
    writeSpec("2026-09-01-prose-a-design.md", "Pure prose, no citations.\n");
    writeSpec("2026-09-01-prose-b-design.md", "Also prose, mentions `control/shorthand.ts` only.\n");

    const result = runGate(["--repo-root", fixtureRoot]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("not one citation resolved");
  });

  test("a spec with no citations at all passes when it claims no currency", () => {
    fs.writeFileSync(path.join(fixtureRoot, "packages", "live.ts"), "export {};\n");
    writeSpec("2026-09-01-prose-design.md", "Pure prose design, no repository citations.\n");
    writeSpec("2026-09-01-cited-design.md", "Implementation lives in `packages/live.ts`.\n");

    const result = runGate(["--repo-root", fixtureRoot]);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("all resolve");
  });
});
