import fs from "node:fs";
import path from "node:path";

import { describe, expect } from "vitest";

import { assertExit, assertFileMode, assertOutputContains } from "../support/assertions.ts";
import { describeCommandResult } from "../support/command.ts";
import { scenario } from "../support/evidence.ts";
import { assertOwnedStateUnchanged, snapshotOwnedState } from "../support/snapshot.ts";
import { withWorld, type E2EWorld } from "../support/world.ts";

const PNG_BYTES = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4]);
const CLEANUP_AGE_MS = 24 * 60 * 60 * 1_000;
const packagedCleanup = "Remove the disposable project, Git repository, home, and XDG roots after the test.";

const packagedInboxEvidence = {
  kind: "modeled-external-step",
  modeledSteps: [
    "A macOS clipboard image supplied through RUNFREE_TEST_CLIPBOARD_IMAGE_PATH",
    "A host clipboard copy failure supplied through RUNFREE_TEST_CLIPBOARD_COPY_ERROR",
  ],
  proofLimits:
    "This P-layer scenario proves packaged host import and cleanup only. It does not prove the real macOS clipboard provider or the Docker read-only /runfree/inbox mount, which remains Ds work.",
} as const;

const inboxMetadata = {
  scenarioIds: ["LH-23"],
  layer: "P",
  cadence: "pull-request",
  implementationStatus: "Partial",
  evidence: packagedInboxEvidence,
  ownedStateAreas: ["project and Git metadata", "host-owned XDG project inbox"],
  requiredPrograms: ["packaged Runfree executable", "Git", "POSIX shell"],
  cleanup: packagedCleanup,
} as const;

const forgedInboxMetadata = {
  ...inboxMetadata,
  evidence: {
    kind: "modeled-external-step",
    modeledSteps: ["A macOS clipboard image supplied through RUNFREE_TEST_CLIPBOARD_IMAGE_PATH"],
    proofLimits:
      "This P-layer scenario proves packaged host refusal and cleanup only. It does not prove the Docker read-only /runfree/inbox mount, which remains Ds work.",
  },
} as const;

async function git(world: E2EWorld, args: readonly string[]): Promise<string> {
  const result = await world.runExternal("git", ["-C", world.projectRoot, ...args]);
  if (result.outcome.kind !== "exit" || result.outcome.exitCode !== 0) {
    throw new Error(`git ${args.join(" ")} failed\n${describeCommandResult(result)}`);
  }
  return result.stdout;
}

async function initializeTrackedProject(world: E2EWorld): Promise<void> {
  fs.writeFileSync(path.join(world.projectRoot, "README.md"), "# Packaged inbox fixture\n");
  await git(world, ["init", "-b", "main"]);
  await git(world, ["config", "user.name", "Runfree Packaged E2E"]);
  await git(world, ["config", "user.email", "packaged-e2e@runfree.invalid"]);
  assertExit(await world.runfree(["init"]), 0);
  await git(world, ["add", "--all"]);
  await git(world, ["commit", "-m", "initial packaged inbox fixture"]);
  expect(await git(world, ["status", "--porcelain=v1", "--untracked-files=all"])).toBe("");
}

async function projectInbox(world: E2EWorld): Promise<string> {
  const id = await world.runfree(["project-id"]);
  assertExit(id, 0);
  expect(id.stdout.trim()).toMatch(/^[a-f0-9]{12}$/u);
  return path.join(world.stateHome, "runfree", "projects", id.stdout.trim(), "inbox");
}

function importedHostPath(inbox: string, containerPath: string): string {
  expect(containerPath).toMatch(/^\/runfree\/inbox\/clip-\d{4}-\d{2}-\d{2}-\d{6}-[a-f0-9]{4,16}\.png$/u);
  return path.join(inbox, path.posix.basename(containerPath));
}

function writeClipboardFixture(world: E2EWorld): string {
  const source = path.join(world.root, "clipboard.png");
  fs.writeFileSync(source, PNG_BYTES, { mode: 0o600 });
  return source;
}

describe("Phase 4 integrations through the packaged CLI", () => {
  scenario("inbox import and canonical cleanup preserve the project and converge", inboxMetadata, async () => {
    await withWorld({}, async (world) => {
      await initializeTrackedProject(world);
      const inbox = await projectInbox(world);
      const source = writeClipboardFixture(world);
      const projectBefore = snapshotOwnedState([{ name: "project and Git metadata", path: world.projectRoot }]);

      const firstPaste = await world.runfree(["inbox", "paste"], {
        env: {
          RUNFREE_TEST_CLIPBOARD_IMAGE_PATH: source,
          RUNFREE_TEST_INBOX_RANDOM: "a8f3",
        },
      });
      assertExit(firstPaste, 0);
      expect(firstPaste.stderr).toBe("");
      const firstContainerPath = firstPaste.stdout.trim();
      const firstHostPath = importedHostPath(inbox, firstContainerPath);
      expect(fs.readFileSync(firstHostPath)).toEqual(PNG_BYTES);
      assertFileMode(inbox, 0o700);
      assertFileMode(firstHostPath, 0o600);
      expect(path.relative(world.projectRoot, firstHostPath).startsWith(`..${path.sep}`)).toBe(true);

      const secondPaste = await world.runfree(["inbox", "paste", "--copy"], {
        env: {
          RUNFREE_TEST_CLIPBOARD_IMAGE_PATH: source,
          RUNFREE_TEST_CLIPBOARD_COPY_ERROR: "modeled clipboard unavailable",
          RUNFREE_TEST_INBOX_RANDOM: "a8f4",
        },
      });
      assertExit(secondPaste, 0);
      const secondContainerPath = secondPaste.stdout.trim();
      const secondHostPath = importedHostPath(inbox, secondContainerPath);
      expect(fs.readFileSync(secondHostPath)).toEqual(PNG_BYTES);
      assertOutputContains(
        secondPaste,
        `warning: image imported at ${secondContainerPath}; copy failed: modeled clipboard unavailable`,
      );

      const oldTime = new Date(Date.now() - CLEANUP_AGE_MS - 60_000);
      fs.utimesSync(firstHostPath, oldTime, oldTime);
      const ageCleanup = await world.runfree(["inbox", "clean"]);
      assertExit(ageCleanup, 0);
      expect(ageCleanup.stdout).toBe("removed 1 inbox file(s)\n");
      expect(fs.existsSync(firstHostPath)).toBe(false);
      expect(fs.readFileSync(secondHostPath)).toEqual(PNG_BYTES);

      const beforeNullCleanup = snapshotOwnedState([{ name: "host-owned inbox", path: inbox }]);
      const nullCleanup = await world.runfree(["inbox", "clean"]);
      assertExit(nullCleanup, 0);
      expect(nullCleanup.stdout).toBe("removed 0 inbox file(s)\n");
      assertOwnedStateUnchanged(beforeNullCleanup, snapshotOwnedState([{ name: "host-owned inbox", path: inbox }]));

      const allCleanup = await world.runfree(["inbox", "clean", "--all"]);
      assertExit(allCleanup, 0);
      expect(allCleanup.stdout).toBe("removed 1 inbox file(s)\n");
      expect(fs.readdirSync(inbox)).toEqual([]);

      const imported = await world.runfree(["paste-image"], {
        env: {
          RUNFREE_TEST_CLIPBOARD_IMAGE_PATH: source,
          RUNFREE_TEST_INBOX_RANDOM: "b8f3",
        },
      });
      assertExit(imported, 0);
      expect(imported.stderr).toBe(
        "warning: `runfree paste-image` is deprecated; use `runfree inbox paste`\n",
      );
      const importedPath = importedHostPath(inbox, imported.stdout.trim());
      expect(fs.readFileSync(importedPath)).toEqual(PNG_BYTES);
      const compatibilityCleanup = await world.runfree(["inbox", "clean", "--all"]);
      assertExit(compatibilityCleanup, 0);
      expect(compatibilityCleanup.stdout).toBe("removed 1 inbox file(s)\n");
      expect(fs.existsSync(importedPath)).toBe(false);

      assertOwnedStateUnchanged(
        projectBefore,
        snapshotOwnedState([{ name: "project and Git metadata", path: world.projectRoot }]),
      );
      expect(await git(world, ["status", "--porcelain=v1", "--untracked-files=all"])).toBe("");
    });
  });

  scenario("redirected and forged inbox entries cannot redirect import or cleanup", forgedInboxMetadata, async () => {
    await withWorld({}, async (world) => {
      await initializeTrackedProject(world);
      const inbox = await projectInbox(world);
      const source = writeClipboardFixture(world);
      const outside = path.join(world.root, "redirect-target");
      fs.mkdirSync(path.dirname(inbox), { recursive: true });
      fs.mkdirSync(outside);
      fs.symlinkSync(outside, inbox, "dir");
      const before = snapshotOwnedState([
        { name: "project and Git metadata", path: world.projectRoot },
        { name: "host state", path: path.join(world.stateHome, "runfree") },
        { name: "redirect target", path: outside },
      ]);

      const refused = await world.runfree(["inbox", "paste"], {
        env: { RUNFREE_TEST_CLIPBOARD_IMAGE_PATH: source },
      });
      assertExit(refused, 1);
      assertOutputContains(refused, "Runfree inbox must be a normal directory");
      assertOwnedStateUnchanged(before, snapshotOwnedState([
        { name: "project and Git metadata", path: world.projectRoot },
        { name: "host state", path: path.join(world.stateHome, "runfree") },
        { name: "redirect target", path: outside },
      ]));

      fs.unlinkSync(inbox);
      assertExit(await world.runfree(["inbox", "clean", "--all"]), 0);

      const outsideTarget = path.join(world.root, "outside-target.png");
      const unrelated = path.join(inbox, "notes.txt");
      const forgedSymlink = path.join(inbox, "clip-2026-08-20-120000-c001.png");
      const forgedHardLink = path.join(inbox, "clip-2026-08-20-120001-c002.png");
      const forgedFifo = path.join(inbox, "clip-2026-08-20-120002-c003.png");
      fs.writeFileSync(outsideTarget, "outside bytes", { mode: 0o600 });
      fs.writeFileSync(unrelated, "unrelated bytes", { mode: 0o600 });
      fs.symlinkSync(outsideTarget, forgedSymlink);
      fs.linkSync(outsideTarget, forgedHardLink);
      const fifo = await world.runExternal("mkfifo", [forgedFifo]);
      assertExit(fifo, 0);

      const selections = [
        { name: "outside target", path: outsideTarget },
        { name: "unrelated inbox file", path: unrelated },
        { name: "forged symlink", path: forgedSymlink },
        { name: "forged hard link", path: forgedHardLink },
        { name: "forged fifo", path: forgedFifo },
      ] as const;
      const forgedBefore = snapshotOwnedState(selections);

      const cleaned = await world.runfree(["inbox", "clean", "--all"]);
      assertExit(cleaned, 0);
      assertOwnedStateUnchanged(forgedBefore, snapshotOwnedState(selections));
      expect(cleaned.stdout).toBe("removed 0 inbox file(s)\n");
    });
  });
});
