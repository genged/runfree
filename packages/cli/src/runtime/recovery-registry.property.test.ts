// Never-throws property for the agent-written recovery inputs (SM3).
//
// The Claude registry under `<state>/claude/sessions/` is written by the
// agent, so it is hostile input to `scanRecoveryInventory`. The promise
// (docs/security.md, "Writes a fake Claude registry entry") is that a forged
// file yields at most a labelled row in its own project: it never throws out
// of the scan, never empties the inventory, and never hides the host's own
// crash evidence. The first counterexample was an integer the Date type
// cannot render; this property generates the whole space of JSON values and
// raw bytes, plus registry-shaped records with adversarial field values, and
// asserts the host record survives every one of them.
//
// This is the template for the other agent-written-input parsers: build the
// hostile file from an arbitrary, run the real reader, assert the typed
// outcome and the survival of the host-written evidence beside it.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import fc from "fast-check";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { propertyParameters } from "../../../../tests/support/property.ts";
import { composeProjectName, projectHash } from "../project-identity.ts";
import { scanRecoveryInventory } from "./recovery.ts";

const BOOT = "linux:11111111-2222-3333-4444-555555555555";
const PROCESS_START = "linux:424242";
const HOST_ID = "rf-20260731-abcdef";

let tmp: string;
let env: NodeJS.ProcessEnv;
let stateDir: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-recovery-registry-"));
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot, { recursive: true });
  env = {
    XDG_STATE_HOME: path.join(tmp, "xdg-state"),
    RUNFREE_TEST_FAKE_DOCKER: "1",
    RUNFREE_TEST_HOST_BOOT_ID: BOOT,
    RUNFREE_TEST_HOST_PROCESS_START: PROCESS_START,
  };
  stateDir = path.join(env.XDG_STATE_HOME as string, "runfree", "projects", projectHash(projectRoot));
  fs.mkdirSync(path.join(stateDir, "sessions"), { recursive: true });
  fs.mkdirSync(path.join(stateDir, "claude", "sessions"), { recursive: true });
  fs.writeFileSync(path.join(stateDir, "project.json"), `${JSON.stringify({ projectRoot, updatedAt: "2026-07-31T00:00:00.000Z" })}\n`);
  // The host's own crash evidence: a dead owner from a previous boot.
  fs.writeFileSync(path.join(stateDir, "sessions", `${HOST_ID}.json`), `${JSON.stringify({
    id: HOST_ID,
    projectRoot,
    composeProject: composeProjectName(projectRoot),
    command: "claude",
    hostPid: 4_194_305,
    hostBootId: "linux:99999999-2222-3333-4444-555555555555",
    hostProcessStart: PROCESS_START,
    startedAt: "2026-07-31T00:00:00.000Z",
    lastSeenAt: "2026-07-31T00:01:00.000Z",
  })}\n`);
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

const registryPath = (pid: number): string => path.join(stateDir, "claude", "sessions", `${pid}.json`);

// Field values an agent might choose to defeat a parser: the wrong type,
// the right type at the wrong magnitude, and the edges of the Date range.
const hostileNumber = fc.oneof(
  fc.integer(),
  fc.double({ noNaN: false, noDefaultInfinity: false }),
  fc.constantFrom(0, -1, 1e16, 8_640_000_000_000_001, Number.MAX_SAFE_INTEGER, 2 ** 53, 2 ** 63, -(2 ** 53)),
);
const hostileField = fc.oneof(
  hostileNumber,
  fc.string(),
  fc.constantFrom(null, true, false, [], {}, "2026-07-31T00:00:00.000Z"),
  fc.constant("00000000-0000-4000-8000-000000000001"),
  fc.constant(4242),
  fc.constant("/workspace"),
  fc.constant("98765"),
);
const registryShaped = fc.record({
  pid: hostileField,
  sessionId: hostileField,
  cwd: hostileField,
  startedAt: hostileField,
  updatedAt: hostileField,
  procStart: hostileField,
  name: hostileField,
  status: hostileField,
}, { requiredKeys: [] });

const registryFile = fc.oneof(
  registryShaped.map((value) => JSON.stringify(value)),
  fc.jsonValue({ maxDepth: 3 }).map((value) => JSON.stringify(value)),
  fc.string({ maxLength: 512 }),
  fc.uint8Array({ maxLength: 512 }).map((bytes) => Buffer.from(bytes)),
);

describe("agent-written Claude registry files", () => {
  it("never throw out of the inventory scan, never empty it, and never hide the host's own evidence", () => {
    fc.assert(
      fc.property(registryFile, registryFile, (first, second) => {
        fs.writeFileSync(registryPath(4242), first);
        fs.writeFileSync(registryPath(4243), second);

        const inventory = scanRecoveryInventory({ env });

        expect(inventory.items.some((item) => item.evidenceKind === "host" && item.sourceId === HOST_ID)).toBe(true);
        expect(inventory.truncated).toBe(false);
        // Every row a registry file produced is labelled as the agent's.
        for (const item of inventory.items.filter((entry) => entry.evidenceKind === "claude")) {
          expect(item.conversationSource).toBe("claude-reported");
          expect(item.startedAt === undefined || Number.isFinite(Date.parse(item.startedAt))).toBe(true);
        }
      }),
      propertyParameters({ numRuns: 150 }),
    );
  });
});
