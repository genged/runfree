// Live core proof for the pinned-tool --session-id contract (same-terminal
// session resume, task 4).
//
// Tasks 2-3 made every Claude and Pi launch pass `--session-id <uuid>`. The
// unit suite (`scripts/agent-session-id-contract.test.ts`) proves the gate's
// own logic against fake runners; it cannot prove the pinned binaries
// actually behave the way the launch and resume paths assume, because no
// Docker runs there. This file runs the exact same gate against the real,
// built project agent image on real Docker — the same image a per-session
// launch runs — so a tool update that silently broke the contract fails here
// before it ever reaches a live launch.
//
// Security review F1: the probe never runs on the host. It is spawned by
// `imageContractRunner` inside a throwaway container
// (`--network none --cap-drop ALL --security-opt no-new-privileges --user
// 1000:1000`), exactly as `scripts/agent-session-id-contract.ts` documents.
// This file itself runs no claude/pi binary and no npm step; it only
// resolves the already-built image and hands it to the shared gate.

import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { assertAgentSessionIdContract, imageContractRunner } from "../../../scripts/agent-session-id-contract.ts";
import { composeProjectName, projectAgentImageId } from "./docker.ts";
import {
  destroyLiveFixture,
  provisionLiveFixture,
  type LiveFixture,
  type LiveRuntimeBackend,
} from "./fixture.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop for the --session-id contract tranche");
  }
  return backend;
}

describe("pinned claude/pi --session-id contract on the built agent image", () => {
  requiredBackend();
  let fixture: LiveFixture;
  let agentImage: string;

  beforeAll(() => {
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT });
    // The project agent image the runtime just built, resolved by its daemon
    // labels (same helper the negative/drift admission tranches use) — this
    // tranche needs no running session, only the image a session would run.
    agentImage = projectAgentImageId(composeProjectName(fixture));
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  test("the exact pinned claude and pi binaries accept and refuse --session-id the way the launch and resume paths assume", () => {
    expect(() => assertAgentSessionIdContract(imageContractRunner(agentImage))).not.toThrow();
  });
});
