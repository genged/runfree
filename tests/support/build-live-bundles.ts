// Vitest globalSetup for the `runtime-live` project: prebuilds the CLI and the
// session-admission runners the live fixture and tranches spawn, and stamps
// this invocation's run token into the environment. See
// `build-test-bundles.ts` (the unit-suite setup this shares its builder with)
// and `prebuilt-entry.ts` for the fallback when Bun is absent.

import type { TestProject } from "vitest/node";

import { createBundleSetup, LIVE_BUNDLES } from "./build-test-bundles.ts";
import { LIVE_RUN_ID_ENV, newLiveRunToken } from "../runtime/live/run-token.ts";

const buildBundles = createBundleSetup(LIVE_BUNDLES);

export default function setupLiveProject(project: TestProject): void {
  // Set before the first worker is forked, so every worker inherits the same
  // token and the fixture's leak guard can tell a sibling file's live runtime
  // from an earlier run's residue. Only this project's files read it, and a
  // caller that pinned one deliberately keeps it.
  process.env[LIVE_RUN_ID_ENV] ??= newLiveRunToken();
  buildBundles(project);
}
