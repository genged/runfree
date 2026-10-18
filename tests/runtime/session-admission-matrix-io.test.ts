// The admission runners' IO must answer an interrupted call the way the
// production IO does. A live launch once failed with a raw "spawnSync docker
// ETIMEDOUT" because this capture threw where the production capture returns
// status 124, which the driver classifies as an unavailable observation.

import { describe, expect, test } from "vitest";

import { createMatrixRuntimeIO } from "./session-admission-matrix-io.ts";

describe("matrix runtime IO", () => {
  test("a capture cut by its timeout returns the fail-closed status instead of throwing", () => {
    const io = createMatrixRuntimeIO();
    const result = io.capture(process.execPath, ["-e", "setTimeout(() => {}, 10_000)"], { timeout: 100 });
    expect(result.status).toBe(124);
    expect(result.timedOut).toBe(true);
  });

  test("a capture of a missing executable returns the spawn-error status instead of throwing", () => {
    const io = createMatrixRuntimeIO();
    expect(io.capture("runfree-no-such-executable", []).status).toBe(125);
  });

  test("a clean capture keeps the child's own status and output", () => {
    const io = createMatrixRuntimeIO();
    const result = io.capture(process.execPath, ["-e", "process.stdout.write('ok'); process.exit(3)"]);
    expect(result).toMatchObject({ status: 3, stdout: "ok" });
    expect(result.timedOut).toBeUndefined();
  });
});
