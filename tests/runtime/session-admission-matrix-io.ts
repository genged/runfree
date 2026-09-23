// The `RuntimeIO` the internal admission runners hand to the driver.
//
// Extracted so the nominal matrix and the crash runner share one execution
// seam. The crash runner wraps this to observe the driver's real Docker command
// stream, which is how it injects a crash at an exact transition without any
// fault-injection hook in production code.
//
// It refuses admin mutation outright: these runners prove admission, and an
// admission proof that could reconfigure the runtime it is measuring would not
// be evidence about the runtime a maintainer actually has.

import childProcess from "node:child_process";

import type { RuntimeIO } from "../../packages/cli/src/runtime/types.ts";

const CAPTURE_MAX_BYTES = 32 * 1024 * 1024;

export function createMatrixRuntimeIO(): RuntimeIO {
  return {
    run(command, args, options = {}) {
      const result = childProcess.spawnSync(command, args, { stdio: "inherit", ...options });
      if (result.error) throw result.error;
      return result.status ?? 1;
    },
    capture(command, args, options = {}) {
      const result = childProcess.spawnSync(command, args, {
        encoding: "utf8",
        maxBuffer: CAPTURE_MAX_BYTES,
        ...options,
      });
      if (result.error) throw result.error;
      return {
        status: result.status ?? 1,
        stdout: typeof result.stdout === "string" ? result.stdout : "",
        stderr: typeof result.stderr === "string" ? result.stderr : "",
      };
    },
    commandExists(command, options = {}) {
      return childProcess.spawnSync("command", ["-v", command], {
        shell: true,
        stdio: "ignore",
        ...options,
      }).status === 0;
    },
    confirm: () => false,
    isInteractive: () => false,
    async admin() {
      throw new Error("internal session admission runners refuse runtime admin mutation");
    },
  };
}
