import childProcess from "node:child_process";

import { describe, expect, test } from "vitest";

// Node behavior the credential cancellation design relies on: a signal that
// arrives while `spawnSync` blocks is handled once the caller has yielded
// with two `setImmediate` awaits, whichever event-loop phase its continuation
// runs in. One await is not enough from an I/O-callback continuation (it runs
// in the poll phase, and the first immediate fires before the next poll), so
// a settle helper that awaited once would read a host Ctrl-C as a foreign
// signal. The probe runs in its own process because it signals its parent.
describe("signal delivery after a blocking child", () => {
  const TRIALS = 10;
  const probe = `
const childProcess = require("node:child_process");
const fs = require("node:fs");
const settle = async () => {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
};
const continuations = {
  io: () => new Promise((resolve) => fs.readFile(__filename, () => resolve())),
  timer: () => new Promise((resolve) => setTimeout(resolve, 1)),
};
(async () => {
  const handled = { io: 0, timer: 0 };
  for (let trial = 0; trial < ${TRIALS}; trial += 1) {
    for (const [kind, continuation] of Object.entries(continuations)) {
      let ran = false;
      const onSignal = () => { ran = true; };
      process.on("SIGINT", onSignal);
      await continuation();
      // The blocking child signals this process, as a terminal Ctrl-C reaches
      // the whole foreground group while a provider runs.
      childProcess.spawnSync("/bin/sh", ["-c", "kill -INT $PPID; sleep 0.02"]);
      await settle();
      if (ran) handled[kind] += 1;
      process.off("SIGINT", onSignal);
      // Let a late delivery drain before the next trial's handler exists.
      process.on("SIGINT", () => {});
      await new Promise((resolve) => setTimeout(resolve, 20));
      process.removeAllListeners("SIGINT");
    }
  }
  process.stdout.write(JSON.stringify(handled));
})();
`;

  test("a signal from a synchronous child is handled within two setImmediate yields", () => {
    const result = childProcess.spawnSync(process.execPath, ["-e", probe], { encoding: "utf8", timeout: 20_000 });
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ io: TRIALS, timer: TRIALS });
  });
});
