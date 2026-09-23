const childProcess = require("node:child_process");
const fs = require("node:fs");

const mode = process.argv[2];

if (mode === "worker" || mode === "ignore-term-worker") {
  const statePath = process.argv[3];
  if (!statePath) throw new Error("watchdog fixture requires a state path");
  const ignoreTerm = mode === "ignore-term-worker";
  if (ignoreTerm) process.on("SIGTERM", () => {});
  const descendant = childProcess.spawn(
    process.execPath,
    [__filename, ignoreTerm ? "ignore-term-descendant" : "descendant"],
    {
      stdio: "ignore",
    },
  );
  if (!descendant.pid) throw new Error("watchdog fixture descendant has no pid");
  fs.writeFileSync(statePath, `${JSON.stringify({ descendantPid: descendant.pid })}\n`, { mode: 0o600 });
  setInterval(() => {}, 1_000);
} else if (mode === "descendant" || mode === "ignore-term-descendant") {
  if (mode === "ignore-term-descendant") process.on("SIGTERM", () => {});
  setInterval(() => {}, 1_000);
} else {
  throw new Error("unknown watchdog fixture mode");
}
