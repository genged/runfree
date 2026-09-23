#!/usr/bin/env node

import childProcess from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(packageRoot, "src", "cli.ts");
const invocationCwd = process.cwd();

function formatRunfreeLog(message) {
  return `${new Date().toISOString()} runfree: ${message}`;
}

const result = childProcess.spawnSync(
  process.execPath,
  ["--import", "tsx", cliPath, ...process.argv.slice(2)],
  {
    cwd: packageRoot,
    env: {
      ...process.env,
      RUNFREE_INVOCATION_CWD: invocationCwd,
      RUNFREE_PROJECT_ROOT: process.env.RUNFREE_PROJECT_ROOT ?? invocationCwd,
    },
    stdio: "inherit",
  },
);

if (result.error) {
  console.error(formatRunfreeLog(result.error.message));
  process.exit(1);
}

process.exit(result.status ?? 1);
