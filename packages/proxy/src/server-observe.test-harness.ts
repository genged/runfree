// Test-only read observer for the spawned proxy server. Never part of the
// proxy build (`*.test-harness.ts` is excluded from the proxy tsconfig and the
// runtime bundle). `startProxy({ observe: true })` loads OBSERVE_PRELOAD_SOURCE
// with `--import` before the server module graph, so every later `node:fs`
// read the server makes goes through the wrappers below.
//
// What it records: content reads (readFile/readFileSync, open/openSync,
// createReadStream, readdir/readdirSync, and the fs/promises equivalents) of
// any path inside PROXY_SECRET_DIR (the proxy-only token directory) and of
// PROXY_RESOLVED_HOSTS_PATH (the resolved-hosts snapshot the DNS lookup reads
// for every hostname target). The proxy reaches fs through the default import
// (`fs.readFileSync(...)`, a property lookup at call time), so patching the
// module object intercepts it; `syncBuiltinESMExports()` also refreshes the
// named ESM exports in case a module binds `readFileSync` directly.
//
// Each read is appended synchronously, with the unpatched appendFileSync, to
// RUNFREE_TEST_OBSERVE_LOG before the read itself runs. A read that happens
// before the proxy writes its response is therefore on disk before the client
// sees the response: a negative assertion cannot pass because an event was
// still in flight on a pipe.
import fs from "node:fs";

export type ObservedRead = {
  kind: "secret" | "resolved-hosts";
  op: string;
  path: string;
};

export const OBSERVE_LOG_ENV = "RUNFREE_TEST_OBSERVE_LOG";

export const OBSERVE_PRELOAD_SOURCE = `
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { syncBuiltinESMExports } from "node:module";

const logPath = process.env.${OBSERVE_LOG_ENV};
if (logPath) {
  const append = fs.appendFileSync.bind(fs);
  const toPath = (value) => {
    if (typeof value === "string") return value;
    if (value instanceof URL) return fileURLToPath(value);
    if (Buffer.isBuffer(value)) return value.toString("utf8");
    return undefined;
  };
  const classify = (absolute) => {
    const secretDir = process.env.PROXY_SECRET_DIR;
    if (secretDir) {
      const root = path.resolve(secretDir);
      if (absolute === root || absolute.startsWith(root + path.sep)) return "secret";
    }
    const resolvedHosts = process.env.PROXY_RESOLVED_HOSTS_PATH;
    if (resolvedHosts && absolute === path.resolve(resolvedHosts)) return "resolved-hosts";
    return undefined;
  };
  const record = (op, target) => {
    const raw = toPath(target);
    if (raw === undefined) return;
    const absolute = path.resolve(raw);
    const kind = classify(absolute);
    if (kind) append(logPath, JSON.stringify({ kind, op, path: absolute }) + "\\n");
  };
  const wrap = (owner, name, op) => {
    const original = owner[name];
    if (typeof original !== "function") return;
    owner[name] = function observedRead(target, ...rest) {
      record(op, target);
      return original.call(this, target, ...rest);
    };
  };
  for (const name of ["readFileSync", "readFile", "openSync", "open", "createReadStream", "readdirSync", "readdir"]) {
    wrap(fs, name, "fs." + name);
  }
  for (const name of ["readFile", "open", "readdir"]) {
    wrap(fsp, name, "fs/promises." + name);
  }
  syncBuiltinESMExports();
}
`;

export function observePreloadArgs(): string[] {
  return ["--import", `data:text/javascript,${encodeURIComponent(OBSERVE_PRELOAD_SOURCE)}`];
}

export function readObservedReads(logPath: string): ObservedRead[] {
  let raw: string;
  try {
    raw = fs.readFileSync(logPath, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return [];
    throw error;
  }
  return raw.split("\n").filter((line) => line !== "").map((line) => JSON.parse(line) as ObservedRead);
}
