#!/usr/bin/env node

// Docker argv ownership gate (todo 83 Phase 2). Non-session `docker` command
// lines are built only in packages/cli/src/runtime/docker-client.ts; the
// sealed session commands are the other owner. A `"docker"` string literal in
// any other CLI source file means hand-written argv came back. Each allowlist
// entry pins the exact number of `"docker"` literal occurrences its file is
// reviewed to carry: more than that count means new hand-written argv landed
// since the review, fewer means the entry is stale and must be corrected (or
// the file dropped from the allowlist). An allowlist entry may carry a
// `pending:` reason while its file is mid-migration; this file's own test
// asserts no `pending:` entry remains, so such an entry is always temporary.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const LITERAL = /(["'`])docker\1/;
const LITERAL_GLOBAL = new RegExp(LITERAL.source, "g");
const EXCLUDED = [/\.test\.ts$/, /test-harness\.ts$/, /embedded-assets\.generated\.ts$/];

export type DockerLiteralAllowlistEntry = Readonly<{
  /** Why this file is allowed to carry the literal, and why its count is safe. */
  reason: string;
  /** The exact number of `"docker"` literal occurrences this file is reviewed to carry. */
  count: number;
}>;

export const DOCKER_LITERAL_ALLOWLIST: Readonly<Record<string, DockerLiteralAllowlistEntry>> = {
  "packages/cli/src/runtime/docker-client.ts": {
    reason: "owner: builds every non-session docker argv, sync and async",
    count: 4,
  },

  // sealed-session: every "docker" literal is either the SessionDockerCommand
  // / SessionDockerExecutor type signature or a sealed builder object literal
  // (executable: "docker" + effect); no raw capture("docker", ...) call.
  "packages/cli/src/runtime/session-container-docker.ts": {
    reason: "sealed-session: SessionDockerCommand/SessionDockerExecutor type signatures plus validatedCommand({ executable: \"docker\", effect, ... }) builders only",
    count: 11,
  },
  "packages/cli/src/runtime/session-container-cleanup.ts": {
    reason: "sealed-session: SessionContainerCleanupCommand/Executor type signatures plus sealedCleanupCommand({ executable: \"docker\", effect, ... }) builders only; executeSessionContainerCleanupCommand executes via command.executable, not the literal",
    count: 8,
  },
  "packages/cli/src/runtime/session-container-running-proof.ts": {
    reason: "sealed-session: SessionContainerRunningProofExecutor type signature only",
    count: 1,
  },
  "packages/cli/src/runtime/session-named-volume-proof.ts": {
    reason: "sealed-session: SessionNamedVolumeInspectRequest type signature and its matching Object.freeze({ executable: \"docker\", ... }) request builder only",
    count: 2,
  },
  "packages/cli/src/runtime/session-container-start.ts": {
    reason: "sealed-session: SessionContainerForegroundSpawner type signature and defaultSpawner's typed parameter only; spawn(executable, ...) uses the parameter, not the literal",
    count: 2,
  },
  "packages/cli/src/runtime/session-file-publisher.ts": {
    reason: "sealed-session: sealed executor of SessionAdmissionDockerCommand args; refuses unsealed commands",
    count: 9,
  },

  // classifier: compares or types the command name; builds no argv.
  "packages/cli/src/runtime/operation-histogram.ts": {
    reason: "classifier: `command !== \"docker\"` routes histogram categorization; builds no argv",
    count: 1,
  },
  "packages/cli/src/runtime/control-plane-rebind-budget.ts": {
    reason: "classifier: `command === \"docker\"` gates budget accounting by command name; builds no argv",
    count: 1,
  },
  "packages/cli/src/runtime/session-admission-docker-gateway.ts": {
    reason: "classifier: types the gateway's accepted executable, compares `command !== \"docker\"` to pass through non-Docker calls (sync and async), and labels histogram categories; builds no argv itself",
    count: 5,
  },

  // classifier: the one remaining literal names the probe target for
  // io.commandExists, not argv; every docker argv in this file builds
  // through createDockerClient (docker-client.ts)
  "packages/cli/src/runtime/docker.ts": {
    reason: "classifier: io.commandExists(\"docker\", ...) names the availability-probe target, not argv; every docker argv in this file builds through createDockerClient",
    count: 1,
  },

  // classifier: Pick<StoppedSelectionDeps, "docker" | ...> names the deps
  // field by its own key, not argv; the `docker` dependency is the typed
  // client runtime.ts builds via createDockerClient, not a hand-written call
  "packages/cli/src/runtime/stopped-selection.ts": {
    reason: "classifier: Pick<StoppedSelectionDeps, \"docker\" | ...> names the deps field by its own key, not argv; the docker dependency is the typed client runtime.ts builds via createDockerClient",
    count: 1,
  },

  // ingress-forwarder.ts and ephemeral-helper.ts build their `docker run`
  // calls through createDockerClient's runContainer, whose DockerRunFlag
  // type admits `--label`; neither file carries a literal "docker" string,
  // so neither is listed here.

  // session-admission-driver.ts, session-eligibility-publication.ts,
  // session-admission-pending-reclaim.ts, and
  // session-internal-network-baseline.ts build their argv through
  // createDockerClient; none carries a literal "docker" string, so none is
  // listed here. session-file-heartbeat.ts and session-file-teardown.ts
  // never had a literal of their own.

  // sealed-session: the only "docker" literal is `executable: "docker"` in
  // `SessionContainerInventoryExecutor`'s function-type signature, the raw
  // executor type `inspectSessionContainerInventory` takes. Both of its
  // capture sites now build argv through
  // `createDockerClient({ capture: executor }, options)`; no literal remains
  // at either call.
  "packages/cli/src/runtime/session-container-reconciliation.ts": {
    reason: "sealed-session: `executable: \"docker\"` appears only in the SessionContainerInventoryExecutor function-type signature; both inventory-scan capture sites build argv through createDockerClient({ capture: executor }, options)",
    count: 1,
  },

  // sealed-session: the only "docker" literal types the local `executor`
  // lambda's first parameter so it matches session-container-cleanup.ts's
  // sealed SessionContainerCleanupExecutor; every call through it reaches
  // executeSessionContainerCleanupCommand or proveSessionContainerOrphanAbsent
  // (both sealed-session), never a raw capture("docker", ...) call.
  "packages/cli/src/runtime/session-reconcile.ts": {
    reason: "sealed-session: `executable: \"docker\"` types the local executor passed only to executeSessionContainerCleanupCommand and proveSessionContainerOrphanAbsent (session-container-cleanup.ts, sealed-session); no raw capture(\"docker\", ...) call in this file",
    count: 1,
  },

  // classifier: every admin docker argv builds through the typed client
  // (admin's own `adminDockerClient()`, built over `runCapture`). The two
  // remaining literals name the command for env/availability routing, not
  // argv: `childEnvForCommand`'s `command === "docker"` selects
  // `dockerChildEnv()` over the plain child env, and `dockerAvailable()`
  // passes "docker" to `commandExists` as the probe target.
  "packages/cli/src/admin/admin-core.ts": {
    reason: "classifier: `command === \"docker\"` in childEnvForCommand selects the Docker-specific child env; `commandExists(\"docker\")` in dockerAvailable names the availability-probe target; every docker argv in this file builds through adminDockerClient()/createDockerClient",
    count: 2,
  },
};

function countDockerLiterals(text: string): number {
  return text.match(LITERAL_GLOBAL)?.length ?? 0;
}

export function findDockerLiteralViolations(
  files: readonly { path: string; text: string }[],
  allowlist: Readonly<Record<string, DockerLiteralAllowlistEntry>>,
): string[] {
  const violations: string[] = [];
  for (const file of files) {
    const count = countDockerLiterals(file.text);
    const entry = allowlist[file.path];
    if (count > 0 && !entry) {
      violations.push(file.path);
      continue;
    }
    if (count === 0 && entry) {
      violations.push(`${file.path} (allowlisted but has no "docker" literal; remove its entry)`);
      continue;
    }
    if (entry && count !== entry.count) {
      violations.push(`${file.path} (allowlisted for ${entry.count} "docker" literal(s), found ${count}; update the allowlist count)`);
    }
  }
  return violations;
}

function trackedSources(): { path: string; text: string }[] {
  const listed = childProcess.execFileSync("git", ["ls-files", "--", "packages/cli/src/*.ts", "packages/cli/src/**/*.ts"], { cwd: repoRoot, encoding: "utf8" });
  return listed.split("\n").filter((file) => file && !EXCLUDED.some((pattern) => pattern.test(file)))
    .map((file) => ({ path: file, text: fs.readFileSync(path.join(repoRoot, file), "utf8") }));
}

const entryPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (entryPath === fileURLToPath(import.meta.url)) {
  const files = trackedSources();
  if (files.length === 0) {
    console.error("check-docker-argv: found no CLI sources; the gate would pass vacuously");
    process.exit(1);
  }
  const violations = findDockerLiteralViolations(files, DOCKER_LITERAL_ALLOWLIST);
  if (violations.length > 0) {
    console.error("Hand-written docker argv outside the Docker client (use packages/cli/src/runtime/docker-client.ts):");
    for (const violation of violations) console.error(`  ${violation}`);
    process.exit(1);
  }
  console.log("check-docker-argv: ok");
}
