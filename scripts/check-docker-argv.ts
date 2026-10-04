#!/usr/bin/env node

// Docker argv ownership gate (todo 83 Phase 2). Non-session `docker` command
// lines are built only in packages/cli/src/runtime/docker-client.ts; the
// sealed session commands are the other owner. A `"docker"` string literal in
// any other CLI source file means hand-written argv came back. Files still
// being migrated carry a `pending:` reason; the list only shrinks.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const LITERAL = /(["'`])docker\1/;
const EXCLUDED = [/\.test\.ts$/, /test-harness\.ts$/, /embedded-assets\.generated\.ts$/];

export const DOCKER_LITERAL_ALLOWLIST: Readonly<Record<string, string>> = {
  "packages/cli/src/runtime/docker-client.ts": "owner: builds every non-session docker argv",

  // sealed-session: every "docker" literal is either the SessionDockerCommand
  // / SessionDockerExecutor type signature or a sealed builder object literal
  // (executable: "docker" + effect); no raw capture("docker", ...) call.
  "packages/cli/src/runtime/session-container-docker.ts": "sealed-session: SessionDockerCommand/SessionDockerExecutor type signatures plus validatedCommand({ executable: \"docker\", effect, ... }) builders only",
  "packages/cli/src/runtime/session-container-cleanup.ts": "sealed-session: SessionContainerCleanupCommand/Executor type signatures plus sealedCleanupCommand({ executable: \"docker\", effect, ... }) builders only; executeSessionContainerCleanupCommand executes via command.executable, not the literal",
  "packages/cli/src/runtime/session-container-running-proof.ts": "sealed-session: SessionContainerRunningProofExecutor type signature only",
  "packages/cli/src/runtime/session-named-volume-proof.ts": "sealed-session: SessionNamedVolumeInspectRequest type signature and its matching Object.freeze({ executable: \"docker\", ... }) request builder only",
  "packages/cli/src/runtime/session-container-start.ts": "sealed-session: SessionContainerForegroundSpawner type signature and defaultSpawner's typed parameter only; spawn(executable, ...) uses the parameter, not the literal",
  "packages/cli/src/runtime/session-file-publisher.ts": "sealed-session: sealed executor of SessionAdmissionDockerCommand args; refuses unsealed commands",

  // classifier: compares or types the command name; builds no argv.
  "packages/cli/src/runtime/operation-histogram.ts": "classifier: `command !== \"docker\"` routes histogram categorization; builds no argv",
  "packages/cli/src/runtime/control-plane-rebind-budget.ts": "classifier: `command === \"docker\"` gates budget accounting by command name; builds no argv",
  "packages/cli/src/runtime/session-admission-docker-gateway.ts": "classifier: types the gateway's accepted executable, compares `command !== \"docker\"` to pass through non-Docker calls, and labels histogram categories; builds no argv itself",

  // classifier: the one remaining literal names the probe target for
  // io.commandExists, not argv; every docker argv in this file builds
  // through createDockerClient (docker-client.ts)
  "packages/cli/src/runtime/docker.ts": "classifier: io.commandExists(\"docker\", ...) names the availability-probe target, not argv; every docker argv in this file builds through createDockerClient",

  // classifier: Pick<StoppedSelectionDeps, "docker" | ...> names the deps
  // field by its own key, not argv; the `docker` dependency is the typed
  // client runtime.ts builds via createDockerClient, not a hand-written call
  "packages/cli/src/runtime/stopped-selection.ts": "classifier: Pick<StoppedSelectionDeps, \"docker\" | ...> names the deps field by its own key, not argv; the docker dependency is the typed client runtime.ts builds via createDockerClient",

  // Task 6 is complete: `DockerRunFlag` now admits `--label` (controller
  // ruling, 2026-10-04), so ingress-forwarder.ts's and ephemeral-helper.ts's
  // remaining `docker run` sites build through `createDockerClient`'s
  // `runContainer` like every other call in the task's seven files. None of
  // them carry a literal "docker" string any more, so none are listed here.

  // Task 7 is complete: the raw session-path capture("docker", ...) and
  // executor("docker", ...) sites in session-admission-driver.ts,
  // session-eligibility-publication.ts, session-admission-pending-reclaim.ts,
  // and session-internal-network-baseline.ts now build their argv through
  // createDockerClient; none of them carry a literal "docker" string any
  // more, so none are listed here. session-file-heartbeat.ts and
  // session-file-teardown.ts never had a literal of their own.

  // sealed-session: the only "docker" literal is `executable: "docker"` in
  // `SessionContainerInventoryExecutor`'s function-type signature, the raw
  // executor type `inspectSessionContainerInventory` takes. Both of its
  // capture sites now build argv through
  // `createDockerClient({ capture: executor }, options)`; no literal remains
  // at either call.
  "packages/cli/src/runtime/session-container-reconciliation.ts": "sealed-session: `executable: \"docker\"` appears only in the SessionContainerInventoryExecutor function-type signature; both inventory-scan capture sites build argv through createDockerClient({ capture: executor }, options)",

  // sealed-session: the only "docker" literal types the local `executor`
  // lambda's first parameter so it matches session-container-cleanup.ts's
  // sealed SessionContainerCleanupExecutor; every call through it reaches
  // executeSessionContainerCleanupCommand or proveSessionContainerOrphanAbsent
  // (both sealed-session), never a raw capture("docker", ...) call.
  "packages/cli/src/runtime/session-reconcile.ts": "sealed-session: `executable: \"docker\"` types the local executor passed only to executeSessionContainerCleanupCommand and proveSessionContainerOrphanAbsent (session-container-cleanup.ts, sealed-session); no raw capture(\"docker\", ...) call in this file",

  // classifier: Task 8 moved every admin docker argv onto the typed client
  // (admin's own `adminDockerClient()`, built over `runCapture`). The two
  // remaining literals name the command for env/availability routing, not
  // argv: `childEnvForCommand`'s `command === "docker"` selects
  // `dockerChildEnv()` over the plain child env, and `dockerAvailable()`
  // passes "docker" to `commandExists` as the probe target.
  "packages/cli/src/admin/admin-core.ts": "classifier: `command === \"docker\"` in childEnvForCommand selects the Docker-specific child env; `commandExists(\"docker\")` in dockerAvailable names the availability-probe target; every docker argv in this file builds through adminDockerClient()/createDockerClient",
};

export function findDockerLiteralViolations(
  files: readonly { path: string; text: string }[],
  allowlist: Readonly<Record<string, string>>,
): string[] {
  const violations: string[] = [];
  for (const file of files) {
    const has = LITERAL.test(file.text);
    if (has && !(file.path in allowlist)) violations.push(file.path);
    if (!has && file.path in allowlist) violations.push(`${file.path} (allowlisted but has no "docker" literal; remove its entry)`);
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
