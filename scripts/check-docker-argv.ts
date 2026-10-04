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

  // classifier: compares or types the command name; builds no argv.
  "packages/cli/src/runtime/operation-histogram.ts": "classifier: `command !== \"docker\"` routes histogram categorization; builds no argv",
  "packages/cli/src/runtime/control-plane-rebind-budget.ts": "classifier: `command === \"docker\"` gates budget accounting by command name; builds no argv",
  "packages/cli/src/runtime/session-admission-docker-gateway.ts": "classifier: types the gateway's accepted executable, compares `command !== \"docker\"` to pass through non-Docker calls, and labels histogram categories; builds no argv itself",
  "packages/cli/src/runtime.ts": "pending: Task 4",

  // pending: Task 3
  "packages/cli/src/runtime/docker.ts": "pending: Task 3",
  "packages/cli/src/runtime/docker-listing.ts": "pending: Task 3",

  // pending: Task 4
  "packages/cli/src/runtime/startup.ts": "pending: Task 4",
  "packages/cli/src/runtime/topology.ts": "pending: Task 4",
  "packages/cli/src/runtime/warm-proof.ts": "pending: Task 4",
  "packages/cli/src/runtime/control-plane-effective-proof.ts": "pending: Task 4",
  "packages/cli/src/runtime/control-plane-rebind-docker.ts": "pending: Task 4",
  "packages/cli/src/runtime/proxy-containment.ts": "pending: Task 4",
  "packages/cli/src/runtime/proxy-firewall-readiness.ts": "pending: Task 4",
  "packages/cli/src/runtime/rebind-trust-receipt.ts": "pending: Task 4",
  "packages/cli/src/runtime/state.ts": "pending: Task 4",
  "packages/cli/src/runtime/probes.ts": "pending: Task 4",
  "packages/cli/src/runtime/attach.ts": "pending: Task 4",
  "packages/cli/src/runtime/images.ts": "pending: Task 4",
  "packages/cli/src/runtime/dependency-overlays.ts": "pending: Task 4",
  "packages/cli/src/control/activation.ts": "pending: Task 4",
  "packages/cli/src/runtime/stopped-selection.ts": "pending: Task 4",

  // pending: Task 5
  "packages/cli/src/runtime/destroy.ts": "pending: Task 5",
  "packages/cli/src/runtime/recovery.ts": "pending: Task 5",
  "packages/cli/src/runtime/sessions.ts": "pending: Task 5",
  "packages/cli/src/runtime/approvals.ts": "pending: Task 5",
  "packages/cli/src/runtime/audit.ts": "pending: Task 5",
  "packages/cli/src/runtime/denial-summary.ts": "pending: Task 5",
  "packages/cli/src/runtime/ingress-forwarder-ownership.ts": "pending: Task 5",

  // pending: Task 6
  "packages/cli/src/runtime/ingress-forwarder.ts": "pending: Task 6",
  "packages/cli/src/runtime/session-callback-ingress.ts": "pending: Task 6",
  "packages/cli/src/runtime/session-mcp-callback.ts": "pending: Task 6",
  "packages/cli/src/runtime/forward.ts": "pending: Task 6",
  "packages/cli/src/runtime/vnc.ts": "pending: Task 6",
  "packages/cli/src/runtime/ephemeral-helper.ts": "pending: Task 6",
  "packages/cli/src/runtime/ephemeral-helper-residue.ts": "pending: Task 6",

  // pending: Task 7
  "packages/cli/src/runtime/session-admission-driver.ts": "pending: Task 7",
  "packages/cli/src/runtime/session-eligibility-publication.ts": "pending: Task 7",
  "packages/cli/src/runtime/session-admission-pending-reclaim.ts": "pending: Task 7",
  "packages/cli/src/runtime/session-internal-network-baseline.ts": "pending: Task 7",
  "packages/cli/src/runtime/session-container-reconciliation.ts": "pending: Task 7",
  "packages/cli/src/runtime/session-reconcile.ts": "pending: Task 7",
  // Unplanned (see task-2-report.md): this is the sealed session-file
  // chokepoint, but captureSealed hardcodes the "docker" literal instead of
  // reading it off the already-validated command, so it fails the
  // sealed-session rule's "one raw capture(\"docker\", ...) call" exception.
  // Only session-file-heartbeat.ts and session-file-teardown.ts call through
  // it, and both are Task 7 files with no "docker" literal of their own, so
  // this is grouped with Task 7 pending the controller's ruling.
  "packages/cli/src/runtime/session-file-publisher.ts": "pending: Task 7 (unplanned; captureSealed's io.capture(\"docker\", ...) is a raw call on an otherwise sealed-session file)",

  // pending: Task 8
  "packages/cli/src/admin/admin-core.ts": "pending: Task 8",
  "packages/cli/src/admin/diagnostics.ts": "pending: Task 8",
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
