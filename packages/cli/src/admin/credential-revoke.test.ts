import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

import { main } from "../cli.ts";
import { setOutputWriterForTest } from "../warnings.ts";
import type { CredentialAddInput } from "./admin-core.ts";
import { createAdminState } from "./context.ts";
import { bindDesiredCredentialSource, credentialClearSourceIntent, revokeDesiredCredentialState } from "./credential-policy.ts";
import { runAdminAction } from "./options.ts";

// Revocation and source binding run against a real admin state on a temp
// root. Docker is only ever a fake `docker` script on PATH that logs its argv.

// V5 drives the real `main` error boundary with an injected `run`, so the
// command tree and command context that only the default `runCli` reaches
// are never used. Stubbing them keeps this file's import time down.
vi.mock("../commands/app.ts", () => ({ runCommandApp: () => Promise.reject(new Error("unused in this file")) }));
vi.mock("../commands/context.ts", () => ({ createCommandContext: () => { throw new Error("unused in this file"); } }));

const PROJECT_ID = "0123456789ab";
const FAKE_PROXY_STARTED_AT = "2026-06-18T00:00:00.000000000Z";

let root: string | undefined;
let consoleLogSpy: ReturnType<typeof vi.spyOn> | undefined;
let consoleErrorSpy: ReturnType<typeof vi.spyOn> | undefined;

afterEach(() => {
  consoleLogSpy?.mockRestore();
  consoleLogSpy = undefined;
  consoleErrorSpy?.mockRestore();
  consoleErrorSpy = undefined;
  setOutputWriterForTest(undefined);
  process.exitCode = undefined;
  if (root) fs.rmSync(root, { recursive: true, force: true });
  root = undefined;
});

// Copied from options.test.ts: the credential observation batch runs for real,
// with the proxy's /run paths mapped onto this test's files.
function dockerCredentialObservationShell(options: { markerPath?: string; secretsDir: string; startedAt?: string }): string {
  fs.mkdirSync(options.secretsDir, { recursive: true });
  const markerPath = options.markerPath ?? path.join(options.secretsDir, "..", "no-runtime-validation-marker");
  return `
if [ "$1" = "inspect" ] && [ "$2" = "--format" ]; then
  case "$3" in
    *"State.Running"*"State.StartedAt"*)
      printf 'true\\t%s\\n' ${JSON.stringify(options.startedAt ?? FAKE_PROXY_STARTED_AT)}
      exit 0
      ;;
  esac
fi
case "$*" in
  *"runfree-credential-observation"*)
    for rf_last; do :; done
    rf_script=$(printf '%s' "$rf_last" | PATH=/usr/bin:/bin sed \\
      -e "s#'/run/runfree-runtime-validation.json'#'${markerPath}'#" \\
      -e "s#'/run/runfree-proxy-secrets'#'${options.secretsDir}'#")
    PATH=/usr/bin:/bin /bin/sh -c "$rf_script"
    exit $?
    ;;
esac
`;
}

// A compose project with one agent and one proxy container.
const DOCKER_DISCOVERY_SHELL = `
if [ "$1" = "info" ]; then exit 0; fi
if [ "$1" = "ps" ]; then
  case "$*" in
    *"com.docker.compose.service=proxy"*) printf '%s\\n' proxy-id ;;
    *) printf '%s\\n' agent-id ;;
  esac
  exit 0
fi
if [ "$1" = "inspect" ] && [ "$2" = "--format" ]; then
  case "$3" in
    *"com.docker.compose.project"*) printf '%s\\n' runfree-fake; exit 0 ;;
  esac
fi
`;

type Harness = {
  dockerLogPath: string;
  receiptsPath: string;
  secretsDir: string;
  state: ReturnType<typeof createAdminState>;
  statusPath: string;
  tokenConfigPath: string;
  projectRoot: string;
};

function harness(options: {
  /** The fake docker body, or a builder given the mapped proxy secrets dir. */
  docker?: string | ((secretsDir: string) => string);
  env?: Record<string, string>;
  tokens?: Record<string, unknown>;
} = {}): Harness {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-credential-revoke-"));
  const projectRoot = path.join(root, "project");
  const fakeBin = path.join(root, "fake-bin");
  const home = path.join(root, "home");
  const stateDir = path.join(root, "state");
  const secretsDir = path.join(root, "proxy-secrets");
  const dockerLogPath = path.join(root, "docker-calls.log");
  const policyPath = path.join(projectRoot, ".runfree", "network-policy.json");
  const tokenConfigPath = path.join(root, "config", "tokens.json");
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.mkdirSync(path.dirname(tokenConfigPath), { recursive: true });
  fs.mkdirSync(fakeBin, { recursive: true });
  fs.writeFileSync(policyPath, `${JSON.stringify({
    hosts: ["api.github.com"],
    tokens: {
      github: {
        description: "GitHub token",
        credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }],
      },
    },
  }, null, 2)}\n`);
  fs.writeFileSync(tokenConfigPath, `${JSON.stringify(options.tokens ?? { github: { source: "env", env: "GH_X" } }, null, 2)}\n`, { mode: 0o600 });
  if (options.docker !== undefined) {
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
printf '%s\\n' "$*" >> ${JSON.stringify(dockerLogPath)}
${typeof options.docker === "function" ? options.docker(secretsDir) : options.docker}
exit 0
`, { mode: 0o755 });
  }
  const state = createAdminState({
    env: {
      HOME: home,
      PATH: fakeBin,
      RUNFREE_PROJECT_ID: PROJECT_ID,
      RUNFREE_TEST_FAKE_DOCKER: "1",
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_STATE_HOME: path.join(home, ".local", "state"),
      ...options.env,
    },
    policyPath,
    projectRoot,
    stateDir,
    tokenConfigPath,
  });
  return {
    dockerLogPath,
    projectRoot,
    receiptsPath: path.join(path.dirname(state.syncStatusPath), `token-resolution-receipts-${PROJECT_ID}.json`),
    secretsDir,
    state,
    statusPath: state.syncStatusPath,
    tokenConfigPath,
  };
}

/** Status and receipt entries for github and an unrelated credential. */
function seedHostState(h: Harness): void {
  fs.mkdirSync(path.dirname(h.statusPath), { recursive: true });
  fs.writeFileSync(h.statusPath, `${JSON.stringify({
    github: { ok: true, state: "ok", syncedAt: "2026-06-18T00:00:00.000Z", message: "synced to proxy tmpfs" },
    other: { ok: true, state: "ok", syncedAt: "2026-06-18T00:00:00.000Z", message: "synced to proxy tmpfs" },
  }, null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(h.receiptsPath, `${JSON.stringify({
    schemaVersion: 1,
    receipts: [
      { tokenName: "github", sourceFingerprint: "f".repeat(64), proxyStoreGeneration: "gen-1", resolvedAt: 1_750_000_000_000 },
      { tokenName: "other", sourceFingerprint: "e".repeat(64), proxyStoreGeneration: "gen-1", resolvedAt: 1_750_000_000_000 },
    ],
  }, null, 2)}\n`, { mode: 0o600 });
}

function hostFiles(h: Harness): Record<string, string | undefined> {
  const read = (file: string) => (fs.existsSync(file) ? fs.readFileSync(file, "utf8") : undefined);
  return { tokens: read(h.tokenConfigPath), status: read(h.statusPath), receipts: read(h.receiptsPath) };
}

function readJson(file: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
}

function dockerLog(h: Harness): string[] {
  return fs.existsSync(h.dockerLogPath) ? fs.readFileSync(h.dockerLogPath, "utf8").split("\n").filter(Boolean) : [];
}

function captureOutput(): { errors: string[]; logs: string[] } {
  const errors: string[] = [];
  const logs: string[] = [];
  consoleErrorSpy = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    errors.push(args.map(String).join(" "));
  });
  consoleLogSpy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  });
  return { errors, logs };
}

/** Every printed error line, without the printer's timestamp prefix and indentation. */
function errorLines(errors: string[]): string[] {
  return errors.join("\n").split("\n")
    .map((line) => line.replace(/^\S+ runfree error: /, "").trim())
    .filter(Boolean);
}

async function revoke(h: Harness, name = "github"): Promise<{ status: number; result?: string; errors: string[] }> {
  const { errors } = captureOutput();
  let result: string | undefined;
  const status = await runAdminAction(h.state, () => {
    result = revokeDesiredCredentialState(name);
  });
  return { status, result, errors };
}

function addInput(overrides: Partial<CredentialAddInput> = {}): CredentialAddInput {
  return {
    name: "github",
    credential: { host: "api.github.com", header: "Authorization", scheme: "bearer" } as CredentialAddInput["credential"],
    reloadProxy: false,
    ...overrides,
  };
}

async function bind(h: Harness, input: CredentialAddInput): Promise<{ status: number; result?: boolean; errors: string[] }> {
  const { errors } = captureOutput();
  let result: boolean | undefined;
  const status = await runAdminAction(h.state, () => {
    result = bindDesiredCredentialSource(input);
  });
  return { status, result, errors };
}

/** A running proxy whose token removal exec fails with `boom`. */
const failingRemovalDocker = (secretsDir: string): string => `${DOCKER_DISCOVERY_SHELL}
${dockerCredentialObservationShell({ secretsDir })}
if [ "$1" = "exec" ]; then
  case "$*" in *"rm -f"*) printf '%s\\n' boom >&2; exit 1 ;; esac
fi`;

/** The seeded entries for `other`, which revoking github must keep unchanged. */
function expectOtherEntriesKept(h: Harness, seeded: Record<string, string | undefined>): void {
  const seededStatus = JSON.parse(seeded.status ?? "{}") as Record<string, unknown>;
  const seededReceipts = (JSON.parse(seeded.receipts ?? "{}") as { receipts: { tokenName: string }[] }).receipts;
  expect(readJson(h.statusPath)).toEqual({ other: seededStatus.other });
  expect(readJson(h.receiptsPath).receipts).toEqual(seededReceipts.filter((receipt) => receipt.tokenName === "other"));
}

const REVOCATION_REFUSAL_TAIL = [
  "the credential is still bound and still injected",
  "restore Docker access and retry",
];

describe("revokeDesiredCredentialState", () => {
  test("V1: Docker unavailable refuses before touching host state", async () => {
    const h = harness();
    seedHostState(h);
    const before = hostFiles(h);

    const { status, result, errors } = await revoke(h);

    expect(status).toBe(1);
    expect(result).toBeUndefined();
    expect(errorLines(errors)).toEqual([
      "github was not removed: cannot verify credential revocation while proxy state is docker-unavailable",
      ...REVOCATION_REFUSAL_TAIL,
    ]);
    expect(hostFiles(h)).toEqual(before);
  });

  test("V2: a running proxy with no StartedAt refuses before any exec", async () => {
    const h = harness({
      docker: `${DOCKER_DISCOVERY_SHELL}
if [ "$1" = "inspect" ] && [ "$2" = "--format" ]; then
  case "$3" in *"State.Running"*"State.StartedAt"*) printf 'true\\t\\n'; exit 0 ;; esac
fi`,
    });
    seedHostState(h);
    const before = hostFiles(h);

    const { status, errors } = await revoke(h);

    expect(status).toBe(1);
    expect(errorLines(errors)).toEqual([
      "github was not removed: cannot verify credential revocation while proxy state is proxy-unreachable",
      ...REVOCATION_REFUSAL_TAIL,
    ]);
    expect(hostFiles(h)).toEqual(before);
    const calls = dockerLog(h);
    expect(calls.some((call) => call.startsWith("info"))).toBe(true);
    expect(calls.filter((call) => call.startsWith("exec"))).toEqual([]);
  });

  test("V3: with no proxy running, the binding, status and receipt go and other entries stay", async () => {
    const h = harness({ docker: "" });
    seedHostState(h);
    const seeded = hostFiles(h);

    const first = await revoke(h);

    expect(first.status).toBe(0);
    expect(first.result).toBe("removed");
    expect(readJson(h.tokenConfigPath)).toEqual({});
    expectOtherEntriesKept(h, seeded);
    expect(dockerLog(h).filter((call) => call.startsWith("exec"))).toEqual([]);

    const second = await revoke(h);
    expect(second.status).toBe(0);
    expect(second.result).toBe("not-present");
  });

  test("V4: a running proxy loses the token and its temporary files before host state is removed", async () => {
    // The removal command runs for real, with the proxy secret dir mapped
    // onto this test's directory.
    const h = harness({
      docker: (secretsDir) => `${DOCKER_DISCOVERY_SHELL}
${dockerCredentialObservationShell({ secretsDir })}
if [ "$1" = "exec" ]; then
  case "$*" in
    *"rm -f"*)
      for rf_last; do :; done
      rf_script=$(printf '%s' "$rf_last" | PATH=/usr/bin:/bin sed -e "s#'/run/runfree-proxy-secrets/#'${secretsDir}/#g")
      PATH=/usr/bin:/bin /bin/sh -c "$rf_script"
      exit $?
      ;;
  esac
fi`,
    });
    const { secretsDir } = h;
    for (const file of ["github", "github.tmp", "github.tmp.123"]) {
      fs.writeFileSync(path.join(secretsDir, file), "secret-value\n", { mode: 0o600 });
    }
    fs.writeFileSync(path.join(secretsDir, "other"), "other-secret-value\n", { mode: 0o600 });
    seedHostState(h);
    const seeded = hostFiles(h);

    const { status, result, errors } = await revoke(h);

    expect(errors).toEqual([]);
    expect(status).toBe(0);
    expect(result).toBe("removed");
    expect(fs.readdirSync(secretsDir).sort()).toEqual(["other"]);
    expect(fs.readFileSync(path.join(secretsDir, "other"), "utf8")).toBe("other-secret-value\n");
    expect(readJson(h.tokenConfigPath)).toEqual({});
    expectOtherEntriesKept(h, seeded);
    expect(dockerLog(h).some((call) => call.startsWith("exec") && call.includes("rm -f"))).toBe(true);
  });

  test("V5: a failed proxy removal leaves every host-side file unchanged", async () => {
    const h = harness({ docker: failingRemovalDocker });
    seedHostState(h);
    const before = hostFiles(h);
    captureOutput();

    // The removal error is not an AdminExit refusal: runAdminAction rethrows it.
    await expect(runAdminAction(h.state, () => {
      revokeDesiredCredentialState("github");
    })).rejects.toThrow("boom");
    expect(hostFiles(h)).toEqual(before);
  });

  test("V5: the CLI top level prints the failed proxy removal and exits 1", async () => {
    const h = harness({ docker: failingRemovalDocker });
    seedHostState(h);
    const before = hostFiles(h);
    const lines: string[] = [];
    setOutputWriterForTest((line) => lines.push(line));

    // `main` is the process boundary every `runfree` command returns through.
    await main(() => runAdminAction(h.state, () => {
      revokeDesiredCredentialState("github");
    }), []);

    expect(process.exitCode).toBe(1);
    expect(lines.map((line) => line.replace(/^\S+ /, ""))).toEqual([
      "runfree error: Error: boom\n  run the command again with --verbose to print the stack trace",
    ]);
    expect(hostFiles(h)).toEqual(before);
  });

  test("V6: an invalid name refuses without touching tokens or Docker", async () => {
    const h = harness({ docker: "" });
    const before = hostFiles(h);

    const { status, errors } = await revoke(h, "Bad Name");

    expect(status).toBe(1);
    expect(errorLines(errors)).toEqual(["invalid credential name: Bad Name (must match ^[a-z][a-z0-9_-]{0,63}$)"]);
    expect(hostFiles(h)).toEqual(before);
    expect(dockerLog(h)).toEqual([]);
  });

  test("V6: a reserved user-service name refuses without touching tokens or Docker", async () => {
    const h = harness({ docker: "", tokens: { github: { source: "env", env: "GH_X" }, "user-github": { source: "env", env: "GH_U", runfreeUserServiceOwner: "user-github" } } });
    const before = hostFiles(h);

    const { status, errors } = await revoke(h, "user-github");

    expect(status).toBe(1);
    expect(errorLines(errors)).toEqual([
      "runfree credential remove cannot mutate reserved user-service token user-github; use runfree service enable user-github or runfree service disable user-github",
    ]);
    expect(hostFiles(h)).toEqual(before);
    expect(dockerLog(h)).toEqual([]);
  });

  test("V6: a credential owned by a curated service refuses without touching tokens or Docker", async () => {
    const h = harness({ docker: "" });
    fs.writeFileSync(path.join(h.projectRoot, ".runfree", "runfree.json"), `${JSON.stringify({ services: { github: { revision: 1 } } }, null, 2)}\n`);
    const before = hostFiles(h);

    const { status, errors } = await revoke(h);

    expect(status).toBe(1);
    expect(errorLines(errors)).toEqual([
      "github is owned by service github",
      "change or remove it with:",
      "runfree service disable github",
    ]);
    expect(hostFiles(h)).toEqual(before);
    expect(dockerLog(h)).toEqual([]);
  });
});

describe("bindDesiredCredentialSource", () => {
  test("B1: no source, or the none source, binds nothing", async () => {
    const h = harness({ tokens: {} });
    const before = hostFiles(h);

    expect(await bind(h, addInput())).toMatchObject({ status: 0, result: false });
    expect(await bind(h, addInput({ tokenSource: { kind: "none" } }))).toMatchObject({ status: 0, result: false });
    expect(hostFiles(h)).toEqual(before);
  });

  test("B2: an env source is saved with mode 0600 and a repeat is unchanged", async () => {
    const h = harness({ tokens: {}, env: { GH_Y: "value-not-stored" } });
    const input = addInput({ tokenSource: { kind: "env", env: "GH_Y" } });

    expect(await bind(h, input)).toMatchObject({ status: 0, result: true });
    expect(readJson(h.tokenConfigPath).github).toMatchObject({ source: "env", env: "GH_Y" });
    expect(fs.readFileSync(h.tokenConfigPath, "utf8")).not.toContain("value-not-stored");
    expect(fs.statSync(h.tokenConfigPath).mode & 0o777).toBe(0o600);

    const before = hostFiles(h);
    expect(await bind(h, input)).toMatchObject({ status: 0, result: false });
    expect(hostFiles(h)).toEqual(before);
  });

  test("B3: an unset env variable refuses before any write", async () => {
    const h = harness({ tokens: {} });
    const before = hostFiles(h);

    const { status, errors } = await bind(h, addInput({ tokenSource: { kind: "env", env: "GH_Y" } }));

    expect(status).toBe(1);
    expect(errorLines(errors)).toEqual(["GH_Y is unset or empty"]);
    expect(hostFiles(h)).toEqual(before);
  });

  test("B4: a different existing binding refuses without replaceSource", async () => {
    const h = harness({ env: { GH_Y: "value" } });
    const before = hostFiles(h);

    const { status, errors } = await bind(h, addInput({ tokenSource: { kind: "env", env: "GH_Y" } }));

    expect(status).toBe(1);
    expect(errorLines(errors)).toEqual(["github credential source is already env GH_X; pass --replace-source to change it"]);
    expect(hostFiles(h)).toEqual(before);
  });

  test("B4: replaceSource replaces the binding and stores the refresh interval", async () => {
    const h = harness({ env: { GH_Y: "value" } });

    const { status, result } = await bind(h, addInput({ tokenSource: { kind: "env", env: "GH_Y" }, replaceSource: true, refreshEvery: "1h" }));

    expect(status).toBe(0);
    expect(result).toBe(true);
    expect(readJson(h.tokenConfigPath).github).toMatchObject({ source: "env", env: "GH_Y", refreshEverySeconds: 3600 });
  });

  test("B5: invalid and reserved names refuse before any write", async () => {
    const h = harness({ docker: "", env: { GH_Y: "value" } });
    const before = hostFiles(h);
    const source = { kind: "env", env: "GH_Y" } as const;

    const bad = await bind(h, addInput({ name: "Bad Name", tokenSource: source }));
    expect(bad.status).toBe(1);
    expect(errorLines(bad.errors)).toEqual(["invalid credential name: Bad Name (must match ^[a-z][a-z0-9_-]{0,63}$)"]);
    consoleErrorSpy?.mockRestore();
    consoleLogSpy?.mockRestore();

    const reserved = await bind(h, addInput({ name: "user-github", tokenSource: source }));
    expect(reserved.status).toBe(1);
    expect(errorLines(reserved.errors)).toEqual([
      "runfree credential add cannot mutate reserved user-service token user-github; use runfree service enable user-github or runfree service disable user-github",
    ]);
    expect(hostFiles(h)).toEqual(before);
    expect(dockerLog(h)).toEqual([]);
  });
});

describe("credentialClearSourceIntent", () => {
  test("L1: an unknown name lists the known credentials", async () => {
    const h = harness();
    const before = hostFiles(h);
    const { errors } = captureOutput();

    const status = await runAdminAction(h.state, () => credentialClearSourceIntent({ name: "nope" }));

    expect(status).toBe(1);
    expect(errorLines(errors)).toEqual(["unknown credential: nope (known: github)"]);
    expect(hostFiles(h)).toEqual(before);
  });

  test("L2: Docker unavailable refuses and keeps the binding", async () => {
    const h = harness();
    const before = hostFiles(h);
    const { errors } = captureOutput();

    const status = await runAdminAction(h.state, () => credentialClearSourceIntent({ name: "github" }));

    expect(status).toBe(1);
    expect(errorLines(errors)).toEqual([
      "github source was not cleared: cannot verify credential revocation while proxy state is docker-unavailable",
      ...REVOCATION_REFUSAL_TAIL,
    ]);
    expect(hostFiles(h)).toEqual(before);
  });
});
