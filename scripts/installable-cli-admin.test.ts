import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { projectInfo } from "../packages/cli/src/config.ts";
import { projectHash } from "../packages/cli/src/project-identity.ts";
import { writeUserServiceDefinition } from "../packages/cli/src/user-services.ts";
import { readActiveControlSelection, readActiveEffectiveControl } from "../packages/cli/src/control/effective.ts";
import {
  runCli,
  runCliInProject,
  runTsCli,
  selectCurrentDesiredControlsForTsCliProject,
  tmp,
  tsCliEnv,
} from "./installable-cli.test-harness.ts";

describe("installable runfree CLI: admin policy", () => {
  function parameterService(revision: number, envVar: string): void {
    writeUserServiceDefinition(tmp, tsCliEnv(), {
      schemaVersion: 1,
      id: "user-parameter-review",
      label: "Parameter review",
      revision,
      hosts: [{ host: "parameters.example.com" }],
      explanations: ["Test service parameter replacement."],
      parameters: [{ key: "account", envVar, description: "Account identifier" }],
    }, { replace: revision > 1 });
  }

  test.each(["enable", "diff"])("service %s replaces obsolete recorded parameters", (operation) => {
    expect(runCli(["init"]).status).toBe(0);
    parameterService(1, "REVIEW_OLD_ACCOUNT");
    const enabled = runCli(["service", "enable", "user-parameter-review", "--param", "account=old", "--no-reload"]);
    expect(enabled.status, enabled.stderr).toBe(0);
    selectCurrentDesiredControlsForTsCliProject();
    parameterService(2, "REVIEW_NEW_ACCOUNT");
    const args = operation === "enable"
      ? ["service", "enable", "user-parameter-review", "--param", "account=new", "--no-reload"]
      : ["service", "diff", "--apply", "--no-reload"];
    const updated = runTsCli(args, { REVIEW_NEW_ACCOUNT: "new" });
    expect(updated.status, updated.stderr).toBe(0);
    const env = fs.readFileSync(projectInfo(tmp, tsCliEnv()).paths.controlAgentEnvPath, "utf8");
    expect(env).toContain("REVIEW_NEW_ACCOUNT=new");
    expect(env).not.toContain("REVIEW_OLD_ACCOUNT");
    // Exercise effective publication, which rejects obsolete recorded names.
    const activated = runCli(["host", "add", "activation.example.com", "--read-only"]);
    expect(activated.status, activated.stderr).toBe(0);
  });

  test("catalog updates preserve a valid saved parameter despite the host environment", () => {
    expect(runCli(["init"]).status).toBe(0);
    parameterService(1, "REVIEW_ACCOUNT");
    expect(runCli(["service", "enable", "user-parameter-review", "--param", "account=saved", "--no-reload"]).status).toBe(0);
    selectCurrentDesiredControlsForTsCliProject();
    parameterService(2, "REVIEW_ACCOUNT");
    const updated = runTsCli(["service", "diff", "--apply", "--no-reload"], { REVIEW_ACCOUNT: "ambient" });
    expect(updated.status, updated.stderr).toBe(0);
    expect(fs.readFileSync(projectInfo(tmp, tsCliEnv()).paths.controlAgentEnvPath, "utf8")).toContain("REVIEW_ACCOUNT=saved");
  });

  test.each([false, true])("service diff refuses missing new parameters before changing approved policy (local: %s)", (local) => {
    expect(runCli(["init"]).status).toBe(0);
    parameterService(1, "REVIEW_OLD_ACCOUNT");
    expect(runCli(["service", "enable", "user-parameter-review", "--param", "account=old", "--no-reload", ...(local ? ["--local"] : [])]).status).toBe(0);
    selectCurrentDesiredControlsForTsCliProject();
    parameterService(2, "REVIEW_NEW_ACCOUNT");
    const policyPath = path.join(tmp, local ? ".runfree/network-policy.local.json" : ".runfree/network-policy.json");
    const before = fs.readFileSync(policyPath, "utf8");
    const updated = runCli(["service", "diff", "--apply", "--no-reload"]);
    expect(updated.status).toBe(1);
    expect(updated.stderr).toContain("REVIEW_NEW_ACCOUNT=<value> runfree service diff --apply");
    expect(updated.stderr).not.toContain("runfree service enable");
    expect(fs.readFileSync(policyPath, "utf8")).toBe(before);
  });

  test("service enable refuses policy drift before writing host credential or parameter state", () => {
    expect(runCli(["init"]).status).toBe(0);
    const policyPath = path.join(tmp, ".runfree/network-policy.json");
    const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    policy.hosts.push("unapproved.example.com");
    fs.writeFileSync(policyPath, JSON.stringify(policy));
    const paths = projectInfo(tmp, tsCliEnv()).paths;
    const result = runTsCli([
      "service", "enable", "apple-ads", "--from-env", "APPLE_REVIEW_SEED",
      "--param", "client-id=SEARCHADS.12345678-1234-1234-1234-123456789012", "--no-reload",
    ], { APPLE_REVIEW_SEED: "test-seed" });
    expect(result.status).toBe(1);
    expect(fs.existsSync(paths.controlAgentEnvPath)).toBe(false);
    expect(fs.existsSync(paths.tokenConfigPath)).toBe(false);
  });

  test("honors project runtime network overrides", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree/runfree.json"), `${JSON.stringify({
      version: 1,
      runtime: {
        subnet: "172.31.0.0/24",
        proxyIp: "172.31.0.10",
        agentIp: "172.31.0.11",
      },
    }, null, 2)}\n`);

    const result = runCliInProject(["init"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("runtime subnet: 172.31.0.0/24");
    expect(result.stdout).toContain("runtime proxy ip: 172.31.0.10");
    expect(result.stdout).toContain("runtime agent ip: 172.31.0.11");
  });

  test("rejects invalid runtime network overrides", () => {
    fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree/runfree.json"), `${JSON.stringify({
      version: 1,
      runtime: {
        proxyIp: "",
      },
    }, null, 2)}\n`);

    const result = runCliInProject(["init"]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("runtime.proxyIp must be a non-empty string");
  });

  test("migrated admin commands accept literal --no-* flags (boolean-negation off)", () => {
    const init = runCliInProject(["init"]);
    expect(init.status, init.stderr).toBe(0);

    // Each --no-* flag must parse as its own option, not as a negation, so these
    // documented flags survive strict yargs parsing and reach enforcement.
    const reload = runCliInProject(["host", "add", "no-neg.example", "--no-reload"]);
    expect(reload.status, reload.stderr).toBe(0);
    expect(reload.stderr).not.toContain("Unknown argument");

    const addReload = runCliInProject(["host", "add", "no-neg2.example", "--read-only", "--no-reload"]);
    expect(addReload.status, addReload.stderr).toBe(0);
    expect(addReload.stderr).not.toContain("Unknown argument");
    selectCurrentDesiredControlsForTsCliProject();

    // --no-reload must actually suppress effective-control activation (not just
    // be accepted). Without it the typed host path selects a new generation;
    // with it, the active generation remains unchanged.
    const withReload = runCliInProject(["host", "add", "reload-on.example", "--read-only"]);
    const reloadMarker = `${withReload.stdout}${withReload.stderr}`;
    expect(reloadMarker).toContain("effective policy: saved; applies when the runtime starts (effective policy generation sha256:");
    const suppressed = runCliInProject(["host", "add", "reload-off.example", "--read-only", "--no-reload"]);
    expect(`${suppressed.stdout}${suppressed.stderr}`).toContain("effective policy: unchanged (--no-reload)");

    // These reach legacy validation (not a yargs "Unknown argument" rejection),
    // proving --no-sync / --no-cache-source-secrets parsed as literal options.
    for (const args of [
      ["token", "set", "github", "--from-env", "RUNFREE_MISSING_ENV", "--no-sync"],
      ["token", "sync", "--no-cache-source-secrets"],
      ["service", "disable", "github", "--no-reload"],
    ]) {
      const result = runCliInProject(args);
      expect(result.stderr, `for: ${args.join(" ")}`).not.toContain("Unknown argument");
    }
  });

  test("service disable prunes the parameter and seed names it recorded in the host-owned agent env", () => {
    const init = runCli(["init"]);
    expect(init.status, init.stderr).toBe(0);
    const clientId = "SEARCHADS.12345678-1234-1234-1234-123456789012";
    const agentEnvPath = projectInfo(tmp, tsCliEnv()).paths.controlAgentEnvPath;

    // A missing parameter refuses before anything is recorded.
    const refused = runTsCli(["service", "enable", "apple-ads", "--from-env", "APPLE_SEED", "--no-reload"], { APPLE_SEED: "seed-jwt" });
    expect(refused.status).toBe(1);
    expect(refused.stderr).toContain("apple-ads needs 1 parameter before it can be enabled");
    expect(refused.stderr).toContain("--param client-id=<value>");
    expect(fs.existsSync(agentEnvPath)).toBe(false);

    const enabled = runTsCli(
      ["service", "enable", "apple-ads", "--from-env", "APPLE_SEED", "--param", `client-id=${clientId}`, "--no-reload"],
      { APPLE_SEED: "seed-jwt" },
    );
    expect(enabled.status, enabled.stderr).toBe(0);
    const recorded = fs.readFileSync(agentEnvPath, "utf8");
    expect(recorded).toContain(`APPLE_ADS_CLIENT_ID=${clientId}`);
    expect(recorded).toMatch(/APPLE_ADS_CLIENT_SECRET=runfree_oauth_secret_/);
    expect(recorded).not.toContain("seed-jwt");

    const project = projectInfo(tmp, tsCliEnv());
    const policyBefore = fs.readFileSync(project.paths.policyPath, "utf8");
    const lockPath = path.join(project.paths.stateDir, `token-store-sync-${projectHash(tmp)}.lock`);
    fs.mkdirSync(lockPath);
    fs.writeFileSync(path.join(lockPath, "pid"), String(process.pid));
    try {
      const refused = runCli(["service", "disable", "apple-ads", "--no-reload"]);
      expect(refused.status).toBe(1);
      expect(refused.stderr).toContain("token store lock");
      expect(fs.readFileSync(project.paths.policyPath, "utf8")).toBe(policyBefore);
      expect(fs.readFileSync(agentEnvPath, "utf8")).toBe(recorded);
    } finally {
      fs.rmSync(lockPath, { recursive: true });
    }
    const disabled = runCli(["service", "disable", "apple-ads", "--no-reload"]);
    expect(disabled.status, disabled.stderr).toBe(0);
    expect(disabled.stdout).toContain("host-owned agent env: removed APPLE_ADS_CLIENT_ID, APPLE_ADS_CLIENT_SECRET");
    expect(fs.readFileSync(agentEnvPath, "utf8")).not.toContain("APPLE_ADS");
  });

  test("a policy mutation before the first start is saved once, reports it, exits 0, and is consumed at start", () => {
    // Pre-`up` there is no approved control set, so activation cannot compile
    // a generation. The desired write is already durable at that point: the
    // command must say "saved; applies when the runtime starts" and exit 0
    // instead of crashing after printing success lines.
    const init = runCliInProject(["init"]);
    expect(init.status, init.stderr).toBe(0);
    const policyPath = path.join(tmp, ".runfree/network-policy.json");

    const add = runCliInProject(["host", "add", "saved.example"]);
    expect(add.status, add.stderr).toBe(0);
    expect(add.stderr).not.toMatch(/^\s+at /m);
    expect(add.stderr).not.toContain("approvals are required");
    expect(add.stdout).toContain("saved.example updated");
    expect(add.stdout).toContain("effective policy: saved; applies when the runtime starts");
    expect(add.stdout).not.toContain("effective policy: pending");
    expect(fs.existsSync(path.join(tmp, ".runfree/generated/proxy-policy.md"))).toBe(false);

    // Durable state: written exactly once, and the failed activation attempt
    // left no active selection behind.
    const written = fs.readFileSync(policyPath, "utf8");
    expect(written).toContain("saved.example");
    const project = projectInfo(tmp, tsCliEnv());
    expect(readActiveControlSelection(project)).toBeUndefined();

    // A second identical mutation is a no-op on the file.
    const again = runCliInProject(["host", "add", "saved.example"]);
    expect(again.status, again.stderr).toBe(0);
    expect(again.stdout).toContain("saved.example unchanged");
    expect(fs.readFileSync(policyPath, "utf8")).toBe(written);

    // Consumed at start: approving and publishing the desired controls (what
    // `runfree up` does) yields a generation whose policy allows the host.
    selectCurrentDesiredControlsForTsCliProject();
    const active = readActiveEffectiveControl(projectInfo(tmp, tsCliEnv()));
    expect(active?.policy.hosts).toContain("saved.example");
  });

  test("admin reads after init refuse without a stack trace and name a runnable next command", () => {
    // The post-init "dead zone": desired policy exists, no effective policy
    // generation is selected. Every read must refuse as a typed CliError
    // (no stack frames) and name the command that closes the gap.
    const init = runCliInProject(["init"]);
    expect(init.status, init.stderr).toBe(0);

    for (const args of [
      ["host", "list"],
      ["host", "explain", "api.example.com"],
      ["service", "list"],
      ["credential", "status"],
      ["runtime", "reload-policy"],
    ]) {
      const result = runCliInProject(args);
      expect(result.status, `${args.join(" ")}\n${result.stderr}`).toBe(1);
      expect(result.stderr, args.join(" ")).not.toMatch(/^\s+at /m);
      expect(result.stderr, args.join(" ")).toContain("runfree up");
      expect(result.stderr, args.join(" ")).toContain("runfree policy status");
      expect(result.stdout, args.join(" ")).toBe("");
    }

    // `doctor` is a diagnosis, not a mutation: it reports the dead zone as a
    // finding with the same next command instead of refusing.
    const doctor = runCliInProject(["doctor"]);
    expect(doctor.stderr, doctor.stderr).not.toMatch(/^\s+at /m);
    expect(`${doctor.stdout}${doctor.stderr}`).toContain("runfree up");

    // A pre-start mutation is saved, says so, and exits 0.
    const add = runCliInProject(["host", "add", "dead-zone.example"]);
    expect(add.status, add.stderr).toBe(0);
    expect(add.stderr).not.toMatch(/^\s+at /m);
    expect(add.stdout).toContain("effective policy: saved; applies when the runtime starts");
  });

});
