import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { flushWarnings, setOutputWriterForTest } from "../warnings.ts";
import { mcpApprovalPath, prepareMcpRuntime } from "./mcp.ts";

// R16 and the wedge rule: a share group whose owner cannot be stored must not
// fail every launch. The projection still publishes a policy, the group's
// login fails closed (no member carries or captures its endpoints, which are
// blocked), and a writable file settles it on the next projection.
describe("share group owner store failures", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let stateDir: string;
  let enabledDir: string;
  let output: string[];

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-share-store-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    stateDir = path.join(tmp, "state");
    enabledDir = path.join(tmp, "enabled");
    for (const dir of [projectRoot, path.join(hostHome, ".codex"), stateDir, enabledDir]) fs.mkdirSync(dir, { recursive: true });
    const url = "https://mcp.shared.example/mcp";
    fs.writeFileSync(path.join(hostHome, ".claude.json"), JSON.stringify({
      mcpServers: { shared: { type: "http", url, oauth: { tokenEndpoint: "https://auth.shared.example/token" } } },
    }));
    fs.writeFileSync(path.join(hostHome, ".codex", "config.toml"), [
      "[mcp_servers.shared]",
      `url = "${url}"`,
      'oauth = { tokenEndpoint = "https://auth.shared.example/token" }',
      "",
    ].join("\n"));
    flushWarnings();
    output = [];
    setOutputWriterForTest((line) => output.push(line));
  });

  afterEach(() => {
    fs.chmodSync(enabledDir, 0o700);
    flushWarnings();
    setOutputWriterForTest(undefined);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  type Policy = {
    blockedEndpoints?: Array<{ host: string; path: string }>;
    providers: Record<string, { captureOwner?: false; tokenEndpoints?: unknown[] }>;
  };

  function prepare(): Policy {
    const runDir = path.join(tmp, "run");
    prepareMcpRuntime({
      approvalPath: mcpApprovalPath(stateDir),
      callbackPort: 47638,
      claudeConfigPath: path.join(runDir, "claude.json"),
      claudeMcpConfigPath: path.join(runDir, "claude-mcp.json"),
      codexDir: path.join(runDir, "codex"),
      env: { HOME: hostHome, CODEX_HOME: path.join(hostHome, ".codex") },
      mcpEnabledPath: path.join(enabledDir, "mcp-enabled.json"),
      mcpOAuthEpochsPath: path.join(stateDir, "mcp-oauth-epochs.json"),
      mcpOAuthPolicyPath: path.join(runDir, "mcp-oauth-policy.json"),
      mcpOperationPolicyPath: path.join(runDir, "mcp-operation-policy.json"),
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });
    return JSON.parse(fs.readFileSync(path.join(runDir, "mcp-oauth-policy.json"), "utf8")) as Policy;
  }

  function warnings(): string {
    flushWarnings();
    const text = output.join("\n");
    output = [];
    return text;
  }

  test("an unwritable owner store blocks the unsettled group's login instead of failing the launch, and a writable store reclaims it", () => {
    fs.chmodSync(enabledDir, 0o500);
    const refused = prepare();
    expect(warnings()).toContain("Runfree could not store which agent holds its shared OAuth login");
    expect(refused.providers["mcp:claude-shared"]).toMatchObject({ captureOwner: false });
    expect(refused.providers["mcp:codex-shared"]).toMatchObject({ captureOwner: false });
    expect(refused.providers["mcp:claude-shared"]?.tokenEndpoints).toBeUndefined();
    expect(refused.providers["mcp:codex-shared"]?.tokenEndpoints).toBeUndefined();
    expect(refused.blockedEndpoints).toEqual([{ host: "auth.shared.example", path: "/token" }]);

    fs.chmodSync(enabledDir, 0o700);
    const settled = prepare();
    expect(warnings()).not.toContain("could not store");
    const owners = Object.values(settled.providers).filter((provider) => provider.captureOwner !== false);
    expect(owners).toHaveLength(1);
    expect(owners[0]?.tokenEndpoints).toEqual([{ host: "auth.shared.example", path: "/token" }]);
    expect(settled.blockedEndpoints).toBeUndefined();

    // Once settled, an unwritable store changes nothing: there is nothing to write.
    fs.chmodSync(enabledDir, 0o500);
    expect(prepare().blockedEndpoints).toBeUndefined();
    expect(warnings()).not.toContain("could not store");
  });
});
