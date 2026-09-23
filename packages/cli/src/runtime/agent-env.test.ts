import { describe, expect, test } from "vitest";

import { composeAgentEnvironment } from "../agents.ts";
import { RUNFREE_PLACEHOLDER_VALUE } from "../../../../scripts/services.ts";
import {
  BASE_AGENT_ENVIRONMENT,
  DEFAULT_AGENT_PLACEHOLDER_ENVIRONMENT,
  assertServiceAgentEnvNamesAreSafe,
  completeAgentEnvironment,
  projectAgentEnvironmentOverrides,
  runtimeOwnedAgentEnvNames,
} from "./agent-env.ts";

describe("agent environment ownership", () => {
  test("builds the full agent environment from base, defaults, and caller-provided env", () => {
    expect(BASE_AGENT_ENVIRONMENT).toMatchObject({
      SHELL: "/usr/bin/zsh",
      RUNFREE_CONTAINER: "1",
      RUNFREE_INBOX_CONTAINER_DIR: "/runfree/inbox",
      RUNFREE_PROJECT_NAME: "${RUNFREE_PROJECT_NAME:-project}",
      HTTPS_PROXY: "http://${RUNFREE_PROXY_IP:-172.30.0.10}:8080",
      NODE_EXTRA_CA_CERTS: "/etc/proxy-ca/proxy-ca.crt",
      NODE_USE_ENV_PROXY: "1",
    });
    // The session entry's wait bound is host-rendered and pinned (design D4).
    // It must exceed the worst-case activation budget: registration and
    // activation acknowledgement waits plus the running-proof maximum, so an
    // entry never gives up on a session the host could still have activated.
    expect(Number(BASE_AGENT_ENVIRONMENT.RUNFREE_SESSION_ENTRY_TIMEOUT_MS)).toBeGreaterThan(5_000 + 5_000 + 30_000);
    expect(DEFAULT_AGENT_PLACEHOLDER_ENVIRONMENT).toEqual({
      GH_TOKEN: RUNFREE_PLACEHOLDER_VALUE,
      GITHUB_TOKEN: RUNFREE_PLACEHOLDER_VALUE,
    });
    expect(completeAgentEnvironment({
      ...composeAgentEnvironment(),
      GH_TOKEN: "caller-secret",
      NPM_CONFIG_STORE_DIR: "/home/agent/.local/share/pnpm/store",
      RUNFREE_PROJECT_NAME: "payments-api",
    })).toMatchObject({
      ...BASE_AGENT_ENVIRONMENT,
      ...composeAgentEnvironment(),
      NPM_CONFIG_STORE_DIR: "/home/agent/.local/share/pnpm/store",
      RUNFREE_PROJECT_NAME: "payments-api",
      ...DEFAULT_AGENT_PLACEHOLDER_ENVIRONMENT,
    });
  });

  test("identifies runtime-owned env names that project agent.env must not override", () => {
    const names = runtimeOwnedAgentEnvNames();

    expect(names).toEqual(expect.arrayContaining([
      "HTTPS_PROXY",
      "RUNFREE_PROJECT_PHYSICAL_ROOT",
      "GH_TOKEN",
      "GITHUB_TOKEN",
      "NODE_USE_ENV_PROXY",
      "CODEX_HOME",
      "DISABLE_AUTOUPDATER",
      "NPM_CONFIG_STORE_DIR",
      "RUNFREE_AGENT_COMMAND",
      "RUNFREE_RESUME_COMMAND",
      "RUNFREE_RESUME_SESSION",
      "RUNFREE_INBOX_CONTAINER_DIR",
      "RUNFREE_INBOX_DIR",
      "RUNFREE_TERMINAL_TITLE",
      "RUNFREE_SESSION_ID",
      "RUNFREE_SESSION_ENTRY_TIMEOUT_MS",
      "HOME",
      "SHELL",
      "PIP_CACHE_DIR",
      "UV_CACHE_DIR",
      "POETRY_CACHE_DIR",
      "POETRY_VIRTUALENVS_IN_PROJECT",
      "PIPENV_CACHE_DIR",
      "PIPENV_VENV_IN_PROJECT",
      "PDM_CACHE_DIR",
      "PDM_USE_VENV",
      "HATCH_CACHE_DIR",
      "HATCH_DATA_DIR",
    ]));
  });

  test("rejects service credential env collisions except explicit default placeholders", () => {
    expect(() => assertServiceAgentEnvNamesAreSafe({
      github: { credential: { agentEnv: ["GH_TOKEN", "GITHUB_TOKEN"] } },
    })).not.toThrow();
    expect(() => assertServiceAgentEnvNamesAreSafe({
      bad: { credential: { agentEnv: ["HTTPS_PROXY"] } },
    })).toThrow("service bad agent env HTTPS_PROXY collides with runtime-owned agent env");
    expect(() => assertServiceAgentEnvNamesAreSafe({
      bad: { credential: { agentEnv: ["PIP_CACHE_DIR"] } },
    })).toThrow("service bad agent env PIP_CACHE_DIR collides with runtime-owned agent env");
    expect(() => assertServiceAgentEnvNamesAreSafe({
      bad: { parameters: [{ envVar: "HTTPS_PROXY" }] },
    })).toThrow("service bad parameter env HTTPS_PROXY collides with runtime-owned agent env");
    expect(() => assertServiceAgentEnvNamesAreSafe({
      ok: { parameters: [{ envVar: "ACME_REGION" }] },
    })).not.toThrow();
  });

  test("projects selected agent env without exposing raw credentials or runtime overrides", () => {
    const clientSecretHandle = `runfree_oauth_secret_${"a".repeat(32)}`;
    expect(projectAgentEnvironmentOverrides([
      "GITHUB_TOKEN=raw-secret",
      "HTTPS_PROXY=http://attacker.invalid:8080",
      "GIT_CONFIG_COUNT=1",
      "GIT_CONFIG_KEY_0=worktree.useRelativePaths",
      "GIT_CONFIG_VALUE_0=false",
      "DISABLE_AUTOUPDATER=0",
      "CUSTOM_SECRET=raw-custom-secret",
      "APPLE_ADS_CLIENT_ID=SEARCHADS.client-id",
      `APPLE_ADS_CLIENT_SECRET=${clientSecretHandle}`,
      "",
    ].join("\n"), "effective/agent.env")).toEqual({
      APPLE_ADS_CLIENT_ID: "SEARCHADS.client-id",
      APPLE_ADS_CLIENT_SECRET: clientSecretHandle,
      CUSTOM_SECRET: RUNFREE_PLACEHOLDER_VALUE,
      GITHUB_TOKEN: RUNFREE_PLACEHOLDER_VALUE,
    });
    expect(projectAgentEnvironmentOverrides(
      "APPLE_ADS_CLIENT_SECRET=not-a-handle\n",
      "effective/agent.env",
    )).toEqual({ APPLE_ADS_CLIENT_SECRET: RUNFREE_PLACEHOLDER_VALUE });
    // Parameters declared by approved user-defined services pass through by
    // name; anything else stays a placeholder and runtime-owned names are
    // dropped even when declared.
    expect(projectAgentEnvironmentOverrides(
      ["ACME_REGION=eu-1", "ACME_TOKEN=raw-acme-secret", "HTTPS_PROXY=http://attacker.invalid:8080", ""].join("\n"),
      "effective/agent.env",
      { declaredParameterEnvNames: ["ACME_REGION", "HTTPS_PROXY"] },
    )).toEqual({ ACME_REGION: "eu-1", ACME_TOKEN: RUNFREE_PLACEHOLDER_VALUE });
    expect(projectAgentEnvironmentOverrides("ACME_REGION=eu-1\n", "effective/agent.env"))
      .toEqual({ ACME_REGION: RUNFREE_PLACEHOLDER_VALUE });
  });

  test("rejects malformed, duplicate, and control-bearing agent env input", () => {
    expect(() => projectAgentEnvironmentOverrides("not-an-assignment\n", "effective/agent.env"))
      .toThrow("invalid agent env line");
    expect(() => projectAgentEnvironmentOverrides("CUSTOM=value\nCUSTOM=other\n", "effective/agent.env"))
      .toThrow("duplicate agent env name");
    expect(() => projectAgentEnvironmentOverrides("CUSTOM=value\u0000forged\n", "effective/agent.env"))
      .toThrow("invalid agent env value");
  });
});
