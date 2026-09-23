import fs from "node:fs";
import path from "node:path";

import { describe, expect, test } from "vitest";

import { renderRuntimeCompose } from "./compose.ts";

const BASE_COMPOSE = fs.readFileSync(path.resolve("packages/agent-runtime/agent/compose.yaml"), "utf8");

describe("per-session compose shape", () => {
  test("the embedded template ships proxy + networks only: no agent service, no legacy proxy env", () => {
    // No shared agent service and none of its render markers.
    expect(BASE_COMPOSE).not.toContain("  agent:");
    expect(BASE_COMPOSE).not.toContain("# RUNFREE_AGENT_ENV");
    expect(BASE_COMPOSE).not.toContain("# RUNFREE_PROJECT_MOUNTS_BEGIN");
    expect(BASE_COMPOSE).not.toContain("io.runfree.container-role: agent");
    // No fixed-agent firewall IP and no legacy request-only principal reach the
    // proxy: agents are admitted per session by source IP.
    expect(BASE_COMPOSE).not.toContain("RUNFREE_AGENT_IP:");
    expect(BASE_COMPOSE).not.toContain("RUNFREE_LEGACY_AGENT_SOURCE_IP:");
    // The fixed control plane and the internal network remain.
    expect(BASE_COMPOSE).toContain("services:\n  proxy:");
    expect(BASE_COMPOSE).toContain("  agent_internal:\n    internal: true");
    expect(BASE_COMPOSE).toContain("  proxy_egress:");
  });

  test("renderRuntimeCompose renders the proxy-only template as-is", () => {
    const rendered = renderRuntimeCompose(BASE_COMPOSE, {});

    expect(rendered).toContain("  proxy:\n    image: ${RUNFREE_PROXY_IMAGE:?RUNFREE_PROXY_IMAGE is required}");
    expect(rendered).not.toContain("  proxy:\n    build:");
    // No agent service and no Compose MCP callback relay sidecar post-cutover.
    expect(rendered).not.toContain("  agent:");
    expect(rendered).not.toContain("  mcp_callback:");
    // Session-only firewall: the proxy carries no fixed agent IP env.
    expect(rendered).not.toContain("RUNFREE_AGENT_IP:");
    expect(rendered).not.toContain("RUNFREE_LEGACY_AGENT_SOURCE_IP:");
  });

  test("mounts only the paired effective proxy generation root", () => {
    const rendered = renderRuntimeCompose(BASE_COMPOSE, {});

    expect(rendered).toContain([
      "      - type: bind",
      "        source: ${RUNFREE_EFFECTIVE_PROXY_DIR:?RUNFREE_EFFECTIVE_PROXY_DIR is required}",
      "        target: /app/runfree-effective",
      "        read_only: true",
    ].join("\n"));
    expect(rendered).toContain("      RUNFREE_EFFECTIVE_PROXY_ROOT: /app/runfree-effective");
  });

  test("renders top-level named volumes", () => {
    const rendered = renderRuntimeCompose(BASE_COMPOSE, { namedVolumes: ["runfree-node-modules"] });

    expect(rendered).toContain([
      "volumes:",
      "  runfree-commandhistory:",
      "  runfree-oauth-state:",
      "  runfree-node-modules:",
      "",
      "networks:",
    ].join("\n"));
  });

  test("rejects duplicate mount targets before rendering", () => {
    expect(() => renderRuntimeCompose(BASE_COMPOSE, {
      agentVolumes: [
        { type: "volume", source: "deps-one", target: "/workspace/node_modules" },
        { type: "volume", source: "deps-two", target: "/workspace/node_modules" },
      ],
    })).toThrow("duplicate runtime compose mount target: /workspace/node_modules");
  });

  test("rejects an invalid named volume", () => {
    expect(() => renderRuntimeCompose(BASE_COMPOSE, {
      namedVolumes: ["../bad"],
    })).toThrow("invalid runtime compose volume name");
  });

  test("fails closed when the top-level volumes block is missing", () => {
    expect(() => renderRuntimeCompose(BASE_COMPOSE.replace("volumes:\n  runfree-commandhistory:\n  runfree-oauth-state:\n\n", ""), {
      namedVolumes: ["deps"],
    })).toThrow("embedded runtime compose.yaml no longer has the expected top-level volumes block");
  });
});

describe("proxy environment injection", () => {
  test("with no entries the output is byte-identical to the template", () => {
    expect(renderRuntimeCompose(BASE_COMPOSE, {})).toBe(BASE_COMPOSE);
  });

  test("one entry adds exactly one line inside the proxy environment block, nothing else changed", () => {
    const rendered = renderRuntimeCompose(BASE_COMPOSE, {
      proxyEnvironment: { RUNFREE_SESSION_ADMISSION_SOURCE: "files" },
    });

    expect(rendered).toContain([
      "      CA_CERT: /ca/public/proxy-ca.crt",
      "      CA_KEY: /ca/private/proxy-ca.key",
      "      RUNFREE_SESSION_ADMISSION_SOURCE: files",
      "",
      "volumes:",
    ].join("\n"));
    // Exactly one line added: removing it round-trips to the original bytes.
    const withoutAddedLine = rendered.replace("      RUNFREE_SESSION_ADMISSION_SOURCE: files\n", "");
    expect(withoutAddedLine).toBe(BASE_COMPOSE);
  });

  test("multiple entries are inserted sorted by key", () => {
    const rendered = renderRuntimeCompose(BASE_COMPOSE, {
      proxyEnvironment: { RUNFREE_ZETA_TEST: "z", RUNFREE_ALPHA_TEST: "a" },
    });

    expect(rendered).toContain([
      "      CA_KEY: /ca/private/proxy-ca.key",
      "      RUNFREE_ALPHA_TEST: a",
      "      RUNFREE_ZETA_TEST: z",
      "",
      "volumes:",
    ].join("\n"));
  });

  test("refuses a key the template already defines", () => {
    expect(() => renderRuntimeCompose(BASE_COMPOSE, {
      proxyEnvironment: { CA_CERT: "/ca/public/proxy-ca.crt" },
    })).toThrow("runtime compose proxy environment already defines CA_CERT");
  });

  test("refuses an invalid environment name before any output", () => {
    expect(() => renderRuntimeCompose(BASE_COMPOSE, {
      proxyEnvironment: { "1BAD": "value" },
    })).toThrow("invalid runtime compose environment name");
  });

  test("refuses a value that would need quoting before any output", () => {
    expect(() => renderRuntimeCompose(BASE_COMPOSE, {
      proxyEnvironment: { RUNFREE_SESSION_ADMISSION_SOURCE: "needs quoting; here" },
    })).toThrow("invalid runtime compose environment value");
  });

  test("fails closed when the proxy environment block cannot be found", () => {
    expect(() => renderRuntimeCompose(BASE_COMPOSE.replace("    environment:\n", ""), {
      proxyEnvironment: { RUNFREE_SESSION_ADMISSION_SOURCE: "files" },
    })).toThrow("embedded runtime compose.yaml no longer has the expected proxy environment block");
  });
});
