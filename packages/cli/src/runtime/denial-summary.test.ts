import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { buildSessionDenialSummary, printSessionDenialSummary } from "./denial-summary.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";
import type { PolicyJson } from "@runfree/runtime-contracts/network-policy";

const GENERATION = `sha256:${"a".repeat(64)}`;

const policy: PolicyJson = {
  hosts: ["api.github.com", "now-allowed.example.com"],
  tokens: {},
};

function denialLine(fields: Record<string, unknown>): string {
  return `proxy-denial: ${JSON.stringify({
    v: 1,
    ts: "2026-06-10T12:00:00.000Z",
    reason: "host-not-allowlisted",
    generation: GENERATION,
    ...fields,
  })}`;
}

describe("buildSessionDenialSummary", () => {
  test("returns no lines when there were no denials", () => {
    expect(buildSessionDenialSummary("proxy: listening on :8080", policy)).toEqual([]);
  });

  test("dedupes hosts with request counts and allow suggestions", () => {
    const logs = [
      denialLine({ host: "api.example.com" }),
      denialLine({ host: "api.example.com" }),
      denialLine({ host: "api.example.com", suppressed: 10 }),
      denialLine({ host: "cdn.example.net" }),
    ].join("\n");

    const lines = buildSessionDenialSummary(logs, policy);
    expect(lines[0]).toBe("Runfree blocked 2 hosts during this session:");
    expect(lines.at(-1)).toBe("Details: runfree doctor");
    const apiLine = lines.find((line) => line.includes("api.example.com"));
    expect(apiLine).toContain("(12 requests)");
    expect(apiLine).toContain("runfree host add api.example.com");
    const cdnLine = lines.find((line) => line.includes("cdn.example.net"));
    expect(cdnLine).toContain("(1 request)");
    expect(cdnLine).toContain("runfree host add cdn.example.net");
  });

  test("annotates hosts allowlisted mid-session instead of repeating the host add command", () => {
    const logs = denialLine({ host: "now-allowed.example.com" });
    const lines = buildSessionDenialSummary(logs, policy);
    const hostLine = lines.find((line) => line.includes("now-allowed.example.com"));
    expect(hostLine).toContain("now allowed; rerun the failed command");
    expect(hostLine).not.toContain("runfree host add now-allowed.example.com");
  });

  test("shape denials suggest the exact widening command instead of a redundant host add", () => {
    const ruledPolicy: PolicyJson = {
      hosts: ["api.github.com"],
      tokens: {},
      requests: { "api.github.com": { methods: ["GET", "HEAD"] } },
    };
    const logs = denialLine({
      reason: "method-not-allowed",
      host: "api.github.com",
      method: "POST",
      path: "/repos",
    });

    const lines = buildSessionDenialSummary(logs, ruledPolicy);
    const hostLine = lines.find((line) => line.includes("api.github.com"));
    expect(hostLine).toContain("runfree host rules api.github.com --method GET --method HEAD --method POST");
    expect(hostLine).not.toContain("now allowed; rerun the failed command");
  });

  test("service member hosts get a secondary, clearly-labeled service line after the primary host add command", () => {
    const logs = [
      denialLine({ host: "registry.npmjs.org" }),
      denialLine({ host: "cdn.example.net" }),
    ].join("\n");

    const lines = buildSessionDenialSummary(logs, policy);
    const primaryIndex = lines.findIndex((line) => line.includes("runfree host add registry.npmjs.org"));
    expect(primaryIndex).toBeGreaterThan(0);
    expect(lines[primaryIndex + 1]).toContain('registry.npmjs.org is part of service "node" (2 hosts).');
    expect(lines[primaryIndex + 2]).toContain("runfree service enable node");
    expect(lines[primaryIndex + 2]).toContain("never applied automatically");
    expect(lines.filter((line) => line.includes("is part of service"))).toHaveLength(1);
  });

  test("adds MCP OAuth context below discovered issuer host denials", () => {
    const lines = buildSessionDenialSummary(denialLine({
      host: "oauth.posthog.com",
      mcpOAuthIssuer: {
        serverName: "posthog",
        resourceHost: "mcp.posthog.com",
      },
    }), policy);

    const primaryIndex = lines.findIndex((line) => line.includes("runfree host add oauth.posthog.com"));
    expect(primaryIndex).toBeGreaterThan(0);
    expect(lines[primaryIndex + 1]).toContain("OAuth issuer for MCP server posthog");
    expect(lines[primaryIndex + 1]).toContain("mcp.posthog.com");
  });

  test("service lines inline the broad-host warning when the service has broad hosts", () => {
    const lines = buildSessionDenialSummary(denialLine({ host: "objects.githubusercontent.com" }), policy).join("\n");
    expect(lines).toContain("runfree host add objects.githubusercontent.com");
    expect(lines).toContain('objects.githubusercontent.com is part of service "github" (6 hosts, 1 broad).');
    expect(lines).toContain("note: objects.githubusercontent.com serves release assets");
  });

  test("caps the summary at 10 unique hosts", () => {
    const logs = Array.from({ length: 14 }, (_, index) => (
      denialLine({ host: `host-${index}.example.com` })
    )).join("\n");

    const lines = buildSessionDenialSummary(logs, policy);
    // Header + 10 hosts + details footer.
    expect(lines).toHaveLength(12);
    expect(lines[0]).toBe("Runfree blocked 14 hosts during this session (showing 10 of 14):");
  });
});

describe("printSessionDenialSummary", () => {
  let tmp: string;
  let context: RuntimeContext;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-denial-summary-"));
    fs.writeFileSync(path.join(tmp, "network-policy.json"), JSON.stringify(policy));
    context = {
      projectRoot: tmp,
      project: {
        config: {},
        paths: {
          policyPath: path.join(tmp, "network-policy.json"),
          stateDir: path.join(tmp, "state"),
        },
      },
      runtimeRoot: "/runtime",
      env: { PATH: "/bin" },
    } as unknown as RuntimeContext;
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function ioWith(capture: RuntimeIO["capture"]): RuntimeIO {
    return {
      run: () => 0,
      capture,
      commandExists: () => true,
      confirm: () => false,
      admin: () => Promise.resolve(0),
    };
  }

  test("prints the summary from proxy logs read since session start", () => {
    const captured: string[][] = [];
    const io = ioWith((command, args) => {
      captured.push([command, ...args]);
      if (args[0] === "ps") return { status: 0, stdout: "proxy-container-id\n", stderr: "" };
      if (args[0] === "logs") {
        return {
          status: 0,
          stdout: denialLine({ host: "api.example.com" }),
          stderr: "",
        };
      }
      return { status: 1, stdout: "", stderr: "" };
    });

    printSessionDenialSummary(context, io, { sinceIso: "2026-06-10T12:00:00.000Z" });

    const logsCall = captured.find((call) => call[1] === "logs");
    expect(logsCall).toEqual(["docker", "logs", "--since", "2026-06-10T12:00:00.000Z", "proxy-container-id"]);
    const printed = vi.mocked(console.log).mock.calls.map((call) => String(call[0]));
    expect(printed[0]).toBe("Runfree blocked 1 host during this session:");
    expect(printed.some((line) => line.includes("runfree host add api.example.com"))).toBe(true);
  });

  test("is suppressed with quiet", () => {
    const capture = vi.fn();
    printSessionDenialSummary(context, ioWith(capture as unknown as RuntimeIO["capture"]), {
      sinceIso: "2026-06-10T12:00:00.000Z",
      quiet: true,
    });
    expect(capture).not.toHaveBeenCalled();
    expect(console.log).not.toHaveBeenCalled();
  });

  test("prints nothing when there is no proxy container or the log read fails", () => {
    printSessionDenialSummary(context, ioWith(() => ({ status: 0, stdout: "", stderr: "" })), {
      sinceIso: "2026-06-10T12:00:00.000Z",
    });
    printSessionDenialSummary(context, ioWith((command, args) => {
      if (args[0] === "ps") return { status: 0, stdout: "proxy-container-id\n", stderr: "" };
      return { status: 1, stdout: "", stderr: "docker logs timed out" };
    }), { sinceIso: "2026-06-10T12:00:00.000Z" });
    expect(console.log).not.toHaveBeenCalled();
  });

  test("swallows log-read errors so session exit is never affected", () => {
    expect(() => printSessionDenialSummary(context, ioWith(() => {
      throw new Error("docker exploded");
    }), { sinceIso: "2026-06-10T12:00:00.000Z" })).not.toThrow();
    expect(console.log).not.toHaveBeenCalled();
  });

  test("reads logs from a known proxy id without a lookup", () => {
    const captured: string[][] = [];
    const io = ioWith((command, args) => {
      captured.push([command, ...args]);
      if (args[0] === "logs") return { status: 0, stdout: denialLine({ host: "api.example.com" }), stderr: "" };
      return { status: 1, stdout: "", stderr: "" };
    });
    printSessionDenialSummary(context, io, { sinceIso: "2026-06-10T12:00:00.000Z", proxyId: "known-proxy" });
    expect(captured).toEqual([["docker", "logs", "--since", "2026-06-10T12:00:00.000Z", "known-proxy"]]);
    expect(vi.mocked(console.log).mock.calls.map((call) => String(call[0]))[0]).toBe("Runfree blocked 1 host during this session:");
  });

  test("falls back to the current proxy when the known proxy's logs are unreadable", () => {
    const captured: string[][] = [];
    const io = ioWith((command, args) => {
      captured.push([command, ...args]);
      if (args[0] === "ps") return { status: 0, stdout: "replacement-proxy\n", stderr: "" };
      if (args[0] === "logs" && args.at(-1) === "replacement-proxy") {
        return { status: 0, stdout: denialLine({ host: "api.example.com" }), stderr: "" };
      }
      return { status: 1, stdout: "", stderr: "No such container" };
    });
    printSessionDenialSummary(context, io, { sinceIso: "2026-06-10T12:00:00.000Z", proxyId: "gone-proxy" });
    expect(captured.filter((call) => call[1] === "logs").map((call) => call.at(-1))).toEqual(["gone-proxy", "replacement-proxy"]);
    expect(console.log).toHaveBeenCalled();
  });
});
